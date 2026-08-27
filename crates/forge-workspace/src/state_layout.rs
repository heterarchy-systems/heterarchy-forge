use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use forge_domain::WorkspaceRootFingerprint;

use thiserror::Error;

const GIT_PROGRAM: &str = "/usr/bin/git";
const STATE_DIRECTORY_NAME: &str = ".heterarchy-forge";
const STATE_FORMAT_FILE_NAME: &str = "FORMAT";
const STATE_FORMAT: &[u8] = b"heterarchy-forge-state-v1\n";
const LOCAL_EXCLUDE_COMMENT: &[u8] = b"# Heterarchy Forge local runtime state\n";
const LOCAL_EXCLUDE_STATE_SUFFIX: &[u8] = b".heterarchy-forge/";
const LOCAL_EXCLUDE_TEMP_SUFFIX: &[u8] = b".heterarchy-forge.init.*/";
const MAX_LOCAL_EXCLUDE_BYTES: usize = 1_048_576;
const MAX_STATE_FORMAT_BYTES: usize = STATE_FORMAT.len();
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_TEMP_ATTEMPTS: u32 = 32;
const INITIALIZATION_LOCK_NAME: &str = ".heterarchy-forge.initialize.lock";
const MAX_INITIALIZATION_LOCK_ATTEMPTS: u32 = 1_024;
const INITIALIZATION_LOCK_WAIT: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitLocalState {
    NotGitRepository,
    LocalExcludeVerified,
}

/// Read-only diagnostic projection of a Workspace's local Git state.
///
/// This projection never grants effect authority and deliberately carries no
/// Git error text or path data.  A caller that needs remediation can use the
/// status to choose a separate, explicit initialization or recovery action.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitLocalStateDoctor {
    NotGitRepository,
    Verified,
    MissingLocalExclude,
    TrackedStateConflict,
    StateVisibleToGit,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStateLayout {
    workspace_root: PathBuf,
    state_root: PathBuf,
    diffs: PathBuf,
    checkpoints: PathBuf,
    artifacts: PathBuf,
    recovery: PathBuf,
    git_local_state: GitLocalState,
}

/// Read-only view of an already initialized Workspace state root.
///
/// Unlike [`WorkspaceStateLayout::initialize`], inspection never creates a
/// directory or file, never opens a database, and never asks Git to update or
/// verify an exclude rule.  The view is therefore suitable for discovery/list
/// operations where observing a candidate must not turn it into a selected
/// Workspace.  Callers must still revalidate the root before granting an
/// effect; this value is an observation, not a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingWorkspaceStateLayout {
    workspace_root: PathBuf,
    state_root: PathBuf,
    diffs: PathBuf,
    checkpoints: PathBuf,
    artifacts: PathBuf,
    recovery: PathBuf,
}

#[derive(Debug)]
struct GitLocalContext {
    exclude_path: PathBuf,
    state_rule_line: Vec<u8>,
    state_rule: Vec<u8>,
    temporary_rule_line: Vec<u8>,
    temporary_rule: Vec<u8>,
}

#[derive(Debug)]
struct InitializationLock {
    path: PathBuf,
}

impl Drop for InitializationLock {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir(&self.path);
    }
}

impl WorkspaceStateLayout {
    pub fn initialize(workspace_root: impl AsRef<Path>) -> Result<Self, StateLayoutError> {
        let workspace_root = canonical_workspace_root(workspace_root.as_ref())?;
        let git_context = discover_git_local_context(&workspace_root)?;
        let lock_parent = match git_context.as_ref() {
            Some(context) => context
                .exclude_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .ok_or_else(|| StateLayoutError::MissingParent(context.exclude_path.clone()))?,
            None => workspace_root.clone(),
        };
        let _initialization_lock = acquire_initialization_lock(&lock_parent)?;
        let git_local_state = match git_context.as_ref() {
            Some(context) => {
                prepare_git_local_ignore(&workspace_root, context)?;
                GitLocalState::LocalExcludeVerified
            }
            None => GitLocalState::NotGitRepository,
        };
        let state_root = workspace_root.join(STATE_DIRECTORY_NAME);

        if state_root.exists() {
            validate_owned_state_directory(&state_root)?;
        } else {
            create_owned_state_directory(&workspace_root, &state_root)?;
        }

        let layout = Self {
            workspace_root: workspace_root.clone(),
            state_root: state_root.clone(),
            diffs: state_root.join("diffs"),
            checkpoints: state_root.join("checkpoints"),
            artifacts: state_root.join("artifacts"),
            recovery: state_root.join("recovery"),
            git_local_state,
        };
        layout.ensure_subdirectories()?;
        if git_local_state == GitLocalState::LocalExcludeVerified {
            verify_state_is_git_invisible(&workspace_root)?;
        }
        Ok(layout)
    }

    /// Inspect an already initialized state root without creating or mutating
    /// anything.
    ///
    /// `Ok(None)` is reserved for the one case where the state root itself is
    /// absent.  A malformed, inaccessible, symlinked, or otherwise unowned
    /// state root is an error so callers cannot mistake damage for a clean
    /// Workspace that is safe to initialize implicitly.
    pub fn inspect_existing(
        workspace_root: impl AsRef<Path>,
    ) -> Result<Option<ExistingWorkspaceStateLayout>, StateLayoutError> {
        let workspace_root = canonical_existing_workspace_root(workspace_root.as_ref())?;
        // Capture and validate the root identity before inspecting the child
        // state tree.  This is intentionally repeated by callers before any
        // effect because the filesystem may change after this observation.
        observe_root_fingerprint(&workspace_root)?;

        let state_root = workspace_root.join(STATE_DIRECTORY_NAME);
        match fs::symlink_metadata(&state_root) {
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(StateLayoutError::InspectStatePath {
                    path: state_root,
                    source,
                });
            }
        }

        validate_owned_state_directory(&state_root)?;
        validate_existing_subdirectories(&state_root)?;

        Ok(Some(ExistingWorkspaceStateLayout {
            workspace_root: workspace_root.clone(),
            state_root: state_root.clone(),
            diffs: state_root.join("diffs"),
            checkpoints: state_root.join("checkpoints"),
            artifacts: state_root.join("artifacts"),
            recovery: state_root.join("recovery"),
        }))
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub fn database_path(&self) -> PathBuf {
        self.state_root.join("state.sqlite3")
    }

    /// Observe the canonical Workspace directory's stable device/inode identity.
    ///
    /// The fixed-width representation is built directly from Unix metadata
    /// without converting the native path or allocating an intermediate
    /// buffer. Callers must treat the result as an observation and re-check it
    /// before granting any Workspace-scoped effect.
    pub fn root_fingerprint(&self) -> Result<WorkspaceRootFingerprint, StateLayoutError> {
        observe_root_fingerprint(&self.workspace_root)
    }

    pub fn diffs(&self) -> &Path {
        &self.diffs
    }

    pub fn checkpoints(&self) -> &Path {
        &self.checkpoints
    }

    pub fn artifacts(&self) -> &Path {
        &self.artifacts
    }

    pub fn recovery(&self) -> &Path {
        &self.recovery
    }

    pub const fn git_local_state(&self) -> GitLocalState {
        self.git_local_state
    }

    /// Inspect local Git visibility without changing Git or Workspace state.
    pub fn inspect_git_local_state_read_only(
        &self,
    ) -> Result<GitLocalStateDoctor, StateLayoutError> {
        inspect_git_local_state_read_only(&self.workspace_root)
    }

    fn ensure_subdirectories(&self) -> Result<(), StateLayoutError> {
        for path in [
            &self.diffs,
            &self.checkpoints,
            &self.artifacts,
            &self.recovery,
        ] {
            ensure_owned_subdirectory(&self.state_root, path)?;
        }
        sync_directory(&self.state_root)?;
        Ok(())
    }
}

impl ExistingWorkspaceStateLayout {
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub fn database_path(&self) -> PathBuf {
        self.state_root.join("state.sqlite3")
    }

    pub fn diffs(&self) -> &Path {
        &self.diffs
    }

    pub fn checkpoints(&self) -> &Path {
        &self.checkpoints
    }

    pub fn artifacts(&self) -> &Path {
        &self.artifacts
    }

    pub fn recovery(&self) -> &Path {
        &self.recovery
    }

    /// Re-observe the canonical Workspace root's stable physical identity.
    pub fn root_fingerprint(&self) -> Result<WorkspaceRootFingerprint, StateLayoutError> {
        observe_root_fingerprint(&self.workspace_root)
    }

    /// Inspect local Git visibility without changing Git or Workspace state.
    pub fn inspect_git_local_state_read_only(
        &self,
    ) -> Result<GitLocalStateDoctor, StateLayoutError> {
        inspect_git_local_state_read_only(&self.workspace_root)
    }
}

fn inspect_git_local_state_read_only(
    workspace_root: &Path,
) -> Result<GitLocalStateDoctor, StateLayoutError> {
    let expected_fingerprint = observe_root_fingerprint(workspace_root)?;
    let result = inspect_git_local_state_at_root(workspace_root);
    let observed_fingerprint = observe_root_fingerprint(workspace_root)?;
    if expected_fingerprint != observed_fingerprint {
        return Err(StateLayoutError::WorkspaceRootFingerprintChanged {
            expected: expected_fingerprint,
            observed: observed_fingerprint,
        });
    }
    Ok(result)
}

fn inspect_git_local_state_at_root(workspace_root: &Path) -> GitLocalStateDoctor {
    let Some(is_git) = inspect_git_repository_read_only(workspace_root) else {
        return GitLocalStateDoctor::Unavailable;
    };
    if !is_git {
        return GitLocalStateDoctor::NotGitRepository;
    }

    let Ok(Some(_context)) = discover_git_local_context(workspace_root) else {
        return GitLocalStateDoctor::Unavailable;
    };
    if let Err(error) = reject_tracked_state_directory(workspace_root) {
        return match error {
            StateLayoutError::TrackedStateConflict(_) => GitLocalStateDoctor::TrackedStateConflict,
            _ => GitLocalStateDoctor::Unavailable,
        };
    }
    if let Err(error) = verify_local_exclude_rule(workspace_root) {
        return match error {
            StateLayoutError::LocalIgnoreVerificationFailed { .. } => {
                GitLocalStateDoctor::MissingLocalExclude
            }
            _ => GitLocalStateDoctor::Unavailable,
        };
    }
    match verify_state_is_git_invisible(workspace_root) {
        Ok(()) => GitLocalStateDoctor::Verified,
        Err(StateLayoutError::StateVisibleToGit { .. }) => GitLocalStateDoctor::StateVisibleToGit,
        Err(_) => GitLocalStateDoctor::Unavailable,
    }
}

fn inspect_git_repository_read_only(workspace_root: &Path) -> Option<bool> {
    let output = run_git(workspace_root, &["rev-parse", "--is-inside-work-tree"]).ok()?;
    if output.status.success() {
        return bounded_stdout(&output, "detect Git repository")
            .ok()
            .map(|stdout| trim_ascii(stdout) == b"true");
    }
    let stderr = output.stderr.as_slice();
    if stderr
        .windows(b"not a git repository".len())
        .any(|window| window == b"not a git repository")
    {
        Some(false)
    } else {
        None
    }
}

fn canonical_existing_workspace_root(path: &Path) -> Result<PathBuf, StateLayoutError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| StateLayoutError::InspectWorkspace {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(StateLayoutError::WorkspaceFingerprintRootIsSymlink(
            path.to_path_buf(),
        ));
    }
    if !metadata.is_dir() {
        return Err(StateLayoutError::WorkspaceIsNotDirectory(
            path.to_path_buf(),
        ));
    }
    fs::canonicalize(path).map_err(|source| StateLayoutError::CanonicalizeWorkspace {
        path: path.to_path_buf(),
        source,
    })
}

fn observe_root_fingerprint(
    workspace_root: &Path,
) -> Result<WorkspaceRootFingerprint, StateLayoutError> {
    let metadata = fs::symlink_metadata(workspace_root).map_err(|source| {
        StateLayoutError::ReadWorkspaceFingerprint {
            path: workspace_root.to_path_buf(),
            source,
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(StateLayoutError::WorkspaceFingerprintRootIsSymlink(
            workspace_root.to_path_buf(),
        ));
    }
    if !metadata.is_dir() {
        return Err(StateLayoutError::WorkspaceFingerprintRootNotDirectory(
            workspace_root.to_path_buf(),
        ));
    }
    let observed_root = fs::canonicalize(workspace_root).map_err(|source| {
        StateLayoutError::ReadWorkspaceFingerprint {
            path: workspace_root.to_path_buf(),
            source,
        }
    })?;
    if observed_root != workspace_root {
        return Err(StateLayoutError::WorkspaceFingerprintRootMoved {
            stored: workspace_root.to_path_buf(),
            observed: observed_root,
        });
    }

    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&metadata.dev().to_le_bytes());
    bytes[8..].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(WorkspaceRootFingerprint::from_bytes(bytes))
}

fn canonical_workspace_root(path: &Path) -> Result<PathBuf, StateLayoutError> {
    let metadata = fs::metadata(path).map_err(|source| StateLayoutError::InspectWorkspace {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(StateLayoutError::WorkspaceIsNotDirectory(
            path.to_path_buf(),
        ));
    }
    fs::canonicalize(path).map_err(|source| StateLayoutError::CanonicalizeWorkspace {
        path: path.to_path_buf(),
        source,
    })
}

fn discover_git_local_context(
    workspace_root: &Path,
) -> Result<Option<GitLocalContext>, StateLayoutError> {
    if !is_git_repository(workspace_root)? {
        return Ok(None);
    }

    let repository_root = git_repository_root(workspace_root)?;
    let relative_workspace = workspace_root.strip_prefix(&repository_root).map_err(|_| {
        StateLayoutError::WorkspaceOutsideGitRepository {
            workspace_root: workspace_root.to_path_buf(),
            repository_root,
        }
    })?;
    let (state_rule_line, state_rule) =
        build_git_exclude_rule(relative_workspace, LOCAL_EXCLUDE_STATE_SUFFIX)?;
    let (temporary_rule_line, temporary_rule) =
        build_git_exclude_rule(relative_workspace, LOCAL_EXCLUDE_TEMP_SUFFIX)?;

    Ok(Some(GitLocalContext {
        exclude_path: git_info_exclude_path(workspace_root)?,
        state_rule_line,
        state_rule,
        temporary_rule_line,
        temporary_rule,
    }))
}

fn git_repository_root(workspace_root: &Path) -> Result<PathBuf, StateLayoutError> {
    let output = run_git(workspace_root, &["rev-parse", "--show-cdup"])?;
    if !output.status.success() {
        return Err(StateLayoutError::GitCommandFailed {
            operation: "resolve Git repository root",
            status: output.status.code(),
            stderr: bounded_stderr_text(&output),
        });
    }
    let cdup =
        strip_single_trailing_newline(bounded_stdout(&output, "resolve Git repository root")?);
    if !is_valid_git_cdup(cdup) {
        return Err(StateLayoutError::InvalidGitRepositoryPrefix);
    }
    let candidate = if cdup.is_empty() {
        workspace_root.to_path_buf()
    } else {
        workspace_root.join(OsStr::from_bytes(cdup))
    };
    let repository_root = fs::canonicalize(&candidate).map_err(|source| {
        StateLayoutError::CanonicalizeGitRepository {
            path: candidate.clone(),
            source,
        }
    })?;
    if !workspace_root.starts_with(&repository_root) {
        return Err(StateLayoutError::WorkspaceOutsideGitRepository {
            workspace_root: workspace_root.to_path_buf(),
            repository_root,
        });
    }
    Ok(repository_root)
}

fn is_valid_git_cdup(cdup: &[u8]) -> bool {
    if cdup.is_empty() {
        return true;
    }
    let Some(without_trailing_slash) = cdup.strip_suffix(b"/") else {
        return false;
    };
    !without_trailing_slash.is_empty()
        && without_trailing_slash
            .split(|byte| *byte == b'/')
            .all(|component| component == b"..")
}

fn strip_single_trailing_newline(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

fn build_git_exclude_rule(
    relative_workspace: &Path,
    suffix: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), StateLayoutError> {
    let relative_bytes = relative_workspace.as_os_str().as_bytes();
    let escaped = escape_git_exclude_path(relative_bytes)?;
    let separator_count: usize = if escaped.is_empty() { 1 } else { 2 };
    let line_length = separator_count
        .saturating_add(escaped.len())
        .saturating_add(suffix.len());
    if line_length > MAX_GIT_OUTPUT_BYTES {
        return Err(StateLayoutError::WorkspaceRelativePathTooLong {
            actual: line_length,
            maximum: MAX_GIT_OUTPUT_BYTES,
        });
    }

    let mut line = Vec::with_capacity(line_length);
    line.push(b'/');
    line.extend_from_slice(&escaped);
    if !escaped.is_empty() {
        line.push(b'/');
    }
    line.extend_from_slice(suffix);

    let mut rule = Vec::with_capacity(line.len() + 1);
    rule.extend_from_slice(&line);
    rule.push(b'\n');
    Ok((line, rule))
}

fn escape_git_exclude_path(path: &[u8]) -> Result<Vec<u8>, StateLayoutError> {
    if path.len() > MAX_GIT_OUTPUT_BYTES {
        return Err(StateLayoutError::WorkspaceRelativePathTooLong {
            actual: path.len(),
            maximum: MAX_GIT_OUTPUT_BYTES,
        });
    }
    let mut escaped = Vec::with_capacity(path.len());
    for &byte in path {
        if matches!(byte, b'\n' | b'\r') {
            return Err(StateLayoutError::WorkspaceRelativePathNotRepresentable { byte });
        }
        if matches!(byte, b'\\' | b'*' | b'?' | b'[') {
            escaped.push(b'\\');
        }
        escaped.push(byte);
    }
    Ok(escaped)
}

fn acquire_initialization_lock(parent: &Path) -> Result<InitializationLock, StateLayoutError> {
    // `create_dir` is the cross-process atomic acquisition primitive. Git
    // workspaces share the lock beside info/exclude; non-Git workspaces use
    // their own root. The bounded wait plus Drop cleanup makes contention
    // converge without an ambient/global lock, while stale locks fail closed.
    let path = parent.join(INITIALIZATION_LOCK_NAME);
    for _attempt in 0..MAX_INITIALIZATION_LOCK_ATTEMPTS {
        match fs::create_dir(&path) {
            Ok(()) => return Ok(InitializationLock { path }),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                thread::sleep(INITIALIZATION_LOCK_WAIT);
            }
            Err(source) => {
                return Err(StateLayoutError::CreateInitializationLock { path, source });
            }
        }
    }
    Err(StateLayoutError::InitializationLockExhausted { path })
}

fn prepare_git_local_ignore(
    workspace_root: &Path,
    context: &GitLocalContext,
) -> Result<(), StateLayoutError> {
    reject_tracked_state_directory(workspace_root)?;
    ensure_local_exclude_rule(
        &context.exclude_path,
        &context.state_rule_line,
        &context.state_rule,
        &context.temporary_rule_line,
        &context.temporary_rule,
    )?;
    verify_local_exclude_rule(workspace_root)?;
    Ok(())
}

fn is_git_repository(workspace_root: &Path) -> Result<bool, StateLayoutError> {
    let output = run_git(workspace_root, &["rev-parse", "--is-inside-work-tree"])?;
    if !output.status.success() {
        return Ok(false);
    }
    let stdout = bounded_stdout(&output, "detect Git repository")?;
    Ok(trim_ascii(stdout) == b"true")
}

fn reject_tracked_state_directory(workspace_root: &Path) -> Result<(), StateLayoutError> {
    let output = run_git(
        workspace_root,
        &["ls-files", "-z", "--", STATE_DIRECTORY_NAME],
    )?;
    if !output.status.success() {
        return Err(StateLayoutError::GitCommandFailed {
            operation: "inspect tracked Forge state",
            status: output.status.code(),
            stderr: bounded_stderr_text(&output),
        });
    }
    if !bounded_stdout(&output, "inspect tracked Forge state")?.is_empty() {
        return Err(StateLayoutError::TrackedStateConflict(
            workspace_root.join(STATE_DIRECTORY_NAME),
        ));
    }
    Ok(())
}

fn git_info_exclude_path(workspace_root: &Path) -> Result<PathBuf, StateLayoutError> {
    let output = run_git(
        workspace_root,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "info/exclude",
        ],
    )?;
    if !output.status.success() {
        return Err(StateLayoutError::GitCommandFailed {
            operation: "resolve Git info/exclude",
            status: output.status.code(),
            stderr: bounded_stderr_text(&output),
        });
    }
    let bytes = trim_ascii(bounded_stdout(&output, "resolve Git info/exclude")?);
    if bytes.is_empty() {
        return Err(StateLayoutError::EmptyGitExcludePath);
    }
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

fn ensure_local_exclude_rule(
    exclude_path: &Path,
    state_rule_line: &[u8],
    state_rule: &[u8],
    temporary_rule_line: &[u8],
    temporary_rule: &[u8],
) -> Result<(), StateLayoutError> {
    let parent = exclude_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| StateLayoutError::MissingParent(exclude_path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| StateLayoutError::CreateStatePath {
        path: parent.to_path_buf(),
        source,
    })?;

    if let Ok(metadata) = fs::symlink_metadata(exclude_path) {
        if metadata.file_type().is_symlink() {
            return Err(StateLayoutError::GitExcludeIsSymlink(
                exclude_path.to_path_buf(),
            ));
        }
        if !metadata.is_file() {
            return Err(StateLayoutError::GitExcludeIsNotFile(
                exclude_path.to_path_buf(),
            ));
        }
    }

    let existing = match File::open(exclude_path) {
        Ok(file) => read_bounded(file, MAX_LOCAL_EXCLUDE_BYTES).map_err(|error| match error {
            BoundedReadError::Io(source) => StateLayoutError::ReadGitExclude {
                path: exclude_path.to_path_buf(),
                source,
            },
            BoundedReadError::TooLarge { actual, maximum } => {
                StateLayoutError::GitExcludeTooLarge {
                    path: exclude_path.to_path_buf(),
                    actual,
                    maximum,
                }
            }
        })?,
        Err(source) if source.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(source) => {
            return Err(StateLayoutError::ReadGitExclude {
                path: exclude_path.to_path_buf(),
                source,
            });
        }
    };
    let state_rule_present = contains_exact_line(&existing, state_rule_line);
    let temporary_rule_present = contains_exact_line(&existing, temporary_rule_line);
    if state_rule_present && temporary_rule_present {
        return Ok(());
    }

    let permissions = fs::metadata(exclude_path)
        .ok()
        .map(|metadata| metadata.permissions());
    let mut next = existing;
    if !next.is_empty() && !next.ends_with(b"\n") {
        next.push(b'\n');
    }
    if !state_rule_present {
        next.extend_from_slice(LOCAL_EXCLUDE_COMMENT);
        next.extend_from_slice(state_rule);
    }
    if !temporary_rule_present {
        next.extend_from_slice(temporary_rule);
    }
    atomic_replace(exclude_path, &next, permissions.as_ref())
}

fn verify_local_exclude_rule(workspace_root: &Path) -> Result<(), StateLayoutError> {
    for probe in [
        format!("{STATE_DIRECTORY_NAME}/probe"),
        ".heterarchy-forge.init.probe/probe".to_owned(),
    ] {
        let output = run_git(
            workspace_root,
            &["check-ignore", "--quiet", "--no-index", "--", &probe],
        )?;
        if !output.status.success() {
            return Err(StateLayoutError::LocalIgnoreVerificationFailed {
                workspace_root: workspace_root.to_path_buf(),
                stderr: bounded_stderr_text(&output),
            });
        }
    }
    Ok(())
}

fn verify_state_is_git_invisible(workspace_root: &Path) -> Result<(), StateLayoutError> {
    let output = run_git(
        workspace_root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            STATE_DIRECTORY_NAME,
        ],
    )?;
    if !output.status.success() {
        return Err(StateLayoutError::GitCommandFailed {
            operation: "verify Forge state invisibility",
            status: output.status.code(),
            stderr: bounded_stderr_text(&output),
        });
    }
    let stdout = bounded_stdout(&output, "verify Forge state invisibility")?;
    if stdout.is_empty() {
        Ok(())
    } else {
        Err(StateLayoutError::StateVisibleToGit {
            workspace_root: workspace_root.to_path_buf(),
        })
    }
}

fn create_owned_state_directory(
    workspace_root: &Path,
    state_root: &Path,
) -> Result<(), StateLayoutError> {
    let temporary = create_unique_temporary_directory(workspace_root)?;
    let result = (|| {
        let format_path = temporary.join(STATE_FORMAT_FILE_NAME);
        let mut format_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&format_path)
            .map_err(|source| StateLayoutError::WriteStateFormat {
                path: format_path.clone(),
                source,
            })?;
        format_file
            .write_all(STATE_FORMAT)
            .and_then(|()| format_file.sync_all())
            .map_err(|source| StateLayoutError::WriteStateFormat {
                path: format_path,
                source,
            })?;
        for name in ["diffs", "checkpoints", "artifacts", "recovery"] {
            let path = temporary.join(name);
            fs::create_dir(&path)
                .map_err(|source| StateLayoutError::CreateStatePath { path, source })?;
        }
        sync_directory(&temporary)?;
        fs::rename(&temporary, state_root).map_err(|source| {
            StateLayoutError::PublishStateRoot {
                from: temporary.clone(),
                to: state_root.to_path_buf(),
                source,
            }
        })?;
        sync_directory(workspace_root)
    })();

    if result.is_err() && temporary.exists() {
        let _ignored = fs::remove_dir_all(&temporary);
    }
    result
}

fn validate_owned_state_directory(state_root: &Path) -> Result<(), StateLayoutError> {
    let metadata =
        fs::symlink_metadata(state_root).map_err(|source| StateLayoutError::InspectStatePath {
            path: state_root.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(StateLayoutError::StatePathIsSymlink(
            state_root.to_path_buf(),
        ));
    }
    if !metadata.is_dir() {
        return Err(StateLayoutError::StateRootIsNotDirectory(
            state_root.to_path_buf(),
        ));
    }
    let format_path = state_root.join(STATE_FORMAT_FILE_NAME);
    let format_metadata = fs::symlink_metadata(&format_path).map_err(|source| {
        StateLayoutError::StateDirectoryOwnershipUnknown {
            path: state_root.to_path_buf(),
            source,
        }
    })?;
    if format_metadata.file_type().is_symlink() {
        return Err(StateLayoutError::StatePathIsSymlink(format_path));
    }
    if !format_metadata.is_file() {
        return Err(StateLayoutError::StateFormatIsNotRegularFile(format_path));
    }
    if format_metadata.nlink() != 1 {
        return Err(StateLayoutError::StateFormatLinkCountInvalid {
            path: format_path,
            links: format_metadata.nlink(),
        });
    }
    let mut format_file = File::open(&format_path).map_err(|source| {
        StateLayoutError::StateDirectoryOwnershipUnknown {
            path: state_root.to_path_buf(),
            source,
        }
    })?;
    let opened_metadata = format_file.metadata().map_err(|source| {
        StateLayoutError::StateDirectoryOwnershipUnknown {
            path: state_root.to_path_buf(),
            source,
        }
    })?;
    validate_format_file_identity(&format_path, &format_metadata, &opened_metadata)?;
    let format =
        read_bounded(&mut format_file, MAX_STATE_FORMAT_BYTES).map_err(|error| match error {
            BoundedReadError::Io(source) => StateLayoutError::StateDirectoryOwnershipUnknown {
                path: state_root.to_path_buf(),
                source,
            },
            BoundedReadError::TooLarge { actual, maximum } => {
                StateLayoutError::StateFormatTooLarge {
                    path: format_path.clone(),
                    actual,
                    maximum,
                }
            }
        })?;
    if format != STATE_FORMAT {
        return Err(StateLayoutError::UnsupportedStateFormat { path: format_path });
    }
    Ok(())
}

fn validate_existing_subdirectories(state_root: &Path) -> Result<(), StateLayoutError> {
    let canonical_state_root =
        fs::canonicalize(state_root).map_err(|source| StateLayoutError::CanonicalizeStatePath {
            path: state_root.to_path_buf(),
            source,
        })?;
    for name in ["diffs", "checkpoints", "artifacts", "recovery"] {
        let path = state_root.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                StateLayoutError::StateSubpathMissing(path.clone())
            } else {
                StateLayoutError::InspectStatePath {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(StateLayoutError::StatePathIsSymlink(path));
        }
        if !metadata.is_dir() {
            return Err(StateLayoutError::StateSubpathIsNotDirectory(path));
        }
        let canonical_path =
            fs::canonicalize(&path).map_err(|source| StateLayoutError::CanonicalizeStatePath {
                path: path.clone(),
                source,
            })?;
        if !canonical_path.starts_with(&canonical_state_root) {
            return Err(StateLayoutError::StatePathEscapesRoot {
                path: canonical_path,
                state_root: canonical_state_root.clone(),
            });
        }
        if canonical_path != path {
            return Err(StateLayoutError::StatePathIdentityChanged { path });
        }
    }
    Ok(())
}

fn validate_format_file_identity(
    format_path: &Path,
    path_metadata: &Metadata,
    opened_metadata: &Metadata,
) -> Result<(), StateLayoutError> {
    if !opened_metadata.is_file() {
        return Err(StateLayoutError::StateFormatIsNotRegularFile(
            format_path.to_path_buf(),
        ));
    }
    if path_metadata.nlink() != 1 || opened_metadata.nlink() != 1 {
        return Err(StateLayoutError::StateFormatLinkCountInvalid {
            path: format_path.to_path_buf(),
            links: opened_metadata.nlink(),
        });
    }
    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(StateLayoutError::StateFormatIdentityChanged {
            path: format_path.to_path_buf(),
        });
    }
    Ok(())
}

fn ensure_owned_subdirectory(state_root: &Path, path: &Path) -> Result<(), StateLayoutError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StateLayoutError::StatePathIsSymlink(path.to_path_buf()));
            }
            if !metadata.is_dir() {
                return Err(StateLayoutError::StateSubpathIsNotDirectory(
                    path.to_path_buf(),
                ));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|source| StateLayoutError::CreateStatePath {
                path: path.to_path_buf(),
                source,
            })?;
        }
        Err(source) => {
            return Err(StateLayoutError::InspectStatePath {
                path: path.to_path_buf(),
                source,
            });
        }
    }

    let canonical_state_root =
        fs::canonicalize(state_root).map_err(|source| StateLayoutError::CanonicalizeStatePath {
            path: state_root.to_path_buf(),
            source,
        })?;
    let canonical_path =
        fs::canonicalize(path).map_err(|source| StateLayoutError::CanonicalizeStatePath {
            path: path.to_path_buf(),
            source,
        })?;
    if !canonical_path.starts_with(&canonical_state_root) {
        return Err(StateLayoutError::StatePathEscapesRoot {
            path: canonical_path,
            state_root: canonical_state_root,
        });
    }
    Ok(())
}

fn create_unique_temporary_directory(workspace_root: &Path) -> Result<PathBuf, StateLayoutError> {
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let path = workspace_root.join(format!(
            ".heterarchy-forge.init.{}.{}",
            std::process::id(),
            attempt
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(StateLayoutError::CreateTemporaryStateRoot { path, source });
            }
        }
    }
    Err(StateLayoutError::TemporaryStateRootExhausted)
}

fn atomic_replace(
    destination: &Path,
    content: &[u8],
    permissions: Option<&Permissions>,
) -> Result<(), StateLayoutError> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| StateLayoutError::MissingParent(destination.to_path_buf()))?;
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temporary = parent.join(format!(
            ".heterarchy-forge-exclude.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(StateLayoutError::CreateTemporaryFile {
                    path: temporary,
                    source,
                });
            }
        };
        let result = (|| {
            file.write_all(content)
                .map_err(|source| StateLayoutError::WriteTemporaryFile {
                    path: temporary.clone(),
                    source,
                })?;
            file.sync_all()
                .map_err(|source| StateLayoutError::SyncFile {
                    path: temporary.clone(),
                    source,
                })?;
            if let Some(permissions) = permissions {
                fs::set_permissions(&temporary, permissions.clone()).map_err(|source| {
                    StateLayoutError::SetPermissions {
                        path: temporary.clone(),
                        source,
                    }
                })?;
            }
            fs::rename(&temporary, destination).map_err(|source| {
                StateLayoutError::ReplaceFile {
                    from: temporary.clone(),
                    to: destination.to_path_buf(),
                    source,
                }
            })?;
            sync_directory(parent)
        })();
        if result.is_err() && temporary.exists() {
            let _ignored = fs::remove_file(&temporary);
        }
        return result;
    }
    Err(StateLayoutError::TemporaryFileExhausted(
        destination.to_path_buf(),
    ))
}

fn sync_directory(path: &Path) -> Result<(), StateLayoutError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StateLayoutError::SyncDirectory {
            path: path.to_path_buf(),
            source,
        })
}

fn contains_exact_line(body: &[u8], expected: &[u8]) -> bool {
    body.split(|byte| *byte == b'\n')
        .any(|line| line == expected)
}

#[derive(Debug)]
struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_total: usize,
}

#[derive(Debug, Error)]
enum BoundedReadError {
    #[error("bounded stream read failed")]
    Io(#[source] io::Error),
    #[error("bounded stream exceeded {maximum} bytes with {actual} bytes")]
    TooLarge { actual: usize, maximum: usize },
}

#[derive(Debug)]
struct BoundedCapture {
    bytes: Vec<u8>,
    total: usize,
}

enum BoundedStreamResult {
    Stdout(Result<BoundedCapture, BoundedReadError>),
    Stderr(Result<BoundedCapture, BoundedReadError>),
}

type BoundedStreamCapture = Result<BoundedCapture, BoundedReadError>;
type BoundedStreamOutput = Result<BoundedStreamCapture, StateLayoutError>;

fn read_bounded<R: Read>(reader: R, maximum: usize) -> Result<Vec<u8>, BoundedReadError> {
    let capture = read_capped(reader, maximum)?;
    if capture.total > maximum {
        Err(BoundedReadError::TooLarge {
            actual: capture.total,
            maximum,
        })
    } else {
        Ok(capture.bytes)
    }
}

fn read_capped<R: Read>(mut reader: R, maximum: usize) -> Result<BoundedCapture, BoundedReadError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_usize;
    let capacity = maximum.saturating_add(1);

    loop {
        let read = reader.read(&mut buffer).map_err(BoundedReadError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let remaining = capacity.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        if retained > 0 {
            bytes.reserve_exact(retained);
            bytes.extend_from_slice(&buffer[..retained]);
        }
        if total > maximum {
            break;
        }
    }

    Ok(BoundedCapture { bytes, total })
}

fn capture_git_streams(
    child: &mut Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
) -> (BoundedStreamOutput, BoundedStreamOutput) {
    thread::scope(|scope| {
        let (result_sender, result_receiver) = mpsc::sync_channel(2);
        let stdout_sender = result_sender.clone();
        let stdout_reader = scope.spawn(move || {
            let result = read_capped(stdout, MAX_GIT_OUTPUT_BYTES);
            let _ignored = stdout_sender.send(BoundedStreamResult::Stdout(result));
        });
        let stderr_reader = scope.spawn(move || {
            let result = read_capped(stderr, MAX_GIT_OUTPUT_BYTES);
            let _ignored = result_sender.send(BoundedStreamResult::Stderr(result));
        });

        let mut stdout_result = None;
        let mut stderr_result = None;
        let mut producer_terminated = false;
        while stdout_result.is_none() || stderr_result.is_none() {
            let Ok(result) = result_receiver.recv() else {
                break;
            };
            match result {
                BoundedStreamResult::Stdout(result) => {
                    let should_terminate = result.is_err()
                        || matches!(
                            &result,
                            Ok(capture) if capture.total > MAX_GIT_OUTPUT_BYTES
                        );
                    if should_terminate && !producer_terminated {
                        // The reader has already dropped stdout. Terminate the
                        // producer before waiting on the other pipe so a
                        // blocked peer cannot hold initialization hostage.
                        let _ignored = child.kill();
                        producer_terminated = true;
                    }
                    stdout_result = Some(result);
                }
                BoundedStreamResult::Stderr(result) => {
                    let should_terminate = result.is_err()
                        || matches!(
                            &result,
                            Ok(capture) if capture.total > MAX_GIT_OUTPUT_BYTES
                        );
                    if should_terminate && !producer_terminated {
                        let _ignored = child.kill();
                        producer_terminated = true;
                    }
                    stderr_result = Some(result);
                }
            }
        }

        if (stdout_result.is_none() || stderr_result.is_none()) && !producer_terminated {
            let _ignored = child.kill();
        }
        let stdout_panicked = stdout_reader.join().is_err();
        let stderr_panicked = stderr_reader.join().is_err();
        let stdout_result = stdout_result.map_or_else(
            || Err(StateLayoutError::GitOutputReaderPanicked { stream: "stdout" }),
            Ok,
        );
        let stderr_result = stderr_result.map_or_else(
            || Err(StateLayoutError::GitOutputReaderPanicked { stream: "stderr" }),
            Ok,
        );
        if stdout_panicked || stderr_panicked {
            let _ignored = child.kill();
        }
        (stdout_result, stderr_result)
    })
}

fn run_git(workspace_root: &Path, arguments: &[&str]) -> Result<BoundedOutput, StateLayoutError> {
    let mut command = Command::new(GIT_PROGRAM);
    command
        .arg("-C")
        .arg(workspace_root)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|source| StateLayoutError::StartGit {
            arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
            source,
        })?;
    let Some(stdout) = child.stdout.take() else {
        let _ignored = child.kill();
        let _ignored = child.wait();
        return Err(StateLayoutError::GitOutputPipeUnavailable { stream: "stdout" });
    };
    let Some(stderr) = child.stderr.take() else {
        let _ignored = child.kill();
        let _ignored = child.wait();
        return Err(StateLayoutError::GitOutputPipeUnavailable { stream: "stderr" });
    };

    let (stdout_result, stderr_result) = capture_git_streams(&mut child, stdout, stderr);

    let status = child.wait().map_err(|source| StateLayoutError::WaitGit {
        arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
        source,
    })?;
    let stdout = map_capture_result(stdout_result, "stdout")?;
    let stderr = map_capture_result(stderr_result, "stderr")?;

    Ok(BoundedOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_total: stdout.total,
    })
}

fn map_capture_result(
    result: Result<Result<BoundedCapture, BoundedReadError>, StateLayoutError>,
    stream: &'static str,
) -> Result<BoundedCapture, StateLayoutError> {
    match result {
        Ok(Ok(capture)) => Ok(capture),
        Ok(Err(BoundedReadError::Io(source))) => {
            Err(StateLayoutError::ReadGitOutput { stream, source })
        }
        Ok(Err(BoundedReadError::TooLarge { actual, maximum })) => {
            Err(StateLayoutError::GitOutputTooLarge {
                operation: "capture Git output",
                actual,
                maximum,
            })
        }
        Err(error) => Err(error),
    }
}

fn bounded_stdout<'a>(
    output: &'a BoundedOutput,
    operation: &'static str,
) -> Result<&'a [u8], StateLayoutError> {
    if output.stdout_total > MAX_GIT_OUTPUT_BYTES {
        Err(StateLayoutError::GitOutputTooLarge {
            operation,
            actual: output.stdout_total,
            maximum: MAX_GIT_OUTPUT_BYTES,
        })
    } else {
        Ok(&output.stdout)
    }
}

fn bounded_stderr_text(output: &BoundedOutput) -> String {
    let bounded = &output.stderr;
    String::from_utf8_lossy(bounded).into_owned()
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

#[derive(Debug, Error)]
pub enum StateLayoutError {
    #[error("failed to inspect Workspace root {path}")]
    InspectWorkspace {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Workspace root is not a directory: {0}")]
    WorkspaceIsNotDirectory(PathBuf),
    #[error("failed to canonicalize Workspace root {path}")]
    CanonicalizeWorkspace {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize Git repository root {path}")]
    CanonicalizeGitRepository {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Git returned an invalid repository-relative prefix")]
    InvalidGitRepositoryPrefix,
    #[error("Workspace root {workspace_root} is outside Git repository root {repository_root}")]
    WorkspaceOutsideGitRepository {
        workspace_root: PathBuf,
        repository_root: PathBuf,
    },
    #[error("failed to read Workspace root fingerprint metadata {path}")]
    ReadWorkspaceFingerprint {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Workspace fingerprint root is not a directory: {0}")]
    WorkspaceFingerprintRootNotDirectory(PathBuf),
    #[error("Workspace fingerprint root is a symlink: {0}")]
    WorkspaceFingerprintRootIsSymlink(PathBuf),
    #[error("Workspace fingerprint root moved: stored={stored}, observed={observed}")]
    WorkspaceFingerprintRootMoved { stored: PathBuf, observed: PathBuf },
    #[error("Workspace root fingerprint changed")]
    WorkspaceRootFingerprintChanged {
        expected: WorkspaceRootFingerprint,
        observed: WorkspaceRootFingerprint,
    },
    #[error("Workspace-relative path contains byte {byte:#04x} that Git excludes cannot represent")]
    WorkspaceRelativePathNotRepresentable { byte: u8 },
    #[error("Workspace-relative Git exclude rule requires {actual} bytes; maximum is {maximum}")]
    WorkspaceRelativePathTooLong { actual: usize, maximum: usize },
    #[error("failed to start Git with arguments {arguments:?}")]
    StartGit {
        arguments: Vec<String>,
        #[source]
        source: io::Error,
    },
    #[error("Git operation {operation} failed with status {status:?}: {stderr}")]
    GitCommandFailed {
        operation: &'static str,
        status: Option<i32>,
        stderr: String,
    },
    #[error("Git operation {operation} returned {actual} bytes; maximum is {maximum}")]
    GitOutputTooLarge {
        operation: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("Git {stream} output pipe was unavailable")]
    GitOutputPipeUnavailable { stream: &'static str },
    #[error("Git {stream} output reader panicked")]
    GitOutputReaderPanicked { stream: &'static str },
    #[error("failed to read Git {stream} output")]
    ReadGitOutput {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to wait for Git with arguments {arguments:?}")]
    WaitGit {
        arguments: Vec<String>,
        #[source]
        source: io::Error,
    },
    #[error("Git returned an empty info/exclude path")]
    EmptyGitExcludePath,
    #[error("Git local exclude path is a symlink: {0}")]
    GitExcludeIsSymlink(PathBuf),
    #[error("Git local exclude path is not a regular file: {0}")]
    GitExcludeIsNotFile(PathBuf),
    #[error("path has no parent directory: {0}")]
    MissingParent(PathBuf),
    #[error("failed to create state path {path}")]
    CreateStatePath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read Git local exclude file {path}")]
    ReadGitExclude {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Git local exclude file {path} returned {actual} bytes; maximum is {maximum}")]
    GitExcludeTooLarge {
        path: PathBuf,
        actual: usize,
        maximum: usize,
    },
    #[error("failed to create temporary file {path}")]
    CreateTemporaryFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write temporary file {path}")]
    WriteTemporaryFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync file {path}")]
    SyncFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to set permissions on {path}")]
    SetPermissions {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to replace {to} from {from}")]
    ReplaceFile {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("temporary file attempts exhausted for {0}")]
    TemporaryFileExhausted(PathBuf),
    #[error("failed to sync directory {path}")]
    SyncDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Forge state path is already tracked: {0}")]
    TrackedStateConflict(PathBuf),
    #[error("Git local-ignore verification failed for {workspace_root}: {stderr}")]
    LocalIgnoreVerificationFailed {
        workspace_root: PathBuf,
        stderr: String,
    },
    #[error("Forge state remains visible to Git under {workspace_root}")]
    StateVisibleToGit { workspace_root: PathBuf },
    #[error("failed to create temporary Forge state root {path}")]
    CreateTemporaryStateRoot {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("temporary Forge state root attempts exhausted")]
    TemporaryStateRootExhausted,
    #[error("failed to create initialization lock {path}")]
    CreateInitializationLock {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("initialization lock attempts exhausted: {path}")]
    InitializationLockExhausted { path: PathBuf },
    #[error("failed to write Forge state format marker {path}")]
    WriteStateFormat {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to publish Forge state root from {from} to {to}")]
    PublishStateRoot {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect Forge state path {path}")]
    InspectStatePath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize Forge state path {path}")]
    CanonicalizeStatePath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Forge state path is a symlink: {0}")]
    StatePathIsSymlink(PathBuf),
    #[error("Forge state format marker is not a regular file: {0}")]
    StateFormatIsNotRegularFile(PathBuf),
    #[error("Forge state format marker has invalid hard-link count {links}: {path}")]
    StateFormatLinkCountInvalid { path: PathBuf, links: u64 },
    #[error("Forge state format marker identity changed before read: {path}")]
    StateFormatIdentityChanged { path: PathBuf },
    #[error("Forge state root is not a directory: {0}")]
    StateRootIsNotDirectory(PathBuf),
    #[error("Forge state subpath is not a directory: {0}")]
    StateSubpathIsNotDirectory(PathBuf),
    #[error("Forge state subpath is missing: {0}")]
    StateSubpathMissing(PathBuf),
    #[error("Forge state path identity changed before read: {path}")]
    StatePathIdentityChanged { path: PathBuf },
    #[error("Forge state path {path} escapes state root {state_root}")]
    StatePathEscapesRoot { path: PathBuf, state_root: PathBuf },
    #[error("Forge state directory ownership is unknown: {path}")]
    StateDirectoryOwnershipUnknown {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsupported Forge state format marker: {path}")]
    UnsupportedStateFormat { path: PathBuf },
    #[error("Forge state format marker {path} returned {actual} bytes; maximum is {maximum}")]
    StateFormatTooLarge {
        path: PathBuf,
        actual: usize,
        maximum: usize,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        GitLocalState, GitLocalStateDoctor, INITIALIZATION_LOCK_NAME, LOCAL_EXCLUDE_COMMENT,
        STATE_DIRECTORY_NAME, STATE_FORMAT, STATE_FORMAT_FILE_NAME, StateLayoutError,
        WorkspaceStateLayout,
    };

    #[test]
    fn non_git_workspace_initializes_owned_local_state_idempotently()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("non-git")?;
        fs::create_dir_all(&root)?;

        let first = WorkspaceStateLayout::initialize(&root)?;
        let second = WorkspaceStateLayout::initialize(&root)?;
        assert_eq!(first, second);
        assert_eq!(first.git_local_state(), GitLocalState::NotGitRepository);
        assert!(first.database_path().ends_with("state.sqlite3"));
        for path in [
            first.diffs(),
            first.checkpoints(),
            first.artifacts(),
            first.recovery(),
        ] {
            assert!(path.is_dir());
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn inspect_existing_is_read_only_and_returns_none_without_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("inspect-absent")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        let exclude_path = root.join(".git/info/exclude");
        let exclude_before = fs::read(&exclude_path)?;

        assert!(WorkspaceStateLayout::inspect_existing(&root)?.is_none());
        assert!(!root.join(STATE_DIRECTORY_NAME).exists());
        assert_eq!(fs::read(&exclude_path)?, exclude_before);
        assert!(!root.join(INITIALIZATION_LOCK_NAME).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn inspect_existing_validates_shape_without_initializing_database_or_git_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("inspect-existing")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let exclude_path = root.join(".git/info/exclude");
        let exclude_before = fs::read(&exclude_path)?;
        assert!(!layout.database_path().exists());

        let existing = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or("initialized state root was not observed")?;
        assert_eq!(existing.workspace_root(), layout.workspace_root());
        assert_eq!(existing.state_root(), layout.state_root());
        assert_eq!(existing.root_fingerprint()?, layout.root_fingerprint()?);
        assert_eq!(fs::read(&exclude_path)?, exclude_before);
        assert!(!existing.database_path().exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn git_local_state_doctor_reports_verified_without_mutating_any_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("git-doctor-verified")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        let gitignore = root.join(".gitignore");
        fs::write(&gitignore, b"target/\n")?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let exclude = root.join(".git/info/exclude");
        let index = root.join(".git/index");
        let format = layout.state_root().join(STATE_FORMAT_FILE_NAME);
        let exclude_before = file_snapshot(&exclude)?;
        let gitignore_before = file_snapshot(&gitignore)?;
        let index_before = optional_file_snapshot(&index)?;
        let format_before = file_snapshot(&format)?;

        assert_eq!(
            layout.inspect_git_local_state_read_only()?,
            GitLocalStateDoctor::Verified
        );
        assert_eq!(file_snapshot(&exclude)?, exclude_before);
        assert_eq!(file_snapshot(&gitignore)?, gitignore_before);
        assert_eq!(optional_file_snapshot(&index)?, index_before);
        assert_eq!(file_snapshot(&format)?, format_before);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn git_local_state_doctor_distinguishes_non_git_and_missing_exclude()
    -> Result<(), Box<dyn std::error::Error>> {
        let non_git = unique_test_root("git-doctor-non-git")?;
        fs::create_dir_all(&non_git)?;
        let non_git_layout = WorkspaceStateLayout::initialize(&non_git)?;
        assert_eq!(
            non_git_layout.inspect_git_local_state_read_only()?,
            GitLocalStateDoctor::NotGitRepository
        );
        fs::remove_dir_all(non_git)?;

        let missing = unique_test_root("git-doctor-missing-exclude")?;
        fs::create_dir_all(&missing)?;
        git(&missing, &["init", "--quiet"])?;
        let layout = WorkspaceStateLayout::initialize(&missing)?;
        let exclude = missing.join(".git/info/exclude");
        let original = fs::read(&exclude)?;
        let filtered = original
            .split(|byte| *byte == b'\n')
            .filter(|line| {
                *line != b"/.heterarchy-forge/"
                    && *line != b"/.heterarchy-forge.init.*/"
                    && *line
                        != LOCAL_EXCLUDE_COMMENT
                            .strip_suffix(b"\n")
                            .unwrap_or_default()
            })
            .flat_map(|line| line.iter().copied().chain(std::iter::once(b'\n')))
            .collect::<Vec<_>>();
        fs::write(&exclude, filtered)?;
        let before = file_snapshot(&exclude)?;
        assert_eq!(
            layout.inspect_git_local_state_read_only()?,
            GitLocalStateDoctor::MissingLocalExclude
        );
        assert_eq!(file_snapshot(&exclude)?, before);

        fs::remove_dir_all(missing)?;
        Ok(())
    }

    #[test]
    fn git_local_state_doctor_distinguishes_tracked_and_visible_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let tracked = unique_test_root("git-doctor-tracked")?;
        fs::create_dir_all(&tracked)?;
        git(&tracked, &["init", "--quiet"])?;
        let tracked_layout = WorkspaceStateLayout::initialize(&tracked)?;
        let tracked_file = tracked_layout.state_root().join("tracked.txt");
        fs::write(&tracked_file, b"tracked")?;
        git(&tracked, &["add", "-f", ".heterarchy-forge/tracked.txt"])?;
        let tracked_index = tracked.join(".git/index");
        let tracked_before = optional_file_snapshot(&tracked_index)?;
        assert_eq!(
            tracked_layout.inspect_git_local_state_read_only()?,
            GitLocalStateDoctor::TrackedStateConflict
        );
        assert_eq!(optional_file_snapshot(&tracked_index)?, tracked_before);
        fs::remove_dir_all(tracked)?;

        let visible = unique_test_root("git-doctor-visible")?;
        fs::create_dir_all(&visible)?;
        git(&visible, &["init", "--quiet"])?;
        let visible_layout = WorkspaceStateLayout::initialize(&visible)?;
        let visible_file = visible_layout.state_root().join("visible.txt");
        fs::write(&visible_file, b"visible")?;
        let exclude = visible.join(".git/info/exclude");
        let exclude_body = fs::read(&exclude)?;
        let exclude_body = exclude_body
            .split(|byte| *byte == b'\n')
            .map(|line| {
                if line == b"/.heterarchy-forge/" {
                    b"/.heterarchy-forge/*".as_slice()
                } else {
                    line
                }
            })
            .flat_map(|line| line.iter().copied().chain(std::iter::once(b'\n')))
            .collect::<Vec<_>>();
        let mut exclude_body = exclude_body;
        exclude_body.extend_from_slice(b"!/.heterarchy-forge/visible.txt\n");
        fs::write(&exclude, exclude_body)?;
        let exclude_before = file_snapshot(&exclude)?;
        assert_eq!(
            visible_layout.inspect_git_local_state_read_only()?,
            GitLocalStateDoctor::StateVisibleToGit
        );
        assert_eq!(file_snapshot(&exclude)?, exclude_before);
        fs::remove_dir_all(visible)?;
        Ok(())
    }

    #[test]
    fn git_local_state_doctor_fails_closed_when_workspace_root_drifts()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = unique_test_root("git-doctor-root-drift")?;
        let root = parent.join("workspace");
        let replacement = parent.join("replacement");
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&replacement)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        fs::remove_dir_all(&root)?;
        symlink(&replacement, &root)?;
        assert!(matches!(
            layout.inspect_git_local_state_read_only(),
            Err(StateLayoutError::WorkspaceFingerprintRootIsSymlink(_))
        ));
        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn inspect_existing_rejects_missing_or_symlinked_subdirectories()
    -> Result<(), Box<dyn std::error::Error>> {
        let missing_root = unique_test_root("inspect-missing-subdir")?;
        fs::create_dir_all(&missing_root)?;
        let layout = WorkspaceStateLayout::initialize(&missing_root)?;
        fs::remove_dir(layout.recovery())?;
        assert!(matches!(
            WorkspaceStateLayout::inspect_existing(&missing_root),
            Err(StateLayoutError::StateSubpathMissing(path)) if path == layout.recovery()
        ));
        fs::remove_dir_all(missing_root)?;

        let symlink_root = unique_test_root("inspect-symlink-subdir")?;
        let target = symlink_root.join("target");
        fs::create_dir_all(&target)?;
        let symlink_layout = WorkspaceStateLayout::initialize(&symlink_root)?;
        fs::remove_dir(symlink_layout.recovery())?;
        symlink(&target, symlink_layout.recovery())?;
        assert!(matches!(
            WorkspaceStateLayout::inspect_existing(&symlink_root),
            Err(StateLayoutError::StatePathIsSymlink(path)) if path == symlink_layout.recovery()
        ));
        fs::remove_dir_all(symlink_root)?;
        Ok(())
    }

    #[test]
    fn root_fingerprint_is_stable_for_one_directory_and_differs_for_another()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_root = unique_test_root("fingerprint-first")?;
        let second_root = unique_test_root("fingerprint-second")?;
        fs::create_dir_all(&first_root)?;
        fs::create_dir_all(&second_root)?;

        let first_layout = WorkspaceStateLayout::initialize(&first_root)?;
        let first_again = WorkspaceStateLayout::initialize(&first_root)?;
        let second_layout = WorkspaceStateLayout::initialize(&second_root)?;
        let first_fingerprint = first_layout.root_fingerprint()?;
        assert_eq!(first_fingerprint, first_again.root_fingerprint()?);
        assert_ne!(first_fingerprint, second_layout.root_fingerprint()?);
        assert_eq!(first_fingerprint.into_bytes().len(), 16);

        fs::remove_dir_all(first_root)?;
        fs::remove_dir_all(second_root)?;
        Ok(())
    }

    #[test]
    fn root_fingerprint_rejects_a_symlink_substitution_after_layout_initialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = unique_test_root("fingerprint-symlink")?;
        let workspace = parent.join("workspace");
        let replacement = parent.join("replacement");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&replacement)?;
        let layout = WorkspaceStateLayout::initialize(&workspace)?;
        let canonical_workspace = layout.workspace_root().to_path_buf();

        fs::remove_dir_all(&workspace)?;
        symlink(&replacement, &workspace)?;
        assert!(matches!(
            layout.root_fingerprint(),
            Err(StateLayoutError::WorkspaceFingerprintRootIsSymlink(path))
                if path == canonical_workspace
        ));

        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn git_workspace_uses_info_exclude_without_mutating_gitignore()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("git")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        fs::write(root.join(".gitignore"), "target/\n")?;
        let original_gitignore = fs::read(root.join(".gitignore"))?;

        let layout = WorkspaceStateLayout::initialize(&root)?;
        assert_eq!(
            layout.git_local_state(),
            GitLocalState::LocalExcludeVerified
        );
        assert_eq!(fs::read(root.join(".gitignore"))?, original_gitignore);
        assert!(
            git_output(
                &root,
                &[
                    "check-ignore",
                    "--quiet",
                    "--no-index",
                    "--",
                    ".heterarchy-forge/probe"
                ]
            )?
            .status
            .success()
        );
        assert!(
            git_output(
                &root,
                &[
                    "check-ignore",
                    "--quiet",
                    "--no-index",
                    "--",
                    ".heterarchy-forge.init.probe/probe",
                ]
            )?
            .status
            .success()
        );
        let status = git_output(
            &root,
            &[
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                ".heterarchy-forge",
            ],
        )?;
        assert!(status.stdout.is_empty());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nested_git_workspace_uses_exact_workspace_relative_exclude_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("nested-git")?;
        let workspace = root.join("projects").join("selected");
        fs::create_dir_all(&workspace)?;
        git(&root, &["init", "--quiet"])?;

        let layout = WorkspaceStateLayout::initialize(&workspace)?;
        assert_eq!(
            layout.git_local_state(),
            GitLocalState::LocalExcludeVerified
        );
        let exclude = fs::read(root.join(".git/info/exclude"))?;
        assert!(super::contains_exact_line(
            &exclude,
            b"/projects/selected/.heterarchy-forge/"
        ));
        assert!(super::contains_exact_line(
            &exclude,
            b"/projects/selected/.heterarchy-forge.init.*/"
        ));
        assert!(!super::contains_exact_line(
            &exclude,
            b"/.heterarchy-forge/"
        ));
        assert!(!super::contains_exact_line(
            &exclude,
            b"/.heterarchy-forge.init.*/"
        ));

        let status = git_output(
            &root,
            &[
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                "projects/selected/.heterarchy-forge",
            ],
        )?;
        assert!(status.stdout.is_empty());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nested_git_workspace_preserves_non_utf8_relative_path_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("nested-non-utf8")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        let workspace = root.join(std::ffi::OsString::from_vec(b"selected-\xC3\xA9".to_vec()));
        fs::create_dir(&workspace)?;

        WorkspaceStateLayout::initialize(&workspace)?;
        let exclude = fs::read(root.join(".git/info/exclude"))?;
        assert!(
            exclude
                .windows(b"/selected-\xC3\xA9/.heterarchy-forge/".len())
                .any(|line| line == b"/selected-\xC3\xA9/.heterarchy-forge/")
        );
        assert!(
            exclude
                .windows(b"/selected-\xC3\xA9/.heterarchy-forge.init.*/".len())
                .any(|line| line == b"/selected-\xC3\xA9/.heterarchy-forge.init.*/")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nested_git_workspace_escapes_git_pattern_bytes_without_broadening_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("nested-pattern")?;
        let workspace = root.join("selected-*");
        let sibling = root.join("selected-other");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&sibling)?;
        git(&root, &["init", "--quiet"])?;

        WorkspaceStateLayout::initialize(&workspace)?;
        let exclude = fs::read(root.join(".git/info/exclude"))?;
        assert!(super::contains_exact_line(
            &exclude,
            b"/selected-\\*/.heterarchy-forge/"
        ));
        assert!(
            git_output(
                &root,
                &[
                    "check-ignore",
                    "--quiet",
                    "--no-index",
                    "--",
                    "selected-*/.heterarchy-forge/probe",
                ],
            )?
            .status
            .success()
        );
        assert!(
            !git_output(
                &root,
                &[
                    "check-ignore",
                    "--quiet",
                    "--no-index",
                    "--",
                    "selected-other/.heterarchy-forge/probe",
                ],
            )?
            .status
            .success()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn concurrent_initialization_converges_and_preserves_each_git_exclude_rule()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("concurrent-git")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        let first_workspace = root.join("first");
        let second_workspace = root.join("second");
        fs::create_dir_all(&first_workspace)?;
        fs::create_dir_all(&second_workspace)?;

        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let first_handle = thread::spawn(move || {
            first_barrier.wait();
            WorkspaceStateLayout::initialize(first_workspace)
        });
        let second_barrier = Arc::clone(&barrier);
        let second_handle = thread::spawn(move || {
            second_barrier.wait();
            WorkspaceStateLayout::initialize(second_workspace)
        });

        let first = first_handle
            .join()
            .map_err(|_| "first initializer thread panicked")??;
        let second = second_handle
            .join()
            .map_err(|_| "second initializer thread panicked")??;
        assert!(first.state_root().is_dir());
        assert!(second.state_root().is_dir());

        let exclude = fs::read(root.join(".git/info/exclude"))?;
        assert!(super::contains_exact_line(
            &exclude,
            b"/first/.heterarchy-forge/"
        ));
        assert!(super::contains_exact_line(
            &exclude,
            b"/first/.heterarchy-forge.init.*/"
        ));
        assert!(super::contains_exact_line(
            &exclude,
            b"/second/.heterarchy-forge/"
        ));
        assert!(super::contains_exact_line(
            &exclude,
            b"/second/.heterarchy-forge.init.*/"
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn concurrent_same_workspace_initialization_converges_on_one_owned_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("concurrent-same")?;
        fs::create_dir_all(&root)?;
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            let workspace = root.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                WorkspaceStateLayout::initialize(workspace)
            }));
        }

        let mut layouts = Vec::new();
        for handle in handles {
            layouts.push(
                handle
                    .join()
                    .map_err(|_| "same-workspace initializer thread panicked")??,
            );
        }
        let state_root = layouts[0].state_root().to_path_buf();
        for layout in &layouts {
            assert_eq!(layout.state_root(), state_root);
            assert!(layout.state_root().join(STATE_FORMAT_FILE_NAME).is_file());
            assert!(layout.diffs().is_dir());
            assert!(layout.checkpoints().is_dir());
            assert!(layout.artifacts().is_dir());
            assert!(layout.recovery().is_dir());
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn initialization_retries_colliding_temporary_names() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("retry")?;
        fs::create_dir_all(&root)?;
        let process_id = std::process::id();
        let state_collision = root.join(format!(".heterarchy-forge.init.{process_id}.0"));
        fs::create_dir(&state_collision)?;

        git(&root, &["init", "--quiet"])?;
        let exclude_directory = root.join(".git/info");
        let exclude_collision =
            exclude_directory.join(format!(".heterarchy-forge-exclude.{process_id}.0.tmp"));
        fs::write(&exclude_collision, "collision")?;

        let layout = WorkspaceStateLayout::initialize(&root)?;
        assert!(layout.state_root().is_dir());
        assert!(state_collision.is_dir());
        assert_eq!(fs::read_to_string(&exclude_collision)?, "collision");
        assert!(
            !root
                .join(format!(".heterarchy-forge.init.{process_id}.1"))
                .exists()
        );
        assert!(
            !exclude_directory
                .join(format!(".heterarchy-forge-exclude.{process_id}.1.tmp"))
                .exists()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn preexisting_unowned_or_tracked_state_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let unowned_root = unique_test_root("unowned")?;
        fs::create_dir_all(unowned_root.join(".heterarchy-forge"))?;
        assert!(matches!(
            WorkspaceStateLayout::initialize(&unowned_root),
            Err(StateLayoutError::StateDirectoryOwnershipUnknown { .. })
        ));
        fs::remove_dir_all(unowned_root)?;

        let tracked_root = unique_test_root("tracked")?;
        fs::create_dir_all(tracked_root.join(".heterarchy-forge"))?;
        fs::write(
            tracked_root.join(".heterarchy-forge/user.txt"),
            "owned by user",
        )?;
        git(&tracked_root, &["init", "--quiet"])?;
        git(&tracked_root, &["add", "-f", ".heterarchy-forge/user.txt"])?;
        assert!(matches!(
            WorkspaceStateLayout::initialize(&tracked_root),
            Err(StateLayoutError::TrackedStateConflict(_))
        ));
        fs::remove_dir_all(tracked_root)?;
        Ok(())
    }

    #[test]
    fn oversized_git_exclude_fails_closed_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("oversized-exclude")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        let exclude = root.join(".git/info/exclude");
        let original = vec![b'x'; 1_048_577];
        fs::write(&exclude, &original)?;

        assert!(matches!(
            WorkspaceStateLayout::initialize(&root),
            Err(StateLayoutError::GitExcludeTooLarge { .. })
        ));
        assert_eq!(fs::read(&exclude)?, original);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn oversized_format_marker_fails_closed_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("oversized-format")?;
        let state_root = root.join(".heterarchy-forge");
        fs::create_dir_all(&state_root)?;
        let original = vec![b'x'; STATE_FORMAT.len() + 1];
        let format_path = state_root.join(STATE_FORMAT_FILE_NAME);
        fs::write(&format_path, &original)?;

        assert!(matches!(
            WorkspaceStateLayout::initialize(&root),
            Err(StateLayoutError::StateFormatTooLarge { .. })
        ));
        assert_eq!(fs::read(&format_path)?, original);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn foreign_format_marker_symlink_is_rejected_before_following_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("foreign-format-marker")?;
        let state_root = root.join(".heterarchy-forge");
        let external_marker = root.join("foreign-FORMAT");
        fs::create_dir_all(&state_root)?;
        fs::write(&external_marker, STATE_FORMAT)?;
        symlink(&external_marker, state_root.join(STATE_FORMAT_FILE_NAME))?;
        let canonical_format_path = fs::canonicalize(&state_root)?.join(STATE_FORMAT_FILE_NAME);

        let result = WorkspaceStateLayout::initialize(&root);
        assert!(matches!(
            result,
            Err(StateLayoutError::StatePathIsSymlink(path))
                if path == canonical_format_path
        ));
        assert_eq!(fs::read(&external_marker)?, STATE_FORMAT);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn non_regular_format_marker_is_rejected_without_opening_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("non-regular-format-marker")?;
        let state_root = root.join(".heterarchy-forge");
        let format_path = state_root.join(STATE_FORMAT_FILE_NAME);
        fs::create_dir_all(&format_path)?;
        let canonical_format_path = fs::canonicalize(&format_path)?;

        assert!(matches!(
            WorkspaceStateLayout::initialize(&root),
            Err(StateLayoutError::StateFormatIsNotRegularFile(path))
                if path == canonical_format_path
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn hardlinked_format_marker_is_rejected_before_opening_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("hardlinked-format-marker")?;
        let state_root = root.join(".heterarchy-forge");
        let format_path = state_root.join(STATE_FORMAT_FILE_NAME);
        let hardlink_path = root.join("foreign-FORMAT");
        fs::create_dir_all(&state_root)?;
        fs::write(&format_path, STATE_FORMAT)?;
        fs::hard_link(&format_path, &hardlink_path)?;
        let canonical_format_path = fs::canonicalize(&format_path)?;

        assert!(matches!(
            WorkspaceStateLayout::initialize(&root),
            Err(StateLayoutError::StateFormatLinkCountInvalid { path, links })
                if path == canonical_format_path && links == 2
        ));
        assert_eq!(fs::read(&format_path)?, STATE_FORMAT);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn opened_format_identity_mismatch_is_rejected_deterministically()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("format-identity-mismatch")?;
        let state_root = root.join(".heterarchy-forge");
        let format_path = state_root.join(STATE_FORMAT_FILE_NAME);
        let replacement_path = root.join("replacement-FORMAT");
        fs::create_dir_all(&state_root)?;
        fs::write(&format_path, STATE_FORMAT)?;
        fs::write(&replacement_path, STATE_FORMAT)?;
        let expected = fs::symlink_metadata(&format_path)?;
        let opened = fs::metadata(&replacement_path)?;
        let canonical_format_path = fs::canonicalize(&format_path)?;

        assert!(matches!(
            super::validate_format_file_identity(&canonical_format_path, &expected, &opened),
            Err(StateLayoutError::StateFormatIdentityChanged { path })
                if path == canonical_format_path
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn bounded_reader_caps_allocation_and_reports_oversize() {
        let bytes = vec![b'x'; 9];
        let result = super::read_bounded(std::io::Cursor::new(bytes), 8);
        assert!(matches!(
            result,
            Err(super::BoundedReadError::TooLarge {
                actual: 9,
                maximum: 8
            })
        ));
    }

    #[test]
    fn bounded_reader_stops_after_first_read_over_maximum() {
        use std::io::Read;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct EndlessReader {
            reads: Arc<AtomicUsize>,
        }

        impl Read for EndlessReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                buffer.fill(b'x');
                Ok(buffer.len())
            }
        }

        let reads = Arc::new(AtomicUsize::new(0));
        let result = super::read_bounded(
            EndlessReader {
                reads: Arc::clone(&reads),
            },
            8,
        );
        assert!(matches!(
            result,
            Err(super::BoundedReadError::TooLarge {
                actual,
                maximum: 8
            }) if actual > 8
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn git_capture_caps_large_stdout_and_reaps_producer() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("large-git-output")?;
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        for index in 0..5_000 {
            fs::write(root.join(format!("tracked-{index:04}.txt")), "x")?;
        }
        git(&root, &["add", "."])?;

        let output = super::run_git(&root, &["ls-files", "-z"])?;
        assert!(output.stdout_total > super::MAX_GIT_OUTPUT_BYTES);
        assert_eq!(output.stdout.len(), super::MAX_GIT_OUTPUT_BYTES + 1);
        assert!(output.stderr.len() <= super::MAX_GIT_OUTPUT_BYTES + 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn git(root: &Path, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let output = git_output(root, arguments)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "git {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into())
        }
    }

    fn git_output(
        root: &Path,
        arguments: &[&str],
    ) -> Result<std::process::Output, Box<dyn std::error::Error>> {
        Ok(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?)
    }

    type FileSnapshot = (Vec<u8>, SystemTime);

    fn file_snapshot(path: &Path) -> Result<FileSnapshot, Box<dyn std::error::Error>> {
        let metadata = fs::symlink_metadata(path)?;
        Ok((fs::read(path)?, metadata.modified()?))
    }

    fn optional_file_snapshot(
        path: &Path,
    ) -> Result<Option<FileSnapshot>, Box<dyn std::error::Error>> {
        match fs::symlink_metadata(path) {
            Ok(_) => file_snapshot(path).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn unique_test_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("heterarchy-forge-{label}-{unique}")))
    }
}
