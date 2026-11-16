//! Shared bare Git object store (`dag-store.git`), tree BLAKE3 manifest,
//! 3-way merge, and atomic directory application primitives for DAG and Swarm
//! isolated workspaces.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use forge_domain::{TimestampMillis, WorkspaceId};
use thiserror::Error;

use crate::{ExistingWorkspaceStateLayout, FORGE_GIT_PROGRAM, StateLayoutError};

pub(crate) const NODE_WORKSPACES_SUBDIR: &str = "node-workspaces";
pub(crate) const DAG_GIT_STORE_DIR: &str = "dag-store.git";
pub(crate) const COMMITS_SUBDIR: &str = "commits";
pub(crate) const WORKTREE_DIR_NAME: &str = "worktree";
pub(crate) const SETTLEMENT_JOURNAL_NAME: &str = "settlement.journal";
pub(crate) const MANIFEST_VERSION: u32 = 2;

static NEXT_STAGING_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub(crate) enum GitTreeStoreError {
    #[error("workspace I/O failed during {context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Git operation failed during {context}: {detail}")]
    GitCommandFailed {
        context: &'static str,
        detail: String,
    },
    #[error("workspace manifest at {} is corrupt: {reason}", path.display())]
    CorruptManifest { path: PathBuf, reason: &'static str },
    #[error("workspace relative path {path:?} is invalid")]
    InvalidRelativePath { path: String },
    #[error(
        "unsupported filesystem entry {path:?} in workspace tree (symlinks and special files are forbidden)"
    )]
    UnsupportedWorkspaceEntry { path: String },
    #[error(transparent)]
    StateLayout(#[from] StateLayoutError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileEntryMeta {
    pub(crate) blake3_hex: String,
    pub(crate) mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeManifest {
    pub(crate) entries: BTreeMap<String, FileEntryMeta>,
    pub(crate) tree_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedBaseline {
    pub(crate) base_commit_oid: String,
    pub(crate) manifest: TreeManifest,
}

/// Durable journal phase for Swarm and DAG workspace settlement.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettlementJournalState {
    Prepared,
    Applied,
    RecoveryRequired,
}

impl SettlementJournalState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "prepared" => Some(Self::Prepared),
            "applied" => Some(Self::Applied),
            "recovery_required" => Some(Self::RecoveryRequired),
            _ => None,
        }
    }
}

pub(crate) fn next_staging_nonce() -> u64 {
    NEXT_STAGING_NONCE.fetch_add(1, Ordering::Relaxed)
}

struct TempFileGuard<'a>(&'a Path);

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

struct TempDirCleanGuard<'a>(&'a Path);

impl Drop for TempDirCleanGuard<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.0);
    }
}

pub(crate) fn dag_git_store_dir(layout: &ExistingWorkspaceStateLayout) -> PathBuf {
    layout
        .artifacts()
        .join(NODE_WORKSPACES_SUBDIR)
        .join(DAG_GIT_STORE_DIR)
}

pub(crate) fn commit_manifest_store_path(
    layout: &ExistingWorkspaceStateLayout,
    commit_oid: &str,
) -> PathBuf {
    layout
        .artifacts()
        .join(NODE_WORKSPACES_SUBDIR)
        .join(COMMITS_SUBDIR)
        .join(format!("{commit_oid}.manifest"))
}

pub(crate) fn resolve_workspace_scope_segment(
    layout: &ExistingWorkspaceStateLayout,
    workspace_id: Option<WorkspaceId>,
) -> Result<String, GitTreeStoreError> {
    let fingerprint = layout.root_fingerprint()?;
    let ws_name = layout
        .workspace_root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace");
    Ok(match workspace_id {
        Some(id) => id.to_string(),
        None => format!("{ws_name}-{}", encode_hex(fingerprint.as_bytes())),
    })
}

pub(crate) fn resolve_external_workspace_scope_dir(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    default_subdir: &str,
) -> Result<PathBuf, GitTreeStoreError> {
    let scope_segment = resolve_workspace_scope_segment(layout, workspace_id)?;
    let base_root = match external_worktrees_root {
        Some(root) => root.to_path_buf(),
        None => std::env::temp_dir().join(default_subdir),
    };
    Ok(base_root.join(scope_segment))
}

pub(crate) fn ensure_dag_git_store(
    layout: &ExistingWorkspaceStateLayout,
) -> Result<PathBuf, GitTreeStoreError> {
    let git_dir = dag_git_store_dir(layout);
    let commits_dir = layout
        .artifacts()
        .join(NODE_WORKSPACES_SUBDIR)
        .join(COMMITS_SUBDIR);
    fs::create_dir_all(&commits_dir).map_err(|source| GitTreeStoreError::Io {
        context: "creating dag commit manifests directory",
        source,
    })?;
    if git_dir.join("HEAD").exists() {
        return Ok(git_dir);
    }
    fs::create_dir_all(&git_dir).map_err(|source| GitTreeStoreError::Io {
        context: "creating bare dag git store directory",
        source,
    })?;
    let output = Command::new(FORGE_GIT_PROGRAM)
        .arg("init")
        .arg("--bare")
        .arg("--quiet")
        .arg(&git_dir)
        .env_clear()
        .output()
        .map_err(|source| GitTreeStoreError::Io {
            context: "spawning git init --bare for dag-store.git",
            source,
        })?;
    if !output.status.success() {
        return Err(GitTreeStoreError::GitCommandFailed {
            context: "git init --bare",
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(git_dir)
}

pub(crate) fn commit_manifest_from_dir(
    layout: &ExistingWorkspaceStateLayout,
    source_dir: &Path,
    manifest: &TreeManifest,
    parents: &[String],
    ref_name: Option<&str>,
    message: &str,
    observed_at: TimestampMillis,
) -> Result<String, GitTreeStoreError> {
    let git_dir = dag_git_store_dir(layout);
    let nonce = next_staging_nonce();
    let temp_index = git_dir.join(format!("forge-tmp-index-{}-{nonce}", std::process::id()));
    let temp_index_guard = TempFileGuard(&temp_index);
    let _ = fs::remove_file(&temp_index);

    let tree_oid = if manifest.entries.is_empty() {
        run_git_command(
            &git_dir,
            Some(&temp_index),
            &["write-tree"],
            None,
            observed_at,
        )?
    } else {
        let mut stdin_paths = String::new();
        let mut ordered_rel_paths = Vec::with_capacity(manifest.entries.len());
        for (rel_path, meta) in &manifest.entries {
            let abs_path = source_dir.join(rel_path);
            let path_str =
                abs_path
                    .to_str()
                    .ok_or_else(|| GitTreeStoreError::InvalidRelativePath {
                        path: rel_path.clone(),
                    })?;
            let _ = writeln!(stdin_paths, "{path_str}");
            ordered_rel_paths.push((rel_path.as_str(), meta.mode));
        }
        let blob_oids_raw = run_git_command(
            &git_dir,
            None,
            &["hash-object", "-w", "--stdin-paths"],
            Some(stdin_paths.as_bytes()),
            observed_at,
        )?;
        let blob_oids: Vec<&str> = blob_oids_raw
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if blob_oids.len() != ordered_rel_paths.len() {
            return Err(GitTreeStoreError::GitCommandFailed {
                context: "git hash-object -w --stdin-paths",
                detail: format!(
                    "expected {} blob OIDs, got {}",
                    ordered_rel_paths.len(),
                    blob_oids.len()
                ),
            });
        }
        let mut index_info = String::new();
        for ((rel_path, mode), blob_oid) in ordered_rel_paths.iter().zip(blob_oids.iter()) {
            let git_mode = if *mode & 0o111 != 0 {
                "100755"
            } else {
                "100644"
            };
            let _ = writeln!(index_info, "{git_mode} blob {blob_oid}\t{rel_path}");
        }
        let _ = run_git_command(
            &git_dir,
            Some(&temp_index),
            &["update-index", "--index-info"],
            Some(index_info.as_bytes()),
            observed_at,
        )?;
        run_git_command(
            &git_dir,
            Some(&temp_index),
            &["write-tree"],
            None,
            observed_at,
        )?
    };
    drop(temp_index_guard);

    let commit_oid = create_git_commit(&git_dir, &tree_oid, parents, message, observed_at)?;
    if let Some(ref_name) = ref_name {
        update_git_ref(&git_dir, ref_name, &commit_oid, observed_at)?;
    }
    let commit_manifest_path = commit_manifest_store_path(layout, &commit_oid);
    write_atomic_file(&commit_manifest_path, &encode_tree_manifest_file(manifest))?;
    Ok(commit_oid)
}

pub(crate) fn update_git_ref(
    git_dir: &Path,
    ref_name: &str,
    commit_oid: &str,
    observed_at: TimestampMillis,
) -> Result<(), GitTreeStoreError> {
    let _ = run_git_command(
        git_dir,
        None,
        &["update-ref", ref_name, commit_oid],
        None,
        observed_at,
    )?;
    Ok(())
}

pub(crate) fn delete_git_ref(
    git_dir: &Path,
    ref_name: &str,
    observed_at: TimestampMillis,
) -> Result<(), GitTreeStoreError> {
    let _ = run_git_command(
        git_dir,
        None,
        &["update-ref", "-d", ref_name],
        None,
        observed_at,
    )?;
    Ok(())
}

pub(crate) fn create_git_commit<S: AsRef<str>>(
    git_dir: &Path,
    tree_oid: &str,
    parents: &[S],
    message: &str,
    observed_at: TimestampMillis,
) -> Result<String, GitTreeStoreError> {
    let mut args = Vec::with_capacity(4 + parents.len() * 2);
    args.push("commit-tree");
    args.push(tree_oid);
    for parent in parents {
        args.push("-p");
        args.push(parent.as_ref());
    }
    args.push("-m");
    args.push(message);
    run_git_command(git_dir, None, &args, None, observed_at)
}

pub(crate) fn checkout_commit_to_dir(
    layout: &ExistingWorkspaceStateLayout,
    commit_oid: &str,
    target_dir: &Path,
) -> Result<(), GitTreeStoreError> {
    let git_dir = dag_git_store_dir(layout);
    let nonce = next_staging_nonce();
    let temp_index = git_dir.join(format!(
        "forge-checkout-index-{}-{nonce}",
        std::process::id()
    ));
    let _temp_index_guard = TempFileGuard(&temp_index);
    let _ = fs::remove_file(&temp_index);
    let dummy_ts = TimestampMillis::new(1).map_err(|_| GitTreeStoreError::CorruptManifest {
        path: target_dir.to_path_buf(),
        reason: "invalid checkout timestamp",
    })?;
    let _ = run_git_command(
        &git_dir,
        Some(&temp_index),
        &["read-tree", commit_oid],
        None,
        dummy_ts,
    )?;
    let work_tree_arg = format!("--work-tree={}", target_dir.display());
    let _ = run_git_command(
        &git_dir,
        Some(&temp_index),
        &[&work_tree_arg, "checkout-index", "-a", "-f"],
        None,
        dummy_ts,
    )?;
    Ok(())
}

pub(crate) fn run_git_merge_base_all(
    git_dir: &Path,
    left_commit: &str,
    right_commit: &str,
    observed_at: TimestampMillis,
) -> Result<Vec<String>, GitTreeStoreError> {
    let merge_bases_raw = run_git_command(
        git_dir,
        None,
        &["merge-base", "--all", left_commit, right_commit],
        None,
        observed_at,
    )?;
    Ok(merge_bases_raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub(crate) fn three_way_merge_manifests(
    git_dir: &Path,
    merged_tree_oid: &str,
    base: &TreeManifest,
    left: &TreeManifest,
    right: &TreeManifest,
) -> Result<(TreeManifest, Vec<String>), GitTreeStoreError> {
    let mut all_paths = BTreeSet::new();
    all_paths.extend(base.entries.keys().map(String::as_str));
    all_paths.extend(left.entries.keys().map(String::as_str));
    all_paths.extend(right.entries.keys().map(String::as_str));

    let mut merged_entries = BTreeMap::new();
    let mut conflicts = Vec::new();

    for path in all_paths {
        let base_entry = base.entries.get(path);
        let left_entry = left.entries.get(path);
        let right_entry = right.entries.get(path);

        if left_entry == right_entry {
            if let Some(entry) = left_entry {
                merged_entries.insert(path.to_owned(), entry.clone());
            }
        } else if left_entry == base_entry {
            if let Some(entry) = right_entry {
                merged_entries.insert(path.to_owned(), entry.clone());
            }
        } else if right_entry == base_entry {
            if let Some(entry) = left_entry {
                merged_entries.insert(path.to_owned(), entry.clone());
            }
        } else if let (Some(l), Some(r)) = (left_entry, right_entry) {
            let blob_bytes = read_git_blob_bytes(git_dir, merged_tree_oid, path)?;
            let blake3_hex = blake3::hash(&blob_bytes).to_hex().to_string();
            let mode = if (l.mode | r.mode) & 0o111 != 0 {
                0o755
            } else {
                0o644
            };
            merged_entries.insert(path.to_owned(), FileEntryMeta { blake3_hex, mode });
        } else {
            conflicts.push(path.to_owned());
        }
    }

    let tree_blake3 = compute_tree_blake3(&merged_entries);
    Ok((
        TreeManifest {
            entries: merged_entries,
            tree_blake3,
        },
        conflicts,
    ))
}

pub(crate) fn read_git_blob_bytes(
    git_dir: &Path,
    tree_oid: &str,
    rel_path: &str,
) -> Result<Vec<u8>, GitTreeStoreError> {
    let git_dir_arg = format!("--git-dir={}", git_dir.display());
    let spec = format!("{tree_oid}:{rel_path}");
    let output = Command::new(FORGE_GIT_PROGRAM)
        .arg(&git_dir_arg)
        .arg("cat-file")
        .arg("blob")
        .arg(&spec)
        .env_clear()
        .output()
        .map_err(|source| GitTreeStoreError::Io {
            context: "spawning git cat-file blob for merged file",
            source,
        })?;
    if !output.status.success() {
        return Err(GitTreeStoreError::GitCommandFailed {
            context: "git cat-file blob",
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

pub(crate) fn run_git_merge_tree(
    git_dir: &Path,
    left_commit: &str,
    right_commit: &str,
) -> Result<Result<String, Vec<String>>, GitTreeStoreError> {
    let git_dir_arg = format!("--git-dir={}", git_dir.display());
    let output = Command::new(FORGE_GIT_PROGRAM)
        .arg(&git_dir_arg)
        .arg("merge-tree")
        .arg("--write-tree")
        .arg(left_commit)
        .arg(right_commit)
        .env_clear()
        .output()
        .map_err(|source| GitTreeStoreError::Io {
            context: "spawning git merge-tree --write-tree",
            source,
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        let tree_oid = stdout
            .lines()
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| GitTreeStoreError::GitCommandFailed {
                context: "git merge-tree --write-tree output",
                detail: "missing merged tree OID".to_owned(),
            })?;
        return Ok(Ok(tree_oid.to_owned()));
    }
    let mut conflicts = Vec::new();
    for line in stdout.lines().skip(1) {
        let trimmed = line.trim();
        if let Some(conflict_idx) = trimmed.find("CONFLICT") {
            conflicts.push(trimmed[conflict_idx..].to_owned());
        } else if let Some((_meta, path)) = trimmed.split_once('\t')
            && !conflicts.iter().any(|existing| existing == path)
        {
            conflicts.push(path.to_owned());
        }
    }
    if conflicts.is_empty() {
        conflicts.push("<merge-tree-conflict>".to_owned());
    }
    Ok(Err(conflicts))
}

pub(crate) fn run_git_command(
    git_dir: &Path,
    index_file: Option<&Path>,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    observed_at: TimestampMillis,
) -> Result<String, GitTreeStoreError> {
    let git_dir_arg = format!("--git-dir={}", git_dir.display());
    run_git_command_with_args(
        None,
        Some(&git_dir_arg),
        index_file,
        args,
        stdin_bytes,
        observed_at,
    )
}

pub(crate) fn run_git_in_workdir(
    work_dir: &Path,
    args: &[&str],
    observed_at: TimestampMillis,
) -> Result<String, GitTreeStoreError> {
    run_git_command_with_args(Some(work_dir), None, None, args, None, observed_at)
}

fn run_git_command_with_args(
    current_dir: Option<&Path>,
    git_dir_arg: Option<&str>,
    index_file: Option<&Path>,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    observed_at: TimestampMillis,
) -> Result<String, GitTreeStoreError> {
    let secs = observed_at.get().div_euclid(1_000).max(0);
    let git_date = format!("@{secs} +0000");

    let mut command = Command::new(FORGE_GIT_PROGRAM);
    if let Some(dir) = current_dir {
        command.current_dir(dir);
    }
    if let Some(git_dir_flag) = git_dir_arg {
        command.arg(git_dir_flag);
    }
    command
        .args(args)
        .env_clear()
        .env("GIT_AUTHOR_NAME", "Forge")
        .env("GIT_AUTHOR_EMAIL", "forge@heterarchy.local")
        .env("GIT_COMMITTER_NAME", "Forge")
        .env("GIT_COMMITTER_EMAIL", "forge@heterarchy.local")
        .env("GIT_AUTHOR_DATE", &git_date)
        .env("GIT_COMMITTER_DATE", &git_date)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
    if let Some(index_path) = index_file {
        command.env("GIT_INDEX_FILE", index_path);
    }
    if stdin_bytes.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|source| GitTreeStoreError::Io {
        context: "spawning git command",
        source,
    })?;
    if let Some(input) = stdin_bytes
        && let Some(mut child_stdin) = child.stdin.take()
    {
        child_stdin
            .write_all(input)
            .map_err(|source| GitTreeStoreError::Io {
                context: "writing stdin to git command",
                source,
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|source| GitTreeStoreError::Io {
            context: "waiting for git command",
            source,
        })?;
    if !output.status.success() {
        return Err(GitTreeStoreError::GitCommandFailed {
            context: "git plumbing command",
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub(crate) fn apply_candidate_to_dir(
    layout: &ExistingWorkspaceStateLayout,
    settlement_dir: &Path,
    target_dir: &Path,
    candidate_commit_oid: &str,
    candidate_manifest: &TreeManifest,
    upserted_paths: &[String],
    deleted_paths: &[String],
) -> Result<(), GitTreeStoreError> {
    let nonce = next_staging_nonce();
    let candidate_dir =
        settlement_dir.join(format!("candidate-tree-{}-{nonce}", std::process::id()));
    if candidate_dir.exists() {
        let _ = fs::remove_dir_all(&candidate_dir);
    }
    fs::create_dir_all(&candidate_dir).map_err(|source| GitTreeStoreError::Io {
        context: "creating settlement candidate staging directory",
        source,
    })?;
    let _candidate_guard = TempDirCleanGuard(&candidate_dir);

    if !candidate_manifest.entries.is_empty() {
        checkout_commit_to_dir(layout, candidate_commit_oid, &candidate_dir)?;
    }

    for deleted_rel in deleted_paths {
        validate_relative_path(deleted_rel)?;
        let target_path = target_dir.join(deleted_rel);
        if target_path.exists() {
            fs::remove_file(&target_path).map_err(|source| GitTreeStoreError::Io {
                context: "removing deleted path during settlement",
                source,
            })?;
        }
        prune_empty_parent_dirs(target_dir, &target_path);
    }

    for upserted_rel in upserted_paths {
        validate_relative_path(upserted_rel)?;
        let src_path = candidate_dir.join(upserted_rel);
        let dst_path = target_dir.join(upserted_rel);
        let entry_meta = candidate_manifest
            .entries
            .get(upserted_rel)
            .ok_or_else(|| GitTreeStoreError::CorruptManifest {
                path: candidate_dir.clone(),
                reason: "upserted path missing from candidate manifest",
            })?;
        copy_file_atomically(&src_path, &dst_path, entry_meta.mode)?;
    }

    Ok(())
}

fn copy_file_atomically(src: &Path, dst: &Path, mode: u32) -> Result<(), GitTreeStoreError> {
    let parent = dst
        .parent()
        .ok_or_else(|| GitTreeStoreError::CorruptManifest {
            path: dst.to_path_buf(),
            reason: "destination path has no parent",
        })?;
    fs::create_dir_all(parent).map_err(|source| GitTreeStoreError::Io {
        context: "creating parent directory for settled file",
        source,
    })?;
    let nonce = next_staging_nonce();
    let tmp_path = parent.join(format!(".forge-settle-{}-{nonce}.tmp", std::process::id()));
    let mut reader = File::open(src).map_err(|source| GitTreeStoreError::Io {
        context: "opening staged candidate file",
        source,
    })?;
    let mut writer = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp_path)
        .map_err(|source| GitTreeStoreError::Io {
            context: "creating temporary settled file",
            source,
        })?;
    io::copy(&mut reader, &mut writer).map_err(|source| GitTreeStoreError::Io {
        context: "writing temporary settled file",
        source,
    })?;
    writer
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| GitTreeStoreError::Io {
            context: "setting permissions on temporary settled file",
            source,
        })?;
    writer.sync_all().map_err(|source| GitTreeStoreError::Io {
        context: "syncing temporary settled file",
        source,
    })?;
    drop(writer);
    fs::rename(&tmp_path, dst).map_err(|source| GitTreeStoreError::Io {
        context: "renaming settled file into target directory",
        source,
    })
}

fn prune_empty_parent_dirs(root: &Path, removed_file: &Path) {
    let mut current = removed_file.parent();
    while let Some(dir) = current {
        if dir == root || !dir.starts_with(root) {
            break;
        }
        match fs::read_dir(dir) {
            Ok(mut entries) => {
                if entries.next().is_none() {
                    let _ = fs::remove_dir(dir);
                    current = dir.parent();
                } else {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

pub(crate) fn compute_manifest_delta(
    baseline: &TreeManifest,
    candidate: &TreeManifest,
) -> (Vec<String>, Vec<String>) {
    let mut upserted = Vec::new();
    let mut deleted = Vec::new();

    for (path, candidate_meta) in &candidate.entries {
        if baseline.entries.get(path) != Some(candidate_meta) {
            upserted.push(path.clone());
        }
    }
    for path in baseline.entries.keys() {
        if !candidate.entries.contains_key(path) {
            deleted.push(path.clone());
        }
    }
    (upserted, deleted)
}

pub(crate) fn diff_manifest_paths(expected: &TreeManifest, actual: &TreeManifest) -> Vec<String> {
    let mut all_paths = BTreeSet::new();
    all_paths.extend(expected.entries.keys().map(String::as_str));
    all_paths.extend(actual.entries.keys().map(String::as_str));
    all_paths
        .into_iter()
        .filter(|&path| expected.entries.get(path) != actual.entries.get(path))
        .map(ToOwned::to_owned)
        .collect()
}

pub(crate) fn find_drifted_paths(
    preimage: &TreeManifest,
    postimage: &TreeManifest,
    current: &TreeManifest,
) -> Vec<String> {
    let mut all_paths = BTreeSet::new();
    all_paths.extend(preimage.entries.keys().map(String::as_str));
    all_paths.extend(postimage.entries.keys().map(String::as_str));
    all_paths.extend(current.entries.keys().map(String::as_str));
    all_paths
        .into_iter()
        .filter(|&path| {
            let cur = current.entries.get(path);
            let pre = preimage.entries.get(path);
            let post = postimage.entries.get(path);
            cur != pre && cur != post
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn should_skip_root_entry(name: &str) -> bool {
    name == ".git"
        || name == ".heterarchy-forge"
        || name == ".heterarchy-forge.initialize.lock"
        || name.starts_with(".heterarchy-forge.init.")
        || name == "target"
}

pub(crate) fn scan_tree_entries(root: &Path) -> Result<TreeManifest, GitTreeStoreError> {
    let mut entries = BTreeMap::new();
    scan_directory_recursive(root, root, true, &mut entries)?;
    let tree_blake3 = compute_tree_blake3(&entries);
    Ok(TreeManifest {
        entries,
        tree_blake3,
    })
}

fn scan_directory_recursive(
    root: &Path,
    current: &Path,
    is_root: bool,
    entries: &mut BTreeMap<String, FileEntryMeta>,
) -> Result<(), GitTreeStoreError> {
    let read_dir = fs::read_dir(current).map_err(|source| GitTreeStoreError::Io {
        context: "reading directory for workspace manifest",
        source,
    })?;
    let mut children = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|source| GitTreeStoreError::Io {
            context: "iterating directory entry for workspace manifest",
            source,
        })?;
        children.push(entry);
    }
    children.sort_by_key(fs::DirEntry::file_name);

    for entry in children {
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            return Err(GitTreeStoreError::InvalidRelativePath {
                path: file_name.to_string_lossy().into_owned(),
            });
        };
        if is_root && should_skip_root_entry(name_str) {
            continue;
        }
        let path = entry.path();
        let relative =
            path.strip_prefix(root)
                .map_err(|_| GitTreeStoreError::InvalidRelativePath {
                    path: path.to_string_lossy().into_owned(),
                })?;
        let rel_str = relative_path_to_slash_string(relative)?;
        if !is_root && name_str == ".git" {
            return Err(GitTreeStoreError::UnsupportedWorkspaceEntry { path: rel_str });
        }

        let metadata = fs::symlink_metadata(&path).map_err(|source| GitTreeStoreError::Io {
            context: "statting directory entry for workspace manifest",
            source,
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(GitTreeStoreError::UnsupportedWorkspaceEntry { path: rel_str });
        }
        if file_type.is_dir() {
            scan_directory_recursive(root, &path, false, entries)?;
        } else if file_type.is_file() {
            let blake3_hex = hash_file_blake3(&path)?;
            let raw_mode = metadata.permissions().mode() & 0o777;
            let normalized_mode = if raw_mode & 0o111 != 0 { 0o755 } else { 0o644 };
            entries.insert(
                rel_str,
                FileEntryMeta {
                    blake3_hex,
                    mode: normalized_mode,
                },
            );
        } else {
            return Err(GitTreeStoreError::UnsupportedWorkspaceEntry { path: rel_str });
        }
    }
    Ok(())
}

fn relative_path_to_slash_string(path: &Path) -> Result<String, GitTreeStoreError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(text) = part.to_str() else {
                    return Err(GitTreeStoreError::InvalidRelativePath {
                        path: path.to_string_lossy().into_owned(),
                    });
                };
                if text.is_empty()
                    || text.contains('\n')
                    || text.contains('\r')
                    || text.contains('\t')
                {
                    return Err(GitTreeStoreError::InvalidRelativePath {
                        path: path.to_string_lossy().into_owned(),
                    });
                }
                parts.push(text);
            }
            _ => {
                return Err(GitTreeStoreError::InvalidRelativePath {
                    path: path.to_string_lossy().into_owned(),
                });
            }
        }
    }
    if parts.is_empty() {
        return Err(GitTreeStoreError::InvalidRelativePath {
            path: path.to_string_lossy().into_owned(),
        });
    }
    Ok(parts.join("/"))
}

pub(crate) fn validate_relative_path(rel_path: &str) -> Result<(), GitTreeStoreError> {
    let path = Path::new(rel_path);
    let normalized = relative_path_to_slash_string(path)?;
    if normalized != rel_path || should_skip_root_entry(rel_path.split('/').next().unwrap_or("")) {
        return Err(GitTreeStoreError::InvalidRelativePath {
            path: rel_path.to_owned(),
        });
    }
    Ok(())
}

fn hash_file_blake3(path: &Path) -> Result<String, GitTreeStoreError> {
    let mut file = File::open(path).map_err(|source| GitTreeStoreError::Io {
        context: "opening file for blake3 digest",
        source,
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| GitTreeStoreError::Io {
                context: "reading file for blake3 digest",
                source,
            })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(crate) fn compute_tree_blake3(entries: &BTreeMap<String, FileEntryMeta>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"heterarchy-forge:node-workspace-tree:v2\n");
    for (path, meta) in entries {
        let exec_flag = if meta.mode & 0o111 != 0 { "x" } else { "r" };
        hasher.update(path.as_bytes());
        hasher.update(b"\t");
        hasher.update(meta.blake3_hex.as_bytes());
        hasher.update(b"\t");
        hasher.update(exec_flag.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

pub(crate) fn decode_hex_32(
    hex: &str,
    path: &Path,
    reason: &'static str,
) -> Result<[u8; 32], GitTreeStoreError> {
    if hex.len() != 64 {
        return Err(GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason,
        });
    }
    let mut out = [0_u8; 32];
    let bytes = hex.as_bytes();
    for (idx, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason,
        })?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason,
        })?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn encode_manifest_entries(out: &mut String, manifest: &TreeManifest) {
    let _ = writeln!(out, "---");
    for (path, meta) in &manifest.entries {
        let _ = writeln!(out, "{}\t{:o}\t{}", meta.blake3_hex, meta.mode, path);
    }
}

pub(crate) fn parse_manifest_entries(
    path: &Path,
    lines: &[&str],
    expected_tree_blake3: &str,
    expected_file_count: u64,
) -> Result<TreeManifest, GitTreeStoreError> {
    let mut entries = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, '\t');
        let Some(blake3_hex) = parts.next() else {
            return Err(GitTreeStoreError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "missing file hash column",
            });
        };
        let Some(mode_octal) = parts.next() else {
            return Err(GitTreeStoreError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "missing file mode column",
            });
        };
        let Some(rel_path) = parts.next() else {
            return Err(GitTreeStoreError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "missing relative path column",
            });
        };
        if blake3_hex.len() != 64 || !blake3_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(GitTreeStoreError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid blake3 hex digest in manifest",
            });
        }
        let mode =
            u32::from_str_radix(mode_octal, 8).map_err(|_| GitTreeStoreError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid octal mode in manifest",
            })?;
        validate_relative_path(rel_path)?;
        if entries
            .insert(
                rel_path.to_owned(),
                FileEntryMeta {
                    blake3_hex: blake3_hex.to_owned(),
                    mode,
                },
            )
            .is_some()
        {
            return Err(GitTreeStoreError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "duplicate relative path in manifest",
            });
        }
    }
    if u64::try_from(entries.len()).unwrap_or(u64::MAX) != expected_file_count {
        return Err(GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "manifest file count does not match header",
        });
    }
    let tree_blake3 = compute_tree_blake3(&entries);
    if tree_blake3 != expected_tree_blake3 {
        return Err(GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "manifest tree digest does not match entries",
        });
    }
    Ok(TreeManifest {
        entries,
        tree_blake3,
    })
}

pub(crate) fn encode_tree_manifest_file(manifest: &TreeManifest) -> Vec<u8> {
    let mut out = String::new();
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "tree_blake3={}", manifest.tree_blake3);
    let _ = writeln!(out, "file_count={}", manifest.entries.len());
    encode_manifest_entries(&mut out, manifest);
    out.into_bytes()
}

pub(crate) fn parse_tree_manifest_file(path: &Path) -> Result<TreeManifest, GitTreeStoreError> {
    let text = fs::read_to_string(path).map_err(|source| GitTreeStoreError::Io {
        context: "reading commit manifest file",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let tree_blake3 = required_header(&headers, path, "tree_blake3")?.to_owned();
    let file_count = parse_u64_header(&headers, path, "file_count")?;
    parse_manifest_entries(path, &entry_lines, &tree_blake3, file_count)
}

pub(crate) fn split_headers_and_entries<'a>(
    path: &Path,
    text: &'a str,
) -> Result<(BTreeMap<&'a str, &'a str>, Vec<&'a str>), GitTreeStoreError> {
    let mut headers = BTreeMap::new();
    let mut entries = Vec::new();
    let mut in_entries = false;
    for line in text.lines() {
        if in_entries {
            entries.push(line);
        } else {
            if line == "---" {
                in_entries = true;
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(GitTreeStoreError::CorruptManifest {
                    path: path.to_path_buf(),
                    reason: "invalid header line",
                });
            };
            headers.insert(key, value);
        }
    }
    if !in_entries {
        return Err(GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "missing header/entries separator",
        });
    }
    let version = required_header(&headers, path, "version")?;
    if version != MANIFEST_VERSION.to_string() {
        return Err(GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "unsupported manifest version",
        });
    }
    Ok((headers, entries))
}

pub(crate) fn required_header<'a>(
    headers: &BTreeMap<&'a str, &'a str>,
    path: &Path,
    key: &'static str,
) -> Result<&'a str, GitTreeStoreError> {
    headers
        .get(key)
        .copied()
        .ok_or_else(|| GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "missing required header",
        })
}

pub(crate) fn parse_i64_header(
    headers: &BTreeMap<&str, &str>,
    path: &Path,
    key: &'static str,
) -> Result<i64, GitTreeStoreError> {
    required_header(headers, path, key)?
        .parse::<i64>()
        .map_err(|_| GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid integer header",
        })
}

pub(crate) fn parse_u64_header(
    headers: &BTreeMap<&str, &str>,
    path: &Path,
    key: &'static str,
) -> Result<u64, GitTreeStoreError> {
    required_header(headers, path, key)?
        .parse::<u64>()
        .map_err(|_| GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid unsigned integer header",
        })
}

pub(crate) fn write_atomic_file(path: &Path, contents: &[u8]) -> Result<(), GitTreeStoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| GitTreeStoreError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "manifest path has no parent",
        })?;
    fs::create_dir_all(parent).map_err(|source| GitTreeStoreError::Io {
        context: "creating manifest parent directory",
        source,
    })?;
    let nonce = next_staging_nonce();
    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{nonce}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("manifest"),
        std::process::id()
    ));
    let mut file = File::create(&temp_path).map_err(|source| GitTreeStoreError::Io {
        context: "creating temporary manifest file",
        source,
    })?;
    file.write_all(contents)
        .map_err(|source| GitTreeStoreError::Io {
            context: "writing temporary manifest file",
            source,
        })?;
    file.sync_all().map_err(|source| GitTreeStoreError::Io {
        context: "syncing temporary manifest file",
        source,
    })?;
    drop(file);
    fs::rename(&temp_path, path).map_err(|source| GitTreeStoreError::Io {
        context: "renaming temporary manifest file",
        source,
    })
}
