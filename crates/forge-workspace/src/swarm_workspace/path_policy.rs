//! External Swarm worktree path confinement, `/Volumes/256.SSD/RustBuild` forbidden-root
//! enforcement (lexical, normalized, and symlink-traversal), and `<workspace_root>`
//! non-nesting validation.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use forge_domain::{SwarmMemberId, SwarmRunId, WorkspaceId};

use super::SwarmWorkspaceError;
use crate::ExistingWorkspaceStateLayout;
use crate::dag_git_store::{WORKTREE_DIR_NAME, resolve_workspace_scope_segment};

const DEFAULT_SWARM_WORKTREES_SUBDIR: &str = "heterarchy-forge-swarm-worktrees";
const FORBIDDEN_SSD_COMPONENTS: [&str; 3] = ["Volumes", "256.SSD", "RustBuild"];
const MAX_SYMLINK_HOPS: usize = 40;

pub(super) fn resolve_swarm_scope_dir(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
) -> Result<PathBuf, SwarmWorkspaceError> {
    let base_root = if let Some(root) = external_worktrees_root {
        validate_external_worktree_root(root, layout.workspace_root())?;
        root.to_path_buf()
    } else {
        let ambient_tmp = std::env::temp_dir();
        let safe_base = if is_forbidden_ssd_path(&ambient_tmp) {
            PathBuf::from("/var/tmp")
        } else {
            ambient_tmp
        };
        let candidate = safe_base.join(DEFAULT_SWARM_WORKTREES_SUBDIR);
        validate_external_worktree_root(&candidate, layout.workspace_root())?;
        candidate
    };
    let scope_segment = resolve_workspace_scope_segment(layout, workspace_id)?;
    let scope_dir = base_root.join(scope_segment);
    validate_external_worktree_path(&scope_dir, layout.workspace_root())?;
    Ok(scope_dir)
}

pub(super) fn resolve_swarm_external_worktree_path(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
) -> Result<PathBuf, SwarmWorkspaceError> {
    let scope_dir = resolve_swarm_scope_dir(layout, external_worktrees_root, workspace_id)?;
    let worktree_path = scope_dir
        .join(swarm_run_id.to_string())
        .join(member_id.to_string())
        .join(WORKTREE_DIR_NAME);
    validate_external_worktree_path(&worktree_path, layout.workspace_root())?;
    Ok(worktree_path)
}

pub(super) fn validate_external_worktree_root(
    root: &Path,
    workspace_root: &Path,
) -> Result<(), SwarmWorkspaceError> {
    if !root.is_absolute() {
        return Err(SwarmWorkspaceError::InvalidExternalWorktreeRoot {
            path: root.to_path_buf(),
            reason: "external worktrees root must be an absolute path",
        });
    }
    if root.as_os_str().is_empty() {
        return Err(SwarmWorkspaceError::InvalidExternalWorktreeRoot {
            path: root.to_path_buf(),
            reason: "external worktrees root must not be empty",
        });
    }
    reject_forbidden_ssd_path(root)?;
    let canonical_root = resolve_path_with_existing_prefix(root)?;
    reject_forbidden_ssd_path(&canonical_root)?;
    let canonical_ws = resolve_path_with_existing_prefix(workspace_root)?;
    if is_same_or_child(root, workspace_root) || is_same_or_child(&canonical_root, &canonical_ws) {
        return Err(SwarmWorkspaceError::WorktreeInsideWorkspaceRoot {
            path: root.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
        });
    }
    Ok(())
}

pub(super) fn validate_external_worktree_path(
    path: &Path,
    workspace_root: &Path,
) -> Result<(), SwarmWorkspaceError> {
    if !path.is_absolute() {
        return Err(SwarmWorkspaceError::InvalidExternalWorktreeRoot {
            path: path.to_path_buf(),
            reason: "worktree path must be absolute",
        });
    }
    reject_forbidden_ssd_path(path)?;
    let canonical_path = resolve_path_with_existing_prefix(path)?;
    reject_forbidden_ssd_path(&canonical_path)?;
    let canonical_ws = resolve_path_with_existing_prefix(workspace_root)?;
    if is_same_or_child(path, workspace_root)
        || is_same_or_child(&canonical_path, &canonical_ws)
        || is_same_or_child(workspace_root, path)
        || is_same_or_child(&canonical_ws, &canonical_path)
    {
        return Err(SwarmWorkspaceError::WorktreeInsideWorkspaceRoot {
            path: path.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
        });
    }
    Ok(())
}

fn is_same_or_child(candidate: &Path, parent: &Path) -> bool {
    let norm_candidate = normalize_lexical_absolute(candidate);
    let norm_parent = normalize_lexical_absolute(parent);
    match (norm_candidate, norm_parent) {
        (Some(c), Some(p)) => c == p || c.starts_with(&p),
        _ => candidate == parent || candidate.starts_with(parent),
    }
}

fn reject_forbidden_ssd_path(path: &Path) -> Result<(), SwarmWorkspaceError> {
    if is_forbidden_ssd_path(path) {
        return Err(SwarmWorkspaceError::ForbiddenSsdWorktreeRoot {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(super) fn is_forbidden_ssd_path(path: &Path) -> bool {
    has_forbidden_ssd_components(path)
        || normalize_lexical_absolute(path).is_some_and(|norm| has_forbidden_ssd_components(&norm))
        || path.ancestors().any(symlink_chain_reaches_forbidden_root)
}

fn has_forbidden_ssd_components(path: &Path) -> bool {
    let mut normal = path.components().filter_map(|component| match component {
        Component::Normal(part) => part.to_str(),
        _ => None,
    });
    matches!(
        (normal.next(), normal.next(), normal.next()),
        (Some(first), Some(second), Some(third))
            if first.eq_ignore_ascii_case(FORBIDDEN_SSD_COMPONENTS[0])
                && second.eq_ignore_ascii_case(FORBIDDEN_SSD_COMPONENTS[1])
                && third.eq_ignore_ascii_case(FORBIDDEN_SSD_COMPONENTS[2])
    )
}

fn symlink_chain_reaches_forbidden_root(path: &Path) -> bool {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_HOPS {
        let Ok(meta) = fs::symlink_metadata(&current) else {
            break;
        };
        if !meta.file_type().is_symlink() {
            break;
        }
        let Ok(target) = fs::read_link(&current) else {
            break;
        };
        let resolved = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .map_or_else(|| target.clone(), |parent| parent.join(&target))
        };
        if has_forbidden_ssd_components(&resolved)
            || normalize_lexical_absolute(&resolved)
                .is_some_and(|norm| has_forbidden_ssd_components(&norm))
        {
            return true;
        }
        current = resolved;
    }
    false
}

fn normalize_lexical_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut stack = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                let _ = stack.pop();
            }
            Component::Normal(segment) => stack.push(segment),
            Component::Prefix(_) => return None,
        }
    }
    let mut out = PathBuf::from("/");
    for segment in stack {
        out.push(segment);
    }
    Some(out)
}

fn resolve_path_with_existing_prefix(path: &Path) -> Result<PathBuf, SwarmWorkspaceError> {
    let normalized = normalize_lexical_absolute(path).unwrap_or_else(|| path.to_path_buf());
    let mut suffix = Vec::new();
    let mut cursor = normalized.as_path();
    loop {
        match fs::canonicalize(cursor) {
            Ok(mut canonical) => {
                for segment in suffix.into_iter().rev() {
                    canonical.push(segment);
                }
                return Ok(canonical);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let Some(name) = cursor.file_name() else {
                    return Ok(normalized);
                };
                suffix.push(name.to_os_string());
                let Some(parent) = cursor.parent() else {
                    return Ok(normalized);
                };
                cursor = parent;
            }
            Err(source) => {
                return Err(SwarmWorkspaceError::Io {
                    context: "canonicalizing swarm external worktree path",
                    source,
                });
            }
        }
    }
}
