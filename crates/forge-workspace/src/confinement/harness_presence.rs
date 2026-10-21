use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use forge_domain::{
    FileEntryKind, MAX_WORKSPACE_RELATIVE_PATH_BYTES, WorkspaceRelativePath,
    WorkspaceRelativePathError, WorkspaceRootFingerprint,
};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat};
use rustix::io::Errno;
use thiserror::Error;

use super::{
    ConfinedFilesystemError, FilesystemOperation, MAX_FILE_PATH_COMPONENTS,
    WorkspaceObservationRoot, directory_identity, is_excluded_workspace_component,
};

/// Maximum number of real `.agents` roots inspected by one Workspace
/// observation.
pub const MAX_WORKSPACE_HARNESS_AGENTS_ROOTS: usize = 64;
/// Maximum non-generated entries inspected in one `.agents` subtree directory.
pub const MAX_WORKSPACE_HARNESS_DIRECTORY_SCAN_ENTRIES: usize = 256;
/// Maximum matching Harness directories exposed by one Workspace observation.
pub const MAX_WORKSPACE_HARNESS_DIRECTORIES: usize = 16;
/// Maximum non-generated entries inspected by one Workspace observation.
pub const MAX_WORKSPACE_HARNESS_SCAN_ENTRIES: usize = 8 * 1024;
/// Maximum native path components accepted while walking this observation.
pub const MAX_WORKSPACE_HARNESS_PATH_COMPONENTS: usize = MAX_FILE_PATH_COMPONENTS;
/// Maximum native bytes accepted in an observed Workspace-relative path.
pub const MAX_WORKSPACE_HARNESS_PATH_BYTES: usize = MAX_WORKSPACE_RELATIVE_PATH_BYTES;

/// Read-only evidence that one real Harness-named directory exists beneath a
/// real `.agents` subtree in the current Workspace.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessDirectoryObservation {
    path: WorkspaceRelativePath,
}

impl HarnessDirectoryObservation {
    fn new(path: WorkspaceRelativePath) -> Self {
        Self { path }
    }

    #[must_use]
    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }
}

/// Bounded read-only projection of currently applied Harness directories.
///
/// This is source-tree observation only. It neither opens nor initializes
/// Forge state, consults a Harness Catalog, nor grants any management
/// authority.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceHarnessObservation {
    directories: Vec<HarnessDirectoryObservation>,
}

/// Maximum entries in one selected bundle tree. Overflow is an explicit error.
pub const MAX_WORKSPACE_HARNESS_TREE_ENTRIES: usize = 2048;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceHarnessTreeEntry {
    path: WorkspaceRelativePath,
    kind: FileEntryKind,
    depth: usize,
}

impl WorkspaceHarnessTreeEntry {
    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn kind(&self) -> FileEntryKind {
        self.kind
    }

    /// Zero for direct children of the selected bundle.
    pub const fn depth(&self) -> usize {
        self.depth
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceHarnessTree {
    entries: Vec<WorkspaceHarnessTreeEntry>,
}

impl WorkspaceHarnessTree {
    pub fn entries(&self) -> &[WorkspaceHarnessTreeEntry] {
        &self.entries
    }
}

/// Observe only a manifested bundle directly beneath a real `.agents` directory.
/// Paths remain native-byte identities; callers must escape labels for display.
/// No Forge state is opened or created, and symbolic links are never followed.
pub fn inspect_workspace_harness_tree(
    workspace_root: &std::path::Path,
    expected_root_fingerprint: WorkspaceRootFingerprint,
    bundle: &WorkspaceRelativePath,
    cancellation: &AtomicBool,
) -> Result<WorkspaceHarnessTree, WorkspaceHarnessObservationError> {
    ensure_not_cancelled(cancellation)?;
    let root = WorkspaceObservationRoot::open(workspace_root, expected_root_fingerprint)?;
    let components: Vec<_> = bundle
        .as_path()
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let Some((name, parents)) = components.split_last() else {
        return Err(WorkspaceHarnessObservationError::InvalidRelativePath);
    };
    let agents_name = parents
        .last()
        .map(OsString::as_os_str)
        .or_else(|| workspace_root.file_name());
    if !agents_name.is_some_and(is_exact_agents_directory_name)
        || components
            .iter()
            .any(|part| is_excluded_workspace_component(part.as_bytes()))
    {
        return Err(WorkspaceHarnessObservationError::NotHarnessBundle);
    }
    let parent = root.open_directory(parents)?;
    if !has_harness_bundle_manifest(&parent, name)? {
        return Err(WorkspaceHarnessObservationError::NotHarnessBundle);
    }
    let descriptor = root.open_directory(&components)?;
    let identity = directory_identity(&descriptor)?;
    let mut entries = Vec::new();
    let mut scanned = 0;
    collect_bundle_tree(
        &root,
        &components,
        0,
        cancellation,
        &mut scanned,
        &mut entries,
    )?;
    ensure_not_cancelled(cancellation)?;
    root.ensure_directory_current(&components, identity)?;
    root.ensure_root()?;
    Ok(WorkspaceHarnessTree { entries })
}

fn collect_bundle_tree(
    root: &WorkspaceObservationRoot,
    components: &[OsString],
    depth: usize,
    cancellation: &AtomicBool,
    scanned: &mut usize,
    result: &mut Vec<WorkspaceHarnessTreeEntry>,
) -> Result<(), WorkspaceHarnessObservationError> {
    ensure_not_cancelled(cancellation)?;
    root.ensure_root()?;
    let descriptor = root.open_directory(components)?;
    let identity = directory_identity(&descriptor)?;
    let entries = read_directory_entries(&descriptor, true, scanned, cancellation)?;
    for entry in entries {
        ensure_not_cancelled(cancellation)?;
        if result.len() >= MAX_WORKSPACE_HARNESS_TREE_ENTRIES {
            return Err(WorkspaceHarnessObservationError::TreeEntryLimitExceeded {
                limit: MAX_WORKSPACE_HARNESS_TREE_ENTRIES,
            });
        }
        let child = append_component(components, &entry.name)?;
        let kind = match entry.kind {
            DirectoryEntryKind::Directory => FileEntryKind::Directory,
            DirectoryEntryKind::RegularFile => FileEntryKind::RegularFile,
            DirectoryEntryKind::SymbolicLink => FileEntryKind::SymbolicLink,
            DirectoryEntryKind::Other => FileEntryKind::Other,
        };
        result.push(WorkspaceHarnessTreeEntry {
            path: workspace_relative_path(&child)?,
            kind,
            depth,
        });
        if kind == FileEntryKind::Directory {
            collect_bundle_tree(root, &child, depth + 1, cancellation, scanned, result)?;
        }
    }
    root.ensure_directory_current(components, identity)?;
    root.ensure_root()?;
    Ok(())
}

impl WorkspaceHarnessObservation {
    pub fn directories(&self) -> &[HarnessDirectoryObservation] {
        &self.directories
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.directories.is_empty()
    }
}

#[derive(Debug)]
struct PendingDirectory {
    components: Vec<OsString>,
    inside_agents: bool,
}

#[derive(Debug)]
struct DirectoryEntryObservation {
    name: OsString,
    kind: DirectoryEntryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryEntryKind {
    Directory,
    RegularFile,
    SymbolicLink,
    Other,
}

/// Descriptor-rooted, bounded discovery of real Harness directories beneath
/// every real `.agents` subtree in a Workspace.
///
/// Symlinks are never followed. A root/path replacement, unreadable subtree,
/// or capacity overflow is an observation error rather than a partial
/// projection. Missing `.agents` trees are a valid empty observation; a
/// missing or non-directory Workspace root is not. The caller-owned
/// cancellation flag is checked at bounded traversal and directory-entry
/// boundaries; cancellation never returns a partial projection.
pub fn inspect_workspace_harness_directories(
    workspace_root: &std::path::Path,
    expected_root_fingerprint: WorkspaceRootFingerprint,
    cancellation: &AtomicBool,
) -> Result<WorkspaceHarnessObservation, WorkspaceHarnessObservationError> {
    ensure_not_cancelled(cancellation)?;
    let root = WorkspaceObservationRoot::open(workspace_root, expected_root_fingerprint)?;
    inspect_with_root(&root, cancellation)
}

fn inspect_with_root(
    root: &WorkspaceObservationRoot,
    cancellation: &AtomicBool,
) -> Result<WorkspaceHarnessObservation, WorkspaceHarnessObservationError> {
    ensure_not_cancelled(cancellation)?;
    root.ensure_root()?;

    let root_is_agents = root
        .workspace_root
        .file_name()
        .is_some_and(is_exact_agents_directory_name);
    let mut pending = vec![PendingDirectory {
        components: Vec::new(),
        inside_agents: root_is_agents,
    }];
    let mut directories = Vec::new();
    let mut agents_roots = usize::from(root_is_agents);
    let mut scanned_entries = 0_usize;

    while let Some(directory) = pending.pop() {
        ensure_not_cancelled(cancellation)?;
        root.ensure_root()?;
        let descriptor = root.open_directory(&directory.components)?;
        let identity = directory_identity(&descriptor)?;
        let entries = read_directory_entries(
            &descriptor,
            directory.inside_agents,
            &mut scanned_entries,
            cancellation,
        )?;

        for entry in entries {
            ensure_not_cancelled(cancellation)?;
            if entry.kind != DirectoryEntryKind::Directory {
                continue;
            }

            let components = append_component(&directory.components, &entry.name)?;
            let relative_path = workspace_relative_path(&components)?;

            if directory.inside_agents {
                if has_harness_bundle_manifest(&descriptor, &entry.name)? {
                    if directories.len() >= MAX_WORKSPACE_HARNESS_DIRECTORIES {
                        return Err(
                            WorkspaceHarnessObservationError::HarnessDirectoryLimitExceeded {
                                limit: MAX_WORKSPACE_HARNESS_DIRECTORIES,
                            },
                        );
                    }
                    directories.push(HarnessDirectoryObservation::new(relative_path));
                }
                continue;
            }

            let enters_agents = is_exact_agents_directory_name(&entry.name);
            if enters_agents {
                if agents_roots >= MAX_WORKSPACE_HARNESS_AGENTS_ROOTS {
                    return Err(WorkspaceHarnessObservationError::AgentsRootLimitExceeded {
                        limit: MAX_WORKSPACE_HARNESS_AGENTS_ROOTS,
                    });
                }
                agents_roots += 1;
            }

            pending.push(PendingDirectory {
                components,
                inside_agents: enters_agents,
            });
        }

        root.ensure_directory_current(&directory.components, identity)?;
        root.ensure_root()?;
    }

    ensure_not_cancelled(cancellation)?;
    root.ensure_root()?;
    directories.sort_by(|left, right| {
        left.path()
            .as_path()
            .as_os_str()
            .as_bytes()
            .cmp(right.path().as_path().as_os_str().as_bytes())
    });
    Ok(WorkspaceHarnessObservation { directories })
}

fn read_directory_entries(
    directory: &OwnedFd,
    inside_agents: bool,
    scanned_entries: &mut usize,
    cancellation: &AtomicBool,
) -> Result<Vec<DirectoryEntryObservation>, WorkspaceHarnessObservationError> {
    ensure_not_cancelled(cancellation)?;
    let stream = Dir::read_from(directory).map_err(|source| ConfinedFilesystemError::Syscall {
        operation: FilesystemOperation::OpenDirectoryStream,
        committed: false,
        source,
    })?;
    let mut entries = Vec::new();
    let mut directory_entries = 0_usize;

    for entry in stream {
        ensure_not_cancelled(cancellation)?;
        let entry = entry.map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::ReadDirectory,
            committed: false,
            source,
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." || is_excluded_workspace_component(bytes) {
            continue;
        }
        let name = OsString::from_vec(bytes.to_vec());
        let stat = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::InspectDirectoryEntry,
                committed: false,
                source,
            }
        })?;
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            file_type if file_type.is_dir() => DirectoryEntryKind::Directory,
            file_type if file_type.is_file() => DirectoryEntryKind::RegularFile,
            file_type if file_type.is_symlink() => DirectoryEntryKind::SymbolicLink,
            _ => DirectoryEntryKind::Other,
        };

        if inside_agents && directory_entries >= MAX_WORKSPACE_HARNESS_DIRECTORY_SCAN_ENTRIES {
            return Err(
                WorkspaceHarnessObservationError::DirectoryEntryLimitExceeded {
                    limit: MAX_WORKSPACE_HARNESS_DIRECTORY_SCAN_ENTRIES,
                },
            );
        }
        if inside_agents {
            directory_entries += 1;
        }

        let consumes_discovery_budget = inside_agents || kind == DirectoryEntryKind::Directory;
        if consumes_discovery_budget {
            if *scanned_entries >= MAX_WORKSPACE_HARNESS_SCAN_ENTRIES {
                return Err(WorkspaceHarnessObservationError::ScanEntryLimitExceeded {
                    limit: MAX_WORKSPACE_HARNESS_SCAN_ENTRIES,
                });
            }
            *scanned_entries += 1;
        }
        entries.push(DirectoryEntryObservation { name, kind });
    }

    entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    ensure_not_cancelled(cancellation)?;
    Ok(entries)
}

fn ensure_not_cancelled(cancellation: &AtomicBool) -> Result<(), WorkspaceHarnessObservationError> {
    if cancellation.load(Ordering::Acquire) {
        Err(WorkspaceHarnessObservationError::Cancelled)
    } else {
        Ok(())
    }
}

fn append_component(
    parent: &[OsString],
    name: &OsStr,
) -> Result<Vec<OsString>, WorkspaceHarnessObservationError> {
    if parent.len() >= MAX_WORKSPACE_HARNESS_PATH_COMPONENTS {
        return Err(
            WorkspaceHarnessObservationError::PathComponentLimitExceeded {
                limit: MAX_WORKSPACE_HARNESS_PATH_COMPONENTS,
            },
        );
    }
    let mut components = parent.to_vec();
    components.push(name.to_os_string());
    Ok(components)
}

fn workspace_relative_path(
    components: &[OsString],
) -> Result<WorkspaceRelativePath, WorkspaceHarnessObservationError> {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    WorkspaceRelativePath::new(path).map_err(|error| match error {
        WorkspaceRelativePathError::TooLong { .. } => {
            WorkspaceHarnessObservationError::PathByteLimitExceeded {
                limit: MAX_WORKSPACE_HARNESS_PATH_BYTES,
            }
        }
        WorkspaceRelativePathError::Empty
        | WorkspaceRelativePathError::ContainsNul
        | WorkspaceRelativePathError::NotConfined
        | WorkspaceRelativePathError::NonCanonical => {
            WorkspaceHarnessObservationError::InvalidRelativePath
        }
    })
}

fn has_harness_bundle_manifest(
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<bool, WorkspaceHarnessObservationError> {
    let directory = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| match source {
        Errno::LOOP => ConfinedFilesystemError::SymlinkRejected,
        Errno::NOTDIR => ConfinedFilesystemError::NonDirectoryAncestor,
        source => ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenAncestor,
            committed: false,
            source,
        },
    })?;
    let _identity = directory_identity(&directory)?;
    match statat(
        &directory,
        OsStr::new("HARNESS_MANIFEST.tsv"),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(stat) => Ok(FileType::from_raw_mode(stat.st_mode).is_file()),
        Err(Errno::NOENT) => Ok(false),
        Err(source) => Err(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::InspectDirectoryEntry,
            committed: false,
            source,
        }
        .into()),
    }
}

fn is_exact_agents_directory_name(name: &OsStr) -> bool {
    name.as_bytes() == b".agents"
}

#[derive(Debug, Error)]
pub enum WorkspaceHarnessObservationError {
    #[error("selected path is not a manifested Harness bundle beneath .agents")]
    NotHarnessBundle,
    #[error("Harness bundle tree exceeded entry limit {limit}")]
    TreeEntryLimitExceeded { limit: usize },
    #[error("Workspace Harness observation was cancelled")]
    Cancelled,
    #[error("Workspace Harness observation filesystem boundary failed")]
    Filesystem(#[from] ConfinedFilesystemError),
    #[error("Workspace Harness observation exceeded .agents root limit {limit}")]
    AgentsRootLimitExceeded { limit: usize },
    #[error("Workspace Harness observation exceeded directory entry limit {limit}")]
    DirectoryEntryLimitExceeded { limit: usize },
    #[error("Workspace Harness observation exceeded total entry limit {limit}")]
    ScanEntryLimitExceeded { limit: usize },
    #[error("Workspace Harness observation exceeded candidate limit {limit}")]
    HarnessDirectoryLimitExceeded { limit: usize },
    #[error("Workspace Harness observation exceeded path component limit {limit}")]
    PathComponentLimitExceeded { limit: usize },
    #[error("Workspace Harness observation exceeded native path-byte limit {limit}")]
    PathByteLimitExceeded { limit: usize },
    #[error("Workspace Harness observation produced an invalid relative path")]
    InvalidRelativePath,
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;

    use uuid::Uuid;

    use super::{
        MAX_WORKSPACE_HARNESS_AGENTS_ROOTS, MAX_WORKSPACE_HARNESS_DIRECTORIES,
        MAX_WORKSPACE_HARNESS_DIRECTORY_SCAN_ENTRIES, MAX_WORKSPACE_HARNESS_PATH_BYTES,
        MAX_WORKSPACE_HARNESS_PATH_COMPONENTS, MAX_WORKSPACE_HARNESS_SCAN_ENTRIES,
        WorkspaceHarnessObservationError, WorkspaceObservationRoot, directory_identity,
        inspect_with_root, inspect_workspace_harness_directories, workspace_relative_path,
    };
    use crate::ConfinedFilesystemError;
    use forge_domain::WorkspaceRootFingerprint;

    static NOT_CANCELLED: AtomicBool = AtomicBool::new(false);

    fn temp_workspace(label: &str) -> Result<PathBuf, std::io::Error> {
        Ok(fs::canonicalize(std::env::temp_dir())?.join(format!(
            "heterarchy-forge-harness-observation-{label}-{}",
            Uuid::now_v7()
        )))
    }

    fn root_fingerprint(root: &Path) -> Result<WorkspaceRootFingerprint, std::io::Error> {
        let metadata = fs::metadata(root)?;
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&metadata.dev().to_le_bytes());
        bytes[8..].copy_from_slice(&metadata.ino().to_le_bytes());
        Ok(WorkspaceRootFingerprint::from_bytes(bytes))
    }

    fn observed_paths(root: &Path) -> Result<Vec<Vec<u8>>, WorkspaceHarnessObservationError> {
        Ok(inspect_workspace_harness_directories(
            root,
            root_fingerprint(root).map_err(|source| {
                WorkspaceHarnessObservationError::Filesystem(ConfinedFilesystemError::StdIo {
                    operation: super::FilesystemOperation::InspectDescriptor,
                    committed: false,
                    source,
                })
            })?,
            &NOT_CANCELLED,
        )?
        .directories()
        .iter()
        .map(|entry| entry.path().as_path().as_os_str().as_bytes().to_vec())
        .collect())
    }

    fn create_harness_bundle(root: &Path, relative: &str) -> Result<(), std::io::Error> {
        let bundle = root.join(relative);
        fs::create_dir_all(&bundle)?;
        fs::write(bundle.join("HARNESS_MANIFEST.tsv"), b"path\tkind\n")
    }

    #[test]
    fn bundle_tree_is_ordered_confined_and_does_not_initialize_state() -> Result<(), Box<dyn Error>>
    {
        let root = temp_workspace("bundle-tree")?;
        create_harness_bundle(&root, ".agents/harness")?;
        fs::create_dir(root.join(".agents/harness/rules"))?;
        fs::write(root.join(".agents/harness/rules/normal.md"), b"rule")?;
        fs::create_dir(root.join("outside"))?;
        fs::write(root.join("outside/secret"), b"secret")?;
        symlink(root.join("outside"), root.join(".agents/harness/link"))?;
        let bundle = forge_domain::WorkspaceRelativePath::new(".agents/harness".into())?;
        let tree = super::inspect_workspace_harness_tree(
            &root,
            root_fingerprint(&root)?,
            &bundle,
            &NOT_CANCELLED,
        )?;
        let observed: Vec<_> = tree
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.path().as_path().to_path_buf(),
                    entry.kind(),
                    entry.depth(),
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (
                    PathBuf::from(".agents/harness/HARNESS_MANIFEST.tsv"),
                    forge_domain::FileEntryKind::RegularFile,
                    0
                ),
                (
                    PathBuf::from(".agents/harness/link"),
                    forge_domain::FileEntryKind::SymbolicLink,
                    0
                ),
                (
                    PathBuf::from(".agents/harness/rules"),
                    forge_domain::FileEntryKind::Directory,
                    0
                ),
                (
                    PathBuf::from(".agents/harness/rules/normal.md"),
                    forge_domain::FileEntryKind::RegularFile,
                    1
                ),
            ]
        );
        assert!(!root.join(".heterarchy-forge").exists());
        let outside = forge_domain::WorkspaceRelativePath::new("outside".into())?;
        assert!(matches!(
            super::inspect_workspace_harness_tree(
                &root,
                root_fingerprint(&root)?,
                &outside,
                &NOT_CANCELLED,
            ),
            Err(WorkspaceHarnessObservationError::NotHarnessBundle)
        ));
        let cancelled = AtomicBool::new(true);
        assert!(matches!(
            super::inspect_workspace_harness_tree(
                &root,
                root_fingerprint(&root)?,
                &bundle,
                &cancelled,
            ),
            Err(WorkspaceHarnessObservationError::Cancelled)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn bundle_tree_rejects_unmanifested_and_symlink_roots_and_overflow()
    -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("bundle-tree-bounds")?;
        fs::create_dir_all(root.join(".agents/ordinary"))?;
        let ordinary = forge_domain::WorkspaceRelativePath::new(".agents/ordinary".into())?;
        assert!(matches!(
            super::inspect_workspace_harness_tree(
                &root,
                root_fingerprint(&root)?,
                &ordinary,
                &NOT_CANCELLED,
            ),
            Err(WorkspaceHarnessObservationError::NotHarnessBundle)
        ));
        create_harness_bundle(&root, ".agents/harness")?;
        symlink(root.join(".agents/harness"), root.join(".agents/linked"))?;
        let linked = forge_domain::WorkspaceRelativePath::new(".agents/linked".into())?;
        assert!(
            super::inspect_workspace_harness_tree(
                &root,
                root_fingerprint(&root)?,
                &linked,
                &NOT_CANCELLED,
            )
            .is_err()
        );
        for directory in 0..9 {
            let directory = root.join(format!(".agents/harness/rules-{directory}"));
            fs::create_dir(&directory)?;
            for file in 0..240 {
                fs::write(directory.join(format!("rule-{file}")), b"")?;
            }
        }
        let bundle = forge_domain::WorkspaceRelativePath::new(".agents/harness".into())?;
        assert!(matches!(
            super::inspect_workspace_harness_tree(
                &root,
                root_fingerprint(&root)?,
                &bundle,
                &NOT_CANCELLED,
            ),
            Err(WorkspaceHarnessObservationError::TreeEntryLimitExceeded { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn only_direct_manifested_children_of_agents_roots_are_observed() -> Result<(), Box<dyn Error>>
    {
        let root = temp_workspace("manifested-bundles")?;
        create_harness_bundle(&root, ".agents/rust_dev_harness")?;
        create_harness_bundle(&root, "backend/.agents/python_dev_harness")?;
        create_harness_bundle(&root, ".agents/rust_dev_harness/harness")?;
        create_harness_bundle(&root, "frontend/.agents/profiles/my-harness-v2")?;
        create_harness_bundle(&root, "services/trader/.agents/tools/custom/harness")?;
        fs::create_dir_all(root.join(".agents/not-a-bundle"))?;
        fs::create_dir_all(root.join("backend/harness"))?;

        assert_eq!(
            observed_paths(&root)?,
            vec![
                b".agents/rust_dev_harness".to_vec(),
                b"backend/.agents/python_dev_harness".to_vec(),
            ]
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_agents_is_empty_without_initializing_forge_state() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("empty")?;
        fs::create_dir_all(&root)?;
        let observation =
            inspect_workspace_harness_directories(&root, root_fingerprint(&root)?, &NOT_CANCELLED)?;
        assert!(observation.is_empty());
        assert!(!root.join(".heterarchy-forge").exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn unrelated_regular_files_do_not_consume_nested_agents_discovery_budget()
    -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("ordinary-files")?;
        create_harness_bundle(&root, ".agents/rust_dev_harness")?;
        for index in 0..=MAX_WORKSPACE_HARNESS_SCAN_ENTRIES {
            fs::write(root.join(format!("ordinary-{index:05}.txt")), [])?;
        }

        assert_eq!(
            observed_paths(&root)?,
            vec![b".agents/rust_dev_harness".to_vec()]
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn root_named_agents_observes_only_direct_manifested_bundle_children()
    -> Result<(), Box<dyn Error>> {
        let parent = temp_workspace("root-agents")?;
        let root = parent.join(".agents");
        create_harness_bundle(&root, "rust_dev_harness")?;
        create_harness_bundle(&root, "profiles/custom-harness")?;
        fs::create_dir_all(root.join("plain_harness_name"))?;

        assert_eq!(observed_paths(&root)?, vec![b"rust_dev_harness".to_vec()]);

        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn manifest_is_authority_not_directory_name() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("manifest-authority")?;
        create_harness_bundle(&root, ".agents/team-policy")?;
        fs::create_dir_all(root.join(".agents/looks_like_harness"))?;

        assert_eq!(
            observed_paths(&root)?,
            vec![b".agents/team-policy".to_vec()]
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn cancellation_returns_no_partial_observation() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("cancelled")?;
        create_harness_bundle(&root, ".agents/rust_dev_harness")?;
        let cancellation = AtomicBool::new(true);

        assert!(matches!(
            inspect_workspace_harness_directories(&root, root_fingerprint(&root)?, &cancellation,),
            Err(WorkspaceHarnessObservationError::Cancelled)
        ));
        assert!(!root.join(".heterarchy-forge").exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn generated_paths_and_symlinks_are_never_followed() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("pruned")?;
        let outside = temp_workspace("outside")?;
        create_harness_bundle(&root, ".agents/real-harness")?;
        create_harness_bundle(&root, "target/generated/.agents/ignored-harness")?;
        create_harness_bundle(&root, "node_modules/pkg/.agents/ignored-harness")?;
        create_harness_bundle(&outside, "escaped-harness")?;
        symlink(
            outside.join("escaped-harness"),
            root.join(".agents/linked-harness"),
        )?;
        symlink(&outside, root.join("backend"))?;

        assert_eq!(
            observed_paths(&root)?,
            vec![b".agents/real-harness".to_vec()]
        );

        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn missing_workspace_root_is_an_observation_error() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("missing-root")?;
        assert!(matches!(
            inspect_workspace_harness_directories(
                &root,
                WorkspaceRootFingerprint::from_bytes([0; 16]),
                &NOT_CANCELLED,
            ),
            Err(WorkspaceHarnessObservationError::Filesystem(_))
        ));
        Ok(())
    }

    #[test]
    fn root_replacement_is_rejected_before_any_result() -> Result<(), Box<dyn Error>> {
        let parent = temp_workspace("root-swap")?;
        let root = parent.join("workspace");
        let moved = parent.join("moved");
        fs::create_dir_all(root.join(".agents/rust_harness"))?;
        let observation_root = WorkspaceObservationRoot::open(&root, root_fingerprint(&root)?)?;
        fs::rename(&root, &moved)?;
        fs::create_dir_all(&root)?;

        assert!(matches!(
            inspect_with_root(&observation_root, &NOT_CANCELLED),
            Err(WorkspaceHarnessObservationError::Filesystem(
                ConfinedFilesystemError::PathChanged
            ))
        ));

        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn expected_fingerprint_rejects_a_root_replaced_before_observation()
    -> Result<(), Box<dyn Error>> {
        let parent = temp_workspace("pre-scan-root-swap")?;
        let root = parent.join("workspace");
        let moved = parent.join("moved");
        fs::create_dir_all(root.join(".agents/rust_harness"))?;
        let expected = root_fingerprint(&root)?;
        fs::rename(&root, &moved)?;
        fs::create_dir_all(root.join(".agents/replacement_harness"))?;

        assert!(matches!(
            inspect_workspace_harness_directories(&root, expected, &NOT_CANCELLED),
            Err(WorkspaceHarnessObservationError::Filesystem(
                ConfinedFilesystemError::WorkspaceUnavailable
            ))
        ));

        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn nested_directory_replacement_is_identity_fenced() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("nested-swap")?;
        let agents = root.join("backend/.agents");
        let moved = root.join("moved-agents");
        fs::create_dir_all(agents.join("rust_harness"))?;
        let observation_root = WorkspaceObservationRoot::open(&root, root_fingerprint(&root)?)?;
        let components = vec!["backend".into(), ".agents".into()];
        let directory = observation_root.open_directory(&components)?;
        let identity = directory_identity(&directory)?;
        fs::rename(&agents, &moved)?;
        fs::create_dir_all(&agents)?;

        assert!(matches!(
            observation_root.ensure_directory_current(&components, identity),
            Err(ConfinedFilesystemError::PathChanged)
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn counts_and_native_path_bounds_fail_closed() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("candidate-limit")?;
        for index in 0..=MAX_WORKSPACE_HARNESS_DIRECTORIES {
            create_harness_bundle(&root, &format!(".agents/bundle-{index:02}"))?;
        }
        assert!(matches!(
            inspect_workspace_harness_directories(&root, root_fingerprint(&root)?, &NOT_CANCELLED,),
            Err(WorkspaceHarnessObservationError::HarnessDirectoryLimitExceeded { .. })
        ));
        fs::remove_dir_all(&root)?;

        let root = temp_workspace("agent-root-limit")?;
        for index in 0..=MAX_WORKSPACE_HARNESS_AGENTS_ROOTS {
            fs::create_dir_all(root.join(format!("project-{index:02}/.agents")))?;
        }
        assert!(matches!(
            inspect_workspace_harness_directories(&root, root_fingerprint(&root)?, &NOT_CANCELLED,),
            Err(WorkspaceHarnessObservationError::AgentsRootLimitExceeded { .. })
        ));
        fs::remove_dir_all(&root)?;

        let root = temp_workspace("agent-entry-limit")?;
        for index in 0..=MAX_WORKSPACE_HARNESS_DIRECTORY_SCAN_ENTRIES {
            fs::create_dir_all(root.join(format!(".agents/ordinary-{index:03}")))?;
        }
        assert!(matches!(
            inspect_workspace_harness_directories(&root, root_fingerprint(&root)?, &NOT_CANCELLED,),
            Err(WorkspaceHarnessObservationError::DirectoryEntryLimitExceeded { .. })
        ));
        fs::remove_dir_all(&root)?;

        let root = temp_workspace("scan-limit")?;
        fs::create_dir_all(&root)?;
        for index in 0..=MAX_WORKSPACE_HARNESS_SCAN_ENTRIES {
            fs::create_dir(root.join(format!("directory-{index:05}")))?;
        }
        assert!(matches!(
            inspect_workspace_harness_directories(&root, root_fingerprint(&root)?, &NOT_CANCELLED,),
            Err(WorkspaceHarnessObservationError::ScanEntryLimitExceeded { .. })
        ));
        fs::remove_dir_all(root)?;

        let too_long =
            std::ffi::OsString::from_vec(vec![b'a'; MAX_WORKSPACE_HARNESS_PATH_BYTES + 1]);
        assert!(matches!(
            workspace_relative_path(&[too_long]),
            Err(WorkspaceHarnessObservationError::PathByteLimitExceeded { .. })
        ));

        let root = temp_workspace("component-limit")?;
        let mut nested = root.clone();
        for index in 0..MAX_WORKSPACE_HARNESS_PATH_COMPONENTS {
            nested.push(format!("d{index}"));
        }
        fs::create_dir_all(nested.join(".agents"))?;
        assert!(matches!(
            inspect_workspace_harness_directories(&root, root_fingerprint(&root)?, &NOT_CANCELLED,),
            Err(WorkspaceHarnessObservationError::PathComponentLimitExceeded { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_unicode_candidate_and_raw_relative_path_round_trip_without_loss()
    -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("native-name")?;
        let name = std::ffi::OsString::from("러스트-policy");
        let bundle = root.join(".agents").join(&name);
        fs::create_dir_all(&bundle)?;
        fs::write(bundle.join("HARNESS_MANIFEST.tsv"), b"path\tkind\n")?;

        assert_eq!(
            observed_paths(&root)?,
            vec![".agents/러스트-policy".as_bytes().to_vec()]
        );

        let raw = workspace_relative_path(&[
            std::ffi::OsString::from(".agents"),
            std::ffi::OsString::from_vec(b"rust-\xff-harness".to_vec()),
        ])?;
        assert_eq!(
            raw.as_path().as_os_str().as_bytes(),
            b".agents/rust-\xff-harness"
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }
}
