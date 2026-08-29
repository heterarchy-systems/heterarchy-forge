use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Maximum number of direct `.agents/` entries observed while deriving picker metadata.
pub const MAX_AGENTS_STATUS_SCAN_ENTRIES: usize = 256;
/// Maximum number of matching Harness directories exposed through one Workspace status projection.
pub const MAX_WORKSPACE_HARNESS_DIRECTORIES: usize = 16;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceHarnessDirectories {
    names: Vec<OsString>,
}

impl WorkspaceHarnessDirectories {
    #[must_use]
    pub fn names(&self) -> &[OsString] {
        &self.names
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Read-only, bounded discovery of direct `.agents/*harness*` directories.
///
/// The `.agents` directory itself must be a real directory rather than a symlink.
/// Matching entries are direct children only, must be real directories, and are
/// sorted deterministically before being returned. Missing `.agents` is a valid
/// empty observation and never initializes Workspace state.
pub fn inspect_workspace_harness_directories(
    workspace_root: &Path,
) -> Result<WorkspaceHarnessDirectories, WorkspaceHarnessDirectoryError> {
    let agents_root = workspace_root.join(".agents");
    let metadata = match fs::symlink_metadata(&agents_root) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(WorkspaceHarnessDirectories::default());
        }
        Err(source) => {
            return Err(WorkspaceHarnessDirectoryError::InspectAgentsDirectory {
                path: agents_root,
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(WorkspaceHarnessDirectoryError::AgentsDirectorySymlink(
            agents_root,
        ));
    }
    if !metadata.is_dir() {
        return Err(WorkspaceHarnessDirectoryError::AgentsPathNotDirectory(
            agents_root,
        ));
    }

    let entries = fs::read_dir(&agents_root).map_err(|source| {
        WorkspaceHarnessDirectoryError::ReadAgentsDirectory {
            path: agents_root.clone(),
            source,
        }
    })?;
    let mut names = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_AGENTS_STATUS_SCAN_ENTRIES {
            return Err(WorkspaceHarnessDirectoryError::AgentsEntryLimitExceeded {
                limit: MAX_AGENTS_STATUS_SCAN_ENTRIES,
            });
        }
        let entry = entry.map_err(|source| WorkspaceHarnessDirectoryError::ReadAgentsEntry {
            path: agents_root.clone(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| {
            WorkspaceHarnessDirectoryError::InspectAgentsEntryType {
                path: entry.path(),
                source,
            }
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if !is_harness_directory_name(&name) {
            continue;
        }
        if names.len() >= MAX_WORKSPACE_HARNESS_DIRECTORIES {
            return Err(
                WorkspaceHarnessDirectoryError::HarnessDirectoryLimitExceeded {
                    limit: MAX_WORKSPACE_HARNESS_DIRECTORIES,
                },
            );
        }
        names.push(name);
    }
    names.sort();
    Ok(WorkspaceHarnessDirectories { names })
}

fn is_harness_directory_name(name: &OsStr) -> bool {
    name.to_string_lossy()
        .to_ascii_lowercase()
        .contains("harness")
}

#[derive(Debug, Error)]
pub enum WorkspaceHarnessDirectoryError {
    #[error("failed to inspect .agents directory at {path}")]
    InspectAgentsDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(".agents must not be a symlink: {0}")]
    AgentsDirectorySymlink(PathBuf),
    #[error(".agents exists but is not a directory: {0}")]
    AgentsPathNotDirectory(PathBuf),
    #[error("failed to read .agents directory at {path}")]
    ReadAgentsDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read an entry under .agents at {path}")]
    ReadAgentsEntry {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect .agents entry type at {path}")]
    InspectAgentsEntryType {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(".agents entry scan exceeded bounded limit {limit}")]
    AgentsEntryLimitExceeded { limit: usize },
    #[error("Harness directory scan exceeded bounded limit {limit}")]
    HarnessDirectoryLimitExceeded { limit: usize },
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::{WorkspaceHarnessDirectoryError, inspect_workspace_harness_directories};

    fn temp_workspace(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-presence-{label}-{}",
            Uuid::now_v7()
        ))
    }

    #[test]
    fn missing_agents_is_empty_and_direct_harness_directories_are_detected()
    -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("detect");
        fs::create_dir_all(&root)?;
        assert!(inspect_workspace_harness_directories(&root)?.is_empty());

        let agents = root.join(".agents");
        fs::create_dir_all(agents.join("rust_dev_harness"))?;
        fs::create_dir_all(agents.join("TS-HARNESS"))?;
        fs::create_dir_all(agents.join("skills/nested_harness"))?;
        fs::write(agents.join("harness-not-a-directory"), b"ignored")?;

        let observation = inspect_workspace_harness_directories(&root)?;
        let names = observation
            .names()
            .iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["TS-HARNESS", "rust_dev_harness"]);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn symlinked_agents_directory_fails_closed() -> Result<(), Box<dyn Error>> {
        let root = temp_workspace("symlink");
        let outside = temp_workspace("outside");
        fs::create_dir_all(&root)?;
        fs::create_dir_all(outside.join("rust_dev_harness"))?;
        symlink(&outside, root.join(".agents"))?;

        let result = inspect_workspace_harness_directories(&root);
        assert!(matches!(
            result,
            Err(WorkspaceHarnessDirectoryError::AgentsDirectorySymlink(_))
        ));

        fs::remove_file(root.join(".agents"))?;
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }
}
