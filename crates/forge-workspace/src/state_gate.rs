//! Advisory cross-process admission gate for one canonical Workspace root.
//!
//! The lock is taken directly on the root directory descriptor.  It therefore
//! leaves no coordination artifact beside the Workspace and remains valid while
//! the Forge-owned state directory is being removed.

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use forge_domain::WorkspaceRootFingerprint;
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, flock, fstat, open};
use rustix::io::Errno;
use thiserror::Error;

const LOCK_RETRY_LIMIT: u32 = 1_000;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(1);

/// Shared admission fence retained for the lifetime of a live Workspace
/// connection.  It is advisory: every Forge effect ingress must use it.
#[derive(Debug)]
pub struct WorkspaceStateSharedGate {
    root: OwnedFd,
    workspace_root: PathBuf,
    expected_fingerprint: WorkspaceRootFingerprint,
}

/// Exclusive state-removal fence retained while disabling and deleting one
/// Forge-owned state directory.
#[derive(Debug)]
pub struct WorkspaceStateExclusiveGate {
    root: OwnedFd,
    workspace_root: PathBuf,
    expected_fingerprint: WorkspaceRootFingerprint,
}

impl WorkspaceStateSharedGate {
    pub fn acquire(
        workspace_root: &Path,
        expected_fingerprint: WorkspaceRootFingerprint,
    ) -> Result<Self, WorkspaceStateGateError> {
        acquire(
            workspace_root,
            expected_fingerprint,
            FlockOperation::NonBlockingLockShared,
        )
        .map(|root| Self {
            root,
            workspace_root: workspace_root.to_path_buf(),
            expected_fingerprint,
        })
    }

    pub fn ensure_root_binding(&self) -> Result<(), WorkspaceStateGateError> {
        ensure_root_binding(&self.workspace_root, &self.root, self.expected_fingerprint)
    }
}

impl WorkspaceStateExclusiveGate {
    pub fn acquire(
        workspace_root: &Path,
        expected_fingerprint: WorkspaceRootFingerprint,
    ) -> Result<Self, WorkspaceStateGateError> {
        acquire(
            workspace_root,
            expected_fingerprint,
            FlockOperation::NonBlockingLockExclusive,
        )
        .map(|root| Self {
            root,
            workspace_root: workspace_root.to_path_buf(),
            expected_fingerprint,
        })
    }

    /// Confirm that this exact exclusive guard still protects the supplied
    /// canonical root and physical identity.
    pub fn ensure_root_binding(
        &self,
        workspace_root: &Path,
        expected_fingerprint: WorkspaceRootFingerprint,
    ) -> Result<(), WorkspaceStateGateError> {
        if self.workspace_root != workspace_root
            || self.expected_fingerprint != expected_fingerprint
        {
            return Err(WorkspaceStateGateError::GuardScopeMismatch);
        }
        ensure_root_binding(&self.workspace_root, &self.root, self.expected_fingerprint)
    }
}

fn acquire(
    workspace_root: &Path,
    expected_fingerprint: WorkspaceRootFingerprint,
    operation: FlockOperation,
) -> Result<OwnedFd, WorkspaceStateGateError> {
    let root = open(
        workspace_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| WorkspaceStateGateError::OpenRoot {
        path: workspace_root.to_path_buf(),
        source,
    })?;
    ensure_root_binding(workspace_root, &root, expected_fingerprint)?;
    for _ in 0..LOCK_RETRY_LIMIT {
        match flock(&root, operation) {
            Ok(()) => {
                ensure_root_binding(workspace_root, &root, expected_fingerprint)?;
                return Ok(root);
            }
            Err(source) if source == Errno::AGAIN || source == Errno::WOULDBLOCK => {
                thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(source) => return Err(WorkspaceStateGateError::Lock { source }),
        }
    }
    Err(WorkspaceStateGateError::Busy)
}

fn ensure_root_binding(
    workspace_root: &Path,
    root: &OwnedFd,
    expected_fingerprint: WorkspaceRootFingerprint,
) -> Result<(), WorkspaceStateGateError> {
    let descriptor = fstat(root).map_err(|source| WorkspaceStateGateError::InspectRoot {
        path: workspace_root.to_path_buf(),
        source,
    })?;
    if !FileType::from_raw_mode(descriptor.st_mode).is_dir() {
        return Err(WorkspaceStateGateError::RootNotDirectory(
            workspace_root.to_path_buf(),
        ));
    }
    #[cfg(target_os = "linux")]
    let descriptor_device = descriptor.st_dev;
    #[cfg(not(target_os = "linux"))]
    let descriptor_device = u64::try_from(descriptor.st_dev)
        .map_err(|_| WorkspaceStateGateError::RootFingerprintChanged)?;
    if fingerprint(descriptor_device, descriptor.st_ino) != expected_fingerprint {
        return Err(WorkspaceStateGateError::RootFingerprintChanged);
    }
    let metadata = fs::symlink_metadata(workspace_root).map_err(|source| {
        WorkspaceStateGateError::InspectRootPath {
            path: workspace_root.to_path_buf(),
            source,
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(WorkspaceStateGateError::RootSymlink(
            workspace_root.to_path_buf(),
        ));
    }
    if !metadata.is_dir() {
        return Err(WorkspaceStateGateError::RootNotDirectory(
            workspace_root.to_path_buf(),
        ));
    }
    if fingerprint(metadata.dev(), metadata.ino()) != expected_fingerprint {
        return Err(WorkspaceStateGateError::RootFingerprintChanged);
    }
    let canonical = fs::canonicalize(workspace_root).map_err(|source| {
        WorkspaceStateGateError::CanonicalizeRoot {
            path: workspace_root.to_path_buf(),
            source,
        }
    })?;
    if canonical != workspace_root {
        return Err(WorkspaceStateGateError::RootPathChanged {
            stored: workspace_root.to_path_buf(),
            observed: canonical,
        });
    }
    Ok(())
}

fn fingerprint(device: u64, inode: u64) -> WorkspaceRootFingerprint {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&device.to_le_bytes());
    bytes[8..].copy_from_slice(&inode.to_le_bytes());
    WorkspaceRootFingerprint::from_bytes(bytes)
}

/// Typed failures from the root-directory advisory gate.
#[derive(Debug, Error)]
pub enum WorkspaceStateGateError {
    #[error("failed to open Workspace root {path}")]
    OpenRoot {
        path: PathBuf,
        #[source]
        source: Errno,
    },
    #[error("failed to inspect Workspace root descriptor {path}")]
    InspectRoot {
        path: PathBuf,
        #[source]
        source: Errno,
    },
    #[error("failed to inspect Workspace root path {path}")]
    InspectRootPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to canonicalize Workspace root {path}")]
    CanonicalizeRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Workspace root is a symbolic link: {0}")]
    RootSymlink(PathBuf),
    #[error("Workspace root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("Workspace root fingerprint changed")]
    RootFingerprintChanged,
    #[error("Workspace root path changed: stored={stored}, observed={observed}")]
    RootPathChanged { stored: PathBuf, observed: PathBuf },
    #[error("Workspace state gate is busy")]
    Busy,
    #[error("Workspace state gate does not match the requested root binding")]
    GuardScopeMismatch,
    #[error("failed to lock Workspace state gate")]
    Lock {
        #[source]
        source: Errno,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::mpsc;
    use std::thread;

    use super::{WorkspaceStateExclusiveGate, WorkspaceStateGateError, WorkspaceStateSharedGate};

    #[test]
    fn root_directory_gate_blocks_exclusive_while_shared_holder_is_live()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-state-gate-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root)?;
        let root = fs::canonicalize(root)?;
        let expected = crate::WorkspaceStateLayout::observe_root_fingerprint(&root)?;
        let shared = WorkspaceStateSharedGate::acquire(&root, expected)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        let thread_root = root.clone();
        let thread = thread::spawn(move || {
            let _ = reply.send(WorkspaceStateExclusiveGate::acquire(&thread_root, expected));
        });
        let result = receiver.recv()?;
        assert!(matches!(result, Err(WorkspaceStateGateError::Busy)));
        drop(shared);
        thread.join().map_err(|_| "gate test thread panicked")?;
        let _exclusive = WorkspaceStateExclusiveGate::acquire(&root, expected)?;
        fs::remove_dir(&root)?;
        Ok(())
    }
}
