//! Descriptor-confined frozen source inputs for verification runs.
//!
//! Verification inputs are ephemeral Workspace artifacts.  The live source
//! tree is only read through descriptors; copied source and manifest stay sealed.
//! On macOS the enclosing directory is resealed after atomic rename and before
//! a validated published handle can be returned. No `SQLite` state is involved.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use forge_domain::{
    FileByteCount, FileContentHash, MAX_VERIFICATION_INPUT_BYTES, MAX_VERIFICATION_INPUT_ENTRIES,
    MAX_VERIFICATION_INPUT_FILE_BYTES, MAX_VERIFICATION_INPUT_FILES,
    MAX_VERIFICATION_INPUT_PATH_BYTES, VerificationInputEntry, VerificationInputEntryKind,
    VerificationInputFingerprint, VerificationInputId, VerificationInputManifest,
    VerificationInputManifestError, VerificationInputPolicy, WorkspaceRelativePath,
};
use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, Stat, fchmod, fstat, fsync, mkdirat, openat,
    renameat_with, statat, unlinkat,
};
use rustix::io::{Errno, dup};
use thiserror::Error;

use super::{
    ConfinedFilesystemError, ConfinedWorkspace, ConfinedWorkspaceWriteGuard, FilesystemOperation,
    MAX_FILE_PATH_COMPONENTS, MAX_FILE_READ_BYTES, STATE_DIRECTORY, WorkspaceStateExclusiveGate,
    directory_identity, ensure_directory_identity, open_regular_leaf, require_regular_single_link,
    sync_file, walk_directories,
};
use crate::{WorkspaceStateGateError, WorkspaceStateSharedGate};

/// Maximum serialized bytes retained for one verification-input manifest.
pub const MAX_VERIFICATION_INPUT_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

const VERIFICATION_DIRECTORY: &str = "verification";
const SOURCE_DIRECTORY: &str = "source";
const MANIFEST_FILE: &str = "manifest";
const PENDING_PREFIX: &str = ".pending-";
const MAX_VERIFICATION_SCAN_ENTRIES: usize = 65_536;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const SEALED_WRITE_MASK: u16 = 0o222;
const MANIFEST_HEADER: &str = "heterarchy-forge-verification-input\t1";

static NO_CANCELLATION: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationInputCleanupStatus {
    Deleted,
    AlreadyMissing,
}

#[derive(Debug, Clone, Copy)]
struct VerificationInputCleanupExpectation {
    id: VerificationInputId,
    fingerprint: VerificationInputFingerprint,
    bytes: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "fault injection points identify which effect has already completed"
)]
pub(super) enum VerificationInputCleanupFault {
    AfterChmod,
    AfterFileDelete,
    AfterManifestUnlink,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationInputPublishFault {
    AfterRenameSync,
    #[cfg(target_os = "macos")]
    Reseal,
}

/// Failure from the frozen verification-input boundary.
#[derive(Debug, Error)]
pub enum VerificationInputError {
    #[error("verification input publication requires exact readback")]
    PublicationUnconfirmed {
        id: VerificationInputId,
        fingerprint: VerificationInputFingerprint,
        #[source]
        source: Box<VerificationInputError>,
    },
    #[error("verification input operation was cancelled")]
    Cancelled,
    #[error(transparent)]
    Filesystem(#[from] ConfinedFilesystemError),
    #[error(transparent)]
    Manifest(#[from] VerificationInputManifestError),
    #[error("verification input manifest is malformed")]
    ManifestMalformed,
    #[error("verification input manifest exceeds its {maximum} byte bound")]
    ManifestTooLarge { maximum: usize },
    #[error("verification input scan exceeds its {maximum} physical-entry bound")]
    ScanLimitExceeded { maximum: usize },
    #[error("verification input snapshot is stale")]
    SnapshotStale,
    #[error("verification input snapshot failed validation")]
    SnapshotInvalid,
    #[error("verification input path is not present as a regular file")]
    FileUnavailable,
    #[error("verification input read exceeds its {maximum} byte bound")]
    ReadTooLarge { maximum: usize },
    #[error("verification input artifact was not found")]
    NotFound,
    #[error("verification input artifact identity collides with an existing entry")]
    Collision,
    #[error("verification input manifest fingerprint does not match")]
    FingerprintMismatch,
    #[error("verification input relative path is invalid")]
    InvalidPath,
    #[error("verification input atomic publication is unsupported")]
    AtomicPublishUnsupported,
    #[error("verification input cleanup failed")]
    CleanupFailed,
    #[error(transparent)]
    StateGate(#[from] WorkspaceStateGateError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NodeState {
    device: i128,
    inode: i128,
    size: i64,
    mode: u16,
    nlink: i128,
    is_directory: bool,
    is_regular: bool,
    mtime: i128,
    mtime_nsec: i128,
    ctime: i128,
    ctime_nsec: i128,
}

impl NodeState {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            device: i128::from(stat.st_dev),
            inode: i128::from(stat.st_ino),
            size: stat.st_size,
            mode: (mode_bits_from_stat(stat) & 0o7777) as u16,
            nlink: i128::from(stat.st_nlink),
            is_directory: FileType::from_raw_mode(stat.st_mode).is_dir(),
            is_regular: FileType::from_raw_mode(stat.st_mode).is_file(),
            mtime: i128::from(stat.st_mtime),
            mtime_nsec: i128::from(stat.st_mtime_nsec),
            ctime: i128::from(stat.st_ctime),
            ctime_nsec: i128::from(stat.st_ctime_nsec),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncludedEntryKind {
    Directory,
    File,
}

#[derive(Debug)]
struct Traversal<'a> {
    cancellation: &'a AtomicBool,
    physical_entries: usize,
}

impl Traversal<'_> {
    fn check_cancelled(&self) -> Result<(), VerificationInputError> {
        if self.cancellation.load(Ordering::Acquire) {
            Err(VerificationInputError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn count_entry(&mut self) -> Result<(), VerificationInputError> {
        self.physical_entries = self.physical_entries.checked_add(1).ok_or(
            VerificationInputError::ScanLimitExceeded {
                maximum: MAX_VERIFICATION_SCAN_ENTRIES,
            },
        )?;
        if self.physical_entries > MAX_VERIFICATION_SCAN_ENTRIES {
            return Err(VerificationInputError::ScanLimitExceeded {
                maximum: MAX_VERIFICATION_SCAN_ENTRIES,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ManifestBuilder {
    entries: Vec<VerificationInputEntry>,
    path_bytes: usize,
    file_count: usize,
    total_bytes: u64,
}

impl ManifestBuilder {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            path_bytes: 0,
            file_count: 0,
            total_bytes: 0,
        }
    }

    fn push(&mut self, entry: VerificationInputEntry) -> Result<(), VerificationInputError> {
        if self.entries.len() >= MAX_VERIFICATION_INPUT_ENTRIES {
            return Err(VerificationInputManifestError::EntryCapacity.into());
        }
        self.path_bytes = self
            .path_bytes
            .checked_add(entry.path().as_path().as_os_str().as_encoded_bytes().len())
            .ok_or(VerificationInputManifestError::PathCapacity)?;
        if self.path_bytes > MAX_VERIFICATION_INPUT_PATH_BYTES {
            return Err(VerificationInputManifestError::PathCapacity.into());
        }
        if let VerificationInputEntryKind::File { size, .. } = entry.kind() {
            self.file_count = self
                .file_count
                .checked_add(1)
                .ok_or(VerificationInputManifestError::FileCapacity)?;
            if self.file_count > MAX_VERIFICATION_INPUT_FILES {
                return Err(VerificationInputManifestError::FileCapacity.into());
            }
            self.total_bytes = self
                .total_bytes
                .checked_add(size.get())
                .ok_or(VerificationInputManifestError::ByteCapacity)?;
            if self.total_bytes > MAX_VERIFICATION_INPUT_BYTES {
                return Err(VerificationInputManifestError::ByteCapacity.into());
            }
        }
        self.entries.push(entry);
        Ok(())
    }

    fn finish(self) -> Result<VerificationInputManifest, VerificationInputError> {
        VerificationInputManifest::new(VerificationInputPolicy::V1, self.entries)
            .map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileObservation {
    mode: u16,
    size: u64,
    hash: FileContentHash,
}

/// A source tree staged for atomic publication.
#[must_use]
pub struct StagedVerificationInput {
    id: VerificationInputId,
    manifest: VerificationInputManifest,
    state_gate: WorkspaceStateSharedGate,
    pending: OwnedFd,
    pending_identity: super::DirectoryIdentity,
    artifacts: OwnedFd,
    artifacts_identity: super::DirectoryIdentity,
    root: OwnedFd,
    root_identity: super::DirectoryIdentity,
    state_identity: super::DirectoryIdentity,
    workspace_root: PathBuf,
    pending_name: OsString,
    publication_uncertain: Mutex<bool>,
    #[cfg(test)]
    publish_fault: Option<VerificationInputPublishFault>,
}

impl std::fmt::Debug for StagedVerificationInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedVerificationInput")
            .field("id", &self.id)
            .field("files", &self.manifest.file_count())
            .field("bytes", &self.manifest.total_bytes())
            .finish_non_exhaustive()
    }
}

impl StagedVerificationInput {
    pub const fn id(&self) -> VerificationInputId {
        self.id
    }

    pub const fn manifest(&self) -> &VerificationInputManifest {
        &self.manifest
    }

    /// Publish with no replacement and validate the complete sealed artifact.
    ///
    /// After `PublicationUnconfirmed`, use exact ID/fingerprint readback; this
    /// stage cannot retry publication or repair a partially sealed artifact.
    pub fn publish(&self) -> Result<PublishedVerificationInput, VerificationInputError> {
        // Serialize before validation: a second publisher must never thaw an
        // inode that the first publisher has already returned to a consumer.
        let mut uncertain = self
            .publication_uncertain
            .lock()
            .map_err(|_| self.publication_unconfirmed(VerificationInputError::SnapshotInvalid))?;
        if *uncertain {
            return Err(self.publication_unconfirmed(VerificationInputError::SnapshotStale));
        }
        let result = self.publish_once();
        if matches!(
            &result,
            Err(VerificationInputError::PublicationUnconfirmed { .. })
        ) {
            *uncertain = true;
        }
        result
    }

    fn publish_once(&self) -> Result<PublishedVerificationInput, VerificationInputError> {
        validate_stage(self)?;
        if open_directory_entry(&self.artifacts, &final_name(self.id))?.is_some() {
            return Err(VerificationInputError::Collision);
        }
        self.rename_pending_entry()?;
        self.finish_publication()
            .map_err(|source| self.publication_unconfirmed(source))
    }

    fn rename_pending_entry(&self) -> Result<(), VerificationInputError> {
        // macOS 15 rejects renaming a read-only directory. Only the private
        // container gets owner-write; source and manifest remain sealed.
        #[cfg(target_os = "macos")]
        fchmod(&self.pending, sealed_mode(0o755) | Mode::WUSR)
            .map_err(|source| fs_error(FilesystemOperation::SetTemporaryMode, source))?;
        let rename = renameat_with(
            &self.artifacts,
            &self.pending_name,
            &self.artifacts,
            final_name(self.id),
            RenameFlags::NOREPLACE,
        );
        #[cfg(target_os = "macos")]
        {
            #[cfg(test)]
            if self.publish_fault == Some(VerificationInputPublishFault::Reseal) {
                return Err(self.publication_unconfirmed(VerificationInputError::SnapshotInvalid));
            }
            // Restore the same owned inode even when rename failed. A failed
            // restore is uncertain even if the rename reported a collision.
            seal_directory(&self.pending, 0o755)
                .and_then(|()| sync_directory_fd(&self.pending))
                .map_err(|source| self.publication_unconfirmed(source))?;
        }
        match rename {
            Ok(()) => Ok(()),
            Err(Errno::EXIST) => Err(VerificationInputError::Collision),
            Err(source) if [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::NOSYS].contains(&source) => {
                Err(VerificationInputError::AtomicPublishUnsupported)
            }
            Err(source) => Err(fs_error(FilesystemOperation::PublishTemporary, source)),
        }
    }

    fn finish_publication(&self) -> Result<PublishedVerificationInput, VerificationInputError> {
        #[cfg(test)]
        if self.publish_fault == Some(VerificationInputPublishFault::AfterRenameSync) {
            return Err(fs_error(FilesystemOperation::SyncParent, Errno::IO));
        }
        fsync(&self.artifacts)
            .map_err(|source| fs_error(FilesystemOperation::SyncParent, source))?;
        let final_fd = open_directory_entry(&self.artifacts, &final_name(self.id))?
            .ok_or(VerificationInputError::SnapshotInvalid)?;
        let final_identity = directory_identity(&final_fd)?;
        if final_identity != self.pending_identity {
            return Err(VerificationInputError::SnapshotStale);
        }
        let published = published_from_parts(PublishedInputParts {
            id: self.id,
            manifest: self.manifest.clone(),
            root: dup(&self.root).map_err(map_dup_error)?,
            root_identity: self.root_identity,
            state_identity: self.state_identity,
            artifacts: dup(&self.artifacts).map_err(map_dup_error)?,
            artifacts_identity: self.artifacts_identity,
            final_root: final_fd,
            final_identity,
            workspace_root: &self.workspace_root,
        })?;
        published.validate()?;
        Ok(published)
    }

    fn publication_unconfirmed(&self, source: VerificationInputError) -> VerificationInputError {
        VerificationInputError::PublicationUnconfirmed {
            id: self.id,
            fingerprint: self.manifest.fingerprint(),
            source: Box::new(source),
        }
    }

    /// Abandon only the pending directory created by this stage.
    pub fn abandon(self) -> Result<(), VerificationInputError> {
        self.state_gate
            .ensure_root_binding()
            .map_err(VerificationInputError::StateGate)?;
        remove_pending(&self.artifacts, &self.pending_name, self.pending_identity)
    }
}

/// An atomically published, read-only verification input.
#[must_use]
pub struct PublishedVerificationInput {
    id: VerificationInputId,
    manifest: VerificationInputManifest,
    state_gate: WorkspaceStateSharedGate,
    root: OwnedFd,
    root_identity: super::DirectoryIdentity,
    state_identity: super::DirectoryIdentity,
    artifacts: OwnedFd,
    artifacts_identity: super::DirectoryIdentity,
    final_root: OwnedFd,
    final_identity: super::DirectoryIdentity,
    source_root: OwnedFd,
    source_identity: super::DirectoryIdentity,
    source_root_path: PathBuf,
}

impl std::fmt::Debug for PublishedVerificationInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishedVerificationInput")
            .field("id", &self.id)
            .field("files", &self.manifest.file_count())
            .field("bytes", &self.manifest.total_bytes())
            .finish_non_exhaustive()
    }
}

impl PublishedVerificationInput {
    pub const fn id(&self) -> VerificationInputId {
        self.id
    }

    pub const fn manifest(&self) -> &VerificationInputManifest {
        &self.manifest
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root_path
    }

    /// Revalidate the published snapshot and all V1 coverage entries.
    pub fn validate(&self) -> Result<(), VerificationInputError> {
        validate_published_bindings(self)?;
        validate_stage_parts(&self.final_root, &self.manifest)?;
        validate_published_bindings(self)
    }

    /// Read one manifested snapshot file through its descriptor boundary.
    pub fn read_file(
        &self,
        path: &WorkspaceRelativePath,
        maximum_bytes: usize,
        cancellation: &AtomicBool,
    ) -> Result<Vec<u8>, VerificationInputError> {
        if maximum_bytes > MAX_FILE_READ_BYTES {
            return Err(VerificationInputError::ReadTooLarge {
                maximum: MAX_FILE_READ_BYTES,
            });
        }
        self.read_snapshot_file(path, maximum_bytes, cancellation)
    }

    /// Read a complete manifested file for an isolated verification launch.
    /// The V1 manifest's file limit applies; interactive reads retain their
    /// smaller limit. This never reads live Workspace source.
    pub fn read_execution_file(
        &self,
        path: &WorkspaceRelativePath,
        cancellation: &AtomicBool,
    ) -> Result<Vec<u8>, VerificationInputError> {
        let maximum = usize::try_from(MAX_VERIFICATION_INPUT_FILE_BYTES).map_err(|_| {
            VerificationInputError::ReadTooLarge {
                maximum: usize::MAX,
            }
        })?;
        self.read_snapshot_file(path, maximum, cancellation)
    }

    fn read_snapshot_file(
        &self,
        path: &WorkspaceRelativePath,
        maximum_bytes: usize,
        cancellation: &AtomicBool,
    ) -> Result<Vec<u8>, VerificationInputError> {
        check_cancelled(cancellation)?;
        validate_published_bindings(self)?;
        let expected = self
            .manifest
            .entries()
            .iter()
            .find(|entry| entry.path() == path)
            .ok_or(VerificationInputError::FileUnavailable)?;
        let VerificationInputEntryKind::File {
            size: expected_size,
            content_hash: expected_hash,
        } = expected.kind()
        else {
            return Err(VerificationInputError::FileUnavailable);
        };
        let components = path_components(path)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(VerificationInputError::FileUnavailable)?;
        let parent = walk_directories(&self.source_root, ancestors, false)?;
        let Some(fd) = open_regular_leaf(&parent, basename)? else {
            return Err(VerificationInputError::FileUnavailable);
        };
        let state = node_state_fd(&fd)?;
        if !sealed_mode_matches_mode(state.mode, expected.mode()) {
            return Err(VerificationInputError::SnapshotInvalid);
        }
        let captured = read_leaf_bounded(fd, maximum_bytes)?;
        if captured.size != expected_size.get() || captured.hash != expected_hash {
            return Err(VerificationInputError::SnapshotInvalid);
        }
        check_cancelled(cancellation)?;
        Ok(captured.content)
    }
}

impl ConfinedWorkspace {
    /// Observe the complete V1 project input without creating Forge state.
    pub fn observe_verification_input(
        &self,
        cancellation: &AtomicBool,
    ) -> Result<VerificationInputManifest, VerificationInputError> {
        let _state_gate = acquire_state_gate(&self.workspace_root, self.root_identity)?;
        check_cancelled(cancellation)?;
        self.ensure_root()?;
        let manifest = collect_manifest(&self.root, cancellation, false)?;
        self.ensure_root()?;
        Ok(manifest)
    }

    /// Capture and stage a complete V1 project input under Forge-owned state.
    pub fn stage_verification_input(
        &self,
        id: VerificationInputId,
        cancellation: &AtomicBool,
    ) -> Result<StagedVerificationInput, VerificationInputError> {
        check_cancelled(cancellation)?;
        self.ensure_root()?;
        let state_gate = acquire_state_gate(&self.workspace_root, self.root_identity)?;
        let _mutation_lock = self.acquire_mutation_lock()?;
        self.ensure_root()?;
        check_cancelled(cancellation)?;

        let artifacts = open_verification_directory(self, true)?;
        let artifacts_identity = directory_identity(&artifacts)?;
        let pending_name = pending_name(id);
        create_directory(&artifacts, &pending_name, temporary_directory_mode())?;
        let pending = open_directory_entry(&artifacts, &pending_name)?
            .ok_or(VerificationInputError::SnapshotInvalid)?;
        let pending_identity = directory_identity(&pending)?;

        let result = stage_capture(
            self,
            cancellation,
            &artifacts,
            artifacts_identity,
            CaptureStage {
                id,
                pending_name: pending_name.clone(),
                pending,
                pending_identity,
                state_gate,
            },
        );
        match result {
            Ok(staged) => Ok(staged),
            Err(error) => {
                if remove_pending(&artifacts, &pending_name, pending_identity).is_err() {
                    return Err(VerificationInputError::CleanupFailed);
                }
                Err(error)
            }
        }
    }

    /// Open one already-published input after matching its exact manifest
    /// fingerprint. This method never creates or repairs artifact state.
    pub fn open_verification_input(
        &self,
        id: VerificationInputId,
        expected_fingerprint: VerificationInputFingerprint,
    ) -> Result<PublishedVerificationInput, VerificationInputError> {
        let _state_gate = acquire_state_gate(&self.workspace_root, self.root_identity)?;
        self.ensure_root()?;
        let artifacts = open_verification_directory(self, false)?;
        let artifacts_identity = directory_identity(&artifacts)?;
        let final_name = final_name(id);
        let final_root = open_directory_entry(&artifacts, &final_name)?
            .ok_or(VerificationInputError::NotFound)?;
        let final_identity = directory_identity(&final_root)?;
        let manifest = read_manifest(&final_root)?;
        if manifest.fingerprint() != expected_fingerprint {
            return Err(VerificationInputError::FingerprintMismatch);
        }
        let published = published_from_parts(PublishedInputParts {
            id,
            manifest,
            root: dup(&self.root).map_err(map_dup_error)?,
            root_identity: self.root_identity,
            state_identity: self.state_identity,
            artifacts,
            artifacts_identity,
            final_root,
            final_identity,
            workspace_root: &self.workspace_root,
        })?;
        published.validate()?;
        Ok(published)
    }

    /// Remove one server-derived published verification input and any matching
    /// pending capture. The exclusive Workspace gate and mutation guard fence
    /// the entire bounded effect; no caller path is accepted.
    pub fn purge_verification_input(
        &self,
        gate: &WorkspaceStateExclusiveGate,
        guard: &ConfinedWorkspaceWriteGuard,
        id: VerificationInputId,
        expected_fingerprint: VerificationInputFingerprint,
        expected_bytes: u64,
        cancellation: &AtomicBool,
    ) -> Result<VerificationInputCleanupStatus, VerificationInputError> {
        self.purge_verification_input_inner(
            gate,
            guard,
            VerificationInputCleanupExpectation {
                id,
                fingerprint: expected_fingerprint,
                bytes: expected_bytes,
            },
            cancellation,
            None,
        )
    }

    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        reason = "test-only fault injection extends the public cleanup contract"
    )]
    pub(super) fn purge_verification_input_with_fault(
        &self,
        gate: &WorkspaceStateExclusiveGate,
        guard: &ConfinedWorkspaceWriteGuard,
        id: VerificationInputId,
        expected_fingerprint: VerificationInputFingerprint,
        expected_bytes: u64,
        cancellation: &AtomicBool,
        fault: VerificationInputCleanupFault,
    ) -> Result<VerificationInputCleanupStatus, VerificationInputError> {
        self.purge_verification_input_inner(
            gate,
            guard,
            VerificationInputCleanupExpectation {
                id,
                fingerprint: expected_fingerprint,
                bytes: expected_bytes,
            },
            cancellation,
            Some(fault),
        )
    }

    fn purge_verification_input_inner(
        &self,
        gate: &WorkspaceStateExclusiveGate,
        guard: &ConfinedWorkspaceWriteGuard,
        expected: VerificationInputCleanupExpectation,
        cancellation: &AtomicBool,
        #[cfg(test)] mut fault: Option<VerificationInputCleanupFault>,
        #[cfg(not(test))] _fault: Option<()>,
    ) -> Result<VerificationInputCleanupStatus, VerificationInputError> {
        self.ensure_state_removal_binding(gate, guard)
            .map_err(VerificationInputError::Filesystem)?;
        check_cancelled(cancellation)?;
        let artifacts = match open_verification_directory(self, false) {
            Ok(artifacts) => artifacts,
            Err(VerificationInputError::NotFound) => {
                return Ok(VerificationInputCleanupStatus::AlreadyMissing);
            }
            Err(error) => return Err(error),
        };
        let final_name = final_name(expected.id);
        let pending_name = pending_name(expected.id);
        let mut observed = false;
        if let Some(final_root) = open_directory_entry(&artifacts, &final_name)? {
            observed = true;
            let manifest = read_manifest(&final_root);
            let manifest = match manifest {
                Ok(manifest) => manifest,
                Err(VerificationInputError::SnapshotInvalid)
                    if open_directory_entry(&final_root, OsStr::new(SOURCE_DIRECTORY))?
                        .is_none()
                        && directory_is_empty(&final_root)? =>
                {
                    unlinkat(&artifacts, &final_name, AtFlags::REMOVEDIR).map_err(|source| {
                        fs_error(FilesystemOperation::CleanupTemporary, source)
                    })?;
                    fsync(&artifacts)
                        .map_err(|source| fs_error(FilesystemOperation::SyncParent, source))?;
                    return Ok(VerificationInputCleanupStatus::Deleted);
                }
                Err(error) => return Err(error),
            };
            if manifest.fingerprint() != expected.fingerprint
                || manifest.total_bytes().get() != expected.bytes
            {
                return Err(VerificationInputError::FingerprintMismatch);
            }
            fchmod(&final_root, temporary_directory_mode())
                .map_err(|source| fs_error(FilesystemOperation::SetTemporaryMode, source))?;
            #[cfg(test)]
            if fault == Some(VerificationInputCleanupFault::AfterChmod) {
                return Err(VerificationInputError::CleanupFailed);
            }
            purge_snapshot_source(
                &final_root,
                &manifest,
                cancellation,
                #[cfg(test)]
                &mut fault,
            )?;
            check_cancelled(cancellation)?;
            unlinkat(&final_root, OsStr::new(MANIFEST_FILE), AtFlags::empty())
                .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
            #[cfg(test)]
            if fault == Some(VerificationInputCleanupFault::AfterManifestUnlink) {
                return Err(VerificationInputError::CleanupFailed);
            }
            fsync(&final_root)
                .map_err(|source| fs_error(FilesystemOperation::SyncTemporary, source))?;
            unlinkat(&artifacts, &final_name, AtFlags::REMOVEDIR)
                .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
        }
        if let Some(pending) = open_directory_entry(&artifacts, &pending_name)? {
            observed = true;
            let manifest = read_manifest(&pending)?;
            if manifest.fingerprint() != expected.fingerprint
                || manifest.total_bytes().get() != expected.bytes
            {
                return Err(VerificationInputError::FingerprintMismatch);
            }
            let mut entries = 0_usize;
            remove_snapshot_directory(
                &pending,
                Path::new(""),
                &manifest,
                &mut entries,
                0,
                cancellation,
                #[cfg(test)]
                &mut fault,
            )?;
            unlinkat(&artifacts, &pending_name, AtFlags::REMOVEDIR)
                .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
        }
        fsync(&artifacts).map_err(|source| fs_error(FilesystemOperation::SyncParent, source))?;
        self.ensure_state_removal_binding(gate, guard)
            .map_err(VerificationInputError::Filesystem)?;
        Ok(if observed {
            VerificationInputCleanupStatus::Deleted
        } else {
            VerificationInputCleanupStatus::AlreadyMissing
        })
    }
}

fn purge_snapshot_source(
    final_root: &OwnedFd,
    manifest: &VerificationInputManifest,
    cancellation: &AtomicBool,
    #[cfg(test)] fault: &mut Option<VerificationInputCleanupFault>,
) -> Result<(), VerificationInputError> {
    let Some(source) = open_directory_entry(final_root, OsStr::new(SOURCE_DIRECTORY))? else {
        return Ok(());
    };
    let mut entries = 0_usize;
    remove_snapshot_directory(
        &source,
        Path::new(""),
        manifest,
        &mut entries,
        0,
        cancellation,
        #[cfg(test)]
        fault,
    )?;
    let source_identity = directory_identity(&source)?;
    let current_source = open_directory_entry(final_root, OsStr::new(SOURCE_DIRECTORY))?
        .ok_or(VerificationInputError::SnapshotStale)?;
    if directory_identity(&current_source)? != source_identity {
        return Err(VerificationInputError::SnapshotStale);
    }
    unlinkat(final_root, OsStr::new(SOURCE_DIRECTORY), AtFlags::REMOVEDIR)
        .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
    Ok(())
}

struct CaptureStage {
    id: VerificationInputId,
    pending_name: OsString,
    pending: OwnedFd,
    pending_identity: super::DirectoryIdentity,
    state_gate: WorkspaceStateSharedGate,
}

fn stage_capture(
    workspace: &ConfinedWorkspace,
    cancellation: &AtomicBool,
    artifacts: &OwnedFd,
    artifacts_identity: super::DirectoryIdentity,
    stage: CaptureStage,
) -> Result<StagedVerificationInput, VerificationInputError> {
    let CaptureStage {
        id,
        pending_name,
        pending,
        pending_identity,
        state_gate,
    } = stage;
    let pending_stat = fstat(&pending).map_err(super::pre_syscall)?;
    let pending_state = NodeState::from_stat(&pending_stat);
    if !is_directory_state(&pending_state) {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    check_cancelled(cancellation)?;
    let source_stat = fstat(&workspace.root).map_err(super::pre_syscall)?;
    let source_state = NodeState::from_stat(&source_stat);
    if !is_directory_state(&source_state) || source_state.mode & 0o7000 != 0 {
        return Err(VerificationInputError::SnapshotStale);
    }
    create_directory(
        &pending,
        OsStr::new(SOURCE_DIRECTORY),
        temporary_directory_mode(),
    )?;
    let copied_root = open_directory_entry(&pending, OsStr::new(SOURCE_DIRECTORY))?
        .ok_or(VerificationInputError::SnapshotInvalid)?;
    let mut traversal = Traversal {
        cancellation,
        physical_entries: 0,
    };
    let mut builder = ManifestBuilder::new();
    capture_directory(
        &workspace.root,
        &copied_root,
        Path::new(""),
        &mut traversal,
        &mut builder,
    )?;
    seal_directory(&copied_root, normalized_mode_from_stat(&source_stat))?;
    sync_directory_fd(&copied_root)?;
    let source_after = NodeState::from_stat(&fstat(&workspace.root).map_err(super::pre_syscall)?);
    if source_after != source_state {
        return Err(VerificationInputError::SnapshotStale);
    }
    let manifest = builder.finish()?;

    check_cancelled(cancellation)?;
    let observed = collect_manifest(&workspace.root, cancellation, false)?;
    if observed != manifest {
        return Err(VerificationInputError::SnapshotStale);
    }
    write_manifest(&pending, &manifest)?;
    seal_directory(&pending, 0o755)?;
    sync_directory_fd(&pending)?;
    validate_stage_parts(&pending, &manifest)?;
    ensure_directory_identity(artifacts, artifacts_identity, false)?;
    workspace.ensure_root()?;
    Ok(StagedVerificationInput {
        id,
        manifest,
        state_gate,
        pending,
        pending_identity,
        artifacts: dup(artifacts).map_err(map_dup_error)?,
        artifacts_identity,
        root: dup(&workspace.root).map_err(map_dup_error)?,
        root_identity: workspace.root_identity,
        state_identity: workspace.state_identity,
        workspace_root: workspace.workspace_root.clone(),
        pending_name,
        publication_uncertain: Mutex::new(false),
        #[cfg(test)]
        publish_fault: None,
    })
}

struct PublishedInputParts<'a> {
    id: VerificationInputId,
    manifest: VerificationInputManifest,
    root: OwnedFd,
    root_identity: super::DirectoryIdentity,
    state_identity: super::DirectoryIdentity,
    artifacts: OwnedFd,
    artifacts_identity: super::DirectoryIdentity,
    final_root: OwnedFd,
    final_identity: super::DirectoryIdentity,
    workspace_root: &'a Path,
}

fn published_from_parts(
    parts: PublishedInputParts<'_>,
) -> Result<PublishedVerificationInput, VerificationInputError> {
    let PublishedInputParts {
        id,
        manifest,
        root,
        root_identity,
        state_identity,
        artifacts,
        artifacts_identity,
        final_root,
        final_identity,
        workspace_root,
    } = parts;
    let source_root = open_directory_entry(&final_root, OsStr::new(SOURCE_DIRECTORY))?
        .ok_or(VerificationInputError::SnapshotInvalid)?;
    let source_identity = directory_identity(&source_root)?;
    let state_gate = acquire_state_gate(workspace_root, root_identity)?;
    Ok(PublishedVerificationInput {
        id,
        manifest,
        state_gate,
        root,
        root_identity,
        state_identity,
        artifacts,
        artifacts_identity,
        final_root,
        final_identity,
        source_root,
        source_identity,
        source_root_path: workspace_root
            .join(STATE_DIRECTORY)
            .join("artifacts")
            .join(VERIFICATION_DIRECTORY)
            .join(id.to_string())
            .join(SOURCE_DIRECTORY),
    })
}

fn validate_stage(stage: &StagedVerificationInput) -> Result<(), VerificationInputError> {
    stage
        .state_gate
        .ensure_root_binding()
        .map_err(VerificationInputError::StateGate)?;
    ensure_directory_identity(&stage.root, stage.root_identity, false)?;
    let owned_state = openat(
        &stage.root,
        STATE_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| fs_error(FilesystemOperation::OpenStateDirectory, source))?;
    ensure_directory_identity(&owned_state, stage.state_identity, false)?;
    ensure_directory_identity(&stage.artifacts, stage.artifacts_identity, false)?;
    ensure_directory_identity(&stage.pending, stage.pending_identity, false)?;
    let current = statat(
        &stage.artifacts,
        &stage.pending_name,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|source| map_entry_stat_error(source, false))?;
    if NodeState::from_stat(&current) != node_state_fd(&stage.pending)? {
        return Err(VerificationInputError::SnapshotStale);
    }
    validate_stage_parts(&stage.pending, &stage.manifest)
}

fn validate_published_bindings(
    published: &PublishedVerificationInput,
) -> Result<(), VerificationInputError> {
    published
        .state_gate
        .ensure_root_binding()
        .map_err(VerificationInputError::StateGate)?;
    ensure_directory_identity(&published.root, published.root_identity, false)?;
    let state = openat(
        &published.root,
        STATE_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| fs_error(FilesystemOperation::OpenStateDirectory, source))?;
    ensure_directory_identity(&state, published.state_identity, false)?;
    ensure_directory_identity(&published.artifacts, published.artifacts_identity, false)?;
    ensure_directory_identity(&published.final_root, published.final_identity, false)?;
    ensure_directory_identity(&published.source_root, published.source_identity, false)?;
    let final_state = node_state_fd(&published.final_root)?;
    let source_state = node_state_fd(&published.source_root)?;
    if !is_directory_state(&final_state)
        || final_state.mode & SEALED_WRITE_MASK != 0
        || !is_directory_state(&source_state)
        || source_state.mode & SEALED_WRITE_MASK != 0
    {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    let current = statat(
        &published.artifacts,
        final_name(published.id),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|source| map_entry_stat_error(source, false))?;
    if NodeState::from_stat(&current) != node_state_fd(&published.final_root)? {
        return Err(VerificationInputError::SnapshotStale);
    }
    Ok(())
}

fn check_cancelled(cancellation: &AtomicBool) -> Result<(), VerificationInputError> {
    if cancellation.load(Ordering::Acquire) {
        Err(VerificationInputError::Cancelled)
    } else {
        Ok(())
    }
}

fn acquire_state_gate(
    workspace_root: &Path,
    root_identity: super::DirectoryIdentity,
) -> Result<WorkspaceStateSharedGate, VerificationInputError> {
    WorkspaceStateSharedGate::acquire(workspace_root, root_identity.fingerprint())
        .map_err(VerificationInputError::StateGate)
}

fn fs_error(operation: FilesystemOperation, source: Errno) -> VerificationInputError {
    VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
        operation,
        committed: false,
        source,
    })
}

fn map_dup_error(source: Errno) -> VerificationInputError {
    fs_error(FilesystemOperation::DuplicateRoot, source)
}

fn is_directory_state(state: &NodeState) -> bool {
    state.is_directory
}

fn node_state_fd(fd: &OwnedFd) -> Result<NodeState, VerificationInputError> {
    Ok(NodeState::from_stat(
        &fstat(fd).map_err(super::pre_syscall)?,
    ))
}

fn mode_bits_from_stat(stat: &Stat) -> u32 {
    #[cfg(target_os = "linux")]
    {
        Mode::from_raw_mode(stat.st_mode).bits()
    }
    #[cfg(not(target_os = "linux"))]
    {
        u32::from(Mode::from_raw_mode(stat.st_mode).bits())
    }
}

fn normalized_mode_from_stat(stat: &Stat) -> u16 {
    (mode_bits_from_stat(stat) & 0o777) as u16
}

fn sealed_mode(mode: u16) -> Mode {
    #[cfg(target_os = "linux")]
    {
        Mode::from_bits_retain(u32::from(mode & !SEALED_WRITE_MASK))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Mode::from_bits_retain(mode & !SEALED_WRITE_MASK)
    }
}

fn sealed_mode_matches(stat: &Stat, original_mode: u16) -> bool {
    let actual = normalized_mode_from_stat(stat);
    sealed_mode_matches_mode(actual, original_mode)
}

fn sealed_mode_matches_mode(actual: u16, original_mode: u16) -> bool {
    actual & SEALED_WRITE_MASK == 0 && actual == original_mode & !SEALED_WRITE_MASK
}

fn encode_manifest(
    manifest: &VerificationInputManifest,
) -> Result<Vec<u8>, VerificationInputError> {
    let mut text = String::new();
    push_manifest_line(&mut text, format_args!("{MANIFEST_HEADER}\n"))?;
    push_manifest_line(
        &mut text,
        format_args!("policy\t{}\n", manifest.policy().version()),
    )?;
    push_manifest_line(
        &mut text,
        format_args!("fingerprint\t{}\n", manifest.fingerprint()),
    )?;
    push_manifest_line(
        &mut text,
        format_args!("entries\t{}\n", manifest.entries().len()),
    )?;
    for entry in manifest.entries() {
        let path = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(entry.path().as_path().as_os_str().as_encoded_bytes());
        match entry.kind() {
            VerificationInputEntryKind::Directory => push_manifest_line(
                &mut text,
                format_args!("directory\t{:o}\t{path}\n", entry.mode()),
            )?,
            VerificationInputEntryKind::File { size, content_hash } => push_manifest_line(
                &mut text,
                format_args!(
                    "file\t{:o}\t{}\t{}\t{path}\n",
                    entry.mode(),
                    size.get(),
                    content_hash
                ),
            )?,
        }
    }
    Ok(text.into_bytes())
}

fn push_manifest_line(
    text: &mut String,
    line: std::fmt::Arguments<'_>,
) -> Result<(), VerificationInputError> {
    text.write_fmt(line)
        .map_err(|_| VerificationInputError::ManifestMalformed)?;
    if text.len() > MAX_VERIFICATION_INPUT_MANIFEST_BYTES {
        return Err(VerificationInputError::ManifestTooLarge {
            maximum: MAX_VERIFICATION_INPUT_MANIFEST_BYTES,
        });
    }
    Ok(())
}

fn decode_manifest(bytes: &[u8]) -> Result<VerificationInputManifest, VerificationInputError> {
    if bytes.len() > MAX_VERIFICATION_INPUT_MANIFEST_BYTES || !bytes.ends_with(b"\n") {
        return Err(if bytes.len() > MAX_VERIFICATION_INPUT_MANIFEST_BYTES {
            VerificationInputError::ManifestTooLarge {
                maximum: MAX_VERIFICATION_INPUT_MANIFEST_BYTES,
            }
        } else {
            VerificationInputError::ManifestMalformed
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| VerificationInputError::ManifestMalformed)?;
    let mut lines = text.split_terminator('\n');
    if lines.next() != Some(MANIFEST_HEADER) {
        return Err(VerificationInputError::ManifestMalformed);
    }
    let policy = VerificationInputPolicy::from_version(
        parse_field(&mut lines, "policy")?
            .parse()
            .map_err(|_| VerificationInputError::ManifestMalformed)?,
    )?;
    let fingerprint =
        VerificationInputFingerprint::from_str(parse_field(&mut lines, "fingerprint")?)
            .map_err(|_| VerificationInputError::ManifestMalformed)?;
    let entry_count = parse_field(&mut lines, "entries")?
        .parse::<usize>()
        .map_err(|_| VerificationInputError::ManifestMalformed)?;
    if entry_count > MAX_VERIFICATION_INPUT_ENTRIES {
        return Err(VerificationInputManifestError::EntryCapacity.into());
    }
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let line = lines
            .next()
            .ok_or(VerificationInputError::ManifestMalformed)?;
        let mut fields = line.split('\t');
        let kind = fields
            .next()
            .ok_or(VerificationInputError::ManifestMalformed)?;
        let mode = parse_mode(
            fields
                .next()
                .ok_or(VerificationInputError::ManifestMalformed)?,
        )?;
        let entry = match kind {
            "directory" => {
                let path = decode_manifest_path(
                    fields
                        .next()
                        .ok_or(VerificationInputError::ManifestMalformed)?,
                )?;
                if fields.next().is_some() {
                    return Err(VerificationInputError::ManifestMalformed);
                }
                VerificationInputEntry::directory(path, mode)?
            }
            "file" => {
                let size = fields
                    .next()
                    .ok_or(VerificationInputError::ManifestMalformed)?
                    .parse::<u64>()
                    .map_err(|_| VerificationInputError::ManifestMalformed)?;
                let content_hash = fields
                    .next()
                    .ok_or(VerificationInputError::ManifestMalformed)?
                    .parse::<FileContentHash>()
                    .map_err(|_| VerificationInputError::ManifestMalformed)?;
                let path = decode_manifest_path(
                    fields
                        .next()
                        .ok_or(VerificationInputError::ManifestMalformed)?,
                )?;
                if fields.next().is_some() {
                    return Err(VerificationInputError::ManifestMalformed);
                }
                VerificationInputEntry::file(path, mode, FileByteCount::new(size), content_hash)?
            }
            _ => return Err(VerificationInputError::ManifestMalformed),
        };
        entries.push(entry);
    }
    if lines.next().is_some() {
        return Err(VerificationInputError::ManifestMalformed);
    }
    for pair in entries.windows(2) {
        let left = pair[0].path().as_path().as_os_str().as_encoded_bytes();
        let right = pair[1].path().as_path().as_os_str().as_encoded_bytes();
        if left >= right {
            return Err(VerificationInputError::ManifestMalformed);
        }
    }
    let manifest = VerificationInputManifest::new(policy, entries)?;
    if manifest.fingerprint() != fingerprint {
        return Err(VerificationInputError::ManifestMalformed);
    }
    Ok(manifest)
}

fn parse_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<&'a str, VerificationInputError> {
    let line = lines
        .next()
        .ok_or(VerificationInputError::ManifestMalformed)?;
    let mut fields = line.split('\t');
    if fields.next() != Some(key) {
        return Err(VerificationInputError::ManifestMalformed);
    }
    let value = fields
        .next()
        .ok_or(VerificationInputError::ManifestMalformed)?;
    if fields.next().is_some() {
        return Err(VerificationInputError::ManifestMalformed);
    }
    Ok(value)
}

fn parse_mode(value: &str) -> Result<u16, VerificationInputError> {
    if value.is_empty() {
        return Err(VerificationInputError::ManifestMalformed);
    }
    let mode =
        u16::from_str_radix(value, 8).map_err(|_| VerificationInputError::ManifestMalformed)?;
    if format!("{mode:o}") != value {
        return Err(VerificationInputError::ManifestMalformed);
    }
    Ok(mode)
}

fn decode_manifest_path(value: &str) -> Result<WorkspaceRelativePath, VerificationInputError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| VerificationInputError::ManifestMalformed)?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(VerificationInputError::ManifestMalformed);
    }
    WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(bytes)))
        .map_err(|_| VerificationInputError::ManifestMalformed)
}

fn read_manifest(directory: &OwnedFd) -> Result<VerificationInputManifest, VerificationInputError> {
    let fd = openat(
        directory,
        MANIFEST_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| {
        if source == Errno::NOENT {
            VerificationInputError::SnapshotInvalid
        } else {
            fs_error(FilesystemOperation::ReadLeaf, source)
        }
    })?;
    require_regular_single_link(&fd)?;
    let mut file = File::from(fd);
    let before = node_state_file(&file)?;
    let bytes = read_bounded_file(&mut file, MAX_VERIFICATION_INPUT_MANIFEST_BYTES)?;
    let after = node_state_file(&file)?;
    if after != before
        || !after.is_regular
        || after.nlink != 1
        || after.mode & SEALED_WRITE_MASK != 0
    {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    decode_manifest(&bytes)
}

fn read_bounded_file(file: &mut File, maximum: usize) -> Result<Vec<u8>, VerificationInputError> {
    let mut bytes = Vec::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error(FilesystemOperation::ReadLeaf, source))?;
        if read == 0 {
            break;
        }
        let next = bytes
            .len()
            .checked_add(read)
            .ok_or(VerificationInputError::ManifestTooLarge { maximum })?;
        if next > maximum {
            return Err(VerificationInputError::ManifestTooLarge { maximum });
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

struct BoundedRead {
    content: Vec<u8>,
    size: u64,
    hash: FileContentHash,
}

fn read_leaf_bounded(fd: OwnedFd, maximum: usize) -> Result<BoundedRead, VerificationInputError> {
    let mut file = File::from(fd);
    let before = node_state_file(&file)?;
    if !before.is_regular || before.nlink != 1 {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    let mut content = Vec::new();
    let mut hasher = blake3::Hasher::new();
    let mut size = 0_usize;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error(FilesystemOperation::ReadLeaf, source))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read)
            .ok_or(VerificationInputError::ReadTooLarge { maximum })?;
        if size > maximum {
            return Err(VerificationInputError::ReadTooLarge { maximum });
        }
        content.extend_from_slice(&buffer[..read]);
        hasher.update(&buffer[..read]);
    }
    let after = node_state_file(&file)?;
    if after != before {
        return Err(VerificationInputError::SnapshotStale);
    }
    Ok(BoundedRead {
        content,
        size: u64::try_from(size).map_err(|_| VerificationInputError::ReadTooLarge { maximum })?,
        hash: FileContentHash::from_bytes(*hasher.finalize().as_bytes()),
    })
}

fn write_manifest(
    pending: &OwnedFd,
    manifest: &VerificationInputManifest,
) -> Result<(), VerificationInputError> {
    let bytes = encode_manifest(manifest)?;
    let fd = openat(
        pending,
        MANIFEST_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|source| {
        if source == Errno::EXIST {
            VerificationInputError::Collision
        } else {
            fs_error(FilesystemOperation::CreateTemporary, source)
        }
    })?;
    require_regular_single_link(&fd)?;
    let mut file = File::from(fd);
    file.write_all(&bytes)
        .map_err(|source| io_error(FilesystemOperation::WriteTemporary, source))?;
    sync_file(&file).map_err(|source| fs_error(FilesystemOperation::SyncTemporary, source))?;
    fchmod(&file, sealed_mode(0o644))
        .map_err(|source| fs_error(FilesystemOperation::SetTemporaryMode, source))?;
    sync_file(&file).map_err(|source| fs_error(FilesystemOperation::SyncTemporary, source))?;
    Ok(())
}

fn validate_stage_parts(
    pending: &OwnedFd,
    manifest: &VerificationInputManifest,
) -> Result<(), VerificationInputError> {
    let pending_state = node_state_fd(pending)?;
    if !is_directory_state(&pending_state)
        || pending_state.mode & SEALED_WRITE_MASK != 0
        || pending_state.mode != 0o755 & !SEALED_WRITE_MASK
    {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    ensure_exact_pending_entries(pending)?;
    if read_manifest(pending)? != *manifest {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    let source = open_directory_entry(pending, OsStr::new(SOURCE_DIRECTORY))?
        .ok_or(VerificationInputError::SnapshotInvalid)?;
    let source_state = node_state_fd(&source)?;
    if !is_directory_state(&source_state) || source_state.mode & SEALED_WRITE_MASK != 0 {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    validate_snapshot_tree(&source, manifest)
}

fn ensure_exact_pending_entries(directory: &OwnedFd) -> Result<(), VerificationInputError> {
    let stream = Dir::read_from(directory).map_err(|source| {
        VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenDirectoryStream,
            committed: false,
            source,
        })
    })?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|source| {
            VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::ReadDirectory,
                committed: false,
                source,
            })
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    names.sort_unstable();
    if names != [b"manifest".to_vec(), b"source".to_vec()] {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    Ok(())
}

fn remove_pending(
    artifacts: &OwnedFd,
    pending_name: &OsStr,
    expected_identity: super::DirectoryIdentity,
) -> Result<(), VerificationInputError> {
    let stat = match statat(artifacts, pending_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(()),
        Err(source) => return Err(map_entry_stat_error(source, false)),
    };
    let current = NodeState::from_stat(&stat);
    if !is_directory_state(&current) {
        return Err(VerificationInputError::Collision);
    }
    ensure_directory_identity(
        &open_directory_entry(artifacts, pending_name)?
            .ok_or(VerificationInputError::SnapshotStale)?,
        expected_identity,
        false,
    )?;
    let pending = open_directory_entry(artifacts, pending_name)?
        .ok_or(VerificationInputError::SnapshotStale)?;
    let pending_identity = directory_identity(&pending)?;
    if pending_identity != expected_identity {
        return Err(VerificationInputError::SnapshotStale);
    }
    let mut entries = 0_usize;
    remove_directory_contents(&pending, &mut entries, 0)?;
    let current = statat(artifacts, pending_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| map_entry_stat_error(source, false))?;
    let current_identity = super::directory_identity_from_stat(&current)?;
    if current_identity != expected_identity {
        return Err(VerificationInputError::SnapshotStale);
    }
    unlinkat(artifacts, pending_name, AtFlags::REMOVEDIR)
        .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
    fsync(artifacts).map_err(|source| fs_error(FilesystemOperation::SyncParent, source))?;
    Ok(())
}

fn directory_is_empty(directory: &OwnedFd) -> Result<bool, VerificationInputError> {
    let stream = Dir::read_from(directory).map_err(|source| {
        VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenDirectoryStream,
            committed: false,
            source,
        })
    })?;
    for entry in stream {
        let entry = entry.map_err(|source| {
            VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::ReadDirectory,
                committed: false,
                source,
            })
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Ok(false);
        }
    }
    Ok(true)
}

fn remove_snapshot_directory(
    directory: &OwnedFd,
    relative: &Path,
    manifest: &VerificationInputManifest,
    entries: &mut usize,
    depth: usize,
    cancellation: &AtomicBool,
    #[cfg(test)] fault: &mut Option<VerificationInputCleanupFault>,
) -> Result<(), VerificationInputError> {
    if depth > MAX_FILE_PATH_COMPONENTS {
        return Err(VerificationInputError::ScanLimitExceeded {
            maximum: MAX_FILE_PATH_COMPONENTS,
        });
    }
    check_cancelled(cancellation)?;
    fchmod(directory, temporary_directory_mode())
        .map_err(|source| fs_error(FilesystemOperation::SetTemporaryMode, source))?;
    let stream = Dir::read_from(directory).map_err(|source| {
        VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenDirectoryStream,
            committed: false,
            source,
        })
    })?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|source| {
            VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::ReadDirectory,
                committed: false,
                source,
            })
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            *entries = entries
                .checked_add(1)
                .ok_or(VerificationInputError::ScanLimitExceeded {
                    maximum: MAX_VERIFICATION_SCAN_ENTRIES,
                })?;
            if *entries > MAX_VERIFICATION_SCAN_ENTRIES {
                return Err(VerificationInputError::ScanLimitExceeded {
                    maximum: MAX_VERIFICATION_SCAN_ENTRIES,
                });
            }
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in names {
        check_cancelled(cancellation)?;
        let stat = stat_entry(directory, &name)?;
        let state = NodeState::from_stat(&stat);
        let path = relative_path(relative, &name)?;
        let expected = manifest
            .entries()
            .iter()
            .find(|entry| entry.path().as_path() == path.as_path())
            .ok_or(VerificationInputError::SnapshotInvalid)?;
        match (classify_entry(&stat)?, expected.kind()) {
            (IncludedEntryKind::Directory, VerificationInputEntryKind::Directory) => {
                if !sealed_mode_matches(&stat, expected.mode()) {
                    return Err(VerificationInputError::SnapshotInvalid);
                }
                let child = open_directory_for_scan(directory, &name, state)?;
                remove_snapshot_directory(
                    &child,
                    path.as_path(),
                    manifest,
                    entries,
                    depth + 1,
                    cancellation,
                    #[cfg(test)]
                    fault,
                )?;
                unlinkat(directory, &name, AtFlags::REMOVEDIR)
                    .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
            }
            (
                IncludedEntryKind::File,
                VerificationInputEntryKind::File {
                    size: expected_size,
                    content_hash: expected_hash,
                },
            ) => {
                let observation = observe_file(directory, &name, state)?;
                if observation.size != expected_size.get() || observation.hash != expected_hash {
                    return Err(VerificationInputError::SnapshotInvalid);
                }
                if !sealed_mode_matches(&stat, expected.mode()) {
                    return Err(VerificationInputError::SnapshotInvalid);
                }
                unlinkat(directory, &name, AtFlags::empty())
                    .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
                #[cfg(test)]
                if *fault == Some(VerificationInputCleanupFault::AfterFileDelete) {
                    *fault = None;
                    return Err(VerificationInputError::CleanupFailed);
                }
            }
            _ => return Err(VerificationInputError::SnapshotInvalid),
        }
    }
    Ok(())
}

fn remove_directory_contents(
    directory: &OwnedFd,
    entries: &mut usize,
    depth: usize,
) -> Result<(), VerificationInputError> {
    if depth > MAX_FILE_PATH_COMPONENTS {
        return Err(VerificationInputError::ScanLimitExceeded {
            maximum: MAX_FILE_PATH_COMPONENTS,
        });
    }
    fchmod(directory, temporary_directory_mode())
        .map_err(|source| fs_error(FilesystemOperation::SetTemporaryMode, source))?;
    let stream = Dir::read_from(directory).map_err(|source| {
        VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenDirectoryStream,
            committed: false,
            source,
        })
    })?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|source| {
            VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::ReadDirectory,
                committed: false,
                source,
            })
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            *entries = entries
                .checked_add(1)
                .ok_or(VerificationInputError::ScanLimitExceeded {
                    maximum: MAX_VERIFICATION_SCAN_ENTRIES,
                })?;
            if *entries > MAX_VERIFICATION_SCAN_ENTRIES {
                return Err(VerificationInputError::ScanLimitExceeded {
                    maximum: MAX_VERIFICATION_SCAN_ENTRIES,
                });
            }
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in names {
        let stat = stat_entry(directory, &name)?;
        let state = NodeState::from_stat(&stat);
        let kind = classify_entry(&stat)?;
        match kind {
            IncludedEntryKind::Directory => {
                let child = open_directory_for_scan(directory, &name, state)?;
                let identity = directory_identity(&child)?;
                remove_directory_contents(&child, entries, depth + 1)?;
                if directory_identity(&child)? != identity {
                    return Err(VerificationInputError::SnapshotStale);
                }
                unlinkat(directory, &name, AtFlags::REMOVEDIR)
                    .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
            }
            IncludedEntryKind::File => {
                let file = open_regular_leaf(directory, &name)?
                    .ok_or(VerificationInputError::SnapshotStale)?;
                if node_state_fd(&file)? != state {
                    return Err(VerificationInputError::SnapshotStale);
                }
                drop(file);
                unlinkat(directory, &name, AtFlags::empty())
                    .map_err(|source| fs_error(FilesystemOperation::CleanupTemporary, source))?;
            }
        }
    }
    Ok(())
}

fn temporary_directory_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::XUSR
}

fn pending_name(id: VerificationInputId) -> OsString {
    OsString::from(format!("{PENDING_PREFIX}{id}"))
}

fn final_name(id: VerificationInputId) -> OsString {
    OsString::from(id.to_string())
}

fn open_verification_directory(
    workspace: &ConfinedWorkspace,
    create: bool,
) -> Result<OwnedFd, VerificationInputError> {
    let state = openat(
        &workspace.root,
        STATE_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| fs_error(FilesystemOperation::OpenStateDirectory, source))?;
    ensure_directory_identity(&state, workspace.state_identity, false)?;
    let artifacts = openat(
        &state,
        "artifacts",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| fs_error(FilesystemOperation::OpenStateDirectory, source))?;
    let verification = match openat(
        &artifacts,
        VERIFICATION_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(Errno::NOENT) if create => {
            mkdirat(
                &artifacts,
                VERIFICATION_DIRECTORY,
                temporary_directory_mode(),
            )
            .map_err(|source| fs_error(FilesystemOperation::CreateDirectory, source))?;
            fsync(&artifacts)
                .map_err(|source| fs_error(FilesystemOperation::SyncParent, source))?;
            openat(
                &artifacts,
                VERIFICATION_DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|source| fs_error(FilesystemOperation::OpenStateDirectory, source))?
        }
        Err(Errno::NOENT) => return Err(VerificationInputError::NotFound),
        Err(source) => return Err(fs_error(FilesystemOperation::OpenStateDirectory, source)),
    };
    let _ = directory_identity(&artifacts)?;
    directory_identity(&verification)?;
    Ok(verification)
}

fn create_directory(
    parent: &OwnedFd,
    name: &OsStr,
    mode: Mode,
) -> Result<(), VerificationInputError> {
    mkdirat(parent, name, mode).map_err(|source| {
        if source == Errno::EXIST {
            VerificationInputError::Collision
        } else {
            fs_error(FilesystemOperation::CreateDirectory, source)
        }
    })
}

fn open_directory_entry(
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<Option<OwnedFd>, VerificationInputError> {
    match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => {
            let stat = fstat(&directory).map_err(super::pre_syscall)?;
            if !FileType::from_raw_mode(stat.st_mode).is_dir() {
                return Err(VerificationInputError::SnapshotInvalid);
            }
            Ok(Some(directory))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Err(ConfinedFilesystemError::SymlinkRejected.into()),
        Err(Errno::NOTDIR) => Err(VerificationInputError::Collision),
        Err(source) => Err(fs_error(FilesystemOperation::OpenAncestor, source)),
    }
}

fn map_entry_stat_error(source: Errno, committed: bool) -> VerificationInputError {
    match source {
        Errno::NOENT => VerificationInputError::SnapshotStale,
        Errno::LOOP => ConfinedFilesystemError::SymlinkRejected.into(),
        source => VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::InspectDirectoryEntry,
            committed,
            source,
        }),
    }
}

fn path_components(path: &WorkspaceRelativePath) -> Result<Vec<OsString>, VerificationInputError> {
    let mut components = Vec::new();
    for component in path.components() {
        if components.len() >= MAX_FILE_PATH_COMPONENTS {
            return Err(ConfinedFilesystemError::TooManyComponents.into());
        }
        components.push(component.to_os_string());
    }
    if components.is_empty() {
        Err(VerificationInputError::FileUnavailable)
    } else {
        Ok(components)
    }
}

fn relative_path(
    relative: &Path,
    name: &OsStr,
) -> Result<WorkspaceRelativePath, VerificationInputError> {
    let mut path = relative.to_path_buf();
    path.push(name);
    WorkspaceRelativePath::new(path).map_err(|_| VerificationInputError::InvalidPath)
}

fn read_directory_names(
    directory: &OwnedFd,
    traversal: &mut Traversal<'_>,
    include_excluded: bool,
) -> Result<Vec<OsString>, VerificationInputError> {
    traversal.check_cancelled()?;
    let stream = Dir::read_from(directory).map_err(|source| {
        VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenDirectoryStream,
            committed: false,
            source,
        })
    })?;
    let mut names = Vec::new();
    for entry in stream {
        traversal.check_cancelled()?;
        let entry = entry.map_err(|source| {
            VerificationInputError::Filesystem(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::ReadDirectory,
                committed: false,
                source,
            })
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        traversal.count_entry()?;
        if !include_excluded && is_verification_excluded(bytes) {
            continue;
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

fn is_verification_excluded(name: &[u8]) -> bool {
    super::is_excluded_workspace_component(name)
        || [
            b".codegraph".as_slice(),
            b".omx".as_slice(),
            b".chatgpt2codex".as_slice(),
            b".DS_Store".as_slice(),
        ]
        .iter()
        .any(|excluded| name.eq_ignore_ascii_case(excluded))
}

fn collect_manifest(
    root: &OwnedFd,
    cancellation: &AtomicBool,
    include_excluded: bool,
) -> Result<VerificationInputManifest, VerificationInputError> {
    check_cancelled(cancellation)?;
    let before = node_state_fd(root)?;
    if !is_directory_state(&before) {
        return Err(VerificationInputError::SnapshotStale);
    }
    let mut traversal = Traversal {
        cancellation,
        physical_entries: 0,
    };
    let mut builder = ManifestBuilder::new();
    collect_directory(
        root,
        Path::new(""),
        &mut traversal,
        &mut builder,
        include_excluded,
    )?;
    let after = node_state_fd(root)?;
    if after != before {
        return Err(VerificationInputError::SnapshotStale);
    }
    builder.finish()
}

fn collect_directory(
    directory: &OwnedFd,
    relative: &Path,
    traversal: &mut Traversal<'_>,
    builder: &mut ManifestBuilder,
    include_excluded: bool,
) -> Result<(), VerificationInputError> {
    traversal.check_cancelled()?;
    let before = node_state_fd(directory)?;
    if !is_directory_state(&before) {
        return Err(VerificationInputError::SnapshotStale);
    }
    let names = read_directory_names(directory, traversal, include_excluded)?;
    for name in names {
        traversal.check_cancelled()?;
        let stat = stat_entry(directory, &name)?;
        let state = NodeState::from_stat(&stat);
        let kind = classify_entry(&stat)?;
        let path = relative_path(relative, &name)?;
        match kind {
            IncludedEntryKind::Directory => {
                let child = open_directory_for_scan(directory, &name, state)?;
                let mode = normalized_mode_from_stat(&stat);
                builder.push(VerificationInputEntry::directory(path.clone(), mode)?)?;
                collect_directory(&child, path.as_path(), traversal, builder, include_excluded)?;
                ensure_entry_unchanged(directory, &name, state)?;
            }
            IncludedEntryKind::File => {
                let observation = observe_file(directory, &name, state)?;
                builder.push(VerificationInputEntry::file(
                    path,
                    observation.mode,
                    FileByteCount::new(observation.size),
                    observation.hash,
                )?)?;
                ensure_entry_unchanged(directory, &name, state)?;
            }
        }
    }
    let after = node_state_fd(directory)?;
    if after != before {
        return Err(VerificationInputError::SnapshotStale);
    }
    Ok(())
}

fn capture_directory(
    source: &OwnedFd,
    destination: &OwnedFd,
    relative: &Path,
    traversal: &mut Traversal<'_>,
    builder: &mut ManifestBuilder,
) -> Result<(), VerificationInputError> {
    traversal.check_cancelled()?;
    let before = node_state_fd(source)?;
    if !is_directory_state(&before) {
        return Err(VerificationInputError::SnapshotStale);
    }
    let names = read_directory_names(source, traversal, false)?;
    for name in names {
        traversal.check_cancelled()?;
        let stat = stat_entry(source, &name)?;
        let state = NodeState::from_stat(&stat);
        let kind = classify_entry(&stat)?;
        let path = relative_path(relative, &name)?;
        match kind {
            IncludedEntryKind::Directory => {
                let source_child = open_directory_for_scan(source, &name, state)?;
                let mode = normalized_mode_from_stat(&stat);
                create_directory(destination, &name, temporary_directory_mode())?;
                let destination_child = open_directory_entry(destination, &name)?
                    .ok_or(VerificationInputError::SnapshotInvalid)?;
                capture_directory(
                    &source_child,
                    &destination_child,
                    path.as_path(),
                    traversal,
                    builder,
                )?;
                seal_directory(&destination_child, mode)?;
                sync_directory_fd(&destination_child)?;
                builder.push(VerificationInputEntry::directory(path, mode)?)?;
                ensure_entry_unchanged(source, &name, state)?;
            }
            IncludedEntryKind::File => {
                let mode = normalized_mode_from_stat(&stat);
                let observation = capture_file(source, destination, &name, state, mode, traversal)?;
                builder.push(VerificationInputEntry::file(
                    path,
                    mode,
                    FileByteCount::new(observation.size),
                    observation.hash,
                )?)?;
                ensure_entry_unchanged(source, &name, state)?;
            }
        }
    }
    let after = node_state_fd(source)?;
    if after != before {
        return Err(VerificationInputError::SnapshotStale);
    }
    sync_directory_fd(destination)?;
    Ok(())
}

fn stat_entry(parent: &OwnedFd, name: &OsStr) -> Result<Stat, VerificationInputError> {
    statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| map_entry_stat_error(source, false))
}

fn classify_entry(stat: &Stat) -> Result<IncludedEntryKind, VerificationInputError> {
    if mode_bits_from_stat(stat) & 0o7000 != 0 {
        return Err(VerificationInputManifestError::UnsupportedMode.into());
    }
    let file_type = FileType::from_raw_mode(stat.st_mode);
    if file_type.is_dir() {
        Ok(IncludedEntryKind::Directory)
    } else if file_type.is_file() {
        if stat.st_nlink != 1 {
            return Err(ConfinedFilesystemError::HardlinkRejected.into());
        }
        Ok(IncludedEntryKind::File)
    } else if file_type.is_symlink() {
        Err(ConfinedFilesystemError::SymlinkRejected.into())
    } else {
        Err(ConfinedFilesystemError::NonRegularLeaf.into())
    }
}

fn open_directory_for_scan(
    parent: &OwnedFd,
    name: &OsStr,
    expected: NodeState,
) -> Result<OwnedFd, VerificationInputError> {
    let directory = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| match source {
        Errno::LOOP => ConfinedFilesystemError::SymlinkRejected.into(),
        Errno::NOTDIR => ConfinedFilesystemError::NonDirectoryAncestor.into(),
        Errno::NOENT => VerificationInputError::SnapshotStale,
        source => fs_error(FilesystemOperation::OpenAncestor, source),
    })?;
    if node_state_fd(&directory)? != expected {
        return Err(VerificationInputError::SnapshotStale);
    }
    Ok(directory)
}

fn ensure_entry_unchanged(
    parent: &OwnedFd,
    name: &OsStr,
    expected: NodeState,
) -> Result<(), VerificationInputError> {
    let current = stat_entry(parent, name)?;
    if NodeState::from_stat(&current) == expected {
        Ok(())
    } else {
        Err(VerificationInputError::SnapshotStale)
    }
}

fn observe_file(
    parent: &OwnedFd,
    name: &OsStr,
    expected: NodeState,
) -> Result<FileObservation, VerificationInputError> {
    let fd = open_regular_leaf(parent, name)?.ok_or(VerificationInputError::SnapshotStale)?;
    let opened = node_state_fd(&fd)?;
    if opened != expected {
        return Err(VerificationInputError::SnapshotStale);
    }
    let mut file = File::from(fd);
    let (size, hash) = hash_file_contents(&mut file, MAX_VERIFICATION_INPUT_FILE_BYTES)?;
    let after = node_state_file(&file)?;
    if after != expected {
        return Err(VerificationInputError::SnapshotStale);
    }
    let mode = expected.mode & 0o777;
    let expected_size =
        u64::try_from(expected.size).map_err(|_| VerificationInputError::SnapshotStale)?;
    if size != expected_size {
        return Err(VerificationInputError::SnapshotStale);
    }
    Ok(FileObservation { mode, size, hash })
}

fn capture_file(
    source_parent: &OwnedFd,
    destination_parent: &OwnedFd,
    name: &OsStr,
    expected: NodeState,
    mode: u16,
    traversal: &mut Traversal<'_>,
) -> Result<FileObservation, VerificationInputError> {
    let source_fd =
        open_regular_leaf(source_parent, name)?.ok_or(VerificationInputError::SnapshotStale)?;
    if node_state_fd(&source_fd)? != expected {
        return Err(VerificationInputError::SnapshotStale);
    }
    let destination_fd = openat(
        destination_parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|source| {
        if source == Errno::EXIST {
            VerificationInputError::Collision
        } else {
            fs_error(FilesystemOperation::CreateTemporary, source)
        }
    })?;
    require_regular_single_link(&destination_fd)?;
    let mut source_file = File::from(source_fd);
    let mut destination_file = File::from(destination_fd);
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    loop {
        traversal.check_cancelled()?;
        let read = source_file
            .read(&mut buffer)
            .map_err(|source| io_error(FilesystemOperation::ReadLeaf, source))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or(VerificationInputManifestError::FileCapacity)?;
        if bytes > MAX_VERIFICATION_INPUT_FILE_BYTES {
            return Err(VerificationInputManifestError::FileCapacity.into());
        }
        hasher.update(&buffer[..read]);
        destination_file
            .write_all(&buffer[..read])
            .map_err(|source| io_error(FilesystemOperation::WriteTemporary, source))?;
    }
    let hash = FileContentHash::from_bytes(*hasher.finalize().as_bytes());
    let source_after = node_state_file(&source_file)?;
    let expected_size =
        u64::try_from(expected.size).map_err(|_| VerificationInputError::SnapshotStale)?;
    if source_after != expected || bytes != expected_size {
        return Err(VerificationInputError::SnapshotStale);
    }
    ensure_entry_unchanged(source_parent, name, expected)?;
    sync_file(&destination_file)
        .map_err(|source| fs_error(FilesystemOperation::SyncTemporary, source))?;
    fchmod(&destination_file, sealed_mode(mode))
        .map_err(|source| fs_error(FilesystemOperation::SetTemporaryMode, source))?;
    sync_file(&destination_file)
        .map_err(|source| fs_error(FilesystemOperation::SyncTemporary, source))?;
    let destination_state = node_state_file(&destination_file)?;
    let destination_size = u64::try_from(destination_state.size)
        .map_err(|_| VerificationInputError::SnapshotInvalid)?;
    if !destination_state.is_regular
        || destination_state.nlink != 1
        || destination_size != bytes
        || destination_state.mode != mode & !SEALED_WRITE_MASK
    {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    destination_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| io_error(FilesystemOperation::ReadLeaf, source))?;
    let (copied_size, copied_hash) =
        hash_file_contents(&mut destination_file, MAX_VERIFICATION_INPUT_FILE_BYTES)?;
    if copied_size != bytes || copied_hash != hash {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    Ok(FileObservation {
        mode,
        size: bytes,
        hash,
    })
}

fn node_state_file(file: &File) -> Result<NodeState, VerificationInputError> {
    Ok(NodeState::from_stat(
        &fstat(file).map_err(super::pre_syscall)?,
    ))
}

fn hash_file_contents(
    file: &mut File,
    maximum: u64,
) -> Result<(u64, FileContentHash), VerificationInputError> {
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error(FilesystemOperation::ReadLeaf, source))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or(VerificationInputManifestError::FileCapacity)?;
        if bytes > maximum {
            return Err(VerificationInputManifestError::FileCapacity.into());
        }
        hasher.update(&buffer[..read]);
    }
    Ok((
        bytes,
        FileContentHash::from_bytes(*hasher.finalize().as_bytes()),
    ))
}

fn io_error(operation: FilesystemOperation, source: std::io::Error) -> VerificationInputError {
    VerificationInputError::Filesystem(ConfinedFilesystemError::StdIo {
        operation,
        committed: false,
        source,
    })
}

fn seal_directory(directory: &OwnedFd, original_mode: u16) -> Result<(), VerificationInputError> {
    fchmod(directory, sealed_mode(original_mode))
        .map_err(|source| fs_error(FilesystemOperation::SetTemporaryMode, source))
}

fn sync_directory_fd(directory: &OwnedFd) -> Result<(), VerificationInputError> {
    fsync(directory).map_err(|source| fs_error(FilesystemOperation::SyncTemporary, source))
}

fn validate_snapshot_tree(
    source_root: &OwnedFd,
    manifest: &VerificationInputManifest,
) -> Result<(), VerificationInputError> {
    let mut expected = manifest
        .entries()
        .iter()
        .map(|entry| (entry.path().as_path().to_path_buf(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut traversal = Traversal {
        cancellation: &NO_CANCELLATION,
        physical_entries: 0,
    };
    validate_snapshot_directory(source_root, Path::new(""), &mut expected, &mut traversal)?;
    if !expected.is_empty() {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    Ok(())
}

fn validate_snapshot_directory(
    directory: &OwnedFd,
    relative: &Path,
    expected: &mut BTreeMap<PathBuf, &VerificationInputEntry>,
    traversal: &mut Traversal<'_>,
) -> Result<(), VerificationInputError> {
    traversal.check_cancelled()?;
    let before = node_state_fd(directory)?;
    if !is_directory_state(&before) {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    let names = read_directory_names(directory, traversal, true)?;
    for name in names {
        traversal.check_cancelled()?;
        let stat = stat_entry(directory, &name)?;
        let state = NodeState::from_stat(&stat);
        let path = relative_path(relative, &name)?;
        let Some(entry) = expected.remove(path.as_path()) else {
            return Err(VerificationInputError::SnapshotInvalid);
        };
        match (classify_entry(&stat)?, entry.kind()) {
            (IncludedEntryKind::Directory, VerificationInputEntryKind::Directory) => {
                let child = open_directory_for_scan(directory, &name, state)?;
                if !sealed_mode_matches(&stat, entry.mode()) {
                    return Err(VerificationInputError::SnapshotInvalid);
                }
                validate_snapshot_directory(&child, path.as_path(), expected, traversal)?;
                ensure_entry_unchanged(directory, &name, state)?;
            }
            (
                IncludedEntryKind::File,
                VerificationInputEntryKind::File {
                    size: expected_size,
                    content_hash: expected_hash,
                },
            ) => {
                let observation = observe_file(directory, &name, state)?;
                if observation.size != expected_size.get() || observation.hash != expected_hash {
                    return Err(VerificationInputError::SnapshotInvalid);
                }
                if !sealed_mode_matches(&stat, entry.mode()) {
                    return Err(VerificationInputError::SnapshotInvalid);
                }
                ensure_entry_unchanged(directory, &name, state)?;
            }
            _ => return Err(VerificationInputError::SnapshotInvalid),
        }
    }
    let after = node_state_fd(directory)?;
    if after != before {
        return Err(VerificationInputError::SnapshotInvalid);
    }
    Ok(())
}
