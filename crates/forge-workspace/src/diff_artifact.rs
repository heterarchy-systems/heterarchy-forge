use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::str::FromStr;

use base64::Engine;
use forge_domain::{
    DeleteOrphanDiffArtifact, DiffArtifactHealth, DiffArtifactInvalidInventoryEntry,
    DiffArtifactInvalidReason, DiffArtifactInventoryEntry, DiffArtifactInventoryKind,
    DiffArtifactInventoryLimit, DiffArtifactInventoryName, DiffArtifactRelativePath,
    DiffArtifactRelativePathError, DiffByteCount, DiffChangeKind, DiffId, DiffLineCount,
    DiffPayloadHash, DiffRenderKind, WorkspaceRelativePath,
};
use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, fchmod, fstat, fsync, openat, renameat_with, unlinkat,
};
use rustix::io::Errno;
use similar::{Algorithm, ChangeTag, TextDiff};
use thiserror::Error;

use crate::confinement::{
    DirectoryIdentity, ensure_directory_identity, require_regular_single_link, sync_file,
    walk_directories,
};
use crate::{CapturedDiffSource, ConfinedFilesystemError};

/// Stable renderer contract recorded beside every durable Diff Evidence row.
pub const DIFF_RENDERER_VERSION: u32 = 1;
/// Stable deterministic redaction contract recorded beside every Diff row.
pub const DIFF_REDACTION_POLICY_VERSION: u32 = 1;
/// Maximum redacted unified-diff bytes retained before compression.
pub const MAX_DIFF_RENDERED_BYTES: usize = 128 * 1024;
/// Maximum line count accepted on either side of the bounded text renderer.
pub const MAX_DIFF_SOURCE_LINES: usize = 4_096;
/// Maximum compressed bytes accepted for one `.diff.zst` artifact.
pub const MAX_DIFF_COMPRESSED_BYTES: usize = 128 * 1024;
/// Fixed zstd level used by renderer contract V1.
pub const DIFF_ZSTD_LEVEL: i32 = 3;

const REDACTED: &str = "[REDACTED]";
const SECRET_KEYS: [&str; 14] = [
    "aws_secret_access_key",
    "client_secret",
    "private_key",
    "refresh_token",
    "access_token",
    "authorization",
    "set-cookie",
    "password",
    "api_key",
    "apikey",
    "client_key",
    "secret",
    "token",
    "cookie",
];

/// Human-review rendering disposition produced before artifact persistence.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderedDiffEvidence {
    Text(RenderedTextDiff),
    SummaryOnly { render_kind: DiffRenderKind },
}

impl RenderedDiffEvidence {
    pub const fn render_kind(&self) -> DiffRenderKind {
        match self {
            Self::Text(_) => DiffRenderKind::Text,
            Self::SummaryOnly { render_kind } => *render_kind,
        }
    }

    pub const fn additions(&self) -> DiffLineCount {
        match self {
            Self::Text(rendered) => rendered.additions(),
            Self::SummaryOnly { .. } => DiffLineCount::new(0),
        }
    }

    pub const fn deletions(&self) -> DiffLineCount {
        match self {
            Self::Text(rendered) => rendered.deletions(),
            Self::SummaryOnly { .. } => DiffLineCount::new(0),
        }
    }
}

/// Bounded redacted unified-diff payload and exact line statistics.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct RenderedTextDiff {
    bytes: Vec<u8>,
    additions: DiffLineCount,
    deletions: DiffLineCount,
}

impl std::fmt::Debug for RenderedTextDiff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RenderedTextDiff")
            .field("bytes", &self.bytes.len())
            .field("additions", &self.additions)
            .field("deletions", &self.deletions)
            .finish()
    }
}

impl RenderedTextDiff {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn additions(&self) -> DiffLineCount {
        self.additions
    }

    pub const fn deletions(&self) -> DiffLineCount {
        self.deletions
    }
}

/// Descriptor-rooted owner for durable Diff Evidence artifacts.
pub struct DiffArtifactStore {
    filesystem_root: OwnedFd,
    root_components: Vec<OsString>,
    root: OwnedFd,
    root_identity: DirectoryIdentity,
    state: OwnedFd,
    state_identity: DirectoryIdentity,
    diffs: OwnedFd,
    diffs_identity: DirectoryIdentity,
    diffs_path: PathBuf,
}

impl std::fmt::Debug for DiffArtifactStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiffArtifactStore")
            .field("root_identity", &self.root_identity)
            .field("state_identity", &self.state_identity)
            .field("diffs_identity", &self.diffs_identity)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffArtifactDeleteStatus {
    Deleted,
    AlreadyMissing,
}

/// Bounded deterministic directory inventory for orphan diagnosis.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArtifactInventory {
    entries: Vec<DiffArtifactInventoryEntry>,
    invalid_entries: Vec<DiffArtifactInvalidInventoryEntry>,
    truncated: bool,
}

impl DiffArtifactInventory {
    pub fn entries(&self) -> &[DiffArtifactInventoryEntry] {
        &self.entries
    }

    pub fn invalid_entries(&self) -> &[DiffArtifactInvalidInventoryEntry] {
        &self.invalid_entries
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

impl DiffArtifactStore {
    pub(crate) fn from_parts(parts: DiffArtifactStoreParts) -> Self {
        Self {
            filesystem_root: parts.filesystem_root,
            root_components: parts.root_components,
            root: parts.root,
            root_identity: parts.root_identity,
            state: parts.state,
            state_identity: parts.state_identity,
            diffs: parts.diffs,
            diffs_identity: parts.diffs_identity,
            diffs_path: parts.diffs_path,
        }
    }

    /// Compress, hash, and durably stage one already-redacted text payload.
    ///
    /// The pending name is identity-derived and exclusive. A retry converges
    /// only when the existing pending bytes match exactly.
    pub fn stage(
        &self,
        id: DiffId,
        rendered: &RenderedTextDiff,
    ) -> Result<StagedDiffArtifact, DiffArtifactStoreError> {
        self.ensure_scope(false)?;
        let compressed = compress_bounded(rendered.bytes())?;
        let metadata = DiffArtifactMetadata::new(id, &compressed, rendered.bytes())?;
        let pending_name = pending_name(id);
        match openat(
            &self.diffs,
            &pending_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => {
                require_regular_single_link(&fd).map_err(DiffArtifactStoreError::Scope)?;
                fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|source| {
                    DiffArtifactStoreError::Syscall {
                        operation: DiffArtifactOperation::SetPendingMode,
                        source,
                    }
                })?;
                let mut file = File::from(fd);
                if let Err(source) = file.write_all(&compressed) {
                    self.cleanup_pending_after_error(&pending_name)?;
                    return Err(DiffArtifactStoreError::Io {
                        operation: DiffArtifactOperation::WritePending,
                        source,
                    });
                }
                if let Err(source) = sync_file(&file) {
                    self.cleanup_pending_after_error(&pending_name)?;
                    return Err(DiffArtifactStoreError::Syscall {
                        operation: DiffArtifactOperation::SyncPending,
                        source,
                    });
                }
                drop(file);
                fsync(&self.diffs).map_err(|source| DiffArtifactStoreError::Syscall {
                    operation: DiffArtifactOperation::SyncDiffDirectory,
                    source,
                })?;
            }
            Err(source) if source == Errno::EXIST => {
                let existing = self.read_named(&pending_name, MAX_DIFF_COMPRESSED_BYTES)?;
                if existing != compressed {
                    return Err(DiffArtifactStoreError::IdentityCollision);
                }
            }
            Err(source) => {
                return Err(DiffArtifactStoreError::Syscall {
                    operation: DiffArtifactOperation::CreatePending,
                    source,
                });
            }
        }
        self.ensure_scope(false)?;
        Ok(StagedDiffArtifact {
            metadata,
            pending_name,
        })
    }

    /// Atomically publish one staged artifact after the filesystem effect is
    /// confirmed. Existing final bytes are accepted only when identical.
    pub fn publish(
        &self,
        staged: StagedDiffArtifact,
    ) -> Result<PublishedDiffArtifact, DiffArtifactStoreError> {
        self.ensure_scope(true)?;
        let final_name = final_name(staged.metadata.id);
        match renameat_with(
            &self.diffs,
            &staged.pending_name,
            &self.diffs,
            &final_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(source) if source == Errno::EXIST => {
                self.verify_named_metadata(&final_name, &staged.metadata)?;
                match unlinkat(&self.diffs, &staged.pending_name, AtFlags::empty()) {
                    Ok(()) => {}
                    Err(source) if source == Errno::NOENT => {}
                    Err(source) => {
                        return Err(DiffArtifactStoreError::Syscall {
                            operation: DiffArtifactOperation::RemovePending,
                            source,
                        });
                    }
                }
            }
            Err(Errno::NOTSUP | Errno::OPNOTSUPP | Errno::NOSYS) => {
                return Err(DiffArtifactStoreError::AtomicPublishUnsupported);
            }
            Err(source) => {
                return Err(DiffArtifactStoreError::Syscall {
                    operation: DiffArtifactOperation::PublishFinal,
                    source,
                });
            }
        }
        fsync(&self.diffs).map_err(|source| DiffArtifactStoreError::Syscall {
            operation: DiffArtifactOperation::SyncDiffDirectory,
            source,
        })?;
        self.ensure_scope(true)?;
        Ok(PublishedDiffArtifact {
            metadata: staged.metadata,
        })
    }

    /// Remove a pre-effect pending artifact after an abandoned mutation.
    pub fn abandon(&self, staged: StagedDiffArtifact) -> Result<(), DiffArtifactStoreError> {
        let StagedDiffArtifact { pending_name, .. } = staged;
        self.ensure_scope(false)?;
        match unlinkat(&self.diffs, &pending_name, AtFlags::empty()) {
            Ok(()) => {}
            Err(source) if source == Errno::NOENT => {}
            Err(source) => {
                return Err(DiffArtifactStoreError::Syscall {
                    operation: DiffArtifactOperation::RemovePending,
                    source,
                });
            }
        }
        fsync(&self.diffs).map_err(|source| DiffArtifactStoreError::Syscall {
            operation: DiffArtifactOperation::SyncDiffDirectory,
            source,
        })?;
        self.ensure_scope(false)
    }

    /// Read and verify one published redacted artifact using durable expected
    /// hashes and exact sizes.
    pub fn read(
        &self,
        expected: &DiffArtifactExpectation,
    ) -> Result<Vec<u8>, DiffArtifactStoreError> {
        self.read_expected_named(&final_name(expected.id()), expected)
    }

    /// Observe a pre-effect pending artifact for recovery diagnostics without
    /// publishing or replaying it.
    pub fn doctor_pending(
        &self,
        expected: &DiffArtifactExpectation,
    ) -> Result<DiffArtifactHealth, DiffArtifactStoreError> {
        self.doctor_named(&pending_name(expected.id()), expected)
    }

    /// Delete the exact published artifact after verifying its compressed and
    /// uncompressed metadata. Missing is idempotent for crash recovery.
    pub fn delete_published(
        &self,
        expected: &DiffArtifactExpectation,
    ) -> Result<DiffArtifactDeleteStatus, DiffArtifactStoreError> {
        self.delete_expected_named(&final_name(expected.id()), expected)
    }

    /// Enumerate bounded regular Diff-directory entries from a freshly opened
    /// descriptor, retaining only native name/hash/size metadata.
    pub fn inventory(
        &self,
        limit: DiffArtifactInventoryLimit,
    ) -> Result<DiffArtifactInventory, DiffArtifactStoreError> {
        self.ensure_scope(false)?;
        self.ensure_diff_path_identity()?;
        let maximum =
            usize::try_from(limit.get()).map_err(|_| DiffArtifactStoreError::SizeOverflow)?;
        let mut entries = Vec::with_capacity(maximum.min(64));
        let mut invalid_entries = Vec::new();
        let mut observed = 0_usize;
        let mut truncated = false;
        let directory =
            std::fs::read_dir(&self.diffs_path).map_err(|source| DiffArtifactStoreError::Io {
                operation: DiffArtifactOperation::ReadDiffDirectory,
                source,
            })?;
        for entry in directory {
            let entry = entry.map_err(|source| DiffArtifactStoreError::Io {
                operation: DiffArtifactOperation::ReadDiffDirectory,
                source,
            })?;
            if observed >= maximum {
                truncated = true;
                break;
            }
            observed = observed.saturating_add(1);
            let file_name = entry.file_name();
            let name = file_name.as_os_str().as_bytes();
            let inventory_name = DiffArtifactInventoryName::new(name.to_vec())
                .map_err(|_| DiffArtifactStoreError::InvalidInventoryName)?;
            let (kind, diff_id) = classify_inventory_name(name);
            let bytes = match self.read_named(OsStr::from_bytes(name), MAX_DIFF_COMPRESSED_BYTES) {
                Ok(bytes) => bytes,
                Err(DiffArtifactStoreError::Missing) => continue,
                Err(DiffArtifactStoreError::Scope(ConfinedFilesystemError::SymlinkRejected)) => {
                    invalid_entries.push(DiffArtifactInvalidInventoryEntry::new(
                        inventory_name,
                        kind,
                        diff_id,
                        DiffArtifactInvalidReason::Symlink,
                    ));
                    continue;
                }
                Err(DiffArtifactStoreError::Scope(ConfinedFilesystemError::NonRegularLeaf)) => {
                    invalid_entries.push(DiffArtifactInvalidInventoryEntry::new(
                        inventory_name,
                        kind,
                        diff_id,
                        DiffArtifactInvalidReason::NonRegular,
                    ));
                    continue;
                }
                Err(DiffArtifactStoreError::Scope(ConfinedFilesystemError::HardlinkRejected)) => {
                    invalid_entries.push(DiffArtifactInvalidInventoryEntry::new(
                        inventory_name,
                        kind,
                        diff_id,
                        DiffArtifactInvalidReason::Hardlink,
                    ));
                    continue;
                }
                Err(error) => return Err(error),
            };
            entries.push(DiffArtifactInventoryEntry::new(
                inventory_name,
                kind,
                diff_id,
                payload_hash(&bytes),
                byte_count(bytes.len())?,
            ));
        }
        entries.sort_by(|left, right| left.name().as_bytes().cmp(right.name().as_bytes()));
        invalid_entries.sort_by(|left, right| left.name().as_bytes().cmp(right.name().as_bytes()));
        self.ensure_diff_path_identity()?;
        self.ensure_scope(false)?;
        Ok(DiffArtifactInventory {
            entries,
            invalid_entries,
            truncated,
        })
    }

    /// Delete one hash-bound orphan entry. The caller must hold the Workspace
    /// writer guard and recheck `SQLite` ownership immediately before calling.
    pub fn delete_orphan(
        &self,
        command: &DeleteOrphanDiffArtifact,
    ) -> Result<DiffArtifactDeleteStatus, DiffArtifactStoreError> {
        self.ensure_scope(false)?;
        let name = OsStr::from_bytes(command.name().as_bytes());
        let bytes = match self.read_named(name, MAX_DIFF_COMPRESSED_BYTES) {
            Ok(bytes) => bytes,
            Err(DiffArtifactStoreError::Missing) => {
                return Ok(DiffArtifactDeleteStatus::AlreadyMissing);
            }
            Err(error) => return Err(error),
        };
        verify_bytes(&bytes, command.expected_hash(), command.expected_size())?;
        self.unlink_and_sync(name)
    }

    fn read_expected_named(
        &self,
        name: &OsStr,
        expected: &DiffArtifactExpectation,
    ) -> Result<Vec<u8>, DiffArtifactStoreError> {
        self.ensure_scope(false)?;
        let compressed = self.read_named(name, MAX_DIFF_COMPRESSED_BYTES)?;
        verify_bytes(
            &compressed,
            expected.compressed_hash(),
            expected.compressed_size(),
        )?;
        let rendered = decompress_bounded(&compressed)?;
        verify_bytes(
            &rendered,
            expected.uncompressed_hash(),
            expected.uncompressed_size(),
        )?;
        std::str::from_utf8(&rendered).map_err(|_| DiffArtifactStoreError::CorruptPayload)?;
        self.ensure_scope(false)?;
        Ok(rendered)
    }

    fn delete_expected_named(
        &self,
        name: &OsStr,
        expected: &DiffArtifactExpectation,
    ) -> Result<DiffArtifactDeleteStatus, DiffArtifactStoreError> {
        match self.read_expected_named(name, expected) {
            Ok(_) => self.unlink_and_sync(name),
            Err(DiffArtifactStoreError::Missing) => Ok(DiffArtifactDeleteStatus::AlreadyMissing),
            Err(error) => Err(error),
        }
    }

    fn unlink_and_sync(
        &self,
        name: &OsStr,
    ) -> Result<DiffArtifactDeleteStatus, DiffArtifactStoreError> {
        match unlinkat(&self.diffs, name, AtFlags::empty()) {
            Ok(()) => {}
            Err(source) if source == Errno::NOENT => {
                return Ok(DiffArtifactDeleteStatus::AlreadyMissing);
            }
            Err(source) => {
                return Err(DiffArtifactStoreError::Syscall {
                    operation: DiffArtifactOperation::DeleteArtifact,
                    source,
                });
            }
        }
        fsync(&self.diffs).map_err(|source| DiffArtifactStoreError::Syscall {
            operation: DiffArtifactOperation::SyncDiffDirectory,
            source,
        })?;
        self.ensure_scope(false)?;
        Ok(DiffArtifactDeleteStatus::Deleted)
    }

    /// Observe artifact availability without changing durable metadata.
    pub fn doctor(
        &self,
        expected: &DiffArtifactExpectation,
    ) -> Result<DiffArtifactHealth, DiffArtifactStoreError> {
        self.doctor_named(&final_name(expected.id()), expected)
    }

    fn doctor_named(
        &self,
        name: &OsStr,
        expected: &DiffArtifactExpectation,
    ) -> Result<DiffArtifactHealth, DiffArtifactStoreError> {
        match self.read_expected_named(name, expected) {
            Ok(_) => Ok(DiffArtifactHealth::Available),
            Err(DiffArtifactStoreError::Missing) => Ok(DiffArtifactHealth::Missing),
            Err(
                DiffArtifactStoreError::CorruptPayload
                | DiffArtifactStoreError::CompressedTooLarge { .. }
                | DiffArtifactStoreError::RenderedTooLarge { .. }
                | DiffArtifactStoreError::Scope(
                    ConfinedFilesystemError::SymlinkRejected
                    | ConfinedFilesystemError::NonRegularLeaf
                    | ConfinedFilesystemError::HardlinkRejected,
                ),
            ) => Ok(DiffArtifactHealth::Corrupt),
            Err(error) => Err(error),
        }
    }

    fn ensure_scope(&self, committed: bool) -> Result<(), DiffArtifactStoreError> {
        ensure_directory_identity(&self.root, self.root_identity, committed)
            .map_err(DiffArtifactStoreError::Scope)?;
        let reopened_root =
            walk_directories(&self.filesystem_root, &self.root_components, committed)
                .map_err(DiffArtifactStoreError::Scope)?;
        ensure_directory_identity(&reopened_root, self.root_identity, committed)
            .map_err(DiffArtifactStoreError::Scope)?;
        ensure_directory_identity(&self.state, self.state_identity, committed)
            .map_err(DiffArtifactStoreError::Scope)?;
        let reopened_state = openat(
            &self.root,
            ".heterarchy-forge",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| DiffArtifactStoreError::Syscall {
            operation: DiffArtifactOperation::OpenStateDirectory,
            source,
        })?;
        ensure_directory_identity(&reopened_state, self.state_identity, committed)
            .map_err(DiffArtifactStoreError::Scope)?;
        ensure_directory_identity(&self.diffs, self.diffs_identity, committed)
            .map_err(DiffArtifactStoreError::Scope)?;
        let reopened_diffs = openat(
            &reopened_state,
            "diffs",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| DiffArtifactStoreError::Syscall {
            operation: DiffArtifactOperation::OpenDiffDirectory,
            source,
        })?;
        ensure_directory_identity(&reopened_diffs, self.diffs_identity, committed)
            .map_err(DiffArtifactStoreError::Scope)
    }

    fn ensure_diff_path_identity(&self) -> Result<(), DiffArtifactStoreError> {
        let metadata = std::fs::symlink_metadata(&self.diffs_path).map_err(|source| {
            DiffArtifactStoreError::Io {
                operation: DiffArtifactOperation::InspectDiffDirectoryPath,
                source,
            }
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !self.diffs_identity.matches_metadata(&metadata)
        {
            return Err(DiffArtifactStoreError::DirectoryPathChanged);
        }
        Ok(())
    }

    fn read_named(&self, name: &OsStr, maximum: usize) -> Result<Vec<u8>, DiffArtifactStoreError> {
        let fd = match openat(
            &self.diffs,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(source) if source == Errno::NOENT => return Err(DiffArtifactStoreError::Missing),
            Err(source) if source == Errno::LOOP => {
                return Err(DiffArtifactStoreError::Scope(
                    ConfinedFilesystemError::SymlinkRejected,
                ));
            }
            Err(source) => {
                return Err(DiffArtifactStoreError::Syscall {
                    operation: DiffArtifactOperation::OpenArtifact,
                    source,
                });
            }
        };
        require_regular_single_link(&fd).map_err(DiffArtifactStoreError::Scope)?;
        read_bounded_file(fd, maximum)
    }

    fn verify_named_metadata(
        &self,
        name: &OsStr,
        expected: &DiffArtifactMetadata,
    ) -> Result<(), DiffArtifactStoreError> {
        let bytes = self.read_named(name, MAX_DIFF_COMPRESSED_BYTES)?;
        verify_bytes(&bytes, expected.compressed_hash, expected.compressed_size)
    }

    fn cleanup_pending_after_error(&self, pending: &OsStr) -> Result<(), DiffArtifactStoreError> {
        match unlinkat(&self.diffs, pending, AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(source) if source == Errno::NOENT => Ok(()),
            Err(source) => Err(DiffArtifactStoreError::Syscall {
                operation: DiffArtifactOperation::RemovePending,
                source,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct DiffArtifactStoreParts {
    pub(crate) filesystem_root: OwnedFd,
    pub(crate) root_components: Vec<OsString>,
    pub(crate) root: OwnedFd,
    pub(crate) root_identity: DirectoryIdentity,
    pub(crate) state: OwnedFd,
    pub(crate) state_identity: DirectoryIdentity,
    pub(crate) diffs: OwnedFd,
    pub(crate) diffs_identity: DirectoryIdentity,
    pub(crate) diffs_path: PathBuf,
}

/// Metadata for a compressed pending artifact awaiting effect confirmation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedDiffArtifact {
    metadata: DiffArtifactMetadata,
    pending_name: OsString,
}

impl StagedDiffArtifact {
    pub const fn id(&self) -> DiffId {
        self.metadata.id
    }

    pub fn pending_relative_path(
        &self,
    ) -> Result<DiffArtifactRelativePath, DiffArtifactStoreError> {
        artifact_relative_path(&self.pending_name)
    }

    pub fn final_relative_path(&self) -> Result<DiffArtifactRelativePath, DiffArtifactStoreError> {
        artifact_relative_path(&final_name(self.id()))
    }

    pub const fn compressed_hash(&self) -> DiffPayloadHash {
        self.metadata.compressed_hash
    }

    pub const fn uncompressed_hash(&self) -> DiffPayloadHash {
        self.metadata.uncompressed_hash
    }

    pub const fn compressed_size(&self) -> DiffByteCount {
        self.metadata.compressed_size
    }

    pub const fn uncompressed_size(&self) -> DiffByteCount {
        self.metadata.uncompressed_size
    }

    pub const fn expectation(&self) -> DiffArtifactExpectation {
        self.metadata.expectation()
    }
}

/// Metadata for one atomically published final artifact.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedDiffArtifact {
    metadata: DiffArtifactMetadata,
}

impl PublishedDiffArtifact {
    pub fn relative_path(&self) -> Result<DiffArtifactRelativePath, DiffArtifactStoreError> {
        artifact_relative_path(&final_name(self.metadata.id))
    }

    pub const fn expectation(&self) -> DiffArtifactExpectation {
        self.metadata.expectation()
    }
}

/// Durable metadata needed to verify and read a final artifact.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffArtifactExpectation {
    id: DiffId,
    compressed_hash: DiffPayloadHash,
    uncompressed_hash: DiffPayloadHash,
    compressed_size: DiffByteCount,
    uncompressed_size: DiffByteCount,
}

impl DiffArtifactExpectation {
    pub const fn new(
        id: DiffId,
        compressed_hash: DiffPayloadHash,
        uncompressed_hash: DiffPayloadHash,
        compressed_size: DiffByteCount,
        uncompressed_size: DiffByteCount,
    ) -> Self {
        Self {
            id,
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
        }
    }

    pub const fn id(self) -> DiffId {
        self.id
    }

    pub const fn compressed_hash(self) -> DiffPayloadHash {
        self.compressed_hash
    }

    pub const fn uncompressed_hash(self) -> DiffPayloadHash {
        self.uncompressed_hash
    }

    pub const fn compressed_size(self) -> DiffByteCount {
        self.compressed_size
    }

    pub const fn uncompressed_size(self) -> DiffByteCount {
        self.uncompressed_size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiffArtifactMetadata {
    id: DiffId,
    compressed_hash: DiffPayloadHash,
    uncompressed_hash: DiffPayloadHash,
    compressed_size: DiffByteCount,
    uncompressed_size: DiffByteCount,
}

impl DiffArtifactMetadata {
    fn new(
        id: DiffId,
        compressed: &[u8],
        uncompressed: &[u8],
    ) -> Result<Self, DiffArtifactStoreError> {
        Ok(Self {
            id,
            compressed_hash: payload_hash(compressed),
            uncompressed_hash: payload_hash(uncompressed),
            compressed_size: byte_count(compressed.len())?,
            uncompressed_size: byte_count(uncompressed.len())?,
        })
    }

    const fn expectation(&self) -> DiffArtifactExpectation {
        DiffArtifactExpectation::new(
            self.id,
            self.compressed_hash,
            self.uncompressed_hash,
            self.compressed_size,
            self.uncompressed_size,
        )
    }
}

fn compress_bounded(uncompressed: &[u8]) -> Result<Vec<u8>, DiffArtifactStoreError> {
    let writer = BoundedWriter::new(
        MAX_DIFF_COMPRESSED_BYTES,
        uncompressed.len().min(MAX_DIFF_COMPRESSED_BYTES),
    );
    let mut encoder = zstd::stream::write::Encoder::new(writer, DIFF_ZSTD_LEVEL)
        .map_err(|_| DiffArtifactStoreError::CorruptPayload)?;
    encoder
        .include_checksum(true)
        .map_err(|_| DiffArtifactStoreError::CorruptPayload)?;
    if let Err(source) = encoder.write_all(uncompressed) {
        return if source.kind() == io::ErrorKind::FileTooLarge {
            Err(DiffArtifactStoreError::CompressedTooLarge {
                maximum: MAX_DIFF_COMPRESSED_BYTES,
            })
        } else {
            Err(DiffArtifactStoreError::Io {
                operation: DiffArtifactOperation::Compress,
                source,
            })
        };
    }
    let writer = encoder.finish().map_err(|source| {
        if source.kind() == io::ErrorKind::FileTooLarge {
            DiffArtifactStoreError::CompressedTooLarge {
                maximum: MAX_DIFF_COMPRESSED_BYTES,
            }
        } else {
            DiffArtifactStoreError::Io {
                operation: DiffArtifactOperation::Compress,
                source,
            }
        }
    })?;
    Ok(writer.into_inner())
}

fn decompress_bounded(compressed: &[u8]) -> Result<Vec<u8>, DiffArtifactStoreError> {
    let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))
        .map_err(|_| DiffArtifactStoreError::CorruptPayload)?;
    let mut output = Vec::with_capacity(compressed.len().min(MAX_DIFF_RENDERED_BYTES));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|_| DiffArtifactStoreError::CorruptPayload)?;
        if read == 0 {
            break;
        }
        if read > MAX_DIFF_RENDERED_BYTES.saturating_sub(output.len()) {
            return Err(DiffArtifactStoreError::RenderedTooLarge {
                maximum: MAX_DIFF_RENDERED_BYTES,
            });
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}

fn read_bounded_file(fd: OwnedFd, maximum: usize) -> Result<Vec<u8>, DiffArtifactStoreError> {
    let before = fstat(&fd).map_err(|source| DiffArtifactStoreError::Syscall {
        operation: DiffArtifactOperation::InspectArtifact,
        source,
    })?;
    let size =
        usize::try_from(before.st_size).map_err(|_| DiffArtifactStoreError::CorruptPayload)?;
    if size > maximum {
        return Err(DiffArtifactStoreError::CompressedTooLarge { maximum });
    }
    let mut file = File::from(fd);
    let mut output = Vec::with_capacity(size);
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| DiffArtifactStoreError::Io {
                operation: DiffArtifactOperation::ReadArtifact,
                source,
            })?;
        if read == 0 {
            break;
        }
        if read > maximum.saturating_sub(output.len()) {
            return Err(DiffArtifactStoreError::CompressedTooLarge { maximum });
        }
        output.extend_from_slice(&buffer[..read]);
    }
    let after = fstat(&file).map_err(|source| DiffArtifactStoreError::Syscall {
        operation: DiffArtifactOperation::InspectArtifact,
        source,
    })?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || after.st_nlink != 1
        || output.len() != size
    {
        return Err(DiffArtifactStoreError::CorruptPayload);
    }
    Ok(output)
}

fn verify_bytes(
    bytes: &[u8],
    expected_hash: DiffPayloadHash,
    expected_size: DiffByteCount,
) -> Result<(), DiffArtifactStoreError> {
    let actual_size = byte_count(bytes.len())?;
    if actual_size != expected_size || payload_hash(bytes) != expected_hash {
        Err(DiffArtifactStoreError::CorruptPayload)
    } else {
        Ok(())
    }
}

fn payload_hash(bytes: &[u8]) -> DiffPayloadHash {
    DiffPayloadHash::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn byte_count(length: usize) -> Result<DiffByteCount, DiffArtifactStoreError> {
    u64::try_from(length)
        .map(DiffByteCount::new)
        .map_err(|_| DiffArtifactStoreError::SizeOverflow)
}

fn pending_name(id: DiffId) -> OsString {
    OsString::from(format!(".diff-{id}.pending"))
}

fn final_name(id: DiffId) -> OsString {
    OsString::from(format!("diff_{id}.diff.zst"))
}

fn classify_inventory_name(value: &[u8]) -> (DiffArtifactInventoryKind, Option<DiffId>) {
    let original = value;
    let Ok(value) = std::str::from_utf8(original) else {
        return (DiffArtifactInventoryKind::Unknown, None);
    };
    if let Some(id) = value
        .strip_prefix(".diff-")
        .and_then(|value| value.strip_suffix(".pending"))
        .and_then(|value| DiffId::from_str(value).ok())
        && pending_name(id).as_bytes() == original
    {
        return (DiffArtifactInventoryKind::Pending, Some(id));
    }
    if let Some(id) = value
        .strip_prefix("diff_")
        .and_then(|value| value.strip_suffix(".diff.zst"))
        .and_then(|value| DiffId::from_str(value).ok())
        && final_name(id).as_bytes() == original
    {
        return (DiffArtifactInventoryKind::Final, Some(id));
    }
    (DiffArtifactInventoryKind::Unknown, None)
}

fn artifact_relative_path(
    name: &OsStr,
) -> Result<DiffArtifactRelativePath, DiffArtifactStoreError> {
    DiffArtifactRelativePath::new(PathBuf::from("diffs").join(name))
        .map_err(DiffArtifactStoreError::InvalidRelativePath)
}

/// Stable artifact I/O operation tag with no absolute path disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffArtifactOperation {
    OpenStateDirectory,
    OpenDiffDirectory,
    CreatePending,
    SetPendingMode,
    WritePending,
    SyncPending,
    SyncDiffDirectory,
    PublishFinal,
    RemovePending,
    OpenArtifact,
    InspectArtifact,
    ReadArtifact,
    ReadDiffDirectory,
    InspectDiffDirectoryPath,
    DeleteArtifact,
    Compress,
}

/// Typed bounded Diff artifact failure.
#[derive(Debug, Error)]
pub enum DiffArtifactStoreError {
    #[error("Diff artifact Workspace scope changed")]
    Scope(#[source] ConfinedFilesystemError),
    #[error("Diff artifact operation {operation:?} failed")]
    Syscall {
        operation: DiffArtifactOperation,
        #[source]
        source: Errno,
    },
    #[error("Diff artifact operation {operation:?} failed")]
    Io {
        operation: DiffArtifactOperation,
        #[source]
        source: io::Error,
    },
    #[error("Diff artifact identity collides with different pending bytes")]
    IdentityCollision,
    #[error("exclusive atomic Diff artifact publish is unsupported")]
    AtomicPublishUnsupported,
    #[error("Diff artifact is missing")]
    Missing,
    #[error("Diff artifact payload is corrupt")]
    CorruptPayload,
    #[error("compressed Diff artifact exceeds {maximum} bytes")]
    CompressedTooLarge { maximum: usize },
    #[error("rendered Diff artifact exceeds {maximum} bytes")]
    RenderedTooLarge { maximum: usize },
    #[error("Diff artifact size cannot be represented")]
    SizeOverflow,
    #[error("Diff artifact relative path is invalid")]
    InvalidRelativePath(#[source] DiffArtifactRelativePathError),
    #[error("Diff artifact inventory name is invalid")]
    InvalidInventoryName,
    #[error("Diff artifact directory path changed")]
    DirectoryPathChanged,
}

/// Render a deterministic, redacted, bounded unified diff.
///
/// Redaction is applied to both source sides before the diff algorithm sees
/// them. Binary, over-retained, over-line-count, and over-output inputs become
/// explicit summary-only evidence rather than truncated or lossy text.
pub fn render_diff_evidence(
    path: &WorkspaceRelativePath,
    kind: DiffChangeKind,
    pre: &CapturedDiffSource,
    post: &CapturedDiffSource,
) -> Result<RenderedDiffEvidence, DiffRenderError> {
    let (old, new) = match (pre, post) {
        (CapturedDiffSource::Oversized { .. }, _) | (_, CapturedDiffSource::Oversized { .. }) => {
            return Ok(RenderedDiffEvidence::SummaryOnly {
                render_kind: DiffRenderKind::Oversized,
            });
        }
        (CapturedDiffSource::Binary { .. }, _) | (_, CapturedDiffSource::Binary { .. }) => {
            return Ok(RenderedDiffEvidence::SummaryOnly {
                render_kind: DiffRenderKind::Binary,
            });
        }
        (CapturedDiffSource::Absent, CapturedDiffSource::Absent) => {
            return Err(DiffRenderError::InvalidSourcePair);
        }
        (CapturedDiffSource::Absent, CapturedDiffSource::Text(new)) => ("", new.as_str()),
        (CapturedDiffSource::Text(old), CapturedDiffSource::Absent) => (old.as_str(), ""),
        (CapturedDiffSource::Text(old), CapturedDiffSource::Text(new)) => {
            (old.as_str(), new.as_str())
        }
    };

    if line_count(old) > MAX_DIFF_SOURCE_LINES || line_count(new) > MAX_DIFF_SOURCE_LINES {
        return Ok(RenderedDiffEvidence::SummaryOnly {
            render_kind: DiffRenderKind::Oversized,
        });
    }

    let redacted_old = redact_text(old);
    let redacted_new = redact_text(new);
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Patience)
        .diff_lines(redacted_old.as_str(), redacted_new.as_str());
    let mut additions = 0_u32;
    let mut deletions = 0_u32;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => deletions = deletions.saturating_add(1),
            ChangeTag::Insert => additions = additions.saturating_add(1),
            ChangeTag::Equal => {}
        }
    }

    let (old_header, new_header) = diff_headers(path, kind);
    let initial_capacity = redacted_old
        .len()
        .saturating_add(redacted_new.len())
        .min(MAX_DIFF_RENDERED_BYTES);
    let mut output = BoundedWriter::new(MAX_DIFF_RENDERED_BYTES, initial_capacity);
    let write_result = diff
        .unified_diff()
        .context_radius(3)
        .header(&old_header, &new_header)
        .to_writer(&mut output);
    if output.overflowed() {
        return Ok(RenderedDiffEvidence::SummaryOnly {
            render_kind: DiffRenderKind::Oversized,
        });
    }
    write_result.map_err(DiffRenderError::Render)?;
    Ok(RenderedDiffEvidence::Text(RenderedTextDiff {
        bytes: output.into_inner(),
        additions: DiffLineCount::new(additions),
        deletions: DiffLineCount::new(deletions),
    }))
}

fn line_count(value: &str) -> usize {
    value.split_inclusive('\n').count()
}

fn redact_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut inside_private_key = false;
    for line in value.split_inclusive('\n') {
        let (body, ending) = strip_line_ending(line);
        let upper = body.to_ascii_uppercase();
        if inside_private_key {
            if is_private_key_end(&upper) {
                inside_private_key = false;
            }
            continue;
        }
        if is_private_key_begin(&upper) {
            output.push_str("[REDACTED PRIVATE KEY]");
            output.push_str(ending);
            inside_private_key = !is_private_key_end(&upper);
        } else {
            output.push_str(&redact_line(line));
        }
    }
    output
}

fn is_private_key_begin(value: &str) -> bool {
    value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
}

fn is_private_key_end(value: &str) -> bool {
    value.contains("-----END ") && value.contains("PRIVATE KEY-----")
}

fn redact_line(line: &str) -> String {
    let (body, ending) = strip_line_ending(line);
    let lower = body.to_ascii_lowercase();
    if let Some(bearer) = lower.find("bearer ") {
        let value_start = bearer + "bearer ".len();
        return format!("{}{}{}", &body[..value_start], REDACTED, ending);
    }

    let secret = SECRET_KEYS
        .iter()
        .filter_map(|key| find_bounded_key(&lower, key).map(|index| (index, key.len())))
        .min_by_key(|(index, _)| *index);
    let Some((index, key_len)) = secret else {
        return line.to_owned();
    };
    let suffix = &body[index + key_len..];
    let separator = suffix
        .char_indices()
        .find(|(offset, character)| *offset <= 32 && matches!(*character, '=' | ':'))
        .map(|(offset, character)| index + key_len + offset + character.len_utf8());
    let Some(value_start) = separator else {
        return line.to_owned();
    };
    format!("{} {}{}", &body[..value_start], REDACTED, ending)
}

fn strip_line_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

fn find_bounded_key(value: &str, key: &str) -> Option<usize> {
    value.match_indices(key).find_map(|(index, _)| {
        let before = value[..index].chars().next_back();
        let after = value[index + key.len()..].chars().next();
        let bounded_before = before.is_none_or(|character| !is_key_character(character));
        let bounded_after = after.is_none_or(|character| !is_key_character(character));
        (bounded_before && bounded_after).then_some(index)
    })
}

const fn is_key_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn diff_headers(path: &WorkspaceRelativePath, kind: DiffChangeKind) -> (String, String) {
    let encoded = diff_path_label(path);
    match kind {
        DiffChangeKind::Created => ("/dev/null".to_owned(), format!("b/{encoded}")),
        DiffChangeKind::Modified => (format!("a/{encoded}"), format!("b/{encoded}")),
        DiffChangeKind::Deleted => (format!("a/{encoded}"), "/dev/null".to_owned()),
    }
}

/// Lossless human-safe label for a native Workspace-relative path.
pub fn diff_path_label(path: &WorkspaceRelativePath) -> String {
    let native = path.as_path().as_os_str();
    if let Some(value) = native.to_str()
        && !value.chars().any(char::is_control)
    {
        return value.to_owned();
    }
    format!(
        ".native/{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(native.as_bytes())
    )
}

#[derive(Debug)]
struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
    overflowed: bool,
}

impl BoundedWriter {
    fn new(maximum: usize, initial_capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(initial_capacity),
            maximum,
            overflowed: false,
        }
    }

    const fn overflowed(&self) -> bool {
        self.overflowed
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.maximum.saturating_sub(self.bytes.len()) {
            self.overflowed = true;
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "bounded Diff renderer exceeded its output limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Typed deterministic renderer failure.
#[derive(Debug, Error)]
pub enum DiffRenderError {
    #[error("Diff source pair does not describe a file change")]
    InvalidSourcePair,
    #[error("unified Diff rendering failed")]
    Render(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use uuid::Uuid;

    use super::*;
    use crate::{ConfinedWorkspace, WorkspaceStateLayout};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
    }

    fn rendered_text(
        rendered: RenderedDiffEvidence,
    ) -> Result<RenderedTextDiff, Box<dyn std::error::Error>> {
        match rendered {
            RenderedDiffEvidence::Text(text) => Ok(text),
            RenderedDiffEvidence::SummaryOnly { .. } => Err("expected text Diff".into()),
        }
    }

    fn workspace_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "forge-diff-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        WorkspaceStateLayout::initialize(&root)?;
        Ok(root)
    }

    fn artifact_store(root: &PathBuf) -> Result<DiffArtifactStore, Box<dyn std::error::Error>> {
        let layout = WorkspaceStateLayout::inspect_existing(root)?.ok_or("missing layout")?;
        Ok(ConfinedWorkspace::open(&layout)?.diff_artifact_store()?)
    }

    #[test]
    fn text_diff_is_deterministic_bounded_and_uses_safe_headers()
    -> Result<(), Box<dyn std::error::Error>> {
        let pre = CapturedDiffSource::Text("one\ntwo\n".to_owned());
        let post = CapturedDiffSource::Text("one\nthree\n".to_owned());
        let first = rendered_text(render_diff_evidence(
            &path("src/main.rs")?,
            DiffChangeKind::Modified,
            &pre,
            &post,
        )?)?;
        let second = rendered_text(render_diff_evidence(
            &path("src/main.rs")?,
            DiffChangeKind::Modified,
            &pre,
            &post,
        )?)?;
        assert_eq!(first, second);
        assert!(first.bytes().len() <= MAX_DIFF_RENDERED_BYTES);
        let display = std::str::from_utf8(first.bytes())?;
        assert!(display.starts_with("--- a/src/main.rs\n+++ b/src/main.rs\n"));
        assert!(display.contains("-two\n+three\n"));
        assert_eq!(first.additions().get(), 1);
        assert_eq!(first.deletions().get(), 1);
        Ok(())
    }

    #[test]
    fn redaction_happens_before_any_rendered_payload_is_exposed()
    -> Result<(), Box<dyn std::error::Error>> {
        let pre = CapturedDiffSource::Text(
            "api_key = old-value\nAuthorization: Bearer old-token\n-----BEGIN PRIVATE KEY-----\nold-private-material\n-----END PRIVATE KEY-----\nunchanged\n".to_owned(),
        );
        let post = CapturedDiffSource::Text(
            "api_key = new-value\nAuthorization: Bearer new-token\n-----BEGIN PRIVATE KEY-----\nnew-private-material\n-----END PRIVATE KEY-----\nchanged\n".to_owned(),
        );
        let rendered = rendered_text(render_diff_evidence(
            &path("config.env")?,
            DiffChangeKind::Modified,
            &pre,
            &post,
        )?)?;
        let display = std::str::from_utf8(rendered.bytes())?;
        assert!(!display.contains("old-value"));
        assert!(!display.contains("new-value"));
        assert!(!display.contains("old-token"));
        assert!(!display.contains("new-token"));
        assert!(!display.contains("old-private-material"));
        assert!(!display.contains("new-private-material"));
        assert!(display.contains(REDACTED));
        assert!(display.contains("[REDACTED PRIVATE KEY]"));
        assert!(display.contains("-unchanged\n+changed\n"));
        Ok(())
    }

    #[test]
    fn binary_oversized_and_path_controls_fail_closed_to_safe_projections()
    -> Result<(), Box<dyn std::error::Error>> {
        let binary = CapturedDiffSource::Binary {
            size: forge_domain::FileByteCount::new(3),
        };
        let absent = CapturedDiffSource::Absent;
        assert_eq!(
            render_diff_evidence(
                &path("image.bin")?,
                DiffChangeKind::Created,
                &absent,
                &binary,
            )?,
            RenderedDiffEvidence::SummaryOnly {
                render_kind: DiffRenderKind::Binary,
            }
        );

        let oversized = CapturedDiffSource::Oversized {
            size: forge_domain::FileByteCount::new(65_537),
        };
        assert_eq!(
            render_diff_evidence(
                &path("large.txt")?,
                DiffChangeKind::Deleted,
                &oversized,
                &absent,
            )?,
            RenderedDiffEvidence::SummaryOnly {
                render_kind: DiffRenderKind::Oversized,
            }
        );

        let native_path = WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(vec![
            b'f', b'o', 0x80, b'o',
        ])))?;
        let text = rendered_text(render_diff_evidence(
            &native_path,
            DiffChangeKind::Created,
            &absent,
            &CapturedDiffSource::Text("safe\n".to_owned()),
        )?)?;
        let display = std::str::from_utf8(text.bytes())?;
        assert!(display.contains("+++ b/.native/"));
        assert!(!display.contains(char::REPLACEMENT_CHARACTER));
        Ok(())
    }

    #[test]
    fn artifact_stage_publish_read_and_doctor_are_hash_bound_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root("lifecycle")?;
        let store = artifact_store(&root)?;
        let rendered = rendered_text(render_diff_evidence(
            &path("config.env")?,
            DiffChangeKind::Modified,
            &CapturedDiffSource::Text("token = old-secret\nline = old\n".to_owned()),
            &CapturedDiffSource::Text("token = new-secret\nline = new\n".to_owned()),
        )?)?;
        let id = DiffId::from_uuid(Uuid::from_u128(0xD1FF));
        let staged = store.stage(id, &rendered)?;
        let retry = store.stage(id, &rendered)?;
        assert_eq!(staged.compressed_hash(), retry.compressed_hash());
        assert_eq!(staged.uncompressed_hash(), retry.uncompressed_hash());
        assert_eq!(staged.final_relative_path()?, retry.final_relative_path()?);
        assert_eq!(
            store.doctor_pending(&staged.expectation())?,
            DiffArtifactHealth::Available
        );
        assert_eq!(
            store.doctor(&staged.expectation())?,
            DiffArtifactHealth::Missing
        );

        let pending = root
            .join(".heterarchy-forge")
            .join(staged.pending_relative_path()?.as_path());
        assert!(pending.is_file());
        let redacted = zstd::stream::decode_all(Cursor::new(fs::read(&pending)?))?;
        assert!(
            !redacted
                .windows(b"old-secret".len())
                .any(|w| w == b"old-secret")
        );
        assert!(
            !redacted
                .windows(b"new-secret".len())
                .any(|w| w == b"new-secret")
        );
        assert!(
            redacted
                .windows(REDACTED.len())
                .any(|w| w == REDACTED.as_bytes())
        );

        let published = store.publish(staged)?;
        let expected = published.expectation();
        assert_eq!(store.read(&expected)?, rendered.bytes());
        assert_eq!(store.doctor(&expected)?, DiffArtifactHealth::Available);
        assert_eq!(
            store.doctor_pending(&expected)?,
            DiffArtifactHealth::Missing
        );
        assert!(!pending.exists());
        let final_path = root
            .join(".heterarchy-forge")
            .join(published.relative_path()?.as_path());
        assert!(final_path.is_file());

        fs::write(&final_path, b"corrupt")?;
        assert_eq!(store.doctor(&expected)?, DiffArtifactHealth::Corrupt);
        fs::remove_file(&final_path)?;
        assert_eq!(store.doctor(&expected)?, DiffArtifactHealth::Missing);
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn crash_like_pending_retry_converges_and_collision_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root("pending-retry")?;
        let id = DiffId::from_uuid(Uuid::from_u128(0xD200));
        let first_render = rendered_text(render_diff_evidence(
            &path("src/lib.rs")?,
            DiffChangeKind::Modified,
            &CapturedDiffSource::Text("old\n".to_owned()),
            &CapturedDiffSource::Text("new\n".to_owned()),
        )?)?;
        let different_render = rendered_text(render_diff_evidence(
            &path("src/lib.rs")?,
            DiffChangeKind::Modified,
            &CapturedDiffSource::Text("old\n".to_owned()),
            &CapturedDiffSource::Text("different\n".to_owned()),
        )?)?;

        let first_store = artifact_store(&root)?;
        let first = first_store.stage(id, &first_render)?;
        drop(first_store);
        let reopened = artifact_store(&root)?;
        assert!(matches!(
            reopened.stage(id, &different_render),
            Err(DiffArtifactStoreError::IdentityCollision)
        ));
        let retry = reopened.stage(id, &first_render)?;
        assert_eq!(first.compressed_hash(), retry.compressed_hash());
        let published = reopened.publish(retry)?;
        assert_eq!(
            reopened.read(&published.expectation())?,
            first_render.bytes()
        );
        drop(first);
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn inventory_and_hash_bound_deletion_are_bounded_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root("inventory-delete")?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let confined = ConfinedWorkspace::open(&layout)?;
        let guard = confined.acquire_write_guard()?;
        let store = confined.diff_artifact_store()?;
        let rendered = rendered_text(render_diff_evidence(
            &path("purge.txt")?,
            DiffChangeKind::Created,
            &CapturedDiffSource::Absent,
            &CapturedDiffSource::Text("purge me\n".to_owned()),
        )?)?;
        let id = DiffId::from_uuid(Uuid::from_u128(0xD400));
        let staged = store.stage(id, &rendered)?;
        let pending_inventory = store.inventory(DiffArtifactInventoryLimit::new(10)?)?;
        assert!(!pending_inventory.truncated());
        assert_eq!(pending_inventory.entries().len(), 1);
        assert_eq!(
            pending_inventory.entries()[0].kind(),
            DiffArtifactInventoryKind::Pending
        );
        let published = store.publish(staged)?;
        let final_inventory = store.inventory(DiffArtifactInventoryLimit::new(10)?)?;
        assert_eq!(final_inventory.entries().len(), 1);
        assert_eq!(
            final_inventory.entries()[0].kind(),
            DiffArtifactInventoryKind::Final
        );
        assert_eq!(final_inventory.entries()[0].diff_id(), Some(id));
        assert_eq!(
            store.delete_published(&published.expectation())?,
            DiffArtifactDeleteStatus::Deleted
        );
        assert_eq!(
            store.delete_published(&published.expectation())?,
            DiffArtifactDeleteStatus::AlreadyMissing
        );

        let orphan_name = b"unexpected.orphan";
        let orphan_bytes = b"bounded orphan bytes";
        fs::write(
            layout.diffs().join(OsStr::from_bytes(orphan_name)),
            orphan_bytes,
        )?;
        let inventory = store.inventory(DiffArtifactInventoryLimit::new(10)?)?;
        assert_eq!(inventory.entries().len(), 1);
        let orphan = &inventory.entries()[0];
        assert_eq!(orphan.kind(), DiffArtifactInventoryKind::Unknown);
        let wrong = DeleteOrphanDiffArtifact::new(
            orphan.name().clone(),
            DiffPayloadHash::from_bytes([9; 32]),
            orphan.compressed_size(),
        );
        assert!(matches!(
            store.delete_orphan(&wrong),
            Err(DiffArtifactStoreError::CorruptPayload)
        ));
        let delete = DeleteOrphanDiffArtifact::new(
            orphan.name().clone(),
            orphan.compressed_hash(),
            orphan.compressed_size(),
        );
        assert_eq!(
            store.delete_orphan(&delete)?,
            DiffArtifactDeleteStatus::Deleted
        );
        assert_eq!(
            store.delete_orphan(&delete)?,
            DiffArtifactDeleteStatus::AlreadyMissing
        );
        fs::write(layout.diffs().join("orphan-a"), b"a")?;
        fs::write(layout.diffs().join("orphan-b"), b"b")?;
        let truncated = store.inventory(DiffArtifactInventoryLimit::new(1)?)?;
        assert_eq!(truncated.entries().len(), 1);
        assert!(truncated.truncated());
        drop(store);
        drop(guard);
        drop(confined);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn inventory_classifies_invalid_nodes_and_bounds_all_observed_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root("invalid-inventory")?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let confined = ConfinedWorkspace::open(&layout)?;
        let store = confined.diff_artifact_store()?;
        let diffs = layout.diffs();

        fs::write(diffs.join("valid.orphan"), b"valid")?;
        symlink("valid.orphan", diffs.join("bad-link"))?;
        fs::create_dir(diffs.join("bad-directory"))?;
        let hardlink_source = root.join("hardlink-source");
        fs::write(&hardlink_source, b"hardlink")?;
        fs::hard_link(&hardlink_source, diffs.join("bad-hardlink"))?;

        let inventory = store.inventory(DiffArtifactInventoryLimit::new(16)?)?;
        assert!(!inventory.truncated());
        assert_eq!(inventory.entries().len(), 1);
        assert_eq!(inventory.entries()[0].name().as_bytes(), b"valid.orphan");
        assert_eq!(inventory.invalid_entries().len(), 3);
        assert!(inventory.invalid_entries().iter().any(|entry| {
            entry.name().as_bytes() == b"bad-link"
                && entry.reason() == DiffArtifactInvalidReason::Symlink
        }));
        assert!(inventory.invalid_entries().iter().any(|entry| {
            entry.name().as_bytes() == b"bad-directory"
                && entry.reason() == DiffArtifactInvalidReason::NonRegular
        }));
        assert!(inventory.invalid_entries().iter().any(|entry| {
            entry.name().as_bytes() == b"bad-hardlink"
                && entry.reason() == DiffArtifactInvalidReason::Hardlink
        }));

        let bounded = store.inventory(DiffArtifactInventoryLimit::new(1)?)?;
        assert!(bounded.truncated());
        assert!(bounded.entries().len() + bounded.invalid_entries().len() <= 1);

        drop(store);
        drop(confined);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn renamed_diff_directory_is_rejected_before_staging() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = workspace_root("directory-race")?;
        let store = artifact_store(&root)?;
        let state = root.join(".heterarchy-forge");
        fs::rename(state.join("diffs"), state.join("diffs-moved"))?;
        fs::create_dir(state.join("diffs"))?;
        let rendered = rendered_text(render_diff_evidence(
            &path("file.txt")?,
            DiffChangeKind::Created,
            &CapturedDiffSource::Absent,
            &CapturedDiffSource::Text("safe\n".to_owned()),
        )?)?;
        assert!(matches!(
            store.stage(DiffId::from_uuid(Uuid::from_u128(0xD300)), &rendered),
            Err(DiffArtifactStoreError::Scope(_))
        ));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
