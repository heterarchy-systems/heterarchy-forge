//! Deterministic identity and manifest for frozen verification input.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{FileByteCount, FileContentHash, FileContentHashParseError, WorkspaceRelativePath};

pub const MAX_VERIFICATION_INPUT_FILES: usize = 4_096;
pub const MAX_VERIFICATION_INPUT_ENTRIES: usize = 16_384;
pub const MAX_VERIFICATION_INPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_VERIFICATION_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_VERIFICATION_INPUT_PATH_BYTES: usize = 512 * 1024;

/// Opaque snapshot identity; generation belongs to the calling effect boundary.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VerificationInputId(Uuid);

impl VerificationInputId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for VerificationInputId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for VerificationInputId {
    type Err = VerificationInputIdError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id = Uuid::parse_str(value).map_err(VerificationInputIdError::InvalidUuid)?;
        if id.hyphenated().to_string() != value {
            return Err(VerificationInputIdError::NonCanonical);
        }
        Ok(Self(id))
    }
}

#[derive(Debug, Error)]
pub enum VerificationInputIdError {
    #[error("verification input identity is invalid")]
    InvalidUuid(#[source] uuid::Error),
    #[error("verification input identity must be canonical lowercase UUID text")]
    NonCanonical,
}

/// Coverage/manifest policy is persisted; an unknown policy is never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationInputPolicy {
    V1,
}

impl VerificationInputPolicy {
    pub const fn version(self) -> u32 {
        match self {
            Self::V1 => 1,
        }
    }
    pub const fn from_version(value: u32) -> Result<Self, VerificationInputManifestError> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(VerificationInputManifestError::UnsupportedPolicy),
        }
    }
}

/// Manifest fingerprint, deliberately distinct from an individual file hash.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerificationInputFingerprint([u8; 32]);

impl VerificationInputFingerprint {
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for VerificationInputFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        FileContentHash::from_bytes(self.0).fmt(f)
    }
}

impl FromStr for VerificationInputFingerprint {
    type Err = VerificationInputFingerprintError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hash = FileContentHash::from_str(value).map_err(VerificationInputFingerprintError)?;
        Ok(Self(*hash.as_bytes()))
    }
}

#[derive(Debug, Error)]
#[error("verification input fingerprint is invalid")]
pub struct VerificationInputFingerprintError(#[source] FileContentHashParseError);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationInputEntryKind {
    Directory,
    File {
        size: FileByteCount,
        content_hash: FileContentHash,
    },
}

/// Metadata only. Source bytes never enter the domain manifest.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationInputEntry {
    path: WorkspaceRelativePath,
    mode: u16,
    kind: VerificationInputEntryKind,
}

impl VerificationInputEntry {
    pub fn directory(
        path: WorkspaceRelativePath,
        mode: u16,
    ) -> Result<Self, VerificationInputManifestError> {
        Self::new(path, mode, VerificationInputEntryKind::Directory)
    }

    pub fn file(
        path: WorkspaceRelativePath,
        mode: u16,
        size: FileByteCount,
        content_hash: FileContentHash,
    ) -> Result<Self, VerificationInputManifestError> {
        if size.get() > MAX_VERIFICATION_INPUT_FILE_BYTES {
            return Err(VerificationInputManifestError::FileCapacity);
        }
        Self::new(
            path,
            mode,
            VerificationInputEntryKind::File { size, content_hash },
        )
    }

    fn new(
        path: WorkspaceRelativePath,
        mode: u16,
        kind: VerificationInputEntryKind,
    ) -> Result<Self, VerificationInputManifestError> {
        if mode & !0o777 != 0 {
            return Err(VerificationInputManifestError::UnsupportedMode);
        }
        Ok(Self { path, mode, kind })
    }

    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }
    pub const fn mode(&self) -> u16 {
        self.mode
    }
    pub const fn kind(&self) -> VerificationInputEntryKind {
        self.kind
    }
}

/// Canonically ordered, complete directory hierarchy for one frozen input.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerificationInputManifest {
    policy: VerificationInputPolicy,
    entries: Vec<VerificationInputEntry>,
    fingerprint: VerificationInputFingerprint,
    file_count: usize,
    total_bytes: FileByteCount,
}

impl VerificationInputManifest {
    pub fn new(
        policy: VerificationInputPolicy,
        mut entries: Vec<VerificationInputEntry>,
    ) -> Result<Self, VerificationInputManifestError> {
        if entries.len() > MAX_VERIFICATION_INPUT_ENTRIES {
            return Err(VerificationInputManifestError::EntryCapacity);
        }
        entries.sort_by(|left, right| path_bytes(left.path()).cmp(path_bytes(right.path())));
        let (file_count, total_bytes) = validate_entries(&entries)?;
        let fingerprint = fingerprint(policy, &entries);
        Ok(Self {
            policy,
            entries,
            fingerprint,
            file_count,
            total_bytes: FileByteCount::new(total_bytes),
        })
    }

    pub const fn policy(&self) -> VerificationInputPolicy {
        self.policy
    }
    pub fn entries(&self) -> &[VerificationInputEntry] {
        &self.entries
    }
    pub const fn fingerprint(&self) -> VerificationInputFingerprint {
        self.fingerprint
    }
    pub const fn file_count(&self) -> usize {
        self.file_count
    }
    pub const fn total_bytes(&self) -> FileByteCount {
        self.total_bytes
    }
}

impl fmt::Debug for VerificationInputManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationInputManifest")
            .field("policy", &self.policy)
            .field("entries", &self.entries.len())
            .field("files", &self.file_count)
            .field("bytes", &self.total_bytes)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

fn path_bytes(path: &WorkspaceRelativePath) -> &[u8] {
    path.as_path().as_os_str().as_encoded_bytes()
}

fn validate_entries(
    entries: &[VerificationInputEntry],
) -> Result<(usize, u64), VerificationInputManifestError> {
    let mut directories: BTreeSet<&Path> = BTreeSet::new();
    let mut previous = None;
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    let mut path_size = 0_usize;
    for entry in entries {
        let path = entry.path().as_path();
        if previous == Some(path) {
            return Err(VerificationInputManifestError::DuplicatePath);
        }
        previous = Some(path);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            && !directories.contains(parent)
        {
            return Err(VerificationInputManifestError::MissingParent);
        }
        path_size = path_size
            .checked_add(path_bytes(entry.path()).len())
            .ok_or(VerificationInputManifestError::PathCapacity)?;
        if path_size > MAX_VERIFICATION_INPUT_PATH_BYTES {
            return Err(VerificationInputManifestError::PathCapacity);
        }
        match entry.kind() {
            VerificationInputEntryKind::Directory => {
                directories.insert(path);
            }
            VerificationInputEntryKind::File { size, .. } => {
                files += 1;
                bytes = bytes
                    .checked_add(size.get())
                    .ok_or(VerificationInputManifestError::ByteCapacity)?;
                if files > MAX_VERIFICATION_INPUT_FILES {
                    return Err(VerificationInputManifestError::FileCapacity);
                }
                if bytes > MAX_VERIFICATION_INPUT_BYTES {
                    return Err(VerificationInputManifestError::ByteCapacity);
                }
            }
        }
    }
    Ok((files, bytes))
}

fn fingerprint(
    policy: VerificationInputPolicy,
    entries: &[VerificationInputEntry],
) -> VerificationInputFingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"heterarchy-forge-verification-input\0");
    hasher.update(&policy.version().to_le_bytes());
    for entry in entries {
        let path = path_bytes(entry.path());
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path);
        hasher.update(&entry.mode().to_le_bytes());
        match entry.kind() {
            VerificationInputEntryKind::Directory => {
                hasher.update(&[0]);
            }
            VerificationInputEntryKind::File { size, content_hash } => {
                hasher.update(&[1]);
                hasher.update(&size.get().to_le_bytes());
                hasher.update(content_hash.as_bytes());
            }
        }
    }
    VerificationInputFingerprint::from_bytes(*hasher.finalize().as_bytes())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationInputManifestError {
    #[error("verification input policy is unsupported")]
    UnsupportedPolicy,
    #[error("verification input contains an unsupported file mode")]
    UnsupportedMode,
    #[error("verification input exceeds its entry bound")]
    EntryCapacity,
    #[error("verification input exceeds its file count or per-file bound")]
    FileCapacity,
    #[error("verification input exceeds its aggregate byte bound")]
    ByteCapacity,
    #[error("verification input exceeds its path metadata bound")]
    PathCapacity,
    #[error("verification input repeats a path")]
    DuplicatePath,
    #[error("verification input omits a parent directory or uses a file as parent")]
    MissingParent,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(
        path: &str,
        value: &[u8],
        mode: u16,
    ) -> Result<VerificationInputEntry, Box<dyn std::error::Error>> {
        Ok(VerificationInputEntry::file(
            WorkspaceRelativePath::new(path.into())?,
            mode,
            FileByteCount::new(u64::try_from(value.len())?),
            FileContentHash::from_bytes(*blake3::hash(value).as_bytes()),
        )?)
    }

    #[test]
    fn fingerprint_is_order_independent_but_binds_content_paths_and_modes()
    -> Result<(), Box<dyn std::error::Error>> {
        let entries = vec![
            file("Cargo.toml", b"manifest", 0o644)?,
            file("build.rs", b"build", 0o755)?,
        ];
        let baseline =
            VerificationInputManifest::new(VerificationInputPolicy::V1, entries.clone())?;
        let mut reordered = entries.clone();
        reordered.reverse();
        assert_eq!(
            baseline,
            VerificationInputManifest::new(VerificationInputPolicy::V1, reordered)?
        );
        for changed in [
            file("build.rs", b"different", 0o755)?,
            file("build.rs", b"build", 0o644)?,
            file("other.rs", b"build", 0o755)?,
        ] {
            let candidate = VerificationInputManifest::new(
                VerificationInputPolicy::V1,
                vec![entries[0].clone(), changed],
            )?;
            assert_ne!(baseline.fingerprint(), candidate.fingerprint());
        }
        assert_eq!(baseline.file_count(), 2);
        assert_eq!(baseline.total_bytes().get(), 13);
        Ok(())
    }

    #[test]
    fn hierarchy_rejects_missing_parent_duplicate_and_file_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let child = file("src/main.rs", b"fn main() {}", 0o644)?;
        assert_eq!(
            VerificationInputManifest::new(VerificationInputPolicy::V1, vec![child.clone()]).err(),
            Some(VerificationInputManifestError::MissingParent)
        );
        let directory =
            VerificationInputEntry::directory(WorkspaceRelativePath::new("src".into())?, 0o755)?;
        assert!(
            VerificationInputManifest::new(
                VerificationInputPolicy::V1,
                vec![child.clone(), directory.clone()]
            )
            .is_ok()
        );
        assert_eq!(
            VerificationInputManifest::new(
                VerificationInputPolicy::V1,
                vec![directory.clone(), directory]
            )
            .err(),
            Some(VerificationInputManifestError::DuplicatePath)
        );
        assert_eq!(
            VerificationInputManifest::new(
                VerificationInputPolicy::V1,
                vec![file("src", b"file", 0o644)?, child]
            )
            .err(),
            Some(VerificationInputManifestError::MissingParent)
        );
        Ok(())
    }

    #[test]
    fn input_bounds_and_unknown_policy_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            VerificationInputPolicy::from_version(2).err(),
            Some(VerificationInputManifestError::UnsupportedPolicy)
        );
        assert_eq!(
            VerificationInputEntry::file(
                WorkspaceRelativePath::new("large".into())?,
                0o644,
                FileByteCount::new(MAX_VERIFICATION_INPUT_FILE_BYTES + 1),
                FileContentHash::from_bytes([0; 32])
            )
            .err(),
            Some(VerificationInputManifestError::FileCapacity)
        );
        assert_eq!(
            file("setuid", b"x", 0o4644)
                .err()
                .map(|error| error.to_string()),
            Some(VerificationInputManifestError::UnsupportedMode.to_string())
        );
        let entries = (0..5)
            .map(|index| {
                VerificationInputEntry::file(
                    WorkspaceRelativePath::new(format!("file-{index}").into())
                        .map_err(|_| VerificationInputManifestError::PathCapacity)?,
                    0o644,
                    FileByteCount::new(MAX_VERIFICATION_INPUT_FILE_BYTES),
                    FileContentHash::from_bytes([0; 32]),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            VerificationInputManifest::new(VerificationInputPolicy::V1, entries).err(),
            Some(VerificationInputManifestError::ByteCapacity)
        );
        Ok(())
    }
}
