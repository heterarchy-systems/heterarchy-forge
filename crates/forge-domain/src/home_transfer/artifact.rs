//! Immutable, bounded identity and manifest contracts for Home handback bytes.
//!
//! This module describes a declared-path archive. It does not claim that the
//! sequential reads formed an atomic Workspace snapshot, that the declared
//! paths exhaust unfinished work, or that a Git object has been retained.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    AgentAssignmentId, AgentAssignmentRevision, CheckpointFileMode, FileByteCount, FileContentHash,
    GitBlobId, GitCommitId, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
};

pub const MAX_HOME_ARTIFACT_PATHS: usize = 256;
pub const MAX_HOME_ARTIFACT_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_HOME_ARTIFACT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_HOME_ARTIFACT_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

const INTENT_MAGIC: &[u8; 5] = b"FHCI\x01";
const MANIFEST_MAGIC: &[u8; 5] = b"FHAM\x01";
const ARCHIVE_MAGIC: &[u8; 5] = b"FHAA\x01";
const INTENT_DOMAIN: &[u8] = b"heterarchy.forge.home-artifact.capture-intent.v1\0";
const MANIFEST_DOMAIN: &[u8] = b"heterarchy.forge.home-artifact.manifest.v1\0";
const ARCHIVE_DOMAIN: &[u8] = b"heterarchy.forge.home-artifact.archive.v1\0";
const DIGEST_BYTES: usize = 32;
const SHA1_BYTES: usize = 20;

/// Genuine identity for one immutable retained Home handback archive.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeArtifactId(Uuid);

impl HomeArtifactId {
    /// Construct one non-nil artifact identity.
    pub fn new(value: Uuid) -> Result<Self, HomeArtifactIdError> {
        if value.is_nil() {
            return Err(HomeArtifactIdError::Nil);
        }
        Ok(Self(value))
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl FromStr for HomeArtifactId {
    type Err = HomeArtifactIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = Uuid::parse_str(value).map_err(HomeArtifactIdParseError::InvalidUuid)?;
        Self::new(value).map_err(HomeArtifactIdParseError::InvalidIdentity)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HomeArtifactIdError {
    #[error("Home artifact identity must not be nil")]
    Nil,
}

#[derive(Debug, Error)]
pub enum HomeArtifactIdParseError {
    #[error("Home artifact UUID is invalid")]
    InvalidUuid(#[source] uuid::Error),
    #[error(transparent)]
    InvalidIdentity(#[from] HomeArtifactIdError),
}

/// Digest of the canonical immutable capture intent.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeArtifactIntentDigest([u8; DIGEST_BYTES]);

impl HomeArtifactIntentDigest {
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// Exact paths and immutable Home lineage promised by one artifact capture.
///
/// `paths` retain caller order. Non-UTF-8 native paths are rejected by the
/// constructor before any filesystem access so the durable snapshot has one
/// portable, byte-exact path representation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactCaptureIntent {
    artifact_id: HomeArtifactId,
    preparation_id: Uuid,
    handoff_id: Uuid,
    workspace_id: WorkspaceId,
    predecessor_assignment_id: AgentAssignmentId,
    predecessor_revision: AgentAssignmentRevision,
    root_assignment_id: AgentAssignmentId,
    paths: Vec<WorkspaceRelativePath>,
    digest: HomeArtifactIntentDigest,
}

impl HomeArtifactCaptureIntent {
    #[allow(
        clippy::too_many_arguments,
        reason = "this constructor validates the complete immutable Home capture binding"
    )]
    pub fn new(
        artifact_id: HomeArtifactId,
        preparation_id: Uuid,
        handoff_id: Uuid,
        workspace_id: WorkspaceId,
        predecessor_assignment_id: AgentAssignmentId,
        predecessor_revision: AgentAssignmentRevision,
        root_assignment_id: AgentAssignmentId,
        paths: Vec<WorkspaceRelativePath>,
    ) -> Result<Self, HomeArtifactCaptureIntentError> {
        if preparation_id.is_nil() {
            return Err(HomeArtifactCaptureIntentError::NilIdentity("preparation"));
        }
        if handoff_id.is_nil() {
            return Err(HomeArtifactCaptureIntentError::NilIdentity("handoff"));
        }
        if workspace_id.into_uuid().is_nil() {
            return Err(HomeArtifactCaptureIntentError::NilIdentity("Workspace"));
        }
        if predecessor_assignment_id.into_uuid().is_nil() {
            return Err(HomeArtifactCaptureIntentError::NilIdentity(
                "predecessor assignment",
            ));
        }
        if root_assignment_id.into_uuid().is_nil() {
            return Err(HomeArtifactCaptureIntentError::NilIdentity(
                "root assignment",
            ));
        }
        if paths.len() > MAX_HOME_ARTIFACT_PATHS {
            return Err(HomeArtifactCaptureIntentError::PathLimit {
                actual: paths.len(),
                maximum: MAX_HOME_ARTIFACT_PATHS,
            });
        }

        let mut unique = BTreeSet::new();
        for path in &paths {
            if path.as_path().to_str().is_none() {
                return Err(HomeArtifactCaptureIntentError::NonUtf8Path);
            }
            if !unique.insert(path) {
                return Err(HomeArtifactCaptureIntentError::DuplicatePath);
            }
        }

        let mut intent = Self {
            artifact_id,
            preparation_id,
            handoff_id,
            workspace_id,
            predecessor_assignment_id,
            predecessor_revision,
            root_assignment_id,
            paths,
            digest: HomeArtifactIntentDigest([0; DIGEST_BYTES]),
        };
        let body = intent.body_bytes()?;
        intent.digest = HomeArtifactIntentDigest(digest(INTENT_DOMAIN, &body));
        Ok(intent)
    }

    pub const fn artifact_id(&self) -> HomeArtifactId {
        self.artifact_id
    }

    pub const fn preparation_id(&self) -> Uuid {
        self.preparation_id
    }

    pub const fn handoff_id(&self) -> Uuid {
        self.handoff_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn predecessor_assignment_id(&self) -> AgentAssignmentId {
        self.predecessor_assignment_id
    }

    pub const fn predecessor_revision(&self) -> AgentAssignmentRevision {
        self.predecessor_revision
    }

    pub const fn root_assignment_id(&self) -> AgentAssignmentId {
        self.root_assignment_id
    }

    pub fn paths(&self) -> &[WorkspaceRelativePath] {
        &self.paths
    }

    pub const fn digest(&self) -> HomeArtifactIntentDigest {
        self.digest
    }

    /// Encode the validated intent as a canonical bounded snapshot.
    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>, HomeArtifactCaptureIntentError> {
        let body = self.body_bytes()?;
        if body.len().saturating_add(DIGEST_BYTES) > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
            return Err(HomeArtifactCaptureIntentError::SnapshotTooLarge);
        }
        let mut bytes = body;
        bytes.extend_from_slice(self.digest.as_bytes());
        Ok(bytes)
    }

    /// Decode one canonical intent snapshot and verify its embedded digest.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, HomeArtifactCaptureIntentError> {
        if bytes.len() > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
            return Err(HomeArtifactCaptureIntentError::SnapshotTooLarge);
        }
        let (body, expected_digest) =
            split_digest(bytes).ok_or(HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        if digest(INTENT_DOMAIN, body).as_slice() != expected_digest {
            return Err(HomeArtifactCaptureIntentError::DigestMismatch);
        }

        let mut reader = SnapshotReader::new(body);
        if reader.take(INTENT_MAGIC.len()) != Some(INTENT_MAGIC.as_slice()) {
            return Err(HomeArtifactCaptureIntentError::InvalidSnapshot);
        }
        let artifact_id = HomeArtifactId::new(reader.uuid()?)?;
        let preparation_id = reader.uuid()?;
        let handoff_id = reader.uuid()?;
        let workspace_id = WorkspaceId::from_uuid(reader.uuid()?);
        let predecessor_assignment_id = AgentAssignmentId::from_uuid(reader.uuid()?);
        let predecessor_revision = AgentAssignmentRevision::new(reader.i64()?)
            .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        let root_assignment_id = AgentAssignmentId::from_uuid(reader.uuid()?);
        let path_count = reader.count(MAX_HOME_ARTIFACT_PATHS)?;
        let mut paths = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            let path_bytes = reader.length_prefixed_intent(MAX_HOME_ARTIFACT_MANIFEST_BYTES)?;
            let path_text = std::str::from_utf8(path_bytes)
                .map_err(|_| HomeArtifactCaptureIntentError::NonUtf8Path)?;
            paths.push(
                WorkspaceRelativePath::new(PathBuf::from(path_text))
                    .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?,
            );
        }
        if !reader.is_finished() {
            return Err(HomeArtifactCaptureIntentError::InvalidSnapshot);
        }
        let intent = Self::new(
            artifact_id,
            preparation_id,
            handoff_id,
            workspace_id,
            predecessor_assignment_id,
            predecessor_revision,
            root_assignment_id,
            paths,
        )?;
        if intent.digest.as_bytes().as_slice() != expected_digest {
            return Err(HomeArtifactCaptureIntentError::DigestMismatch);
        }
        Ok(intent)
    }

    fn body_bytes(&self) -> Result<Vec<u8>, HomeArtifactCaptureIntentError> {
        let mut bytes = Vec::with_capacity(160 + self.paths.len().saturating_mul(32));
        bytes.extend_from_slice(INTENT_MAGIC);
        bytes.extend_from_slice(self.artifact_id.into_uuid().as_bytes());
        bytes.extend_from_slice(self.preparation_id.as_bytes());
        bytes.extend_from_slice(self.handoff_id.as_bytes());
        bytes.extend_from_slice(self.workspace_id.into_uuid().as_bytes());
        bytes.extend_from_slice(self.predecessor_assignment_id.into_uuid().as_bytes());
        bytes.extend_from_slice(&self.predecessor_revision.get().to_be_bytes());
        bytes.extend_from_slice(self.root_assignment_id.into_uuid().as_bytes());
        push_count(&mut bytes, self.paths.len())
            .map_err(|()| HomeArtifactCaptureIntentError::SnapshotTooLarge)?;
        for path in &self.paths {
            let path = path
                .as_path()
                .to_str()
                .ok_or(HomeArtifactCaptureIntentError::NonUtf8Path)?
                .as_bytes();
            push_bytes(&mut bytes, path)
                .map_err(|()| HomeArtifactCaptureIntentError::SnapshotTooLarge)?;
        }
        if bytes.len() > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
            return Err(HomeArtifactCaptureIntentError::SnapshotTooLarge);
        }
        Ok(bytes)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HomeArtifactCaptureIntentError {
    #[error("Home artifact intent has a nil {0} identity")]
    NilIdentity(&'static str),
    #[error("Home artifact intent has {actual} paths; maximum is {maximum}")]
    PathLimit { actual: usize, maximum: usize },
    #[error("Home artifact intent contains a duplicate path")]
    DuplicatePath,
    #[error("Home artifact paths must be UTF-8 before capture")]
    NonUtf8Path,
    #[error("Home artifact intent snapshot exceeds its bound")]
    SnapshotTooLarge,
    #[error("Home artifact intent snapshot is invalid")]
    InvalidSnapshot,
    #[error("Home artifact intent snapshot digest does not match")]
    DigestMismatch,
    #[error(transparent)]
    ArtifactId(#[from] HomeArtifactIdError),
}

/// One declared path and its exact retained state.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactPathEntry {
    path: WorkspaceRelativePath,
    state: HomeArtifactPathState,
}

impl HomeArtifactPathEntry {
    pub const fn new(path: WorkspaceRelativePath, state: HomeArtifactPathState) -> Self {
        Self { path, state }
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn state(&self) -> &HomeArtifactPathState {
        &self.state
    }
}

/// Exact absence or regular-file metadata retained for one declared path.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeArtifactPathState {
    Absent,
    Regular {
        blob: GitBlobId,
        hash: FileContentHash,
        size: FileByteCount,
        mode: CheckpointFileMode,
    },
}

/// Canonical, bounded manifest for a retained capture.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactManifest {
    intent: HomeArtifactCaptureIntent,
    source_observed_at: TimestampMillis,
    entries: Vec<HomeArtifactPathEntry>,
    digest: HomeArtifactManifestDigest,
}

/// Digest of the canonical manifest body, excluding its digest trailer.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeArtifactManifestDigest([u8; DIGEST_BYTES]);

impl HomeArtifactManifestDigest {
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl HomeArtifactManifest {
    pub fn new(
        intent: HomeArtifactCaptureIntent,
        source_observed_at: TimestampMillis,
        entries: Vec<HomeArtifactPathEntry>,
    ) -> Result<Self, HomeArtifactManifestError> {
        if entries.len() != intent.paths().len() {
            return Err(HomeArtifactManifestError::PathSetMismatch);
        }
        let mut total_bytes = 0_u64;
        for (entry, expected_path) in entries.iter().zip(intent.paths()) {
            if &entry.path != expected_path {
                return Err(HomeArtifactManifestError::PathSetMismatch);
            }
            if let HomeArtifactPathState::Regular { size, .. } = &entry.state {
                if size.get() > MAX_HOME_ARTIFACT_FILE_BYTES {
                    return Err(HomeArtifactManifestError::FileTooLarge {
                        actual: size.get(),
                        maximum: MAX_HOME_ARTIFACT_FILE_BYTES,
                    });
                }
                total_bytes = total_bytes.checked_add(size.get()).ok_or(
                    HomeArtifactManifestError::TotalTooLarge {
                        actual: u64::MAX,
                        maximum: MAX_HOME_ARTIFACT_TOTAL_BYTES,
                    },
                )?;
                if total_bytes > MAX_HOME_ARTIFACT_TOTAL_BYTES {
                    return Err(HomeArtifactManifestError::TotalTooLarge {
                        actual: total_bytes,
                        maximum: MAX_HOME_ARTIFACT_TOTAL_BYTES,
                    });
                }
            }
        }
        let mut manifest = Self {
            intent,
            source_observed_at,
            entries,
            digest: HomeArtifactManifestDigest([0; DIGEST_BYTES]),
        };
        let body = manifest.body_bytes()?;
        manifest.digest = HomeArtifactManifestDigest(digest(MANIFEST_DOMAIN, &body));
        Ok(manifest)
    }

    pub const fn intent(&self) -> &HomeArtifactCaptureIntent {
        &self.intent
    }

    pub const fn source_observed_at(&self) -> TimestampMillis {
        self.source_observed_at
    }

    pub fn entries(&self) -> &[HomeArtifactPathEntry] {
        &self.entries
    }

    pub const fn digest(&self) -> HomeArtifactManifestDigest {
        self.digest
    }

    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>, HomeArtifactManifestError> {
        let body = self.body_bytes()?;
        if body.len().saturating_add(DIGEST_BYTES) > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
            return Err(HomeArtifactManifestError::SnapshotTooLarge);
        }
        let mut bytes = body;
        bytes.extend_from_slice(self.digest.as_bytes());
        Ok(bytes)
    }

    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, HomeArtifactManifestError> {
        if bytes.len() > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
            return Err(HomeArtifactManifestError::SnapshotTooLarge);
        }
        let (body, expected_digest) =
            split_digest(bytes).ok_or(HomeArtifactManifestError::InvalidSnapshot)?;
        if digest(MANIFEST_DOMAIN, body).as_slice() != expected_digest {
            return Err(HomeArtifactManifestError::DigestMismatch);
        }
        let mut reader = SnapshotReader::new(body);
        if reader.take(MANIFEST_MAGIC.len()) != Some(MANIFEST_MAGIC.as_slice()) {
            return Err(HomeArtifactManifestError::InvalidSnapshot);
        }
        let intent_bytes = reader.length_prefixed(MAX_HOME_ARTIFACT_MANIFEST_BYTES)?;
        let intent = HomeArtifactCaptureIntent::from_snapshot_bytes(intent_bytes)
            .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        let source_observed_at = TimestampMillis::new(
            reader
                .i64()
                .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?,
        )
        .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        let entry_count = reader.count_manifest(MAX_HOME_ARTIFACT_PATHS)?;
        if entry_count != intent.paths().len() {
            return Err(HomeArtifactManifestError::PathSetMismatch);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for path in intent.paths() {
            let state = match reader.u8()? {
                0 => HomeArtifactPathState::Absent,
                1 => {
                    let mode = CheckpointFileMode::new(reader.u16()?)
                        .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
                    let size = FileByteCount::new(reader.u64()?);
                    let hash = FileContentHash::from_bytes(reader.array32()?);
                    let blob = GitBlobId::from_sha1_bytes(reader.array20()?);
                    HomeArtifactPathState::Regular {
                        blob,
                        hash,
                        size,
                        mode,
                    }
                }
                _ => return Err(HomeArtifactManifestError::InvalidSnapshot),
            };
            entries.push(HomeArtifactPathEntry::new(path.clone(), state));
        }
        if !reader.is_finished() {
            return Err(HomeArtifactManifestError::InvalidSnapshot);
        }
        let manifest = Self::new(intent, source_observed_at, entries)?;
        if manifest.digest.as_bytes().as_slice() != expected_digest {
            return Err(HomeArtifactManifestError::DigestMismatch);
        }
        Ok(manifest)
    }

    fn body_bytes(&self) -> Result<Vec<u8>, HomeArtifactManifestError> {
        let intent_bytes = self
            .intent
            .to_snapshot_bytes()
            .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        let mut bytes = Vec::with_capacity(128 + intent_bytes.len());
        bytes.extend_from_slice(MANIFEST_MAGIC);
        push_bytes(&mut bytes, &intent_bytes)
            .map_err(|()| HomeArtifactManifestError::SnapshotTooLarge)?;
        bytes.extend_from_slice(&self.source_observed_at.get().to_be_bytes());
        push_count(&mut bytes, self.entries.len())
            .map_err(|()| HomeArtifactManifestError::SnapshotTooLarge)?;
        for entry in &self.entries {
            match &entry.state {
                HomeArtifactPathState::Absent => bytes.push(0),
                HomeArtifactPathState::Regular {
                    blob,
                    hash,
                    size,
                    mode,
                } => {
                    bytes.push(1);
                    bytes.extend_from_slice(&mode.get().to_be_bytes());
                    bytes.extend_from_slice(&size.get().to_be_bytes());
                    bytes.extend_from_slice(hash.as_bytes());
                    bytes.extend_from_slice(blob.object_id().as_bytes());
                }
            }
            if bytes.len().saturating_add(DIGEST_BYTES) > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
                return Err(HomeArtifactManifestError::SnapshotTooLarge);
            }
        }
        Ok(bytes)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HomeArtifactManifestError {
    #[error("Home artifact manifest does not match the exact ordered intent paths")]
    PathSetMismatch,
    #[error("Home artifact file has {actual} bytes; maximum is {maximum}")]
    FileTooLarge { actual: u64, maximum: u64 },
    #[error("Home artifact total has {actual} bytes; maximum is {maximum}")]
    TotalTooLarge { actual: u64, maximum: u64 },
    #[error("Home artifact manifest snapshot exceeds its bound")]
    SnapshotTooLarge,
    #[error("Home artifact manifest snapshot is invalid")]
    InvalidSnapshot,
    #[error("Home artifact manifest digest does not match")]
    DigestMismatch,
}

/// Immutable archive receipt persisted by the Git adapter and SQL owner.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactArchive {
    manifest: HomeArtifactManifest,
    commit_id: GitCommitId,
}

impl HomeArtifactArchive {
    pub fn new(
        manifest: HomeArtifactManifest,
        commit_id: GitCommitId,
    ) -> Result<Self, HomeArtifactArchiveError> {
        if commit_id.object_id().as_bytes() == &[0; SHA1_BYTES] {
            return Err(HomeArtifactArchiveError::EmptyCommitId);
        }
        Ok(Self {
            manifest,
            commit_id,
        })
    }

    pub const fn manifest(&self) -> &HomeArtifactManifest {
        &self.manifest
    }

    pub const fn commit_id(&self) -> GitCommitId {
        self.commit_id
    }

    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>, HomeArtifactArchiveError> {
        let manifest_bytes = self
            .manifest
            .to_snapshot_bytes()
            .map_err(HomeArtifactArchiveError::Manifest)?;
        let mut body = Vec::with_capacity(manifest_bytes.len().saturating_add(64));
        body.extend_from_slice(ARCHIVE_MAGIC);
        push_bytes(&mut body, &manifest_bytes)
            .map_err(|()| HomeArtifactArchiveError::SnapshotTooLarge)?;
        body.extend_from_slice(self.commit_id.object_id().as_bytes());
        if body.len().saturating_add(DIGEST_BYTES) > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
            return Err(HomeArtifactArchiveError::SnapshotTooLarge);
        }
        let archive_digest = digest(ARCHIVE_DOMAIN, &body);
        body.extend_from_slice(&archive_digest);
        Ok(body)
    }

    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, HomeArtifactArchiveError> {
        if bytes.len() > MAX_HOME_ARTIFACT_MANIFEST_BYTES {
            return Err(HomeArtifactArchiveError::SnapshotTooLarge);
        }
        let (body, expected_digest) =
            split_digest(bytes).ok_or(HomeArtifactArchiveError::InvalidSnapshot)?;
        if digest(ARCHIVE_DOMAIN, body).as_slice() != expected_digest {
            return Err(HomeArtifactArchiveError::DigestMismatch);
        }
        let mut reader = SnapshotReader::new(body);
        if reader.take(ARCHIVE_MAGIC.len()) != Some(ARCHIVE_MAGIC.as_slice()) {
            return Err(HomeArtifactArchiveError::InvalidSnapshot);
        }
        let manifest_bytes = reader.length_prefixed(MAX_HOME_ARTIFACT_MANIFEST_BYTES)?;
        let manifest = HomeArtifactManifest::from_snapshot_bytes(manifest_bytes)
            .map_err(HomeArtifactArchiveError::Manifest)?;
        let commit_id = GitCommitId::from_sha1_bytes(reader.array20()?);
        if !reader.is_finished() {
            return Err(HomeArtifactArchiveError::InvalidSnapshot);
        }
        Self::new(manifest, commit_id)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HomeArtifactArchiveError {
    #[error("Home artifact archive snapshot is invalid")]
    InvalidSnapshot,
    #[error("Home artifact archive snapshot exceeds its bound")]
    SnapshotTooLarge,
    #[error("Home artifact archive digest does not match")]
    DigestMismatch,
    #[error("Home artifact archive has an empty commit identity")]
    EmptyCommitId,
    #[error(transparent)]
    Manifest(#[from] HomeArtifactManifestError),
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn push_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), ()> {
    let count = u32::try_from(count).map_err(|_| ())?;
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ()> {
    let length = u32::try_from(value.len()).map_err(|_| ())?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn split_digest(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let body_length = bytes.len().checked_sub(DIGEST_BYTES)?;
    Some(bytes.split_at(body_length))
}

struct SnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let value = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(value)
    }

    fn u8(&mut self) -> Result<u8, HomeArtifactManifestError> {
        self.take(1)
            .map(|value| value[0])
            .ok_or(HomeArtifactManifestError::InvalidSnapshot)
    }

    fn u16(&mut self) -> Result<u16, HomeArtifactManifestError> {
        let value = self
            .take(2)
            .ok_or(HomeArtifactManifestError::InvalidSnapshot)?;
        let bytes: [u8; 2] = value
            .try_into()
            .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, HomeArtifactManifestError> {
        let value = self
            .take(4)
            .ok_or(HomeArtifactManifestError::InvalidSnapshot)?;
        let bytes: [u8; 4] = value
            .try_into()
            .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, HomeArtifactCaptureIntentError> {
        let value = self
            .take(8)
            .ok_or(HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        let bytes: [u8; 8] = value
            .try_into()
            .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, HomeArtifactManifestError> {
        let value = self
            .take(8)
            .ok_or(HomeArtifactManifestError::InvalidSnapshot)?;
        let bytes: [u8; 8] = value
            .try_into()
            .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn uuid(&mut self) -> Result<Uuid, HomeArtifactCaptureIntentError> {
        let value = self
            .take(16)
            .ok_or(HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        Uuid::from_slice(value).map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)
    }

    fn length_prefixed(&mut self, maximum: usize) -> Result<&'a [u8], HomeArtifactManifestError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        if length > maximum {
            return Err(HomeArtifactManifestError::SnapshotTooLarge);
        }
        self.take(length)
            .ok_or(HomeArtifactManifestError::InvalidSnapshot)
    }

    fn count(&mut self, maximum: usize) -> Result<usize, HomeArtifactCaptureIntentError> {
        let value = self
            .take(4)
            .ok_or(HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        let raw: [u8; 4] = value
            .try_into()
            .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        let length = usize::try_from(u32::from_be_bytes(raw))
            .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        if length > maximum {
            return Err(HomeArtifactCaptureIntentError::PathLimit {
                actual: length,
                maximum,
            });
        }
        Ok(length)
    }

    fn count_manifest(&mut self, maximum: usize) -> Result<usize, HomeArtifactManifestError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| HomeArtifactManifestError::InvalidSnapshot)?;
        if length > maximum {
            return Err(HomeArtifactManifestError::InvalidSnapshot);
        }
        Ok(length)
    }

    fn length_prefixed_intent(
        &mut self,
        maximum: usize,
    ) -> Result<&'a [u8], HomeArtifactCaptureIntentError> {
        let value = self
            .take(4)
            .ok_or(HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        let raw: [u8; 4] = value
            .try_into()
            .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        let length = usize::try_from(u32::from_be_bytes(raw))
            .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?;
        if length > maximum {
            return Err(HomeArtifactCaptureIntentError::SnapshotTooLarge);
        }
        self.take(length)
            .ok_or(HomeArtifactCaptureIntentError::InvalidSnapshot)
    }

    fn array32(&mut self) -> Result<[u8; 32], HomeArtifactManifestError> {
        self.take(32)
            .ok_or(HomeArtifactManifestError::InvalidSnapshot)?
            .try_into()
            .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)
    }

    fn array20(&mut self) -> Result<[u8; SHA1_BYTES], HomeArtifactManifestError> {
        self.take(SHA1_BYTES)
            .ok_or(HomeArtifactManifestError::InvalidSnapshot)?
            .try_into()
            .map_err(|_| HomeArtifactManifestError::InvalidSnapshot)
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
    }

    fn intent(
        paths: Vec<WorkspaceRelativePath>,
    ) -> Result<HomeArtifactCaptureIntent, HomeArtifactCaptureIntentError> {
        HomeArtifactCaptureIntent::new(
            HomeArtifactId::new(Uuid::from_u128(1))?,
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            WorkspaceId::from_uuid(Uuid::from_u128(4)),
            AgentAssignmentId::from_uuid(Uuid::from_u128(5)),
            AgentAssignmentRevision::new(6)
                .map_err(|_| HomeArtifactCaptureIntentError::InvalidSnapshot)?,
            AgentAssignmentId::from_uuid(Uuid::from_u128(7)),
            paths,
        )
    }

    fn regular(
        size: u64,
        mode: u16,
        value: u8,
    ) -> Result<HomeArtifactPathState, Box<dyn std::error::Error>> {
        Ok(HomeArtifactPathState::Regular {
            blob: GitBlobId::from_sha1_bytes([value; SHA1_BYTES]),
            hash: FileContentHash::from_bytes([value; DIGEST_BYTES]),
            size: FileByteCount::new(size),
            mode: CheckpointFileMode::new(mode)?,
        })
    }

    #[test]
    fn intent_binds_root_assignment_and_preserves_exact_order() -> TestResult {
        let first = intent(vec![path("src/a.rs")?, path("README.md")?])?;
        let reordered = intent(vec![path("README.md")?, path("src/a.rs")?])?;
        assert_ne!(first.digest(), reordered.digest());
        assert_eq!(first.paths()[0].as_path(), PathBuf::from("src/a.rs"));
        assert_eq!(
            HomeArtifactCaptureIntent::from_snapshot_bytes(&first.to_snapshot_bytes()?)?,
            first
        );
        let other_root = HomeArtifactCaptureIntent::new(
            first.artifact_id(),
            first.preparation_id(),
            first.handoff_id(),
            first.workspace_id(),
            first.predecessor_assignment_id(),
            first.predecessor_revision(),
            AgentAssignmentId::from_uuid(Uuid::from_u128(8)),
            first.paths().to_vec(),
        )?;
        assert_ne!(first.digest(), other_root.digest());
        Ok(())
    }

    #[test]
    fn artifact_id_parser_rejects_invalid_and_nil_uuids() -> TestResult {
        let id = HomeArtifactId::new(Uuid::from_u128(91))?;
        assert_eq!(id.into_uuid().to_string().parse::<HomeArtifactId>()?, id);
        assert!(matches!(
            "00000000-0000-0000-0000-000000000000".parse::<HomeArtifactId>(),
            Err(HomeArtifactIdParseError::InvalidIdentity(
                HomeArtifactIdError::Nil
            ))
        ));
        assert!(matches!(
            "not-a-uuid".parse::<HomeArtifactId>(),
            Err(HomeArtifactIdParseError::InvalidUuid(_))
        ));
        Ok(())
    }

    #[test]
    fn intent_rejects_duplicate_paths_and_path_count_overflow() -> TestResult {
        assert!(matches!(
            intent(vec![path("same")?, path("same")?]),
            Err(HomeArtifactCaptureIntentError::DuplicatePath)
        ));
        let paths = (0..=MAX_HOME_ARTIFACT_PATHS)
            .map(|index| path(&format!("file-{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(matches!(
            intent(paths),
            Err(HomeArtifactCaptureIntentError::PathLimit { .. })
        ));
        Ok(())
    }

    #[test]
    fn manifest_archive_snapshot_round_trip_and_tampering_fail_closed() -> TestResult {
        let intent = intent(vec![path("src/lib.rs")?, path("not-created")?])?;
        let manifest = HomeArtifactManifest::new(
            intent,
            TimestampMillis::new(123)?,
            vec![
                HomeArtifactPathEntry::new(path("src/lib.rs")?, regular(4, 0o644, 0x11)?),
                HomeArtifactPathEntry::new(path("not-created")?, HomeArtifactPathState::Absent),
            ],
        )?;
        let manifest_bytes = manifest.to_snapshot_bytes()?;
        let decoded = HomeArtifactManifest::from_snapshot_bytes(&manifest_bytes)?;
        assert_eq!(decoded, manifest);
        let archive =
            HomeArtifactArchive::new(manifest, GitCommitId::from_sha1_bytes([0x22; SHA1_BYTES]))?;
        assert_eq!(
            HomeArtifactArchive::from_snapshot_bytes(&archive.to_snapshot_bytes()?)?,
            archive
        );
        let mut tampered = manifest_bytes;
        tampered[10] ^= 1;
        assert!(matches!(
            HomeArtifactManifest::from_snapshot_bytes(&tampered),
            Err(HomeArtifactManifestError::DigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn manifest_requires_exact_paths_and_cumulative_bounds() -> TestResult {
        let ordered = intent(vec![path("a")?, path("b")?])?;
        assert!(matches!(
            HomeArtifactManifest::new(
                ordered.clone(),
                TimestampMillis::new(1)?,
                vec![
                    HomeArtifactPathEntry::new(path("b")?, HomeArtifactPathState::Absent),
                    HomeArtifactPathEntry::new(path("a")?, HomeArtifactPathState::Absent),
                ],
            ),
            Err(HomeArtifactManifestError::PathSetMismatch)
        ));

        let one_path = intent(vec![path("oversized")?])?;
        assert!(matches!(
            HomeArtifactManifest::new(
                one_path.clone(),
                TimestampMillis::new(1)?,
                vec![HomeArtifactPathEntry::new(
                    path("oversized")?,
                    regular(MAX_HOME_ARTIFACT_FILE_BYTES + 1, 0o600, 0x01)?,
                )],
            ),
            Err(HomeArtifactManifestError::FileTooLarge { .. })
        ));

        let paths = (0..17)
            .map(|index| path(&format!("path-{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        let too_much = intent(paths.clone())?;
        let entries = paths
            .into_iter()
            .enumerate()
            .map(|(index, path)| {
                Ok(HomeArtifactPathEntry::new(
                    path,
                    regular(MAX_HOME_ARTIFACT_FILE_BYTES, 0o600, u8::try_from(index)?)?,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        assert!(matches!(
            HomeArtifactManifest::new(too_much, TimestampMillis::new(1)?, entries),
            Err(HomeArtifactManifestError::TotalTooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn maximum_near_four_kib_paths_fit_the_bounded_manifest_snapshot() -> TestResult {
        let maximum = crate::MAX_WORKSPACE_RELATIVE_PATH_BYTES;
        let paths = (0..MAX_HOME_ARTIFACT_PATHS)
            .map(|index| {
                let suffix = format!("-{index:03}");
                let prefix = "x".repeat(maximum.saturating_sub(suffix.len()));
                path(&format!("{prefix}{suffix}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(paths.len(), MAX_HOME_ARTIFACT_PATHS);
        assert!(
            paths
                .iter()
                .all(|path| { path.as_path().as_os_str().as_encoded_bytes().len() >= maximum - 3 })
        );

        let capture = intent(paths.clone())?;
        let entries = paths
            .into_iter()
            .map(|path| HomeArtifactPathEntry::new(path, HomeArtifactPathState::Absent))
            .collect();
        let manifest = HomeArtifactManifest::new(capture, TimestampMillis::new(1)?, entries)?;
        let bytes = manifest.to_snapshot_bytes()?;
        assert!(bytes.len() < MAX_HOME_ARTIFACT_MANIFEST_BYTES);
        assert_eq!(HomeArtifactManifest::from_snapshot_bytes(&bytes)?, manifest);
        Ok(())
    }
}
