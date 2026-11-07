//! Immutable Home handback archives retained in the Source-owned Git object
//! store. This is deliberately separate from checkpoint identities and refs.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Component;

use forge_domain::{
    CheckpointFileMode, FileByteCount, FileContentHash, GitBlobId, GitCommitId,
    HomeArtifactArchive, HomeArtifactArchiveError, HomeArtifactCaptureIntent,
    HomeArtifactCaptureIntentError, HomeArtifactId, HomeArtifactManifest,
    HomeArtifactManifestDigest, HomeArtifactManifestError, HomeArtifactPathEntry,
    HomeArtifactPathState, MAX_HOME_ARTIFACT_FILE_BYTES, MAX_HOME_ARTIFACT_MANIFEST_BYTES,
    MAX_HOME_ARTIFACT_PATHS, MAX_HOME_ARTIFACT_TOTAL_BYTES, MAX_WORKSPACE_RELATIVE_PATH_BYTES,
    TimestampMillis, WorkspaceRelativePath,
};
use thiserror::Error;

use super::{
    GitCheckpointObjectExpectation, GitCheckpointObjectVerificationStatus, GitCheckpointStore,
    GitOutput, GitSafetyError, arg, arg_bytes, command_failed, mktree_entry, object_hex, os,
    parse_git_object_id, trim_single_newline,
};

mod durability;

const HOME_ARTIFACT_REF_NAMESPACE: &str = "refs/heterarchy-forge/home-artifacts";
pub const HOME_ARTIFACT_REF_PREFIX: &str = "refs/heterarchy-forge/home-artifacts/";
pub const HOME_ARTIFACT_REF_INVENTORY_MAX: u16 = 512;
const HOME_ARTIFACT_TREE_MANIFEST_NAME: &[u8] = b"manifest";
const HOME_ARTIFACT_TREE_PAYLOAD_NAME: &[u8] = b"payload";
const HOME_ARTIFACT_TREE_RECORD_OVERHEAD: usize = 80;
const MIN_HOME_ARTIFACT_TREE_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_HOME_ARTIFACT_TREE_OUTPUT_BYTES: usize = MAX_HOME_ARTIFACT_PATHS
    * (crate::MAX_FILE_PATH_COMPONENTS + 1)
    * (MAX_WORKSPACE_RELATIVE_PATH_BYTES
        + HOME_ARTIFACT_TREE_PAYLOAD_NAME.len()
        + 1
        + HOME_ARTIFACT_TREE_RECORD_OVERHEAD)
    + 128;
const MAX_HOME_ARTIFACT_TREE_ENTRIES: usize =
    MAX_HOME_ARTIFACT_PATHS * crate::MAX_FILE_PATH_COMPONENTS + 2;
const MAX_HOME_ARTIFACT_REF_READ_OUTPUT_BYTES: usize = 512;
const MAX_HOME_ARTIFACT_PACKED_REFS_BYTES: u64 = 1_048_576;

/// Read-only archive adapter over the existing confined checkpoint object store.
#[derive(Debug)]
pub struct HomeArtifactStore<'a> {
    store: &'a GitCheckpointStore,
}

impl<'a> HomeArtifactStore<'a> {
    pub const fn new(store: &'a GitCheckpointStore) -> Self {
        Self { store }
    }

    /// Capture the declared paths once and publish a create-only artifact ref.
    ///
    /// The Source-sampled time is recorded as manifest provenance. Reads are
    /// sequential: this archive is not an atomic Workspace snapshot and does
    /// not prove that its path list exhausts unfinished work. A pre-existing
    /// ref is fully verified and returned without rereading live files.
    pub fn publish(
        &self,
        intent: &HomeArtifactCaptureIntent,
        source_observed_at: TimestampMillis,
    ) -> Result<HomeArtifactArchive, HomeArtifactStoreError> {
        if let Some(existing) = self.read_archive_by_id(intent.artifact_id())? {
            return Self::require_matching_intent(intent, existing);
        }

        let manifest = self.capture(intent, source_observed_at)?;
        let manifest_bytes = manifest.to_snapshot_bytes()?;
        let manifest_blob = self.store.write_blob(&manifest_bytes)?;
        let tree = self.build_archive_tree(manifest_blob, &manifest)?;
        let commit_id = self.create_commit(
            intent.artifact_id(),
            manifest.digest(),
            tree,
            source_observed_at,
        )?;
        let archive = HomeArtifactArchive::new(manifest, commit_id)?;
        self.publish_ref_or_read_back(intent, archive)
    }

    /// Read and fully verify one retained archive by its exact capture intent.
    /// `None` is only absence of the exact artifact ref; malformed or damaged
    /// retained state is an error and is never treated as empty content.
    pub fn read(
        &self,
        expected_intent: &HomeArtifactCaptureIntent,
    ) -> Result<Option<HomeArtifactArchive>, HomeArtifactStoreError> {
        let Some(archive) = self.read_archive_by_id(expected_intent.artifact_id())? else {
            return Ok(None);
        };
        if archive.manifest().intent() != expected_intent {
            return Err(HomeArtifactStoreError::IntentConflict);
        }
        Ok(Some(archive))
    }

    /// Read only one path declared by the expected intent after verifying the
    /// full manifest/tree and every promised blob. No arbitrary OID is accepted.
    pub fn read_member(
        &self,
        expected_intent: &HomeArtifactCaptureIntent,
        path: &WorkspaceRelativePath,
    ) -> Result<Option<HomeArtifactPathRead>, HomeArtifactStoreError> {
        Ok(self
            .read_member_with_archive(expected_intent, path)?
            .map(|(_, member)| member))
    }

    /// Read one declared member and return the archive verified in the same
    /// Git observation. The full intent is checked before either value escapes.
    pub fn read_member_with_archive(
        &self,
        expected_intent: &HomeArtifactCaptureIntent,
        path: &WorkspaceRelativePath,
    ) -> Result<Option<(HomeArtifactArchive, HomeArtifactPathRead)>, HomeArtifactStoreError> {
        if !expected_intent.paths().contains(path) {
            return Err(HomeArtifactStoreError::PathNotDeclared);
        }
        let Some((archive, member)) =
            self.read_archive_inner(expected_intent.artifact_id(), Some(path))?
        else {
            return Ok(None);
        };
        if archive.manifest().intent() != expected_intent {
            return Err(HomeArtifactStoreError::IntentConflict);
        }
        let Some(member) = member else {
            return Err(HomeArtifactStoreError::Corrupt(
                "declared member was not verified",
            ));
        };
        Ok(Some((archive, member)))
    }

    /// Inventory the bounded Home ref namespace. Invalid names, non-commit
    /// objects and missing objects remain visible as protected unknown entries.
    pub fn inventory_refs_read_only(
        &self,
        limit: HomeArtifactRefInventoryLimit,
    ) -> Result<HomeArtifactRefInventory, HomeArtifactStoreError> {
        let maximum = usize::from(limit.get());
        let count = maximum.saturating_add(1);
        let count_argument = format!("--count={count}");
        let output = self.store.run_git_with_limit(
            "inventory Home artifact refs",
            &[
                arg("for-each-ref"),
                arg("--sort=refname"),
                os(&count_argument),
                arg("--format=%(refname)%00%(objectname)"),
                arg(HOME_ARTIFACT_REF_NAMESPACE),
            ],
            None,
            &[],
            MAX_HOME_ARTIFACT_MANIFEST_BYTES,
        )?;
        if !output.status.success() {
            return Err(command_failed("inventory Home artifact refs", &output).into());
        }
        if !output.stderr.is_empty() {
            return Err(
                command_failed("inventory Home artifact refs with diagnostics", &output).into(),
            );
        }

        let records = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|record| !record.is_empty())
            .take(count)
            .collect::<Vec<_>>();
        let truncated = records.len() > maximum;
        let mut candidates = Vec::new();
        let mut entries = Vec::with_capacity(maximum.min(records.len()));

        for record in records.iter().take(maximum) {
            match Self::parse_inventory_candidate(record) {
                Ok(candidate) => {
                    candidates.push(candidate);
                    entries.push(InventoryEntryWork::Candidate(candidates.len() - 1));
                }
                Err((name, reason)) => {
                    entries.push(InventoryEntryWork::Unknown(name, reason));
                }
            }
        }

        let expectations = candidates
            .iter()
            .map(|candidate| GitCheckpointObjectExpectation::Commit(candidate.commit_id))
            .collect::<Vec<_>>();
        let verification = self.store.verify_objects_read_only(&expectations)?;
        let mut result = Vec::with_capacity(entries.len());
        for entry in entries {
            match entry {
                InventoryEntryWork::Unknown(name, reason) => {
                    result.push(HomeArtifactRefInventoryEntry::ProtectedUnknown { name, reason });
                }
                InventoryEntryWork::Candidate(index) => {
                    let Some(candidate) = candidates.get(index) else {
                        return Err(HomeArtifactStoreError::Corrupt("inventory candidate index"));
                    };
                    let Some(status) = verification.get(index).map(|value| value.status()) else {
                        return Err(HomeArtifactStoreError::Corrupt(
                            "inventory verification count",
                        ));
                    };
                    match status {
                        GitCheckpointObjectVerificationStatus::Present => {
                            result.push(HomeArtifactRefInventoryEntry::Retained {
                                artifact_id: candidate.artifact_id,
                                commit_id: candidate.commit_id,
                            });
                        }
                        GitCheckpointObjectVerificationStatus::Missing => {
                            result.push(HomeArtifactRefInventoryEntry::ProtectedUnknown {
                                name: candidate.name.clone(),
                                reason: HomeArtifactRefIssue::MissingObject,
                            });
                        }
                        GitCheckpointObjectVerificationStatus::TypeMismatch => {
                            result.push(HomeArtifactRefInventoryEntry::ProtectedUnknown {
                                name: candidate.name.clone(),
                                reason: HomeArtifactRefIssue::NonCommit,
                            });
                        }
                    }
                }
            }
        }

        Ok(HomeArtifactRefInventory {
            entries: result,
            truncated,
        })
    }

    fn capture(
        &self,
        intent: &HomeArtifactCaptureIntent,
        source_observed_at: TimestampMillis,
    ) -> Result<HomeArtifactManifest, HomeArtifactStoreError> {
        if intent.paths().len() > MAX_HOME_ARTIFACT_PATHS {
            return Err(HomeArtifactStoreError::Bounds("declared path count"));
        }
        let mut entries = Vec::with_capacity(intent.paths().len());
        let mut total_bytes = 0_u64;
        for path in intent.paths() {
            let captured = self
                .store
                .confined
                .read_checkpoint(path)
                .map_err(HomeArtifactStoreError::Confined)?;
            let Some(captured) = captured else {
                entries.push(HomeArtifactPathEntry::new(
                    path.clone(),
                    HomeArtifactPathState::Absent,
                ));
                continue;
            };
            let size = captured.size();
            if size.get() > MAX_HOME_ARTIFACT_FILE_BYTES {
                return Err(HomeArtifactStoreError::Bounds("per-file byte count"));
            }
            total_bytes = total_bytes
                .checked_add(size.get())
                .ok_or(HomeArtifactStoreError::Bounds("total byte count overflow"))?;
            if total_bytes > MAX_HOME_ARTIFACT_TOTAL_BYTES {
                return Err(HomeArtifactStoreError::Bounds("total byte count"));
            }
            let blob = self.store.write_blob(captured.content())?;
            entries.push(HomeArtifactPathEntry::new(
                path.clone(),
                HomeArtifactPathState::Regular {
                    blob,
                    hash: captured.hash(),
                    size,
                    mode: captured.mode(),
                },
            ));
        }
        Ok(HomeArtifactManifest::new(
            intent.clone(),
            source_observed_at,
            entries,
        )?)
    }

    fn publish_ref_or_read_back(
        &self,
        intent: &HomeArtifactCaptureIntent,
        archive: HomeArtifactArchive,
    ) -> Result<HomeArtifactArchive, HomeArtifactStoreError> {
        let name = home_artifact_ref_name(intent.artifact_id());
        let commit_hex = object_hex(archive.commit_id().object_id());
        let zero_oid = b"0000000000000000000000000000000000000000";
        let update = self.store.run_git(
            "publish Home artifact ref with create-only CAS",
            &[
                arg("update-ref"),
                os(&name),
                arg_bytes(&commit_hex),
                arg_bytes(zero_oid),
            ],
            None,
            &[],
        );
        match update {
            Ok(output) if output.status.success() => Ok(archive),
            Ok(output) => {
                let failure =
                    command_failed("publish Home artifact ref with create-only CAS", &output);
                self.recover_publication(intent, failure)
            }
            Err(failure) => self.recover_publication(intent, failure),
        }
    }

    fn recover_publication(
        &self,
        intent: &HomeArtifactCaptureIntent,
        publication: GitSafetyError,
    ) -> Result<HomeArtifactArchive, HomeArtifactStoreError> {
        match self.read_archive_by_id(intent.artifact_id()) {
            Ok(Some(archive)) if archive.manifest().intent() == intent => Ok(archive),
            Ok(Some(_)) => Err(HomeArtifactStoreError::IntentConflict),
            Ok(None) => Err(HomeArtifactStoreError::Git(publication)),
            Err(readback) => Err(HomeArtifactStoreError::PublicationUnknown {
                publication: Box::new(publication),
                readback: Box::new(readback),
            }),
        }
    }

    fn require_matching_intent(
        intent: &HomeArtifactCaptureIntent,
        archive: HomeArtifactArchive,
    ) -> Result<HomeArtifactArchive, HomeArtifactStoreError> {
        if archive.manifest().intent() != intent {
            return Err(HomeArtifactStoreError::IntentConflict);
        }
        Ok(archive)
    }

    fn read_archive_by_id(
        &self,
        artifact_id: HomeArtifactId,
    ) -> Result<Option<HomeArtifactArchive>, HomeArtifactStoreError> {
        Ok(self
            .read_archive_inner(artifact_id, None)?
            .map(|(archive, _)| archive))
    }

    fn read_archive_inner(
        &self,
        artifact_id: HomeArtifactId,
        requested_member: Option<&WorkspaceRelativePath>,
    ) -> Result<Option<(HomeArtifactArchive, Option<HomeArtifactPathRead>)>, HomeArtifactStoreError>
    {
        self.store.ensure_sha1_object_format()?;
        let Some(commit_id) = self.read_ref(artifact_id)? else {
            return Ok(None);
        };
        let root_entries = self.list_tree(commit_id, false, MIN_HOME_ARTIFACT_TREE_OUTPUT_BYTES)?;
        if root_entries.len() != 2 {
            return Err(HomeArtifactStoreError::Corrupt("archive root entries"));
        }
        let manifest_tree_entry = root_entries
            .iter()
            .find(|entry| entry.path == HOME_ARTIFACT_TREE_MANIFEST_NAME)
            .ok_or(HomeArtifactStoreError::Corrupt("manifest tree entry"))?;
        let payload_tree_entry = root_entries
            .iter()
            .find(|entry| entry.path == HOME_ARTIFACT_TREE_PAYLOAD_NAME)
            .ok_or(HomeArtifactStoreError::Corrupt("payload tree entry"))?;
        if manifest_tree_entry.mode != b"100644"
            || manifest_tree_entry.kind != b"blob"
            || payload_tree_entry.mode != b"040000"
            || payload_tree_entry.kind != b"tree"
        {
            return Err(HomeArtifactStoreError::Corrupt("archive root entry type"));
        }

        let manifest_blob = GitBlobId::from_sha1_bytes(*manifest_tree_entry.object.as_bytes());
        let manifest_bytes = self.store.read_blob(manifest_blob)?;
        let manifest = HomeArtifactManifest::from_snapshot_bytes(&manifest_bytes)?;
        if manifest.intent().artifact_id() != artifact_id {
            return Err(HomeArtifactStoreError::ArtifactIdentityMismatch);
        }

        let output_limit = home_artifact_tree_output_limit(&manifest)?;
        let recursive_entries = self.list_tree(commit_id, true, output_limit)?;
        Self::verify_payload_tree(
            &recursive_entries,
            manifest_tree_entry,
            payload_tree_entry,
            &manifest,
        )?;

        let mut total_bytes = 0_u64;
        let mut requested_read = None;
        for entry in manifest.entries() {
            match entry.state() {
                HomeArtifactPathState::Absent => {
                    if requested_member == Some(entry.path()) {
                        requested_read = Some(HomeArtifactPathRead::Absent);
                    }
                }
                HomeArtifactPathState::Regular {
                    blob,
                    hash,
                    size,
                    mode,
                } => {
                    if size.get() > MAX_HOME_ARTIFACT_FILE_BYTES {
                        return Err(HomeArtifactStoreError::Corrupt("per-file byte bound"));
                    }
                    total_bytes = total_bytes
                        .checked_add(size.get())
                        .ok_or(HomeArtifactStoreError::Corrupt("total byte count overflow"))?;
                    if total_bytes > MAX_HOME_ARTIFACT_TOTAL_BYTES {
                        return Err(HomeArtifactStoreError::Corrupt("total byte bound"));
                    }
                    let content = self.store.read_blob(*blob)?;
                    if u64::try_from(content.len()).ok() != Some(size.get()) {
                        return Err(HomeArtifactStoreError::Corrupt("retained blob length"));
                    }
                    let actual_hash =
                        FileContentHash::from_bytes(*blake3::hash(&content).as_bytes());
                    if actual_hash != *hash {
                        return Err(HomeArtifactStoreError::Corrupt("retained blob hash"));
                    }
                    if requested_member == Some(entry.path()) {
                        requested_read = Some(HomeArtifactPathRead::Regular {
                            hash: *hash,
                            size: *size,
                            mode: *mode,
                            content,
                        });
                    }
                }
            }
        }

        if requested_member.is_some() && requested_read.is_none() {
            return Err(HomeArtifactStoreError::Corrupt(
                "requested path missing from manifest",
            ));
        }
        let archive = HomeArtifactArchive::new(manifest, commit_id)?;
        Ok(Some((archive, requested_read)))
    }

    fn verify_payload_tree(
        actual: &[TreeEntry],
        manifest_entry: &TreeEntry,
        payload_entry: &TreeEntry,
        manifest: &HomeArtifactManifest,
    ) -> Result<(), HomeArtifactStoreError> {
        let mut expected = BTreeMap::new();
        expected.insert(
            HOME_ARTIFACT_TREE_MANIFEST_NAME.to_vec(),
            TreeEntryExpectation {
                mode: b"100644".to_vec(),
                kind: b"blob".to_vec(),
                object: Some(manifest_entry.object),
            },
        );
        expected.insert(
            HOME_ARTIFACT_TREE_PAYLOAD_NAME.to_vec(),
            TreeEntryExpectation {
                mode: b"040000".to_vec(),
                kind: b"tree".to_vec(),
                object: Some(payload_entry.object),
            },
        );
        for entry in manifest.entries() {
            if let HomeArtifactPathState::Regular { blob, mode, .. } = entry.state() {
                let components = entry
                    .path()
                    .as_path()
                    .components()
                    .map(|component| component.as_os_str().as_bytes().to_vec())
                    .collect::<Vec<_>>();
                if components.is_empty() || components.len() > crate::MAX_FILE_PATH_COMPONENTS {
                    return Err(HomeArtifactStoreError::Corrupt("payload component count"));
                }
                let mut path = HOME_ARTIFACT_TREE_PAYLOAD_NAME.to_vec();
                for (index, component) in components.iter().enumerate() {
                    path.push(b'/');
                    path.extend_from_slice(component);
                    let is_leaf = index + 1 == components.len();
                    let value = if is_leaf {
                        TreeEntryExpectation {
                            mode: if mode.get() & 0o111 == 0 {
                                b"100644".to_vec()
                            } else {
                                b"100755".to_vec()
                            },
                            kind: b"blob".to_vec(),
                            object: Some(blob.object_id()),
                        }
                    } else {
                        TreeEntryExpectation {
                            mode: b"040000".to_vec(),
                            kind: b"tree".to_vec(),
                            object: None,
                        }
                    };
                    if let Some(existing) = expected.get(&path) {
                        if existing != &value {
                            return Err(HomeArtifactStoreError::Corrupt(
                                "conflicting expected payload tree path",
                            ));
                        }
                    } else {
                        expected.insert(path.clone(), value);
                    }
                }
            }
        }
        if actual.len() != expected.len() {
            return Err(HomeArtifactStoreError::Corrupt(
                "archive payload tree entries",
            ));
        }
        let mut observed = BTreeSet::new();
        for entry in actual {
            if !observed.insert(entry.path.clone()) {
                return Err(HomeArtifactStoreError::Corrupt(
                    "duplicate archive tree path",
                ));
            }
            let Some(expected_entry) = expected.get(&entry.path) else {
                return Err(HomeArtifactStoreError::Corrupt(
                    "unpromised archive tree entry",
                ));
            };
            if expected_entry.mode != entry.mode
                || expected_entry.kind != entry.kind
                || expected_entry
                    .object
                    .is_some_and(|object| object != entry.object)
            {
                return Err(HomeArtifactStoreError::Corrupt("archive payload identity"));
            }
        }
        if observed.len() != expected.len() {
            return Err(HomeArtifactStoreError::Corrupt(
                "archive payload tree entries",
            ));
        }
        Ok(())
    }

    fn read_ref(
        &self,
        artifact_id: HomeArtifactId,
    ) -> Result<Option<GitCommitId>, HomeArtifactStoreError> {
        let name = home_artifact_ref_name(artifact_id);
        let output = self.store.run_git_with_limit(
            "read Home artifact ref",
            &[
                arg("for-each-ref"),
                arg("--count=2"),
                arg("--format=%(refname)%00%(objectname)%00%(objecttype)%00%(symref)"),
                os(&name),
            ],
            None,
            &[],
            MAX_HOME_ARTIFACT_REF_READ_OUTPUT_BYTES,
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(command_failed("read Home artifact ref", &output).into());
        }
        if output.stdout.is_empty() {
            self.ensure_exact_ref_absent(&name)?;
            return Ok(None);
        }

        let Some(record) = output.stdout.strip_suffix(b"\n") else {
            return Err(GitSafetyError::TamperedRef { name }.into());
        };
        if record.contains(&b'\n') {
            return Err(GitSafetyError::TamperedRef { name }.into());
        }
        let fields = record.split(|byte| *byte == 0).collect::<Vec<_>>();
        if fields.len() != 4
            || fields[0] != name.as_bytes()
            || fields[2] != b"commit"
            || !fields[3].is_empty()
        {
            return Err(GitSafetyError::TamperedRef { name }.into());
        }
        let object = parse_git_object_id("read Home artifact ref", fields[1])?;
        let object_hex = object_hex(object);
        let type_output = self.store.run_git(
            "validate Home artifact ref object",
            &[arg("cat-file"), arg("-t"), arg_bytes(&object_hex)],
            None,
            &[],
        )?;
        if !type_output.status.success() || trim_single_newline(&type_output.stdout) != b"commit" {
            return Err(GitSafetyError::TamperedRef { name }.into());
        }
        Ok(Some(GitCommitId::from_sha1_bytes(*object.as_bytes())))
    }

    fn ensure_exact_ref_absent(&self, name: &str) -> Result<(), HomeArtifactStoreError> {
        let mut path = self.store.git_store_path().to_path_buf();
        let mut components = name.split('/').peekable();
        while let Some(component) = components.next() {
            path.push(component);
            let is_leaf = components.peek().is_none();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    return self.ensure_exact_packed_ref_absent(name);
                }
                Err(source) => {
                    return Err(GitSafetyError::Filesystem {
                        operation: "inspect exact Home artifact ref absence".to_owned(),
                        path,
                        source,
                    }
                    .into());
                }
            };
            if is_leaf || metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(GitSafetyError::TamperedRef {
                    name: name.to_owned(),
                }
                .into());
            }
        }
        Ok(())
    }

    fn ensure_exact_packed_ref_absent(&self, name: &str) -> Result<(), HomeArtifactStoreError> {
        let path = self.store.git_store_path().join("packed-refs");
        let path_metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(GitSafetyError::Filesystem {
                    operation: "inspect packed Home artifact refs".to_owned(),
                    path,
                    source,
                }
                .into());
            }
        };
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(GitSafetyError::TamperedRef {
                name: name.to_owned(),
            }
            .into());
        }
        if path_metadata.len() > MAX_HOME_ARTIFACT_PACKED_REFS_BYTES {
            return Err(HomeArtifactStoreError::Bounds("packed ref scan"));
        }

        let file = fs::File::open(&path).map_err(|source| GitSafetyError::Filesystem {
            operation: "open packed Home artifact refs".to_owned(),
            path: path.clone(),
            source,
        })?;
        let file_metadata = file
            .metadata()
            .map_err(|source| GitSafetyError::Filesystem {
                operation: "inspect opened packed Home artifact refs".to_owned(),
                path: path.clone(),
                source,
            })?;
        let current_path_metadata =
            fs::symlink_metadata(&path).map_err(|source| GitSafetyError::Filesystem {
                operation: "recheck packed Home artifact refs".to_owned(),
                path: path.clone(),
                source,
            })?;
        if current_path_metadata.file_type().is_symlink()
            || !current_path_metadata.is_file()
            || current_path_metadata.dev() != file_metadata.dev()
            || current_path_metadata.ino() != file_metadata.ino()
        {
            return Err(GitSafetyError::TamperedRef {
                name: name.to_owned(),
            }
            .into());
        }

        let maximum = usize::try_from(MAX_HOME_ARTIFACT_PACKED_REFS_BYTES)
            .map_err(|_| HomeArtifactStoreError::Bounds("packed ref scan"))?;
        let mut contents = Vec::new();
        file.take(MAX_HOME_ARTIFACT_PACKED_REFS_BYTES.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|source| GitSafetyError::Filesystem {
                operation: "read packed Home artifact refs".to_owned(),
                path: path.clone(),
                source,
            })?;
        if contents.len() > maximum {
            return Err(HomeArtifactStoreError::Bounds("packed ref scan"));
        }

        let name = name.as_bytes();
        for line in contents.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line
                .first()
                .is_some_and(|byte| matches!(*byte, b'#' | b'^'))
            {
                continue;
            }
            if packed_ref_line_contains_name(line, name) {
                return Err(GitSafetyError::TamperedRef {
                    name: String::from_utf8_lossy(name).into_owned(),
                }
                .into());
            }
        }
        Ok(())
    }

    fn list_tree(
        &self,
        commit_id: GitCommitId,
        recursive: bool,
        output_limit: usize,
    ) -> Result<Vec<TreeEntry>, HomeArtifactStoreError> {
        let commit_hex = object_hex(commit_id.object_id());
        let mut arguments = vec![arg("ls-tree")];
        if recursive {
            arguments.push(arg("-r"));
            arguments.push(arg("-t"));
        }
        arguments.push(arg("-z"));
        arguments.push(arg_bytes(&commit_hex));
        let operation = if recursive {
            "verify Home artifact payload tree"
        } else {
            "read Home artifact root tree"
        };
        let output =
            self.store
                .run_git_with_limit(operation, &arguments, None, &[], output_limit)?;
        if !output.status.success() {
            return Err(command_failed(operation, &output).into());
        }
        parse_tree_entries(&output, operation)
    }

    fn build_archive_tree(
        &self,
        manifest_blob: GitBlobId,
        manifest: &HomeArtifactManifest,
    ) -> Result<super::GitObjectId, HomeArtifactStoreError> {
        let mut root = TreeDirectory::default();
        root.insert_file(
            HOME_ARTIFACT_TREE_MANIFEST_NAME.to_vec(),
            manifest_blob,
            false,
        )?;
        let mut payload = TreeDirectory::default();
        for entry in manifest.entries() {
            if let HomeArtifactPathState::Regular { blob, mode, .. } = entry.state() {
                payload.insert_path(entry.path(), *blob, mode.get() & 0o111 != 0)?;
            }
        }
        if root
            .directories
            .insert(HOME_ARTIFACT_TREE_PAYLOAD_NAME.to_vec(), payload)
            .is_some()
        {
            return Err(HomeArtifactStoreError::Corrupt("duplicate payload tree"));
        }
        root.write(self.store)
    }

    fn create_commit(
        &self,
        artifact_id: HomeArtifactId,
        manifest_digest: HomeArtifactManifestDigest,
        tree: super::GitObjectId,
        source_observed_at: TimestampMillis,
    ) -> Result<GitCommitId, HomeArtifactStoreError> {
        let message = format!(
            "Heterarchy Home artifact {}\n\nManifest digest: {}\n",
            artifact_id.into_uuid(),
            digest_hex(manifest_digest.as_bytes())
        );
        let date = format!("@{} +0000", source_observed_at.get().div_euclid(1_000));
        let commit_env = [
            ("GIT_AUTHOR_NAME", OsString::from("Heterarchy Forge")),
            ("GIT_AUTHOR_EMAIL", OsString::from("forge@localhost")),
            ("GIT_COMMITTER_NAME", OsString::from("Heterarchy Forge")),
            ("GIT_COMMITTER_EMAIL", OsString::from("forge@localhost")),
            ("GIT_AUTHOR_DATE", OsString::from(date.clone())),
            ("GIT_COMMITTER_DATE", OsString::from(date)),
        ];
        let output = self.store.run_git(
            "create Home artifact commit",
            &[
                arg("commit-tree"),
                arg_bytes(&object_hex(tree)),
                arg("-m"),
                OsString::from(message),
            ],
            None,
            &commit_env,
        )?;
        if !output.status.success() {
            return Err(command_failed("create Home artifact commit", &output).into());
        }
        let commit = parse_git_object_id("create Home artifact commit", &output.stdout)?;
        Ok(GitCommitId::from_sha1_bytes(*commit.as_bytes()))
    }

    fn parse_inventory_candidate(
        record: &[u8],
    ) -> Result<InventoryCandidate, (Vec<u8>, HomeArtifactRefIssue)> {
        let mut fields = record.split(|byte| *byte == 0);
        let Some(name) = fields.next() else {
            return Err((record.to_vec(), HomeArtifactRefIssue::MalformedRecord));
        };
        let Some(object_name) = fields.next() else {
            return Err((name.to_vec(), HomeArtifactRefIssue::MalformedRecord));
        };
        if fields.next().is_some() {
            return Err((name.to_vec(), HomeArtifactRefIssue::MalformedRecord));
        }
        let suffix = name
            .strip_prefix(HOME_ARTIFACT_REF_NAMESPACE.as_bytes())
            .and_then(|value| value.strip_prefix(b"/"))
            .ok_or_else(|| (name.to_vec(), HomeArtifactRefIssue::MalformedName))?;
        let suffix_text = std::str::from_utf8(suffix)
            .map_err(|_| (name.to_vec(), HomeArtifactRefIssue::MalformedName))?;
        let artifact_id = suffix_text
            .parse::<HomeArtifactId>()
            .map_err(|_| (name.to_vec(), HomeArtifactRefIssue::MalformedName))?;
        if artifact_id.into_uuid().to_string().as_bytes() != suffix {
            return Err((name.to_vec(), HomeArtifactRefIssue::MalformedName));
        }
        let object = parse_git_object_id("inventory Home artifact ref", object_name)
            .map_err(|_| (name.to_vec(), HomeArtifactRefIssue::InvalidObjectId))?;
        Ok(InventoryCandidate {
            name: name.to_vec(),
            artifact_id,
            commit_id: GitCommitId::from_sha1_bytes(*object.as_bytes()),
        })
    }
}

/// Exact member read after full archive verification.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeArtifactPathRead {
    Absent,
    Regular {
        hash: FileContentHash,
        size: FileByteCount,
        mode: CheckpointFileMode,
        content: Vec<u8>,
    },
}

/// Maximum Home refs returned by one inventory pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeArtifactRefInventoryLimit(u16);

impl HomeArtifactRefInventoryLimit {
    pub const DEFAULT: Self = Self(HOME_ARTIFACT_REF_INVENTORY_MAX);

    pub const fn new(value: u16) -> Result<Self, HomeArtifactStoreError> {
        if value == 0 || value > HOME_ARTIFACT_REF_INVENTORY_MAX {
            Err(HomeArtifactStoreError::InvalidInventoryLimit {
                actual: value,
                maximum: HOME_ARTIFACT_REF_INVENTORY_MAX,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeArtifactRefIssue {
    MalformedRecord,
    MalformedName,
    InvalidObjectId,
    NonCommit,
    MissingObject,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeArtifactRefInventoryEntry {
    Retained {
        artifact_id: HomeArtifactId,
        commit_id: GitCommitId,
    },
    ProtectedUnknown {
        name: Vec<u8>,
        reason: HomeArtifactRefIssue,
    },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeArtifactRefInventory {
    entries: Vec<HomeArtifactRefInventoryEntry>,
    truncated: bool,
}

impl HomeArtifactRefInventory {
    pub fn entries(&self) -> &[HomeArtifactRefInventoryEntry] {
        &self.entries
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Debug, Error)]
pub enum HomeArtifactStoreError {
    #[error(transparent)]
    Git(#[from] GitSafetyError),
    #[error(transparent)]
    Confined(#[from] super::ConfinedFilesystemError),
    #[error(transparent)]
    Intent(#[from] HomeArtifactCaptureIntentError),
    #[error(transparent)]
    Manifest(#[from] HomeArtifactManifestError),
    #[error(transparent)]
    Archive(#[from] HomeArtifactArchiveError),
    #[error("Home artifact identity is already bound to a different capture intent")]
    IntentConflict,
    #[error("Home artifact read path is not declared by the exact intent")]
    PathNotDeclared,
    #[error("Home artifact ref identity does not match its manifest")]
    ArtifactIdentityMismatch,
    #[error("Home artifact archive is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("Home artifact capture exceeded its {0} bound")]
    Bounds(&'static str),
    #[error("Home artifact ref inventory limit {actual} is outside 1..={maximum}")]
    InvalidInventoryLimit { actual: u16, maximum: u16 },
    #[error("Home artifact publication outcome is unknown; exact readback failed")]
    PublicationUnknown {
        #[source]
        publication: Box<GitSafetyError>,
        readback: Box<Self>,
    },
}

struct TreeEntry {
    mode: Vec<u8>,
    kind: Vec<u8>,
    object: super::GitObjectId,
    path: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeEntryExpectation {
    mode: Vec<u8>,
    kind: Vec<u8>,
    object: Option<super::GitObjectId>,
}

struct InventoryCandidate {
    name: Vec<u8>,
    artifact_id: HomeArtifactId,
    commit_id: GitCommitId,
}

enum InventoryEntryWork {
    Candidate(usize),
    Unknown(Vec<u8>, HomeArtifactRefIssue),
}

#[derive(Default)]
struct TreeDirectory {
    directories: BTreeMap<Vec<u8>, TreeDirectory>,
    files: BTreeMap<Vec<u8>, TreeFile>,
}

struct TreeFile {
    blob: GitBlobId,
    executable: bool,
}

impl TreeDirectory {
    fn insert_path(
        &mut self,
        path: &WorkspaceRelativePath,
        blob: GitBlobId,
        executable: bool,
    ) -> Result<(), HomeArtifactStoreError> {
        let components = path.as_path().components().collect::<Vec<_>>();
        let Some((leaf, parents)) = components.split_last() else {
            return Err(HomeArtifactStoreError::Corrupt("empty payload path"));
        };
        if parents
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
            || !matches!(leaf, Component::Normal(_))
        {
            return Err(HomeArtifactStoreError::Corrupt("unconfined payload path"));
        }
        let mut directory = self;
        for component in parents {
            let name = component.as_os_str().as_bytes().to_vec();
            if directory.files.contains_key(&name) {
                return Err(HomeArtifactStoreError::Corrupt(
                    "payload file-directory collision",
                ));
            }
            directory = directory.directories.entry(name).or_default();
        }
        let leaf = leaf.as_os_str().as_bytes().to_vec();
        if directory.directories.contains_key(&leaf)
            || directory
                .files
                .insert(leaf, TreeFile { blob, executable })
                .is_some()
        {
            return Err(HomeArtifactStoreError::Corrupt("duplicate payload path"));
        }
        Ok(())
    }

    fn insert_file(
        &mut self,
        name: Vec<u8>,
        blob: GitBlobId,
        executable: bool,
    ) -> Result<(), HomeArtifactStoreError> {
        if name.is_empty()
            || name.contains(&0)
            || self.directories.contains_key(&name)
            || self
                .files
                .insert(name, TreeFile { blob, executable })
                .is_some()
        {
            return Err(HomeArtifactStoreError::Corrupt(
                "duplicate archive tree path",
            ));
        }
        Ok(())
    }

    fn write(
        &self,
        store: &GitCheckpointStore,
    ) -> Result<super::GitObjectId, HomeArtifactStoreError> {
        let mut entries = Vec::with_capacity(self.directories.len() + self.files.len());
        for (name, directory) in &self.directories {
            let object = directory.write(store)?;
            let mut sort_key = name.clone();
            sort_key.push(b'/');
            let entry = mktree_entry(b"040000", b"tree", object, name)?;
            entries.push((sort_key, entry));
        }
        for (name, file) in &self.files {
            let mode = if file.executable {
                b"100755"
            } else {
                b"100644"
            };
            let entry = mktree_entry(mode, b"blob", file.blob.object_id(), name)?;
            entries.push((name.clone(), entry));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let input = entries
            .into_iter()
            .flat_map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        Ok(store.write_mktree(&input)?)
    }
}

fn parse_tree_entries(
    output: &GitOutput,
    operation: &str,
) -> Result<Vec<TreeEntry>, HomeArtifactStoreError> {
    let mut entries = Vec::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let Some(separator) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(HomeArtifactStoreError::Corrupt("Git tree record separator"));
        };
        let metadata = &record[..separator];
        let path = &record[separator + 1..];
        if path.is_empty() {
            return Err(HomeArtifactStoreError::Corrupt("Git tree empty path"));
        }
        let mut fields = metadata.split(|byte| *byte == b' ');
        let Some(mode) = fields.next() else {
            return Err(HomeArtifactStoreError::Corrupt("Git tree mode"));
        };
        let Some(kind) = fields.next() else {
            return Err(HomeArtifactStoreError::Corrupt("Git tree type"));
        };
        let Some(object_hex) = fields.next() else {
            return Err(HomeArtifactStoreError::Corrupt("Git tree object"));
        };
        if fields.next().is_some() {
            return Err(HomeArtifactStoreError::Corrupt("Git tree metadata shape"));
        }
        let object = parse_git_object_id(operation, object_hex)?;
        entries.push(TreeEntry {
            mode: mode.to_vec(),
            kind: kind.to_vec(),
            object,
            path: path.to_vec(),
        });
        if entries.len() > MAX_HOME_ARTIFACT_TREE_ENTRIES {
            return Err(HomeArtifactStoreError::Bounds("tree entry count"));
        }
    }
    Ok(entries)
}

fn home_artifact_tree_output_limit(
    manifest: &HomeArtifactManifest,
) -> Result<usize, HomeArtifactStoreError> {
    let mut output_limit = 128_usize;
    for entry in manifest.entries() {
        if !matches!(entry.state(), HomeArtifactPathState::Regular { .. }) {
            continue;
        }
        let mut component_count = 0_usize;
        let mut prefix_length = HOME_ARTIFACT_TREE_PAYLOAD_NAME.len();
        for component in entry.path().components() {
            component_count =
                component_count
                    .checked_add(1)
                    .ok_or(HomeArtifactStoreError::Corrupt(
                        "tree output bound overflow",
                    ))?;
            prefix_length = prefix_length
                .checked_add(1)
                .and_then(|length| length.checked_add(component.as_bytes().len()))
                .ok_or(HomeArtifactStoreError::Corrupt(
                    "tree output bound overflow",
                ))?;
            let record_bound = prefix_length
                .checked_add(HOME_ARTIFACT_TREE_RECORD_OVERHEAD)
                .ok_or(HomeArtifactStoreError::Corrupt(
                    "tree output bound overflow",
                ))?;
            output_limit =
                output_limit
                    .checked_add(record_bound)
                    .ok_or(HomeArtifactStoreError::Corrupt(
                        "tree output bound overflow",
                    ))?;
        }
        if component_count == 0 || component_count > crate::MAX_FILE_PATH_COMPONENTS {
            return Err(HomeArtifactStoreError::Corrupt("payload component count"));
        }
    }
    output_limit = output_limit.max(MIN_HOME_ARTIFACT_TREE_OUTPUT_BYTES);
    if output_limit > MAX_HOME_ARTIFACT_TREE_OUTPUT_BYTES {
        return Err(HomeArtifactStoreError::Corrupt("tree output bound"));
    }
    Ok(output_limit)
}

fn home_artifact_ref_name(artifact_id: HomeArtifactId) -> String {
    format!("{HOME_ARTIFACT_REF_PREFIX}{}", artifact_id.into_uuid())
}

fn packed_ref_line_contains_name(line: &[u8], name: &[u8]) -> bool {
    !name.is_empty()
        && line.windows(name.len()).enumerate().any(|(index, window)| {
            let end = index + name.len();
            window == name
                && (index == 0 || line[index - 1].is_ascii_whitespace())
                && (end == line.len() || line[end].is_ascii_whitespace())
        })
}

fn digest_hex(digest: &[u8; 32]) -> String {
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Barrier;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct TestRepo {
        root: PathBuf,
    }

    impl TestRepo {
        fn create(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let root = std::env::temp_dir().join(format!(
                "forge-home-artifact-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            run_git(&root, &["init", "--initial-branch=main"])?;
            run_git(&root, &["config", "user.name", "Forge Home Artifact Tests"])?;
            run_git(
                &root,
                &[
                    "config",
                    "user.email",
                    "forge-home-artifact-tests@localhost",
                ],
            )?;
            fs::write(root.join("seed.txt"), b"seed\n")?;
            run_git(&root, &["add", "seed.txt"])?;
            run_git(&root, &["commit", "-m", "initial"])?;
            let _layout = super::super::WorkspaceStateLayout::initialize(&root)?;
            Ok(Self { root })
        }

        fn open_store(&self) -> Result<GitCheckpointStore, GitSafetyError> {
            let layout = super::super::WorkspaceStateLayout::inspect_existing(&self.root)
                .map_err(|_| GitSafetyError::InvalidCheckpointRoot {
                    path: self.root.clone(),
                })?
                .ok_or_else(|| GitSafetyError::InvalidCheckpointRoot {
                    path: self.root.clone(),
                })?;
            GitCheckpointStore::new(&self.root, layout.checkpoints())
        }
    }

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn run_git(root: &Path, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(super::super::FORGE_GIT_PROGRAM)
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "git {:?} failed: {}",
                arguments,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn run_git_store(
        store: &GitCheckpointStore,
        arguments: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(super::super::FORGE_GIT_PROGRAM)
            .arg("--git-dir")
            .arg(store.git_store_path())
            .args(arguments)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "git store {:?} failed: {}",
                arguments,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
    }

    fn make_intent(
        artifact: u128,
        paths: Vec<WorkspaceRelativePath>,
    ) -> Result<HomeArtifactCaptureIntent, Box<dyn std::error::Error>> {
        Ok(HomeArtifactCaptureIntent::new(
            HomeArtifactId::new(Uuid::from_u128(artifact))?,
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            forge_domain::WorkspaceId::from_uuid(Uuid::from_u128(4)),
            forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(5)),
            forge_domain::AgentAssignmentRevision::new(6)?,
            forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(7)),
            paths,
        )?)
    }

    fn open_test_store(repo: &TestRepo) -> Result<GitCheckpointStore, Box<dyn std::error::Error>> {
        Ok(repo.open_store()?)
    }

    fn replace_ref_for_test(
        store: &GitCheckpointStore,
        artifact_id: HomeArtifactId,
        tree: super::super::GitObjectId,
        expected: GitCommitId,
    ) -> Result<GitCommitId, Box<dyn std::error::Error>> {
        let output = store.run_git(
            "create test Home artifact commit",
            &[
                arg("commit-tree"),
                arg_bytes(&object_hex(tree)),
                arg("-m"),
                arg("tampered"),
            ],
            None,
            &[
                ("GIT_AUTHOR_NAME", OsString::from("Forge Tests")),
                ("GIT_AUTHOR_EMAIL", OsString::from("forge-tests@localhost")),
                ("GIT_COMMITTER_NAME", OsString::from("Forge Tests")),
                (
                    "GIT_COMMITTER_EMAIL",
                    OsString::from("forge-tests@localhost"),
                ),
                ("GIT_AUTHOR_DATE", OsString::from("@1 +0000")),
                ("GIT_COMMITTER_DATE", OsString::from("@1 +0000")),
            ],
        )?;
        if !output.status.success() {
            return Err(command_failed("create test Home artifact commit", &output).into());
        }
        let object = parse_git_object_id("create test Home artifact commit", &output.stdout)?;
        let commit_id = GitCommitId::from_sha1_bytes(*object.as_bytes());
        let name = home_artifact_ref_name(artifact_id);
        let updated = store.run_git(
            "tamper test Home artifact ref",
            &[
                arg("update-ref"),
                os(&name),
                arg_bytes(&object_hex(commit_id.object_id())),
                arg_bytes(&object_hex(expected.object_id())),
            ],
            None,
            &[],
        )?;
        if !updated.status.success() {
            return Err(command_failed("tamper test Home artifact ref", &updated).into());
        }
        Ok(commit_id)
    }

    fn store_entry_blob_path(store: &GitCheckpointStore, blob: GitBlobId) -> PathBuf {
        let hex = object_hex(blob.object_id());
        store
            .git_store_path()
            .join("objects")
            .join(std::ffi::OsStr::from_bytes(&hex[..2]))
            .join(std::ffi::OsStr::from_bytes(&hex[2..]))
    }

    fn write_loose_ref(
        store: &GitCheckpointStore,
        name: &str,
        contents: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = store.git_store_path().join(name);
        let parent = path.parent().ok_or("loose ref has no parent directory")?;
        fs::create_dir_all(parent)?;
        fs::write(path, contents)?;
        Ok(())
    }

    fn inventory_does_not_turn_broken_refs_into_empty_state(
        label: &str,
        name: &str,
        contents: &[u8],
    ) -> TestResult {
        let repo = TestRepo::create(label)?;
        let store = open_test_store(&repo)?;
        write_loose_ref(&store, name, contents)?;
        let inventory = HomeArtifactStore::new(&store)
            .inventory_refs_read_only(HomeArtifactRefInventoryLimit::DEFAULT);
        match inventory {
            Err(_) => Ok(()),
            Ok(inventory) if !inventory.entries().is_empty() => Ok(()),
            Ok(_) => Err(format!("broken loose ref {name} disappeared from inventory").into()),
        }
    }

    #[test]
    fn archive_keeps_promised_bytes_after_live_edit_and_deletion() -> TestResult {
        let repo = TestRepo::create("retained-bytes")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(101, vec![path("src/lib.rs")?, path("src/new.rs")?])?;
        fs::create_dir_all(repo.root.join("src"))?;
        fs::write(repo.root.join("src/lib.rs"), b"original\0bytes")?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(100)?)?;
        fs::write(repo.root.join("src/lib.rs"), b"changed live value")?;
        fs::remove_file(repo.root.join("src/lib.rs"))?;
        fs::write(repo.root.join("src/new.rs"), b"late file")?;

        let (retained_archive, retained) = artifacts
            .read_member_with_archive(&intent, &path("src/lib.rs")?)?
            .ok_or("retained archive disappeared")?;
        assert_eq!(retained_archive, archive);
        assert!(matches!(
            retained,
            HomeArtifactPathRead::Regular { ref content, .. } if content == b"original\0bytes"
        ));
        assert_eq!(
            artifacts.read_member(&intent, &path("src/new.rs")?)?,
            Some(HomeArtifactPathRead::Absent)
        );
        assert_eq!(artifacts.read(&intent)?, Some(archive));
        Ok(())
    }

    #[test]
    fn replay_returns_original_archive_without_recapturing_live_paths() -> TestResult {
        let repo = TestRepo::create("replay")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(102, vec![path("src/file.rs")?])?;
        fs::create_dir_all(repo.root.join("src"))?;
        fs::write(repo.root.join("src/file.rs"), b"first capture")?;
        let artifacts = HomeArtifactStore::new(&store);
        let first = artifacts.publish(&intent, TimestampMillis::new(200)?)?;
        fs::write(repo.root.join("src/file.rs"), b"later live value")?;
        let replay = artifacts.publish(&intent, TimestampMillis::new(999)?)?;
        assert_eq!(replay, first);
        assert!(matches!(
            artifacts.read_member(&intent, &path("src/file.rs")?)?,
            Some(HomeArtifactPathRead::Regular { ref content, .. }) if content == b"first capture"
        ));
        Ok(())
    }

    #[test]
    fn hardened_archive_reopens_and_reads_the_same_member() -> TestResult {
        let repo = TestRepo::create("durability-reopen")?;
        let store = open_test_store(&repo)?;
        let member_path = path("src/home.md")?;
        fs::create_dir_all(repo.root.join("src"))?;
        fs::write(
            repo.root.join(member_path.as_path()),
            b"retained home bytes",
        )?;
        let intent = make_intent(109, vec![member_path.clone()])?;
        let archive =
            HomeArtifactStore::new(&store).publish(&intent, TimestampMillis::new(901)?)?;
        HomeArtifactStore::new(&store).harden_archive(&archive)?;
        drop(store);

        let reopened = open_test_store(&repo)?;
        let artifacts = HomeArtifactStore::new(&reopened);
        assert_eq!(artifacts.read(&intent)?, Some(archive.clone()));
        assert!(matches!(
            artifacts.read_member(&intent, &member_path)?,
            Some(HomeArtifactPathRead::Regular { ref content, .. })
                if content == b"retained home bytes"
        ));
        Ok(())
    }

    #[test]
    fn hardened_archive_supports_packed_objects_and_packed_refs() -> TestResult {
        let repo = TestRepo::create("durability-packed")?;
        let store = open_test_store(&repo)?;
        let member_path = path("src/packed.md")?;
        fs::create_dir_all(repo.root.join("src"))?;
        fs::write(repo.root.join(member_path.as_path()), b"packed home bytes")?;
        let intent = make_intent(110, vec![member_path.clone()])?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(902)?)?;
        let blob = match archive
            .manifest()
            .entries()
            .first()
            .ok_or("archive has no member")?
            .state()
        {
            HomeArtifactPathState::Regular { blob, .. } => *blob,
            HomeArtifactPathState::Absent => return Err("archive member is absent".into()),
        };
        let loose_object = store_entry_blob_path(&store, blob);
        let ref_name = home_artifact_ref_name(intent.artifact_id());
        let loose_ref = store.git_store_path().join(&ref_name);

        run_git_store(&store, &["config", "gc.writeCommitGraph", "false"])?;
        run_git_store(&store, &["gc", "--prune=now"])?;
        run_git_store(&store, &["pack-refs", "--all", "--prune"])?;

        assert!(!loose_object.exists());
        assert!(!loose_ref.exists());
        assert!(
            fs::read(store.git_store_path().join("packed-refs"))?
                .windows(ref_name.len())
                .any(|window| window == ref_name.as_bytes())
        );
        artifacts.harden_archive(&archive)?;
        assert_eq!(artifacts.read(&intent)?, Some(archive.clone()));
        assert!(matches!(
            artifacts.read_member(&intent, &member_path)?,
            Some(HomeArtifactPathRead::Regular { ref content, .. })
                if content == b"packed home bytes"
        ));
        Ok(())
    }

    #[test]
    fn durability_rejects_tampered_refs_missing_objects_and_unsafe_info_entries() -> TestResult {
        let repo = TestRepo::create("durability-corruption")?;
        let store = open_test_store(&repo)?;
        let member_path = path("src/checked.md")?;
        fs::create_dir_all(repo.root.join("src"))?;
        fs::write(repo.root.join(member_path.as_path()), b"checked home bytes")?;
        let intent = make_intent(111, vec![member_path])?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(903)?)?;
        let ref_path = store
            .git_store_path()
            .join(home_artifact_ref_name(intent.artifact_id()));
        let ref_bytes = fs::read(&ref_path)?;
        fs::write(&ref_path, b"not a commit ref\n")?;
        assert!(artifacts.harden_archive(&archive).is_err());
        assert_eq!(fs::read(&ref_path)?, b"not a commit ref\n");
        fs::write(&ref_path, &ref_bytes)?;

        let blob = match archive
            .manifest()
            .entries()
            .first()
            .ok_or("archive has no member")?
            .state()
        {
            HomeArtifactPathState::Regular { blob, .. } => *blob,
            HomeArtifactPathState::Absent => return Err("archive member is absent".into()),
        };
        let object_path = store_entry_blob_path(&store, blob);
        let object_bytes = fs::read(&object_path)?;
        fs::remove_file(&object_path)?;
        assert!(artifacts.harden_archive(&archive).is_err());
        assert!(!object_path.exists());
        fs::write(&object_path, &object_bytes)?;

        let info = store.git_store_path().join("objects/info");
        fs::create_dir_all(&info)?;
        let packs = info.join("packs");
        let outside = repo.root.join("outside-packs");
        fs::write(&outside, b"outside")?;
        symlink(&outside, &packs)?;
        assert_eq!(artifacts.read(&intent)?, Some(archive.clone()));
        assert!(artifacts.harden_archive(&archive).is_err());
        assert!(fs::symlink_metadata(&packs)?.file_type().is_symlink());
        fs::remove_file(&packs)?;
        fs::create_dir(&packs)?;
        assert_eq!(artifacts.read(&intent)?, Some(archive.clone()));
        assert!(artifacts.harden_archive(&archive).is_err());
        assert!(fs::symlink_metadata(&packs)?.is_dir());
        fs::remove_dir(&packs)?;

        assert_eq!(artifacts.read(&intent)?, Some(archive.clone()));
        artifacts.harden_archive(&archive)?;
        Ok(())
    }

    #[test]
    fn same_artifact_identity_with_different_path_intent_conflicts() -> TestResult {
        let repo = TestRepo::create("intent-conflict")?;
        let store = open_test_store(&repo)?;
        fs::create_dir_all(repo.root.join("src"))?;
        fs::write(repo.root.join("src/one.rs"), b"one")?;
        fs::write(repo.root.join("src/two.rs"), b"two")?;
        let first_intent = make_intent(103, vec![path("src/one.rs")?])?;
        let other_intent = make_intent(103, vec![path("src/two.rs")?])?;
        let artifacts = HomeArtifactStore::new(&store);
        let first = artifacts.publish(&first_intent, TimestampMillis::new(300)?)?;
        assert!(matches!(
            artifacts.read(&other_intent),
            Err(HomeArtifactStoreError::IntentConflict)
        ));
        assert!(matches!(
            artifacts.publish(&other_intent, TimestampMillis::new(301)?),
            Err(HomeArtifactStoreError::IntentConflict)
        ));
        assert_eq!(artifacts.read(&first_intent)?, Some(first));
        Ok(())
    }

    #[test]
    fn confined_capture_rejects_symlink_and_product_state_paths() -> TestResult {
        let repo = TestRepo::create("confinement")?;
        let outside = repo.root.with_extension("outside");
        fs::create_dir_all(&outside)?;
        fs::write(outside.join("private"), b"outside")?;
        symlink(&outside, repo.root.join("escape"))?;
        let store = open_test_store(&repo)?;
        let artifacts = HomeArtifactStore::new(&store);
        let symlink_intent = make_intent(104, vec![path("escape/private")?])?;
        assert!(matches!(
            artifacts.publish(&symlink_intent, TimestampMillis::new(400)?),
            Err(HomeArtifactStoreError::Confined(_))
        ));
        let state_intent = make_intent(105, vec![path(".heterarchy-forge/checkpoints/private")?])?;
        assert!(matches!(
            artifacts.publish(&state_intent, TimestampMillis::new(401)?),
            Err(HomeArtifactStoreError::Confined(_))
        ));
        let _ignored = fs::remove_dir_all(outside);
        Ok(())
    }

    #[test]
    fn declared_total_bound_and_missing_ref_are_explicit() -> TestResult {
        let repo = TestRepo::create("bounds")?;
        let store = open_test_store(&repo)?;
        let intent_paths = (0..17)
            .map(|index| path(&format!("large-{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        let intent = make_intent(106, intent_paths.clone())?;
        let content = vec![0x51; usize::try_from(MAX_HOME_ARTIFACT_FILE_BYTES)?];
        for path in &intent_paths {
            fs::write(repo.root.join(path.as_path()), &content)?;
        }
        let artifacts = HomeArtifactStore::new(&store);
        assert!(matches!(
            artifacts.publish(&intent, TimestampMillis::new(500)?),
            Err(HomeArtifactStoreError::Bounds("total byte count"))
        ));
        assert_eq!(artifacts.read(&intent)?, None);
        Ok(())
    }

    #[test]
    fn exact_read_rejects_broken_loose_refs_instead_of_reporting_absence() -> TestResult {
        let zero_oid = b"0000000000000000000000000000000000000000\n";
        let fixtures = [
            ("empty", b"".as_slice()),
            ("zero-oid", zero_oid.as_slice()),
            ("non-oid", b"not-a-git-object\n".as_slice()),
            (
                "dangling-symbolic",
                b"ref: refs/heterarchy-forge/home-artifacts/missing\n".as_slice(),
            ),
        ];
        for (index, (label, contents)) in fixtures.into_iter().enumerate() {
            let repo = TestRepo::create(label)?;
            let store = open_test_store(&repo)?;
            let artifact_id =
                HomeArtifactId::new(Uuid::from_u128(130_u128 + u128::try_from(index)?))?;
            let intent = HomeArtifactCaptureIntent::new(
                artifact_id,
                Uuid::from_u128(2),
                Uuid::from_u128(3),
                forge_domain::WorkspaceId::from_uuid(Uuid::from_u128(4)),
                forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(5)),
                forge_domain::AgentAssignmentRevision::new(6)?,
                forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(7)),
                vec![path("file.rs")?],
            )?;
            write_loose_ref(&store, &home_artifact_ref_name(artifact_id), contents)?;

            assert!(
                HomeArtifactStore::new(&store).read(&intent).is_err(),
                "broken exact loose ref {label} must remain an error"
            );
        }
        Ok(())
    }

    #[test]
    fn exact_read_rejects_a_malformed_packed_ref() -> TestResult {
        let repo = TestRepo::create("packed-ref")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(134, vec![path("file.rs")?])?;
        let name = home_artifact_ref_name(intent.artifact_id());
        let packed_refs =
            format!("# pack-refs with: peeled fully-peeled sorted\nnot-a-git-object {name}\n");
        fs::write(store.git_store_path().join("packed-refs"), packed_refs)?;

        assert!(HomeArtifactStore::new(&store).read(&intent).is_err());
        Ok(())
    }

    #[test]
    fn tampered_manifest_and_missing_blob_are_not_empty_archives() -> TestResult {
        let repo = TestRepo::create("tamper")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(107, vec![path("src/file.rs")?])?;
        fs::create_dir_all(repo.root.join("src"))?;
        fs::write(repo.root.join("src/file.rs"), b"archived")?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(600)?)?;
        let manifest_blob = store.write_blob(b"not a manifest")?;
        let payload_tree = store.write_mktree(&[])?;
        let mut input = mktree_entry(
            b"100644",
            b"blob",
            manifest_blob.object_id(),
            HOME_ARTIFACT_TREE_MANIFEST_NAME,
        )?;
        input.extend_from_slice(&mktree_entry(
            b"040000",
            b"tree",
            payload_tree,
            HOME_ARTIFACT_TREE_PAYLOAD_NAME,
        )?);
        let tampered_tree = store.write_mktree(&input)?;
        let _tampered_commit = replace_ref_for_test(
            &store,
            intent.artifact_id(),
            tampered_tree,
            archive.commit_id(),
        )?;
        assert!(matches!(
            artifacts.read(&intent),
            Err(HomeArtifactStoreError::Manifest(_))
        ));

        let repo = TestRepo::create("missing-blob")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(108, vec![path("file.rs")?])?;
        fs::write(repo.root.join("file.rs"), b"archived")?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(601)?)?;
        let regular = archive
            .manifest()
            .entries()
            .first()
            .ok_or("missing manifest path entry")?;
        let blob = match regular.state() {
            HomeArtifactPathState::Regular { blob, .. } => *blob,
            HomeArtifactPathState::Absent => return Err("expected regular archived file".into()),
        };
        fs::remove_file(store_entry_blob_path(&store, blob))?;
        assert!(artifacts.read(&intent).is_err());
        Ok(())
    }

    #[test]
    fn tampered_manifest_hash_cannot_change_the_retained_member_bytes() -> TestResult {
        let repo = TestRepo::create("tampered-payload-hash")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(112, vec![path("file.rs")?])?;
        fs::write(repo.root.join("file.rs"), b"archive bytes")?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(650)?)?;
        let original = archive
            .manifest()
            .entries()
            .first()
            .ok_or("missing manifest path entry")?;
        let HomeArtifactPathState::Regular {
            blob, size, mode, ..
        } = original.state()
        else {
            return Err("expected regular archived file".into());
        };
        let tampered_manifest = HomeArtifactManifest::new(
            intent.clone(),
            archive.manifest().source_observed_at(),
            vec![HomeArtifactPathEntry::new(
                original.path().clone(),
                HomeArtifactPathState::Regular {
                    blob: *blob,
                    hash: FileContentHash::from_bytes([0xA5; FileContentHash::BYTE_LEN]),
                    size: *size,
                    mode: *mode,
                },
            )],
        )?;
        let manifest_blob = store.write_blob(&tampered_manifest.to_snapshot_bytes()?)?;
        let tree = artifacts.build_archive_tree(manifest_blob, &tampered_manifest)?;
        let _tampered_commit =
            replace_ref_for_test(&store, intent.artifact_id(), tree, archive.commit_id())?;
        assert!(matches!(
            artifacts.read(&intent),
            Err(HomeArtifactStoreError::Corrupt("retained blob hash"))
        ));
        Ok(())
    }

    #[test]
    fn read_rejects_an_unpromised_empty_subtree_at_an_absent_path() -> TestResult {
        let repo = TestRepo::create("empty-subtree")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(115, vec![path("missing")?])?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(660)?)?;

        let empty_tree = store.write_mktree(&[])?;
        let nested_tree =
            store.write_mktree(&mktree_entry(b"040000", b"tree", empty_tree, b"missing")?)?;
        let payload_tree = store.write_mktree(&mktree_entry(
            b"040000",
            b"tree",
            nested_tree,
            HOME_ARTIFACT_TREE_PAYLOAD_NAME,
        )?)?;
        let manifest_blob = store.write_blob(&archive.manifest().to_snapshot_bytes()?)?;
        let mut root_input = mktree_entry(
            b"100644",
            b"blob",
            manifest_blob.object_id(),
            HOME_ARTIFACT_TREE_MANIFEST_NAME,
        )?;
        root_input.extend_from_slice(&mktree_entry(
            b"040000",
            b"tree",
            payload_tree,
            HOME_ARTIFACT_TREE_PAYLOAD_NAME,
        )?);
        let tampered_tree = store.write_mktree(&root_input)?;
        let _tampered_commit = replace_ref_for_test(
            &store,
            intent.artifact_id(),
            tampered_tree,
            archive.commit_id(),
        )?;
        assert!(matches!(
            artifacts.read(&intent),
            Err(HomeArtifactStoreError::Corrupt(
                "archive payload tree entries"
            ))
        ));
        Ok(())
    }

    #[test]
    fn inventory_keeps_malformed_home_refs_as_protected_unknown() -> TestResult {
        let repo = TestRepo::create("inventory")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(109, vec![])?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(700)?)?;
        let malformed_name = format!("{HOME_ARTIFACT_REF_PREFIX}not-a-uuid");
        let malformed = store.run_git(
            "create malformed Home artifact ref fixture",
            &[
                arg("update-ref"),
                os(&malformed_name),
                arg_bytes(&object_hex(archive.commit_id().object_id())),
                arg_bytes(b"0000000000000000000000000000000000000000"),
            ],
            None,
            &[],
        )?;
        if !malformed.status.success() {
            return Err(
                command_failed("create malformed Home artifact ref fixture", &malformed).into(),
            );
        }
        let inventory =
            artifacts.inventory_refs_read_only(HomeArtifactRefInventoryLimit::DEFAULT)?;
        assert!(inventory.entries().iter().any(|entry| matches!(
            entry,
            HomeArtifactRefInventoryEntry::ProtectedUnknown { name, reason: HomeArtifactRefIssue::MalformedName }
                if name == malformed_name.as_bytes()
        )));
        assert!(inventory.entries().iter().any(|entry| matches!(
            entry,
            HomeArtifactRefInventoryEntry::Retained { artifact_id, commit_id }
                if *artifact_id == intent.artifact_id() && *commit_id == archive.commit_id()
        )));
        let checkpoint_inventory = store
            .inventory_refs_read_only(super::super::GitCheckpointRefInventoryLimit::DEFAULT)?;
        assert!(checkpoint_inventory.entries().is_empty());
        Ok(())
    }

    #[test]
    fn inventory_keeps_exact_namespace_root_ref_as_protected_unknown() -> TestResult {
        let repo = TestRepo::create("inventory-root")?;
        let store = open_test_store(&repo)?;
        let tree = store.write_mktree(&[])?;
        let output = store.run_git(
            "create namespace-root test commit",
            &[
                arg("commit-tree"),
                arg_bytes(&object_hex(tree)),
                arg("-m"),
                arg("malformed namespace root"),
            ],
            None,
            &[
                ("GIT_AUTHOR_NAME", OsString::from("Forge Tests")),
                ("GIT_AUTHOR_EMAIL", OsString::from("forge-tests@localhost")),
                ("GIT_COMMITTER_NAME", OsString::from("Forge Tests")),
                (
                    "GIT_COMMITTER_EMAIL",
                    OsString::from("forge-tests@localhost"),
                ),
                ("GIT_AUTHOR_DATE", OsString::from("@1 +0000")),
                ("GIT_COMMITTER_DATE", OsString::from("@1 +0000")),
            ],
        )?;
        if !output.status.success() {
            return Err(command_failed("create namespace-root test commit", &output).into());
        }
        let object = parse_git_object_id("create namespace-root test commit", &output.stdout)?;
        let commit = GitCommitId::from_sha1_bytes(*object.as_bytes());
        let updated = store.run_git(
            "create namespace-root Home artifact ref fixture",
            &[
                arg("update-ref"),
                arg(HOME_ARTIFACT_REF_NAMESPACE),
                arg_bytes(&object_hex(commit.object_id())),
                arg_bytes(b"0000000000000000000000000000000000000000"),
            ],
            None,
            &[],
        )?;
        if !updated.status.success() {
            return Err(command_failed(
                "create namespace-root Home artifact ref fixture",
                &updated,
            )
            .into());
        }
        let inventory = HomeArtifactStore::new(&store)
            .inventory_refs_read_only(HomeArtifactRefInventoryLimit::DEFAULT)?;
        assert_eq!(
            inventory.entries(),
            &[HomeArtifactRefInventoryEntry::ProtectedUnknown {
                name: HOME_ARTIFACT_REF_NAMESPACE.as_bytes().to_vec(),
                reason: HomeArtifactRefIssue::MalformedName,
            }]
        );
        Ok(())
    }

    #[test]
    fn inventory_fails_closed_on_broken_loose_refs() -> TestResult {
        let zero_oid = b"0000000000000000000000000000000000000000\n";
        let fixtures = [
            (
                "empty-child-ref",
                format!("{HOME_ARTIFACT_REF_PREFIX}{}", Uuid::from_u128(120)),
                b"".as_slice(),
            ),
            (
                "zero-child-ref",
                format!("{HOME_ARTIFACT_REF_PREFIX}{}", Uuid::from_u128(121)),
                zero_oid.as_slice(),
            ),
            (
                "empty-namespace-root-ref",
                HOME_ARTIFACT_REF_NAMESPACE.to_owned(),
                b"".as_slice(),
            ),
        ];
        for (label, name, contents) in fixtures {
            inventory_does_not_turn_broken_refs_into_empty_state(label, &name, contents)?;
        }
        Ok(())
    }

    #[test]
    fn read_member_refuses_paths_outside_the_intent_before_io() -> TestResult {
        let repo = TestRepo::create("undeclared")?;
        let store = open_test_store(&repo)?;
        let intent = make_intent(110, vec![path("declared")?])?;
        let artifacts = HomeArtifactStore::new(&store);
        assert!(matches!(
            artifacts.read_member(&intent, &path("other")?),
            Err(HomeArtifactStoreError::PathNotDeclared)
        ));
        Ok(())
    }

    #[test]
    fn read_member_requires_the_full_exact_intent_before_returning_bytes() -> TestResult {
        let repo = TestRepo::create("member-intent")?;
        let store = open_test_store(&repo)?;
        fs::write(repo.root.join("first"), b"first bytes")?;
        fs::write(repo.root.join("second"), b"second bytes")?;
        let expected = make_intent(111, vec![path("first")?, path("second")?])?;
        let artifacts = HomeArtifactStore::new(&store);
        let published = artifacts.publish(&expected, TimestampMillis::new(800)?)?;
        assert_eq!(published.manifest().intent(), &expected);

        let other_ancestry = HomeArtifactCaptureIntent::new(
            expected.artifact_id(),
            Uuid::from_u128(12),
            Uuid::from_u128(13),
            expected.workspace_id(),
            expected.predecessor_assignment_id(),
            expected.predecessor_revision(),
            forge_domain::AgentAssignmentId::from_uuid(Uuid::from_u128(14)),
            expected.paths().to_vec(),
        )?;
        assert!(matches!(
            artifacts.read_member(&other_ancestry, &path("first")?),
            Err(HomeArtifactStoreError::IntentConflict)
        ));

        let reordered = HomeArtifactCaptureIntent::new(
            expected.artifact_id(),
            expected.preparation_id(),
            expected.handoff_id(),
            expected.workspace_id(),
            expected.predecessor_assignment_id(),
            expected.predecessor_revision(),
            expected.root_assignment_id(),
            vec![path("second")?, path("first")?],
        )?;
        assert!(matches!(
            artifacts.read_member(&reordered, &path("first")?),
            Err(HomeArtifactStoreError::IntentConflict)
        ));
        Ok(())
    }

    #[test]
    fn publication_races_are_create_only_and_return_the_winning_archive() -> TestResult {
        let repo = TestRepo::create("publication-race")?;
        let store = open_test_store(&repo)?;
        fs::write(repo.root.join("shared"), b"same intent bytes")?;
        fs::write(repo.root.join("first"), b"first competing intent")?;
        fs::write(repo.root.join("second"), b"second competing intent")?;
        let artifacts = HomeArtifactStore::new(&store);

        let same_intent = make_intent(113, vec![path("shared")?])?;
        let early = TimestampMillis::new(900)?;
        let late = TimestampMillis::new(901)?;
        let barrier = Barrier::new(3);
        let (same_left, same_right) = std::thread::scope(|scope| {
            let barrier_left = &barrier;
            let barrier_right = &barrier;
            let store_left = &store;
            let store_right = &store;
            let intent_left = &same_intent;
            let intent_right = &same_intent;
            let left = scope.spawn(move || {
                barrier_left.wait();
                HomeArtifactStore::new(store_left).publish(intent_left, early)
            });
            let right = scope.spawn(move || {
                barrier_right.wait();
                HomeArtifactStore::new(store_right).publish(intent_right, late)
            });
            barrier.wait();
            let left = left
                .join()
                .map_err(|_| std::io::Error::other("same-intent publisher panicked"))?;
            let right = right
                .join()
                .map_err(|_| std::io::Error::other("same-intent publisher panicked"))?;
            Ok::<_, std::io::Error>((left, right))
        })?;
        let same_left = same_left?;
        let same_right = same_right?;
        assert_eq!(same_left, same_right);
        let winning_time = same_left.manifest().source_observed_at();
        assert!(winning_time == early || winning_time == late);

        let first_intent = make_intent(114, vec![path("first")?])?;
        let second_intent = make_intent(114, vec![path("second")?])?;
        let first_time = TimestampMillis::new(902)?;
        let second_time = TimestampMillis::new(903)?;
        let barrier = Barrier::new(3);
        // Align API entry without claiming exhaustive scheduling coverage.
        let (first_result, second_result) = std::thread::scope(|scope| {
            let barrier_first = &barrier;
            let barrier_second = &barrier;
            let store_first = &store;
            let store_second = &store;
            let intent_first = &first_intent;
            let intent_second = &second_intent;
            let first = scope.spawn(move || {
                barrier_first.wait();
                HomeArtifactStore::new(store_first).publish(intent_first, first_time)
            });
            let second = scope.spawn(move || {
                barrier_second.wait();
                HomeArtifactStore::new(store_second).publish(intent_second, second_time)
            });
            barrier.wait();
            let first = first
                .join()
                .map_err(|_| std::io::Error::other("competing publisher panicked"))?;
            let second = second
                .join()
                .map_err(|_| std::io::Error::other("competing publisher panicked"))?;
            Ok::<_, std::io::Error>((first, second))
        })?;

        let (winner_intent, loser_intent, winner_archive) = match (first_result, second_result) {
            (Ok(archive), Err(HomeArtifactStoreError::IntentConflict)) => {
                (&first_intent, &second_intent, archive)
            }
            (Err(HomeArtifactStoreError::IntentConflict), Ok(archive)) => {
                (&second_intent, &first_intent, archive)
            }
            other => {
                return Err(format!("expected one winner and one conflict, got {other:?}").into());
            }
        };
        assert_eq!(artifacts.read(winner_intent)?, Some(winner_archive));
        assert!(matches!(
            artifacts.read(loser_intent),
            Err(HomeArtifactStoreError::IntentConflict)
        ));
        assert!(matches!(
            artifacts.publish(loser_intent, TimestampMillis::new(904)?),
            Err(HomeArtifactStoreError::IntentConflict)
        ));
        Ok(())
    }
}
