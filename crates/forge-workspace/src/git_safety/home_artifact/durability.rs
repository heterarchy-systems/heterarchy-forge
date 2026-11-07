//! Descriptor-rooted durability barrier for retained Home artifact archives.
//!
//! The Git archive reader remains the authority for the logical archive. This
//! module verifies that same archive around a conservative fsync walk of the
//! exact reachable objects, the ref that retains them, and the owned Git
//! directory chain. It deliberately does not repair, recapture, prune, or run
//! Git maintenance.

use std::collections::{BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use forge_domain::{GitObjectId, HomeArtifactArchive};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fsync, open, openat, statat};
use rustix::io::Errno;

use crate::confinement::{
    directory_identity, directory_identity_by_path, sync_file as sync_file_descriptor,
};

use super::super::{
    GitCheckpointStore, GitSafetyError, arg, arg_bytes, command_failed, object_hex,
    parse_git_object_id,
};
use super::{
    HOME_ARTIFACT_REF_PREFIX, HomeArtifactStore, HomeArtifactStoreError,
    MAX_HOME_ARTIFACT_PACKED_REFS_BYTES,
};

const STORE_METADATA_FILE_BYTES: u64 = 64 * 1024;
const STORE_HEAD_FILE_BYTES: u64 = 256;
const OBJECT_INFO_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OBJECT_ROOT_ENTRIES: usize = 258;
const MAX_OBJECT_INFO_ENTRIES: usize = 16;
const MAX_PACK_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_PACKED_STORAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_REACHABLE_OBJECTS: usize = super::MAX_HOME_ARTIFACT_TREE_ENTRIES + 2;
const MAX_COMMIT_HEADER_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncPoint {
    LooseObject,
    PackedMetadata,
    StoreMetadata,
    LooseRef,
    PackedRefs,
    Directory,
    FinalMetadata,
}

trait SyncOperations {
    fn sync_file(&mut self, file: &File, point: SyncPoint) -> Result<(), Errno>;
    fn sync_directory(&mut self, directory: &File, point: SyncPoint) -> Result<(), Errno>;
}

struct KernelSync;

impl SyncOperations for KernelSync {
    fn sync_file(&mut self, file: &File, _point: SyncPoint) -> Result<(), Errno> {
        sync_file_descriptor(file)
    }

    fn sync_directory(&mut self, directory: &File, _point: SyncPoint) -> Result<(), Errno> {
        fsync(directory)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    is_directory: bool,
    is_regular: bool,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl MetadataSnapshot {
    fn from_file(file: &File, path: &Path) -> Result<Self, HomeArtifactStoreError> {
        let metadata = file
            .metadata()
            .map_err(|source| filesystem_error("inspect durability descriptor", path, source))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            is_directory: metadata.is_dir(),
            is_regular: metadata.is_file(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn matches_stat(self, stat: &Stat) -> bool {
        u64::try_from(stat.st_dev).ok() == Some(self.device)
            && stat.st_ino == self.inode
            && stat_nlink(stat) == self.links
            && stat_mode(stat) == self.mode
            && u64::try_from(stat.st_size).ok() == Some(self.size)
    }

    fn same_directory_identity(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.is_directory
            && other.is_directory
    }

    fn matches_directory_stat(self, stat: &Stat) -> bool {
        u64::try_from(stat.st_dev).ok() == Some(self.device)
            && stat.st_ino == self.inode
            && self.is_directory
            && FileType::from_raw_mode(stat.st_mode).is_dir()
    }
}

#[cfg(target_os = "macos")]
fn stat_nlink(stat: &Stat) -> u64 {
    u64::from(stat.st_nlink)
}

#[cfg(not(target_os = "macos"))]
fn stat_nlink(stat: &Stat) -> u64 {
    stat.st_nlink
}

#[cfg(target_os = "macos")]
fn stat_mode(stat: &Stat) -> u32 {
    u32::from(stat.st_mode)
}

#[cfg(not(target_os = "macos"))]
fn stat_mode(stat: &Stat) -> u32 {
    stat.st_mode
}

struct DirectoryHandle {
    file: File,
    path: PathBuf,
    snapshot: MetadataSnapshot,
    parent: Option<File>,
    name: Option<OsString>,
}

struct RegularFile {
    file: File,
    parent: File,
    name: OsString,
    path: PathBuf,
    snapshot: MetadataSnapshot,
    point: SyncPoint,
}

struct ObjectDirectories {
    objects: DirectoryHandle,
    fanout: std::collections::BTreeMap<Vec<u8>, MetadataSnapshot>,
    pack: Option<DirectoryHandle>,
    info: Option<DirectoryHandle>,
}

struct PackCensus {
    pack: Option<DirectoryHandle>,
    files: Vec<(OsString, MetadataSnapshot)>,
}

struct WorkspaceDirectoryChain {
    store: DirectoryHandle,
    checkpoints: DirectoryHandle,
    state: DirectoryHandle,
    workspace: DirectoryHandle,
}

struct ObjectSyncPlan {
    objects: DirectoryHandle,
    fanout: std::collections::BTreeMap<Vec<u8>, MetadataSnapshot>,
    info: Option<DirectoryHandle>,
    packs: PackCensus,
    info_files: Vec<RegularFile>,
    loose_fanout_to_sync: BTreeSet<Vec<u8>>,
}

struct RefSyncPlan {
    directories: Vec<DirectoryHandle>,
    retained_ref: RegularFile,
}

impl HomeArtifactStore<'_> {
    /// Verify and durably synchronize an already-published exact archive.
    ///
    /// This operation never creates or changes Git state. It is intentionally
    /// repeatable and may be called during recovery for the same archive ref.
    pub fn harden_archive(
        &self,
        archive: &HomeArtifactArchive,
    ) -> Result<(), HomeArtifactStoreError> {
        self.harden_archive_with(archive, &mut KernelSync)
    }

    fn harden_archive_with(
        &self,
        archive: &HomeArtifactArchive,
        sync: &mut impl SyncOperations,
    ) -> Result<(), HomeArtifactStoreError> {
        let artifact_id = archive.manifest().intent().artifact_id();
        verify_archive_before(self, archive, artifact_id)?;
        let reachable = self.reachable_object_ids(archive)?;
        self.store.ensure_sha1_object_format()?;
        let directories = WorkspaceDirectoryChain::open(self.store)?;
        ensure_store_and_workspace_binding(self.store, &directories)?;
        let mut retained_metadata = sync_store_metadata(&directories.store, sync)?;
        let mut objects = open_object_sync_plan(&directories.store)?;
        sync_reachable_loose_objects(&directories.store, &mut objects, &reachable, sync)?;
        sync_pack_and_info_files(&directories.store, &objects, &mut retained_metadata, sync)?;
        let mut reference = sync_archive_ref(
            &directories.store,
            artifact_id,
            archive,
            &mut retained_metadata,
            sync,
        )?;

        sync_archive_directories(&mut objects, &mut reference, &directories, sync)?;
        sync_final_metadata(
            &directories.store,
            &objects,
            &mut retained_metadata,
            &mut reference,
            sync,
        )?;
        ensure_store_and_workspace_binding(self.store, &directories)?;
        verify_archive_after(self, archive, artifact_id)?;
        ensure_store_and_workspace_binding(self.store, &directories)?;
        Ok(())
    }

    fn reachable_object_ids(
        &self,
        archive: &HomeArtifactArchive,
    ) -> Result<BTreeSet<GitObjectId>, HomeArtifactStoreError> {
        let commit = archive.commit_id();
        let commit_hex = object_hex(commit.object_id());
        let output = self.store.run_git_with_limit(
            "inspect retained Home artifact commit tree",
            &[arg("cat-file"), arg("commit"), arg_bytes(&commit_hex)],
            None,
            &[],
            MAX_COMMIT_HEADER_BYTES,
        )?;
        if !output.status.success() {
            return Err(
                command_failed("inspect retained Home artifact commit tree", &output).into(),
            );
        }
        let mut tree = None;
        for line in output.stdout.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                break;
            }
            if let Some(value) = line.strip_prefix(b"tree ") {
                if tree.is_some() {
                    return Err(HomeArtifactStoreError::Corrupt(
                        "archive commit contains multiple root trees",
                    ));
                }
                tree = Some(parse_git_object_id(
                    "inspect Home artifact root tree",
                    value,
                )?);
            } else if line.starts_with(b"parent ") {
                return Err(HomeArtifactStoreError::Corrupt(
                    "Home artifact commit unexpectedly has a parent",
                ));
            }
        }
        let Some(tree) = tree else {
            return Err(HomeArtifactStoreError::Corrupt(
                "Home artifact commit has no root tree",
            ));
        };

        let entries = self.list_tree(commit, true, super::MAX_HOME_ARTIFACT_TREE_OUTPUT_BYTES)?;
        let mut objects = BTreeSet::new();
        objects.insert(commit.object_id());
        objects.insert(tree);
        for entry in entries {
            if entry.kind != b"tree" && entry.kind != b"blob" {
                return Err(HomeArtifactStoreError::Corrupt(
                    "archive tree references an unsupported object type",
                ));
            }
            objects.insert(entry.object);
            if objects.len() > MAX_REACHABLE_OBJECTS {
                return Err(HomeArtifactStoreError::Bounds("reachable object inventory"));
            }
        }
        if objects.len() > MAX_REACHABLE_OBJECTS {
            return Err(HomeArtifactStoreError::Bounds("reachable object inventory"));
        }
        Ok(objects)
    }
}

impl WorkspaceDirectoryChain {
    fn open(store: &GitCheckpointStore) -> Result<Self, HomeArtifactStoreError> {
        let mut root = open_store_root(store)?;
        let mut checkpoints =
            open_parent_directory(&root, OsStr::new("store.git"), store.checkpoints.as_path())?;
        let state_path = store
            .checkpoints
            .parent()
            .ok_or(HomeArtifactStoreError::Corrupt(
                "checkpoint directory has no state parent",
            ))?;
        let mut state = open_parent_directory(&checkpoints, OsStr::new("checkpoints"), state_path)?;
        let workspace = open_parent_directory(
            &state,
            OsStr::new(".heterarchy-forge"),
            store.workspace_root(),
        )?;
        bind_parent(&mut root, &checkpoints, OsStr::new("store.git"))?;
        bind_parent(&mut checkpoints, &state, OsStr::new("checkpoints"))?;
        bind_parent(&mut state, &workspace, OsStr::new(".heterarchy-forge"))?;
        Ok(Self {
            store: root,
            checkpoints,
            state,
            workspace,
        })
    }

    fn sync_bottom_up(&self, sync: &mut impl SyncOperations) -> Result<(), HomeArtifactStoreError> {
        for directory in [&self.store, &self.checkpoints, &self.state, &self.workspace] {
            sync_directory(directory, sync)?;
        }
        Ok(())
    }
}

fn ensure_store_and_workspace_binding(
    store: &GitCheckpointStore,
    directories: &WorkspaceDirectoryChain,
) -> Result<(), HomeArtifactStoreError> {
    store
        .confined
        .ensure_for_git(false)
        .map_err(HomeArtifactStoreError::Confined)?;
    if directory_identity_by_path(&store.store).map_err(HomeArtifactStoreError::Confined)?
        != store.store_identity
        || !snapshot_at_path(store.workspace_root())?
            .same_directory_identity(directories.workspace.snapshot)
    {
        return Err(
            GitSafetyError::Confined(crate::ConfinedFilesystemError::CommittedPathChanged).into(),
        );
    }
    verify_directory_snapshot(&directories.store)?;
    verify_directory_snapshot(&directories.workspace)
}

fn verify_archive_before(
    store: &HomeArtifactStore<'_>,
    archive: &HomeArtifactArchive,
    artifact_id: forge_domain::HomeArtifactId,
) -> Result<(), HomeArtifactStoreError> {
    let before = store
        .read_archive_by_id(artifact_id)?
        .ok_or(HomeArtifactStoreError::Corrupt(
            "archive ref disappeared before durability barrier",
        ))?;
    if before == *archive {
        Ok(())
    } else {
        Err(HomeArtifactStoreError::Corrupt(
            "durability input differs from exact retained archive",
        ))
    }
}

fn verify_archive_after(
    store: &HomeArtifactStore<'_>,
    archive: &HomeArtifactArchive,
    artifact_id: forge_domain::HomeArtifactId,
) -> Result<(), HomeArtifactStoreError> {
    let after = store
        .read_archive_by_id(artifact_id)?
        .ok_or(HomeArtifactStoreError::Corrupt(
            "archive ref disappeared after durability barrier",
        ))?;
    if after == *archive {
        Ok(())
    } else {
        Err(HomeArtifactStoreError::Corrupt(
            "retained archive changed during durability barrier",
        ))
    }
}

fn sync_store_metadata(
    root: &DirectoryHandle,
    sync: &mut impl SyncOperations,
) -> Result<Vec<RegularFile>, HomeArtifactStoreError> {
    let head = open_required_regular_file(
        root,
        OsStr::new("HEAD"),
        STORE_HEAD_FILE_BYTES,
        root.snapshot.device,
        SyncPoint::StoreMetadata,
    )?;
    let config = open_required_regular_file(
        root,
        OsStr::new("config"),
        STORE_METADATA_FILE_BYTES,
        root.snapshot.device,
        SyncPoint::StoreMetadata,
    )?;
    let mut retained = Vec::with_capacity(2);
    for file in [&head, &config] {
        sync_regular_file(file, sync)?;
        retained.push(duplicate_regular_file(file, SyncPoint::FinalMetadata)?);
    }
    Ok(retained)
}

fn open_object_sync_plan(root: &DirectoryHandle) -> Result<ObjectSyncPlan, HomeArtifactStoreError> {
    let directories = open_object_directories(root)?;
    let ObjectDirectories {
        objects,
        fanout,
        pack,
        info,
    } = directories;
    let packs = census_pack_storage(root, pack)?;
    let info_files = census_object_info(root, info.as_ref())?;
    Ok(ObjectSyncPlan {
        objects,
        fanout,
        info,
        packs,
        info_files,
        loose_fanout_to_sync: BTreeSet::new(),
    })
}

fn sync_reachable_loose_objects(
    root: &DirectoryHandle,
    plan: &mut ObjectSyncPlan,
    objects: &BTreeSet<GitObjectId>,
    sync: &mut impl SyncOperations,
) -> Result<(), HomeArtifactStoreError> {
    let mut missing_loose = 0_usize;
    for object in objects {
        let hex = object_hex(*object);
        if hex.len() != 40 {
            return Err(HomeArtifactStoreError::Corrupt(
                "non-SHA1 object in archive reachability census",
            ));
        }
        let fanout_name = &hex[..2];
        let object_name = OsStr::from_bytes(&hex[2..]);
        let Some(expected_directory) = plan.fanout.get(fanout_name) else {
            missing_loose = missing_loose.saturating_add(1);
            continue;
        };
        let fanout_path = plan.objects.path.join(OsStr::from_bytes(fanout_name));
        let directory = open_child_directory(
            &plan.objects.file,
            OsStr::from_bytes(fanout_name),
            &fanout_path,
            root.snapshot.device,
        )?;
        if !directory
            .snapshot
            .same_directory_identity(*expected_directory)
        {
            return Err(changed_path(&fanout_path));
        }
        let Some(file) = open_optional_regular_file(
            &directory,
            object_name,
            super::MAX_HOME_ARTIFACT_TOTAL_BYTES
                .saturating_add(super::MAX_HOME_ARTIFACT_MANIFEST_BYTES as u64),
            root.snapshot.device,
            SyncPoint::LooseObject,
        )?
        else {
            missing_loose = missing_loose.saturating_add(1);
            continue;
        };
        sync_regular_file(&file, sync)?;
        plan.loose_fanout_to_sync.insert(fanout_name.to_vec());
    }
    if missing_loose > 0 && plan.packs.files.is_empty() {
        return Err(HomeArtifactStoreError::Corrupt(
            "reachable Git object has no loose or packed backing",
        ));
    }
    Ok(())
}

fn sync_pack_and_info_files(
    root: &DirectoryHandle,
    plan: &ObjectSyncPlan,
    retained_metadata: &mut Vec<RegularFile>,
    sync: &mut impl SyncOperations,
) -> Result<(), HomeArtifactStoreError> {
    for (name, expected_snapshot) in &plan.packs.files {
        let pack = plan
            .packs
            .pack
            .as_ref()
            .ok_or(HomeArtifactStoreError::Corrupt(
                "pack metadata exists without its directory",
            ))?;
        let file = open_required_regular_file(
            pack,
            name,
            MAX_PACKED_STORAGE_BYTES,
            root.snapshot.device,
            SyncPoint::PackedMetadata,
        )?;
        if file.snapshot != *expected_snapshot {
            return Err(changed_path(&file.path));
        }
        sync_regular_file(&file, sync)?;
    }
    for file in &plan.info_files {
        sync_regular_file(file, sync)?;
        retained_metadata.push(duplicate_regular_file(file, SyncPoint::FinalMetadata)?);
    }
    Ok(())
}

fn sync_archive_ref(
    root: &DirectoryHandle,
    artifact_id: forge_domain::HomeArtifactId,
    archive: &HomeArtifactArchive,
    retained_metadata: &mut Vec<RegularFile>,
    sync: &mut impl SyncOperations,
) -> Result<RefSyncPlan, HomeArtifactStoreError> {
    let ref_name = super::home_artifact_ref_name(artifact_id);
    if !ref_name.starts_with(HOME_ARTIFACT_REF_PREFIX) {
        return Err(HomeArtifactStoreError::Corrupt(
            "Home artifact ref escaped its owned namespace",
        ));
    }
    let (loose_ref, directories) = open_loose_ref(root, &ref_name)?;
    let packed_refs = open_optional_regular_file(
        root,
        OsStr::new("packed-refs"),
        MAX_HOME_ARTIFACT_PACKED_REFS_BYTES,
        root.snapshot.device,
        SyncPoint::PackedRefs,
    )?;
    let (retained_ref, point) = match (loose_ref, packed_refs) {
        (Some(file), packed) => {
            verify_loose_ref(&file, archive)?;
            if let Some(packed) = packed.as_ref() {
                sync_regular_file(packed, sync)?;
                retained_metadata.push(duplicate_regular_file(packed, SyncPoint::FinalMetadata)?);
            }
            (file, SyncPoint::LooseRef)
        }
        (None, Some(file)) => {
            verify_packed_ref(&file, &ref_name, archive)?;
            (file, SyncPoint::PackedRefs)
        }
        (None, None) => {
            return Err(HomeArtifactStoreError::Corrupt(
                "exact archive ref has no loose or packed storage",
            ));
        }
    };
    let retained_ref = RegularFile {
        point,
        ..retained_ref
    };
    sync_regular_file(&retained_ref, sync)?;
    Ok(RefSyncPlan {
        directories,
        retained_ref,
    })
}

fn sync_archive_directories(
    objects: &mut ObjectSyncPlan,
    reference: &mut RefSyncPlan,
    workspace: &WorkspaceDirectoryChain,
    sync: &mut impl SyncOperations,
) -> Result<(), HomeArtifactStoreError> {
    for name in &objects.loose_fanout_to_sync {
        let expected =
            objects
                .fanout
                .get(name.as_slice())
                .ok_or(HomeArtifactStoreError::Corrupt(
                    "loose object fanout directory disappeared",
                ))?;
        let fanout_name = OsStr::from_bytes(name);
        let path = objects.objects.path.join(fanout_name);
        let directory = open_child_directory(
            &objects.objects.file,
            fanout_name,
            &path,
            workspace.store.snapshot.device,
        )?;
        if !directory.snapshot.same_directory_identity(*expected) {
            return Err(changed_path(&path));
        }
        sync_directory(&directory, sync)?;
    }
    if let Some(pack) = objects.packs.pack.as_ref()
        && !objects.packs.files.is_empty()
    {
        sync_directory(pack, sync)?;
    }
    if let Some(info) = objects.info.as_ref()
        && !objects.info_files.is_empty()
    {
        sync_directory(info, sync)?;
    }
    sync_directory(&objects.objects, sync)?;
    for directory in reference.directories.iter_mut().rev() {
        sync_directory(directory, sync)?;
    }
    workspace.sync_bottom_up(sync)
}

fn sync_final_metadata(
    root: &DirectoryHandle,
    objects: &ObjectSyncPlan,
    retained_metadata: &mut [RegularFile],
    reference: &mut RefSyncPlan,
    sync: &mut impl SyncOperations,
) -> Result<(), HomeArtifactStoreError> {
    for file in retained_metadata {
        file.point = SyncPoint::FinalMetadata;
        sync_regular_file(file, sync)?;
    }
    for (name, expected_snapshot) in &objects.packs.files {
        let pack = objects
            .packs
            .pack
            .as_ref()
            .ok_or(HomeArtifactStoreError::Corrupt(
                "packed metadata directory disappeared",
            ))?;
        let file = open_required_regular_file(
            pack,
            name,
            MAX_PACKED_STORAGE_BYTES,
            root.snapshot.device,
            SyncPoint::FinalMetadata,
        )?;
        if file.snapshot != *expected_snapshot {
            return Err(changed_path(&file.path));
        }
        sync_regular_file(&file, sync)?;
    }
    reference.retained_ref.point = SyncPoint::FinalMetadata;
    sync_regular_file(&reference.retained_ref, sync)
}

fn open_store_root(store: &GitCheckpointStore) -> Result<DirectoryHandle, HomeArtifactStoreError> {
    store
        .confined
        .ensure_for_git(false)
        .map_err(HomeArtifactStoreError::Confined)?;
    if directory_identity_by_path(&store.store).map_err(HomeArtifactStoreError::Confined)?
        != store.store_identity
    {
        return Err(
            GitSafetyError::Confined(crate::ConfinedFilesystemError::CommittedPathChanged).into(),
        );
    }
    let descriptor = open(
        &store.store,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| errno_error("open captured Git store root", &store.store, source))?;
    if directory_identity(&descriptor).map_err(HomeArtifactStoreError::Confined)?
        != store.store_identity
    {
        return Err(
            GitSafetyError::Confined(crate::ConfinedFilesystemError::CommittedPathChanged).into(),
        );
    }
    let file = File::from(descriptor);
    let snapshot = MetadataSnapshot::from_file(&file, &store.store)?;
    require_directory(&snapshot, None, &store.store)?;
    verify_directory_identity_path(&store.store, store.store_identity)?;
    Ok(DirectoryHandle {
        file,
        path: store.store.clone(),
        snapshot,
        parent: None,
        name: None,
    })
}

fn open_parent_directory(
    child: &DirectoryHandle,
    child_name: &OsStr,
    expected_parent_path: &Path,
) -> Result<DirectoryHandle, HomeArtifactStoreError> {
    let descriptor = openat(
        &child.file,
        OsStr::new(".."),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| errno_error("open Git state ancestor", expected_parent_path, source))?;
    let parent_identity =
        directory_identity(&descriptor).map_err(HomeArtifactStoreError::Confined)?;
    let file = File::from(descriptor);
    let snapshot = MetadataSnapshot::from_file(&file, expected_parent_path)?;
    require_directory(&snapshot, None, expected_parent_path)?;
    let path_identity = directory_identity_by_path(expected_parent_path)
        .map_err(HomeArtifactStoreError::Confined)?;
    if parent_identity != path_identity {
        return Err(changed_path(expected_parent_path));
    }
    let child_from_parent =
        open_child_directory(&file, child_name, &child.path, child.snapshot.device)?;
    if !child_from_parent
        .snapshot
        .same_directory_identity(child.snapshot)
    {
        return Err(changed_path(&child.path));
    }
    let parent = DirectoryHandle {
        file,
        path: expected_parent_path.to_path_buf(),
        snapshot,
        parent: None,
        name: None,
    };
    Ok(parent)
}

fn bind_parent(
    child: &mut DirectoryHandle,
    parent: &DirectoryHandle,
    name: &OsStr,
) -> Result<(), HomeArtifactStoreError> {
    let opened = open_child_directory(&parent.file, name, &child.path, child.snapshot.device)?;
    if !opened.snapshot.same_directory_identity(child.snapshot) {
        return Err(changed_path(&child.path));
    }
    child.parent = Some(parent.file.try_clone().map_err(|source| {
        filesystem_error("duplicate Git directory descriptor", &child.path, source)
    })?);
    child.name = Some(name.to_os_string());
    Ok(())
}

fn open_child_directory(
    parent: &File,
    name: &OsStr,
    path: &Path,
    expected_device: u64,
) -> Result<DirectoryHandle, HomeArtifactStoreError> {
    let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| errno_error("inspect Git directory entry", path, source))?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    if kind.is_symlink() {
        return Err(GitSafetyError::SymlinkPath {
            path: path.to_path_buf(),
        }
        .into());
    }
    if !kind.is_dir() {
        return Err(GitSafetyError::InvalidCheckpointRoot {
            path: path.to_path_buf(),
        }
        .into());
    }
    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| errno_error("open Git directory entry", path, source))?;
    let _identity = directory_identity(&descriptor).map_err(HomeArtifactStoreError::Confined)?;
    let file = File::from(descriptor);
    let snapshot = MetadataSnapshot::from_file(&file, path)?;
    require_directory(&snapshot, Some(expected_device), path)?;
    if !snapshot.matches_directory_stat(&stat) {
        return Err(changed_path(path));
    }
    let parent_copy = parent
        .try_clone()
        .map_err(|source| filesystem_error("duplicate Git directory parent", path, source))?;
    Ok(DirectoryHandle {
        file,
        path: path.to_path_buf(),
        snapshot,
        parent: Some(parent_copy),
        name: Some(name.to_os_string()),
    })
}

fn verify_directory_snapshot(directory: &DirectoryHandle) -> Result<(), HomeArtifactStoreError> {
    if !MetadataSnapshot::from_file(&directory.file, &directory.path)?
        .same_directory_identity(directory.snapshot)
    {
        return Err(changed_path(&directory.path));
    }
    if let (Some(parent), Some(name)) = (&directory.parent, &directory.name) {
        let current = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            errno_error("verify Git directory binding", &directory.path, source)
        })?;
        if !directory.snapshot.matches_directory_stat(&current) {
            return Err(changed_path(&directory.path));
        }
    } else if !snapshot_at_path(&directory.path)?.same_directory_identity(directory.snapshot) {
        return Err(changed_path(&directory.path));
    }
    Ok(())
}

fn sync_directory(
    directory: &DirectoryHandle,
    sync: &mut impl SyncOperations,
) -> Result<(), HomeArtifactStoreError> {
    verify_directory_snapshot(directory)?;
    sync.sync_directory(&directory.file, SyncPoint::Directory)
        .map_err(|source| errno_error("sync Git directory", &directory.path, source))?;
    verify_directory_snapshot(directory)
}

fn open_object_directories(
    store: &DirectoryHandle,
) -> Result<ObjectDirectories, HomeArtifactStoreError> {
    let objects_path = store.path.join("objects");
    let objects = open_child_directory(
        &store.file,
        OsStr::new("objects"),
        &objects_path,
        store.snapshot.device,
    )?;
    let names = directory_names(&objects, MAX_OBJECT_ROOT_ENTRIES, "object root")?;
    let mut fanout = std::collections::BTreeMap::new();
    let mut pack = None;
    let mut info = None;
    for name in names {
        let bytes = name.as_bytes();
        let path = objects.path.join(&name);
        if bytes == b"pack" {
            pack = Some(open_child_directory(
                &objects.file,
                &name,
                &path,
                store.snapshot.device,
            )?);
        } else if bytes == b"info" {
            info = Some(open_child_directory(
                &objects.file,
                &name,
                &path,
                store.snapshot.device,
            )?);
        } else if bytes.len() == 2 && bytes.iter().all(u8::is_ascii_hexdigit) {
            if bytes.iter().any(u8::is_ascii_uppercase) {
                return Err(HomeArtifactStoreError::Corrupt(
                    "uppercase loose-object fanout directory",
                ));
            }
            let directory =
                open_child_directory(&objects.file, &name, &path, store.snapshot.device)?;
            if fanout.insert(bytes.to_vec(), directory.snapshot).is_some() {
                return Err(HomeArtifactStoreError::Corrupt(
                    "duplicate loose-object fanout directory",
                ));
            }
        } else {
            return Err(HomeArtifactStoreError::Corrupt(
                "unknown Git object storage entry",
            ));
        }
    }
    Ok(ObjectDirectories {
        objects,
        fanout,
        pack,
        info,
    })
}

fn census_pack_storage(
    store: &DirectoryHandle,
    pack: Option<DirectoryHandle>,
) -> Result<PackCensus, HomeArtifactStoreError> {
    let Some(pack) = pack else {
        return Ok(PackCensus {
            pack: None,
            files: Vec::new(),
        });
    };
    let names = directory_names(&pack, MAX_PACK_DIRECTORY_ENTRIES, "packed object storage")?;
    let mut pack_bases = HashSet::new();
    let mut index_bases = HashSet::new();
    let mut auxiliary_bases = HashSet::new();
    let mut has_multi_pack_index = false;
    let mut files = Vec::with_capacity(names.len());
    let mut bytes = 0_u64;
    for name in names {
        let name_bytes = name.as_bytes();
        let category = classify_pack_file(name_bytes).ok_or(HomeArtifactStoreError::Corrupt(
            "unknown packed Git object metadata",
        ))?;
        let file = open_required_regular_file(
            &pack,
            &name,
            MAX_PACKED_STORAGE_BYTES,
            store.snapshot.device,
            SyncPoint::PackedMetadata,
        )?;
        bytes = bytes
            .checked_add(file.snapshot.size)
            .filter(|total| *total <= MAX_PACKED_STORAGE_BYTES)
            .ok_or(HomeArtifactStoreError::Bounds("packed storage bytes"))?;
        match category {
            PackFileKind::Pack(base) => {
                pack_bases.insert(base.to_vec());
            }
            PackFileKind::Index(base) => {
                index_bases.insert(base.to_vec());
            }
            PackFileKind::Auxiliary(base) => {
                auxiliary_bases.insert(base.to_vec());
            }
            PackFileKind::MultiPackIndex => has_multi_pack_index = true,
            PackFileKind::MultiPackBitmap => {
                if !name_bytes.starts_with(b"multi-pack-index-") {
                    return Err(HomeArtifactStoreError::Corrupt(
                        "invalid multi-pack-index bitmap name",
                    ));
                }
                has_multi_pack_index = true;
            }
        }
        files.push((name, file.snapshot));
    }
    if pack_bases != index_bases
        || auxiliary_bases
            .iter()
            .any(|base| !pack_bases.contains(base))
    {
        return Err(HomeArtifactStoreError::Corrupt(
            "packed Git objects have incomplete pack/index metadata",
        ));
    }
    if has_multi_pack_index
        && !files
            .iter()
            .any(|(name, _)| name.as_bytes() == b"multi-pack-index")
    {
        return Err(HomeArtifactStoreError::Corrupt(
            "multi-pack-index bitmap has no index",
        ));
    }
    Ok(PackCensus {
        pack: Some(pack),
        files,
    })
}

enum PackFileKind<'a> {
    Pack(&'a [u8]),
    Index(&'a [u8]),
    Auxiliary(&'a [u8]),
    MultiPackIndex,
    MultiPackBitmap,
}

fn classify_pack_file(name: &[u8]) -> Option<PackFileKind<'_>> {
    if name == b"multi-pack-index" {
        return Some(PackFileKind::MultiPackIndex);
    }
    if let Some(hash) = name
        .strip_prefix(b"multi-pack-index-")
        .and_then(|value| value.strip_suffix(b".bitmap"))
        && is_sha1_hex(hash)
    {
        return Some(PackFileKind::MultiPackBitmap);
    }
    let value = name.strip_prefix(b"pack-")?;
    let separator = value.iter().position(|byte| *byte == b'.')?;
    let (hash, extension_with_dot) = value.split_at(separator);
    if !is_sha1_hex(hash) {
        return None;
    }
    match extension_with_dot {
        b".pack" => Some(PackFileKind::Pack(hash)),
        b".idx" => Some(PackFileKind::Index(hash)),
        b".bitmap" | b".rev" => Some(PackFileKind::Auxiliary(hash)),
        _ => None,
    }
}

fn is_sha1_hex(value: &[u8]) -> bool {
    value.len() == 40
        && value.iter().all(u8::is_ascii_hexdigit)
        && !value.iter().any(u8::is_ascii_uppercase)
}

fn census_object_info(
    store: &DirectoryHandle,
    info: Option<&DirectoryHandle>,
) -> Result<Vec<RegularFile>, HomeArtifactStoreError> {
    let Some(info) = info else {
        return Ok(Vec::new());
    };
    let names = directory_names(info, MAX_OBJECT_INFO_ENTRIES, "object info")?;
    let mut files = Vec::with_capacity(names.len());
    for name in names {
        match name.as_bytes() {
            b"alternates" => {
                return Err(HomeArtifactStoreError::Corrupt(
                    "external Git object alternates are unsupported",
                ));
            }
            b"commit-graph" | b"packs" => {
                files.push(open_required_regular_file(
                    info,
                    &name,
                    OBJECT_INFO_FILE_BYTES,
                    store.snapshot.device,
                    SyncPoint::PackedMetadata,
                )?);
            }
            _ => {
                return Err(HomeArtifactStoreError::Corrupt(
                    "unknown Git object info storage",
                ));
            }
        }
    }
    Ok(files)
}

fn directory_names(
    directory: &DirectoryHandle,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<OsString>, HomeArtifactStoreError> {
    let stream = Dir::read_from(&directory.file)
        .map_err(|source| errno_error("open Git directory inventory", &directory.path, source))?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|source| {
            errno_error("read Git directory inventory", &directory.path, source)
        })?;
        let name = entry.file_name();
        let name_bytes = name.to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        if names.len() >= maximum {
            return Err(HomeArtifactStoreError::Bounds(label));
        }
        names.push(OsString::from_vec(name_bytes.to_vec()));
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

fn open_loose_ref(
    store: &DirectoryHandle,
    name: &str,
) -> Result<(Option<RegularFile>, Vec<DirectoryHandle>), HomeArtifactStoreError> {
    let components = name.split('/').collect::<Vec<_>>();
    if components.len() != 4
        || components[0] != "refs"
        || components[1] != "heterarchy-forge"
        || components[2] != "home-artifacts"
    {
        return Err(HomeArtifactStoreError::Corrupt(
            "Home artifact ref path has an unexpected shape",
        ));
    }
    let mut directories = Vec::new();
    for component in &components[..3] {
        let parent = directories.last().unwrap_or(store);
        let path = parent.path.join(component);
        match open_optional_child_directory(
            parent,
            OsStr::new(component),
            &path,
            store.snapshot.device,
        )? {
            Some(directory) => {
                directories.push(directory);
            }
            None => return Ok((None, directories)),
        }
    }
    let directory = directories.last().ok_or(HomeArtifactStoreError::Corrupt(
        "Home artifact ref parent directory was not opened",
    ))?;
    let file = open_optional_regular_file(
        directory,
        OsStr::new(components[3]),
        STORE_HEAD_FILE_BYTES,
        store.snapshot.device,
        SyncPoint::LooseRef,
    )?;
    Ok((file, directories))
}

fn open_optional_child_directory(
    parent: &DirectoryHandle,
    name: &OsStr,
    path: &Path,
    device: u64,
) -> Result<Option<DirectoryHandle>, HomeArtifactStoreError> {
    match statat(&parent.file, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_symlink() => {
            Err(GitSafetyError::SymlinkPath {
                path: path.to_path_buf(),
            }
            .into())
        }
        Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_dir() => Ok(Some(
            open_child_directory(&parent.file, name, path, device)?,
        )),
        Ok(_) => Err(GitSafetyError::InvalidCheckpointRoot {
            path: path.to_path_buf(),
        }
        .into()),
        Err(Errno::NOENT) => Ok(None),
        Err(source) => Err(errno_error(
            "inspect Home artifact ref directory",
            path,
            source,
        )),
    }
}

fn open_required_regular_file(
    parent: &DirectoryHandle,
    name: &OsStr,
    maximum_bytes: u64,
    device: u64,
    point: SyncPoint,
) -> Result<RegularFile, HomeArtifactStoreError> {
    open_optional_regular_file(parent, name, maximum_bytes, device, point)?.ok_or(
        HomeArtifactStoreError::Corrupt("required Git durability file is missing"),
    )
}

fn open_optional_regular_file(
    parent: &DirectoryHandle,
    name: &OsStr,
    maximum_bytes: u64,
    device: u64,
    point: SyncPoint,
) -> Result<Option<RegularFile>, HomeArtifactStoreError> {
    let path = parent.path.join(name);
    let stat = match statat(&parent.file, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(None),
        Err(source) => return Err(errno_error("inspect Git regular file", &path, source)),
    };
    let kind = FileType::from_raw_mode(stat.st_mode);
    if kind.is_symlink() {
        return Err(GitSafetyError::SymlinkPath { path }.into());
    }
    if !kind.is_file() {
        return Err(GitSafetyError::NonRegularFile { path }.into());
    }
    let descriptor = openat(
        &parent.file,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| errno_error("open Git regular file", &path, source))?;
    let file = File::from(descriptor);
    let snapshot = MetadataSnapshot::from_file(&file, &path)?;
    require_regular_file(&snapshot, device, maximum_bytes, &path)?;
    if !snapshot.matches_stat(&stat) {
        return Err(changed_path(&path));
    }
    let parent_copy = parent
        .file
        .try_clone()
        .map_err(|source| filesystem_error("duplicate Git file parent", &path, source))?;
    Ok(Some(RegularFile {
        file,
        parent: parent_copy,
        name: name.to_os_string(),
        path,
        snapshot,
        point,
    }))
}

fn require_directory(
    snapshot: &MetadataSnapshot,
    expected_device: Option<u64>,
    path: &Path,
) -> Result<(), HomeArtifactStoreError> {
    if !snapshot.is_directory {
        return Err(GitSafetyError::InvalidCheckpointRoot {
            path: path.to_path_buf(),
        }
        .into());
    }
    if expected_device.is_some_and(|device| snapshot.device != device) {
        return Err(changed_path(path));
    }
    Ok(())
}

fn require_regular_file(
    snapshot: &MetadataSnapshot,
    expected_device: u64,
    maximum_bytes: u64,
    path: &Path,
) -> Result<(), HomeArtifactStoreError> {
    if !snapshot.is_regular {
        return Err(GitSafetyError::NonRegularFile {
            path: path.to_path_buf(),
        }
        .into());
    }
    if snapshot.links != 1 {
        return Err(HomeArtifactStoreError::Corrupt(
            "Git durability file has multiple hard links",
        ));
    }
    if snapshot.device != expected_device {
        return Err(changed_path(path));
    }
    if snapshot.size > maximum_bytes {
        return Err(HomeArtifactStoreError::Bounds("Git durability file size"));
    }
    Ok(())
}

fn sync_regular_file(
    file: &RegularFile,
    sync: &mut impl SyncOperations,
) -> Result<(), HomeArtifactStoreError> {
    verify_regular_file(file)?;
    sync.sync_file(&file.file, file.point)
        .map_err(|source| errno_error("sync Git regular file", &file.path, source))?;
    verify_regular_file(file)
}

fn verify_regular_file(file: &RegularFile) -> Result<(), HomeArtifactStoreError> {
    if MetadataSnapshot::from_file(&file.file, &file.path)? != file.snapshot {
        return Err(changed_path(&file.path));
    }
    let current = statat(&file.parent, &file.name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| errno_error("verify Git file binding", &file.path, source))?;
    if !file.snapshot.matches_stat(&current)
        || FileType::from_raw_mode(current.st_mode).is_symlink()
    {
        return Err(changed_path(&file.path));
    }
    Ok(())
}

fn duplicate_regular_file(
    file: &RegularFile,
    point: SyncPoint,
) -> Result<RegularFile, HomeArtifactStoreError> {
    Ok(RegularFile {
        file: file.file.try_clone().map_err(|source| {
            filesystem_error("duplicate Git metadata file", &file.path, source)
        })?,
        parent: file.parent.try_clone().map_err(|source| {
            filesystem_error("duplicate Git metadata parent", &file.path, source)
        })?,
        name: file.name.clone(),
        path: file.path.clone(),
        snapshot: file.snapshot,
        point,
    })
}

fn verify_loose_ref(
    file: &RegularFile,
    archive: &HomeArtifactArchive,
) -> Result<(), HomeArtifactStoreError> {
    let bytes = read_bounded(file, STORE_HEAD_FILE_BYTES)?;
    let mut expected = object_hex(archive.commit_id().object_id());
    expected.push(b'\n');
    if bytes != expected {
        return Err(GitSafetyError::TamperedRef {
            name: file.path.to_string_lossy().into_owned(),
        }
        .into());
    }
    Ok(())
}

fn verify_packed_ref(
    file: &RegularFile,
    ref_name: &str,
    archive: &HomeArtifactArchive,
) -> Result<(), HomeArtifactStoreError> {
    let bytes = read_bounded(file, MAX_HOME_ARTIFACT_PACKED_REFS_BYTES)?;
    let name = ref_name.as_bytes();
    let expected = object_hex(archive.commit_id().object_id());
    let mut matches = 0_usize;
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty()
            || line
                .first()
                .is_some_and(|byte| matches!(*byte, b'#' | b'^'))
        {
            continue;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b' ') else {
            return Err(HomeArtifactStoreError::Corrupt(
                "packed refs contains a malformed record",
            ));
        };
        if &line[separator + 1..] == name {
            matches = matches.saturating_add(1);
            if &line[..separator] != expected.as_slice() {
                return Err(GitSafetyError::TamperedRef {
                    name: ref_name.to_owned(),
                }
                .into());
            }
        }
    }
    if matches != 1 {
        return Err(HomeArtifactStoreError::Corrupt(
            "packed refs does not contain exactly one archive ref",
        ));
    }
    Ok(())
}

fn verify_directory_identity_path(
    path: &Path,
    expected: crate::confinement::DirectoryIdentity,
) -> Result<(), HomeArtifactStoreError> {
    if directory_identity_by_path(path).map_err(HomeArtifactStoreError::Confined)? != expected {
        return Err(changed_path(path));
    }
    Ok(())
}

fn snapshot_at_path(path: &Path) -> Result<MetadataSnapshot, HomeArtifactStoreError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|source| filesystem_error("inspect durability path", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GitSafetyError::InvalidCheckpointRoot {
            path: path.to_path_buf(),
        }
        .into());
    }
    Ok(MetadataSnapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        is_directory: metadata.is_dir(),
        is_regular: metadata.is_file(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn read_bounded(file: &RegularFile, maximum_bytes: u64) -> Result<Vec<u8>, HomeArtifactStoreError> {
    let reader = file
        .file
        .try_clone()
        .map_err(|source| filesystem_error("duplicate bounded Git file", &file.path, source))?;
    let mut bytes = Vec::new();
    reader
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| filesystem_error("read bounded Git file", &file.path, source))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(HomeArtifactStoreError::Bounds("Git durability file read"));
    }
    Ok(bytes)
}

fn changed_path(path: &Path) -> HomeArtifactStoreError {
    GitSafetyError::FileChanged {
        path: path.to_path_buf(),
    }
    .into()
}

fn filesystem_error(operation: &str, path: &Path, source: io::Error) -> HomeArtifactStoreError {
    GitSafetyError::Filesystem {
        operation: operation.to_owned(),
        path: path.to_path_buf(),
        source,
    }
    .into()
}

fn errno_error(operation: &str, path: &Path, source: Errno) -> HomeArtifactStoreError {
    filesystem_error(
        operation,
        path,
        io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    use forge_domain::{
        AgentAssignmentId, AgentAssignmentRevision, HomeArtifactCaptureIntent, HomeArtifactId,
        TimestampMillis, WorkspaceId, WorkspaceRelativePath,
    };

    use super::{HomeArtifactStore, SyncOperations, SyncPoint};
    use crate::confinement::sync_file as sync_file_descriptor;
    use crate::git_safety::{GitCheckpointStore, WorkspaceStateLayout};
    use rustix::fs::fsync;
    use rustix::io::Errno;

    struct TestRepo {
        root: PathBuf,
    }

    impl TestRepo {
        fn create(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let root = std::env::temp_dir().join(format!(
                "forge-home-artifact-durability-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            run_git(&root, &["init", "--initial-branch=main"])?;
            run_git(&root, &["config", "user.name", "Forge Durability Tests"])?;
            run_git(
                &root,
                &["config", "user.email", "forge-home-durability@localhost"],
            )?;
            fs::write(root.join("seed.txt"), b"seed\n")?;
            run_git(&root, &["add", "seed.txt"])?;
            run_git(&root, &["commit", "-m", "initial"])?;
            let _layout = WorkspaceStateLayout::initialize(&root)?;
            Ok(Self { root })
        }

        fn store(&self) -> Result<GitCheckpointStore, Box<dyn std::error::Error>> {
            let layout = WorkspaceStateLayout::inspect_existing(&self.root)?
                .ok_or("Workspace state layout was not created")?;
            Ok(GitCheckpointStore::new(&self.root, layout.checkpoints())?)
        }
    }

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn run_git(root: &Path, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(crate::git_safety::FORGE_GIT_PROGRAM)
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

    fn intent() -> Result<HomeArtifactCaptureIntent, Box<dyn std::error::Error>> {
        Ok(HomeArtifactCaptureIntent::new(
            HomeArtifactId::new(Uuid::from_u128(0xD0A1))?,
            Uuid::from_u128(0xD0A2),
            Uuid::from_u128(0xD0A3),
            WorkspaceId::from_uuid(Uuid::from_u128(0xD0A4)),
            AgentAssignmentId::from_uuid(Uuid::from_u128(0xD0A5)),
            AgentAssignmentRevision::new(1)?,
            AgentAssignmentId::from_uuid(Uuid::from_u128(0xD0A6)),
            vec![WorkspaceRelativePath::new(PathBuf::from("member.md"))?],
        )?)
    }

    struct FailAt {
        point: Option<SyncPoint>,
        observed: Vec<SyncPoint>,
    }

    impl SyncOperations for FailAt {
        fn sync_file(&mut self, file: &std::fs::File, point: SyncPoint) -> Result<(), Errno> {
            self.observed.push(point);
            if Some(point) == self.point {
                return Err(Errno::IO);
            }
            sync_file_descriptor(file)
        }

        fn sync_directory(
            &mut self,
            directory: &std::fs::File,
            point: SyncPoint,
        ) -> Result<(), Errno> {
            self.observed.push(point);
            if Some(point) == self.point {
                return Err(Errno::IO);
            }
            fsync(directory)
        }
    }

    struct ReplaceStoreRoot {
        store: PathBuf,
        saved: PathBuf,
        replaced: bool,
    }

    struct InsertUnrelatedEntries<'a> {
        store: &'a GitCheckpointStore,
        ref_name: String,
        commit_hex: Vec<u8>,
        inserted: bool,
    }

    impl SyncOperations for InsertUnrelatedEntries<'_> {
        fn sync_file(&mut self, file: &std::fs::File, _point: SyncPoint) -> Result<(), Errno> {
            sync_file_descriptor(file)
        }

        fn sync_directory(
            &mut self,
            directory: &std::fs::File,
            _point: SyncPoint,
        ) -> Result<(), Errno> {
            if !self.inserted {
                let _unrelated_blob = self
                    .store
                    .write_blob(b"unrelated object inserted during directory sync")
                    .map_err(|_| Errno::IO)?;
                let update = self
                    .store
                    .run_git(
                        "insert unrelated test Home artifact ref during sync",
                        &[
                            super::arg("update-ref"),
                            OsString::from(self.ref_name.as_str()),
                            super::arg_bytes(&self.commit_hex),
                        ],
                        None,
                        &[],
                    )
                    .map_err(|_| Errno::IO)?;
                if !update.status.success() {
                    return Err(Errno::IO);
                }
                self.inserted = true;
            }
            fsync(directory)
        }
    }

    impl SyncOperations for ReplaceStoreRoot {
        fn sync_file(&mut self, file: &std::fs::File, point: SyncPoint) -> Result<(), Errno> {
            sync_file_descriptor(file)?;
            if point == SyncPoint::StoreMetadata && !self.replaced {
                fs::rename(&self.store, &self.saved).map_err(|_| Errno::IO)?;
                symlink(&self.saved, &self.store).map_err(|_| Errno::IO)?;
                self.replaced = true;
            }
            Ok(())
        }

        fn sync_directory(
            &mut self,
            directory: &std::fs::File,
            _point: SyncPoint,
        ) -> Result<(), Errno> {
            fsync(directory)
        }
    }

    #[test]
    fn injected_file_and_directory_sync_failures_preserve_the_exact_archive_ref()
    -> Result<(), Box<dyn std::error::Error>> {
        for (label, point) in [
            ("file", SyncPoint::LooseObject),
            ("directory", SyncPoint::Directory),
        ] {
            let repo = TestRepo::create(label)?;
            let store = repo.store()?;
            let intent = intent()?;
            fs::write(repo.root.join("member.md"), b"source bytes")?;
            let artifacts = HomeArtifactStore::new(&store);
            let archive = artifacts.publish(&intent, TimestampMillis::new(10)?)?;
            let mut sync = FailAt {
                point: Some(point),
                observed: Vec::new(),
            };

            assert!(artifacts.harden_archive_with(&archive, &mut sync).is_err());
            assert!(sync.observed.contains(&point));
            let directory_stage = sync
                .observed
                .iter()
                .position(|observed| *observed == SyncPoint::Directory);
            if point == SyncPoint::Directory {
                let directory_stage =
                    directory_stage.ok_or("directory sync stage was not reached")?;
                let prior = &sync.observed[..directory_stage];
                assert!(prior.contains(&SyncPoint::StoreMetadata));
                assert!(prior.contains(&SyncPoint::LooseObject));
                assert!(prior.contains(&SyncPoint::LooseRef));
            }
            assert_eq!(artifacts.read(&intent)?, Some(archive.clone()));
            assert!(
                artifacts
                    .read_member(
                        &intent,
                        &WorkspaceRelativePath::new(PathBuf::from("member.md"))?
                    )?
                    .is_some()
            );
        }
        Ok(())
    }

    #[test]
    fn retained_files_are_flushed_again_after_directories() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = TestRepo::create("sync-order")?;
        let store = repo.store()?;
        let intent = intent()?;
        fs::write(repo.root.join("member.md"), b"source bytes")?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(12)?)?;
        let mut sync = FailAt {
            point: None,
            observed: Vec::new(),
        };

        artifacts.harden_archive_with(&archive, &mut sync)?;
        let first_directory = sync
            .observed
            .iter()
            .position(|point| *point == SyncPoint::Directory)
            .ok_or("directory sync stage was not reached")?;
        let final_metadata = sync
            .observed
            .iter()
            .rposition(|point| *point == SyncPoint::FinalMetadata)
            .ok_or("final metadata flush was not reached")?;
        assert!(final_metadata > first_directory);
        assert!(sync.observed[..first_directory].contains(&SyncPoint::LooseObject));
        assert!(sync.observed[..first_directory].contains(&SyncPoint::LooseRef));
        assert_eq!(sync.observed[final_metadata], SyncPoint::FinalMetadata);
        Ok(())
    }

    #[test]
    fn store_root_identity_drift_fails_closed_and_same_archive_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("identity-drift")?;
        let store = repo.store()?;
        let intent = intent()?;
        fs::write(repo.root.join("member.md"), b"source bytes")?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(11)?)?;
        let store_path = store.git_store_path().to_path_buf();
        let saved = store_path.with_file_name("store.git.durability-test-saved");
        let mut sync = ReplaceStoreRoot {
            store: store_path.clone(),
            saved: saved.clone(),
            replaced: false,
        };

        assert!(artifacts.harden_archive_with(&archive, &mut sync).is_err());
        assert!(sync.replaced);
        assert!(fs::symlink_metadata(&store_path)?.file_type().is_symlink());
        fs::remove_file(&store_path)?;
        fs::rename(&saved, &store_path)?;
        assert_eq!(artifacts.read(&intent)?, Some(archive.clone()));
        artifacts.harden_archive(&archive)?;
        Ok(())
    }

    #[test]
    fn unrelated_object_and_ref_insertions_do_not_invalidate_archive_hardening()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = TestRepo::create("unrelated-insertions")?;
        let store = repo.store()?;
        let intent = intent()?;
        fs::write(repo.root.join("member.md"), b"source bytes")?;
        let artifacts = HomeArtifactStore::new(&store);
        let archive = artifacts.publish(&intent, TimestampMillis::new(13)?)?;
        let ref_name = format!(
            "{}{}",
            super::HOME_ARTIFACT_REF_PREFIX,
            Uuid::from_u128(0xD0FF)
        );
        let mut sync = InsertUnrelatedEntries {
            store: &store,
            ref_name,
            commit_hex: super::object_hex(archive.commit_id().object_id()),
            inserted: false,
        };

        artifacts.harden_archive_with(&archive, &mut sync)?;
        assert!(sync.inserted);
        assert_eq!(artifacts.read(&intent)?, Some(archive));
        Ok(())
    }
}
