//! Descriptor-confined source-tree transaction preflight.
//!
//! This layer acquires one Workspace writer lock, validates the entire bounded
//! tree plan, and retains the lock until the caller either applies or abandons
//! the prepared transaction. It performs no source effect during preflight.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use forge_domain::{
    CompiledFilePatch, FileContentHash, FileMutationId, FileMutationKind, FileMutationPlan,
    FilePathState, FilePrecondition, TreeChangeSetIntent, TreeChangeSetPlan, TreeMutationId,
    TreeMutationPlan, WorkspaceRelativePath,
};
use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, fstat, fsync, mkdirat, openat,
    renameat_with, unlinkat,
};
use rustix::io::Errno;

use super::{
    ConfinedFilesystemError, ConfinedWorkspace, FilesystemOperation, MAX_FILE_WRITE_BYTES,
    MutationLock, collect_components, observe_leaf, read_leaf, validate_not_protected,
    walk_directories,
};

/// Maximum aggregate create/update payload retained for one tree transaction.
pub const MAX_SOURCE_TREE_PAYLOAD_BYTES: usize =
    MAX_FILE_WRITE_BYTES * forge_domain::MAX_TREE_CHANGESET_MUTATIONS;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTreeMutationPayload {
    mutation_id: TreeMutationId,
    content: SourceTreeContent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceTreeContent {
    WholeFile(Vec<u8>),
    CompiledPatch(CompiledFilePatch),
}

impl SourceTreeMutationPayload {
    pub fn new(
        mutation_id: TreeMutationId,
        content: Vec<u8>,
    ) -> Result<Self, ConfinedFilesystemError> {
        if content.len() > MAX_FILE_WRITE_BYTES {
            return Err(ConfinedFilesystemError::WriteTooLarge {
                actual: content.len(),
                maximum: MAX_FILE_WRITE_BYTES,
            });
        }
        Ok(Self {
            mutation_id,
            content: SourceTreeContent::WholeFile(content),
        })
    }

    /// Retain the validated source/result hashes and bounded patch output.
    pub fn from_compiled_patch(mutation_id: TreeMutationId, patch: CompiledFilePatch) -> Self {
        Self {
            mutation_id,
            content: SourceTreeContent::CompiledPatch(patch),
        }
    }

    pub const fn mutation_id(&self) -> TreeMutationId {
        self.mutation_id
    }

    pub fn content(&self) -> &[u8] {
        match &self.content {
            SourceTreeContent::WholeFile(content) => content,
            SourceTreeContent::CompiledPatch(patch) => patch.content(),
        }
    }

    fn matches_plan(&self, plan: &TreeMutationPlan) -> Result<bool, ConfinedFilesystemError> {
        match (plan, &self.content) {
            (
                TreeMutationPlan::CreateFile { intended_hash, .. }
                | TreeMutationPlan::UpdateFile { intended_hash, .. },
                SourceTreeContent::WholeFile(content),
            ) => Ok(super::bounded_write_content_hash(content)? == *intended_hash),
            (
                TreeMutationPlan::UpdateFile {
                    expected_hash,
                    intended_hash,
                    ..
                },
                SourceTreeContent::CompiledPatch(patch),
            ) => Ok(patch.source_hash() == *expected_hash && patch.result_hash() == *intended_hash),
            _ => Ok(false),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTreePayloadSet {
    entries: BTreeMap<TreeMutationId, SourceTreeMutationPayload>,
}

impl SourceTreePayloadSet {
    pub fn new(entries: Vec<SourceTreeMutationPayload>) -> Result<Self, ConfinedFilesystemError> {
        let total = entries.iter().try_fold(0_usize, |total, entry| {
            total
                .checked_add(entry.content().len())
                .ok_or(ConfinedFilesystemError::WriteTooLarge {
                    actual: usize::MAX,
                    maximum: MAX_SOURCE_TREE_PAYLOAD_BYTES,
                })
        })?;
        if total > MAX_SOURCE_TREE_PAYLOAD_BYTES {
            return Err(ConfinedFilesystemError::WriteTooLarge {
                actual: total,
                maximum: MAX_SOURCE_TREE_PAYLOAD_BYTES,
            });
        }
        let mut indexed = BTreeMap::new();
        for entry in entries {
            if indexed.insert(entry.mutation_id, entry).is_some() {
                return Err(ConfinedFilesystemError::InvalidPayload);
            }
        }
        Ok(Self { entries: indexed })
    }

    fn content(&self, mutation_id: TreeMutationId) -> Option<&[u8]> {
        self.entries
            .get(&mutation_id)
            .map(SourceTreeMutationPayload::content)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSourceTreeTransaction {
    applied_mutations: Vec<TreeMutationId>,
}

impl AppliedSourceTreeTransaction {
    pub fn applied_mutations(&self) -> &[TreeMutationId] {
        &self.applied_mutations
    }
}

/// Partial progress acknowledged by the journal before this failure.
/// The uncertain mutation may already have changed the filesystem or committed
/// its journal row; recovery/readback must resolve it before any retry.
#[derive(Debug)]
pub enum SourceTreeApplyError<JournalError> {
    Filesystem {
        applied_mutations: Vec<TreeMutationId>,
        uncertain_mutation: Option<TreeMutationId>,
        source: ConfinedFilesystemError,
    },
    Journal {
        applied_mutations: Vec<TreeMutationId>,
        uncertain_mutation: TreeMutationId,
        source: JournalError,
    },
}

impl<JournalError> SourceTreeApplyError<JournalError> {
    pub fn applied_mutations(&self) -> &[TreeMutationId] {
        match self {
            Self::Filesystem {
                applied_mutations, ..
            }
            | Self::Journal {
                applied_mutations, ..
            } => applied_mutations,
        }
    }

    pub const fn uncertain_mutation(&self) -> Option<TreeMutationId> {
        match self {
            Self::Filesystem {
                uncertain_mutation, ..
            } => *uncertain_mutation,
            Self::Journal {
                uncertain_mutation, ..
            } => Some(*uncertain_mutation),
        }
    }
}

/// Exact preflight observation retained for one tree mutation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeMutationObservation {
    CreateDirectory {
        path: WorkspaceRelativePath,
    },
    CreateFile {
        path: WorkspaceRelativePath,
    },
    UpdateFile {
        path: WorkspaceRelativePath,
        state: FilePathState,
    },
    DeleteFile {
        path: WorkspaceRelativePath,
        state: FilePathState,
    },
    MoveFile {
        source: WorkspaceRelativePath,
        source_state: FilePathState,
        destination: WorkspaceRelativePath,
    },
    MoveDirectory {
        source: WorkspaceRelativePath,
        destination: WorkspaceRelativePath,
    },
    DeleteDirectory {
        path: WorkspaceRelativePath,
    },
}

/// Validated source-tree plan retaining the single cross-process writer lock.
///
/// Dropping this value performs no effect and simply releases the lock.
#[derive(Debug)]
pub struct PreparedSourceTreeTransaction {
    plan: TreeChangeSetPlan,
    observations: Vec<TreeMutationObservation>,
    _mutation_lock: MutationLock,
}

impl PreparedSourceTreeTransaction {
    pub const fn plan(&self) -> &TreeChangeSetPlan {
        &self.plan
    }

    pub fn observations(&self) -> &[TreeMutationObservation] {
        &self.observations
    }
}

impl PreparedSourceTreeTransaction {
    pub fn apply_with_journal<JournalError, Journal>(
        self,
        workspace: &ConfinedWorkspace,
        intent: &TreeChangeSetIntent,
        payloads: &SourceTreePayloadSet,
        mut on_applied: Journal,
    ) -> Result<AppliedSourceTreeTransaction, SourceTreeApplyError<JournalError>>
    where
        Journal: FnMut(TreeMutationId) -> Result<(), JournalError>,
    {
        if let Err(source) = self.validate_apply_inputs(intent, payloads) {
            return Err(SourceTreeApplyError::Filesystem {
                applied_mutations: Vec::new(),
                uncertain_mutation: None,
                source,
            });
        }
        let mut applied_mutations = Vec::with_capacity(intent.mutations().len());
        for mutation in intent.mutations() {
            if let Err(source) = workspace.apply_tree_mutation_under_held_lock(mutation, payloads) {
                let uncertain_mutation =
                    source.effect_may_have_committed().then_some(mutation.id());
                return Err(SourceTreeApplyError::Filesystem {
                    applied_mutations,
                    uncertain_mutation,
                    source,
                });
            }
            if let Err(source) = on_applied(mutation.id()) {
                return Err(SourceTreeApplyError::Journal {
                    applied_mutations,
                    uncertain_mutation: mutation.id(),
                    source,
                });
            }
            // Only an acknowledged journal write joins the confirmed prefix.
            applied_mutations.push(mutation.id());
        }
        Ok(AppliedSourceTreeTransaction { applied_mutations })
    }

    fn validate_apply_inputs(
        &self,
        intent: &TreeChangeSetIntent,
        payloads: &SourceTreePayloadSet,
    ) -> Result<(), ConfinedFilesystemError> {
        if intent.mutations().len() != self.plan.mutations().len() {
            return Err(ConfinedFilesystemError::InvalidPayload);
        }
        let mut required_payloads = 0_usize;
        for (intent_mutation, planned) in intent.mutations().iter().zip(self.plan.mutations()) {
            if intent_mutation.plan() != planned {
                return Err(ConfinedFilesystemError::InvalidPayload);
            }
            match planned {
                TreeMutationPlan::CreateFile { .. } | TreeMutationPlan::UpdateFile { .. } => {
                    required_payloads += 1;
                    let payload = payloads
                        .entries
                        .get(&intent_mutation.id())
                        .ok_or(ConfinedFilesystemError::InvalidPayload)?;
                    if !payload.matches_plan(planned)? {
                        return Err(ConfinedFilesystemError::InvalidPayload);
                    }
                }
                TreeMutationPlan::CreateDirectory { .. }
                | TreeMutationPlan::DeleteFile { .. }
                | TreeMutationPlan::MoveFile { .. }
                | TreeMutationPlan::MoveDirectory { .. }
                | TreeMutationPlan::DeleteDirectory { .. } => {
                    if payloads.content(intent_mutation.id()).is_some() {
                        return Err(ConfinedFilesystemError::InvalidPayload);
                    }
                }
            }
        }
        if payloads.len() != required_payloads {
            return Err(ConfinedFilesystemError::InvalidPayload);
        }
        Ok(())
    }
}

impl ConfinedWorkspace {
    /// Validate every endpoint and CAS precondition before any tree effect.
    ///
    /// Explicit `CreateDirectory` ancestors are modeled virtually so a nested
    /// greenfield tree can be validated without creating directories during
    /// preflight. Existing-file operations may never rely on virtual parents.
    pub fn prepare_source_tree_transaction(
        &self,
        plan: &TreeChangeSetPlan,
    ) -> Result<PreparedSourceTreeTransaction, ConfinedFilesystemError> {
        self.ensure_root()?;
        let mutation_lock = self.acquire_mutation_lock()?;
        let mut virtual_directories = BTreeSet::<PathBuf>::new();
        let mut observations = Vec::with_capacity(plan.mutations().len());

        for mutation in plan.mutations() {
            let observation = self.preflight_tree_mutation(mutation, &virtual_directories)?;
            if let TreeMutationPlan::CreateDirectory { path } = mutation {
                virtual_directories.insert(path.as_path().to_path_buf());
            }
            observations.push(observation);
        }

        self.ensure_root()?;
        Ok(PreparedSourceTreeTransaction {
            plan: plan.clone(),
            observations,
            _mutation_lock: mutation_lock,
        })
    }

    fn preflight_tree_mutation(
        &self,
        mutation: &TreeMutationPlan,
        virtual_directories: &BTreeSet<PathBuf>,
    ) -> Result<TreeMutationObservation, ConfinedFilesystemError> {
        match mutation {
            TreeMutationPlan::CreateDirectory { path } => {
                self.require_tree_target_absent(path, virtual_directories)?;
                Ok(TreeMutationObservation::CreateDirectory { path: path.clone() })
            }
            TreeMutationPlan::CreateFile {
                path,
                intended_hash: _,
            } => {
                self.require_tree_target_absent(path, virtual_directories)?;
                Ok(TreeMutationObservation::CreateFile { path: path.clone() })
            }
            TreeMutationPlan::UpdateFile {
                path,
                expected_hash,
                intended_hash: _,
            } => {
                let state = self.require_existing_regular(path, *expected_hash)?;
                Ok(TreeMutationObservation::UpdateFile {
                    path: path.clone(),
                    state,
                })
            }
            TreeMutationPlan::DeleteFile {
                path,
                expected_hash,
            } => {
                let state = self.require_existing_regular(path, *expected_hash)?;
                Ok(TreeMutationObservation::DeleteFile {
                    path: path.clone(),
                    state,
                })
            }
            TreeMutationPlan::MoveFile {
                source,
                destination,
                expected_hash,
            } => {
                let source_state = self.require_existing_regular(source, *expected_hash)?;
                self.require_tree_target_absent(destination, virtual_directories)?;
                Ok(TreeMutationObservation::MoveFile {
                    source: source.clone(),
                    source_state,
                    destination: destination.clone(),
                })
            }
            TreeMutationPlan::MoveDirectory {
                source,
                destination,
            } => {
                self.require_existing_directory(source)?;
                self.require_tree_target_absent(destination, virtual_directories)?;
                Ok(TreeMutationObservation::MoveDirectory {
                    source: source.clone(),
                    destination: destination.clone(),
                })
            }
            TreeMutationPlan::DeleteDirectory { path } => {
                self.require_empty_existing_directory(path)?;
                Ok(TreeMutationObservation::DeleteDirectory { path: path.clone() })
            }
        }
    }

    fn apply_tree_mutation_under_held_lock(
        &self,
        mutation: &forge_domain::TreeMutationIntent,
        payloads: &SourceTreePayloadSet,
    ) -> Result<(), ConfinedFilesystemError> {
        match mutation.plan() {
            TreeMutationPlan::CreateDirectory { path } => {
                self.create_directory_under_held_lock(path)
            }
            TreeMutationPlan::CreateFile { path, .. } => {
                let plan = FileMutationPlan::new(
                    path.clone(),
                    FileMutationKind::Create,
                    FilePrecondition::Absent,
                );
                let payload = payloads
                    .entries
                    .get(&mutation.id())
                    .ok_or(ConfinedFilesystemError::InvalidPayload)?;
                let SourceTreeContent::WholeFile(content) = &payload.content else {
                    return Err(ConfinedFilesystemError::InvalidPayload);
                };
                let _applied = self.prepare_mutation_under_held_lock(&plan)?.apply(
                    FileMutationId::from_uuid(mutation.id().into_uuid()),
                    Some(content),
                )?;
                Ok(())
            }
            TreeMutationPlan::UpdateFile {
                path,
                expected_hash,
                ..
            } => {
                let plan = FileMutationPlan::new(
                    path.clone(),
                    FileMutationKind::Replace,
                    FilePrecondition::Matches(*expected_hash),
                );
                let payload = payloads
                    .entries
                    .get(&mutation.id())
                    .ok_or(ConfinedFilesystemError::InvalidPayload)?;
                let prepared = self.prepare_mutation_under_held_lock(&plan)?;
                let mutation_id = FileMutationId::from_uuid(mutation.id().into_uuid());
                let _applied = match &payload.content {
                    SourceTreeContent::WholeFile(content) => {
                        prepared.apply(mutation_id, Some(content))
                    }
                    SourceTreeContent::CompiledPatch(patch) => {
                        prepared.apply_source_patch(mutation_id, patch.content())
                    }
                }?;
                Ok(())
            }
            TreeMutationPlan::DeleteFile {
                path,
                expected_hash,
            } => {
                let plan = FileMutationPlan::new(
                    path.clone(),
                    FileMutationKind::Delete,
                    FilePrecondition::Matches(*expected_hash),
                );
                let _applied = self
                    .prepare_mutation_under_held_lock(&plan)?
                    .apply(FileMutationId::from_uuid(mutation.id().into_uuid()), None)?;
                Ok(())
            }
            TreeMutationPlan::MoveFile {
                source,
                destination,
                expected_hash,
            } => {
                let _applied = self
                    .prepare_move_under_held_lock(source, *expected_hash, destination)?
                    .apply()?;
                Ok(())
            }
            TreeMutationPlan::MoveDirectory {
                source,
                destination,
            } => self.move_directory_under_held_lock(source, destination),
            TreeMutationPlan::DeleteDirectory { path } => {
                self.delete_directory_under_held_lock(path)
            }
        }
    }

    fn create_directory_under_held_lock(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<(), ConfinedFilesystemError> {
        self.ensure_root()?;
        let (parent, basename, _) = self.open_parent(path)?;
        require_leaf_absent(&parent, &basename)?;
        mkdirat(&parent, &basename, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|source| {
            if source == Errno::EXIST {
                ConfinedFilesystemError::PathConflict
            } else {
                ConfinedFilesystemError::Syscall {
                    operation: FilesystemOperation::CreateDirectory,
                    committed: false,
                    source,
                }
            }
        })?;
        fsync(&parent).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncParent,
            committed: true,
            source,
        })?;
        let created = openat(
            &parent,
            &basename,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        let stat =
            fstat(&created).map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(ConfinedFilesystemError::CommittedObservationFailed);
        }
        self.ensure_root()
            .map_err(|_| ConfinedFilesystemError::CommittedPathChanged)
    }

    fn move_directory_under_held_lock(
        &self,
        source: &WorkspaceRelativePath,
        destination: &WorkspaceRelativePath,
    ) -> Result<(), ConfinedFilesystemError> {
        self.ensure_root()?;
        let (source_parent, source_basename, _) = self.open_parent(source)?;
        let source_directory = openat(
            &source_parent,
            &source_basename,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_directory_open_error)?;
        let source_stat =
            fstat(&source_directory).map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::InspectAncestor,
                committed: false,
                source,
            })?;
        if !FileType::from_raw_mode(source_stat.st_mode).is_dir() {
            return Err(ConfinedFilesystemError::NonDirectoryAncestor);
        }
        let (destination_parent, destination_basename, _) = self.open_parent(destination)?;
        require_leaf_absent(&destination_parent, &destination_basename)?;
        if let Err(source) = renameat_with(
            &source_parent,
            &source_basename,
            &destination_parent,
            &destination_basename,
            RenameFlags::NOREPLACE,
        ) {
            if source == Errno::EXIST {
                return Err(ConfinedFilesystemError::PathConflict);
            }
            if [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::NOSYS].contains(&source) {
                return Err(ConfinedFilesystemError::AtomicMoveUnsupported);
            }
            return Err(ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::MoveLeaf,
                committed: false,
                source,
            });
        }
        fsync(&source_parent).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncMoveSourceParent,
            committed: true,
            source,
        })?;
        fsync(&destination_parent).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncMoveDestinationParent,
            committed: true,
            source,
        })?;
        if leaf_exists(&source_parent, &source_basename)? {
            return Err(ConfinedFilesystemError::CommittedObservationFailed);
        }
        let destination_directory = openat(
            &destination_parent,
            &destination_basename,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        let destination_stat = fstat(&destination_directory)
            .map_err(|_| ConfinedFilesystemError::CommittedObservationFailed)?;
        if !FileType::from_raw_mode(destination_stat.st_mode).is_dir() {
            return Err(ConfinedFilesystemError::CommittedObservationFailed);
        }
        self.ensure_root()
            .map_err(|_| ConfinedFilesystemError::CommittedPathChanged)
    }

    fn delete_directory_under_held_lock(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<(), ConfinedFilesystemError> {
        self.require_empty_existing_directory(path)?;
        let (parent, basename, _) = self.open_parent(path)?;
        unlinkat(&parent, &basename, AtFlags::REMOVEDIR).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::DeleteLeaf,
                committed: false,
                source,
            }
        })?;
        fsync(&parent).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::SyncParent,
            committed: true,
            source,
        })?;
        if leaf_exists(&parent, &basename)? {
            return Err(ConfinedFilesystemError::CommittedObservationFailed);
        }
        self.ensure_root()
            .map_err(|_| ConfinedFilesystemError::CommittedPathChanged)
    }

    fn require_existing_regular(
        &self,
        path: &WorkspaceRelativePath,
        expected_hash: FileContentHash,
    ) -> Result<FilePathState, ConfinedFilesystemError> {
        let (parent, basename, _) = self.open_parent(path)?;
        let captured = read_leaf(&parent, &basename, super::MAX_HASHED_FILE_BYTES, None)?
            .ok_or(ConfinedFilesystemError::NotFound)?;
        let FilePathState::Regular { hash, .. } = captured.state else {
            return Err(ConfinedFilesystemError::NonRegularLeaf);
        };
        if hash != expected_hash {
            return Err(ConfinedFilesystemError::StaleWrite);
        }
        Ok(captured.state)
    }

    fn require_existing_directory(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<OwnedFd, ConfinedFilesystemError> {
        validate_not_protected(path)?;
        let components = collect_components(path)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(ConfinedFilesystemError::InvalidPath)?;
        let parent = walk_directories(&self.root, ancestors, false)?;
        let directory = openat(
            &parent,
            basename,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| match source {
            Errno::NOENT => ConfinedFilesystemError::NotFound,
            Errno::LOOP => ConfinedFilesystemError::SymlinkRejected,
            Errno::NOTDIR => ConfinedFilesystemError::NonDirectoryAncestor,
            _ => ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::OpenAncestor,
                committed: false,
                source,
            },
        })?;
        let stat = fstat(&directory).map_err(|source| ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::InspectAncestor,
            committed: false,
            source,
        })?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(ConfinedFilesystemError::NonDirectoryAncestor);
        }
        Ok(directory)
    }

    fn require_empty_existing_directory(
        &self,
        path: &WorkspaceRelativePath,
    ) -> Result<(), ConfinedFilesystemError> {
        let directory = self.require_existing_directory(path)?;
        let stream =
            Dir::read_from(&directory).map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::OpenDirectoryStream,
                committed: false,
                source,
            })?;
        for entry in stream {
            let entry = entry.map_err(|source| ConfinedFilesystemError::Syscall {
                operation: FilesystemOperation::ReadDirectory,
                committed: false,
                source,
            })?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                return Err(ConfinedFilesystemError::PathConflict);
            }
        }
        Ok(())
    }

    fn require_tree_target_absent(
        &self,
        path: &WorkspaceRelativePath,
        virtual_directories: &BTreeSet<PathBuf>,
    ) -> Result<(), ConfinedFilesystemError> {
        validate_not_protected(path)?;
        let components = collect_components(path)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(ConfinedFilesystemError::InvalidPath)?;

        let mut prefix = PathBuf::new();
        for (index, component) in ancestors.iter().enumerate() {
            prefix.push(component);
            if virtual_directories.contains(&prefix) {
                // A parent that is intentionally absent until apply guarantees
                // every descendant target is currently absent as well.
                return Ok(());
            }
            let parent_components = &ancestors[..index];
            let parent = walk_directories(&self.root, parent_components, false)?;
            let opened = openat(
                &parent,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            );
            match opened {
                Ok(_directory) => {}
                Err(Errno::NOENT) => return Err(ConfinedFilesystemError::NotFound),
                Err(Errno::LOOP) => return Err(ConfinedFilesystemError::SymlinkRejected),
                Err(Errno::NOTDIR) => return Err(ConfinedFilesystemError::NonDirectoryAncestor),
                Err(source) => {
                    return Err(ConfinedFilesystemError::Syscall {
                        operation: FilesystemOperation::OpenAncestor,
                        committed: false,
                        source,
                    });
                }
            }
        }

        let parent = walk_directories(&self.root, ancestors, false)?;
        match observe_leaf(&parent, basename) {
            Ok(FilePathState::Absent) => Ok(()),
            Ok(FilePathState::Regular { .. }) => Err(ConfinedFilesystemError::PathConflict),
            Err(
                ConfinedFilesystemError::NonRegularLeaf
                | ConfinedFilesystemError::InvalidPathKind { .. },
            ) => {
                // A directory/symlink/other leaf is still an occupied target.
                Err(ConfinedFilesystemError::PathConflict)
            }
            Err(error) => Err(error),
        }
    }
}

fn map_directory_open_error(source: Errno) -> ConfinedFilesystemError {
    match source {
        Errno::NOENT => ConfinedFilesystemError::NotFound,
        Errno::LOOP => ConfinedFilesystemError::SymlinkRejected,
        Errno::NOTDIR => ConfinedFilesystemError::NonDirectoryAncestor,
        _ => ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenAncestor,
            committed: false,
            source,
        },
    }
}

fn leaf_exists(
    parent: &OwnedFd,
    basename: &std::ffi::OsStr,
) -> Result<bool, ConfinedFilesystemError> {
    match openat(
        parent,
        basename,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(_leaf) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(Errno::LOOP) => Ok(true),
        Err(source) => Err(ConfinedFilesystemError::Syscall {
            operation: FilesystemOperation::OpenLeaf,
            committed: false,
            source,
        }),
    }
}

fn require_leaf_absent(
    parent: &OwnedFd,
    basename: &std::ffi::OsStr,
) -> Result<(), ConfinedFilesystemError> {
    if leaf_exists(parent, basename)? {
        Err(ConfinedFilesystemError::PathConflict)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use forge_domain::{
        ActivityId, ActivityLeaseRevision, ChangeSetAttribution, ChangeSetId, FileContentHash,
        RuntimeInstanceId, TreeChangeSetIntent, TreeChangeSetPlan, TreeMutationId,
        TreeMutationPlan, WorkspaceId, WorkspaceRelativePath, WorkspaceRevision,
    };

    use super::*;
    use crate::WorkspaceStateLayout;

    fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
    }

    fn hash_bytes(content: &[u8]) -> FileContentHash {
        FileContentHash::from_bytes(*blake3::hash(content).as_bytes())
    }

    fn workspace() -> Result<(PathBuf, ConfinedWorkspace), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "forge-source-tree-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let _layout = WorkspaceStateLayout::initialize(&root)?;
        let existing =
            WorkspaceStateLayout::inspect_existing(&root)?.ok_or("workspace layout missing")?;
        let confined = ConfinedWorkspace::open(&existing)?;
        Ok((root, confined))
    }

    #[test]
    fn nested_greenfield_tree_preflights_without_creating_anything()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, confined) = workspace()?;
        let plan = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::create_directory(path(".agents")?),
            TreeMutationPlan::create_directory(path(".agents/rust")?),
            TreeMutationPlan::create_file(path(".agents/rust/rules.md")?, hash_bytes(b"rules\n")),
        ])?;
        let prepared = confined.prepare_source_tree_transaction(&plan)?;
        assert_eq!(prepared.observations().len(), 3);
        assert!(!root.join(".agents").exists());
        drop(prepared);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_existing_file_rejects_entire_preflight() -> Result<(), Box<dyn std::error::Error>> {
        let (root, confined) = workspace()?;
        fs::write(root.join("current.txt"), b"current\n")?;
        let plan = TreeChangeSetPlan::new(vec![TreeMutationPlan::update_file(
            path("current.txt")?,
            hash_bytes(b"stale\n"),
            hash_bytes(b"replacement\n"),
        )])?;
        let error = confined
            .prepare_source_tree_transaction(&plan)
            .err()
            .ok_or("expected stale preflight")?;
        assert!(matches!(error, ConfinedFilesystemError::StaleWrite));
        assert_eq!(fs::read(root.join("current.txt"))?, b"current\n");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn intent_for(
        plan: &TreeChangeSetPlan,
        seed: u128,
    ) -> Result<TreeChangeSetIntent, Box<dyn std::error::Error>> {
        let attribution = ChangeSetAttribution::new(
            ChangeSetId::from_uuid(uuid::Uuid::from_u128(seed)),
            WorkspaceId::from_uuid(uuid::Uuid::from_u128(seed + 1)),
            WorkspaceRevision::INITIAL,
            ActivityId::from_uuid(uuid::Uuid::from_u128(seed + 2)),
            RuntimeInstanceId::from_uuid(uuid::Uuid::from_u128(seed + 3)),
            ActivityLeaseRevision::INITIAL,
        );
        let ids = (0..plan.mutations().len())
            .map(|offset| {
                TreeMutationId::from_uuid(uuid::Uuid::from_u128(seed + 10 + offset as u128))
            })
            .collect();
        Ok(TreeChangeSetIntent::from_plan(
            attribution,
            ids,
            plan,
            forge_domain::TimestampMillis::new(10)?,
        )?)
    }

    fn apply_without_journal_failure(
        prepared: PreparedSourceTreeTransaction,
        confined: &ConfinedWorkspace,
        intent: &TreeChangeSetIntent,
        payloads: &SourceTreePayloadSet,
    ) -> Result<AppliedSourceTreeTransaction, Box<dyn std::error::Error>> {
        prepared
            .apply_with_journal(confined, intent, payloads, |_id| Ok::<(), ()>(()))
            .map_err(|_| std::io::Error::other("source tree apply failed").into())
    }

    #[test]
    fn payload_mismatch_rejects_before_first_tree_effect() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, confined) = workspace()?;
        let expected = hash_bytes(b"expected\n");
        let plan = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::create_directory(path("generated")?),
            TreeMutationPlan::create_file(path("generated/file.txt")?, expected),
        ])?;
        let intent = intent_for(&plan, 0xD100)?;
        let file_id = intent.mutations()[1].id();
        let payloads = SourceTreePayloadSet::new(vec![SourceTreeMutationPayload::new(
            file_id,
            b"wrong\n".to_vec(),
        )?])?;
        let prepared = confined.prepare_source_tree_transaction(&plan)?;
        let result =
            prepared.apply_with_journal(&confined, &intent, &payloads, |_id| Ok::<(), ()>(()));
        assert!(result.is_err());
        assert!(!root.join("generated").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn compiled_patch(
        source: &[u8],
        replacement: Vec<u8>,
    ) -> Result<CompiledFilePatch, Box<dyn std::error::Error>> {
        Ok(forge_domain::FilePatch::new(
            hash_bytes(source),
            vec![forge_domain::FilePatchHunk::new(
                forge_domain::SourceLineRange::new(1, 1)?,
                forge_domain::SourceRangeHash::from_bytes(*blake3::hash(source).as_bytes()),
                replacement,
            )?],
        )?
        .compile(source)?)
    }

    #[test]
    fn compiled_patch_payload_rejects_create_and_mismatched_source_or_result_before_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, confined) = workspace()?;
        fs::write(root.join("source.txt"), b"current\n")?;
        let valid = compiled_patch(b"current\n", b"patched\n".to_vec())?;
        let wrong_source = compiled_patch(b"different\n", b"patched\n".to_vec())?;
        let wrong_result = compiled_patch(b"current\n", b"different\n".to_vec())?;
        for (file_plan, compiled) in [
            (
                TreeMutationPlan::create_file(path("generated/new.txt")?, valid.result_hash()),
                valid,
            ),
            (
                TreeMutationPlan::update_file(
                    path("source.txt")?,
                    hash_bytes(b"current\n"),
                    hash_bytes(b"patched\n"),
                ),
                wrong_source,
            ),
            (
                TreeMutationPlan::update_file(
                    path("source.txt")?,
                    hash_bytes(b"current\n"),
                    hash_bytes(b"patched\n"),
                ),
                wrong_result,
            ),
        ] {
            let plan = TreeChangeSetPlan::new(vec![
                TreeMutationPlan::create_directory(path("generated")?),
                file_plan,
            ])?;
            let intent = intent_for(&plan, 0xD300)?;
            let payloads =
                SourceTreePayloadSet::new(vec![SourceTreeMutationPayload::from_compiled_patch(
                    intent.mutations()[1].id(),
                    compiled,
                )])?;
            let prepared = confined.prepare_source_tree_transaction(&plan)?;
            let result =
                prepared.apply_with_journal(&confined, &intent, &payloads, |_id| Ok::<(), ()>(()));
            assert!(
                matches!(result, Err(SourceTreeApplyError::Filesystem { applied_mutations, uncertain_mutation: None, source: ConfinedFilesystemError::InvalidPayload }) if applied_mutations.is_empty())
            );
            assert!(!root.join("generated").exists());
            assert_eq!(fs::read(root.join("source.txt"))?, b"current\n");
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn compiled_patch_payloads_keep_raw_and_aggregate_limits()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = |value| TreeMutationId::from_uuid(uuid::Uuid::from_u128(value));
        assert!(matches!(
            SourceTreeMutationPayload::new(id(1), vec![b'x'; MAX_FILE_WRITE_BYTES + 1]),
            Err(ConfinedFilesystemError::WriteTooLarge {
                maximum: MAX_FILE_WRITE_BYTES,
                ..
            })
        ));
        let compiled = compiled_patch(b"x\n", vec![b'x'; forge_domain::MAX_SOURCE_PATCH_BYTES])?;
        let payload =
            |value| SourceTreeMutationPayload::from_compiled_patch(id(value), compiled.clone());
        let accepted = SourceTreePayloadSet::new(vec![payload(1), payload(2)])?;
        assert_eq!(accepted.len(), 2);
        assert!(matches!(
            SourceTreePayloadSet::new(vec![payload(1), payload(2), payload(3)]),
            Err(ConfinedFilesystemError::WriteTooLarge {
                maximum: MAX_SOURCE_TREE_PAYLOAD_BYTES,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn nested_tree_and_file_move_apply_in_deterministic_journal_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, confined) = workspace()?;
        fs::write(root.join("source.txt"), b"move-me\n")?;
        let plan = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::create_directory(path("nested")?),
            TreeMutationPlan::create_directory(path("nested/deep")?),
            TreeMutationPlan::create_file(path("nested/deep/new.txt")?, hash_bytes(b"new\n")),
            TreeMutationPlan::move_file(
                path("source.txt")?,
                path("nested/moved.txt")?,
                hash_bytes(b"move-me\n"),
            ),
        ])?;
        let intent = intent_for(&plan, 0xD200)?;
        let create_id = intent
            .mutations()
            .iter()
            .find(|mutation| matches!(mutation.plan(), TreeMutationPlan::CreateFile { .. }))
            .map(forge_domain::TreeMutationIntent::id)
            .ok_or("create mutation missing")?;
        let payloads = SourceTreePayloadSet::new(vec![SourceTreeMutationPayload::new(
            create_id,
            b"new\n".to_vec(),
        )?])?;
        let prepared = confined.prepare_source_tree_transaction(&plan)?;
        let mut journal = Vec::new();
        let applied = prepared
            .apply_with_journal(&confined, &intent, &payloads, |id| {
                journal.push(id);
                Ok::<(), ()>(())
            })
            .map_err(|_| std::io::Error::other("source tree apply failed"))?;
        assert_eq!(journal, applied.applied_mutations());
        assert_eq!(journal.len(), 4);
        assert_eq!(fs::read(root.join("nested/deep/new.txt"))?, b"new\n");
        assert_eq!(fs::read(root.join("nested/moved.txt"))?, b"move-me\n");
        assert!(!root.join("source.txt").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn empty_directory_move_and_delete_are_descriptor_confined()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, confined) = workspace()?;
        fs::create_dir(root.join("from"))?;
        let move_plan = TreeChangeSetPlan::new(vec![TreeMutationPlan::move_directory(
            path("from")?,
            path("to")?,
        )])?;
        let move_intent = intent_for(&move_plan, 0xD300)?;
        let prepared = confined.prepare_source_tree_transaction(&move_plan)?;
        let empty_payloads = SourceTreePayloadSet::new(Vec::new())?;
        let _applied =
            apply_without_journal_failure(prepared, &confined, &move_intent, &empty_payloads)?;
        assert!(!root.join("from").exists());
        assert!(root.join("to").is_dir());

        let delete_plan =
            TreeChangeSetPlan::new(vec![TreeMutationPlan::delete_directory(path("to")?)])?;
        let delete_intent = intent_for(&delete_plan, 0xD400)?;
        let prepared = confined.prepare_source_tree_transaction(&delete_plan)?;
        let _applied =
            apply_without_journal_failure(prepared, &confined, &delete_intent, &empty_payloads)?;
        assert!(!root.join("to").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nonempty_directory_delete_is_rejected_before_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, confined) = workspace()?;
        fs::create_dir(root.join("nested"))?;
        fs::write(root.join("nested/file.txt"), b"content\n")?;
        let plan =
            TreeChangeSetPlan::new(vec![TreeMutationPlan::delete_directory(path("nested")?)])?;
        let error = confined
            .prepare_source_tree_transaction(&plan)
            .err()
            .ok_or("expected nonempty directory conflict")?;
        assert!(matches!(error, ConfinedFilesystemError::PathConflict));
        assert!(root.join("nested/file.txt").is_file());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
