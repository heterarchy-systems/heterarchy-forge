use std::cmp::Ordering;

use thiserror::Error;

use crate::{
    DiffChangeKind, DiffEntrySubject, DiffEntrySummary, DiffLineCount, FileContentHash,
    WorkspaceRelativePath,
};

/// Maximum tree mutations admitted in one bounded source-tree transaction.
pub const MAX_TREE_CHANGESET_MUTATIONS: usize = 256;
/// Maximum distinct path endpoints admitted by one source-tree transaction.
pub const MAX_TREE_CHANGESET_PATHS: usize = MAX_TREE_CHANGESET_MUTATIONS * 2;

/// Stable digest of one caller-authored source-tree request. This identity is
/// persisted before effects so exact retries do not need to recompile patches
/// against source that may already have changed.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceTreeRequestDigest([u8; 32]);

impl SourceTreeRequestDigest {
    pub const BYTE_LEN: usize = 32;

    pub const fn from_bytes(value: [u8; Self::BYTE_LEN]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LEN] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }
}

/// One source-tree mutation plan. Payload bytes remain outside the domain;
/// file writes carry only exact CAS/intended hashes at this boundary.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeMutationPlan {
    CreateDirectory {
        path: WorkspaceRelativePath,
    },
    CreateFile {
        path: WorkspaceRelativePath,
        intended_hash: FileContentHash,
    },
    UpdateFile {
        path: WorkspaceRelativePath,
        expected_hash: FileContentHash,
        intended_hash: FileContentHash,
    },
    DeleteFile {
        path: WorkspaceRelativePath,
        expected_hash: FileContentHash,
    },
    MoveFile {
        source: WorkspaceRelativePath,
        destination: WorkspaceRelativePath,
        expected_hash: FileContentHash,
    },
    MoveDirectory {
        source: WorkspaceRelativePath,
        destination: WorkspaceRelativePath,
    },
    DeleteDirectory {
        path: WorkspaceRelativePath,
    },
}

impl TreeMutationPlan {
    pub const fn create_directory(path: WorkspaceRelativePath) -> Self {
        Self::CreateDirectory { path }
    }

    pub const fn create_file(path: WorkspaceRelativePath, intended_hash: FileContentHash) -> Self {
        Self::CreateFile {
            path,
            intended_hash,
        }
    }

    pub const fn update_file(
        path: WorkspaceRelativePath,
        expected_hash: FileContentHash,
        intended_hash: FileContentHash,
    ) -> Self {
        Self::UpdateFile {
            path,
            expected_hash,
            intended_hash,
        }
    }

    pub const fn delete_file(path: WorkspaceRelativePath, expected_hash: FileContentHash) -> Self {
        Self::DeleteFile {
            path,
            expected_hash,
        }
    }

    pub const fn move_file(
        source: WorkspaceRelativePath,
        destination: WorkspaceRelativePath,
        expected_hash: FileContentHash,
    ) -> Self {
        Self::MoveFile {
            source,
            destination,
            expected_hash,
        }
    }

    pub const fn move_directory(
        source: WorkspaceRelativePath,
        destination: WorkspaceRelativePath,
    ) -> Self {
        Self::MoveDirectory {
            source,
            destination,
        }
    }

    pub const fn delete_directory(path: WorkspaceRelativePath) -> Self {
        Self::DeleteDirectory { path }
    }

    pub const fn primary_path(&self) -> &WorkspaceRelativePath {
        match self {
            Self::CreateDirectory { path }
            | Self::CreateFile { path, .. }
            | Self::UpdateFile { path, .. }
            | Self::DeleteFile { path, .. }
            | Self::DeleteDirectory { path } => path,
            Self::MoveFile { source, .. } | Self::MoveDirectory { source, .. } => source,
        }
    }

    pub const fn secondary_path(&self) -> Option<&WorkspaceRelativePath> {
        match self {
            Self::MoveFile { destination, .. } | Self::MoveDirectory { destination, .. } => {
                Some(destination)
            }
            Self::CreateDirectory { .. }
            | Self::CreateFile { .. }
            | Self::UpdateFile { .. }
            | Self::DeleteFile { .. }
            | Self::DeleteDirectory { .. } => None,
        }
    }

    pub const fn is_create_directory(&self) -> bool {
        matches!(self, Self::CreateDirectory { .. })
    }

    const fn has_structural_subtree_effect(&self) -> bool {
        matches!(
            self,
            Self::MoveDirectory { .. } | Self::DeleteDirectory { .. }
        )
    }

    fn path_depth(path: &WorkspaceRelativePath) -> usize {
        path.components().count()
    }

    fn execution_rank(&self) -> (u8, usize) {
        match self {
            Self::CreateDirectory { path } => (0, Self::path_depth(path)),
            Self::CreateFile { path, .. } => (1, Self::path_depth(path)),
            Self::UpdateFile { path, .. } => (2, Self::path_depth(path)),
            Self::MoveFile { source, .. } => (3, Self::path_depth(source)),
            Self::DeleteFile { path, .. } => (4, usize::MAX - Self::path_depth(path)),
            Self::MoveDirectory { source, .. } => (5, usize::MAX - Self::path_depth(source)),
            Self::DeleteDirectory { path } => (6, usize::MAX - Self::path_depth(path)),
        }
    }
}

/// Validated, deterministic tree-level source mutation plan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeChangeSetPlan {
    mutations: Vec<TreeMutationPlan>,
}

impl TreeChangeSetPlan {
    pub fn new(mut mutations: Vec<TreeMutationPlan>) -> Result<Self, TreeChangeSetPlanError> {
        if mutations.is_empty() {
            return Err(TreeChangeSetPlanError::Empty);
        }
        if mutations.len() > MAX_TREE_CHANGESET_MUTATIONS {
            return Err(TreeChangeSetPlanError::TooManyMutations {
                actual: mutations.len(),
                maximum: MAX_TREE_CHANGESET_MUTATIONS,
            });
        }
        let path_count = mutations
            .iter()
            .map(|mutation| usize::from(mutation.secondary_path().is_some()) + 1)
            .sum::<usize>();
        if path_count > MAX_TREE_CHANGESET_PATHS {
            return Err(TreeChangeSetPlanError::TooManyPaths {
                actual: path_count,
                maximum: MAX_TREE_CHANGESET_PATHS,
            });
        }
        validate_move_endpoints(&mutations)?;
        validate_pairwise_conflicts(&mutations)?;
        mutations.sort_by(compare_mutations);
        Ok(Self { mutations })
    }

    pub fn mutations(&self) -> &[TreeMutationPlan] {
        &self.mutations
    }

    pub fn affected_paths(&self) -> Vec<&WorkspaceRelativePath> {
        let mut paths = Vec::with_capacity(self.mutations.len() * 2);
        for mutation in &self.mutations {
            paths.push(mutation.primary_path());
            if let Some(path) = mutation.secondary_path() {
                paths.push(path);
            }
        }
        paths.sort_unstable();
        paths.dedup();
        paths
    }
}

fn compare_mutations(left: &TreeMutationPlan, right: &TreeMutationPlan) -> Ordering {
    left.execution_rank()
        .cmp(&right.execution_rank())
        .then_with(|| left.primary_path().cmp(right.primary_path()))
        .then_with(|| left.secondary_path().cmp(&right.secondary_path()))
}

fn validate_move_endpoints(mutations: &[TreeMutationPlan]) -> Result<(), TreeChangeSetPlanError> {
    for mutation in mutations {
        let Some(destination) = mutation.secondary_path() else {
            continue;
        };
        let source = mutation.primary_path();
        if source == destination
            || destination.as_path().starts_with(source.as_path())
            || (matches!(mutation, TreeMutationPlan::MoveDirectory { .. })
                && source.as_path().starts_with(destination.as_path()))
        {
            return Err(TreeChangeSetPlanError::InvalidMoveEndpoint);
        }
    }
    Ok(())
}

fn validate_pairwise_conflicts(
    mutations: &[TreeMutationPlan],
) -> Result<(), TreeChangeSetPlanError> {
    for (index, left) in mutations.iter().enumerate() {
        for right in &mutations[index + 1..] {
            if mutations_conflict(left, right) {
                return Err(TreeChangeSetPlanError::OverlappingMutation);
            }
        }
    }
    Ok(())
}

fn mutations_conflict(left: &TreeMutationPlan, right: &TreeMutationPlan) -> bool {
    for left_path in mutation_paths(left).into_iter().flatten() {
        for right_path in mutation_paths(right).into_iter().flatten() {
            if left_path == right_path {
                return true;
            }
            let left_contains_right = right_path.as_path().starts_with(left_path.as_path());
            let right_contains_left = left_path.as_path().starts_with(right_path.as_path());
            if !left_contains_right && !right_contains_left {
                continue;
            }

            // Explicit directory creation is the only compatible ancestor
            // relation: it enables greenfield nested trees while every other
            // ancestor mutation would make staging/order semantics ambiguous.
            if left_contains_right && left.is_create_directory() {
                continue;
            }
            if right_contains_left && right.is_create_directory() {
                continue;
            }
            if left.has_structural_subtree_effect() || right.has_structural_subtree_effect() {
                return true;
            }
            return true;
        }
    }
    false
}

fn mutation_paths(mutation: &TreeMutationPlan) -> [Option<&WorkspaceRelativePath>; 2] {
    [Some(mutation.primary_path()), mutation.secondary_path()]
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TreeChangeSetPlanError {
    #[error("Tree ChangeSet must contain at least one mutation")]
    Empty,
    #[error("Tree ChangeSet contains {actual} mutations; maximum is {maximum}")]
    TooManyMutations { actual: usize, maximum: usize },
    #[error("Tree ChangeSet touches {actual} path endpoints; maximum is {maximum}")]
    TooManyPaths { actual: usize, maximum: usize },
    #[error("Tree ChangeSet contains duplicate or overlapping mutation authority")]
    OverlappingMutation,
    #[error("Tree move source and destination are structurally invalid")]
    InvalidMoveEndpoint,
}

/// Stable identity for one ordered mutation inside a tree-level `ChangeSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TreeMutationId(uuid::Uuid);

impl TreeMutationId {
    pub const fn from_uuid(value: uuid::Uuid) -> Self {
        Self(value)
    }
    pub const fn into_uuid(self) -> uuid::Uuid {
        self.0
    }
}

impl std::fmt::Display for TreeMutationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Deterministic zero-based ordering inside one tree-level `ChangeSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TreeMutationOrdinal(u16);

impl TreeMutationOrdinal {
    pub fn new(value: usize) -> Result<Self, TreeChangeSetIntentError> {
        if value >= MAX_TREE_CHANGESET_MUTATIONS {
            return Err(TreeChangeSetIntentError::OrdinalOutOfRange);
        }
        Ok(Self(u16::try_from(value).map_err(|_| {
            TreeChangeSetIntentError::OrdinalOutOfRange
        })?))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Durable tree mutation intent: stable identity + deterministic ordinal + plan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeMutationIntent {
    id: TreeMutationId,
    ordinal: TreeMutationOrdinal,
    plan: TreeMutationPlan,
}

impl TreeMutationIntent {
    pub const fn new(
        id: TreeMutationId,
        ordinal: TreeMutationOrdinal,
        plan: TreeMutationPlan,
    ) -> Self {
        Self { id, ordinal, plan }
    }
    pub const fn id(&self) -> TreeMutationId {
        self.id
    }
    pub const fn ordinal(&self) -> TreeMutationOrdinal {
        self.ordinal
    }
    pub const fn plan(&self) -> &TreeMutationPlan {
        &self.plan
    }
}

/// Caller-authored tree mutation identity kept attached to its mutation while
/// the validated plan canonicalizes execution ordering.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeMutationDraft {
    id: TreeMutationId,
    plan: TreeMutationPlan,
}

impl TreeMutationDraft {
    pub const fn new(id: TreeMutationId, plan: TreeMutationPlan) -> Self {
        Self { id, plan }
    }

    pub const fn id(&self) -> TreeMutationId {
        self.id
    }
    pub const fn plan(&self) -> &TreeMutationPlan {
        &self.plan
    }
}

/// Validated draft that preserves mutation identity through canonical ordering.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeChangeSetDraft {
    plan: TreeChangeSetPlan,
    mutation_ids: Vec<TreeMutationId>,
}

impl TreeChangeSetDraft {
    pub fn new(mutations: &[TreeMutationDraft]) -> Result<Self, TreeChangeSetIntentError> {
        if mutations.is_empty() {
            return Err(TreeChangeSetIntentError::Plan(
                TreeChangeSetPlanError::Empty,
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for mutation in mutations {
            if !ids.insert(mutation.id()) {
                return Err(TreeChangeSetIntentError::DuplicateMutationId);
            }
        }
        let plan = TreeChangeSetPlan::new(
            mutations
                .iter()
                .map(|mutation| mutation.plan().clone())
                .collect(),
        )
        .map_err(TreeChangeSetIntentError::Plan)?;
        let mut mutation_ids = Vec::with_capacity(plan.mutations().len());
        for canonical in plan.mutations() {
            let id = mutations
                .iter()
                .find(|mutation| mutation.plan() == canonical)
                .map(TreeMutationDraft::id)
                .ok_or(TreeChangeSetIntentError::CanonicalizationMismatch)?;
            mutation_ids.push(id);
        }
        Ok(Self { plan, mutation_ids })
    }

    pub const fn plan(&self) -> &TreeChangeSetPlan {
        &self.plan
    }
    pub fn mutation_ids(&self) -> &[TreeMutationId] {
        &self.mutation_ids
    }
}

/// Durable admission payload for one ordered tree-level `ChangeSet`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeChangeSetIntent {
    attribution: crate::ChangeSetAttribution,
    mutations: Vec<TreeMutationIntent>,
    diff_entries: Vec<DiffEntrySummary>,
    observed_at: crate::TimestampMillis,
}

impl TreeChangeSetIntent {
    pub fn from_draft(
        attribution: crate::ChangeSetAttribution,
        draft: &TreeChangeSetDraft,
        observed_at: crate::TimestampMillis,
    ) -> Result<Self, TreeChangeSetIntentError> {
        Self::from_plan(
            attribution,
            draft.mutation_ids().to_vec(),
            draft.plan(),
            observed_at,
        )
    }

    pub fn from_plan(
        attribution: crate::ChangeSetAttribution,
        mutation_ids: Vec<TreeMutationId>,
        plan: &TreeChangeSetPlan,
        observed_at: crate::TimestampMillis,
    ) -> Result<Self, TreeChangeSetIntentError> {
        if mutation_ids.len() != plan.mutations().len() {
            return Err(TreeChangeSetIntentError::IdentityCountMismatch);
        }
        let mut unique = std::collections::BTreeSet::new();
        let mut mutations = Vec::with_capacity(mutation_ids.len());
        for (ordinal, (id, mutation)) in mutation_ids
            .into_iter()
            .zip(plan.mutations().iter().cloned())
            .enumerate()
        {
            if !unique.insert(id) {
                return Err(TreeChangeSetIntentError::DuplicateMutationId);
            }
            mutations.push(TreeMutationIntent::new(
                id,
                TreeMutationOrdinal::new(ordinal)?,
                mutation,
            ));
        }
        let diff_entries = mutations
            .iter()
            .map(|mutation| canonical_diff_entry(mutation.plan()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            attribution,
            mutations,
            diff_entries,
            observed_at,
        })
    }

    /// Build an intent while retaining renderer-produced line counts for its
    /// canonical mutation order. The supplied entries may vary only in their
    /// additions/deletions; their subject, paths, kind, and order stay bound to
    /// the validated mutation plan.
    pub fn from_plan_with_diff_entries(
        attribution: crate::ChangeSetAttribution,
        mutation_ids: Vec<TreeMutationId>,
        plan: &TreeChangeSetPlan,
        observed_at: crate::TimestampMillis,
        diff_entries: Vec<DiffEntrySummary>,
    ) -> Result<Self, TreeChangeSetIntentError> {
        Self::from_plan(attribution, mutation_ids, plan, observed_at)?
            .with_diff_entries(diff_entries)
    }

    /// Replace zero-count canonical entries with validated renderer metadata.
    /// The mutation plan remains the sole authority for entry identity and
    /// ordering; only line counts are caller-provided evidence.
    pub fn with_diff_entries(
        mut self,
        diff_entries: Vec<DiffEntrySummary>,
    ) -> Result<Self, TreeChangeSetIntentError> {
        if diff_entries.len() != self.mutations.len() {
            return Err(TreeChangeSetIntentError::DiffEntriesMismatch);
        }
        let metadata_matches =
            self.diff_entries
                .iter()
                .zip(&diff_entries)
                .all(|(expected, actual)| {
                    actual.subject() == expected.subject()
                        && actual.primary_path() == expected.primary_path()
                        && actual.secondary_path() == expected.secondary_path()
                        && actual.kind() == expected.kind()
                });
        if !metadata_matches {
            return Err(TreeChangeSetIntentError::DiffEntriesMismatch);
        }
        self.diff_entries = diff_entries;
        Ok(self)
    }

    pub const fn attribution(&self) -> crate::ChangeSetAttribution {
        self.attribution
    }
    pub fn mutations(&self) -> &[TreeMutationIntent] {
        &self.mutations
    }
    pub const fn observed_at(&self) -> crate::TimestampMillis {
        self.observed_at
    }

    /// Canonical path-level aggregate Diff entries for this exact durable
    /// tree intent. Entry order is identical to mutation journal order.
    pub fn diff_entries(&self) -> &[DiffEntrySummary] {
        &self.diff_entries
    }
}

fn canonical_diff_entry(
    plan: &TreeMutationPlan,
) -> Result<DiffEntrySummary, TreeChangeSetIntentError> {
    let (subject, primary, secondary, kind) = match plan {
        TreeMutationPlan::CreateDirectory { path } => (
            DiffEntrySubject::Directory,
            path.clone(),
            None,
            DiffChangeKind::Created,
        ),
        TreeMutationPlan::CreateFile { path, .. } => (
            DiffEntrySubject::File,
            path.clone(),
            None,
            DiffChangeKind::Created,
        ),
        TreeMutationPlan::UpdateFile { path, .. } => (
            DiffEntrySubject::File,
            path.clone(),
            None,
            DiffChangeKind::Modified,
        ),
        TreeMutationPlan::DeleteFile { path, .. } => (
            DiffEntrySubject::File,
            path.clone(),
            None,
            DiffChangeKind::Deleted,
        ),
        TreeMutationPlan::MoveFile {
            source,
            destination,
            ..
        } => (
            DiffEntrySubject::File,
            source.clone(),
            Some(destination.clone()),
            DiffChangeKind::Moved,
        ),
        TreeMutationPlan::MoveDirectory {
            source,
            destination,
        } => (
            DiffEntrySubject::Directory,
            source.clone(),
            Some(destination.clone()),
            DiffChangeKind::Moved,
        ),
        TreeMutationPlan::DeleteDirectory { path } => (
            DiffEntrySubject::Directory,
            path.clone(),
            None,
            DiffChangeKind::Deleted,
        ),
    };
    DiffEntrySummary::new(
        subject,
        primary,
        secondary,
        kind,
        DiffLineCount::new(0),
        DiffLineCount::new(0),
    )
    .map_err(|_| TreeChangeSetIntentError::DiffEntryShape)
}

/// Durable admission outcome for a tree-level `ChangeSet` retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TreeChangeSetAdmissionStatus {
    Started,
    RecoveryRequired,
    AlreadyApplied,
    TerminalFailed,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeChangeSetAdmission {
    change_set: crate::RegisteredChangeSet,
    status: TreeChangeSetAdmissionStatus,
}

impl TreeChangeSetAdmission {
    pub const fn new(
        change_set: crate::RegisteredChangeSet,
        status: TreeChangeSetAdmissionStatus,
    ) -> Self {
        Self { change_set, status }
    }
    pub const fn change_set(&self) -> &crate::RegisteredChangeSet {
        &self.change_set
    }
    pub const fn status(&self) -> TreeChangeSetAdmissionStatus {
        self.status
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TreeChangeSetIntentError {
    #[error("tree mutation plan is invalid")]
    Plan(TreeChangeSetPlanError),
    #[error("tree mutation identity could not be retained through canonical ordering")]
    CanonicalizationMismatch,
    #[error("tree mutation identity count does not match the validated plan")]
    IdentityCountMismatch,
    #[error("tree mutation identity is duplicated")]
    DuplicateMutationId,
    #[error("tree mutation ordinal exceeds the bounded transaction range")]
    OrdinalOutOfRange,
    #[error("tree mutation Diff entry has an invalid shape")]
    DiffEntryShape,
    #[error("tree Diff entries do not match the canonical mutation order or identity")]
    DiffEntriesMismatch,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn std::error::Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
    }

    fn hash(value: u8) -> FileContentHash {
        FileContentHash::from_bytes([value; FileContentHash::BYTE_LEN])
    }

    fn attribution(seed: u128) -> crate::ChangeSetAttribution {
        crate::ChangeSetAttribution::new(
            crate::ChangeSetId::from_uuid(uuid::Uuid::from_u128(seed)),
            crate::WorkspaceId::from_uuid(uuid::Uuid::from_u128(seed + 1)),
            crate::WorkspaceRevision::INITIAL,
            crate::ActivityId::from_uuid(uuid::Uuid::from_u128(seed + 2)),
            crate::RuntimeInstanceId::from_uuid(uuid::Uuid::from_u128(seed + 3)),
            crate::ActivityLeaseRevision::INITIAL,
        )
    }

    #[test]
    fn nested_greenfield_tree_is_valid_and_ordered_parent_first()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::create_file(path(".agents/python/rules.md")?, hash(1)),
            TreeMutationPlan::create_directory(path(".agents/python")?),
            TreeMutationPlan::create_directory(path(".agents")?),
        ])?;
        assert!(matches!(
            &plan.mutations()[0],
            TreeMutationPlan::CreateDirectory { path } if path.as_path() == std::path::Path::new(".agents")
        ));
        assert!(matches!(
            &plan.mutations()[1],
            TreeMutationPlan::CreateDirectory { path } if path.as_path() == std::path::Path::new(".agents/python")
        ));
        assert!(matches!(
            &plan.mutations()[2],
            TreeMutationPlan::CreateFile { path, .. } if path.as_path() == std::path::Path::new(".agents/python/rules.md")
        ));
        Ok(())
    }

    #[test]
    fn duplicate_exact_path_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let shared = path("src/lib.rs")?;
        let error = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::update_file(shared.clone(), hash(1), hash(2)),
            TreeMutationPlan::delete_file(shared, hash(1)),
        ])
        .err()
        .ok_or("expected overlap conflict")?;
        assert_eq!(error, TreeChangeSetPlanError::OverlappingMutation);
        Ok(())
    }

    #[test]
    fn structural_directory_mutation_rejects_child_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let error = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::delete_directory(path("src")?),
            TreeMutationPlan::delete_file(path("src/lib.rs")?, hash(1)),
        ])
        .err()
        .ok_or("expected structural overlap conflict")?;
        assert_eq!(error, TreeChangeSetPlanError::OverlappingMutation);
        Ok(())
    }

    #[test]
    fn move_directory_cannot_move_into_itself() -> Result<(), Box<dyn std::error::Error>> {
        let error = TreeChangeSetPlan::new(vec![TreeMutationPlan::move_directory(
            path("src")?,
            path("src/generated")?,
        )])
        .err()
        .ok_or("expected invalid move endpoint")?;
        assert_eq!(error, TreeChangeSetPlanError::InvalidMoveEndpoint);
        Ok(())
    }

    #[test]
    fn affected_paths_are_sorted_and_unique() -> Result<(), Box<dyn std::error::Error>> {
        let plan = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::create_directory(path("dst")?),
            TreeMutationPlan::move_file(path("src/a.rs")?, path("dst/a.rs")?, hash(1)),
        ])?;
        let observed = plan
            .affected_paths()
            .into_iter()
            .map(|path| path.as_path().to_path_buf())
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            vec![
                PathBuf::from("dst"),
                PathBuf::from("dst/a.rs"),
                PathBuf::from("src/a.rs")
            ]
        );
        Ok(())
    }

    #[test]
    fn draft_keeps_ids_attached_through_canonical_ordering()
    -> Result<(), Box<dyn std::error::Error>> {
        let file_id = TreeMutationId::from_uuid(uuid::Uuid::from_u128(10));
        let parent_id = TreeMutationId::from_uuid(uuid::Uuid::from_u128(11));
        let draft = TreeChangeSetDraft::new(&[
            TreeMutationDraft::new(
                file_id,
                TreeMutationPlan::create_file(path("nested/file.txt")?, hash(1)),
            ),
            TreeMutationDraft::new(
                parent_id,
                TreeMutationPlan::create_directory(path("nested")?),
            ),
        ])?;
        assert_eq!(draft.mutation_ids(), &[parent_id, file_id]);
        assert!(matches!(
            draft.plan().mutations()[0],
            TreeMutationPlan::CreateDirectory { .. }
        ));
        Ok(())
    }

    #[test]
    fn intent_retains_bounded_zero_count_entries_in_mutation_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = TreeChangeSetPlan::new(vec![
            TreeMutationPlan::update_file(path("src/lib.rs")?, hash(1), hash(2)),
            TreeMutationPlan::delete_file(path("src/main.rs")?, hash(3)),
        ])?;
        let ids = [10_u128, 11]
            .into_iter()
            .map(|value| TreeMutationId::from_uuid(uuid::Uuid::from_u128(value)))
            .collect();
        let intent = TreeChangeSetIntent::from_plan(
            attribution(20),
            ids,
            &plan,
            crate::TimestampMillis::new(1)?,
        )?;
        assert_eq!(intent.diff_entries().len(), 2);
        assert_eq!(
            intent.diff_entries()[0].primary_path().as_path(),
            std::path::Path::new("src/lib.rs")
        );
        assert_eq!(intent.diff_entries()[0].kind(), DiffChangeKind::Modified);
        assert_eq!(intent.diff_entries()[0].additions(), DiffLineCount::new(0));
        assert_eq!(intent.diff_entries()[0].deletions(), DiffLineCount::new(0));
        assert_eq!(intent.diff_entries()[1].kind(), DiffChangeKind::Deleted);
        Ok(())
    }

    #[test]
    fn intent_diff_entries_allow_counts_only_and_reject_identity_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = TreeChangeSetPlan::new(vec![TreeMutationPlan::update_file(
            path("src/lib.rs")?,
            hash(1),
            hash(2),
        )])?;
        let id = TreeMutationId::from_uuid(uuid::Uuid::from_u128(30));
        let intent = TreeChangeSetIntent::from_plan(
            attribution(40),
            vec![id],
            &plan,
            crate::TimestampMillis::new(1)?,
        )?;
        let counted = vec![DiffEntrySummary::new(
            DiffEntrySubject::File,
            path("src/lib.rs")?,
            None,
            DiffChangeKind::Modified,
            DiffLineCount::new(8),
            DiffLineCount::new(3),
        )?];
        let intent = intent.with_diff_entries(counted)?;
        assert_eq!(intent.diff_entries()[0].additions(), DiffLineCount::new(8));
        assert_eq!(intent.diff_entries()[0].deletions(), DiffLineCount::new(3));

        let wrong_path = vec![DiffEntrySummary::new(
            DiffEntrySubject::File,
            path("src/other.rs")?,
            None,
            DiffChangeKind::Modified,
            DiffLineCount::new(8),
            DiffLineCount::new(3),
        )?];
        assert_eq!(
            TreeChangeSetIntent::from_plan_with_diff_entries(
                attribution(40),
                vec![id],
                &plan,
                crate::TimestampMillis::new(1)?,
                wrong_path,
            )
            .err(),
            Some(TreeChangeSetIntentError::DiffEntriesMismatch)
        );
        assert_eq!(
            TreeChangeSetIntent::from_plan_with_diff_entries(
                attribution(40),
                vec![id],
                &plan,
                crate::TimestampMillis::new(1)?,
                Vec::new(),
            )
            .err(),
            Some(TreeChangeSetIntentError::DiffEntriesMismatch)
        );
        Ok(())
    }

    #[test]
    fn empty_plan_is_rejected() {
        assert_eq!(
            TreeChangeSetPlan::new(Vec::new()).err(),
            Some(TreeChangeSetPlanError::Empty)
        );
    }
}
