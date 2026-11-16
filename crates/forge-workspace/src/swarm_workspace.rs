//! Isolated Swarm member workspace provisioning (`Inherit`, `Share`, `Branch`),
//! deterministic 3-way merge convergence, and crash-safe canonical/hybrid
//! settlement (`StandaloneSwarm` vs `DagNodeHybrid`).
//!
//! Architecture & Isolation Boundaries:
//! - **Bare Git Store (`dag-store.git`)**:
//!   Reuses `<workspace_root>/.heterarchy-forge/artifacts/node-workspaces/dag-store.git`
//!   with Swarm-scoped refs `refs/forge/swarm/<swarm_run_id>/base`,
//!   `refs/forge/swarm/<swarm_run_id>/member/<member_id>`, and
//!   `refs/forge/swarm/<swarm_run_id>/converged`.
//! - **External Runtime Worktrees**:
//!   Always materialized outside `<workspace_root>` and strictly forbidden under
//!   `/Volumes/256.SSD/RustBuild` (checked lexically, normalized, and across symlinks).
//! - **Modes**:
//!   - `Inherit`: read/verify-only view pinned to a baseline or candidate tree; refuses
//!     `capture_member_output` if any file mutated and never emits divergent output commits.
//!   - `Share`: isolated external worktree backed by `dag-store.git` member ref.
//!   - `Branch`: isolated standalone Git clone with independent `.git` metadata outside
//!     `<workspace_root>`, importing the resulting tree into `dag-store.git` on capture.
//! - **Settlement**:
//!   - `StandaloneSwarm`: enforces `Preimage CAS` against `baseline_tree_blake3`, writes
//!     crash-safe `Prepared -> Applied` journal at
//!     `.heterarchy-forge/recovery/swarm-settlements/<swarm_run_id>/settlement.journal`,
//!     and atomically applies the converged tree to `<workspace_root>`.
//!   - `DagNodeHybrid`: materializes into the owning DAG node's isolated worktree
//!     without mutating `<workspace_root>` directly.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use forge_domain::{DagNodeId, DagRevisionNumber, GoalId, TimestampMillis, WorkspaceId};
pub use forge_domain::{SwarmMemberId, SwarmRunId, SwarmSettlementTarget, SwarmWorkspaceMode};
use thiserror::Error;

pub use crate::dag_git_store::SettlementJournalState;
use crate::dag_git_store::{
    GitTreeStoreError, PinnedBaseline, SETTLEMENT_JOURNAL_NAME, TreeManifest,
    apply_candidate_to_dir, checkout_commit_to_dir, commit_manifest_from_dir,
    commit_manifest_store_path, compute_manifest_delta, create_git_commit, dag_git_store_dir,
    delete_git_ref, diff_manifest_paths, encode_tree_manifest_file, ensure_dag_git_store,
    find_drifted_paths, next_staging_nonce, parse_tree_manifest_file, run_git_in_workdir,
    run_git_merge_base_all, run_git_merge_tree, scan_tree_entries, three_way_merge_manifests,
    update_git_ref, write_atomic_file,
};
use crate::{
    ExistingWorkspaceStateLayout, FORGE_GIT_PROGRAM, NodeWorkspaceError, StateLayoutError,
    inspect_node_workspace,
};

mod manifests;
mod path_policy;
mod sha256;
#[cfg(test)]
mod tests;

use manifests::{
    COMPLETED_MANIFEST_NAME, HANDOFF_MANIFEST_NAME, baseline_manifest_path,
    compute_transition_diff_digest_for_paths, encode_baseline_manifest, encode_completed_manifest,
    encode_handoff_manifest, encode_settlement_journal, member_metadata_dir,
    parse_baseline_manifest, parse_completed_manifest, parse_handoff_manifest,
    parse_settlement_journal, swarm_base_ref, swarm_converged_ref, swarm_member_ref,
    swarm_run_metadata_dir, swarm_settlement_dir,
};
use path_policy::{
    resolve_swarm_external_worktree_path, resolve_swarm_scope_dir, validate_external_worktree_path,
};

/// Durable receipt describing a provisioned isolated workspace for one Swarm member.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmWorkspaceReceipt {
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    mode: SwarmWorkspaceMode,
    target: SwarmSettlementTarget,
    worktree_path: PathBuf,
    provisioned_at: TimestampMillis,
    initial_tree_blake3: String,
    initial_file_count: u64,
    input_commit_oid: String,
    completed: Option<SwarmMemberOutputReceipt>,
}

impl SwarmWorkspaceReceipt {
    pub const fn swarm_run_id(&self) -> SwarmRunId {
        self.swarm_run_id
    }

    pub const fn member_id(&self) -> SwarmMemberId {
        self.member_id
    }

    pub const fn mode(&self) -> SwarmWorkspaceMode {
        self.mode
    }

    pub const fn target(&self) -> SwarmSettlementTarget {
        self.target
    }

    pub fn worktree_path(&self) -> &Path {
        &self.worktree_path
    }

    pub const fn provisioned_at(&self) -> TimestampMillis {
        self.provisioned_at
    }

    pub fn initial_tree_blake3(&self) -> &str {
        &self.initial_tree_blake3
    }

    pub const fn initial_file_count(&self) -> u64 {
        self.initial_file_count
    }

    pub fn input_commit_oid(&self) -> &str {
        &self.input_commit_oid
    }

    pub const fn completed(&self) -> Option<&SwarmMemberOutputReceipt> {
        self.completed.as_ref()
    }
}

/// Sealed capture receipt for one Swarm member's isolated workspace output.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmMemberOutputReceipt {
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    mode: SwarmWorkspaceMode,
    input_commit_oid: String,
    output_commit_oid: String,
    initial_tree_blake3: String,
    final_tree_blake3: String,
    final_file_count: u64,
    changed_paths: Vec<String>,
    diff_digest: [u8; 32],
    captured_at: TimestampMillis,
}

impl SwarmMemberOutputReceipt {
    pub const fn swarm_run_id(&self) -> SwarmRunId {
        self.swarm_run_id
    }

    pub const fn member_id(&self) -> SwarmMemberId {
        self.member_id
    }

    pub const fn mode(&self) -> SwarmWorkspaceMode {
        self.mode
    }

    pub fn input_commit_oid(&self) -> &str {
        &self.input_commit_oid
    }

    pub fn output_commit_oid(&self) -> &str {
        &self.output_commit_oid
    }

    pub fn initial_tree_blake3(&self) -> &str {
        &self.initial_tree_blake3
    }

    pub fn final_tree_blake3(&self) -> &str {
        &self.final_tree_blake3
    }

    pub const fn final_file_count(&self) -> u64 {
        self.final_file_count
    }

    pub fn changed_paths(&self) -> &[String] {
        &self.changed_paths
    }

    pub const fn diff_digest(&self) -> [u8; 32] {
        self.diff_digest
    }

    pub const fn captured_at(&self) -> TimestampMillis {
        self.captured_at
    }
}

/// Typed outcome of deterministic 3-way merge convergence across Swarm member outputs.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmConvergenceOutcome {
    Converged {
        converged_commit_oid: String,
        converged_tree_blake3: String,
        converged_diff_digest: [u8; 32],
        changed_files: Vec<String>,
    },
    Conflict {
        conflicting_member_id: SwarmMemberId,
        details: Vec<String>,
    },
}

/// Return whether `path` resolves inside the forbidden `/Volumes/256.SSD/RustBuild` root.
pub fn is_forbidden_ssd_worktree_path(path: &Path) -> bool {
    path_policy::is_forbidden_ssd_path(path)
}

/// Receipt emitted by `settle_standalone_swarm_workspace` or
/// `materialize_dag_node_hybrid_swarm_workspace` and read back by `inspect_swarm_settlement`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmSettlementReceipt {
    settlement_id: String,
    swarm_run_id: SwarmRunId,
    target: SwarmSettlementTarget,
    state: SettlementJournalState,
    settled_at: TimestampMillis,
    baseline_commit_oid: String,
    converged_commit_oid: String,
    baseline_tree_blake3: String,
    settled_tree_blake3: String,
    converged_diff_digest: [u8; 32],
    settled_file_count: u64,
    upserted_paths: Vec<String>,
    deleted_paths: Vec<String>,
}

impl SwarmSettlementReceipt {
    pub fn settlement_id(&self) -> &str {
        &self.settlement_id
    }

    pub const fn swarm_run_id(&self) -> SwarmRunId {
        self.swarm_run_id
    }

    pub const fn target(&self) -> SwarmSettlementTarget {
        self.target
    }

    pub const fn state(&self) -> SettlementJournalState {
        self.state
    }

    pub const fn settled_at(&self) -> TimestampMillis {
        self.settled_at
    }

    pub fn baseline_commit_oid(&self) -> &str {
        &self.baseline_commit_oid
    }

    pub fn converged_commit_oid(&self) -> &str {
        &self.converged_commit_oid
    }

    pub fn baseline_tree_blake3(&self) -> &str {
        &self.baseline_tree_blake3
    }

    pub fn settled_tree_blake3(&self) -> &str {
        &self.settled_tree_blake3
    }

    pub const fn converged_diff_digest(&self) -> [u8; 32] {
        self.converged_diff_digest
    }

    pub const fn settled_file_count(&self) -> u64 {
        self.settled_file_count
    }

    pub fn upserted_paths(&self) -> &[String] {
        &self.upserted_paths
    }

    pub fn deleted_paths(&self) -> &[String] {
        &self.deleted_paths
    }
}

/// Typed failure modes for Swarm workspace isolation, capture, convergence, and settlement.
#[derive(Debug, Error)]
pub enum SwarmWorkspaceError {
    #[error("swarm workspace I/O failed during {context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("swarm workspace Git operation failed during {context}: {detail}")]
    GitCommandFailed {
        context: &'static str,
        detail: String,
    },
    #[error("swarm workspace manifest at {} is corrupt: {reason}", path.display())]
    CorruptManifest { path: PathBuf, reason: &'static str },
    #[error("swarm workspace relative path {path:?} is invalid")]
    InvalidRelativePath { path: String },
    #[error(
        "unsupported filesystem entry {path:?} in swarm workspace tree (symlinks and special files are forbidden)"
    )]
    UnsupportedWorkspaceEntry { path: String },
    #[error("swarm runtime worktree root {} is forbidden under /Volumes/256.SSD/RustBuild", path.display())]
    ForbiddenSsdWorktreeRoot { path: PathBuf },
    #[error(
        "swarm runtime worktree path {} must remain outside workspace root {}",
        path.display(),
        workspace_root.display()
    )]
    WorktreeInsideWorkspaceRoot {
        path: PathBuf,
        workspace_root: PathBuf,
    },
    #[error("swarm external worktree root {} is invalid: {reason}", path.display())]
    InvalidExternalWorktreeRoot { path: PathBuf, reason: &'static str },
    #[error("swarm run {swarm_run_id} has no pinned baseline")]
    BaselineNotPinned { swarm_run_id: SwarmRunId },
    #[error("swarm run {swarm_run_id} settlement target does not match pinned baseline")]
    TargetMismatch { swarm_run_id: SwarmRunId },
    #[error("swarm member {member_id} for run {swarm_run_id} was not provisioned")]
    MemberWorkspaceNotProvisioned {
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
    },
    #[error(
        "swarm member {member_id} for run {swarm_run_id} was provisioned as {expected}, cannot re-provision as {actual}"
    )]
    MemberModeMismatch {
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
        expected: SwarmWorkspaceMode,
        actual: SwarmWorkspaceMode,
    },
    #[error(
        "swarm Inherit member {member_id} for run {swarm_run_id} mutated read-only view on paths {changed_paths:?}"
    )]
    InheritWorkspaceMutated {
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
        changed_paths: Vec<String>,
    },
    #[error(
        "swarm Inherit member {member_id} for run {swarm_run_id} cannot contribute candidate commits to convergence"
    )]
    InheritCannotContributeCandidate {
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
    },
    #[error(
        "swarm convergence for run {swarm_run_id} requires at least one Share or Branch candidate"
    )]
    EmptyConvergenceCandidates { swarm_run_id: SwarmRunId },
    #[error(
        "swarm convergence for run {swarm_run_id} received duplicate candidate member {member_id}"
    )]
    DuplicateConvergenceMember {
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
    },
    #[error("swarm convergence candidate {member_id} for run {swarm_run_id} is invalid: {reason}")]
    ConvergenceCandidateMismatch {
        swarm_run_id: SwarmRunId,
        member_id: SwarmMemberId,
        reason: &'static str,
    },
    #[error(
        "hybrid swarm run {swarm_run_id} target DAG node {goal_id} rev {} node {node_id} is not provisioned",
        dag_revision.get()
    )]
    HybridTargetNodeNotProvisioned {
        swarm_run_id: SwarmRunId,
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    },
    #[error(
        "hybrid swarm run {swarm_run_id} target DAG node {goal_id} rev {} node {node_id} is already completed/sealed",
        dag_revision.get()
    )]
    HybridTargetNodeAlreadySealed {
        swarm_run_id: SwarmRunId,
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    },
    #[error("swarm settlement for run {swarm_run_id} failed converged diff digest verification")]
    SettlementDiffDigestMismatch { swarm_run_id: SwarmRunId },
    #[error(
        "swarm settlement target drifted from pinned baseline for run {swarm_run_id} on paths {modified_paths:?}"
    )]
    SettlementBaselineConflict {
        swarm_run_id: SwarmRunId,
        modified_paths: Vec<String>,
    },
    #[error(
        "swarm settlement {settlement_id} for run {swarm_run_id} requires recovery due to drifted paths {drifted_paths:?}"
    )]
    SettlementRecoveryRequired {
        swarm_run_id: SwarmRunId,
        settlement_id: String,
        drifted_paths: Vec<String>,
    },
    #[error(transparent)]
    StateLayout(#[from] StateLayoutError),
    #[error(transparent)]
    NodeWorkspace(#[from] NodeWorkspaceError),
}

impl From<GitTreeStoreError> for SwarmWorkspaceError {
    fn from(error: GitTreeStoreError) -> Self {
        match error {
            GitTreeStoreError::Io { context, source } => Self::Io { context, source },
            GitTreeStoreError::GitCommandFailed { context, detail } => {
                Self::GitCommandFailed { context, detail }
            }
            GitTreeStoreError::CorruptManifest { path, reason } => {
                Self::CorruptManifest { path, reason }
            }
            GitTreeStoreError::InvalidRelativePath { path } => Self::InvalidRelativePath { path },
            GitTreeStoreError::UnsupportedWorkspaceEntry { path } => {
                Self::UnsupportedWorkspaceEntry { path }
            }
            GitTreeStoreError::StateLayout(err) => Self::StateLayout(err),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SwarmPinnedBaseline {
    pub(super) target: SwarmSettlementTarget,
    pub(super) baseline: PinnedBaseline,
}

struct TempDirGuard(Option<PathBuf>);

impl TempDirGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

/// Provision an isolated Swarm member workspace using the default non-SSD external worktree root.
#[allow(clippy::too_many_arguments)]
pub fn provision_swarm_member_workspace(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    mode: SwarmWorkspaceMode,
    target: SwarmSettlementTarget,
    candidate_commit_oid: Option<&str>,
    observed_at: TimestampMillis,
) -> Result<SwarmWorkspaceReceipt, SwarmWorkspaceError> {
    provision_swarm_member_workspace_in(
        layout,
        None,
        None,
        swarm_run_id,
        member_id,
        mode,
        target,
        candidate_commit_oid,
        observed_at,
    )
}

/// Provision an isolated Swarm member workspace under an explicit external worktrees root.
///
/// Rejects any path resolving inside `/Volumes/256.SSD/RustBuild` or inside `<workspace_root>`.
#[allow(clippy::too_many_arguments)]
pub fn provision_swarm_member_workspace_in(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    mode: SwarmWorkspaceMode,
    target: SwarmSettlementTarget,
    candidate_commit_oid: Option<&str>,
    observed_at: TimestampMillis,
) -> Result<SwarmWorkspaceReceipt, SwarmWorkspaceError> {
    let worktree_dir = resolve_swarm_external_worktree_path(
        layout,
        external_worktrees_root,
        workspace_id,
        swarm_run_id,
        member_id,
    )?;

    ensure_dag_git_store(layout)?;
    let pinned = pin_or_load_swarm_baseline(layout, swarm_run_id, target, observed_at)?;
    if pinned.target != target {
        return Err(SwarmWorkspaceError::TargetMismatch { swarm_run_id });
    }

    let (input_commit_oid, input_manifest) = match candidate_commit_oid {
        Some(oid) => {
            let manifest = parse_tree_manifest_file(&commit_manifest_store_path(layout, oid))?;
            (oid.to_owned(), manifest)
        }
        None => (pinned.baseline.base_commit_oid, pinned.baseline.manifest),
    };

    if let Some(existing) = reuse_existing_member_workspace(
        layout,
        swarm_run_id,
        member_id,
        mode,
        target,
        &input_commit_oid,
    )? {
        return Ok(existing);
    }

    materialize_member_worktree(
        layout,
        swarm_run_id,
        member_id,
        mode,
        &input_commit_oid,
        &input_manifest,
        &worktree_dir,
        observed_at,
    )?;

    if matches!(mode, SwarmWorkspaceMode::Share | SwarmWorkspaceMode::Branch) {
        let git_dir = dag_git_store_dir(layout);
        let member_ref = swarm_member_ref(swarm_run_id, member_id);
        update_git_ref(&git_dir, &member_ref, &input_commit_oid, observed_at)?;
    }

    let member_meta_dir = member_metadata_dir(layout, swarm_run_id, member_id);
    fs::create_dir_all(&member_meta_dir).map_err(|source| SwarmWorkspaceError::Io {
        context: "creating swarm member metadata directory",
        source,
    })?;

    let initial_file_count = u64::try_from(input_manifest.entries.len()).unwrap_or(u64::MAX);
    let receipt = SwarmWorkspaceReceipt {
        swarm_run_id,
        member_id,
        mode,
        target,
        worktree_path: worktree_dir,
        provisioned_at: observed_at,
        initial_tree_blake3: input_manifest.tree_blake3.clone(),
        initial_file_count,
        input_commit_oid,
        completed: None,
    };

    let manifest_bytes = encode_handoff_manifest(&receipt, &input_manifest);
    write_atomic_file(
        &member_meta_dir.join(HANDOFF_MANIFEST_NAME),
        &manifest_bytes,
    )?;
    Ok(receipt)
}

fn reuse_existing_member_workspace(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    mode: SwarmWorkspaceMode,
    target: SwarmSettlementTarget,
    input_commit_oid: &str,
) -> Result<Option<SwarmWorkspaceReceipt>, SwarmWorkspaceError> {
    let Some(existing) = inspect_swarm_member_workspace(layout, swarm_run_id, member_id)? else {
        return Ok(None);
    };
    if existing.mode != mode {
        return Err(SwarmWorkspaceError::MemberModeMismatch {
            swarm_run_id,
            member_id,
            expected: existing.mode,
            actual: mode,
        });
    }
    if existing.target != target {
        return Err(SwarmWorkspaceError::TargetMismatch { swarm_run_id });
    }
    if existing.input_commit_oid != input_commit_oid {
        return Err(SwarmWorkspaceError::CorruptManifest {
            path: member_metadata_dir(layout, swarm_run_id, member_id).join(HANDOFF_MANIFEST_NAME),
            reason: "member input commit OID differs from existing handoff receipt",
        });
    }
    if !existing.worktree_path.is_dir() {
        return Ok(None);
    }
    validate_external_worktree_path(&existing.worktree_path, layout.workspace_root())?;
    Ok(Some(existing))
}

#[allow(clippy::too_many_arguments)]
fn materialize_member_worktree(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    mode: SwarmWorkspaceMode,
    input_commit_oid: &str,
    input_manifest: &TreeManifest,
    worktree_dir: &Path,
    observed_at: TimestampMillis,
) -> Result<(), SwarmWorkspaceError> {
    let worktree_parent =
        worktree_dir
            .parent()
            .ok_or_else(|| SwarmWorkspaceError::CorruptManifest {
                path: worktree_dir.to_path_buf(),
                reason: "worktree path has no parent directory",
            })?;
    fs::create_dir_all(worktree_parent).map_err(|source| SwarmWorkspaceError::Io {
        context: "creating external swarm worktree parent directory",
        source,
    })?;

    let nonce = next_staging_nonce();
    let staging_dir = worktree_parent.join(format!(
        ".swarm-worktree.staging.{}.{nonce}",
        std::process::id()
    ));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir).map_err(|source| SwarmWorkspaceError::Io {
            context: "cleaning stale swarm staging worktree",
            source,
        })?;
    }
    fs::create_dir_all(&staging_dir).map_err(|source| SwarmWorkspaceError::Io {
        context: "creating swarm staging worktree directory",
        source,
    })?;
    let mut staging_guard = TempDirGuard(Some(staging_dir.clone()));

    match mode {
        SwarmWorkspaceMode::Inherit | SwarmWorkspaceMode::Share => {
            if !input_manifest.entries.is_empty() {
                checkout_commit_to_dir(layout, input_commit_oid, &staging_dir)?;
            }
        }
        SwarmWorkspaceMode::Branch => initialize_standalone_branch_clone(
            layout,
            swarm_run_id,
            member_id,
            input_commit_oid,
            &staging_dir,
            observed_at,
        )?,
    }

    let materialized_manifest = scan_tree_entries(&staging_dir)?;
    if materialized_manifest.tree_blake3 != input_manifest.tree_blake3 {
        return Err(SwarmWorkspaceError::CorruptManifest {
            path: staging_dir,
            reason: "materialized swarm worktree digest did not match input commit manifest",
        });
    }

    if worktree_dir.exists() {
        fs::remove_dir_all(worktree_dir).map_err(|source| SwarmWorkspaceError::Io {
            context: "replacing partial swarm worktree directory",
            source,
        })?;
    }
    fs::rename(&staging_dir, worktree_dir).map_err(|source| SwarmWorkspaceError::Io {
        context: "promoting swarm staging worktree directory",
        source,
    })?;
    staging_guard.disarm();
    Ok(())
}

/// Inspect the durable receipt for one Swarm member workspace.
pub fn inspect_swarm_member_workspace(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
) -> Result<Option<SwarmWorkspaceReceipt>, SwarmWorkspaceError> {
    let member_meta_dir = member_metadata_dir(layout, swarm_run_id, member_id);
    let handoff_path = member_meta_dir.join(HANDOFF_MANIFEST_NAME);
    if !handoff_path.exists() {
        return Ok(None);
    }
    let (mut receipt, _) = parse_handoff_manifest(&handoff_path)?;
    if receipt.swarm_run_id != swarm_run_id || receipt.member_id != member_id {
        return Err(SwarmWorkspaceError::CorruptManifest {
            path: handoff_path,
            reason: "swarm member handoff identity does not match directory path",
        });
    }
    let completed_path = member_meta_dir.join(COMPLETED_MANIFEST_NAME);
    if completed_path.exists() {
        let completed = parse_completed_manifest(&completed_path)?;
        if completed.swarm_run_id != swarm_run_id
            || completed.member_id != member_id
            || completed.mode != receipt.mode
        {
            return Err(SwarmWorkspaceError::CorruptManifest {
                path: completed_path,
                reason: "swarm member completed receipt does not match handoff identity",
            });
        }
        receipt.completed = Some(completed);
    }
    Ok(Some(receipt))
}

/// Capture and seal the output state of a Swarm member's external workspace.
///
/// - `Inherit`: refuses capture with `InheritWorkspaceMutated` if any file was added,
///   modified, or deleted, and never creates a divergent commit or `member/<id>` ref.
/// - `Share`: commits resulting tree into `dag-store.git` under
///   `refs/forge/swarm/<swarm_run_id>/member/<member_id>` and computes canonical `diff_digest`.
/// - `Branch`: imports the standalone clone's working tree back into `dag-store.git` under
///   `refs/forge/swarm/<swarm_run_id>/member/<member_id>`.
pub fn capture_member_output(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    captured_at: TimestampMillis,
) -> Result<SwarmMemberOutputReceipt, SwarmWorkspaceError> {
    let active_receipt = inspect_swarm_member_workspace(layout, swarm_run_id, member_id)?.ok_or(
        SwarmWorkspaceError::MemberWorkspaceNotProvisioned {
            swarm_run_id,
            member_id,
        },
    )?;
    validate_external_worktree_path(&active_receipt.worktree_path, layout.workspace_root())?;
    ensure_dag_git_store(layout)?;

    let input_manifest = parse_tree_manifest_file(&commit_manifest_store_path(
        layout,
        &active_receipt.input_commit_oid,
    ))?;
    let final_manifest = scan_tree_entries(&active_receipt.worktree_path)?;
    let changed_paths = diff_manifest_paths(&input_manifest, &final_manifest);
    let diff_digest =
        compute_transition_diff_digest_for_paths(&input_manifest, &final_manifest, &changed_paths);

    let output_commit_oid = match active_receipt.mode {
        SwarmWorkspaceMode::Inherit => {
            if !changed_paths.is_empty()
                || final_manifest.tree_blake3 != active_receipt.initial_tree_blake3
            {
                return Err(SwarmWorkspaceError::InheritWorkspaceMutated {
                    swarm_run_id,
                    member_id,
                    changed_paths,
                });
            }
            active_receipt.input_commit_oid.clone()
        }
        SwarmWorkspaceMode::Share | SwarmWorkspaceMode::Branch => {
            let member_ref = swarm_member_ref(swarm_run_id, member_id);
            if changed_paths.is_empty()
                && final_manifest.tree_blake3 == active_receipt.initial_tree_blake3
            {
                let git_dir = dag_git_store_dir(layout);
                update_git_ref(
                    &git_dir,
                    &member_ref,
                    &active_receipt.input_commit_oid,
                    captured_at,
                )?;
                active_receipt.input_commit_oid.clone()
            } else {
                commit_manifest_from_dir(
                    layout,
                    &active_receipt.worktree_path,
                    &final_manifest,
                    std::slice::from_ref(&active_receipt.input_commit_oid),
                    Some(&member_ref),
                    &format!("forge swarm {swarm_run_id} member {member_id} output"),
                    captured_at,
                )?
            }
        }
    };

    let output_receipt = SwarmMemberOutputReceipt {
        swarm_run_id,
        member_id,
        mode: active_receipt.mode,
        input_commit_oid: active_receipt.input_commit_oid,
        output_commit_oid,
        initial_tree_blake3: active_receipt.initial_tree_blake3,
        final_tree_blake3: final_manifest.tree_blake3,
        final_file_count: u64::try_from(final_manifest.entries.len()).unwrap_or(u64::MAX),
        changed_paths,
        diff_digest,
        captured_at,
    };

    let completed_path =
        member_metadata_dir(layout, swarm_run_id, member_id).join(COMPLETED_MANIFEST_NAME);
    write_atomic_file(&completed_path, &encode_completed_manifest(&output_receipt))?;
    Ok(output_receipt)
}

/// Deterministically 3-way merge ordered `Share`/`Branch` member `output_commit_oid`s
/// in `dag-store.git` starting from `baseline_commit_oid`.
///
/// Rejects any `Inherit` candidate, empty candidate list, duplicate member IDs, or
/// cross-run receipts. Returns `SwarmConvergenceOutcome::Conflict` on merge conflict.
pub fn converge_swarm_candidates(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    candidates: &[SwarmMemberOutputReceipt],
    observed_at: TimestampMillis,
) -> Result<SwarmConvergenceOutcome, SwarmWorkspaceError> {
    if candidates.is_empty() {
        return Err(SwarmWorkspaceError::EmptyConvergenceCandidates { swarm_run_id });
    }
    ensure_dag_git_store(layout)?;
    let pinned = load_swarm_baseline(layout, swarm_run_id)?;
    let verified_candidates = validate_convergence_candidates(layout, swarm_run_id, candidates)?;

    let git_dir = dag_git_store_dir(layout);
    let base_oid = pinned.baseline.base_commit_oid.as_str();
    let mut acc_commit_oid = base_oid.to_owned();
    let mut acc_manifest: Cow<'_, TreeManifest> = Cow::Borrowed(&pinned.baseline.manifest);

    for (candidate, right_manifest) in verified_candidates {
        if candidate.output_commit_oid == acc_commit_oid || candidate.output_commit_oid == base_oid
        {
            continue;
        }
        if acc_commit_oid == base_oid && candidate.input_commit_oid == base_oid {
            acc_commit_oid.clone_from(&candidate.output_commit_oid);
            acc_manifest = Cow::Owned(right_manifest);
            continue;
        }
        match merge_candidate_into_accumulator(
            layout,
            &git_dir,
            swarm_run_id,
            &acc_commit_oid,
            acc_manifest.as_ref(),
            candidate,
            &right_manifest,
            observed_at,
        )? {
            CandidateMergeStep::Merged {
                commit_oid,
                manifest,
            } => {
                acc_commit_oid = commit_oid;
                acc_manifest = Cow::Owned(manifest);
            }
            CandidateMergeStep::Conflict(details) => {
                return Ok(SwarmConvergenceOutcome::Conflict {
                    conflicting_member_id: candidate.member_id,
                    details,
                });
            }
        }
    }

    let converged_ref = swarm_converged_ref(swarm_run_id);
    update_git_ref(&git_dir, &converged_ref, &acc_commit_oid, observed_at)?;

    let changed_files = diff_manifest_paths(&pinned.baseline.manifest, acc_manifest.as_ref());
    let converged_diff_digest = compute_transition_diff_digest_for_paths(
        &pinned.baseline.manifest,
        acc_manifest.as_ref(),
        &changed_files,
    );
    let converged_tree_blake3 = match acc_manifest {
        Cow::Borrowed(manifest) => manifest.tree_blake3.clone(),
        Cow::Owned(manifest) => manifest.tree_blake3,
    };

    Ok(SwarmConvergenceOutcome::Converged {
        converged_commit_oid: acc_commit_oid,
        converged_tree_blake3,
        converged_diff_digest,
        changed_files,
    })
}

fn validate_convergence_candidates<'a>(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    candidates: &'a [SwarmMemberOutputReceipt],
) -> Result<Vec<(&'a SwarmMemberOutputReceipt, TreeManifest)>, SwarmWorkspaceError> {
    let mut seen_members = BTreeSet::new();
    let mut verified = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.swarm_run_id != swarm_run_id {
            return Err(SwarmWorkspaceError::ConvergenceCandidateMismatch {
                swarm_run_id,
                member_id: candidate.member_id,
                reason: "candidate belongs to a different swarm run",
            });
        }
        if !seen_members.insert(candidate.member_id) {
            return Err(SwarmWorkspaceError::DuplicateConvergenceMember {
                swarm_run_id,
                member_id: candidate.member_id,
            });
        }
        if candidate.mode == SwarmWorkspaceMode::Inherit {
            return Err(SwarmWorkspaceError::InheritCannotContributeCandidate {
                swarm_run_id,
                member_id: candidate.member_id,
            });
        }
        let manifest = parse_tree_manifest_file(&commit_manifest_store_path(
            layout,
            &candidate.output_commit_oid,
        ))?;
        if manifest.tree_blake3 != candidate.final_tree_blake3 {
            return Err(SwarmWorkspaceError::ConvergenceCandidateMismatch {
                swarm_run_id,
                member_id: candidate.member_id,
                reason: "candidate commit manifest digest does not match output receipt",
            });
        }
        verified.push((candidate, manifest));
    }
    Ok(verified)
}

enum CandidateMergeStep {
    Merged {
        commit_oid: String,
        manifest: TreeManifest,
    },
    Conflict(Vec<String>),
}

#[allow(clippy::too_many_arguments)]
fn merge_candidate_into_accumulator(
    layout: &ExistingWorkspaceStateLayout,
    git_dir: &Path,
    swarm_run_id: SwarmRunId,
    acc_commit_oid: &str,
    acc_manifest: &TreeManifest,
    candidate: &SwarmMemberOutputReceipt,
    right_manifest: &TreeManifest,
    observed_at: TimestampMillis,
) -> Result<CandidateMergeStep, SwarmWorkspaceError> {
    let merge_bases = run_git_merge_base_all(
        git_dir,
        acc_commit_oid,
        &candidate.output_commit_oid,
        observed_at,
    )?;
    if merge_bases.len() != 1 {
        return Ok(CandidateMergeStep::Conflict(vec![
            "<ambiguous-merge-base>".to_owned(),
        ]));
    }
    let base_manifest =
        parse_tree_manifest_file(&commit_manifest_store_path(layout, &merge_bases[0]))?;

    let merged_tree_oid =
        match run_git_merge_tree(git_dir, acc_commit_oid, &candidate.output_commit_oid)? {
            Ok(tree_oid) => tree_oid,
            Err(details) => return Ok(CandidateMergeStep::Conflict(details)),
        };

    let (merged_manifest, manifest_conflicts) = three_way_merge_manifests(
        git_dir,
        &merged_tree_oid,
        &base_manifest,
        acc_manifest,
        right_manifest,
    )?;
    if !manifest_conflicts.is_empty() {
        return Ok(CandidateMergeStep::Conflict(manifest_conflicts));
    }

    let parents = [acc_commit_oid, candidate.output_commit_oid.as_str()];
    let merged_commit_oid = create_git_commit(
        git_dir,
        &merged_tree_oid,
        &parents,
        &format!(
            "forge swarm {swarm_run_id} 3-way merge member {}",
            candidate.member_id
        ),
        observed_at,
    )?;
    write_atomic_file(
        &commit_manifest_store_path(layout, &merged_commit_oid),
        &encode_tree_manifest_file(&merged_manifest),
    )?;
    Ok(CandidateMergeStep::Merged {
        commit_oid: merged_commit_oid,
        manifest: merged_manifest,
    })
}

/// Settle a `StandaloneSwarm` converged tree into `<workspace_root>` with strict `Preimage CAS`
/// and a crash-safe `Prepared -> Applied` settlement journal under
/// `.heterarchy-forge/recovery/swarm-settlements/<swarm_run_id>/settlement.journal`.
pub fn settle_standalone_swarm_workspace(
    layout: &ExistingWorkspaceStateLayout,
    settlement_id: &str,
    swarm_run_id: SwarmRunId,
    converged_commit_oid: &str,
    expected_diff_digest: Option<[u8; 32]>,
    settled_at: TimestampMillis,
) -> Result<SwarmSettlementReceipt, SwarmWorkspaceError> {
    let pinned = load_swarm_baseline(layout, swarm_run_id)?;
    if pinned.target != SwarmSettlementTarget::StandaloneSwarm {
        return Err(SwarmWorkspaceError::TargetMismatch { swarm_run_id });
    }
    settle_swarm_to_directory(
        layout,
        &pinned,
        settlement_id,
        swarm_run_id,
        layout.workspace_root(),
        converged_commit_oid,
        expected_diff_digest,
        settled_at,
    )
}

/// Materialize a `DagNodeHybrid` micro-swarm's converged tree into the owning DAG node's
/// isolated external worktree without mutating `<workspace_root>` directly.
#[allow(clippy::too_many_arguments)]
pub fn materialize_dag_node_hybrid_swarm_workspace(
    layout: &ExistingWorkspaceStateLayout,
    settlement_id: &str,
    swarm_run_id: SwarmRunId,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
    converged_commit_oid: &str,
    expected_diff_digest: Option<[u8; 32]>,
    settled_at: TimestampMillis,
) -> Result<SwarmSettlementReceipt, SwarmWorkspaceError> {
    let expected_target = SwarmSettlementTarget::DagNodeHybrid {
        goal_id,
        dag_revision,
        node_id,
    };
    let pinned = load_swarm_baseline(layout, swarm_run_id)?;
    if pinned.target != expected_target {
        return Err(SwarmWorkspaceError::TargetMismatch { swarm_run_id });
    }
    let node_receipt = inspect_node_workspace(layout, goal_id, dag_revision, node_id)?.ok_or(
        SwarmWorkspaceError::HybridTargetNodeNotProvisioned {
            swarm_run_id,
            goal_id,
            dag_revision,
            node_id,
        },
    )?;
    if node_receipt.completed().is_some() {
        return Err(SwarmWorkspaceError::HybridTargetNodeAlreadySealed {
            swarm_run_id,
            goal_id,
            dag_revision,
            node_id,
        });
    }
    validate_external_worktree_path(node_receipt.worktree_path(), layout.workspace_root())?;
    settle_swarm_to_directory(
        layout,
        &pinned,
        settlement_id,
        swarm_run_id,
        node_receipt.worktree_path(),
        converged_commit_oid,
        expected_diff_digest,
        settled_at,
    )
}

/// Inspect the durable settlement receipt for `swarm_run_id`, if present.
pub fn inspect_swarm_settlement(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
) -> Result<Option<SwarmSettlementReceipt>, SwarmWorkspaceError> {
    let journal_path = swarm_settlement_dir(layout, swarm_run_id).join(SETTLEMENT_JOURNAL_NAME);
    if !journal_path.exists() {
        return Ok(None);
    }
    parse_settlement_journal(&journal_path).map(Some)
}

/// Remove all Swarm workspace manifests, baselines, settlement journals, git refs,
/// and external worktrees for `swarm_run_id`.
pub fn purge_swarm_workspaces(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    swarm_run_id: SwarmRunId,
) -> Result<(), SwarmWorkspaceError> {
    let run_meta_dir = swarm_run_metadata_dir(layout, swarm_run_id);
    if run_meta_dir.exists() {
        fs::remove_dir_all(&run_meta_dir).map_err(|source| SwarmWorkspaceError::Io {
            context: "removing swarm run workspace metadata",
            source,
        })?;
    }
    let settlement_dir = swarm_settlement_dir(layout, swarm_run_id);
    if settlement_dir.exists() {
        fs::remove_dir_all(&settlement_dir).map_err(|source| SwarmWorkspaceError::Io {
            context: "removing swarm settlement journal",
            source,
        })?;
    }
    if let Ok(scope_root) = resolve_swarm_scope_dir(layout, external_worktrees_root, workspace_id) {
        let external_run_dir = scope_root.join(swarm_run_id.to_string());
        if external_run_dir.exists() {
            let _ = fs::remove_dir_all(&external_run_dir);
        }
    }
    let git_dir = dag_git_store_dir(layout);
    if git_dir.join("HEAD").exists() {
        let prefix = format!("refs/forge/swarm/{swarm_run_id}/");
        if let Ok(dummy_ts) = TimestampMillis::new(1)
            && let Ok(refs_raw) = run_git_in_workdir(
                &git_dir,
                &["for-each-ref", "--format=%(refname)", &prefix],
                dummy_ts,
            )
        {
            for ref_name in refs_raw.lines().map(str::trim).filter(|r| !r.is_empty()) {
                let _ = delete_git_ref(&git_dir, ref_name, dummy_ts);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn settle_swarm_to_directory(
    layout: &ExistingWorkspaceStateLayout,
    pinned: &SwarmPinnedBaseline,
    settlement_id: &str,
    swarm_run_id: SwarmRunId,
    target_dir: &Path,
    converged_commit_oid: &str,
    expected_diff_digest: Option<[u8; 32]>,
    settled_at: TimestampMillis,
) -> Result<SwarmSettlementReceipt, SwarmWorkspaceError> {
    ensure_dag_git_store(layout)?;
    let candidate_manifest =
        parse_tree_manifest_file(&commit_manifest_store_path(layout, converged_commit_oid))?;
    let changed_paths = diff_manifest_paths(&pinned.baseline.manifest, &candidate_manifest);
    let converged_diff_digest = compute_transition_diff_digest_for_paths(
        &pinned.baseline.manifest,
        &candidate_manifest,
        &changed_paths,
    );
    if let Some(expected) = expected_diff_digest
        && expected != converged_diff_digest
    {
        return Err(SwarmWorkspaceError::SettlementDiffDigestMismatch { swarm_run_id });
    }

    let (upserted_paths, deleted_paths) =
        compute_manifest_delta(&pinned.baseline.manifest, &candidate_manifest);
    let settlement_dir = swarm_settlement_dir(layout, swarm_run_id);
    fs::create_dir_all(&settlement_dir).map_err(|source| SwarmWorkspaceError::Io {
        context: "creating swarm settlement recovery directory",
        source,
    })?;
    let journal_path = settlement_dir.join(SETTLEMENT_JOURNAL_NAME);

    if let Some(applied) = verify_settlement_journal_or_preimage(
        &journal_path,
        pinned,
        &candidate_manifest,
        swarm_run_id,
        target_dir,
        converged_commit_oid,
    )? {
        return Ok(applied);
    }

    let prepared_receipt = SwarmSettlementReceipt {
        settlement_id: settlement_id.to_owned(),
        swarm_run_id,
        target: pinned.target,
        state: SettlementJournalState::Prepared,
        settled_at,
        baseline_commit_oid: pinned.baseline.base_commit_oid.clone(),
        converged_commit_oid: converged_commit_oid.to_owned(),
        baseline_tree_blake3: pinned.baseline.manifest.tree_blake3.clone(),
        settled_tree_blake3: candidate_manifest.tree_blake3.clone(),
        converged_diff_digest,
        settled_file_count: u64::try_from(candidate_manifest.entries.len()).unwrap_or(u64::MAX),
        upserted_paths,
        deleted_paths,
    };
    write_atomic_file(&journal_path, &encode_settlement_journal(&prepared_receipt))?;

    apply_candidate_to_dir(
        layout,
        &settlement_dir,
        target_dir,
        converged_commit_oid,
        &candidate_manifest,
        &prepared_receipt.upserted_paths,
        &prepared_receipt.deleted_paths,
    )?;

    let post_tree = scan_tree_entries(target_dir)?;
    if post_tree.tree_blake3 != candidate_manifest.tree_blake3 {
        let drifted_paths = diff_manifest_paths(&candidate_manifest, &post_tree);
        let recovery_receipt = SwarmSettlementReceipt {
            state: SettlementJournalState::RecoveryRequired,
            ..prepared_receipt
        };
        let _ = write_atomic_file(&journal_path, &encode_settlement_journal(&recovery_receipt));
        return Err(SwarmWorkspaceError::SettlementRecoveryRequired {
            swarm_run_id,
            settlement_id: recovery_receipt.settlement_id,
            drifted_paths,
        });
    }

    let applied_receipt = SwarmSettlementReceipt {
        state: SettlementJournalState::Applied,
        ..prepared_receipt
    };
    write_atomic_file(&journal_path, &encode_settlement_journal(&applied_receipt))?;
    Ok(applied_receipt)
}

fn verify_settlement_journal_or_preimage(
    journal_path: &Path,
    pinned: &SwarmPinnedBaseline,
    candidate_manifest: &TreeManifest,
    swarm_run_id: SwarmRunId,
    target_dir: &Path,
    converged_commit_oid: &str,
) -> Result<Option<SwarmSettlementReceipt>, SwarmWorkspaceError> {
    let current_tree = scan_tree_entries(target_dir)?;
    if !journal_path.exists() {
        if current_tree.tree_blake3 != pinned.baseline.manifest.tree_blake3 {
            let modified_paths = diff_manifest_paths(&pinned.baseline.manifest, &current_tree);
            return Err(SwarmWorkspaceError::SettlementBaselineConflict {
                swarm_run_id,
                modified_paths,
            });
        }
        return Ok(None);
    }

    let existing = parse_settlement_journal(journal_path)?;
    if existing.target != pinned.target {
        return Err(SwarmWorkspaceError::TargetMismatch { swarm_run_id });
    }
    match existing.state {
        SettlementJournalState::Applied => {
            if current_tree.tree_blake3 != existing.settled_tree_blake3 {
                let modified_paths = diff_manifest_paths(candidate_manifest, &current_tree);
                return Err(SwarmWorkspaceError::SettlementBaselineConflict {
                    swarm_run_id,
                    modified_paths,
                });
            }
            if existing.converged_commit_oid != converged_commit_oid {
                return Err(SwarmWorkspaceError::SettlementDiffDigestMismatch { swarm_run_id });
            }
            Ok(Some(existing))
        }
        SettlementJournalState::RecoveryRequired => {
            let drifted_paths =
                find_drifted_paths(&pinned.baseline.manifest, candidate_manifest, &current_tree);
            Err(SwarmWorkspaceError::SettlementRecoveryRequired {
                swarm_run_id,
                settlement_id: existing.settlement_id,
                drifted_paths,
            })
        }
        SettlementJournalState::Prepared => {
            if existing.converged_commit_oid != converged_commit_oid {
                return Err(SwarmWorkspaceError::SettlementDiffDigestMismatch { swarm_run_id });
            }
            let drifted_paths =
                find_drifted_paths(&pinned.baseline.manifest, candidate_manifest, &current_tree);
            if !drifted_paths.is_empty() {
                let recovery_receipt = SwarmSettlementReceipt {
                    state: SettlementJournalState::RecoveryRequired,
                    ..existing
                };
                let _ =
                    write_atomic_file(journal_path, &encode_settlement_journal(&recovery_receipt));
                return Err(SwarmWorkspaceError::SettlementRecoveryRequired {
                    swarm_run_id,
                    settlement_id: recovery_receipt.settlement_id,
                    drifted_paths,
                });
            }
            Ok(None)
        }
    }
}

fn initialize_standalone_branch_clone(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
    input_commit_oid: &str,
    staging_dir: &Path,
    observed_at: TimestampMillis,
) -> Result<(), SwarmWorkspaceError> {
    let git_dir = dag_git_store_dir(layout);
    let staging_arg =
        staging_dir
            .to_str()
            .ok_or_else(|| SwarmWorkspaceError::InvalidExternalWorktreeRoot {
                path: staging_dir.to_path_buf(),
                reason: "staging path is not valid UTF-8",
            })?;
    let init_out = Command::new(FORGE_GIT_PROGRAM)
        .args([
            "init",
            "--quiet",
            "--initial-branch=swarm-member",
            staging_arg,
        ])
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .map_err(|source| SwarmWorkspaceError::Io {
            context: "spawning git init for swarm Branch clone",
            source,
        })?;
    if !init_out.status.success() {
        return Err(SwarmWorkspaceError::GitCommandFailed {
            context: "git init branch clone",
            detail: String::from_utf8_lossy(&init_out.stderr).trim().to_owned(),
        });
    }

    run_git_in_workdir(staging_dir, &["config", "user.name", "Forge"], observed_at)?;
    run_git_in_workdir(
        staging_dir,
        &["config", "user.email", "forge@heterarchy.local"],
        observed_at,
    )?;

    let input_ref = format!("refs/forge/swarm/{swarm_run_id}/member-input/{member_id}");
    update_git_ref(&git_dir, &input_ref, input_commit_oid, observed_at)?;
    let git_dir_str =
        git_dir
            .to_str()
            .ok_or_else(|| SwarmWorkspaceError::InvalidExternalWorktreeRoot {
                path: git_dir.clone(),
                reason: "dag-store.git path is not valid UTF-8",
            })?;
    let refspec = format!("+{input_ref}:refs/remotes/forge/member-input");
    let fetch_res = run_git_in_workdir(
        staging_dir,
        &["fetch", "--quiet", "--no-tags", git_dir_str, &refspec],
        observed_at,
    );
    let _ = delete_git_ref(&git_dir, &input_ref, observed_at);
    fetch_res?;

    run_git_in_workdir(
        staging_dir,
        &[
            "checkout",
            "--quiet",
            "-B",
            "swarm-member",
            "refs/remotes/forge/member-input",
        ],
        observed_at,
    )?;
    run_git_in_workdir(
        staging_dir,
        &["update-ref", "-d", "refs/remotes/forge/member-input"],
        observed_at,
    )?;
    Ok(())
}

fn pin_or_load_swarm_baseline(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    target: SwarmSettlementTarget,
    observed_at: TimestampMillis,
) -> Result<SwarmPinnedBaseline, SwarmWorkspaceError> {
    let path = baseline_manifest_path(layout, swarm_run_id);
    if path.exists() {
        return parse_baseline_manifest(&path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SwarmWorkspaceError::Io {
            context: "creating swarm baseline manifest directory",
            source,
        })?;
    }

    let source_dir = match target {
        SwarmSettlementTarget::StandaloneSwarm => layout.workspace_root().to_path_buf(),
        SwarmSettlementTarget::DagNodeHybrid {
            goal_id,
            dag_revision,
            node_id,
        } => {
            let node_receipt = inspect_node_workspace(layout, goal_id, dag_revision, node_id)?
                .ok_or(SwarmWorkspaceError::HybridTargetNodeNotProvisioned {
                    swarm_run_id,
                    goal_id,
                    dag_revision,
                    node_id,
                })?;
            if node_receipt.completed().is_some() {
                return Err(SwarmWorkspaceError::HybridTargetNodeAlreadySealed {
                    swarm_run_id,
                    goal_id,
                    dag_revision,
                    node_id,
                });
            }
            validate_external_worktree_path(node_receipt.worktree_path(), layout.workspace_root())?;
            node_receipt.worktree_path().to_path_buf()
        }
    };

    let manifest = scan_tree_entries(&source_dir)?;
    let base_ref = swarm_base_ref(swarm_run_id);
    let base_commit_oid = commit_manifest_from_dir(
        layout,
        &source_dir,
        &manifest,
        &[],
        Some(&base_ref),
        &format!("forge swarm baseline {swarm_run_id}"),
        observed_at,
    )?;
    let pinned = SwarmPinnedBaseline {
        target,
        baseline: PinnedBaseline {
            base_commit_oid,
            manifest,
        },
    };
    let bytes = encode_baseline_manifest(swarm_run_id, observed_at, &pinned);
    write_atomic_file(&path, &bytes)?;
    Ok(pinned)
}

fn load_swarm_baseline(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
) -> Result<SwarmPinnedBaseline, SwarmWorkspaceError> {
    let path = baseline_manifest_path(layout, swarm_run_id);
    if !path.exists() {
        return Err(SwarmWorkspaceError::BaselineNotPinned { swarm_run_id });
    }
    parse_baseline_manifest(&path)
}
