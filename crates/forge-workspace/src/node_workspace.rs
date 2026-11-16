//! Isolated per-DAG-node working tree provisioning, 3-way merge handoff, and
//! explicit canonical workspace settlement (`dag.settle`).
//!
//! Architecture & Storage Boundaries:
//! - **Forge-Owned Bare Git Store (`dag-store.git`)**:
//!   Stored inside `<workspace_root>/.heterarchy-forge/artifacts/node-workspaces/dag-store.git`.
//!   Provides real Git commit ancestry (`refs/forge/dag/<goal_id>/<dag_rev>/base` and
//!   `refs/forge/dag/<goal_id>/<dag_rev>/node/<node_id>`) and true 3-way merge via
//!   `git merge-base` and `git merge-tree --write-tree` without ever mutating the user's
//!   `<workspace_root>/.git` metadata.
//! - **External Runtime Node Worktrees**:
//!   Materialized outside `<workspace_root>` and outside `<location_root>` under the host
//!   state root (`<external_worktrees_root>/<workspace_scope>/<goal_id>/<dag_rev>/<node_id>/worktree`),
//!   eliminating nested-worktree collisions with `rg`, `git`, `cargo`, and `WorkspaceDiscovery`.
//! - **Pinned Baseline (`baseline.manifest`)**:
//!   Pinned once on the first root node provisioning of `(goal_id, dag_revision)` so later
//!   root nodes and `dag.settle` preimage CAS always reference the exact initial snapshot.
//! - **Explicit Settlement (`settle_dag_revision_workspace`)**:
//!   Merges all terminal sink nodes (`out-degree == 0`) in `dag-store.git`, verifies that
//!   `<workspace_root>` still matches the pinned baseline (`Preimage CAS`), records a
//!   crash-safe `Prepared -> Applied` journal under
//!   `<workspace_root>/.heterarchy-forge/recovery/dag-settlements/<goal_id>/<dag_rev>/settlement.journal`,
//!   and atomically applies the changes to `<workspace_root>`.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use forge_domain::{DagNodeId, DagRevisionNumber, GoalId, TimestampMillis, WorkspaceId};
use thiserror::Error;

use crate::dag_git_store::{
    self, GitTreeStoreError, MANIFEST_VERSION, NODE_WORKSPACES_SUBDIR, PinnedBaseline,
    SETTLEMENT_JOURNAL_NAME, TreeManifest, WORKTREE_DIR_NAME, apply_candidate_to_dir,
    checkout_commit_to_dir, commit_manifest_from_dir, commit_manifest_store_path,
    compute_manifest_delta, create_git_commit, dag_git_store_dir, diff_manifest_paths,
    encode_manifest_entries, encode_tree_manifest_file, ensure_dag_git_store, find_drifted_paths,
    next_staging_nonce, parse_i64_header, parse_manifest_entries, parse_tree_manifest_file,
    parse_u64_header, required_header, run_git_merge_base_all, run_git_merge_tree,
    scan_tree_entries, split_headers_and_entries, three_way_merge_manifests,
    validate_relative_path, write_atomic_file,
};
use crate::{ExistingWorkspaceStateLayout, StateLayoutError};

const BASELINES_SUBDIR: &str = "baselines";
const DAG_SETTLEMENTS_SUBDIR: &str = "dag-settlements";
const HANDOFF_MANIFEST_NAME: &str = "handoff.manifest";
const COMPLETED_MANIFEST_NAME: &str = "completed.manifest";
const BASELINE_MANIFEST_NAME: &str = "baseline.manifest";

/// Durable receipt describing a provisioned isolated working tree for one DAG node.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWorkspaceReceipt {
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
    worktree_path: PathBuf,
    upstream_node_ids: Vec<DagNodeId>,
    provisioned_at: TimestampMillis,
    initial_tree_blake3: String,
    initial_file_count: u64,
    input_commit_oid: String,
    completed: Option<NodeWorkspaceCompletedState>,
}

impl NodeWorkspaceReceipt {
    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    pub const fn dag_revision(&self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn node_id(&self) -> DagNodeId {
        self.node_id
    }

    pub fn worktree_path(&self) -> &Path {
        &self.worktree_path
    }

    pub fn upstream_node_ids(&self) -> &[DagNodeId] {
        &self.upstream_node_ids
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

    pub const fn completed(&self) -> Option<&NodeWorkspaceCompletedState> {
        self.completed.as_ref()
    }
}

/// Sealed post-completion state for a node's isolated working tree.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWorkspaceCompletedState {
    completed_at: TimestampMillis,
    final_tree_blake3: String,
    final_file_count: u64,
    output_commit_oid: String,
}

impl NodeWorkspaceCompletedState {
    pub const fn completed_at(&self) -> TimestampMillis {
        self.completed_at
    }

    pub fn final_tree_blake3(&self) -> &str {
        &self.final_tree_blake3
    }

    pub const fn final_file_count(&self) -> u64 {
        self.final_file_count
    }

    pub fn output_commit_oid(&self) -> &str {
        &self.output_commit_oid
    }
}

/// Summary returned when a node completes and hands off its working tree to
/// newly ready downstream nodes.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWorkspaceCompletionReceipt {
    completed: NodeWorkspaceReceipt,
    provisioned_downstreams: Vec<NodeWorkspaceReceipt>,
}

impl NodeWorkspaceCompletionReceipt {
    pub const fn completed(&self) -> &NodeWorkspaceReceipt {
        &self.completed
    }

    pub fn provisioned_downstreams(&self) -> &[NodeWorkspaceReceipt] {
        &self.provisioned_downstreams
    }
}

/// Durable journal phase for explicit canonical workspace settlement (`dag.settle`).
pub type DagSettlementJournalState = crate::dag_git_store::SettlementJournalState;

/// Receipt emitted by `settle_dag_revision_workspace` and read back by `inspect_dag_settlement`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagSettlementReceipt {
    settlement_id: String,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    state: DagSettlementJournalState,
    settled_at: TimestampMillis,
    terminal_sink_node_ids: Vec<DagNodeId>,
    baseline_commit_oid: String,
    candidate_commit_oid: String,
    baseline_tree_blake3: String,
    settled_tree_blake3: String,
    settled_file_count: u64,
    upserted_paths: Vec<String>,
    deleted_paths: Vec<String>,
}

impl DagSettlementReceipt {
    pub fn settlement_id(&self) -> &str {
        &self.settlement_id
    }

    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }

    pub const fn dag_revision(&self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn state(&self) -> DagSettlementJournalState {
        self.state
    }

    pub const fn settled_at(&self) -> TimestampMillis {
        self.settled_at
    }

    pub fn terminal_sink_node_ids(&self) -> &[DagNodeId] {
        &self.terminal_sink_node_ids
    }

    pub fn baseline_commit_oid(&self) -> &str {
        &self.baseline_commit_oid
    }

    pub fn candidate_commit_oid(&self) -> &str {
        &self.candidate_commit_oid
    }

    pub fn baseline_tree_blake3(&self) -> &str {
        &self.baseline_tree_blake3
    }

    pub fn settled_tree_blake3(&self) -> &str {
        &self.settled_tree_blake3
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

#[derive(Debug, Error)]
pub enum NodeWorkspaceError {
    #[error("node workspace I/O failed during {context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("node workspace Git operation failed during {context}: {detail}")]
    GitCommandFailed {
        context: &'static str,
        detail: String,
    },
    #[error("node workspace manifest at {} is corrupt: {reason}", path.display())]
    CorruptManifest { path: PathBuf, reason: &'static str },
    #[error("node workspace relative path {path:?} is invalid")]
    InvalidRelativePath { path: String },
    #[error(
        "unsupported filesystem entry {path:?} in workspace tree (symlinks and special files are forbidden)"
    )]
    UnsupportedWorkspaceEntry { path: String },
    #[error("node workspace for goal {goal_id} rev {} node {node_id} was not provisioned before completion", dag_revision.get())]
    WorkspaceNotProvisioned {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    },
    #[error("node workspace for goal {goal_id} rev {} node {node_id} was already provisioned with a different upstream set", dag_revision.get())]
    UpstreamSetMismatch {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    },
    #[error("handoff input for goal {goal_id} rev {} node {node_id} is unavailable because upstream node {missing_upstream_id} has no sealed completion receipt", dag_revision.get())]
    HandoffInputUnavailable {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
        missing_upstream_id: DagNodeId,
    },
    #[error("3-way merge conflict provisioning goal {goal_id} rev {} node {node_id} from upstreams {upstream_node_ids:?} on paths {conflicting_paths:?}", dag_revision.get())]
    HandoffMergeConflict {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
        upstream_node_ids: Vec<DagNodeId>,
        conflicting_paths: Vec<String>,
    },
    #[error("canonical workspace root drifted from pinned baseline for goal {goal_id} rev {} on paths {modified_paths:?}", dag_revision.get())]
    SettlementBaselineConflict {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        modified_paths: Vec<String>,
    },
    #[error("canonical workspace settlement {settlement_id} for goal {goal_id} rev {} requires recovery due to drifted paths {drifted_paths:?}", dag_revision.get())]
    SettlementRecoveryRequired {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        settlement_id: String,
        drifted_paths: Vec<String>,
    },
    #[error(transparent)]
    StateLayout(#[from] StateLayoutError),
}

impl From<GitTreeStoreError> for NodeWorkspaceError {
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

/// Provision an isolated working tree for `node_id` using the default external host worktree root.
pub fn provision_node_workspace(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
    upstream_node_ids: &[DagNodeId],
    observed_at: TimestampMillis,
) -> Result<NodeWorkspaceReceipt, NodeWorkspaceError> {
    provision_node_workspace_in(
        layout,
        None,
        None,
        goal_id,
        dag_revision,
        node_id,
        upstream_node_ids,
        observed_at,
    )
}

/// Provision an isolated working tree for `node_id` under an explicit external worktrees root.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn provision_node_workspace_in(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
    upstream_node_ids: &[DagNodeId],
    observed_at: TimestampMillis,
) -> Result<NodeWorkspaceReceipt, NodeWorkspaceError> {
    let sorted_upstreams = canonicalize_node_ids(upstream_node_ids);
    if let Some(existing) = inspect_node_workspace(layout, goal_id, dag_revision, node_id)? {
        if existing.upstream_node_ids != sorted_upstreams {
            return Err(NodeWorkspaceError::UpstreamSetMismatch {
                goal_id,
                dag_revision,
                node_id,
            });
        }
        if existing.worktree_path.is_dir() {
            return Ok(existing);
        }
    }

    ensure_dag_git_store(layout)?;
    let baseline = pin_or_load_dag_baseline(layout, goal_id, dag_revision, observed_at)?;

    let (input_commit_oid, input_manifest) = if sorted_upstreams.is_empty() {
        (baseline.base_commit_oid, baseline.manifest)
    } else {
        resolve_and_merge_upstream_commits(
            layout,
            goal_id,
            dag_revision,
            node_id,
            &sorted_upstreams,
            observed_at,
        )?
    };

    let worktree_dir = resolve_external_worktree_path(
        layout,
        external_worktrees_root,
        workspace_id,
        goal_id,
        dag_revision,
        node_id,
    )?;
    let worktree_parent =
        worktree_dir
            .parent()
            .ok_or_else(|| NodeWorkspaceError::CorruptManifest {
                path: worktree_dir.clone(),
                reason: "worktree path has no parent directory",
            })?;
    fs::create_dir_all(worktree_parent).map_err(|source| NodeWorkspaceError::Io {
        context: "creating external node worktree parent directory",
        source,
    })?;

    let nonce = next_staging_nonce();
    let staging_dir =
        worktree_parent.join(format!(".worktree.staging.{}.{nonce}", std::process::id()));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir).map_err(|source| NodeWorkspaceError::Io {
            context: "cleaning stale staging worktree",
            source,
        })?;
    }
    fs::create_dir_all(&staging_dir).map_err(|source| NodeWorkspaceError::Io {
        context: "creating staging worktree directory",
        source,
    })?;

    if !input_manifest.entries.is_empty() {
        checkout_commit_to_dir(layout, &input_commit_oid, &staging_dir)?;
    }

    let materialized_manifest = scan_tree_entries(&staging_dir)?;
    if materialized_manifest.tree_blake3 != input_manifest.tree_blake3 {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(NodeWorkspaceError::CorruptManifest {
            path: staging_dir,
            reason: "materialized worktree digest did not match input commit manifest",
        });
    }

    if worktree_dir.exists() {
        fs::remove_dir_all(&worktree_dir).map_err(|source| NodeWorkspaceError::Io {
            context: "replacing partial node worktree directory",
            source,
        })?;
    }
    fs::rename(&staging_dir, &worktree_dir).map_err(|source| NodeWorkspaceError::Io {
        context: "promoting staging worktree directory",
        source,
    })?;

    let node_meta_dir = node_metadata_dir(layout, goal_id, dag_revision, node_id);
    fs::create_dir_all(&node_meta_dir).map_err(|source| NodeWorkspaceError::Io {
        context: "creating node workspace metadata directory",
        source,
    })?;

    let receipt = NodeWorkspaceReceipt {
        goal_id,
        dag_revision,
        node_id,
        worktree_path: worktree_dir,
        upstream_node_ids: sorted_upstreams,
        provisioned_at: observed_at,
        initial_tree_blake3: input_manifest.tree_blake3.clone(),
        initial_file_count: u64::try_from(input_manifest.entries.len()).unwrap_or(u64::MAX),
        input_commit_oid,
        completed: None,
    };

    let manifest_bytes = encode_handoff_manifest(&receipt, &input_manifest);
    write_atomic_file(&node_meta_dir.join(HANDOFF_MANIFEST_NAME), &manifest_bytes)?;
    Ok(receipt)
}

/// Complete `completed_node_id`, seal its post-state commit in `dag-store.git`,
/// and eagerly provision every newly ready downstream node.
pub fn complete_and_handoff_node_workspace(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    completed_node_id: DagNodeId,
    completed_upstream_ids: &[DagNodeId],
    ready_downstream_nodes: &[(DagNodeId, Vec<DagNodeId>)],
    observed_at: TimestampMillis,
) -> Result<NodeWorkspaceCompletionReceipt, NodeWorkspaceError> {
    complete_and_handoff_node_workspace_in(
        layout,
        None,
        None,
        goal_id,
        dag_revision,
        completed_node_id,
        completed_upstream_ids,
        ready_downstream_nodes,
        observed_at,
    )
}

/// Complete `completed_node_id` and provision ready downstreams under an explicit external worktrees root.
#[allow(clippy::too_many_arguments)]
pub fn complete_and_handoff_node_workspace_in(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    completed_node_id: DagNodeId,
    completed_upstream_ids: &[DagNodeId],
    ready_downstream_nodes: &[(DagNodeId, Vec<DagNodeId>)],
    observed_at: TimestampMillis,
) -> Result<NodeWorkspaceCompletionReceipt, NodeWorkspaceError> {
    let sorted_upstreams = canonicalize_node_ids(completed_upstream_ids);
    let active_receipt = inspect_node_workspace(layout, goal_id, dag_revision, completed_node_id)?
        .ok_or(NodeWorkspaceError::WorkspaceNotProvisioned {
            goal_id,
            dag_revision,
            node_id: completed_node_id,
        })?;
    if active_receipt.upstream_node_ids != sorted_upstreams {
        return Err(NodeWorkspaceError::UpstreamSetMismatch {
            goal_id,
            dag_revision,
            node_id: completed_node_id,
        });
    }

    ensure_dag_git_store(layout)?;
    let final_manifest = scan_tree_entries(active_receipt.worktree_path())?;
    let node_ref = format!(
        "refs/forge/dag/{}/{}/node/{}",
        goal_id,
        dag_revision.get(),
        completed_node_id
    );
    let output_commit_oid = commit_manifest_from_dir(
        layout,
        active_receipt.worktree_path(),
        &final_manifest,
        std::slice::from_ref(&active_receipt.input_commit_oid),
        Some(&node_ref),
        &format!(
            "forge dag node {} rev {} complete",
            completed_node_id,
            dag_revision.get()
        ),
        observed_at,
    )?;

    let completed_state = NodeWorkspaceCompletedState {
        completed_at: observed_at,
        final_tree_blake3: final_manifest.tree_blake3.clone(),
        final_file_count: u64::try_from(final_manifest.entries.len()).unwrap_or(u64::MAX),
        output_commit_oid,
    };

    let node_meta_dir = node_metadata_dir(layout, goal_id, dag_revision, completed_node_id);
    let completed_manifest_path = node_meta_dir.join(COMPLETED_MANIFEST_NAME);
    let completed_bytes = encode_completed_manifest(&completed_state, &final_manifest);
    write_atomic_file(&completed_manifest_path, &completed_bytes)?;

    let mut provisioned_downstreams = Vec::with_capacity(ready_downstream_nodes.len());
    for (downstream_id, downstream_upstreams) in ready_downstream_nodes {
        match provision_node_workspace_in(
            layout,
            external_worktrees_root,
            workspace_id,
            goal_id,
            dag_revision,
            *downstream_id,
            downstream_upstreams,
            observed_at,
        ) {
            Ok(receipt) => provisioned_downstreams.push(receipt),
            Err(error) => {
                // Roll back the completion seal so a retry or conflict inspection sees
                // the node as unsealed if downstream fan-in fails closed.
                let _ = fs::remove_file(&completed_manifest_path);
                return Err(error);
            }
        }
    }

    let completed_receipt = NodeWorkspaceReceipt {
        completed: Some(completed_state),
        ..active_receipt
    };

    Ok(NodeWorkspaceCompletionReceipt {
        completed: completed_receipt,
        provisioned_downstreams,
    })
}

/// Inspect the durable receipt for `(goal_id, dag_revision, node_id)`.
pub fn inspect_node_workspace(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
) -> Result<Option<NodeWorkspaceReceipt>, NodeWorkspaceError> {
    let node_meta_dir = node_metadata_dir(layout, goal_id, dag_revision, node_id);
    let handoff_path = node_meta_dir.join(HANDOFF_MANIFEST_NAME);
    if !handoff_path.exists() {
        return Ok(None);
    }
    let (mut receipt, _) = parse_handoff_manifest(&handoff_path)?;
    if receipt.goal_id != goal_id
        || receipt.dag_revision != dag_revision
        || receipt.node_id != node_id
    {
        return Err(NodeWorkspaceError::CorruptManifest {
            path: handoff_path,
            reason: "manifest identity does not match directory path",
        });
    }
    let completed_path = node_meta_dir.join(COMPLETED_MANIFEST_NAME);
    if completed_path.exists() {
        let (completed_state, _) = parse_completed_manifest(&completed_path)?;
        receipt.completed = Some(completed_state);
    }
    Ok(Some(receipt))
}

/// Explicitly settle all terminal sink node outputs (`out-degree == 0`) for `(goal_id, dag_revision)`
/// into the canonical `<workspace_root>` with Preimage CAS and a crash-safe `Prepared -> Applied` journal.
#[allow(clippy::too_many_lines)]
pub fn settle_dag_revision_workspace(
    layout: &ExistingWorkspaceStateLayout,
    settlement_id: &str,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    terminal_sink_node_ids: &[DagNodeId],
    settled_at: TimestampMillis,
) -> Result<DagSettlementReceipt, NodeWorkspaceError> {
    let sorted_sinks = canonicalize_node_ids(terminal_sink_node_ids);
    if sorted_sinks.is_empty() {
        return Err(NodeWorkspaceError::CorruptManifest {
            path: layout.workspace_root().to_path_buf(),
            reason: "cannot settle a DAG revision with zero terminal sink nodes",
        });
    }

    ensure_dag_git_store(layout)?;
    let baseline = pin_or_load_dag_baseline(layout, goal_id, dag_revision, settled_at)?;

    // Merge all terminal sink nodes in deterministic sorted order via 3-way merge.
    let synthetic_sink_id = sorted_sinks[0];
    let (candidate_commit_oid, candidate_manifest) = resolve_and_merge_upstream_commits(
        layout,
        goal_id,
        dag_revision,
        synthetic_sink_id,
        &sorted_sinks,
        settled_at,
    )?;

    let (upserted_paths, deleted_paths) =
        compute_manifest_delta(&baseline.manifest, &candidate_manifest);

    let settlement_dir = dag_settlement_dir(layout, goal_id, dag_revision);
    fs::create_dir_all(&settlement_dir).map_err(|source| NodeWorkspaceError::Io {
        context: "creating dag settlement recovery directory",
        source,
    })?;
    let journal_path = settlement_dir.join(SETTLEMENT_JOURNAL_NAME);

    if journal_path.exists() {
        let existing = parse_settlement_journal(&journal_path)?;
        let current_ws = scan_tree_entries(layout.workspace_root())?;
        match existing.state {
            DagSettlementJournalState::Applied => {
                if current_ws.tree_blake3 != existing.settled_tree_blake3 {
                    let modified_paths = diff_manifest_paths(&candidate_manifest, &current_ws);
                    return Err(NodeWorkspaceError::SettlementBaselineConflict {
                        goal_id,
                        dag_revision,
                        modified_paths,
                    });
                }
                return Ok(existing);
            }
            DagSettlementJournalState::RecoveryRequired => {
                let drifted_paths =
                    find_drifted_paths(&baseline.manifest, &candidate_manifest, &current_ws);
                return Err(NodeWorkspaceError::SettlementRecoveryRequired {
                    goal_id,
                    dag_revision,
                    settlement_id: existing.settlement_id,
                    drifted_paths,
                });
            }
            DagSettlementJournalState::Prepared => {
                let drifted_paths =
                    find_drifted_paths(&baseline.manifest, &candidate_manifest, &current_ws);
                if !drifted_paths.is_empty() {
                    let recovery_receipt = DagSettlementReceipt {
                        state: DagSettlementJournalState::RecoveryRequired,
                        ..existing.clone()
                    };
                    let _ = write_atomic_file(
                        &journal_path,
                        &encode_settlement_journal(&recovery_receipt),
                    );
                    return Err(NodeWorkspaceError::SettlementRecoveryRequired {
                        goal_id,
                        dag_revision,
                        settlement_id: existing.settlement_id,
                        drifted_paths,
                    });
                }
                // All paths match either preimage or postimage; resume applying cleanly.
            }
        }
    } else {
        // Fresh settlement: enforce strict Preimage CAS against pinned baseline.
        let current_ws = scan_tree_entries(layout.workspace_root())?;
        if current_ws.tree_blake3 != baseline.manifest.tree_blake3 {
            let modified_paths = diff_manifest_paths(&baseline.manifest, &current_ws);
            return Err(NodeWorkspaceError::SettlementBaselineConflict {
                goal_id,
                dag_revision,
                modified_paths,
            });
        }
    }

    let prepared_receipt = DagSettlementReceipt {
        settlement_id: settlement_id.to_owned(),
        goal_id,
        dag_revision,
        state: DagSettlementJournalState::Prepared,
        settled_at,
        terminal_sink_node_ids: sorted_sinks,
        baseline_commit_oid: baseline.base_commit_oid,
        candidate_commit_oid: candidate_commit_oid.clone(),
        baseline_tree_blake3: baseline.manifest.tree_blake3.clone(),
        settled_tree_blake3: candidate_manifest.tree_blake3.clone(),
        settled_file_count: u64::try_from(candidate_manifest.entries.len()).unwrap_or(u64::MAX),
        upserted_paths,
        deleted_paths,
    };
    write_atomic_file(&journal_path, &encode_settlement_journal(&prepared_receipt))?;

    apply_candidate_to_dir(
        layout,
        &settlement_dir,
        layout.workspace_root(),
        &candidate_commit_oid,
        &candidate_manifest,
        &prepared_receipt.upserted_paths,
        &prepared_receipt.deleted_paths,
    )?;

    let post_ws = scan_tree_entries(layout.workspace_root())?;
    if post_ws.tree_blake3 != candidate_manifest.tree_blake3 {
        let drifted_paths = diff_manifest_paths(&candidate_manifest, &post_ws);
        let recovery_receipt = DagSettlementReceipt {
            state: DagSettlementJournalState::RecoveryRequired,
            ..prepared_receipt
        };
        let _ = write_atomic_file(&journal_path, &encode_settlement_journal(&recovery_receipt));
        return Err(NodeWorkspaceError::SettlementRecoveryRequired {
            goal_id,
            dag_revision,
            settlement_id: settlement_id.to_owned(),
            drifted_paths,
        });
    }

    let applied_receipt = DagSettlementReceipt {
        state: DagSettlementJournalState::Applied,
        ..prepared_receipt
    };
    write_atomic_file(&journal_path, &encode_settlement_journal(&applied_receipt))?;
    Ok(applied_receipt)
}

/// Inspect the durable settlement receipt for `(goal_id, dag_revision)`.
pub fn inspect_dag_settlement(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
) -> Result<Option<DagSettlementReceipt>, NodeWorkspaceError> {
    let journal_path =
        dag_settlement_dir(layout, goal_id, dag_revision).join(SETTLEMENT_JOURNAL_NAME);
    if !journal_path.exists() {
        return Ok(None);
    }
    parse_settlement_journal(&journal_path).map(Some)
}

/// Verify whether `(goal_id, dag_revision)` has either:
/// 1. An `Applied` settlement receipt whose `settled_tree_blake3` matches the current `<workspace_root>`, OR
/// 2. Zero file changes across all terminal sink worktrees relative to the pinned baseline (and no pending/failed settlement journal).
pub fn verify_dag_revision_settled(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    terminal_sink_node_ids: &[DagNodeId],
) -> Result<bool, NodeWorkspaceError> {
    if let Some(settlement) = inspect_dag_settlement(layout, goal_id, dag_revision)? {
        if settlement.state != DagSettlementJournalState::Applied {
            return Ok(false);
        }
        let current_ws = scan_tree_entries(layout.workspace_root())?;
        return Ok(current_ws.tree_blake3 == settlement.settled_tree_blake3);
    }

    let baseline_path = baseline_manifest_path(layout, goal_id, dag_revision);
    if !baseline_path.exists() {
        return Ok(true);
    }
    let baseline = parse_baseline_manifest(&baseline_path)?;

    let sorted_sinks = canonicalize_node_ids(terminal_sink_node_ids);
    for sink_id in &sorted_sinks {
        let Some(receipt) = inspect_node_workspace(layout, goal_id, dag_revision, *sink_id)? else {
            continue;
        };
        let Some(completed) = receipt.completed() else {
            return Ok(false);
        };
        if completed.final_tree_blake3() != baseline.manifest.tree_blake3 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Remove all node-workspace manifests, baselines, settlement journals, git refs, and external
/// worktrees for `goal_id` when a Goal or its DAG history is permanently deleted.
pub fn purge_goal_node_workspaces(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    goal_id: GoalId,
) -> Result<(), NodeWorkspaceError> {
    let artifacts_goal_dir = layout
        .artifacts()
        .join(NODE_WORKSPACES_SUBDIR)
        .join(goal_id.to_string());
    if artifacts_goal_dir.exists() {
        fs::remove_dir_all(&artifacts_goal_dir).map_err(|source| NodeWorkspaceError::Io {
            context: "removing goal node workspace metadata",
            source,
        })?;
    }
    let baseline_goal_dir = layout
        .artifacts()
        .join(NODE_WORKSPACES_SUBDIR)
        .join(BASELINES_SUBDIR)
        .join(goal_id.to_string());
    if baseline_goal_dir.exists() {
        fs::remove_dir_all(&baseline_goal_dir).map_err(|source| NodeWorkspaceError::Io {
            context: "removing goal baseline manifests",
            source,
        })?;
    }
    let settlement_goal_dir = layout
        .recovery()
        .join(DAG_SETTLEMENTS_SUBDIR)
        .join(goal_id.to_string());
    if settlement_goal_dir.exists() {
        fs::remove_dir_all(&settlement_goal_dir).map_err(|source| NodeWorkspaceError::Io {
            context: "removing goal settlement journals",
            source,
        })?;
    }
    if let Ok(scope_root) =
        resolve_external_workspace_scope_dir(layout, external_worktrees_root, workspace_id)
    {
        let external_goal_dir = scope_root.join(goal_id.to_string());
        if external_goal_dir.exists() {
            let _ = fs::remove_dir_all(&external_goal_dir);
        }
    }
    Ok(())
}

fn canonicalize_node_ids(node_ids: &[DagNodeId]) -> Vec<DagNodeId> {
    let mut sorted = node_ids.to_vec();
    sorted.sort_by_key(|id| id.into_uuid().as_u128());
    sorted.dedup();
    sorted
}

fn baseline_manifest_path(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
) -> PathBuf {
    layout
        .artifacts()
        .join(NODE_WORKSPACES_SUBDIR)
        .join(BASELINES_SUBDIR)
        .join(goal_id.to_string())
        .join(dag_revision.get().to_string())
        .join(BASELINE_MANIFEST_NAME)
}

fn node_metadata_dir(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
) -> PathBuf {
    layout
        .artifacts()
        .join(NODE_WORKSPACES_SUBDIR)
        .join(goal_id.to_string())
        .join(dag_revision.get().to_string())
        .join(node_id.to_string())
}

fn dag_settlement_dir(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
) -> PathBuf {
    layout
        .recovery()
        .join(DAG_SETTLEMENTS_SUBDIR)
        .join(goal_id.to_string())
        .join(dag_revision.get().to_string())
}

fn resolve_external_workspace_scope_dir(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
) -> Result<PathBuf, NodeWorkspaceError> {
    dag_git_store::resolve_external_workspace_scope_dir(
        layout,
        external_worktrees_root,
        workspace_id,
        "heterarchy-forge-node-worktrees",
    )
    .map_err(Into::into)
}

fn resolve_external_worktree_path(
    layout: &ExistingWorkspaceStateLayout,
    external_worktrees_root: Option<&Path>,
    workspace_id: Option<WorkspaceId>,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
) -> Result<PathBuf, NodeWorkspaceError> {
    let scope_dir =
        resolve_external_workspace_scope_dir(layout, external_worktrees_root, workspace_id)?;
    Ok(scope_dir
        .join(goal_id.to_string())
        .join(dag_revision.get().to_string())
        .join(node_id.to_string())
        .join(WORKTREE_DIR_NAME))
}

fn pin_or_load_dag_baseline(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    observed_at: TimestampMillis,
) -> Result<PinnedBaseline, NodeWorkspaceError> {
    let path = baseline_manifest_path(layout, goal_id, dag_revision);
    if path.exists() {
        return parse_baseline_manifest(&path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| NodeWorkspaceError::Io {
            context: "creating baseline manifest directory",
            source,
        })?;
    }
    let manifest = scan_tree_entries(layout.workspace_root())?;
    let base_ref = format!("refs/forge/dag/{}/{}/base", goal_id, dag_revision.get());
    let base_commit_oid = commit_manifest_from_dir(
        layout,
        layout.workspace_root(),
        &manifest,
        &[],
        Some(&base_ref),
        &format!("forge dag baseline {} rev {}", goal_id, dag_revision.get()),
        observed_at,
    )?;
    let baseline = PinnedBaseline {
        base_commit_oid,
        manifest,
    };
    let bytes = encode_baseline_manifest(goal_id, dag_revision, observed_at, &baseline);
    write_atomic_file(&path, &bytes)?;
    Ok(baseline)
}

#[allow(clippy::too_many_lines)]
fn resolve_and_merge_upstream_commits(
    layout: &ExistingWorkspaceStateLayout,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    target_node_id: DagNodeId,
    sorted_upstreams: &[DagNodeId],
    observed_at: TimestampMillis,
) -> Result<(String, TreeManifest), NodeWorkspaceError> {
    let mut upstream_commits = Vec::with_capacity(sorted_upstreams.len());
    for upstream_id in sorted_upstreams {
        let receipt = inspect_node_workspace(layout, goal_id, dag_revision, *upstream_id)?.ok_or(
            NodeWorkspaceError::HandoffInputUnavailable {
                goal_id,
                dag_revision,
                node_id: target_node_id,
                missing_upstream_id: *upstream_id,
            },
        )?;
        let Some(completed) = receipt.completed else {
            return Err(NodeWorkspaceError::HandoffInputUnavailable {
                goal_id,
                dag_revision,
                node_id: target_node_id,
                missing_upstream_id: *upstream_id,
            });
        };
        let manifest_path = commit_manifest_store_path(layout, &completed.output_commit_oid);
        let manifest = parse_tree_manifest_file(&manifest_path)?;
        upstream_commits.push((completed.output_commit_oid, manifest));
    }

    let mut current_iter = upstream_commits.into_iter();
    let Some((mut acc_commit_oid, mut acc_manifest)) = current_iter.next() else {
        return Err(NodeWorkspaceError::CorruptManifest {
            path: layout.workspace_root().to_path_buf(),
            reason: "empty upstream commit list",
        });
    };

    let git_dir = dag_git_store_dir(layout);
    for (right_commit_oid, right_manifest) in current_iter {
        if acc_commit_oid == right_commit_oid {
            continue;
        }
        let merge_bases =
            run_git_merge_base_all(&git_dir, &acc_commit_oid, &right_commit_oid, observed_at)?;
        if merge_bases.len() != 1 {
            return Err(NodeWorkspaceError::HandoffMergeConflict {
                goal_id,
                dag_revision,
                node_id: target_node_id,
                upstream_node_ids: sorted_upstreams.to_vec(),
                conflicting_paths: vec!["<ambiguous-merge-base>".to_owned()],
            });
        }
        let base_commit_oid = &merge_bases[0];
        let base_manifest =
            parse_tree_manifest_file(&commit_manifest_store_path(layout, base_commit_oid))?;

        let merge_tree_out = run_git_merge_tree(&git_dir, &acc_commit_oid, &right_commit_oid)?;
        let merged_tree_oid = match merge_tree_out {
            Ok(tree_oid) => tree_oid,
            Err(conflicting_paths) => {
                return Err(NodeWorkspaceError::HandoffMergeConflict {
                    goal_id,
                    dag_revision,
                    node_id: target_node_id,
                    upstream_node_ids: sorted_upstreams.to_vec(),
                    conflicting_paths,
                });
            }
        };

        let (merged_manifest, manifest_conflicts) = three_way_merge_manifests(
            &git_dir,
            &merged_tree_oid,
            &base_manifest,
            &acc_manifest,
            &right_manifest,
        )?;
        if !manifest_conflicts.is_empty() {
            return Err(NodeWorkspaceError::HandoffMergeConflict {
                goal_id,
                dag_revision,
                node_id: target_node_id,
                upstream_node_ids: sorted_upstreams.to_vec(),
                conflicting_paths: manifest_conflicts,
            });
        }

        let parents = vec![acc_commit_oid, right_commit_oid];
        let merged_commit_oid = create_git_commit(
            &git_dir,
            &merged_tree_oid,
            &parents,
            &format!(
                "forge dag 3-way merge for node {} rev {}",
                target_node_id,
                dag_revision.get()
            ),
            observed_at,
        )?;
        write_atomic_file(
            &commit_manifest_store_path(layout, &merged_commit_oid),
            &encode_tree_manifest_file(&merged_manifest),
        )?;
        acc_commit_oid = merged_commit_oid;
        acc_manifest = merged_manifest;
    }

    Ok((acc_commit_oid, acc_manifest))
}

fn encode_baseline_manifest(
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    pinned_at: TimestampMillis,
    baseline: &PinnedBaseline,
) -> Vec<u8> {
    let mut out = String::new();
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "goal_id={goal_id}");
    let _ = writeln!(out, "dag_revision={}", dag_revision.get());
    let _ = writeln!(out, "pinned_at_ms={}", pinned_at.get());
    let _ = writeln!(out, "base_commit_oid={}", baseline.base_commit_oid);
    let _ = writeln!(out, "tree_blake3={}", baseline.manifest.tree_blake3);
    let _ = writeln!(out, "file_count={}", baseline.manifest.entries.len());
    encode_manifest_entries(&mut out, &baseline.manifest);
    out.into_bytes()
}

fn parse_baseline_manifest(path: &Path) -> Result<PinnedBaseline, NodeWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| NodeWorkspaceError::Io {
        context: "reading baseline manifest",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let base_commit_oid = required_header(&headers, path, "base_commit_oid")?.to_owned();
    let tree_blake3 = required_header(&headers, path, "tree_blake3")?.to_owned();
    let file_count = parse_u64_header(&headers, path, "file_count")?;
    let manifest = parse_manifest_entries(path, &entry_lines, &tree_blake3, file_count)?;
    Ok(PinnedBaseline {
        base_commit_oid,
        manifest,
    })
}

fn encode_handoff_manifest(receipt: &NodeWorkspaceReceipt, manifest: &TreeManifest) -> Vec<u8> {
    let mut out = String::new();
    let upstreams = receipt
        .upstream_node_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "goal_id={}", receipt.goal_id);
    let _ = writeln!(out, "dag_revision={}", receipt.dag_revision.get());
    let _ = writeln!(out, "node_id={}", receipt.node_id);
    let _ = writeln!(out, "worktree_path={}", receipt.worktree_path.display());
    let _ = writeln!(out, "provisioned_at_ms={}", receipt.provisioned_at.get());
    let _ = writeln!(out, "upstreams={upstreams}");
    let _ = writeln!(out, "input_commit_oid={}", receipt.input_commit_oid);
    let _ = writeln!(out, "initial_tree_blake3={}", receipt.initial_tree_blake3);
    let _ = writeln!(out, "initial_file_count={}", receipt.initial_file_count);
    encode_manifest_entries(&mut out, manifest);
    out.into_bytes()
}

fn parse_handoff_manifest(
    path: &Path,
) -> Result<(NodeWorkspaceReceipt, TreeManifest), NodeWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| NodeWorkspaceError::Io {
        context: "reading handoff manifest",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let goal_id = GoalId::from_str(required_header(&headers, path, "goal_id")?).map_err(|_| {
        NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid goal_id UUID",
        }
    })?;
    let dag_rev_raw = parse_i64_header(&headers, path, "dag_revision")?;
    let dag_revision =
        DagRevisionNumber::new(dag_rev_raw).map_err(|_| NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid dag_revision number",
        })?;
    let node_id =
        DagNodeId::from_str(required_header(&headers, path, "node_id")?).map_err(|_| {
            NodeWorkspaceError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid node_id UUID",
            }
        })?;
    let worktree_path = PathBuf::from(required_header(&headers, path, "worktree_path")?);
    let provisioned_at_raw = parse_i64_header(&headers, path, "provisioned_at_ms")?;
    let provisioned_at = TimestampMillis::new(provisioned_at_raw).map_err(|_| {
        NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid provisioned_at_ms timestamp",
        }
    })?;
    let upstreams_raw = required_header(&headers, path, "upstreams")?;
    let upstream_node_ids = parse_node_id_csv(path, upstreams_raw)?;
    let input_commit_oid = required_header(&headers, path, "input_commit_oid")?.to_owned();
    let initial_tree_blake3 = required_header(&headers, path, "initial_tree_blake3")?.to_owned();
    let initial_file_count = parse_u64_header(&headers, path, "initial_file_count")?;

    let manifest =
        parse_manifest_entries(path, &entry_lines, &initial_tree_blake3, initial_file_count)?;
    let receipt = NodeWorkspaceReceipt {
        goal_id,
        dag_revision,
        node_id,
        worktree_path,
        upstream_node_ids,
        provisioned_at,
        initial_tree_blake3,
        initial_file_count,
        input_commit_oid,
        completed: None,
    };
    Ok((receipt, manifest))
}

fn encode_completed_manifest(
    completed: &NodeWorkspaceCompletedState,
    manifest: &TreeManifest,
) -> Vec<u8> {
    let mut out = String::new();
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "completed_at_ms={}", completed.completed_at.get());
    let _ = writeln!(out, "output_commit_oid={}", completed.output_commit_oid);
    let _ = writeln!(out, "final_tree_blake3={}", completed.final_tree_blake3);
    let _ = writeln!(out, "final_file_count={}", completed.final_file_count);
    encode_manifest_entries(&mut out, manifest);
    out.into_bytes()
}

fn parse_completed_manifest(
    path: &Path,
) -> Result<(NodeWorkspaceCompletedState, TreeManifest), NodeWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| NodeWorkspaceError::Io {
        context: "reading completed manifest",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let completed_at_raw = parse_i64_header(&headers, path, "completed_at_ms")?;
    let completed_at = TimestampMillis::new(completed_at_raw).map_err(|_| {
        NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid completed_at_ms timestamp",
        }
    })?;
    let output_commit_oid = required_header(&headers, path, "output_commit_oid")?.to_owned();
    let final_tree_blake3 = required_header(&headers, path, "final_tree_blake3")?.to_owned();
    let final_file_count = parse_u64_header(&headers, path, "final_file_count")?;
    let manifest =
        parse_manifest_entries(path, &entry_lines, &final_tree_blake3, final_file_count)?;
    Ok((
        NodeWorkspaceCompletedState {
            completed_at,
            final_tree_blake3,
            final_file_count,
            output_commit_oid,
        },
        manifest,
    ))
}

fn encode_settlement_journal(receipt: &DagSettlementReceipt) -> Vec<u8> {
    let mut out = String::new();
    let sinks = receipt
        .terminal_sink_node_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "settlement_id={}", receipt.settlement_id);
    let _ = writeln!(out, "goal_id={}", receipt.goal_id);
    let _ = writeln!(out, "dag_revision={}", receipt.dag_revision.get());
    let _ = writeln!(out, "state={}", receipt.state.as_str());
    let _ = writeln!(out, "settled_at_ms={}", receipt.settled_at.get());
    let _ = writeln!(out, "terminal_sinks={sinks}");
    let _ = writeln!(out, "baseline_commit_oid={}", receipt.baseline_commit_oid);
    let _ = writeln!(out, "candidate_commit_oid={}", receipt.candidate_commit_oid);
    let _ = writeln!(out, "baseline_tree_blake3={}", receipt.baseline_tree_blake3);
    let _ = writeln!(out, "settled_tree_blake3={}", receipt.settled_tree_blake3);
    let _ = writeln!(out, "settled_file_count={}", receipt.settled_file_count);
    let _ = writeln!(out, "---");
    for path in &receipt.upserted_paths {
        let _ = writeln!(out, "U\t{path}");
    }
    for path in &receipt.deleted_paths {
        let _ = writeln!(out, "D\t{path}");
    }
    out.into_bytes()
}

fn parse_settlement_journal(path: &Path) -> Result<DagSettlementReceipt, NodeWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| NodeWorkspaceError::Io {
        context: "reading settlement journal",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let settlement_id = required_header(&headers, path, "settlement_id")?.to_owned();
    let goal_id = GoalId::from_str(required_header(&headers, path, "goal_id")?).map_err(|_| {
        NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid goal_id in settlement journal",
        }
    })?;
    let dag_rev_raw = parse_i64_header(&headers, path, "dag_revision")?;
    let dag_revision =
        DagRevisionNumber::new(dag_rev_raw).map_err(|_| NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid dag_revision in settlement journal",
        })?;
    let state = DagSettlementJournalState::parse(required_header(&headers, path, "state")?)
        .ok_or_else(|| NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid state in settlement journal",
        })?;
    let settled_at_raw = parse_i64_header(&headers, path, "settled_at_ms")?;
    let settled_at =
        TimestampMillis::new(settled_at_raw).map_err(|_| NodeWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid settled_at_ms in settlement journal",
        })?;
    let terminal_sink_node_ids =
        parse_node_id_csv(path, required_header(&headers, path, "terminal_sinks")?)?;
    let baseline_commit_oid = required_header(&headers, path, "baseline_commit_oid")?.to_owned();
    let candidate_commit_oid = required_header(&headers, path, "candidate_commit_oid")?.to_owned();
    let baseline_tree_blake3 = required_header(&headers, path, "baseline_tree_blake3")?.to_owned();
    let settled_tree_blake3 = required_header(&headers, path, "settled_tree_blake3")?.to_owned();
    let settled_file_count = parse_u64_header(&headers, path, "settled_file_count")?;

    let mut upserted_paths = Vec::new();
    let mut deleted_paths = Vec::new();
    for line in entry_lines {
        if line.is_empty() {
            continue;
        }
        let Some((op, rel_path)) = line.split_once('\t') else {
            return Err(NodeWorkspaceError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid delta line in settlement journal",
            });
        };
        validate_relative_path(rel_path)?;
        match op {
            "U" => upserted_paths.push(rel_path.to_owned()),
            "D" => deleted_paths.push(rel_path.to_owned()),
            _ => {
                return Err(NodeWorkspaceError::CorruptManifest {
                    path: path.to_path_buf(),
                    reason: "unknown delta operation in settlement journal",
                });
            }
        }
    }

    Ok(DagSettlementReceipt {
        settlement_id,
        goal_id,
        dag_revision,
        state,
        settled_at,
        terminal_sink_node_ids,
        baseline_commit_oid,
        candidate_commit_oid,
        baseline_tree_blake3,
        settled_tree_blake3,
        settled_file_count,
        upserted_paths,
        deleted_paths,
    })
}

fn parse_node_id_csv(path: &Path, raw: &str) -> Result<Vec<DagNodeId>, NodeWorkspaceError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|item| {
            DagNodeId::from_str(item).map_err(|_| NodeWorkspaceError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid DagNodeId in CSV header",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use uuid::Uuid;

    use super::*;
    use crate::WorkspaceStateLayout;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    /// Builder fixture for node workspace, 3-way merge handoff, and canonical settlement tests.
    struct NodeWorkspaceTestHarness {
        root: PathBuf,
        external_worktrees_root: PathBuf,
        workspace_root: PathBuf,
        layout: ExistingWorkspaceStateLayout,
        workspace_id: WorkspaceId,
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
    }

    impl NodeWorkspaceTestHarness {
        fn new(
            label: &str,
            initial_files: &[(&str, &str)],
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "heterarchy-forge-node-ws-{label}-{}-{id}",
                std::process::id()
            ));
            let external_worktrees_root = root.join("host-state").join("node-worktrees");
            let workspace_root = root.join("location").join("workspace-0");
            fs::create_dir_all(&workspace_root)?;
            for (rel_path, content) in initial_files {
                let target = workspace_root.join(rel_path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(target, content)?;
            }
            let _ = WorkspaceStateLayout::initialize(&workspace_root)?;
            let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
                .ok_or("missing workspace state layout")?;
            Ok(Self {
                root,
                external_worktrees_root,
                workspace_root,
                layout,
                workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(0xAA00 + u128::from(id))),
                goal_id: GoalId::from_uuid(Uuid::from_u128(0xBB00 + u128::from(id))),
                dag_revision: DagRevisionNumber::INITIAL,
            })
        }

        fn provision(
            &self,
            node_id: DagNodeId,
            upstreams: &[DagNodeId],
            at_ms: i64,
        ) -> Result<NodeWorkspaceReceipt, NodeWorkspaceError> {
            provision_node_workspace_in(
                &self.layout,
                Some(&self.external_worktrees_root),
                Some(self.workspace_id),
                self.goal_id,
                self.dag_revision,
                node_id,
                upstreams,
                TimestampMillis::new(at_ms).map_err(|_| NodeWorkspaceError::CorruptManifest {
                    path: self.workspace_root.clone(),
                    reason: "invalid test timestamp",
                })?,
            )
        }

        fn complete(
            &self,
            node_id: DagNodeId,
            upstreams: &[DagNodeId],
            ready_downstreams: &[(DagNodeId, Vec<DagNodeId>)],
            at_ms: i64,
        ) -> Result<NodeWorkspaceCompletionReceipt, NodeWorkspaceError> {
            complete_and_handoff_node_workspace_in(
                &self.layout,
                Some(&self.external_worktrees_root),
                Some(self.workspace_id),
                self.goal_id,
                self.dag_revision,
                node_id,
                upstreams,
                ready_downstreams,
                TimestampMillis::new(at_ms).map_err(|_| NodeWorkspaceError::CorruptManifest {
                    path: self.workspace_root.clone(),
                    reason: "invalid test timestamp",
                })?,
            )
        }
    }

    impl Drop for NodeWorkspaceTestHarness {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn node(seed: u128) -> DagNodeId {
        DagNodeId::from_uuid(Uuid::from_u128(seed))
    }

    #[test]
    fn linear_handoff_external_isolation_and_pinned_baseline_invariance()
    -> Result<(), Box<dyn std::error::Error>> {
        let harness = NodeWorkspaceTestHarness::new(
            "linear",
            &[
                ("src/lib.rs", "pub fn step() -> u32 { 0 }\n"),
                ("obsolete.txt", "delete me in A\n"),
            ],
        )?;
        let (node_a, node_b, node_c) = (node(1), node(2), node(3));

        // 1. Provision root node A: worktree must be outside workspace_root and location_root.
        let receipt_a = harness.provision(node_a, &[], 1_000)?;
        assert!(
            receipt_a
                .worktree_path()
                .starts_with(&harness.external_worktrees_root)
        );
        assert!(
            !receipt_a
                .worktree_path()
                .starts_with(&harness.workspace_root)
        );

        // Mutate A's isolated worktree: edit tracked file, add untracked file, delete obsolete.txt.
        fs::write(
            receipt_a.worktree_path().join("src/lib.rs"),
            "pub fn step() -> u32 { 1 }\n",
        )?;
        fs::write(
            receipt_a.worktree_path().join("from_a.txt"),
            "created by A\n",
        )?;
        fs::remove_file(receipt_a.worktree_path().join("obsolete.txt"))?;

        // Canonical workspace_root remains untouched during DAG execution.
        assert_eq!(
            fs::read_to_string(harness.workspace_root.join("src/lib.rs"))?,
            "pub fn step() -> u32 { 0 }\n"
        );
        assert!(harness.workspace_root.join("obsolete.txt").exists());
        assert!(!harness.workspace_root.join("from_a.txt").exists());

        // 2. Complete A -> B and complete B -> C.
        let comp_a = harness.complete(node_a, &[], &[(node_b, vec![node_a])], 2_000)?;
        let receipt_b = &comp_a.provisioned_downstreams()[0];
        assert_eq!(
            fs::read_to_string(receipt_b.worktree_path().join("src/lib.rs"))?,
            "pub fn step() -> u32 { 1 }\n"
        );
        assert_eq!(
            fs::read_to_string(receipt_b.worktree_path().join("from_a.txt"))?,
            "created by A\n"
        );
        assert!(!receipt_b.worktree_path().join("obsolete.txt").exists());

        fs::write(
            receipt_b.worktree_path().join("from_b.txt"),
            "created by B\n",
        )?;
        let comp_b = harness.complete(node_b, &[node_a], &[(node_c, vec![node_b])], 3_000)?;
        let receipt_c = &comp_b.provisioned_downstreams()[0];
        assert_eq!(
            fs::read_to_string(receipt_c.worktree_path().join("from_b.txt"))?,
            "created by B\n"
        );
        let _comp_c = harness.complete(node_c, &[node_b], &[], 4_000)?;

        // Before settlement, verify_dag_revision_settled is false.
        assert!(!verify_dag_revision_settled(
            &harness.layout,
            harness.goal_id,
            harness.dag_revision,
            &[node_c],
        )?);

        // 3. Explicit settlement applies C's output tree to workspace_root.
        let settlement = settle_dag_revision_workspace(
            &harness.layout,
            "settle-linear-1",
            harness.goal_id,
            harness.dag_revision,
            &[node_c],
            TimestampMillis::new(5_000)?,
        )?;
        assert_eq!(settlement.state(), DagSettlementJournalState::Applied);
        assert_eq!(
            fs::read_to_string(harness.workspace_root.join("src/lib.rs"))?,
            "pub fn step() -> u32 { 1 }\n"
        );
        assert_eq!(
            fs::read_to_string(harness.workspace_root.join("from_a.txt"))?,
            "created by A\n"
        );
        assert_eq!(
            fs::read_to_string(harness.workspace_root.join("from_b.txt"))?,
            "created by B\n"
        );
        assert!(!harness.workspace_root.join("obsolete.txt").exists());
        assert!(verify_dag_revision_settled(
            &harness.layout,
            harness.goal_id,
            harness.dag_revision,
            &[node_c],
        )?);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn diamond_three_way_merge_table_cases() -> Result<(), Box<dyn std::error::Error>> {
        struct DiamondCase {
            name: &'static str,
            b1_edits: &'static [(&'static str, Option<&'static str>)],
            b2_edits: &'static [(&'static str, Option<&'static str>)],
            expected_conflict_path: Option<&'static str>,
            expected_c_files: &'static [(&'static str, Option<&'static str>)],
        }

        let cases = [
            DiamondCase {
                name: "disjoint_edit_and_delete_preserved",
                b1_edits: &[
                    ("mod_a.rs", Some("pub const A: u32 = 10;\n")),
                    ("obsolete.txt", None),
                ],
                b2_edits: &[
                    ("mod_b.rs", Some("pub const B: u32 = 20;\n")),
                    ("new_from_b2.txt", Some("b2 payload\n")),
                ],
                expected_conflict_path: None,
                expected_c_files: &[
                    ("shared.txt", Some("base\n")),
                    ("mod_a.rs", Some("pub const A: u32 = 10;\n")),
                    ("mod_b.rs", Some("pub const B: u32 = 20;\n")),
                    ("new_from_b2.txt", Some("b2 payload\n")),
                    ("obsolete.txt", None),
                ],
            },
            DiamondCase {
                name: "waw_modify_conflict_fails_closed",
                b1_edits: &[("shared.txt", Some("b1 version\n"))],
                b2_edits: &[("shared.txt", Some("b2 conflicting version\n"))],
                expected_conflict_path: Some("shared.txt"),
                expected_c_files: &[],
            },
            DiamondCase {
                name: "delete_vs_modify_conflict_fails_closed",
                b1_edits: &[("shared.txt", None)],
                b2_edits: &[("shared.txt", Some("b2 modified deleted file\n"))],
                expected_conflict_path: Some("shared.txt"),
                expected_c_files: &[],
            },
        ];

        for case in cases {
            let harness = NodeWorkspaceTestHarness::new(
                case.name,
                &[("shared.txt", "base\n"), ("obsolete.txt", "remove me\n")],
            )?;
            let (node_a, node_b1, node_b2, node_c) = (node(10), node(21), node(22), node(30));

            let _ = harness.provision(node_a, &[], 1_000)?;
            let comp_a = harness.complete(
                node_a,
                &[],
                &[(node_b1, vec![node_a]), (node_b2, vec![node_a])],
                2_000,
            )?;
            let b1_ws = &comp_a.provisioned_downstreams()[0];
            let b2_ws = &comp_a.provisioned_downstreams()[1];

            for (path, content) in case.b1_edits {
                let target = b1_ws.worktree_path().join(path);
                match content {
                    Some(text) => fs::write(target, text)?,
                    None => fs::remove_file(target)?,
                }
            }
            for (path, content) in case.b2_edits {
                let target = b2_ws.worktree_path().join(path);
                match content {
                    Some(text) => fs::write(target, text)?,
                    None => fs::remove_file(target)?,
                }
            }

            let _ = harness.complete(node_b1, &[node_a], &[], 3_000)?;
            let b2_result = harness.complete(
                node_b2,
                &[node_a],
                &[(node_c, vec![node_b1, node_b2])],
                4_000,
            );

            if let Some(conflict_path) = case.expected_conflict_path {
                match b2_result {
                    Err(NodeWorkspaceError::HandoffMergeConflict {
                        conflicting_paths, ..
                    }) => {
                        assert!(
                            conflicting_paths.iter().any(|p| p == conflict_path),
                            "case {} expected conflict on {conflict_path}, got {conflicting_paths:?}",
                            case.name
                        );
                    }
                    other => {
                        return Err(format!(
                            "case {} expected HandoffMergeConflict, got {other:?}",
                            case.name
                        )
                        .into());
                    }
                }
                assert!(
                    inspect_node_workspace(
                        &harness.layout,
                        harness.goal_id,
                        harness.dag_revision,
                        node_c
                    )?
                    .is_none()
                );
            } else {
                let comp_b2 = b2_result?;
                let c_ws = &comp_b2.provisioned_downstreams()[0];
                for (path, expected) in case.expected_c_files {
                    let target = c_ws.worktree_path().join(path);
                    match expected {
                        Some(text) => assert_eq!(
                            fs::read_to_string(&target)?,
                            *text,
                            "case {} mismatch on {path}",
                            case.name
                        ),
                        None => assert!(
                            !target.exists(),
                            "case {} expected {path} to remain deleted",
                            case.name
                        ),
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn fail_closed_guards_and_settlement_cas_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let harness = NodeWorkspaceTestHarness::new("guards", &[("tracked.txt", "baseline\n")])?;
        let (node_a, node_b) = (node(101), node(102));

        // Guard 1: Provisioning downstream node B when upstream A has no completed receipt fails closed.
        let err = harness.provision(node_b, &[node_a], 1_000);
        assert!(matches!(
            err,
            Err(NodeWorkspaceError::HandoffInputUnavailable {
                missing_upstream_id,
                ..
            }) if missing_upstream_id == node_a
        ));

        // Guard 2: Completing unprovisioned node fails closed without falling back to workspace_root.
        let err = harness.complete(node_a, &[], &[], 1_000);
        assert!(matches!(
            err,
            Err(NodeWorkspaceError::WorkspaceNotProvisioned { node_id, .. }) if node_id == node_a
        ));

        // Guard 3: Symlinks in node worktree are rejected on completion.
        let receipt_a = harness.provision(node_a, &[], 1_000)?;
        let symlink_path = receipt_a.worktree_path().join("bad_link");
        symlink(receipt_a.worktree_path().join("tracked.txt"), &symlink_path)?;
        let err = harness.complete(node_a, &[], &[], 2_000);
        assert!(matches!(
            err,
            Err(NodeWorkspaceError::UnsupportedWorkspaceEntry { path }) if path == "bad_link"
        ));
        fs::remove_file(&symlink_path)?;

        // Complete A cleanly with a file modification.
        fs::write(receipt_a.worktree_path().join("tracked.txt"), "settled\n")?;
        let _ = harness.complete(node_a, &[], &[], 2_500)?;

        // Guard 4: Settlement Preimage CAS rejects when workspace_root drifted from pinned baseline.
        fs::write(
            harness.workspace_root.join("tracked.txt"),
            "dirty external edit\n",
        )?;
        let err = settle_dag_revision_workspace(
            &harness.layout,
            "settle-cas-1",
            harness.goal_id,
            harness.dag_revision,
            &[node_a],
            TimestampMillis::new(3_000)?,
        );
        assert!(matches!(
            err,
            Err(NodeWorkspaceError::SettlementBaselineConflict { modified_paths, .. })
                if modified_paths == vec!["tracked.txt".to_owned()]
        ));

        // Restore baseline and verify Prepared journal crash recovery.
        fs::write(harness.workspace_root.join("tracked.txt"), "baseline\n")?;
        let settled = settle_dag_revision_workspace(
            &harness.layout,
            "settle-cas-1",
            harness.goal_id,
            harness.dag_revision,
            &[node_a],
            TimestampMillis::new(3_500)?,
        )?;
        assert_eq!(settled.state(), DagSettlementJournalState::Applied);
        assert_eq!(
            fs::read_to_string(harness.workspace_root.join("tracked.txt"))?,
            "settled\n"
        );
        Ok(())
    }
}
