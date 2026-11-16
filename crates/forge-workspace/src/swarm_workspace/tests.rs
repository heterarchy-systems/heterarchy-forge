use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use forge_domain::{DagNodeId, DagRevisionNumber, GoalId, TimestampMillis, WorkspaceId};
use uuid::Uuid;

use super::manifests::swarm_run_metadata_dir;
use super::path_policy::is_forbidden_ssd_path;
use super::sha256::Sha256State;
use super::*;
use crate::dag_git_store::{encode_hex, run_git_in_workdir};
use crate::{
    ExistingWorkspaceStateLayout, WorkspaceStateLayout, complete_and_handoff_node_workspace_in,
    provision_node_workspace_in,
};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct SwarmWorkspaceTestHarness {
    ssd_temp_root: PathBuf,
    non_ssd_worktree_root: PathBuf,
    workspace_root: PathBuf,
    layout: ExistingWorkspaceStateLayout,
    workspace_id: WorkspaceId,
    swarm_run_id: SwarmRunId,
}

impl SwarmWorkspaceTestHarness {
    fn new(
        label: &str,
        initial_files: &[(&str, &str)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let ssd_temp_root = std::env::temp_dir().join(format!(
            "heterarchy-forge-swarm-ws-{label}-{}-{id}",
            std::process::id()
        ));
        let non_ssd_base = {
            let ambient = std::env::temp_dir();
            if is_forbidden_ssd_path(&ambient) {
                PathBuf::from("/var/tmp")
            } else {
                ambient
            }
        };
        let non_ssd_worktree_root = non_ssd_base.join(format!(
            "heterarchy-forge-swarm-ext-{label}-{}-{id}",
            std::process::id()
        ));
        let workspace_root = ssd_temp_root.join("location").join("workspace-0");
        fs::create_dir_all(&workspace_root)?;
        fs::create_dir_all(&non_ssd_worktree_root)?;
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
            ssd_temp_root,
            non_ssd_worktree_root,
            workspace_root,
            layout,
            workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(0xCC00 + u128::from(id))),
            swarm_run_id: SwarmRunId::from_uuid(Uuid::from_u128(0xDD00 + u128::from(id))),
        })
    }

    fn provision(
        &self,
        member_id: SwarmMemberId,
        mode: SwarmWorkspaceMode,
        target: SwarmSettlementTarget,
        candidate_commit_oid: Option<&str>,
        at_ms: i64,
    ) -> Result<SwarmWorkspaceReceipt, SwarmWorkspaceError> {
        provision_swarm_member_workspace_in(
            &self.layout,
            Some(&self.non_ssd_worktree_root),
            Some(self.workspace_id),
            self.swarm_run_id,
            member_id,
            mode,
            target,
            candidate_commit_oid,
            TimestampMillis::new(at_ms).map_err(|_| SwarmWorkspaceError::CorruptManifest {
                path: self.workspace_root.clone(),
                reason: "invalid test timestamp",
            })?,
        )
    }
}

impl Drop for SwarmWorkspaceTestHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.ssd_temp_root);
        let _ = fs::remove_dir_all(&self.non_ssd_worktree_root);
    }
}

fn member(seed: u128) -> SwarmMemberId {
    SwarmMemberId::from_uuid(Uuid::from_u128(seed))
}

#[test]
fn sha256_matches_nist_test_vectors() {
    let empty = Sha256State::new().finalize();
    assert_eq!(
        encode_hex(&empty),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let mut abc_hasher = Sha256State::new();
    abc_hasher.update(b"abc");
    assert_eq!(
        encode_hex(&abc_hasher.finalize()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let mut multi_hasher = Sha256State::new();
    multi_hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        encode_hex(&multi_hasher.finalize()),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn external_worktree_root_forbids_rustbuild_ssd_symlinks_and_workspace_nesting()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = SwarmWorkspaceTestHarness::new("paths", &[("lib.rs", "fn main() {}\n")])?;
    let verifier = member(1);

    // 1. Explicit /Volumes/256.SSD/RustBuild root is rejected fail-closed.
    let ssd_err = provision_swarm_member_workspace_in(
        &harness.layout,
        Some(Path::new("/Volumes/256.SSD/RustBuild/forbidden-swarm")),
        Some(harness.workspace_id),
        harness.swarm_run_id,
        verifier,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        TimestampMillis::new(1_000)?,
    );
    assert!(matches!(
        ssd_err,
        Err(SwarmWorkspaceError::ForbiddenSsdWorktreeRoot { .. })
    ));

    // 2. Symlink pointing into /Volumes/256.SSD/RustBuild is rejected fail-closed.
    let link_root = harness.non_ssd_worktree_root.join("ssd-symlink-trap");
    symlink(Path::new("/Volumes/256.SSD/RustBuild"), &link_root)?;
    let symlink_err = provision_swarm_member_workspace_in(
        &harness.layout,
        Some(&link_root),
        Some(harness.workspace_id),
        harness.swarm_run_id,
        verifier,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        TimestampMillis::new(1_000)?,
    );
    assert!(matches!(
        symlink_err,
        Err(SwarmWorkspaceError::ForbiddenSsdWorktreeRoot { .. })
    ));

    // 3. Worktree root inside <workspace_root> is rejected fail-closed (test against non-SSD workspace).
    let non_ssd_ws = harness.non_ssd_worktree_root.join("non-ssd-ws");
    fs::create_dir_all(&non_ssd_ws)?;
    let _ = WorkspaceStateLayout::initialize(&non_ssd_ws)?;
    let non_ssd_layout = WorkspaceStateLayout::inspect_existing(&non_ssd_ws)?
        .ok_or("missing non-ssd workspace state layout")?;
    let nested_root = non_ssd_ws.join("nested-worktrees");
    let nested_err = provision_swarm_member_workspace_in(
        &non_ssd_layout,
        Some(&nested_root),
        Some(harness.workspace_id),
        harness.swarm_run_id,
        verifier,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        TimestampMillis::new(1_000)?,
    );
    assert!(matches!(
        nested_err,
        Err(SwarmWorkspaceError::WorktreeInsideWorkspaceRoot { .. })
    ));
    Ok(())
}

#[test]
fn inherit_mode_enforces_immutability_and_forbids_convergence_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = SwarmWorkspaceTestHarness::new(
        "inherit",
        &[("src/lib.rs", "pub fn val() -> u32 { 1 }\n")],
    )?;
    let verifier = member(10);
    let receipt = harness.provision(
        verifier,
        SwarmWorkspaceMode::Inherit,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        1_000,
    )?;
    assert_eq!(receipt.mode(), SwarmWorkspaceMode::Inherit);
    assert!(
        receipt
            .worktree_path()
            .starts_with(&harness.non_ssd_worktree_root)
    );

    // Clean read-only capture succeeds with non-divergent output_commit_oid == input_commit_oid.
    let clean_capture = capture_member_output(
        &harness.layout,
        harness.swarm_run_id,
        verifier,
        TimestampMillis::new(1_500)?,
    )?;
    assert_eq!(
        clean_capture.output_commit_oid(),
        clean_capture.input_commit_oid()
    );
    assert!(clean_capture.changed_paths().is_empty());

    // Passing an Inherit receipt to converge_swarm_candidates fails closed.
    let converge_err = converge_swarm_candidates(
        &harness.layout,
        harness.swarm_run_id,
        &[clean_capture],
        TimestampMillis::new(1_600)?,
    );
    assert!(matches!(
        converge_err,
        Err(SwarmWorkspaceError::InheritCannotContributeCandidate { member_id, .. })
            if member_id == verifier
    ));

    // Mutating any file in the Inherit worktree causes capture_member_output to fail closed.
    fs::write(
        receipt.worktree_path().join("src/lib.rs"),
        "pub fn val() -> u32 { 999 }\n",
    )?;
    let mutated_err = capture_member_output(
        &harness.layout,
        harness.swarm_run_id,
        verifier,
        TimestampMillis::new(2_000)?,
    );
    assert!(matches!(
        mutated_err,
        Err(SwarmWorkspaceError::InheritWorkspaceMutated { changed_paths, .. })
            if changed_paths == vec!["src/lib.rs".to_owned()]
    ));
    Ok(())
}

#[test]
fn parallel_share_and_branch_three_way_merge_convergence_and_preimage_cas_settlement()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = SwarmWorkspaceTestHarness::new(
        "converge",
        &[
            ("shared.txt", "line1\nline2\nline3\nline4\nline5\n"),
            ("obsolete.txt", "delete me\n"),
        ],
    )?;
    let (m_share, m_branch, m_verifier) = (member(101), member(102), member(103));
    let ws_share = harness.provision(
        m_share,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        1_000,
    )?;
    let ws_branch = harness.provision(
        m_branch,
        SwarmWorkspaceMode::Branch,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        1_000,
    )?;
    assert!(ws_branch.worktree_path().join(".git").is_dir());
    assert!(!ws_share.worktree_path().join(".git").exists());

    populate_parallel_share_and_branch_edits(&ws_share, &ws_branch)?;
    let out_share = capture_member_output(
        &harness.layout,
        harness.swarm_run_id,
        m_share,
        TimestampMillis::new(2_000)?,
    )?;
    let out_branch = capture_member_output(
        &harness.layout,
        harness.swarm_run_id,
        m_branch,
        TimestampMillis::new(2_100)?,
    )?;
    assert_ne!(out_share.diff_digest(), [0_u8; 32]);
    assert_ne!(out_branch.diff_digest(), [0_u8; 32]);

    let SwarmConvergenceOutcome::Converged {
        converged_commit_oid,
        converged_tree_blake3,
        converged_diff_digest,
        changed_files,
    } = converge_swarm_candidates(
        &harness.layout,
        harness.swarm_run_id,
        &[out_share, out_branch],
        TimestampMillis::new(2_500)?,
    )?
    else {
        return Err("expected Converged outcome".into());
    };
    assert_eq!(
        changed_files,
        vec!["branch.rs", "obsolete.txt", "share.rs", "shared.txt"]
    );

    let verifier_ws = harness.provision(
        m_verifier,
        SwarmWorkspaceMode::Inherit,
        SwarmSettlementTarget::StandaloneSwarm,
        Some(&converged_commit_oid),
        2_600,
    )?;
    assert_eq!(verifier_ws.initial_tree_blake3(), converged_tree_blake3);
    assert_eq!(
        fs::read_to_string(verifier_ws.worktree_path().join("shared.txt"))?,
        "line1-share\nline2\nline3\nline4\nline5-branch\n"
    );

    verify_preimage_cas_and_standalone_settlement(
        &harness,
        &converged_commit_oid,
        &converged_tree_blake3,
        converged_diff_digest,
    )
}

fn populate_parallel_share_and_branch_edits(
    ws_share: &SwarmWorkspaceReceipt,
    ws_branch: &SwarmWorkspaceReceipt,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(
        ws_share.worktree_path().join("shared.txt"),
        "line1-share\nline2\nline3\nline4\nline5\n",
    )?;
    fs::write(
        ws_share.worktree_path().join("share.rs"),
        "pub const SHARE: u32 = 1;\n",
    )?;
    fs::remove_file(ws_share.worktree_path().join("obsolete.txt"))?;

    fs::write(
        ws_branch.worktree_path().join("shared.txt"),
        "line1\nline2\nline3\nline4\nline5-branch\n",
    )?;
    fs::write(
        ws_branch.worktree_path().join("branch.rs"),
        "pub const BRANCH: u32 = 2;\n",
    )?;
    run_git_in_workdir(
        ws_branch.worktree_path(),
        &["add", "-A"],
        TimestampMillis::new(1_500)?,
    )?;
    run_git_in_workdir(
        ws_branch.worktree_path(),
        &["commit", "-q", "-m", "branch work"],
        TimestampMillis::new(1_500)?,
    )?;
    Ok(())
}

fn verify_preimage_cas_and_standalone_settlement(
    harness: &SwarmWorkspaceTestHarness,
    converged_commit_oid: &str,
    converged_tree_blake3: &str,
    converged_diff_digest: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(
        harness.workspace_root.join("shared.txt"),
        "external dirty edit\n",
    )?;
    let cas_err = settle_standalone_swarm_workspace(
        &harness.layout,
        "swarm-settle-1",
        harness.swarm_run_id,
        converged_commit_oid,
        Some(converged_diff_digest),
        TimestampMillis::new(3_000)?,
    );
    assert!(matches!(
        cas_err,
        Err(SwarmWorkspaceError::SettlementBaselineConflict { modified_paths, .. })
            if modified_paths == vec!["shared.txt".to_owned()]
    ));

    fs::write(
        harness.workspace_root.join("shared.txt"),
        "line1\nline2\nline3\nline4\nline5\n",
    )?;
    let receipt = settle_standalone_swarm_workspace(
        &harness.layout,
        "swarm-settle-1",
        harness.swarm_run_id,
        converged_commit_oid,
        Some(converged_diff_digest),
        TimestampMillis::new(3_500)?,
    )?;
    assert_eq!(receipt.state(), SettlementJournalState::Applied);
    assert_eq!(receipt.settled_tree_blake3(), converged_tree_blake3);
    assert_eq!(receipt.converged_diff_digest(), converged_diff_digest);
    assert_eq!(
        fs::read_to_string(harness.workspace_root.join("shared.txt"))?,
        "line1-share\nline2\nline3\nline4\nline5-branch\n"
    );
    assert_eq!(
        fs::read_to_string(harness.workspace_root.join("share.rs"))?,
        "pub const SHARE: u32 = 1;\n"
    );
    assert_eq!(
        fs::read_to_string(harness.workspace_root.join("branch.rs"))?,
        "pub const BRANCH: u32 = 2;\n"
    );
    assert!(!harness.workspace_root.join("obsolete.txt").exists());
    assert_eq!(
        inspect_swarm_settlement(&harness.layout, harness.swarm_run_id)?,
        Some(receipt)
    );
    Ok(())
}

#[test]
fn parallel_share_merge_conflict_returns_typed_conflict_without_mutating_workspace()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = SwarmWorkspaceTestHarness::new("conflict", &[("shared.txt", "baseline\n")])?;
    let (m1, m2) = (member(201), member(202));
    let ws1 = harness.provision(
        m1,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        1_000,
    )?;
    let ws2 = harness.provision(
        m2,
        SwarmWorkspaceMode::Share,
        SwarmSettlementTarget::StandaloneSwarm,
        None,
        1_000,
    )?;
    fs::write(ws1.worktree_path().join("shared.txt"), "member 1 edit\n")?;
    fs::write(
        ws2.worktree_path().join("shared.txt"),
        "member 2 conflict\n",
    )?;

    let out1 = capture_member_output(
        &harness.layout,
        harness.swarm_run_id,
        m1,
        TimestampMillis::new(2_000)?,
    )?;
    let out2 = capture_member_output(
        &harness.layout,
        harness.swarm_run_id,
        m2,
        TimestampMillis::new(2_100)?,
    )?;

    let outcome = converge_swarm_candidates(
        &harness.layout,
        harness.swarm_run_id,
        &[out1, out2],
        TimestampMillis::new(2_500)?,
    )?;
    match outcome {
        SwarmConvergenceOutcome::Conflict {
            conflicting_member_id,
            details,
        } => {
            assert_eq!(conflicting_member_id, m2);
            assert!(!details.is_empty());
        }
        SwarmConvergenceOutcome::Converged { .. } => {
            return Err("expected Conflict outcome".into());
        }
    }
    assert_eq!(
        fs::read_to_string(harness.workspace_root.join("shared.txt"))?,
        "baseline\n"
    );
    Ok(())
}

#[test]
fn dag_node_hybrid_materializes_into_node_worktree_without_mutating_workspace_root()
-> Result<(), Box<dyn std::error::Error>> {
    let harness =
        SwarmWorkspaceTestHarness::new("hybrid", &[("app.rs", "pub fn ver() -> u32 { 0 }\n")])?;
    let goal_id = GoalId::from_uuid(Uuid::from_u128(0xEE01));
    let dag_revision = DagRevisionNumber::INITIAL;
    let node_id = DagNodeId::from_uuid(Uuid::from_u128(0xEE02));
    let dag_worktrees_root = harness.non_ssd_worktree_root.join("dag-nodes");
    let node_ws = provision_node_workspace_in(
        &harness.layout,
        Some(&dag_worktrees_root),
        Some(harness.workspace_id),
        goal_id,
        dag_revision,
        node_id,
        &[],
        TimestampMillis::new(500)?,
    )?;

    let (converged_commit_oid, converged_diff_digest) =
        run_hybrid_worker(&harness, goal_id, dag_revision, node_id)?;

    // Standalone settlement MUST refuse a DagNodeHybrid swarm run.
    let wrong_target = settle_standalone_swarm_workspace(
        &harness.layout,
        "wrong-standalone",
        harness.swarm_run_id,
        &converged_commit_oid,
        Some(converged_diff_digest),
        TimestampMillis::new(2_200)?,
    );
    assert!(matches!(
        wrong_target,
        Err(SwarmWorkspaceError::TargetMismatch { .. })
    ));

    let hybrid_receipt = materialize_dag_node_hybrid_swarm_workspace(
        &harness.layout,
        "hybrid-settle-1",
        harness.swarm_run_id,
        goal_id,
        dag_revision,
        node_id,
        &converged_commit_oid,
        Some(converged_diff_digest),
        TimestampMillis::new(2_500)?,
    )?;
    assert_eq!(hybrid_receipt.state(), SettlementJournalState::Applied);
    assert_eq!(
        fs::read_to_string(node_ws.worktree_path().join("app.rs"))?,
        "pub fn ver() -> u32 { 42 }\n"
    );
    assert_eq!(
        fs::read_to_string(harness.workspace_root.join("app.rs"))?,
        "pub fn ver() -> u32 { 0 }\n"
    );

    let completed_node = complete_and_handoff_node_workspace_in(
        &harness.layout,
        Some(&dag_worktrees_root),
        Some(harness.workspace_id),
        goal_id,
        dag_revision,
        node_id,
        &[],
        &[],
        TimestampMillis::new(3_000)?,
    )?;
    assert_eq!(
        completed_node
            .completed()
            .completed()
            .map(crate::NodeWorkspaceCompletedState::final_tree_blake3),
        Some(hybrid_receipt.settled_tree_blake3())
    );

    purge_swarm_workspaces(
        &harness.layout,
        Some(&harness.non_ssd_worktree_root),
        Some(harness.workspace_id),
        harness.swarm_run_id,
    )?;
    assert!(!swarm_run_metadata_dir(&harness.layout, harness.swarm_run_id).exists());
    Ok(())
}

fn run_hybrid_worker(
    harness: &SwarmWorkspaceTestHarness,
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
) -> Result<(String, [u8; 32]), Box<dyn std::error::Error>> {
    let target = SwarmSettlementTarget::DagNodeHybrid {
        goal_id,
        dag_revision,
        node_id,
    };
    let worker = member(301);
    let worker_ws = harness.provision(worker, SwarmWorkspaceMode::Share, target, None, 1_000)?;
    fs::write(
        worker_ws.worktree_path().join("app.rs"),
        "pub fn ver() -> u32 { 42 }\n",
    )?;
    let worker_out = capture_member_output(
        &harness.layout,
        harness.swarm_run_id,
        worker,
        TimestampMillis::new(1_500)?,
    )?;
    let SwarmConvergenceOutcome::Converged {
        converged_commit_oid,
        converged_diff_digest,
        ..
    } = converge_swarm_candidates(
        &harness.layout,
        harness.swarm_run_id,
        &[worker_out],
        TimestampMillis::new(2_000)?,
    )?
    else {
        return Err("expected hybrid convergence".into());
    };
    Ok((converged_commit_oid, converged_diff_digest))
}
