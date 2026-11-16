//! Durable Swarm baseline/handoff/completed manifests, crash-safe settlement journal codec,
//! and canonical SHA-256 transition diff digest computation.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use forge_domain::{
    DagNodeId, DagRevisionNumber, GoalId, SwarmMemberId, SwarmRunId, SwarmSettlementTarget,
    SwarmWorkspaceMode, TimestampMillis,
};

use super::sha256::Sha256State;
use super::{
    SwarmMemberOutputReceipt, SwarmPinnedBaseline, SwarmSettlementReceipt, SwarmWorkspaceError,
    SwarmWorkspaceReceipt,
};
use crate::ExistingWorkspaceStateLayout;
use crate::dag_git_store::{
    MANIFEST_VERSION, PinnedBaseline, SettlementJournalState, TreeManifest, decode_hex_32,
    encode_hex, encode_manifest_entries, parse_i64_header, parse_manifest_entries,
    parse_u64_header, required_header, split_headers_and_entries, validate_relative_path,
};

const SWARM_WORKSPACES_SUBDIR: &str = "swarm-workspaces";
const MEMBERS_SUBDIR: &str = "members";
const SWARM_SETTLEMENTS_SUBDIR: &str = "swarm-settlements";
pub(super) const BASELINE_MANIFEST_NAME: &str = "baseline.manifest";
pub(super) const HANDOFF_MANIFEST_NAME: &str = "handoff.manifest";
pub(super) const COMPLETED_MANIFEST_NAME: &str = "completed.manifest";
const SWARM_DIFF_DIGEST_DOMAIN: &[u8] = b"heterarchy-forge:swarm-diff-transition:v1\0";

pub(super) fn swarm_base_ref(swarm_run_id: SwarmRunId) -> String {
    format!("refs/forge/swarm/{swarm_run_id}/base")
}

pub(super) fn swarm_member_ref(swarm_run_id: SwarmRunId, member_id: SwarmMemberId) -> String {
    format!("refs/forge/swarm/{swarm_run_id}/member/{member_id}")
}

pub(super) fn swarm_converged_ref(swarm_run_id: SwarmRunId) -> String {
    format!("refs/forge/swarm/{swarm_run_id}/converged")
}

pub(super) fn swarm_run_metadata_dir(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
) -> PathBuf {
    layout
        .artifacts()
        .join(SWARM_WORKSPACES_SUBDIR)
        .join(swarm_run_id.to_string())
}

pub(super) fn baseline_manifest_path(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
) -> PathBuf {
    swarm_run_metadata_dir(layout, swarm_run_id).join(BASELINE_MANIFEST_NAME)
}

pub(super) fn member_metadata_dir(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
    member_id: SwarmMemberId,
) -> PathBuf {
    swarm_run_metadata_dir(layout, swarm_run_id)
        .join(MEMBERS_SUBDIR)
        .join(member_id.to_string())
}

pub(super) fn swarm_settlement_dir(
    layout: &ExistingWorkspaceStateLayout,
    swarm_run_id: SwarmRunId,
) -> PathBuf {
    layout
        .recovery()
        .join(SWARM_SETTLEMENTS_SUBDIR)
        .join(swarm_run_id.to_string())
}

/// Compute canonical SHA-256 over the sorted tree transition `(initial -> final_manifest)`
/// using the caller's already-computed sorted `changed_paths` slice.
pub(super) fn compute_transition_diff_digest_for_paths(
    initial: &TreeManifest,
    final_manifest: &TreeManifest,
    changed_paths: &[String],
) -> [u8; 32] {
    let mut hasher = Sha256State::new();
    hasher.update(SWARM_DIFF_DIGEST_DOMAIN);
    hasher.update_length_prefixed(initial.tree_blake3.as_bytes());
    hasher.update_length_prefixed(final_manifest.tree_blake3.as_bytes());
    let count = u64::try_from(changed_paths.len()).unwrap_or(u64::MAX);
    hasher.update(&count.to_be_bytes());
    for path in changed_paths {
        hasher.update_length_prefixed(path.as_bytes());
        match initial.entries.get(path) {
            Some(meta) => {
                hasher.update(&[1]);
                hasher.update(&meta.mode.to_be_bytes());
                hasher.update_length_prefixed(meta.blake3_hex.as_bytes());
            }
            None => hasher.update(&[0]),
        }
        match final_manifest.entries.get(path) {
            Some(meta) => {
                hasher.update(&[1]);
                hasher.update(&meta.mode.to_be_bytes());
                hasher.update_length_prefixed(meta.blake3_hex.as_bytes());
            }
            None => hasher.update(&[0]),
        }
    }
    hasher.finalize()
}

fn encode_target_headers(out: &mut String, target: SwarmSettlementTarget) {
    match target {
        SwarmSettlementTarget::StandaloneSwarm => {
            let _ = writeln!(out, "target_kind=standalone_swarm");
        }
        SwarmSettlementTarget::DagNodeHybrid {
            goal_id,
            dag_revision,
            node_id,
        } => {
            let _ = writeln!(out, "target_kind=dag_node_hybrid");
            let _ = writeln!(out, "target_goal_id={goal_id}");
            let _ = writeln!(out, "target_dag_revision={}", dag_revision.get());
            let _ = writeln!(out, "target_node_id={node_id}");
        }
    }
}

fn parse_target_headers(
    headers: &BTreeMap<&str, &str>,
    path: &Path,
) -> Result<SwarmSettlementTarget, SwarmWorkspaceError> {
    match required_header(headers, path, "target_kind")? {
        "standalone_swarm" => Ok(SwarmSettlementTarget::StandaloneSwarm),
        "dag_node_hybrid" => {
            let goal_id = GoalId::from_str(required_header(headers, path, "target_goal_id")?)
                .map_err(|_| SwarmWorkspaceError::CorruptManifest {
                    path: path.to_path_buf(),
                    reason: "invalid target_goal_id UUID",
                })?;
            let dag_rev_raw = parse_i64_header(headers, path, "target_dag_revision")?;
            let dag_revision = DagRevisionNumber::new(dag_rev_raw).map_err(|_| {
                SwarmWorkspaceError::CorruptManifest {
                    path: path.to_path_buf(),
                    reason: "invalid target_dag_revision",
                }
            })?;
            let node_id = DagNodeId::from_str(required_header(headers, path, "target_node_id")?)
                .map_err(|_| SwarmWorkspaceError::CorruptManifest {
                    path: path.to_path_buf(),
                    reason: "invalid target_node_id UUID",
                })?;
            Ok(SwarmSettlementTarget::DagNodeHybrid {
                goal_id,
                dag_revision,
                node_id,
            })
        }
        _ => Err(SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "unknown swarm settlement target_kind",
        }),
    }
}

pub(super) fn encode_baseline_manifest(
    swarm_run_id: SwarmRunId,
    pinned_at: TimestampMillis,
    pinned: &SwarmPinnedBaseline,
) -> Vec<u8> {
    let mut out = String::new();
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "swarm_run_id={swarm_run_id}");
    encode_target_headers(&mut out, pinned.target);
    let _ = writeln!(out, "pinned_at_ms={}", pinned_at.get());
    let _ = writeln!(out, "base_commit_oid={}", pinned.baseline.base_commit_oid);
    let _ = writeln!(out, "tree_blake3={}", pinned.baseline.manifest.tree_blake3);
    let _ = writeln!(out, "file_count={}", pinned.baseline.manifest.entries.len());
    encode_manifest_entries(&mut out, &pinned.baseline.manifest);
    out.into_bytes()
}

pub(super) fn parse_baseline_manifest(
    path: &Path,
) -> Result<SwarmPinnedBaseline, SwarmWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| SwarmWorkspaceError::Io {
        context: "reading swarm baseline manifest",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let target = parse_target_headers(&headers, path)?;
    let base_commit_oid = required_header(&headers, path, "base_commit_oid")?.to_owned();
    let tree_blake3 = required_header(&headers, path, "tree_blake3")?.to_owned();
    let file_count = parse_u64_header(&headers, path, "file_count")?;
    let manifest = parse_manifest_entries(path, &entry_lines, &tree_blake3, file_count)?;
    Ok(SwarmPinnedBaseline {
        target,
        baseline: PinnedBaseline {
            base_commit_oid,
            manifest,
        },
    })
}

pub(super) fn encode_handoff_manifest(
    receipt: &SwarmWorkspaceReceipt,
    manifest: &TreeManifest,
) -> Vec<u8> {
    let mut out = String::new();
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "swarm_run_id={}", receipt.swarm_run_id);
    let _ = writeln!(out, "member_id={}", receipt.member_id);
    let _ = writeln!(out, "mode={}", receipt.mode.as_str());
    encode_target_headers(&mut out, receipt.target);
    let _ = writeln!(out, "worktree_path={}", receipt.worktree_path.display());
    let _ = writeln!(out, "provisioned_at_ms={}", receipt.provisioned_at.get());
    let _ = writeln!(out, "input_commit_oid={}", receipt.input_commit_oid);
    let _ = writeln!(out, "initial_tree_blake3={}", receipt.initial_tree_blake3);
    let _ = writeln!(out, "initial_file_count={}", receipt.initial_file_count);
    encode_manifest_entries(&mut out, manifest);
    out.into_bytes()
}

pub(super) fn parse_handoff_manifest(
    path: &Path,
) -> Result<(SwarmWorkspaceReceipt, TreeManifest), SwarmWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| SwarmWorkspaceError::Io {
        context: "reading swarm member handoff manifest",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let swarm_run_id = SwarmRunId::from_str(required_header(&headers, path, "swarm_run_id")?)
        .map_err(|_| SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid swarm_run_id UUID",
        })?;
    let member_id = SwarmMemberId::from_str(required_header(&headers, path, "member_id")?)
        .map_err(|_| SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid member_id UUID",
        })?;
    let mode =
        SwarmWorkspaceMode::from_str(required_header(&headers, path, "mode")?).map_err(|_| {
            SwarmWorkspaceError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid swarm workspace mode",
            }
        })?;
    let target = parse_target_headers(&headers, path)?;
    let worktree_path = PathBuf::from(required_header(&headers, path, "worktree_path")?);
    let provisioned_at_raw = parse_i64_header(&headers, path, "provisioned_at_ms")?;
    let provisioned_at = TimestampMillis::new(provisioned_at_raw).map_err(|_| {
        SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid provisioned_at_ms timestamp",
        }
    })?;
    let input_commit_oid = required_header(&headers, path, "input_commit_oid")?.to_owned();
    let initial_tree_blake3 = required_header(&headers, path, "initial_tree_blake3")?.to_owned();
    let initial_file_count = parse_u64_header(&headers, path, "initial_file_count")?;
    let manifest =
        parse_manifest_entries(path, &entry_lines, &initial_tree_blake3, initial_file_count)?;
    Ok((
        SwarmWorkspaceReceipt {
            swarm_run_id,
            member_id,
            mode,
            target,
            worktree_path,
            provisioned_at,
            initial_tree_blake3,
            initial_file_count,
            input_commit_oid,
            completed: None,
        },
        manifest,
    ))
}

pub(super) fn encode_completed_manifest(receipt: &SwarmMemberOutputReceipt) -> Vec<u8> {
    let mut out = String::new();
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "swarm_run_id={}", receipt.swarm_run_id);
    let _ = writeln!(out, "member_id={}", receipt.member_id);
    let _ = writeln!(out, "mode={}", receipt.mode.as_str());
    let _ = writeln!(out, "input_commit_oid={}", receipt.input_commit_oid);
    let _ = writeln!(out, "output_commit_oid={}", receipt.output_commit_oid);
    let _ = writeln!(out, "initial_tree_blake3={}", receipt.initial_tree_blake3);
    let _ = writeln!(out, "final_tree_blake3={}", receipt.final_tree_blake3);
    let _ = writeln!(out, "final_file_count={}", receipt.final_file_count);
    let _ = writeln!(out, "diff_digest={}", encode_hex(&receipt.diff_digest));
    let _ = writeln!(out, "captured_at_ms={}", receipt.captured_at.get());
    let _ = writeln!(out, "---");
    for path in &receipt.changed_paths {
        let _ = writeln!(out, "{path}");
    }
    out.into_bytes()
}

pub(super) fn parse_completed_manifest(
    path: &Path,
) -> Result<SwarmMemberOutputReceipt, SwarmWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| SwarmWorkspaceError::Io {
        context: "reading swarm member completed manifest",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let swarm_run_id = SwarmRunId::from_str(required_header(&headers, path, "swarm_run_id")?)
        .map_err(|_| SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid swarm_run_id UUID",
        })?;
    let member_id = SwarmMemberId::from_str(required_header(&headers, path, "member_id")?)
        .map_err(|_| SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid member_id UUID",
        })?;
    let mode =
        SwarmWorkspaceMode::from_str(required_header(&headers, path, "mode")?).map_err(|_| {
            SwarmWorkspaceError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid swarm workspace mode",
            }
        })?;
    let input_commit_oid = required_header(&headers, path, "input_commit_oid")?.to_owned();
    let output_commit_oid = required_header(&headers, path, "output_commit_oid")?.to_owned();
    let initial_tree_blake3 = required_header(&headers, path, "initial_tree_blake3")?.to_owned();
    let final_tree_blake3 = required_header(&headers, path, "final_tree_blake3")?.to_owned();
    let final_file_count = parse_u64_header(&headers, path, "final_file_count")?;
    let diff_digest = decode_hex_32(
        required_header(&headers, path, "diff_digest")?,
        path,
        "invalid diff_digest hex",
    )?;
    let captured_at_raw = parse_i64_header(&headers, path, "captured_at_ms")?;
    let captured_at = TimestampMillis::new(captured_at_raw).map_err(|_| {
        SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid captured_at_ms timestamp",
        }
    })?;
    let mut changed_paths = Vec::new();
    for line in entry_lines {
        if !line.is_empty() {
            validate_relative_path(line)?;
            changed_paths.push(line.to_owned());
        }
    }
    Ok(SwarmMemberOutputReceipt {
        swarm_run_id,
        member_id,
        mode,
        input_commit_oid,
        output_commit_oid,
        initial_tree_blake3,
        final_tree_blake3,
        final_file_count,
        changed_paths,
        diff_digest,
        captured_at,
    })
}

pub(super) fn encode_settlement_journal(receipt: &SwarmSettlementReceipt) -> Vec<u8> {
    let mut out = String::new();
    let _ = writeln!(out, "version={MANIFEST_VERSION}");
    let _ = writeln!(out, "settlement_id={}", receipt.settlement_id);
    let _ = writeln!(out, "swarm_run_id={}", receipt.swarm_run_id);
    encode_target_headers(&mut out, receipt.target);
    let _ = writeln!(out, "state={}", receipt.state.as_str());
    let _ = writeln!(out, "settled_at_ms={}", receipt.settled_at.get());
    let _ = writeln!(out, "baseline_commit_oid={}", receipt.baseline_commit_oid);
    let _ = writeln!(out, "converged_commit_oid={}", receipt.converged_commit_oid);
    let _ = writeln!(out, "baseline_tree_blake3={}", receipt.baseline_tree_blake3);
    let _ = writeln!(out, "settled_tree_blake3={}", receipt.settled_tree_blake3);
    let _ = writeln!(
        out,
        "converged_diff_digest={}",
        encode_hex(&receipt.converged_diff_digest)
    );
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

pub(super) fn parse_settlement_journal(
    path: &Path,
) -> Result<SwarmSettlementReceipt, SwarmWorkspaceError> {
    let text = fs::read_to_string(path).map_err(|source| SwarmWorkspaceError::Io {
        context: "reading swarm settlement journal",
        source,
    })?;
    let (headers, entry_lines) = split_headers_and_entries(path, &text)?;
    let settlement_id = required_header(&headers, path, "settlement_id")?.to_owned();
    let swarm_run_id = SwarmRunId::from_str(required_header(&headers, path, "swarm_run_id")?)
        .map_err(|_| SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid swarm_run_id in settlement journal",
        })?;
    let target = parse_target_headers(&headers, path)?;
    let state = SettlementJournalState::parse(required_header(&headers, path, "state")?)
        .ok_or_else(|| SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid state in swarm settlement journal",
        })?;
    let settled_at_raw = parse_i64_header(&headers, path, "settled_at_ms")?;
    let settled_at =
        TimestampMillis::new(settled_at_raw).map_err(|_| SwarmWorkspaceError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "invalid settled_at_ms in swarm settlement journal",
        })?;
    let baseline_commit_oid = required_header(&headers, path, "baseline_commit_oid")?.to_owned();
    let converged_commit_oid = required_header(&headers, path, "converged_commit_oid")?.to_owned();
    let baseline_tree_blake3 = required_header(&headers, path, "baseline_tree_blake3")?.to_owned();
    let settled_tree_blake3 = required_header(&headers, path, "settled_tree_blake3")?.to_owned();
    let converged_diff_digest = decode_hex_32(
        required_header(&headers, path, "converged_diff_digest")?,
        path,
        "invalid converged_diff_digest hex in swarm settlement journal",
    )?;
    let settled_file_count = parse_u64_header(&headers, path, "settled_file_count")?;

    let mut upserted_paths = Vec::new();
    let mut deleted_paths = Vec::new();
    for line in entry_lines {
        if line.is_empty() {
            continue;
        }
        let Some((op, rel_path)) = line.split_once('\t') else {
            return Err(SwarmWorkspaceError::CorruptManifest {
                path: path.to_path_buf(),
                reason: "invalid delta line in swarm settlement journal",
            });
        };
        validate_relative_path(rel_path)?;
        match op {
            "U" => upserted_paths.push(rel_path.to_owned()),
            "D" => deleted_paths.push(rel_path.to_owned()),
            _ => {
                return Err(SwarmWorkspaceError::CorruptManifest {
                    path: path.to_path_buf(),
                    reason: "unknown delta operation in swarm settlement journal",
                });
            }
        }
    }

    Ok(SwarmSettlementReceipt {
        settlement_id,
        swarm_run_id,
        target,
        state,
        settled_at,
        baseline_commit_oid,
        converged_commit_oid,
        baseline_tree_blake3,
        settled_tree_blake3,
        converged_diff_digest,
        settled_file_count,
        upserted_paths,
        deleted_paths,
    })
}
