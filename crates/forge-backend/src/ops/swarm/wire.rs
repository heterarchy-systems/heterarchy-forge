//! Typed wire projections shared between Forge backend Swarm command responses
//! and the official `ForgeHttpClient` Swarm adapter.

use forge_control::{
    SettlementJournalState, SwarmConvergenceOutcome, SwarmMemberOutputReceipt, SwarmSettleOutcome,
    SwarmSettledOutboxEntry, SwarmSettlementReceipt, SwarmSettlementView, SwarmWorkspaceReceipt,
};
use forge_domain::{DagNodeId, GoalId, SwarmSettlementTarget, SwarmWorkspaceMode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::effect_facts::wire::{EffectFactWire, swarm_settled_wire};
use super::super::{decode_dag_revision, encode_hex};
use crate::error::ForgeError;

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWorkspaceModeWire {
    Inherit,
    Share,
    Branch,
}

impl SwarmWorkspaceModeWire {
    pub(crate) const fn from_domain(mode: SwarmWorkspaceMode) -> Self {
        match mode {
            SwarmWorkspaceMode::Inherit => Self::Inherit,
            SwarmWorkspaceMode::Share => Self::Share,
            SwarmWorkspaceMode::Branch => Self::Branch,
        }
    }

    pub(crate) const fn into_domain(self) -> SwarmWorkspaceMode {
        match self {
            Self::Inherit => SwarmWorkspaceMode::Inherit,
            Self::Share => SwarmWorkspaceMode::Share,
            Self::Branch => SwarmWorkspaceMode::Branch,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SwarmTargetWire {
    StandaloneSwarm,
    DagNodeHybrid {
        goal_id: Uuid,
        dag_revision: i64,
        node_id: Uuid,
    },
}

impl SwarmTargetWire {
    pub(crate) const fn from_domain(target: SwarmSettlementTarget) -> Self {
        match target {
            SwarmSettlementTarget::StandaloneSwarm => Self::StandaloneSwarm,
            SwarmSettlementTarget::DagNodeHybrid {
                goal_id,
                dag_revision,
                node_id,
            } => Self::DagNodeHybrid {
                goal_id: goal_id.into_uuid(),
                dag_revision: dag_revision.get(),
                node_id: node_id.into_uuid(),
            },
        }
    }

    pub(crate) fn into_domain(self) -> Result<SwarmSettlementTarget, ForgeError> {
        match self {
            Self::StandaloneSwarm => Ok(SwarmSettlementTarget::StandaloneSwarm),
            Self::DagNodeHybrid {
                goal_id,
                dag_revision,
                node_id,
            } => Ok(SwarmSettlementTarget::DagNodeHybrid {
                goal_id: GoalId::from_uuid(goal_id),
                dag_revision: decode_dag_revision(dag_revision)?,
                node_id: DagNodeId::from_uuid(node_id),
            }),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementJournalStateWire {
    Prepared,
    Applied,
    RecoveryRequired,
}

impl SettlementJournalStateWire {
    pub(crate) const fn from_domain(state: SettlementJournalState) -> Self {
        match state {
            SettlementJournalState::Prepared => Self::Prepared,
            SettlementJournalState::Applied => Self::Applied,
            SettlementJournalState::RecoveryRequired => Self::RecoveryRequired,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmMemberOutputWire {
    pub swarm_run_id: Uuid,
    pub member_id: Uuid,
    pub mode: SwarmWorkspaceModeWire,
    pub input_commit_oid: String,
    pub output_commit_oid: String,
    pub initial_tree_blake3: String,
    pub final_tree_blake3: String,
    pub final_file_count: u64,
    pub changed_paths: Vec<String>,
    pub diff_digest: String,
    pub captured_at_ms: i64,
}

impl SwarmMemberOutputWire {
    pub(crate) fn from_domain(receipt: &SwarmMemberOutputReceipt) -> Self {
        Self {
            swarm_run_id: receipt.swarm_run_id().into_uuid(),
            member_id: receipt.member_id().into_uuid(),
            mode: SwarmWorkspaceModeWire::from_domain(receipt.mode()),
            input_commit_oid: receipt.input_commit_oid().to_owned(),
            output_commit_oid: receipt.output_commit_oid().to_owned(),
            initial_tree_blake3: receipt.initial_tree_blake3().to_owned(),
            final_tree_blake3: receipt.final_tree_blake3().to_owned(),
            final_file_count: receipt.final_file_count(),
            changed_paths: receipt.changed_paths().to_vec(),
            diff_digest: encode_hex(&receipt.diff_digest()),
            captured_at_ms: receipt.captured_at().get(),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmWorkspaceReceiptWire {
    pub swarm_run_id: Uuid,
    pub member_id: Uuid,
    pub mode: SwarmWorkspaceModeWire,
    pub target: SwarmTargetWire,
    pub worktree_path: String,
    pub provisioned_at_ms: i64,
    pub initial_tree_blake3: String,
    pub initial_file_count: u64,
    pub input_commit_oid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<SwarmMemberOutputWire>,
}

impl SwarmWorkspaceReceiptWire {
    pub(crate) fn from_domain(receipt: &SwarmWorkspaceReceipt) -> Self {
        Self {
            swarm_run_id: receipt.swarm_run_id().into_uuid(),
            member_id: receipt.member_id().into_uuid(),
            mode: SwarmWorkspaceModeWire::from_domain(receipt.mode()),
            target: SwarmTargetWire::from_domain(receipt.target()),
            worktree_path: receipt.worktree_path().to_string_lossy().into_owned(),
            provisioned_at_ms: receipt.provisioned_at().get(),
            initial_tree_blake3: receipt.initial_tree_blake3().to_owned(),
            initial_file_count: receipt.initial_file_count(),
            input_commit_oid: receipt.input_commit_oid().to_owned(),
            completed: receipt.completed().map(SwarmMemberOutputWire::from_domain),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmWorkspaceGetWire {
    pub workspace_id: Uuid,
    pub swarm_run_id: Uuid,
    pub member_id: Uuid,
    pub found: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SwarmWorkspaceReceiptWire>,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SwarmConvergenceOutcomeWire {
    Converged {
        swarm_run_id: Uuid,
        converged_commit_oid: String,
        converged_tree_blake3: String,
        converged_diff_digest: String,
        changed_files: Vec<String>,
    },
    Conflict {
        swarm_run_id: Uuid,
        conflicting_member_id: Uuid,
        details: Vec<String>,
    },
}

impl SwarmConvergenceOutcomeWire {
    pub(crate) fn from_domain(swarm_run_id: Uuid, outcome: &SwarmConvergenceOutcome) -> Self {
        match outcome {
            SwarmConvergenceOutcome::Converged {
                converged_commit_oid,
                converged_tree_blake3,
                converged_diff_digest,
                changed_files,
            } => Self::Converged {
                swarm_run_id,
                converged_commit_oid: converged_commit_oid.clone(),
                converged_tree_blake3: converged_tree_blake3.clone(),
                converged_diff_digest: encode_hex(converged_diff_digest),
                changed_files: changed_files.clone(),
            },
            SwarmConvergenceOutcome::Conflict {
                conflicting_member_id,
                details,
            } => Self::Conflict {
                swarm_run_id,
                conflicting_member_id: conflicting_member_id.into_uuid(),
                details: details.clone(),
            },
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmSettlementReceiptWire {
    pub settlement_id: String,
    pub swarm_run_id: Uuid,
    pub target: SwarmTargetWire,
    pub state: SettlementJournalStateWire,
    pub settled_at_ms: i64,
    pub baseline_commit_oid: String,
    pub converged_commit_oid: String,
    pub baseline_tree_blake3: String,
    pub settled_tree_blake3: String,
    pub converged_diff_digest: String,
    pub settled_file_count: u64,
    pub upserted_paths: Vec<String>,
    pub deleted_paths: Vec<String>,
}

impl SwarmSettlementReceiptWire {
    pub(crate) fn from_domain(receipt: &SwarmSettlementReceipt) -> Self {
        Self {
            settlement_id: receipt.settlement_id().to_owned(),
            swarm_run_id: receipt.swarm_run_id().into_uuid(),
            target: SwarmTargetWire::from_domain(receipt.target()),
            state: SettlementJournalStateWire::from_domain(receipt.state()),
            settled_at_ms: receipt.settled_at().get(),
            baseline_commit_oid: receipt.baseline_commit_oid().to_owned(),
            converged_commit_oid: receipt.converged_commit_oid().to_owned(),
            baseline_tree_blake3: receipt.baseline_tree_blake3().to_owned(),
            settled_tree_blake3: receipt.settled_tree_blake3().to_owned(),
            converged_diff_digest: encode_hex(&receipt.converged_diff_digest()),
            settled_file_count: receipt.settled_file_count(),
            upserted_paths: receipt.upserted_paths().to_vec(),
            deleted_paths: receipt.deleted_paths().to_vec(),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmSettleWire {
    pub receipt: SwarmSettlementReceiptWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_sequence: Option<u64>,
}

impl SwarmSettleWire {
    pub(crate) fn from_domain(outcome: &SwarmSettleOutcome) -> Self {
        Self {
            receipt: SwarmSettlementReceiptWire::from_domain(&outcome.receipt),
            outbox_sequence: outcome.outbox_sequence,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmSettledOutboxEntryWire {
    pub sequence: u64,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub workspace_id: Uuid,
    pub fact: EffectFactWire,
}

impl SwarmSettledOutboxEntryWire {
    pub(crate) fn from_domain(entry: &SwarmSettledOutboxEntry) -> Self {
        Self {
            sequence: entry.sequence(),
            migration_id: entry.migration_id(),
            destination_id: entry.destination_id(),
            workspace_id: entry.workspace_id().into_uuid(),
            fact: swarm_settled_wire(entry.fact()),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmSettlementGetWire {
    pub workspace_id: Uuid,
    pub swarm_run_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SwarmSettlementReceiptWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_entry: Option<SwarmSettledOutboxEntryWire>,
}

impl SwarmSettlementGetWire {
    pub(crate) fn from_domain(
        workspace_id: Uuid,
        swarm_run_id: Uuid,
        view: &SwarmSettlementView,
    ) -> Self {
        Self {
            workspace_id,
            swarm_run_id,
            receipt: view
                .receipt
                .as_ref()
                .map(SwarmSettlementReceiptWire::from_domain),
            outbox_entry: view
                .outbox_entry
                .as_ref()
                .map(SwarmSettledOutboxEntryWire::from_domain),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SwarmPurgeWire {
    pub workspace_id: Uuid,
    pub swarm_run_id: Uuid,
    pub purged: bool,
}
