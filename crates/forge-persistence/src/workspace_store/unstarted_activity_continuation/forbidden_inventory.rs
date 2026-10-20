//! Closed denial census for physical/effect/history state.

use forge_domain::{ActivityId, WorkspaceId};
use rusqlite::{Connection, params};

use super::UnstartedActivityContinuationStoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ForbiddenInventoryAttribution {
    Direct,
    ParentJoin,
    WorkspaceWide,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryBinding {
    Invalid,
    None,
    Workspace,
    WorkspaceActivity,
}

impl QueryBinding {
    const fn parameter_count(self) -> usize {
        match self {
            Self::Invalid => usize::MAX,
            Self::None => 0,
            Self::Workspace => 1,
            Self::WorkspaceActivity => 2,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ForbiddenInventoryDescriptor {
    pub(super) key: &'static str,
    pub(super) table: &'static str,
    pub(super) attribution: ForbiddenInventoryAttribution,
    denied_sql: &'static str,
    denied_binding: QueryBinding,
    corrupt_sql: Option<&'static str>,
    corrupt_binding: QueryBinding,
}

const fn query_binding(sql: &str) -> QueryBinding {
    let bytes = sql.as_bytes();
    let mut index = 0;
    let mut binding = QueryBinding::None;
    while index + 1 < bytes.len() {
        if bytes[index] == b'?' {
            binding = match bytes[index + 1] {
                b'1' if matches!(binding, QueryBinding::None) => QueryBinding::Workspace,
                b'1' => binding,
                b'2' => QueryBinding::WorkspaceActivity,
                _ => QueryBinding::Invalid,
            };
        }
        index += 1;
    }
    binding
}

macro_rules! descriptor {
    ($table:literal, $attribution:ident, $denied:literal) => {
        ForbiddenInventoryDescriptor {
            key: concat!("forbidden:", $table),
            table: $table,
            attribution: ForbiddenInventoryAttribution::$attribution,
            denied_sql: $denied,
            denied_binding: query_binding($denied),
            corrupt_sql: None,
            corrupt_binding: QueryBinding::None,
        }
    };
    ($table:literal, $attribution:ident, $denied:literal, $corrupt:literal) => {
        ForbiddenInventoryDescriptor {
            key: concat!("forbidden:", $table),
            table: $table,
            attribution: ForbiddenInventoryAttribution::$attribution,
            denied_sql: $denied,
            denied_binding: query_binding($denied),
            corrupt_sql: Some($corrupt),
            corrupt_binding: query_binding($corrupt),
        }
    };
}

pub(super) const CONDITIONAL_SEMANTIC_META_KEY: &str = "conditional:semantic_events_meta";

pub(super) const FORBIDDEN_INVENTORY: &[ForbiddenInventoryDescriptor] = &[
    descriptor!(
        "activity_coordinator_recoveries",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM activity_coordinator_recoveries WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "agent_departure_reconciliations",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM agent_departure_reconciliations WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "agent_work_update_evidence_refs",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM agent_work_update_evidence_refs r JOIN agent_work_updates u ON u.update_id=r.update_id AND u.agent_id=r.agent_id AND u.workspace_id=r.workspace_id WHERE u.workspace_id=?1 AND u.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM agent_work_update_evidence_refs r LEFT JOIN agent_work_updates u ON u.update_id=r.update_id AND u.agent_id=r.agent_id AND u.workspace_id=r.workspace_id WHERE r.workspace_id=?1 AND u.update_id IS NULL)"
    ),
    descriptor!(
        "approval_requests",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM approval_requests WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "assignment_continuation_acknowledgments",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_acknowledgments a JOIN assignment_continuation_proposals p ON p.successor_id=a.successor_id JOIN assignment_continuation_batches b ON b.transfer_id=p.transfer_id AND b.cut_id=p.cut_id JOIN leadership_work_cuts c ON c.cut_id=b.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_acknowledgments a LEFT JOIN assignment_continuation_proposals p ON p.successor_id=a.successor_id WHERE p.successor_id IS NULL)"
    ),
    descriptor!(
        "assignment_continuation_batches",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_batches b JOIN leadership_work_cuts c ON c.cut_id=b.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_batches b LEFT JOIN leadership_work_cuts c ON c.cut_id=b.cut_id WHERE c.cut_id IS NULL)"
    ),
    descriptor!(
        "assignment_continuation_proposals",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_proposals p JOIN assignment_continuation_batches b ON b.transfer_id=p.transfer_id AND b.cut_id=p.cut_id JOIN leadership_work_cuts c ON c.cut_id=b.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM assignment_continuation_proposals p LEFT JOIN assignment_continuation_batches b ON b.transfer_id=p.transfer_id AND b.cut_id=p.cut_id LEFT JOIN leadership_work_cut_nodes n ON n.cut_id=p.cut_id AND n.ordinal=p.source_ordinal WHERE b.transfer_id IS NULL OR n.cut_id IS NULL)"
    ),
    descriptor!(
        "authority_stop_batches",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM authority_stop_batches b JOIN workspace_execution_stops s ON s.stop_id=b.stop_id WHERE s.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM authority_stop_batches b LEFT JOIN workspace_execution_stops s ON s.stop_id=b.stop_id WHERE s.stop_id IS NULL OR b.workspace_id!=s.workspace_id)"
    ),
    descriptor!(
        "authority_stop_targets",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM authority_stop_targets t JOIN authority_stop_batches b ON b.stop_id=t.stop_id JOIN workspace_execution_stops s ON s.stop_id=b.stop_id WHERE s.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM authority_stop_targets t LEFT JOIN authority_stop_batches b ON b.stop_id=t.stop_id WHERE b.stop_id IS NULL)"
    ),
    descriptor!(
        "auto_approval_scopes",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM auto_approval_scopes WHERE workspace_id=?1 AND (activity_id IS NULL OR activity_id=?2))"
    ),
    descriptor!(
        "change_sets",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM change_sets WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "checkpoint_restores",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM checkpoint_restores r JOIN checkpoints c ON c.checkpoint_id=r.checkpoint_id WHERE c.workspace_id=?1 AND c.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM checkpoint_restores r LEFT JOIN checkpoints c ON c.checkpoint_id=r.checkpoint_id WHERE c.checkpoint_id IS NULL OR r.workspace_id!=c.workspace_id)"
    ),
    descriptor!(
        "checkpoints",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "diff_entries",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM diff_entries e JOIN diff_evidence d ON d.diff_id=e.diff_id JOIN change_sets c ON c.changeset_id=d.changeset_id WHERE c.workspace_id=?1 AND c.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM diff_entries e LEFT JOIN diff_evidence d ON d.diff_id=e.diff_id WHERE d.diff_id IS NULL)"
    ),
    descriptor!(
        "diff_evidence",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM diff_evidence d JOIN change_sets c ON c.changeset_id=d.changeset_id WHERE c.workspace_id=?1 AND c.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM diff_evidence d LEFT JOIN change_sets c ON c.changeset_id=d.changeset_id WHERE c.changeset_id IS NULL)"
    ),
    descriptor!(
        "effect_fact_outbox_assignment_review",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_review WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "effect_fact_outbox_assignment_submitted",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_submitted WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "effect_fact_outbox_assignment_submitted_source_ref",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_submitted_source_ref r JOIN effect_fact_outbox_assignment_submitted s ON s.outbox_sequence=r.outbox_sequence WHERE s.workspace_id=?1 AND s.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_submitted_source_ref r LEFT JOIN effect_fact_outbox_assignment_submitted s ON s.outbox_sequence=r.outbox_sequence WHERE s.outbox_sequence IS NULL)"
    ),
    descriptor!(
        "effect_fact_outbox_change_set",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_change_set WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "effect_fact_outbox_execution_terminal",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_execution_terminal f JOIN executions e ON e.execution_id=f.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM effect_fact_outbox_execution_terminal f LEFT JOIN executions e ON e.execution_id=f.execution_id LEFT JOIN effect_fact_outbox_entries o ON o.sequence=f.outbox_sequence WHERE e.execution_id IS NULL OR o.sequence IS NULL OR (e.execution_id IS NOT NULL AND (f.activity_id!=e.activity_id OR o.workspace_id!=e.workspace_id OR o.fact_kind!=2)))"
    ),
    descriptor!(
        "execution_admission_consumptions",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM execution_admission_consumptions a JOIN executions e ON e.execution_id=a.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM execution_admission_consumptions a LEFT JOIN executions e ON e.execution_id=a.execution_id WHERE e.execution_id IS NULL)"
    ),
    descriptor!(
        "execution_command_evidence",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM execution_command_evidence x JOIN executions e ON e.execution_id=x.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM execution_command_evidence x LEFT JOIN executions e ON e.execution_id=x.execution_id WHERE e.execution_id IS NULL)"
    ),
    descriptor!(
        "execution_generated_artifacts",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM execution_generated_artifacts x JOIN executions e ON e.execution_id=x.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM execution_generated_artifacts x LEFT JOIN executions e ON e.execution_id=x.execution_id WHERE e.execution_id IS NULL OR (e.execution_id IS NOT NULL AND x.workspace_id!=e.workspace_id))"
    ),
    descriptor!(
        "execution_grants",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM execution_grants WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "execution_native_closures",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM execution_native_closures WHERE workspace_id=?1 AND activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM execution_native_closures x LEFT JOIN executions e ON e.execution_id=x.execution_id WHERE x.workspace_id=?1 AND x.activity_id=?2 AND (e.execution_id IS NULL OR x.workspace_id!=e.workspace_id OR x.activity_id!=e.activity_id))"
    ),
    descriptor!(
        "execution_output_events",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM execution_output_events x JOIN executions e ON e.execution_id=x.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM execution_output_events x LEFT JOIN executions e ON e.execution_id=x.execution_id WHERE e.execution_id IS NULL)"
    ),
    descriptor!(
        "execution_provenance",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM execution_provenance x JOIN executions e ON e.execution_id=x.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM execution_provenance x LEFT JOIN executions e ON e.execution_id=x.execution_id LEFT JOIN goals g ON g.goal_id=x.goal_id LEFT JOIN agent_instances a ON a.agent_id=x.agent_id WHERE e.execution_id IS NULL OR g.goal_id IS NULL OR a.agent_id IS NULL OR (e.execution_id IS NOT NULL AND g.goal_id IS NOT NULL AND (g.workspace_id!=e.workspace_id OR g.activity_id!=e.activity_id OR x.goal_revision!=g.revision)) OR (e.execution_id IS NOT NULL AND a.agent_id IS NOT NULL AND (a.workspace_id!=e.workspace_id OR a.activity_id!=e.activity_id OR x.agent_revision>a.revision OR x.session_id IS NOT a.session_id)))"
    ),
    descriptor!(
        "executions",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM executions WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "file_mutations",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM file_mutations m JOIN change_sets c ON c.changeset_id=m.changeset_id WHERE c.workspace_id=?1 AND c.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM file_mutations m LEFT JOIN change_sets c ON c.changeset_id=m.changeset_id WHERE c.changeset_id IS NULL)"
    ),
    descriptor!(
        "goal_completion_reviews",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM goal_completion_reviews r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM goal_completion_reviews r LEFT JOIN goals g ON g.goal_id=r.goal_id WHERE g.goal_id IS NULL OR (g.goal_id IS NOT NULL AND r.goal_revision!=g.revision))"
    ),
    descriptor!(
        "goal_dag_node_evidence_refs",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM goal_dag_node_evidence_refs r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM goal_dag_node_evidence_refs r LEFT JOIN goal_dag_nodes n ON n.goal_id=r.goal_id AND n.dag_revision=r.dag_revision AND n.node_id=r.node_id LEFT JOIN goals g ON g.goal_id=r.goal_id WHERE n.node_id IS NULL OR g.goal_id IS NULL)"
    ),
    descriptor!(
        "goal_deletion_cleanup_journal",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM goal_deletion_cleanup_journal WHERE workspace_id=?1 AND activity_id=?2)"
    ),
    descriptor!(
        "goal_evidence_refs",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM goal_evidence_refs r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM goal_evidence_refs r LEFT JOIN goals g ON g.goal_id=r.goal_id WHERE g.goal_id IS NULL)"
    ),
    descriptor!(
        "leadership_work_cut_agents",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_agents a JOIN leadership_work_cuts c ON c.cut_id=a.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_agents a LEFT JOIN leadership_work_cuts c ON c.cut_id=a.cut_id WHERE c.cut_id IS NULL)"
    ),
    descriptor!(
        "leadership_work_cut_effects",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_effects e JOIN leadership_work_cuts c ON c.cut_id=e.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_effects e LEFT JOIN leadership_work_cuts c ON c.cut_id=e.cut_id WHERE c.cut_id IS NULL)"
    ),
    descriptor!(
        "leadership_work_cut_nodes",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_nodes n JOIN leadership_work_cuts c ON c.cut_id=n.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_nodes n LEFT JOIN leadership_work_cuts c ON c.cut_id=n.cut_id LEFT JOIN leadership_work_cut_agents a ON a.cut_id=n.cut_id AND a.agent_id=n.agent_id WHERE c.cut_id IS NULL OR a.agent_id IS NULL OR (a.agent_id IS NOT NULL AND n.activity_id!=a.activity_id))"
    ),
    descriptor!(
        "leadership_work_cut_sessions",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_sessions s JOIN leadership_work_cuts c ON c.cut_id=s.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_sessions s LEFT JOIN leadership_work_cuts c ON c.cut_id=s.cut_id WHERE c.cut_id IS NULL)"
    ),
    descriptor!(
        "leadership_work_cut_team_nodes",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_team_nodes n JOIN leadership_work_cuts c ON c.cut_id=n.cut_id WHERE c.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cut_team_nodes n LEFT JOIN leadership_work_cuts c ON c.cut_id=n.cut_id WHERE c.cut_id IS NULL)"
    ),
    descriptor!(
        "leadership_work_cuts",
        WorkspaceWide,
        "SELECT EXISTS(SELECT 1 FROM leadership_work_cuts WHERE workspace_id=?1)"
    ),
    descriptor!(
        "recovery_run_activities",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM recovery_run_activities a JOIN recovery_runs r ON r.request_id=a.request_id WHERE r.workspace_id=?1 AND a.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM recovery_run_activities a LEFT JOIN recovery_runs r ON r.request_id=a.request_id WHERE a.workspace_id=?1 AND (r.request_id IS NULL OR a.workspace_id!=r.workspace_id))"
    ),
    descriptor!(
        "recovery_run_executions",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM recovery_run_executions x JOIN recovery_runs r ON r.request_id=x.request_id WHERE r.workspace_id=?1 AND x.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM recovery_run_executions x LEFT JOIN recovery_runs r ON r.request_id=x.request_id LEFT JOIN executions e ON e.execution_id=x.execution_id WHERE x.workspace_id=?1 AND (r.request_id IS NULL OR e.execution_id IS NULL OR x.workspace_id!=r.workspace_id OR (e.execution_id IS NOT NULL AND (x.workspace_id!=e.workspace_id OR x.activity_id!=e.activity_id OR x.request_digest!=e.request_digest))) )"
    ),
    descriptor!(
        "root_recovery_delegation_receipts",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM root_recovery_delegation_receipts WHERE workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM root_recovery_delegation_receipts d LEFT JOIN workspace_root_recovery_receipts r ON r.request_id=d.request_id WHERE d.workspace_id=?1 AND (r.request_id IS NULL OR d.workspace_id!=r.workspace_id))"
    ),
    descriptor!(
        "source_tree_requests",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM source_tree_requests r JOIN change_sets c ON c.changeset_id=r.changeset_id WHERE c.workspace_id=?1 AND c.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM source_tree_requests r LEFT JOIN change_sets c ON c.changeset_id=r.changeset_id WHERE c.changeset_id IS NULL)"
    ),
    descriptor!(
        "tree_mutations",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM tree_mutations m JOIN change_sets c ON c.changeset_id=m.changeset_id WHERE c.workspace_id=?1 AND c.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM tree_mutations m LEFT JOIN change_sets c ON c.changeset_id=m.changeset_id WHERE c.changeset_id IS NULL)"
    ),
    descriptor!(
        "verification_inputs",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM verification_inputs i JOIN verification_runs r ON r.input_id=i.input_id JOIN executions e ON e.execution_id=r.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM verification_runs r LEFT JOIN verification_inputs i ON i.input_id=r.input_id LEFT JOIN executions e ON e.execution_id=r.execution_id WHERE r.workspace_id=?1 AND (i.input_id IS NULL OR e.execution_id IS NULL OR (i.input_id IS NOT NULL AND i.workspace_id!=r.workspace_id)))"
    ),
    descriptor!(
        "verification_requirement_links",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM verification_requirement_links l JOIN verification_runs r ON r.execution_id=l.execution_id JOIN executions e ON e.execution_id=r.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM verification_requirement_links l LEFT JOIN verification_runs r ON r.execution_id=l.execution_id LEFT JOIN goals g ON g.goal_id=l.goal_id WHERE r.execution_id IS NULL OR g.goal_id IS NULL OR (g.goal_id IS NOT NULL AND l.goal_revision!=g.revision))"
    ),
    descriptor!(
        "verification_runs",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM verification_runs r JOIN executions e ON e.execution_id=r.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM verification_runs r LEFT JOIN executions e ON e.execution_id=r.execution_id WHERE r.workspace_id=?1 AND (e.execution_id IS NULL OR r.workspace_id!=e.workspace_id))"
    ),
    descriptor!(
        "workspace_execution_stop_fences",
        WorkspaceWide,
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_fences WHERE workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_fences f LEFT JOIN workspace_execution_stops s ON s.stop_id=f.stop_id WHERE f.workspace_id=?1 AND (s.stop_id IS NULL OR f.workspace_id!=s.workspace_id))"
    ),
    descriptor!(
        "workspace_execution_stop_settlement_targets",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_settlement_targets t JOIN workspace_execution_stops s ON s.stop_id=t.stop_id WHERE s.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_settlement_targets t LEFT JOIN workspace_execution_stop_settlements z ON z.stop_id=t.stop_id LEFT JOIN executions e ON e.execution_id=t.execution_id WHERE z.stop_id IS NULL OR e.execution_id IS NULL)"
    ),
    descriptor!(
        "workspace_execution_stop_settlements",
        WorkspaceWide,
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_settlements WHERE workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_settlements z LEFT JOIN workspace_execution_stops s ON s.stop_id=z.stop_id WHERE z.workspace_id=?1 AND (s.stop_id IS NULL OR z.workspace_id!=s.workspace_id OR z.request_id!=s.request_id OR z.owner_runtime_instance_id!=s.owner_runtime_instance_id))"
    ),
    descriptor!(
        "workspace_execution_stop_targets",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_targets t JOIN workspace_execution_stops s ON s.stop_id=t.stop_id WHERE s.workspace_id=?1)",
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_targets t LEFT JOIN workspace_execution_stops s ON s.stop_id=t.stop_id LEFT JOIN executions e ON e.execution_id=t.execution_id WHERE s.stop_id IS NULL OR e.execution_id IS NULL OR (s.stop_id IS NOT NULL AND e.execution_id IS NOT NULL AND e.workspace_id!=s.workspace_id))"
    ),
    descriptor!(
        "workspace_execution_stops",
        WorkspaceWide,
        "SELECT EXISTS(SELECT 1 FROM workspace_execution_stops WHERE workspace_id=?1)"
    ),
    descriptor!(
        "workspace_root_recovery_receipts",
        WorkspaceWide,
        "SELECT EXISTS(SELECT 1 FROM workspace_root_recovery_receipts WHERE workspace_id=?1)"
    ),
    descriptor!(
        "writer_lease_scope_entries",
        ParentJoin,
        "SELECT EXISTS(SELECT 1 FROM writer_lease_scope_entries s JOIN writer_leases l ON l.lease_id=s.lease_id WHERE l.workspace_id=?1 AND l.activity_id=?2)",
        "SELECT EXISTS(SELECT 1 FROM writer_lease_scope_entries s LEFT JOIN writer_leases l ON l.lease_id=s.lease_id WHERE l.lease_id IS NULL)"
    ),
    descriptor!(
        "writer_leases",
        Direct,
        "SELECT EXISTS(SELECT 1 FROM writer_leases WHERE workspace_id=?1 AND activity_id=?2)"
    ),
];

pub(super) const FORBIDDEN_INVENTORY_TABLES: &[&str] = &[
    "activity_coordinator_recoveries",
    "agent_departure_reconciliations",
    "agent_work_update_evidence_refs",
    "approval_requests",
    "assignment_continuation_acknowledgments",
    "assignment_continuation_batches",
    "assignment_continuation_proposals",
    "authority_stop_batches",
    "authority_stop_targets",
    "auto_approval_scopes",
    "change_sets",
    "checkpoint_restores",
    "checkpoints",
    "diff_entries",
    "diff_evidence",
    "effect_fact_outbox_assignment_review",
    "effect_fact_outbox_assignment_submitted",
    "effect_fact_outbox_assignment_submitted_source_ref",
    "effect_fact_outbox_change_set",
    "effect_fact_outbox_execution_terminal",
    "execution_admission_consumptions",
    "execution_command_evidence",
    "execution_generated_artifacts",
    "execution_grants",
    "execution_native_closures",
    "execution_output_events",
    "execution_provenance",
    "executions",
    "file_mutations",
    "goal_completion_reviews",
    "goal_dag_node_evidence_refs",
    "goal_deletion_cleanup_journal",
    "goal_evidence_refs",
    "leadership_work_cut_agents",
    "leadership_work_cut_effects",
    "leadership_work_cut_nodes",
    "leadership_work_cut_sessions",
    "leadership_work_cut_team_nodes",
    "leadership_work_cuts",
    "recovery_run_activities",
    "recovery_run_executions",
    "root_recovery_delegation_receipts",
    "source_tree_requests",
    "tree_mutations",
    "verification_inputs",
    "verification_requirement_links",
    "verification_runs",
    "workspace_execution_stop_fences",
    "workspace_execution_stop_settlement_targets",
    "workspace_execution_stop_settlements",
    "workspace_execution_stop_targets",
    "workspace_execution_stops",
    "workspace_root_recovery_receipts",
    "writer_lease_scope_entries",
    "writer_leases",
];

pub(super) fn validate_forbidden_inventory_empty(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    validate_registry()?;
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let conditional_orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_assignment_sources s LEFT JOIN agent_assignments a ON a.assignment_id=s.assignment_id WHERE a.assignment_id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    if conditional_orphan {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "forbidden inventory attribution",
        ));
    }
    for descriptor in FORBIDDEN_INVENTORY {
        if let Some(sql) = descriptor.corrupt_sql {
            let corrupt = query_bool(
                connection,
                sql,
                descriptor.corrupt_binding,
                &workspace,
                &activity,
            )?;
            if corrupt {
                return Err(UnstartedActivityContinuationStoreError::Corrupt(
                    "forbidden inventory attribution",
                ));
            }
        }
        let denied = query_bool(
            connection,
            descriptor.denied_sql,
            descriptor.denied_binding,
            &workspace,
            &activity,
        )?;
        if denied {
            return Err(UnstartedActivityContinuationStoreError::Conflict(
                descriptor.key,
            ));
        }
    }
    validate_recovery_runs(connection, workspace.as_slice())?;
    validate_semantic_events_meta(connection, workspace.as_slice())
}

fn query_bool(
    connection: &Connection,
    sql: &str,
    binding: QueryBinding,
    workspace_id: &[u8],
    activity_id: &[u8],
) -> Result<bool, UnstartedActivityContinuationStoreError> {
    let mut statement = connection.prepare(sql)?;
    if statement.parameter_count() != binding.parameter_count() {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "forbidden inventory query parameter count",
        ));
    }
    let value = match binding {
        QueryBinding::Invalid => {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "forbidden inventory query parameter shape",
            ));
        }
        QueryBinding::None => statement.query_row([], |row| row.get(0))?,
        QueryBinding::Workspace => statement.query_row(params![workspace_id], |row| row.get(0))?,
        QueryBinding::WorkspaceActivity => {
            statement.query_row(params![workspace_id, activity_id], |row| row.get(0))?
        }
    };
    Ok(value)
}

fn validate_registry() -> Result<(), UnstartedActivityContinuationStoreError> {
    if FORBIDDEN_INVENTORY.len() != 55
        || FORBIDDEN_INVENTORY_TABLES.len() != 55
        || CONDITIONAL_SEMANTIC_META_KEY.is_empty()
        || CONDITIONAL_RECOVERY_RUNS_KEY.is_empty()
    {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "forbidden inventory registry size",
        ));
    }
    let mut attribution_counts = [0_usize; 3];
    for (index, descriptor) in FORBIDDEN_INVENTORY.iter().enumerate() {
        attribution_counts[match descriptor.attribution {
            ForbiddenInventoryAttribution::Direct => 0,
            ForbiddenInventoryAttribution::ParentJoin => 1,
            ForbiddenInventoryAttribution::WorkspaceWide => 2,
        }] += 1;
        if descriptor.key.is_empty()
            || descriptor.table.is_empty()
            || descriptor.table != FORBIDDEN_INVENTORY_TABLES[index]
            || FORBIDDEN_INVENTORY[..index]
                .iter()
                .any(|prior| prior.key == descriptor.key || prior.table == descriptor.table)
        {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "forbidden inventory registry",
            ));
        }
    }
    if attribution_counts != [14, 36, 5] {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "forbidden inventory attribution registry",
        ));
    }
    Ok(())
}

/// Conditional key for workspace recovery classification history.
pub(super) const CONDITIONAL_RECOVERY_RUNS_KEY: &str = "conditional:recovery_runs";

/// Every Source boot records one released recovery classification run. A run
/// that classified nothing is not a physical effect; any run that interrupted
/// an Activity or settled an Execution is not classified as unstarted history
/// and denies, and declared counts must agree with the child rows.
fn validate_recovery_runs(
    connection: &Connection,
    workspace_id: &[u8],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let mismatch: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM recovery_runs r
           WHERE r.workspace_id=?1 AND (
             r.activity_count != (SELECT COUNT(*) FROM recovery_run_activities a WHERE a.request_id=r.request_id)
             OR r.execution_count != (SELECT COUNT(*) FROM recovery_run_executions x WHERE x.request_id=r.request_id)))",
        params![workspace_id],
        |row| row.get(0),
    )?;
    if mismatch {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "forbidden inventory attribution",
        ));
    }
    let effectful: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM recovery_runs WHERE workspace_id=?1 AND (activity_count != 0 OR execution_count != 0))",
        params![workspace_id],
        |row| row.get(0),
    )?;
    if effectful {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            CONDITIONAL_RECOVERY_RUNS_KEY,
        ));
    }
    Ok(())
}

fn validate_semantic_events_meta(
    connection: &Connection,
    workspace_id: &[u8],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let invalid: bool = connection.query_row(
        "SELECT
           (EXISTS(SELECT 1 FROM semantic_events WHERE workspace_id=?1)
             AND NOT EXISTS(SELECT 1 FROM semantic_events_meta WHERE workspace_id=?1))
           OR EXISTS(
             SELECT 1 FROM semantic_events_meta m
             WHERE m.workspace_id=?1 AND (
               m.retained_low!=0 OR
               m.high_water_seq!=(SELECT COALESCE(MAX(e.sequence),0) FROM semantic_events e WHERE e.workspace_id=m.workspace_id)))",
        params![workspace_id],
        |row| row.get(0),
    )?;
    if invalid {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "semantic event cursor is incomplete, inconsistent, or pruned",
        ));
    }
    Ok(())
}
