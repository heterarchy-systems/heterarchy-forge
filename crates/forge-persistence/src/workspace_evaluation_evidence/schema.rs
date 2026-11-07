use rusqlite::{Connection, OptionalExtension};

use super::EvaluationEvidenceStoreError;

const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;

const SOURCE_STATE: &str = "CREATE TABLE workspace_evaluation_source_state (workspace_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), source_sequence INTEGER NOT NULL CHECK(source_sequence >= 0), clock_health INTEGER NOT NULL CHECK(clock_health IN (0, 1, 2)), last_trusted_at_ms INTEGER CHECK(last_trusted_at_ms IS NULL OR last_trusted_at_ms >= 0), last_uncertainty_sequence INTEGER CHECK(last_uncertainty_sequence IS NULL OR last_uncertainty_sequence BETWEEN 1 AND source_sequence), CHECK((clock_health = 0 AND last_trusted_at_ms IS NULL AND last_uncertainty_sequence IS NULL) OR (clock_health = 1 AND last_trusted_at_ms IS NOT NULL) OR (clock_health = 2 AND last_uncertainty_sequence IS NOT NULL)))";
const ORIGINAL_BINDINGS: &str = "CREATE TABLE workspace_evaluation_original_bindings (workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), assignment_id BLOB NOT NULL CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), backend_id BLOB NOT NULL CHECK(length(backend_id) = 16 AND backend_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), delegation_migration_id BLOB NOT NULL CHECK(length(delegation_migration_id) = 16 AND delegation_migration_id != zeroblob(16)), delegation_destination_id BLOB NOT NULL CHECK(length(delegation_destination_id) = 16 AND delegation_destination_id != zeroblob(16)), delegation_freeze_revision INTEGER NOT NULL CHECK(delegation_freeze_revision >= 1), delegation_manifest_digest BLOB NOT NULL CHECK(length(delegation_manifest_digest) = 32 AND delegation_manifest_digest != zeroblob(32)), target_agent_id BLOB NOT NULL CHECK(length(target_agent_id) = 16 AND target_agent_id != zeroblob(16)), target_session_id BLOB NOT NULL CHECK(length(target_session_id) = 16 AND target_session_id != zeroblob(16)), assignment_revision INTEGER NOT NULL CHECK(assignment_revision >= 1), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16 AND goal_id != zeroblob(16)), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)), node_revision INTEGER NOT NULL CHECK(node_revision >= 1), work_unit_id BLOB NOT NULL CHECK(length(work_unit_id) = 16 AND work_unit_id != zeroblob(16)), obligation_id BLOB NOT NULL CHECK(length(obligation_id) = 16 AND obligation_id != zeroblob(16)), criteria_digest BLOB NOT NULL CHECK(length(criteria_digest) = 32 AND criteria_digest != zeroblob(32)), binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32 AND binding_digest != zeroblob(32)), binding_sequence INTEGER NOT NULL CHECK(binding_sequence >= 1), PRIMARY KEY(workspace_id, assignment_id), UNIQUE(workspace_id, work_unit_id))";
const MANIFESTS: &str = "CREATE TABLE workspace_evaluation_manifests (workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), manifest_id BLOB NOT NULL CHECK(length(manifest_id) = 16 AND manifest_id != zeroblob(16)), manifest_revision INTEGER NOT NULL CHECK(manifest_revision >= 1), backend_id BLOB NOT NULL CHECK(length(backend_id) = 16 AND backend_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), delegation_migration_id BLOB NOT NULL CHECK(length(delegation_migration_id) = 16 AND delegation_migration_id != zeroblob(16)), delegation_destination_id BLOB NOT NULL CHECK(length(delegation_destination_id) = 16 AND delegation_destination_id != zeroblob(16)), delegation_freeze_revision INTEGER NOT NULL CHECK(delegation_freeze_revision >= 1), delegation_manifest_digest BLOB NOT NULL CHECK(length(delegation_manifest_digest) = 32 AND delegation_manifest_digest != zeroblob(32)), plan_id BLOB NOT NULL CHECK(length(plan_id) = 16 AND plan_id != zeroblob(16)), plan_revision INTEGER NOT NULL CHECK(plan_revision >= 1), plan_digest BLOB NOT NULL CHECK(length(plan_digest) = 32 AND plan_digest != zeroblob(32)), deadline_ms INTEGER NOT NULL CHECK(deadline_ms >= 0), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)), sealed_sequence INTEGER NOT NULL CHECK(sealed_sequence >= 1), seal_time_status INTEGER NOT NULL CHECK(seal_time_status IN (0, 1, 2)), sealed_at_ms INTEGER CHECK(sealed_at_ms IS NULL OR sealed_at_ms >= 0), PRIMARY KEY(workspace_id, manifest_id, manifest_revision), CHECK((seal_time_status = 0 AND sealed_at_ms IS NOT NULL) OR (seal_time_status IN (1, 2) AND sealed_at_ms IS NULL)))";
const MANIFEST_MEMBERS: &str = "CREATE TABLE workspace_evaluation_manifest_members (workspace_id BLOB NOT NULL, manifest_id BLOB NOT NULL, manifest_revision INTEGER NOT NULL CHECK(manifest_revision >= 1), assignment_id BLOB NOT NULL CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), work_unit_id BLOB NOT NULL CHECK(length(work_unit_id) = 16 AND work_unit_id != zeroblob(16)), obligation_id BLOB NOT NULL CHECK(length(obligation_id) = 16 AND obligation_id != zeroblob(16)), assignment_revision INTEGER NOT NULL CHECK(assignment_revision >= 1), target_agent_id BLOB NOT NULL CHECK(length(target_agent_id) = 16 AND target_agent_id != zeroblob(16)), target_session_id BLOB NOT NULL CHECK(length(target_session_id) = 16 AND target_session_id != zeroblob(16)), criteria_digest BLOB NOT NULL CHECK(length(criteria_digest) = 32 AND criteria_digest != zeroblob(32)), binding_status INTEGER NOT NULL CHECK(binding_status IN (0, 1)), binding_assignment_id BLOB CHECK(binding_assignment_id IS NULL OR (length(binding_assignment_id) = 16 AND binding_assignment_id != zeroblob(16))), binding_digest BLOB CHECK(binding_digest IS NULL OR (length(binding_digest) = 32 AND binding_digest != zeroblob(32))), binding_sequence INTEGER CHECK(binding_sequence IS NULL OR binding_sequence >= 1), PRIMARY KEY(workspace_id, manifest_id, manifest_revision, assignment_id), UNIQUE(workspace_id, manifest_id, manifest_revision, work_unit_id), UNIQUE(workspace_id, manifest_id, manifest_revision, obligation_id), FOREIGN KEY(workspace_id, manifest_id, manifest_revision) REFERENCES workspace_evaluation_manifests(workspace_id, manifest_id, manifest_revision), FOREIGN KEY(workspace_id, binding_assignment_id) REFERENCES workspace_evaluation_original_bindings(workspace_id, assignment_id), CHECK((binding_status = 0 AND binding_assignment_id IS NOT NULL AND binding_assignment_id = assignment_id AND binding_digest IS NOT NULL AND binding_sequence IS NOT NULL) OR (binding_status = 1 AND binding_assignment_id IS NULL AND binding_digest IS NULL AND binding_sequence IS NULL)))";
const SUBMISSION_RECEIPTS: &str = "CREATE TABLE workspace_evaluation_submission_receipts (workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), assignment_id BLOB NOT NULL CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), submitted_revision INTEGER NOT NULL CHECK(submitted_revision >= 1), author_agent_id BLOB NOT NULL CHECK(length(author_agent_id) = 16 AND author_agent_id != zeroblob(16)), author_session_id BLOB NOT NULL CHECK(length(author_session_id) = 16 AND author_session_id != zeroblob(16)), original_binding_digest BLOB CHECK(original_binding_digest IS NULL OR (length(original_binding_digest) = 32 AND original_binding_digest != zeroblob(32))), criteria_digest BLOB CHECK(criteria_digest IS NULL OR (length(criteria_digest) = 32 AND criteria_digest != zeroblob(32))), source_sequence INTEGER NOT NULL CHECK(source_sequence >= 1), admission_time_status INTEGER NOT NULL CHECK(admission_time_status IN (0, 1, 2)), admitted_at_ms INTEGER CHECK(admitted_at_ms IS NULL OR admitted_at_ms >= 0), result_digest BLOB NOT NULL CHECK(length(result_digest) = 32 AND result_digest != zeroblob(32)), sources_digest BLOB CHECK(sources_digest IS NULL OR (length(sources_digest) = 32 AND sources_digest != zeroblob(32))), PRIMARY KEY(workspace_id, assignment_id, submitted_revision), CHECK((original_binding_digest IS NULL AND criteria_digest IS NULL) OR (original_binding_digest IS NOT NULL AND criteria_digest IS NOT NULL)), CHECK((admission_time_status = 0 AND admitted_at_ms IS NOT NULL) OR (admission_time_status IN (1, 2) AND admitted_at_ms IS NULL)))";
const REVIEW_RECEIPTS: &str = "CREATE TABLE workspace_evaluation_review_receipts (workspace_id BLOB NOT NULL, assignment_id BLOB NOT NULL, submitted_revision INTEGER NOT NULL CHECK(submitted_revision >= 1), review_revision INTEGER NOT NULL CHECK(review_revision > submitted_revision), source_sequence INTEGER NOT NULL CHECK(source_sequence >= 1), review_time_status INTEGER NOT NULL CHECK(review_time_status IN (0, 1, 2)), reviewed_at_ms INTEGER CHECK(reviewed_at_ms IS NULL OR reviewed_at_ms >= 0), outcome INTEGER NOT NULL CHECK(outcome IN (0, 1)), author_agent_id BLOB NOT NULL CHECK(length(author_agent_id) = 16 AND author_agent_id != zeroblob(16)), author_session_id BLOB NOT NULL CHECK(length(author_session_id) = 16 AND author_session_id != zeroblob(16)), reviewer_agent_id BLOB NOT NULL CHECK(length(reviewer_agent_id) = 16 AND reviewer_agent_id != zeroblob(16)), reviewer_session_id BLOB NOT NULL CHECK(length(reviewer_session_id) = 16 AND reviewer_session_id != zeroblob(16)), result_digest BLOB NOT NULL CHECK(length(result_digest) = 32 AND result_digest != zeroblob(32)), PRIMARY KEY(workspace_id, assignment_id, submitted_revision, review_revision), FOREIGN KEY(workspace_id, assignment_id, submitted_revision) REFERENCES workspace_evaluation_submission_receipts(workspace_id, assignment_id, submitted_revision), CHECK((review_time_status = 0 AND reviewed_at_ms IS NOT NULL) OR (review_time_status IN (1, 2) AND reviewed_at_ms IS NULL)), CHECK(reviewer_agent_id != author_agent_id))";
const T1_CUTS: &str = "CREATE TABLE workspace_evaluation_t1_cuts (workspace_id BLOB NOT NULL, cut_id BLOB NOT NULL CHECK(length(cut_id) = 16 AND cut_id != zeroblob(16)), manifest_id BLOB NOT NULL CHECK(length(manifest_id) = 16 AND manifest_id != zeroblob(16)), manifest_revision INTEGER NOT NULL CHECK(manifest_revision >= 1), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)), deadline_ms INTEGER NOT NULL CHECK(deadline_ms >= 0), closed_at_ms INTEGER NOT NULL CHECK(closed_at_ms > deadline_ms), source_high_water INTEGER NOT NULL CHECK(source_high_water >= 1), PRIMARY KEY(workspace_id, cut_id), UNIQUE(workspace_id, manifest_id, manifest_revision, deadline_ms), FOREIGN KEY(workspace_id, manifest_id, manifest_revision) REFERENCES workspace_evaluation_manifests(workspace_id, manifest_id, manifest_revision))";
const T1_CUT_MEMBERS: &str = "CREATE TABLE workspace_evaluation_t1_cut_members (workspace_id BLOB NOT NULL, cut_id BLOB NOT NULL, assignment_id BLOB NOT NULL CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), coverage_status INTEGER NOT NULL CHECK(coverage_status IN (0, 1, 2)), submitted_revision INTEGER CHECK(submitted_revision IS NULL OR submitted_revision >= 1), receipt_sequence INTEGER CHECK(receipt_sequence IS NULL OR receipt_sequence >= 1), unknown_reason INTEGER CHECK(unknown_reason IS NULL OR unknown_reason BETWEEN 0 AND 4), PRIMARY KEY(workspace_id, cut_id, assignment_id), FOREIGN KEY(workspace_id, cut_id) REFERENCES workspace_evaluation_t1_cuts(workspace_id, cut_id), FOREIGN KEY(workspace_id, assignment_id, submitted_revision) REFERENCES workspace_evaluation_submission_receipts(workspace_id, assignment_id, submitted_revision), CHECK((coverage_status = 0 AND submitted_revision IS NOT NULL AND receipt_sequence IS NOT NULL AND unknown_reason IS NULL) OR (coverage_status = 1 AND submitted_revision IS NULL AND receipt_sequence IS NULL AND unknown_reason IS NULL) OR (coverage_status = 2 AND unknown_reason IS NOT NULL)))";
const REVIEW_CUTS: &str = "CREATE TABLE workspace_evaluation_review_cuts (workspace_id BLOB NOT NULL, review_cut_id BLOB NOT NULL CHECK(length(review_cut_id) = 16 AND review_cut_id != zeroblob(16)), t1_cut_id BLOB NOT NULL CHECK(length(t1_cut_id) = 16 AND t1_cut_id != zeroblob(16)), source_high_water INTEGER NOT NULL CHECK(source_high_water >= 1), cut_time_status INTEGER NOT NULL CHECK(cut_time_status IN (0, 1, 2)), cut_at_ms INTEGER CHECK(cut_at_ms IS NULL OR cut_at_ms >= 0), PRIMARY KEY(workspace_id, review_cut_id), UNIQUE(workspace_id, t1_cut_id, source_high_water), FOREIGN KEY(workspace_id, t1_cut_id) REFERENCES workspace_evaluation_t1_cuts(workspace_id, cut_id), CHECK((cut_time_status = 0 AND cut_at_ms IS NOT NULL) OR (cut_time_status IN (1, 2) AND cut_at_ms IS NULL)))";
const REVIEW_CUT_MEMBERS: &str = "CREATE TABLE workspace_evaluation_review_cut_members (workspace_id BLOB NOT NULL, review_cut_id BLOB NOT NULL, assignment_id BLOB NOT NULL CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), coverage_status INTEGER NOT NULL CHECK(coverage_status IN (0, 1, 2)), submitted_revision INTEGER CHECK(submitted_revision IS NULL OR submitted_revision >= 1), review_status INTEGER NOT NULL CHECK(review_status IN (0, 1, 2, 3, 4)), review_revision INTEGER CHECK(review_revision IS NULL OR review_revision >= 1), review_sequence INTEGER CHECK(review_sequence IS NULL OR review_sequence >= 1), reviewer_agent_id BLOB CHECK(reviewer_agent_id IS NULL OR (length(reviewer_agent_id) = 16 AND reviewer_agent_id != zeroblob(16))), reviewer_session_id BLOB CHECK(reviewer_session_id IS NULL OR (length(reviewer_session_id) = 16 AND reviewer_session_id != zeroblob(16))), result_digest BLOB CHECK(result_digest IS NULL OR (length(result_digest) = 32 AND result_digest != zeroblob(32))), review_unknown_reason INTEGER CHECK(review_unknown_reason IS NULL OR review_unknown_reason BETWEEN 0 AND 4), PRIMARY KEY(workspace_id, review_cut_id, assignment_id), FOREIGN KEY(workspace_id, review_cut_id) REFERENCES workspace_evaluation_review_cuts(workspace_id, review_cut_id), FOREIGN KEY(workspace_id, assignment_id, submitted_revision) REFERENCES workspace_evaluation_submission_receipts(workspace_id, assignment_id, submitted_revision), FOREIGN KEY(workspace_id, assignment_id, submitted_revision, review_revision) REFERENCES workspace_evaluation_review_receipts(workspace_id, assignment_id, submitted_revision, review_revision), CHECK((review_status = 0 AND review_unknown_reason IS NULL AND review_revision IS NULL AND review_sequence IS NULL AND reviewer_agent_id IS NULL AND reviewer_session_id IS NULL AND result_digest IS NULL) OR (review_status = 1 AND review_unknown_reason IS NULL AND submitted_revision IS NOT NULL AND review_revision IS NULL AND review_sequence IS NULL AND reviewer_agent_id IS NULL AND reviewer_session_id IS NULL AND result_digest IS NULL) OR (review_status IN (2, 3) AND review_unknown_reason IS NULL AND submitted_revision IS NOT NULL AND review_revision IS NOT NULL AND review_sequence IS NOT NULL AND reviewer_agent_id IS NOT NULL AND reviewer_session_id IS NOT NULL AND result_digest IS NOT NULL) OR (review_status = 4 AND review_unknown_reason IS NOT NULL AND review_revision IS NULL AND review_sequence IS NULL AND reviewer_agent_id IS NULL AND reviewer_session_id IS NULL AND result_digest IS NULL)))";
const SUBMISSION_SEQUENCE_INDEX: &str = "CREATE INDEX workspace_evaluation_submission_sequence_idx ON workspace_evaluation_submission_receipts(workspace_id, source_sequence, assignment_id, submitted_revision)";
const REVIEW_SEQUENCE_INDEX: &str = "CREATE INDEX workspace_evaluation_review_sequence_idx ON workspace_evaluation_review_receipts(workspace_id, source_sequence, assignment_id, submitted_revision, review_revision)";
const OBJECTS: [(&str, &str, &str); 12] = [
    ("table", "workspace_evaluation_source_state", SOURCE_STATE),
    (
        "table",
        "workspace_evaluation_original_bindings",
        ORIGINAL_BINDINGS,
    ),
    ("table", "workspace_evaluation_manifests", MANIFESTS),
    (
        "table",
        "workspace_evaluation_manifest_members",
        MANIFEST_MEMBERS,
    ),
    (
        "table",
        "workspace_evaluation_submission_receipts",
        SUBMISSION_RECEIPTS,
    ),
    (
        "table",
        "workspace_evaluation_review_receipts",
        REVIEW_RECEIPTS,
    ),
    ("table", "workspace_evaluation_t1_cuts", T1_CUTS),
    (
        "table",
        "workspace_evaluation_t1_cut_members",
        T1_CUT_MEMBERS,
    ),
    ("table", "workspace_evaluation_review_cuts", REVIEW_CUTS),
    (
        "table",
        "workspace_evaluation_review_cut_members",
        REVIEW_CUT_MEMBERS,
    ),
    (
        "index",
        "workspace_evaluation_submission_sequence_idx",
        SUBMISSION_SEQUENCE_INDEX,
    ),
    (
        "index",
        "workspace_evaluation_review_sequence_idx",
        REVIEW_SEQUENCE_INDEX,
    ),
];

pub(crate) fn create_schema(connection: &Connection) -> Result<(), EvaluationEvidenceStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    OBJECTS
        .iter()
        .map(|(kind, name, _)| (*kind, *name))
        .collect()
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), EvaluationEvidenceStoreError> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                [kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(actual) = actual else {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(name));
        };
        if actual.len() > MAX_SCHEMA_SQL_BYTES
            || normalize_schema_sql(&actual) != normalize_schema_sql(expected)
        {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(name));
        }
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}
