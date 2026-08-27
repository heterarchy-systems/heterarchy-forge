//! Canonical `SQLite` schema, migration, and exact-shape validation for Goal DAG persistence.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::DagStoreError;

const EXPECTED_DAG_REVISIONS_TABLE_SQL: &str = "CREATE TABLE goal_dag_revisions (goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), revision_id BLOB NOT NULL UNIQUE CHECK(length(revision_id) = 16), parent_dag_revision INTEGER, base_goal_revision INTEGER NOT NULL CHECK(base_goal_revision >= 1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), node_count INTEGER NOT NULL CHECK(node_count BETWEEN 1 AND 128), edge_count INTEGER NOT NULL CHECK(edge_count BETWEEN 0 AND 512), PRIMARY KEY(goal_id, dag_revision), FOREIGN KEY(goal_id, parent_dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), CHECK((dag_revision = 1 AND parent_dag_revision IS NULL) OR (dag_revision > 1 AND parent_dag_revision = dag_revision - 1)))";
const EXPECTED_DAG_HEADS_TABLE_SQL: &str = "CREATE TABLE goal_dag_heads (goal_id BLOB PRIMARY KEY NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id) = 16), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), head_revision INTEGER NOT NULL CHECK(head_revision >= 1), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), FOREIGN KEY(goal_id, dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision))";
const EXPECTED_DAG_NODES_TABLE_SQL: &str = "CREATE TABLE goal_dag_nodes (goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), node_id BLOB NOT NULL CHECK(length(node_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 127), title TEXT NOT NULL CHECK(length(CAST(title AS BLOB)) BETWEEN 1 AND 256), objective TEXT NOT NULL CHECK(length(CAST(objective AS BLOB)) BETWEEN 1 AND 2048), lifecycle_state INTEGER NOT NULL CHECK(lifecycle_state IN (0, 1, 2, 3, 4, 5, 6)), reason_text TEXT CHECK(reason_text IS NULL OR length(CAST(reason_text AS BLOB)) BETWEEN 1 AND 2048), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), node_revision INTEGER NOT NULL CHECK(node_revision >= 1), PRIMARY KEY(goal_id, dag_revision, node_id), UNIQUE(goal_id, dag_revision, ordinal), FOREIGN KEY(goal_id, dag_revision) REFERENCES goal_dag_revisions(goal_id, dag_revision), CHECK((lifecycle_state IN (0, 1, 3, 6) AND reason_text IS NULL) OR (lifecycle_state IN (2, 4, 5) AND reason_text IS NOT NULL)), CHECK((node_revision = 1 AND lifecycle_state = 0 AND updated_at_ms = created_at_ms) OR node_revision >= 2))";
const EXPECTED_DAG_ACCEPTANCE_TABLE_SQL: &str = "CREATE TABLE goal_dag_node_acceptance (goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), node_id BLOB NOT NULL CHECK(length(node_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31), criterion TEXT NOT NULL CHECK(length(CAST(criterion AS BLOB)) BETWEEN 1 AND 1024), PRIMARY KEY(goal_id, dag_revision, node_id, ordinal), FOREIGN KEY(goal_id, dag_revision, node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id))";
const EXPECTED_DAG_NODE_EVIDENCE_TABLE_SQL: &str = "CREATE TABLE goal_dag_node_evidence_refs (goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), node_id BLOB NOT NULL CHECK(length(node_id) = 16), evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN (0, 1, 2, 3)), evidence_id BLOB NOT NULL CHECK(length(evidence_id) = 16), associated_at_ms INTEGER NOT NULL CHECK(associated_at_ms >= 0), PRIMARY KEY(goal_id, dag_revision, node_id, evidence_kind, evidence_id), UNIQUE(goal_id, dag_revision, evidence_kind, evidence_id), FOREIGN KEY(goal_id, dag_revision, node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), FOREIGN KEY(goal_id, evidence_kind, evidence_id) REFERENCES goal_evidence_refs(goal_id, evidence_kind, evidence_id))";
const EXPECTED_DAG_LINEAGE_TABLE_SQL: &str = "CREATE TABLE goal_dag_node_lineage (goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), new_dag_revision INTEGER NOT NULL CHECK(new_dag_revision > 1), parent_dag_revision INTEGER NOT NULL CHECK(parent_dag_revision = new_dag_revision - 1), prior_node_id BLOB NOT NULL CHECK(length(prior_node_id) = 16), successor_node_id BLOB NOT NULL CHECK(length(successor_node_id) = 16), lineage_kind INTEGER NOT NULL CHECK(lineage_kind IN (0, 1, 2)), PRIMARY KEY(goal_id, new_dag_revision, prior_node_id, successor_node_id), FOREIGN KEY(goal_id, parent_dag_revision, prior_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), FOREIGN KEY(goal_id, new_dag_revision, successor_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), CHECK(prior_node_id != successor_node_id))";
const EXPECTED_DAG_EDGES_TABLE_SQL: &str = "CREATE TABLE goal_dag_edges (goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), dag_revision INTEGER NOT NULL CHECK(dag_revision >= 1), upstream_node_id BLOB NOT NULL CHECK(length(upstream_node_id) = 16), downstream_node_id BLOB NOT NULL CHECK(length(downstream_node_id) = 16), PRIMARY KEY(goal_id, dag_revision, upstream_node_id, downstream_node_id), FOREIGN KEY(goal_id, dag_revision, upstream_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), FOREIGN KEY(goal_id, dag_revision, downstream_node_id) REFERENCES goal_dag_nodes(goal_id, dag_revision, node_id), CHECK(upstream_node_id != downstream_node_id))";
const EXPECTED_DAG_NODE_STATE_INDEX_SQL: &str = "CREATE INDEX goal_dag_nodes_state_ordinal_idx ON goal_dag_nodes(goal_id, dag_revision, lifecycle_state, ordinal, node_id)";

const OBJECTS: [(&str, &str, &str); 8] = [
    (
        "table",
        "goal_dag_revisions",
        EXPECTED_DAG_REVISIONS_TABLE_SQL,
    ),
    ("table", "goal_dag_heads", EXPECTED_DAG_HEADS_TABLE_SQL),
    ("table", "goal_dag_nodes", EXPECTED_DAG_NODES_TABLE_SQL),
    ("table", "goal_dag_edges", EXPECTED_DAG_EDGES_TABLE_SQL),
    (
        "table",
        "goal_dag_node_acceptance",
        EXPECTED_DAG_ACCEPTANCE_TABLE_SQL,
    ),
    (
        "table",
        "goal_dag_node_evidence_refs",
        EXPECTED_DAG_NODE_EVIDENCE_TABLE_SQL,
    ),
    (
        "table",
        "goal_dag_node_lineage",
        EXPECTED_DAG_LINEAGE_TABLE_SQL,
    ),
    (
        "index",
        "goal_dag_nodes_state_ordinal_idx",
        EXPECTED_DAG_NODE_STATE_INDEX_SQL,
    ),
];

pub(super) fn create_schema(connection: &Connection) -> Result<(), DagStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(super) fn migrate_v9_to_v10(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), DagStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(super) const fn objects() -> [(&'static str, &'static str); 8] {
    [
        ("table", "goal_dag_revisions"),
        ("table", "goal_dag_heads"),
        ("table", "goal_dag_nodes"),
        ("table", "goal_dag_edges"),
        ("table", "goal_dag_node_acceptance"),
        ("table", "goal_dag_node_evidence_refs"),
        ("table", "goal_dag_node_lineage"),
        ("index", "goal_dag_nodes_state_ordinal_idx"),
    ]
}

pub(super) fn validate_schema(connection: &Connection) -> Result<(), DagStoreError> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(DagStoreError::DamagedSchema(name));
        }
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
