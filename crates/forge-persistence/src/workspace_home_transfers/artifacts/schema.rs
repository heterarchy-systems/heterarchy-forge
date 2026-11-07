//! One DDL authority for immutable Home-artifact stages and seals.

use rusqlite::Connection;

use super::HomeArtifactJournalError;

pub(super) const MAX_ARTIFACT_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

const STAGES: &str = "CREATE TABLE home_transfer_artifact_stages (handoff_id BLOB PRIMARY KEY NOT NULL CHECK(length(handoff_id)=16 AND handoff_id!=zeroblob(16)), artifact_id BLOB NOT NULL UNIQUE CHECK(length(artifact_id)=16 AND artifact_id!=zeroblob(16)), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16 AND preparation_id!=zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id)=16 AND workspace_id!=zeroblob(16)), workspace_revision INTEGER NOT NULL CHECK(workspace_revision>=1), workspace_root_fingerprint BLOB NOT NULL CHECK(length(workspace_root_fingerprint)=16 AND workspace_root_fingerprint!=zeroblob(16)), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id)=16 AND activity_id!=zeroblob(16)), goal_id BLOB NOT NULL REFERENCES goals(goal_id) CHECK(length(goal_id)=16 AND goal_id!=zeroblob(16)), predecessor_assignment_id BLOB NOT NULL REFERENCES agent_assignments(assignment_id) CHECK(length(predecessor_assignment_id)=16 AND predecessor_assignment_id!=zeroblob(16)), predecessor_revision INTEGER NOT NULL CHECK(predecessor_revision>=1), root_assignment_id BLOB NOT NULL REFERENCES agent_assignments(assignment_id) CHECK(length(root_assignment_id)=16 AND root_assignment_id!=zeroblob(16)), coordinator_agent_id BLOB NOT NULL CHECK(length(coordinator_agent_id)=16 AND coordinator_agent_id!=zeroblob(16)), coordinator_session_id BLOB NOT NULL CHECK(length(coordinator_session_id)=16 AND coordinator_session_id!=zeroblob(16)), coordinator_principal_kind INTEGER NOT NULL CHECK(coordinator_principal_kind IN(0,1,2)), coordinator_principal_id BLOB CHECK(coordinator_principal_id IS NULL OR (length(coordinator_principal_id)=16 AND coordinator_principal_id!=zeroblob(16))), coordinator_revision INTEGER NOT NULL CHECK(coordinator_revision>=1), source_request_digest BLOB NOT NULL CHECK(length(source_request_digest)=32 AND source_request_digest!=zeroblob(32)), source_outcome_digest BLOB NOT NULL CHECK(length(source_outcome_digest)=32 AND source_outcome_digest!=zeroblob(32)), source_inventory_digest BLOB NOT NULL CHECK(length(source_inventory_digest)=32 AND source_inventory_digest!=zeroblob(32)), source_observed_at_ms INTEGER NOT NULL CHECK(source_observed_at_ms>=0), intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32 AND intent_digest!=zeroblob(32)), intent_snapshot BLOB NOT NULL CHECK(length(intent_snapshot) BETWEEN 1 AND 2097152), staged_at_ms INTEGER NOT NULL CHECK(staged_at_ms>=0), UNIQUE(handoff_id,artifact_id,workspace_id), FOREIGN KEY(preparation_id,workspace_id) REFERENCES home_transfer_source_operations(preparation_id,workspace_id), CHECK((coordinator_principal_kind=0 AND coordinator_principal_id IS NULL) OR (coordinator_principal_kind IN(1,2) AND coordinator_principal_id IS NOT NULL))) STRICT";

const SEALS: &str = "CREATE TABLE home_transfer_artifact_seals (handoff_id BLOB PRIMARY KEY NOT NULL CHECK(length(handoff_id)=16 AND handoff_id!=zeroblob(16)), artifact_id BLOB NOT NULL CHECK(length(artifact_id)=16 AND artifact_id!=zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id)=16 AND workspace_id!=zeroblob(16)), archive_snapshot BLOB NOT NULL CHECK(length(archive_snapshot) BETWEEN 1 AND 2097152), archive_digest BLOB NOT NULL CHECK(length(archive_digest)=32 AND archive_digest!=zeroblob(32)), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32 AND manifest_digest!=zeroblob(32)), commit_id BLOB NOT NULL CHECK(length(commit_id)=20 AND commit_id!=zeroblob(20)), sealed_at_ms INTEGER NOT NULL CHECK(sealed_at_ms>=0), sealed_by_agent_id BLOB NOT NULL CHECK(length(sealed_by_agent_id)=16 AND sealed_by_agent_id!=zeroblob(16)), sealed_by_session_id BLOB NOT NULL CHECK(length(sealed_by_session_id)=16 AND sealed_by_session_id!=zeroblob(16)), sealed_by_principal_kind INTEGER NOT NULL CHECK(sealed_by_principal_kind IN(0,1,2)), sealed_by_principal_id BLOB CHECK(sealed_by_principal_id IS NULL OR (length(sealed_by_principal_id)=16 AND sealed_by_principal_id!=zeroblob(16))), sealed_by_revision INTEGER NOT NULL CHECK(sealed_by_revision>=1), FOREIGN KEY(handoff_id,artifact_id,workspace_id) REFERENCES home_transfer_artifact_stages(handoff_id,artifact_id,workspace_id), CHECK((sealed_by_principal_kind=0 AND sealed_by_principal_id IS NULL) OR (sealed_by_principal_kind IN(1,2) AND sealed_by_principal_id IS NOT NULL))) STRICT";

const STAGE_PARENT_TRIGGER: &str = "CREATE TRIGGER home_transfer_artifact_stages_prepared_parent BEFORE INSERT ON home_transfer_artifact_stages WHEN NOT EXISTS(SELECT 1 FROM home_transfer_source_operations p WHERE p.preparation_id=NEW.preparation_id AND p.workspace_id=NEW.workspace_id AND p.outcome=0 AND p.request_digest=NEW.source_request_digest AND p.outcome_digest=NEW.source_outcome_digest AND p.inventory_digest=NEW.source_inventory_digest AND p.observed_at_ms=NEW.source_observed_at_ms) BEGIN SELECT RAISE(ABORT,'Home artifact stage requires exact Prepared Source'); END";
const SEAL_STAGE_TRIGGER: &str = "CREATE TRIGGER home_transfer_artifact_seals_exact_stage BEFORE INSERT ON home_transfer_artifact_seals WHEN NOT EXISTS(SELECT 1 FROM home_transfer_artifact_stages s WHERE s.handoff_id=NEW.handoff_id AND s.artifact_id=NEW.artifact_id AND s.workspace_id=NEW.workspace_id) BEGIN SELECT RAISE(ABORT,'Home artifact seal requires exact stage'); END";

const IMMUTABILITY: &[(&str, &str)] = &[
    (
        "home_transfer_artifact_stages_no_update",
        "CREATE TRIGGER home_transfer_artifact_stages_no_update BEFORE UPDATE ON home_transfer_artifact_stages BEGIN SELECT RAISE(ABORT,'Home artifact stages are immutable'); END",
    ),
    (
        "home_transfer_artifact_stages_no_delete",
        "CREATE TRIGGER home_transfer_artifact_stages_no_delete BEFORE DELETE ON home_transfer_artifact_stages BEGIN SELECT RAISE(ABORT,'Home artifact stages are permanent pins'); END",
    ),
    (
        "home_transfer_artifact_seals_no_update",
        "CREATE TRIGGER home_transfer_artifact_seals_no_update BEFORE UPDATE ON home_transfer_artifact_seals BEGIN SELECT RAISE(ABORT,'Home artifact seals are immutable'); END",
    ),
    (
        "home_transfer_artifact_seals_no_delete",
        "CREATE TRIGGER home_transfer_artifact_seals_no_delete BEFORE DELETE ON home_transfer_artifact_seals BEGIN SELECT RAISE(ABORT,'Home artifact seals are permanent pins'); END",
    ),
];

const TABLES: &[(&str, &str)] = &[
    ("home_transfer_artifact_stages", STAGES),
    ("home_transfer_artifact_seals", SEALS),
];

pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    let mut objects = TABLES
        .iter()
        .map(|(name, _)| ("table", *name))
        .collect::<Vec<_>>();
    objects.push(("trigger", "home_transfer_artifact_stages_prepared_parent"));
    objects.push(("trigger", "home_transfer_artifact_seals_exact_stage"));
    objects.extend(IMMUTABILITY.iter().map(|(name, _)| ("trigger", *name)));
    objects
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), HomeArtifactJournalError> {
    for (_, sql) in TABLES {
        connection.execute_batch(sql)?;
    }
    connection.execute_batch(STAGE_PARENT_TRIGGER)?;
    connection.execute_batch(SEAL_STAGE_TRIGGER)?;
    for (_, sql) in IMMUTABILITY {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), HomeArtifactJournalError> {
    for (name, sql) in TABLES {
        validate_sql(connection, "table", name, sql)?;
    }
    validate_sql(
        connection,
        "trigger",
        "home_transfer_artifact_stages_prepared_parent",
        STAGE_PARENT_TRIGGER,
    )?;
    validate_sql(
        connection,
        "trigger",
        "home_transfer_artifact_seals_exact_stage",
        SEAL_STAGE_TRIGGER,
    )?;
    for (name, sql) in IMMUTABILITY {
        validate_sql(connection, "trigger", name, sql)?;
    }
    Ok(())
}

fn validate_sql(
    connection: &Connection,
    kind: &str,
    name: &str,
    expected: &str,
) -> Result<(), HomeArtifactJournalError> {
    let actual: Option<String> = connection.query_row(
        "SELECT CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql END FROM sqlite_schema WHERE type=?1 AND name=?2",
        rusqlite::params![kind, name],
        |row| row.get(0),
    )?;
    let normalize = |sql: &str| {
        sql.chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
    };
    if actual.as_deref().map(normalize) != Some(normalize(expected)) {
        return Err(HomeArtifactJournalError::Corrupt("artifact schema"));
    }
    Ok(())
}
