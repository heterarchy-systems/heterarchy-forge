//! One canonical DDL authority for immutable Home proposal history and its CAS head.

use rusqlite::{Connection, OptionalExtension, params};

use super::HomeHandoffProposalStoreError;

pub(super) const MAX_REQUEST_SNAPSHOT_BYTES: usize = 320;
pub(super) const MAX_SOURCE_SNAPSHOT_BYTES: usize = 512;

const CASES: &str = "CREATE TABLE home_handoff_cases (handoff_id BLOB PRIMARY KEY NOT NULL CHECK(length(handoff_id)=16 AND handoff_id!=zeroblob(16)), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16 AND preparation_id!=zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id)=16 AND workspace_id!=zeroblob(16)), predecessor_assignment_id BLOB NOT NULL REFERENCES agent_assignments(assignment_id) CHECK(length(predecessor_assignment_id)=16 AND predecessor_assignment_id!=zeroblob(16)), root_assignment_id BLOB NOT NULL REFERENCES agent_assignments(assignment_id) CHECK(length(root_assignment_id)=16 AND root_assignment_id!=zeroblob(16)), opened_at_ms INTEGER NOT NULL CHECK(opened_at_ms>=0), UNIQUE(predecessor_assignment_id), UNIQUE(handoff_id,preparation_id,workspace_id,predecessor_assignment_id,root_assignment_id), FOREIGN KEY(preparation_id,workspace_id) REFERENCES home_transfer_source_operations(preparation_id,workspace_id)) STRICT";
const PROPOSALS: &str = "CREATE TABLE home_handoff_proposals (proposal_id BLOB PRIMARY KEY NOT NULL CHECK(length(proposal_id)=16 AND proposal_id!=zeroblob(16)), handoff_id BLOB NOT NULL CHECK(length(handoff_id)=16 AND handoff_id!=zeroblob(16)), case_revision INTEGER NOT NULL CHECK(case_revision>=1), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16 AND preparation_id!=zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16 AND workspace_id!=zeroblob(16)), predecessor_assignment_id BLOB NOT NULL CHECK(length(predecessor_assignment_id)=16 AND predecessor_assignment_id!=zeroblob(16)), root_assignment_id BLOB NOT NULL CHECK(length(root_assignment_id)=16 AND root_assignment_id!=zeroblob(16)), request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)), request_snapshot BLOB NOT NULL CHECK(length(request_snapshot) BETWEEN 1 AND 320), source_digest BLOB NOT NULL CHECK(length(source_digest)=32 AND source_digest!=zeroblob(32)), source_snapshot BLOB NOT NULL CHECK(length(source_snapshot) BETWEEN 1 AND 512), prepared_outcome_digest BLOB NOT NULL CHECK(length(prepared_outcome_digest)=32 AND prepared_outcome_digest!=zeroblob(32)), evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN(0,1)), artifact_id BLOB CHECK(artifact_id IS NULL OR (length(artifact_id)=16 AND artifact_id!=zeroblob(16))), artifact_digest BLOB CHECK(artifact_digest IS NULL OR (length(artifact_digest)=32 AND artifact_digest!=zeroblob(32))), created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0), payload_digest BLOB NOT NULL CHECK(length(payload_digest)=32 AND payload_digest!=zeroblob(32)), UNIQUE(handoff_id,case_revision), UNIQUE(proposal_id,handoff_id,case_revision), FOREIGN KEY(handoff_id,preparation_id,workspace_id,predecessor_assignment_id,root_assignment_id) REFERENCES home_handoff_cases(handoff_id,preparation_id,workspace_id,predecessor_assignment_id,root_assignment_id), FOREIGN KEY(handoff_id,artifact_id,workspace_id) REFERENCES home_transfer_artifact_stages(handoff_id,artifact_id,workspace_id), CHECK((evidence_kind=0 AND artifact_id IS NULL AND artifact_digest IS NULL) OR (evidence_kind=1 AND artifact_id IS NOT NULL AND artifact_digest IS NOT NULL))) STRICT";
const HEADS: &str = "CREATE TABLE home_handoff_proposal_heads (handoff_id BLOB PRIMARY KEY NOT NULL REFERENCES home_handoff_cases(handoff_id) CHECK(length(handoff_id)=16 AND handoff_id!=zeroblob(16)), case_revision INTEGER NOT NULL CHECK(case_revision>=1), proposal_id BLOB NOT NULL CHECK(length(proposal_id)=16 AND proposal_id!=zeroblob(16)), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0), FOREIGN KEY(proposal_id,handoff_id,case_revision) REFERENCES home_handoff_proposals(proposal_id,handoff_id,case_revision)) STRICT";

const CASES_PREPARED_PARENT: &str = "CREATE TRIGGER home_handoff_cases_prepared_parent BEFORE INSERT ON home_handoff_cases WHEN NOT EXISTS(SELECT 1 FROM home_transfer_source_operations p WHERE p.preparation_id=NEW.preparation_id AND p.workspace_id=NEW.workspace_id AND p.outcome=0) BEGIN SELECT RAISE(ABORT,'Home handoff case requires its exact Prepared parent'); END";
const PROPOSALS_PREPARED_PARENT: &str = "CREATE TRIGGER home_handoff_proposals_prepared_parent BEFORE INSERT ON home_handoff_proposals WHEN NOT EXISTS(SELECT 1 FROM home_transfer_source_operations p WHERE p.preparation_id=NEW.preparation_id AND p.workspace_id=NEW.workspace_id AND p.outcome=0 AND p.outcome_digest=NEW.prepared_outcome_digest) BEGIN SELECT RAISE(ABORT,'Home handoff proposal requires its exact Prepared outcome'); END";
const CASES_NO_UPDATE: &str = "CREATE TRIGGER home_handoff_cases_no_update BEFORE UPDATE ON home_handoff_cases BEGIN SELECT RAISE(ABORT,'Home handoff cases are immutable'); END";
const CASES_NO_DELETE: &str = "CREATE TRIGGER home_handoff_cases_no_delete BEFORE DELETE ON home_handoff_cases BEGIN SELECT RAISE(ABORT,'Home handoff cases are permanent'); END";
const PROPOSALS_NO_UPDATE: &str = "CREATE TRIGGER home_handoff_proposals_no_update BEFORE UPDATE ON home_handoff_proposals BEGIN SELECT RAISE(ABORT,'Home handoff proposals are immutable'); END";
const PROPOSALS_NO_DELETE: &str = "CREATE TRIGGER home_handoff_proposals_no_delete BEFORE DELETE ON home_handoff_proposals BEGIN SELECT RAISE(ABORT,'Home handoff proposals are permanent history'); END";
const HEADS_NO_DELETE: &str = "CREATE TRIGGER home_handoff_proposal_heads_no_delete BEFORE DELETE ON home_handoff_proposal_heads BEGIN SELECT RAISE(ABORT,'Home handoff proposal heads are durable'); END";
const HEADS_INSERT: &str = "CREATE TRIGGER home_handoff_proposal_heads_exact_insert BEFORE INSERT ON home_handoff_proposal_heads WHEN NOT EXISTS(SELECT 1 FROM home_handoff_proposals p WHERE p.proposal_id=NEW.proposal_id AND p.handoff_id=NEW.handoff_id AND p.case_revision=NEW.case_revision AND p.created_at_ms=NEW.updated_at_ms) BEGIN SELECT RAISE(ABORT,'Home handoff head requires its exact proposal'); END";
const HEADS_UPDATE: &str = "CREATE TRIGGER home_handoff_proposal_heads_monotonic_update BEFORE UPDATE ON home_handoff_proposal_heads WHEN NEW.handoff_id!=OLD.handoff_id OR NEW.case_revision!=OLD.case_revision+1 OR NEW.updated_at_ms<OLD.updated_at_ms OR NOT EXISTS(SELECT 1 FROM home_handoff_proposals p WHERE p.proposal_id=NEW.proposal_id AND p.handoff_id=NEW.handoff_id AND p.case_revision=NEW.case_revision AND p.created_at_ms=NEW.updated_at_ms) BEGIN SELECT RAISE(ABORT,'Home handoff head must advance to its exact next proposal'); END";

const OBJECTS: &[(&str, &str, &str)] = &[
    ("table", "home_handoff_cases", CASES),
    ("table", "home_handoff_proposals", PROPOSALS),
    ("table", "home_handoff_proposal_heads", HEADS),
    (
        "trigger",
        "home_handoff_cases_prepared_parent",
        CASES_PREPARED_PARENT,
    ),
    (
        "trigger",
        "home_handoff_proposals_prepared_parent",
        PROPOSALS_PREPARED_PARENT,
    ),
    ("trigger", "home_handoff_cases_no_update", CASES_NO_UPDATE),
    ("trigger", "home_handoff_cases_no_delete", CASES_NO_DELETE),
    (
        "trigger",
        "home_handoff_proposals_no_update",
        PROPOSALS_NO_UPDATE,
    ),
    (
        "trigger",
        "home_handoff_proposals_no_delete",
        PROPOSALS_NO_DELETE,
    ),
    (
        "trigger",
        "home_handoff_proposal_heads_no_delete",
        HEADS_NO_DELETE,
    ),
    (
        "trigger",
        "home_handoff_proposal_heads_exact_insert",
        HEADS_INSERT,
    ),
    (
        "trigger",
        "home_handoff_proposal_heads_monotonic_update",
        HEADS_UPDATE,
    ),
];

pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    OBJECTS
        .iter()
        .map(|(kind, name, _)| (*kind, *name))
        .collect()
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), HomeHandoffProposalStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), HomeHandoffProposalStoreError> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql END FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "Home handoff proposal schema object",
            ));
        }
    }
    validate_foreign_keys(connection, "home_handoff_cases")?;
    validate_foreign_keys(connection, "home_handoff_proposals")?;
    validate_foreign_keys(connection, "home_handoff_proposal_heads")?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "this validator checks the exact targets for all canonical Home proposal FKs"
)]
fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
) -> Result<(), HomeHandoffProposalStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected: &[(&str, &str, &str)] = match table {
        "home_handoff_cases" => &[
            ("workspace", "workspace_id", "workspace_id"),
            (
                "agent_assignments",
                "predecessor_assignment_id",
                "assignment_id",
            ),
            ("agent_assignments", "root_assignment_id", "assignment_id"),
            (
                "home_transfer_source_operations",
                "preparation_id",
                "preparation_id",
            ),
            (
                "home_transfer_source_operations",
                "workspace_id",
                "workspace_id",
            ),
        ],
        "home_handoff_proposals" => &[
            ("home_handoff_cases", "handoff_id", "handoff_id"),
            ("home_handoff_cases", "preparation_id", "preparation_id"),
            ("home_handoff_cases", "workspace_id", "workspace_id"),
            (
                "home_handoff_cases",
                "predecessor_assignment_id",
                "predecessor_assignment_id",
            ),
            (
                "home_handoff_cases",
                "root_assignment_id",
                "root_assignment_id",
            ),
            ("home_transfer_artifact_stages", "handoff_id", "handoff_id"),
            (
                "home_transfer_artifact_stages",
                "artifact_id",
                "artifact_id",
            ),
            (
                "home_transfer_artifact_stages",
                "workspace_id",
                "workspace_id",
            ),
        ],
        "home_handoff_proposal_heads" => &[
            ("home_handoff_cases", "handoff_id", "handoff_id"),
            ("home_handoff_proposals", "proposal_id", "proposal_id"),
            ("home_handoff_proposals", "handoff_id", "handoff_id"),
            ("home_handoff_proposals", "case_revision", "case_revision"),
        ],
        _ => {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "Home handoff proposal foreign-key table",
            ));
        }
    };
    // Composite FKs produce one pragma row per child column. DDL equality
    // verifies grouping and order; this pass checks every exact target tuple.
    let valid = actual.len() == expected.len()
        && expected.iter().all(|expected| {
            actual.iter().any(|actual| {
                actual.0 == expected.0
                    && actual.1 == expected.1
                    && actual.2 == expected.2
                    && actual.3 == "NO ACTION"
            })
        });
    if !valid {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "Home handoff proposal foreign-key shape",
        ));
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}
