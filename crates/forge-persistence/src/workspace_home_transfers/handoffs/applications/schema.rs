//! One DDL authority for immutable Home acceptance terminal outcomes.

use rusqlite::{Connection, OptionalExtension, params};

use super::HomeHandoffApplicationStoreError as Error;

pub(super) const MAX_REQUEST_SNAPSHOT_BYTES: usize = 320;
pub(super) const MAX_GRANT_SNAPSHOT_BYTES: usize = 320;
pub(super) const MAX_SUCCESSOR_SNAPSHOT_BYTES: usize = 384;

const OUTCOMES: &str = "CREATE TABLE home_handoff_acceptance_outcomes (acceptance_id BLOB PRIMARY KEY NOT NULL CHECK(length(acceptance_id)=16 AND acceptance_id!=zeroblob(16)), request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)), request_snapshot BLOB NOT NULL CHECK(length(request_snapshot) BETWEEN 1 AND 320), authenticated_issuer_id BLOB NOT NULL CHECK(length(authenticated_issuer_id)=16 AND authenticated_issuer_id!=zeroblob(16)), handoff_id BLOB NOT NULL CHECK(length(handoff_id)=16 AND handoff_id!=zeroblob(16)), proposal_id BLOB NOT NULL CHECK(length(proposal_id)=16 AND proposal_id!=zeroblob(16)), case_revision INTEGER NOT NULL CHECK(case_revision>=1), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16 AND preparation_id!=zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16 AND workspace_id!=zeroblob(16)), predecessor_assignment_id BLOB NOT NULL CHECK(length(predecessor_assignment_id)=16 AND predecessor_assignment_id!=zeroblob(16)), root_assignment_id BLOB NOT NULL CHECK(length(root_assignment_id)=16 AND root_assignment_id!=zeroblob(16)), outcome_kind INTEGER NOT NULL CHECK(outcome_kind IN(1,2)), source_observed_at_ms INTEGER NOT NULL CHECK(source_observed_at_ms>=0), predecessor_revision_before INTEGER CHECK(predecessor_revision_before IS NULL OR predecessor_revision_before>=1), predecessor_revision_after INTEGER CHECK(predecessor_revision_after IS NULL OR predecessor_revision_after>=1), predecessor_terminal_disposition INTEGER CHECK(predecessor_terminal_disposition IS NULL OR predecessor_terminal_disposition IN(5,6)), successor_assignment_id BLOB CHECK(successor_assignment_id IS NULL OR (length(successor_assignment_id)=16 AND successor_assignment_id!=zeroblob(16))), successor_initial_revision INTEGER CHECK(successor_initial_revision IS NULL OR successor_initial_revision=1), successor_snapshot BLOB CHECK(successor_snapshot IS NULL OR length(successor_snapshot) BETWEEN 1 AND 384), grant_evidence_snapshot BLOB CHECK(grant_evidence_snapshot IS NULL OR length(grant_evidence_snapshot) BETWEEN 1 AND 320), payload_digest BLOB NOT NULL CHECK(length(payload_digest)=32 AND payload_digest!=zeroblob(32)), UNIQUE(acceptance_id,outcome_kind), FOREIGN KEY(workspace_id) REFERENCES workspace(workspace_id), FOREIGN KEY(predecessor_assignment_id) REFERENCES agent_assignments(assignment_id), FOREIGN KEY(root_assignment_id) REFERENCES agent_assignments(assignment_id), FOREIGN KEY(handoff_id,preparation_id,workspace_id,predecessor_assignment_id,root_assignment_id) REFERENCES home_handoff_cases(handoff_id,preparation_id,workspace_id,predecessor_assignment_id,root_assignment_id), FOREIGN KEY(proposal_id,handoff_id,case_revision) REFERENCES home_handoff_proposals(proposal_id,handoff_id,case_revision), FOREIGN KEY(successor_assignment_id) REFERENCES agent_assignments(assignment_id), CHECK((outcome_kind=1 AND predecessor_revision_before IS NOT NULL AND predecessor_revision_after=predecessor_revision_before+1 AND predecessor_terminal_disposition IN(5,6) AND successor_assignment_id IS NOT NULL AND successor_initial_revision=1 AND successor_snapshot IS NOT NULL AND grant_evidence_snapshot IS NOT NULL) OR (outcome_kind=2 AND predecessor_revision_before IS NULL AND predecessor_revision_after IS NULL AND predecessor_terminal_disposition IS NULL AND successor_assignment_id IS NULL AND successor_initial_revision IS NULL AND successor_snapshot IS NULL AND grant_evidence_snapshot IS NULL))) STRICT";
const HANDOFF_APPLIED_INDEX: &str = "CREATE UNIQUE INDEX home_handoff_acceptance_applied_handoff_idx ON home_handoff_acceptance_outcomes(handoff_id) WHERE outcome_kind=1";
const PREDECESSOR_APPLIED_INDEX: &str = "CREATE UNIQUE INDEX home_handoff_acceptance_applied_predecessor_idx ON home_handoff_acceptance_outcomes(predecessor_assignment_id) WHERE outcome_kind=1";
const SUCCESSOR_APPLIED_INDEX: &str = "CREATE UNIQUE INDEX home_handoff_acceptance_applied_successor_idx ON home_handoff_acceptance_outcomes(successor_assignment_id) WHERE outcome_kind=1";
const HANDOFF_LOOKUP_INDEX: &str = "CREATE INDEX home_handoff_acceptance_handoff_idx ON home_handoff_acceptance_outcomes(handoff_id,outcome_kind,source_observed_at_ms,acceptance_id)";
const NO_UPDATE: &str = "CREATE TRIGGER home_handoff_acceptance_outcomes_no_update BEFORE UPDATE ON home_handoff_acceptance_outcomes BEGIN SELECT RAISE(ABORT,'Home acceptance outcomes are immutable'); END";
const NO_DELETE: &str = "CREATE TRIGGER home_handoff_acceptance_outcomes_no_delete BEFORE DELETE ON home_handoff_acceptance_outcomes BEGIN SELECT RAISE(ABORT,'Home acceptance outcomes are permanent'); END";

const OBJECTS: &[(&str, &str, &str)] = &[
    ("table", "home_handoff_acceptance_outcomes", OUTCOMES),
    (
        "index",
        "home_handoff_acceptance_applied_handoff_idx",
        HANDOFF_APPLIED_INDEX,
    ),
    (
        "index",
        "home_handoff_acceptance_applied_predecessor_idx",
        PREDECESSOR_APPLIED_INDEX,
    ),
    (
        "index",
        "home_handoff_acceptance_applied_successor_idx",
        SUCCESSOR_APPLIED_INDEX,
    ),
    (
        "index",
        "home_handoff_acceptance_handoff_idx",
        HANDOFF_LOOKUP_INDEX,
    ),
    (
        "trigger",
        "home_handoff_acceptance_outcomes_no_update",
        NO_UPDATE,
    ),
    (
        "trigger",
        "home_handoff_acceptance_outcomes_no_delete",
        NO_DELETE,
    ),
];

pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    OBJECTS
        .iter()
        .map(|(kind, name, _)| (*kind, *name))
        .collect()
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), Error> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), Error> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql END FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(Error::Corrupt("Home acceptance schema object"));
        }
    }
    validate_columns(connection)?;
    validate_foreign_keys(connection)?;
    Ok(())
}

fn validate_columns(connection: &Connection) -> Result<(), Error> {
    const EXPECTED: &[(&str, &str, i64, i64)] = &[
        ("acceptance_id", "BLOB", 1, 1),
        ("request_digest", "BLOB", 1, 0),
        ("request_snapshot", "BLOB", 1, 0),
        ("authenticated_issuer_id", "BLOB", 1, 0),
        ("handoff_id", "BLOB", 1, 0),
        ("proposal_id", "BLOB", 1, 0),
        ("case_revision", "INTEGER", 1, 0),
        ("preparation_id", "BLOB", 1, 0),
        ("workspace_id", "BLOB", 1, 0),
        ("predecessor_assignment_id", "BLOB", 1, 0),
        ("root_assignment_id", "BLOB", 1, 0),
        ("outcome_kind", "INTEGER", 1, 0),
        ("source_observed_at_ms", "INTEGER", 1, 0),
        ("predecessor_revision_before", "INTEGER", 0, 0),
        ("predecessor_revision_after", "INTEGER", 0, 0),
        ("predecessor_terminal_disposition", "INTEGER", 0, 0),
        ("successor_assignment_id", "BLOB", 0, 0),
        ("successor_initial_revision", "INTEGER", 0, 0),
        ("successor_snapshot", "BLOB", 0, 0),
        ("grant_evidence_snapshot", "BLOB", 0, 0),
        ("payload_digest", "BLOB", 1, 0),
    ];
    let mut statement =
        connection.prepare("PRAGMA table_info(home_handoff_acceptance_outcomes)")?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != EXPECTED.len()
        || !actual
            .iter()
            .zip(EXPECTED)
            .all(|((name, kind, not_null, primary_key), expected)| {
                name == expected.0
                    && kind == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            })
    {
        return Err(Error::Corrupt("Home acceptance table columns"));
    }
    Ok(())
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), Error> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_list(home_handoff_acceptance_outcomes)")?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = [
        ("workspace", "workspace_id", "workspace_id"),
        (
            "agent_assignments",
            "predecessor_assignment_id",
            "assignment_id",
        ),
        ("agent_assignments", "root_assignment_id", "assignment_id"),
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
        ("home_handoff_proposals", "proposal_id", "proposal_id"),
        ("home_handoff_proposals", "handoff_id", "handoff_id"),
        ("home_handoff_proposals", "case_revision", "case_revision"),
        (
            "agent_assignments",
            "successor_assignment_id",
            "assignment_id",
        ),
    ];
    if actual.len() != expected.len()
        || !expected.iter().all(|expected| {
            actual.iter().any(|actual| {
                actual.2 == expected.0 && actual.3 == expected.1 && actual.4 == expected.2
            })
        })
    {
        return Err(Error::Corrupt("Home acceptance foreign keys"));
    }
    let mut grouped: std::collections::BTreeMap<i64, Vec<(i64, &str, &str, &str)>> =
        std::collections::BTreeMap::new();
    for (id, sequence, table, from, to) in &actual {
        grouped.entry(*id).or_default().push((
            *sequence,
            table.as_str(),
            from.as_str(),
            to.as_str(),
        ));
    }
    let mut actual_groups = grouped.into_values().collect::<Vec<_>>();
    for group in &mut actual_groups {
        group.sort_unstable_by_key(|entry| entry.0);
    }
    let expected_groups: &[&[(&str, &str, &str)]] = &[
        &[("workspace", "workspace_id", "workspace_id")],
        &[(
            "agent_assignments",
            "predecessor_assignment_id",
            "assignment_id",
        )],
        &[("agent_assignments", "root_assignment_id", "assignment_id")],
        &[
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
        ],
        &[
            ("home_handoff_proposals", "proposal_id", "proposal_id"),
            ("home_handoff_proposals", "handoff_id", "handoff_id"),
            ("home_handoff_proposals", "case_revision", "case_revision"),
        ],
        &[(
            "agent_assignments",
            "successor_assignment_id",
            "assignment_id",
        )],
    ];
    if actual_groups.len() != expected_groups.len()
        || !expected_groups.iter().all(|expected| {
            actual_groups.iter().any(|actual| {
                actual.len() == expected.len()
                    && actual
                        .iter()
                        .zip(*expected)
                        .all(|((_, table, from, to), expected)| {
                            *table == expected.0 && *from == expected.1 && *to == expected.2
                        })
            })
        })
    {
        return Err(Error::Corrupt("Home acceptance composite foreign keys"));
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
