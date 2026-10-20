use rusqlite::{Connection, OptionalExtension, params};

use super::super::WorkCutError;

const BATCHES: &str = "CREATE TABLE assignment_continuation_batches (transfer_id BLOB PRIMARY KEY NOT NULL CHECK(length(transfer_id)=16 AND transfer_id!=zeroblob(16)), cut_id BLOB UNIQUE NOT NULL REFERENCES leadership_work_cuts(cut_id) CHECK(length(cut_id)=16), cut_revision INTEGER NOT NULL CHECK(cut_revision>=1), cut_request_digest BLOB NOT NULL CHECK(length(cut_request_digest)=32), cut_snapshot_digest BLOB NOT NULL CHECK(length(cut_snapshot_digest)=32), recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0), UNIQUE(transfer_id,cut_id))";
const PROPOSALS: &str = "CREATE TABLE assignment_continuation_proposals (successor_id BLOB PRIMARY KEY NOT NULL CHECK(length(successor_id)=16 AND successor_id!=zeroblob(16)), transfer_id BLOB NOT NULL CHECK(length(transfer_id)=16), cut_id BLOB NOT NULL CHECK(length(cut_id)=16), source_ordinal INTEGER NOT NULL CHECK(source_ordinal BETWEEN 0 AND 255), source_assignment_id BLOB NOT NULL CHECK(length(source_assignment_id)=16 AND source_assignment_id!=zeroblob(16)), source_revision INTEGER NOT NULL CHECK(source_revision>=1), source_digest BLOB NOT NULL CHECK(length(source_digest)=32), recipient_agent_id BLOB NOT NULL CHECK(length(recipient_agent_id)=16 AND recipient_agent_id!=zeroblob(16)), recipient_session_id BLOB NOT NULL CHECK(length(recipient_session_id)=16 AND recipient_session_id!=zeroblob(16)), recipient_principal_kind INTEGER NOT NULL CHECK(recipient_principal_kind IN(0,1,2)), recipient_principal_id BLOB CHECK(recipient_principal_id IS NULL OR length(recipient_principal_id)=16), recipient_revision INTEGER NOT NULL CHECK(recipient_revision>=1), node_revision INTEGER NOT NULL CHECK(node_revision>=1), node_state INTEGER NOT NULL CHECK(node_state IN(0,1,2)), successor_state INTEGER NOT NULL CHECK(successor_state IN(0,1)), credit_budget INTEGER CHECK(credit_budget IS NULL OR credit_budget IN(1,3,5)), planned_at_ms INTEGER NOT NULL CHECK(planned_at_ms>=0), recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=planned_at_ms), request_digest BLOB NOT NULL CHECK(length(request_digest)=32), record_digest BLOB NOT NULL CHECK(length(record_digest)=32), CHECK(successor_id!=source_assignment_id), CHECK((recipient_principal_kind=0 AND recipient_principal_id IS NULL) OR (recipient_principal_kind IN(1,2) AND recipient_principal_id IS NOT NULL)), CHECK((successor_state=0 AND node_state IN(0,2)) OR (successor_state=1 AND node_state IN(1,2))), FOREIGN KEY(transfer_id,cut_id) REFERENCES assignment_continuation_batches(transfer_id,cut_id), FOREIGN KEY(cut_id,source_ordinal) REFERENCES leadership_work_cut_nodes(cut_id,ordinal))";
const PROPOSALS_BY_CUT: &str = "CREATE INDEX assignment_continuation_proposals_cut ON assignment_continuation_proposals(cut_id,successor_id)";
const ACKS: &str = "CREATE TABLE assignment_continuation_acknowledgments (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id)=16 AND request_id!=zeroblob(16)), successor_id BLOB UNIQUE NOT NULL REFERENCES assignment_continuation_proposals(successor_id) CHECK(length(successor_id)=16), proposal_digest BLOB NOT NULL CHECK(length(proposal_digest)=32), recipient_revision INTEGER NOT NULL CHECK(recipient_revision>=1), recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0), record_digest BLOB NOT NULL CHECK(length(record_digest)=32))";

const OBJECTS: [(&str, &str, &str); 4] = [
    ("table", "assignment_continuation_batches", BATCHES),
    ("table", "assignment_continuation_proposals", PROPOSALS),
    (
        "index",
        "assignment_continuation_proposals_cut",
        PROPOSALS_BY_CUT,
    ),
    ("table", "assignment_continuation_acknowledgments", ACKS),
];

pub(crate) fn create(connection: &Connection) -> Result<(), WorkCutError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn objects() -> Vec<(&'static str, &'static str)> {
    OBJECTS
        .iter()
        .map(|(kind, name, _)| (*kind, *name))
        .collect()
}

pub(crate) fn validate(connection: &Connection) -> Result<(), WorkCutError> {
    for (kind, name, sql) in OBJECTS {
        let observed: Option<String> = connection
            .query_row(
                "SELECT substr(sql,1,16385) FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if observed.as_deref().map(normalize) != Some(normalize(sql)) {
            return Err(WorkCutError::Corrupt(name));
        }
    }
    Ok(())
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}
