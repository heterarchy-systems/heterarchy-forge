//! Canonical schema for immutable work-cut custody receipts.
//!
//! Creation and exact schema validation share this single DDL authority.

use super::WorkCutError;
use rusqlite::{Connection, OptionalExtension, params};

const CUTS: &str = "CREATE TABLE leadership_work_cuts (cut_id BLOB PRIMARY KEY NOT NULL CHECK(length(cut_id)=16 AND cut_id!=zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id)=16), election_id BLOB NOT NULL CHECK(length(election_id)=16 AND election_id!=zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id)=16 AND destination_id!=zeroblob(16)), backend_id BLOB NOT NULL CHECK(length(backend_id)=16 AND backend_id!=zeroblob(16)), issuer_id BLOB NOT NULL CHECK(length(issuer_id)=16 AND issuer_id!=zeroblob(16)), grant_issued_at_ms INTEGER NOT NULL CHECK(grant_issued_at_ms>=0), grant_expires_at_ms INTEGER NOT NULL CHECK(grant_expires_at_ms>grant_issued_at_ms), workspace_revision INTEGER NOT NULL CHECK(workspace_revision>=1), leadership_revision INTEGER NOT NULL CHECK(leadership_revision>=1), scope_kind INTEGER NOT NULL CHECK(scope_kind IN(0,1)), team_id BLOB CHECK(team_id IS NULL OR length(team_id)=16), incumbent_participation_id BLOB NOT NULL CHECK(length(incumbent_participation_id)=16), elected_participation_id BLOB NOT NULL CHECK(length(elected_participation_id)=16), incumbent_profile_id BLOB NOT NULL CHECK(length(incumbent_profile_id)=16), elected_profile_id BLOB NOT NULL CHECK(length(elected_profile_id)=16), roster_digest BLOB NOT NULL CHECK(length(roster_digest)=32), request_digest BLOB NOT NULL CHECK(length(request_digest)=32), snapshot_digest BLOB NOT NULL CHECK(length(snapshot_digest)=32), state INTEGER NOT NULL CHECK(state IN(0,1)), revision INTEGER NOT NULL CHECK(revision>=1), prepared_at_ms INTEGER NOT NULL CHECK(prepared_at_ms>=grant_issued_at_ms AND prepared_at_ms<grant_expires_at_ms), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=prepared_at_ms), team_node_count INTEGER NOT NULL CHECK(team_node_count BETWEEN 0 AND 256), session_count INTEGER NOT NULL CHECK(session_count BETWEEN 0 AND 128), agent_count INTEGER NOT NULL CHECK(agent_count BETWEEN 0 AND 256), node_count INTEGER NOT NULL CHECK(node_count BETWEEN 0 AND 256), effect_count INTEGER NOT NULL CHECK(effect_count BETWEEN 0 AND 1024), CHECK((scope_kind=0 AND team_id IS NULL) OR (scope_kind=1 AND team_id IS NOT NULL)), CHECK(incumbent_participation_id!=elected_participation_id AND incumbent_profile_id!=elected_profile_id), CHECK((state=0 AND revision=1 AND updated_at_ms=prepared_at_ms) OR (state=1 AND revision=2)))";
const ACTIVE: &str = "CREATE UNIQUE INDEX leadership_work_cuts_active ON leadership_work_cuts(workspace_id,election_id) WHERE state=0";
const SESSIONS: &str = "CREATE TABLE leadership_work_cut_sessions (cut_id BLOB NOT NULL REFERENCES leadership_work_cuts(cut_id) CHECK(length(cut_id)=16), session_id BLOB NOT NULL CHECK(length(session_id)=16 AND session_id!=zeroblob(16)), side INTEGER NOT NULL CHECK(side IN(0,1)), PRIMARY KEY(cut_id,session_id), UNIQUE(cut_id,session_id,side))";
const SESSION_INDEX: &str = "CREATE INDEX leadership_work_cut_sessions_session ON leadership_work_cut_sessions(session_id,cut_id)";
const AGENTS: &str = "CREATE TABLE leadership_work_cut_agents (cut_id BLOB NOT NULL REFERENCES leadership_work_cuts(cut_id) CHECK(length(cut_id)=16), agent_id BLOB NOT NULL CHECK(length(agent_id)=16 AND agent_id!=zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id)=16 AND activity_id!=zeroblob(16)), session_id BLOB NOT NULL CHECK(length(session_id)=16 AND session_id!=zeroblob(16)), side INTEGER NOT NULL CHECK(side IN(0,1)), principal_kind INTEGER NOT NULL CHECK(principal_kind IN(0,1,2)), principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id)=16), agent_revision INTEGER NOT NULL CHECK(agent_revision>=1), focus_goal_id BLOB CHECK(focus_goal_id IS NULL OR length(focus_goal_id)=16), focus_goal_revision INTEGER CHECK(focus_goal_revision IS NULL OR focus_goal_revision>=1), focus_dag_revision INTEGER CHECK(focus_dag_revision IS NULL OR focus_dag_revision>=1), focus_node_id BLOB CHECK(focus_node_id IS NULL OR length(focus_node_id)=16), focus_node_revision INTEGER CHECK(focus_node_revision IS NULL OR focus_node_revision>=1), PRIMARY KEY(cut_id,agent_id), FOREIGN KEY(cut_id,session_id,side) REFERENCES leadership_work_cut_sessions(cut_id,session_id,side), CHECK((principal_kind=0 AND principal_id IS NULL) OR (principal_kind IN(1,2) AND principal_id IS NOT NULL)))";
const NODES: &str = "CREATE TABLE leadership_work_cut_nodes (cut_id BLOB NOT NULL REFERENCES leadership_work_cuts(cut_id) CHECK(length(cut_id)=16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), agent_id BLOB NOT NULL CHECK(length(agent_id)=16), activity_id BLOB NOT NULL CHECK(length(activity_id)=16), goal_id BLOB NOT NULL CHECK(length(goal_id)=16), goal_created_at_ms INTEGER NOT NULL CHECK(goal_created_at_ms>=0), goal_revision INTEGER NOT NULL CHECK(goal_revision>=1), dag_revision INTEGER NOT NULL CHECK(dag_revision>=1), dag_base_goal_revision INTEGER NOT NULL CHECK(dag_base_goal_revision>=1), head_dag_revision INTEGER NOT NULL CHECK(head_dag_revision>=1), dag_head_revision INTEGER NOT NULL CHECK(dag_head_revision>=1), node_id BLOB NOT NULL CHECK(length(node_id)=16), node_revision INTEGER NOT NULL CHECK(node_revision>=1), lifecycle_state INTEGER NOT NULL CHECK(lifecycle_state IN(0,1,2,3,4,5,6)), direct_focus INTEGER NOT NULL CHECK(direct_focus IN(0,1)), assignment_id BLOB CHECK(assignment_id IS NULL OR length(assignment_id)=16), assignment_revision INTEGER CHECK(assignment_revision IS NULL OR assignment_revision>=1), assignment_state INTEGER CHECK(assignment_state IS NULL OR assignment_state IN(0,1,2)), assignment_cancellation INTEGER CHECK(assignment_cancellation IS NULL OR assignment_cancellation IN(0,1)), PRIMARY KEY(cut_id,ordinal), UNIQUE(cut_id,goal_id,goal_created_at_ms,dag_base_goal_revision,dag_revision,node_id,agent_id), FOREIGN KEY(cut_id,agent_id) REFERENCES leadership_work_cut_agents(cut_id,agent_id), CHECK((assignment_id IS NULL AND assignment_revision IS NULL AND assignment_state IS NULL AND assignment_cancellation IS NULL AND direct_focus=1) OR (assignment_id IS NOT NULL AND assignment_revision IS NOT NULL AND assignment_state IS NOT NULL AND assignment_cancellation IS NOT NULL)))";
const NODE_INDEX: &str = "CREATE INDEX leadership_work_cut_nodes_identity ON leadership_work_cut_nodes(goal_id,goal_created_at_ms,dag_revision,node_id,cut_id)";
const EFFECTS: &str = "CREATE TABLE leadership_work_cut_effects (cut_id BLOB NOT NULL REFERENCES leadership_work_cuts(cut_id) CHECK(length(cut_id)=16), effect_kind INTEGER NOT NULL CHECK(effect_kind IN(0,1,2)), effect_id BLOB NOT NULL CHECK(length(effect_id)=16 AND effect_id!=zeroblob(16)), agent_id BLOB CHECK(agent_id IS NULL OR length(agent_id)=16), node_ordinal INTEGER CHECK(node_ordinal IS NULL OR node_ordinal BETWEEN 0 AND 255), activity_id BLOB NOT NULL CHECK(length(activity_id)=16 AND activity_id!=zeroblob(16)), effect_revision INTEGER NOT NULL CHECK(effect_revision>=1), effect_state INTEGER NOT NULL CHECK(effect_state>=0), PRIMARY KEY(cut_id,effect_kind,effect_id), FOREIGN KEY(cut_id,node_ordinal) REFERENCES leadership_work_cut_nodes(cut_id,ordinal))";
const TEAM_NODES: &str = "CREATE TABLE leadership_work_cut_team_nodes (cut_id BLOB NOT NULL REFERENCES leadership_work_cuts(cut_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 255), activity_id BLOB NOT NULL CHECK(length(activity_id)=16), goal_id BLOB NOT NULL CHECK(length(goal_id)=16), goal_created_at_ms INTEGER NOT NULL CHECK(goal_created_at_ms>=0), dag_base_goal_revision INTEGER NOT NULL CHECK(dag_base_goal_revision>=1), dag_revision INTEGER NOT NULL CHECK(dag_revision>=1), node_id BLOB NOT NULL CHECK(length(node_id)=16), PRIMARY KEY(cut_id,ordinal), UNIQUE(cut_id,activity_id,goal_id,goal_created_at_ms,dag_base_goal_revision,dag_revision,node_id))";
const OBJECTS: [(&str, &str, &str); 9] = [
    ("table", "leadership_work_cuts", CUTS),
    ("index", "leadership_work_cuts_active", ACTIVE),
    ("table", "leadership_work_cut_sessions", SESSIONS),
    (
        "index",
        "leadership_work_cut_sessions_session",
        SESSION_INDEX,
    ),
    ("table", "leadership_work_cut_agents", AGENTS),
    ("table", "leadership_work_cut_nodes", NODES),
    ("index", "leadership_work_cut_nodes_identity", NODE_INDEX),
    ("table", "leadership_work_cut_effects", EFFECTS),
    ("table", "leadership_work_cut_team_nodes", TEAM_NODES),
];

pub(super) fn create_schema(connection: &Connection) -> Result<(), WorkCutError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(super) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    OBJECTS
        .iter()
        .map(|(kind, name, _)| (*kind, *name))
        .collect()
}

pub(super) fn validate_schema(connection: &Connection) -> Result<(), WorkCutError> {
    for (kind, name, expected) in OBJECTS {
        let row: Option<String> = connection
            .query_row(
                "SELECT substr(sql,1,16385) FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if row.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(WorkCutError::Corrupt(name));
        }
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}
