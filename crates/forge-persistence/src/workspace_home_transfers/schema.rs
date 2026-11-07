//! One DDL authority for original Home-transfer outcomes and active fences.

use rusqlite::Connection;

use super::HomeTransferStoreError;

pub(super) const MAX_REQUEST_BYTES: usize = 131_072;

const OPERATIONS: &str = "CREATE TABLE home_transfer_source_operations (preparation_id BLOB PRIMARY KEY NOT NULL CHECK(length(preparation_id)=16 AND preparation_id!=zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id)=16), target_profile_id BLOB NOT NULL CHECK(length(target_profile_id)=16 AND target_profile_id!=zeroblob(16)), target_participation_id BLOB NOT NULL CHECK(length(target_participation_id)=16 AND target_participation_id!=zeroblob(16)), issuer_id BLOB NOT NULL CHECK(length(issuer_id)=16 AND issuer_id!=zeroblob(16)), request_digest BLOB NOT NULL CHECK(length(request_digest)=32), request_payload BLOB NOT NULL CHECK(length(request_payload) BETWEEN 1 AND 131072), outcome INTEGER NOT NULL CHECK(outcome IN(0,1)), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0), grant_issued_at_ms INTEGER NOT NULL CHECK(grant_issued_at_ms>=0), grant_expires_at_ms INTEGER NOT NULL CHECK(grant_expires_at_ms>grant_issued_at_ms), migration_id BLOB NOT NULL CHECK(length(migration_id)=16 AND migration_id!=zeroblob(16)), freeze_revision INTEGER NOT NULL CHECK(freeze_revision>=1), delegation_digest BLOB NOT NULL CHECK(length(delegation_digest)=32), inventory_payload BLOB CHECK(inventory_payload IS NULL OR length(inventory_payload) BETWEEN 1 AND 524288), inventory_digest BLOB CHECK(inventory_digest IS NULL OR length(inventory_digest)=32), outcome_digest BLOB NOT NULL CHECK(length(outcome_digest)=32), UNIQUE(preparation_id,workspace_id,target_profile_id,target_participation_id), UNIQUE(preparation_id,workspace_id), CHECK((outcome=0 AND inventory_payload IS NOT NULL AND inventory_digest IS NOT NULL) OR (outcome=1 AND inventory_payload IS NULL AND inventory_digest IS NULL)), CHECK(observed_at_ms>=grant_issued_at_ms AND observed_at_ms<grant_expires_at_ms))";
const SUBJECTS: &str = "CREATE TABLE home_transfer_source_subjects (workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16), target_profile_id BLOB NOT NULL CHECK(length(target_profile_id)=16), target_participation_id BLOB NOT NULL CHECK(length(target_participation_id)=16), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16), PRIMARY KEY(workspace_id,target_profile_id), UNIQUE(workspace_id,target_participation_id), UNIQUE(preparation_id,workspace_id), FOREIGN KEY(preparation_id,workspace_id,target_profile_id,target_participation_id) REFERENCES home_transfer_source_operations(preparation_id,workspace_id,target_profile_id,target_participation_id))";
const SUBJECTS_PREPARED: &str = "CREATE TRIGGER home_transfer_source_subjects_prepared BEFORE INSERT ON home_transfer_source_subjects WHEN NOT EXISTS(SELECT 1 FROM home_transfer_source_operations o WHERE o.preparation_id=NEW.preparation_id AND o.workspace_id=NEW.workspace_id AND o.outcome=0) BEGIN SELECT RAISE(ABORT,'Home source fence requires Prepared outcome'); END";
const SESSIONS: &str = "CREATE TABLE home_transfer_source_sessions (workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16), session_id BLOB NOT NULL CHECK(length(session_id)=16 AND session_id!=zeroblob(16)), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16), PRIMARY KEY(workspace_id,session_id), FOREIGN KEY(preparation_id,workspace_id) REFERENCES home_transfer_source_subjects(preparation_id,workspace_id))";
const AGENTS: &str = "CREATE TABLE home_transfer_source_agents (workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16), agent_id BLOB NOT NULL CHECK(length(agent_id)=16 AND agent_id!=zeroblob(16)), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16), PRIMARY KEY(workspace_id,agent_id), FOREIGN KEY(preparation_id,workspace_id) REFERENCES home_transfer_source_subjects(preparation_id,workspace_id))";
const ACTIVITIES: &str = "CREATE TABLE home_transfer_source_activities (workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16), activity_id BLOB NOT NULL CHECK(length(activity_id)=16 AND activity_id!=zeroblob(16)), preparation_id BLOB NOT NULL CHECK(length(preparation_id)=16), PRIMARY KEY(workspace_id,activity_id,preparation_id), FOREIGN KEY(preparation_id,workspace_id) REFERENCES home_transfer_source_subjects(preparation_id,workspace_id))";

pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    let mut objects = TABLES
        .iter()
        .map(|(name, _)| ("table", *name))
        .collect::<Vec<_>>();
    objects.push(("trigger", "home_transfer_source_subjects_prepared"));
    objects.extend(IMMUTABILITY.iter().map(|(name, _)| ("trigger", *name)));
    objects
}

const TABLES: &[(&str, &str)] = &[
    ("home_transfer_source_operations", OPERATIONS),
    ("home_transfer_source_subjects", SUBJECTS),
    ("home_transfer_source_sessions", SESSIONS),
    ("home_transfer_source_agents", AGENTS),
    ("home_transfer_source_activities", ACTIVITIES),
];

// There is intentionally no release writer yet. A later disposition protocol
// must preserve the original record and positively authorize any fence removal.
const IMMUTABILITY: &[(&str, &str)] = &[
    (
        "home_transfer_source_operations_no_update",
        "CREATE TRIGGER home_transfer_source_operations_no_update BEFORE UPDATE ON home_transfer_source_operations BEGIN SELECT RAISE(ABORT,'Home source outcomes are immutable'); END",
    ),
    (
        "home_transfer_source_operations_no_delete",
        "CREATE TRIGGER home_transfer_source_operations_no_delete BEFORE DELETE ON home_transfer_source_operations BEGIN SELECT RAISE(ABORT,'Home source outcomes are immutable'); END",
    ),
    (
        "home_transfer_source_subjects_no_update",
        "CREATE TRIGGER home_transfer_source_subjects_no_update BEFORE UPDATE ON home_transfer_source_subjects BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
    (
        "home_transfer_source_subjects_no_delete",
        "CREATE TRIGGER home_transfer_source_subjects_no_delete BEFORE DELETE ON home_transfer_source_subjects BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
    (
        "home_transfer_source_sessions_no_update",
        "CREATE TRIGGER home_transfer_source_sessions_no_update BEFORE UPDATE ON home_transfer_source_sessions BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
    (
        "home_transfer_source_sessions_no_delete",
        "CREATE TRIGGER home_transfer_source_sessions_no_delete BEFORE DELETE ON home_transfer_source_sessions BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
    (
        "home_transfer_source_agents_no_update",
        "CREATE TRIGGER home_transfer_source_agents_no_update BEFORE UPDATE ON home_transfer_source_agents BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
    (
        "home_transfer_source_agents_no_delete",
        "CREATE TRIGGER home_transfer_source_agents_no_delete BEFORE DELETE ON home_transfer_source_agents BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
    (
        "home_transfer_source_activities_no_update",
        "CREATE TRIGGER home_transfer_source_activities_no_update BEFORE UPDATE ON home_transfer_source_activities BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
    (
        "home_transfer_source_activities_no_delete",
        "CREATE TRIGGER home_transfer_source_activities_no_delete BEFORE DELETE ON home_transfer_source_activities BEGIN SELECT RAISE(ABORT,'Home source fences require disposition'); END",
    ),
];

pub(crate) fn create_schema(c: &Connection) -> Result<(), HomeTransferStoreError> {
    for (_, sql) in TABLES {
        c.execute_batch(sql)?;
    }
    c.execute_batch(SUBJECTS_PREPARED)?;
    for (_, sql) in IMMUTABILITY {
        c.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn validate_schema(c: &Connection) -> Result<(), HomeTransferStoreError> {
    for (name, sql) in TABLES {
        validate_sql(c, "table", name, sql)?;
    }
    validate_sql(
        c,
        "trigger",
        "home_transfer_source_subjects_prepared",
        SUBJECTS_PREPARED,
    )?;
    for (name, sql) in IMMUTABILITY {
        validate_sql(c, "trigger", name, sql)?;
    }
    Ok(())
}

fn validate_sql(
    c: &Connection,
    kind: &str,
    name: &str,
    expected: &str,
) -> Result<(), HomeTransferStoreError> {
    let actual:Option<String>=c.query_row(
        "SELECT CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql END FROM sqlite_schema WHERE type=?1 AND name=?2",
        rusqlite::params![kind,name],|r|r.get(0))?;
    let normalize = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if actual.as_deref().map(normalize) != Some(normalize(expected)) {
        return Err(HomeTransferStoreError::Corrupt("Home source schema"));
    }
    Ok(())
}
