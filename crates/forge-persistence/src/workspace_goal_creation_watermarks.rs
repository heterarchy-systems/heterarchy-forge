//! Permanent created-at fences for reused Workspace Goal UUIDs.
//!
//! Schema v52 records the greatest known creation timestamp for each exact
//! `(Workspace, Goal UUID)` pair. The row deliberately has no Goal foreign key
//! and cannot be deleted, so Goal deletion cannot erase the fence.
//!
//! The migration can recover current Goals, exact pending deletion rows, and
//! retained `GoalCreated` events. Deleted Goal identities from before that
//! event existed are unknowable; the guarantee is migration-forward from the
//! histories that remain durably observable when schema v52 is installed.

use forge_domain::{GoalId, WorkspaceId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::workspace_goals::GoalStoreError;

const TABLE_SQL: &str = "CREATE TABLE goal_creation_watermarks (workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16), greatest_created_at_ms INTEGER NOT NULL CHECK(greatest_created_at_ms >= 0), PRIMARY KEY(workspace_id, goal_id))";
const NO_DELETE_SQL: &str = "CREATE TRIGGER goal_creation_watermarks_no_delete BEFORE DELETE ON goal_creation_watermarks BEGIN SELECT RAISE(ABORT, 'Goal creation watermarks are permanent'); END";
const MONOTONIC_SQL: &str = "CREATE TRIGGER goal_creation_watermarks_monotonic BEFORE UPDATE ON goal_creation_watermarks WHEN NEW.workspace_id != OLD.workspace_id OR NEW.goal_id != OLD.goal_id OR NEW.greatest_created_at_ms <= OLD.greatest_created_at_ms BEGIN SELECT RAISE(ABORT, 'Goal creation watermarks can only advance'); END";
const OBJECTS: [(&str, &str, &str); 3] = [
    ("table", "goal_creation_watermarks", TABLE_SQL),
    (
        "trigger",
        "goal_creation_watermarks_no_delete",
        NO_DELETE_SQL,
    ),
    (
        "trigger",
        "goal_creation_watermarks_monotonic",
        MONOTONIC_SQL,
    ),
];

const CURRENT_GOALS_BACKFILL_SQL: &str = "INSERT INTO goal_creation_watermarks (workspace_id, goal_id, greatest_created_at_ms) SELECT workspace_id, goal_id, created_at_ms FROM goals WHERE true ON CONFLICT(workspace_id, goal_id) DO UPDATE SET greatest_created_at_ms = excluded.greatest_created_at_ms WHERE excluded.greatest_created_at_ms > goal_creation_watermarks.greatest_created_at_ms";
const PENDING_DELETIONS_BACKFILL_SQL: &str = "INSERT INTO goal_creation_watermarks (workspace_id, goal_id, greatest_created_at_ms) SELECT workspace_id, goal_id, goal_created_at_ms FROM goal_deletion_cleanup_journal WHERE true ON CONFLICT(workspace_id, goal_id) DO UPDATE SET greatest_created_at_ms = excluded.greatest_created_at_ms WHERE excluded.greatest_created_at_ms > goal_creation_watermarks.greatest_created_at_ms";
const GOAL_CREATED_EVENTS_BACKFILL_SQL: &str = "INSERT INTO goal_creation_watermarks (workspace_id, goal_id, greatest_created_at_ms) SELECT workspace_id, subject_goal_id, observed_at_ms FROM semantic_events WHERE event_kind = 'goal_created' AND subject_goal_id IS NOT NULL ON CONFLICT(workspace_id, goal_id) DO UPDATE SET greatest_created_at_ms = excluded.greatest_created_at_ms WHERE excluded.greatest_created_at_ms > goal_creation_watermarks.greatest_created_at_ms";
const RECORD_CREATION_SQL: &str = "INSERT INTO goal_creation_watermarks (workspace_id, goal_id, greatest_created_at_ms) VALUES (?1, ?2, ?3) ON CONFLICT(workspace_id, goal_id) DO UPDATE SET greatest_created_at_ms = excluded.greatest_created_at_ms WHERE excluded.greatest_created_at_ms > goal_creation_watermarks.greatest_created_at_ms";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), GoalStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "goal_creation_watermarks"),
        ("trigger", "goal_creation_watermarks_no_delete"),
        ("trigger", "goal_creation_watermarks_monotonic"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), GoalStoreError> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(GoalStoreError::DamagedSchema(name));
        }
    }
    Ok(())
}

pub(crate) fn backfill(connection: &Connection) -> Result<(), GoalStoreError> {
    connection.execute(CURRENT_GOALS_BACKFILL_SQL, [])?;
    connection.execute(PENDING_DELETIONS_BACKFILL_SQL, [])?;
    // GoalCreated append sites persist this exact Goal.created_at timestamp.
    // Never infer creation time from another event kind's observed_at value.
    connection.execute(GOAL_CREATED_EVENTS_BACKFILL_SQL, [])?;
    Ok(())
}

pub(crate) fn record_creation(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    goal_id: GoalId,
    created_at_ms: i64,
) -> Result<bool, GoalStoreError> {
    let changed = transaction.execute(
        RECORD_CREATION_SQL,
        params![
            workspace_id.into_uuid().as_bytes(),
            goal_id.into_uuid().as_bytes(),
            created_at_ms,
        ],
    )?;
    Ok(changed == 1)
}

pub(crate) fn greatest_created_at_ms(
    connection: &Connection,
    workspace_id: WorkspaceId,
    goal_id: GoalId,
) -> Result<Option<i64>, GoalStoreError> {
    connection
        .query_row(
            "SELECT greatest_created_at_ms FROM goal_creation_watermarks
             WHERE workspace_id = ?1 AND goal_id = ?2",
            params![
                workspace_id.into_uuid().as_bytes(),
                goal_id.into_uuid().as_bytes(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}
