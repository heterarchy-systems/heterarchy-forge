//! `SQLite` schema creation and exact-shape validation for checkpoint persistence.

use rusqlite::{Connection, OptionalExtension, params};

use super::CheckpointStoreError;

pub(super) const CHECKPOINTS_TABLE_SQL: &str = r"
CREATE TABLE checkpoints (
    checkpoint_id BLOB PRIMARY KEY NOT NULL CHECK(length(checkpoint_id) = 16),
    changeset_id BLOB NOT NULL UNIQUE REFERENCES change_sets(changeset_id) CHECK(length(changeset_id) = 16),
    workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
    activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16),
    workspace_revision INTEGER NOT NULL CHECK(workspace_revision >= 1),
    relative_path BLOB NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096),
    object_format INTEGER NOT NULL CHECK(object_format IN (0)),
    state INTEGER NOT NULL CHECK(state IN (0, 1)),
    pre_state INTEGER NOT NULL CHECK(pre_state IN (0, 1)),
    pre_blob BLOB CHECK(pre_blob IS NULL OR length(pre_blob) = 20),
    pre_hash BLOB CHECK(pre_hash IS NULL OR length(pre_hash) = 32),
    pre_size INTEGER CHECK(pre_size IS NULL OR pre_size >= 0),
    pre_mode INTEGER CHECK(pre_mode IS NULL OR pre_mode BETWEEN 0 AND 511),
    pre_commit BLOB NOT NULL CHECK(length(pre_commit) = 20),
    post_state INTEGER CHECK(post_state IS NULL OR post_state IN (0, 1)),
    post_blob BLOB CHECK(post_blob IS NULL OR length(post_blob) = 20),
    post_hash BLOB CHECK(post_hash IS NULL OR length(post_hash) = 32),
    post_size INTEGER CHECK(post_size IS NULL OR post_size >= 0),
    post_mode INTEGER CHECK(post_mode IS NULL OR post_mode BETWEEN 0 AND 511),
    post_commit BLOB CHECK(post_commit IS NULL OR length(post_commit) = 20),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    CHECK((pre_state = 0 AND pre_blob IS NULL AND pre_hash IS NULL AND pre_size IS NULL AND pre_mode IS NULL)
       OR (pre_state = 1 AND pre_blob IS NOT NULL AND pre_hash IS NOT NULL AND pre_size IS NOT NULL AND pre_mode IS NOT NULL)),
    CHECK((state = 0 AND post_state IS NULL AND post_blob IS NULL AND post_hash IS NULL AND post_size IS NULL AND post_mode IS NULL AND post_commit IS NULL)
       OR (state = 1 AND post_state IS NOT NULL AND post_commit IS NOT NULL
           AND ((post_state = 0 AND post_blob IS NULL AND post_hash IS NULL AND post_size IS NULL AND post_mode IS NULL)
             OR (post_state = 1 AND post_blob IS NOT NULL AND post_hash IS NOT NULL AND post_size IS NOT NULL AND post_mode IS NOT NULL)))),
    CHECK((state = 0 AND revision = 1 AND updated_at_ms = created_at_ms)
       OR (state = 1 AND revision = 2 AND updated_at_ms >= created_at_ms))
)
";

pub(super) const RESTORES_V12_TABLE_SQL: &str = r"
CREATE TABLE checkpoint_restores (
    restore_id BLOB PRIMARY KEY NOT NULL CHECK(length(restore_id) = 16),
    checkpoint_id BLOB NOT NULL REFERENCES checkpoints(checkpoint_id) CHECK(length(checkpoint_id) = 16),
    workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
    expected_checkpoint_revision INTEGER NOT NULL CHECK(expected_checkpoint_revision >= 1),
    initiator_runtime_instance_id BLOB NOT NULL CHECK(length(initiator_runtime_instance_id) = 16),
    activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16),
    approval_request_id BLOB REFERENCES approval_requests(approval_id) CHECK(approval_request_id IS NULL OR length(approval_request_id) = 16),
    maintenance_owner BLOB CHECK(maintenance_owner IS NULL OR length(maintenance_owner) = 16),
    maintenance_lease_epoch INTEGER CHECK(maintenance_lease_epoch IS NULL OR maintenance_lease_epoch >= 0),
    expected_post_state INTEGER NOT NULL CHECK(expected_post_state IN (0, 1)),
    expected_post_hash BLOB CHECK(expected_post_hash IS NULL OR length(expected_post_hash) = 32),
    expected_post_size INTEGER CHECK(expected_post_size IS NULL OR expected_post_size >= 0),
    expected_post_mode INTEGER CHECK(expected_post_mode IS NULL OR expected_post_mode BETWEEN 0 AND 511),
    inverse_kind INTEGER NOT NULL CHECK(inverse_kind IN (0, 1)),
    inverse_blob BLOB CHECK(inverse_blob IS NULL OR length(inverse_blob) = 20),
    inverse_hash BLOB CHECK(inverse_hash IS NULL OR length(inverse_hash) = 32),
    inverse_size INTEGER CHECK(inverse_size IS NULL OR inverse_size >= 0),
    inverse_mode INTEGER CHECK(inverse_mode IS NULL OR inverse_mode BETWEEN 0 AND 511),
    state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)),
    failure_code INTEGER CHECK(failure_code IS NULL OR failure_code IN (0, 1, 2, 3)),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    CHECK((maintenance_owner IS NULL) = (maintenance_lease_epoch IS NULL)),
    CHECK((expected_post_state = 0 AND expected_post_hash IS NULL AND expected_post_size IS NULL AND expected_post_mode IS NULL)
       OR (expected_post_state = 1 AND expected_post_hash IS NOT NULL AND expected_post_size IS NOT NULL AND expected_post_mode IS NOT NULL)),
    CHECK((inverse_kind = 0 AND inverse_blob IS NULL AND inverse_hash IS NULL AND inverse_size IS NULL AND inverse_mode IS NULL)
       OR (inverse_kind = 1 AND inverse_blob IS NOT NULL AND inverse_hash IS NOT NULL AND inverse_size IS NOT NULL AND inverse_mode IS NOT NULL)),
    CHECK((state IN (0, 1, 3) AND failure_code IS NULL) OR (state = 2 AND failure_code IS NOT NULL)),
    CHECK((state = 0 AND revision = 1 AND updated_at_ms = created_at_ms AND failure_code IS NULL)
       OR (state = 1 AND revision = 2 AND updated_at_ms >= created_at_ms AND failure_code IS NULL)
       OR (state = 2 AND revision = 2 AND updated_at_ms >= created_at_ms AND failure_code IS NOT NULL)
       OR (state = 3 AND revision = 2 AND updated_at_ms >= created_at_ms AND failure_code IS NULL))
)
";

pub(super) const CHECKPOINTS_WORKSPACE_INDEX_SQL: &str = "CREATE INDEX checkpoints_workspace_created_idx ON checkpoints(workspace_id, created_at_ms DESC, checkpoint_id DESC)";
pub(super) const CHECKPOINTS_STATE_INDEX_SQL: &str = "CREATE INDEX checkpoints_state_updated_idx ON checkpoints(state, updated_at_ms, checkpoint_id)";
pub(super) const RESTORES_WORKSPACE_INDEX_SQL: &str = "CREATE INDEX checkpoint_restores_workspace_created_idx ON checkpoint_restores(workspace_id, created_at_ms DESC, restore_id DESC)";
pub(super) const RESTORES_STATE_INDEX_SQL: &str = "CREATE INDEX checkpoint_restores_state_updated_idx ON checkpoint_restores(state, updated_at_ms, restore_id)";

const CURRENT_SCHEMA_SQL: [&str; 6] = [
    CHECKPOINTS_TABLE_SQL,
    RESTORES_V12_TABLE_SQL,
    CHECKPOINTS_WORKSPACE_INDEX_SQL,
    CHECKPOINTS_STATE_INDEX_SQL,
    RESTORES_WORKSPACE_INDEX_SQL,
    RESTORES_STATE_INDEX_SQL,
];

pub(super) fn create_schema(connection: &Connection) -> Result<(), CheckpointStoreError> {
    for sql in CURRENT_SCHEMA_SQL {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(super) const fn objects() -> [(&'static str, &'static str); 6] {
    [
        ("table", "checkpoints"),
        ("table", "checkpoint_restores"),
        ("index", "checkpoints_workspace_created_idx"),
        ("index", "checkpoints_state_updated_idx"),
        ("index", "checkpoint_restores_workspace_created_idx"),
        ("index", "checkpoint_restores_state_updated_idx"),
    ]
}

pub(super) fn validate_current(connection: &Connection) -> Result<(), CheckpointStoreError> {
    validate_schema_sqls(connection, RESTORES_V12_TABLE_SQL)?;
    validate_checkpoint_columns(connection)?;
    validate_table_columns(
        connection,
        "checkpoint_restores",
        &[
            ("restore_id", "BLOB", 1, 1),
            ("checkpoint_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("expected_checkpoint_revision", "INTEGER", 1, 0),
            ("initiator_runtime_instance_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("approval_request_id", "BLOB", 0, 0),
            ("maintenance_owner", "BLOB", 0, 0),
            ("maintenance_lease_epoch", "INTEGER", 0, 0),
            ("expected_post_state", "INTEGER", 1, 0),
            ("expected_post_hash", "BLOB", 0, 0),
            ("expected_post_size", "INTEGER", 0, 0),
            ("expected_post_mode", "INTEGER", 0, 0),
            ("inverse_kind", "INTEGER", 1, 0),
            ("inverse_blob", "BLOB", 0, 0),
            ("inverse_hash", "BLOB", 0, 0),
            ("inverse_size", "INTEGER", 0, 0),
            ("inverse_mode", "INTEGER", 0, 0),
            ("state", "INTEGER", 1, 0),
            ("failure_code", "INTEGER", 0, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_common_indexes(connection)?;
    validate_foreign_keys(
        connection,
        "checkpoints",
        &[
            ("change_sets", "changeset_id", "changeset_id"),
            ("workspace", "workspace_id", "workspace_id"),
            ("activities", "activity_id", "activity_id"),
        ],
    )?;
    validate_foreign_keys(
        connection,
        "checkpoint_restores",
        &[
            ("checkpoints", "checkpoint_id", "checkpoint_id"),
            ("workspace", "workspace_id", "workspace_id"),
            ("activities", "activity_id", "activity_id"),
            ("approval_requests", "approval_request_id", "approval_id"),
        ],
    )
}

fn validate_schema_sqls(
    connection: &Connection,
    restore_table_sql: &'static str,
) -> Result<(), CheckpointStoreError> {
    for (kind, name, expected) in [
        ("table", "checkpoints", CHECKPOINTS_TABLE_SQL),
        ("table", "checkpoint_restores", restore_table_sql),
        (
            "index",
            "checkpoints_workspace_created_idx",
            CHECKPOINTS_WORKSPACE_INDEX_SQL,
        ),
        (
            "index",
            "checkpoints_state_updated_idx",
            CHECKPOINTS_STATE_INDEX_SQL,
        ),
        (
            "index",
            "checkpoint_restores_workspace_created_idx",
            RESTORES_WORKSPACE_INDEX_SQL,
        ),
        (
            "index",
            "checkpoint_restores_state_updated_idx",
            RESTORES_STATE_INDEX_SQL,
        ),
    ] {
        validate_schema_sql(connection, kind, name, expected)?;
    }
    Ok(())
}

fn validate_checkpoint_columns(connection: &Connection) -> Result<(), CheckpointStoreError> {
    validate_table_columns(
        connection,
        "checkpoints",
        &[
            ("checkpoint_id", "BLOB", 1, 1),
            ("changeset_id", "BLOB", 1, 0),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("workspace_revision", "INTEGER", 1, 0),
            ("relative_path", "BLOB", 1, 0),
            ("object_format", "INTEGER", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("pre_state", "INTEGER", 1, 0),
            ("pre_blob", "BLOB", 0, 0),
            ("pre_hash", "BLOB", 0, 0),
            ("pre_size", "INTEGER", 0, 0),
            ("pre_mode", "INTEGER", 0, 0),
            ("pre_commit", "BLOB", 1, 0),
            ("post_state", "INTEGER", 0, 0),
            ("post_blob", "BLOB", 0, 0),
            ("post_hash", "BLOB", 0, 0),
            ("post_size", "INTEGER", 0, 0),
            ("post_mode", "INTEGER", 0, 0),
            ("post_commit", "BLOB", 0, 0),
            ("created_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )
}

fn validate_common_indexes(connection: &Connection) -> Result<(), CheckpointStoreError> {
    for (index, columns) in [
        (
            "checkpoints_workspace_created_idx",
            &["workspace_id", "created_at_ms", "checkpoint_id"][..],
        ),
        (
            "checkpoints_state_updated_idx",
            &["state", "updated_at_ms", "checkpoint_id"][..],
        ),
        (
            "checkpoint_restores_workspace_created_idx",
            &["workspace_id", "created_at_ms", "restore_id"][..],
        ),
        (
            "checkpoint_restores_state_updated_idx",
            &["state", "updated_at_ms", "restore_id"][..],
        ),
    ] {
        validate_index_columns(connection, index, columns)?;
    }
    Ok(())
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &'static str,
) -> Result<(), CheckpointStoreError> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    let sql = sql.ok_or(CheckpointStoreError::CorruptRecord(name))?;
    if normalize_sql(&sql) == normalize_sql(expected) {
        Ok(())
    } else {
        Err(CheckpointStoreError::CorruptRecord(name))
    }
}

fn validate_table_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), CheckpointStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::with_capacity(expected.len());
    while let Some(row) = rows.next()? {
        if actual.len() >= expected.len() {
            return Err(CheckpointStoreError::CorruptRecord(table));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(|(actual, expected)| {
            actual.0 == expected.0
                && actual.1.eq_ignore_ascii_case(expected.1)
                && actual.2 == expected.2
                && actual.3 == expected.3
        })
    {
        return Err(CheckpointStoreError::CorruptRecord(table));
    }
    Ok(())
}

fn validate_index_columns(
    connection: &Connection,
    index: &'static str,
    expected: &[&str],
) -> Result<(), CheckpointStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA index_info({index})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::with_capacity(expected.len());
    while let Some(row) = rows.next()? {
        if actual.len() >= expected.len() {
            return Err(CheckpointStoreError::CorruptRecord(index));
        }
        actual.push(row.get::<_, String>(2)?);
    }
    if actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(CheckpointStoreError::CorruptRecord(index))
    }
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, &str)],
) -> Result<(), CheckpointStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::with_capacity(expected.len());
    while let Some(row) = rows.next()? {
        if actual.len() >= expected.len() {
            return Err(CheckpointStoreError::CorruptRecord(table));
        }
        actual.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ));
    }
    if actual.len() != expected.len()
        || !expected.iter().all(|item| {
            actual
                .iter()
                .any(|value| value.0 == item.0 && value.1 == item.1 && value.2 == item.2)
        })
    {
        return Err(CheckpointStoreError::CorruptRecord(table));
    }
    Ok(())
}

pub(super) fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
