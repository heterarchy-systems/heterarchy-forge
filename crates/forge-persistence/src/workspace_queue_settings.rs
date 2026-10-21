//! `SQLite` authority for the optional per-Workspace queue-capacity preference.
//!
//! The app-global queue settings catalog remains a separate legacy surface.
//! This module stores only a Workspace-attributed preference and never creates
//! a missing row while reading it.

use forge_domain::{TimestampMillis, TimestampMillisError, WorkspaceId};
use heterarchy_orchestration_policy::QueueCapacity;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use thiserror::Error;
use uuid::Uuid;

use crate::queue_settings_catalog::{
    QueueSettings, QueueSettingsRevision, QueueSettingsRevisionError, QueueSettingsTransitionError,
    RegisteredQueueSettings,
};

pub(crate) const WORKSPACE_QUEUE_SETTINGS_TABLE_SQL: &str = "CREATE TABLE workspace_queue_settings (workspace_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), capacity_slots INTEGER NOT NULL CHECK(capacity_slots IN (32, 64, 128, 256)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1))";

const EXPECTED_COLUMNS: [(&str, &str, i64, i64); 5] = [
    ("workspace_id", "BLOB", 1, 1),
    ("capacity_slots", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 32;
const ID_BYTES: usize = 16;
const ID_BYTES_I64: i64 = 16;

const SETTINGS_QUERY: &str = "SELECT length(CAST(workspace_id AS BLOB)), workspace_id,
       capacity_slots, created_at_ms, updated_at_ms, revision
FROM workspace_queue_settings
WHERE workspace_id = ?1";

pub(crate) const fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", "workspace_queue_settings")]
}

pub(crate) fn create_schema(
    connection: &Connection,
) -> Result<(), WorkspaceQueueSettingsStoreError> {
    connection.execute_batch(WORKSPACE_QUEUE_SETTINGS_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), WorkspaceQueueSettingsStoreError> {
    let sql_length: Option<i64> = connection.query_row(
        "SELECT length(CAST(sql AS BLOB))
         FROM sqlite_schema WHERE type = 'table' AND name = 'workspace_queue_settings'",
        [],
        |row| row.get(0),
    )?;
    let Some(sql_length) = sql_length else {
        return Err(WorkspaceQueueSettingsStoreError::DamagedSchema(
            "workspace_queue_settings table is missing",
        ));
    };
    if sql_length < 0 {
        return Err(WorkspaceQueueSettingsStoreError::DamagedSchema(
            "workspace_queue_settings SQL length is negative",
        ));
    }
    let sql_length = usize::try_from(sql_length).unwrap_or(usize::MAX);
    if sql_length > MAX_SCHEMA_SQL_BYTES {
        return Err(WorkspaceQueueSettingsStoreError::SchemaSqlTooLarge {
            actual: sql_length,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'workspace_queue_settings'",
        [],
        |row| row.get(0),
    )?;
    if !schema_sql_matches(&actual, WORKSPACE_QUEUE_SETTINGS_TABLE_SQL) {
        return Err(WorkspaceQueueSettingsStoreError::DamagedSchema(
            "workspace_queue_settings table SQL definition does not match the expected policy",
        ));
    }

    let mut statement = connection.prepare("PRAGMA table_info(workspace_queue_settings)")?;
    let mut rows = statement.query([])?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next()? {
        if columns.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(WorkspaceQueueSettingsStoreError::SchemaMetadataTooLarge);
        }
        columns.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let columns_match = columns.len() == EXPECTED_COLUMNS.len()
        && columns.iter().zip(EXPECTED_COLUMNS).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !columns_match {
        return Err(WorkspaceQueueSettingsStoreError::DamagedSchema(
            "workspace_queue_settings table columns do not match the expected policy",
        ));
    }

    let mut statement = connection.prepare("PRAGMA foreign_key_list(workspace_queue_settings)")?;
    let mut rows = statement.query([])?;
    let mut foreign_keys = Vec::new();
    while let Some(row) = rows.next()? {
        if foreign_keys.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(WorkspaceQueueSettingsStoreError::SchemaMetadataTooLarge);
        }
        foreign_keys.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ));
    }
    let valid_foreign_keys = foreign_keys.len() == 1
        && foreign_keys.iter().any(|actual| {
            actual.0 == "workspace"
                && actual.1 == "workspace_id"
                && actual.2 == "workspace_id"
                && actual.3 == "NO ACTION"
                && actual.4 == "NO ACTION"
                && actual.5 == "NONE"
        });
    if !valid_foreign_keys {
        return Err(WorkspaceQueueSettingsStoreError::DamagedSchema(
            "workspace_queue_settings foreign-key shape is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn get(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<RegisteredQueueSettings>, WorkspaceQueueSettingsStoreError> {
    let id = workspace_id.into_uuid().into_bytes();
    connection
        .query_row(SETTINGS_QUERY, params![id.as_slice()], decode_row)
        .optional()?
        .map(|raw| decode(&raw, workspace_id))
        .transpose()
}

pub(crate) fn replace(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    settings: QueueSettings,
    expected_revision: Option<QueueSettingsRevision>,
    observed_at: TimestampMillis,
) -> Result<RegisteredQueueSettings, WorkspaceQueueSettingsStoreError> {
    let id = workspace_id.into_uuid().into_bytes();
    let current = transaction
        .query_row(SETTINGS_QUERY, params![id.as_slice()], decode_row)
        .optional()?
        .map(|raw| decode(&raw, workspace_id))
        .transpose()?;

    let updated = match (current, expected_revision) {
        (None, None) => RegisteredQueueSettings::initial(settings, observed_at),
        (Some(current), Some(expected_revision)) => {
            current.update(settings, expected_revision, observed_at)?
        }
        (None, Some(_)) | (Some(_), None) => {
            return Err(WorkspaceQueueSettingsStoreError::Transition(
                QueueSettingsTransitionError::RevisionConflict,
            ));
        }
    };

    match expected_revision {
        None => {
            transaction.execute(
                "INSERT INTO workspace_queue_settings(
                    workspace_id, capacity_slots, created_at_ms, updated_at_ms, revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id.as_slice(),
                    i64::from(updated.capacity().slots()),
                    updated.created_at().get(),
                    updated.updated_at().get(),
                    revision_as_i64(updated.revision())?,
                ],
            )?;
        }
        Some(expected_revision) => {
            let changed = transaction.execute(
                "UPDATE workspace_queue_settings
                 SET capacity_slots = ?1, updated_at_ms = ?2, revision = ?3
                 WHERE workspace_id = ?4 AND revision = ?5",
                params![
                    i64::from(updated.capacity().slots()),
                    updated.updated_at().get(),
                    revision_as_i64(updated.revision())?,
                    id.as_slice(),
                    revision_as_i64(expected_revision)?,
                ],
            )?;
            if changed != 1 {
                return Err(WorkspaceQueueSettingsStoreError::Transition(
                    QueueSettingsTransitionError::RevisionConflict,
                ));
            }
        }
    }
    Ok(updated)
}

fn revision_as_i64(
    revision: QueueSettingsRevision,
) -> Result<i64, WorkspaceQueueSettingsStoreError> {
    i64::try_from(revision.get()).map_err(WorkspaceQueueSettingsStoreError::IntConversion)
}

fn decode_row(row: &Row<'_>) -> Result<RawQueueSettings, rusqlite::Error> {
    Ok(RawQueueSettings {
        workspace_length: row.get(0)?,
        workspace_id: row.get(1)?,
        capacity_slots: row.get(2)?,
        created_at_ms: row.get(3)?,
        updated_at_ms: row.get(4)?,
        revision: row.get(5)?,
    })
}

fn decode(
    raw: &RawQueueSettings,
    expected_workspace_id: WorkspaceId,
) -> Result<RegisteredQueueSettings, WorkspaceQueueSettingsStoreError> {
    validate_exact_length(
        "workspace_queue_settings.workspace_id",
        raw.workspace_length,
    )?;
    let workspace_id = decode_workspace_id(&raw.workspace_id)?;
    if workspace_id != expected_workspace_id {
        return Err(WorkspaceQueueSettingsStoreError::CorruptRecord(
            "workspace_queue_settings.workspace_id",
        ));
    }
    let capacity = QueueCapacity::ALL
        .into_iter()
        .find(|capacity| i64::from(capacity.slots()) == raw.capacity_slots)
        .ok_or(WorkspaceQueueSettingsStoreError::StoredCapacity(
            raw.capacity_slots,
        ))?;
    RegisteredQueueSettings::from_parts(
        QueueSettings::new(capacity),
        TimestampMillis::new(raw.created_at_ms)?,
        TimestampMillis::new(raw.updated_at_ms)?,
        QueueSettingsRevision::new(
            u64::try_from(raw.revision)
                .map_err(|_| WorkspaceQueueSettingsStoreError::StoredRevision(raw.revision))?,
        )?,
    )
    .map_err(WorkspaceQueueSettingsStoreError::Transition)
}

fn decode_workspace_id(bytes: &[u8]) -> Result<WorkspaceId, WorkspaceQueueSettingsStoreError> {
    Uuid::from_slice(bytes)
        .map(WorkspaceId::from_uuid)
        .map_err(|_| {
            WorkspaceQueueSettingsStoreError::CorruptRecord("workspace_queue_settings.workspace_id")
        })
}

fn validate_exact_length(
    field: &'static str,
    length: i64,
) -> Result<(), WorkspaceQueueSettingsStoreError> {
    if length != ID_BYTES_I64 {
        return Err(
            WorkspaceQueueSettingsStoreError::PersistedFieldLengthInvalid {
                field,
                actual: usize::try_from(length).unwrap_or(usize::MAX),
                expected: ID_BYTES,
            },
        );
    }
    Ok(())
}

fn schema_sql_matches(actual: &str, expected: &str) -> bool {
    actual
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .eq(expected
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|byte| byte.to_ascii_lowercase()))
}

#[derive(Debug)]
struct RawQueueSettings {
    workspace_length: i64,
    workspace_id: Vec<u8>,
    capacity_slots: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
    revision: i64,
}

#[derive(Debug, Error)]
pub enum WorkspaceQueueSettingsStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Revision(#[from] QueueSettingsRevisionError),
    #[error(transparent)]
    Transition(#[from] QueueSettingsTransitionError),
    #[error(transparent)]
    IntConversion(#[from] std::num::TryFromIntError),
    #[error("workspace queue-settings schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("workspace queue-settings schema metadata exceeded its bound")]
    SchemaMetadataTooLarge,
    #[error("workspace queue-settings schema SQL is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge { actual: usize, maximum: usize },
    #[error(
        "persisted Workspace queue-settings field {field} has {actual} bytes; expected exactly {expected}"
    )]
    PersistedFieldLengthInvalid {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("stored Workspace queue capacity is invalid: {0}")]
    StoredCapacity(i64),
    #[error("stored Workspace queue settings revision is invalid: {0}")]
    StoredRevision(i64),
    #[error("corrupt Workspace queue settings record: {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        EstablishWorkspace, LocationId, TimestampMillis, WorkspaceId, WorkspaceRoot,
    };
    use forge_workspace::WorkspaceStateLayout;
    use heterarchy_orchestration_policy::QueueCapacity;
    use rusqlite::Connection;
    use uuid::Uuid;

    use super::*;
    use crate::workspace_store::{WorkspaceStore, WorkspaceStoreError};

    fn unique_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-workspace-queue-{label}-{unique}"));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn open_store(
        label: &str,
        seed: u128,
    ) -> Result<(PathBuf, WorkspaceStateLayout, WorkspaceStore), Box<dyn std::error::Error>> {
        let root = unique_root(label)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(seed));
        let location_id = LocationId::from_uuid(Uuid::from_u128(seed + 1));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(1)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        Ok((root, layout, store))
    }

    fn drop_recovery_and_stop_fixture_tables(
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute_batch(
            "DROP TABLE IF EXISTS unstarted_activity_continuation_receipts;
             DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
             DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
             DROP TABLE IF EXISTS agent_binding_rejections;
             DROP TABLE IF EXISTS expired_activity_recovery_agents;
             DROP INDEX IF EXISTS expired_activity_recovery_receipts_successor_uidx;
             DROP TABLE IF EXISTS expired_activity_recovery_receipts;
             DROP TABLE root_recovery_delegation_receipts;
             DROP TABLE recovery_run_executions;
             DROP TABLE recovery_run_activities;
             DROP TABLE recovery_runs;
             DROP TABLE workspace_root_recovery_receipts;
             DROP TABLE workspace_execution_stop_settlement_targets;
             DROP TABLE workspace_execution_stop_settlements;
             DROP TABLE workspace_execution_stop_fences;
             DROP TABLE execution_native_closures;
             DROP TABLE authority_stop_targets;
             DROP TABLE authority_stop_batches;
             DROP TABLE workspace_execution_stop_targets;
             DROP TABLE workspace_execution_stops;",
        )
    }

    #[test]
    fn missing_row_is_none_and_default_has_no_read_side_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store) = open_store("missing", 0x1000)?;
        assert_eq!(store.get_workspace_queue_settings()?, None);
        assert_eq!(QueueSettings::default().capacity(), QueueCapacity::C128);
        let connection = Connection::open(layout.database_path())?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM workspace_queue_settings", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 0);
        drop(connection);
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn replace_uses_exact_cas_and_timestamp_order() -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store) = open_store("cas", 0x1100)?;
        let initial = store.replace_workspace_queue_settings(
            QueueSettings::new(QueueCapacity::C128),
            None,
            timestamp(10)?,
        )?;
        assert_eq!(initial.revision(), QueueSettingsRevision::INITIAL);
        assert_eq!(initial.created_at(), timestamp(10)?);
        let updated = store.replace_workspace_queue_settings(
            QueueSettings::new(QueueCapacity::C64),
            Some(initial.revision()),
            timestamp(11)?,
        )?;
        assert_eq!(updated.capacity(), QueueCapacity::C64);
        assert_eq!(updated.revision().get(), 2);
        assert!(matches!(
            store.replace_workspace_queue_settings(
                QueueSettings::new(QueueCapacity::C32),
                Some(initial.revision()),
                timestamp(12)?,
            ),
            Err(WorkspaceStoreError::WorkspaceQueueSettings(
                WorkspaceQueueSettingsStoreError::Transition(
                    QueueSettingsTransitionError::RevisionConflict
                )
            ))
        ));
        assert!(matches!(
            store.replace_workspace_queue_settings(
                QueueSettings::new(QueueCapacity::C32),
                Some(updated.revision()),
                timestamp(9)?,
            ),
            Err(WorkspaceStoreError::WorkspaceQueueSettings(
                WorkspaceQueueSettingsStoreError::Transition(
                    QueueSettingsTransitionError::TimestampOrder
                )
            ))
        ));
        assert_eq!(store.get_workspace_queue_settings()?, Some(updated));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn replace_rolls_back_on_create_or_update_precondition_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store) = open_store("rollback", 0x1200)?;
        let initial = store.replace_workspace_queue_settings(
            QueueSettings::default(),
            None,
            timestamp(20)?,
        )?;
        assert!(matches!(
            store.replace_workspace_queue_settings(
                QueueSettings::new(QueueCapacity::C256),
                None,
                timestamp(21)?,
            ),
            Err(WorkspaceStoreError::WorkspaceQueueSettings(
                WorkspaceQueueSettingsStoreError::Transition(
                    QueueSettingsTransitionError::RevisionConflict
                )
            ))
        ));
        assert_eq!(store.get_workspace_queue_settings()?, Some(initial));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn corrupt_row_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store) = open_store("corrupt", 0x1300)?;
        let _ = store.replace_workspace_queue_settings(
            QueueSettings::default(),
            None,
            timestamp(30)?,
        )?;
        let connection = Connection::open(layout.database_path())?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute("UPDATE workspace_queue_settings SET capacity_slots = 7", [])?;
        assert!(matches!(
            store.get_workspace_queue_settings(),
            Err(WorkspaceStoreError::WorkspaceQueueSettings(
                WorkspaceQueueSettingsStoreError::StoredCapacity(7)
            ))
        ));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn independent_workspaces_do_not_share_settings() -> Result<(), Box<dyn std::error::Error>> {
        let (root_a, _layout_a, mut store_a) = open_store("isolation-a", 0x1400)?;
        let (root_b, _layout_b, store_b) = open_store("isolation-b", 0x1500)?;
        let saved = store_a.replace_workspace_queue_settings(
            QueueSettings::new(QueueCapacity::C256),
            None,
            timestamp(40)?,
        )?;
        assert_eq!(store_a.get_workspace_queue_settings()?, Some(saved));
        assert_eq!(store_b.get_workspace_queue_settings()?, None);
        drop(store_a);
        drop(store_b);
        fs::remove_dir_all(root_a)?;
        fs::remove_dir_all(root_b)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v32_migration_adds_empty_workspace_settings_and_read_only_is_non_mutating()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store) = open_store("migration-v32", 0x1600)?;
        drop(store);
        let database = layout.database_path();
        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        for (kind, name) in crate::workspace_effect_fact_outbox::base_schema_objects()
            .into_iter()
            .chain(crate::workspace_effect_fact_outbox::change_set_schema_objects())
            .chain(crate::workspace_effect_fact_outbox::work_credit_schema_objects())
            .chain(crate::workspace_effect_fact_outbox::assignment_offered_schema_objects())
            .chain(crate::workspace_effect_fact_outbox::assignment_submitted_schema_objects())
            .chain(crate::workspace_semantic_events::schema_objects())
            .chain(crate::workspace_admission_envelopes::schema_objects())
            .chain(crate::workspace_goal_mutations::schema_objects())
            .chain(crate::workspace_coordinator_recovery::schema_objects())
            .chain(crate::workspace_goal_creation_watermarks::schema_objects())
            .chain(crate::workspace_work_cuts::schema_objects())
            .chain(crate::workspace_work_cuts::continuation_schema_objects())
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_departure_reconciliation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_session_reconciliation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.execute_batch(
            "DROP TABLE IF EXISTS unstarted_activity_continuation_receipts;
             DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
             DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
             DROP TABLE IF EXISTS agent_binding_rejections;
             DROP TABLE IF EXISTS expired_activity_recovery_agents;
             DROP INDEX IF EXISTS expired_activity_recovery_receipts_successor_uidx;
             DROP TABLE IF EXISTS expired_activity_recovery_receipts;",
        )?;
        for (kind, name) in crate::workspace_agent_binding_activation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_effect_outbox::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        for (kind, name) in crate::workspace_agent_delegation::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.execute_batch("DROP TABLE agent_binding_reservations")?;
        for (kind, name) in crate::workspace_agent_migration::schema_objects()
            .into_iter()
            .rev()
        {
            connection.execute_batch(&format!("DROP {kind} {name}"))?;
        }
        connection.execute_batch(
            "DROP TABLE workspace_queue_settings;
            DROP TRIGGER agent_assignment_offer_seals_no_delete;
            DROP TRIGGER agent_assignment_offer_seals_no_update;
            DROP TABLE agent_assignment_offer_seals;
            DROP TABLE agent_assignment_sources;
            DROP TABLE agent_assignments;
            DROP TABLE goal_deletion_cleanup_journal;",
        )?;
        crate::workspace_approvals::rebuild_v55_auto_scopes_fixture(&connection)?;
        drop_recovery_and_stop_fixture_tables(&connection)?;
        connection.pragma_update(None, "user_version", 32_i64)?;
        drop(connection);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = database.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
        }
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert_eq!(
            WorkspaceStore::inspect_queue_settings_live_read_only(&existing)?,
            None
        );
        let migrated = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(migrated.get_workspace_queue_settings()?, None);
        assert_eq!(
            migrated.health()?.schema_version(),
            crate::workspace_store::CURRENT_SCHEMA_VERSION
        );
        drop(migrated);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn current_live_read_only_queue_settings_reads_without_inserting()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store) = open_store("live-read", 0x1700)?;
        assert_eq!(
            WorkspaceStore::inspect_queue_settings_live_read_only(
                &WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?,
            )?,
            None
        );
        let saved = store.replace_workspace_queue_settings(
            QueueSettings::new(QueueCapacity::C64),
            None,
            timestamp(50)?,
        )?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        assert_eq!(
            WorkspaceStore::inspect_queue_settings_live_read_only(&existing)?,
            Some(saved)
        );
        let connection = Connection::open(layout.database_path())?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM workspace_queue_settings", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 1);
        drop(connection);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_validation_checks_foreign_key_and_columns() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY);
             CREATE TABLE workspace_queue_settings (
                 workspace_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
                 capacity_slots INTEGER NOT NULL CHECK(capacity_slots IN (32, 64, 128, 256)),
                 created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                 updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
                 revision INTEGER NOT NULL CHECK(revision >= 1)
             );",
        )?;
        validate_schema(&connection)?;
        connection.execute_batch(
            "DROP TABLE workspace_queue_settings;
             CREATE TABLE workspace_queue_settings (
                 workspace_id BLOB PRIMARY KEY NOT NULL,
                 capacity_slots INTEGER NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 revision INTEGER NOT NULL
             );",
        )?;
        assert!(matches!(
            validate_schema(&connection),
            Err(WorkspaceQueueSettingsStoreError::DamagedSchema(_))
        ));
        Ok(())
    }
}
