//! Test-only downgrade of empty later-generation tables when constructing legacy fixtures.
#![cfg(test)]

use rusqlite::{Connection, OptionalExtension};

mod assignment_table_sql {
    include!("workspace_agent_assignments/table_sql.rs");
}

use assignment_table_sql::{
    AGENT_ASSIGNMENTS_TABLE_SQL, AGENT_ASSIGNMENTS_TABLE_SQL_V73,
    AGENT_ASSIGNMENTS_V73_COPY_COLUMNS_SQL, CREDIT_BUDGET_COLUMN_SQL,
};

// Closed identifiers in reverse dependency order. DDL remains owned by the
// evaluation schema; this helper neither recreates nor changes its definition.
const TABLES: &[&str] = &[
    "workspace_evaluation_review_cut_members",
    "workspace_evaluation_review_cuts",
    "workspace_evaluation_t1_cut_members",
    "workspace_evaluation_t1_cuts",
    "workspace_evaluation_review_receipts",
    "workspace_evaluation_submission_receipts",
    "workspace_evaluation_manifest_members",
    "workspace_evaluation_manifests",
    "workspace_evaluation_original_bindings",
    "workspace_evaluation_source_state",
];

const HOME_HANDOFF_OBJECTS: &[(&str, &str)] = &[
    ("table", "home_handoff_cases"),
    ("table", "home_handoff_proposals"),
    ("table", "home_handoff_proposal_heads"),
    ("trigger", "home_handoff_cases_prepared_parent"),
    ("trigger", "home_handoff_proposals_prepared_parent"),
    ("trigger", "home_handoff_cases_no_update"),
    ("trigger", "home_handoff_cases_no_delete"),
    ("trigger", "home_handoff_proposals_no_update"),
    ("trigger", "home_handoff_proposals_no_delete"),
    ("trigger", "home_handoff_proposal_heads_no_delete"),
    ("trigger", "home_handoff_proposal_heads_exact_insert"),
    ("trigger", "home_handoff_proposal_heads_monotonic_update"),
    ("table", "home_handoff_acceptance_outcomes"),
    ("index", "home_handoff_acceptance_applied_handoff_idx"),
    ("index", "home_handoff_acceptance_applied_predecessor_idx"),
    ("index", "home_handoff_acceptance_applied_successor_idx"),
    ("index", "home_handoff_acceptance_handoff_idx"),
    ("trigger", "home_handoff_acceptance_outcomes_no_update"),
    ("trigger", "home_handoff_acceptance_outcomes_no_delete"),
];

const HOME_HANDOFF_TABLES: &[&str] = &[
    "home_handoff_proposal_heads",
    "home_handoff_proposals",
    "home_handoff_acceptance_outcomes",
    "home_handoff_cases",
];

const ASSIGNMENT_INDEX_NAMES: &[&str] = &[
    "agent_assignments_active_agent_idx",
    "agent_assignments_active_node_idx",
    "agent_assignments_workspace_activity_idx",
    "agent_assignments_workspace_state_idx",
];
const FIRST_ASSIGNMENT_SCHEMA_VERSION: i64 = 34;
const HOME_ORIGIN_SCHEMA_VERSION: i64 = 74;
const PREVIOUS_HOME_ORIGIN_SCHEMA_VERSION: i64 = 73;

/// Remove only empty v74 Home-handoff state and restore the exact legacy v73
/// Assignment shape. Ordinary Assignment rows and their child rows survive.
/// The shared source file is also included by downstream integration tests.
#[allow(
    clippy::too_many_lines,
    reason = "fixture downgrade verifies and restores the complete v73 assignment shape atomically"
)]
pub(crate) fn downgrade_home_assignment_origin_to_v73(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    if !connection.is_autocommit() {
        return Err("Home Assignment fixture downgrade requires autocommit".into());
    }

    let home_objects = schema_objects_with_prefix(connection, "home_handoff_")?;
    let assignment_sql = schema_sql(connection, "table", "agent_assignments")?;
    let schema_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let Some(assignment_sql) = assignment_sql else {
        if home_objects.is_empty() && schema_version < FIRST_ASSIGNMENT_SCHEMA_VERSION {
            return Ok(());
        }
        return Err("Home handoff schema exists without its Assignment parent".into());
    };
    let columns = table_column_names(connection, "agent_assignments")?;
    let has_origin_kind = columns.iter().any(|name| name == "origin_kind");
    let has_home_receipt = columns.iter().any(|name| name == "home_receipt_id");
    if has_origin_kind != has_home_receipt {
        return Err("corrupt Home Assignment origin column pair".into());
    }

    if !has_origin_kind {
        // Older fixture builders can revisit this helper after intentionally
        // removing the v42 credit column. Recognize only that exact historical
        // shape; this helper does not certify the intermediate version label.
        let before_credit =
            AGENT_ASSIGNMENTS_TABLE_SQL_V73.replace(&format!(", {CREDIT_BUDGET_COLUMN_SQL}"), "");
        let known_legacy =
            assignment_schema_matches(&assignment_sql, AGENT_ASSIGNMENTS_TABLE_SQL_V73)
                || assignment_schema_matches(&assignment_sql, &before_credit);
        if schema_version > PREVIOUS_HOME_ORIGIN_SCHEMA_VERSION
            || !known_legacy
            || !home_objects.is_empty()
        {
            return Err("unknown legacy Home Assignment fixture shape".into());
        }
        return Ok(());
    }
    if schema_version != HOME_ORIGIN_SCHEMA_VERSION
        || !assignment_schema_matches(&assignment_sql, AGENT_ASSIGNMENTS_TABLE_SQL)
        || home_objects != sorted_home_handoff_objects()
    {
        return Err("unknown or partial v74 Home Assignment fixture shape".into());
    }
    for table in HOME_HANDOFF_TABLES {
        if exists(connection, "table", table)? && table_has_rows(connection, table)? {
            return Err(format!("refusing to downgrade populated {table}").into());
        }
    }
    let invalid_origin_pair: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM agent_assignments
            WHERE NOT ((origin_kind=0 AND home_receipt_id IS NULL)
                OR (origin_kind=1 AND home_receipt_id IS NOT NULL))
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_origin_pair {
        return Err("corrupt Home Assignment origin/receipt pair".into());
    }
    let home_assignment: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_assignments
                       WHERE origin_kind!=0 OR home_receipt_id IS NOT NULL)",
        [],
        |row| row.get(0),
    )?;
    if home_assignment {
        return Err("refusing to downgrade a Home-origin Assignment fixture".into());
    }
    if assignment_trigger_names(connection)? != ["agent_assignments_origin_immutable"] {
        return Err("unknown Assignment trigger in v74 fixture".into());
    }
    ensure_foreign_keys_valid(connection)?;

    let assignment_count = table_row_count(connection, "agent_assignments")?;
    let source_count = table_row_count(connection, "agent_assignment_sources")?;
    let indexes = assignment_indexes(connection)?;
    let other_triggers = non_handoff_triggers(connection)?;
    let previous_foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let previous_legacy_alter_table: i64 =
        connection.pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;

    let downgrade = (|| {
        const STAGING_TABLE: &str = "agent_assignments_home_handoff_fixture";
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "legacy_alter_table", true)?;
        let transaction = connection.unchecked_transaction()?;
        for table in HOME_HANDOFF_TABLES {
            transaction.execute_batch(&format!("DROP TABLE IF EXISTS {table}"))?;
        }

        let old_ddl = AGENT_ASSIGNMENTS_TABLE_SQL_V73.replacen(
            "CREATE TABLE agent_assignments (",
            "CREATE TABLE agent_assignments_home_handoff_fixture (",
            1,
        );
        if old_ddl == AGENT_ASSIGNMENTS_TABLE_SQL_V73 {
            return Err("legacy Assignment DDL authority has an unexpected table name".into());
        }
        transaction.execute_batch(&old_ddl)?;
        transaction.execute_batch(&format!(
            "INSERT INTO {STAGING_TABLE} ({AGENT_ASSIGNMENTS_V73_COPY_COLUMNS_SQL})
             SELECT {AGENT_ASSIGNMENTS_V73_COPY_COLUMNS_SQL} FROM agent_assignments;
             DROP TABLE agent_assignments;
             ALTER TABLE \"{STAGING_TABLE}\" RENAME TO \"agent_assignments\";"
        ))?;
        for (_, sql) in &indexes {
            transaction.execute_batch(sql)?;
        }
        transaction.pragma_update(None, "user_version", 73_i64)?;
        ensure_foreign_keys_valid(&transaction)?;
        transaction.commit()?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })();

    let restore_legacy_alter_table =
        connection.pragma_update(None, "legacy_alter_table", previous_legacy_alter_table);
    let restore_foreign_keys =
        connection.pragma_update(None, "foreign_keys", previous_foreign_keys);
    downgrade?;
    restore_legacy_alter_table?;
    restore_foreign_keys?;

    let migrated_sql = schema_sql(connection, "table", "agent_assignments")?
        .ok_or("Assignment table disappeared during fixture downgrade")?;
    if !assignment_schema_matches(&migrated_sql, AGENT_ASSIGNMENTS_TABLE_SQL_V73)
        || !schema_objects_with_prefix(connection, "home_handoff_")?.is_empty()
        || table_row_count(connection, "agent_assignments")? != assignment_count
        || table_row_count(connection, "agent_assignment_sources")? != source_count
        || assignment_indexes(connection)? != indexes
        || non_handoff_triggers(connection)? != other_triggers
    {
        return Err(
            "Home Assignment fixture downgrade did not preserve the exact v73 shape".into(),
        );
    }
    ensure_foreign_keys_valid(connection)?;
    Ok(())
}

fn sorted_home_handoff_objects() -> Vec<(String, String)> {
    let mut objects = HOME_HANDOFF_OBJECTS
        .iter()
        .map(|(kind, name)| ((*kind).to_owned(), (*name).to_owned()))
        .collect::<Vec<_>>();
    objects.sort();
    objects
}

fn schema_objects_with_prefix(
    connection: &Connection,
    prefix: &str,
) -> Result<Vec<(String, String)>, rusqlite::Error> {
    let mut statement = connection
        .prepare("SELECT type,name FROM sqlite_schema WHERE name LIKE ?1 ORDER BY type,name")?;
    let prefix_pattern = format!("{prefix}%");
    statement
        .query_map([prefix_pattern], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

fn schema_sql(
    connection: &Connection,
    kind: &str,
    name: &str,
) -> Result<Option<String>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type=?1 AND name=?2",
            [kind, name],
            |row| row.get(0),
        )
        .optional()
}

fn assignment_schema_matches(actual: &str, expected: &str) -> bool {
    normalize_schema_sql(actual) == normalize_schema_sql(expected)
        || normalize_schema_sql(actual)
            == normalize_schema_sql(&expected.replacen(
                "CREATE TABLE agent_assignments (",
                "CREATE TABLE \"agent_assignments\" (",
                1,
            ))
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn table_column_names(
    connection: &Connection,
    table: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    statement.query_map([], |row| row.get(1))?.collect()
}

fn exists(connection: &Connection, kind: &str, name: &str) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type=?1 AND name=?2)",
        [kind, name],
        |row| row.get(0),
    )
}

fn table_has_rows(connection: &Connection, table: &str) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
        [],
        |row| row.get(0),
    )
}

fn table_row_count(connection: &Connection, table: &str) -> Result<i64, rusqlite::Error> {
    connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
}

fn assignment_indexes(
    connection: &Connection,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut statement = connection.prepare(
        "SELECT name,sql FROM sqlite_schema
         WHERE type='index' AND tbl_name='agent_assignments' AND sql IS NOT NULL
         ORDER BY name",
    )?;
    let indexes = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = ASSIGNMENT_INDEX_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if indexes
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>()
        != expected
    {
        return Err("unknown Assignment index set in v74 fixture".into());
    }
    Ok(indexes)
}

fn assignment_trigger_names(connection: &Connection) -> Result<Vec<String>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type='trigger' AND tbl_name='agent_assignments'
         ORDER BY name",
    )?;
    statement.query_map([], |row| row.get(0))?.collect()
}

fn non_handoff_triggers(connection: &Connection) -> Result<Vec<(String, String)>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT name,sql FROM sqlite_schema
         WHERE type='trigger'
           AND name NOT LIKE 'home_handoff_%'
           AND name!='agent_assignments_origin_immutable'
         ORDER BY name",
    )?;
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

fn ensure_foreign_keys_valid(connection: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    if statement.query([])?.next()?.is_some() {
        return Err("fixture Workspace contains a foreign key violation".into());
    }
    Ok(())
}

pub(crate) fn remove_empty_evaluation_schema(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    downgrade_home_assignment_origin_to_v73(connection)?;
    let transaction = connection.unchecked_transaction()?;
    remove_empty_home_transfer_schema_objects(&transaction)?;
    for table in TABLES {
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists {
            let populated: bool = transaction.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                [],
                |row| row.get(0),
            )?;
            if populated {
                return Err("refusing to downgrade a populated evaluation fixture".into());
            }
        }
    }
    for table in TABLES {
        transaction.execute_batch(&format!("DROP TABLE IF EXISTS {table}"))?;
    }
    transaction.commit()?;
    Ok(())
}

#[allow(
    dead_code,
    reason = "shared test fixture is included by crates that only downgrade evaluation tables"
)]
pub(crate) fn remove_empty_home_transfer_schema(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    downgrade_home_assignment_origin_to_v73(connection)?;
    let transaction = connection.unchecked_transaction()?;
    remove_empty_home_transfer_schema_objects(&transaction)?;
    transaction.commit()?;
    Ok(())
}

#[allow(
    dead_code,
    reason = "shared fixture is included by downstream crates with different migration cases"
)]
pub(crate) fn remove_empty_home_reservation_retirement_schema_objects(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    downgrade_home_assignment_origin_to_v73(connection)?;
    remove_empty_home_reservation_retirement_schema_objects_v73(connection)
}

fn remove_empty_home_reservation_retirement_schema_objects_v73(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    const TABLE: &str = "home_transfer_reservation_retirements";
    remove_empty_home_artifact_schema_objects_v73(connection)?;
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [TABLE],
        |row| row.get(0),
    )?;
    if exists {
        let populated: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM home_transfer_reservation_retirements)",
            [],
            |row| row.get(0),
        )?;
        if populated {
            return Err(
                "refusing to downgrade a populated Home reservation retirement fixture".into(),
            );
        }
    }
    // These triggers belong to the new journal but attach to older tables.
    // Dropping only the journal does not remove them from a legacy fixture.
    for name in [
        "agent_binding_activations_block_home_reservation_retirement",
        "agent_binding_rejections_block_home_reservation_retirement",
        "agent_instances_block_home_reservation_retirement",
        "agent_instances_update_block_home_reservation_retirement",
    ] {
        connection.execute_batch(&format!("DROP TRIGGER IF EXISTS {name}"))?;
    }
    connection.execute_batch("DROP TABLE IF EXISTS home_transfer_reservation_retirements")?;
    Ok(())
}

fn remove_empty_home_transfer_schema_objects(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    // Shared by persistence and downstream crate fixtures. Only fixed table
    // identifiers live here; each owning module remains the DDL authority.
    const HOME_TABLES: &[&str] = &[
        "home_transfer_source_activities",
        "home_transfer_source_agents",
        "home_transfer_source_sessions",
        "home_transfer_source_subjects",
        "home_transfer_source_operations",
        "approval_agent_provenance",
    ];
    for table in HOME_TABLES {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists {
            let populated: bool = connection.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                [],
                |row| row.get(0),
            )?;
            if populated {
                return Err("refusing to downgrade a populated Home source fixture".into());
            }
        }
    }
    remove_empty_home_reservation_retirement_schema_objects_v73(connection)?;
    // SQLite drops a table's own triggers and indexes with the empty table.
    for table in HOME_TABLES {
        connection.execute_batch(&format!("DROP TABLE IF EXISTS {table}"))?;
    }
    Ok(())
}

/// Test-only removal of empty v73 artifacts before constructing a v72 snapshot.
#[allow(
    dead_code,
    reason = "shared historical fixture is also included by downstream crates"
)]
pub(crate) fn remove_empty_home_artifact_schema_objects(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    downgrade_home_assignment_origin_to_v73(connection)?;
    remove_empty_home_artifact_schema_objects_v73(connection)
}

fn remove_empty_home_artifact_schema_objects_v73(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    const ARTIFACT_TABLES: &[&str] = &[
        "home_transfer_artifact_seals",
        "home_transfer_artifact_stages",
    ];
    for table in ARTIFACT_TABLES {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists {
            let populated: bool = connection.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                [],
                |row| row.get(0),
            )?;
            if populated {
                return Err("refusing to downgrade a populated Home artifact fixture".into());
            }
        }
    }
    for table in ARTIFACT_TABLES {
        connection.execute_batch(&format!("DROP TABLE IF EXISTS {table}"))?;
    }
    Ok(())
}
