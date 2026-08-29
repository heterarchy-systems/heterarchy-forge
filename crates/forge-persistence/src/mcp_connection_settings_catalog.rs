//! App-global `SQLite` authority for the MCP connection settings singleton.
//!
//! This catalog is intentionally separate from the bearer-token catalog.  It
//! stores only validated public connection metadata and never stores a bearer
//! value, credential, or secret.  The one-row schema is opened and validated
//! fail-closed before any settings are returned or changed.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_domain::{
    McpConnectionRevision, McpConnectionRevisionError, McpConnectionSettings,
    McpConnectionSettingsTransitionError, McpLocalPort, McpLocalPortError, McpPublicBase,
    McpPublicBaseError, RegisteredMcpConnectionSettings, TimestampMillis, TimestampMillisError,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use thiserror::Error;

pub const MCP_CONNECTION_SETTINGS_APPLICATION_ID: i64 = 0x4846_434e;
pub const MCP_CONNECTION_SETTINGS_SCHEMA_VERSION: i64 = 2;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SETTINGS_ID: i64 = 1;
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const EXPECTED_SETTINGS_TABLE_SQL: &str = "CREATE TABLE mcp_connection_settings (settings_id INTEGER PRIMARY KEY NOT NULL CHECK(settings_id = 1), public_origin TEXT CHECK(length(CAST(public_origin AS BLOB)) BETWEEN 1 AND 261), local_port INTEGER NOT NULL CHECK(local_port BETWEEN 1 AND 65535), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1))";
const LEGACY_V1_SETTINGS_TABLE_SQL: &str = "CREATE TABLE mcp_connection_settings (settings_id INTEGER PRIMARY KEY NOT NULL CHECK(settings_id = 1), public_origin TEXT NOT NULL CHECK(length(CAST(public_origin AS BLOB)) BETWEEN 1 AND 261), local_port INTEGER NOT NULL CHECK(local_port BETWEEN 1 AND 65535), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1))";
const EXPECTED_COLUMNS: [(&str, &str, i64, i64); 6] = [
    ("settings_id", "INTEGER", 1, 1),
    ("public_origin", "TEXT", 0, 0),
    ("local_port", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

/// SQLite-backed app-global MCP connection settings authority.
pub struct McpConnectionSettingsCatalog {
    path: PathBuf,
    connection: Connection,
}

impl fmt::Debug for McpConnectionSettingsCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpConnectionSettingsCatalog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl McpConnectionSettingsCatalog {
    /// Open or create the catalog at an application-owned path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, McpConnectionSettingsCatalogError> {
        let path = canonical_catalog_path(path.as_ref())?;
        validate_catalog_path(&path)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        validate_catalog_path(&path)?;
        configure(&connection)?;
        let mut connection = connection;
        initialize_or_validate(&mut connection)?;
        Ok(Self { path, connection })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the singleton settings record, if the operator has configured it.
    pub fn get(
        &self,
    ) -> Result<Option<RegisteredMcpConnectionSettings>, McpConnectionSettingsCatalogError> {
        load_settings(&self.connection)
    }

    /// Create the first settings record at revision one.
    pub fn create(
        &mut self,
        settings: McpConnectionSettings,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredMcpConnectionSettings, McpConnectionSettingsCatalogError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM mcp_connection_settings WHERE settings_id = ?1)",
            params![SETTINGS_ID],
            |row| row.get(0),
        )?;
        if exists {
            return Err(McpConnectionSettingsCatalogError::AlreadyConfigured);
        }
        let record = RegisteredMcpConnectionSettings::initial(settings, observed_at);
        insert_settings(&transaction, &record)?;
        transaction.commit()?;
        Ok(record)
    }

    /// Replace settings using an atomic durable revision compare-and-swap.
    pub fn update(
        &mut self,
        settings: McpConnectionSettings,
        expected_revision: McpConnectionRevision,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredMcpConnectionSettings, McpConnectionSettingsCatalogError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            load_settings(&transaction)?.ok_or(McpConnectionSettingsCatalogError::NotConfigured)?;
        let updated = current.update(settings, expected_revision, observed_at)?;
        let changed = transaction.execute(
            "UPDATE mcp_connection_settings
             SET public_origin = ?1, local_port = ?2, updated_at_ms = ?3, revision = ?4
             WHERE settings_id = ?5 AND revision = ?6",
            params![
                updated.public_origin(),
                i64::from(updated.local_port().get()),
                updated.updated_at().get(),
                updated.revision().get(),
                SETTINGS_ID,
                expected_revision.get(),
            ],
        )?;
        if changed != 1 {
            return Err(McpConnectionSettingsCatalogError::RevisionConflict);
        }
        transaction.commit()?;
        Ok(updated)
    }
}

fn canonical_catalog_path(
    requested_path: &Path,
) -> Result<PathBuf, McpConnectionSettingsCatalogError> {
    let parent = requested_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            McpConnectionSettingsCatalogError::MissingParent(requested_path.to_path_buf())
        })?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| McpConnectionSettingsCatalogError::PathIo {
            path: parent.to_path_buf(),
            source,
        })?;
    let file_name = requested_path.file_name().ok_or_else(|| {
        McpConnectionSettingsCatalogError::MissingParent(requested_path.to_path_buf())
    })?;
    Ok(canonical_parent.join(file_name))
}

fn validate_catalog_path(path: &Path) -> Result<(), McpConnectionSettingsCatalogError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| McpConnectionSettingsCatalogError::MissingParent(path.to_path_buf()))?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|source| {
        McpConnectionSettingsCatalogError::PathIo {
            path: parent.to_path_buf(),
            source,
        }
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(McpConnectionSettingsCatalogError::InvalidPath(
            parent.to_path_buf(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() != 1
            {
                return Err(McpConnectionSettingsCatalogError::InvalidPath(
                    path.to_path_buf(),
                ));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(McpConnectionSettingsCatalogError::PathIo {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

fn configure(connection: &Connection) -> Result<(), McpConnectionSettingsCatalogError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn initialize_or_validate(
    connection: &mut Connection,
) -> Result<(), McpConnectionSettingsCatalogError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let object_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;

    match (application_id, user_version, object_count) {
        (0, 0, 0) => create_schema(connection),
        (MCP_CONNECTION_SETTINGS_APPLICATION_ID, MCP_CONNECTION_SETTINGS_SCHEMA_VERSION, _) => {
            validate_schema(connection)
        }
        (MCP_CONNECTION_SETTINGS_APPLICATION_ID, 1, 1) => {
            let quick: String =
                connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
            let schema_sql = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                    params!["table", "mcp_connection_settings"],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let legacy_matches = quick == "ok"
                && schema_sql.as_deref().is_some_and(|sql| {
                    normalize_sql(sql) == normalize_sql(LEGACY_V1_SETTINGS_TABLE_SQL)
                });
            if !legacy_matches {
                return validate_schema(connection);
            }
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "ALTER TABLE mcp_connection_settings RENAME TO mcp_connection_settings_v1;
                 CREATE TABLE mcp_connection_settings (
                     settings_id INTEGER PRIMARY KEY NOT NULL CHECK(settings_id = 1),
                     public_origin TEXT CHECK(length(CAST(public_origin AS BLOB)) BETWEEN 1 AND 261),
                     local_port INTEGER NOT NULL CHECK(local_port BETWEEN 1 AND 65535),
                     created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                     updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
                     revision INTEGER NOT NULL CHECK(revision >= 1)
                 );
                 INSERT INTO mcp_connection_settings(
                     settings_id, public_origin, local_port, created_at_ms, updated_at_ms, revision
                 )
                 SELECT settings_id, public_origin, local_port, created_at_ms, updated_at_ms, revision
                 FROM mcp_connection_settings_v1;
                 DROP TABLE mcp_connection_settings_v1;",
            )?;
            transaction.pragma_update(
                None,
                "user_version",
                MCP_CONNECTION_SETTINGS_SCHEMA_VERSION,
            )?;
            transaction.commit()?;
            validate_schema(connection)
        }
        _ => Err(McpConnectionSettingsCatalogError::Ownership {
            application_id,
            user_version,
            object_count,
        }),
    }
}

fn create_schema(connection: &mut Connection) -> Result<(), McpConnectionSettingsCatalogError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(EXPECTED_SETTINGS_TABLE_SQL)?;
    transaction.pragma_update(
        None,
        "application_id",
        MCP_CONNECTION_SETTINGS_APPLICATION_ID,
    )?;
    transaction.pragma_update(None, "user_version", MCP_CONNECTION_SETTINGS_SCHEMA_VERSION)?;
    transaction.commit()?;
    validate_schema(connection)
}

fn validate_schema(connection: &Connection) -> Result<(), McpConnectionSettingsCatalogError> {
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(McpConnectionSettingsCatalogError::Integrity);
    }
    let schema_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params!["table", "mcp_connection_settings"],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(McpConnectionSettingsCatalogError::Schema(
            "mcp_connection_settings",
        ))?;
    if schema_sql.len() > MAX_SCHEMA_SQL_BYTES
        || normalize_sql(&schema_sql) != normalize_sql(EXPECTED_SETTINGS_TABLE_SQL)
    {
        return Err(McpConnectionSettingsCatalogError::Schema(
            "mcp_connection_settings",
        ));
    }

    let mut statement = connection.prepare("PRAGMA table_info(mcp_connection_settings)")?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
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
        return Err(McpConnectionSettingsCatalogError::Schema(
            "mcp_connection_settings columns",
        ));
    }

    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if foreign_key_violation {
        return Err(McpConnectionSettingsCatalogError::Integrity);
    }
    let object_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if object_count != 1 {
        return Err(McpConnectionSettingsCatalogError::Schema("object count"));
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" ,", ",")
}

fn insert_settings(
    transaction: &Transaction<'_>,
    record: &RegisteredMcpConnectionSettings,
) -> Result<(), McpConnectionSettingsCatalogError> {
    transaction.execute(
        "INSERT INTO mcp_connection_settings(
            settings_id, public_origin, local_port, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            SETTINGS_ID,
            record.public_origin(),
            i64::from(record.local_port().get()),
            record.created_at().get(),
            record.updated_at().get(),
            record.revision().get(),
        ],
    )?;
    Ok(())
}

fn load_settings(
    connection: &Connection,
) -> Result<Option<RegisteredMcpConnectionSettings>, McpConnectionSettingsCatalogError> {
    let raw = connection
        .query_row(
            "SELECT public_origin, local_port, created_at_ms, updated_at_ms, revision
             FROM mcp_connection_settings WHERE settings_id = ?1",
            params![SETTINGS_ID],
            |row| {
                Ok(RawSettings {
                    public_origin: row.get(0)?,
                    local_port: row.get(1)?,
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                    revision: row.get(4)?,
                })
            },
        )
        .optional()?;
    raw.map(decode_settings).transpose()
}

#[derive(Debug)]
struct RawSettings {
    public_origin: Option<String>,
    local_port: i64,
    created_at: i64,
    updated_at: i64,
    revision: i64,
}

fn decode_settings(
    raw: RawSettings,
) -> Result<RegisteredMcpConnectionSettings, McpConnectionSettingsCatalogError> {
    let local_port = u16::try_from(raw.local_port)
        .map_err(|_| McpConnectionSettingsCatalogError::StoredLocalPort(raw.local_port))?;
    let settings = McpConnectionSettings::new(
        raw.public_origin.map(McpPublicBase::parse).transpose()?,
        McpLocalPort::new(local_port)?,
    );
    RegisteredMcpConnectionSettings::from_parts(
        settings,
        TimestampMillis::new(raw.created_at)?,
        TimestampMillis::new(raw.updated_at)?,
        McpConnectionRevision::new(raw.revision)?,
    )
    .map_err(McpConnectionSettingsCatalogError::Transition)
}

#[derive(Debug, Error)]
pub enum McpConnectionSettingsCatalogError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("MCP connection settings catalog path is missing its parent: {0}")]
    MissingParent(PathBuf),
    #[error("MCP connection settings catalog path is unsafe: {0}")]
    InvalidPath(PathBuf),
    #[error("failed to inspect MCP connection settings catalog path {path}")]
    PathIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "MCP connection settings catalog ownership is invalid: application_id={application_id}, user_version={user_version}, object_count={object_count}"
    )]
    Ownership {
        application_id: i64,
        user_version: i64,
        object_count: i64,
    },
    #[error("MCP connection settings catalog schema is invalid: {0}")]
    Schema(&'static str),
    #[error("MCP connection settings catalog integrity check failed")]
    Integrity,
    #[error("MCP connection settings are already configured")]
    AlreadyConfigured,
    #[error("MCP connection settings are not configured")]
    NotConfigured,
    #[error("MCP connection settings revision conflict")]
    RevisionConflict,
    #[error("stored MCP connection local port is invalid: {0}")]
    StoredLocalPort(i64),
    #[error(transparent)]
    PublicBase(#[from] McpPublicBaseError),
    #[error(transparent)]
    LocalPort(#[from] McpLocalPortError),
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Revision(#[from] McpConnectionRevisionError),
    #[error(transparent)]
    Transition(#[from] McpConnectionSettingsTransitionError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use forge_domain::{McpConnectionSettings, McpLocalPort, McpPublicBase, TimestampMillis};
    use rusqlite::Connection;
    use uuid::Uuid;

    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "heterarchy-forge-{name}-{}-{}.sqlite3",
            std::process::id(),
            Uuid::now_v7()
        ))
    }

    fn settings(
        host: &str,
        port: u16,
    ) -> Result<McpConnectionSettings, Box<dyn std::error::Error>> {
        Ok(McpConnectionSettings::new(
            Some(McpPublicBase::parse(host)?),
            McpLocalPort::new(port)?,
        ))
    }

    #[test]
    fn create_reopen_and_update_are_durable() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("mcp-connection-reopen");
        let initial_settings = settings("skygptcodex.store", 7_979)?;
        let updated_settings = settings("mcp.skygptcodex.store", 8_000)?;
        let mut catalog = McpConnectionSettingsCatalog::open(&database)?;
        assert_eq!(catalog.get()?, None);
        let initial = catalog.create(initial_settings, TimestampMillis::new(10)?)?;
        assert_eq!(
            initial.mcp_endpoint(),
            Some("https://skygptcodex.store/mcp")
        );
        assert_eq!(catalog.get()?, Some(initial.clone()));
        drop(catalog);

        let mut reopened = McpConnectionSettingsCatalog::open(&database)?;
        assert_eq!(reopened.get()?, Some(initial.clone()));
        let updated = reopened.update(
            updated_settings,
            initial.revision(),
            TimestampMillis::new(11)?,
        )?;
        assert_eq!(updated.revision().get(), 2);
        assert_eq!(
            updated.mcp_endpoint(),
            Some("https://mcp.skygptcodex.store/mcp")
        );
        drop(reopened);

        let reopened = McpConnectionSettingsCatalog::open(&database)?;
        assert_eq!(reopened.get()?, Some(updated));
        drop(reopened);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn quick_tunnel_mode_is_durable_without_public_origin() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = path("mcp-connection-quick-tunnel");
        let mut catalog = McpConnectionSettingsCatalog::open(&database)?;
        let quick = McpConnectionSettings::new(None, McpLocalPort::new(7_979)?);
        let saved = catalog.create(quick, TimestampMillis::new(10)?)?;
        assert_eq!(saved.public_origin(), None);
        assert_eq!(saved.mcp_endpoint(), None);
        drop(catalog);

        let reopened = McpConnectionSettingsCatalog::open(&database)?;
        let loaded = reopened.get()?.ok_or("missing quick tunnel settings")?;
        assert_eq!(loaded.public_origin(), None);
        assert_eq!(loaded.local_port().get(), 7_979);
        drop(reopened);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn v1_catalog_migrates_without_changing_custom_origin() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = path("mcp-connection-v1-migration");
        let connection = Connection::open(&database)?;
        connection.execute_batch(LEGACY_V1_SETTINGS_TABLE_SQL)?;
        connection.pragma_update(
            None,
            "application_id",
            MCP_CONNECTION_SETTINGS_APPLICATION_ID,
        )?;
        connection.pragma_update(None, "user_version", 1_i64)?;
        connection.execute(
            "INSERT INTO mcp_connection_settings(
                settings_id, public_origin, local_port, created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                1_i64,
                "https://skygptcodex.store",
                7_979_i64,
                10_i64,
                10_i64,
                1_i64
            ],
        )?;
        drop(connection);

        let catalog = McpConnectionSettingsCatalog::open(&database)?;
        let loaded = catalog.get()?.ok_or("missing migrated settings")?;
        assert_eq!(loaded.public_origin(), Some("https://skygptcodex.store"));
        assert_eq!(loaded.mcp_endpoint(), Some("https://skygptcodex.store/mcp"));
        drop(catalog);
        let connection = Connection::open(&database)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, MCP_CONNECTION_SETTINGS_SCHEMA_VERSION);
        drop(connection);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn stale_revision_and_duplicate_create_fail_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = path("mcp-connection-cas");
        let mut catalog = McpConnectionSettingsCatalog::open(&database)?;
        let initial = catalog.create(
            settings("skygptcodex.store", 7_979)?,
            TimestampMillis::new(10)?,
        )?;
        assert!(matches!(
            catalog.create(settings("other.example", 8_000)?, TimestampMillis::new(11)?),
            Err(McpConnectionSettingsCatalogError::AlreadyConfigured)
        ));
        assert!(matches!(
            catalog.update(
                settings("other.example", 8_000)?,
                McpConnectionRevision::new(99)?,
                TimestampMillis::new(11)?,
            ),
            Err(McpConnectionSettingsCatalogError::Transition(
                McpConnectionSettingsTransitionError::RevisionConflict
            ))
        ));
        assert_eq!(catalog.get()?, Some(initial));
        drop(catalog);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn corrupt_schema_and_database_path_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("mcp-connection-corrupt");
        let catalog = McpConnectionSettingsCatalog::open(&database)?;
        drop(catalog);
        let connection = Connection::open(&database)?;
        connection.execute("DROP TABLE mcp_connection_settings", [])?;
        drop(connection);
        assert!(matches!(
            McpConnectionSettingsCatalog::open(&database),
            Err(McpConnectionSettingsCatalogError::Schema(
                "mcp_connection_settings"
            ))
        ));
        fs::remove_file(&database)?;

        let real = path("mcp-connection-real");
        let linked = path("mcp-connection-link");
        let catalog = McpConnectionSettingsCatalog::open(&real)?;
        drop(catalog);
        symlink(&real, &linked)?;
        assert!(matches!(
            McpConnectionSettingsCatalog::open(&linked),
            Err(McpConnectionSettingsCatalogError::InvalidPath(_))
        ));
        fs::remove_file(linked)?;
        fs::remove_file(real)?;
        Ok(())
    }
}
