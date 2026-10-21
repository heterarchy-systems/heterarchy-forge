//! App-global `SQLite` authority for the saved general queue-capacity preference.
//!
//! This catalog stores only the user's bounded preset preference. Runtime queue
//! admission remains owned by the effective control worker and is never inferred
//! from this file when the file is missing, corrupt, or unreadable.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_domain::{TimestampMillis, TimestampMillisError};
use heterarchy_orchestration_policy::QueueCapacity;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use thiserror::Error;

pub(crate) const QUEUE_SETTINGS_APPLICATION_ID: i64 = 0x4846_5153;
pub(crate) const QUEUE_SETTINGS_SCHEMA_VERSION: i64 = 1;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SETTINGS_ID: i64 = 1;
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 256;
const EXPECTED_SETTINGS_TABLE_SQL: &str = "CREATE TABLE queue_settings (settings_id INTEGER PRIMARY KEY NOT NULL CHECK(settings_id = 1), capacity_slots INTEGER NOT NULL CHECK(capacity_slots IN (32, 64, 128, 256)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1))";
const EXPECTED_COLUMNS: [(&str, &str, i64, i64); 5] = [
    ("settings_id", "INTEGER", 1, 1),
    ("capacity_slots", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueueSettingsRevision(u64);

impl QueueSettingsRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: u64) -> Result<Self, QueueSettingsRevisionError> {
        if value == 0 {
            Err(QueueSettingsRevisionError::Zero)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, QueueSettingsRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(QueueSettingsRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum QueueSettingsRevisionError {
    #[error("queue settings revision must be nonzero")]
    Zero,
    #[error("queue settings revision overflowed at {current}")]
    Overflow { current: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSettings {
    capacity: QueueCapacity,
}

impl QueueSettings {
    pub const fn new(capacity: QueueCapacity) -> Self {
        Self { capacity }
    }

    pub const fn capacity(self) -> QueueCapacity {
        self.capacity
    }

    pub const fn slots(self) -> u16 {
        self.capacity.slots()
    }
}

impl Default for QueueSettings {
    fn default() -> Self {
        Self::new(QueueCapacity::default())
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredQueueSettings {
    settings: QueueSettings,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: QueueSettingsRevision,
}

impl RegisteredQueueSettings {
    pub const fn initial(settings: QueueSettings, observed_at: TimestampMillis) -> Self {
        Self {
            settings,
            created_at: observed_at,
            updated_at: observed_at,
            revision: QueueSettingsRevision::INITIAL,
        }
    }

    pub fn from_parts(
        settings: QueueSettings,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: QueueSettingsRevision,
    ) -> Result<Self, QueueSettingsTransitionError> {
        if updated_at.get() < created_at.get() {
            return Err(QueueSettingsTransitionError::TimestampOrder);
        }
        Ok(Self {
            settings,
            created_at,
            updated_at,
            revision,
        })
    }

    pub fn update(
        &self,
        settings: QueueSettings,
        expected_revision: QueueSettingsRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, QueueSettingsTransitionError> {
        if self.revision != expected_revision {
            return Err(QueueSettingsTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(QueueSettingsTransitionError::TimestampOrder);
        }
        Ok(Self {
            settings,
            updated_at: observed_at,
            revision: self
                .revision
                .checked_next()
                .map_err(QueueSettingsTransitionError::RevisionOverflow)?,
            ..*self
        })
    }

    pub const fn settings(self) -> QueueSettings {
        self.settings
    }

    pub const fn capacity(self) -> QueueCapacity {
        self.settings.capacity()
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(self) -> QueueSettingsRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum QueueSettingsTransitionError {
    #[error("queue settings revision conflict")]
    RevisionConflict,
    #[error("queue settings timestamp moved backwards")]
    TimestampOrder,
    #[error("queue settings revision overflowed")]
    RevisionOverflow(#[source] QueueSettingsRevisionError),
}

/// SQLite-backed app-global saved queue-capacity preference.
pub struct QueueSettingsCatalog {
    path: PathBuf,
    database_parent_identity: DirectoryIdentity,
    database_identity: FileIdentity,
    connection: Connection,
}

impl fmt::Debug for QueueSettingsCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueueSettingsCatalog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl QueueSettingsCatalog {
    /// Open or create the catalog schema. This does not create a preference row.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QueueSettingsCatalogError> {
        let path = canonical_catalog_path(path.as_ref())?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| QueueSettingsCatalogError::MissingParent(path.clone()))?;
        let database_parent_identity = inspect_directory(parent)?;
        let database_before = inspect_regular_file(&path, true)?;
        validate_catalog_path(&path)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let database_after = inspect_regular_file(&path, false)?
            .ok_or_else(|| QueueSettingsCatalogError::DatabasePathChanged(path.clone()))?;
        if database_before.is_some_and(|before| before != database_after) {
            return Err(QueueSettingsCatalogError::DatabasePathChanged(path));
        }
        ensure_directory_identity(parent, database_parent_identity)?;
        let mut connection = connection;
        initialize_or_validate(&mut connection)?;
        configure(&connection)?;
        ensure_directory_identity(parent, database_parent_identity)?;
        let database_identity = inspect_regular_file(&path, false)?
            .ok_or_else(|| QueueSettingsCatalogError::DatabasePathChanged(path.clone()))?;
        Ok(Self {
            path,
            database_parent_identity,
            database_identity,
            connection,
        })
    }

    /// Read startup preference without creating a database or changing files.
    /// Missing application preference is represented as `None`.
    pub fn inspect(
        path: impl AsRef<Path>,
    ) -> Result<Option<RegisteredQueueSettings>, QueueSettingsCatalogError> {
        let requested = path.as_ref();
        let metadata = match fs::symlink_metadata(requested) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(QueueSettingsCatalogError::PathIo {
                    path: requested.to_path_buf(),
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(QueueSettingsCatalogError::InvalidPath(
                requested.to_path_buf(),
            ));
        }
        let path = canonical_catalog_path(requested)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| QueueSettingsCatalogError::MissingParent(path.clone()))?;
        let database_parent_identity = inspect_directory(parent)?;
        validate_catalog_path(&path)?;
        let database_before = inspect_regular_file(&path, false)?
            .ok_or_else(|| QueueSettingsCatalogError::DatabasePathChanged(path.clone()))?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let database_after = inspect_regular_file(&path, false)?
            .ok_or_else(|| QueueSettingsCatalogError::DatabasePathChanged(path.clone()))?;
        if database_before != database_after {
            return Err(QueueSettingsCatalogError::DatabasePathChanged(path));
        }
        ensure_directory_identity(parent, database_parent_identity)?;
        configure_readonly(&connection)?;
        validate_ownership(&connection)?;
        validate_schema(&connection)?;
        let loaded = load_settings(&connection)?;
        ensure_directory_identity(parent, database_parent_identity)?;
        if inspect_regular_file(&path, false)? != Some(database_after) {
            return Err(QueueSettingsCatalogError::DatabasePathChanged(path));
        }
        Ok(loaded)
    }

    pub fn inspect_or_default(
        path: impl AsRef<Path>,
    ) -> Result<QueueSettings, QueueSettingsCatalogError> {
        Ok(Self::inspect(path)?
            .map_or_else(QueueSettings::default, RegisteredQueueSettings::settings))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self) -> Result<Option<RegisteredQueueSettings>, QueueSettingsCatalogError> {
        self.ensure_identity()?;
        let loaded = load_settings(&self.connection)?;
        self.ensure_identity()?;
        Ok(loaded)
    }

    pub fn create(
        &mut self,
        settings: QueueSettings,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredQueueSettings, QueueSettingsCatalogError> {
        self.ensure_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM queue_settings WHERE settings_id = ?1)",
            params![SETTINGS_ID],
            |row| row.get(0),
        )?;
        if exists {
            return Err(QueueSettingsCatalogError::AlreadyConfigured);
        }
        let record = RegisteredQueueSettings::initial(settings, observed_at);
        insert_settings(&transaction, &record)?;
        transaction.commit()?;
        self.ensure_identity()?;
        Ok(record)
    }

    pub fn update(
        &mut self,
        settings: QueueSettings,
        expected_revision: QueueSettingsRevision,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredQueueSettings, QueueSettingsCatalogError> {
        self.ensure_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            load_settings(&transaction)?.ok_or(QueueSettingsCatalogError::NotConfigured)?;
        let updated = current.update(settings, expected_revision, observed_at)?;
        let changed = transaction.execute(
            "UPDATE queue_settings
             SET capacity_slots = ?1, updated_at_ms = ?2, revision = ?3
             WHERE settings_id = ?4 AND revision = ?5",
            params![
                i64::from(updated.capacity().slots()),
                updated.updated_at().get(),
                i64::try_from(updated.revision().get())?,
                SETTINGS_ID,
                i64::try_from(expected_revision.get())?,
            ],
        )?;
        if changed != 1 {
            return Err(QueueSettingsCatalogError::RevisionConflict);
        }
        transaction.commit()?;
        self.ensure_identity()?;
        Ok(updated)
    }

    fn ensure_identity(&self) -> Result<(), QueueSettingsCatalogError> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| QueueSettingsCatalogError::MissingParent(self.path.clone()))?;
        ensure_directory_identity(parent, self.database_parent_identity)?;
        if inspect_regular_file(&self.path, false)? != Some(self.database_identity) {
            return Err(QueueSettingsCatalogError::DatabasePathChanged(
                self.path.clone(),
            ));
        }
        Ok(())
    }
}

fn canonical_catalog_path(requested_path: &Path) -> Result<PathBuf, QueueSettingsCatalogError> {
    let parent = requested_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| QueueSettingsCatalogError::MissingParent(requested_path.to_path_buf()))?;
    inspect_directory(parent)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| QueueSettingsCatalogError::PathIo {
            path: parent.to_path_buf(),
            source,
        })?;
    let file_name = requested_path
        .file_name()
        .ok_or_else(|| QueueSettingsCatalogError::MissingParent(requested_path.to_path_buf()))?;
    Ok(canonical_parent.join(file_name))
}

fn inspect_regular_file(
    path: &Path,
    allow_missing: bool,
) -> Result<Option<FileIdentity>, QueueSettingsCatalogError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if allow_missing && source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => {
            return Err(QueueSettingsCatalogError::PathIo {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(QueueSettingsCatalogError::InvalidPath(path.to_path_buf()));
    }
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(QueueSettingsCatalogError::InvalidPath(path.to_path_buf()));
    }
    Ok(Some(FileIdentity::from_metadata(&metadata)))
}

fn inspect_directory(path: &Path) -> Result<DirectoryIdentity, QueueSettingsCatalogError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| QueueSettingsCatalogError::PathIo {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(QueueSettingsCatalogError::InvalidPath(path.to_path_buf()));
    }
    Ok(DirectoryIdentity::from_metadata(&metadata))
}

fn ensure_directory_identity(
    path: &Path,
    expected: DirectoryIdentity,
) -> Result<(), QueueSettingsCatalogError> {
    if inspect_directory(path)? != expected {
        return Err(QueueSettingsCatalogError::DatabaseParentChanged(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn validate_catalog_path(path: &Path) -> Result<(), QueueSettingsCatalogError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| QueueSettingsCatalogError::MissingParent(path.to_path_buf()))?;
    inspect_directory(parent)?;
    let _ = inspect_regular_file(path, true)?;
    Ok(())
}

fn configure(connection: &Connection) -> Result<(), QueueSettingsCatalogError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn configure_readonly(connection: &Connection) -> Result<(), QueueSettingsCatalogError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

fn initialize_or_validate(connection: &mut Connection) -> Result<(), QueueSettingsCatalogError> {
    let ownership = read_ownership(connection)?;
    match ownership {
        (0, 0, 0) => create_schema(connection),
        (QUEUE_SETTINGS_APPLICATION_ID, QUEUE_SETTINGS_SCHEMA_VERSION, _) => {
            validate_schema(connection)
        }
        (application_id, user_version, object_count) => Err(QueueSettingsCatalogError::Ownership {
            application_id,
            user_version,
            object_count,
        }),
    }
}

fn read_ownership(connection: &Connection) -> Result<(i64, i64, i64), QueueSettingsCatalogError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let object_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    Ok((application_id, user_version, object_count))
}

fn validate_ownership(connection: &Connection) -> Result<(), QueueSettingsCatalogError> {
    let (application_id, user_version, object_count) = read_ownership(connection)?;
    if application_id != QUEUE_SETTINGS_APPLICATION_ID
        || user_version != QUEUE_SETTINGS_SCHEMA_VERSION
    {
        return Err(QueueSettingsCatalogError::Ownership {
            application_id,
            user_version,
            object_count,
        });
    }
    Ok(())
}

fn create_schema(connection: &mut Connection) -> Result<(), QueueSettingsCatalogError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(EXPECTED_SETTINGS_TABLE_SQL)?;
    transaction.pragma_update(None, "application_id", QUEUE_SETTINGS_APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", QUEUE_SETTINGS_SCHEMA_VERSION)?;
    transaction.commit()?;
    validate_schema(connection)
}

fn validate_schema(connection: &Connection) -> Result<(), QueueSettingsCatalogError> {
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(QueueSettingsCatalogError::Integrity);
    }
    validate_schema_sql(
        connection,
        "table",
        "queue_settings",
        EXPECTED_SETTINGS_TABLE_SQL,
    )?;
    let mut statement = connection.prepare("PRAGMA table_info(queue_settings)")?;
    let mut rows = statement.query([])?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next()? {
        if columns.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(QueueSettingsCatalogError::SchemaMetadataTooLarge {
                object: "queue_settings columns",
                maximum: MAX_SCHEMA_METADATA_ROWS,
            });
        }
        columns.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    if columns.len() != EXPECTED_COLUMNS.len()
        || !columns.iter().zip(EXPECTED_COLUMNS).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(QueueSettingsCatalogError::Schema("queue_settings columns"));
    }
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if foreign_key_violation {
        return Err(QueueSettingsCatalogError::Integrity);
    }
    let object_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if object_count != 1 {
        return Err(QueueSettingsCatalogError::Schema("object count"));
    }
    Ok(())
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    object_name: &'static str,
    expected: &str,
) -> Result<(), QueueSettingsCatalogError> {
    let mut statement = connection.prepare(
        "SELECT length(CAST(sql AS BLOB)), sql
         FROM sqlite_schema WHERE type = ?1 AND name = ?2",
    )?;
    let mut rows = statement.query(params![object_type, object_name])?;
    let Some(row) = rows.next()? else {
        return Err(QueueSettingsCatalogError::Schema(object_name));
    };
    let actual = usize::try_from(row.get::<_, i64>(0)?).unwrap_or(usize::MAX);
    if actual > MAX_SCHEMA_SQL_BYTES {
        return Err(QueueSettingsCatalogError::SchemaSqlTooLarge {
            object: object_name,
            actual,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let schema_sql = row.get::<_, String>(1)?;
    if normalize_sql(&schema_sql) != normalize_sql(expected) {
        return Err(QueueSettingsCatalogError::Schema(object_name));
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
    record: &RegisteredQueueSettings,
) -> Result<(), QueueSettingsCatalogError> {
    transaction.execute(
        "INSERT INTO queue_settings(
            settings_id, capacity_slots, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            SETTINGS_ID,
            i64::from(record.capacity().slots()),
            record.created_at().get(),
            record.updated_at().get(),
            i64::try_from(record.revision().get())?,
        ],
    )?;
    Ok(())
}

fn load_settings(
    connection: &Connection,
) -> Result<Option<RegisteredQueueSettings>, QueueSettingsCatalogError> {
    let raw = connection
        .query_row(
            "SELECT capacity_slots, created_at_ms, updated_at_ms, revision
             FROM queue_settings WHERE settings_id = ?1",
            params![SETTINGS_ID],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    raw.map(decode_settings).transpose()
}

fn decode_settings(
    (capacity_slots, created_at, updated_at, revision): (i64, i64, i64, i64),
) -> Result<RegisteredQueueSettings, QueueSettingsCatalogError> {
    let capacity = QueueCapacity::ALL
        .into_iter()
        .find(|capacity| i64::from(capacity.slots()) == capacity_slots)
        .ok_or(QueueSettingsCatalogError::StoredCapacity(capacity_slots))?;
    RegisteredQueueSettings::from_parts(
        QueueSettings::new(capacity),
        TimestampMillis::new(created_at)?,
        TimestampMillis::new(updated_at)?,
        QueueSettingsRevision::new(
            u64::try_from(revision)
                .map_err(|_| QueueSettingsCatalogError::StoredRevision(revision))?,
        )?,
    )
    .map_err(QueueSettingsCatalogError::Transition)
}

#[derive(Debug, Error)]
pub enum QueueSettingsCatalogError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("queue settings catalog path is missing its parent: {0}")]
    MissingParent(PathBuf),
    #[error("queue settings catalog path is unsafe: {0}")]
    InvalidPath(PathBuf),
    #[error("queue settings catalog database path identity changed: {0}")]
    DatabasePathChanged(PathBuf),
    #[error("queue settings catalog parent identity changed: {0}")]
    DatabaseParentChanged(PathBuf),
    #[error("failed to inspect queue settings catalog path {path}")]
    PathIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "queue settings catalog ownership is invalid: application_id={application_id}, user_version={user_version}, object_count={object_count}"
    )]
    Ownership {
        application_id: i64,
        user_version: i64,
        object_count: i64,
    },
    #[error("queue settings catalog schema is invalid: {0}")]
    Schema(&'static str),
    #[error(
        "queue settings catalog schema object {object} is {actual} bytes; maximum is {maximum}"
    )]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error(
        "queue settings catalog schema metadata object {object} exceeded the maximum of {maximum} rows"
    )]
    SchemaMetadataTooLarge {
        object: &'static str,
        maximum: usize,
    },
    #[error("queue settings catalog integrity check failed")]
    Integrity,
    #[error("queue settings are already configured")]
    AlreadyConfigured,
    #[error("queue settings are not configured")]
    NotConfigured,
    #[error("queue settings revision conflict")]
    RevisionConflict,
    #[error("stored queue capacity is invalid: {0}")]
    StoredCapacity(i64),
    #[error("stored queue settings revision is invalid: {0}")]
    StoredRevision(i64),
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Revision(#[from] QueueSettingsRevisionError),
    #[error(transparent)]
    Transition(#[from] QueueSettingsTransitionError),
    #[error(transparent)]
    IntConversion(#[from] std::num::TryFromIntError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use uuid::Uuid;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "heterarchy-forge-{name}-{}-{}.sqlite3",
            std::process::id(),
            Uuid::now_v7()
        ))
    }

    #[test]
    fn create_reopen_update_and_inspect_are_durable() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("queue-settings-reopen");
        assert_eq!(QueueSettingsCatalog::inspect(&database)?, None);
        assert_eq!(
            QueueSettingsCatalog::inspect_or_default(&database)?,
            QueueSettings::default()
        );
        let mut catalog = QueueSettingsCatalog::open(&database)?;
        let initial = catalog.create(
            QueueSettings::new(QueueCapacity::C64),
            TimestampMillis::new(10)?,
        )?;
        assert_eq!(initial.capacity(), QueueCapacity::C64);
        drop(catalog);
        let mut reopened = QueueSettingsCatalog::open(&database)?;
        let updated = reopened.update(
            QueueSettings::new(QueueCapacity::C256),
            initial.revision(),
            TimestampMillis::new(11)?,
        )?;
        assert_eq!(updated.capacity(), QueueCapacity::C256);
        assert_eq!(QueueSettingsCatalog::inspect(&database)?, Some(updated));
        drop(reopened);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn stale_cas_and_duplicate_create_do_not_mutate() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("queue-settings-cas");
        let mut catalog = QueueSettingsCatalog::open(&database)?;
        let initial = catalog.create(QueueSettings::default(), TimestampMillis::new(1)?)?;
        assert!(matches!(
            catalog.create(
                QueueSettings::new(QueueCapacity::C32),
                TimestampMillis::new(2)?
            ),
            Err(QueueSettingsCatalogError::AlreadyConfigured)
        ));
        assert!(matches!(
            catalog.update(
                QueueSettings::new(QueueCapacity::C32),
                QueueSettingsRevision::new(99)?,
                TimestampMillis::new(2)?,
            ),
            Err(QueueSettingsCatalogError::Transition(
                QueueSettingsTransitionError::RevisionConflict
            ))
        ));
        assert_eq!(catalog.get()?, Some(initial));
        drop(catalog);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn corrupt_schema_and_bad_capacity_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("queue-settings-corrupt");
        let mut catalog = QueueSettingsCatalog::open(&database)?;
        let _initial = catalog.create(QueueSettings::default(), TimestampMillis::new(1)?)?;
        drop(catalog);
        let connection = Connection::open(&database)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute("UPDATE queue_settings SET capacity_slots = 7", [])?;
        drop(connection);
        assert!(matches!(
            QueueSettingsCatalog::inspect(&database),
            Err(QueueSettingsCatalogError::StoredCapacity(7))
        ));
        fs::remove_file(database)?;

        let malformed_database = path("queue-settings-malformed-schema");
        let connection = Connection::open(&malformed_database)?;
        connection.execute_batch(
            "CREATE TABLE queue_settings (
                settings_id INTEGER PRIMARY KEY NOT NULL CHECK(settings_id = 1),
                capacity_slots INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                revision INTEGER NOT NULL
            );",
        )?;
        connection.pragma_update(None, "application_id", QUEUE_SETTINGS_APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", QUEUE_SETTINGS_SCHEMA_VERSION)?;
        drop(connection);
        assert!(matches!(
            QueueSettingsCatalog::inspect(&malformed_database),
            Err(QueueSettingsCatalogError::Schema("queue_settings"))
        ));
        fs::remove_file(malformed_database)?;

        let oversized_database = path("queue-settings-oversized-schema");
        let connection = Connection::open(&oversized_database)?;
        let filler = "q".repeat(MAX_SCHEMA_SQL_BYTES);
        let sql = format!(
            "CREATE TABLE queue_settings (\
                settings_id INTEGER PRIMARY KEY NOT NULL CHECK(settings_id = 1),\
                capacity_slots INTEGER NOT NULL CHECK(capacity_slots IN (32, 64, 128, 256)),\
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),\
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),\
                revision INTEGER NOT NULL CHECK(revision >= 1),\
                CHECK(length('{filler}') >= 0)\
            )"
        );
        connection.execute_batch(&sql)?;
        connection.pragma_update(None, "application_id", QUEUE_SETTINGS_APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", QUEUE_SETTINGS_SCHEMA_VERSION)?;
        drop(connection);
        assert!(matches!(
            QueueSettingsCatalog::inspect(&oversized_database),
            Err(QueueSettingsCatalogError::SchemaSqlTooLarge {
                object: "queue_settings",
                actual,
                maximum: max_bytes,
            }) if actual > max_bytes
        ));
        fs::remove_file(oversized_database)?;
        Ok(())
    }
}
