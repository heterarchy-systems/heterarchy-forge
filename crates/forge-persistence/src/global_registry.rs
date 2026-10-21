use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_domain::{
    LocationId, LocationListLimit, LocationName, LocationRevision, LocationRoot, LocationState,
    RegisterLocation, RegisteredLocation, SetLocationState, TimestampMillis,
};
use forge_workspace::{LocationRepository, LocationRepositoryError};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, Rows, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

mod relocation;

const CURRENT_SCHEMA_VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x4846_4752;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 256;
const LOCATION_ID_BYTES: usize = 16;
const LOCATION_ID_BYTES_I64: i64 = 16;
const MAX_LOCATION_NAME_BYTES: usize = 512;
const MAX_LOCATION_ROOT_BYTES: usize = 4_096;
const LOCATION_LIST_QUERY: &str = "SELECT length(CAST(location_id AS BLOB)),
            length(CAST(display_name AS BLOB)),
            length(CAST(root_path AS BLOB)),
            location_id, display_name, root_path, state, created_at_ms, updated_at_ms, revision
                                    FROM locations
                                    ORDER BY display_name COLLATE NOCASE ASC, location_id ASC
                                    LIMIT ?1";
const LOCATION_BY_ID_QUERY: &str = "SELECT length(CAST(location_id AS BLOB)),
            length(CAST(display_name AS BLOB)),
            length(CAST(root_path AS BLOB)),
            location_id, display_name, root_path, state, created_at_ms, updated_at_ms, revision
                                    FROM locations
                                    WHERE location_id = ?1";
const REQUIRED_INDEX_NAME: &str = "locations_state_name_idx";
const EXPECTED_LOCATIONS_TABLE_V2_SQL: &str = "CREATE TABLE locations (location_id BLOB PRIMARY KEY NOT NULL CHECK(length(location_id) = 16), display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128), root_path BLOB NOT NULL UNIQUE, state INTEGER NOT NULL CHECK(state IN (0, 1)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1))";
const EXPECTED_LOCATIONS_INDEX_SQL: &str =
    "CREATE INDEX locations_state_name_idx ON locations(state, display_name COLLATE NOCASE)";

const EXPECTED_LOCATION_COLUMNS_V2: [(&str, &str, i64, i64); 7] = [
    ("location_id", "BLOB", 1, 1),
    ("display_name", "TEXT", 1, 0),
    ("root_path", "BLOB", 1, 0),
    ("state", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

/// Health projection for the global application registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryHealth {
    schema_version: i64,
    application_id: i64,
    journal_mode: String,
    foreign_keys_enabled: bool,
}

impl RegistryHealth {
    pub const fn schema_version(&self) -> i64 {
        self.schema_version
    }

    pub const fn application_id(&self) -> i64 {
        self.application_id
    }

    pub fn journal_mode(&self) -> &str {
        &self.journal_mode
    }

    pub const fn foreign_keys_enabled(&self) -> bool {
        self.foreign_keys_enabled
    }
}

/// SQLite-backed registry for app-global Location metadata.
pub struct GlobalRegistry {
    path: PathBuf,
    database_parent: PathBuf,
    database_parent_identity: DirectoryIdentity,
    database_identity: FileIdentity,
    wal_identity: Option<FileIdentity>,
    shm_identity: Option<FileIdentity>,
    connection: Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
        }
    }
}

impl fmt::Debug for GlobalRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GlobalRegistry")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl GlobalRegistry {
    /// Observed canonical database path, without exposing the `SQLite` handle.
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        Self::open_with_timeout(&path, BUSY_TIMEOUT)
    }

    /// Open an already-owned Registry without creating a parent directory or
    /// `SQLite` database. This is the non-creating startup path for standalone
    /// consumers that must fail closed when the Registry is absent or fresh.
    pub fn open_existing(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        Self::open_with_mode(&path, BUSY_TIMEOUT, RegistryOpenMode::ExistingOnly)
    }

    /// Inspect an already-created Registry without creating or mutating it.
    ///
    /// Doctor and other diagnostic callers must not turn an absent Registry
    /// into a durable application state. This path resolves the existing
    /// parent, opens `SQLite` through a read-only `file:` URI with `NOFOLLOW`,
    /// and never runs startup configuration or schema rewriting. The database and
    /// both `SQLite` sidecars are identity-checked before and after inspection
    /// so a replacement or unexpected side effect is reported rather than
    /// hidden.
    pub fn inspect_existing_read_only(
        requested_path: impl AsRef<Path>,
    ) -> Result<Option<RegistryHealth>, RegistryError> {
        let Some(database) = ReadOnlyRegistryDatabase::open(requested_path.as_ref())? else {
            return Ok(None);
        };
        database.inspect().map(Some)
    }

    fn open_with_timeout(
        requested_path: &Path,
        busy_timeout: Duration,
    ) -> Result<Self, RegistryError> {
        Self::open_with_mode(
            requested_path,
            busy_timeout,
            RegistryOpenMode::CreateIfMissing,
        )
    }

    fn open_with_mode(
        requested_path: &Path,
        busy_timeout: Duration,
        mode: RegistryOpenMode,
    ) -> Result<Self, RegistryError> {
        let parent = requested_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| RegistryError::MissingParent(requested_path.to_path_buf()))?;
        if mode == RegistryOpenMode::CreateIfMissing {
            fs::create_dir_all(parent).map_err(|source| RegistryError::CreateParent {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let canonical_parent =
            fs::canonicalize(parent).map_err(|source| RegistryError::DatabaseParentMetadata {
                path: parent.to_path_buf(),
                source,
            })?;
        let database_parent_identity = inspect_directory(&canonical_parent)?;
        let file_name = requested_path
            .file_name()
            .ok_or_else(|| RegistryError::MissingParent(requested_path.to_path_buf()))?;
        let path = canonical_parent.join(file_name);

        let database_before = inspect_regular_file(&path, true)?;
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        let wal_before = inspect_regular_file(&wal_path, true)?;
        let shm_before = inspect_regular_file(&shm_path, true)?;
        if database_before.is_none() {
            if wal_before.is_some() {
                return Err(RegistryError::DatabaseSidecarWithoutMain(wal_path));
            }
            if shm_before.is_some() {
                return Err(RegistryError::DatabaseSidecarWithoutMain(shm_path));
            }
            if mode == RegistryOpenMode::ExistingOnly {
                return Err(RegistryError::DatabasePathInvariant {
                    path: path.clone(),
                    detail: "existing Registry database is missing",
                });
            }
        }

        let flags = match mode {
            RegistryOpenMode::CreateIfMissing => {
                OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW
            }
            RegistryOpenMode::ExistingOnly => {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW
            }
        };
        let connection =
            Connection::open_with_flags(&path, flags).map_err(|source| RegistryError::Open {
                path: path.clone(),
                source,
            })?;
        let database_after = inspect_regular_file(&path, false)?.ok_or_else(|| {
            RegistryError::DatabasePathInvariant {
                path: path.clone(),
                detail: "SQLite open returned without a regular database file",
            }
        })?;
        if let Some(expected) = database_before
            && expected != database_after
        {
            return Err(RegistryError::DatabasePathChanged(path));
        }
        ensure_directory_identity(&canonical_parent, database_parent_identity)?;
        let mut registry = Self {
            path,
            database_parent: canonical_parent,
            database_parent_identity,
            database_identity: database_after,
            wal_identity: wal_before,
            shm_identity: shm_before,
            connection,
        };
        match inspect_database(&registry.connection)? {
            DatabaseOwnership::Fresh => {
                if mode == RegistryOpenMode::ExistingOnly {
                    return Err(RegistryError::UnownedDatabase);
                }
                configure_connection(&registry.connection, busy_timeout)?;
                migrate_fresh(&mut registry.connection)?;
                validate_schema_shape(&registry.connection)?;
            }
            DatabaseOwnership::Current => {
                validate_schema_shape(&registry.connection)?;
                configure_connection(&registry.connection, busy_timeout)?;
            }
        }

        registry.ensure_live_binding()?;
        registry.capture_sidecar_identities()?;
        registry.ensure_live_binding()?;
        Ok(registry)
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_live_binding(&self) -> Result<(), RegistryError> {
        ensure_live_paths(
            &self.database_parent,
            self.database_parent_identity,
            &self.path,
            self.database_identity,
            self.wal_identity,
            self.shm_identity,
        )
    }

    fn capture_sidecar_identities(&mut self) -> Result<(), RegistryError> {
        self.wal_identity = inspect_regular_file(&sidecar_path(&self.path, "-wal"), true)?;
        self.shm_identity = inspect_regular_file(&sidecar_path(&self.path, "-shm"), true)?;
        Ok(())
    }

    pub fn health(&self) -> Result<RegistryHealth, RegistryError> {
        self.ensure_live_binding()?;
        validate_owned_database(&self.connection)?;
        let schema_version = schema_version(&self.connection)?;
        let application_id = application_id(&self.connection)?;
        let policy = runtime_policy(&self.connection)?;
        validate_runtime_policy(&policy)?;
        let health = RegistryHealth {
            schema_version,
            application_id,
            journal_mode: policy.journal_mode,
            foreign_keys_enabled: policy.foreign_keys_enabled,
        };
        self.ensure_live_binding()?;
        Ok(health)
    }

    /// Compare-and-set the persisted root of one Location without filesystem effects.
    pub fn relocate_location_root(
        &mut self,
        id: LocationId,
        expected_revision: LocationRevision,
        expected_root: &LocationRoot,
        new_root: &LocationRoot,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredLocation, RegistryError> {
        relocation::relocate_location_root(
            self,
            id,
            expected_revision,
            expected_root,
            new_root,
            observed_at,
        )
    }

    fn register_location(
        &mut self,
        command: &RegisterLocation,
    ) -> Result<RegisteredLocation, RegistryError> {
        self.ensure_live_binding()?;
        let root_bytes = path_to_bytes_bounded(command.root().as_path())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id_bytes = command.id().into_uuid().into_bytes();

        let existing_id_length: Option<i64> = transaction
            .query_row(
                "SELECT length(CAST(location_id AS BLOB))
                 FROM locations
                 WHERE root_path = ?1",
                params![root_bytes.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_id_length) = existing_id_length {
            validate_location_id_length(existing_id_length)?;
            let existing_id: Vec<u8> = transaction.query_row(
                "SELECT location_id FROM locations WHERE root_path = ?1",
                params![root_bytes.as_slice()],
                |row| row.get(0),
            )?;
            return Err(RegistryError::LocationAlreadyRegistered {
                existing_id: decode_location_id(&existing_id)?,
            });
        }

        let id_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM locations WHERE location_id = ?1)",
            params![id_bytes.as_slice()],
            |row| row.get(0),
        )?;
        if id_exists {
            return Err(RegistryError::LocationIdConflict(command.id()));
        }

        transaction.execute(
            "INSERT INTO locations (
                location_id,
                display_name,
                root_path,
                state,
                created_at_ms,
                updated_at_ms,
                revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id_bytes.as_slice(),
                command.name().as_str(),
                root_bytes,
                encode_state(LocationState::Enabled),
                command.observed_at().get(),
                command.observed_at().get(),
                LocationRevision::INITIAL.get(),
            ],
        )?;
        ensure_live_paths(
            &self.database_parent,
            self.database_parent_identity,
            &self.path,
            self.database_identity,
            self.wal_identity,
            self.shm_identity,
        )?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;

        Ok(RegisteredLocation::from_parts_with_revision(
            command.id(),
            command.name().clone(),
            command.root().clone(),
            LocationState::Enabled,
            command.observed_at(),
            command.observed_at(),
            LocationRevision::INITIAL,
        ))
    }

    fn list_locations(
        &self,
        limit: LocationListLimit,
    ) -> Result<Vec<RegisteredLocation>, RegistryError> {
        self.ensure_live_binding()?;
        let mut statement = self.connection.prepare(LOCATION_LIST_QUERY)?;
        let mut rows = statement.query(params![i64::from(limit.get())])?;
        let mut locations = Vec::new();
        while let Some(row) = rows.next()? {
            locations.push(decode_location(decode_raw_row(row)?)?);
        }
        self.ensure_live_binding()?;
        Ok(locations)
    }

    fn get_location(&self, id: LocationId) -> Result<Option<RegisteredLocation>, RegistryError> {
        self.ensure_live_binding()?;
        let location = query_location_row(&self.connection, id)?
            .map(decode_location)
            .transpose()?;
        self.ensure_live_binding()?;
        Ok(location)
    }

    fn set_location_state(
        &mut self,
        command: &SetLocationState,
    ) -> Result<RegisteredLocation, RegistryError> {
        self.set_location_state_with_hook(command, |_| {})
    }

    fn set_location_state_with_hook<F>(
        &mut self,
        command: &SetLocationState,
        after_commit: F,
    ) -> Result<RegisteredLocation, RegistryError>
    where
        F: FnOnce(&mut Self),
    {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = command.id();
        let id_bytes = id.into_uuid().into_bytes();
        let current_raw =
            query_location_row(&transaction, id)?.ok_or(RegistryError::LocationNotFound(id))?;
        let current = decode_location(current_raw)?;
        if current.revision() != command.expected_revision() {
            return Err(RegistryError::RevisionConflict {
                id,
                expected: command.expected_revision(),
                actual: current.revision(),
            });
        }
        let next_revision =
            current
                .revision()
                .checked_next()
                .map_err(|_| RegistryError::RevisionOverflow {
                    id,
                    current: current.revision(),
                })?;
        let changed = transaction.execute(
            "UPDATE locations
             SET state = ?1, updated_at_ms = ?2, revision = ?3
             WHERE location_id = ?4 AND revision = ?5",
            params![
                encode_state(command.state()),
                command.observed_at().get(),
                next_revision.get(),
                id_bytes.as_slice(),
                command.expected_revision().get(),
            ],
        )?;
        if changed == 0 {
            return Err(RegistryError::RevisionConflict {
                id,
                expected: command.expected_revision(),
                actual: current.revision(),
            });
        }
        let updated_raw =
            query_location_row(&transaction, id)?.ok_or(RegistryError::LocationNotFound(id))?;
        let location = decode_location(updated_raw)?;
        ensure_live_paths(
            &self.database_parent,
            self.database_parent_identity,
            &self.path,
            self.database_identity,
            self.wal_identity,
            self.shm_identity,
        )?;
        transaction.commit().map_err(|source| {
            RegistryError::LocationStateCommittedUnconfirmed {
                id,
                expected_revision: command.expected_revision(),
                desired_state: command.state(),
                source: Box::new(source.into()),
            }
        })?;
        after_commit(self);
        self.confirm_location_state_commit(id, command.expected_revision(), command.state())?;
        Ok(location)
    }

    fn confirm_location_state_commit(
        &mut self,
        id: LocationId,
        expected_revision: LocationRevision,
        desired_state: LocationState,
    ) -> Result<(), RegistryError> {
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| RegistryError::LocationStateCommittedUnconfirmed {
                id,
                expected_revision,
                desired_state,
                source: Box::new(source),
            })
    }
}

struct ReadOnlyRegistryDatabase {
    observation: ReadOnlyRegistryObservation,
    connection: Connection,
}

struct ReadOnlyRegistryObservation {
    path: PathBuf,
    parent: PathBuf,
    parent_identity: DirectoryIdentity,
    database_identity: FileIdentity,
    wal_path: PathBuf,
    wal_identity: Option<FileIdentity>,
    shm_path: PathBuf,
    shm_identity: Option<FileIdentity>,
}

impl ReadOnlyRegistryObservation {
    fn from_path(requested_path: &Path) -> Result<Option<Self>, RegistryError> {
        let parent = requested_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| RegistryError::MissingParent(requested_path.to_path_buf()))?;
        let canonical_parent = match fs::canonicalize(parent) {
            Ok(parent) => parent,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(RegistryError::DatabaseParentMetadata {
                    path: parent.to_path_buf(),
                    source,
                });
            }
        };
        let parent_identity = inspect_directory(&canonical_parent)?;
        let file_name = requested_path
            .file_name()
            .ok_or_else(|| RegistryError::MissingParent(requested_path.to_path_buf()))?;
        let path = canonical_parent.join(file_name);
        let database_identity = inspect_regular_file(&path, true)?;
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        let wal_identity = inspect_regular_file(&wal_path, true)?;
        let shm_identity = inspect_regular_file(&shm_path, true)?;
        let Some(database_identity) = database_identity else {
            if wal_identity.is_some() {
                return Err(RegistryError::DatabaseSidecarWithoutMain(wal_path));
            }
            if shm_identity.is_some() {
                return Err(RegistryError::DatabaseSidecarWithoutMain(shm_path));
            }
            return Ok(None);
        };
        if wal_identity.is_none() != shm_identity.is_none() {
            return Err(RegistryError::DatabaseSidecarPairMismatch {
                wal: wal_path,
                shm: shm_path,
            });
        }
        if wal_identity.is_some() {
            return Err(RegistryError::ReadOnlyWalActive {
                wal: wal_path,
                shm: shm_path,
            });
        }
        Ok(Some(Self {
            path,
            parent: canonical_parent,
            parent_identity,
            database_identity,
            wal_path,
            wal_identity,
            shm_path,
            shm_identity,
        }))
    }

    fn uri(&self) -> String {
        sqlite_uri(&self.path, "immutable=1")
    }

    fn ensure_unchanged(&self) -> Result<(), RegistryError> {
        ensure_directory_identity(&self.parent, self.parent_identity)?;
        let database = inspect_regular_file(&self.path, false)?;
        if database != Some(self.database_identity) {
            return Err(RegistryError::DatabasePathChanged(self.path.clone()));
        }
        for (path, expected) in [
            (&self.wal_path, self.wal_identity),
            (&self.shm_path, self.shm_identity),
        ] {
            if inspect_regular_file(path, true)? != expected {
                return Err(RegistryError::DatabasePathChanged(path.clone()));
            }
        }
        Ok(())
    }
}

impl ReadOnlyRegistryDatabase {
    fn open(requested_path: &Path) -> Result<Option<Self>, RegistryError> {
        let Some(observation) = ReadOnlyRegistryObservation::from_path(requested_path)? else {
            return Ok(None);
        };
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI;
        let connection =
            Connection::open_with_flags(observation.uri(), flags).map_err(|source| {
                RegistryError::Open {
                    path: observation.path.clone(),
                    source,
                }
            })?;
        let database = Self {
            observation,
            connection,
        };
        database.observation.ensure_unchanged()?;
        database.connection.busy_timeout(BUSY_TIMEOUT)?;
        database
            .connection
            .pragma_update(None, "foreign_keys", true)?;
        database
            .connection
            .pragma_update(None, "query_only", true)?;
        database.observation.ensure_unchanged()?;
        Ok(Some(database))
    }

    fn inspect(&self) -> Result<RegistryHealth, RegistryError> {
        validate_owned_database(&self.connection)?;
        let policy = runtime_policy(&self.connection)?;
        validate_read_only_runtime_policy(&policy)?;
        validate_wal_header(&self.observation.path)?;
        validate_integrity(&self.connection)?;
        let health = RegistryHealth {
            schema_version: schema_version(&self.connection)?,
            application_id: application_id(&self.connection)?,
            journal_mode: "wal".to_owned(),
            foreign_keys_enabled: policy.foreign_keys_enabled,
        };
        self.observation.ensure_unchanged()?;
        Ok(health)
    }
}

impl LocationRepository for GlobalRegistry {
    fn register_location(
        &mut self,
        command: &RegisterLocation,
    ) -> Result<RegisteredLocation, LocationRepositoryError> {
        GlobalRegistry::register_location(self, command)
            .map_err(|error| map_repository_error("register_location", error))
    }

    fn list_locations(
        &self,
        limit: LocationListLimit,
    ) -> Result<Vec<RegisteredLocation>, LocationRepositoryError> {
        GlobalRegistry::list_locations(self, limit)
            .map_err(|error| map_repository_error("list_locations", error))
    }

    fn get_location(
        &self,
        id: LocationId,
    ) -> Result<Option<RegisteredLocation>, LocationRepositoryError> {
        GlobalRegistry::get_location(self, id)
            .map_err(|error| map_repository_error("get_location", error))
    }

    fn set_location_state(
        &mut self,
        command: &SetLocationState,
    ) -> Result<RegisteredLocation, LocationRepositoryError> {
        GlobalRegistry::set_location_state(self, command)
            .map_err(|error| map_repository_error("set_location_state", error))
    }
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut file_name = database
        .file_name()
        .map_or_else(std::ffi::OsString::new, std::ffi::OsStr::to_os_string);
    file_name.push(suffix);
    database.with_file_name(file_name)
}

fn inspect_regular_file(
    path: &Path,
    allow_missing: bool,
) -> Result<Option<FileIdentity>, RegistryError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if allow_missing && source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => {
            return Err(RegistryError::DatabasePathMetadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(RegistryError::DatabasePathSymlink(path.to_path_buf()));
    }
    if !metadata.is_file() {
        return Err(RegistryError::DatabasePathNotRegular(path.to_path_buf()));
    }
    let identity = FileIdentity::from_metadata(&metadata);
    if identity.links != 1 {
        return Err(RegistryError::DatabasePathHardlink {
            path: path.to_path_buf(),
            links: identity.links,
        });
    }
    Ok(Some(identity))
}

fn inspect_directory(path: &Path) -> Result<DirectoryIdentity, RegistryError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| RegistryError::DatabaseParentMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(RegistryError::DatabaseParentSymlink(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(RegistryError::DatabaseParentNotDirectory(
            path.to_path_buf(),
        ));
    }
    Ok(DirectoryIdentity::from_metadata(&metadata))
}

fn ensure_directory_identity(
    path: &Path,
    expected: DirectoryIdentity,
) -> Result<(), RegistryError> {
    if inspect_directory(path)? != expected {
        return Err(RegistryError::DatabaseParentChanged(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_live_paths(
    database_parent: &Path,
    database_parent_identity: DirectoryIdentity,
    database_path: &Path,
    database_identity: FileIdentity,
    wal_identity: Option<FileIdentity>,
    shm_identity: Option<FileIdentity>,
) -> Result<(), RegistryError> {
    ensure_directory_identity(database_parent, database_parent_identity)?;
    let observed_database = inspect_regular_file(database_path, false)?.ok_or_else(|| {
        RegistryError::DatabasePathInvariant {
            path: database_path.to_path_buf(),
            detail: "database file disappeared",
        }
    })?;
    if observed_database != database_identity {
        return Err(RegistryError::DatabasePathChanged(
            database_path.to_path_buf(),
        ));
    }
    for (path, expected) in [
        (sidecar_path(database_path, "-wal"), wal_identity),
        (sidecar_path(database_path, "-shm"), shm_identity),
    ] {
        let observed = inspect_regular_file(&path, true)?;
        if let (Some(expected), Some(observed)) = (expected, observed)
            && expected != observed
        {
            return Err(RegistryError::DatabasePathChanged(path));
        }
    }
    Ok(())
}

fn sqlite_uri(path: &Path, query: &str) -> String {
    let bytes = path.as_os_str().as_bytes();
    let mut uri = String::with_capacity(5 + bytes.len() * 3 + query.len() + 1);
    uri.push_str("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
            uri.push(*byte as char);
        } else {
            uri.push('%');
            uri.push(hex_digit(byte >> 4));
            uri.push(hex_digit(byte & 0x0f));
        }
    }
    uri.push('?');
    uri.push_str(query);
    uri
}

const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => unreachable!(),
    }
}

fn validate_integrity(connection: &Connection) -> Result<(), RegistryError> {
    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if !quick_check.eq_ignore_ascii_case("ok") {
        return Err(RegistryError::DamagedSchema {
            detail: "SQLite quick_check reported a violation".to_owned(),
        });
    }

    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        return Err(RegistryError::DamagedSchema {
            detail: "SQLite foreign_key_check reported a violation".to_owned(),
        });
    }
    Ok(())
}

fn validate_read_only_runtime_policy(policy: &RuntimePolicy) -> Result<(), RegistryError> {
    if !policy.foreign_keys_enabled {
        return Err(RegistryError::UnhealthyConfiguration {
            setting: "foreign_keys",
            actual: "OFF".to_owned(),
            expected: "ON",
        });
    }
    if policy.synchronous != 2 {
        return Err(RegistryError::UnhealthyConfiguration {
            setting: "synchronous",
            actual: synchronous_label(policy.synchronous).to_owned(),
            expected: "FULL",
        });
    }
    Ok(())
}

fn validate_wal_header(path: &Path) -> Result<(), RegistryError> {
    let mut file = fs::File::open(path).map_err(|source| RegistryError::DatabasePathMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    let mut header = [0_u8; 20];
    file.read_exact(&mut header)
        .map_err(|source| RegistryError::DatabasePathMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if header[18] != 2 || header[19] != 2 {
        return Err(RegistryError::UnhealthyConfiguration {
            setting: "journal_mode",
            actual: "database header is not WAL".to_owned(),
            expected: "WAL",
        });
    }
    Ok(())
}

fn map_repository_error(operation: &'static str, error: RegistryError) -> LocationRepositoryError {
    match error {
        RegistryError::LocationAlreadyRegistered { existing_id } => {
            LocationRepositoryError::AlreadyRegistered { existing_id }
        }
        RegistryError::LocationIdConflict(id) => LocationRepositoryError::IdentityConflict(id),
        RegistryError::LocationNotFound(id) => LocationRepositoryError::NotFound(id),
        RegistryError::RevisionConflict {
            id,
            expected,
            actual,
        } => LocationRepositoryError::RevisionConflict {
            id,
            expected,
            actual,
        },
        RegistryError::RevisionOverflow { id, current } => {
            LocationRepositoryError::RevisionOverflow { id, current }
        }
        RegistryError::LocationStateCommittedUnconfirmed {
            id,
            expected_revision,
            desired_state,
            source,
        } => LocationRepositoryError::CommittedUnconfirmed {
            id,
            expected_revision,
            desired_state,
            source: Box::new(*source),
        },
        error => LocationRepositoryError::Backend {
            operation,
            source: Box::new(error),
        },
    }
}

fn configure_connection(
    connection: &Connection,
    busy_timeout: Duration,
) -> Result<(), RegistryError> {
    connection.busy_timeout(busy_timeout)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryOpenMode {
    CreateIfMissing,
    ExistingOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseOwnership {
    Fresh,
    Current,
}

fn inspect_database(connection: &Connection) -> Result<DatabaseOwnership, RegistryError> {
    let app_id = application_id(connection)?;
    let version = schema_version(connection)?;
    if app_id != 0 && app_id != APPLICATION_ID {
        return Err(RegistryError::DatabaseOwnershipMismatch {
            actual: app_id,
            expected: APPLICATION_ID,
        });
    }
    if app_id == APPLICATION_ID && version != CURRENT_SCHEMA_VERSION {
        return Err(RegistryError::UnsupportedSchemaVersion {
            actual: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }

    let empty = database_is_empty(connection)?;
    if app_id == 0 {
        if version == 0 && empty {
            return Ok(DatabaseOwnership::Fresh);
        }
        return Err(RegistryError::UnownedDatabase);
    }

    if version == 0 && empty {
        return Ok(DatabaseOwnership::Fresh);
    }
    if empty {
        return Err(RegistryError::DamagedSchema {
            detail: "owned database has an empty schema".to_owned(),
        });
    }
    Ok(DatabaseOwnership::Current)
}

fn validate_owned_database(connection: &Connection) -> Result<(), RegistryError> {
    match inspect_database(connection)? {
        DatabaseOwnership::Current => validate_schema_shape(connection),
        DatabaseOwnership::Fresh => Err(RegistryError::DamagedSchema {
            detail: "registry schema is not initialized".to_owned(),
        }),
    }
}

fn database_is_empty(connection: &Connection) -> Result<bool, RegistryError> {
    let has_user_objects: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
        )",
        [],
        |row| row.get(0),
    )?;
    Ok(has_user_objects == 0)
}

fn validate_schema_shape(connection: &Connection) -> Result<(), RegistryError> {
    let table_sql = bounded_schema_sql(connection, "table", "locations", "locations table")?;
    let Some(table_sql) = table_sql else {
        return Err(RegistryError::DamagedSchema {
            detail: "required locations table is missing".to_owned(),
        });
    };
    if !schema_sql_matches(&table_sql, EXPECTED_LOCATIONS_TABLE_V2_SQL) {
        return Err(RegistryError::DamagedSchema {
            detail: "locations table SQL definition does not match the expected policy".to_owned(),
        });
    }

    let mut table_info = connection.prepare("PRAGMA table_info(locations)")?;
    let mut table_rows = table_info.query([])?;
    let columns = collect_bounded_metadata(&mut table_rows, "locations table", |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    let expected_columns = EXPECTED_LOCATION_COLUMNS_V2.as_slice();
    let columns_match = columns.len() == expected_columns.len()
        && columns.iter().zip(expected_columns).all(
            |(
                (name, data_type, not_null, primary_key),
                (expected_name, expected_type, expected_not_null, expected_primary_key),
            )| {
                name == expected_name
                    && data_type == expected_type
                    && not_null == expected_not_null
                    && primary_key == expected_primary_key
            },
        );
    if !columns_match {
        return Err(RegistryError::DamagedSchema {
            detail: "locations table columns do not match the expected shape".to_owned(),
        });
    }

    let mut index_list = connection.prepare("PRAGMA index_list(locations)")?;
    let mut index_rows = index_list.query([])?;
    let indexes = collect_bounded_metadata(&mut index_rows, "locations indexes", |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
    })?;
    let Some((_, unique)) = indexes.iter().find(|(name, _)| name == REQUIRED_INDEX_NAME) else {
        return Err(RegistryError::DamagedSchema {
            detail: "required Location ordering index is missing".to_owned(),
        });
    };
    let index_sql = bounded_schema_sql(connection, "index", REQUIRED_INDEX_NAME, "ordering index")?;
    let Some(index_sql) = index_sql else {
        return Err(RegistryError::DamagedSchema {
            detail: "required Location ordering index SQL is missing".to_owned(),
        });
    };
    if !schema_sql_matches(&index_sql, EXPECTED_LOCATIONS_INDEX_SQL) {
        return Err(RegistryError::DamagedSchema {
            detail: "Location ordering index SQL definition does not match the expected policy"
                .to_owned(),
        });
    }
    if *unique != 0 {
        return Err(RegistryError::DamagedSchema {
            detail: "required Location ordering index has unexpected uniqueness".to_owned(),
        });
    }

    let mut index_info = connection.prepare("PRAGMA index_info(locations_state_name_idx)")?;
    let mut index_rows = index_info.query([])?;
    let index_columns =
        collect_bounded_metadata(&mut index_rows, "ordering index columns", |row| {
            row.get::<_, String>(2)
        })?;
    if index_columns != ["state", "display_name"] {
        return Err(RegistryError::DamagedSchema {
            detail: "required Location ordering index columns are invalid".to_owned(),
        });
    }
    Ok(())
}

fn bounded_schema_sql(
    connection: &Connection,
    object_type: &str,
    object_name: &str,
    object: &'static str,
) -> Result<Option<String>, RegistryError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB))
             FROM sqlite_schema
             WHERE type = ?1 AND name = ?2",
            params![object_type, object_name],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Ok(None);
    };
    let actual = usize::try_from(length).unwrap_or(usize::MAX);
    if actual > MAX_SCHEMA_SQL_BYTES {
        return Err(RegistryError::SchemaSqlTooLarge {
            object,
            actual,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    connection
        .query_row(
            "SELECT sql
             FROM sqlite_schema
             WHERE type = ?1 AND name = ?2",
            params![object_type, object_name],
            |row| row.get(0),
        )
        .optional()
        .map_err(RegistryError::from)
}

fn collect_bounded_metadata<T, F>(
    rows: &mut Rows<'_>,
    object: &'static str,
    mut decode: F,
) -> Result<Vec<T>, RegistryError>
where
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        if values.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(RegistryError::SchemaMetadataTooLarge {
                object,
                maximum: MAX_SCHEMA_METADATA_ROWS,
            });
        }
        values.push(decode(row)?);
    }
    Ok(values)
}

fn schema_sql_matches(actual: &str, expected: &str) -> bool {
    let actual_bytes = actual
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase());
    let expected_bytes = expected
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase());
    actual_bytes.eq(expected_bytes)
}

#[derive(Debug)]
struct RuntimePolicy {
    journal_mode: String,
    foreign_keys_enabled: bool,
    synchronous: i64,
}

fn runtime_policy(connection: &Connection) -> Result<RuntimePolicy, RegistryError> {
    let journal_mode = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    Ok(RuntimePolicy {
        journal_mode,
        foreign_keys_enabled: foreign_keys == 1,
        synchronous,
    })
}

fn validate_runtime_policy(policy: &RuntimePolicy) -> Result<(), RegistryError> {
    if !policy.journal_mode.eq_ignore_ascii_case("wal") {
        return Err(RegistryError::UnhealthyConfiguration {
            setting: "journal_mode",
            actual: policy.journal_mode.clone(),
            expected: "WAL",
        });
    }
    if !policy.foreign_keys_enabled {
        return Err(RegistryError::UnhealthyConfiguration {
            setting: "foreign_keys",
            actual: "OFF".to_owned(),
            expected: "ON",
        });
    }
    if policy.synchronous != 2 {
        return Err(RegistryError::UnhealthyConfiguration {
            setting: "synchronous",
            actual: synchronous_label(policy.synchronous).to_owned(),
            expected: "FULL",
        });
    }
    Ok(())
}

const fn synchronous_label(value: i64) -> &'static str {
    match value {
        0 => "OFF",
        1 => "NORMAL",
        2 => "FULL",
        3 => "EXTRA",
        _ => "UNKNOWN",
    }
}

fn migrate_fresh(connection: &mut Connection) -> Result<(), RegistryError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.execute_batch(
        "CREATE TABLE locations (
            location_id BLOB PRIMARY KEY NOT NULL CHECK(length(location_id) = 16),
            display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
            root_path BLOB NOT NULL UNIQUE,
            state INTEGER NOT NULL CHECK(state IN (0, 1)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1)
         );
         CREATE INDEX locations_state_name_idx
             ON locations(state, display_name COLLATE NOCASE);",
    )?;
    transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn application_id(connection: &Connection) -> Result<i64, RegistryError> {
    connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(RegistryError::from)
}

fn schema_version(connection: &Connection) -> Result<i64, RegistryError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(RegistryError::from)
}

#[derive(Debug)]
struct RawLocationRow {
    id: Vec<u8>,
    name: String,
    root: Vec<u8>,
    state: i64,
    created_at: i64,
    updated_at: i64,
    revision: LocationRevision,
}

fn query_location_row(
    connection: &Connection,
    id: LocationId,
) -> Result<Option<RawLocationRow>, RegistryError> {
    let id_bytes = id.into_uuid().into_bytes();
    let mut statement = connection.prepare(LOCATION_BY_ID_QUERY)?;
    let mut rows = statement.query(params![id_bytes.as_slice()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let raw = decode_raw_row(row)?;
    drop(rows);
    drop(statement);
    Ok(Some(raw))
}

fn decode_raw_row(row: &Row<'_>) -> Result<RawLocationRow, RegistryError> {
    let id_length = row.get::<_, i64>(0).map_err(RegistryError::from)?;
    validate_location_id_length(id_length)?;
    let name_length = row.get::<_, i64>(1).map_err(RegistryError::from)?;
    validate_persisted_length("display_name", name_length, MAX_LOCATION_NAME_BYTES)?;
    let root_length = row.get::<_, i64>(2).map_err(RegistryError::from)?;
    validate_persisted_length("root_path", root_length, MAX_LOCATION_ROOT_BYTES)?;
    Ok(RawLocationRow {
        id: row.get(3).map_err(RegistryError::from)?,
        name: row.get(4).map_err(RegistryError::from)?,
        root: row.get(5).map_err(RegistryError::from)?,
        state: row.get(6).map_err(RegistryError::from)?,
        created_at: row.get(7).map_err(RegistryError::from)?,
        updated_at: row.get(8).map_err(RegistryError::from)?,
        revision: LocationRevision::new(row.get(9).map_err(RegistryError::from)?).map_err(
            |source| RegistryError::CorruptRecord {
                field: "revision",
                detail: source.to_string(),
            },
        )?,
    })
}

fn decode_location(raw: RawLocationRow) -> Result<RegisteredLocation, RegistryError> {
    let id = decode_location_id(&raw.id)?;
    let name = LocationName::new(raw.name).map_err(|source| RegistryError::CorruptRecord {
        field: "display_name",
        detail: source.to_string(),
    })?;
    let root = LocationRoot::from_canonical(path_from_bytes(raw.root)).map_err(|source| {
        RegistryError::CorruptRecord {
            field: "root_path",
            detail: source.to_string(),
        }
    })?;
    let state = decode_state(raw.state)?;
    let created_at =
        TimestampMillis::new(raw.created_at).map_err(|source| RegistryError::CorruptRecord {
            field: "created_at_ms",
            detail: source.to_string(),
        })?;
    let updated_at =
        TimestampMillis::new(raw.updated_at).map_err(|source| RegistryError::CorruptRecord {
            field: "updated_at_ms",
            detail: source.to_string(),
        })?;
    Ok(RegisteredLocation::from_parts_with_revision(
        id,
        name,
        root,
        state,
        created_at,
        updated_at,
        raw.revision,
    ))
}

fn decode_location_id(bytes: &[u8]) -> Result<LocationId, RegistryError> {
    Uuid::from_slice(bytes)
        .map(LocationId::from_uuid)
        .map_err(|source| RegistryError::CorruptRecord {
            field: "location_id",
            detail: source.to_string(),
        })
}

const fn encode_state(state: LocationState) -> i64 {
    match state {
        LocationState::Enabled => 1,
        LocationState::Disabled => 0,
    }
}

fn decode_state(value: i64) -> Result<LocationState, RegistryError> {
    match value {
        1 => Ok(LocationState::Enabled),
        0 => Ok(LocationState::Disabled),
        other => Err(RegistryError::CorruptRecord {
            field: "state",
            detail: format!("unknown state code {other}"),
        }),
    }
}

fn path_to_bytes_bounded(path: &Path) -> Result<Vec<u8>, RegistryError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_LOCATION_ROOT_BYTES {
        return Err(RegistryError::InputRootTooLarge {
            actual: bytes.len(),
            maximum: MAX_LOCATION_ROOT_BYTES,
        });
    }
    Ok(bytes.to_vec())
}

fn path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn validate_location_id_length(length: i64) -> Result<(), RegistryError> {
    if length == LOCATION_ID_BYTES_I64 {
        Ok(())
    } else {
        let actual = usize::try_from(length).unwrap_or(usize::MAX);
        Err(RegistryError::PersistedFieldLengthInvalid {
            field: "location_id",
            actual,
            expected: LOCATION_ID_BYTES,
        })
    }
}

fn validate_persisted_length(
    field: &'static str,
    length: i64,
    maximum: usize,
) -> Result<(), RegistryError> {
    let actual = usize::try_from(length).unwrap_or(usize::MAX);
    if actual > maximum {
        Err(RegistryError::PersistedFieldTooLarge {
            field,
            actual,
            maximum,
        })
    } else if length < 0 {
        Err(RegistryError::CorruptRecord {
            field,
            detail: "persisted length is negative".to_owned(),
        })
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry path has no parent directory: {0}")]
    MissingParent(PathBuf),
    #[error("failed to create registry parent directory {path}")]
    CreateParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open registry database {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("registry database has application id {actual:#x}; expected {expected:#x}")]
    DatabaseOwnershipMismatch { actual: i64, expected: i64 },
    #[error("registry database is non-empty but has no Forge ownership marker")]
    UnownedDatabase,
    #[error("registry schema is damaged: {detail}")]
    DamagedSchema { detail: String },
    #[error("registry {object} SQL is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("registry {object} metadata has more than {maximum} rows")]
    SchemaMetadataTooLarge {
        object: &'static str,
        maximum: usize,
    },
    #[error("persisted registry field {field} is {actual} bytes; maximum is {maximum}")]
    PersistedFieldTooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("persisted registry field {field} has {actual} bytes; expected exactly {expected}")]
    PersistedFieldLengthInvalid {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("input Location root is {actual} bytes; maximum is {maximum}")]
    InputRootTooLarge { actual: usize, maximum: usize },
    #[error("registry database path is a symbolic link: {0}")]
    DatabasePathSymlink(PathBuf),
    #[error("registry database path is not a regular file: {0}")]
    DatabasePathNotRegular(PathBuf),
    #[error("registry database path has {links} hard links: {path}")]
    DatabasePathHardlink { path: PathBuf, links: u64 },
    #[error("failed to inspect registry database path {path}: {source}")]
    DatabasePathMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("registry database path invariant failed for {path}: {detail}")]
    DatabasePathInvariant { path: PathBuf, detail: &'static str },
    #[error("registry database sidecar exists without its main database: {0}")]
    DatabaseSidecarWithoutMain(PathBuf),
    #[error("registry database WAL/SHM sidecars are incomplete: WAL {wal}, SHM {shm}")]
    DatabaseSidecarPairMismatch { wal: PathBuf, shm: PathBuf },
    #[error(
        "registry database has an active WAL; read-only inspection requires a quiescent database"
    )]
    ReadOnlyWalActive { wal: PathBuf, shm: PathBuf },
    #[error("registry database path identity changed: {0}")]
    DatabasePathChanged(PathBuf),
    #[error("registry database parent is a symbolic link: {0}")]
    DatabaseParentSymlink(PathBuf),
    #[error("registry database parent is not a directory: {0}")]
    DatabaseParentNotDirectory(PathBuf),
    #[error("failed to inspect registry database parent {path}: {source}")]
    DatabaseParentMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("registry database parent physical identity changed: {0}")]
    DatabaseParentChanged(PathBuf),
    #[error("SQLite runtime policy {setting} is {actual}; expected {expected}")]
    UnhealthyConfiguration {
        setting: &'static str,
        actual: String,
        expected: &'static str,
    },
    #[error("registry schema version {actual} is unsupported; supported version is {supported}")]
    UnsupportedSchemaVersion { actual: i64, supported: i64 },
    #[error("Location root is already registered as {existing_id}")]
    LocationAlreadyRegistered { existing_id: LocationId },
    #[error("Location identity already exists: {0}")]
    LocationIdConflict(LocationId),
    #[error("Location was not found: {0}")]
    LocationNotFound(LocationId),
    #[error("Location revision conflict for {id}: expected {expected}, actual {actual}")]
    RevisionConflict {
        id: LocationId,
        expected: LocationRevision,
        actual: LocationRevision,
    },
    #[error("Location revision overflow for {id} at {current}")]
    RevisionOverflow {
        id: LocationId,
        current: LocationRevision,
    },
    #[error("Location update time for {id} regressed: minimum {minimum:?}, observed {observed:?}")]
    LocationTimestampRegression {
        id: LocationId,
        minimum: TimestampMillis,
        observed: TimestampMillis,
    },
    #[error("Location root changed for {id}; expected root is stale")]
    LocationRootConflict { id: LocationId },
    #[error("Location root is unchanged for {id}")]
    LocationRootUnchanged { id: LocationId },
    #[error("Location state commit for {id} requires durable readback")]
    LocationStateCommittedUnconfirmed {
        id: LocationId,
        expected_revision: LocationRevision,
        desired_state: LocationState,
        #[source]
        source: Box<RegistryError>,
    },
    #[error("Location root commit for {id} requires durable readback")]
    LocationRootCommittedUnconfirmed {
        id: LocationId,
        expected_revision: LocationRevision,
        new_root: LocationRoot,
        #[source]
        source: Box<RegistryError>,
    },
    #[error("corrupt registry field {field}: {detail}")]
    CorruptRecord { field: &'static str, detail: String },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use forge_domain::{
        LocationId, LocationListLimit, LocationName, LocationRevision, LocationRoot, LocationState,
        RegisterLocation, SetLocationState, TimestampMillis,
    };
    use forge_workspace::{LocationRepositoryError, LocationService, LocationServiceError};
    use rusqlite::{Connection, TransactionBehavior, params};
    use uuid::Uuid;

    use super::{
        APPLICATION_ID, CURRENT_SCHEMA_VERSION, GlobalRegistry, RegistryError, sidecar_path,
    };

    #[test]
    fn fresh_registry_persists_locations_and_health_across_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("reopen")?;
        let workspace = root.join("workspace-a");
        fs::create_dir_all(&workspace)?;
        let database = root.join("registry.sqlite3");
        let location_id = location_id(1);
        let command = command(location_id, "Workspace A", workspace.clone(), 100)?;

        {
            let mut registry = GlobalRegistry::open(&database)?;
            let health = registry.health()?;
            assert_eq!(health.schema_version(), 2);
            assert_eq!(health.application_id(), APPLICATION_ID);
            assert_eq!(health.journal_mode().to_ascii_lowercase(), "wal");
            assert!(health.foreign_keys_enabled());

            let registered = registry.register_location(&command)?;
            assert_eq!(registered.id(), location_id);
            assert_eq!(registered.state(), LocationState::Enabled);
            let disabled = registry.set_location_state(&SetLocationState::new(
                location_id,
                registered.revision(),
                LocationState::Disabled,
                TimestampMillis::new(200)?,
            ))?;
            assert_eq!(disabled.state(), LocationState::Disabled);
            assert_eq!(disabled.updated_at().get(), 200);
        }

        let registry = GlobalRegistry::open(&database)?;
        let locations = registry.list_locations(LocationListLimit::DEFAULT)?;
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].id(), location_id);
        assert_eq!(locations[0].root().as_path(), workspace);
        assert_eq!(locations[0].state(), LocationState::Disabled);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn read_only_inspection_does_not_initialize_missing_or_mutate_existing_registry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("read-only-inspection")?;
        let missing_parent_path = root.join("missing-parent").join("registry.sqlite3");
        assert_eq!(
            GlobalRegistry::inspect_existing_read_only(&missing_parent_path)?,
            None
        );
        assert!(!missing_parent_path.exists());
        assert!(!missing_parent_path.parent().is_some_and(Path::exists));

        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let registry = GlobalRegistry::open(&database)?;
        drop(registry);
        assert!(!sidecar_path(&database, "-wal").exists());
        assert!(!sidecar_path(&database, "-shm").exists());
        let before_database = fs::read(&database)?;
        let before_database_metadata = fs::metadata(&database)?;
        let before_wal = sidecar_path(&database, "-wal");
        let before_shm = sidecar_path(&database, "-shm");
        let before_wal_bytes = before_wal
            .exists()
            .then(|| fs::read(&before_wal))
            .transpose()?;
        let before_shm_bytes = before_shm
            .exists()
            .then(|| fs::read(&before_shm))
            .transpose()?;

        let health = GlobalRegistry::inspect_existing_read_only(&database)?
            .ok_or("existing Registry was reported as missing")?;
        assert_eq!(health.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(health.application_id(), APPLICATION_ID);
        assert!(health.foreign_keys_enabled());
        assert!(health.journal_mode().eq_ignore_ascii_case("wal"));
        assert_eq!(fs::read(&database)?, before_database);
        assert_eq!(
            fs::metadata(&database)?.len(),
            before_database_metadata.len()
        );
        assert_eq!(
            before_wal_bytes,
            before_wal
                .exists()
                .then(|| fs::read(&before_wal))
                .transpose()?
        );
        assert_eq!(
            before_shm_bytes,
            before_shm
                .exists()
                .then(|| fs::read(&before_shm))
                .transpose()?
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn global_database_path_shape_is_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        for (index, case) in ["symlink", "directory", "hardlink"].into_iter().enumerate() {
            let root = unique_test_root(case)?;
            fs::create_dir_all(&root)?;
            let database = root.join("registry.sqlite3");
            let canonical_database = fs::canonicalize(&root)?.join("registry.sqlite3");
            let result = match case {
                "symlink" => {
                    let target = root.join("target.sqlite3");
                    fs::write(&target, b"not-a-database")?;
                    symlink(&target, &database)?;
                    GlobalRegistry::open(&database)
                }
                "directory" => {
                    fs::create_dir(&database)?;
                    GlobalRegistry::open(&database)
                }
                "hardlink" => {
                    let source = root.join(format!("source-{index}.sqlite3"));
                    fs::write(&source, b"not-a-database")?;
                    fs::hard_link(&source, &database)?;
                    GlobalRegistry::open(&database)
                }
                _ => unreachable!(),
            };
            match case {
                "symlink" => assert!(matches!(
                    result,
                    Err(RegistryError::DatabasePathSymlink(path)) if path == canonical_database
                )),
                "directory" => assert!(matches!(
                    result,
                    Err(RegistryError::DatabasePathNotRegular(path)) if path == canonical_database
                )),
                "hardlink" => assert!(matches!(
                    result,
                    Err(RegistryError::DatabasePathHardlink { path, links: 2 }) if path == canonical_database
                )),
                _ => unreachable!(),
            }
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn global_sidecar_shape_and_long_lived_replacement_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("global-sidecar")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let canonical_database = fs::canonicalize(&root)?.join("registry.sqlite3");
        let registry = GlobalRegistry::open(&database)?;
        drop(registry);
        let sidecar = super::sidecar_path(&database, "-wal");
        let canonical_sidecar = super::sidecar_path(&canonical_database, "-wal");
        if sidecar.exists() {
            fs::remove_file(&sidecar)?;
        }
        let target = root.join("target-wal");
        fs::write(&target, b"not-a-wal")?;
        symlink(&target, &sidecar)?;
        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::DatabasePathSymlink(path)) if path == canonical_sidecar
        ));
        fs::remove_file(&sidecar)?;

        let registry = GlobalRegistry::open(&database)?;
        let replacement = root.join("replacement.sqlite3");
        fs::copy(&database, &replacement)?;
        fs::rename(&replacement, &database)?;
        assert!(matches!(
            registry.health(),
            Err(RegistryError::DatabasePathChanged(path)) if path == canonical_database
        ));
        drop(registry);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn global_database_parent_symlink_to_original_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("global-parent-symlink")?;
        fs::create_dir_all(&root)?;
        let canonical_root = fs::canonicalize(&root)?;
        let database = canonical_root.join("registry.sqlite3");
        let registry = GlobalRegistry::open(&database)?;
        let moved = canonical_root.with_file_name(format!(
            "{}-original",
            canonical_root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("root")
        ));
        fs::rename(&canonical_root, &moved)?;
        symlink(&moved, &canonical_root)?;
        assert!(matches!(
            registry.health(),
            Err(RegistryError::DatabaseParentSymlink(path)) if path == canonical_root
        ));
        drop(registry);
        fs::remove_file(&canonical_root)?;
        fs::remove_dir_all(moved)?;
        Ok(())
    }

    #[test]
    fn global_database_parent_replacement_is_rejected_without_false_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("global-parent-replacement")?;
        fs::create_dir_all(&root)?;
        let canonical_root = fs::canonicalize(&root)?;
        let database = canonical_root.join("registry.sqlite3");
        let registry = GlobalRegistry::open(&database)?;
        let moved = canonical_root.with_file_name(format!(
            "{}-replaced",
            canonical_root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("root")
        ));
        fs::rename(&canonical_root, &moved)?;
        fs::create_dir(&canonical_root)?;
        assert!(matches!(
            registry.health(),
            Err(RegistryError::DatabaseParentChanged(path)) if path == canonical_root
        ));
        drop(registry);
        fs::remove_dir_all(&canonical_root)?;
        fs::remove_dir_all(moved)?;
        Ok(())
    }

    #[test]
    fn native_non_utf8_root_bytes_round_trip_without_loss() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("native-path")?;
        let invalid_name = std::ffi::OsString::from_vec(b"workspace-\xFF".to_vec());
        let workspace = root.join(invalid_name);
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let mut registry = GlobalRegistry::open(&database)?;
        registry.register_location(&command(
            location_id(2),
            "Native Path",
            workspace.clone(),
            10,
        )?)?;

        let locations = registry.list_locations(LocationListLimit::DEFAULT)?;
        let location = &locations[0];
        assert_eq!(
            location.root().as_path().as_os_str().as_bytes(),
            workspace.as_os_str().as_bytes()
        );
        drop(registry);
        fs::remove_file(database)?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[test]
    fn duplicate_root_id_and_not_found_errors_are_typed() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("duplicates")?;
        let first_root = root.join("first");
        let second_root = root.join("second");
        fs::create_dir_all(&first_root)?;
        fs::create_dir_all(&second_root)?;
        let database = root.join("registry.sqlite3");
        let mut registry = GlobalRegistry::open(&database)?;
        registry.register_location(&command(location_id(3), "First", first_root.clone(), 1)?)?;

        let duplicate_root =
            registry.register_location(&command(location_id(4), "Duplicate Root", first_root, 2)?);
        assert!(matches!(
            duplicate_root,
            Err(RegistryError::LocationAlreadyRegistered { existing_id })
                if existing_id == location_id(3)
        ));

        let duplicate_id =
            registry.register_location(&command(location_id(3), "Duplicate Id", second_root, 3)?);
        assert!(matches!(
            duplicate_id,
            Err(RegistryError::LocationIdConflict(id)) if id == location_id(3)
        ));
        assert!(matches!(
            registry.set_location_state(&SetLocationState::new(
                location_id(99),
                LocationRevision::INITIAL,
                LocationState::Disabled,
                TimestampMillis::new(4)?,
            )),
            Err(RegistryError::LocationNotFound(id)) if id == location_id(99)
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn list_order_is_deterministic_for_casefold_ties_and_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("ordering")?;
        let database = root.join("registry.sqlite3");
        let mut registry = GlobalRegistry::open(&database)?;
        for (id, name) in [(20, "Beta"), (3, "alpha"), (2, "Alpha")] {
            let workspace = root.join(format!("workspace-{id}"));
            fs::create_dir_all(&workspace)?;
            registry.register_location(&command(
                location_id(id),
                name,
                workspace,
                i64::try_from(id)?,
            )?)?;
        }

        let locations = registry.list_locations(LocationListLimit::new(2)?)?;
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].name().as_str(), "Alpha");
        assert_eq!(locations[0].id(), location_id(2));
        assert_eq!(locations[1].name().as_str(), "alpha");
        assert_eq!(locations[1].id(), location_id(3));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn unowned_nonempty_v0_database_is_not_mutated() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("unowned")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        {
            let connection = Connection::open(&database)?;
            connection.execute_batch("CREATE TABLE unrelated(value TEXT);")?;
        }

        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::UnownedDatabase)
        ));
        let connection = Connection::open(&database)?;
        let table_count: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'unrelated'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(table_count, 1);
        let app_id: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        assert_eq!(app_id, 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn open_existing_never_creates_missing_or_fresh_registry_and_opens_owned_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("open-existing")?;
        let missing_parent_database = root.join("missing-parent").join("registry.sqlite3");
        assert!(matches!(
            GlobalRegistry::open_existing(&missing_parent_database),
            Err(RegistryError::DatabaseParentMetadata { .. })
        ));
        assert!(!root.exists());

        fs::create_dir_all(&root)?;
        let missing_database = root.join("missing.sqlite3");
        assert!(matches!(
            GlobalRegistry::open_existing(&missing_database),
            Err(RegistryError::DatabasePathInvariant { detail, .. })
                if detail == "existing Registry database is missing"
        ));
        assert!(!missing_database.exists());

        let fresh_database = root.join("fresh.sqlite3");
        fs::write(&fresh_database, [])?;
        assert!(matches!(
            GlobalRegistry::open_existing(&fresh_database),
            Err(RegistryError::UnownedDatabase)
        ));
        assert_eq!(fs::metadata(&fresh_database)?.len(), 0);

        let owned_database = root.join("owned.sqlite3");
        let workspace = root.join("owned-workspace");
        fs::create_dir_all(&workspace)?;
        let mut created = GlobalRegistry::open(&owned_database)?;
        created.register_location(&command(location_id(901), "owned", workspace, 1)?)?;
        drop(created);

        let reopened = GlobalRegistry::open_existing(&owned_database)?;
        assert_eq!(
            reopened.list_locations(LocationListLimit::DEFAULT)?.len(),
            1
        );
        assert_eq!(reopened.health()?.schema_version(), CURRENT_SCHEMA_VERSION);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn mismatched_application_id_fails_without_mutating_database()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("wrong-app")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let wrong_id = 0x1234_5678_i64;
        {
            let connection = Connection::open(&database)?;
            connection.pragma_update(None, "application_id", wrong_id)?;
        }

        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::DatabaseOwnershipMismatch { actual, expected })
                if actual == wrong_id && expected == APPLICATION_ID
        ));
        let connection = Connection::open(&database)?;
        let app_id: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        assert_eq!(app_id, wrong_id);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn future_schema_version_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("future-schema")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        {
            let connection = Connection::open(&database)?;
            connection.pragma_update(None, "application_id", APPLICATION_ID)?;
            connection.pragma_update(None, "user_version", 99_i64)?;
        }
        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::UnsupportedSchemaVersion {
                actual: 99,
                supported: 2
            })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn damaged_schema_is_rejected_by_open_and_health() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("damaged-schema")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let registry = GlobalRegistry::open(&database)?;
        drop(registry);
        {
            let connection = Connection::open(&database)?;
            connection.execute("DROP INDEX locations_state_name_idx", [])?;
        }
        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::DamagedSchema { .. })
        ));
        assert!(matches!(
            GlobalRegistry::inspect_existing_read_only(&database),
            Err(RegistryError::DamagedSchema { .. })
        ));

        let health_root = unique_test_root("damaged-health")?;
        let healthy_registry = create_registry_with_location(&health_root, "health")?;
        {
            let connection = Connection::open(healthy_registry.path())?;
            connection.execute("DROP INDEX locations_state_name_idx", [])?;
        }
        assert!(matches!(
            healthy_registry.health(),
            Err(RegistryError::DamagedSchema { .. })
        ));
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(health_root)?;
        Ok(())
    }

    #[test]
    fn read_only_inspection_rejects_partial_sidecars_and_foreign_key_damage()
    -> Result<(), Box<dyn std::error::Error>> {
        let sidecar_root = unique_test_root("read-only-sidecar-pair")?;
        let sidecar_database = sidecar_root.join("registry.sqlite3");
        let registry = GlobalRegistry::open(&sidecar_database)?;
        drop(registry);
        let wal = sidecar_path(&sidecar_database, "-wal");
        fs::write(&wal, b"partial")?;
        assert!(matches!(
            GlobalRegistry::inspect_existing_read_only(&sidecar_database),
            Err(RegistryError::DatabaseSidecarPairMismatch { .. })
        ));
        fs::remove_file(&wal)?;
        fs::remove_dir_all(sidecar_root)?;

        let foreign_key_root = unique_test_root("read-only-foreign-key")?;
        let database = foreign_key_root.join("registry.sqlite3");
        let registry = GlobalRegistry::open(&database)?;
        drop(registry);
        let connection = Connection::open(&database)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = OFF;
             CREATE TABLE doctor_child(parent_id BLOB REFERENCES locations(location_id));
             INSERT INTO doctor_child(parent_id) VALUES (zeroblob(16));",
        )?;
        drop(connection);
        assert!(matches!(
            GlobalRegistry::inspect_existing_read_only(&database),
            Err(RegistryError::DamagedSchema { detail })
                if detail.contains("foreign_key_check")
        ));
        fs::remove_dir_all(foreign_key_root)?;
        Ok(())
    }

    #[test]
    fn read_only_inspection_rejects_an_active_wal_without_touching_sidecars()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("read-only-wal")?;
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        let database = root.join("registry.sqlite3");
        let mut registry = GlobalRegistry::open(&database)?;
        registry.register_location(&command(location_id(7), "WAL", workspace, 7)?)?;

        let wal = sidecar_path(&database, "-wal");
        let shm = sidecar_path(&database, "-shm");
        if !wal.is_file() || !shm.is_file() {
            return Err("write-capable Registry did not retain its WAL/SHM pair".into());
        }
        let before_database = fs::read(&database)?;
        let before_wal = fs::read(&wal)?;
        let before_shm = fs::read(&shm)?;
        let before_database_modified = fs::metadata(&database)?.modified()?;
        let before_wal_modified = fs::metadata(&wal)?.modified()?;
        let before_shm_modified = fs::metadata(&shm)?.modified()?;
        assert!(matches!(
            GlobalRegistry::inspect_existing_read_only(&database),
            Err(RegistryError::ReadOnlyWalActive { .. })
        ));
        assert_eq!(fs::read(&database)?, before_database);
        assert_eq!(fs::read(&wal)?, before_wal);
        assert_eq!(fs::read(&shm)?, before_shm);
        assert_eq!(
            fs::metadata(&database)?.modified()?,
            before_database_modified
        );
        assert_eq!(fs::metadata(&wal)?.modified()?, before_wal_modified);
        assert_eq!(fs::metadata(&shm)?.modified()?, before_shm_modified);

        drop(registry);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_without_check_constraints_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("missing-checks")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        create_owned_schema(
            &database,
            "CREATE TABLE locations (
                location_id BLOB PRIMARY KEY NOT NULL,
                display_name TEXT NOT NULL,
                root_path BLOB NOT NULL UNIQUE,
                state INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );",
        )?;

        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::DamagedSchema { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_without_unique_root_constraint_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("missing-root-unique")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        create_owned_schema(
            &database,
            "CREATE TABLE locations (
                location_id BLOB PRIMARY KEY NOT NULL CHECK(length(location_id) = 16),
                display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
                root_path BLOB NOT NULL,
                state INTEGER NOT NULL CHECK(state IN (0, 1)),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
             );",
        )?;

        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::DamagedSchema { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn health_rejects_mutated_sqlite_durability_invariants()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut healthy_results = Vec::new();
        for (label, pragma, value) in [
            ("journal-mode", "journal_mode", "DELETE"),
            ("foreign-keys", "foreign_keys", "OFF"),
            ("synchronous", "synchronous", "NORMAL"),
        ] {
            let root = unique_test_root(label)?;
            let registry = create_registry_with_location(&root, label)?;
            registry.connection.pragma_update(None, pragma, value)?;
            if !matches!(
                registry.health(),
                Err(RegistryError::UnhealthyConfiguration { setting, .. })
                    if setting == pragma
            ) {
                healthy_results.push(label);
            }
            fs::remove_dir_all(root)?;
        }
        assert!(
            healthy_results.is_empty(),
            "apparently healthy after mutation: {healthy_results:?}"
        );
        Ok(())
    }

    #[test]
    fn oversized_schema_sql_fails_before_sql_allocation() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("oversized-schema-sql")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let oversized_literal = "x".repeat(16_385);
        let table_sql = format!(
            "CREATE TABLE locations (
                location_id BLOB PRIMARY KEY NOT NULL CHECK(length(location_id) = 16),
                display_name TEXT NOT NULL CHECK(display_name != '{oversized_literal}'),
                root_path BLOB NOT NULL UNIQUE,
                state INTEGER NOT NULL CHECK(state IN (0, 1)),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
             );"
        );
        create_owned_schema(&database, &table_sql)?;

        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::SchemaSqlTooLarge { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn oversized_persisted_name_and_root_fail_before_value_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let name_root = unique_test_root("oversized-name")?;
        let name_registry = create_registry_with_location(&name_root, "name")?;
        let name_id = name_registry.list_locations(LocationListLimit::DEFAULT)?[0].id();
        let oversized_name = "n".repeat(513);
        corrupt_column(
            name_registry.path(),
            name_id,
            "display_name",
            &oversized_name,
        )?;
        assert!(matches!(
            name_registry.list_locations(LocationListLimit::DEFAULT),
            Err(RegistryError::PersistedFieldTooLarge {
                field: "display_name",
                ..
            })
        ));
        assert!(matches!(
            name_registry.get_location(name_id),
            Err(RegistryError::PersistedFieldTooLarge {
                field: "display_name",
                ..
            })
        ));

        let root_root = unique_test_root("oversized-root")?;
        let root_registry = create_registry_with_location(&root_root, "root")?;
        let root_id = root_registry.list_locations(LocationListLimit::DEFAULT)?[0].id();
        let oversized_root = vec![b'r'; 4_097];
        corrupt_blob_column(root_registry.path(), root_id, "root_path", &oversized_root)?;
        assert!(matches!(
            root_registry.list_locations(LocationListLimit::DEFAULT),
            Err(RegistryError::PersistedFieldTooLarge {
                field: "root_path",
                ..
            })
        ));
        assert!(matches!(
            root_registry.get_location(root_id),
            Err(RegistryError::PersistedFieldTooLarge {
                field: "root_path",
                ..
            })
        ));

        fs::remove_dir_all(name_root)?;
        fs::remove_dir_all(root_root)?;
        Ok(())
    }

    #[test]
    fn persisted_location_id_length_is_rejected_before_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("short-id")?;
        let registry = create_registry_with_location(&root, "short-id")?;
        let id = registry.list_locations(LocationListLimit::DEFAULT)?[0].id();
        let connection = Connection::open(registry.path())?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        let id_bytes = id.into_uuid().into_bytes();
        connection.execute(
            "UPDATE locations SET location_id = zeroblob(15) WHERE location_id = ?1",
            params![id_bytes.as_slice()],
        )?;
        assert!(matches!(
            registry.list_locations(LocationListLimit::DEFAULT),
            Err(RegistryError::PersistedFieldLengthInvalid {
                field: "location_id",
                actual: 15,
                expected: 16
            })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn oversized_input_root_is_rejected_before_insert() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("oversized-input-root")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let mut registry = GlobalRegistry::open(&database)?;
        let oversized_path = PathBuf::from(format!("/{}", "r".repeat(4_096)));
        let command = RegisterLocation::new(
            location_id(77),
            LocationName::new("Oversized Root")?,
            LocationRoot::from_canonical(oversized_path)?,
            TimestampMillis::new(1)?,
        );
        assert!(matches!(
            registry.register_location(&command),
            Err(RegistryError::InputRootTooLarge { .. })
        ));
        assert!(
            registry
                .list_locations(LocationListLimit::DEFAULT)?
                .is_empty()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn outdated_schema_is_rejected_without_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("v1-rejected")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        create_owned_schema_v1(&database)?;
        let before = fs::read(&database)?;

        assert!(matches!(
            GlobalRegistry::open(&database),
            Err(RegistryError::UnsupportedSchemaVersion {
                actual: 1,
                supported: 2
            })
        ));
        assert!(matches!(
            GlobalRegistry::inspect_existing_read_only(&database),
            Err(RegistryError::UnsupportedSchemaVersion {
                actual: 1,
                supported: 2
            })
        ));
        assert_eq!(fs::read(&database)?, before);
        let connection = Connection::open(&database)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn get_location_preserves_revision_and_native_root_and_maps_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("get-location")?;
        fs::create_dir_all(&root)?;
        let database = root.join("registry.sqlite3");
        let native_root = root.join(std::ffi::OsString::from_vec(b"native-get-\xFF".to_vec()));
        let id = location_id(82);
        let mut registry = GlobalRegistry::open(&database)?;
        registry.register_location(&command(id, "Get", native_root.clone(), 1)?)?;
        let location = registry
            .get_location(id)?
            .ok_or("registered Location was not returned")?;
        assert_eq!(location.id(), id);
        assert_eq!(location.revision(), LocationRevision::INITIAL);
        assert_eq!(
            location.root().as_path().as_os_str().as_bytes(),
            native_root.as_os_str().as_bytes()
        );
        let missing_id = location_id(83);
        assert!(registry.get_location(missing_id)?.is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn relocate_location_root_preserves_location_identity_and_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("location-relocation")?;
        let old_root = root.join("old-root");
        let new_root_path = root.join("new-root");
        fs::create_dir_all(&old_root)?;
        fs::create_dir_all(&new_root_path)?;
        let database = root.join("registry.sqlite3");
        let id = location_id(84);
        let mut registry = GlobalRegistry::open(&database)?;
        let registered = registry.register_location(&command(id, "Relocate", old_root, 10)?)?;
        let disabled = registry.set_location_state(&SetLocationState::new(
            id,
            registered.revision(),
            LocationState::Disabled,
            TimestampMillis::new(20)?,
        ))?;

        let new_root = LocationRoot::from_canonical(new_root_path.clone())?;
        let relocated = registry.relocate_location_root(
            id,
            disabled.revision(),
            disabled.root(),
            &new_root,
            TimestampMillis::new(30)?,
        )?;

        assert_eq!(relocated.id(), disabled.id());
        assert_eq!(relocated.name(), disabled.name());
        assert_eq!(relocated.root(), &new_root);
        assert_eq!(relocated.state(), LocationState::Disabled);
        assert_eq!(relocated.created_at().get(), 10);
        assert_eq!(relocated.updated_at().get(), 30);
        assert_eq!(relocated.revision().get(), disabled.revision().get() + 1);
        assert_eq!(registry.get_location(id)?, Some(relocated));

        drop(registry);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn relocate_location_root_rejects_timestamp_regression_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("location-relocation-time-regression")?;
        let old_root = root.join("old-root");
        let new_root_path = root.join("new-root");
        fs::create_dir_all(&old_root)?;
        fs::create_dir_all(&new_root_path)?;
        let database = root.join("registry.sqlite3");
        let id = location_id(89);
        let mut registry = GlobalRegistry::open(&database)?;
        let registered = registry.register_location(&command(id, "Time", old_root, 10)?)?;
        let current = registry.set_location_state(&SetLocationState::new(
            id,
            registered.revision(),
            LocationState::Disabled,
            TimestampMillis::new(20)?,
        ))?;
        let new_root = LocationRoot::from_canonical(new_root_path)?;

        assert!(matches!(
            registry.relocate_location_root(
                id,
                current.revision(),
                current.root(),
                &new_root,
                TimestampMillis::new(19)?,
            ),
            Err(RegistryError::LocationTimestampRegression {
                id: conflict_id,
                minimum,
                observed,
            }) if conflict_id == id && minimum.get() == 20 && observed.get() == 19
        ));
        assert_eq!(registry.get_location(id)?, Some(current));

        drop(registry);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn relocate_location_root_rejects_stale_revision_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("location-relocation-stale")?;
        let old_root_path = root.join("old-root");
        let first_new_root_path = root.join("first-new-root");
        let stale_new_root_path = root.join("stale-new-root");
        fs::create_dir_all(&old_root_path)?;
        fs::create_dir_all(&first_new_root_path)?;
        fs::create_dir_all(&stale_new_root_path)?;
        let database = root.join("registry.sqlite3");
        let id = location_id(85);
        let mut first = GlobalRegistry::open(&database)?;
        let original = first.register_location(&command(id, "Stale", old_root_path, 1)?)?;
        let mut second = GlobalRegistry::open(&database)?;
        let second_snapshot = second
            .get_location(id)?
            .ok_or("registered Location was not returned")?;
        let first_new_root = LocationRoot::from_canonical(first_new_root_path.clone())?;
        let relocated = first.relocate_location_root(
            id,
            original.revision(),
            original.root(),
            &first_new_root,
            TimestampMillis::new(2)?,
        )?;
        let stale_new_root = LocationRoot::from_canonical(stale_new_root_path)?;

        assert!(matches!(
            second.relocate_location_root(
                id,
                second_snapshot.revision(),
                second_snapshot.root(),
                &stale_new_root,
                TimestampMillis::new(3)?,
            ),
            Err(RegistryError::RevisionConflict {
                id: conflict_id,
                expected,
                actual,
            }) if conflict_id == id
                && expected == LocationRevision::INITIAL
                && actual == relocated.revision()
        ));
        assert_eq!(second.get_location(id)?, Some(relocated));

        drop(first);
        drop(second);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn relocate_location_root_rejects_wrong_old_root_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("location-relocation-wrong-old")?;
        let old_root_path = root.join("old-root");
        let wrong_old_root_path = root.join("wrong-old-root");
        let new_root_path = root.join("new-root");
        fs::create_dir_all(&old_root_path)?;
        fs::create_dir_all(&wrong_old_root_path)?;
        fs::create_dir_all(&new_root_path)?;
        let database = root.join("registry.sqlite3");
        let id = location_id(86);
        let mut registry = GlobalRegistry::open(&database)?;
        let original = registry.register_location(&command(id, "Wrong old", old_root_path, 1)?)?;
        let wrong_old_root = LocationRoot::from_canonical(wrong_old_root_path)?;
        let new_root = LocationRoot::from_canonical(new_root_path)?;

        assert!(matches!(
            registry.relocate_location_root(
                id,
                original.revision(),
                &wrong_old_root,
                &new_root,
                TimestampMillis::new(2)?,
            ),
            Err(RegistryError::LocationRootConflict { id: conflict_id })
                if conflict_id == id
        ));
        assert_eq!(registry.get_location(id)?, Some(original));

        drop(registry);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn relocate_location_root_rejects_duplicate_and_unchanged_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("location-relocation-root-conflicts")?;
        let first_root_path = root.join("first-root");
        let second_root_path = root.join("second-root");
        fs::create_dir_all(&first_root_path)?;
        fs::create_dir_all(&second_root_path)?;
        let database = root.join("registry.sqlite3");
        let first_id = location_id(87);
        let second_id = location_id(88);
        let mut registry = GlobalRegistry::open(&database)?;
        let first = registry.register_location(&command(
            first_id,
            "First root",
            first_root_path.clone(),
            1,
        )?)?;
        let second = registry.register_location(&command(
            second_id,
            "Second root",
            second_root_path.clone(),
            1,
        )?)?;
        let second_root = LocationRoot::from_canonical(second_root_path)?;

        assert!(matches!(
            registry.relocate_location_root(
                first_id,
                first.revision(),
                first.root(),
                &second_root,
                TimestampMillis::new(2)?,
            ),
            Err(RegistryError::LocationAlreadyRegistered { existing_id })
                if existing_id == second_id
        ));
        assert!(matches!(
            registry.relocate_location_root(
                first_id,
                first.revision(),
                first.root(),
                first.root(),
                TimestampMillis::new(2)?,
            ),
            Err(RegistryError::LocationRootUnchanged { id }) if id == first_id
        ));
        assert_eq!(registry.get_location(first_id)?, Some(first));
        assert_eq!(registry.get_location(second_id)?, Some(second));

        drop(registry);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn two_registry_handles_enforce_revision_cas_and_same_state_advances()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("revision-cas")?;
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        let database = root.join("registry.sqlite3");
        let mut first = GlobalRegistry::open(&database)?;
        let id = location_id(81);
        first.register_location(&command(id, "CAS", workspace, 1)?)?;
        let mut second = GlobalRegistry::open(&database)?;
        let first_snapshot = first.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        let second_snapshot = second.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        assert_eq!(first_snapshot.revision(), LocationRevision::INITIAL);
        assert_eq!(second_snapshot.revision(), LocationRevision::INITIAL);

        let updated = first.set_location_state(&SetLocationState::new(
            id,
            first_snapshot.revision(),
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ))?;
        assert_eq!(updated.revision().get(), 2);
        assert_eq!(updated.updated_at().get(), 2);

        let stale = second.set_location_state(&SetLocationState::new(
            id,
            second_snapshot.revision(),
            LocationState::Enabled,
            TimestampMillis::new(3)?,
        ));
        assert!(matches!(
            stale,
            Err(RegistryError::RevisionConflict {
                id: conflict_id,
                expected,
                actual
            }) if conflict_id == id
                && expected == LocationRevision::INITIAL
                && actual.get() == 2
        ));
        let unchanged = second.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        assert_eq!(unchanged.state(), LocationState::Disabled);
        assert_eq!(unchanged.updated_at().get(), 2);
        assert_eq!(unchanged.revision().get(), 2);

        let same_state = second.set_location_state(&SetLocationState::new(
            id,
            unchanged.revision(),
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ))?;
        assert_eq!(same_state.state(), LocationState::Disabled);
        assert_eq!(same_state.updated_at().get(), 2);
        assert_eq!(same_state.revision().get(), 3);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn location_state_sqlite_commit_failure_preserves_unknown_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("location-state-commit-unknown")?;
        let mut registry = create_registry_with_location(&root, "commit-unknown")?;
        registry.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TEMP TABLE location_commit_guard_parent (
                 id INTEGER PRIMARY KEY
             );
             CREATE TEMP TABLE location_commit_guard_child (
                 parent_id INTEGER REFERENCES location_commit_guard_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             );
             CREATE TEMP TRIGGER location_commit_guard
             AFTER UPDATE ON locations
             BEGIN
                 INSERT INTO location_commit_guard_child(parent_id) VALUES (99);
             END;",
        )?;
        let location = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        let outcome = registry.set_location_state(&SetLocationState::new(
            location.id(),
            location.revision(),
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ));
        match outcome {
            Err(RegistryError::LocationStateCommittedUnconfirmed {
                id,
                expected_revision,
                desired_state,
                source,
            }) => {
                assert_eq!(id, location.id());
                assert_eq!(expected_revision, location.revision());
                assert_eq!(desired_state, LocationState::Disabled);
                assert!(matches!(source.as_ref(), RegistryError::Sqlite(_)));
            }
            other => return Err(format!("unexpected Location state outcome: {other:?}").into()),
        }
        let unchanged = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        assert_eq!(unchanged.state(), LocationState::Enabled);
        assert_eq!(unchanged.revision(), location.revision());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn location_state_post_commit_binding_failure_requires_reopen_readback()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("location-state-post-commit-binding")?;
        let mut registry = create_registry_with_location(&root, "post-commit-binding")?;
        let location = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        let marker = location.root().as_path().join("preserved");
        fs::write(&marker, b"preserved")?;
        let original_identity = registry.database_identity;
        let outcome = registry.set_location_state_with_hook(
            &SetLocationState::new(
                location.id(),
                location.revision(),
                LocationState::Disabled,
                TimestampMillis::new(2)?,
            ),
            |registry| registry.database_identity.inode ^= 1,
        );
        assert!(matches!(
            outcome,
            Err(RegistryError::LocationStateCommittedUnconfirmed {
                id,
                expected_revision,
                desired_state: LocationState::Disabled,
                source,
            }) if id == location.id()
                && expected_revision == location.revision()
                && matches!(source.as_ref(), RegistryError::DatabasePathChanged(_))
        ));
        registry.database_identity = original_identity;
        let readback = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        assert_eq!(readback.id(), location.id());
        assert_eq!(readback.state(), LocationState::Disabled);
        assert_eq!(readback.revision().get(), location.revision().get() + 1);
        assert_eq!(readback.updated_at().get(), 2);
        assert_eq!(fs::read(&marker)?, b"preserved");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_revision_target_and_overflow_do_not_write() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("revision-errors")?;
        let mut registry = create_registry_with_location(&root, "revision-errors")?;
        let id = registry.list_locations(LocationListLimit::DEFAULT)?[0].id();
        let missing = registry.set_location_state(&SetLocationState::new(
            location_id(999),
            LocationRevision::INITIAL,
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ));
        assert!(matches!(
            missing,
            Err(RegistryError::LocationNotFound(id)) if id == location_id(999)
        ));

        let connection = Connection::open(registry.path())?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        let id_bytes = id.into_uuid().into_bytes();
        connection.execute(
            "UPDATE locations SET revision = ?1 WHERE location_id = ?2",
            params![i64::MAX, id_bytes.as_slice()],
        )?;
        let overflow = registry.set_location_state(&SetLocationState::new(
            id,
            LocationRevision::new(i64::MAX)?,
            LocationState::Disabled,
            TimestampMillis::new(3)?,
        ));
        assert!(matches!(
            overflow,
            Err(RegistryError::RevisionOverflow { .. })
        ));
        let unchanged = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        assert_eq!(unchanged.revision().get(), i64::MAX);
        assert_eq!(unchanged.state(), LocationState::Enabled);
        assert_eq!(unchanged.updated_at().get(), 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn corrupt_read_and_list_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("corrupt-list")?;
        let registry = create_registry_with_location(&root, "corrupt")?;
        let id = registry.list_locations(LocationListLimit::DEFAULT)?[0].id();
        corrupt_display_name(registry.path(), id)?;
        assert!(matches!(
            registry.list_locations(LocationListLimit::DEFAULT),
            Err(RegistryError::CorruptRecord {
                field: "display_name",
                ..
            })
        ));
        assert!(matches!(
            registry.get_location(id),
            Err(RegistryError::CorruptRecord {
                field: "display_name",
                ..
            })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn corrupt_state_rolls_back_state_and_timestamp_before_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("corrupt-rollback")?;
        let mut registry = create_registry_with_location(&root, "rollback")?;
        let id = registry.list_locations(LocationListLimit::DEFAULT)?[0].id();
        let current = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        corrupt_display_name(registry.path(), id)?;

        assert!(matches!(
            registry.set_location_state(&SetLocationState::new(
                id,
                current.revision(),
                LocationState::Disabled,
                TimestampMillis::new(999)?,
            )),
            Err(RegistryError::CorruptRecord {
                field: "display_name",
                ..
            })
        ));
        let connection = Connection::open(registry.path())?;
        let id_bytes = id.into_uuid().into_bytes();
        let (state, updated): (i64, i64) = connection.query_row(
            "SELECT state, updated_at_ms FROM locations WHERE location_id = ?1",
            params![id_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(state, 1);
        assert_eq!(updated, 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn busy_write_is_bounded_without_partial_row() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("busy")?;
        fs::create_dir_all(&root)?;
        let workspace = root.join("workspace-busy");
        fs::create_dir_all(&workspace)?;
        let database = root.join("busy.sqlite3");
        let mut registry = GlobalRegistry::open_with_timeout(&database, Duration::from_millis(20))?;
        registry.register_location(&command(location_id(1), "busy", workspace, 1)?)?;
        let id = registry.list_locations(LocationListLimit::DEFAULT)?[0].id();
        let mut blocker = Connection::open(registry.path())?;
        blocker.busy_timeout(Duration::from_millis(20))?;
        let transaction = blocker.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        let result = GlobalRegistry::set_location_state(
            &mut registry,
            &SetLocationState::new(
                id,
                current.revision(),
                LocationState::Disabled,
                TimestampMillis::new(500)?,
            ),
        );
        assert!(matches!(result, Err(RegistryError::Sqlite(_))));
        drop(transaction);

        let location = registry.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        assert_eq!(location.state(), LocationState::Enabled);
        assert_eq!(location.updated_at().get(), 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn location_service_uses_global_registry_and_maps_repository_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("service")?;
        let first = root.join("first");
        let second = root.join("second");
        fs::create_dir_all(&first)?;
        fs::create_dir_all(&second)?;
        let database = root.join("registry.sqlite3");
        let mut service = LocationService::new(GlobalRegistry::open(&database)?);
        let first_id = location_id(40);
        service.register_selected_path(first_id, "First", &first, TimestampMillis::new(1)?)?;

        let duplicate_root = service.register_selected_path(
            location_id(41),
            "Duplicate Root",
            &first,
            TimestampMillis::new(2)?,
        );
        assert!(matches!(
            duplicate_root,
            Err(LocationServiceError::Repository(
                LocationRepositoryError::AlreadyRegistered { existing_id }
            )) if existing_id == first_id
        ));

        let duplicate_id = service.register_selected_path(
            first_id,
            "Duplicate Id",
            &second,
            TimestampMillis::new(3)?,
        );
        assert!(matches!(
            duplicate_id,
            Err(LocationServiceError::Repository(
                LocationRepositoryError::IdentityConflict(id)
            )) if id == first_id
        ));

        assert!(matches!(
            service.set_location_state(&SetLocationState::new(
                location_id(99),
                LocationRevision::INITIAL,
                LocationState::Disabled,
                TimestampMillis::new(4)?,
            )),
            Err(LocationServiceError::Repository(
                LocationRepositoryError::NotFound(id)
            )) if id == location_id(99)
        ));
        let registered = service.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        let moved = root.join("first-moved");
        fs::rename(&first, &moved)?;
        let listed_after_root_move = service.list_locations(LocationListLimit::DEFAULT)?;
        assert_eq!(listed_after_root_move.len(), 1);
        assert_eq!(listed_after_root_move[0], registered);
        assert!(!listed_after_root_move[0].root().as_path().exists());
        assert!(moved.is_dir());
        fs::remove_dir_all(&moved)?;
        let listed_after_root_deletion = service.list_locations(LocationListLimit::DEFAULT)?;
        assert_eq!(listed_after_root_deletion.len(), 1);
        assert_eq!(listed_after_root_deletion[0], registered);
        assert!(!listed_after_root_deletion[0].root().as_path().exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn command(
        id: LocationId,
        name: &str,
        root: PathBuf,
        observed_at: i64,
    ) -> Result<RegisterLocation, Box<dyn std::error::Error>> {
        Ok(RegisterLocation::new(
            id,
            LocationName::new(name)?,
            LocationRoot::from_canonical(root)?,
            TimestampMillis::new(observed_at)?,
        ))
    }

    fn create_registry_with_location(
        root: &Path,
        label: &str,
    ) -> Result<GlobalRegistry, Box<dyn std::error::Error>> {
        fs::create_dir_all(root)?;
        let workspace = root.join(format!("workspace-{label}"));
        fs::create_dir_all(&workspace)?;
        let database = root.join(format!("{label}.sqlite3"));
        let mut registry = GlobalRegistry::open(&database)?;
        registry.register_location(&command(location_id(1), label, workspace, 1)?)?;
        Ok(registry)
    }

    fn corrupt_display_name(path: &Path, id: LocationId) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        let id_bytes = id.into_uuid().into_bytes();
        connection.execute(
            "UPDATE locations SET display_name = '' WHERE location_id = ?1",
            params![id_bytes.as_slice()],
        )?;
        Ok(())
    }

    fn corrupt_column(
        path: &Path,
        id: LocationId,
        column: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        let id_bytes = id.into_uuid().into_bytes();
        connection.execute(
            &format!("UPDATE locations SET {column} = ?1 WHERE location_id = ?2"),
            params![value, id_bytes.as_slice()],
        )?;
        Ok(())
    }

    fn corrupt_blob_column(
        path: &Path,
        id: LocationId,
        column: &str,
        value: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        let id_bytes = id.into_uuid().into_bytes();
        connection.execute(
            &format!("UPDATE locations SET {column} = ?1 WHERE location_id = ?2"),
            params![value, id_bytes.as_slice()],
        )?;
        Ok(())
    }

    fn create_owned_schema(
        database: &Path,
        table_sql: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open(database)?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.execute_batch(table_sql)?;
        connection.execute(
            "CREATE INDEX locations_state_name_idx
             ON locations(state, display_name COLLATE NOCASE)",
            [],
        )?;
        connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
        Ok(())
    }

    fn create_owned_schema_v1(database: &Path) -> Result<(), Box<dyn std::error::Error>> {
        create_owned_schema(
            database,
            "CREATE TABLE locations (
                location_id BLOB PRIMARY KEY NOT NULL CHECK(length(location_id) = 16),
                display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
                root_path BLOB NOT NULL UNIQUE,
                state INTEGER NOT NULL CHECK(state IN (0, 1)),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
             );",
        )?;
        let connection = Connection::open(database)?;
        connection.pragma_update(None, "user_version", 1_i64)?;
        Ok(())
    }

    fn location_id(value: u128) -> LocationId {
        LocationId::from_uuid(Uuid::from_u128(value))
    }

    fn unique_test_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("heterarchy-forge-{label}-{unique}")))
    }
}
