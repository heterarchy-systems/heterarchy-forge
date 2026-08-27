//! App-global durable registry of owner-registered Harness Bundles.
//!
//! This database is deliberately separate from the Location Global Registry
//! and from Workspace-local `SQLite`. It stores only bounded Bundle metadata and
//! the canonical local source root; bundle file bodies stay in owner-managed
//! local storage and are re-inspected before apply/update operations.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_domain::{
    HarnessBundleDescriptor, HarnessBundleError, HarnessBundleId, HarnessContentHash, HarnessName,
    HarnessNameError, HarnessRevision, HarnessRevisionError, HarnessVersion, HarnessVersionError,
    RegisteredHarnessBundle, RegisteredHarnessBundleError, TimestampMillis, TimestampMillisError,
};
use forge_workspace::InspectedHarnessBundle;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub const HARNESS_CATALOG_APPLICATION_ID: i64 = 0x4846_4843;
pub const HARNESS_CATALOG_SCHEMA_VERSION: i64 = 1;
pub const MAX_HARNESS_CATALOG_RESULTS: usize = 256;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const ID_BYTES: usize = 16;
const HASH_BYTES: usize = HarnessContentHash::BYTE_LEN;
const MAX_SOURCE_ROOT_BYTES: usize = 4_096;
const REQUIRED_INDEX_NAME: &str = "harness_bundles_name_idx";

const EXPECTED_BUNDLES_TABLE_SQL: &str = "CREATE TABLE harness_bundles (bundle_id BLOB PRIMARY KEY NOT NULL CHECK(length(bundle_id) = 16), display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128), version TEXT NOT NULL CHECK(length(CAST(version AS BLOB)) BETWEEN 1 AND 64), source_root BLOB NOT NULL UNIQUE CHECK(length(source_root) BETWEEN 1 AND 4096), content_hash BLOB NOT NULL CHECK(length(content_hash) = 32), managed_file_count INTEGER NOT NULL CHECK(managed_file_count BETWEEN 1 AND 256), skill_count INTEGER NOT NULL CHECK(skill_count BETWEEN 0 AND 64), verifier_count INTEGER NOT NULL CHECK(verifier_count BETWEEN 0 AND 32), registered_at_ms INTEGER NOT NULL CHECK(registered_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= registered_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1))";
const EXPECTED_BUNDLES_INDEX_SQL: &str = "CREATE INDEX harness_bundles_name_idx ON harness_bundles(display_name COLLATE NOCASE, bundle_id)";
const EXPECTED_COLUMNS: [(&str, &str, i64, i64); 11] = [
    ("bundle_id", "BLOB", 1, 1),
    ("display_name", "TEXT", 1, 0),
    ("version", "TEXT", 1, 0),
    ("source_root", "BLOB", 1, 0),
    ("content_hash", "BLOB", 1, 0),
    ("managed_file_count", "INTEGER", 1, 0),
    ("skill_count", "INTEGER", 1, 0),
    ("verifier_count", "INTEGER", 1, 0),
    ("registered_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessCatalogEntry {
    bundle: RegisteredHarnessBundle,
    source_root: PathBuf,
}

impl HarnessCatalogEntry {
    pub const fn bundle(&self) -> &RegisteredHarnessBundle {
        &self.bundle
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
}

pub struct HarnessCatalog {
    path: PathBuf,
    database_parent: PathBuf,
    database_parent_identity: DirectoryIdentity,
    database_identity: FileIdentity,
    wal_identity: Option<FileIdentity>,
    shm_identity: Option<FileIdentity>,
    connection: Connection,
}

impl fmt::Debug for HarnessCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessCatalog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
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

impl HarnessCatalog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, HarnessCatalogError> {
        let path = path.into();
        Self::open_with_timeout(&path, BUSY_TIMEOUT)
    }

    fn open_with_timeout(path: &Path, busy_timeout: Duration) -> Result<Self, HarnessCatalogError> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| HarnessCatalogError::MissingParent(path.to_path_buf()))?;
        fs::create_dir_all(parent).map_err(|source| HarnessCatalogError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;
        let database_parent =
            fs::canonicalize(parent).map_err(|source| HarnessCatalogError::ParentMetadata {
                path: parent.to_path_buf(),
                source,
            })?;
        let database_parent_identity = inspect_directory(&database_parent)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| HarnessCatalogError::MissingParent(path.to_path_buf()))?;
        let path = database_parent.join(file_name);
        let before = inspect_regular_file(&path, true)?;
        validate_sidecars(&path, before.is_some())?;
        let flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags).map_err(|source| {
            HarnessCatalogError::Open {
                path: path.clone(),
                source,
            }
        })?;
        let after = inspect_regular_file(&path, false)?.ok_or_else(|| {
            HarnessCatalogError::DatabasePathInvariant {
                path: path.clone(),
                detail: "SQLite open returned without a regular database file",
            }
        })?;
        if before.is_some_and(|identity| identity != after) {
            return Err(HarnessCatalogError::DatabasePathChanged(path));
        }
        ensure_directory_identity(&database_parent, database_parent_identity)?;
        let mut catalog = Self {
            path,
            database_parent,
            database_parent_identity,
            database_identity: after,
            wal_identity: None,
            shm_identity: None,
            connection,
        };
        match inspect_database(&catalog.connection)? {
            DatabaseOwnership::Fresh => {
                configure_connection(&catalog.connection, busy_timeout)?;
                migrate_fresh(&mut catalog.connection)?;
            }
            DatabaseOwnership::OwnedV1 => {
                configure_connection(&catalog.connection, busy_timeout)?;
            }
        }
        validate_schema(&catalog.connection)?;
        catalog.capture_sidecar_identities()?;
        catalog.ensure_live_binding()?;
        Ok(catalog)
    }

    pub fn register(
        &mut self,
        inspected: &InspectedHarnessBundle,
        observed_at: TimestampMillis,
    ) -> Result<HarnessCatalogEntry, HarnessCatalogError> {
        self.ensure_live_binding()?;
        let source_root = source_root_bytes(inspected.source_root())?;
        let id = inspected.descriptor().id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = query_by_id(&transaction, id)? {
            let existing = decode_entry(existing)?;
            if existing.source_root() == inspected.source_root()
                && existing.bundle().descriptor() == inspected.descriptor()
            {
                transaction.commit()?;
                self.capture_sidecar_identities()?;
                return Ok(existing);
            }
            return Err(HarnessCatalogError::BundleIdConflict(id));
        }
        if let Some(existing_id) = query_id_by_source(&transaction, &source_root)? {
            return Err(HarnessCatalogError::SourceAlreadyRegistered(existing_id));
        }
        let bundle = RegisteredHarnessBundle::create(inspected.descriptor().clone(), observed_at);
        insert_entry(&transaction, &bundle, &source_root)?;
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        self.get(id)?.ok_or(HarnessCatalogError::RecordMissing(id))
    }

    pub fn refresh(
        &mut self,
        inspected: &InspectedHarnessBundle,
        expected_revision: HarnessRevision,
        observed_at: TimestampMillis,
    ) -> Result<HarnessCatalogEntry, HarnessCatalogError> {
        self.ensure_live_binding()?;
        let id = inspected.descriptor().id();
        let source_root = source_root_bytes(inspected.source_root())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = query_by_id(&transaction, id)?
            .map(decode_entry)
            .transpose()?
            .ok_or(HarnessCatalogError::RecordMissing(id))?;
        if existing.source_root() != inspected.source_root() {
            return Err(HarnessCatalogError::SourceMismatch(id));
        }
        let updated = existing
            .bundle()
            .refresh(
                inspected.descriptor().clone(),
                expected_revision,
                observed_at,
            )
            .map_err(HarnessCatalogError::BundleTransition)?;
        let changed = update_entry(&transaction, &updated, &source_root, expected_revision)?;
        if changed != 1 {
            return Err(HarnessCatalogError::CompareAndSwapConflict);
        }
        transaction.commit()?;
        self.capture_sidecar_identities()?;
        self.ensure_live_binding()?;
        self.get(id)?.ok_or(HarnessCatalogError::RecordMissing(id))
    }

    pub fn get(
        &self,
        id: HarnessBundleId,
    ) -> Result<Option<HarnessCatalogEntry>, HarnessCatalogError> {
        self.ensure_live_binding()?;
        let entry = query_by_id(&self.connection, id)?
            .map(decode_entry)
            .transpose()?;
        self.ensure_live_binding()?;
        Ok(entry)
    }

    pub fn list(&self, limit: usize) -> Result<Vec<HarnessCatalogEntry>, HarnessCatalogError> {
        if limit == 0 || limit > MAX_HARNESS_CATALOG_RESULTS {
            return Err(HarnessCatalogError::InvalidListLimit {
                actual: limit,
                maximum: MAX_HARNESS_CATALOG_RESULTS,
            });
        }
        self.ensure_live_binding()?;
        let mut statement = self.connection.prepare(
            "SELECT length(bundle_id), length(CAST(display_name AS BLOB)),
                    length(CAST(version AS BLOB)), length(source_root), length(content_hash),
                    bundle_id, display_name, version, source_root, content_hash,
                    managed_file_count, skill_count, verifier_count,
                    registered_at_ms, updated_at_ms, revision
             FROM harness_bundles
             ORDER BY display_name COLLATE NOCASE ASC, bundle_id ASC
             LIMIT ?1",
        )?;
        let rows = statement
            .query_map(
                params![i64::try_from(limit).map_err(|_| {
                    HarnessCatalogError::InvalidListLimit {
                        actual: limit,
                        maximum: MAX_HARNESS_CATALOG_RESULTS,
                    }
                })?],
                decode_raw_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let entries = rows
            .into_iter()
            .map(decode_entry)
            .collect::<Result<Vec<_>, _>>()?;
        self.ensure_live_binding()?;
        Ok(entries)
    }

    fn ensure_live_binding(&self) -> Result<(), HarnessCatalogError> {
        ensure_directory_identity(&self.database_parent, self.database_parent_identity)?;
        let database = inspect_regular_file(&self.path, false)?.ok_or_else(|| {
            HarnessCatalogError::DatabasePathInvariant {
                path: self.path.clone(),
                detail: "catalog database disappeared",
            }
        })?;
        if database != self.database_identity {
            return Err(HarnessCatalogError::DatabasePathChanged(self.path.clone()));
        }
        compare_optional_identity(sidecar_path(&self.path, "-wal"), self.wal_identity)?;
        compare_optional_identity(sidecar_path(&self.path, "-shm"), self.shm_identity)
    }

    fn capture_sidecar_identities(&mut self) -> Result<(), HarnessCatalogError> {
        self.wal_identity = inspect_regular_file(&sidecar_path(&self.path, "-wal"), true)?;
        self.shm_identity = inspect_regular_file(&sidecar_path(&self.path, "-shm"), true)?;
        Ok(())
    }
}

#[derive(Debug)]
struct RawCatalogEntry {
    bundle_id: Vec<u8>,
    display_name: String,
    version: String,
    source_root: Vec<u8>,
    content_hash: Vec<u8>,
    managed_file_count: i64,
    skill_count: i64,
    verifier_count: i64,
    registered_at: i64,
    updated_at: i64,
    revision: i64,
}

fn query_by_id(
    connection: &Connection,
    id: HarnessBundleId,
) -> Result<Option<RawCatalogEntry>, HarnessCatalogError> {
    connection
        .query_row(
            "SELECT length(bundle_id), length(CAST(display_name AS BLOB)),
                    length(CAST(version AS BLOB)), length(source_root), length(content_hash),
                    bundle_id, display_name, version, source_root, content_hash,
                    managed_file_count, skill_count, verifier_count,
                    registered_at_ms, updated_at_ms, revision
             FROM harness_bundles WHERE bundle_id = ?1",
            params![id.into_uuid().as_bytes()],
            decode_raw_row,
        )
        .optional()
        .map_err(HarnessCatalogError::from)
}

fn query_id_by_source(
    connection: &Connection,
    source_root: &[u8],
) -> Result<Option<HarnessBundleId>, HarnessCatalogError> {
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT bundle_id FROM harness_bundles WHERE source_root = ?1",
            params![source_root],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|value| decode_uuid("bundle_id", &value).map(HarnessBundleId::from_uuid))
        .transpose()
}

fn insert_entry(
    transaction: &rusqlite::Transaction<'_>,
    bundle: &RegisteredHarnessBundle,
    source_root: &[u8],
) -> Result<(), HarnessCatalogError> {
    let descriptor = bundle.descriptor();
    transaction.execute(
        "INSERT INTO harness_bundles (
            bundle_id, display_name, version, source_root, content_hash,
            managed_file_count, skill_count, verifier_count,
            registered_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            descriptor.id().into_uuid().as_bytes(),
            descriptor.name().as_str(),
            descriptor.version().as_str(),
            source_root,
            descriptor.content_hash().as_bytes().as_slice(),
            i64::from(descriptor.managed_file_count()),
            i64::from(descriptor.skill_count()),
            i64::from(descriptor.verifier_count()),
            bundle.registered_at().get(),
            bundle.updated_at().get(),
            bundle.revision().get(),
        ],
    )?;
    Ok(())
}

fn update_entry(
    transaction: &rusqlite::Transaction<'_>,
    bundle: &RegisteredHarnessBundle,
    source_root: &[u8],
    expected_revision: HarnessRevision,
) -> Result<usize, HarnessCatalogError> {
    let descriptor = bundle.descriptor();
    transaction
        .execute(
            "UPDATE harness_bundles
             SET display_name = ?2, version = ?3, source_root = ?4, content_hash = ?5,
                 managed_file_count = ?6, skill_count = ?7, verifier_count = ?8,
                 updated_at_ms = ?9, revision = ?10
             WHERE bundle_id = ?1 AND revision = ?11",
            params![
                descriptor.id().into_uuid().as_bytes(),
                descriptor.name().as_str(),
                descriptor.version().as_str(),
                source_root,
                descriptor.content_hash().as_bytes().as_slice(),
                i64::from(descriptor.managed_file_count()),
                i64::from(descriptor.skill_count()),
                i64::from(descriptor.verifier_count()),
                bundle.updated_at().get(),
                bundle.revision().get(),
                expected_revision.get(),
            ],
        )
        .map_err(HarnessCatalogError::from)
}

fn decode_raw_row(row: &Row<'_>) -> rusqlite::Result<RawCatalogEntry> {
    validate_row_lengths(row).map_err(sql_decode_error)?;
    Ok(RawCatalogEntry {
        bundle_id: row.get(5)?,
        display_name: row.get(6)?,
        version: row.get(7)?,
        source_root: row.get(8)?,
        content_hash: row.get(9)?,
        managed_file_count: row.get(10)?,
        skill_count: row.get(11)?,
        verifier_count: row.get(12)?,
        registered_at: row.get(13)?,
        updated_at: row.get(14)?,
        revision: row.get(15)?,
    })
}

fn validate_row_lengths(row: &Row<'_>) -> Result<(), HarnessCatalogError> {
    validate_exact_length("bundle_id", row.get(0)?, ID_BYTES)?;
    validate_max_length(
        "display_name",
        row.get(1)?,
        forge_domain::MAX_HARNESS_NAME_BYTES,
    )?;
    validate_max_length(
        "version",
        row.get(2)?,
        forge_domain::MAX_HARNESS_VERSION_BYTES,
    )?;
    validate_max_length("source_root", row.get(3)?, MAX_SOURCE_ROOT_BYTES)?;
    validate_exact_length("content_hash", row.get(4)?, HASH_BYTES)
}

fn decode_entry(raw: RawCatalogEntry) -> Result<HarnessCatalogEntry, HarnessCatalogError> {
    let descriptor = HarnessBundleDescriptor::new(
        HarnessBundleId::from_uuid(decode_uuid("bundle_id", &raw.bundle_id)?),
        HarnessName::new(raw.display_name).map_err(HarnessCatalogError::Name)?,
        HarnessVersion::new(raw.version).map_err(HarnessCatalogError::Version)?,
        decode_hash(&raw.content_hash)?,
        decode_count("managed_file_count", raw.managed_file_count)?,
        decode_count("skill_count", raw.skill_count)?,
        decode_count("verifier_count", raw.verifier_count)?,
    )
    .map_err(HarnessCatalogError::Bundle)?;
    let bundle = RegisteredHarnessBundle::from_parts(
        descriptor,
        TimestampMillis::new(raw.registered_at).map_err(HarnessCatalogError::Timestamp)?,
        TimestampMillis::new(raw.updated_at).map_err(HarnessCatalogError::Timestamp)?,
        HarnessRevision::new(raw.revision).map_err(HarnessCatalogError::Revision)?,
    )
    .map_err(HarnessCatalogError::BundleTransition)?;
    Ok(HarnessCatalogEntry {
        bundle,
        source_root: PathBuf::from(std::ffi::OsString::from_vec(raw.source_root)),
    })
}

fn configure_connection(
    connection: &Connection,
    timeout: Duration,
) -> Result<(), HarnessCatalogError> {
    connection.busy_timeout(timeout)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseOwnership {
    Fresh,
    OwnedV1,
}

fn inspect_database(connection: &Connection) -> Result<DatabaseOwnership, HarnessCatalogError> {
    let app_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let nonempty: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%')",
        [],
        |row| row.get(0),
    )?;
    if app_id == 0 && version == 0 && !nonempty {
        return Ok(DatabaseOwnership::Fresh);
    }
    if app_id != HARNESS_CATALOG_APPLICATION_ID {
        return Err(HarnessCatalogError::DatabaseOwnershipMismatch {
            actual: app_id,
            expected: HARNESS_CATALOG_APPLICATION_ID,
        });
    }
    if version != HARNESS_CATALOG_SCHEMA_VERSION {
        return Err(HarnessCatalogError::UnsupportedSchemaVersion {
            actual: version,
            maximum_supported: HARNESS_CATALOG_SCHEMA_VERSION,
        });
    }
    Ok(DatabaseOwnership::OwnedV1)
}

fn migrate_fresh(connection: &mut Connection) -> Result<(), HarnessCatalogError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "application_id", HARNESS_CATALOG_APPLICATION_ID)?;
    transaction.execute_batch(EXPECTED_BUNDLES_TABLE_SQL)?;
    transaction.execute_batch(EXPECTED_BUNDLES_INDEX_SQL)?;
    transaction.pragma_update(None, "user_version", HARNESS_CATALOG_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), HarnessCatalogError> {
    validate_schema_sql(
        connection,
        "table",
        "harness_bundles",
        EXPECTED_BUNDLES_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        REQUIRED_INDEX_NAME,
        EXPECTED_BUNDLES_INDEX_SQL,
    )?;
    let mut statement = connection.prepare("PRAGMA table_info(harness_bundles)")?;
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
        return Err(HarnessCatalogError::DamagedSchema(
            "harness_bundles columns do not match the expected shape",
        ));
    }
    let mut index = connection.prepare("PRAGMA index_info(harness_bundles_name_idx)")?;
    let index_columns = index
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if index_columns != ["display_name", "bundle_id"] {
        return Err(HarnessCatalogError::DamagedSchema(
            "harness_bundles_name_idx columns do not match the expected shape",
        ));
    }
    Ok(())
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &str,
) -> Result<(), HarnessCatalogError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) == Some(normalize_sql(expected)) {
        Ok(())
    } else {
        Err(HarnessCatalogError::DamagedSchema(
            "Harness Catalog SQL definition does not match the expected policy",
        ))
    }
}

fn normalize_sql(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" ,", ",")
}

fn source_root_bytes(path: &Path) -> Result<Vec<u8>, HarnessCatalogError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_ROOT_BYTES {
        return Err(HarnessCatalogError::SourceRootTooLarge {
            actual: bytes.len(),
            maximum: MAX_SOURCE_ROOT_BYTES,
        });
    }
    Ok(bytes.to_vec())
}

fn decode_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, HarnessCatalogError> {
    Uuid::from_slice(bytes).map_err(|_| HarnessCatalogError::CorruptRecord { field })
}

fn decode_hash(bytes: &[u8]) -> Result<HarnessContentHash, HarnessCatalogError> {
    let hash: [u8; HASH_BYTES] =
        bytes
            .try_into()
            .map_err(|_| HarnessCatalogError::CorruptRecord {
                field: "content_hash",
            })?;
    Ok(HarnessContentHash::from_bytes(hash))
}

fn decode_count(field: &'static str, value: i64) -> Result<u16, HarnessCatalogError> {
    u16::try_from(value).map_err(|_| HarnessCatalogError::CorruptRecord { field })
}

fn validate_exact_length(
    field: &'static str,
    actual: i64,
    expected: usize,
) -> Result<(), HarnessCatalogError> {
    if usize::try_from(actual).ok() == Some(expected) {
        Ok(())
    } else {
        Err(HarnessCatalogError::CorruptRecord { field })
    }
}

fn validate_max_length(
    field: &'static str,
    actual: i64,
    maximum: usize,
) -> Result<(), HarnessCatalogError> {
    if usize::try_from(actual).is_ok_and(|value| value >= 1 && value <= maximum) {
        Ok(())
    } else {
        Err(HarnessCatalogError::CorruptRecord { field })
    }
}

fn sql_decode_error(error: HarnessCatalogError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut file_name = database
        .file_name()
        .map_or_else(std::ffi::OsString::new, std::ffi::OsStr::to_os_string);
    file_name.push(suffix);
    database.with_file_name(file_name)
}

fn inspect_directory(path: &Path) -> Result<DirectoryIdentity, HarnessCatalogError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| HarnessCatalogError::ParentMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_dir() {
        return Err(HarnessCatalogError::ParentNotDirectory(path.to_path_buf()));
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn ensure_directory_identity(
    path: &Path,
    expected: DirectoryIdentity,
) -> Result<(), HarnessCatalogError> {
    if inspect_directory(path)? == expected {
        Ok(())
    } else {
        Err(HarnessCatalogError::ParentChanged(path.to_path_buf()))
    }
}

fn inspect_regular_file(
    path: &Path,
    allow_missing: bool,
) -> Result<Option<FileIdentity>, HarnessCatalogError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if allow_missing && source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => {
            return Err(HarnessCatalogError::DatabaseMetadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(HarnessCatalogError::DatabaseSymlink(path.to_path_buf()));
    }
    if !metadata.file_type().is_file() {
        return Err(HarnessCatalogError::DatabaseNotRegular(path.to_path_buf()));
    }
    if metadata.nlink() != 1 {
        return Err(HarnessCatalogError::DatabaseHardlink {
            path: path.to_path_buf(),
            links: metadata.nlink(),
        });
    }
    Ok(Some(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
    }))
}

fn compare_optional_identity(
    path: PathBuf,
    expected: Option<FileIdentity>,
) -> Result<(), HarnessCatalogError> {
    let actual = inspect_regular_file(&path, true)?;
    if actual == expected {
        Ok(())
    } else {
        Err(HarnessCatalogError::DatabasePathChanged(path))
    }
}

fn validate_sidecars(database: &Path, database_exists: bool) -> Result<(), HarnessCatalogError> {
    let wal = inspect_regular_file(&sidecar_path(database, "-wal"), true)?;
    let shm = inspect_regular_file(&sidecar_path(database, "-shm"), true)?;
    if !database_exists && (wal.is_some() || shm.is_some()) {
        return Err(HarnessCatalogError::SidecarWithoutDatabase);
    }
    if wal.is_some() != shm.is_some() {
        return Err(HarnessCatalogError::SidecarPairMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum HarnessCatalogError {
    #[error("Harness Catalog path has no parent directory: {0}")]
    MissingParent(PathBuf),
    #[error("failed to create Harness Catalog parent directory {path}")]
    CreateParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect Harness Catalog parent {path}")]
    ParentMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Harness Catalog parent is not a directory: {0}")]
    ParentNotDirectory(PathBuf),
    #[error("Harness Catalog parent physical identity changed: {0}")]
    ParentChanged(PathBuf),
    #[error("failed to open Harness Catalog database {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to inspect Harness Catalog database {path}")]
    DatabaseMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Harness Catalog database is a symbolic link: {0}")]
    DatabaseSymlink(PathBuf),
    #[error("Harness Catalog database is not a regular file: {0}")]
    DatabaseNotRegular(PathBuf),
    #[error("Harness Catalog database has {links} hard links: {path}")]
    DatabaseHardlink { path: PathBuf, links: u64 },
    #[error("Harness Catalog database path invariant failed for {path}: {detail}")]
    DatabasePathInvariant { path: PathBuf, detail: &'static str },
    #[error("Harness Catalog database path identity changed: {0}")]
    DatabasePathChanged(PathBuf),
    #[error("Harness Catalog SQLite sidecar exists without its database")]
    SidecarWithoutDatabase,
    #[error("Harness Catalog SQLite WAL/SHM sidecars are incomplete")]
    SidecarPairMismatch,
    #[error("Harness Catalog database application id is {actual:#x}; expected {expected:#x}")]
    DatabaseOwnershipMismatch { actual: i64, expected: i64 },
    #[error(
        "Harness Catalog schema version {actual} is newer/unsupported; maximum is {maximum_supported}"
    )]
    UnsupportedSchemaVersion { actual: i64, maximum_supported: i64 },
    #[error("Harness Catalog schema is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Harness Catalog Bundle identity already exists with different metadata: {0}")]
    BundleIdConflict(HarnessBundleId),
    #[error("Harness Catalog source root is already registered by Bundle {0}")]
    SourceAlreadyRegistered(HarnessBundleId),
    #[error("Harness Catalog source root changed for Bundle {0}")]
    SourceMismatch(HarnessBundleId),
    #[error("Harness Catalog Bundle was not found: {0}")]
    RecordMissing(HarnessBundleId),
    #[error("Harness Catalog compare-and-set found a changed row")]
    CompareAndSwapConflict,
    #[error("Harness Catalog list limit {actual} is outside 1..={maximum}")]
    InvalidListLimit { actual: usize, maximum: usize },
    #[error("Harness Catalog source root is {actual} bytes; maximum is {maximum}")]
    SourceRootTooLarge { actual: usize, maximum: usize },
    #[error("Harness Catalog persisted field is corrupt: {field}")]
    CorruptRecord { field: &'static str },
    #[error("Harness Catalog Bundle name is invalid")]
    Name(#[source] HarnessNameError),
    #[error("Harness Catalog Bundle version is invalid")]
    Version(#[source] HarnessVersionError),
    #[error("Harness Catalog Bundle metadata is invalid")]
    Bundle(#[source] HarnessBundleError),
    #[error("Harness Catalog Bundle revision is invalid")]
    Revision(#[source] HarnessRevisionError),
    #[error("Harness Catalog timestamp is invalid")]
    Timestamp(#[source] TimestampMillisError),
    #[error("Harness Catalog Bundle transition is invalid")]
    BundleTransition(#[source] RegisteredHarnessBundleError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use forge_workspace::inspect_harness_bundle;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn bundle_source(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-catalog-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("rules"))?;
        fs::write(root.join("rules/base.md"), b"# Rules\n")?;
        fs::write(
            root.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
            format!(
                "[harness]\nid = \"00000000-0000-0000-0000-{serial:012x}\"\nname = \"Rust Dev Harness\"\nversion = \"1.0.0\"\ninstall_root = \".agents/rust_dev_harness\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n"
            ),
        )?;
        Ok(root)
    }

    #[test]
    fn catalog_register_reopen_list_and_refresh_are_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = bundle_source("durable")?;
        let inspected = inspect_harness_bundle(&source)?;
        let database = source
            .parent()
            .ok_or("fixture parent missing")?
            .join(format!(
                "catalog-{}-{}.sqlite3",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        let id = inspected.descriptor().id();
        let mut catalog = HarnessCatalog::open(&database)?;
        let first = catalog.register(&inspected, TimestampMillis::new(10)?)?;
        assert_eq!(first.bundle().descriptor(), inspected.descriptor());
        assert_eq!(
            catalog.register(&inspected, TimestampMillis::new(11)?)?,
            first
        );
        assert_eq!(catalog.list(10)?, vec![first.clone()]);
        drop(catalog);

        fs::write(source.join("rules/base.md"), b"# Changed rules\n")?;
        let changed = inspect_harness_bundle(&source)?;
        let mut catalog = HarnessCatalog::open(&database)?;
        let refreshed = catalog.refresh(
            &changed,
            first.bundle().revision(),
            TimestampMillis::new(12)?,
        )?;
        assert_eq!(refreshed.bundle().revision().get(), 2);
        assert_ne!(
            refreshed.bundle().descriptor().content_hash(),
            first.bundle().descriptor().content_hash()
        );
        assert_eq!(catalog.get(id)?, Some(refreshed));
        fs::remove_dir_all(source)?;
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn catalog_rejects_identity_conflict_without_mutating_existing_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = bundle_source("conflict")?;
        let inspected = inspect_harness_bundle(&source)?;
        let database = source
            .parent()
            .ok_or("fixture parent missing")?
            .join(format!(
                "catalog-conflict-{}-{}.sqlite3",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        let mut catalog = HarnessCatalog::open(&database)?;
        let first = catalog.register(&inspected, TimestampMillis::new(10)?)?;
        fs::write(source.join("rules/base.md"), b"# Unrefreshed drift\n")?;
        let drifted = inspect_harness_bundle(&source)?;
        assert!(matches!(
            catalog.register(&drifted, TimestampMillis::new(11)?),
            Err(HarnessCatalogError::BundleIdConflict(_))
        ));
        assert_eq!(catalog.get(first.bundle().descriptor().id())?, Some(first));
        fs::remove_dir_all(source)?;
        fs::remove_file(database)?;
        Ok(())
    }
}
