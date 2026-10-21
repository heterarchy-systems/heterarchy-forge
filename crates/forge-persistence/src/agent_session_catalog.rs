//! App-global `SQLite` authority for logical Agent session identities.
//!
//! A session is issued before a Workspace attachment exists.  This catalog
//! stores only the opaque session identity, its idempotency nonce, the
//! authenticated principal identity, and lifecycle timestamps/revision.  It
//! intentionally has no Workspace, Activity, Goal, transcript, `ChatGPT`, or
//! bearer-secret authority.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_domain::{
    AgentSessionId, AgentSessionOpenOutcome, AgentSessionOpenRequestId, AgentSessionRecordParts,
    AgentSessionRevision, AgentSessionRevisionError, AgentSessionState,
    AgentSessionTransitionError, AuthenticatedPrincipal, DirectTokenId, OAuthGrantId,
    OpenAgentSession, RegisteredAgentSession, TimestampMillis, TimestampMillisError,
};
use rusqlite::{
    Connection, ErrorCode, OpenFlags, OptionalExtension, Row, Rows, Transaction,
    TransactionBehavior, params,
};
use thiserror::Error;
use uuid::Uuid;

/// Application identifier written into `PRAGMA application_id` for this
/// catalog.  It is deliberately distinct from the Location, token, OAuth,
/// and connection-settings catalogs.
pub const AGENT_SESSION_APPLICATION_ID: i64 = 0x4846_4153;
/// Current schema version for the logical Agent session catalog.
pub const AGENT_SESSION_SCHEMA_VERSION: i64 = 1;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const JOURNAL_MODE_RETRY_LIMIT: usize = 8;
const JOURNAL_MODE_RETRY_DELAY: Duration = Duration::from_millis(10);
const MAX_SCHEMA_SQL_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 256;
const UUID_BYTES: usize = 16;

// This is the one canonical DDL authority for this catalog.  Creation and
// validation both consume the same string; tests must inspect the live
// sqlite_schema entry rather than maintain a second DDL copy.
const AGENT_SESSIONS_TABLE_SQL: &str = r"
CREATE TABLE agent_sessions (
    session_id BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 16),
    principal_kind INTEGER NOT NULL CHECK(principal_kind IN (0, 1, 2)),
    principal_id BLOB NOT NULL CHECK(length(principal_id) = 16),
    request_id BLOB NOT NULL CHECK(length(request_id) = 16),
    state INTEGER NOT NULL CHECK(state IN (1, 2)),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
    revision INTEGER NOT NULL CHECK(revision > 0),
    UNIQUE(principal_kind, principal_id, request_id),
    CHECK((principal_kind = 0 AND principal_id = zeroblob(16)) OR principal_kind IN (1, 2))
);
";

const AGENT_SESSIONS_INDEX_SQL: &str = r"
CREATE INDEX agent_sessions_state_updated_idx
ON agent_sessions(state, updated_at_ms DESC, session_id);
";

const EXPECTED_COLUMNS: [(&str, &str, i64, i64); 8] = [
    ("session_id", "BLOB", 1, 1),
    ("principal_kind", "INTEGER", 1, 0),
    ("principal_id", "BLOB", 1, 0),
    ("request_id", "BLOB", 1, 0),
    ("state", "INTEGER", 1, 0),
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

/// SQLite-backed app-global logical Agent session catalog.
pub struct AgentSessionCatalog {
    path: PathBuf,
    database_parent: PathBuf,
    database_parent_identity: DirectoryIdentity,
    database_identity: FileIdentity,
    wal_identity: Option<FileIdentity>,
    shm_identity: Option<FileIdentity>,
    connection: Connection,
}

impl fmt::Debug for AgentSessionCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentSessionCatalog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl AgentSessionCatalog {
    /// Open an existing catalog or create a fresh catalog at an
    /// application-owned path.  The parent and database identities are
    /// checked before and after opening so a path replacement is reported.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AgentSessionCatalogError> {
        let path = canonical_catalog_path(path.as_ref())?;
        let database_parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| AgentSessionCatalogError::MissingParent(path.clone()))?
            .to_path_buf();
        let database_parent_identity = inspect_directory(&database_parent)?;
        let database_before = inspect_regular_file(&path, true)?;
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        let wal_before = inspect_regular_file(&wal_path, true)?;
        let shm_before = inspect_regular_file(&shm_path, true)?;
        if database_before.is_none() {
            if wal_before.is_some() {
                return Err(AgentSessionCatalogError::DatabaseSidecarWithoutMain(
                    wal_path,
                ));
            }
            if shm_before.is_some() {
                return Err(AgentSessionCatalogError::DatabaseSidecarWithoutMain(
                    shm_path,
                ));
            }
        }

        let flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags).map_err(|source| {
            AgentSessionCatalogError::Open {
                path: path.clone(),
                source,
            }
        })?;
        let database_after = inspect_regular_file(&path, false)?.ok_or_else(|| {
            AgentSessionCatalogError::DatabasePathInvariant {
                path: path.clone(),
                detail: "SQLite open returned without a regular database file",
            }
        })?;
        if let Some(expected) = database_before
            && expected != database_after
        {
            return Err(AgentSessionCatalogError::DatabasePathChanged(path));
        }
        ensure_directory_identity(&database_parent, database_parent_identity)?;

        let mut catalog = Self {
            path,
            database_parent,
            database_parent_identity,
            database_identity: database_after,
            wal_identity: wal_before,
            shm_identity: shm_before,
            connection,
        };
        // A bounded connection-only timeout lets concurrent fresh openers
        // serialize on the initialization transaction without changing any
        // on-disk journal or durability setting before ownership validation.
        catalog.connection.busy_timeout(BUSY_TIMEOUT)?;
        // Validate ownership and schema before issuing any journal or
        // durability configuration.  In particular, an existing foreign or
        // malformed database must not be converted to WAL as a side effect of
        // discovering that it is not this catalog.
        initialize_or_validate(&mut catalog.connection)?;
        configure(&catalog.connection)?;
        catalog.capture_sidecar_identities()?;
        catalog.ensure_live_binding()?;
        Ok(catalog)
    }

    /// Open an already-created catalog without creating a new empty database.
    ///
    /// Read-only resolution callers should use this entry point when the
    /// application-global catalog may not have been issued yet.  A missing
    /// main database returns `Ok(None)` after validating the parent and
    /// rejecting orphaned sidecars; malformed existing paths and schemas
    /// remain errors.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Option<Self>, AgentSessionCatalogError> {
        let canonical_path = canonical_catalog_path(path.as_ref())?;
        let database = inspect_regular_file(&canonical_path, true)?;
        if database.is_none() {
            let wal_path = sidecar_path(&canonical_path, "-wal");
            if inspect_regular_file(&wal_path, true)?.is_some() {
                return Err(AgentSessionCatalogError::DatabaseSidecarWithoutMain(
                    wal_path,
                ));
            }
            let shm_path = sidecar_path(&canonical_path, "-shm");
            if inspect_regular_file(&shm_path, true)?.is_some() {
                return Err(AgentSessionCatalogError::DatabaseSidecarWithoutMain(
                    shm_path,
                ));
            }
            return Ok(None);
        }
        Self::open(canonical_path).map(Some)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Issue a new logical session, or return the durable session already
    /// associated with this principal and retry nonce.  A retry may propose a
    /// different random ID; the first committed ID remains authoritative.
    pub fn open_session(
        &mut self,
        command: &OpenAgentSession,
    ) -> Result<AgentSessionOpenOutcome, AgentSessionCatalogError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (principal_kind, principal_id) = encode_principal(command.principal());
        let request_id = command.request_id().into_uuid().into_bytes();
        let existing_id = transaction
            .query_row(
                "SELECT session_id
                 FROM agent_sessions
                 WHERE principal_kind = ?1 AND principal_id = ?2 AND request_id = ?3",
                params![
                    principal_kind,
                    principal_id.as_slice(),
                    request_id.as_slice()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;

        if let Some(existing_id) = existing_id {
            let existing_id = decode_session_id(&existing_id, "session_id")?;
            let session = load_session(&transaction, existing_id)?
                .ok_or(AgentSessionCatalogError::SessionMissing(existing_id))?;
            transaction.commit()?;
            self.ensure_live_binding()?;
            return Ok(AgentSessionOpenOutcome::new(session, false));
        }

        if load_session(&transaction, command.proposed_id())?.is_some() {
            return Err(AgentSessionCatalogError::SessionIdConflict(
                command.proposed_id(),
            ));
        }
        let session = RegisteredAgentSession::open(
            command.proposed_id(),
            command.request_id(),
            command.principal(),
            command.observed_at(),
        );
        insert_session(&transaction, &session)?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(AgentSessionOpenOutcome::new(session, true))
    }

    /// Resolve a session only when the supplied principal is its exact owner.
    /// A missing or foreign session is projected as `None`, avoiding an
    /// existence oracle at this boundary.
    pub fn resolve(
        &self,
        id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Option<RegisteredAgentSession>, AgentSessionCatalogError> {
        self.ensure_live_binding()?;
        let session = load_session(&self.connection, id)?;
        self.ensure_live_binding()?;
        Ok(session.filter(|session| session.principal() == principal))
    }

    /// Close one session under exact principal and revision compare-and-set.
    /// Closing is terminal; a later open retry returns the closed projection
    /// rather than silently reopening it.
    pub fn close(
        &mut self,
        id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        expected_revision: AgentSessionRevision,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredAgentSession, AgentSessionCatalogError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            load_session(&transaction, id)?.ok_or(AgentSessionCatalogError::SessionMissing(id))?;
        if current.principal() != principal {
            return Err(AgentSessionCatalogError::ForeignPrincipal(id));
        }
        let closed = current.close(expected_revision, observed_at)?;
        let (principal_kind, principal_id) = encode_principal(principal);
        let id_bytes = id.into_uuid().into_bytes();
        let changed = transaction.execute(
            "UPDATE agent_sessions
             SET state = ?1, updated_at_ms = ?2, revision = ?3
             WHERE session_id = ?4 AND principal_kind = ?5 AND principal_id = ?6
               AND revision = ?7 AND state = ?8",
            params![
                encode_state(closed.state()),
                closed.updated_at().get(),
                closed.revision().get(),
                id_bytes.as_slice(),
                principal_kind,
                principal_id.as_slice(),
                expected_revision.get(),
                encode_state(AgentSessionState::Open),
            ],
        )?;
        if changed != 1 {
            return Err(AgentSessionCatalogError::RevisionConflict(id));
        }
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(closed)
    }

    fn ensure_live_binding(&self) -> Result<(), AgentSessionCatalogError> {
        ensure_directory_identity(&self.database_parent, self.database_parent_identity)?;
        let observed_database = inspect_regular_file(&self.path, false)?.ok_or_else(|| {
            AgentSessionCatalogError::DatabasePathInvariant {
                path: self.path.clone(),
                detail: "database file disappeared",
            }
        })?;
        if observed_database != self.database_identity {
            return Err(AgentSessionCatalogError::DatabasePathChanged(
                self.path.clone(),
            ));
        }
        for (path, expected) in [
            (sidecar_path(&self.path, "-wal"), self.wal_identity),
            (sidecar_path(&self.path, "-shm"), self.shm_identity),
        ] {
            let observed = inspect_regular_file(&path, true)?;
            if let (Some(expected), Some(observed)) = (expected, observed)
                && expected != observed
            {
                return Err(AgentSessionCatalogError::DatabasePathChanged(path));
            }
        }
        Ok(())
    }

    fn capture_sidecar_identities(&mut self) -> Result<(), AgentSessionCatalogError> {
        self.wal_identity = inspect_regular_file(&sidecar_path(&self.path, "-wal"), true)?;
        self.shm_identity = inspect_regular_file(&sidecar_path(&self.path, "-shm"), true)?;
        Ok(())
    }
}

fn canonical_catalog_path(requested_path: &Path) -> Result<PathBuf, AgentSessionCatalogError> {
    let parent = requested_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| AgentSessionCatalogError::MissingParent(requested_path.to_path_buf()))?;
    // Inspect the requested parent before canonicalization so a caller cannot
    // silently route the catalog through a final symlink component.
    inspect_directory(parent)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| AgentSessionCatalogError::PathIo {
            path: parent.to_path_buf(),
            source,
        })?;
    let file_name = requested_path
        .file_name()
        .ok_or_else(|| AgentSessionCatalogError::MissingParent(requested_path.to_path_buf()))?;
    Ok(canonical_parent.join(file_name))
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
) -> Result<Option<FileIdentity>, AgentSessionCatalogError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if allow_missing && source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => {
            return Err(AgentSessionCatalogError::PathIo {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(AgentSessionCatalogError::DatabasePathSymlink(
            path.to_path_buf(),
        ));
    }
    if !metadata.is_file() {
        return Err(AgentSessionCatalogError::DatabasePathNotRegular(
            path.to_path_buf(),
        ));
    }
    let identity = FileIdentity::from_metadata(&metadata);
    if identity.links != 1 {
        return Err(AgentSessionCatalogError::DatabasePathHardlink {
            path: path.to_path_buf(),
            links: identity.links,
        });
    }
    Ok(Some(identity))
}

fn inspect_directory(path: &Path) -> Result<DirectoryIdentity, AgentSessionCatalogError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| AgentSessionCatalogError::PathIo {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(AgentSessionCatalogError::DatabaseParentSymlink(
            path.to_path_buf(),
        ));
    }
    if !metadata.is_dir() {
        return Err(AgentSessionCatalogError::DatabaseParentNotDirectory(
            path.to_path_buf(),
        ));
    }
    Ok(DirectoryIdentity::from_metadata(&metadata))
}

fn ensure_directory_identity(
    path: &Path,
    expected: DirectoryIdentity,
) -> Result<(), AgentSessionCatalogError> {
    if inspect_directory(path)? != expected {
        return Err(AgentSessionCatalogError::DatabaseParentChanged(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn configure(connection: &Connection) -> Result<(), AgentSessionCatalogError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    for attempt in 0..JOURNAL_MODE_RETRY_LIMIT {
        match connection.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => break,
            Err(error) if is_busy_error(&error) && attempt + 1 < JOURNAL_MODE_RETRY_LIMIT => {
                std::thread::sleep(JOURNAL_MODE_RETRY_DELAY);
            }
            Err(error) => return Err(error.into()),
        }
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn is_busy_error(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(
            error,
            _
        ) if matches!(error.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn initialize_or_validate(connection: &mut Connection) -> Result<(), AgentSessionCatalogError> {
    let (application_id, user_version, object_count) = catalog_ownership(connection)?;
    match (application_id, user_version, object_count) {
        (0, 0, 0) => create_schema(connection),
        (AGENT_SESSION_APPLICATION_ID, AGENT_SESSION_SCHEMA_VERSION, _) => {
            validate_schema(connection)
        }
        _ => Err(AgentSessionCatalogError::Ownership {
            application_id,
            user_version,
            object_count,
        }),
    }
}

fn catalog_ownership(connection: &Connection) -> Result<(i64, i64, i64), AgentSessionCatalogError> {
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

fn create_schema(connection: &mut Connection) -> Result<(), AgentSessionCatalogError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (application_id, user_version, object_count) = catalog_ownership(&transaction)?;
    match (application_id, user_version, object_count) {
        (0, 0, 0) => {
            transaction.execute_batch(AGENT_SESSIONS_TABLE_SQL)?;
            transaction.execute_batch(AGENT_SESSIONS_INDEX_SQL)?;
            transaction.pragma_update(None, "application_id", AGENT_SESSION_APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", AGENT_SESSION_SCHEMA_VERSION)?;
        }
        (AGENT_SESSION_APPLICATION_ID, AGENT_SESSION_SCHEMA_VERSION, _) => {
            transaction.commit()?;
            return validate_schema(connection);
        }
        _ => {
            return Err(AgentSessionCatalogError::Ownership {
                application_id,
                user_version,
                object_count,
            });
        }
    }
    transaction.commit()?;
    validate_schema(connection)
}

fn validate_schema(connection: &Connection) -> Result<(), AgentSessionCatalogError> {
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(AgentSessionCatalogError::Integrity);
    }
    let object_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if object_count != 2 {
        return Err(AgentSessionCatalogError::Schema("object count"));
    }
    validate_schema_sql(
        connection,
        "table",
        "agent_sessions",
        AGENT_SESSIONS_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "agent_sessions_state_updated_idx",
        AGENT_SESSIONS_INDEX_SQL,
    )?;
    let mut statement = connection.prepare("PRAGMA table_info(agent_sessions)")?;
    let mut rows = statement.query([])?;
    let columns = collect_bounded_metadata(&mut rows, "agent_sessions columns", |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    let columns_match = columns.len() == EXPECTED_COLUMNS.len()
        && columns.iter().zip(EXPECTED_COLUMNS.iter()).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !columns_match {
        return Err(AgentSessionCatalogError::Schema("agent_sessions columns"));
    }
    let mut index_list = connection.prepare("PRAGMA index_list(agent_sessions)")?;
    let mut index_rows = index_list.query([])?;
    let indexes = collect_bounded_metadata(&mut index_rows, "agent_sessions indexes", |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
    })?;
    let Some((_, unique)) = indexes
        .iter()
        .find(|(name, _)| name == "agent_sessions_state_updated_idx")
    else {
        return Err(AgentSessionCatalogError::Schema(
            "agent_sessions state index",
        ));
    };
    if *unique != 0 {
        return Err(AgentSessionCatalogError::Schema(
            "agent_sessions state index uniqueness",
        ));
    }
    let mut index_info =
        connection.prepare("PRAGMA index_info(agent_sessions_state_updated_idx)")?;
    let mut index_rows = index_info.query([])?;
    let index_columns = collect_bounded_metadata(
        &mut index_rows,
        "agent_sessions state index columns",
        |row| row.get::<_, String>(2),
    )?;
    if index_columns != ["state", "updated_at_ms", "session_id"] {
        return Err(AgentSessionCatalogError::Schema(
            "agent_sessions state index columns",
        ));
    }
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if foreign_key_violation {
        return Err(AgentSessionCatalogError::Integrity);
    }
    Ok(())
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &str,
) -> Result<(), AgentSessionCatalogError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB))
             FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    let Some(length) = length else {
        return Err(AgentSessionCatalogError::Schema(name));
    };
    let actual = usize::try_from(length).unwrap_or(usize::MAX);
    if actual > MAX_SCHEMA_SQL_BYTES {
        return Err(AgentSessionCatalogError::SchemaSqlTooLarge {
            object: name,
            actual,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
        params![object_type, name],
        |row| row.get(0),
    )?;
    if normalize_sql(&sql) != normalize_sql(expected) {
        return Err(AgentSessionCatalogError::Schema(name));
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

fn collect_bounded_metadata<T, F>(
    rows: &mut Rows<'_>,
    object: &'static str,
    mut decode: F,
) -> Result<Vec<T>, AgentSessionCatalogError>
where
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        if values.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentSessionCatalogError::SchemaMetadataTooLarge {
                object,
                maximum: MAX_SCHEMA_METADATA_ROWS,
            });
        }
        values.push(decode(row)?);
    }
    Ok(values)
}

fn insert_session(
    transaction: &Transaction<'_>,
    session: &RegisteredAgentSession,
) -> Result<(), AgentSessionCatalogError> {
    let (principal_kind, principal_id) = encode_principal(session.principal());
    let session_id = session.id().into_uuid().into_bytes();
    let request_id = session.request_id().into_uuid().into_bytes();
    transaction
        .execute(
            "INSERT INTO agent_sessions(
                session_id, principal_kind, principal_id, request_id, state,
                created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                session_id.as_slice(),
                principal_kind,
                principal_id.as_slice(),
                request_id.as_slice(),
                encode_state(session.state()),
                session.created_at().get(),
                session.updated_at().get(),
                session.revision().get(),
            ],
        )
        .map(|_| ())
        .map_err(AgentSessionCatalogError::from)
}

#[derive(Debug)]
struct RawAgentSession {
    session_id: Vec<u8>,
    principal_kind: i64,
    principal_id: Option<Vec<u8>>,
    request_id: Vec<u8>,
    state: i64,
    created_at: i64,
    updated_at: i64,
    revision: i64,
}

fn load_session(
    connection: &Connection,
    id: AgentSessionId,
) -> Result<Option<RegisteredAgentSession>, AgentSessionCatalogError> {
    let id_bytes = id.into_uuid().into_bytes();
    let raw = connection
        .query_row(
            "SELECT session_id, principal_kind, principal_id, request_id, state,
                    created_at_ms, updated_at_ms, revision
             FROM agent_sessions WHERE session_id = ?1",
            params![id_bytes.as_slice()],
            |row| {
                Ok(RawAgentSession {
                    session_id: row.get(0)?,
                    principal_kind: row.get(1)?,
                    principal_id: row.get(2)?,
                    request_id: row.get(3)?,
                    state: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                    revision: row.get(7)?,
                })
            },
        )
        .optional()?;
    raw.map(decode_session).transpose()
}

fn decode_session(
    raw: RawAgentSession,
) -> Result<RegisteredAgentSession, AgentSessionCatalogError> {
    let id = decode_session_id(&raw.session_id, "session_id")?;
    let request_id =
        AgentSessionOpenRequestId::from_uuid(decode_uuid("request_id", &raw.request_id)?);
    let principal = decode_principal(raw.principal_kind, raw.principal_id)?;
    let state = decode_state(raw.state)?;
    let created_at = TimestampMillis::new(raw.created_at)?;
    let updated_at = TimestampMillis::new(raw.updated_at)?;
    let revision = AgentSessionRevision::new(raw.revision)?;
    RegisteredAgentSession::from_parts(AgentSessionRecordParts {
        id,
        principal,
        request_id,
        state,
        created_at,
        updated_at,
        revision,
    })
    .map_err(AgentSessionCatalogError::Transition)
}

fn decode_session_id(
    bytes: &[u8],
    field: &'static str,
) -> Result<AgentSessionId, AgentSessionCatalogError> {
    Ok(AgentSessionId::from_uuid(decode_uuid(field, bytes)?))
}

fn decode_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, AgentSessionCatalogError> {
    if bytes.len() != UUID_BYTES {
        return Err(AgentSessionCatalogError::InvalidUuidLength {
            field,
            actual: bytes.len(),
            expected: UUID_BYTES,
        });
    }
    Uuid::from_slice(bytes).map_err(|source| AgentSessionCatalogError::Uuid { field, source })
}

fn encode_principal(principal: AuthenticatedPrincipal) -> (i64, [u8; UUID_BYTES]) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => (0, [0; UUID_BYTES]),
        AuthenticatedPrincipal::DirectToken(id) => (1, id.into_uuid().into_bytes()),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, id.into_uuid().into_bytes()),
    }
}

fn decode_principal(
    kind: i64,
    bytes: Option<Vec<u8>>,
) -> Result<AuthenticatedPrincipal, AgentSessionCatalogError> {
    let bytes = bytes.ok_or(AgentSessionCatalogError::InvalidPrincipalEncoding {
        kind,
        detail: "principal_id is NULL",
    })?;
    if bytes.len() != UUID_BYTES {
        return Err(AgentSessionCatalogError::InvalidUuidLength {
            field: "principal_id",
            actual: bytes.len(),
            expected: UUID_BYTES,
        });
    }
    if kind == 0 && bytes.iter().any(|byte| *byte != 0) {
        return Err(AgentSessionCatalogError::InvalidPrincipalEncoding {
            kind,
            detail: "TrustedStdio principal_id must be zero",
        });
    }
    let uuid = decode_uuid("principal_id", &bytes)?;
    match kind {
        0 => Ok(AuthenticatedPrincipal::TrustedStdio),
        1 => Ok(AuthenticatedPrincipal::DirectToken(
            DirectTokenId::from_uuid(uuid),
        )),
        2 => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
            uuid,
        ))),
        _ => Err(AgentSessionCatalogError::InvalidPrincipalEncoding {
            kind,
            detail: "principal_kind is outside 0..=2",
        }),
    }
}

const fn encode_state(state: AgentSessionState) -> i64 {
    match state {
        AgentSessionState::Open => 1,
        AgentSessionState::Closed => 2,
    }
}

fn decode_state(value: i64) -> Result<AgentSessionState, AgentSessionCatalogError> {
    match value {
        1 => Ok(AgentSessionState::Open),
        2 => Ok(AgentSessionState::Closed),
        _ => Err(AgentSessionCatalogError::InvalidState(value)),
    }
}

#[derive(Debug, Error)]
pub enum AgentSessionCatalogError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("failed to open Agent session catalog at {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("Agent session catalog path has no usable parent: {0}")]
    MissingParent(PathBuf),
    #[error("failed to inspect Agent session catalog path {path}")]
    PathIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Agent session catalog database path is a symbolic link: {0}")]
    DatabasePathSymlink(PathBuf),
    #[error("Agent session catalog database path is not a regular file: {0}")]
    DatabasePathNotRegular(PathBuf),
    #[error("Agent session catalog database path has {links} hard links: {path}")]
    DatabasePathHardlink { path: PathBuf, links: u64 },
    #[error("Agent session catalog database sidecar exists without its main database: {0}")]
    DatabaseSidecarWithoutMain(PathBuf),
    #[error("Agent session catalog database path identity changed: {0}")]
    DatabasePathChanged(PathBuf),
    #[error("Agent session catalog database invariant failed for {path}: {detail}")]
    DatabasePathInvariant { path: PathBuf, detail: &'static str },
    #[error("Agent session catalog parent is a symbolic link: {0}")]
    DatabaseParentSymlink(PathBuf),
    #[error("Agent session catalog parent is not a directory: {0}")]
    DatabaseParentNotDirectory(PathBuf),
    #[error("Agent session catalog parent identity changed: {0}")]
    DatabaseParentChanged(PathBuf),
    #[error(
        "Agent session catalog ownership is invalid: application_id={application_id}, user_version={user_version}, object_count={object_count}"
    )]
    Ownership {
        application_id: i64,
        user_version: i64,
        object_count: i64,
    },
    #[error("Agent session catalog is missing or has invalid schema object {0}")]
    Schema(&'static str),
    #[error("Agent session catalog schema object {object} is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge {
        object: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("Agent session catalog schema metadata for {object} exceeds {maximum} rows")]
    SchemaMetadataTooLarge {
        object: &'static str,
        maximum: usize,
    },
    #[error("Agent session catalog integrity check failed")]
    Integrity,
    #[error("Agent session identity already exists: {0}")]
    SessionIdConflict(AgentSessionId),
    #[error("Agent session was not found: {0}")]
    SessionMissing(AgentSessionId),
    #[error("Agent session belongs to a different authenticated principal: {0}")]
    ForeignPrincipal(AgentSessionId),
    #[error("Agent session revision conflict: {0}")]
    RevisionConflict(AgentSessionId),
    #[error("Agent session persisted state is invalid: {0}")]
    InvalidState(i64),
    #[error("Agent session persisted principal encoding is invalid for kind {kind}: {detail}")]
    InvalidPrincipalEncoding { kind: i64, detail: &'static str },
    #[error("Agent session persisted UUID field {field} has {actual} bytes; expected {expected}")]
    InvalidUuidLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Agent session persisted UUID field {field} is invalid")]
    Uuid {
        field: &'static str,
        #[source]
        source: uuid::Error,
    },
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Revision(#[from] AgentSessionRevisionError),
    #[error(transparent)]
    Transition(#[from] AgentSessionTransitionError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::fs::hard_link;
    use std::io;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    fn database(name: &str) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-agent-session-{name}-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir(&root)?;
        Ok((root.clone(), root.join("catalog.sqlite3")))
    }

    fn command(
        session: u128,
        request: u128,
        principal: AuthenticatedPrincipal,
        observed_at: i64,
    ) -> Result<OpenAgentSession, Box<dyn Error>> {
        Ok(OpenAgentSession::new(
            AgentSessionId::from_uuid(Uuid::from_u128(session)),
            AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(request)),
            principal,
            TimestampMillis::new(observed_at)?,
        ))
    }

    fn token_principal(value: u128) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(value)))
    }

    fn cleanup(root: PathBuf) -> Result<(), Box<dyn Error>> {
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn one_hundred_retries_return_the_first_server_issued_identity() -> Result<(), Box<dyn Error>> {
        let (root, path) = database("retries")?;
        let principal = token_principal(10);
        let request = AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(11));
        let mut catalog = AgentSessionCatalog::open(&path)?;
        let first = catalog.open_session(&command(12, 11, principal, 1)?)?;
        assert!(first.created());
        for retry in 0..100_u128 {
            let retry_offset = i64::try_from(retry)?;
            let result =
                catalog.open_session(&command(1000 + retry, 11, principal, 100 + retry_offset)?)?;
            assert!(!result.created());
            assert_eq!(result.session().id(), first.session().id());
            assert_eq!(result.session().request_id(), request);
            assert_eq!(result.session().created_at(), first.session().created_at());
        }
        cleanup(root)?;
        Ok(())
    }

    #[test]
    fn same_request_is_durable_across_restart_and_closed_sessions_do_not_reopen()
    -> Result<(), Box<dyn Error>> {
        let (root, path) = database("restart-close")?;
        let principal = token_principal(20);
        let mut catalog = AgentSessionCatalog::open(&path)?;
        let first = catalog.open_session(&command(21, 22, principal, 10)?)?;
        let closed = catalog.close(
            first.session().id(),
            principal,
            first.session().revision(),
            TimestampMillis::new(11)?,
        )?;
        drop(catalog);
        let mut reopened = AgentSessionCatalog::open(&path)?;
        let retry = reopened.open_session(&command(23, 22, principal, 12)?)?;
        assert!(!retry.created());
        assert_eq!(retry.session(), &closed);
        assert_eq!(reopened.resolve(closed.id(), principal)?, Some(closed));
        cleanup(root)?;
        Ok(())
    }

    #[test]
    fn concurrent_same_request_creates_exactly_one_session() -> Result<(), Box<dyn Error>> {
        let (root, path) = database("concurrent")?;
        let path = Arc::new(path);
        let barrier = Arc::new(Barrier::new(2));
        let principal = token_principal(30);
        let left_path = Arc::clone(&path);
        let left_barrier = Arc::clone(&barrier);
        let left = thread::spawn(move || -> Result<AgentSessionOpenOutcome, String> {
            left_barrier.wait();
            let mut catalog = AgentSessionCatalog::open(left_path.as_ref())
                .map_err(|error| format!("left catalog open: {error}"))?;
            catalog
                .open_session(
                    &command(31, 32, principal, 1)
                        .map_err(|error| format!("left command: {error}"))?,
                )
                .map_err(|error| format!("left session open: {error}"))
        });
        let right_path = Arc::clone(&path);
        let right_barrier = Arc::clone(&barrier);
        let right = thread::spawn(move || -> Result<AgentSessionOpenOutcome, String> {
            right_barrier.wait();
            let mut catalog = AgentSessionCatalog::open(right_path.as_ref())
                .map_err(|error| format!("right catalog open: {error}"))?;
            catalog
                .open_session(
                    &command(33, 32, principal, 2)
                        .map_err(|error| format!("right command: {error}"))?,
                )
                .map_err(|error| format!("right session open: {error}"))
        });
        let left = left
            .join()
            .map_err(|_| io::Error::other("left thread panicked"))?
            .map_err(io::Error::other)?;
        let right = right
            .join()
            .map_err(|_| io::Error::other("right thread panicked"))?
            .map_err(io::Error::other)?;
        assert_ne!(left.created(), right.created());
        assert_eq!(left.session().id(), right.session().id());
        drop(path);
        cleanup(root)?;
        Ok(())
    }

    #[test]
    fn foreign_principal_is_not_resolvable_and_close_is_rejected() -> Result<(), Box<dyn Error>> {
        let (root, path) = database("principal")?;
        let owner = token_principal(40);
        let foreign = token_principal(41);
        let mut catalog = AgentSessionCatalog::open(&path)?;
        let session = catalog
            .open_session(&command(42, 43, owner, 1)?)?
            .into_session();
        assert_eq!(catalog.resolve(session.id(), foreign)?, None);
        assert!(matches!(
            catalog.close(
                session.id(),
                foreign,
                session.revision(),
                TimestampMillis::new(2)?
            ),
            Err(AgentSessionCatalogError::ForeignPrincipal(id)) if id == session.id()
        ));
        cleanup(root)?;
        Ok(())
    }

    #[test]
    fn close_uses_exact_revision_and_preserves_terminal_state() -> Result<(), Box<dyn Error>> {
        let (root, path) = database("revision")?;
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let mut catalog = AgentSessionCatalog::open(&path)?;
        let session = catalog
            .open_session(&command(50, 51, principal, 10)?)?
            .into_session();
        assert!(matches!(
            catalog.close(
                session.id(),
                principal,
                AgentSessionRevision::new(2)?,
                TimestampMillis::new(11)?
            ),
            Err(AgentSessionCatalogError::Transition(
                AgentSessionTransitionError::RevisionConflict
            ))
        ));
        let closed = catalog.close(
            session.id(),
            principal,
            session.revision(),
            TimestampMillis::new(11)?,
        )?;
        assert!(matches!(
            catalog.close(
                closed.id(),
                principal,
                closed.revision(),
                TimestampMillis::new(12)?
            ),
            Err(AgentSessionCatalogError::Transition(
                AgentSessionTransitionError::AlreadyClosed
            ))
        ));
        cleanup(root)?;
        Ok(())
    }

    #[test]
    fn foreign_database_is_rejected_without_reconfiguration() -> Result<(), Box<dyn Error>> {
        let (root, path) = database("foreign-unchanged")?;
        {
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "CREATE TABLE another_application (value INTEGER);
                 INSERT INTO another_application(value) VALUES (1);
                 PRAGMA application_id = 0x12345678;
                 PRAGMA user_version = 7;",
            )?;
        }
        let database_before = fs::read(&path)?;
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        assert!(!wal_path.exists());
        assert!(!shm_path.exists());

        assert!(matches!(
            AgentSessionCatalog::open(&path),
            Err(AgentSessionCatalogError::Ownership { .. })
        ));
        assert_eq!(fs::read(&path)?, database_before);
        assert!(!wal_path.exists());
        assert!(!shm_path.exists());
        cleanup(root)?;
        Ok(())
    }

    #[test]
    fn malformed_schema_and_path_are_rejected_fail_closed() -> Result<(), Box<dyn Error>> {
        let (root, path) = database("malformed")?;
        {
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "CREATE TABLE agent_sessions (session_id BLOB PRIMARY KEY);
                 PRAGMA application_id = 0x48464153;
                 PRAGMA user_version = 1;",
            )?;
        }
        let database_before = fs::read(&path)?;
        let wal_path = sidecar_path(&path, "-wal");
        let shm_path = sidecar_path(&path, "-shm");
        assert!(!wal_path.exists());
        assert!(!shm_path.exists());
        assert!(matches!(
            AgentSessionCatalog::open(&path),
            Err(AgentSessionCatalogError::Schema(_) | AgentSessionCatalogError::Ownership { .. })
        ));
        assert_eq!(fs::read(&path)?, database_before);
        assert!(!wal_path.exists());
        assert!(!shm_path.exists());

        let symlink_path = root.join("symlink.sqlite3");
        symlink(&path, &symlink_path)?;
        assert!(matches!(
            AgentSessionCatalog::open(&symlink_path),
            Err(AgentSessionCatalogError::DatabasePathSymlink(_))
        ));

        let hardlink_path = root.join("hardlink.sqlite3");
        hard_link(&path, &hardlink_path)?;
        assert!(matches!(
            AgentSessionCatalog::open(&hardlink_path),
            Err(AgentSessionCatalogError::DatabasePathHardlink { .. })
        ));
        cleanup(root)?;
        Ok(())
    }

    #[test]
    fn open_existing_does_not_create_an_unissued_catalog() -> Result<(), Box<dyn Error>> {
        let (root, path) = database("open-existing")?;
        assert!(AgentSessionCatalog::open_existing(&path)?.is_none());
        assert!(!path.exists());
        cleanup(root)?;
        Ok(())
    }
}
