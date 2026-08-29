//! App-global `SQLite` authority for local MCP bearer-token metadata.
//!
//! Raw bearer values and the keyed-hash pepper are intentionally absent from
//! this schema and API.

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io};

use std::os::unix::fs::MetadataExt as _;

use forge_domain::{
    LocationId, McpTokenDigest, McpTokenId, McpTokenLabel, McpTokenLabelError, McpTokenRecordParts,
    McpTokenRevision, McpTokenRevisionError, McpTokenState, McpTokenTransitionError,
    McpTokenWorkspaceScope, RegisteredMcpToken, TimestampMillis, TimestampMillisError, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

const APPLICATION_ID: i64 = 0x4846_544b;
const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_MCP_TOKEN_CATALOG_RESULTS: usize = 256;

const TOKENS_TABLE_SQL: &str = r"
CREATE TABLE mcp_tokens (
    token_id BLOB PRIMARY KEY NOT NULL CHECK(length(token_id) = 16),
    token_digest BLOB NOT NULL UNIQUE CHECK(length(token_digest) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3)),
    label TEXT NOT NULL CHECK(length(CAST(label AS BLOB)) BETWEEN 1 AND 128),
    created_at_ms INTEGER NOT NULL,
    disabled_at_ms INTEGER,
    replacement_token_id BLOB REFERENCES mcp_tokens(token_id),
    revision INTEGER NOT NULL CHECK(revision > 0),
    CHECK(
        (state = 1 AND disabled_at_ms IS NULL AND replacement_token_id IS NULL)
        OR (state = 2 AND disabled_at_ms IS NOT NULL AND replacement_token_id IS NULL)
        OR (state = 3 AND disabled_at_ms IS NOT NULL AND replacement_token_id IS NOT NULL)
    ),
    CHECK(disabled_at_ms IS NULL OR disabled_at_ms >= created_at_ms),
    CHECK(replacement_token_id IS NULL OR replacement_token_id != token_id)
);
";

const SCOPES_TABLE_SQL: &str = r"
CREATE TABLE mcp_token_workspace_scopes (
    token_id BLOB NOT NULL REFERENCES mcp_tokens(token_id) ON DELETE CASCADE,
    location_id BLOB NOT NULL CHECK(length(location_id) = 16),
    workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16),
    PRIMARY KEY(token_id, location_id, workspace_id)
);
";

const TOKENS_INDEX_SQL: &str = r"
CREATE INDEX mcp_tokens_state_created_idx
ON mcp_tokens(state, created_at_ms DESC, token_id);
";

const SCOPES_INDEX_SQL: &str = r"
CREATE INDEX mcp_token_scopes_location_workspace_idx
ON mcp_token_workspace_scopes(location_id, workspace_id, token_id);
";

#[derive(Debug)]
pub struct McpTokenCatalog {
    path: PathBuf,
    connection: Connection,
}

impl McpTokenCatalog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, McpTokenCatalogError> {
        let path = path.as_ref().to_path_buf();
        validate_catalog_path(&path)?;
        let mut connection = Connection::open(&path)?;
        validate_catalog_path(&path)?;
        configure(&connection)?;
        initialize_or_validate(&mut connection)?;
        Ok(Self { path, connection })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn issue(&mut self, token: &RegisteredMcpToken) -> Result<(), McpTokenCatalogError> {
        if token.state() != McpTokenState::Active || token.revision() != McpTokenRevision::INITIAL {
            return Err(McpTokenCatalogError::InvalidIssueState);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_token(&transaction, token)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get(&self, id: McpTokenId) -> Result<Option<RegisteredMcpToken>, McpTokenCatalogError> {
        load_token(&self.connection, id)
    }

    pub fn find_active_by_digest(
        &self,
        digest: McpTokenDigest,
    ) -> Result<Option<RegisteredMcpToken>, McpTokenCatalogError> {
        let id = self
            .connection
            .query_row(
                "SELECT token_id FROM mcp_tokens WHERE token_digest = ?1 AND state = 1",
                params![digest.into_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|bytes| decode_token_id(&bytes))
            .transpose()?;
        id.map(|id| load_token(&self.connection, id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn list(&self, limit: usize) -> Result<Vec<RegisteredMcpToken>, McpTokenCatalogError> {
        if limit == 0 || limit > MAX_MCP_TOKEN_CATALOG_RESULTS {
            return Err(McpTokenCatalogError::InvalidLimit(limit));
        }
        let limit = i64::try_from(limit).map_err(|_| McpTokenCatalogError::InvalidLimit(limit))?;
        let mut statement = self.connection.prepare(
            "SELECT token_id FROM mcp_tokens ORDER BY created_at_ms DESC, token_id LIMIT ?1",
        )?;
        let ids = statement
            .query_map(params![limit], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|bytes| {
                let id = decode_token_id(&bytes)?;
                load_token(&self.connection, id)?.ok_or(McpTokenCatalogError::TokenMissing(id))
            })
            .collect()
    }

    pub fn revoke(
        &mut self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<RegisteredMcpToken, McpTokenCatalogError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            load_token(&transaction, id)?.ok_or(McpTokenCatalogError::TokenMissing(id))?;
        let updated = current.revoke(expected_revision, disabled_at)?;
        update_terminal(&transaction, &updated, expected_revision)?;
        transaction.commit()?;
        Ok(updated)
    }

    pub fn rotate(
        &mut self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        replacement: &RegisteredMcpToken,
        disabled_at: TimestampMillis,
    ) -> Result<(RegisteredMcpToken, RegisteredMcpToken), McpTokenCatalogError> {
        if replacement.state() != McpTokenState::Active
            || replacement.revision() != McpTokenRevision::INITIAL
        {
            return Err(McpTokenCatalogError::InvalidIssueState);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            load_token(&transaction, id)?.ok_or(McpTokenCatalogError::TokenMissing(id))?;
        let rotated = current.rotate(replacement.id(), expected_revision, disabled_at)?;
        insert_token(&transaction, replacement)?;
        update_terminal(&transaction, &rotated, expected_revision)?;
        transaction.commit()?;
        Ok((rotated, replacement.clone()))
    }
}

fn validate_catalog_path(path: &Path) -> Result<(), McpTokenCatalogError> {
    let parent = path
        .parent()
        .ok_or_else(|| McpTokenCatalogError::InvalidPath(path.to_path_buf()))?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|source| McpTokenCatalogError::PathIo {
            path: parent.to_path_buf(),
            source,
        })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(McpTokenCatalogError::InvalidPath(parent.to_path_buf()));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() != 1
            {
                return Err(McpTokenCatalogError::InvalidPath(path.to_path_buf()));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(McpTokenCatalogError::PathIo {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

fn configure(connection: &Connection) -> Result<(), McpTokenCatalogError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn initialize_or_validate(connection: &mut Connection) -> Result<(), McpTokenCatalogError> {
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
        (APPLICATION_ID, SCHEMA_VERSION, _) => validate_schema(connection),
        _ => Err(McpTokenCatalogError::Ownership {
            application_id,
            user_version,
        }),
    }
}

fn create_schema(connection: &mut Connection) -> Result<(), McpTokenCatalogError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(TOKENS_TABLE_SQL)?;
    transaction.execute_batch(SCOPES_TABLE_SQL)?;
    transaction.execute_batch(TOKENS_INDEX_SQL)?;
    transaction.execute_batch(SCOPES_INDEX_SQL)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    validate_schema(connection)
}

fn validate_schema(connection: &Connection) -> Result<(), McpTokenCatalogError> {
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(McpTokenCatalogError::Integrity);
    }
    validate_schema_sql(connection, "table", "mcp_tokens", TOKENS_TABLE_SQL)?;
    validate_schema_sql(
        connection,
        "table",
        "mcp_token_workspace_scopes",
        SCOPES_TABLE_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "mcp_tokens_state_created_idx",
        TOKENS_INDEX_SQL,
    )?;
    validate_schema_sql(
        connection,
        "index",
        "mcp_token_scopes_location_workspace_idx",
        SCOPES_INDEX_SQL,
    )?;
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if foreign_key_violation {
        return Err(McpTokenCatalogError::Integrity);
    }
    Ok(())
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &str,
) -> Result<(), McpTokenCatalogError> {
    let actual = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) == Some(normalize_sql(expected)) {
        Ok(())
    } else {
        Err(McpTokenCatalogError::Schema(name))
    }
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

fn insert_token(
    transaction: &Transaction<'_>,
    token: &RegisteredMcpToken,
) -> Result<(), McpTokenCatalogError> {
    transaction.execute(
        "INSERT INTO mcp_tokens(token_id, token_digest, state, label, created_at_ms, disabled_at_ms, replacement_token_id, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            token.id().into_uuid().as_bytes(),
            token.digest().into_bytes().as_slice(),
            encode_state(token.state()),
            token.label().as_str(),
            token.created_at().get(),
            token.disabled_at().map(TimestampMillis::get),
            token.replacement_token_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            token.revision().get(),
        ],
    )?;
    for scope in token.scopes() {
        transaction.execute(
            "INSERT INTO mcp_token_workspace_scopes(token_id, location_id, workspace_id) VALUES (?1, ?2, ?3)",
            params![
                token.id().into_uuid().as_bytes(),
                scope.location_id().into_uuid().as_bytes(),
                scope.workspace_id().into_uuid().as_bytes(),
            ],
        )?;
    }
    Ok(())
}

fn update_terminal(
    transaction: &Transaction<'_>,
    token: &RegisteredMcpToken,
    expected_revision: McpTokenRevision,
) -> Result<(), McpTokenCatalogError> {
    let changed = transaction.execute(
        "UPDATE mcp_tokens SET state = ?1, disabled_at_ms = ?2, replacement_token_id = ?3, revision = ?4 WHERE token_id = ?5 AND revision = ?6 AND state = 1",
        params![
            encode_state(token.state()),
            token.disabled_at().map(TimestampMillis::get),
            token.replacement_token_id().map(|id| id.into_uuid().as_bytes().to_vec()),
            token.revision().get(),
            token.id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(McpTokenCatalogError::RevisionConflict);
    }
    Ok(())
}

fn load_token(
    connection: &Connection,
    id: McpTokenId,
) -> Result<Option<RegisteredMcpToken>, McpTokenCatalogError> {
    let raw = connection
        .query_row(
            "SELECT token_digest, state, label, created_at_ms, disabled_at_ms, replacement_token_id, revision FROM mcp_tokens WHERE token_id = ?1",
            params![id.into_uuid().as_bytes()],
            |row| {
                Ok(RawToken {
                    digest: row.get(0)?,
                    state: row.get(1)?,
                    label: row.get(2)?,
                    created_at: row.get(3)?,
                    disabled_at: row.get(4)?,
                    replacement_token_id: row.get(5)?,
                    revision: row.get(6)?,
                })
            },
        )
        .optional()?;
    raw.map(|raw| decode_token(connection, id, raw)).transpose()
}

#[derive(Debug)]
struct RawToken {
    digest: Vec<u8>,
    state: i64,
    label: String,
    created_at: i64,
    disabled_at: Option<i64>,
    replacement_token_id: Option<Vec<u8>>,
    revision: i64,
}

fn decode_token(
    connection: &Connection,
    id: McpTokenId,
    raw: RawToken,
) -> Result<RegisteredMcpToken, McpTokenCatalogError> {
    let digest_length = raw.digest.len();
    let digest = raw
        .digest
        .try_into()
        .map_err(|_| McpTokenCatalogError::InvalidDigestLength(digest_length))?;
    let scopes = load_scopes(connection, id)?;
    RegisteredMcpToken::from_parts(McpTokenRecordParts {
        id,
        label: McpTokenLabel::new(raw.label)?,
        digest: McpTokenDigest::new(digest),
        state: decode_state(raw.state)?,
        scopes,
        created_at: TimestampMillis::new(raw.created_at)?,
        disabled_at: raw.disabled_at.map(TimestampMillis::new).transpose()?,
        replacement_token_id: raw
            .replacement_token_id
            .map(|bytes| decode_token_id(&bytes))
            .transpose()?,
        revision: McpTokenRevision::new(raw.revision)?,
    })
    .map_err(McpTokenCatalogError::Transition)
}

fn load_scopes(
    connection: &Connection,
    id: McpTokenId,
) -> Result<Vec<McpTokenWorkspaceScope>, McpTokenCatalogError> {
    let mut statement = connection.prepare(
        "SELECT location_id, workspace_id FROM mcp_token_workspace_scopes WHERE token_id = ?1 ORDER BY location_id, workspace_id",
    )?;
    statement
        .query_map(params![id.into_uuid().as_bytes()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .map(|row| {
            let (location, workspace) = row?;
            Ok(McpTokenWorkspaceScope::new(
                LocationId::from_uuid(decode_uuid("location_id", &location)?),
                WorkspaceId::from_uuid(decode_uuid("workspace_id", &workspace)?),
            ))
        })
        .collect()
}

fn decode_token_id(bytes: &[u8]) -> Result<McpTokenId, McpTokenCatalogError> {
    Ok(McpTokenId::from_uuid(decode_uuid("token_id", bytes)?))
}

fn decode_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, McpTokenCatalogError> {
    Uuid::from_slice(bytes).map_err(|source| McpTokenCatalogError::Uuid { field, source })
}

const fn encode_state(state: McpTokenState) -> i64 {
    match state {
        McpTokenState::Active => 1,
        McpTokenState::Revoked => 2,
        McpTokenState::Rotated => 3,
    }
}

fn decode_state(value: i64) -> Result<McpTokenState, McpTokenCatalogError> {
    match value {
        1 => Ok(McpTokenState::Active),
        2 => Ok(McpTokenState::Revoked),
        3 => Ok(McpTokenState::Rotated),
        _ => Err(McpTokenCatalogError::InvalidState(value)),
    }
}

#[derive(Debug, Error)]
pub enum McpTokenCatalogError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("MCP token catalog path is unsafe: {0}")]
    InvalidPath(PathBuf),
    #[error("failed to inspect MCP token catalog path {path}")]
    PathIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "MCP token catalog ownership is invalid: application_id={application_id}, user_version={user_version}"
    )]
    Ownership {
        application_id: i64,
        user_version: i64,
    },
    #[error("MCP token catalog is missing required schema object {0}")]
    Schema(&'static str),
    #[error("MCP token catalog integrity check failed")]
    Integrity,
    #[error("MCP token issue requires a new active revision-one token")]
    InvalidIssueState,
    #[error("MCP token list limit is invalid: {0}")]
    InvalidLimit(usize),
    #[error("MCP token was not found: {0}")]
    TokenMissing(McpTokenId),
    #[error("MCP token revision conflict")]
    RevisionConflict,
    #[error("MCP token digest length is invalid: {0}")]
    InvalidDigestLength(usize),
    #[error("MCP token persisted state is invalid: {0}")]
    InvalidState(i64),
    #[error("MCP token UUID field {field} is invalid")]
    Uuid {
        field: &'static str,
        #[source]
        source: uuid::Error,
    },
    #[error(transparent)]
    Label(#[from] McpTokenLabelError),
    #[error(transparent)]
    Timestamp(#[from] TimestampMillisError),
    #[error(transparent)]
    Revision(#[from] McpTokenRevisionError),
    #[error(transparent)]
    Transition(#[from] McpTokenTransitionError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "heterarchy-forge-{name}-{}-{}.sqlite3",
            std::process::id(),
            Uuid::now_v7()
        ))
    }

    fn token(value: u128) -> Result<RegisteredMcpToken, Box<dyn std::error::Error>> {
        Ok(RegisteredMcpToken::issue(
            McpTokenId::from_uuid(Uuid::from_u128(value)),
            McpTokenLabel::new(format!("Token {value}"))?,
            McpTokenDigest::new([u8::try_from(value)?; forge_domain::MCP_TOKEN_DIGEST_BYTES]),
            vec![McpTokenWorkspaceScope::new(
                LocationId::from_uuid(Uuid::from_u128(value + 1)),
                WorkspaceId::from_uuid(Uuid::from_u128(value + 2)),
            )],
            TimestampMillis::new(i64::try_from(value)?)?,
        )?)
    }

    #[test]
    fn issue_lookup_list_and_reopen_are_durable() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("mcp-token-reopen");
        let first = token(10)?;
        let mut catalog = McpTokenCatalog::open(&database)?;
        catalog.issue(&first)?;
        assert_eq!(catalog.get(first.id())?, Some(first.clone()));
        assert_eq!(
            catalog.find_active_by_digest(first.digest())?,
            Some(first.clone())
        );
        assert_eq!(catalog.list(10)?, vec![first.clone()]);
        drop(catalog);
        let reopened = McpTokenCatalog::open(&database)?;
        assert_eq!(reopened.get(first.id())?, Some(first));
        drop(reopened);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn revoke_and_rotate_are_revision_bound_and_atomic() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("mcp-token-lifecycle");
        let first = token(20)?;
        let replacement = token(30)?;
        let mut catalog = McpTokenCatalog::open(&database)?;
        catalog.issue(&first)?;
        let (rotated, inserted) = catalog.rotate(
            first.id(),
            first.revision(),
            &replacement,
            TimestampMillis::new(40)?,
        )?;
        assert_eq!(rotated.state(), McpTokenState::Rotated);
        assert_eq!(inserted, replacement);
        assert!(catalog.find_active_by_digest(first.digest())?.is_none());
        let revoked = catalog.revoke(
            inserted.id(),
            inserted.revision(),
            TimestampMillis::new(50)?,
        )?;
        assert_eq!(revoked.state(), McpTokenState::Revoked);
        assert!(
            catalog
                .revoke(revoked.id(), revoked.revision(), TimestampMillis::new(51)?)
                .is_err()
        );
        drop(catalog);
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn corrupt_digest_and_foreign_schema_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let database = path("mcp-token-corrupt");
        let token = token(60)?;
        let mut catalog = McpTokenCatalog::open(&database)?;
        catalog.issue(&token)?;
        catalog
            .connection
            .pragma_update(None, "ignore_check_constraints", true)?;
        catalog.connection.execute(
            "UPDATE mcp_tokens SET token_digest = x'01' WHERE token_id = ?1",
            params![token.id().into_uuid().as_bytes()],
        )?;
        assert!(matches!(
            catalog.get(token.id()),
            Err(McpTokenCatalogError::InvalidDigestLength(1))
        ));
        drop(catalog);
        fs::remove_file(&database)?;

        let foreign = path("mcp-token-foreign");
        let connection = Connection::open(&foreign)?;
        connection.execute_batch("CREATE TABLE unrelated(value TEXT);")?;
        drop(connection);
        assert!(matches!(
            McpTokenCatalog::open(&foreign),
            Err(McpTokenCatalogError::Ownership { .. })
        ));
        fs::remove_file(foreign)?;
        Ok(())
    }

    #[test]
    fn catalog_rejects_symlink_database_path() -> Result<(), Box<dyn std::error::Error>> {
        let real = path("mcp-token-real");
        let linked = path("mcp-token-link");
        let catalog = McpTokenCatalog::open(&real)?;
        drop(catalog);
        symlink(&real, &linked)?;
        assert!(matches!(
            McpTokenCatalog::open(&linked),
            Err(McpTokenCatalogError::InvalidPath(_))
        ));
        fs::remove_file(linked)?;
        fs::remove_file(real)?;
        Ok(())
    }
}
