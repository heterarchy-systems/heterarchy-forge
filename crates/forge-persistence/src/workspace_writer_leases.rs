//! Workspace-local durable Writer Lease authority for source mutation scopes.
//!
//! Expired Active leases held by another owner remain durable conflict fences.
//! Reacquisition by the same Workspace/Activity/Agent releases its expired
//! overlap atomically; other owners require explicit release/recovery.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use forge_domain::{
    AcquireWriterLease, ActivityId, ActivityLeaseRevision, AgentInstanceId, AgentSessionId,
    AuthenticatedPrincipal, MAX_WORKSPACE_RELATIVE_PATH_BYTES, MAX_WRITER_LEASE_SCOPE_ENTRIES,
    ReleaseWriterLease, RenewWriterLease, SourceWriteAuthority, TimestampMillis, WorkspaceId,
    WorkspaceRelativePath, WorkspaceRelativePathError, WriterLease, WriterLeaseId,
    WriterLeaseRevision, WriterLeaseScope, WriterLeaseScopeEntry, WriterLeaseScopeError,
    WriterLeaseScopeKind, WriterLeaseState, WriterLeaseStatus, WriterLeaseTransitionError,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agents::{self, AgentStoreError};

const ID_BYTES: usize = 16;
/// Defensive cap for all unreleased Writer Leases in one Workspace.
pub const MAX_ACTIVE_WRITER_LEASES: usize = 256;

const EXPECTED_WRITER_LEASES_TABLE_SQL: &str = "CREATE TABLE writer_leases (lease_id BLOB PRIMARY KEY NOT NULL CHECK(length(lease_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16), state INTEGER NOT NULL CHECK(state IN (0, 1)), acquired_at_ms INTEGER NOT NULL CHECK(acquired_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= acquired_at_ms), lease_until_ms INTEGER NOT NULL CHECK(lease_until_ms > acquired_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), UNIQUE(lease_id, workspace_id, activity_id, agent_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";
const EXPECTED_WRITER_LEASE_SCOPE_TABLE_SQL: &str = "CREATE TABLE writer_lease_scope_entries (lease_id BLOB NOT NULL REFERENCES writer_leases(lease_id) ON DELETE CASCADE CHECK(length(lease_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 63), scope_kind INTEGER NOT NULL CHECK(scope_kind IN (0, 1)), relative_path BLOB NOT NULL CHECK(length(relative_path) BETWEEN 1 AND 4096), PRIMARY KEY(lease_id, ordinal), UNIQUE(lease_id, scope_kind, relative_path))";
const EXPECTED_WRITER_LEASE_ACTIVE_INDEX_SQL: &str = "CREATE INDEX writer_leases_workspace_active_idx ON writer_leases(workspace_id, state, acquired_at_ms, lease_id)";

const OBJECTS: [(&str, &str, &str); 3] = [
    ("table", "writer_leases", EXPECTED_WRITER_LEASES_TABLE_SQL),
    (
        "table",
        "writer_lease_scope_entries",
        EXPECTED_WRITER_LEASE_SCOPE_TABLE_SQL,
    ),
    (
        "index",
        "writer_leases_workspace_active_idx",
        EXPECTED_WRITER_LEASE_ACTIVE_INDEX_SQL,
    ),
];

pub(crate) fn create_schema(connection: &Connection) -> Result<(), WriterLeaseStoreError> {
    for (_, _, sql) in OBJECTS {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "writer_leases"),
        ("table", "writer_lease_scope_entries"),
        ("index", "writer_leases_workspace_active_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), WriterLeaseStoreError> {
    for (kind, name, expected) in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(WriterLeaseStoreError::DamagedSchema(name));
        }
    }
    validate_columns(
        connection,
        "writer_leases",
        &[
            ("lease_id", "BLOB", 1, 1),
            ("workspace_id", "BLOB", 1, 0),
            ("activity_id", "BLOB", 1, 0),
            ("agent_id", "BLOB", 1, 0),
            ("state", "INTEGER", 1, 0),
            ("acquired_at_ms", "INTEGER", 1, 0),
            ("updated_at_ms", "INTEGER", 1, 0),
            ("lease_until_ms", "INTEGER", 1, 0),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "writer_lease_scope_entries",
        &[
            ("lease_id", "BLOB", 1, 1),
            ("ordinal", "INTEGER", 1, 2),
            ("scope_kind", "INTEGER", 1, 0),
            ("relative_path", "BLOB", 1, 0),
        ],
    )?;
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), WriterLeaseStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(WriterLeaseStoreError::DamagedSchema(table));
    }
    Ok(())
}

pub(crate) fn get(
    connection: &Connection,
    lease_id: WriterLeaseId,
) -> Result<Option<WriterLease>, WriterLeaseStoreError> {
    query_lease(connection, lease_id)
}

pub(crate) fn acquire(
    connection: &mut Connection,
    command: &AcquireWriterLease,
) -> Result<WriterLease, WriterLeaseStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_activity_and_agent(
        &transaction,
        WriterLeaseActorCheck {
            workspace_id: command.workspace_id(),
            activity_id: command.activity_id(),
            agent_id: command.agent_id(),
            session_id: command.session_id(),
            principal: command.principal(),
        },
    )?;

    if let Some(existing) = query_lease(&transaction, command.lease_id())? {
        if is_same_acquire(&existing, command) {
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(WriterLeaseStoreError::LeaseIdConflict(command.lease_id()));
    }
    crate::workspace_work_cuts::guards::ensure_lease_acquisition_open(
        &transaction,
        command.workspace_id(),
        command.agent_id(),
    )?;

    let candidate = WriterLease::acquire(command)?;
    loop {
        let Some(conflicting) = first_conflicting_active(&transaction, &candidate)? else {
            break;
        };
        if can_reconcile_expired_same_owner(&conflicting, &candidate, command.observed_at()) {
            release_expired_same_owner_in_transaction(
                &transaction,
                &conflicting,
                command.observed_at(),
            )?;
            continue;
        }
        return Err(WriterLeaseStoreError::ScopeConflict {
            conflicting_lease_id: conflicting.id(),
        });
    }

    transaction.execute(
        "INSERT INTO writer_leases (
             lease_id, workspace_id, activity_id, agent_id, state,
             acquired_at_ms, updated_at_ms, lease_until_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5, ?6, ?7)",
        params![
            uuid_bytes(candidate.id().into_uuid()).as_slice(),
            uuid_bytes(candidate.workspace_id().into_uuid()).as_slice(),
            uuid_bytes(candidate.activity_id().into_uuid()).as_slice(),
            uuid_bytes(candidate.agent_id().into_uuid()).as_slice(),
            candidate.acquired_at().get(),
            candidate.lease_until().get(),
            candidate.revision().get(),
        ],
    )?;
    insert_scope_entries(&transaction, candidate.id(), candidate.scope())?;
    transaction.commit()?;
    Ok(candidate)
}

pub(crate) fn renew(
    connection: &mut Connection,
    command: RenewWriterLease,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<WriterLease, WriterLeaseStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = query_lease(&transaction, command.lease_id())?
        .ok_or(WriterLeaseStoreError::LeaseMissing)?;
    validate_scope_identity(&existing, workspace_id, activity_id)?;
    validate_activity_and_agent(
        &transaction,
        WriterLeaseActorCheck {
            workspace_id,
            activity_id,
            agent_id: command.agent_id(),
            session_id: command.session_id(),
            principal: command.principal(),
        },
    )?;
    crate::workspace_work_cuts::guards::ensure_lease_renewal_open(
        &transaction,
        workspace_id,
        command.lease_id(),
    )?;
    let renewed = existing.renew(&command)?;
    let changed = transaction.execute(
        "UPDATE writer_leases
         SET updated_at_ms = ?1, lease_until_ms = ?2, revision = ?3
         WHERE lease_id = ?4 AND state = 0 AND revision = ?5",
        params![
            renewed.updated_at().get(),
            renewed.lease_until().get(),
            renewed.revision().get(),
            uuid_bytes(renewed.id().into_uuid()).as_slice(),
            existing.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(WriterLeaseStoreError::CompareAndSwapConflict);
    }
    transaction.commit()?;
    Ok(renewed)
}

pub(crate) fn release(
    connection: &mut Connection,
    command: ReleaseWriterLease,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<WriterLease, WriterLeaseStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = query_lease(&transaction, command.lease_id())?
        .ok_or(WriterLeaseStoreError::LeaseMissing)?;
    validate_scope_identity(&existing, workspace_id, activity_id)?;
    validate_activity_and_agent(
        &transaction,
        WriterLeaseActorCheck {
            workspace_id,
            activity_id,
            agent_id: command.agent_id(),
            session_id: command.session_id(),
            principal: command.principal(),
        },
    )?;
    let released = existing.release(&command)?;
    let changed = transaction.execute(
        "UPDATE writer_leases
         SET state = 1, updated_at_ms = ?1, revision = ?2
         WHERE lease_id = ?3 AND state = 0 AND revision = ?4",
        params![
            released.updated_at().get(),
            released.revision().get(),
            uuid_bytes(released.id().into_uuid()).as_slice(),
            existing.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(WriterLeaseStoreError::CompareAndSwapConflict);
    }
    transaction.commit()?;
    Ok(released)
}

/// Recovery-only release. This deliberately bypasses Activity/Agent liveness,
/// but still requires the exact durable revision so recovery cannot clear a
/// lease that changed after observation.
pub(crate) fn release_for_recovery(
    connection: &mut Connection,
    lease_id: WriterLeaseId,
    expected_revision: WriterLeaseRevision,
    observed_at: TimestampMillis,
) -> Result<WriterLease, WriterLeaseStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing =
        query_lease(&transaction, lease_id)?.ok_or(WriterLeaseStoreError::LeaseMissing)?;
    if existing.state() != WriterLeaseState::Active {
        return Err(WriterLeaseStoreError::LeaseReleased);
    }
    if observed_at < existing.lease_until() {
        return Err(WriterLeaseStoreError::WriterLeaseNotExpired);
    }
    if existing.revision() != expected_revision {
        return Err(WriterLeaseStoreError::CompareAndSwapConflict);
    }
    if observed_at < existing.updated_at() {
        return Err(WriterLeaseStoreError::RecoveryTimestampInversion);
    }
    let next_revision = existing.revision().checked_next()?;
    let changed = transaction.execute(
        "UPDATE writer_leases
         SET state = 1, updated_at_ms = ?1, revision = ?2
         WHERE lease_id = ?3 AND state = 0 AND revision = ?4",
        params![
            observed_at.get(),
            next_revision.get(),
            uuid_bytes(lease_id.into_uuid()).as_slice(),
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(WriterLeaseStoreError::CompareAndSwapConflict);
    }
    let released =
        query_lease(&transaction, lease_id)?.ok_or(WriterLeaseStoreError::LeaseMissing)?;
    transaction.commit()?;
    Ok(released)
}

pub(crate) fn list_active(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Vec<WriterLease>, WriterLeaseStoreError> {
    active_leases(connection, workspace_id)
}

/// Read a deterministic bounded page of active Writer Leases. The cursor is
/// the last returned lease identity; scope rows are decoded only for the
/// bounded page rather than for the Workspace's complete active set.
pub(crate) fn list_active_page(
    connection: &Connection,
    workspace_id: WorkspaceId,
    cursor: Option<WriterLeaseId>,
    limit: usize,
) -> Result<(Vec<WriterLease>, Option<WriterLeaseId>), WriterLeaseStoreError> {
    if limit == 0 || limit > MAX_ACTIVE_WRITER_LEASES {
        return Err(WriterLeaseStoreError::ActiveLeaseLimitExceeded);
    }
    let workspace = uuid_bytes(workspace_id.into_uuid());
    let cursor_bytes = cursor.map(|value| uuid_bytes(value.into_uuid()));
    let cursor_param = cursor_bytes.as_ref().map(<[u8; 16]>::as_slice);
    let fetch_limit =
        i64::try_from(limit + 1).map_err(|_| WriterLeaseStoreError::ActiveLeaseLimitExceeded)?;
    let mut statement = connection.prepare(
        "SELECT lease_id
         FROM writer_leases
         WHERE workspace_id = ?1 AND state = 0
           AND (?2 IS NULL OR lease_id > ?2)
         ORDER BY lease_id ASC
         LIMIT ?3",
    )?;
    let ids = statement
        .query_map(
            params![workspace.as_slice(), cursor_param, fetch_limit],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = ids.len() > limit;
    let ids = ids.into_iter().take(limit).collect::<Vec<_>>();
    let next_cursor = if has_more {
        ids.last()
            .map(|bytes| decode_uuid("writer_leases.lease_id", bytes))
            .transpose()?
            .map(WriterLeaseId::from_uuid)
    } else {
        None
    };
    let leases = ids
        .into_iter()
        .map(|bytes| {
            let id = WriterLeaseId::from_uuid(decode_uuid("writer_leases.lease_id", &bytes)?);
            query_lease(connection, id)?.ok_or(WriterLeaseStoreError::CorruptRecord(
                "writer lease disappeared during page snapshot",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((leases, next_cursor))
}

fn is_same_acquire(existing: &WriterLease, command: &AcquireWriterLease) -> bool {
    existing.state() == WriterLeaseState::Active
        && existing.workspace_id() == command.workspace_id()
        && existing.activity_id() == command.activity_id()
        && existing.agent_id() == command.agent_id()
        && existing.scope() == command.scope()
        && existing.acquired_at() == command.observed_at()
        && existing.lease_until() == command.lease_until()
}

fn validate_scope_identity(
    lease: &WriterLease,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), WriterLeaseStoreError> {
    if lease.workspace_id() != workspace_id {
        return Err(WriterLeaseStoreError::WorkspaceMismatch);
    }
    if lease.activity_id() != activity_id {
        return Err(WriterLeaseStoreError::ActivityMismatch);
    }
    Ok(())
}

fn can_reconcile_expired_same_owner(
    existing: &WriterLease,
    candidate: &WriterLease,
    observed_at: TimestampMillis,
) -> bool {
    existing.state() == WriterLeaseState::Active
        && existing.workspace_id() == candidate.workspace_id()
        && existing.activity_id() == candidate.activity_id()
        && existing.agent_id() == candidate.agent_id()
        && existing.lease_until() <= observed_at
}

fn release_expired_same_owner_in_transaction(
    transaction: &Transaction<'_>,
    existing: &WriterLease,
    observed_at: TimestampMillis,
) -> Result<(), WriterLeaseStoreError> {
    if existing.state() != WriterLeaseState::Active || observed_at < existing.lease_until() {
        return Err(WriterLeaseStoreError::CompareAndSwapConflict);
    }
    let next_revision = existing.revision().checked_next()?;
    let changed = transaction.execute(
        "UPDATE writer_leases
         SET state = 1, updated_at_ms = ?1, revision = ?2
         WHERE lease_id = ?3 AND state = 0 AND revision = ?4",
        params![
            observed_at.get(),
            next_revision.get(),
            uuid_bytes(existing.id().into_uuid()).as_slice(),
            existing.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(WriterLeaseStoreError::CompareAndSwapConflict);
    }
    Ok(())
}

fn first_conflicting_active(
    connection: &Connection,
    candidate: &WriterLease,
) -> Result<Option<WriterLease>, WriterLeaseStoreError> {
    Ok(active_leases(connection, candidate.workspace_id())?
        .into_iter()
        .find(|existing| existing.conflicts_with(candidate)))
}

fn active_leases(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Vec<WriterLease>, WriterLeaseStoreError> {
    let workspace = uuid_bytes(workspace_id.into_uuid());
    let mut statement = connection.prepare(
        "SELECT lease_id
         FROM writer_leases
         WHERE workspace_id = ?1 AND state = 0
         ORDER BY acquired_at_ms ASC, lease_id ASC
         LIMIT ?2",
    )?;
    let limit = i64::try_from(MAX_ACTIVE_WRITER_LEASES + 1)
        .map_err(|_| WriterLeaseStoreError::ActiveLeaseLimitExceeded)?;
    let ids = statement
        .query_map(params![workspace.as_slice(), limit], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > MAX_ACTIVE_WRITER_LEASES {
        return Err(WriterLeaseStoreError::ActiveLeaseLimitExceeded);
    }
    ids.into_iter()
        .map(|bytes| {
            let id = WriterLeaseId::from_uuid(decode_uuid("writer_leases.lease_id", &bytes)?);
            query_lease(connection, id)?.ok_or(WriterLeaseStoreError::CorruptRecord(
                "writer lease disappeared during snapshot",
            ))
        })
        .collect()
}

fn query_lease(
    connection: &Connection,
    lease_id: WriterLeaseId,
) -> Result<Option<WriterLease>, WriterLeaseStoreError> {
    let lease = uuid_bytes(lease_id.into_uuid());
    let raw = connection
        .query_row(
            "SELECT lease_id, workspace_id, activity_id, agent_id, state,
                    acquired_at_ms, updated_at_ms, lease_until_ms, revision
             FROM writer_leases WHERE lease_id = ?1",
            params![lease.as_slice()],
            decode_lease_row,
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let scope = load_scope_entries(connection, lease_id)?;
    Ok(Some(WriterLease::from_parts(
        WriterLeaseId::from_uuid(decode_uuid("writer_leases.lease_id", &raw.lease_id)?),
        WorkspaceId::from_uuid(decode_uuid(
            "writer_leases.workspace_id",
            &raw.workspace_id,
        )?),
        ActivityId::from_uuid(decode_uuid("writer_leases.activity_id", &raw.activity_id)?),
        AgentInstanceId::from_uuid(decode_uuid("writer_leases.agent_id", &raw.agent_id)?),
        scope,
        decode_state(raw.state)?,
        TimestampMillis::new(raw.acquired_at_ms)
            .map_err(|_| WriterLeaseStoreError::CorruptRecord("writer_leases.acquired_at_ms"))?,
        TimestampMillis::new(raw.updated_at_ms)
            .map_err(|_| WriterLeaseStoreError::CorruptRecord("writer_leases.updated_at_ms"))?,
        TimestampMillis::new(raw.lease_until_ms)
            .map_err(|_| WriterLeaseStoreError::CorruptRecord("writer_leases.lease_until_ms"))?,
        WriterLeaseRevision::new(raw.revision)?,
    )?))
}

struct RawWriterLease {
    lease_id: Vec<u8>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    agent_id: Vec<u8>,
    state: i64,
    acquired_at_ms: i64,
    updated_at_ms: i64,
    lease_until_ms: i64,
    revision: i64,
}

fn decode_lease_row(row: &Row<'_>) -> rusqlite::Result<RawWriterLease> {
    Ok(RawWriterLease {
        lease_id: row.get(0)?,
        workspace_id: row.get(1)?,
        activity_id: row.get(2)?,
        agent_id: row.get(3)?,
        state: row.get(4)?,
        acquired_at_ms: row.get(5)?,
        updated_at_ms: row.get(6)?,
        lease_until_ms: row.get(7)?,
        revision: row.get(8)?,
    })
}

fn insert_scope_entries(
    transaction: &Transaction<'_>,
    lease_id: WriterLeaseId,
    scope: &WriterLeaseScope,
) -> Result<(), WriterLeaseStoreError> {
    let lease = uuid_bytes(lease_id.into_uuid());
    for (ordinal, entry) in scope.entries().iter().enumerate() {
        transaction.execute(
            "INSERT INTO writer_lease_scope_entries
             (lease_id, ordinal, scope_kind, relative_path)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                lease.as_slice(),
                i64::try_from(ordinal).map_err(|_| WriterLeaseStoreError::ScopeOrdinalOverflow)?,
                encode_scope_kind(entry.kind()),
                entry.path().as_path().as_os_str().as_bytes(),
            ],
        )?;
    }
    Ok(())
}

fn load_scope_entries(
    connection: &Connection,
    lease_id: WriterLeaseId,
) -> Result<WriterLeaseScope, WriterLeaseStoreError> {
    let lease = uuid_bytes(lease_id.into_uuid());
    let mut statement = connection.prepare(
        "SELECT ordinal, scope_kind, relative_path
         FROM writer_lease_scope_entries
         WHERE lease_id = ?1
         ORDER BY ordinal ASC
         LIMIT ?2",
    )?;
    let limit = i64::try_from(MAX_WRITER_LEASE_SCOPE_ENTRIES + 1)
        .map_err(|_| WriterLeaseStoreError::ScopeOrdinalOverflow)?;
    let raw = statement
        .query_map(params![lease.as_slice(), limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if raw.len() > MAX_WRITER_LEASE_SCOPE_ENTRIES {
        return Err(WriterLeaseStoreError::ScopeLimitExceeded);
    }
    let mut entries = Vec::with_capacity(raw.len());
    for (expected, (ordinal, kind, path)) in raw.into_iter().enumerate() {
        if ordinal
            != i64::try_from(expected).map_err(|_| WriterLeaseStoreError::ScopeOrdinalOverflow)?
        {
            return Err(WriterLeaseStoreError::CorruptRecord(
                "writer_lease_scope_entries.ordinal",
            ));
        }
        if path.is_empty() || path.len() > MAX_WORKSPACE_RELATIVE_PATH_BYTES {
            return Err(WriterLeaseStoreError::CorruptRecord(
                "writer_lease_scope_entries.relative_path",
            ));
        }
        let path = WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(path)))?;
        entries.push(WriterLeaseScopeEntry::new(decode_scope_kind(kind)?, path));
    }
    WriterLeaseScope::new(entries).map_err(WriterLeaseStoreError::from)
}

#[derive(Clone, Copy)]
struct WriterLeaseActorCheck {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

fn validate_activity_and_agent(
    transaction: &Transaction<'_>,
    check: WriterLeaseActorCheck,
) -> Result<(), WriterLeaseStoreError> {
    let WriterLeaseActorCheck {
        workspace_id,
        activity_id,
        agent_id,
        session_id,
        principal,
    } = check;
    let activity = transaction
        .query_row(
            "SELECT workspace_id, state, lease_revision
             FROM activities WHERE activity_id = ?1",
            params![uuid_bytes(activity_id.into_uuid()).as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(WriterLeaseStoreError::ActivityMissing)?;
    if WorkspaceId::from_uuid(decode_uuid("activities.workspace_id", &activity.0)?) != workspace_id
    {
        return Err(WriterLeaseStoreError::ActivityWorkspaceMismatch);
    }
    if activity.1 != 1 {
        return Err(WriterLeaseStoreError::ActivityNotOpen);
    }
    ActivityLeaseRevision::new(activity.2)
        .map_err(|_| WriterLeaseStoreError::CorruptRecord("activities.lease_revision"))?;

    let agent = workspace_agents::get_in_transaction(transaction, agent_id)?
        .ok_or(WriterLeaseStoreError::AgentMissing)?;
    if agent.workspace_id() != workspace_id || agent.activity_id() != activity_id {
        return Err(WriterLeaseStoreError::AgentScopeMismatch);
    }
    if !agent.attachment_state().is_attached() {
        return Err(WriterLeaseStoreError::AgentDetached);
    }
    if agent.session_id() != Some(session_id) || agent.principal() != principal {
        return Err(WriterLeaseStoreError::AgentAuthorityConflict);
    }
    Ok(())
}

/// Validate exact Agent work authority and Writer Lease coverage inside the
/// caller's durable mutation transaction.
pub(crate) fn authorize_source_write(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    authority: SourceWriteAuthority,
    observed_at: TimestampMillis,
    paths: &[&WorkspaceRelativePath],
) -> Result<(), WriterLeaseStoreError> {
    let agent = workspace_agents::get_in_transaction(connection, authority.agent_id())?
        .ok_or(WriterLeaseStoreError::AgentMissing)?;
    if agent.workspace_id() != workspace_id || agent.activity_id() != activity_id {
        return Err(WriterLeaseStoreError::AgentScopeMismatch);
    }
    if !agent.attachment_state().is_attached() {
        return Err(WriterLeaseStoreError::AgentDetached);
    }
    if agent.revision() != authority.expected_agent_revision()
        || agent.principal() != authority.principal()
        || agent.session_id() != Some(authority.session_id())
    {
        return Err(WriterLeaseStoreError::AgentAuthorityConflict);
    }
    let focus = agent.focus();
    let attribution = authority.attribution();
    let Some(goal) = focus.goal() else {
        return Err(WriterLeaseStoreError::AgentFocusConflict);
    };
    let Some(dag_revision) = focus.dag_revision() else {
        return Err(WriterLeaseStoreError::AgentFocusConflict);
    };
    let Some(node) = focus.node() else {
        return Err(WriterLeaseStoreError::AgentFocusConflict);
    };
    if goal.goal_id() != attribution.goal_id()
        || goal.expected_revision() != attribution.expected_goal_revision()
        || dag_revision != attribution.dag_revision()
        || node.node_id() != attribution.node_id()
        || node.expected_revision() != attribution.expected_node_revision()
    {
        return Err(WriterLeaseStoreError::AgentFocusConflict);
    }

    let lease = query_lease(connection, authority.writer_lease_id())?
        .ok_or(WriterLeaseStoreError::LeaseMissing)?;
    if lease.workspace_id() != workspace_id {
        return Err(WriterLeaseStoreError::WorkspaceMismatch);
    }
    if lease.activity_id() != activity_id {
        return Err(WriterLeaseStoreError::ActivityMismatch);
    }
    if lease.agent_id() != authority.agent_id() {
        return Err(WriterLeaseStoreError::AgentAuthorityConflict);
    }
    if lease.revision() != authority.expected_writer_lease_revision() {
        return Err(WriterLeaseStoreError::WriterLeaseRevisionConflict);
    }
    match lease.status(observed_at) {
        WriterLeaseStatus::Active => {}
        WriterLeaseStatus::Released => return Err(WriterLeaseStoreError::LeaseReleased),
        WriterLeaseStatus::ExpiredRecoveryRequired => {
            return Err(WriterLeaseStoreError::ExpiredRecoveryRequired);
        }
    }
    if paths.is_empty() || paths.iter().any(|path| !lease.scope().covers(path)) {
        return Err(WriterLeaseStoreError::ScopeNotCovered);
    }
    Ok(())
}

const fn encode_scope_kind(kind: WriterLeaseScopeKind) -> i64 {
    match kind {
        WriterLeaseScopeKind::ExactPath => 0,
        WriterLeaseScopeKind::DirectorySubtree => 1,
    }
}

fn decode_scope_kind(value: i64) -> Result<WriterLeaseScopeKind, WriterLeaseStoreError> {
    match value {
        0 => Ok(WriterLeaseScopeKind::ExactPath),
        1 => Ok(WriterLeaseScopeKind::DirectorySubtree),
        _ => Err(WriterLeaseStoreError::CorruptRecord(
            "writer_lease_scope_entries.scope_kind",
        )),
    }
}

fn decode_state(value: i64) -> Result<WriterLeaseState, WriterLeaseStoreError> {
    match value {
        0 => Ok(WriterLeaseState::Active),
        1 => Ok(WriterLeaseState::Released),
        _ => Err(WriterLeaseStoreError::CorruptRecord("writer_leases.state")),
    }
}

fn uuid_bytes(value: Uuid) -> [u8; ID_BYTES] {
    value.into_bytes()
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, WriterLeaseStoreError> {
    let bytes: [u8; ID_BYTES] = value
        .try_into()
        .map_err(|_| WriterLeaseStoreError::CorruptRecord(field))?;
    Ok(Uuid::from_bytes(bytes))
}

#[derive(Debug, Error)]
pub enum WriterLeaseStoreError {
    #[error(transparent)]
    WorkCut(#[from] Box<crate::WorkCutError>),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    Scope(#[from] WriterLeaseScopeError),
    #[error(transparent)]
    Path(#[from] WorkspaceRelativePathError),
    #[error(transparent)]
    Domain(#[from] forge_domain::WriterLeaseError),
    #[error(transparent)]
    Transition(#[from] WriterLeaseTransitionError),
    #[error(transparent)]
    Revision(#[from] forge_domain::WriterLeaseRevisionError),
    #[error("Writer Lease schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("Writer Lease durable record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Writer Lease ID already identifies a different lease: {0}")]
    LeaseIdConflict(WriterLeaseId),
    #[error("Writer Lease does not exist")]
    LeaseMissing,
    #[error("Writer Lease is already released")]
    LeaseReleased,
    #[error("Writer Lease Workspace does not match the requested scope")]
    WorkspaceMismatch,
    #[error("Writer Lease Activity does not match the requested scope")]
    ActivityMismatch,
    #[error("Writer Lease scope conflicts with active lease {conflicting_lease_id}")]
    ScopeConflict { conflicting_lease_id: WriterLeaseId },
    #[error("Writer Lease active-set exceeds the bounded Workspace capacity")]
    ActiveLeaseLimitExceeded,
    #[error("Writer Lease scope exceeds the bounded entry capacity")]
    ScopeLimitExceeded,
    #[error("Writer Lease scope ordinal cannot be represented")]
    ScopeOrdinalOverflow,
    #[error("Activity does not exist")]
    ActivityMissing,
    #[error("Activity belongs to another Workspace")]
    ActivityWorkspaceMismatch,
    #[error("Activity is not open")]
    ActivityNotOpen,
    #[error("Activity lease is unavailable")]
    ActivityLeaseUnavailable,
    #[error("Activity lease owner does not match")]
    ActivityLeaseOwnerMismatch,
    #[error("Activity lease is expired")]
    ActivityLeaseExpired,
    #[error("Writer Lease Agent does not exist")]
    AgentMissing,
    #[error("Writer Lease Agent is attached to another Workspace/Activity")]
    AgentScopeMismatch,
    #[error("Writer Lease Agent is detached")]
    AgentDetached,
    #[error("Writer Lease Agent revision/principal authority is stale")]
    AgentAuthorityConflict,
    #[error("Writer Lease Agent Goal/DAG/node focus is stale")]
    AgentFocusConflict,
    #[error("Writer Lease revision is stale")]
    WriterLeaseRevisionConflict,
    #[error("Writer Lease expired and requires explicit recovery")]
    ExpiredRecoveryRequired,
    #[error("Writer Lease scope does not cover every requested source path")]
    ScopeNotCovered,
    #[error("Writer Lease compare-and-set found a changed row")]
    CompareAndSwapConflict,
    #[error("Writer Lease recovery timestamp precedes the current durable update")]
    RecoveryTimestampInversion,
    #[error("Writer Lease has not expired at the recovery observation timestamp")]
    WriterLeaseNotExpired,
}

impl From<crate::WorkCutError> for WriterLeaseStoreError {
    fn from(error: crate::WorkCutError) -> Self {
        Self::WorkCut(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use forge_domain::{
        AcquireWriterLease, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, DirectTokenId,
        ReleaseWriterLease, RenewWriterLease, RuntimeInstanceId, TimestampMillis, WorkspaceId,
        WorkspaceRelativePath, WriterLeaseDurationMillis, WriterLeaseId, WriterLeaseScope,
        WriterLeaseScopeEntry, WriterLeaseScopeKind, WriterLeaseState, WriterLeaseStatus,
    };
    use rusqlite::{Connection, params};
    use uuid::Uuid;

    use super::{
        WriterLeaseStoreError, acquire, create_schema, get, list_active, list_active_page, release,
        release_for_recovery, renew,
    };
    use crate::workspace_agents;

    struct Fixture {
        connection: Connection,
        workspace_id: WorkspaceId,
        activity_id: forge_domain::ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "CREATE TABLE workspace (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                workspace_id BLOB NOT NULL UNIQUE CHECK(length(workspace_id) = 16)
             );
             CREATE TABLE activities (
                activity_id BLOB PRIMARY KEY NOT NULL CHECK(length(activity_id) = 16),
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
                state INTEGER NOT NULL,
                lease_owner_id BLOB,
                lease_until_ms INTEGER,
                lease_revision INTEGER NOT NULL
             );
             CREATE TABLE goals (
                goal_id BLOB PRIMARY KEY NOT NULL CHECK(length(goal_id) = 16)
             );
             CREATE TABLE goal_dag_revisions (
                goal_id BLOB NOT NULL,
                dag_revision INTEGER NOT NULL,
                PRIMARY KEY(goal_id, dag_revision)
             );
             CREATE TABLE goal_dag_nodes (
                goal_id BLOB NOT NULL,
                dag_revision INTEGER NOT NULL,
                node_id BLOB NOT NULL CHECK(length(node_id) = 16),
                PRIMARY KEY(goal_id, dag_revision, node_id)
             );",
        )?;
        workspace_agents::create_schema(&connection)?;
        create_schema(&connection)?;
        crate::workspace_work_cuts::create_schema(&connection)?;

        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x100));
        let activity_id = forge_domain::ActivityId::from_uuid(Uuid::from_u128(0x200));
        let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(0x300));
        let session_id = AgentSessionId::from_uuid(Uuid::from_u128(0x500));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0x400));
        connection.execute(
            "INSERT INTO workspace (singleton, workspace_id) VALUES (1, ?1)",
            params![workspace_id.into_uuid().into_bytes().as_slice()],
        )?;
        connection.execute(
            "INSERT INTO activities (
                 activity_id, workspace_id, state, lease_owner_id, lease_until_ms, lease_revision
             ) VALUES (?1, ?2, 1, ?3, 100000, 1)",
            params![
                activity_id.into_uuid().into_bytes().as_slice(),
                workspace_id.into_uuid().into_bytes().as_slice(),
                runtime_id.into_uuid().into_bytes().as_slice(),
            ],
        )?;
        insert_writer_agent(&connection, workspace_id, activity_id, agent_id, session_id)?;
        Ok(Fixture {
            connection,
            workspace_id,
            activity_id,
            agent_id,
            session_id,
        })
    }

    fn insert_writer_agent(
        connection: &Connection,
        workspace_id: WorkspaceId,
        activity_id: forge_domain::ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        connection.execute(
            "INSERT INTO agent_instances (
                 agent_id, workspace_id, activity_id, session_id, display_name, declared_role,
                 transport_kind, principal_kind, principal_id, attachment_state,
                 focus_goal_id, focus_goal_revision, focus_dag_revision,
                 focus_node_id, focus_node_revision, created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, 'Writer', 'worker', 0, 0, NULL, 0,
                       NULL, NULL, NULL, NULL, NULL, 1, 1, 1)",
            params![
                agent_id.into_uuid().into_bytes().as_slice(),
                workspace_id.into_uuid().into_bytes().as_slice(),
                activity_id.into_uuid().into_bytes().as_slice(),
                session_id.into_uuid().into_bytes().as_slice(),
            ],
        )?;
        Ok(())
    }

    fn exact(path: &str) -> Result<WriterLeaseScope, Box<dyn std::error::Error>> {
        Ok(WriterLeaseScope::new(vec![WriterLeaseScopeEntry::new(
            WriterLeaseScopeKind::ExactPath,
            WorkspaceRelativePath::new(PathBuf::from(path))?,
        )])?)
    }

    fn subtree(path: &str) -> Result<WriterLeaseScope, Box<dyn std::error::Error>> {
        Ok(WriterLeaseScope::new(vec![WriterLeaseScopeEntry::new(
            WriterLeaseScopeKind::DirectorySubtree,
            WorkspaceRelativePath::new(PathBuf::from(path))?,
        )])?)
    }

    fn command(
        fixture: &Fixture,
        id: u128,
        scope: WriterLeaseScope,
        observed_at: i64,
        duration: i64,
    ) -> Result<AcquireWriterLease, Box<dyn std::error::Error>> {
        command_with_identity(
            fixture,
            id,
            scope,
            observed_at,
            duration,
            fixture.session_id,
            AuthenticatedPrincipal::TrustedStdio,
        )
    }

    fn command_with_identity(
        fixture: &Fixture,
        id: u128,
        scope: WriterLeaseScope,
        observed_at: i64,
        duration: i64,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<AcquireWriterLease, Box<dyn std::error::Error>> {
        Ok(AcquireWriterLease::new(
            WriterLeaseId::from_uuid(Uuid::from_u128(id)),
            fixture.workspace_id,
            fixture.activity_id,
            fixture.agent_id,
            scope,
            WriterLeaseDurationMillis::new(duration)?,
            TimestampMillis::new(observed_at)?,
            session_id,
            principal,
        )?)
    }

    #[test]
    fn disjoint_scopes_can_be_acquired_together() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let first = command(&fixture, 1, subtree("src")?, 1_000, 5_000)?;
        let second = command(&fixture, 2, subtree("tests")?, 1_100, 5_000)?;
        acquire(&mut fixture.connection, &first)?;
        acquire(&mut fixture.connection, &second)?;
        assert_eq!(
            list_active(&fixture.connection, fixture.workspace_id)?.len(),
            2
        );
        Ok(())
    }

    #[test]
    fn active_writer_lease_pages_are_cursor_ordered_without_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        for index in 0..5_u128 {
            let command = command(
                &fixture,
                0x700 + index,
                exact(&format!("page-{index}.txt"))?,
                1_000,
                60_000,
            )?;
            acquire(&mut fixture.connection, &command)?;
        }
        let (first, cursor) = list_active_page(&fixture.connection, fixture.workspace_id, None, 4)?;
        assert_eq!(first.len(), 4);
        let cursor = cursor.ok_or("first Writer Lease page lacked a cursor")?;
        assert!(
            first
                .windows(2)
                .all(|leases| leases[0].id() < leases[1].id())
        );
        let (second, next_cursor) =
            list_active_page(&fixture.connection, fixture.workspace_id, Some(cursor), 4)?;
        assert_eq!(second.len(), 1);
        assert!(next_cursor.is_none());
        assert!(first.iter().all(|lease| second[0].id() != lease.id()));
        Ok(())
    }

    #[test]
    fn acquire_uses_current_activity_lease_after_stale_revision_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let lease = command(&fixture, 3, exact("src/lib.rs")?, 1_000, 5_000)?;
        let observed_revision: i64 = fixture.connection.query_row(
            "SELECT lease_revision FROM activities WHERE activity_id = ?1",
            params![fixture.activity_id.into_uuid().into_bytes().as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(observed_revision, 1);
        fixture.connection.execute(
            "UPDATE activities SET lease_revision = lease_revision + 1 WHERE activity_id = ?1",
            params![fixture.activity_id.into_uuid().into_bytes().as_slice()],
        )?;
        let current_revision: i64 = fixture.connection.query_row(
            "SELECT lease_revision FROM activities WHERE activity_id = ?1",
            params![fixture.activity_id.into_uuid().into_bytes().as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(current_revision, 2);
        assert_ne!(observed_revision, current_revision);

        let acquired = acquire(&mut fixture.connection, &lease)?;
        assert_eq!(acquired.id(), lease.lease_id());
        Ok(())
    }

    #[test]
    fn acquire_ignores_activity_heartbeat_owner_and_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        fixture.connection.execute(
            "UPDATE activities SET lease_owner_id = ?1, lease_until_ms = 1
             WHERE activity_id = ?2",
            params![
                Uuid::from_u128(0xFFFF).as_bytes(),
                fixture.activity_id.into_uuid().as_bytes(),
            ],
        )?;
        let lease = command(&fixture, 33, exact("src/lib.rs")?, 1_000, 5_000)?;
        let acquired = acquire(&mut fixture.connection, &lease)?;
        assert_eq!(acquired.id(), lease.lease_id());
        Ok(())
    }

    #[test]
    fn wrong_session_is_rejected_inside_writer_lease_transaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let lease = command_with_identity(
            &fixture,
            4,
            exact("src/lib.rs")?,
            1_000,
            5_000,
            AgentSessionId::from_uuid(Uuid::from_u128(0x501)),
            AuthenticatedPrincipal::TrustedStdio,
        )?;

        assert!(matches!(
            acquire(&mut fixture.connection, &lease),
            Err(WriterLeaseStoreError::AgentAuthorityConflict)
        ));
        assert!(get(&fixture.connection, lease.lease_id())?.is_none());
        Ok(())
    }

    #[test]
    fn unresolved_legacy_session_is_rejected_before_writer_lease_insert()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        fixture.connection.execute(
            "UPDATE agent_instances SET session_id = NULL WHERE agent_id = ?1",
            params![fixture.agent_id.into_uuid().into_bytes().as_slice()],
        )?;
        let lease = command(&fixture, 5, exact("src/lib.rs")?, 1_000, 5_000)?;

        assert!(matches!(
            acquire(&mut fixture.connection, &lease),
            Err(WriterLeaseStoreError::AgentAuthorityConflict)
        ));
        assert!(get(&fixture.connection, lease.lease_id())?.is_none());
        Ok(())
    }

    #[test]
    fn principal_mismatch_is_rejected_before_writer_lease_insert()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let lease = command_with_identity(
            &fixture,
            6,
            exact("src/lib.rs")?,
            1_000,
            5_000,
            fixture.session_id,
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(0x502))),
        )?;

        assert!(matches!(
            acquire(&mut fixture.connection, &lease),
            Err(WriterLeaseStoreError::AgentAuthorityConflict)
        ));
        assert!(get(&fixture.connection, lease.lease_id())?.is_none());
        Ok(())
    }

    #[test]
    fn renew_and_release_reject_wrong_session_inside_their_transactions()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let command = command(&fixture, 7, exact("src/lib.rs")?, 1_000, 5_000)?;
        let acquired = acquire(&mut fixture.connection, &command)?;
        let wrong_session = AgentSessionId::from_uuid(Uuid::from_u128(0x503));
        let renewal = RenewWriterLease::new(
            acquired.id(),
            acquired.agent_id(),
            acquired.revision(),
            WriterLeaseDurationMillis::new(5_000)?,
            TimestampMillis::new(1_100)?,
            wrong_session,
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        assert!(matches!(
            renew(
                &mut fixture.connection,
                renewal,
                fixture.workspace_id,
                fixture.activity_id,
            ),
            Err(WriterLeaseStoreError::AgentAuthorityConflict)
        ));
        let release_command = ReleaseWriterLease::new(
            acquired.id(),
            acquired.agent_id(),
            acquired.revision(),
            TimestampMillis::new(1_100)?,
            wrong_session,
            AuthenticatedPrincipal::TrustedStdio,
        );
        assert!(matches!(
            release(
                &mut fixture.connection,
                release_command,
                fixture.workspace_id,
                fixture.activity_id,
            ),
            Err(WriterLeaseStoreError::AgentAuthorityConflict)
        ));
        let persisted = get(&fixture.connection, acquired.id())?.ok_or("lease missing")?;
        assert_eq!(persisted.revision(), acquired.revision());
        assert_eq!(persisted.state(), WriterLeaseState::Active);
        Ok(())
    }

    #[test]
    fn expired_foreign_owner_overlap_remains_fenced_until_explicit_recovery_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let first = command(&fixture, 11, subtree("src")?, 1_000, 1_000)?;
        fixture.agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(0x301));
        fixture.session_id = AgentSessionId::from_uuid(Uuid::from_u128(0x501));
        insert_writer_agent(
            &fixture.connection,
            fixture.workspace_id,
            fixture.activity_id,
            fixture.agent_id,
            fixture.session_id,
        )?;
        let second = command(&fixture, 12, exact("src/lib.rs")?, 3_000, 1_000)?;
        let stored = acquire(&mut fixture.connection, &first)?;
        assert_eq!(
            stored.status(TimestampMillis::new(3_000)?),
            WriterLeaseStatus::ExpiredRecoveryRequired
        );
        assert!(matches!(
            acquire(&mut fixture.connection, &second),
            Err(WriterLeaseStoreError::ScopeConflict { .. })
        ));
        let released = release_for_recovery(
            &mut fixture.connection,
            stored.id(),
            stored.revision(),
            TimestampMillis::new(3_000)?,
        )?;
        assert_eq!(
            released.status(TimestampMillis::new(3_000)?),
            WriterLeaseStatus::Released
        );
        let acquired = acquire(&mut fixture.connection, &second)?;
        assert_eq!(acquired.id(), second.lease_id());
        Ok(())
    }

    #[test]
    fn recovery_release_rejects_live_lease_before_cas() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let command = command(&fixture, 21, exact("src/lib.rs")?, 1_000, 5_000)?;
        let stored = acquire(&mut fixture.connection, &command)?;
        assert!(matches!(
            release_for_recovery(
                &mut fixture.connection,
                stored.id(),
                stored.revision(),
                TimestampMillis::new(1_001)?,
            ),
            Err(WriterLeaseStoreError::WriterLeaseNotExpired)
        ));
        let persisted = get(&fixture.connection, stored.id())?.ok_or("lease missing")?;
        assert_eq!(persisted.state(), WriterLeaseState::Active);
        assert_eq!(persisted.revision(), stored.revision());
        Ok(())
    }

    #[test]
    fn expired_same_owner_overlap_is_released_during_reacquisition()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let first = command(&fixture, 31, subtree("src")?, 1_000, 1_000)?;
        let second = command(&fixture, 32, exact("src/lib.rs")?, 3_000, 1_000)?;
        let stored = acquire(&mut fixture.connection, &first)?;
        let acquired = acquire(&mut fixture.connection, &second)?;
        assert_eq!(acquired.id(), second.lease_id());
        let released = get(&fixture.connection, stored.id())?.ok_or("expired lease missing")?;
        assert_eq!(
            released.status(TimestampMillis::new(3_000)?),
            WriterLeaseStatus::Released
        );
        assert_eq!(released.revision(), stored.revision().checked_next()?);
        let active = list_active(&fixture.connection, fixture.workspace_id)?;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id(), acquired.id());
        Ok(())
    }

    #[test]
    fn detached_agent_cannot_acquire_source_authority() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        fixture.connection.execute(
            "UPDATE agent_instances SET attachment_state = 1, revision = 2 WHERE agent_id = ?1",
            params![fixture.agent_id.into_uuid().into_bytes().as_slice()],
        )?;
        let lease = command(&fixture, 21, exact("src/lib.rs")?, 1_000, 5_000)?;
        assert!(matches!(
            acquire(&mut fixture.connection, &lease),
            Err(WriterLeaseStoreError::AgentDetached)
        ));
        assert!(get(&fixture.connection, lease.lease_id())?.is_none());
        Ok(())
    }
}
