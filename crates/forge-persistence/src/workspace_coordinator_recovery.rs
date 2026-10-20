//! Durable, native-owner recovery of one Activity planning Coordinator.
//!
//! This module stores an immutable audit receipt and changes only the
//! `activity_coordinators` binding. Agent attachments, focus, membership and
//! Goal/DAG state remain owned by their existing persistence authorities.

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorBinding, ActivityCoordinatorRevision, ActivityId,
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal,
    ConfirmedCoordinatorRecovery, CoordinatorRecoveryAgent, CoordinatorRecoveryError,
    CoordinatorRecoveryFence, CoordinatorRecoveryReason, CoordinatorRecoveryReceipt, DirectTokenId,
    OAuthGrantId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_agent_migration;
use crate::workspace_agents::{self, AgentStoreError};
use crate::workspace_coordinators::{self, CoordinatorStoreError};

const RECOVERIES_TABLE: &str = "activity_coordinator_recoveries";
const OPERATOR_AUTHORITY: &str = "local_operator";
const MAX_RECOVERY_LIST_LIMIT: u32 = 32;
const EXPECTED_RECOVERIES_TABLE_SQL: &str = "CREATE TABLE activity_coordinator_recoveries (recovery_id BLOB PRIMARY KEY NOT NULL CHECK(length(recovery_id) = 16 AND recovery_id != zeroblob(16)), operator_authority TEXT NOT NULL CHECK(operator_authority = 'local_operator'), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), source_agent_id BLOB NOT NULL CHECK(length(source_agent_id) = 16 AND source_agent_id != zeroblob(16)), source_session_id BLOB NOT NULL CHECK(length(source_session_id) = 16 AND source_session_id != zeroblob(16)), source_revision INTEGER NOT NULL CHECK(source_revision >= 1), source_principal_kind INTEGER NOT NULL CHECK(source_principal_kind IN (0, 1, 2)), source_principal_id BLOB CHECK(source_principal_id IS NULL OR (length(source_principal_id) = 16 AND source_principal_id != zeroblob(16))), source_updated_at_ms INTEGER NOT NULL CHECK(source_updated_at_ms >= 0), target_agent_id BLOB NOT NULL CHECK(length(target_agent_id) = 16 AND target_agent_id != zeroblob(16)), target_session_id BLOB NOT NULL CHECK(length(target_session_id) = 16 AND target_session_id != zeroblob(16)), target_revision INTEGER NOT NULL CHECK(target_revision >= 1), target_principal_kind INTEGER NOT NULL CHECK(target_principal_kind IN (0, 1, 2)), target_principal_id BLOB CHECK(target_principal_id IS NULL OR (length(target_principal_id) = 16 AND target_principal_id != zeroblob(16))), target_updated_at_ms INTEGER NOT NULL CHECK(target_updated_at_ms >= 0), before_coordinator_revision INTEGER NOT NULL CHECK(before_coordinator_revision >= 1), before_coordinator_updated_at_ms INTEGER NOT NULL CHECK(before_coordinator_updated_at_ms >= 0), reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB)) BETWEEN 1 AND 1024), confirmed_at_ms INTEGER NOT NULL CHECK(confirmed_at_ms >= 0), resulting_coordinator_revision INTEGER NOT NULL CHECK(resulting_coordinator_revision = before_coordinator_revision + 1), UNIQUE(activity_id, resulting_coordinator_revision), FOREIGN KEY(source_agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(target_agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), CHECK((source_principal_kind = 0 AND source_principal_id IS NULL) OR (source_principal_kind IN (1, 2) AND source_principal_id IS NOT NULL)), CHECK(target_principal_kind = 0 AND target_principal_id IS NULL), CHECK(source_agent_id != target_agent_id), CHECK(source_session_id != target_session_id), CHECK(confirmed_at_ms >= source_updated_at_ms AND confirmed_at_ms >= target_updated_at_ms AND confirmed_at_ms >= before_coordinator_updated_at_ms))";

const RECOVERY_SELECT: &str = "SELECT operator_authority, recovery_id, workspace_id, activity_id, source_agent_id, source_session_id, source_revision, source_principal_kind, source_principal_id, source_updated_at_ms, target_agent_id, target_session_id, target_revision, target_principal_kind, target_principal_id, target_updated_at_ms, before_coordinator_revision, before_coordinator_updated_at_ms, reason, confirmed_at_ms, resulting_coordinator_revision FROM activity_coordinator_recoveries";

#[derive(Debug, Error)]
pub enum CoordinatorRecoveryStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Coordinator(CoordinatorStoreError),
    #[error(transparent)]
    Agent(AgentStoreError),
    #[error(transparent)]
    Domain(#[from] CoordinatorRecoveryError),
    #[error(transparent)]
    Migration(#[from] crate::AgentOperationsMigrationError),
    #[error("Coordinator recovery fence conflicts with current authority")]
    FenceConflict,
    #[error("Coordinator recovery request was already used with different contents")]
    ReplayConflict,
    #[error("Coordinator recovery record is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Coordinator recovery list limit {limit} is outside 1..=32")]
    InvalidLimit { limit: u32 },
    #[error("Coordinator recovery {recovery_id} commit is unconfirmed")]
    CommitUnconfirmed {
        recovery_id: Uuid,
        #[source]
        source: rusqlite::Error,
    },
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), CoordinatorRecoveryStoreError> {
    connection.execute_batch(EXPECTED_RECOVERIES_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), CoordinatorRecoveryStoreError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            params![RECOVERIES_TABLE],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref().map(normalize_sql) != Some(normalize_sql(EXPECTED_RECOVERIES_TABLE_SQL)) {
        return Err(CoordinatorRecoveryStoreError::CorruptRecord(
            RECOVERIES_TABLE,
        ));
    }
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", RECOVERIES_TABLE)]
}

pub(crate) fn preview(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    target_agent_id: AgentInstanceId,
) -> Result<CoordinatorRecoveryFence, CoordinatorRecoveryStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let fence = preview_in_transaction(&transaction, workspace_id, activity_id, target_agent_id)?;
    transaction.commit()?;
    Ok(fence)
}

pub(crate) fn recover(
    connection: &mut Connection,
    request: &ConfirmedCoordinatorRecovery,
) -> Result<CoordinatorRecoveryReceipt, CoordinatorRecoveryStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    workspace_agent_migration::ensure_work_writes(&transaction)?;

    if let Some(existing) = load_receipt(&transaction, request.id())? {
        if existing.request() == request {
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(CoordinatorRecoveryStoreError::ReplayConflict);
    }

    let fence = preview_in_transaction(
        &transaction,
        request.fence().binding().workspace_id(),
        request.fence().binding().activity_id(),
        request.fence().target().id(),
    )?;
    if fence != request.fence() {
        return Err(CoordinatorRecoveryStoreError::FenceConflict);
    }
    let receipt = CoordinatorRecoveryReceipt::new(request.clone())?;
    let before = fence.binding();
    let changed = transaction.execute(
        "UPDATE activity_coordinators SET agent_id = ?1, revision = ?2, updated_at_ms = ?3 WHERE activity_id = ?4 AND workspace_id = ?5 AND agent_id = ?6 AND revision = ?7 AND updated_at_ms = ?8",
        params![
            fence.target().id().into_uuid().as_bytes(),
            receipt.binding().revision().get(),
            receipt.binding().updated_at().get(),
            before.activity_id().into_uuid().as_bytes(),
            before.workspace_id().into_uuid().as_bytes(),
            before.agent_id().into_uuid().as_bytes(),
            before.revision().get(),
            before.updated_at().get(),
        ],
    )?;
    if changed != 1 {
        return Err(CoordinatorRecoveryStoreError::FenceConflict);
    }
    insert_receipt(&transaction, &receipt)?;
    transaction
        .commit()
        .map_err(|source| CoordinatorRecoveryStoreError::CommitUnconfirmed {
            recovery_id: request.id(),
            source,
        })?;
    Ok(receipt)
}

pub(crate) fn get(
    connection: &Connection,
    recovery_id: Uuid,
) -> Result<Option<CoordinatorRecoveryReceipt>, CoordinatorRecoveryStoreError> {
    if recovery_id.is_nil() {
        return Err(CoordinatorRecoveryStoreError::CorruptRecord("recovery_id"));
    }
    load_receipt(connection, recovery_id)
}

pub(crate) fn list(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    limit: u32,
) -> Result<Vec<CoordinatorRecoveryReceipt>, CoordinatorRecoveryStoreError> {
    if !(1..=MAX_RECOVERY_LIST_LIMIT).contains(&limit) {
        return Err(CoordinatorRecoveryStoreError::InvalidLimit { limit });
    }
    let query = format!(
        "{RECOVERY_SELECT} WHERE workspace_id = ?1 AND activity_id = ?2 ORDER BY confirmed_at_ms DESC, recovery_id DESC LIMIT ?3"
    );
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        activity_id.into_uuid().as_bytes(),
        i64::from(limit),
    ])?;
    let mut receipts = Vec::new();
    while let Some(row) = rows.next()? {
        receipts.push(decode_receipt_row(row)?);
    }
    Ok(receipts)
}

fn preview_in_transaction(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    target_agent_id: AgentInstanceId,
) -> Result<CoordinatorRecoveryFence, CoordinatorRecoveryStoreError> {
    let binding = workspace_coordinators::get_in_transaction(connection, activity_id)
        .map_err(map_coordinator)?
        .ok_or(CoordinatorRecoveryStoreError::Coordinator(
            CoordinatorStoreError::CoordinatorMissing(activity_id),
        ))?;
    if binding.workspace_id() != workspace_id {
        return Err(CoordinatorRecoveryStoreError::FenceConflict);
    }
    let source = workspace_agents::get_in_transaction(connection, binding.agent_id())
        .map_err(CoordinatorRecoveryStoreError::Agent)?
        .ok_or(CoordinatorRecoveryStoreError::Agent(
            AgentStoreError::AgentNotFound(binding.agent_id()),
        ))?;
    let source_snapshot = CoordinatorRecoveryAgent::from_agent(&source)?;
    let actor = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        source_snapshot.id(),
        binding.revision(),
        source_snapshot.principal(),
        source_snapshot.session_id(),
    );
    let authorized = workspace_coordinators::authorize_in_transaction(connection, actor)
        .map_err(map_coordinator)?;
    if authorized != binding {
        return Err(CoordinatorRecoveryStoreError::FenceConflict);
    }
    let target = workspace_agents::get_in_transaction(connection, target_agent_id)
        .map_err(CoordinatorRecoveryStoreError::Agent)?
        .ok_or(CoordinatorRecoveryStoreError::Agent(
            AgentStoreError::AgentNotFound(target_agent_id),
        ))?;
    let fence = CoordinatorRecoveryFence::from_agents(binding, &source, &target)?;
    workspace_coordinators::ensure_no_active_writer_lease(
        connection,
        fence.source().id(),
        activity_id,
    )
    .map_err(map_coordinator)?;
    workspace_coordinators::ensure_no_active_execution(
        connection,
        fence.source().id(),
        activity_id,
    )
    .map_err(map_coordinator)?;
    workspace_coordinators::ensure_no_active_writer_lease(
        connection,
        fence.target().id(),
        activity_id,
    )
    .map_err(map_coordinator)?;
    workspace_coordinators::ensure_no_active_execution(
        connection,
        fence.target().id(),
        activity_id,
    )
    .map_err(map_coordinator)?;
    Ok(fence)
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    receipt: &CoordinatorRecoveryReceipt,
) -> Result<(), CoordinatorRecoveryStoreError> {
    let request = receipt.request();
    let fence = request.fence();
    let before = fence.binding();
    let (source_principal_kind, source_principal_id) = encode_principal(fence.source().principal());
    let (target_principal_kind, target_principal_id) = encode_principal(fence.target().principal());
    transaction.execute(
        "INSERT INTO activity_coordinator_recoveries (recovery_id, operator_authority, workspace_id, activity_id, source_agent_id, source_session_id, source_revision, source_principal_kind, source_principal_id, source_updated_at_ms, target_agent_id, target_session_id, target_revision, target_principal_kind, target_principal_id, target_updated_at_ms, before_coordinator_revision, before_coordinator_updated_at_ms, reason, confirmed_at_ms, resulting_coordinator_revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            request.id().as_bytes(),
            OPERATOR_AUTHORITY,
            before.workspace_id().into_uuid().as_bytes(),
            before.activity_id().into_uuid().as_bytes(),
            fence.source().id().into_uuid().as_bytes(),
            fence.source().session_id().into_uuid().as_bytes(),
            fence.source().revision().get(),
            source_principal_kind,
            source_principal_id,
            fence.source().updated_at().get(),
            fence.target().id().into_uuid().as_bytes(),
            fence.target().session_id().into_uuid().as_bytes(),
            fence.target().revision().get(),
            target_principal_kind,
            target_principal_id,
            fence.target().updated_at().get(),
            before.revision().get(),
            before.updated_at().get(),
            request.reason().as_str(),
            request.confirmed_at().get(),
            receipt.binding().revision().get(),
        ],
    )?;
    Ok(())
}

fn load_receipt(
    connection: &Connection,
    recovery_id: Uuid,
) -> Result<Option<CoordinatorRecoveryReceipt>, CoordinatorRecoveryStoreError> {
    let query = format!("{RECOVERY_SELECT} WHERE recovery_id = ?1");
    let mut statement = connection.prepare(&query)?;
    let mut rows = statement.query(params![recovery_id.as_bytes()])?;
    rows.next()?.map(decode_receipt_row).transpose()
}

fn decode_receipt_row(
    row: &rusqlite::Row<'_>,
) -> Result<CoordinatorRecoveryReceipt, CoordinatorRecoveryStoreError> {
    let authority: String = row.get(0)?;
    if authority != OPERATOR_AUTHORITY {
        return Err(CoordinatorRecoveryStoreError::CorruptRecord(
            "operator_authority",
        ));
    }
    let recovery_id = decode_uuid(&row.get::<_, Vec<u8>>(1)?, "recovery_id")?;
    let workspace_id =
        WorkspaceId::from_uuid(decode_uuid(&row.get::<_, Vec<u8>>(2)?, "workspace_id")?);
    let activity_id =
        ActivityId::from_uuid(decode_uuid(&row.get::<_, Vec<u8>>(3)?, "activity_id")?);
    let source_id =
        AgentInstanceId::from_uuid(decode_uuid(&row.get::<_, Vec<u8>>(4)?, "source_agent_id")?);
    let source_session_id = AgentSessionId::from_uuid(decode_uuid(
        &row.get::<_, Vec<u8>>(5)?,
        "source_session_id",
    )?);
    let source = CoordinatorRecoveryAgent::new(
        source_id,
        source_session_id,
        AgentInstanceRevision::new(row.get(6)?)
            .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("source_revision"))?,
        decode_principal(row.get(7)?, row.get(8)?)?,
        decode_timestamp(row.get(9)?, "source_updated_at_ms")?,
    )
    .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("source"))?;
    let target_id =
        AgentInstanceId::from_uuid(decode_uuid(&row.get::<_, Vec<u8>>(10)?, "target_agent_id")?);
    let target_session_id = AgentSessionId::from_uuid(decode_uuid(
        &row.get::<_, Vec<u8>>(11)?,
        "target_session_id",
    )?);
    let target = CoordinatorRecoveryAgent::new(
        target_id,
        target_session_id,
        AgentInstanceRevision::new(row.get(12)?)
            .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("target_revision"))?,
        decode_principal(row.get(13)?, row.get(14)?)?,
        decode_timestamp(row.get(15)?, "target_updated_at_ms")?,
    )
    .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("target"))?;
    let before = ActivityCoordinatorBinding::new(
        workspace_id,
        activity_id,
        source.id(),
        ActivityCoordinatorRevision::new(row.get(16)?).map_err(|_| {
            CoordinatorRecoveryStoreError::CorruptRecord("before_coordinator_revision")
        })?,
        decode_timestamp(row.get(17)?, "before_coordinator_updated_at_ms")?,
    );
    let fence = CoordinatorRecoveryFence::new(before, source, target)
        .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("fence"))?;
    let reason = CoordinatorRecoveryReason::new(row.get(18)?)
        .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("reason"))?;
    let request = ConfirmedCoordinatorRecovery::new(
        recovery_id,
        fence,
        reason,
        decode_timestamp(row.get(19)?, "confirmed_at_ms")?,
    )
    .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("request"))?;
    let receipt = CoordinatorRecoveryReceipt::new(request)
        .map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord("receipt"))?;
    if receipt.binding().revision().get() != row.get::<_, i64>(20)? {
        return Err(CoordinatorRecoveryStoreError::CorruptRecord(
            "resulting_coordinator_revision",
        ));
    }
    Ok(receipt)
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes().to_vec())),
    }
}

fn decode_principal(
    kind: i64,
    identifier: Option<Vec<u8>>,
) -> Result<AuthenticatedPrincipal, CoordinatorRecoveryStoreError> {
    match (kind, identifier) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(value)) => Ok(AuthenticatedPrincipal::DirectToken(
            DirectTokenId::from_uuid(decode_uuid(&value, "principal_id")?),
        )),
        (2, Some(value)) => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
            decode_uuid(&value, "principal_id")?,
        ))),
        _ => Err(CoordinatorRecoveryStoreError::CorruptRecord("principal")),
    }
}

fn decode_uuid(value: &[u8], field: &'static str) -> Result<Uuid, CoordinatorRecoveryStoreError> {
    Uuid::from_slice(value).map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord(field))
}

fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, CoordinatorRecoveryStoreError> {
    TimestampMillis::new(value).map_err(|_| CoordinatorRecoveryStoreError::CorruptRecord(field))
}

fn map_coordinator(error: CoordinatorStoreError) -> CoordinatorRecoveryStoreError {
    match error {
        CoordinatorStoreError::Sqlite(source) => CoordinatorRecoveryStoreError::Sqlite(source),
        CoordinatorStoreError::Agent(source) => CoordinatorRecoveryStoreError::Agent(source),
        CoordinatorStoreError::OperationsMigration(source) => {
            CoordinatorRecoveryStoreError::Migration(source)
        }
        other => CoordinatorRecoveryStoreError::Coordinator(other),
    }
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[cfg(test)]
mod tests;
