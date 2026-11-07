//! One IMMEDIATE owner for immutable outcomes and all admission indexes.
use forge_domain::{
    ForgeBackendId, HomeTransferSourceAction, HomeTransferSourceGrant, HomeTransferSourceRequest,
    HomeTransferSourceScope, OrchestrationIssuerId, TimestampMillis,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use uuid::Uuid;

/// Inspect original records before their indexes so a missing Activity index
/// cannot make custody disappear. This is a bounded completeness check inside
/// the continuation owner's existing transaction; it does not start another.
pub(crate) fn blocks_activity_continuation(
    connection: &Connection,
    workspace: forge_domain::WorkspaceId,
    activity: forge_domain::ActivityId,
) -> Result<bool, Error> {
    let mut query=connection.prepare("SELECT substr(preparation_id,1,17) FROM home_transfer_source_operations WHERE workspace_id=?1 ORDER BY preparation_id LIMIT 1025")?;
    let ids = query
        .query_map(params![workspace.into_uuid().as_bytes()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > super::inventory::MAX_HOME_SOURCE_ENTRIES {
        return Err(Error::Bounds("Home continuation history"));
    }
    let mut blocked = false;
    for raw_id in ids {
        let (_record, inventory) = read_record_with_inventory(connection, uuid(&raw_id)?)?
            .ok_or(Error::Corrupt("Home continuation original"))?;
        if let Some(inventory) = inventory {
            blocked |= inventory
                .affected_activity_ids
                .binary_search(&activity.into_uuid())
                .is_ok();
        }
    }
    // Orphaned fences have no original to enumerate. Fail closed rather than
    // treating those rows as unrelated or pretending a canonical record exists.
    let orphaned:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM home_transfer_source_subjects s LEFT JOIN home_transfer_source_operations o ON o.preparation_id=s.preparation_id AND o.workspace_id=s.workspace_id WHERE o.preparation_id IS NULL) OR EXISTS(SELECT 1 FROM home_transfer_source_sessions s LEFT JOIN home_transfer_source_subjects p ON p.preparation_id=s.preparation_id AND p.workspace_id=s.workspace_id WHERE p.preparation_id IS NULL) OR EXISTS(SELECT 1 FROM home_transfer_source_agents s LEFT JOIN home_transfer_source_subjects p ON p.preparation_id=s.preparation_id AND p.workspace_id=s.workspace_id WHERE p.preparation_id IS NULL) OR EXISTS(SELECT 1 FROM home_transfer_source_activities s LEFT JOIN home_transfer_source_subjects p ON p.preparation_id=s.preparation_id AND p.workspace_id=s.workspace_id WHERE p.preparation_id IS NULL)",[],|row|row.get(0))?;
    if orphaned {
        return Err(Error::Corrupt("orphaned Home source fence"));
    }
    Ok(blocked)
}

use super::{
    HomeTransferSourceOutcome, HomeTransferSourceRecord, HomeTransferSourceRecordParts,
    HomeTransferSourceState, HomeTransferStoreError as Error,
    inventory::HomeTransferSourceInventory,
    inventory_codec, record,
    record::{digest_inventory, digest_outcome, state_tag},
    request_codec,
};

#[allow(
    clippy::too_many_arguments,
    reason = "explicit authenticated host scope and action"
)]
pub(crate) fn apply<C>(
    connection: &mut Connection,
    request: &HomeTransferSourceRequest,
    action: HomeTransferSourceAction,
    grant: HomeTransferSourceGrant,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
    destination: Uuid,
    sample_clock: C,
) -> Result<HomeTransferSourceOutcome, Error>
where
    C: FnOnce() -> Result<TimestampMillis, Error>,
{
    // Check immutable authority fields on replay too; grant expiry only gates
    // fresh admission. History remains recoverable through exact Get/replay.
    grant.validate_for(issuer, action, request.request_digest(), grant.issued_at())?;
    if backend != request.scope().backend_id() || destination != request.scope().destination_id() {
        return Err(Error::Conflict("configured service scope"));
    }
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let preparation_id = request.witness().preparation_id();
    if let Some(record) = read_record(&tx, preparation_id)? {
        if record.request != *request || record.issuer != issuer {
            return Err(Error::Conflict("preparation identity or issuer"));
        }
        // Prepared never becomes Aborted, and an Aborted tombstone never
        // becomes Prepared. Both callers must inspect the original outcome.
        tx.commit()?;
        return Ok(HomeTransferSourceOutcome::Existing(record));
    }
    let delegation = validate_source(&tx, request)?;
    let inventory = match action {
        HomeTransferSourceAction::Prepare => {
            ensure_subject_available(&tx, request)?;
            Some(
                HomeTransferSourceInventory::capture(&tx, request)
                    .map_err(|e| Error::Inventory(Box::new(e)))?,
            )
        }
        HomeTransferSourceAction::AbortUnstarted => None,
    };
    let inventory_payload = inventory
        .as_ref()
        .map(inventory_codec::encode)
        .transpose()
        .map_err(|e| Error::Inventory(Box::new(e)))?;
    // The clock callback runs after the write lock and capture, immediately
    // before the journal/fence mutation; queue time cannot extend a grant.
    let now = sample_clock()?;
    grant.validate_for(issuer, action, request.request_digest(), now)?;
    if now < delegation.delegated_at()
        || now < delegation.freeze().updated_at()
        || inventory
            .as_ref()
            .is_some_and(|v| now.get() < v.source_high_water_ms)
    {
        return Err(Error::Conflict("source observation clock"));
    }
    let inventory_digest = inventory_payload.as_deref().map(digest_inventory);
    let mut parts = HomeTransferSourceRecordParts {
        request: request.clone(),
        issuer,
        state: match action {
            HomeTransferSourceAction::Prepare => HomeTransferSourceState::Prepared,
            HomeTransferSourceAction::AbortUnstarted => HomeTransferSourceState::AbortedUnstarted,
        },
        observed_at: now,
        grant_issued_at: grant.issued_at(),
        grant_expires_at: grant.expires_at(),
        migration_id: delegation.migration_id(),
        freeze_revision: delegation.freeze().revision(),
        delegation_digest: delegation.manifest_digest(),
        inventory_payload,
        inventory_digest,
        outcome_digest: [0; 32],
    };
    parts.outcome_digest = digest_outcome(&parts);
    let (record, decoded_inventory) = record::from_parts_with_inventory(parts)?;
    if decoded_inventory != inventory {
        return Err(Error::Corrupt(
            "captured inventory differs from canonical capsule",
        ));
    }
    persist(&tx, &record)?;
    if let Some(inventory) = &inventory {
        install_fences(&tx, request, inventory)?;
    }
    let readback =
        read_record(&tx, preparation_id)?.ok_or(Error::Corrupt("new outcome missing"))?;
    if readback != record {
        return Err(Error::Corrupt("new outcome differs"));
    }
    tx.commit().map_err(|source| Error::CommitUnconfirmed {
        preparation_id,
        source: Box::new(source),
    })?;
    Ok(HomeTransferSourceOutcome::Created(record))
}

pub(crate) fn get(
    connection: &Connection,
    preparation_id: Uuid,
) -> Result<Option<HomeTransferSourceRecord>, Error> {
    if preparation_id.is_nil() {
        return Err(Error::Conflict("nil preparation"));
    }
    let tx = connection.unchecked_transaction()?;
    let record = read_record(&tx, preparation_id)?;
    tx.commit()?;
    Ok(record)
}

fn validate_source(
    connection: &Connection,
    request: &HomeTransferSourceRequest,
) -> Result<crate::AgentOperationsDelegation, Error> {
    validate_current_scope(connection, request.scope())
}

pub(super) fn validate_current_scope(
    connection: &Connection,
    scope: HomeTransferSourceScope,
) -> Result<crate::AgentOperationsDelegation, Error> {
    let (workspace, revision): (Vec<u8>, i64) = connection.query_row(
        "SELECT substr(workspace_id,1,17),revision FROM workspace WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if uuid(&workspace)? != scope.workspace_id().into_uuid()
        || revision != scope.workspace_revision().get()
    {
        return Err(Error::Conflict("Workspace identity or revision"));
    }
    let delegation = crate::workspace_agent_migration::delegation(connection)
        .map_err(|e| Error::Migration(Box::new(e)))?
        .ok_or(Error::Conflict("Workspace is not delegated"))?;
    if delegation.workspace_id() != scope.workspace_id()
        || delegation.destination_id() != scope.destination_id()
        || delegation.freeze().state() != crate::AgentOperationsFreezeState::Frozen
    {
        return Err(Error::Conflict("current source delegation"));
    }
    Ok(delegation)
}

fn ensure_subject_available(
    connection: &Connection,
    request: &HomeTransferSourceRequest,
) -> Result<(), Error> {
    let subject = request.subject();
    let existing:Option<Vec<u8>>=connection.query_row(
        "SELECT substr(preparation_id,1,17) FROM home_transfer_source_subjects WHERE workspace_id=?1 AND (target_profile_id=?2 OR target_participation_id=?3) LIMIT 1",
        params![request.scope().workspace_id().into_uuid().as_bytes(),subject.target_profile_id().as_bytes(),subject.target_participation_id().as_bytes()],|r|r.get(0)).optional()?;
    if let Some(id) = existing {
        return Err(Error::Fenced {
            preparation_id: uuid(&id)?,
        });
    }
    for session in request.sessions() {
        let existing:Option<Vec<u8>>=connection.query_row(
            "SELECT substr(preparation_id,1,17) FROM home_transfer_source_sessions WHERE workspace_id=?1 AND session_id=?2",
            params![request.scope().workspace_id().into_uuid().as_bytes(),session.into_uuid().as_bytes()],|r|r.get(0)).optional()?;
        if let Some(id) = existing {
            return Err(Error::Fenced {
                preparation_id: uuid(&id)?,
            });
        }
    }
    Ok(())
}

fn persist(connection: &Connection, record: &HomeTransferSourceRecord) -> Result<(), Error> {
    let request = &record.request;
    let payload = request_codec::encode(request)?;
    connection.execute(
        "INSERT INTO home_transfer_source_operations (preparation_id,workspace_id,target_profile_id,target_participation_id,issuer_id,request_digest,request_payload,outcome,observed_at_ms,grant_issued_at_ms,grant_expires_at_ms,migration_id,freeze_revision,delegation_digest,inventory_payload,inventory_digest,outcome_digest) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        params![request.witness().preparation_id().as_bytes(),request.scope().workspace_id().into_uuid().as_bytes(),request.subject().target_profile_id().as_bytes(),request.subject().target_participation_id().as_bytes(),record.issuer.into_uuid().as_bytes(),request.request_digest().as_bytes(),payload,state_tag(record.state),record.observed_at.get(),record.grant_issued_at.get(),record.grant_expires_at.get(),record.migration_id.as_bytes(),i64::try_from(record.freeze_revision).map_err(|_|Error::Bounds("freeze revision"))?,record.delegation_digest,record.inventory_payload,record.inventory_digest,record.outcome_digest])?;
    Ok(())
}

fn install_fences(
    connection: &Connection,
    request: &HomeTransferSourceRequest,
    inventory: &HomeTransferSourceInventory,
) -> Result<(), Error> {
    let workspace = request.scope().workspace_id().into_uuid();
    let preparation = request.witness().preparation_id();
    connection.execute("INSERT INTO home_transfer_source_subjects (workspace_id,target_profile_id,target_participation_id,preparation_id) VALUES (?1,?2,?3,?4)",params![workspace.as_bytes(),request.subject().target_profile_id().as_bytes(),request.subject().target_participation_id().as_bytes(),preparation.as_bytes()])?;
    for session in request.sessions() {
        connection.execute("INSERT INTO home_transfer_source_sessions (workspace_id,session_id,preparation_id) VALUES (?1,?2,?3)",params![workspace.as_bytes(),session.into_uuid().as_bytes(),preparation.as_bytes()])?;
    }
    for agent in &inventory.affected_agent_ids {
        connection.execute("INSERT INTO home_transfer_source_agents (workspace_id,agent_id,preparation_id) VALUES (?1,?2,?3)",params![workspace.as_bytes(),agent.as_bytes(),preparation.as_bytes()])?;
    }
    for activity in &inventory.affected_activity_ids {
        connection.execute("INSERT INTO home_transfer_source_activities (workspace_id,activity_id,preparation_id) VALUES (?1,?2,?3)",params![workspace.as_bytes(),activity.as_bytes(),preparation.as_bytes()])?;
    }
    Ok(())
}

struct RawRecord {
    workspace: Vec<u8>,
    profile: Vec<u8>,
    participation: Vec<u8>,
    issuer: Vec<u8>,
    request_digest: Vec<u8>,
    request_payload: Vec<u8>,
    state: i64,
    observed: i64,
    issued: i64,
    expires: i64,
    migration: Vec<u8>,
    freeze_revision: i64,
    delegation_digest: Vec<u8>,
    inventory_payload: Option<Vec<u8>>,
    inventory_digest: Option<Vec<u8>>,
    outcome_digest: Vec<u8>,
}

fn read_record(
    connection: &Connection,
    preparation: Uuid,
) -> Result<Option<HomeTransferSourceRecord>, Error> {
    Ok(read_record_with_inventory(connection, preparation)?.map(|(record, _inventory)| record))
}

pub(super) fn read_record_with_inventory(
    connection: &Connection,
    preparation: Uuid,
) -> Result<
    Option<(
        HomeTransferSourceRecord,
        Option<HomeTransferSourceInventory>,
    )>,
    Error,
> {
    let raw=connection.query_row(
        "SELECT substr(workspace_id,1,17),substr(target_profile_id,1,17),substr(target_participation_id,1,17),substr(issuer_id,1,17),substr(request_digest,1,33),substr(request_payload,1,131073),outcome,observed_at_ms,grant_issued_at_ms,grant_expires_at_ms,substr(migration_id,1,17),freeze_revision,substr(delegation_digest,1,33),substr(inventory_payload,1,524289),substr(inventory_digest,1,33),substr(outcome_digest,1,33) FROM home_transfer_source_operations WHERE preparation_id=?1",
        params![preparation.as_bytes()],|r|Ok(RawRecord {workspace:r.get(0)?,profile:r.get(1)?,participation:r.get(2)?,issuer:r.get(3)?,request_digest:r.get(4)?,request_payload:r.get(5)?,state:r.get(6)?,observed:r.get(7)?,issued:r.get(8)?,expires:r.get(9)?,migration:r.get(10)?,freeze_revision:r.get(11)?,delegation_digest:r.get(12)?,inventory_payload:r.get(13)?,inventory_digest:r.get(14)?,outcome_digest:r.get(15)?})).optional()?;
    let Some(raw) = raw else { return Ok(None) };
    let request = request_codec::decode(&raw.request_payload)?;
    if request.witness().preparation_id() != preparation
        || request.scope().workspace_id().into_uuid() != uuid(&raw.workspace)?
        || request.subject().target_profile_id() != uuid(&raw.profile)?
        || request.subject().target_participation_id() != uuid(&raw.participation)?
        || request.request_digest().as_bytes() != &digest(&raw.request_digest)?
    {
        return Err(Error::Corrupt("request indexes"));
    }
    let state = match raw.state {
        0 => HomeTransferSourceState::Prepared,
        1 => HomeTransferSourceState::AbortedUnstarted,
        _ => return Err(Error::Corrupt("outcome state")),
    };
    let parts = HomeTransferSourceRecordParts {
        request,
        issuer: OrchestrationIssuerId::from_uuid(uuid(&raw.issuer)?),
        state,
        observed_at: timestamp(raw.observed)?,
        grant_issued_at: timestamp(raw.issued)?,
        grant_expires_at: timestamp(raw.expires)?,
        migration_id: uuid(&raw.migration)?,
        freeze_revision: u64::try_from(raw.freeze_revision)
            .map_err(|_| Error::Corrupt("freeze revision"))?,
        delegation_digest: digest(&raw.delegation_digest)?,
        inventory_payload: raw.inventory_payload,
        inventory_digest: raw.inventory_digest.as_deref().map(digest).transpose()?,
        outcome_digest: digest(&raw.outcome_digest)?,
    };
    let (record, inventory) = record::from_parts_with_inventory(parts)?;
    validate_fences(connection, &record, inventory.as_ref())?;
    Ok(Some((record, inventory)))
}

fn validate_fences(
    connection: &Connection,
    record: &HomeTransferSourceRecord,
    inventory: Option<&HomeTransferSourceInventory>,
) -> Result<(), Error> {
    let preparation = record.request.witness().preparation_id();
    let workspace = record.request.scope().workspace_id().into_uuid();
    let mut stmt=connection.prepare("SELECT substr(workspace_id,1,17),substr(target_profile_id,1,17),substr(target_participation_id,1,17) FROM home_transfer_source_subjects WHERE preparation_id=?1 LIMIT 2")?;
    let rows = stmt
        .query_map(params![preparation.as_bytes()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = if inventory.is_some() {
        vec![(
            workspace.as_bytes().to_vec(),
            record
                .request
                .subject()
                .target_profile_id()
                .as_bytes()
                .to_vec(),
            record
                .request
                .subject()
                .target_participation_id()
                .as_bytes()
                .to_vec(),
        )]
    } else {
        Vec::new()
    };
    if rows != expected {
        return Err(Error::Corrupt("subject fence"));
    }
    let sessions = inventory.map_or_else(Vec::new, |v| v.session_ids.clone());
    let agents = inventory.map_or_else(Vec::new, |v| v.affected_agent_ids.clone());
    let activities = inventory.map_or_else(Vec::new, |v| v.affected_activity_ids.clone());
    // SQL identifiers are fixed owner constants; all identity values are bound.
    for (table, column, expected) in [
        ("home_transfer_source_sessions", "session_id", sessions),
        ("home_transfer_source_agents", "agent_id", agents),
        ("home_transfer_source_activities", "activity_id", activities),
    ] {
        let sql = format!(
            "SELECT substr(workspace_id,1,17),substr({column},1,17) FROM {table} WHERE preparation_id=?1 ORDER BY {column} LIMIT 1025"
        );
        let mut stmt = connection.prepare(&sql)?;
        let rows = stmt
            .query_map(params![preparation.as_bytes()], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() != expected.len() {
            return Err(Error::Corrupt("fence cardinality"));
        }
        for ((row_workspace, row_id), expected_id) in rows.into_iter().zip(expected) {
            if uuid(&row_workspace)? != workspace || uuid(&row_id)? != expected_id {
                return Err(Error::Corrupt("fence scope"));
            }
        }
    }
    Ok(())
}

fn uuid(bytes: &[u8]) -> Result<Uuid, Error> {
    let value = Uuid::from_slice(bytes).map_err(|_| Error::Corrupt("UUID width"))?;
    if value.is_nil() {
        return Err(Error::Corrupt("nil UUID"));
    }
    Ok(value)
}
fn digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::Corrupt("digest width"))
}
fn timestamp(value: i64) -> Result<TimestampMillis, Error> {
    TimestampMillis::new(value).map_err(|_| Error::Corrupt("timestamp"))
}
