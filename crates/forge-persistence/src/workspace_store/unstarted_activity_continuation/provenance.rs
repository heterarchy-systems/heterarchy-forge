//! Exact p28 recovery provenance required by same-Activity continuation.

use forge_domain::{ActivityId, WorkspaceId};
use rusqlite::{Connection, params, types::ValueRef};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::UnstartedActivityContinuationStoreError;

const DOMAIN: &[u8] = b"heterarchy.forge.unstarted-activity-continuation.p28-provenance.v1";
const MAX_AGENT_ROWS: u32 = forge_domain::MAX_AGENT_LIST_RESULTS;

/// Return whether the Activity participates in any P28 lineage.
///
/// The selector deliberately keys only on the Activity identity.  A receipt,
/// successor relation, or recovery-agent mapping with a mismatched Workspace,
/// or with a damaged reciprocal counterpart, is still P28 evidence and must be
/// rejected by the existing P28 validator; it must never silently select
/// normal-bootstrap provenance.
pub(super) fn p28_lineage_present(
    connection: &Connection,
    activity_id: ActivityId,
) -> Result<bool, UnstartedActivityContinuationStoreError> {
    let activity = activity_id.into_uuid().into_bytes();
    let present: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM expired_activity_recovery_receipts
             WHERE predecessor_activity_id=?1 OR successor_activity_id=?1
         ) OR EXISTS(
             SELECT 1 FROM activity_successors
             WHERE predecessor_activity_id=?1 OR successor_activity_id=?1
         ) OR EXISTS(
             SELECT 1 FROM expired_activity_recovery_agents
             WHERE activity_id=?1
         )",
        params![activity.as_slice()],
        |row| row.get(0),
    )?;
    Ok(present)
}

pub(super) fn validate_and_digest_p28_provenance(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<[u8; 32], UnstartedActivityContinuationStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let request_id = exact_recovery_request(connection, &workspace, &activity)?;
    let receipt = super::super::expired_activity_recovery::load_receipt(connection, request_id)?
        .ok_or(UnstartedActivityContinuationStoreError::Corrupt(
            "p28 recovery receipt missing",
        ))?;
    super::super::expired_activity_recovery::validate_receipt(connection, &receipt)?;

    let scope = receipt.probe_scope();
    let expectation = receipt.expectation();
    let predecessor = expectation.predecessor();
    let relation = receipt.relation();
    if scope.workspace_id() != workspace_id
        || receipt.delegation().workspace_id() != workspace_id
        || receipt.successor().workspace_id() != workspace_id
        || receipt.successor().id() != activity_id
        || expectation.successor_activity_id() != activity_id
        || relation.workspace_id() != workspace_id
        || relation.predecessor_activity_id() != predecessor.activity_id()
        || relation.predecessor_activity_revision() != receipt.predecessor_after().revision()
        || relation.successor_activity_id() != activity_id
        || relation.initiating_session_id() != expectation.initiating_session_id()
        || relation.runtime_instance_id() != receipt.owner_id()
        || relation.created_at() != receipt.recovered_at()
    {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "p28 recovery provenance scope/lineage",
        ));
    }

    let workspace_row = super::super::query_workspace_row(connection)?.ok_or(
        UnstartedActivityContinuationStoreError::Corrupt("p28 Workspace missing"),
    )?;
    let current_workspace = super::super::decode_workspace(workspace_row)?;
    if current_workspace.id() != workspace_id
        || current_workspace.revision() != scope.workspace_revision()
        || current_workspace.location_id() != scope.location_id()
        || current_workspace.root_fingerprint() != scope.root_fingerprint()
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "p28 recovery root scope",
        ));
    }

    validate_raw_counterparts(
        connection,
        &workspace,
        &activity,
        request_id,
        predecessor.activity_id(),
        receipt.agents().len(),
    )?;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hash_bytes(&mut hasher, &workspace);
    hash_bytes(&mut hasher, &activity);
    for query in DIGEST_QUERIES {
        hash_rows(
            &mut hasher,
            connection,
            query,
            &workspace,
            &activity,
            request_id.as_bytes(),
        )?;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) fn validate_and_digest_p28_provenance_for_test(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<[u8; 32], UnstartedActivityContinuationStoreError> {
    validate_and_digest_p28_provenance(connection, workspace_id, activity_id)
}

fn exact_recovery_request(
    connection: &Connection,
    workspace_id: &[u8],
    activity_id: &[u8],
) -> Result<Uuid, UnstartedActivityContinuationStoreError> {
    let mut statement = connection.prepare(
        "SELECT request_id
         FROM expired_activity_recovery_receipts
         WHERE workspace_id=?1 AND successor_activity_id=?2
         ORDER BY request_id
         LIMIT 2",
    )?;
    let mut rows = statement.query(params![workspace_id, activity_id])?;
    let Some(first) = rows.next()? else {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "p28 recovery provenance missing",
        ));
    };
    let raw = first.get::<_, Vec<u8>>(0)?;
    if rows.next()?.is_some() {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "multiple p28 recovery receipts",
        ));
    }
    Uuid::from_slice(&raw).map_err(|_| {
        UnstartedActivityContinuationStoreError::Corrupt("p28 recovery request identity")
    })
}

fn validate_raw_counterparts(
    connection: &Connection,
    workspace_id: &[u8],
    activity_id: &[u8],
    request_id: Uuid,
    predecessor_activity_id: ActivityId,
    agent_count: usize,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let invalid_receipt: i64 = connection.query_row(
        INVALID_RECEIPT_QUERY,
        params![request_id.as_bytes(), workspace_id, activity_id],
        |row| row.get(0),
    )?;
    if invalid_receipt != 0 {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "p28 recovery receipt/relation counterpart",
        ));
    }

    let predecessor = predecessor_activity_id.into_uuid().into_bytes();
    let invalid_agents: i64 = connection.query_row(
        INVALID_AGENTS_QUERY,
        params![request_id.as_bytes(), workspace_id, predecessor],
        |row| row.get(0),
    )?;
    if invalid_agents != 0
        || agent_count == 0
        || u64::try_from(agent_count).unwrap_or(u64::MAX) > u64::from(MAX_AGENT_ROWS)
    {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "p28 recovery Agent counterparts",
        ));
    }
    Ok(())
}

const INVALID_RECEIPT_QUERY: &str =
    "SELECT COUNT(*)
     FROM expired_activity_recovery_receipts r
     LEFT JOIN activity_successors s
       ON s.predecessor_activity_id=r.predecessor_activity_id
     WHERE r.request_id=?1 AND (
       r.workspace_id<>?2 OR r.successor_activity_id<>?3 OR
       r.delegation_workspace_id<>r.workspace_id OR
       r.service_destination_id<>r.delegation_destination_id OR
       r.predecessor_before_state<>1 OR r.predecessor_after_state<>2 OR
       r.predecessor_after_revision<>r.predecessor_before_revision+1 OR
       r.predecessor_after_updated_at_ms<>r.recovered_at_ms OR
       r.predecessor_after_lease_revision<>r.predecessor_before_lease_revision+1 OR
       r.successor_state<>1 OR r.successor_owner_id<>r.owner_runtime_instance_id OR
       r.successor_lease_until_ms<>r.claimed_lease_until_ms OR
       r.successor_revision<>1 OR r.successor_lease_revision<>1 OR
       r.successor_created_at_ms<>r.recovered_at_ms OR
       r.successor_updated_at_ms<>r.recovered_at_ms OR
       r.released_epoch<>r.claimed_epoch OR
       r.released_revision<>r.claimed_revision+1 OR
       r.released_updated_at_ms<>r.recovered_at_ms OR
       s.predecessor_activity_id IS NULL OR s.workspace_id<>r.workspace_id OR
       s.predecessor_activity_revision<>r.predecessor_after_revision OR
       s.successor_activity_id<>r.successor_activity_id OR
       s.initiating_session_id<>r.initiating_session_id OR
       s.runtime_instance_id<>r.owner_runtime_instance_id OR
       s.created_at_ms<>r.recovered_at_ms OR
       r.agent_count<>(SELECT COUNT(*) FROM expired_activity_recovery_agents a WHERE a.request_id=r.request_id)
     )";

const INVALID_AGENTS_QUERY: &str = "SELECT COUNT(*)
     FROM expired_activity_recovery_agents a
     LEFT JOIN expired_activity_recovery_receipts r ON r.request_id=a.request_id
     WHERE a.workspace_id=?2 AND a.activity_id=?3 AND (
       r.request_id IS NULL OR a.request_id<>?1 OR
       r.workspace_id<>a.workspace_id OR r.predecessor_activity_id<>a.activity_id OR
       a.ordinal<0 OR a.ordinal>=256 OR
       a.ordinal<>(SELECT COUNT(*)-1 FROM expired_activity_recovery_agents p
                    WHERE p.request_id=a.request_id AND p.ordinal<=a.ordinal)
     )";

struct DigestQuery {
    table: &'static str,
    sql: &'static str,
    minimum_rows: u32,
    maximum_rows: u32,
}

const DIGEST_QUERIES: &[DigestQuery] = &[
    DigestQuery {
        table: "activity_successors",
        sql: "SELECT * FROM activity_successors WHERE workspace_id=?1 AND successor_activity_id=?2 ORDER BY predecessor_activity_id",
        minimum_rows: 1,
        maximum_rows: 1,
    },
    DigestQuery {
        table: "expired_activity_recovery_receipts",
        sql: "SELECT * FROM expired_activity_recovery_receipts WHERE request_id=?3 AND workspace_id=?1 AND successor_activity_id=?2 ORDER BY request_id",
        minimum_rows: 1,
        maximum_rows: 1,
    },
    DigestQuery {
        table: "expired_activity_recovery_agents",
        sql: "SELECT * FROM expired_activity_recovery_agents WHERE request_id=?3 ORDER BY request_id,ordinal",
        minimum_rows: 1,
        maximum_rows: MAX_AGENT_ROWS,
    },
];

fn hash_rows(
    hasher: &mut Sha256,
    connection: &Connection,
    query: &DigestQuery,
    workspace_id: &[u8],
    activity_id: &[u8],
    request_id: &[u8],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    hash_bytes(hasher, query.table.as_bytes());
    hasher.update(query.minimum_rows.to_le_bytes());
    hasher.update(query.maximum_rows.to_le_bytes());
    let mut statement = connection.prepare(query.sql)?;
    let columns = statement
        .column_names()
        .iter()
        .map(|column| (*column).to_owned())
        .collect::<Vec<_>>();
    hash_u64(hasher, u64::try_from(columns.len()).unwrap_or(u64::MAX));
    for column in &columns {
        hash_bytes(hasher, column.as_bytes());
    }
    let mut rows = match statement.parameter_count() {
        2 => statement.query(params![workspace_id, activity_id])?,
        3 => statement.query(params![workspace_id, activity_id, request_id])?,
        _ => {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "p28 provenance query parameter count",
            ));
        }
    };
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .ok_or(UnstartedActivityContinuationStoreError::Corrupt(
                "p28 provenance row count overflow",
            ))?;
        if count > u64::from(query.maximum_rows) {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "p28 provenance row bound",
            ));
        }
        hasher.update([0xFD]);
        for index in 0..columns.len() {
            match row.get_ref(index)? {
                ValueRef::Null => {
                    hasher.update([0]);
                    hash_u64(hasher, 0);
                }
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hash_u64(hasher, 8);
                    hasher.update(value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hash_u64(hasher, 8);
                    hasher.update(value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) => {
                    hasher.update([3]);
                    hash_bytes(hasher, value);
                }
                ValueRef::Blob(value) => {
                    hasher.update([4]);
                    hash_bytes(hasher, value);
                }
            }
        }
        hasher.update([0xFE]);
    }
    if count < u64::from(query.minimum_rows) {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "p28 provenance row missing",
        ));
    }
    hash_u64(hasher, count);
    hasher.update([0xFF]);
    Ok(())
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hash_u64(hasher, u64::try_from(value.len()).unwrap_or(u64::MAX));
    hasher.update(value);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
