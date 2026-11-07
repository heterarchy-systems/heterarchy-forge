//! Test-only construction of a truthful historical v1 Prepared capsule.

use std::error::Error;

use rusqlite::{Connection, TransactionBehavior, params};

use super::{
    HomeTransferSourceRecord, HomeTransferSourceState,
    inventory::CURRENT_NON_HOME_INVENTORY_VERSION,
    inventory_codec,
    record::{self, HomeTransferSourceRecordParts},
};

const SOURCE_NO_UPDATE_TRIGGER: &str = "home_transfer_source_operations_no_update";

/// Rewrites one isolated Prepared fixture as the canonical v1 record that a
/// pre-v72 source could have produced.
///
/// The input must be the canonical v2 Prepared record from the non-Home source
/// producer. The supplied record remains untouched; only its isolated fixture
/// row receives a v1-compatible capsule, with inventory and outcome digests
/// substituted together. The immutable source trigger is captured after
/// canonical schema validation and restored inside the same scratch-database
/// transaction.
pub(crate) fn install_v1_prepared_record(
    connection: &mut Connection,
    current: &HomeTransferSourceRecord,
) -> Result<HomeTransferSourceRecord, Box<dyn Error>> {
    if current.state() != HomeTransferSourceState::Prepared {
        return Err(invalid_fixture("v1 fixture requires a Prepared record").into());
    }
    let current_payload = current
        .inventory_payload()
        .ok_or_else(|| invalid_fixture("Prepared record is missing its inventory capsule"))?;
    let mut inventory = inventory_codec::decode(current_payload, current.request())?;
    if inventory.version != CURRENT_NON_HOME_INVENTORY_VERSION {
        return Err(invalid_fixture("v1 fixture requires a non-Home v2 inventory").into());
    }

    // The v1 encoder rejects v2-only reservation outcomes. If that format
    // cannot represent the captured data, fail rather than relabeling bytes.
    inventory.version = 1;
    let legacy_payload = inventory_codec::encode(&inventory)?;
    if legacy_payload.as_slice() == current_payload {
        return Err(invalid_fixture("v1 fixture did not change the capsule version").into());
    }

    let mut parts = HomeTransferSourceRecordParts {
        request: current.request().clone(),
        issuer: current.issuer(),
        state: current.state(),
        observed_at: current.observed_at(),
        grant_issued_at: current.grant_issued_at(),
        grant_expires_at: current.grant_expires_at(),
        migration_id: current.migration_id(),
        freeze_revision: current.freeze_revision(),
        delegation_digest: *current.delegation_digest(),
        inventory_payload: Some(legacy_payload),
        inventory_digest: None,
        outcome_digest: [0; 32],
    };
    let legacy_payload = parts
        .inventory_payload
        .as_deref()
        .ok_or_else(|| invalid_fixture("synthetic v1 capsule disappeared"))?;
    parts.inventory_digest = Some(record::digest_inventory(legacy_payload));
    parts.outcome_digest = record::digest_outcome(&parts);
    let legacy = HomeTransferSourceRecord::from_parts(parts)?;

    let old_inventory_digest = *current
        .inventory_digest()
        .ok_or_else(|| invalid_fixture("Prepared record is missing its inventory digest"))?;
    let new_inventory_digest = *legacy
        .inventory_digest()
        .ok_or_else(|| invalid_fixture("synthetic v1 record is missing its inventory digest"))?;
    let legacy_payload = legacy
        .inventory_payload()
        .ok_or_else(|| invalid_fixture("synthetic v1 record is missing its capsule"))?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    super::schema::validate_schema(&transaction)?;
    let trigger_sql: String = transaction.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
        [SOURCE_NO_UPDATE_TRIGGER],
        |row| row.get(0),
    )?;
    transaction.execute_batch("DROP TRIGGER home_transfer_source_operations_no_update")?;
    let changed = transaction.execute(
        "UPDATE home_transfer_source_operations
         SET inventory_payload=?1, inventory_digest=?2, outcome_digest=?3
         WHERE preparation_id=?4 AND workspace_id=?5 AND outcome=0
           AND request_digest=?6 AND inventory_payload=?7
           AND inventory_digest=?8 AND outcome_digest=?9",
        params![
            legacy_payload,
            &new_inventory_digest[..],
            &legacy.outcome_digest()[..],
            &current.request().witness().preparation_id().as_bytes()[..],
            &current
                .request()
                .scope()
                .workspace_id()
                .into_uuid()
                .as_bytes()[..],
            &current.request().request_digest().as_bytes()[..],
            current_payload,
            &old_inventory_digest[..],
            &current.outcome_digest()[..],
        ],
    )?;
    if changed != 1 {
        return Err(invalid_fixture("original Prepared row did not match the CAS").into());
    }
    transaction.execute_batch(&trigger_sql)?;
    super::schema::validate_schema(&transaction)?;
    transaction.commit()?;

    Ok(legacy)
}

fn invalid_fixture(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
