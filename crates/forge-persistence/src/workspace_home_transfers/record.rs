//! Pure consistency validation for a Home-transfer source record.
//!
//! The public snapshot constructor validates typed and canonical contents. It
//! does not authenticate an issuer, open a Workspace, or establish current
//! source custody.

use forge_domain::{HomeTransferSourceRequest, OrchestrationIssuerId, TimestampMillis};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    HomeTransferSourceRecord, HomeTransferSourceState, HomeTransferStoreError,
    inventory::{HomeTransferSourceInventory, MAX_HOME_SOURCE_INVENTORY_BYTES},
    inventory_codec,
};

/// Exact, self-contained data needed to revalidate one immutable source result.
///
/// Constructing this value is only deserialization. Use
/// [`HomeTransferSourceRecord::from_parts`] to verify its digests, state shape,
/// and canonical inventory capsule before consuming it.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTransferSourceRecordParts {
    /// The canonical checked Ops request and source scope.
    pub request: HomeTransferSourceRequest,
    /// Issuer identity recorded by the source owner; not authenticated here.
    pub issuer: OrchestrationIssuerId,
    /// Original immutable result state.
    pub state: HomeTransferSourceState,
    /// Source observation time.
    pub observed_at: TimestampMillis,
    /// Original authorization issue time.
    pub grant_issued_at: TimestampMillis,
    /// Original authorization expiry time.
    pub grant_expires_at: TimestampMillis,
    /// Delegated Agent operations migration identity.
    pub migration_id: Uuid,
    /// Exact freeze revision witnessed by the source owner.
    pub freeze_revision: u64,
    /// Digest of the delegated source manifest.
    pub delegation_digest: [u8; 32],
    /// Canonical bounded source inventory for Prepared outcomes.
    pub inventory_payload: Option<Vec<u8>>,
    /// SHA-256 digest of `inventory_payload` for Prepared outcomes.
    pub inventory_digest: Option<[u8; 32]>,
    /// Domain-separated SHA-256 digest of the complete immutable outcome.
    pub outcome_digest: [u8; 32],
}

impl HomeTransferSourceRecord {
    /// Rebuild one checked snapshot from public transport data.
    ///
    /// This proves internal consistency and request/capsule binding only. It
    /// does not authenticate `issuer`, recheck the live Workspace/delegation,
    /// or prove that the captured source still has current custody.
    pub fn from_parts(
        parts: HomeTransferSourceRecordParts,
    ) -> Result<Self, HomeTransferStoreError> {
        from_parts_with_inventory(parts).map(|(record, _)| record)
    }
}

/// Shared owner validation used by both the public constructor and SQLite
/// readback so the capsule is decoded and verified exactly once per read.
pub(super) fn from_parts_with_inventory(
    parts: HomeTransferSourceRecordParts,
) -> Result<
    (
        HomeTransferSourceRecord,
        Option<HomeTransferSourceInventory>,
    ),
    HomeTransferStoreError,
> {
    if parts.issuer.into_uuid().is_nil()
        || parts.migration_id.is_nil()
        || parts.freeze_revision == 0
        || i64::try_from(parts.freeze_revision).is_err()
        || parts.delegation_digest == [0; 32]
        || parts.grant_issued_at >= parts.grant_expires_at
        || parts.observed_at < parts.grant_issued_at
        || parts.observed_at >= parts.grant_expires_at
    {
        return Err(HomeTransferStoreError::Corrupt(
            "record identity or time window",
        ));
    }

    let inventory = match (
        parts.state,
        parts.inventory_payload.as_deref(),
        parts.inventory_digest,
    ) {
        (HomeTransferSourceState::Prepared, Some(payload), Some(expected_digest)) => {
            if payload.is_empty() || payload.len() > MAX_HOME_SOURCE_INVENTORY_BYTES {
                return Err(HomeTransferStoreError::Corrupt("inventory capsule bound"));
            }
            if digest_inventory(payload) != expected_digest {
                return Err(HomeTransferStoreError::Corrupt("inventory checksum"));
            }
            let inventory = inventory_codec::decode(payload, &parts.request)
                .map_err(|error| HomeTransferStoreError::Inventory(Box::new(error)))?;
            if inventory.source_high_water_ms > parts.observed_at.get() {
                return Err(HomeTransferStoreError::Corrupt("inventory source clock"));
            }
            Some(inventory)
        }
        (HomeTransferSourceState::AbortedUnstarted, None, None) => None,
        _ => return Err(HomeTransferStoreError::Corrupt("outcome inventory shape")),
    };

    if parts.outcome_digest != digest_outcome(&parts) {
        return Err(HomeTransferStoreError::Corrupt("original outcome digest"));
    }
    let record = unchecked_record(parts);
    Ok((record, inventory))
}

pub(super) fn digest_inventory(payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"forge.home-transfer.source.inventory.v1\0");
    hash.update(payload);
    hash.finalize().into()
}

pub(super) fn digest_outcome(parts: &HomeTransferSourceRecordParts) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"forge.home-transfer.source.outcome.v1\0");
    hash.update(parts.request.request_digest().as_bytes());
    hash.update(parts.issuer.into_uuid().as_bytes());
    hash.update(state_tag(parts.state).to_be_bytes());
    hash.update(parts.observed_at.get().to_be_bytes());
    hash.update(parts.grant_issued_at.get().to_be_bytes());
    hash.update(parts.grant_expires_at.get().to_be_bytes());
    hash.update(parts.migration_id.as_bytes());
    hash.update(parts.freeze_revision.to_be_bytes());
    hash.update(parts.delegation_digest);
    if let Some(digest) = parts.inventory_digest {
        hash.update([1]);
        hash.update(digest);
    } else {
        hash.update([0]);
    }
    hash.finalize().into()
}

pub(super) const fn state_tag(state: HomeTransferSourceState) -> i64 {
    match state {
        HomeTransferSourceState::Prepared => 0,
        HomeTransferSourceState::AbortedUnstarted => 1,
    }
}

fn unchecked_record(parts: HomeTransferSourceRecordParts) -> HomeTransferSourceRecord {
    HomeTransferSourceRecord {
        request: parts.request,
        issuer: parts.issuer,
        state: parts.state,
        observed_at: parts.observed_at,
        grant_issued_at: parts.grant_issued_at,
        grant_expires_at: parts.grant_expires_at,
        migration_id: parts.migration_id,
        freeze_revision: parts.freeze_revision,
        delegation_digest: parts.delegation_digest,
        inventory_payload: parts.inventory_payload,
        inventory_digest: parts.inventory_digest,
        outcome_digest: parts.outcome_digest,
    }
}

#[cfg(test)]
mod tests {
    use forge_domain::{
        AgentSessionId, ForgeBackendId, HomeTransferSourceRequest, HomeTransferSourceScope,
        HomeTransferSourceSubject, HomeTransferSourceWitness, OrchestrationIssuerId,
        TimestampMillis, WorkspaceId, WorkspaceRevision,
    };

    use super::*;

    fn request() -> Result<HomeTransferSourceRequest, Box<dyn std::error::Error>> {
        request_with_transfer(7)
    }

    fn request_with_transfer(
        transfer_id: u128,
    ) -> Result<HomeTransferSourceRequest, Box<dyn std::error::Error>> {
        Ok(HomeTransferSourceRequest::new(
            HomeTransferSourceWitness::new(Uuid::from_u128(1), [2; 32], [3; 32])?,
            HomeTransferSourceScope::new(
                WorkspaceId::from_uuid(Uuid::from_u128(4)),
                WorkspaceRevision::INITIAL,
                ForgeBackendId::from_uuid(Uuid::from_u128(5)),
                Uuid::from_u128(6),
            )?,
            HomeTransferSourceSubject::new(
                Uuid::from_u128(transfer_id),
                1,
                Uuid::from_u128(8),
                Uuid::from_u128(9),
                Uuid::from_u128(10),
                Uuid::from_u128(11),
                1,
                1,
            )?,
            vec![AgentSessionId::from_uuid(Uuid::from_u128(12))],
            Vec::new(),
        )?)
    }

    fn inventory(request: &HomeTransferSourceRequest) -> HomeTransferSourceInventory {
        HomeTransferSourceInventory {
            version: 1,
            request_digest: *request.request_digest().as_bytes(),
            workspace_id: request.scope().workspace_id().into_uuid(),
            workspace_revision: request.scope().workspace_revision().get(),
            session_ids: request
                .sessions()
                .iter()
                .map(|session| session.into_uuid())
                .collect(),
            agents: Vec::new(),
            reservations: Vec::new(),
            assignments: Vec::new(),
            writer_leases: Vec::new(),
            executions: Vec::new(),
            closed_execution_count: 0,
            closed_execution_digest: [0; 32],
            closed_execution_high_water_ms: 0,
            approvals: Vec::new(),
            change_sets: Vec::new(),
            affected_activity_ids: Vec::new(),
            affected_agent_ids: Vec::new(),
            source_high_water_ms: 0,
        }
    }

    fn prepared_parts() -> Result<HomeTransferSourceRecordParts, Box<dyn std::error::Error>> {
        let request = request()?;
        let payload = inventory_codec::encode(&inventory(&request))?;
        let mut parts = HomeTransferSourceRecordParts {
            request,
            issuer: OrchestrationIssuerId::from_uuid(Uuid::from_u128(13)),
            state: HomeTransferSourceState::Prepared,
            observed_at: TimestampMillis::new(20)?,
            grant_issued_at: TimestampMillis::new(10)?,
            grant_expires_at: TimestampMillis::new(30)?,
            migration_id: Uuid::from_u128(14),
            freeze_revision: 1,
            delegation_digest: [15; 32],
            inventory_payload: Some(payload.clone()),
            inventory_digest: Some(digest_inventory(&payload)),
            outcome_digest: [0; 32],
        };
        parts.outcome_digest = digest_outcome(&parts);
        Ok(parts)
    }

    #[test]
    fn checked_snapshot_round_trips_through_public_parts() -> Result<(), Box<dyn std::error::Error>>
    {
        let parts = prepared_parts()?;
        let record = HomeTransferSourceRecord::from_parts(parts.clone())?;
        let round_trip = HomeTransferSourceRecord::from_parts(HomeTransferSourceRecordParts {
            request: record.request.clone(),
            issuer: record.issuer,
            state: record.state,
            observed_at: record.observed_at,
            grant_issued_at: record.grant_issued_at,
            grant_expires_at: record.grant_expires_at,
            migration_id: record.migration_id,
            freeze_revision: record.freeze_revision,
            delegation_digest: record.delegation_digest,
            inventory_payload: record.inventory_payload.clone(),
            inventory_digest: record.inventory_digest,
            outcome_digest: record.outcome_digest,
        })?;
        assert_eq!(round_trip, record);
        Ok(())
    }

    #[test]
    fn altered_identity_window_hash_and_capsule_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = prepared_parts()?;

        let mut altered_identity = valid.clone();
        altered_identity.migration_id = Uuid::nil();
        assert!(HomeTransferSourceRecord::from_parts(altered_identity).is_err());

        let mut altered_request = valid.clone();
        altered_request.request = request_with_transfer(0x70)?;
        altered_request.outcome_digest = digest_outcome(&altered_request);
        assert!(HomeTransferSourceRecord::from_parts(altered_request).is_err());

        let mut altered_window = valid.clone();
        altered_window.grant_expires_at = altered_window.grant_issued_at;
        assert!(HomeTransferSourceRecord::from_parts(altered_window).is_err());

        let mut altered_hash = valid.clone();
        altered_hash.inventory_digest = Some([0xFF; 32]);
        assert!(HomeTransferSourceRecord::from_parts(altered_hash).is_err());

        let mut altered_capsule = valid;
        let payload = altered_capsule
            .inventory_payload
            .as_mut()
            .ok_or("capsule missing")?;
        payload.push(0);
        altered_capsule.inventory_digest = Some(digest_inventory(payload));
        altered_capsule.outcome_digest = digest_outcome(&altered_capsule);
        assert!(HomeTransferSourceRecord::from_parts(altered_capsule).is_err());
        Ok(())
    }

    #[test]
    fn snapshot_bytes_round_trip_and_reject_bounds_truncation_tail_and_tamper()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = HomeTransferSourceRecord::from_parts(prepared_parts()?)?;
        let bytes = record.to_snapshot_bytes()?;
        assert!(bytes.len() <= 1_048_576);
        assert_eq!(
            HomeTransferSourceRecord::from_snapshot_bytes(&bytes)?,
            record
        );

        assert!(HomeTransferSourceRecord::from_snapshot_bytes(&bytes[..bytes.len() - 1]).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(HomeTransferSourceRecord::from_snapshot_bytes(&trailing).is_err());

        let mut tampered = bytes;
        let final_byte = tampered.last_mut().ok_or("empty snapshot")?;
        *final_byte ^= 0x01;
        assert!(HomeTransferSourceRecord::from_snapshot_bytes(&tampered).is_err());

        assert!(HomeTransferSourceRecord::from_snapshot_bytes(&vec![0; 1_048_577]).is_err());
        Ok(())
    }

    #[test]
    fn public_request_codec_reuses_the_canonical_fhtr_envelope()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let bytes = super::super::encode_home_transfer_source_request(&request)?;
        assert!(bytes.starts_with(b"FHTR\x01"));
        assert_eq!(
            super::super::decode_home_transfer_source_request(&bytes)?,
            request
        );
        Ok(())
    }
}
