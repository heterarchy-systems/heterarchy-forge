//! Immutable retirement value and its pure receipt/reservation digest checks.

use forge_domain::{
    AuthenticatedPrincipal, HomeTransferReservationRetirementRequest, OrchestrationIssuerId,
    TimestampMillis,
};
use sha2::{Digest, Sha256};

use crate::{AgentBindingReservation, HomeTransferStoreError};

const DIGEST_BYTES: usize = 32;
const RECEIPT_DOMAIN: &[u8] = b"forge.home-transfer.reservation-retirement.receipt.v1\0";
const RESERVATION_DOMAIN: &[u8] = b"forge.home-transfer.reservation-retirement.reservation.v1\0";

/// Checked local data needed to reconstruct one immutable retirement receipt.
///
/// This proves only the receipt's internal digest consistency. Source
/// authentication and current reservation provenance belong to the owner.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTransferReservationRetirementRecordParts {
    pub request: HomeTransferReservationRetirementRequest,
    pub issuer: OrchestrationIssuerId,
    pub observed_at: TimestampMillis,
    pub grant_issued_at: TimestampMillis,
    pub grant_expires_at: TimestampMillis,
    pub source_inventory_digest: [u8; DIGEST_BYTES],
    pub reservation_digest: [u8; DIGEST_BYTES],
    pub receipt_digest: [u8; DIGEST_BYTES],
}

/// Immutable result for retiring one exact unused reservation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTransferReservationRetirementRecord {
    request: HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
    observed_at: TimestampMillis,
    grant_issued_at: TimestampMillis,
    grant_expires_at: TimestampMillis,
    source_inventory_digest: [u8; DIGEST_BYTES],
    reservation_digest: [u8; DIGEST_BYTES],
    receipt_digest: [u8; DIGEST_BYTES],
}

impl HomeTransferReservationRetirementRecord {
    pub const fn request(&self) -> &HomeTransferReservationRetirementRequest {
        &self.request
    }

    pub const fn issuer(&self) -> OrchestrationIssuerId {
        self.issuer
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn grant_issued_at(&self) -> TimestampMillis {
        self.grant_issued_at
    }

    pub const fn grant_expires_at(&self) -> TimestampMillis {
        self.grant_expires_at
    }

    pub const fn source_inventory_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.source_inventory_digest
    }

    pub const fn reservation_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.reservation_digest
    }

    pub const fn receipt_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.receipt_digest
    }

    /// Rebuild one transport value and validate its own canonical digest.
    /// This does not authenticate the issuer or consult a Workspace.
    pub fn from_parts(
        parts: &HomeTransferReservationRetirementRecordParts,
    ) -> Result<Self, HomeTransferStoreError> {
        if parts.issuer.into_uuid().is_nil()
            || parts.source_inventory_digest == [0; DIGEST_BYTES]
            || parts.reservation_digest == [0; DIGEST_BYTES]
            || parts.receipt_digest == [0; DIGEST_BYTES]
            || parts.grant_issued_at >= parts.grant_expires_at
            || parts.observed_at < parts.grant_issued_at
            || parts.observed_at >= parts.grant_expires_at
        {
            return Err(HomeTransferStoreError::Corrupt(
                "reservation retirement identity or time window",
            ));
        }
        if parts.receipt_digest
            != receipt_digest(
                &parts.request,
                parts.issuer,
                parts.observed_at,
                parts.grant_issued_at,
                parts.grant_expires_at,
                &parts.source_inventory_digest,
                &parts.reservation_digest,
            )
        {
            return Err(HomeTransferStoreError::Corrupt(
                "reservation retirement receipt digest",
            ));
        }

        Ok(Self {
            request: parts.request,
            issuer: parts.issuer,
            observed_at: parts.observed_at,
            grant_issued_at: parts.grant_issued_at,
            grant_expires_at: parts.grant_expires_at,
            source_inventory_digest: parts.source_inventory_digest,
            reservation_digest: parts.reservation_digest,
            receipt_digest: parts.receipt_digest,
        })
    }
}

/// Build the checked receipt from values validated by the Source owner.
///
/// This is pure: callers supply the observation time and the exact current
/// native reservation selected by the enclosing transaction.
pub(super) fn record_from_reservation(
    request: &HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
    observed_at: TimestampMillis,
    grant_issued_at: TimestampMillis,
    grant_expires_at: TimestampMillis,
    source_inventory_digest: [u8; DIGEST_BYTES],
    reservation: &AgentBindingReservation,
) -> Result<HomeTransferReservationRetirementRecord, HomeTransferStoreError> {
    let reservation_digest = reservation_digest(reservation);
    let parts = HomeTransferReservationRetirementRecordParts {
        request: *request,
        issuer,
        observed_at,
        grant_issued_at,
        grant_expires_at,
        source_inventory_digest,
        reservation_digest,
        receipt_digest: receipt_digest(
            request,
            issuer,
            observed_at,
            grant_issued_at,
            grant_expires_at,
            &source_inventory_digest,
            &reservation_digest,
        ),
    };
    HomeTransferReservationRetirementRecord::from_parts(&parts)
}

/// Created or exact replay of one immutable reservation-retirement receipt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeTransferReservationRetirementOutcome {
    Created(HomeTransferReservationRetirementRecord),
    Existing(HomeTransferReservationRetirementRecord),
}

impl HomeTransferReservationRetirementOutcome {
    pub const fn record(&self) -> &HomeTransferReservationRetirementRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }
}

pub(super) fn reservation_digest(reservation: &AgentBindingReservation) -> [u8; DIGEST_BYTES] {
    let request = reservation.request();
    let (principal_kind, principal_id) = match request.principal() {
        AuthenticatedPrincipal::TrustedStdio => (0_u8, [0; 16]),
        AuthenticatedPrincipal::DirectToken(id) => (1_u8, *id.into_uuid().as_bytes()),
        AuthenticatedPrincipal::OAuthGrant(id) => (2_u8, *id.into_uuid().as_bytes()),
    };
    let mut hash = Sha256::new();
    hash.update(RESERVATION_DOMAIN);
    hash.update([1]);
    hash_field(&mut hash, 1, 16, reservation.migration_id().as_bytes());
    hash_field(&mut hash, 2, 16, reservation.destination_id().as_bytes());
    hash_field(
        &mut hash,
        3,
        16,
        reservation.workspace_id().into_uuid().as_bytes(),
    );
    hash_field(
        &mut hash,
        4,
        8,
        &reservation.freeze_revision().to_be_bytes(),
    );
    hash_field(&mut hash, 5, 16, request.request_id().as_bytes());
    hash_field(
        &mut hash,
        6,
        16,
        request.activity_id().into_uuid().as_bytes(),
    );
    hash_field(&mut hash, 7, 16, request.agent_id().into_uuid().as_bytes());
    hash_field(
        &mut hash,
        8,
        16,
        request.session_id().into_uuid().as_bytes(),
    );
    hash_field(&mut hash, 9, 1, &[principal_kind]);
    hash_field(&mut hash, 10, 16, &principal_id);
    hash_field(
        &mut hash,
        11,
        8,
        &request.requested_at().get().to_be_bytes(),
    );
    hash_field(
        &mut hash,
        12,
        8,
        &reservation.reserved_at().get().to_be_bytes(),
    );
    hash.finalize().into()
}

pub(super) fn receipt_digest(
    request: &HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
    observed_at: TimestampMillis,
    grant_issued_at: TimestampMillis,
    grant_expires_at: TimestampMillis,
    source_inventory_digest: &[u8; DIGEST_BYTES],
    reservation_digest: &[u8; DIGEST_BYTES],
) -> [u8; DIGEST_BYTES] {
    let mut hash = Sha256::new();
    hash.update(RECEIPT_DOMAIN);
    hash.update([1]);
    hash_field(&mut hash, 1, 32, request.request_digest().as_bytes());
    hash_field(&mut hash, 2, 16, issuer.into_uuid().as_bytes());
    hash_field(&mut hash, 3, 8, &observed_at.get().to_be_bytes());
    hash_field(&mut hash, 4, 8, &grant_issued_at.get().to_be_bytes());
    hash_field(&mut hash, 5, 8, &grant_expires_at.get().to_be_bytes());
    hash_field(&mut hash, 6, 32, source_inventory_digest);
    hash_field(&mut hash, 7, 32, reservation_digest);
    hash.finalize().into()
}

fn hash_field(hash: &mut Sha256, tag: u8, length: u8, value: &[u8]) {
    hash.update([tag, length]);
    hash.update(value);
}

#[cfg(test)]
mod tests {
    use forge_domain::{
        HomeTransferReservationRetirementRequest, HomeTransferSourceRequestDigest,
        HomeTransferSourceScope, OrchestrationIssuerId, TimestampMillis, WorkspaceId,
        WorkspaceRevision,
    };
    use uuid::Uuid;

    use super::*;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn request() -> Result<HomeTransferReservationRetirementRequest, Box<dyn std::error::Error>> {
        Ok(HomeTransferReservationRetirementRequest::new(
            HomeTransferSourceScope::new(
                WorkspaceId::from_uuid(id(1)),
                WorkspaceRevision::new(2)?,
                forge_domain::ForgeBackendId::from_uuid(id(3)),
                id(4),
            )?,
            id(5),
            HomeTransferSourceRequestDigest::from_bytes([6; 32]),
            [7; 32],
            id(8),
        )?)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    #[test]
    fn receipt_parts_prove_internal_digest_consistency_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let issuer = OrchestrationIssuerId::from_uuid(id(20));
        let observed_at = timestamp(30)?;
        let grant_issued_at = timestamp(25)?;
        let grant_expires_at = timestamp(40)?;
        let reservation_digest = [21; 32];
        let mut parts = HomeTransferReservationRetirementRecordParts {
            request,
            issuer,
            observed_at,
            grant_issued_at,
            grant_expires_at,
            source_inventory_digest: [22; 32],
            reservation_digest,
            receipt_digest: [0; 32],
        };
        parts.receipt_digest = receipt_digest(
            &parts.request,
            parts.issuer,
            parts.observed_at,
            parts.grant_issued_at,
            parts.grant_expires_at,
            &parts.source_inventory_digest,
            &parts.reservation_digest,
        );
        let record = HomeTransferReservationRetirementRecord::from_parts(&parts)?;
        assert_eq!(record.request(), &request);
        assert_eq!(record.issuer(), issuer);
        assert_eq!(record.observed_at(), observed_at);
        assert_eq!(record.grant_issued_at(), grant_issued_at);
        assert_eq!(record.grant_expires_at(), grant_expires_at);
        assert_eq!(record.reservation_digest(), &reservation_digest);

        parts.observed_at = timestamp(31)?;
        assert!(HomeTransferReservationRetirementRecord::from_parts(&parts).is_err());
        Ok(())
    }
}
