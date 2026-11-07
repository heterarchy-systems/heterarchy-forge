//! Exact domain request and short-lived grant for retiring one unused source
//! reservation. Construction is validation only; Source still authenticates the
//! issuer and correlates both parent digests with its immutable Prepared record.

use super::{
    HomeTransferSourceError, HomeTransferSourceRequestDigest, HomeTransferSourceScope, check_id,
};
use crate::{OrchestrationIssuerId, TimestampMillis};
use blake3::Hasher;
use thiserror::Error;
use uuid::Uuid;

const DIGEST_BYTES: usize = 32;
const REQUEST_DOMAIN: &[u8] = b"heterarchy.forge.home-transfer-reservation-retirement-request.v1\0";

/// Domain-specific digest of one exact reservation-retirement request.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeTransferReservationRetirementRequestDigest([u8; DIGEST_BYTES]);

impl HomeTransferReservationRetirementRequestDigest {
    pub const fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// Checked pointer to one reservation selected for retirement within an
/// immutable Prepared Source record. The Source owner verifies it is still
/// Pending; this value alone is neither authentication nor current authority.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeTransferReservationRetirementRequest {
    scope: HomeTransferSourceScope,
    preparation_id: Uuid,
    source_request_digest: HomeTransferSourceRequestDigest,
    source_outcome_digest: [u8; DIGEST_BYTES],
    reservation_request_id: Uuid,
    request_digest: HomeTransferReservationRetirementRequestDigest,
}

impl HomeTransferReservationRetirementRequest {
    /// Construct one exact retirement request and calculate its canonical
    /// domain-separated digest.
    ///
    /// # Errors
    /// Rejects nil parent or reservation identities and empty parent Source
    /// request/outcome digests. It cannot establish that the parent record or
    /// selected Pending reservation exists; the Source transaction does that.
    pub fn new(
        scope: HomeTransferSourceScope,
        preparation_id: Uuid,
        source_request_digest: HomeTransferSourceRequestDigest,
        source_outcome_digest: [u8; DIGEST_BYTES],
        reservation_request_id: Uuid,
    ) -> Result<Self, HomeTransferReservationRetirementError> {
        check_id(preparation_id, "preparation")?;
        check_id(reservation_request_id, "reservation request")?;
        if source_request_digest.as_bytes() == &[0; DIGEST_BYTES] {
            return Err(HomeTransferReservationRetirementError::EmptySourceRequestDigest);
        }
        if source_outcome_digest == [0; DIGEST_BYTES] {
            return Err(HomeTransferReservationRetirementError::EmptySourceOutcomeDigest);
        }

        let mut request = Self {
            scope,
            preparation_id,
            source_request_digest,
            source_outcome_digest,
            reservation_request_id,
            request_digest: HomeTransferReservationRetirementRequestDigest([0; DIGEST_BYTES]),
        };
        request.request_digest =
            HomeTransferReservationRetirementRequestDigest(request.compute_digest());
        Ok(request)
    }

    pub const fn scope(&self) -> HomeTransferSourceScope {
        self.scope
    }

    pub const fn preparation_id(&self) -> Uuid {
        self.preparation_id
    }

    pub const fn source_request_digest(&self) -> HomeTransferSourceRequestDigest {
        self.source_request_digest
    }

    pub const fn source_outcome_digest(&self) -> [u8; DIGEST_BYTES] {
        self.source_outcome_digest
    }

    pub const fn reservation_request_id(&self) -> Uuid {
        self.reservation_request_id
    }

    pub const fn request_digest(&self) -> HomeTransferReservationRetirementRequestDigest {
        self.request_digest
    }

    fn compute_digest(&self) -> [u8; DIGEST_BYTES] {
        let mut hash = Hasher::new();
        hash.update(REQUEST_DOMAIN);
        hash.update(&[1]);

        // Each field has a stable tag and length prefix. Scope is framed as its
        // four typed components so revisions and owner identities cannot alias.
        hash_field(
            &mut hash,
            1,
            16,
            self.scope.workspace_id().into_uuid().as_bytes(),
        );
        hash_field(
            &mut hash,
            2,
            8,
            &self.scope.workspace_revision().get().to_be_bytes(),
        );
        hash_field(
            &mut hash,
            3,
            16,
            self.scope.backend_id().into_uuid().as_bytes(),
        );
        hash_field(&mut hash, 4, 16, self.scope.destination_id().as_bytes());
        hash_field(&mut hash, 5, 16, self.preparation_id.as_bytes());
        hash_field(&mut hash, 6, 32, self.source_request_digest.as_bytes());
        hash_field(&mut hash, 7, 32, &self.source_outcome_digest);
        hash_field(&mut hash, 8, 16, self.reservation_request_id.as_bytes());
        *hash.finalize().as_bytes()
    }
}

/// A short-lived grant bound only to one exact reservation-retirement request.
/// It is a separate type from Prepare/Abort grants and conveys no host identity
/// authentication by itself.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeTransferReservationRetirementGrant {
    issuer: OrchestrationIssuerId,
    request_digest: HomeTransferReservationRetirementRequestDigest,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
}

impl HomeTransferReservationRetirementGrant {
    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.issuer
    }

    pub const fn request_digest(self) -> HomeTransferReservationRetirementRequestDigest {
        self.request_digest
    }

    pub const fn issued_at(self) -> TimestampMillis {
        self.issued_at
    }

    pub const fn expires_at(self) -> TimestampMillis {
        self.expires_at
    }

    /// # Errors
    /// Rejects a nil issuer or a non-increasing grant interval.
    pub fn new(
        issuer: OrchestrationIssuerId,
        request_digest: HomeTransferReservationRetirementRequestDigest,
        issued_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, HomeTransferReservationRetirementError> {
        check_id(issuer.into_uuid(), "issuer")?;
        if issued_at >= expires_at {
            return Err(HomeTransferSourceError::InvalidWindow.into());
        }
        Ok(Self {
            issuer,
            request_digest,
            issued_at,
            expires_at,
        })
    }

    /// Check issuer, exact request identity and the half-open validity interval.
    /// The Host must authenticate the issuer separately before trusting a grant.
    ///
    /// # Errors
    /// Returns the corresponding source-grant validation failure for a mismatched
    /// issuer/request or a source time outside `[issued_at, expires_at)`.
    pub fn validate_for(
        self,
        authenticated_issuer: OrchestrationIssuerId,
        actual_digest: HomeTransferReservationRetirementRequestDigest,
        observed_at: TimestampMillis,
    ) -> Result<(), HomeTransferReservationRetirementError> {
        if self.issuer != authenticated_issuer {
            return Err(HomeTransferSourceError::IssuerMismatch.into());
        }
        if self.request_digest != actual_digest {
            return Err(HomeTransferSourceError::RequestMismatch.into());
        }
        if observed_at < self.issued_at {
            return Err(HomeTransferSourceError::NotYetValid.into());
        }
        if observed_at >= self.expires_at {
            return Err(HomeTransferSourceError::Expired.into());
        }
        Ok(())
    }
}

/// Validation failures for reservation-retirement requests and grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HomeTransferReservationRetirementError {
    #[error(transparent)]
    Source(#[from] HomeTransferSourceError),
    #[error("Home transfer reservation retirement parent Source request digest is empty")]
    EmptySourceRequestDigest,
    #[error("Home transfer reservation retirement parent Source outcome digest is empty")]
    EmptySourceOutcomeDigest,
}

fn hash_field(hash: &mut Hasher, tag: u8, length: u64, value: &[u8]) {
    hash.update(&[tag]);
    hash.update(&length.to_be_bytes());
    hash.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ForgeBackendId, WorkspaceId, WorkspaceRevision};

    type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

    fn scope(
        workspace: u128,
        revision: i64,
        backend: u128,
        destination: u128,
    ) -> TestResult<HomeTransferSourceScope> {
        Ok(HomeTransferSourceScope::new(
            WorkspaceId::from_uuid(Uuid::from_u128(workspace)),
            WorkspaceRevision::new(revision)?,
            ForgeBackendId::from_uuid(Uuid::from_u128(backend)),
            Uuid::from_u128(destination),
        )?)
    }

    fn request(
        scope: HomeTransferSourceScope,
        preparation_id: u128,
        source_request_digest: [u8; DIGEST_BYTES],
        source_outcome_digest: [u8; DIGEST_BYTES],
        reservation_request_id: u128,
    ) -> Result<HomeTransferReservationRetirementRequest, HomeTransferReservationRetirementError>
    {
        HomeTransferReservationRetirementRequest::new(
            scope,
            Uuid::from_u128(preparation_id),
            HomeTransferSourceRequestDigest::from_bytes(source_request_digest),
            source_outcome_digest,
            Uuid::from_u128(reservation_request_id),
        )
    }

    fn timestamp(value: i64) -> TestResult<TimestampMillis> {
        Ok(TimestampMillis::new(value)?)
    }

    #[test]
    fn request_digest_binds_scope_parent_and_selected_reservation() -> TestResult<()> {
        let base_scope = scope(1, 1, 2, 3)?;
        let original = request(base_scope, 4, [0x11; 32], [0x21; 32], 5)?;
        assert_eq!(
            original.request_digest(),
            request(base_scope, 4, [0x11; 32], [0x21; 32], 5)?.request_digest()
        );

        for other_scope in [
            scope(6, 1, 2, 3)?,
            scope(1, 2, 2, 3)?,
            scope(1, 1, 6, 3)?,
            scope(1, 1, 2, 6)?,
        ] {
            assert_ne!(
                original.request_digest(),
                request(other_scope, 4, [0x11; 32], [0x21; 32], 5)?.request_digest()
            );
        }

        for other in [
            request(base_scope, 6, [0x11; 32], [0x21; 32], 5)?,
            request(base_scope, 4, [0x12; 32], [0x21; 32], 5)?,
            request(base_scope, 4, [0x11; 32], [0x22; 32], 5)?,
            request(base_scope, 4, [0x11; 32], [0x21; 32], 6)?,
        ] {
            assert_ne!(original.request_digest(), other.request_digest());
        }
        Ok(())
    }

    #[test]
    fn request_rejects_missing_parent_or_reservation_identity_evidence() -> TestResult<()> {
        assert_eq!(
            request(scope(1, 1, 2, 3)?, 0, [0x11; 32], [0x21; 32], 5),
            Err(HomeTransferReservationRetirementError::Source(
                HomeTransferSourceError::NilIdentity("preparation")
            ))
        );
        assert_eq!(
            request(scope(1, 1, 2, 3)?, 4, [0x11; 32], [0x21; 32], 0),
            Err(HomeTransferReservationRetirementError::Source(
                HomeTransferSourceError::NilIdentity("reservation request")
            ))
        );
        assert_eq!(
            request(scope(1, 1, 2, 3)?, 4, [0; 32], [0x21; 32], 5),
            Err(HomeTransferReservationRetirementError::EmptySourceRequestDigest)
        );
        assert_eq!(
            request(scope(1, 1, 2, 3)?, 4, [0x11; 32], [0; 32], 5),
            Err(HomeTransferReservationRetirementError::EmptySourceOutcomeDigest)
        );
        Ok(())
    }

    #[test]
    fn retirement_grant_binds_issuer_request_and_half_open_time_window() -> TestResult<()> {
        let request = request(scope(1, 1, 2, 3)?, 4, [0x11; 32], [0x21; 32], 5)?;
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(6));
        let grant = HomeTransferReservationRetirementGrant::new(
            issuer,
            request.request_digest(),
            timestamp(10)?,
            timestamp(20)?,
        )?;

        assert_eq!(
            grant.validate_for(issuer, request.request_digest(), timestamp(10)?),
            Ok(())
        );
        assert_eq!(
            grant.validate_for(
                OrchestrationIssuerId::from_uuid(Uuid::from_u128(7)),
                request.request_digest(),
                timestamp(10)?,
            ),
            Err(HomeTransferSourceError::IssuerMismatch.into())
        );
        assert_eq!(
            grant.validate_for(
                issuer,
                HomeTransferReservationRetirementRequestDigest::from_bytes([0x31; 32]),
                timestamp(10)?,
            ),
            Err(HomeTransferSourceError::RequestMismatch.into())
        );
        assert_eq!(
            grant.validate_for(issuer, request.request_digest(), timestamp(9)?),
            Err(HomeTransferSourceError::NotYetValid.into())
        );
        assert_eq!(
            grant.validate_for(issuer, request.request_digest(), timestamp(20)?),
            Err(HomeTransferSourceError::Expired.into())
        );
        assert_eq!(
            HomeTransferReservationRetirementGrant::new(
                issuer,
                request.request_digest(),
                timestamp(20)?,
                timestamp(20)?,
            ),
            Err(HomeTransferReservationRetirementError::Source(
                HomeTransferSourceError::InvalidWindow
            ))
        );
        Ok(())
    }
}
