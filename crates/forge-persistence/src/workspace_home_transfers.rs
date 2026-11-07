//! Source-owned Home-transfer preparation and abort-before-create journal.
//!
//! A Prepared record holds admission fences. It is not a settlement, a transfer
//! of work, or permission to change Home membership. The host authenticates the
//! service before invoking this owner; typed request/grant values are not credentials.

use forge_domain::{HomeTransferSourceRequest, OrchestrationIssuerId, TimestampMillis};
use thiserror::Error;
use uuid::Uuid;

pub(crate) mod artifacts;
pub(crate) mod guards;
pub(crate) mod handoffs;
mod inventory;
mod inventory_codec;
#[cfg(test)]
pub(crate) mod legacy_fixture;
mod record;
mod record_codec;
mod repository;
mod request_codec;
pub(crate) mod retirements;
pub(crate) mod schema;

pub(crate) use handoffs::{
    applications_schema_objects as home_handoff_application_schema_objects,
    create_applications_schema as create_home_handoff_application_schema,
    validate_applications_schema as validate_home_handoff_application_schema,
};

pub use handoffs::{
    HomeHandoffAcceptanceOutcome, HomeHandoffAcceptanceOutcomeKind,
    HomeHandoffAcceptanceOutcomeRecord, HomeHandoffApplicationStoreError,
    HomeHandoffAppliedAcceptance, HomeHandoffAssignmentLineage, HomeHandoffCaseSnapshot,
    HomeHandoffInitialSuccessorSnapshot, HomeHandoffProposalEvidence, HomeHandoffProposalOutcome,
    HomeHandoffProposalRecord, HomeHandoffProposalStoreError, HomeHandoffSourceAssignmentPin,
};

pub use inventory::HomeTransferSourceInventoryError;
pub use record::HomeTransferSourceRecordParts;
pub(crate) use repository::blocks_activity_continuation;
pub(crate) use repository::{apply, get};
pub use retirements::{
    HomeTransferReservationRetirementOutcome, HomeTransferReservationRetirementRecord,
    HomeTransferReservationRetirementRecordParts,
};

#[derive(Debug, Error)]
pub enum HomeTransferStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Domain(#[from] forge_domain::HomeTransferSourceError),
    #[error(transparent)]
    RetirementDomain(#[from] forge_domain::HomeTransferReservationRetirementError),
    #[error(transparent)]
    RetirementReservation(#[from] Box<crate::AgentBindingReservationError>),
    #[error(transparent)]
    RetirementActivation(#[from] Box<crate::AgentBindingActivationError>),
    #[error(transparent)]
    RetirementRejection(#[from] Box<crate::AgentBindingRejectionStoreError>),
    #[error(transparent)]
    RetirementAgent(#[from] Box<crate::AgentStoreError>),
    #[error(transparent)]
    Inventory(#[from] Box<HomeTransferSourceInventoryError>),
    #[error(transparent)]
    Migration(#[from] Box<crate::AgentOperationsMigrationError>),
    #[error("Home source bounds exceeded: {0}")]
    Bounds(&'static str),
    #[error("Home source conflict: {0}")]
    Conflict(&'static str),
    #[error("Home source stored record is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("Home source clock could not establish admission time")]
    Clock,
    #[error("Home source preparation {preparation_id} fences fresh work")]
    Fenced { preparation_id: Uuid },
    #[error(
        "Home source preparation {preparation_id} outcome is unknown; read that exact identity"
    )]
    CommitUnconfirmed {
        preparation_id: Uuid,
        #[source]
        source: Box<rusqlite::Error>,
    },
    #[error(
        "Home source reservation {reservation_request_id} retirement under preparation {preparation_id} is unconfirmed; read the exact identity"
    )]
    RetirementCommitUnconfirmed {
        preparation_id: Uuid,
        reservation_request_id: Uuid,
        #[source]
        source: Box<rusqlite::Error>,
    },
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeTransferSourceState {
    Prepared,
    AbortedUnstarted,
}

/// Immutable original source outcome. A capsule is present only for Prepared.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTransferSourceRecord {
    request: HomeTransferSourceRequest,
    issuer: OrchestrationIssuerId,
    state: HomeTransferSourceState,
    observed_at: TimestampMillis,
    grant_issued_at: TimestampMillis,
    grant_expires_at: TimestampMillis,
    migration_id: Uuid,
    freeze_revision: u64,
    delegation_digest: [u8; 32],
    inventory_payload: Option<Vec<u8>>,
    inventory_digest: Option<[u8; 32]>,
    outcome_digest: [u8; 32],
}

impl HomeTransferSourceRecord {
    pub const fn request(&self) -> &HomeTransferSourceRequest {
        &self.request
    }
    pub const fn issuer(&self) -> OrchestrationIssuerId {
        self.issuer
    }
    pub const fn state(&self) -> HomeTransferSourceState {
        self.state
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
    pub const fn migration_id(&self) -> Uuid {
        self.migration_id
    }
    pub const fn freeze_revision(&self) -> u64 {
        self.freeze_revision
    }
    pub const fn delegation_digest(&self) -> &[u8; 32] {
        &self.delegation_digest
    }
    pub fn inventory_payload(&self) -> Option<&[u8]> {
        self.inventory_payload.as_deref()
    }
    pub const fn inventory_digest(&self) -> Option<&[u8; 32]> {
        self.inventory_digest.as_ref()
    }
    pub const fn outcome_digest(&self) -> &[u8; 32] {
        &self.outcome_digest
    }

    /// Historical Pending reservation IDs from this original capture.
    /// These are candidates only; retirement revalidates current eligibility.
    pub fn captured_pending_binding_reservation_ids(
        &self,
    ) -> Result<Vec<Uuid>, HomeTransferStoreError> {
        let Some(payload) = self.inventory_payload() else {
            return Ok(Vec::new());
        };
        let captured = inventory_codec::decode(payload, self.request())
            .map_err(|error| HomeTransferStoreError::Inventory(Box::new(error)))?;
        Ok(captured
            .reservations
            .into_iter()
            .filter_map(|reservation| {
                matches!(
                    reservation.outcome,
                    inventory::SourceReservationOutcome::Pending
                )
                .then_some(reservation.request_id)
            })
            .collect())
    }

    /// Encode this immutable record as bounded, versioned snapshot bytes.
    /// This is a consistency-checked data snapshot, not proof of issuer
    /// authentication or current Source authority.
    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>, HomeTransferStoreError> {
        record_codec::encode(self)
    }

    /// Reconstruct and validate one immutable record snapshot without opening
    /// a Workspace or checking current Source authority.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, HomeTransferStoreError> {
        record_codec::decode(bytes)
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeTransferSourceOutcome {
    Created(HomeTransferSourceRecord),
    Existing(HomeTransferSourceRecord),
}

impl HomeTransferSourceOutcome {
    pub const fn record(&self) -> &HomeTransferSourceRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }
}

/// Encode the canonical FHTR v1 Operations request envelope. This validates
/// only the typed request contents; it does not authenticate an issuer or grant.
pub fn encode_home_transfer_source_request(
    request: &HomeTransferSourceRequest,
) -> Result<Vec<u8>, HomeTransferStoreError> {
    request_codec::encode(request)
}

/// Decode one canonical FHTR v1 Operations request envelope without opening a
/// Workspace or checking current Source authority.
pub fn decode_home_transfer_source_request(
    bytes: &[u8],
) -> Result<HomeTransferSourceRequest, HomeTransferStoreError> {
    request_codec::decode(bytes)
}
