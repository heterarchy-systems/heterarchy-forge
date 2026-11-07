//! Source-owned immutable retirement receipts for unused binding reservations.

mod model;
mod repository;
pub(crate) mod schema;

pub use model::{
    HomeTransferReservationRetirementOutcome, HomeTransferReservationRetirementRecord,
    HomeTransferReservationRetirementRecordParts,
};
pub(crate) use repository::{
    ensure_binding_identity_open, get, get_for_reservation, is_valid_settlement, retire,
};

#[cfg(test)]
pub(crate) fn receipt_parts_digest_for_fixture(
    parts: &HomeTransferReservationRetirementRecordParts,
) -> [u8; 32] {
    model::receipt_digest(
        &parts.request,
        parts.issuer,
        parts.observed_at,
        parts.grant_issued_at,
        parts.grant_expires_at,
        &parts.source_inventory_digest,
        &parts.reservation_digest,
    )
}
