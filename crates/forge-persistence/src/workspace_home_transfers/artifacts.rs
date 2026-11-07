//! Immutable SQL staging and sealing journal for retained Home artifacts.
//!
//! The journal is the durable publication permit and cleanup pin. Git owns the
//! retained bytes; this owner pins the exact capture intent and Source outcome
//! before any Git store construction or publication.

mod model;
mod repository;
pub(crate) mod schema;

pub use model::{
    HomeArtifactCaptureOutcome, HomeArtifactDoctorReference, HomeArtifactDoctorReport,
    HomeArtifactReadback, HomeArtifactSealRecord, HomeArtifactStageRecord,
};
pub use repository::HomeArtifactJournalError;
#[cfg(test)]
pub(crate) use repository::HomeArtifactStageOutcome;
pub(crate) use repository::{
    blocks_state_removal, doctor_references, get, get_by_handoff_id_in_transaction, seal, stage,
};
