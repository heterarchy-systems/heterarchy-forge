//! Immutable Source proposals for one stable Home-handoff case.
//!
//! A proposal records intent and exact historical Source pins. It does not
//! authorize recipient acceptance, prove no prior work, establish custody,
//! create a Running Assignment, or apply a handoff.

mod abort;
mod proposal_codec;
mod proposal_model;
mod proposal_schema;
mod proposals;

pub(super) mod applications;

pub(crate) use abort::{abort_unstarted, get_terminal};
pub use applications::{
    HomeHandoffAcceptanceOutcome, HomeHandoffAcceptanceOutcomeKind,
    HomeHandoffAcceptanceOutcomeRecord, HomeHandoffApplicationStoreError,
    HomeHandoffAppliedAcceptance, HomeHandoffInitialSuccessorSnapshot,
};
pub(crate) use applications::{
    HomeHandoffAcceptanceOutcomeRecordParts, HomeHandoffAcceptanceTerminal,
    create_schema as create_applications_schema, get_applied_origin_for_assignment, get_outcome,
    handoff_is_applied, home_origin_matches_applied_receipt, insert_outcome_in_transaction,
    schema_objects as applications_schema_objects, validate_schema as validate_applications_schema,
};
use proposal_codec::decode_record as decode_proposal_record;
pub use proposal_model::{
    HomeHandoffAssignmentLineage, HomeHandoffCaseSnapshot, HomeHandoffProposalEvidence,
    HomeHandoffProposalOutcome, HomeHandoffProposalRecord, HomeHandoffSourceAssignmentPin,
};
pub(crate) use proposal_schema::{create_schema, schema_objects, validate_schema};
pub(crate) use proposals::{
    HomeHandoffProposalHooks, get, get_current, get_current_in_transaction, get_in_transaction,
    propose,
};

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum HomeHandoffProposalStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Domain(#[from] forge_domain::HomeHandoffDomainError),
    #[error(transparent)]
    HomeTransfer(#[from] Box<super::HomeTransferStoreError>),
    #[error(transparent)]
    Artifact(#[from] Box<super::artifacts::HomeArtifactJournalError>),
    #[error(transparent)]
    AgentAssignment(#[from] Box<crate::AgentAssignmentStoreError>),
    #[error(transparent)]
    Agent(#[from] Box<crate::AgentStoreError>),
    #[error(transparent)]
    Coordinator(#[from] Box<crate::CoordinatorStoreError>),
    #[error(transparent)]
    Goal(#[from] Box<crate::GoalStoreError>),
    #[error(transparent)]
    Dag(#[from] Box<crate::DagStoreError>),
    #[error(transparent)]
    Migration(#[from] Box<crate::AgentOperationsMigrationError>),
    #[error(transparent)]
    Application(Box<applications::HomeHandoffApplicationStoreError>),
    #[error("Home handoff proposal source is invalid: {0}")]
    Conflict(&'static str),
    #[error("Home handoff proposal record is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("Home handoff proposal clock could not establish monotonic Source time")]
    Clock,
    #[error(
        "Home handoff proposal {proposal_id} for handoff {handoff_id} may have committed; read that exact identity"
    )]
    CommitUnconfirmed {
        handoff_id: Uuid,
        proposal_id: Uuid,
        #[source]
        source: Box<rusqlite::Error>,
    },
    #[error(
        "Home handoff proposal {proposal_id} for handoff {handoff_id} committed; exact readback is required"
    )]
    ReadbackRequired { handoff_id: Uuid, proposal_id: Uuid },
}
