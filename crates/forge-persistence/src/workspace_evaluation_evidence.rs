//! Workspace-owned source receipts and immutable evaluation cuts.

mod repository;
mod schema;

pub(crate) use repository::{
    EvaluationT1ClosureOutcome, assignment_requires_source_clock_in_transaction,
    close_t1_in_transaction, create_review_cut_in_transaction,
    get_registered_manifest_in_transaction, get_review_cut_in_transaction,
    get_review_receipt_in_transaction, get_submission_receipt_in_transaction,
    get_t1_cut_in_transaction, record_review_in_transaction, record_submission_in_transaction,
    seal_manifest_in_transaction,
};
pub(crate) use schema::{create_schema, schema_objects, validate_schema};

use std::error::Error;

use rusqlite::Error as SqliteError;
use thiserror::Error as ThisError;

use forge_domain::EvaluationEvidenceError;

#[derive(Debug, ThisError)]
pub(crate) enum EvaluationEvidenceStoreError {
    #[error(transparent)]
    Sqlite(#[from] SqliteError),
    #[error(transparent)]
    Domain(#[from] EvaluationEvidenceError),
    #[error("exact source assignment lookup failed")]
    AssignmentLookup(#[source] Box<dyn Error + Send + Sync + 'static>),
    #[error("source delegation lookup failed")]
    SourceDelegation(#[source] Box<dyn Error + Send + Sync + 'static>),
    #[error("evaluation source scope differs from the active Workspace delegation")]
    SourceScopeMismatch,
    #[error("Workspace has no active source delegation for evaluation evidence")]
    MissingDelegation,
    #[error("evaluation manifest identity already exists with different contents")]
    ManifestConflict,
    #[error("original assignment binding conflicts with a previously sealed unit or criteria")]
    OriginalBindingConflict,
    #[error("assignment is not an original coordinator offer in the requested source scope")]
    InvalidOriginalAssignment,
    #[error("assignment revision does not match the exact registered source revision")]
    AssignmentRevisionConflict,
    #[error("assignment is missing from the source Workspace")]
    AssignmentNotFound,
    #[error("evaluation source receipt conflicts with the exact assignment version")]
    ReceiptConflict,
    #[error("evaluation cut identity already exists with different contents")]
    CutConflict,
    #[error("requested source evaluation record was not found")]
    RecordNotFound,
    #[error("persisted evaluation source record is damaged: {0}")]
    CorruptRecord(&'static str),
}
