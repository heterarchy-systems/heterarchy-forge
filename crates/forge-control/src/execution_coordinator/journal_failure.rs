//! Bounded first-failure diagnostics; never execution or recovery authority.

use super::{CoordinatorRuntime, ForgeExecutionCoordinatorError};
use crate::{ControlClientError, ControlErrorCode, ControlErrorView, ControlOperationOutcome};
use forge_persistence::{ExecutionStoreError as Execution, WorkspaceStoreError as Store};
use std::error::Error as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalFailureStage {
    StartIdentity,
    StartObservation,
    OutputRead,
    OutputIdentity,
    OutputWrite,
    OutputReadback,
    OutputAcknowledgement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalFailure {
    pub stage: JournalFailureStage,
    pub code: Option<ControlErrorCode>,
    pub outcome: Option<ControlOperationOutcome>,
    pub persistence: Option<JournalPersistenceFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalPersistenceFailure {
    Sqlite { extended_code: Option<i32> },
    SidecarPairMismatch,
    DamagedSchema,
    ExecutionOutputConflict,
    CorruptExecution,
    OtherExecution,
    OtherWorkspace,
}

fn persistence_failure(error: &ControlClientError) -> Option<JournalPersistenceFailure> {
    let ControlClientError::Service(error) = error else {
        return None;
    };
    let source = error
        .source()?
        .downcast_ref::<forge_persistence::WorkspaceStoreError>()?;
    Some(match source {
        Store::Sqlite(error) | Store::Execution(Execution::Sqlite(error)) => {
            JournalPersistenceFailure::Sqlite {
                extended_code: error.sqlite_extended_error_code(),
            }
        }
        Store::DatabaseSidecarPairMismatch { .. } => JournalPersistenceFailure::SidecarPairMismatch,
        Store::DamagedSchema { .. } => JournalPersistenceFailure::DamagedSchema,
        Store::Execution(Execution::OutputEventConflict) => {
            JournalPersistenceFailure::ExecutionOutputConflict
        }
        Store::Execution(Execution::CorruptRecord(_)) => {
            JournalPersistenceFailure::CorruptExecution
        }
        Store::Execution(_) => JournalPersistenceFailure::OtherExecution,
        _ => JournalPersistenceFailure::OtherWorkspace,
    })
}

impl CoordinatorRuntime {
    pub(super) fn latch_journal_failure(
        &mut self,
        stage: JournalFailureStage,
        view: Option<&ControlErrorView>,
    ) {
        if !self.journal_failed {
            let failure = JournalFailure {
                stage,
                code: view.map(|view| view.code()),
                outcome: view.map(|view| view.outcome()),
                persistence: None,
            };
            tracing::error!(stage = ?failure.stage, code = ?failure.code, outcome = ?failure.outcome,
                "execution journal first failure");
            self.first_journal_failure = Some(failure);
        }
        self.journal_failed = true;
    }

    pub(super) fn latch_journal_service_failure(
        &mut self,
        stage: JournalFailureStage,
        error: &ControlClientError,
    ) {
        let first = !self.journal_failed;
        self.latch_journal_failure(stage, Some(&error.view()));
        if first && let Some(failure) = self.first_journal_failure.as_mut() {
            failure.persistence = persistence_failure(error);
            tracing::error!(persistence = ?failure.persistence, "execution journal failure category");
        }
    }

    pub(super) fn journal_failure_error(&self) -> ForgeExecutionCoordinatorError {
        self.first_journal_failure.map_or(
            ForgeExecutionCoordinatorError::JournalFailed,
            ForgeExecutionCoordinatorError::JournalFailure,
        )
    }
}
