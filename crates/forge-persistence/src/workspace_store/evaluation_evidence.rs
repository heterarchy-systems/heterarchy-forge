//! Workspace-bound facade for Forge-owned evaluation source evidence.

use forge_domain::{
    AgentAssignmentId, AgentAssignmentRevision, EvaluationAdmissionTiming, EvaluationClockReading,
    EvaluationCutId, EvaluationDigest, EvaluationManifestId, EvaluationManifestProposal,
    EvaluationRegisteredManifest, EvaluationReviewCut, EvaluationReviewCutId,
    EvaluationReviewReceipt, EvaluationRevision, EvaluationSubmissionReceipt,
    EvaluationT1CloseRequest, EvaluationT1CoverageCut, ForgeBackendId, ReviewAgentAssignment,
    SubmitAgentAssignment, TimestampMillis, WorkspaceId,
};
use rusqlite::{Transaction, TransactionBehavior};
use thiserror::Error;

use crate::{workspace_agent_assignments, workspace_evaluation_evidence};

use super::{WorkspaceStore, WorkspaceStoreError};

/// Exact durable selector for resolving an uncertain evaluation mutation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationEvidenceMutationIdentity {
    /// Immutable manifest creation or exact replay.
    Manifest {
        /// Stable manifest identity.
        manifest_id: EvaluationManifestId,
        /// Immutable manifest revision.
        revision: EvaluationRevision,
        /// Canonical payload digest from the exact proposal.
        digest: EvaluationDigest,
    },
    /// One assignment submission revision and its optional source receipt.
    Submission {
        /// Stable Forge assignment identity.
        assignment_id: AgentAssignmentId,
        /// Exact submitted assignment revision.
        submitted_revision: AgentAssignmentRevision,
    },
    /// One review of one exact submitted assignment revision.
    Review {
        /// Stable Forge assignment identity.
        assignment_id: AgentAssignmentId,
        /// Exact submitted assignment revision under review.
        submitted_revision: AgentAssignmentRevision,
        /// Exact review assignment revision.
        review_revision: AgentAssignmentRevision,
    },
    /// One exact T1 closure request. An absent cut does not prove no clock state changed.
    T1Closure {
        /// Complete checked request, including the frozen manifest and deadline fences.
        request: EvaluationT1CloseRequest,
    },
    /// One review cut over an exact T1 coverage cut.
    ReviewCut {
        /// Stable review-cut identity.
        review_cut_id: EvaluationReviewCutId,
        /// Exact T1 cut identity.
        t1_cut_id: EvaluationCutId,
    },
}

/// T1 closure result. `NotClosed` may still commit clock-health uncertainty.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationT1ClosureOutcome {
    /// Closure was not yet certified; source-clock uncertainty may be durable.
    NotClosed(EvaluationAdmissionTiming),
    /// Exact immutable T1 coverage cut was created or replayed.
    Closed(EvaluationT1CoverageCut),
}

/// Assignment submit plus the source receipt committed in the same SQLite transaction.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationAssignmentSubmission {
    assignment: forge_domain::RegisteredAgentAssignment,
    receipt: Option<EvaluationSubmissionReceipt>,
}

impl EvaluationAssignmentSubmission {
    /// Assignment state committed with this evidence attempt.
    pub const fn assignment(&self) -> &forge_domain::RegisteredAgentAssignment {
        &self.assignment
    }

    /// Exact source receipt, if the assignment belongs to registered evaluation evidence.
    pub const fn receipt(&self) -> Option<&EvaluationSubmissionReceipt> {
        self.receipt.as_ref()
    }
}

/// Assignment review plus its source receipt committed in the same SQLite transaction.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationAssignmentReview {
    assignment: forge_domain::RegisteredAgentAssignment,
    receipt: Option<EvaluationReviewReceipt>,
}

impl EvaluationAssignmentReview {
    /// Assignment state committed with this review evidence attempt.
    pub const fn assignment(&self) -> &forge_domain::RegisteredAgentAssignment {
        &self.assignment
    }

    /// Exact source review receipt, if this version is under registered evaluation evidence.
    pub const fn receipt(&self) -> Option<&EvaluationReviewReceipt> {
        self.receipt.as_ref()
    }
}

impl WorkspaceStore {
    /// Seal the exact source manifest and original assignment bindings.
    ///
    /// The assignment lookup and clock sampler execute inside the same IMMEDIATE
    /// transaction that stores the immutable source manifest.
    pub fn seal_evaluation_manifest<C>(
        &mut self,
        actual_backend: ForgeBackendId,
        proposal: &EvaluationManifestProposal,
        sample_clock: C,
    ) -> Result<EvaluationRegisteredManifest, WorkspaceStoreError>
    where
        C: FnOnce() -> EvaluationClockReading,
    {
        self.ensure_live_binding()?;
        let identity = EvaluationEvidenceMutationIdentity::Manifest {
            manifest_id: proposal.manifest_id(),
            revision: proposal.revision(),
            digest: proposal.digest(),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let manifest = workspace_evaluation_evidence::seal_manifest_in_transaction(
            &transaction,
            actual_backend,
            proposal,
            |transaction, assignment_id| {
                workspace_agent_assignments::get_in_transaction(transaction, assignment_id)
            },
            sample_clock,
        )
        .map_err(|error| WorkspaceStoreError::EvaluationEvidence(Box::new(error)))?;
        if let Err(source) = transaction.commit() {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        let live_binding = self
            .capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding());
        if let Err(source) = live_binding {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        Ok(manifest)
    }

    /// Read one exact registered manifest from one SQLite snapshot.
    pub fn get_evaluation_manifest(
        &self,
        actual_backend: ForgeBackendId,
        manifest_id: EvaluationManifestId,
        revision: EvaluationRevision,
    ) -> Result<Option<EvaluationRegisteredManifest>, WorkspaceStoreError> {
        self.read_evaluation_snapshot(|transaction, _workspace_id| {
            workspace_evaluation_evidence::get_registered_manifest_in_transaction(
                transaction,
                actual_backend,
                manifest_id,
                revision,
            )
        })
    }

    /// Close the exact frozen T1 cut using a source-clock observation.
    ///
    /// The supplied deadline must equal the deadline sealed into the manifest.
    /// A `NotClosed` outcome is committed because it can persist source-clock
    /// uncertainty; an absent cut after an unknown commit does not prove no effect.
    pub fn close_evaluation_t1<C>(
        &mut self,
        actual_backend: ForgeBackendId,
        request: &EvaluationT1CloseRequest,
        sample_clock: C,
    ) -> Result<EvaluationT1ClosureOutcome, WorkspaceStoreError>
    where
        C: FnOnce() -> EvaluationClockReading,
    {
        self.ensure_live_binding()?;
        let identity = EvaluationEvidenceMutationIdentity::T1Closure { request: *request };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = workspace_evaluation_evidence::close_t1_in_transaction(
            &transaction,
            actual_backend,
            request,
            |transaction, assignment_id| {
                workspace_agent_assignments::get_in_transaction(transaction, assignment_id)
            },
            sample_clock,
        )
        .map_err(|error| WorkspaceStoreError::EvaluationEvidence(Box::new(error)))?;
        let outcome = match outcome {
            workspace_evaluation_evidence::EvaluationT1ClosureOutcome::NotClosed(timing) => {
                EvaluationT1ClosureOutcome::NotClosed(timing)
            }
            workspace_evaluation_evidence::EvaluationT1ClosureOutcome::Closed(cut) => {
                EvaluationT1ClosureOutcome::Closed(cut)
            }
        };
        if let Err(source) = transaction.commit() {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        let live_binding = self
            .capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding());
        if let Err(source) = live_binding {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        Ok(outcome)
    }

    /// Read one exact immutable T1 coverage cut.
    pub fn get_evaluation_t1_cut(
        &self,
        actual_backend: ForgeBackendId,
        cut_id: EvaluationCutId,
    ) -> Result<Option<EvaluationT1CoverageCut>, WorkspaceStoreError> {
        self.read_evaluation_snapshot(|transaction, _workspace_id| {
            workspace_evaluation_evidence::get_t1_cut_in_transaction(
                transaction,
                actual_backend,
                cut_id,
            )
        })
    }

    /// Freeze reviews against the exact T1 cut and source high-water.
    pub fn create_evaluation_review_cut<C>(
        &mut self,
        actual_backend: ForgeBackendId,
        review_cut_id: EvaluationReviewCutId,
        t1_cut_id: EvaluationCutId,
        sample_clock: C,
    ) -> Result<EvaluationReviewCut, WorkspaceStoreError>
    where
        C: FnOnce() -> EvaluationClockReading,
    {
        self.ensure_live_binding()?;
        let identity = EvaluationEvidenceMutationIdentity::ReviewCut {
            review_cut_id,
            t1_cut_id,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cut = workspace_evaluation_evidence::create_review_cut_in_transaction(
            &transaction,
            actual_backend,
            review_cut_id,
            t1_cut_id,
            |transaction, assignment_id| {
                workspace_agent_assignments::get_in_transaction(transaction, assignment_id)
            },
            sample_clock,
        )
        .map_err(|error| WorkspaceStoreError::EvaluationEvidence(Box::new(error)))?;
        if let Err(source) = transaction.commit() {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        let live_binding = self
            .capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding());
        if let Err(source) = live_binding {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        Ok(cut)
    }

    /// Read one exact immutable review cut.
    pub fn get_evaluation_review_cut(
        &self,
        actual_backend: ForgeBackendId,
        review_cut_id: EvaluationReviewCutId,
    ) -> Result<Option<EvaluationReviewCut>, WorkspaceStoreError> {
        self.read_evaluation_snapshot(|transaction, _workspace_id| {
            workspace_evaluation_evidence::get_review_cut_in_transaction(
                transaction,
                actual_backend,
                review_cut_id,
            )
        })
    }

    /// Read one immutable submission receipt at its exact submitted revision.
    pub fn get_evaluation_submission_receipt(
        &self,
        actual_backend: ForgeBackendId,
        assignment_id: AgentAssignmentId,
        submitted_revision: AgentAssignmentRevision,
    ) -> Result<Option<EvaluationSubmissionReceipt>, WorkspaceStoreError> {
        self.read_evaluation_snapshot(|transaction, workspace_id| {
            workspace_evaluation_evidence::get_submission_receipt_in_transaction(
                transaction,
                actual_backend,
                workspace_id,
                assignment_id,
                submitted_revision,
            )
        })
    }

    /// Read one immutable review receipt linked to exact submitted and review revisions.
    pub fn get_evaluation_review_receipt(
        &self,
        actual_backend: ForgeBackendId,
        assignment_id: AgentAssignmentId,
        submitted_revision: AgentAssignmentRevision,
        review_revision: AgentAssignmentRevision,
    ) -> Result<Option<EvaluationReviewReceipt>, WorkspaceStoreError> {
        self.read_evaluation_snapshot(|transaction, workspace_id| {
            workspace_evaluation_evidence::get_review_receipt_in_transaction(
                transaction,
                actual_backend,
                workspace_id,
                assignment_id,
                submitted_revision,
                review_revision,
            )
        })
    }

    /// Submit an Agent result and record its source-clock receipt atomically.
    pub fn submit_agent_assignment_with_source_clock<C>(
        &mut self,
        command: &SubmitAgentAssignment,
        admitted_at: TimestampMillis,
        actual_backend: ForgeBackendId,
        sample_clock: C,
    ) -> Result<EvaluationAssignmentSubmission, WorkspaceStoreError>
    where
        C: FnOnce() -> EvaluationClockReading,
    {
        self.ensure_live_binding()?;
        let result = workspace_agent_assignments::submit_with_source_clock(
            &mut self.connection,
            command,
            admitted_at,
            actual_backend,
            sample_clock,
        );
        let (assignment, receipt) = match result {
            Ok(value) => value,
            Err(error) => return Err(map_assignment_evaluation_error(self, error)),
        };
        let identity = EvaluationEvidenceMutationIdentity::Submission {
            assignment_id: assignment.id(),
            submitted_revision: assignment.revision(),
        };
        let live_binding = self
            .capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding());
        if let Err(source) = live_binding {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        Ok(EvaluationAssignmentSubmission {
            assignment,
            receipt,
        })
    }

    /// Accept a submitted result and record its exact source review atomically.
    pub fn accept_agent_assignment_with_source_clock<C>(
        &mut self,
        command: &ReviewAgentAssignment,
        admitted_at: TimestampMillis,
        actual_backend: ForgeBackendId,
        sample_clock: C,
    ) -> Result<EvaluationAssignmentReview, WorkspaceStoreError>
    where
        C: FnOnce() -> EvaluationClockReading,
    {
        self.review_agent_assignment_with_source_clock(
            command,
            admitted_at,
            actual_backend,
            sample_clock,
            true,
        )
    }

    /// Reject a submitted result and record its exact source review atomically.
    pub fn reject_agent_assignment_with_source_clock<C>(
        &mut self,
        command: &ReviewAgentAssignment,
        admitted_at: TimestampMillis,
        actual_backend: ForgeBackendId,
        sample_clock: C,
    ) -> Result<EvaluationAssignmentReview, WorkspaceStoreError>
    where
        C: FnOnce() -> EvaluationClockReading,
    {
        self.review_agent_assignment_with_source_clock(
            command,
            admitted_at,
            actual_backend,
            sample_clock,
            false,
        )
    }

    fn review_agent_assignment_with_source_clock<C>(
        &mut self,
        command: &ReviewAgentAssignment,
        admitted_at: TimestampMillis,
        actual_backend: ForgeBackendId,
        sample_clock: C,
        accepted: bool,
    ) -> Result<EvaluationAssignmentReview, WorkspaceStoreError>
    where
        C: FnOnce() -> EvaluationClockReading,
    {
        self.ensure_live_binding()?;
        let result = if accepted {
            workspace_agent_assignments::accept_with_source_clock(
                &mut self.connection,
                command,
                admitted_at,
                actual_backend,
                sample_clock,
            )
        } else {
            workspace_agent_assignments::reject_with_source_clock(
                &mut self.connection,
                command,
                admitted_at,
                actual_backend,
                sample_clock,
            )
        };
        let (assignment, receipt) = match result {
            Ok(value) => value,
            Err(error) => return Err(map_assignment_evaluation_error(self, error)),
        };
        let identity = EvaluationEvidenceMutationIdentity::Review {
            assignment_id: assignment.id(),
            submitted_revision: command.expected_revision(),
            review_revision: assignment.revision(),
        };
        let live_binding = self
            .capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding());
        if let Err(source) = live_binding {
            return Err(evaluation_commit_unconfirmed(
                self,
                identity,
                Box::new(source),
            ));
        }
        Ok(EvaluationAssignmentReview {
            assignment,
            receipt,
        })
    }

    fn read_evaluation_snapshot<T, F>(&self, read: F) -> Result<T, WorkspaceStoreError>
    where
        F: FnOnce(
            &Transaction<'_>,
            WorkspaceId,
        )
            -> Result<T, crate::workspace_evaluation_evidence::EvaluationEvidenceStoreError>,
    {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let transaction = self.connection.unchecked_transaction()?;
        let value = read(&transaction, workspace_id)
            .map_err(|error| WorkspaceStoreError::EvaluationEvidence(Box::new(error)))?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(value)
    }
}

fn map_assignment_evaluation_error(
    store: &mut WorkspaceStore,
    error: crate::AgentAssignmentStoreError,
) -> WorkspaceStoreError {
    match error {
        crate::AgentAssignmentStoreError::EvaluationEvidenceCommitUnconfirmed {
            identity,
            source,
        } => evaluation_commit_unconfirmed(store, identity, source),
        crate::AgentAssignmentStoreError::EvaluationEvidence(source) => {
            WorkspaceStoreError::EvaluationEvidence(source)
        }
        error => WorkspaceStoreError::AgentAssignment(error),
    }
}

fn evaluation_commit_unconfirmed(
    store: &mut WorkspaceStore,
    identity: EvaluationEvidenceMutationIdentity,
    commit_source: Box<dyn std::error::Error + Send + Sync + 'static>,
) -> WorkspaceStoreError {
    let source = match store
        .capture_sidecar_identities()
        .and_then(|()| store.ensure_live_binding())
    {
        Ok(()) => commit_source,
        Err(live_binding_source) => Box::new(EvaluationCommitAndRefreshError {
            commit_source,
            live_binding_source,
        }) as Box<dyn std::error::Error + Send + Sync>,
    };
    WorkspaceStoreError::EvaluationEvidenceCommittedUnconfirmed { identity, source }
}

#[derive(Debug, Error)]
#[error("evaluation commit is unconfirmed and live binding refresh failed")]
struct EvaluationCommitAndRefreshError {
    #[source]
    commit_source: Box<dyn std::error::Error + Send + Sync + 'static>,
    live_binding_source: WorkspaceStoreError,
}
