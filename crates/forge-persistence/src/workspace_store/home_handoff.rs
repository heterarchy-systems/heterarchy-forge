//! Live Workspace access to immutable Home proposals and their actual ledger.

use forge_domain::{
    AgentAssignmentHomeHandoffOrigin, AgentAssignmentId, ForgeBackendId,
    HomeHandoffProposalRequest, HomeHandoffTakeRequest, OrchestrationIssuerId, TimestampMillis,
};
use rusqlite::Connection;
use uuid::Uuid;

use super::{WorkspaceStore, WorkspaceStoreError};
use crate::workspace_home_transfers::handoffs::{
    self, HomeHandoffAcceptanceOutcomeRecord, HomeHandoffApplicationStoreError,
    HomeHandoffCaseSnapshot, HomeHandoffProposalHooks, HomeHandoffProposalOutcome,
    HomeHandoffProposalRecord, HomeHandoffProposalStoreError,
};

/// Read the immutable application owner in the proposal's own transaction.
/// There is no cached decision or permissive missing-ledger fallback.
struct DurableHomeHandoffApplications;

impl HomeHandoffProposalHooks for DurableHomeHandoffApplications {
    fn handoff_is_applied(
        &self,
        connection: &Connection,
        handoff_id: Uuid,
    ) -> Result<bool, HomeHandoffProposalStoreError> {
        Ok(handoffs::handoff_is_applied(connection, handoff_id)?)
    }

    fn home_origin_matches_applied_receipt(
        &self,
        connection: &Connection,
        successor_assignment_id: AgentAssignmentId,
        origin: AgentAssignmentHomeHandoffOrigin,
    ) -> Result<bool, HomeHandoffProposalStoreError> {
        Ok(handoffs::home_origin_matches_applied_receipt(
            connection,
            successor_assignment_id,
            origin,
        )?)
    }
}

impl WorkspaceStore {
    /// Permanently prevent a never-applied acceptance or return its existing
    /// exact terminal result. An existing Applied result is never undone.
    ///
    /// The private service caller must authenticate its configured issuer.
    /// Recovery does not require completed Operations admission, current
    /// recipient eligibility or a current proposal head. Source validates the
    /// exact historical proposal and Prepared parent in the writer transaction.
    ///
    /// # Errors
    /// Rejects changed request/service identity, corrupt history, invalid Source
    /// time, and uncertain commit or live-binding outcomes. An uncertain outcome
    /// requires exact terminal readback and does not authorize hold release.
    pub fn abort_unstarted_home_assignment_handoff<C>(
        &mut self,
        request: &HomeHandoffTakeRequest,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
        sample_clock: C,
    ) -> Result<HomeHandoffAcceptanceOutcomeRecord, WorkspaceStoreError>
    where
        C: FnOnce() -> Result<TimestampMillis, HomeHandoffApplicationStoreError>,
    {
        self.ensure_live_binding()?;
        let outcome = handoffs::abort_unstarted(
            &mut self.connection,
            request,
            issuer,
            backend,
            destination,
            sample_clock,
        )
        .map_err(application_error)?;
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::HomeHandoffAcceptanceReadbackRequired {
                    acceptance_id: request.acceptance_id(),
                    source: Box::new(source),
                },
            )?;
        Ok(outcome)
    }

    /// Read exact Source terminal history. Absence alone is not cancellation.
    /// The caller authenticates the configured issuer before using this method.
    ///
    /// # Errors
    /// Rejects inconsistent history, changed service scope and loss of the live
    /// Workspace binding; this method never creates a new terminal outcome.
    pub fn get_home_assignment_handoff_acceptance(
        &self,
        acceptance_id: Uuid,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
    ) -> Result<Option<HomeHandoffAcceptanceOutcomeRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let outcome = handoffs::get_terminal(
            &self.connection,
            acceptance_id,
            issuer,
            backend,
            destination,
        )
        .map_err(application_error)?;
        self.ensure_live_binding()?;
        Ok(outcome)
    }

    /// Persist an exact Coordinator proposal or return its immutable replay.
    ///
    /// The caller authenticates the request's Coordinator. The Source owner
    /// checks its current authority, predecessor, recipient and case head.
    /// Recording a proposal grants neither recipient acceptance nor execution.
    ///
    /// # Errors
    /// Rejects changed identity, stale authority or head, invalid lineage,
    /// corrupt evidence, unavailable Source time and uncertain commit readback.
    pub fn propose_home_assignment_handoff<C>(
        &mut self,
        request: &HomeHandoffProposalRequest,
        sample_clock: C,
    ) -> Result<HomeHandoffProposalOutcome, WorkspaceStoreError>
    where
        C: FnOnce() -> Result<TimestampMillis, HomeHandoffProposalStoreError>,
    {
        self.ensure_live_binding()?;
        let outcome = handoffs::propose(
            &mut self.connection,
            request,
            &DurableHomeHandoffApplications,
            sample_clock,
        )
        .map_err(proposal_error)?;
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::HomeHandoffProposalReadbackRequired {
                    handoff_id: request.handoff_id(),
                    proposal_id: request.proposal_id(),
                    source: Box::new(source),
                },
            )?;
        Ok(outcome)
    }

    /// Read one exact proposal, including a superseded historical proposal.
    /// The result is history and does not authorize taking an obsolete head.
    ///
    /// # Errors
    /// Rejects corrupt proposal/parent/evidence records and a lost Workspace
    /// binding. A missing row does not prove an in-flight proposal cannot commit.
    pub fn get_home_assignment_handoff_proposal(
        &self,
        handoff_id: Uuid,
        proposal_id: Uuid,
    ) -> Result<Option<HomeHandoffProposalRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let record =
            handoffs::get(&self.connection, handoff_id, proposal_id).map_err(proposal_error)?;
        self.ensure_live_binding()?;
        Ok(record)
    }

    /// Read the exact case head and its immutable proposal in one snapshot.
    /// This observation is not an acceptance or a hold on later head changes.
    ///
    /// # Errors
    /// Rejects inconsistent head, proposal, Prepared parent or sealed artifact
    /// records and loss of the live Workspace binding.
    pub fn get_current_home_assignment_handoff(
        &self,
        handoff_id: Uuid,
    ) -> Result<Option<HomeHandoffCaseSnapshot>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let record = handoffs::get_current(&self.connection, handoff_id).map_err(proposal_error)?;
        self.ensure_live_binding()?;
        Ok(record)
    }
}

fn proposal_error(error: HomeHandoffProposalStoreError) -> WorkspaceStoreError {
    WorkspaceStoreError::HomeHandoffProposal(Box::new(error))
}

fn application_error(error: HomeHandoffApplicationStoreError) -> WorkspaceStoreError {
    WorkspaceStoreError::HomeHandoffApplication(Box::new(error))
}
