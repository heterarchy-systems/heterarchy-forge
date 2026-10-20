//! Exact bounded cleanup plans behind the checked Workspace store binding.

use super::{WorkspaceStore, WorkspaceStoreError, workspace_approvals};
use crate::{
    ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId, ApprovalCleanupMode,
    ApprovalCleanupPlan, ApprovalCleanupReadback, ApprovalCleanupSelector,
};
use forge_domain::{ExecutionListLimit, TimestampMillis};

impl WorkspaceStore {
    /// Capture exact eligible targets from one consistent Workspace snapshot.
    pub fn prepare_approval_cleanup(
        &self,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<ApprovalCleanupPlan, WorkspaceStoreError> {
        self.prepare_approval_cleanup_for_mode(
            selector,
            observed_at,
            limit,
            ApprovalCleanupMode::AuthorityCancellation,
        )
    }

    /// Capture only elapsed authority; active non-expired rows remain untouched.
    pub fn prepare_expired_approval_cleanup(
        &self,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<ApprovalCleanupPlan, WorkspaceStoreError> {
        self.prepare_approval_cleanup_for_mode(
            selector,
            observed_at,
            limit,
            ApprovalCleanupMode::ExpiredOnly,
        )
    }

    fn prepare_approval_cleanup_for_mode(
        &self,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
        mode: ApprovalCleanupMode,
    ) -> Result<ApprovalCleanupPlan, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let plan = workspace_approvals::prepare_cleanup_plan(
            &self.connection,
            workspace_id,
            selector,
            observed_at,
            limit,
            mode,
        )?;
        self.ensure_live_binding()?;
        Ok(plan)
    }

    /// Apply only an immutable plan; a successful commit still needs live binding confirmation.
    pub fn apply_approval_cleanup(
        &mut self,
        plan: &ApprovalCleanupPlan,
        attempt: ApprovalCleanupAttemptId,
    ) -> Result<ApprovalCleanupApplyOutcome, WorkspaceStoreError> {
        let outcome = self.apply_approval_cleanup_transaction(plan, attempt)?;
        self.confirm_approval_cleanup_outcome(&outcome)?;
        Ok(outcome)
    }

    fn apply_approval_cleanup_transaction(
        &mut self,
        plan: &ApprovalCleanupPlan,
        attempt: ApprovalCleanupAttemptId,
    ) -> Result<ApprovalCleanupApplyOutcome, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        workspace_approvals::apply_cleanup_plan(&mut self.connection, workspace_id, plan, attempt)
            .map_err(Into::into)
    }

    fn confirm_approval_cleanup_commit(&mut self) -> Result<(), WorkspaceStoreError> {
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::ApprovalCleanupCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )
    }

    fn confirm_approval_cleanup_outcome(
        &mut self,
        outcome: &ApprovalCleanupApplyOutcome,
    ) -> Result<(), WorkspaceStoreError> {
        match outcome {
            ApprovalCleanupApplyOutcome::Applied(_) => self.confirm_approval_cleanup_commit(),
            ApprovalCleanupApplyOutcome::RejectedBeforeWrite(_) => {
                self.capture_sidecar_identities()?;
                self.ensure_live_binding()
            }
        }
    }

    #[cfg(test)]
    pub(super) fn apply_approval_cleanup_with_posttransaction_hook(
        &mut self,
        plan: &ApprovalCleanupPlan,
        attempt: ApprovalCleanupAttemptId,
        hook: impl FnOnce(&mut Self),
    ) -> Result<ApprovalCleanupApplyOutcome, WorkspaceStoreError> {
        let outcome = self.apply_approval_cleanup_transaction(plan, attempt)?;
        hook(self);
        self.confirm_approval_cleanup_outcome(&outcome)?;
        Ok(outcome)
    }

    /// Observe every exact before/after image; unavailable bindings return errors, never Absent.
    pub fn observe_approval_cleanup(
        &self,
        plan: &ApprovalCleanupPlan,
    ) -> Result<ApprovalCleanupReadback, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let workspace_id = self.workspace()?.id();
        let result =
            workspace_approvals::observe_cleanup_plan(&self.connection, workspace_id, plan)?;
        self.ensure_live_binding()?;
        Ok(result)
    }
}
