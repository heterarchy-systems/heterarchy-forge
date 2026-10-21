//! Goal mutation commands and historical receipt observation.
use super::{TransactionBehavior, WorkspaceStore, WorkspaceStoreError};
use crate::workspace_goal_mutations;

impl WorkspaceStore {
    pub fn apply_goal_mutation(
        &mut self,
        command: &forge_domain::GoalMutationCommand,
        completion: Option<(&forge_domain::GoalReview, &crate::GoalCompletionReceipt)>,
        admitted_at: forge_domain::TimestampMillis,
    ) -> Result<crate::GoalMutationResult, WorkspaceStoreError> {
        self.apply_goal_mutation_with_hook(command, completion, admitted_at, |_| {})
    }

    pub(super) fn apply_goal_mutation_with_hook<F>(
        &mut self,
        command: &forge_domain::GoalMutationCommand,
        completion: Option<(&forge_domain::GoalReview, &crate::GoalCompletionReceipt)>,
        admitted_at: forge_domain::TimestampMillis,
        after_commit: F,
    ) -> Result<crate::GoalMutationResult, WorkspaceStoreError>
    where
        F: FnOnce(&mut Self),
    {
        self.ensure_live_binding()?;
        let result = workspace_goal_mutations::mutate(
            &mut self.connection,
            command,
            completion,
            admitted_at,
        )?;
        after_commit(self);
        self.confirm_planning_commit()?;
        Ok(result)
    }

    pub fn replay_goal_mutation(
        &mut self,
        command: &forge_domain::GoalMutationCommand,
        admitted_at: forge_domain::TimestampMillis,
    ) -> Result<Option<crate::GoalMutationResult>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_goal_mutations::replay(&mut self.connection, command, admitted_at)?;
        if result.is_some() {
            self.confirm_planning_commit()?;
        } else {
            self.ensure_live_binding()?;
        }
        Ok(result)
    }

    pub fn goal_mutation_receipt(
        &mut self,
        request_id: forge_domain::GoalMutationRequestId,
    ) -> Result<Option<forge_domain::GoalMutationReceipt>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let result = workspace_goal_mutations::read_receipt(&transaction, request_id)?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }
}
