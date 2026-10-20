//! Request-identified Goal writes and historical immutable receipt reads.
use crate::goal::{goal_from_store, map_goal_store_error, review_goal_with_files};
use crate::{ControlError, ControlErrorCode, ForgeControl, ResolvedWorkspaceScope};
use forge_domain::{
    ActivityId, GoalId, GoalMutationAction, GoalMutationCommand, GoalMutationDigest,
    GoalMutationReceipt, GoalMutationRequestId, GoalReview,
};
use forge_persistence::{
    GoalCompletionReceipt, GoalMutationResult, GoalMutationStoreError, WorkspaceStore,
    WorkspaceStoreError,
};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalMutationRequest {
    pub scope: ResolvedWorkspaceScope,
    pub command: GoalMutationCommand,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalMutationReadbackRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub goal_id: GoalId,
    pub mutation_request_id: GoalMutationRequestId,
    pub expected_request_digest: Option<GoalMutationDigest>,
}

impl ForgeControl {
    pub(crate) fn goal_mutation(
        &self,
        request: &GoalMutationRequest,
        admitted_at: forge_domain::TimestampMillis,
    ) -> Result<GoalMutationResult, ControlError> {
        let command = &request.command;
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: command.actor().session_id(),
            principal: command.actor().principal(),
        })?;
        if command.actor().workspace_id() != request.scope.workspace_id()
            || command.workspace_revision() != request.scope.workspace_revision()
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        let (scope, layout, mut store) = self.open_goal_workspace_with_layout(&request.scope)?;
        let completion = if matches!(command.action(), GoalMutationAction::Complete { .. }) {
            if let Some(result) = store
                .replay_goal_mutation(command, admitted_at)
                .map_err(map_mutation_error)?
            {
                self.confirm_goal_mutation_result(&scope, &store)?;
                return Ok(result);
            }
            match prepare_completion(&store, &layout, command) {
                Ok(proof) => Some(proof),
                Err(error) => {
                    // A concurrent identical completion may have committed while
                    // its filesystem/evidence review was being observed.
                    if let Some(result) = store
                        .replay_goal_mutation(command, admitted_at)
                        .map_err(map_mutation_error)?
                    {
                        self.confirm_goal_mutation_result(&scope, &store)?;
                        return Ok(result);
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        let proof = completion
            .as_ref()
            .map(|(review, receipt)| (review, receipt));
        let result = store
            .apply_goal_mutation(command, proof, admitted_at)
            .map_err(map_mutation_error)?;
        self.confirm_goal_mutation_result(&scope, &store)?;
        Ok(result)
    }

    pub fn goal_mutation_readback(
        &self,
        request: &GoalMutationReadbackRequest,
    ) -> Result<Option<GoalMutationReceipt>, ControlError> {
        let (scope, mut store) = self.open_goal_workspace(&request.scope)?;
        let receipt = store
            .goal_mutation_receipt(request.mutation_request_id)
            .map_err(map_mutation_error)?;
        if let Some(receipt) = &receipt {
            let data = receipt.data();
            if data.request_id != request.mutation_request_id
                || data.actor.workspace_id() != scope.workspace_id()
                || data.actor.activity_id() != request.activity_id
                || data.goal_id != request.goal_id
                || request
                    .expected_request_digest
                    .is_some_and(|digest| digest != data.digest)
            {
                return Err(ControlError::new(ControlErrorCode::GoalConflict));
            }
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(receipt)
    }

    fn confirm_goal_mutation_result(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> Result<(), ControlError> {
        if self.committed_scope_matches_with_store(scope, store) {
            Ok(())
        } else {
            Err(ControlError::committed())
        }
    }
}

fn prepare_completion(
    store: &WorkspaceStore,
    layout: &forge_workspace::ExistingWorkspaceStateLayout,
    command: &GoalMutationCommand,
) -> Result<(GoalReview, GoalCompletionReceipt), ControlError> {
    let GoalMutationAction::Complete { review_id } = command.action() else {
        return Err(ControlError::new(ControlErrorCode::InvalidInput));
    };
    let current = goal_from_store(
        store,
        command.goal_id(),
        command.actor().workspace_id(),
        command.actor().activity_id(),
    )?;
    let expected = command
        .expected_revision()
        .ok_or_else(|| ControlError::new(ControlErrorCode::InvalidInput))?;
    if current.revision() != expected {
        return Err(ControlError::new(ControlErrorCode::GoalConflict));
    }
    let review = review_goal_with_files(store, layout, &current)?;
    if !review.can_complete() {
        return Err(ControlError::new(ControlErrorCode::GoalCompletionBlocked));
    }
    let count = store
        .list_goal_evidence(current.id(), crate::goal::MAX_GOAL_EVIDENCE_RESULTS)
        .map_err(map_goal_store_error)?
        .len();
    let receipt = GoalCompletionReceipt::new(
        *review_id,
        current.id(),
        expected,
        command.observed_at(),
        u16::try_from(review.hard_checks().len())
            .map_err(|_| ControlError::new(ControlErrorCode::CapacityExceeded))?,
        u16::try_from(count).map_err(|_| ControlError::new(ControlErrorCode::CapacityExceeded))?,
    );
    Ok((review, receipt))
}

fn map_mutation_error(error: WorkspaceStoreError) -> ControlError {
    match error {
        WorkspaceStoreError::PlanningCommittedUnconfirmed { .. } => ControlError::committed(),
        WorkspaceStoreError::GoalMutation(GoalMutationStoreError::Goal(source)) => {
            map_goal_store_error(WorkspaceStoreError::Goal(source))
        }
        WorkspaceStoreError::GoalMutation(GoalMutationStoreError::Coordinator(source)) => {
            crate::coordinator::map_coordinator_store_error(WorkspaceStoreError::Coordinator(
                source,
            ))
        }
        error @ WorkspaceStoreError::GoalMutation(
            GoalMutationStoreError::RequestIdentityConflict,
        ) => ControlError::with_source(ControlErrorCode::GoalConflict, error),
        error @ WorkspaceStoreError::GoalMutation(
            GoalMutationStoreError::MissingCompletionProof,
        ) => ControlError::with_source(ControlErrorCode::GoalCompletionBlocked, error),
        error @ WorkspaceStoreError::GoalMutation(
            GoalMutationStoreError::WorkspaceRevisionConflict,
        ) => ControlError::with_source(ControlErrorCode::WorkspaceRevisionConflict, error),
        error => map_goal_store_error(error),
    }
}
