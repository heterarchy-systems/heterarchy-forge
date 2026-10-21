//! Control-plane admission and readback for terminal Activity successors.

use forge_domain::{
    ActivityId, ActivitySuccessorResult, AuthenticatedPrincipal, CreateActivitySuccessor,
};
use forge_persistence::WorkspaceStoreError;

use crate::agent_session::AgentSessionResolveRequest;
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivitySuccessorCreateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub command: CreateActivitySuccessor,
    pub principal: AuthenticatedPrincipal,
}

impl ForgeControl {
    /// Create or replay one terminal-Activity successor and its immutable
    /// predecessor relation in the existing Workspace transaction.
    pub fn activity_successor_create(
        &self,
        request: &ActivitySuccessorCreateRequest,
    ) -> Result<ActivitySuccessorResult, ControlError> {
        let session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.command.initiating_session_id(),
            principal: request.principal,
        })?;
        if request.command.workspace_id() != request.scope.workspace_id()
            || session.id() != request.command.initiating_session_id()
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope
            || request.command.expected_workspace_revision() != fresh_scope.workspace_revision()
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let result = store
            .create_activity_successor(&request.command)
            .map_err(|error| {
                map_activity_successor_create_error(
                    error,
                    request.command.predecessor_activity_id(),
                    request.command.successor_activity_id(),
                )
            })?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(result)
    }

    /// Read one exact predecessor relation and current successor projection.
    /// This path is observational and never claims a successor or Activity
    /// lease.
    pub fn activity_successor_get(
        &self,
        scope: &ResolvedWorkspaceScope,
        predecessor_activity_id: ActivityId,
    ) -> Result<
        Option<(
            forge_domain::ActivitySuccessor,
            forge_domain::RegisteredActivity,
        )>,
        ControlError,
    > {
        let (fresh_scope, store) = self.open_resolved_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let result = store
            .get_activity_successor(predecessor_activity_id)
            .map_err(map_activity_store_error)?;
        if let Some((relation, successor)) = &result
            && (relation.workspace_id() != fresh_scope.workspace_id()
                || successor.workspace_id() != fresh_scope.workspace_id())
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }
}

fn map_activity_successor_create_error(
    error: WorkspaceStoreError,
    predecessor_activity_id: ActivityId,
    requested_successor_activity_id: ActivityId,
) -> ControlError {
    let successor_activity_id = match &error {
        WorkspaceStoreError::ActivitySuccessorConflict {
            existing_successor, ..
        } => Some(*existing_successor),
        WorkspaceStoreError::ActivitySuccessorTargetAlreadyExists(successor) => Some(*successor),
        WorkspaceStoreError::ActivitySuccessorPredecessorNotTerminal { .. }
        | WorkspaceStoreError::ActivitySuccessorTimestampOrder { .. } => {
            Some(requested_successor_activity_id)
        }
        _ => None,
    };
    let control = map_activity_store_error(error);
    if let Some(successor_activity_id) = successor_activity_id {
        control.with_details(crate::ControlErrorDetails::ActivitySuccessorTarget {
            predecessor_activity_id,
            successor_activity_id,
        })
    } else {
        control
    }
}
