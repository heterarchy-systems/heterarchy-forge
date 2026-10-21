//! Activity-local planning Coordinator application authority.
//!
//! Coordinator identity is durable Workspace state with a monotonic revision
//! fence. Declared Agent role metadata is never consulted for authorization.

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorBinding, ActivityCoordinatorRevision, ActivityId,
    AgentInstanceId, AuthenticatedPrincipal, ClaimActivityCoordinator, TimestampMillis,
    TransferActivityCoordinator,
};
use forge_persistence::{
    AgentStoreError, CoordinatorStoreError, WorkspaceStore, WorkspaceStoreError,
};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorActorRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub principal: AuthenticatedPrincipal,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorClaimRequest {
    pub session_id: forge_domain::AgentSessionId,
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub principal: AuthenticatedPrincipal,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorTransferRequest {
    pub current_session_id: forge_domain::AgentSessionId,
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub current_agent_id: AgentInstanceId,
    pub expected_coordinator_revision: ActivityCoordinatorRevision,
    pub principal: AuthenticatedPrincipal,
    pub next_agent_id: AgentInstanceId,
    pub observed_at: TimestampMillis,
}

impl ForgeControl {
    pub fn activity_coordinator_get(
        &self,
        request: &CoordinatorGetRequest,
    ) -> Result<Option<ActivityCoordinatorBinding>, ControlError> {
        let (scope, store) = self.open_coordinator_workspace(&request.scope)?;
        let result = store
            .get_activity_coordinator(request.activity_id)
            .map_err(map_coordinator_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    /// Resolve the current attached Coordinator into a session-bound actor for
    /// read-only UI consumers. A closed, foreign, detached, or legacy session
    /// returns no actor so the UI cannot synthesize authority.
    pub fn activity_coordinator_actor(
        &self,
        request: &CoordinatorActorRequest,
    ) -> Result<Option<ActivityCoordinatorActor>, ControlError> {
        let (scope, store) = self.open_coordinator_workspace(&request.scope)?;
        let binding = store
            .get_activity_coordinator(request.activity_id)
            .map_err(map_coordinator_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        let Some(binding) = binding else {
            return Ok(None);
        };
        if binding.workspace_id() != scope.workspace_id()
            || binding.activity_id() != request.activity_id
        {
            return Ok(None);
        }
        let agent = store
            .get_agent(binding.agent_id())
            .map_err(map_coordinator_store_error)?;
        let Some(agent) = agent else {
            return Ok(None);
        };
        let Some(session_id) = agent.session_id() else {
            return Ok(None);
        };
        if agent.workspace_id() != scope.workspace_id()
            || agent.activity_id() != request.activity_id
            || !agent.attachment_state().is_attached()
            || agent.principal() != request.principal
        {
            return Ok(None);
        }
        match self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id,
            principal: request.principal,
        }) {
            Ok(_) => Ok(Some(ActivityCoordinatorActor::new(
                scope.workspace_id(),
                request.activity_id,
                binding.agent_id(),
                binding.revision(),
                request.principal,
                session_id,
            ))),
            Err(error)
                if matches!(
                    error.code(),
                    ControlErrorCode::AgentSessionNotFound
                        | ControlErrorCode::AgentSessionClosed
                        | ControlErrorCode::AgentSessionConflict
                        | ControlErrorCode::AgentSessionUnresolved
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn activity_coordinator_claim(
        &self,
        request: &CoordinatorClaimRequest,
        admitted_at: TimestampMillis,
    ) -> Result<ActivityCoordinatorBinding, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_coordinator_workspace(&request.scope)?;
        let result = store
            .claim_activity_coordinator(
                ClaimActivityCoordinator::new(
                    scope.workspace_id(),
                    request.activity_id,
                    request.agent_id,
                    request.principal,
                    request.observed_at,
                    request.session_id,
                ),
                admitted_at,
            )
            .map_err(map_coordinator_store_error)?;
        self.confirm_coordinator_write(&scope, &store)?;
        Ok(result)
    }

    pub(crate) fn activity_coordinator_transfer(
        &self,
        request: &CoordinatorTransferRequest,
        admitted_at: TimestampMillis,
    ) -> Result<ActivityCoordinatorBinding, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.current_session_id,
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_coordinator_workspace(&request.scope)?;
        let actor = ActivityCoordinatorActor::new(
            scope.workspace_id(),
            request.activity_id,
            request.current_agent_id,
            request.expected_coordinator_revision,
            request.principal,
            request.current_session_id,
        );
        let result = store
            .transfer_activity_coordinator(
                TransferActivityCoordinator::new(actor, request.next_agent_id, request.observed_at),
                admitted_at,
            )
            .map_err(map_coordinator_store_error)?;
        self.confirm_coordinator_write(&scope, &store)?;
        Ok(result)
    }

    fn open_coordinator_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
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
        Ok((fresh_scope, store))
    }

    fn confirm_coordinator_write(
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

pub(crate) fn map_coordinator_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::Coordinator(CoordinatorStoreError::CoordinatorMissing(_)) => {
            ControlErrorCode::CoordinatorNotFound
        }
        WorkspaceStoreError::Coordinator(
            CoordinatorStoreError::ActivityNotLive(_)
            | CoordinatorStoreError::ActivityLeaseNotLive(_),
        ) => ControlErrorCode::ActivityLeaseConflict,
        WorkspaceStoreError::Coordinator(
            CoordinatorStoreError::AlreadyBound(_)
            | CoordinatorStoreError::CoordinatorFenceConflict
            | CoordinatorStoreError::ActivityWorkspaceMismatch
            | CoordinatorStoreError::AgentMismatch
            | CoordinatorStoreError::PrincipalMismatch
            | CoordinatorStoreError::TargetAlreadyCoordinator
            | CoordinatorStoreError::SameSessionHandoff
            | CoordinatorStoreError::TimestampOrder
            | CoordinatorStoreError::RevisionConflict
            | CoordinatorStoreError::RevisionOverflow
            | CoordinatorStoreError::RecordMissing
            | CoordinatorStoreError::ActiveWriterLease(_)
            | CoordinatorStoreError::ActiveExecution(_)
            | CoordinatorStoreError::CoordinationRevisionConflict
            | CoordinatorStoreError::Agent(
                AgentStoreError::SessionAttachmentConflict
                | AgentStoreError::SessionPrincipalConflict
                | AgentStoreError::SessionBindingConflict
                | AgentStoreError::PrincipalConflict
                | AgentStoreError::UnresolvedLegacy(_)
                | AgentStoreError::AgentDetached(_)
                | AgentStoreError::CurrentCoordinatorCannotDetach(_)
                | AgentStoreError::ActiveWriterLease(_)
                | AgentStoreError::ActiveExecution(_)
                | AgentStoreError::ActivityNotFound(_)
                | AgentStoreError::ActivityWorkspaceMismatch { .. }
                | AgentStoreError::ActivityAgentMismatch { .. }
                | AgentStoreError::WorkspaceMismatch { .. }
                | AgentStoreError::RevisionConflict { .. }
                | AgentStoreError::FocusGoalMissing(_)
                | AgentStoreError::FocusWorkspaceMismatch
                | AgentStoreError::FocusDagMissing(_)
                | AgentStoreError::FocusDagNotCurrent { .. }
                | AgentStoreError::FocusNodeMissing(_)
                | AgentStoreError::FocusGoalRevisionConflict { .. }
                | AgentStoreError::FocusNodeRevisionConflict { .. }
                | AgentStoreError::InvalidProjection(_)
                | AgentStoreError::Transition(_),
            ),
        ) => ControlErrorCode::CoordinatorConflict,
        WorkspaceStoreError::Coordinator(CoordinatorStoreError::ActivityNotFound(_)) => {
            ControlErrorCode::ActivityNotFound
        }
        WorkspaceStoreError::Coordinator(CoordinatorStoreError::AgentNotFound(_)) => {
            ControlErrorCode::AgentNotFound
        }
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::StateRootChanged(_)
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}
