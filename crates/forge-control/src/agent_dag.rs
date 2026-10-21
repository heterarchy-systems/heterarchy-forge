//! Control-plane admission for Activity Coordinator DAG planning.
//!
//! The current revision-fenced Activity Coordinator owns initial DAG creation and
//! successor replanning. The control plane resolves the exact Workspace scope;
//! persistence atomically owns Coordinator fencing, Goal revision, DAG head CAS,
//! and replay-ledger validation.

use forge_domain::{ActivityCoordinatorActor, AgentDagPlanRequest};
use forge_persistence::{
    AgentDagPlanCommitResult, AgentDagStoreError, AgentStoreError, CoordinatorStoreError,
    WorkspaceStore, WorkspaceStoreError,
};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagPlanCommitRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request: AgentDagPlanRequest,
}

impl ForgeControl {
    /// Commit an initial or successor Coordinator-authorized DAG plan in one Workspace transaction.
    pub(crate) fn agent_dag_plan_commit(
        &self,
        request: &AgentDagPlanCommitRequest,
        admitted_at: forge_domain::TimestampMillis,
    ) -> Result<AgentDagPlanCommitResult, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.request.actor().session_id(),
            principal: request.request.actor().principal(),
        })?;
        ensure_actor_workspace(&request.scope, request.request.actor())?;
        let (scope, mut store) = open_agent_dag_workspace(self, &request.scope)?;
        let result = store
            .commit_coordinator_dag_plan(&request.request, admitted_at)
            .map_err(map_agent_dag_store_error)?;
        confirm_agent_dag_write(self, &scope, &store)?;
        Ok(result)
    }
}

fn ensure_actor_workspace(
    scope: &ResolvedWorkspaceScope,
    actor: ActivityCoordinatorActor,
) -> Result<(), ControlError> {
    if actor.workspace_id() == scope.workspace_id() {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ))
    }
}

fn open_agent_dag_workspace(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
    let (fresh_scope, store) = control.open_resolved_workspace(
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

fn confirm_agent_dag_write(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    store: &WorkspaceStore,
) -> Result<(), ControlError> {
    if control.committed_scope_matches_with_store(scope, store) {
        Ok(())
    } else {
        Err(ControlError::committed())
    }
}

pub(crate) fn map_agent_dag_store_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        WorkspaceStoreError::PlanningCommittedUnconfirmed { .. }
    ) {
        return ControlError::committed();
    }
    let code = match &error {
        WorkspaceStoreError::AgentDag(AgentDagStoreError::Coordinator(
            CoordinatorStoreError::CoordinatorMissing(_),
        )) => ControlErrorCode::CoordinatorNotFound,
        WorkspaceStoreError::AgentDag(AgentDagStoreError::Coordinator(
            CoordinatorStoreError::ActivityNotFound(_),
        )) => ControlErrorCode::ActivityNotFound,
        WorkspaceStoreError::AgentDag(AgentDagStoreError::Coordinator(
            CoordinatorStoreError::AgentNotFound(_),
        )) => ControlErrorCode::AgentNotFound,
        WorkspaceStoreError::AgentDag(AgentDagStoreError::Coordinator(_)) => {
            ControlErrorCode::CoordinatorConflict
        }
        WorkspaceStoreError::AgentDag(AgentDagStoreError::Agent(
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
        )) => ControlErrorCode::CoordinatorConflict,
        WorkspaceStoreError::AgentDag(
            AgentDagStoreError::RequestIdentityConflict | AgentDagStoreError::UnresolvedSession,
        ) => ControlErrorCode::AgentDagReplayConflict,
        WorkspaceStoreError::AgentDag(
            AgentDagStoreError::GoalMissing(_)
            | AgentDagStoreError::GoalConflict
            | AgentDagStoreError::DraftConflict
            | AgentDagStoreError::HistoryInvalid
            | AgentDagStoreError::Dag(_),
        ) => ControlErrorCode::AgentDagPlanConflict,
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
        | WorkspaceStoreError::DatabasePathChanged(_) => ControlErrorCode::WorkspaceRootConflict,
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}
