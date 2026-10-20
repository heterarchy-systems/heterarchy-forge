use forge_domain::{
    ActivityId, AgentSessionId, AuthenticatedPrincipal, DagNodeId, DagNodeRevision,
    DagRevisionNumber, GoalId, GoalRevision, RegisteredDagNode, TimestampMillis,
};
use forge_persistence::{
    CoordinatorStoreError, DagNodeAssignmentSnapshot, DagNodeEvidenceScope, DagNodeTransition,
    DagStoreError, DagTransitionScope, StoredDagRevision, WorkspaceStore, WorkspaceStoreError,
};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeStartRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub goal_id: GoalId,
    pub expected_goal_revision: GoalRevision,
    pub expected_dag_revision: DagRevisionNumber,
    pub node_id: DagNodeId,
    pub expected_revision: DagNodeRevision,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeCompleteRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub goal_id: GoalId,
    pub expected_goal_revision: GoalRevision,
    pub expected_dag_revision: DagRevisionNumber,
    pub node_id: DagNodeId,
    pub expected_revision: DagNodeRevision,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeUpdateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub node: RegisteredDagNode,
    pub expected_revision: DagNodeRevision,
}

impl ForgeControl {
    pub fn dag_get_current(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<Option<StoredDagRevision>, ControlError> {
        self.read_dag(scope, |store| store.get_current_dag(goal_id))
    }

    /// Observe one exact node and its active assignment without granting work.
    ///
    /// # Errors
    /// Revalidates the Workspace root and propagates corrupt or unavailable state.
    pub fn dag_node_assignment_snapshot(
        &self,
        scope: &ResolvedWorkspaceScope,
        node_scope: DagNodeEvidenceScope,
    ) -> Result<Option<DagNodeAssignmentSnapshot>, ControlError> {
        self.read_dag(scope, |store| {
            store.dag_node_assignment_snapshot(node_scope)
        })
    }

    pub fn dag_get_revision(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
        number: DagRevisionNumber,
    ) -> Result<Option<StoredDagRevision>, ControlError> {
        self.read_dag(scope, |store| store.get_dag_revision(goal_id, number))
    }

    pub(crate) fn dag_node_start(
        &self,
        request: &DagNodeStartRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_dag_workspace(&request.scope)?;
        let node = store
            .start_dag_node_authorized(
                DagNodeTransition::new(
                    DagTransitionScope::new(
                        scope.workspace_id(),
                        request.activity_id,
                        request.goal_id,
                        request.expected_goal_revision,
                        request.expected_dag_revision,
                    ),
                    request.node_id,
                    request.expected_revision,
                    request.observed_at,
                ),
                request.session_id,
                request.principal,
                admitted_at,
            )
            .map_err(map_dag_store_error)?;
        self.confirm_dag_write(&scope, &store)?;
        Ok(node)
    }

    pub(crate) fn dag_node_complete(
        &self,
        request: &DagNodeCompleteRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_dag_workspace(&request.scope)?;
        let node = store
            .complete_dag_node_authorized(
                DagNodeTransition::new(
                    DagTransitionScope::new(
                        scope.workspace_id(),
                        request.activity_id,
                        request.goal_id,
                        request.expected_goal_revision,
                        request.expected_dag_revision,
                    ),
                    request.node_id,
                    request.expected_revision,
                    request.observed_at,
                ),
                request.session_id,
                request.principal,
                admitted_at,
            )
            .map_err(map_dag_store_error)?;
        self.confirm_dag_write(&scope, &store)?;
        Ok(node)
    }

    pub(crate) fn dag_node_update(
        &self,
        request: &DagNodeUpdateRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, ControlError> {
        let (scope, mut store) = self.open_dag_workspace(&request.scope)?;
        let node = store
            .update_dag_node(&request.node, request.expected_revision, admitted_at)
            .map_err(map_dag_store_error)?;
        self.confirm_dag_write(&scope, &store)?;
        Ok(node)
    }

    fn read_dag<T>(
        &self,
        scope: &ResolvedWorkspaceScope,
        read: impl FnOnce(&WorkspaceStore) -> Result<T, WorkspaceStoreError>,
    ) -> Result<T, ControlError> {
        let (fresh_scope, store) = self.open_dag_workspace(scope)?;
        let result = read(&store).map_err(map_dag_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    fn open_dag_workspace(
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

    fn confirm_dag_write(
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

pub(crate) fn map_dag_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::Dag(
            DagStoreError::GoalMissing | DagStoreError::HeadMissing | DagStoreError::NodeMissing,
        ) => ControlErrorCode::DagNotFound,
        WorkspaceStoreError::Dag(DagStoreError::AgentAuthorizationConflict) => {
            ControlErrorCode::AgentSessionConflict
        }
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::ActivityNotLive(_)
            | CoordinatorStoreError::ActivityLeaseNotLive(_),
        )) => ControlErrorCode::ActivityLeaseConflict,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::ActivityNotFound(_),
        )) => ControlErrorCode::ActivityNotFound,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::ActivityWorkspaceMismatch,
        )) => ControlErrorCode::WorkspaceIdentityConflict,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::CorruptRecord(_) | CoordinatorStoreError::Sqlite(_),
        )) => ControlErrorCode::PersistenceFailure,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(_)) => {
            ControlErrorCode::CoordinatorConflict
        }
        WorkspaceStoreError::Dag(
            DagStoreError::GoalConflict
            | DagStoreError::IdentityConflict
            | DagStoreError::HeadConflict
            | DagStoreError::ProjectionMismatch
            | DagStoreError::CompletedNodeDropped(_)
            | DagStoreError::CompletedNodeChanged(_)
            | DagStoreError::RevisionOverflow
            | DagStoreError::Transition(_)
            | DagStoreError::NodeConflict
            | DagStoreError::HistoricalRevisionImmutable
            | DagStoreError::GoalEvidenceMissing
            | DagStoreError::LineageConflict
            | DagStoreError::LineageMissing(_),
        ) => ControlErrorCode::DagConflict,
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::ExistingWorkspaceBindingMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
        | WorkspaceStoreError::WorkspaceRootCanonicalPathChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}
