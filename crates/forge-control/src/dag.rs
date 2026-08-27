use forge_domain::{
    DagHeadRevision, DagNodeId, DagNodeLineage, DagNodeRevision, DagRevision, DagRevisionNumber,
    GoalId, RegisteredDagNode, TimestampMillis,
};
use forge_persistence::{DagStoreError, StoredDagRevision, WorkspaceStore, WorkspaceStoreError};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagRevisionCreateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub revision: DagRevision,
    pub nodes: Vec<RegisteredDagNode>,
    pub lineage: Vec<DagNodeLineage>,
    pub expected_head_revision: Option<DagHeadRevision>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeStartRequest {
    pub scope: ResolvedWorkspaceScope,
    pub goal_id: GoalId,
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
    pub fn dag_revision_create(
        &self,
        request: &DagRevisionCreateRequest,
    ) -> Result<StoredDagRevision, ControlError> {
        let (scope, mut store) = self.open_dag_workspace(&request.scope)?;
        if request.revision.goal_id()
            != request
                .nodes
                .first()
                .map_or(request.revision.goal_id(), RegisteredDagNode::goal_id)
        {
            return Err(ControlError::new(ControlErrorCode::DagConflict));
        }
        let result = store
            .insert_dag_revision(
                &request.revision,
                &request.nodes,
                &request.lineage,
                request.expected_head_revision,
            )
            .map_err(map_dag_store_error)?;
        self.confirm_dag_write(&scope, &store)?;
        Ok(result)
    }

    pub fn dag_get_current(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<Option<StoredDagRevision>, ControlError> {
        self.read_dag(scope, |store| store.get_current_dag(goal_id))
    }

    pub fn dag_get_revision(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
        number: DagRevisionNumber,
    ) -> Result<Option<StoredDagRevision>, ControlError> {
        self.read_dag(scope, |store| store.get_dag_revision(goal_id, number))
    }

    pub fn dag_node_start(
        &self,
        request: &DagNodeStartRequest,
    ) -> Result<RegisteredDagNode, ControlError> {
        let (scope, mut store) = self.open_dag_workspace(&request.scope)?;
        let node = store
            .start_dag_node(
                request.goal_id,
                request.node_id,
                request.expected_revision,
                request.observed_at,
            )
            .map_err(map_dag_store_error)?;
        self.confirm_dag_write(&scope, &store)?;
        Ok(node)
    }

    pub fn dag_node_update(
        &self,
        request: &DagNodeUpdateRequest,
    ) -> Result<RegisteredDagNode, ControlError> {
        let (scope, mut store) = self.open_dag_workspace(&request.scope)?;
        let node = store
            .update_dag_node(&request.node, request.expected_revision)
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
            | DagStoreError::NodeEvidenceLimit
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
