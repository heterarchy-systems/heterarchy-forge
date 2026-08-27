use forge_domain::{
    ActivityId, CompleteExecution, ExecutionId, ExecutionListLimit, FailExecution,
    MarkExecutionRunning, RegisteredExecution, TimestampMillis,
};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

impl ForgeControl {
    pub fn execution_mark_running(
        &self,
        scope: &ResolvedWorkspaceScope,
        command: MarkExecutionRunning,
    ) -> Result<RegisteredExecution, ControlError> {
        self.update_execution(scope, |store| store.mark_execution_running(command))
    }

    pub fn execution_complete(
        &self,
        scope: &ResolvedWorkspaceScope,
        command: &CompleteExecution,
    ) -> Result<RegisteredExecution, ControlError> {
        self.update_execution(scope, |store| store.complete_execution(command))
    }

    pub fn execution_fail(
        &self,
        scope: &ResolvedWorkspaceScope,
        command: FailExecution,
    ) -> Result<RegisteredExecution, ControlError> {
        self.update_execution(scope, |store| store.fail_execution(command))
    }

    pub fn reconcile_interrupted_executions(
        &self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredExecution>, ControlError> {
        let (fresh_scope, mut store) = self.open_execution_workspace(scope)?;
        let records = store
            .reconcile_interrupted_executions(observed_at, limit)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(records)
    }

    pub fn execution_get(
        &self,
        scope: &ResolvedWorkspaceScope,
        id: ExecutionId,
    ) -> Result<Option<RegisteredExecution>, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(scope)?;
        let record = store.get_execution(id).map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(record)
    }

    pub fn execution_list(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredExecution>, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(scope)?;
        let records = store
            .list_executions(activity_id, limit)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(records)
    }

    fn update_execution(
        &self,
        scope: &ResolvedWorkspaceScope,
        update: impl FnOnce(
            &mut forge_persistence::WorkspaceStore,
        )
            -> Result<RegisteredExecution, forge_persistence::WorkspaceStoreError>,
    ) -> Result<RegisteredExecution, ControlError> {
        let (fresh_scope, mut store) = self.open_execution_workspace(scope)?;
        let record = update(&mut store).map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(record)
    }

    fn open_execution_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, forge_persistence::WorkspaceStore), ControlError> {
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
}
