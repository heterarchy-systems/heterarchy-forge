use forge_domain::{
    ActivityId, AuthorizedExecutionRead, CompleteExecution, ExecutionId, ExecutionListLimit,
    ExecutionOutputCursor, ExecutionOutputEvent, ExecutionOutputRead, FailExecution,
    GeneratedPackageManifest, MarkExecutionRunning, RegisteredExecution, TimestampMillis,
    VerificationProjection,
};
use forge_persistence::AuthorizedExecutionSnapshot;

use crate::agent::AgentExecutionAuthorityRequest;
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

    /// Commit a fixed-name generated package manifest with the successful
    /// terminal execution record. The store rejects every other outcome or
    /// non-generated provenance before the transaction can commit.
    pub fn execution_complete_with_generated_package(
        &self,
        scope: &ResolvedWorkspaceScope,
        command: &CompleteExecution,
        manifest: GeneratedPackageManifest,
    ) -> Result<RegisteredExecution, ControlError> {
        self.update_execution(scope, |store| {
            store.complete_execution_with_generated_package(command, manifest)
        })
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

    pub fn verification_projection(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<VerificationProjection, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(scope)?;
        let projection = store
            .verification_projection()
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(projection)
    }

    /// Host service/operator observation. The HTTP issuer already authorizes
    /// this read; agent execution/mutation APIs retain their full authority.
    pub fn execution_evidence_inventory(
        &self,
        scope: &ResolvedWorkspaceScope,
        selection: forge_domain::ExecutionObservationSelection,
        limit: ExecutionListLimit,
    ) -> Result<forge_persistence::ExecutionEvidenceInventory, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(scope)?;
        let result = store
            .execution_evidence_inventory(selection, limit)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    pub fn execution_evidence_read(
        &self,
        scope: &ResolvedWorkspaceScope,
        selection: forge_domain::ExecutionObservationSelection,
        id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<forge_persistence::ExecutionEvidenceRead, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(scope)?;
        let result = store
            .execution_evidence_read(selection, id, cursor, max_bytes, max_events)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    pub fn execution_generated_package_manifest(
        &self,
        scope: &ResolvedWorkspaceScope,
        execution_id: ExecutionId,
    ) -> Result<Option<GeneratedPackageManifest>, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(scope)?;
        let manifest = store
            .generated_package_manifest(execution_id)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(manifest)
    }

    /// Read one Agent-originated execution through the single persistence
    /// snapshot that verifies its immutable provenance and current Agent
    /// authority.
    pub fn execution_get_authorized(
        &self,
        request: &AgentExecutionAuthorityRequest,
        execution_id: ExecutionId,
    ) -> Result<RegisteredExecution, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (fresh_scope, store) = self.open_execution_workspace(&request.scope)?;
        let provenance = request.provenance(execution_id);
        let record = store
            .get_execution_authorized(
                fresh_scope.workspace_id(),
                request.activity_id,
                execution_id,
                &provenance,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(record)
    }

    /// Read one Agent-originated execution and its optional generated-package
    /// manifest through one durable persistence snapshot.
    pub fn execution_get_authorized_with_generated_package(
        &self,
        request: &AgentExecutionAuthorityRequest,
        execution_id: ExecutionId,
    ) -> Result<AuthorizedExecutionSnapshot, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (fresh_scope, store) = self.open_execution_workspace(&request.scope)?;
        let provenance = request.provenance(execution_id);
        let result = store
            .get_execution_authorized_with_generated_package(
                fresh_scope.workspace_id(),
                request.activity_id,
                execution_id,
                &provenance,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
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

    /// Persist a bounded output prefix in one Workspace transaction.
    pub fn execution_output_append_batch(
        &self,
        scope: &ResolvedWorkspaceScope,
        events: &[ExecutionOutputEvent],
    ) -> Result<(), ControlError> {
        let (fresh_scope, mut store) = self.open_execution_workspace(scope)?;
        store
            .append_execution_output_events(events)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(())
    }

    /// Read a bounded durable output prefix without consuming it.
    pub fn execution_output_read(
        &self,
        scope: &ResolvedWorkspaceScope,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<ExecutionOutputRead, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(scope)?;
        let result = store
            .read_execution_output_events(cursor, max_bytes, max_events)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(result)
    }

    /// Read one Agent-owned output prefix through the same persistence
    /// snapshot that verifies its immutable provenance and current focus.
    pub fn execution_output_read_authorized(
        &self,
        request: &AgentExecutionAuthorityRequest,
        execution_id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<ExecutionOutputRead, ControlError> {
        let (fresh_scope, store) = self.open_execution_workspace(&request.scope)?;
        let provenance = request.provenance(execution_id);
        let result = store
            .read_execution_output_events_authorized(
                request.activity_id,
                execution_id,
                &provenance,
                cursor,
                max_bytes,
                max_events,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    /// Read one Agent-owned execution record and bounded output through one
    /// durable `SQLite` snapshot and one committed Workspace-scope fence.
    /// Session admission occurs in this same control operation, before opening
    /// the snapshot; callers must not enqueue a separate session preflight.
    pub fn execution_read_authorized(
        &self,
        request: &AgentExecutionAuthorityRequest,
        execution_id: ExecutionId,
        cursor: ExecutionOutputCursor,
        max_bytes: u64,
        max_events: usize,
    ) -> Result<AuthorizedExecutionRead, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (fresh_scope, store) = self.open_execution_workspace(&request.scope)?;
        let provenance = request.provenance(execution_id);
        let result = store
            .read_execution_authorized(
                fresh_scope.workspace_id(),
                request.activity_id,
                &provenance,
                cursor,
                max_bytes,
                max_events,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
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
