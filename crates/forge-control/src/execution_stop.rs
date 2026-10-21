//! Private control boundary for the queued Workspace execution-stop capture.
//!
//! The context retains one exact logical scope and physical journal binding
//! between queue admission and the persistence operation.  It carries no
//! native process capability and never settles, releases, or terminalizes an
//! execution.

use std::fmt;

pub(crate) mod owned;

use forge_persistence::{
    ExecutionStopCapture, ExecutionStopRecord, ExecutionStopRequest, WorkspaceJournalBinding,
    WorkspaceStore,
};
use forge_workspace::ExistingWorkspaceStateLayout;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

/// Immutable scope and journal binding retained by one queued stop request.
///
/// The fields remain private so callers cannot replace the Workspace, layout,
/// binding, or request after admission.  This is a local correlation fence,
/// not an authorization grant and not a process-ownership capability.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExecutionStopContext {
    scope: ResolvedWorkspaceScope,
    layout: ExistingWorkspaceStateLayout,
    binding: WorkspaceJournalBinding,
    request: ExecutionStopRequest,
}

impl fmt::Debug for ExecutionStopContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionStopContext")
            .field("workspace_id", &"<redacted>")
            .field("request_id", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ExecutionStopContext {
    fn new(
        scope: ResolvedWorkspaceScope,
        layout: ExistingWorkspaceStateLayout,
        binding: WorkspaceJournalBinding,
        request: ExecutionStopRequest,
    ) -> Result<Self, ControlError> {
        if request.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(Self {
            scope,
            layout,
            binding,
            request,
        })
    }

    pub(crate) const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub(crate) const fn request(&self) -> &ExecutionStopRequest {
        &self.request
    }

    fn validate(&self) -> Result<(), ControlError> {
        if self.request.workspace_id() != self.scope.workspace_id() {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(())
    }
}

impl ForgeControl {
    /// Capture the exact logical and physical authority needed by a queued
    /// stop. Preparation only observes the checked Workspace and performs no
    /// durable or native mutation.
    pub(crate) fn prepare_execution_stop_context(
        &self,
        scope: &ResolvedWorkspaceScope,
        request: ExecutionStopRequest,
    ) -> Result<ExecutionStopContext, ControlError> {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        ExecutionStopContext::new(fresh_scope, layout, binding, request)
    }

    /// Apply one retained stop context through the exact live Workspace
    /// journal. The persistence layer owns the atomic cohort capture and
    /// fresh-execution fence; this control method does not claim native stop
    /// or terminal authority.
    pub(crate) fn apply_execution_stop_context(
        &self,
        context: &ExecutionStopContext,
    ) -> Result<ExecutionStopCapture, ControlError> {
        context.validate()?;
        let (fresh_scope, layout, mut store) = self.open_resolved_workspace_with_layout(
            context.scope.locator().location_id(),
            context.scope.locator().expected_revision(),
            context.scope.locator(),
        )?;
        if fresh_scope != context.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        if layout != context.layout || binding != context.binding {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        let capture = store
            .capture_execution_stop(&context.request)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&context.scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(capture)
    }

    /// Observe the original durable capture through its retained physical
    /// binding. Location resolution is intentionally absent here so a later
    /// logical Location disable does not erase recovery readback.
    pub(crate) fn observe_execution_stop_context(
        context: &ExecutionStopContext,
    ) -> Result<Option<ExecutionStopRecord>, ControlError> {
        context.validate()?;
        let store = WorkspaceStore::open_existing_journal(&context.layout, &context.binding)
            .map_err(map_activity_store_error)?;
        store
            .execution_stop_for_request(&context.request)
            .map_err(map_activity_store_error)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};

    use forge_domain::{
        LocationState, RuntimeInstanceId, SetLocationState, TimestampMillis, WorkspaceId,
        WorkspaceRevision,
    };
    use forge_persistence::{ExecutionStopRequest, ExecutionStopStatus, WorkspaceStore};
    use forge_workspace::{ExistingWorkspaceStateLayout, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;

    fn fixture_layout(root: &Path) -> Result<ExistingWorkspaceStateLayout, Box<dyn Error>> {
        WorkspaceStateLayout::inspect_existing(root.join("location/workspace"))?
            .ok_or_else(|| "Workspace layout missing".into())
    }

    fn stop_request(
        workspace_id: WorkspaceId,
        seed: u128,
        observed_at: i64,
    ) -> Result<ExecutionStopRequest, forge_domain::TimestampMillisError> {
        Ok(ExecutionStopRequest::new(
            Uuid::from_u128(seed),
            workspace_id,
            Uuid::from_u128(seed + 1),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 2)),
            [seed.to_le_bytes()[0]; 32],
            TimestampMillis::new(observed_at)?,
        ))
    }

    fn finish(root: PathBuf, control: ForgeControl) -> Result<(), Box<dyn Error>> {
        drop(control);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn prepare_does_not_capture_a_stop_row() -> Result<(), Box<dyn Error>> {
        let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let request = stop_request(scope.workspace_id(), 0xE701, 20)?;
        let context = control.prepare_execution_stop_context(&scope, request)?;
        assert_eq!(context.request(), &request);

        let layout = fixture_layout(&root)?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(store.execution_stop_for_request(&request)?.is_none());
        drop(store);
        finish(root, control)
    }

    #[test]
    fn apply_records_pending_empty_cohort_and_reads_back_exactly() -> Result<(), Box<dyn Error>> {
        let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let request = stop_request(scope.workspace_id(), 0xE711, 21)?;
        let context = control.prepare_execution_stop_context(&scope, request)?;
        let capture = control.apply_execution_stop_context(&context)?;
        assert_eq!(capture.status(), ExecutionStopStatus::Pending);
        assert_eq!(capture.record().target_count(), 0);
        assert!(capture.record().targets().is_empty());

        let observed = ForgeControl::observe_execution_stop_context(&context)?
            .ok_or("captured stop was not readable")?;
        assert_eq!(observed, capture.record().clone());
        finish(root, control)
    }

    #[test]
    fn stale_scope_and_foreign_workspace_request_are_rejected_before_capture()
    -> Result<(), Box<dyn Error>> {
        let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let request = stop_request(scope.workspace_id(), 0xE721, 22)?;
        let stale_scope = ResolvedWorkspaceScope::from_observation(
            scope.workspace_id(),
            WorkspaceRevision::new(scope.workspace_revision().get() + 1)?,
            scope.locator().clone(),
        );
        let stale = control.prepare_execution_stop_context(&stale_scope, request);
        assert!(matches!(
            stale,
            Err(error) if error.code() == ControlErrorCode::WorkspaceRevisionConflict
        ));

        let foreign_request =
            stop_request(WorkspaceId::from_uuid(Uuid::from_u128(0xE7FF)), 0xE731, 23)?;
        let foreign = control.prepare_execution_stop_context(&scope, foreign_request);
        assert!(matches!(
            foreign,
            Err(error) if error.code() == ControlErrorCode::ExecutionProvenanceConflict
        ));

        let layout = fixture_layout(&root)?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(store.execution_stop_for_request(&request)?.is_none());
        drop(store);
        finish(root, control)
    }

    #[test]
    fn disabled_location_blocks_apply_but_original_context_reads_back() -> Result<(), Box<dyn Error>>
    {
        let (root, mut control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let request = stop_request(scope.workspace_id(), 0xE741, 24)?;
        let context = control.prepare_execution_stop_context(&scope, request)?;
        let capture = control.apply_execution_stop_context(&context)?;
        control.set_location_state(&SetLocationState::new(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            LocationState::Disabled,
            TimestampMillis::new(25)?,
        ))?;

        let apply = control.apply_execution_stop_context(&context);
        assert!(matches!(
            apply,
            Err(error)
                if matches!(
                    error.code(),
                    ControlErrorCode::LocationUnavailable
                        | ControlErrorCode::LocationRevisionConflict
                )
        ));
        let observed = ForgeControl::observe_execution_stop_context(&context)?
            .ok_or("disabled-location readback was absent")?;
        assert_eq!(observed, capture.record().clone());
        finish(root, control)
    }

    #[test]
    fn state_directory_rename_blocks_observe_until_original_binding_is_restored()
    -> Result<(), Box<dyn Error>> {
        let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let request = stop_request(scope.workspace_id(), 0xE751, 26)?;
        let context = control.prepare_execution_stop_context(&scope, request)?;
        let capture = control.apply_execution_stop_context(&context)?;
        let layout = fixture_layout(&root)?;
        let original_state_root = layout.state_root().to_path_buf();
        let moved_state_root = original_state_root.with_file_name(".heterarchy-forge-moved");
        fs::rename(&original_state_root, &moved_state_root)?;
        assert!(ForgeControl::observe_execution_stop_context(&context).is_err());
        fs::rename(&moved_state_root, &original_state_root)?;

        let restored = ForgeControl::observe_execution_stop_context(&context)?
            .ok_or("restored physical binding did not read back stop")?;
        assert_eq!(restored, capture.record().clone());
        finish(root, control)
    }
}
