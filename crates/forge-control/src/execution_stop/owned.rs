//! Control authority for an owner-approved Workspace execution stop.
//!
//! The context retains the already-minted administrative cleanup permit and
//! the exact request identity. It never resolves a Location again, creates a
//! new permit, or grants native process ownership. Persistence performs the
//! execution and authority capture atomically against the retained journal.

use std::fmt;

use forge_persistence::{
    AuthorityStopReceipt, ExecutionStopRecord, ExecutionStopRequest, OwnedWorkspaceStopCapture,
    WorkspaceStore,
};

use crate::approval_cleanup::{ApprovalCleanupOwner, ApprovalCleanupPermit};
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

/// Retained only after the Coordinator validates the same current native owner.
#[derive(Clone, Debug)]
pub(crate) struct OwnedExecutionStopSettlement {
    context: OwnedExecutionStopContext,
    quiescence: Option<forge_execution::NativeWorkspaceQuiescence>,
    observed_at: forge_domain::TimestampMillis,
}

impl OwnedExecutionStopSettlement {
    pub(crate) fn new(
        context: OwnedExecutionStopContext,
        quiescence: Option<forge_execution::NativeWorkspaceQuiescence>,
        supervisor: &forge_execution::ExecutionSupervisorClient,
        observed_at: forge_domain::TimestampMillis,
    ) -> Result<Self, ControlError> {
        context.validate()?;
        if quiescence.as_ref().is_some_and(|proof| {
            proof.workspace_id() != context.scope().workspace_id()
                || !supervisor.owns_workspace_quiescence(proof)
        }) {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(Self {
            context,
            quiescence,
            observed_at,
        })
    }
    pub(crate) const fn context(&self) -> &OwnedExecutionStopContext {
        &self.context
    }
    pub(crate) fn ensure_live_owner(
        &self,
        supervisor: &forge_execution::ExecutionSupervisorClient,
    ) -> Result<(), ControlError> {
        if self
            .quiescence
            .as_ref()
            .is_some_and(|proof| !supervisor.owns_workspace_quiescence(proof))
        {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(())
    }
}

/// Immutable control-side context for one owner-approved Workspace stop.
///
/// The permit is an existing cleanup authority, not a native cancellation
/// capability. Its layout and journal binding remain private so callers
/// cannot replace the physical Workspace after admission.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OwnedExecutionStopContext {
    permit: ApprovalCleanupPermit,
    owner: ApprovalCleanupOwner,
    request: ExecutionStopRequest,
}

impl fmt::Debug for OwnedExecutionStopContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedExecutionStopContext")
            .field("workspace_id", &"<redacted>")
            .field("request_id", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl OwnedExecutionStopContext {
    fn new(
        permit: &ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: ExecutionStopRequest,
    ) -> Result<Self, ControlError> {
        permit.validate_workspace_stop(owner)?;
        if request.workspace_id() != permit.scope().workspace_id() {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(Self {
            permit: permit.clone(),
            owner,
            request,
        })
    }

    pub(crate) const fn scope(&self) -> &ResolvedWorkspaceScope {
        self.permit.scope()
    }

    pub(crate) const fn request(&self) -> &ExecutionStopRequest {
        &self.request
    }

    fn validate(&self) -> Result<(), ControlError> {
        self.permit.validate_workspace_stop(self.owner)?;
        if self.request.workspace_id() != self.permit.scope().workspace_id() {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(())
    }
}

fn open_original_journal(
    context: &OwnedExecutionStopContext,
) -> Result<WorkspaceStore, ControlError> {
    context.validate()?;
    WorkspaceStore::open_existing_journal(context.permit.layout(), context.permit.binding())
        .map_err(map_activity_store_error)
}

impl ForgeControl {
    pub(crate) fn observe_owned_stop_history(
        permit: &ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: ExecutionStopRequest,
    ) -> Result<Option<(ExecutionStopRecord, AuthorityStopReceipt)>, ControlError> {
        let context = OwnedExecutionStopContext::new(permit, owner, request)?;
        Self::observe_owned_execution_stop_context(&context)
    }
    pub(crate) fn settle_owned_execution_stop_context(
        settlement: &OwnedExecutionStopSettlement,
    ) -> Result<(ExecutionStopRecord, AuthorityStopReceipt), ControlError> {
        let mut store = open_original_journal(&settlement.context)?;
        store
            .settle_owned_workspace_stop(
                settlement.context.request(),
                settlement.quiescence.is_some(),
                settlement.observed_at,
            )
            .map_err(map_activity_store_error)
    }
    /// Prepare one immutable owner-approved Workspace stop against the exact
    /// physical journal retained by the permit. No current Location lookup is
    /// performed, so a later Location disable does not invalidate this bound
    /// recovery operation.
    pub(crate) fn prepare_owned_execution_stop_context(
        permit: &ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: ExecutionStopRequest,
    ) -> Result<OwnedExecutionStopContext, ControlError> {
        let context = OwnedExecutionStopContext::new(permit, owner, request)?;
        let _store = open_original_journal(&context)?;
        Ok(context)
    }

    /// Capture the execution and administrative authority cohorts atomically
    /// through the original journal binding. This method grants no native
    /// cancellation or release rights.
    pub(crate) fn apply_owned_execution_stop_context(
        context: &OwnedExecutionStopContext,
    ) -> Result<OwnedWorkspaceStopCapture, ControlError> {
        let mut store = open_original_journal(context)?;
        store
            .capture_owned_workspace_stop(context.request())
            .map_err(map_activity_store_error)
    }

    /// Read the paired durable execution and authority receipts through the
    /// same retained physical journal binding.
    pub(crate) fn observe_owned_execution_stop_context(
        context: &OwnedExecutionStopContext,
    ) -> Result<Option<(ExecutionStopRecord, AuthorityStopReceipt)>, ControlError> {
        let store = open_original_journal(context)?;
        store
            .owned_workspace_stop_for_request(context.request())
            .map_err(map_activity_store_error)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;

    use forge_domain::{
        ActivityId, LocationState, RuntimeInstanceId, SetLocationState, TimestampMillis,
        WorkspaceId,
    };
    use forge_persistence::{ExecutionStopRequest, WorkspaceStore};
    use forge_workspace::WorkspaceStateLayout;
    use uuid::Uuid;

    use super::ForgeControl;
    use crate::approval_cleanup::{ApprovalCleanupOwner, ApprovalCleanupSelector};
    use crate::error::ControlErrorCode;

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
    fn owned_stop_rejects_foreign_owner_and_activity_permit_before_write()
    -> Result<(), Box<dyn Error>> {
        let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let owner = ApprovalCleanupOwner::new();
        let foreign_owner = ApprovalCleanupOwner::new();
        let request = stop_request(scope.workspace_id(), 0xF001, 20)?;

        let workspace_permit = control.mint_approval_cleanup_permit(
            owner,
            scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        let foreign = ForgeControl::prepare_owned_execution_stop_context(
            &workspace_permit,
            foreign_owner,
            request,
        );
        assert!(matches!(
            foreign,
            Err(error) if error.code() == ControlErrorCode::ExecutionProvenanceConflict
        ));

        let activity_permit = control.mint_approval_cleanup_permit(
            owner,
            scope.clone(),
            ApprovalCleanupSelector::Activity(ActivityId::from_uuid(Uuid::from_u128(0xF002))),
        )?;
        let activity =
            ForgeControl::prepare_owned_execution_stop_context(&activity_permit, owner, request);
        assert!(matches!(
            activity,
            Err(error) if error.code() == ControlErrorCode::ApprovalConflict
        ));

        let layout = WorkspaceStateLayout::inspect_existing(root.join("location/workspace"))?
            .ok_or("Workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(store.execution_stop_for_request(&request)?.is_none());
        drop(store);
        finish(root, control)
    }

    #[test]
    fn owned_stop_uses_original_binding_after_location_disable() -> Result<(), Box<dyn Error>> {
        let (root, mut control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let owner = ApprovalCleanupOwner::new();
        let permit = control.mint_approval_cleanup_permit(
            owner,
            scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        let request = stop_request(scope.workspace_id(), 0xF011, 21)?;
        control.set_location_state(&SetLocationState::new(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            LocationState::Disabled,
            TimestampMillis::new(22)?,
        ))?;

        let context = ForgeControl::prepare_owned_execution_stop_context(&permit, owner, request)?;
        let capture = ForgeControl::apply_owned_execution_stop_context(&context)?;
        let observed = ForgeControl::observe_owned_execution_stop_context(&context)?
            .ok_or("paired owned stop receipt was absent")?;
        assert_eq!(&observed.0, capture.execution().record());
        assert_eq!(&observed.1, capture.authority());
        finish(root, control)
    }

    #[test]
    fn owned_stop_rejects_replaced_physical_binding() -> Result<(), Box<dyn Error>> {
        let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
        let owner = ApprovalCleanupOwner::new();
        let permit = control.mint_approval_cleanup_permit(
            owner,
            scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        let request = stop_request(scope.workspace_id(), 0xF021, 23)?;
        let layout = WorkspaceStateLayout::inspect_existing(root.join("location/workspace"))?
            .ok_or("Workspace layout missing")?;
        let state_root = layout.state_root().to_path_buf();
        let moved_state_root = state_root.with_file_name(".heterarchy-forge-original");
        fs::rename(&state_root, &moved_state_root)?;
        fs::create_dir(&state_root)?;

        let result = ForgeControl::prepare_owned_execution_stop_context(&permit, owner, request);

        fs::remove_dir_all(&state_root)?;
        fs::rename(&moved_state_root, &state_root)?;
        assert!(result.is_err());

        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(store.execution_stop_for_request(&request)?.is_none());
        drop(store);
        finish(root, control)
    }
}
