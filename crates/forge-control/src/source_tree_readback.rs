//! Historical source-tree observation without granting retry authority.

use forge_domain::{ActivityId, ChangeSetId, DiffOrigin, SourceTreeRequestDigest};
use forge_persistence::SourceTreeReadSnapshot;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Original source-tree identity and an optional known request-digest fence.
/// A caller that lost the entire response can discover the stored digest by ID.
/// Neither form authorizes another filesystem effect.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTreeReadbackRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub change_set_id: ChangeSetId,
    pub expected_request_digest: Option<SourceTreeRequestDigest>,
}

impl ForgeControl {
    pub fn source_tree_readback(
        &self,
        request: &SourceTreeReadbackRequest,
    ) -> Result<Option<SourceTreeReadSnapshot>, ControlError> {
        let (scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let snapshot = store
            .source_tree_read_snapshot(request.change_set_id)
            .map_err(crate::service::map_store_error)?;
        if let Some(snapshot) = &snapshot {
            let change_set = snapshot.change_set();
            if change_set.workspace_id() != scope.workspace_id()
                || change_set.activity_id() != request.activity_id
                || change_set.id() != request.change_set_id
                || request
                    .expected_request_digest
                    .is_some_and(|digest| digest != snapshot.request_digest())
                || snapshot.diff().is_some_and(|diff| {
                    diff.workspace_id() != scope.workspace_id()
                        || diff.activity_id() != request.activity_id
                        || diff.change_set_id() != request.change_set_id
                        || diff.origin() != DiffOrigin::TreeChangeSet
                })
            {
                return Err(ControlError::new(ControlErrorCode::FileConflict));
            }
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(snapshot)
    }
}
