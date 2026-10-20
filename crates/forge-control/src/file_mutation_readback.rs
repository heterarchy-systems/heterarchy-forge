//! Historical source-mutation observation without reauthorizing a new effect.

use forge_domain::{ActivityId, ChangeSetId, DiffOrigin, FileMutationId};
use forge_persistence::FileMutationReadSnapshot;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Exact identity tuple used to read one historical source mutation outcome.
///
/// This request is observational. It does not require a live Activity lease,
/// Writer Lease, session proof, or patch provenance.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationReadbackRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub change_set_id: ChangeSetId,
    pub mutation_id: FileMutationId,
}

impl ForgeControl {
    /// Read one durable source-mutation record and its same-snapshot Diff.
    ///
    /// A missing `ChangeSet` is a valid historical absence. Any durable
    /// attribution mismatch is reported as a file conflict, while a root or
    /// binding drift observed after the read is reported as a workspace-root
    /// conflict.
    pub fn file_mutation_readback(
        &self,
        request: &FileMutationReadbackRequest,
    ) -> Result<Option<FileMutationReadSnapshot>, ControlError> {
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }

        let snapshot = store
            .file_mutation_read_snapshot(request.change_set_id)
            .map_err(crate::service::map_store_error)?;
        if let Some(snapshot) = &snapshot {
            validate_snapshot(snapshot, &fresh_scope, request)?;
        }
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(snapshot)
    }
}

fn validate_snapshot(
    snapshot: &FileMutationReadSnapshot,
    scope: &ResolvedWorkspaceScope,
    request: &FileMutationReadbackRequest,
) -> Result<(), ControlError> {
    let record = snapshot.record();
    let change_set = record.change_set();
    let mutation = record.mutation();
    if change_set.workspace_id() != scope.workspace_id()
        || change_set.activity_id() != request.activity_id
        || change_set.id() != request.change_set_id
        || mutation.change_set_id() != request.change_set_id
        || mutation.id() != request.mutation_id
    {
        return Err(ControlError::new(ControlErrorCode::FileConflict));
    }

    if snapshot.diff().is_some_and(|diff| {
        diff.workspace_id() != scope.workspace_id()
            || diff.activity_id() != request.activity_id
            || diff.change_set_id() != request.change_set_id
            || diff.origin() != DiffOrigin::FileMutation(request.mutation_id)
    }) {
        return Err(ControlError::new(ControlErrorCode::FileConflict));
    }
    Ok(())
}
