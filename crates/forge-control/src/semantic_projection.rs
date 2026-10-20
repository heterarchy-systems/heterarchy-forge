//! Read-only semantic event stream and Workspace snapshot projections for
//! transport adapters.
//!
//! These queries expose the durable Workspace semantic event stream and one
//! consistent current-state summary through the single-owner control worker.
//! They are bounded reads only; they never mutate durable state, never invent
//! events, and never become a second durable authority.

use forge_persistence::{SemanticEventPage, WorkspaceSemanticSnapshot};

use crate::service::{ForgeControl, ResolvedWorkspaceScope};
use crate::{ControlError, ControlErrorCode};

/// Maximum Goal summaries carried by one Workspace snapshot read.
pub const MAX_SNAPSHOT_GOAL_SUMMARIES: u32 =
    forge_persistence::MAX_WORKSPACE_SNAPSHOT_GOAL_SUMMARIES;

/// Request for one bounded page of the durable semantic event stream.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticEventsPageRequest {
    pub scope: ResolvedWorkspaceScope,
    pub after: u64,
    pub limit: u32,
}

/// One bounded semantic event page plus the exact Workspace scope observed.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticEventsPageResult {
    scope: ResolvedWorkspaceScope,
    page: SemanticEventPage,
}

impl SemanticEventsPageResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn page(&self) -> &SemanticEventPage {
        &self.page
    }
}

/// Request for one consistent Workspace semantic snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSemanticSnapshotRequest {
    pub scope: ResolvedWorkspaceScope,
}

/// One consistent Workspace snapshot result.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSemanticSnapshotResult {
    scope: ResolvedWorkspaceScope,
    snapshot: WorkspaceSemanticSnapshot,
}

impl WorkspaceSemanticSnapshotResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn snapshot(&self) -> &WorkspaceSemanticSnapshot {
        &self.snapshot
    }
}

impl ForgeControl {
    fn read_semantic_workspace<T>(
        &self,
        scope: &ResolvedWorkspaceScope,
        read: impl FnOnce(
            &forge_persistence::WorkspaceStore,
        ) -> Result<T, forge_persistence::WorkspaceStoreError>,
    ) -> Result<T, ControlError> {
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
        let result = read(&store).map_err(crate::service::map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    /// Read one bounded semantic event page through the control worker.
    pub fn semantic_events_page(
        &self,
        request: &SemanticEventsPageRequest,
    ) -> Result<SemanticEventsPageResult, ControlError> {
        let workspace_id = request.scope.workspace_id();
        let page = self.read_semantic_workspace(&request.scope, |store| {
            store.semantic_events_page(workspace_id, request.after, request.limit)
        })?;
        Ok(SemanticEventsPageResult {
            scope: request.scope.clone(),
            page,
        })
    }

    /// Read one consistent Workspace snapshot through the control worker.
    pub fn workspace_semantic_snapshot(
        &self,
        request: &WorkspaceSemanticSnapshotRequest,
    ) -> Result<WorkspaceSemanticSnapshotResult, ControlError> {
        let snapshot = self.read_semantic_workspace(&request.scope, |store| {
            store.semantic_snapshot(MAX_SNAPSHOT_GOAL_SUMMARIES)
        })?;
        Ok(WorkspaceSemanticSnapshotResult {
            scope: request.scope.clone(),
            snapshot,
        })
    }
}
