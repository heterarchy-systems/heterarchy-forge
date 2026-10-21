//! Exact, read-only observation of one registered Activity.
//!
//! The request carries an already resolved Workspace scope and one Activity
//! identity.  This operation revalidates that scope before and after the
//! SQLite read, and never creates, migrates, reconciles, leases, or closes an
//! Activity.

use forge_domain::{ActivityId, RegisteredActivity};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

/// Read one exact Activity within a resolved Workspace scope.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
}

/// One exact Activity observation and the scope that was checked around it.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityReadSnapshot {
    scope: ResolvedWorkspaceScope,
    activity: Option<RegisteredActivity>,
}

impl ActivityReadSnapshot {
    const fn new(scope: ResolvedWorkspaceScope, activity: Option<RegisteredActivity>) -> Self {
        Self { scope, activity }
    }

    /// Return the exact Workspace scope used for this observation.
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    /// Return the Activity row when the requested identity is registered.
    pub const fn activity(&self) -> Option<&RegisteredActivity> {
        self.activity.as_ref()
    }
}

impl ForgeControl {
    /// Read one registered Activity without creating or changing durable state.
    ///
    /// The scope is resolved before the read and fenced again after the read.
    /// A missing Activity is a valid observation; a row attributed to another
    /// Workspace or identity is a durable identity conflict.
    pub fn activity_read(
        &self,
        request: &ActivityReadRequest,
    ) -> Result<ActivityReadSnapshot, ControlError> {
        let (fresh_scope, store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }

        let activity = store
            .get_activity(request.activity_id)
            .map_err(map_activity_store_error)?;
        if let Some(activity) = &activity {
            if activity.workspace_id() != fresh_scope.workspace_id() {
                return Err(ControlError::new(
                    ControlErrorCode::WorkspaceIdentityConflict,
                ));
            }
            if activity.id() != request.activity_id {
                return Err(ControlError::new(ControlErrorCode::ActivityConflict));
            }
        }

        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(
                ControlErrorCode::ProjectionResyncRequired,
            ));
        }

        Ok(ActivityReadSnapshot::new(request.scope.clone(), activity))
    }
}
