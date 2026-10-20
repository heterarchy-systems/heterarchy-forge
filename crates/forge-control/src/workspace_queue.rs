//! Workspace queue preference authority. Runtime admission is owned by the mailbox.

use forge_domain::TimestampMillis;
use forge_persistence::{
    QueueSettings, QueueSettingsRevision, RegisteredQueueSettings, WorkspaceStore,
};

use crate::service::map_store_error;
use crate::{ControlError, ControlErrorCode, ForgeControl, ResolvedWorkspaceScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceQueueSettingsRequest {
    pub scope: ResolvedWorkspaceScope,
    pub settings: QueueSettings,
    pub expected_revision: Option<QueueSettingsRevision>,
    pub observed_at: TimestampMillis,
}

impl ForgeControl {
    /// Read only. Older supported schemas have no preference and are not migrated.
    pub fn workspace_queue_settings(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<Option<RegisteredQueueSettings>, ControlError> {
        let (fresh, layout, _) = self.inspect_resolved_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let settings = WorkspaceStore::inspect_queue_settings_live_read_only(&layout)
            .map_err(map_queue_store_error)?;
        let current = self.resolve_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if current != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok(settings)
    }

    /// Persist an exact Workspace preference CAS, without changing approval policy.
    pub fn replace_workspace_queue_settings(
        &self,
        request: &WorkspaceQueueSettingsRequest,
    ) -> Result<RegisteredQueueSettings, ControlError> {
        let (scope, mut store) = self.open_agent_workspace(&request.scope)?;
        let saved = store
            .replace_workspace_queue_settings(
                request.settings,
                request.expected_revision,
                request.observed_at,
            )
            .map_err(map_queue_store_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(saved)
    }
}

fn map_queue_store_error(error: forge_persistence::WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        forge_persistence::WorkspaceStoreError::WorkspaceQueueSettingsCommittedUnconfirmed { .. }
    ) {
        return ControlError::committed();
    }
    if matches!(
        &error,
        forge_persistence::WorkspaceStoreError::WorkspaceQueueSettings(
            forge_persistence::WorkspaceQueueSettingsStoreError::Transition(
                forge_persistence::QueueSettingsTransitionError::RevisionConflict
            )
        )
    ) {
        ControlError::with_source(ControlErrorCode::WorkspaceQueueSettingsConflict, error)
    } else {
        map_store_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_preference_conflict_is_distinct_from_unknown_after_commit() {
        let stale = map_queue_store_error(
            forge_persistence::WorkspaceStoreError::WorkspaceQueueSettings(
                forge_persistence::WorkspaceQueueSettingsStoreError::Transition(
                    forge_persistence::QueueSettingsTransitionError::RevisionConflict,
                ),
            ),
        );
        assert_eq!(
            stale.code(),
            ControlErrorCode::WorkspaceQueueSettingsConflict
        );
        assert!(!stale.is_committed());
        let unknown = map_queue_store_error(
            forge_persistence::WorkspaceStoreError::WorkspaceQueueSettingsCommittedUnconfirmed {
                source: Box::new(forge_persistence::WorkspaceStoreError::WorkspaceIdentityMissing),
            },
        );
        assert_eq!(unknown.code(), ControlErrorCode::CommittedButUnconfirmed);
        assert!(unknown.is_committed());
    }
}
