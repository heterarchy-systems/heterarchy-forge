//! Authorized execution readbacks that include immutable generated evidence.

use forge_domain::{ActivityId, ExecutionAgentProvenance, ExecutionId};

use super::{WorkspaceStore, WorkspaceStoreError};

impl WorkspaceStore {
    /// Read one Agent-owned execution and its optional generated-package
    /// manifest from one durable `SQLite` snapshot.
    pub fn get_execution_authorized_with_generated_package(
        &self,
        workspace_id: forge_domain::WorkspaceId,
        activity_id: ActivityId,
        execution_id: ExecutionId,
        provenance: &ExecutionAgentProvenance,
    ) -> Result<crate::workspace_executions::AuthorizedExecutionSnapshot, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = crate::workspace_executions::get_execution_authorized_with_generated_package(
            &self.connection,
            workspace_id,
            activity_id,
            execution_id,
            provenance,
        )?;
        self.ensure_live_binding()?;
        Ok(result)
    }
}
