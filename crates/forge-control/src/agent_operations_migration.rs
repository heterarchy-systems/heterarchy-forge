//! Control-owner operations for the Workspace Agent-operations migration fence.
//!
//! These requests are deliberately transport-neutral.  The control worker
//! re-resolves the caller's Workspace scope before every operation and then
//! delegates durable state, CAS, source fencing, and read consistency to the
//! existing `WorkspaceStore` authority.

use forge_domain::TimestampMillis;
use forge_persistence::{
    AgentOperationsExportCursor, AgentOperationsExportPage, AgentOperationsFreeze,
    AgentOperationsFreezeState, AgentOperationsMigrationError, WorkspaceStore, WorkspaceStoreError,
};
use uuid::Uuid;

use crate::{ControlError, ControlErrorCode, ForgeControl, ResolvedWorkspaceScope};

const MAX_FREEZE_REVISION: u64 = i64::MAX as u64;

/// Create or exactly replay one source freeze for a destination migration.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsFreezeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub observed_at: TimestampMillis,
}

/// Read one exact source freeze row.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsFreezeReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
}

/// Read one bounded page from the frozen source.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsExportRequest {
    pub scope: ResolvedWorkspaceScope,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub cursor: AgentOperationsExportCursor,
}

/// Release one source freeze with exact revision and timestamp fencing.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsFreezeReleaseRequest {
    pub scope: ResolvedWorkspaceScope,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub expected_revision: u64,
    pub observed_at: TimestampMillis,
}

impl ForgeControl {
    /// Create or exactly replay one source freeze under the current Workspace
    /// scope.  The persistence owner performs request-equivalence checks and
    /// installs the SQLite writer fences atomically.
    pub fn agent_operations_freeze(
        &self,
        request: &AgentOperationsFreezeRequest,
    ) -> Result<AgentOperationsFreeze, ControlError> {
        validate_identity(request.migration_id, request.destination_id)?;
        let (scope, mut store) = open_migration_scope(self, &request.scope)?;
        let native = forge_persistence::AgentOperationsFreezeRequest::new(
            request.migration_id,
            request.destination_id,
            request.observed_at,
        )
        .map_err(map_migration_error)?;
        let result = store
            .freeze_agent_operations(&native)
            .map_err(map_store_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Read one exact source freeze under the current Workspace scope.
    pub fn agent_operations_freeze_read(
        &self,
        request: &AgentOperationsFreezeReadRequest,
    ) -> Result<Option<AgentOperationsFreeze>, ControlError> {
        validate_identity(request.migration_id, request.destination_id)?;
        let (scope, store) = open_migration_scope(self, &request.scope)?;
        let result = store
            .agent_operations_freeze(request.migration_id)
            .map_err(map_store_error)?;
        self.confirm_agent_read(&scope, &store)?;
        if let Some(freeze) = &result
            && (freeze.workspace_id() != scope.workspace_id()
                || freeze.migration_id() != request.migration_id
                || freeze.destination_id() != request.destination_id)
        {
            return Err(agent_conflict());
        }
        Ok(result)
    }

    /// Read one bounded source page under the exact frozen migration identity.
    pub fn agent_operations_export(
        &self,
        request: &AgentOperationsExportRequest,
    ) -> Result<AgentOperationsExportPage, ControlError> {
        validate_identity(request.migration_id, request.destination_id)?;
        let (scope, store) = open_migration_scope(self, &request.scope)?;
        let page = store
            .export_agent_operations(request.migration_id, request.cursor)
            .map_err(map_store_error)?;
        if page.workspace_id() != scope.workspace_id()
            || page.migration_id() != request.migration_id
            || page.destination_id() != request.destination_id
            || page.requested_cursor() != request.cursor
        {
            return Err(agent_conflict());
        }
        self.confirm_agent_read(&scope, &store)?;
        Ok(page)
    }

    /// Release one source freeze with exact compare-and-set semantics.  The
    /// destination is checked before the mutation because the native release
    /// API intentionally fences by Workspace/migration/revision only.
    pub fn agent_operations_freeze_release(
        &self,
        request: &AgentOperationsFreezeReleaseRequest,
    ) -> Result<AgentOperationsFreeze, ControlError> {
        validate_identity(request.migration_id, request.destination_id)?;
        if request.expected_revision == 0 || request.expected_revision > MAX_FREEZE_REVISION {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        let (scope, mut store) = open_migration_scope(self, &request.scope)?;
        let current = store
            .agent_operations_freeze(request.migration_id)
            .map_err(map_store_error)?
            .ok_or_else(agent_conflict)?;
        if current.workspace_id() != scope.workspace_id()
            || current.destination_id() != request.destination_id
            || (current.state() != AgentOperationsFreezeState::Frozen
                && !(current.state() == AgentOperationsFreezeState::Released
                    && current.revision() == request.expected_revision.saturating_add(1)))
        {
            return Err(agent_conflict());
        }
        let result = store
            .release_agent_operations_freeze(
                request.migration_id,
                request.expected_revision,
                request.observed_at,
            )
            .map_err(map_store_error)?;
        if result.workspace_id() != scope.workspace_id()
            || result.destination_id() != request.destination_id
        {
            return Err(agent_conflict());
        }
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }
}

fn open_migration_scope(
    control: &ForgeControl,
    requested: &ResolvedWorkspaceScope,
) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
    let (scope, store) = control.open_agent_workspace(requested)?;
    if scope != *requested {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceRevisionConflict,
        ));
    }
    Ok((scope, store))
}

fn validate_identity(migration_id: Uuid, destination_id: Uuid) -> Result<(), ControlError> {
    if migration_id.is_nil() || destination_id.is_nil() {
        Err(ControlError::new(ControlErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn agent_conflict() -> ControlError {
    ControlError::new(ControlErrorCode::AgentConflict)
}

fn map_store_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        WorkspaceStoreError::AgentOperationsMigrationCommittedUnconfirmed { .. }
    ) {
        return ControlError::committed();
    }
    match error {
        WorkspaceStoreError::AgentOperationsMigration(source) => map_migration_error(source),
        WorkspaceStoreError::AgentOperationsExport(source) => map_export_error(source),
        other => crate::service::map_store_error(other),
    }
}

fn map_migration_error(error: AgentOperationsMigrationError) -> ControlError {
    let code = match &error {
        AgentOperationsMigrationError::InvalidMigrationId
        | AgentOperationsMigrationError::InvalidDestinationId
        | AgentOperationsMigrationError::TimestampOrder
        | AgentOperationsMigrationError::InvalidState(_)
        | AgentOperationsMigrationError::InvalidRevision(_) => ControlErrorCode::InvalidInput,
        AgentOperationsMigrationError::MigrationMissing(_)
        | AgentOperationsMigrationError::RequestConflict
        | AgentOperationsMigrationError::WorkspaceMissing(_)
        | AgentOperationsMigrationError::WorkspaceMismatch { .. }
        | AgentOperationsMigrationError::ActiveMigrationConflict { .. }
        | AgentOperationsMigrationError::PendingGoalDeletionCleanup { .. }
        | AgentOperationsMigrationError::Delegated { .. }
        | AgentOperationsMigrationError::Frozen { .. }
        | AgentOperationsMigrationError::RevisionConflict(_) => ControlErrorCode::AgentConflict,
        AgentOperationsMigrationError::CommitUnconfirmed { .. } => {
            return ControlError::committed();
        }
        AgentOperationsMigrationError::Delegation(_)
        | AgentOperationsMigrationError::Sqlite(_)
        | AgentOperationsMigrationError::DamagedSchema(_)
        | AgentOperationsMigrationError::CorruptRecord(_) => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

#[allow(
    clippy::match_same_arms,
    reason = "Migration errors retain a separate source remapping below."
)]
fn map_export_error(error: forge_persistence::AgentOperationsExportError) -> ControlError {
    let code = match &error {
        forge_persistence::AgentOperationsExportError::Migration(_) => {
            ControlErrorCode::PersistenceFailure
        }
        forge_persistence::AgentOperationsExportError::Released(_)
        | forge_persistence::AgentOperationsExportError::WorkspaceMismatch { .. }
        | forge_persistence::AgentOperationsExportError::InvalidPage(_) => {
            ControlErrorCode::AgentConflict
        }
        forge_persistence::AgentOperationsExportError::Sqlite(_)
        | forge_persistence::AgentOperationsExportError::Agents(_)
        | forge_persistence::AgentOperationsExportError::Events(_)
        | forge_persistence::AgentOperationsExportError::Coordinators(_) => {
            ControlErrorCode::PersistenceFailure
        }
    };
    if let forge_persistence::AgentOperationsExportError::Migration(source) = error {
        return map_migration_error(source);
    }
    ControlError::with_source(code, error)
}
