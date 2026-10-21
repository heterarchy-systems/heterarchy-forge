//! Application control for durable source Writer Leases.
//!
//! A Writer Lease is not an Agent heartbeat. Every mutation-authority change is
//! reopened against the exact Workspace, current Activity lease and durable
//! attached Agent principal before persistence is allowed to mutate state.

use forge_domain::{
    AcquireWriterLease, ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal,
    ReleaseWriterLease, RenewWriterLease, TimestampMillis, WriterLease, WriterLeaseId,
    WriterLeaseRevision,
};
use forge_persistence::{WorkspaceStore, WorkspaceStoreError, WriterLeaseStoreError};

use crate::agent::map_agent_store_error;
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterLeaseAcquireRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub principal: AuthenticatedPrincipal,
    pub command: AcquireWriterLease,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterLeaseRenewRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub principal: AuthenticatedPrincipal,
    pub command: RenewWriterLease,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterLeaseReleaseRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub principal: AuthenticatedPrincipal,
    pub command: ReleaseWriterLease,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterLeaseGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub lease_id: WriterLeaseId,
    pub expected_revision: Option<WriterLeaseRevision>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterLeaseListRequest {
    pub scope: ResolvedWorkspaceScope,
    pub cursor: Option<WriterLeaseId>,
    pub limit: usize,
}

const MAX_WRITER_LEASE_PAGE_SIZE: usize = 4;

pub(crate) type WriterLeaseListEntry = (WriterLease, Option<AgentSessionId>);
pub(crate) type WriterLeaseListPage = (Vec<WriterLeaseListEntry>, Option<WriterLeaseId>);

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterLeaseRecoveryReleaseRequest {
    pub scope: ResolvedWorkspaceScope,
    pub lease_id: WriterLeaseId,
    pub expected_revision: WriterLeaseRevision,
    pub observed_at: TimestampMillis,
}

impl ForgeControl {
    pub fn writer_lease_acquire(
        &self,
        request: &WriterLeaseAcquireRequest,
    ) -> Result<WriterLease, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.command.session_id(),
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_writer_lease_workspace(&request.scope)?;
        if request.command.workspace_id() != scope.workspace_id()
            || request.command.activity_id() != request.activity_id
            || request.command.agent_id() != request.agent_id
        {
            return Err(ControlError::new(ControlErrorCode::WriterLeaseConflict));
        }
        if request.command.principal() != request.principal {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        verify_writer_agent_principal(
            &store,
            request.agent_id,
            request.activity_id,
            request.principal,
            request.command.session_id(),
        )?;
        let lease = store
            .acquire_writer_lease(&request.command)
            .map_err(map_writer_lease_store_error)?;
        self.confirm_writer_lease_write(&scope, &store)?;
        Ok(lease)
    }

    pub fn writer_lease_renew(
        &self,
        request: &WriterLeaseRenewRequest,
    ) -> Result<WriterLease, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.command.session_id(),
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_writer_lease_workspace(&request.scope)?;
        if request.command.principal() != request.principal {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        verify_writer_agent_principal(
            &store,
            request.command.agent_id(),
            request.activity_id,
            request.principal,
            request.command.session_id(),
        )?;
        let lease = store
            .renew_writer_lease(scope.workspace_id(), request.activity_id, request.command)
            .map_err(map_writer_lease_store_error)?;
        self.confirm_writer_lease_write(&scope, &store)?;
        Ok(lease)
    }

    pub fn writer_lease_release(
        &self,
        request: &WriterLeaseReleaseRequest,
    ) -> Result<WriterLease, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.command.session_id(),
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_writer_lease_workspace(&request.scope)?;
        if request.command.principal() != request.principal {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        verify_writer_agent_principal(
            &store,
            request.command.agent_id(),
            request.activity_id,
            request.principal,
            request.command.session_id(),
        )?;
        let lease = store
            .release_writer_lease(scope.workspace_id(), request.activity_id, request.command)
            .map_err(map_writer_lease_store_error)?;
        self.confirm_writer_lease_write(&scope, &store)?;
        Ok(lease)
    }

    pub fn writer_lease_get(
        &self,
        request: &WriterLeaseGetRequest,
    ) -> Result<Option<(WriterLease, Option<AgentSessionId>)>, ControlError> {
        let (scope, store) = self.open_writer_lease_workspace(&request.scope)?;
        let lease = store
            .get_writer_lease(request.lease_id)
            .map_err(map_writer_lease_store_error)?;
        if let Some(lease) = &lease
            && lease.workspace_id() != scope.workspace_id()
        {
            return Err(ControlError::new(ControlErrorCode::WriterLeaseConflict));
        }
        let Some(lease) = lease else {
            self.confirm_writer_lease_read(&scope, &store)?;
            return Ok(None);
        };
        if request
            .expected_revision
            .is_some_and(|revision| lease.revision() != revision)
        {
            return Err(ControlError::new(ControlErrorCode::WriterLeaseConflict));
        }
        let session_id = store
            .get_agent(lease.agent_id())
            .map_err(map_writer_lease_store_error)?
            .and_then(|agent| agent.session_id());
        self.confirm_writer_lease_read(&scope, &store)?;
        Ok(Some((lease, session_id)))
    }

    pub fn writer_lease_list(
        &self,
        request: &WriterLeaseListRequest,
    ) -> Result<WriterLeaseListPage, ControlError> {
        if request.limit == 0 || request.limit > MAX_WRITER_LEASE_PAGE_SIZE {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        let (scope, store) = self.open_writer_lease_workspace(&request.scope)?;
        let (leases, next_cursor) = store
            .list_active_writer_leases_page(request.cursor, request.limit)
            .map_err(map_writer_lease_store_error)?;
        let leases = leases
            .into_iter()
            .map(|lease| {
                let session_id = store
                    .get_agent(lease.agent_id())
                    .map_err(map_writer_lease_store_error)?
                    .and_then(|agent| agent.session_id());
                Ok((lease, session_id))
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        self.confirm_writer_lease_read(&scope, &store)?;
        Ok((leases, next_cursor))
    }

    pub fn writer_lease_release_for_recovery(
        &self,
        request: &WriterLeaseRecoveryReleaseRequest,
    ) -> Result<WriterLease, ControlError> {
        let (scope, mut store) = self.open_writer_lease_workspace(&request.scope)?;
        let existing = store
            .get_writer_lease(request.lease_id)
            .map_err(map_writer_lease_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::WriterLeaseNotFound))?;
        if existing.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::WriterLeaseConflict));
        }
        if request.observed_at < existing.lease_until() {
            return Err(ControlError::new(ControlErrorCode::WriterLeaseConflict));
        }
        let lease = store
            .release_writer_lease_for_recovery(
                request.lease_id,
                request.expected_revision,
                request.observed_at,
            )
            .map_err(map_writer_lease_store_error)?;
        self.confirm_writer_lease_write(&scope, &store)?;
        Ok(lease)
    }

    fn open_writer_lease_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
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

    fn confirm_writer_lease_write(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> Result<(), ControlError> {
        if self.committed_scope_matches_with_store(scope, store) {
            Ok(())
        } else {
            Err(ControlError::committed())
        }
    }

    fn confirm_writer_lease_read(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> Result<(), ControlError> {
        if self.committed_scope_matches_with_store(scope, store) {
            Ok(())
        } else {
            Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict))
        }
    }
}

fn verify_writer_agent_principal(
    store: &WorkspaceStore,
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
    principal: AuthenticatedPrincipal,
    session_id: forge_domain::AgentSessionId,
) -> Result<(), ControlError> {
    let agent = store
        .get_agent(agent_id)
        .map_err(map_writer_lease_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
    if agent.activity_id() != activity_id
        || agent.principal() != principal
        || agent.session_id() != Some(session_id)
        || !agent.attachment_state().is_attached()
    {
        return Err(ControlError::new(ControlErrorCode::AgentConflict));
    }
    Ok(())
}

pub(crate) fn map_writer_lease_store_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        WorkspaceStoreError::WriterLeaseCommittedUnconfirmed { .. }
    ) {
        return ControlError::committed();
    }
    let code = match &error {
        WorkspaceStoreError::WriterLease(WriterLeaseStoreError::LeaseMissing) => {
            ControlErrorCode::WriterLeaseNotFound
        }
        WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::Transition(
                forge_domain::WriterLeaseTransitionError::ExpiredRecoveryRequired,
            )
            | WriterLeaseStoreError::ExpiredRecoveryRequired
            | WriterLeaseStoreError::RecoveryTimestampInversion,
        ) => ControlErrorCode::WriterLeaseRecoveryRequired,
        WorkspaceStoreError::WriterLease(WriterLeaseStoreError::ActivityMissing) => {
            ControlErrorCode::ActivityNotFound
        }
        WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::ActivityLeaseUnavailable
            | WriterLeaseStoreError::ActivityLeaseOwnerMismatch
            | WriterLeaseStoreError::ActivityLeaseExpired,
        ) => ControlErrorCode::ActivityLeaseConflict,
        WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::ActivityWorkspaceMismatch
            | WriterLeaseStoreError::ActivityNotOpen
            | WriterLeaseStoreError::ActivityMismatch,
        ) => ControlErrorCode::ActivityConflict,
        WorkspaceStoreError::WriterLease(WriterLeaseStoreError::AgentMissing) => {
            ControlErrorCode::AgentNotFound
        }
        WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::AgentScopeMismatch
            | WriterLeaseStoreError::AgentDetached
            | WriterLeaseStoreError::AgentAuthorityConflict
            | WriterLeaseStoreError::AgentFocusConflict,
        ) => ControlErrorCode::AgentConflict,
        WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::ActiveLeaseLimitExceeded
            | WriterLeaseStoreError::ScopeLimitExceeded
            | WriterLeaseStoreError::ScopeOrdinalOverflow,
        ) => ControlErrorCode::CapacityExceeded,
        WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::LeaseIdConflict(_)
            | WriterLeaseStoreError::LeaseReleased
            | WriterLeaseStoreError::WriterLeaseNotExpired
            | WriterLeaseStoreError::WorkspaceMismatch
            | WriterLeaseStoreError::ScopeConflict { .. }
            | WriterLeaseStoreError::CompareAndSwapConflict
            | WriterLeaseStoreError::WriterLeaseRevisionConflict
            | WriterLeaseStoreError::ScopeNotCovered
            | WriterLeaseStoreError::Transition(_),
        ) => ControlErrorCode::WriterLeaseConflict,
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::OutdatedSchema { .. }
        | WorkspaceStoreError::UnsupportedSchemaVersion { .. }
        | WorkspaceStoreError::UnsupportedForReadOnly { .. } => {
            ControlErrorCode::WorkspaceSchemaOutdated
        }
        WorkspaceStoreError::WriterLease(_) => ControlErrorCode::PersistenceFailure,
        _ => return map_agent_store_error(error),
    };
    ControlError::with_source(code, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_conflict_and_post_commit_failure_keep_distinct_outcomes() {
        let conflict = map_writer_lease_store_error(WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::CompareAndSwapConflict,
        ));
        assert_eq!(conflict.code(), ControlErrorCode::WriterLeaseConflict);
        assert!(!conflict.is_committed());
        let committed =
            map_writer_lease_store_error(WorkspaceStoreError::WriterLeaseCommittedUnconfirmed {
                source: Box::new(WorkspaceStoreError::WorkspaceIdentityMissing),
            });
        assert_eq!(committed.code(), ControlErrorCode::CommittedButUnconfirmed);
        assert!(committed.is_committed());
    }
}
