//! Durable capture only. Native cancellation and settlement have separate owners.

use std::os::unix::ffi::OsStrExt;

use rusqlite::TransactionBehavior;
use sha2::{Digest, Sha256};

use super::{
    WorkspaceJournalBinding, WorkspaceStore, WorkspaceStoreError, decode_workspace,
    query_workspace_row,
};
use crate::workspace_approvals::cleanup::stop_receipts::{self, AuthorityStopReceipt};
use crate::workspace_approvals::{self, ApprovalCleanupMode, ApprovalCleanupSelector};
use crate::workspace_execution_stops::{self, ExecutionStopRequest};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedWorkspaceStopCapture {
    execution: crate::ExecutionStopCapture,
    authority: AuthorityStopReceipt,
}

impl OwnedWorkspaceStopCapture {
    pub const fn execution(&self) -> &crate::ExecutionStopCapture {
        &self.execution
    }
    pub const fn authority(&self) -> &AuthorityStopReceipt {
        &self.authority
    }
}

impl WorkspaceStore {
    /// Trusted SQL primitive; Control alone derives readiness from the live
    /// serialized native owner. No boolean is accepted from the HTTP caller.
    pub fn settle_owned_workspace_stop(
        &mut self,
        request: &ExecutionStopRequest,
        quiescent: bool,
        observed_at: forge_domain::TimestampMillis,
    ) -> Result<(crate::ExecutionStopRecord, AuthorityStopReceipt), WorkspaceStoreError> {
        let binding = self.journal_binding()?;
        if binding.workspace_id != request.workspace_id() {
            return Err(workspace_execution_stops::ExecutionStopStoreError::Conflict.into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_stop_binding(&transaction, &binding)?;
        let record = workspace_execution_stops::get_for_request(
            &transaction,
            request,
            execution_stop_binding_digest(&binding),
        )?
        .ok_or(workspace_execution_stops::ExecutionStopStoreError::Conflict)?;
        let authority = stop_receipts::observe_stop_authority_receipt_in_transaction(
            &transaction,
            request.stop_id(),
            request.workspace_id(),
        )?
        .ok_or(workspace_approvals::ApprovalStoreError::CleanupPlanMismatch)?;
        let outcome = workspace_execution_stops::settlement::settle_in_transaction(
            &transaction,
            &record,
            &authority,
            quiescent,
            observed_at,
        )
        .map_err(WorkspaceStoreError::from);
        let record = match outcome {
            Ok(record) => record,
            Err(source) => {
                return match transaction.rollback() {
                    Ok(()) => Err(source),
                    Err(rollback) => Err(WorkspaceStoreError::ExecutionStopRollbackUnconfirmed {
                        source: Box::new(source),
                        rollback,
                    }),
                };
            }
        };
        transaction.commit().map_err(|source| {
            WorkspaceStoreError::ExecutionStopCommittedUnconfirmed {
                source: Box::new(source.into()),
            }
        })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::ExecutionStopCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )?;
        Ok((record, authority))
    }

    /// Atomically fence execution and settle the exact administrative authority
    /// cohort. Runtime administrative permission must be checked by Control.
    pub fn capture_owned_workspace_stop(
        &mut self,
        request: &ExecutionStopRequest,
    ) -> Result<OwnedWorkspaceStopCapture, WorkspaceStoreError> {
        self.capture_owned_workspace_stop_with_hook(request, |_| {})
    }

    #[cfg(test)]
    pub(super) fn capture_owned_workspace_stop_with_postcommit_hook(
        &mut self,
        request: &ExecutionStopRequest,
        hook: impl FnOnce(&mut Self),
    ) -> Result<OwnedWorkspaceStopCapture, WorkspaceStoreError> {
        self.capture_owned_workspace_stop_with_hook(request, hook)
    }

    fn capture_owned_workspace_stop_with_hook(
        &mut self,
        request: &ExecutionStopRequest,
        after_commit: impl FnOnce(&mut Self),
    ) -> Result<OwnedWorkspaceStopCapture, WorkspaceStoreError> {
        let binding = self.journal_binding()?;
        if binding.workspace_id != request.workspace_id() {
            return Err(workspace_execution_stops::ExecutionStopStoreError::Conflict.into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_stop_binding(&transaction, &binding)?;
        let outcome = capture_owned_stop_in_transaction(
            &transaction,
            request,
            execution_stop_binding_digest(&binding),
        );
        let capture = match outcome {
            Ok(capture) => capture,
            Err(source) => {
                return match transaction.rollback() {
                    Ok(()) => Err(source),
                    Err(rollback) => Err(WorkspaceStoreError::ExecutionStopRollbackUnconfirmed {
                        source: Box::new(source),
                        rollback,
                    }),
                };
            }
        };
        transaction.commit().map_err(|source| {
            WorkspaceStoreError::ExecutionStopCommittedUnconfirmed {
                source: Box::new(source.into()),
            }
        })?;
        after_commit(self);
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::ExecutionStopCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )?;
        Ok(capture)
    }

    pub fn owned_workspace_stop_for_request(
        &self,
        request: &ExecutionStopRequest,
    ) -> Result<Option<(crate::ExecutionStopRecord, AuthorityStopReceipt)>, WorkspaceStoreError>
    {
        let binding = self.journal_binding()?;
        if binding.workspace_id != request.workspace_id() {
            return Err(workspace_execution_stops::ExecutionStopStoreError::Conflict.into());
        }
        let transaction = self.connection.unchecked_transaction()?;
        let execution = workspace_execution_stops::get_for_request(
            &transaction,
            request,
            execution_stop_binding_digest(&binding),
        )?;
        let receipt = stop_receipts::observe_stop_authority_receipt_in_transaction(
            &transaction,
            request.stop_id(),
            request.workspace_id(),
        )?;
        let result = match execution {
            None if receipt.is_none() => None,
            None => return Err(workspace_approvals::ApprovalStoreError::CleanupPlanMismatch.into()),
            Some(execution) => {
                let authority =
                    receipt.ok_or(workspace_approvals::ApprovalStoreError::CleanupPlanMismatch)?;
                Some((execution, authority))
            }
        };
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(result)
    }
    #[cfg(test)]
    pub(super) fn capture_execution_stop_with_postcommit_hook(
        &mut self,
        request: &ExecutionStopRequest,
        hook: impl FnOnce(&mut Self),
    ) -> Result<crate::ExecutionStopCapture, WorkspaceStoreError> {
        self.capture_execution_stop_with_hook(request, hook)
    }
    /// Atomically capture a finite execution cohort and fence fresh beginnings.
    /// This is a persistence primitive, not authorization to stop a process.
    /// All requests remain pending until a future settlement owner proves closure.
    pub fn capture_execution_stop(
        &mut self,
        request: &ExecutionStopRequest,
    ) -> Result<crate::ExecutionStopCapture, WorkspaceStoreError> {
        self.capture_execution_stop_with_hook(request, |_| {})
    }

    fn capture_execution_stop_with_hook(
        &mut self,
        request: &ExecutionStopRequest,
        after_commit: impl FnOnce(&mut Self),
    ) -> Result<crate::ExecutionStopCapture, WorkspaceStoreError> {
        let binding = self.journal_binding()?;
        if binding.workspace_id != request.workspace_id() {
            return Err(workspace_execution_stops::ExecutionStopStoreError::Conflict.into());
        }
        let binding_digest = execution_stop_binding_digest(&binding);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_stop_binding(&transaction, &binding)?;
        let capture = match workspace_execution_stops::capture_in_transaction(
            &transaction,
            request,
            binding_digest,
        ) {
            Ok(capture) => capture,
            Err(source) => {
                let source = WorkspaceStoreError::from(source);
                return match transaction.rollback() {
                    Ok(()) => Err(source),
                    Err(rollback) => Err(WorkspaceStoreError::ExecutionStopRollbackUnconfirmed {
                        source: Box::new(source),
                        rollback,
                    }),
                };
            }
        };
        transaction.commit().map_err(|source| {
            WorkspaceStoreError::ExecutionStopCommittedUnconfirmed {
                source: Box::new(source.into()),
            }
        })?;
        after_commit(self);
        self.capture_sidecar_identities()
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::ExecutionStopCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )?;
        Ok(capture)
    }

    /// Read the original request and cohort without admitting any native effect.
    pub fn execution_stop_for_request(
        &self,
        request: &ExecutionStopRequest,
    ) -> Result<Option<crate::ExecutionStopRecord>, WorkspaceStoreError> {
        let binding = self.journal_binding()?;
        if binding.workspace_id != request.workspace_id() {
            return Err(workspace_execution_stops::ExecutionStopStoreError::Conflict.into());
        }
        let transaction = self.connection.unchecked_transaction()?;
        let record = workspace_execution_stops::get_for_request(
            &transaction,
            request,
            execution_stop_binding_digest(&binding),
        )?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(record)
    }
}

fn validate_stop_binding(
    transaction: &rusqlite::Transaction<'_>,
    binding: &WorkspaceJournalBinding,
) -> Result<(), WorkspaceStoreError> {
    let workspace = query_workspace_row(transaction)?
        .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
        .and_then(decode_workspace)?;
    if workspace.id() != binding.workspace_id
        || workspace.revision() != binding.workspace_revision
        || workspace.location_id() != binding.location_id
        || workspace.root().as_path() != binding.workspace_root
        || workspace.root_fingerprint() != binding.root_fingerprint
    {
        return Err(workspace_execution_stops::ExecutionStopStoreError::Conflict.into());
    }
    Ok(())
}

fn capture_owned_stop_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    request: &ExecutionStopRequest,
    binding_digest: [u8; 32],
) -> Result<OwnedWorkspaceStopCapture, WorkspaceStoreError> {
    if workspace_execution_stops::get_for_request(transaction, request, binding_digest)?.is_some() {
        let authority = stop_receipts::observe_stop_authority_receipt_in_transaction(
            transaction,
            request.stop_id(),
            request.workspace_id(),
        )?
        .ok_or(workspace_approvals::ApprovalStoreError::CleanupPlanMismatch)?;
        let execution = workspace_execution_stops::capture_in_transaction(
            transaction,
            request,
            binding_digest,
        )?;
        return Ok(OwnedWorkspaceStopCapture {
            execution,
            authority,
        });
    }
    let plan = workspace_approvals::prepare_cleanup_plan_in_transaction(
        transaction,
        request.workspace_id(),
        ApprovalCleanupSelector::Workspace,
        request.observed_at(),
        forge_domain::ExecutionListLimit::new(256)
            .map_err(|_| workspace_approvals::ApprovalStoreError::CleanupLimitExceeded)?,
        ApprovalCleanupMode::AuthorityCancellation,
    )?;
    if plan.has_more() {
        return Err(workspace_approvals::ApprovalStoreError::CleanupLimitExceeded.into());
    }
    let execution =
        workspace_execution_stops::capture_in_transaction(transaction, request, binding_digest)?;
    let authority =
        stop_receipts::capture_and_apply_in_transaction(transaction, &plan, request.stop_id())?;
    Ok(OwnedWorkspaceStopCapture {
        execution,
        authority,
    })
}

fn execution_stop_binding_digest(binding: &WorkspaceJournalBinding) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"forge.workspace.execution-stop.binding.v1\0");
    hasher.update(binding.workspace_id.into_uuid().as_bytes());
    hasher.update(binding.workspace_revision.get().to_le_bytes());
    hasher.update(binding.location_id.into_uuid().as_bytes());
    hasher.update(binding.root_fingerprint.as_bytes());
    for path in [
        &binding.workspace_root,
        &binding.state_root,
        &binding.database_path,
    ] {
        let bytes = path.as_os_str().as_bytes();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    for identity in [
        (
            binding.state_root_identity.device,
            binding.state_root_identity.inode,
        ),
        (
            binding.database_identity.device,
            binding.database_identity.inode,
        ),
    ] {
        hasher.update(identity.0.to_le_bytes());
        hasher.update(identity.1.to_le_bytes());
    }
    hasher.finalize().into()
}
