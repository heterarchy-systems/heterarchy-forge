//! Atomic recovery-maintenance classification against an exact lease/binding.

use forge_domain::{
    ActivityListLimit, ExecutionListLimit, ReconcileExpiredActivities,
    RecoveryLeaseReleaseDecision, RecoveryLeaseTransitionError, RecoveryMaintenanceLease,
    RegisteredActivity, RegisteredExecution, ReleaseRecoveryLease, TimestampMillis,
};
use rusqlite::{Transaction, TransactionBehavior};

use super::{WorkspaceJournalBinding, WorkspaceStore, WorkspaceStoreError};
use crate::RecoveryStoreError;

impl WorkspaceStore {
    /// Classify both durable families behind the exact original live lease.
    /// This does not establish process closure or release any admission fence.
    pub fn classify_recovery_maintenance(
        &mut self,
        binding: &WorkspaceJournalBinding,
        lease: &RecoveryMaintenanceLease,
        observed_at: TimestampMillis,
        activity_limit: ActivityListLimit,
        execution_limit: ExecutionListLimit,
    ) -> Result<(Vec<RegisteredActivity>, Vec<RegisteredExecution>), WorkspaceStoreError> {
        if self.journal_binding()? != *binding {
            return Err(WorkspaceStoreError::RecoveryClassificationBindingConflict);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = classify_in_transaction(
            &transaction,
            binding,
            lease,
            observed_at,
            activity_limit,
            execution_limit,
        );
        let classified = match result {
            Ok(classified) => classified,
            Err(source) => {
                return match transaction.rollback() {
                    Ok(()) => Err(source),
                    Err(rollback) => Err(
                        WorkspaceStoreError::RecoveryClassificationRollbackUnconfirmed {
                            source: Box::new(source),
                            rollback,
                        },
                    ),
                };
            }
        };
        transaction.commit().map_err(|source| {
            WorkspaceStoreError::RecoveryClassificationCommittedUnconfirmed {
                source: Box::new(source.into()),
            }
        })?;
        self.capture_sidecar_identities()
            .and_then(|()| self.journal_binding())
            .and_then(|current| {
                if current == *binding {
                    Ok(())
                } else {
                    Err(WorkspaceStoreError::RecoveryClassificationBindingConflict)
                }
            })
            .map_err(
                |source| WorkspaceStoreError::RecoveryClassificationCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )?;
        Ok(classified)
    }
}

/// Revalidate the claimed physical Workspace/lease snapshot and classify the
/// existing expired Activity/Execution rows in one caller-owned transaction.
pub(super) fn classify_in_transaction(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    lease: &RecoveryMaintenanceLease,
    observed_at: TimestampMillis,
    activity_limit: ActivityListLimit,
    execution_limit: ExecutionListLimit,
) -> Result<(Vec<RegisteredActivity>, Vec<RegisteredExecution>), WorkspaceStoreError> {
    validate_binding_and_lease(transaction, binding, lease, observed_at)?;
    let activities = WorkspaceStore::reconcile_expired_activities_in_transaction(
        transaction,
        ReconcileExpiredActivities::new(observed_at),
        activity_limit,
    )?;
    let executions =
        crate::workspace_executions::reconcile_expired_authority_executions_in_transaction(
            transaction,
            observed_at,
            execution_limit,
        )?;
    Ok((activities, executions))
}

pub(super) fn validate_binding_and_lease(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    expected_lease: &RecoveryMaintenanceLease,
    observed_at: TimestampMillis,
) -> Result<(), WorkspaceStoreError> {
    if expected_lease.workspace_id() != binding.workspace_id() {
        return Err(WorkspaceStoreError::RecoveryClassificationBindingConflict);
    }

    let workspace = super::query_workspace_row(transaction)?
        .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
        .and_then(super::decode_workspace)?;
    if workspace.id() != binding.workspace_id()
        || workspace.revision() != binding.workspace_revision()
        || workspace.location_id() != binding.location_id()
        || workspace.root().as_path() != binding.workspace_root
        || workspace.root_fingerprint() != binding.root_fingerprint
    {
        return Err(WorkspaceStoreError::RecoveryClassificationBindingConflict);
    }

    let current_lease = crate::workspace_recovery::get(transaction, binding.workspace_id())?;
    if current_lease != *expected_lease {
        return Err(RecoveryStoreError::CompareAndSwapConflict.into());
    }
    let owner_id = expected_lease
        .owner_id()
        .ok_or(RecoveryStoreError::Transition(
            RecoveryLeaseTransitionError::StaleOwner,
        ))?;
    let release = ReleaseRecoveryLease::new(
        binding.workspace_id(),
        owner_id,
        expected_lease.epoch(),
        expected_lease.revision(),
        observed_at,
    );
    if expected_lease
        .decide_release(&release)
        .map_err(RecoveryStoreError::Transition)?
        != RecoveryLeaseReleaseDecision::Release
    {
        return Err(WorkspaceStoreError::RecoveryClassificationBindingConflict);
    }
    if !current_lease.is_live_at(observed_at) {
        return Err(RecoveryStoreError::Transition(RecoveryLeaseTransitionError::Expired).into());
    }
    Ok(())
}
