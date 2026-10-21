//! One durable recovery business request owns one atomic classification result.

use super::{
    WorkspaceJournalBinding, WorkspaceStore, WorkspaceStoreError, decode_activity,
    decode_activity_id, query_activity_row,
};
use crate::workspace_recovery_runs::{
    self, RecoveryActivityFact, RecoveryExecutionFact, RecoveryRunReceipt, RecoveryRunRequest,
    RecoveryRunStoreError,
};
use crate::{workspace_executions, workspace_recovery};
use forge_domain::{
    ActivityState, ClaimRecoveryLease, ReconcileExpiredActivities, RecoveryMaintenanceLease,
    RegisteredActivity, RegisteredExecution, ReleaseRecoveryLease,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use uuid::Uuid;

#[must_use]
#[derive(Debug)]
pub enum RecoveryRunOperation {
    Recorded {
        receipt: RecoveryRunReceipt,
        activities: Vec<RegisteredActivity>,
        executions: Vec<RegisteredExecution>,
    },
    Replay(RecoveryRunReceipt),
    Busy(RecoveryMaintenanceLease),
    ClaimConflict(RecoveryMaintenanceLease),
}

impl WorkspaceStore {
    pub fn recovery_run_for_request(
        &self,
        binding: &WorkspaceJournalBinding,
        request_id: Uuid,
        request_digest: [u8; 32],
    ) -> Result<Option<RecoveryRunReceipt>, WorkspaceStoreError> {
        if self.journal_binding()? != *binding {
            return Err(WorkspaceStoreError::RecoveryClassificationBindingConflict);
        }
        let transaction = self.connection.unchecked_transaction()?;
        let receipt = workspace_recovery_runs::get_for_request(
            &transaction,
            binding.workspace_id,
            request_id,
            request_digest,
            binding.recovery_history_digest(),
        )?;
        transaction.commit()?;
        if self.journal_binding()? != *binding {
            return Err(WorkspaceStoreError::RecoveryClassificationBindingConflict);
        }
        Ok(receipt)
    }

    pub fn run_recovery_request(
        &mut self,
        binding: &WorkspaceJournalBinding,
        request: &RecoveryRunRequest,
    ) -> Result<RecoveryRunOperation, WorkspaceStoreError> {
        if self.journal_binding()? != *binding
            || request.workspace_id != binding.workspace_id
            || request.binding_digest != binding.recovery_history_digest()
        {
            return Err(WorkspaceStoreError::RecoveryClassificationBindingConflict);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = run_in_transaction(&transaction, binding, request);
        let result = match result {
            Ok(result) => result,
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
        Ok(result)
    }
}

fn run_in_transaction(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    request: &RecoveryRunRequest,
) -> Result<RecoveryRunOperation, WorkspaceStoreError> {
    if let Some(receipt) = workspace_recovery_runs::get_for_request(
        transaction,
        request.workspace_id,
        request.request_id,
        request.request_digest,
        request.binding_digest,
    )? {
        let original = receipt.request();
        if original.owner_id != request.owner_id
            || original.duration != request.duration
            || original.activity_limit != request.activity_limit
            || original.execution_limit != request.execution_limit
        {
            return Err(RecoveryRunStoreError::Conflict.into());
        }
        return Ok(RecoveryRunOperation::Replay(receipt));
    }
    let claim = workspace_recovery::claim(
        transaction,
        &ClaimRecoveryLease::new(
            request.workspace_id,
            request.owner_id,
            request.duration,
            request.claimed_at,
        )
        .map_err(|_| RecoveryRunStoreError::Invalid("claim duration overflow"))?,
    )?;
    match claim.status() {
        workspace_recovery::RecoveryLeaseClaimStatus::Busy => {
            return Ok(RecoveryRunOperation::Busy(claim.into_lease()));
        }
        workspace_recovery::RecoveryLeaseClaimStatus::ClaimConflict => {
            return Ok(RecoveryRunOperation::ClaimConflict(claim.into_lease()));
        }
        workspace_recovery::RecoveryLeaseClaimStatus::Acquired
        | workspace_recovery::RecoveryLeaseClaimStatus::AlreadyOwned => {}
    }
    let claimed_lease = claim.into_lease();
    let before_activities = capture_activities(transaction, request)?;
    let before_executions = workspace_executions::select_expired_authority_executions(
        transaction,
        request.classify_at,
        request.execution_limit,
    )?;
    let eligibility = before_executions
        .iter()
        .map(|execution| {
            query_activity_row(transaction, execution.activity_id())?
                .ok_or(WorkspaceStoreError::ActivityNotFound(
                    execution.activity_id(),
                ))
                .and_then(|raw| decode_activity(&raw))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (activities, executions) = super::recovery_maintenance::classify_in_transaction(
        transaction,
        binding,
        &claimed_lease,
        request.classify_at,
        request.activity_limit,
        request.execution_limit,
    )?;
    let activity_facts = activity_facts(&before_activities, &activities)?;
    let execution_facts =
        execution_facts(transaction, &before_executions, &eligibility, &executions)?;
    let released_lease = workspace_recovery::release(
        transaction,
        &ReleaseRecoveryLease::new(
            request.workspace_id,
            request.owner_id,
            claimed_lease.epoch(),
            claimed_lease.revision(),
            request.classify_at,
        ),
    )?;
    let receipt = RecoveryRunReceipt::new(
        *request,
        claimed_lease,
        released_lease,
        activity_facts,
        execution_facts,
    )?;
    workspace_recovery_runs::append_in_transaction(transaction, &receipt)?;
    Ok(RecoveryRunOperation::Recorded {
        receipt,
        activities,
        executions,
    })
}

fn capture_activities(
    transaction: &Transaction<'_>,
    request: &RecoveryRunRequest,
) -> Result<Vec<RegisteredActivity>, WorkspaceStoreError> {
    WorkspaceStore::expired_activity_ids(
        transaction,
        ReconcileExpiredActivities::new(request.classify_at),
        request.activity_limit,
    )?
    .iter()
    .map(|bytes| {
        let id = decode_activity_id(bytes)?;
        query_activity_row(transaction, id)?
            .ok_or(WorkspaceStoreError::ActivityNotFound(id))
            .and_then(|raw| decode_activity(&raw))
    })
    .collect()
}

fn activity_facts(
    before: &[RegisteredActivity],
    after: &[RegisteredActivity],
) -> Result<Vec<RecoveryActivityFact>, WorkspaceStoreError> {
    if before.len() != after.len() {
        return Err(RecoveryRunStoreError::Conflict.into());
    }
    before
        .iter()
        .zip(after)
        .enumerate()
        .map(|(ordinal, (before, after))| {
            if before.id() != after.id()
                || after.state() != ActivityState::Interrupted
                || after.lease_owner_id().is_some()
                || after.lease_until().is_some()
            {
                return Err(RecoveryRunStoreError::Conflict.into());
            }
            Ok(RecoveryActivityFact::from_before(
                u16::try_from(ordinal).map_err(|_| RecoveryRunStoreError::Overflow)?,
                before,
                after.revision(),
                after.updated_at(),
                after.lease_revision(),
            )?)
        })
        .collect()
}

fn execution_facts(
    transaction: &Transaction<'_>,
    before: &[RegisteredExecution],
    eligibility: &[RegisteredActivity],
    after: &[RegisteredExecution],
) -> Result<Vec<RecoveryExecutionFact>, WorkspaceStoreError> {
    if before.len() != after.len() || before.len() != eligibility.len() {
        return Err(RecoveryRunStoreError::Conflict.into());
    }
    before.iter().zip(eligibility).zip(after).enumerate().map(|(ordinal,((before,activity),after))| {
        let sequence=transaction.query_row("SELECT sequence FROM semantic_events WHERE workspace_id=?1 AND event_kind='execution_terminal'
            AND subject_execution_id=?2 AND revision=?3 AND observed_at_ms=?4 ORDER BY sequence LIMIT 1",
            params![after.workspace_id().into_uuid().as_bytes(),after.id().into_uuid().as_bytes(),after.revision().get(),after.timestamps().updated_at().get()],|row|row.get::<_,i64>(0))?;
        let effect=transaction.query_row("SELECT outbox_sequence FROM effect_fact_outbox_execution_terminal WHERE execution_id=?1 AND execution_revision=?2 AND observed_at_ms=?3",
            params![after.id().into_uuid().as_bytes(),after.revision().get(),after.timestamps().updated_at().get()],|row|row.get::<_,i64>(0)).optional()?;
        Ok(RecoveryExecutionFact::from_before_after(u8::try_from(ordinal).map_err(|_|RecoveryRunStoreError::Overflow)?,before,activity,after,sequence,effect)?)
    }).collect()
}
