use super::*;

use std::fs;

use forge_domain::{
    ActivityListLimit, ClaimRecoveryLease, ExecutionListLimit, RecoveryLeaseDurationMillis,
    RuntimeInstanceId,
};
use uuid::Uuid;

fn owner(value: u128) -> RuntimeInstanceId {
    RuntimeInstanceId::from_uuid(Uuid::from_u128(value))
}

fn expired_activity_and_claim(
    store: &mut WorkspaceStore,
) -> Result<(RegisteredActivity, forge_domain::RecoveryMaintenanceLease), Box<dyn std::error::Error>>
{
    let workspace = store.workspace()?;
    let activity = store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
        ActivityId::from_uuid(Uuid::from_u128(0xC411)),
        workspace.id(),
        workspace.revision(),
        owner(0xC412),
        timestamp(5)?,
        timestamp(2)?,
    ))?;
    let claim = store.claim_recovery_maintenance_lease(ClaimRecoveryLease::new(
        workspace.id(),
        owner(0xC413),
        RecoveryLeaseDurationMillis::new(5_000)?,
        timestamp(10)?,
    )?)?;
    Ok((activity, claim.into_lease()))
}

#[test]
fn classification_requires_the_exact_live_claim_and_preserves_empty_vectors()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _activity_id) = store_with_activity("recovery-classify")?;
    let binding = store.journal_binding()?;
    let workspace = store.workspace()?;
    let claim = ClaimRecoveryLease::new(
        workspace.id(),
        owner(0xC401),
        RecoveryLeaseDurationMillis::new(5_000)?,
        timestamp(10)?,
    )?;
    let claimed = store.claim_recovery_maintenance_lease(claim)?;
    let (activities, executions) = store.classify_recovery_maintenance(
        &binding,
        claimed.lease(),
        timestamp(20)?,
        ActivityListLimit::DEFAULT,
        ExecutionListLimit::DEFAULT,
    )?;
    assert!(activities.is_empty());
    assert!(executions.is_empty());
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn stale_claim_is_rejected_before_classification_effects() -> Result<(), Box<dyn std::error::Error>>
{
    let (root, _layout, mut store, _activity_id) = store_with_activity("recovery-stale")?;
    let binding = store.journal_binding()?;
    let workspace = store.workspace()?;
    let claim = ClaimRecoveryLease::new(
        workspace.id(),
        owner(0xC402),
        RecoveryLeaseDurationMillis::new(5_000)?,
        timestamp(10)?,
    )?;
    let claimed = store.claim_recovery_maintenance_lease(claim)?;
    let release = forge_domain::ReleaseRecoveryLease::new(
        workspace.id(),
        owner(0xC402),
        claimed.lease().epoch(),
        claimed.lease().revision(),
        timestamp(11)?,
    );
    let released = store.release_recovery_maintenance_lease(release)?;
    assert!(released.is_released());
    let result = store.classify_recovery_maintenance(
        &binding,
        claimed.lease(),
        timestamp(20)?,
        ActivityListLimit::DEFAULT,
        ExecutionListLimit::DEFAULT,
    );
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::Recovery(
            crate::RecoveryStoreError::CompareAndSwapConflict
        ))
    ));
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn expired_claim_is_rejected_without_reconciling_rows() -> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _activity_id) = store_with_activity("recovery-expired")?;
    let binding = store.journal_binding()?;
    let workspace = store.workspace()?;
    let claim = ClaimRecoveryLease::new(
        workspace.id(),
        owner(0xC403),
        RecoveryLeaseDurationMillis::new(1_000)?,
        timestamp(10)?,
    )?;
    let claimed = store.claim_recovery_maintenance_lease(claim)?;
    let result = store.classify_recovery_maintenance(
        &binding,
        claimed.lease(),
        timestamp(1_010)?,
        ActivityListLimit::DEFAULT,
        ExecutionListLimit::DEFAULT,
    );
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::Recovery(
            crate::RecoveryStoreError::Transition(
                forge_domain::RecoveryLeaseTransitionError::Expired
            )
        ))
    ));
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn classification_deferred_commit_failure_is_unknown_and_keeps_original_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _) = store_with_activity("recovery-commit-unknown")?;
    let binding = store.journal_binding()?;
    let (before, lease) = expired_activity_and_claim(&mut store)?;
    store.connection.execute_batch(
        "CREATE TABLE recovery_fault_parent (id INTEGER PRIMARY KEY);
         CREATE TABLE recovery_fault_child (
             parent_id INTEGER REFERENCES recovery_fault_parent(id)
             DEFERRABLE INITIALLY DEFERRED
         );
         CREATE TRIGGER recovery_commit_fault AFTER UPDATE ON activities
         WHEN OLD.lease_owner_id IS NOT NULL AND NEW.lease_owner_id IS NULL
         BEGIN INSERT INTO recovery_fault_child(parent_id) VALUES (9); END;",
    )?;
    let result = store.classify_recovery_maintenance(
        &binding,
        &lease,
        timestamp(20)?,
        ActivityListLimit::DEFAULT,
        ExecutionListLimit::DEFAULT,
    );
    assert!(
        matches!(
            &result,
            Err(WorkspaceStoreError::RecoveryClassificationCommittedUnconfirmed { .. })
        ),
        "actual classification result: {result:?}"
    );
    assert_eq!(store.get_activity(before.id())?, Some(before));
    assert_eq!(
        crate::workspace_recovery::get(&store.connection, lease.workspace_id())?,
        lease
    );
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn classification_post_commit_binding_drift_is_unknown_and_keeps_original_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, _) = store_with_activity("recovery-binding-unknown")?;
    let binding = store.journal_binding()?;
    let (before, lease) = expired_activity_and_claim(&mut store)?;
    store.connection.execute_batch(
        "CREATE TRIGGER recovery_binding_fault AFTER UPDATE ON activities
         WHEN OLD.lease_owner_id IS NOT NULL AND NEW.lease_owner_id IS NULL
         BEGIN UPDATE workspace SET revision = revision + 1; END;",
    )?;
    let result = store.classify_recovery_maintenance(
        &binding,
        &lease,
        timestamp(20)?,
        ActivityListLimit::DEFAULT,
        ExecutionListLimit::DEFAULT,
    );
    assert!(matches!(
        result,
        Err(WorkspaceStoreError::RecoveryClassificationCommittedUnconfirmed { .. })
    ));
    let interrupted = store
        .get_activity(before.id())?
        .ok_or("committed activity missing")?;
    assert_eq!(
        interrupted.state(),
        forge_domain::ActivityState::Interrupted
    );
    assert_eq!(interrupted.revision(), before.revision().checked_next()?);
    assert_eq!(
        crate::workspace_recovery::get(&store.connection, lease.workspace_id())?,
        lease
    );
    drop(store);
    fs::remove_dir_all(root)?;
    Ok(())
}
