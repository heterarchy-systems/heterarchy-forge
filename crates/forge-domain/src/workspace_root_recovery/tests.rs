use super::*;
use crate::{LocationId, WorkspaceId, WorkspaceRevision, decide_workspace_root};
use std::path::PathBuf;

fn workspace(revision: i64) -> Result<RegisteredWorkspace, Box<dyn std::error::Error>> {
    Ok(RegisteredWorkspace::from_parts_with_revision(
        WorkspaceId::from_uuid(Uuid::from_u128(1)),
        LocationId::from_uuid(Uuid::from_u128(2)),
        WorkspaceRoot::from_canonical(PathBuf::from("/recovery/selected"))?,
        WorkspaceRootFingerprint::from_bytes([1; 16]),
        TimestampMillis::new(10)?,
        TimestampMillis::new(11)?,
        WorkspaceRevision::new(revision)?,
    ))
}

fn observation(current: &RegisteredWorkspace) -> WorkspaceRootRecoveryObservation {
    WorkspaceRootRecoveryObservation::new(
        current.root().clone(),
        WorkspaceRootFingerprint::from_bytes([2; 16]),
        WorkspaceRootRecoveryWitness::from_bytes([3; 32]),
    )
}

#[test]
fn explicit_recovery_preserves_identity_and_does_not_relax_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let current = workspace(7)?;
    let observed = observation(&current);
    let at = TimestampMillis::new(12)?;
    assert!(
        decide_workspace_root(
            &current,
            observed.root().clone(),
            observed.fingerprint(),
            at,
        )
        .is_err()
    );
    let request = WorkspaceRootRecoveryRequest::new(
        Uuid::from_u128(3),
        LocationRevision::new(1)?,
        current.clone(),
        observed.clone(),
        at,
    )?;
    let updated = decide_workspace_root_recovery(&current, &observed, &request)?;
    assert_eq!(updated.id(), current.id());
    assert_eq!(updated.location_id(), current.location_id());
    assert_eq!(updated.root(), current.root());
    assert_eq!(updated.created_at(), current.created_at());
    assert_eq!(updated.updated_at(), at);
    assert_eq!(updated.root_fingerprint(), observed.fingerprint());
    assert_eq!(updated.revision().get(), 8);
    assert_eq!(
        decide_workspace_root_recovery(&updated, &observed, &request),
        Err(WorkspaceRootRecoveryError::WorkspaceChanged)
    );
    Ok(())
}

#[test]
fn changed_workspace_or_observation_cannot_consume_selected_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let current = workspace(7)?;
    let observed = observation(&current);
    let request = WorkspaceRootRecoveryRequest::new(
        Uuid::from_u128(3),
        LocationRevision::new(1)?,
        current.clone(),
        observed.clone(),
        TimestampMillis::new(12)?,
    )?;
    assert_eq!(
        decide_workspace_root_recovery(&workspace(8)?, &observed, &request),
        Err(WorkspaceRootRecoveryError::WorkspaceChanged)
    );
    let replaced = WorkspaceRootRecoveryObservation::new(
        observed.root().clone(),
        observed.fingerprint(),
        WorkspaceRootRecoveryWitness::from_bytes([4; 32]),
    );
    assert_eq!(
        decide_workspace_root_recovery(&current, &replaced, &request),
        Err(WorkspaceRootRecoveryError::ObservationChanged)
    );
    Ok(())
}

#[test]
fn recovery_revision_overflow_is_a_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let current = workspace(i64::MAX)?;
    let observed = observation(&current);
    let request = WorkspaceRootRecoveryRequest::new(
        Uuid::from_u128(3),
        LocationRevision::new(1)?,
        current.clone(),
        observed.clone(),
        TimestampMillis::new(12)?,
    )?;
    assert_eq!(
        decide_workspace_root_recovery(&current, &observed, &request),
        Err(WorkspaceRootRecoveryError::RevisionOverflow)
    );
    Ok(())
}

#[test]
fn recovery_requires_explicit_changed_binding_and_ordered_time()
-> Result<(), Box<dyn std::error::Error>> {
    let current = workspace(7)?;
    let observed = observation(&current);
    let location_revision = LocationRevision::new(1)?;
    let at = TimestampMillis::new(12)?;
    assert_eq!(
        WorkspaceRootRecoveryRequest::new(
            Uuid::nil(),
            location_revision,
            current.clone(),
            observed.clone(),
            at,
        ),
        Err(WorkspaceRootRecoveryError::NilRequestIdentity)
    );
    assert_eq!(
        WorkspaceRootRecoveryRequest::new(
            Uuid::from_u128(3),
            location_revision,
            current.clone(),
            observed.clone(),
            TimestampMillis::new(10)?,
        ),
        Err(WorkspaceRootRecoveryError::TimestampBeforeSelection)
    );
    let moved = WorkspaceRootRecoveryObservation::new(
        WorkspaceRoot::from_canonical(PathBuf::from("/recovery/different"))?,
        observed.fingerprint(),
        observed.witness(),
    );
    assert_eq!(
        WorkspaceRootRecoveryRequest::new(
            Uuid::from_u128(3),
            location_revision,
            current.clone(),
            moved,
            at,
        ),
        Err(WorkspaceRootRecoveryError::RootPathChanged)
    );
    let unchanged = WorkspaceRootRecoveryObservation::new(
        current.root().clone(),
        current.root_fingerprint(),
        observed.witness(),
    );
    assert_eq!(
        WorkspaceRootRecoveryRequest::new(
            Uuid::from_u128(3),
            location_revision,
            current,
            unchanged,
            at,
        ),
        Err(WorkspaceRootRecoveryError::UnchangedFingerprint)
    );
    Ok(())
}
