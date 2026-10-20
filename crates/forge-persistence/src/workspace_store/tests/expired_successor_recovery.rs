//! Focused source proof for the frozen expired-successor recovery contract.

#![allow(clippy::too_many_lines)]

use super::*;

use crate::{ExpiredActivityRecoveryOperation, ExpiredActivityRecoveryStoreRequest};
use forge_domain::{
    ActivityId, ActivityState, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal,
    BootstrapActivity, ExpiredActivityRecoveryExpectation, ExpiredActivityRecoveryProbeScope,
    ExpiredActivityRecoverySessionEvidence, ForgeBackendId, OrchestrationIssuerId,
    RecoveryLeaseDurationMillis, RuntimeInstanceId,
};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

#[test]
fn expired_attached_activity_recovers_atomically_and_reopens_with_history()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, _unused_activity_id) =
        store_with_activity("expired-successor-recovery")?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xE010));
    let workspace = store.workspace()?;
    let owner = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xE001));
    let activity = store.bootstrap_activity(&BootstrapActivity::new(
        activity_id,
        workspace.id(),
        workspace.revision(),
        owner,
        timestamp(50)?,
        timestamp(10)?,
    ))?;
    let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(0xE002));
    let session_id = AgentSessionId::from_uuid(Uuid::from_u128(0xE003));
    store.connection.execute(
        "INSERT INTO agent_instances (
            agent_id, workspace_id, activity_id, display_name, declared_role,
            transport_kind, principal_kind, principal_id, attachment_state,
            focus_goal_id, focus_goal_revision, focus_dag_revision, focus_node_id,
            focus_node_revision, created_at_ms, updated_at_ms, revision, session_id
         ) VALUES (?1, ?2, ?3, 'recovery-agent', 'operator', 1, 0, NULL, 0,
                   NULL, NULL, NULL, NULL, NULL, 20, 20, 1, ?4)",
        params![
            agent_id.into_uuid().as_bytes(),
            workspace.id().into_uuid().as_bytes(),
            activity.id().into_uuid().as_bytes(),
            session_id.into_uuid().as_bytes(),
        ],
    )?;
    store.connection.execute(
        "INSERT INTO activity_coordinators (
            activity_id, workspace_id, agent_id, revision, updated_at_ms
         ) VALUES (?1, ?2, ?3, 1, 20)",
        params![
            activity.id().into_uuid().as_bytes(),
            workspace.id().into_uuid().as_bytes(),
            agent_id.into_uuid().as_bytes(),
        ],
    )?;

    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(0xE004),
        Uuid::from_u128(0xE005),
        timestamp(30)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x5A; 32], timestamp(31)?)?;
    let binding = store.journal_binding()?;
    let probe_scope = ExpiredActivityRecoveryProbeScope::new(
        workspace.id(),
        workspace.revision(),
        workspace.location_id(),
        forge_domain::LocationRevision::INITIAL,
        b".".to_vec(),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
    )?;
    let probe = store.probe_expired_activity_recovery(
        &binding,
        &probe_scope,
        activity.id(),
        timestamp(100)?,
    )?;
    assert!(probe.expired_at_observation());
    assert!(probe.recoverable_now());
    assert_eq!(probe.agent_count(), 1);
    assert_eq!(
        probe
            .coordinator()
            .map(forge_domain::ExpectedActivityCoordinator::agent_id),
        Some(agent_id)
    );

    let expectation = ExpiredActivityRecoveryExpectation::new(
        probe.predecessor(),
        ActivityId::from_uuid(Uuid::from_u128(0xE006)),
        session_id,
        AuthenticatedPrincipal::TrustedStdio,
        probe.agent_count(),
        *probe.agent_digest(),
        probe.coordinator(),
    )?;
    let request = ExpiredActivityRecoveryStoreRequest {
        request_id: Uuid::from_u128(0xE007),
        request_digest: [0xA7; 32],
        probe_scope,
        probe_observed_at: probe.probe_observed_at(),
        probe_digest: *probe.probe_digest(),
        delegation: probe.delegation(),
        delegation_digest: *probe.delegation_digest(),
        service_backend_id: ForgeBackendId::from_uuid(Uuid::from_u128(0xE008)),
        service_issuer: OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xE009)),
        service_destination_id: delegation.destination_id(),
        owner_id: RuntimeInstanceId::from_uuid(Uuid::from_u128(0xE00A)),
        duration: RecoveryLeaseDurationMillis::new(5_000)?,
        expectation,
        session: ExpiredActivityRecoverySessionEvidence::new(
            session_id,
            AuthenticatedPrincipal::TrustedStdio,
            1,
            timestamp(20)?,
        )?,
    };
    let mut stale_request = request.clone();
    stale_request.probe_digest = [0xA8; 32];
    assert!(
        store
            .run_expired_activity_recovery_with_clock(&binding, &stale_request, || {
                let contender =
                    rusqlite::Connection::open(layout.database_path()).map_err(|error| {
                        WorkspaceStoreError::RecoveryLeaseClockObservation {
                            source: Box::new(error),
                        }
                    })?;
                contender
                    .busy_timeout(std::time::Duration::from_millis(0))
                    .map_err(|error| WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(error),
                    })?;
                let write_attempt = contender.execute(
                    "UPDATE activities SET updated_at_ms=updated_at_ms WHERE activity_id=?1",
                    params![activity.id().into_uuid().as_bytes()],
                );
                assert!(
                    write_attempt.is_err(),
                    "recovery clock must run after the writer lock"
                );
                TimestampMillis::new(100).map_err(|error| {
                    WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(error),
                    }
                })
            },)
            .is_err()
    );
    assert_eq!(
        store.get_activity(activity.id())?.map(|row| row.state()),
        Some(ActivityState::Open)
    );
    assert!(
        store
            .get_activity(request.expectation.successor_activity_id())?
            .is_none()
    );
    let mut mismatched_session = request.clone();
    mismatched_session.session = ExpiredActivityRecoverySessionEvidence::new(
        AgentSessionId::from_uuid(Uuid::from_u128(0xE00C)),
        AuthenticatedPrincipal::TrustedStdio,
        1,
        timestamp(20)?,
    )?;
    assert!(
        store
            .run_expired_activity_recovery_with_clock(&binding, &mismatched_session, || {
                TimestampMillis::new(100).map_err(|error| {
                    WorkspaceStoreError::RecoveryLeaseClockObservation {
                        source: Box::new(error),
                    }
                })
            },)
            .is_err()
    );

    store.connection.execute(
        "INSERT INTO writer_leases (
            lease_id, workspace_id, activity_id, agent_id, state,
            acquired_at_ms, updated_at_ms, lease_until_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, 0, 20, 20, 10000, 1)",
        params![
            Uuid::from_u128(0xE00B).as_bytes(),
            workspace.id().into_uuid().as_bytes(),
            activity.id().into_uuid().as_bytes(),
            agent_id.into_uuid().as_bytes(),
        ],
    )?;
    assert!(
        store
            .run_expired_activity_recovery_with_clock(&binding, &request, || timestamp(100)
                .map_err(|_| WorkspaceStoreError::RecoveryLeaseClockObservation {
                    source: std::io::Error::other("test clock").into(),
                }),)
            .is_err()
    );
    assert_eq!(
        store.get_activity(activity.id())?.map(|row| row.state()),
        Some(ActivityState::Open)
    );
    store.connection.execute(
        "DELETE FROM writer_leases WHERE lease_id=?1",
        params![Uuid::from_u128(0xE00B).as_bytes()],
    )?;

    let foreign_claim =
        store.claim_recovery_maintenance_lease(forge_domain::ClaimRecoveryLease::new(
            workspace.id(),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xE00D)),
            request.duration,
            timestamp(100)?,
        )?)?;
    assert_eq!(
        foreign_claim.status(),
        crate::RecoveryLeaseClaimStatus::Acquired
    );
    let busy = store.run_expired_activity_recovery_with_clock(&binding, &request, || {
        TimestampMillis::new(100).map_err(|error| {
            WorkspaceStoreError::RecoveryLeaseClockObservation {
                source: Box::new(error),
            }
        })
    })?;
    assert!(matches!(busy, ExpiredActivityRecoveryOperation::Busy(_)));
    let _ = store.release_recovery_maintenance_lease(forge_domain::ReleaseRecoveryLease::new(
        workspace.id(),
        foreign_claim
            .lease()
            .owner_id()
            .ok_or("foreign owner missing")?,
        foreign_claim.lease().epoch(),
        foreign_claim.lease().revision(),
        timestamp(100)?,
    ))?;

    let preclaimed =
        store.claim_recovery_maintenance_lease(forge_domain::ClaimRecoveryLease::new(
            workspace.id(),
            request.owner_id,
            request.duration,
            timestamp(100)?,
        )?)?;
    assert!(preclaimed.is_acquired());

    let already_owned =
        store.run_expired_activity_recovery_with_clock(&binding, &request, || {
            TimestampMillis::new(100).map_err(|error| {
                WorkspaceStoreError::RecoveryLeaseClockObservation {
                    source: Box::new(error),
                }
            })
        })?;
    assert!(matches!(
        already_owned,
        ExpiredActivityRecoveryOperation::ClaimConflict(_)
    ));
    let _ = store.release_recovery_maintenance_lease(forge_domain::ReleaseRecoveryLease::new(
        workspace.id(),
        request.owner_id,
        preclaimed.lease().epoch(),
        preclaimed.lease().revision(),
        timestamp(100)?,
    ))?;

    let operation = store.run_expired_activity_recovery_with_clock(&binding, &request, || {
        timestamp(100).map_err(|_| WorkspaceStoreError::RecoveryLeaseClockObservation {
            source: std::io::Error::other("test clock").into(),
        })
    })?;
    let ExpiredActivityRecoveryOperation::Recorded(receipt) = operation else {
        return Err("recovery did not record".into());
    };
    assert_eq!(receipt.agents().len(), 1);
    assert_eq!(
        receipt.relation().successor_activity_id(),
        request.expectation.successor_activity_id()
    );
    assert_eq!(
        store.get_activity(activity.id())?.map(|row| row.state()),
        Some(ActivityState::Interrupted)
    );
    assert_eq!(
        store
            .get_activity(request.expectation.successor_activity_id())?
            .map(|row| row.lease_owner_id()),
        Some(Some(request.owner_id)),
    );
    let readback = store
        .expired_activity_recovery_readback_for_request(
            &binding,
            request.request_id,
            request.request_digest,
        )?
        .ok_or("receipt missing after recovery")?;
    assert_eq!(readback.receipt(), &receipt);
    assert_eq!(
        readback.current_successor().id(),
        request.expectation.successor_activity_id()
    );
    drop(store);
    let reopened_layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    let mut reopened = WorkspaceStore::open_existing(&reopened_layout)?;
    let reopened_binding = reopened.journal_binding()?;
    let reopened_readback = reopened
        .expired_activity_recovery_readback_for_request(
            &reopened_binding,
            request.request_id,
            request.request_digest,
        )?
        .ok_or("receipt missing after reopen")?;
    assert_eq!(reopened_readback.receipt(), &receipt);
    let replay =
        reopened.run_expired_activity_recovery_with_clock(&reopened_binding, &request, || {
            Err(WorkspaceStoreError::RecoveryLeaseClockObservation {
                source: std::io::Error::other("replay must not sample clock").into(),
            })
        })?;
    assert!(matches!(
        replay,
        ExpiredActivityRecoveryOperation::Replay(_)
    ));
    let renewed = reopened.renew_activity_lease(&forge_domain::RenewActivityLease::new(
        request.expectation.successor_activity_id(),
        request.owner_id,
        forge_domain::ActivityLeaseRevision::INITIAL,
        timestamp(6_000)?,
        timestamp(200)?,
    ))?;
    assert_eq!(renewed.lease_revision().get(), 2);
    let later_readback = reopened
        .expired_activity_recovery_readback_for_request(
            &reopened_binding,
            request.request_id,
            request.request_digest,
        )?
        .ok_or("receipt missing after later lease change")?;
    assert_eq!(later_readback.receipt(), &receipt);
    assert_eq!(later_readback.current_successor().lease_revision().get(), 2);
    reopened.connection.execute(
        "UPDATE expired_activity_recovery_receipts SET receipt_digest=zeroblob(32) WHERE request_id=?1",
        params![request.request_id.as_bytes()],
    )?;
    assert!(
        reopened
            .expired_activity_recovery_readback_for_request(
                &reopened_binding,
                request.request_id,
                request.request_digest,
            )
            .is_err()
    );
    drop(reopened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_v63_to_v64_migration_recreates_empty_receipts_and_foreign_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, store, _) = store_with_activity("expired-successor-v63-migration")?;
    downgrade_admission_identity(&store.connection)?;
    store.connection.execute_batch(
        "DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
         DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
         DROP TABLE IF EXISTS agent_binding_rejections;
         DROP TABLE expired_activity_recovery_agents;
         DROP INDEX expired_activity_recovery_receipts_successor_uidx;
         DROP TABLE expired_activity_recovery_receipts;
         DROP TABLE unstarted_activity_continuation_receipts;
         PRAGMA user_version = 63;",
    )?;
    drop(store);
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(migrated.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    let object_count: i64 = migrated.connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name IN (
            'expired_activity_recovery_receipts',
            'expired_activity_recovery_agents',
            'expired_activity_recovery_receipts_successor_uidx'
        )",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(object_count, 3);
    let foreign_key_violation: Option<String> = migrated
        .connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()?;
    assert!(foreign_key_violation.is_none());
    drop(migrated);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
