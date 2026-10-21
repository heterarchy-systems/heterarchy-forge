//! Focused Source settlement regressions for Plan27.

#![allow(clippy::too_many_lines)]
#![allow(clippy::expect_used)]

use super::*;
use forge_domain::{
    AgentBindingRejectionReason, AgentDeclaredRole, AgentDisplayName, AgentInstanceId,
    AgentSessionId, AgentTransportKind, AuthenticatedPrincipal, DirectTokenId, TimestampMillis,
};
use rusqlite::{Connection, ErrorCode};
use uuid::Uuid;

fn token(value: u128) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(value)))
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn rejection_request(
    store: &WorkspaceStore,
    workspace: &forge_domain::RegisteredWorkspace,
    reservation: &crate::AgentBindingReservation,
    delegation: &crate::AgentOperationsDelegation,
    request_id: Uuid,
    principal: AuthenticatedPrincipal,
    transport: AgentTransportKind,
    membership_byte: u8,
    observed_at: i64,
) -> Result<crate::AgentBindingRejectionStoreRequest, Box<dyn std::error::Error>> {
    let binding = store.journal_binding()?;
    let request = forge_domain::AgentBindingRejectionRequest::new(
        request_id,
        workspace.id(),
        reservation.request().activity_id(),
        reservation.request().agent_id(),
        reservation.request().session_id(),
        principal,
        reservation.migration_id(),
        reservation.destination_id(),
        reservation.freeze_revision(),
        delegation.manifest_digest(),
        Uuid::from_u128(0xBEEF),
        workspace.root_fingerprint(),
        binding.recovery_history_digest(),
        crate::workspace_agent_binding_rejections::agent_binding_rejection_delegation_digest(
            delegation,
        ),
        [membership_byte; 32],
        AgentDisplayName::new("rejected-worker".to_owned())?,
        AgentDeclaredRole::new("operator".to_owned())?,
        transport,
        AgentBindingRejectionReason::PrincipalTransportMismatch,
        reservation.reserved_at(),
        reservation.request().requested_at(),
        TimestampMillis::new(observed_at)?,
    )?;
    Ok(crate::AgentBindingRejectionStoreRequest {
        binding_digest: request.binding_digest(),
        observed_root_fingerprint: workspace.root_fingerprint(),
        current_delegation: delegation.clone(),
        request,
    })
}

#[test]
#[allow(clippy::too_many_lines)]
fn rejection_records_replays_reads_back_and_blocks_only_until_valid_settlement()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, activity_id) = store_with_activity("binding-rejection")?;
    let workspace = store.workspace()?;
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(0xB001),
        Uuid::from_u128(0xB002),
        timestamp(3)?,
    )?)?;
    let principal = token(0xB003);
    let reservation_request = crate::AgentBindingReservationRequest::new(
        Uuid::from_u128(0xB004),
        activity_id,
        AgentInstanceId::from_uuid(Uuid::from_u128(0xB005)),
        AgentSessionId::from_uuid(Uuid::from_u128(0xB006)),
        principal,
        timestamp(10)?,
    )?;
    let reservation = store.reserve_agent_binding(&freeze, &reservation_request, timestamp(11)?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x31; 32], timestamp(20)?)?;
    assert_eq!(
        crate::workspace_store::expired_activity_recovery::first_blocker(
            &store.connection,
            workspace.id(),
            activity_id,
        )?,
        Some(forge_domain::ExpiredActivityRecoveryBlocker::PendingBindingActivation)
    );
    let native = rejection_request(
        &store,
        &workspace,
        &reservation,
        &delegation,
        reservation_request.request_id(),
        principal,
        AgentTransportKind::Other,
        0x41,
        40,
    )?;
    let binding = store.journal_binding()?;
    let database_path = layout.database_path().clone();
    let mut clock_called = false;
    let recorded = crate::workspace_agent_binding_rejections::reject_with_clock(
        &mut store.connection,
        &native,
        || {
            clock_called = true;
            let contender = Connection::open(&database_path)?;
            contender.busy_timeout(std::time::Duration::from_millis(0))?;
            let result = contender.execute(
                "UPDATE agent_binding_reservations SET requested_at_ms=requested_at_ms WHERE request_id=?1",
                rusqlite::params![reservation_request.request_id().as_bytes()],
            );
            assert!(
                result.is_err(),
                "Source clock ran before the IMMEDIATE writer lock"
            );
            TimestampMillis::new(40).map_err(|_| crate::AgentBindingRejectionStoreError::Clock)
        },
    )?;
    assert!(clock_called);
    let crate::AgentBindingRejectionOperation::Recorded(receipt) = recorded else {
        return Err("first rejection did not record".into());
    };
    assert_eq!(
        receipt.request_digest(),
        crate::workspace_agent_binding_rejections::agent_binding_rejection_intent_digest(
            &native.request
        )
    );
    assert!(receipt.rejected_at().get() >= receipt.request().observed_at().get());
    assert!(store.get_agent(reservation.request().agent_id())?.is_none());
    let activation_after_rejection = store.connection.execute(
        "INSERT INTO agent_binding_activations(
            request_id, membership_digest, display_name, declared_role,
            transport_kind, activated_at_ms
         ) VALUES(?1, ?2, 'rejected-worker', 'operator', 3, 41)",
        rusqlite::params![
            reservation_request.request_id().as_bytes(),
            [0x41_u8; 32].as_slice()
        ],
    );
    assert!(
        activation_after_rejection.is_err(),
        "activation trigger allowed a settled rejection"
    );
    assert_eq!(
        crate::workspace_store::expired_activity_recovery::first_blocker(
            &store.connection,
            workspace.id(),
            activity_id,
        )?,
        None
    );

    let mut replay_clock_called = false;
    let replay = crate::workspace_agent_binding_rejections::reject_with_clock(
        &mut store.connection,
        &native,
        || {
            replay_clock_called = true;
            Err(crate::AgentBindingRejectionStoreError::Clock)
        },
    )?;
    assert!(
        !replay_clock_called,
        "exact replay must skip the Source clock"
    );
    assert_eq!(
        replay,
        crate::AgentBindingRejectionOperation::Replay(receipt.clone())
    );
    let changed_intent = rejection_request(
        &store,
        &workspace,
        &reservation,
        &delegation,
        reservation_request.request_id(),
        principal,
        AgentTransportKind::Other,
        0x42,
        40,
    )?;
    assert!(matches!(
        crate::workspace_agent_binding_rejections::reject_with_clock(
            &mut store.connection,
            &changed_intent,
            || Err(crate::AgentBindingRejectionStoreError::Clock),
        ),
        Err(crate::AgentBindingRejectionStoreError::Conflict(
            "rejection request changed"
        ))
    ));
    drop(binding);

    drop(store);
    let reopened = WorkspaceStore::open_existing(
        &WorkspaceStateLayout::inspect_existing(layout.workspace_root())?
            .ok_or("layout missing")?,
    )?;
    assert_eq!(
        reopened.agent_binding_rejection(reservation_request.request_id())?,
        Some(receipt.clone())
    );
    reopened.connection.execute(
        "UPDATE agent_binding_rejections SET receipt_digest=?1 WHERE request_id=?2",
        rusqlite::params![
            [0xAA_u8; 32].as_slice(),
            reservation_request.request_id().as_bytes()
        ],
    )?;
    assert!(
        reopened
            .agent_binding_rejection(reservation_request.request_id())
            .is_err()
    );
    assert!(
        crate::workspace_store::expired_activity_recovery::first_blocker(
            &reopened.connection,
            workspace.id(),
            activity_id,
        )
        .is_err(),
        "corrupt rejection must not clear a recovery blocker"
    );
    reopened.connection.execute(
        "UPDATE agent_binding_rejections SET receipt_digest=?1 WHERE request_id=?2",
        rusqlite::params![
            receipt.receipt_digest().as_slice(),
            reservation_request.request_id().as_bytes()
        ],
    )?;
    reopened.connection.execute(
        "UPDATE agent_binding_reservations SET requested_at_ms=99 WHERE request_id=?1",
        rusqlite::params![reservation_request.request_id().as_bytes()],
    )?;
    assert!(
        reopened
            .agent_binding_rejection(reservation_request.request_id())
            .is_err(),
        "reservation provenance corruption must fail closed"
    );
    drop(reopened);

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn valid_transport_cannot_be_rejected_and_sql_guards_are_mutually_exclusive()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, activity_id) = store_with_activity("binding-rejection-guards")?;
    let workspace = store.workspace()?;
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(0xB101),
        Uuid::from_u128(0xB102),
        timestamp(3)?,
    )?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x52; 32], timestamp(20)?)?;
    let valid_request = crate::AgentBindingReservationRequest::new(
        Uuid::from_u128(0xB103),
        activity_id,
        AgentInstanceId::from_uuid(Uuid::from_u128(0xB104)),
        AgentSessionId::from_uuid(Uuid::from_u128(0xB105)),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(10)?,
    )?;
    let valid_reservation = store.reserve_agent_binding(&freeze, &valid_request, timestamp(11)?)?;
    let valid_native = rejection_request(
        &store,
        &workspace,
        &valid_reservation,
        &delegation,
        valid_request.request_id(),
        AuthenticatedPrincipal::TrustedStdio,
        AgentTransportKind::Stdio,
        0x61,
        40,
    )?;
    assert!(matches!(
        crate::workspace_agent_binding_rejections::reject_with_clock(
            &mut store.connection,
            &valid_native,
            || Ok(TimestampMillis::new(40).expect("valid test timestamp")),
        ),
        Err(crate::AgentBindingRejectionStoreError::Conflict(
            "transport is valid"
        ))
    ));
    let activation = crate::AgentBindingActivationRequest::new(
        valid_request.request_id(),
        [0x61; 32],
        AgentDisplayName::new("rejected-worker".to_owned())?,
        AgentDeclaredRole::new("operator".to_owned())?,
        AgentTransportKind::Stdio,
    )?;
    assert!(
        store
            .activate_agent_binding(&delegation, &activation, timestamp(41)?)
            .is_ok()
    );
    let source = &valid_native.request;
    let request_digest =
        crate::workspace_agent_binding_rejections::agent_binding_rejection_intent_digest(source);
    let freeze_revision = i64::try_from(source.expected_freeze_revision())?;
    let trigger_result = store.connection.execute(
        "INSERT INTO agent_binding_rejections(
            request_id, request_digest, workspace_id, activity_id, agent_id, session_id,
            principal_kind, principal_id, migration_id, destination_id, freeze_revision,
            manifest_digest, issuer_id, workspace_root_fingerprint, binding_digest,
            delegation_digest, membership_digest, display_name, declared_role, transport_kind,
            reserved_at_ms, requested_at_ms, reason, observed_at_ms, rejected_at_ms, receipt_digest
         ) VALUES(
            ?1,?2,?3,?4,?5,?6,0,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,1,?19,?20,0,?21,?21,?22
         )",
        rusqlite::params![
            source.request_id().as_bytes(),
            request_digest.as_slice(),
            source.workspace_id().into_uuid().as_bytes(),
            source.activity_id().into_uuid().as_bytes(),
            source.agent_id().into_uuid().as_bytes(),
            source.session_id().into_uuid().as_bytes(),
            [0_u8; 16].as_slice(),
            source.migration_id().as_bytes(),
            source.destination_id().as_bytes(),
            freeze_revision,
            source.manifest_digest().as_slice(),
            source.issuer_id().as_bytes(),
            source.workspace_root_fingerprint().as_bytes(),
            source.binding_digest().as_slice(),
            source.delegation_digest().as_slice(),
            source.membership_digest().as_slice(),
            source.display_name().as_str(),
            source.declared_role().as_str(),
            source.reserved_at().get(),
            source.requested_at().get(),
            source.observed_at().get(),
            [0xA9_u8; 32].as_slice(),
        ],
    );
    match trigger_result {
        Err(rusqlite::Error::SqliteFailure(error, Some(message))) => {
            assert_eq!(error.code, ErrorCode::ConstraintViolation);
            assert_eq!(message, "agent binding activation already exists");
        }
        Err(error) => return Err(format!("unexpected trigger error: {error}").into()),
        Ok(_) => return Err("rejection trigger allowed activation race".into()),
    }
    let rejection_count: i64 = store.connection.query_row(
        "SELECT COUNT(*) FROM agent_binding_rejections WHERE request_id=?1",
        rusqlite::params![valid_request.request_id().as_bytes()],
        |row| row.get(0),
    )?;
    assert_eq!(rejection_count, 0);
    drop(store);
    std::fs::remove_dir_all(root)?;
    let _ = layout;
    Ok(())
}

#[test]
fn schema_v64_to_v65_recreates_rejection_objects_without_losing_activation_history()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, mut store, activity_id) =
        store_with_activity("binding-rejection-migration")?;
    let reservation_request = crate::AgentBindingReservationRequest::new(
        Uuid::from_u128(0xB203),
        activity_id,
        AgentInstanceId::from_uuid(Uuid::from_u128(0xB204)),
        AgentSessionId::from_uuid(Uuid::from_u128(0xB205)),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(10)?,
    )?;
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(0xB201),
        Uuid::from_u128(0xB202),
        timestamp(3)?,
    )?)?;
    let reservation = store.reserve_agent_binding(&freeze, &reservation_request, timestamp(11)?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x72; 32], timestamp(20)?)?;
    let activation = crate::AgentBindingActivationRequest::new(
        reservation_request.request_id(),
        [0x73; 32],
        AgentDisplayName::new("migration-worker".to_owned())?,
        AgentDeclaredRole::new("operator".to_owned())?,
        AgentTransportKind::Stdio,
    )?;
    let activation = store.activate_agent_binding(&delegation, &activation, timestamp(21)?)?;
    downgrade_admission_identity(&store.connection)?;
    store.connection.execute_batch(
        "DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
         DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
         DROP TABLE IF EXISTS agent_binding_rejections;
         DROP TABLE unstarted_activity_continuation_receipts;
         PRAGMA user_version = 64;",
    )?;
    drop(store);
    let existing =
        WorkspaceStateLayout::inspect_existing(layout.workspace_root())?.ok_or("layout missing")?;
    let migrated = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        migrated.health()?.schema_version(),
        crate::workspace_store::CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        migrated.agent_binding_reservation(reservation_request.request_id())?,
        Some(reservation)
    );
    assert_eq!(
        migrated.agent_binding_activation(reservation_request.request_id())?,
        Some(activation)
    );
    drop(migrated);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
