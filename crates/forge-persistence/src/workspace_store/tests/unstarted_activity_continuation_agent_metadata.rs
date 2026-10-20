//! Focused schema-v66 Agent metadata continuation regressions.

use super::*;

use forge_domain::{
    AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId, AgentTransportKind,
    AuthenticatedPrincipal, ExpectedActivityCoordinator, ExpiredActivityRecoveryAgentSnapshot,
};
use uuid::Uuid;

type Fixture = (
    std::path::PathBuf,
    WorkspaceStore,
    WorkspaceId,
    ActivityId,
    Vec<ExpiredActivityRecoveryAgentSnapshot>,
    ExpectedActivityCoordinator,
);

fn activated_fixture(label: &str, seed: u128) -> Result<Fixture, Box<dyn std::error::Error>> {
    activated_fixture_at(label, seed, 21)
}

fn activated_fixture_at(
    label: &str,
    seed: u128,
    activated_at: i64,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let (root, _layout, mut store, activity_id) = store_with_live_activity(label)?;
    let workspace_id = store.workspace()?.id();
    let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(seed + 1),
        Uuid::from_u128(seed + 2),
        timestamp(3)?,
    )?)?;
    let reservation = crate::AgentBindingReservationRequest::new(
        Uuid::from_u128(seed + 3),
        activity_id,
        AgentInstanceId::from_uuid(Uuid::from_u128(seed + 4)),
        AgentSessionId::from_uuid(Uuid::from_u128(seed + 5)),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(10)?,
    )?;
    let _reservation = store.reserve_agent_binding(&freeze, &reservation, timestamp(11)?)?;
    let delegation = store.delegate_agent_operations(&freeze, [0x72; 32], timestamp(20)?)?;
    let activation = crate::AgentBindingActivationRequest::new(
        reservation.request_id(),
        [0x73; 32],
        AgentDisplayName::new("continuation coordinator".to_owned())?,
        AgentDeclaredRole::new("planner".to_owned())?,
        AgentTransportKind::Stdio,
    )?;
    let _activation =
        store.activate_agent_binding(&delegation, &activation, timestamp(activated_at)?)?;
    let agent = store
        .get_agent(reservation.agent_id())?
        .ok_or("activated Agent missing")?;
    let coordinator = store.claim_activity_coordinator(
        forge_domain::ClaimActivityCoordinator::new(
            workspace_id,
            activity_id,
            agent.id(),
            agent.principal(),
            timestamp(activated_at + 1)?,
            agent.session_id().ok_or("activated Session missing")?,
        ),
        timestamp(activated_at + 1)?,
    )?;
    Ok((
        root,
        store,
        workspace_id,
        activity_id,
        vec![ExpiredActivityRecoveryAgentSnapshot::from_agent(&agent)],
        ExpectedActivityCoordinator::new(
            coordinator.agent_id(),
            coordinator.revision().get(),
            coordinator.updated_at(),
        )?,
    ))
}

#[test]
fn actual_activation_and_coordinator_metadata_validate_and_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, store, workspace, activity, agents, coordinator) =
        activated_fixture("continuation-agent-metadata-positive", 0xA600)?;
    let digest = crate::workspace_store::unstarted_activity_continuation::agent_metadata::validate_and_digest_agent_metadata_for_test(
        &store.connection,
        workspace,
        activity,
        &agents,
        coordinator,
    )?;
    assert_ne!(digest, [0; 32]);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn missing_probe_agent_and_bad_focus_counterpart_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, store, workspace, activity, agents, coordinator) =
        activated_fixture("continuation-agent-metadata-counterpart", 0xA700)?;
    assert!(
        crate::workspace_store::unstarted_activity_continuation::agent_metadata::validate_and_digest_agent_metadata_for_test(
            &store.connection,
            workspace,
            activity,
            &[],
            coordinator,
        )
        .is_err()
    );
    store.connection.execute(
        "UPDATE agent_effect_outbox_focus SET event_sequence=event_sequence+1 WHERE activity_id=?1",
        rusqlite::params![activity.into_uuid().as_bytes()],
    )?;
    assert!(
        crate::workspace_store::unstarted_activity_continuation::agent_metadata::validate_and_digest_agent_metadata_for_test(
            &store.connection,
            workspace,
            activity,
            &agents,
            coordinator,
        )
        .is_err()
    );
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn orphaned_outbox_payload_and_corrupt_agent_row_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, store, workspace, activity, agents, coordinator) =
        activated_fixture("continuation-agent-metadata-orphan", 0xA800)?;
    let original_event_id: Vec<u8> = store.connection.query_row(
        "SELECT event_id FROM agent_effect_outbox_transitions WHERE activity_id=?1 LIMIT 1",
        rusqlite::params![activity.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    store
        .connection
        .pragma_update(None, "ignore_check_constraints", "ON")?;
    store.connection.execute(
        "UPDATE agent_effect_outbox_transitions SET event_id=zeroblob(15) WHERE activity_id=?1",
        rusqlite::params![activity.into_uuid().as_bytes()],
    )?;
    assert!(
        crate::workspace_store::unstarted_activity_continuation::agent_metadata::validate_and_digest_agent_metadata_for_test(
            &store.connection,
            workspace,
            activity,
            &agents,
            coordinator,
        )
        .is_err()
    );
    store.connection.execute(
        "UPDATE agent_effect_outbox_transitions SET event_id=?1 WHERE activity_id=?2",
        rusqlite::params![original_event_id, activity.into_uuid().as_bytes()],
    )?;
    store
        .connection
        .pragma_update(None, "ignore_check_constraints", "OFF")?;

    store
        .connection
        .pragma_update(None, "foreign_keys", "OFF")?;
    store.connection.execute(
        "DELETE FROM agent_effect_outbox_entries WHERE sequence=(SELECT outbox_sequence FROM agent_effect_outbox_focus WHERE activity_id=?1 LIMIT 1)",
        rusqlite::params![activity.into_uuid().as_bytes()],
    )?;
    store.connection.pragma_update(None, "foreign_keys", "ON")?;
    assert!(
        crate::workspace_store::unstarted_activity_continuation::agent_metadata::validate_and_digest_agent_metadata_for_test(
            &store.connection,
            workspace,
            activity,
            &agents,
            coordinator,
        )
        .is_err()
    );
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn digest_changes_when_allowed_canonical_focus_timestamps_change()
-> Result<(), Box<dyn std::error::Error>> {
    let (root_a, store_a, workspace_a, activity_a, agents_a, coordinator_a) =
        activated_fixture_at("continuation-agent-metadata-digest-a", 0xA900, 21)?;
    let before = crate::workspace_store::unstarted_activity_continuation::agent_metadata::validate_and_digest_agent_metadata_for_test(
        &store_a.connection,
        workspace_a,
        activity_a,
        &agents_a,
        coordinator_a,
    )?;
    let (root_b, store_b, workspace_b, activity_b, agents_b, coordinator_b) =
        activated_fixture_at("continuation-agent-metadata-digest-b", 0xA900, 22)?;
    let after = crate::workspace_store::unstarted_activity_continuation::agent_metadata::validate_and_digest_agent_metadata_for_test(
        &store_b.connection,
        workspace_b,
        activity_b,
        &agents_b,
        coordinator_b,
    )?;
    assert_ne!(before, after);
    drop(store_a);
    drop(store_b);
    std::fs::remove_dir_all(root_a)?;
    std::fs::remove_dir_all(root_b)?;
    Ok(())
}
