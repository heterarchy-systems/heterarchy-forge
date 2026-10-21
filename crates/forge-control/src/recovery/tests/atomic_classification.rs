//! Lease expiry and cross-family rollback are prerequisites for recovery HTTP.

use super::*;

#[test]
fn durable_run_preserves_interrupted_activity_eligibility_and_rejects_lost_event_link()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("durable-interrupted-eligibility")?;
    let scope = resolved_scope(&fixture.control, fixture.location_id)?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xAD31));
    let _activity = fixture.control.bootstrap_activity(
        &scope,
        activity_id,
        runtime_id(0xAD32),
        timestamp(1)?,
        timestamp(5)?,
    )?;
    let execution_id = {
        let mut store = seed_store(&fixture.root)?;
        let id = insert_running_execution(&mut store, 0xAD33, fixture.workspace_id, activity_id)?;
        let interrupted = store.reconcile_expired_activities(
            &forge_domain::ReconcileExpiredActivities::new(timestamp(20)?),
        )?;
        assert_eq!(interrupted.len(), 1);
        id
    };
    let request = maintenance_request(&scope, 0xAD34, 100)?;
    let report = fixture.control.run_recovery_maintenance(&request)?;
    let receipt = report.receipt().ok_or("receipt missing")?;
    assert_eq!(receipt.activities().len(), 0);
    assert_eq!(receipt.executions().len(), 1);
    let fact = &receipt.executions()[0];
    assert_eq!(fact.execution_id(), execution_id);
    assert_eq!(
        fact.eligibility_activity_state(),
        forge_domain::ActivityState::Interrupted
    );
    assert!(fact.eligibility_activity_lease_owner().is_none());
    assert!(fact.eligibility_activity_lease_until().is_none());
    let root = fixture.root.join("location/workspace-0");
    let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("state missing")?;
    let connection = rusqlite::Connection::open(layout.database_path())?;
    connection.execute(
        "DELETE FROM semantic_events WHERE sequence=?1",
        rusqlite::params![fact.terminal_semantic_sequence()],
    )?;
    drop(connection);
    assert!(
        fixture
            .control
            .recovery_maintenance_get(&scope, request.request_id, request.request_digest)
            .is_err()
    );
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn dropped_actual_recovery_response_reads_original_history_before_replay()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::worker::ForgeControlRequest;
    let fixture = fixture("durable-response-loss")?;
    let scope = resolved_scope(&fixture.control, fixture.location_id)?;
    let request = maintenance_request(&scope, 0xAD21, 100)?;
    let (client, requests) = crate::ForgeControlClient::journal_test_channel(1);
    let control = fixture.control;
    let original = request.clone();
    let handler = std::thread::spawn(move || -> Result<(), String> {
        let first = requests
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        let ForgeControlRequest::RecoveryMaintenanceRun { request, response } = first else {
            return Err("wrong initial operation".to_owned());
        };
        let committed = control
            .run_recovery_maintenance(&request)
            .map_err(|e| format!("actual commit: {e:?}"))?;
        let receipt = committed.receipt().ok_or("receipt missing")?.clone();
        drop(response);
        let next = requests
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        let ForgeControlRequest::RecoveryMaintenanceGet {
            scope,
            request_id,
            request_digest,
            response,
        } = next
        else {
            return Err("readback must precede retry".to_owned());
        };
        let observed = control
            .recovery_maintenance_get(&scope, request_id, request_digest)
            .map_err(|e| format!("actual readback: {e:?}"))?;
        if observed.as_ref() != Some(&receipt) {
            return Err("original receipt changed".to_owned());
        }
        response
            .send(Ok(observed))
            .map_err(|_| "readback receiver dropped")?;
        let next = requests
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        let ForgeControlRequest::RecoveryMaintenanceRun { request, response } = next else {
            return Err("wrong identical retry operation".to_owned());
        };
        if request != original {
            return Err("retry identity changed".to_owned());
        }
        let replay = control
            .run_recovery_maintenance(&request)
            .map_err(|e| format!("actual replay: {e:?}"))?;
        if !replay.replayed() || replay.receipt() != Some(&receipt) {
            return Err("retry recaptured".to_owned());
        }
        response
            .send(Ok(replay))
            .map_err(|_| "retry receiver dropped")?;
        Ok(())
    });
    assert!(matches!(
        client.run_recovery_maintenance(request.clone()),
        Err(crate::ControlClientError::ResponseDropped)
    ));
    let observed = client
        .recovery_maintenance_get(scope, request.request_id, request.request_digest)?
        .ok_or("history missing")?;
    let replay = client.run_recovery_maintenance(request)?;
    assert_eq!(replay.receipt(), Some(&observed));
    assert!(replay.replayed());
    handler
        .join()
        .map_err(|_| "recovery handler panicked")?
        .map_err(std::io::Error::other)?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn durable_replay_uses_original_history_before_new_owner_and_never_recaptures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("durable-old-owner-replay")?;
    let scope = resolved_scope(&fixture.control, fixture.location_id)?;
    let request = maintenance_request(&scope, 0xAD10, 100)?;
    let first = fixture.control.run_recovery_maintenance(&request)?;
    let mut intent = crate::DurableRecoveryMaintenanceRequest {
        scope: scope.clone(),
        request_id: request.request_id,
        request_digest: request.request_digest,
        original_owner_id: request.owner_id,
        configured_owner_id: runtime_id(0xAD11),
        duration: request.duration,
        activity_limit: request.activity_limit,
        execution_limit: request.execution_limit,
    };
    let replay = fixture
        .control
        .run_durable_recovery_maintenance(&intent, timestamp(200)?)?;
    assert!(replay.replayed());
    assert_eq!(replay.receipt(), first.receipt());
    assert_eq!(
        fixture.control.recovery_maintenance_lease(&scope)?,
        *first.lease()
    );
    let observed = fixture.control.recovery_maintenance_get(
        &scope,
        request.request_id,
        request.request_digest,
    )?;
    assert_eq!(observed.as_ref(), first.receipt());
    intent.request_id = Uuid::now_v7();
    assert!(
        fixture
            .control
            .run_durable_recovery_maintenance(&intent, timestamp(201)?)
            .is_err()
    );
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn execution_classification_error_rolls_back_activity_interruption()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("atomic-execution-error")?;
    let scope = resolved_scope(&fixture.control, fixture.location_id)?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xAC01));
    let _bootstrapped = fixture.control.bootstrap_activity(
        &scope,
        activity_id,
        runtime_id(0xAC02),
        timestamp(1)?,
        timestamp(5)?,
    )?;
    let before_execution = {
        let mut store = seed_store(&fixture.root)?;
        let id = insert_running_execution(&mut store, 0xAC03, fixture.workspace_id, activity_id)?;
        let starting = store.get_execution(id)?.ok_or("seeded execution missing")?;
        store.mark_execution_running(forge_domain::MarkExecutionRunning::new(
            id,
            starting.revision(),
            timestamp(200)?,
        ))?
    };
    let before_activity = seed_store(&fixture.root)?
        .get_activity(activity_id)?
        .ok_or("activity missing")?;
    let result = fixture
        .control
        .run_recovery_maintenance(&maintenance_request(&scope, 0xAC04, 100)?);
    assert!(
        result.is_err(),
        "future execution timestamp must reject classification"
    );
    let store = seed_store(&fixture.root)?;
    let after_activity = store
        .get_activity(activity_id)?
        .ok_or("activity disappeared")?;
    assert_eq!(
        after_activity, before_activity,
        "Activity committed before Execution error"
    );
    assert_eq!(
        store.get_execution(before_execution.id())?,
        Some(before_execution)
    );
    drop(store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn maintenance_expired_before_classification_changes_no_activity_or_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("atomic-expired-claim")?;
    let scope = resolved_scope(&fixture.control, fixture.location_id)?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xAC11));
    let _bootstrapped = fixture.control.bootstrap_activity(
        &scope,
        activity_id,
        runtime_id(0xAC12),
        timestamp(1)?,
        timestamp(5)?,
    )?;
    let before_execution = {
        let mut store = seed_store(&fixture.root)?;
        let id = insert_running_execution(&mut store, 0xAC13, fixture.workspace_id, activity_id)?;
        store.get_execution(id)?.ok_or("seeded execution missing")?
    };
    let before_activity = seed_store(&fixture.root)?
        .get_activity(activity_id)?
        .ok_or("activity missing")?;
    let mut request = maintenance_request(&scope, 0xAC14, 100)?;
    request.classify_at = timestamp(1_100)?;
    let result = fixture.control.run_recovery_maintenance(&request);
    assert!(
        result.is_err(),
        "classification accepted an expired recovery lease"
    );
    let store = seed_store(&fixture.root)?;
    assert_eq!(store.get_activity(activity_id)?, Some(before_activity));
    assert_eq!(
        store.get_execution(before_execution.id())?,
        Some(before_execution)
    );
    drop(store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
