//! Worker and native-queue evidence for approval-scoped Workspace stops.
//!
//! These tests keep the durable execution/authority receipt separate from the
//! native cancellation result.  Every response-loss case performs a real
//! SQLite operation before dropping the response so a retry is forced through
//! durable readback instead of an in-memory success path.

use super::workspace_stop::{
    approved_start, join_fixture_producer, stop_request, wait_for_started_marker,
};
use super::*;
use crate::approval_cleanup::{ApprovalCleanupOwner, ApprovalCleanupSelector};
use crate::worker::ForgeControlRequest;
use crate::{
    ControlClientError, ExecutionStartDisposition, OwnedWorkspaceExecutionStopObservation,
};
use forge_persistence::{ExecutionStopRequest, ExecutionStopStatus};

fn owned_permit(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    owner: ApprovalCleanupOwner,
) -> Result<crate::approval_cleanup::ApprovalCleanupPermit, Box<dyn Error>> {
    Ok(control.mint_approval_cleanup_permit(
        owner,
        scope.clone(),
        ApprovalCleanupSelector::Workspace,
    )?)
}

fn owned_stop_request(
    scope: &ResolvedWorkspaceScope,
    seed: u128,
    observed_at: i64,
) -> Result<ExecutionStopRequest, Box<dyn Error>> {
    Ok(ExecutionStopRequest::new(
        id(seed),
        scope.workspace_id(),
        id(seed + 1),
        RuntimeInstanceId::from_uuid(id(seed + 2)),
        [0x82; 32],
        timestamp(observed_at)?,
    ))
}

fn serve_owned_prepare_response_loss(
    requests: &std::sync::mpsc::Receiver<ForgeControlRequest>,
    prepare_count: &AtomicU64,
    apply_count: &AtomicU64,
    readback_count: &AtomicU64,
    timestamp_log: &std::sync::Mutex<Vec<i64>>,
) -> Result<(), String> {
    while let Ok(request) = requests.recv() {
        match request {
            ForgeControlRequest::OwnedExecutionStopHistory {
                permit,
                owner,
                request,
                response,
            } => {
                let _ignored = response.send(ForgeControl::observe_owned_stop_history(
                    &permit, owner, request,
                ));
            }
            ForgeControlRequest::OwnedExecutionStopSettle {
                settlement,
                response,
            } => {
                let _ignored = response.send(ForgeControl::settle_owned_execution_stop_context(
                    &settlement,
                ));
            }
            ForgeControlRequest::OwnedExecutionStopPrepare {
                permit,
                owner,
                request,
                response,
            } => {
                timestamp_log
                    .lock()
                    .map_err(|_| "prepare timestamp mutex poisoned".to_owned())?
                    .push(request.observed_at().get());
                let context =
                    ForgeControl::prepare_owned_execution_stop_context(&permit, owner, request)
                        .map_err(|error| format!("actual owned prepare failed: {error:?}"))?;
                if prepare_count.fetch_add(1, Ordering::Relaxed) == 0 {
                    // Prepare is read-only. Dropping this reply must not
                    // manufacture a durable capture or native result.
                    drop((context, response));
                } else {
                    let _ignored = response.send(Ok(context));
                }
            }
            ForgeControlRequest::OwnedExecutionStopApply { context, response } => {
                apply_count.fetch_add(1, Ordering::Relaxed);
                let _ignored =
                    response.send(ForgeControl::apply_owned_execution_stop_context(&context));
            }
            ForgeControlRequest::OwnedExecutionStopObserve { context, response } => {
                readback_count.fetch_add(1, Ordering::Relaxed);
                let _ignored =
                    response.send(ForgeControl::observe_owned_execution_stop_context(&context));
            }
            _ => return Err("unexpected control request".to_owned()),
        }
    }
    Ok(())
}

fn create_owned_stop_fifo(workspace: &WaitWorkspace) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let fifo = workspace.workspace_root.join("owned-stop-input.fifo");
    if !std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()?
        .success()
    {
        return Err("FIFO creation failed".into());
    }
    Ok(fifo)
}

fn spawn_owned_stop_producer(
    fifo: &std::path::Path,
) -> Result<std::process::Child, Box<dyn Error>> {
    Ok(std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("exec 3>\"$1\"; printf stop-started >&3; exec /bin/sleep 30")
        .arg("owned-stop-producer")
        .arg(fifo)
        .spawn()?)
}

fn queue_owned_stop_retry(
    client: &ForgeExecutionCoordinatorClient,
    permit: crate::approval_cleanup::ApprovalCleanupPermit,
    owner: ApprovalCleanupOwner,
    request: ExecutionStopRequest,
    fresh: ExecutionCoordinatorStartRequest,
) -> Result<OwnedWorkspaceExecutionStopObservation, Box<dyn Error>> {
    let (lost_tx, lost_rx) = mpsc::sync_channel(1);
    client
        .sender
        .send(CoordinatorRequest::StopOwnedWorkspaceDurable {
            permit: Box::new(permit.clone()),
            owner,
            request: Box::new(request),
            response: lost_tx,
        })?;
    drop(lost_rx);
    let (retry_tx, retry_rx) = mpsc::sync_channel(1);
    client
        .sender
        .send(CoordinatorRequest::StopOwnedWorkspaceDurable {
            permit: Box::new(permit),
            owner,
            request: Box::new(request),
            response: retry_tx,
        })?;
    let (fresh_tx, fresh_rx) = mpsc::sync_channel(1);
    client.sender.send(CoordinatorRequest::Start {
        request: Box::new(fresh),
        response: fresh_tx,
    })?;
    let observation = retry_rx.recv()??;
    assert!(fresh_rx.recv()?.is_err());
    Ok(observation)
}

fn serve_owned_apply_response_loss(
    requests: &std::sync::mpsc::Receiver<ForgeControlRequest>,
    apply_count: &AtomicU64,
    readback_count: &AtomicU64,
) -> Result<(), String> {
    while let Ok(request) = requests.recv() {
        match request {
            ForgeControlRequest::OwnedExecutionStopHistory {
                permit,
                owner,
                request,
                response,
            } => {
                let _ignored = response.send(ForgeControl::observe_owned_stop_history(
                    &permit, owner, request,
                ));
            }
            ForgeControlRequest::OwnedExecutionStopSettle {
                settlement,
                response,
            } => {
                let _ignored = response.send(ForgeControl::settle_owned_execution_stop_context(
                    &settlement,
                ));
            }
            ForgeControlRequest::OwnedExecutionStopPrepare {
                permit,
                owner,
                request,
                response,
            } => {
                let _ignored = response.send(ForgeControl::prepare_owned_execution_stop_context(
                    &permit, owner, request,
                ));
            }
            ForgeControlRequest::OwnedExecutionStopApply { context, response } => {
                apply_count.fetch_add(1, Ordering::Relaxed);
                let _capture = ForgeControl::apply_owned_execution_stop_context(&context)
                    .map_err(|error| format!("actual owned capture failed: {error:?}"))?;
                drop(response);
            }
            ForgeControlRequest::OwnedExecutionStopObserve { context, response } => {
                let readback = ForgeControl::observe_owned_execution_stop_context(&context)
                    .map_err(|error| format!("actual owned readback failed: {error:?}"))?;
                if readback_count.fetch_add(1, Ordering::Relaxed) == 0 {
                    if readback.is_none() {
                        return Err("actual owned readback did not contain capture".to_owned());
                    }
                    drop(response);
                } else {
                    let _ignored = response.send(Ok(readback));
                }
            }
            _ => return Err("unexpected control request".to_owned()),
        }
    }
    Ok(())
}

#[test]
fn owned_workspace_stop_apply_response_loss_reads_back_before_retry() -> Result<(), Box<dyn Error>>
{
    let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
    let owner = ApprovalCleanupOwner::new();
    let permit = owned_permit(&control, &scope, owner)?;
    let (client, requests) = ForgeControlClient::journal_test_channel(8);
    let applies = Arc::new(AtomicU64::new(0));
    let apply_count = Arc::clone(&applies);
    let readbacks = Arc::new(AtomicU64::new(0));
    let readback_count = Arc::clone(&readbacks);
    let service = thread::spawn(move || {
        serve_owned_apply_response_loss(&requests, &apply_count, &readback_count)
    });
    let (mut runtime, _native_client) = runtime_and_client_with_control(client)?;
    let request = owned_stop_request(&scope, 0x8100, 20)?;
    let first = runtime.stop_owned_workspace_durable(permit.clone(), owner, request);
    let retry = runtime.stop_owned_workspace_durable(permit.clone(), owner, request);
    let replayed = runtime.stop_owned_workspace_durable(permit, owner, request);
    let shutdown = runtime.teardown();
    drop(runtime);
    service
        .join()
        .map_err(|_| "owned capture service panicked")?
        .map_err(std::io::Error::other)?;
    fs::remove_dir_all(root)?;

    assert!(matches!(
        first,
        Err(ForgeExecutionCoordinatorError::WorkspaceStopCaptureAndExecution {
            capture,
            native: None,
            native_cancel_requested: Some(0),
            ..
        }) if matches!(capture.as_ref(), ControlClientError::ResponseDropped)
    ));
    assert!(matches!(
        retry,
        Err(ForgeExecutionCoordinatorError::WorkspaceStopCaptureAndExecution {
            capture,
            native: None,
            native_cancel_requested: Some(0),
            ..
        }) if matches!(capture.as_ref(), ControlClientError::ResponseDropped)
    ));
    let receipt = replayed?;
    assert_eq!(receipt.record().stop_id(), request.stop_id());
    assert_eq!(receipt.record().status(), ExecutionStopStatus::Completed);
    assert_eq!(receipt.record().target_count(), 0);
    assert_eq!(
        receipt
            .native_quiescence()
            .map_err(ToString::to_string)?
            .ok_or("empty native owner not observed")?
            .workspace_id(),
        request.workspace_id()
    );
    assert_eq!(receipt.record().created_at(), request.observed_at());
    assert_eq!(receipt.authority().stop_id(), request.stop_id());
    assert_eq!(receipt.authority().observed_at(), request.observed_at());
    assert_eq!(applies.load(Ordering::Relaxed), 1);
    assert_eq!(readbacks.load(Ordering::Relaxed), 3);
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn owned_workspace_stop_observe_response_loss_retries_without_apply() -> Result<(), Box<dyn Error>>
{
    let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
    let owner = ApprovalCleanupOwner::new();
    let permit = owned_permit(&control, &scope, owner)?;
    let (client, requests) = ForgeControlClient::journal_test_channel(8);
    let applies = Arc::new(AtomicU64::new(0));
    let apply_count = Arc::clone(&applies);
    let readbacks = Arc::new(AtomicU64::new(0));
    let readback_count = Arc::clone(&readbacks);
    let service = thread::spawn(move || -> Result<(), String> {
        while let Ok(request) = requests.recv() {
            match request {
                ForgeControlRequest::OwnedExecutionStopHistory {
                    permit,
                    owner,
                    request,
                    response,
                } => {
                    let _ignored = response.send(ForgeControl::observe_owned_stop_history(
                        &permit, owner, request,
                    ));
                }
                ForgeControlRequest::OwnedExecutionStopSettle {
                    settlement,
                    response,
                } => {
                    let _ignored = response.send(
                        ForgeControl::settle_owned_execution_stop_context(&settlement),
                    );
                }
                ForgeControlRequest::OwnedExecutionStopPrepare {
                    permit,
                    owner,
                    request,
                    response,
                } => {
                    let _ignored = response.send(
                        ForgeControl::prepare_owned_execution_stop_context(&permit, owner, request),
                    );
                }
                ForgeControlRequest::OwnedExecutionStopApply { context, response } => {
                    apply_count.fetch_add(1, Ordering::Relaxed);
                    let _ignored =
                        response.send(ForgeControl::apply_owned_execution_stop_context(&context));
                }
                ForgeControlRequest::OwnedExecutionStopObserve { context, response } => {
                    let readback = ForgeControl::observe_owned_execution_stop_context(&context)
                        .map_err(|error| format!("actual owned readback failed: {error:?}"))?;
                    if readback_count.fetch_add(1, Ordering::Relaxed) == 0 {
                        if readback.is_none() {
                            return Err("actual owned readback did not contain capture".to_owned());
                        }
                        drop(response);
                    } else {
                        let _ignored = response.send(Ok(readback));
                    }
                }
                _ => return Err("unexpected control request".to_owned()),
            }
        }
        Ok(())
    });
    let (mut runtime, _native_client) = runtime_and_client_with_control(client)?;
    let request = owned_stop_request(&scope, 0x8200, 21)?;
    let first = runtime.stop_owned_workspace_durable(permit.clone(), owner, request);
    let retry = runtime.stop_owned_workspace_durable(permit, owner, request);
    let shutdown = runtime.teardown();
    drop(runtime);
    service
        .join()
        .map_err(|_| "owned capture service panicked")?
        .map_err(std::io::Error::other)?;
    fs::remove_dir_all(root)?;

    assert!(matches!(
        first,
        Err(ForgeExecutionCoordinatorError::WorkspaceStopCaptureAndExecution {
            capture,
            native: None,
            native_cancel_requested: Some(0),
            ..
        }) if matches!(capture.as_ref(), ControlClientError::ResponseDropped)
    ));
    let receipt = retry?;
    assert_eq!(receipt.record().stop_id(), request.stop_id());
    assert_eq!(receipt.record().created_at(), request.observed_at());
    assert_eq!(receipt.authority().observed_at(), request.observed_at());
    assert_eq!(applies.load(Ordering::Relaxed), 1);
    assert_eq!(readbacks.load(Ordering::Relaxed), 3);
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn owned_settlement_reply_loss_reads_completed_before_retry_without_recancel()
-> Result<(), Box<dyn Error>> {
    let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
    let owner = ApprovalCleanupOwner::new();
    let permit = owned_permit(&control, &scope, owner)?;
    let (client, requests) = ForgeControlClient::journal_test_channel(8);
    let service = thread::spawn(move || -> Result<(), String> {
        while let Ok(request) = requests.recv() {
            match request {
                ForgeControlRequest::OwnedExecutionStopHistory {
                    permit,
                    owner,
                    request,
                    response,
                } => {
                    let _sent = response.send(ForgeControl::observe_owned_stop_history(
                        &permit, owner, request,
                    ));
                }
                ForgeControlRequest::OwnedExecutionStopPrepare {
                    permit,
                    owner,
                    request,
                    response,
                } => {
                    let _sent = response.send(ForgeControl::prepare_owned_execution_stop_context(
                        &permit, owner, request,
                    ));
                }
                ForgeControlRequest::OwnedExecutionStopApply { context, response } => {
                    let _sent =
                        response.send(ForgeControl::apply_owned_execution_stop_context(&context));
                }
                ForgeControlRequest::OwnedExecutionStopObserve { context, response } => {
                    let _sent =
                        response.send(ForgeControl::observe_owned_execution_stop_context(&context));
                }
                ForgeControlRequest::OwnedExecutionStopSettle {
                    settlement,
                    response,
                } => {
                    let _committed = ForgeControl::settle_owned_execution_stop_context(&settlement)
                        .map_err(|error| error.to_string())?;
                    drop(response);
                }
                _ => return Err("unexpected settlement request".to_owned()),
            }
        }
        Ok(())
    });
    let (mut runtime, _coordinator_client) = runtime_and_client_with_control(client)?;
    let request = owned_stop_request(&scope, 0x8240, 20)?;
    let first = runtime.stop_owned_workspace_durable(permit.clone(), owner, request);
    assert!(
        matches!(first, Err(ForgeExecutionCoordinatorError::WorkspaceStopSettlementAndExecution {settlement,..})
        if matches!(*settlement, ControlClientError::ResponseDropped))
    );
    assert!(
        runtime
            .owned_workspace_stops
            .contains_key(&scope.workspace_id())
    );
    let retry = runtime.stop_owned_workspace_durable(permit, owner, request)?;
    assert_eq!(retry.record().status(), ExecutionStopStatus::Completed);
    assert!(retry.native_result().is_none());
    assert!(
        !runtime
            .owned_workspace_stops
            .contains_key(&scope.workspace_id())
    );
    let shutdown = runtime.teardown();
    drop(runtime);
    service
        .join()
        .map_err(|_| "settlement service panicked")?
        .map_err(std::io::Error::other)?;
    fs::remove_dir_all(root)?;
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn owned_workspace_stop_prepare_response_loss_retains_identity_before_apply()
-> Result<(), Box<dyn Error>> {
    let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
    let owner = ApprovalCleanupOwner::new();
    let permit = owned_permit(&control, &scope, owner)?;
    let (client, requests) = ForgeControlClient::journal_test_channel(8);
    let prepares = Arc::new(AtomicU64::new(0));
    let prepare_count = Arc::clone(&prepares);
    let applies = Arc::new(AtomicU64::new(0));
    let apply_count = Arc::clone(&applies);
    let readbacks = Arc::new(AtomicU64::new(0));
    let readback_count = Arc::clone(&readbacks);
    let prepare_timestamps = Arc::new(std::sync::Mutex::new(Vec::<i64>::new()));
    let timestamp_log = Arc::clone(&prepare_timestamps);
    let service = thread::spawn(move || {
        serve_owned_prepare_response_loss(
            &requests,
            &prepare_count,
            &apply_count,
            &readback_count,
            &timestamp_log,
        )
    });
    let (mut runtime, _native_client) = runtime_and_client_with_control(client)?;
    let original = owned_stop_request(&scope, 0x8230, 20)?;
    let first = runtime.stop_owned_workspace_durable(permit.clone(), owner, original);
    assert!(matches!(
        first,
        Err(ForgeExecutionCoordinatorError::Control(
            ControlClientError::ResponseDropped
        ))
    ));

    // A changed stop identity must be rejected from the retained envelope;
    // it must not trigger another read-only Prepare request.
    let changed = ExecutionStopRequest::new(
        id(0x8231),
        original.workspace_id(),
        original.request_id(),
        original.owner_runtime_instance_id(),
        *original.request_digest(),
        timestamp(99)?,
    );
    let changed_result = runtime.stop_owned_workspace_durable(permit.clone(), owner, changed);
    assert!(matches!(
        changed_result,
        Err(ForgeExecutionCoordinatorError::AttributionMismatch)
    ));
    assert_eq!(prepares.load(Ordering::Relaxed), 1);

    // The same retry identity may rebase its observation clock, but the
    // retained pre-Prepare request remains authoritative for the write.
    let rebased = ExecutionStopRequest::new(
        original.stop_id(),
        original.workspace_id(),
        original.request_id(),
        original.owner_runtime_instance_id(),
        *original.request_digest(),
        timestamp(99)?,
    );
    let receipt = runtime.stop_owned_workspace_durable(permit, owner, rebased)?;
    let shutdown = runtime.teardown();
    drop(runtime);
    service
        .join()
        .map_err(|_| "owned prepare service panicked")?
        .map_err(std::io::Error::other)?;
    fs::remove_dir_all(root)?;

    assert_eq!(receipt.record().created_at(), original.observed_at());
    assert_eq!(receipt.authority().observed_at(), original.observed_at());
    assert_eq!(prepares.load(Ordering::Relaxed), 2);
    assert_eq!(applies.load(Ordering::Relaxed), 1);
    assert_eq!(readbacks.load(Ordering::Relaxed), 2);
    assert_eq!(
        *prepare_timestamps
            .lock()
            .map_err(|_| "prepare timestamp mutex poisoned")?,
        vec![original.observed_at().get(), original.observed_at().get()]
    );
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn fresh_native_quiescence_does_not_settle_an_interrupted_durable_target()
-> Result<(), Box<dyn Error>> {
    let fixture = WaitFixture::new()?;
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace.workspace_root)?
        .ok_or("state missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let _interrupted = store.reconcile_interrupted_executions(
        timestamp(1_000_000)?,
        forge_domain::ExecutionListLimit::DEFAULT,
    )?;
    assert_eq!(
        store
            .get_execution(fixture.execution_id)?
            .ok_or("execution missing")?
            .state(),
        ExecutionState::Interrupted
    );
    drop(store);
    let owner = ApprovalCleanupOwner::new();
    let permit = fixture.workspace.client.mint_approval_cleanup_permit(
        owner,
        fixture.workspace.scope.clone(),
        ApprovalCleanupSelector::Workspace,
    )?;
    let request = owned_stop_request(&fixture.workspace.scope, 0x8290, 1_000_001)?;
    let mut runtime = runtime_for(&fixture)?;
    let observation = runtime.stop_owned_workspace_durable(permit, owner, request)?;
    assert_eq!(
        observation
            .native_result()
            .ok_or("native stop not attempted")?
            .map_err(ToString::to_string)?,
        0
    );
    assert!(
        observation
            .native_quiescence()
            .map_err(ToString::to_string)?
            .is_some()
    );
    assert_eq!(observation.record().status(), ExecutionStopStatus::Pending);
    assert_eq!(observation.record().target_count(), 1);
    assert_eq!(
        observation.record().targets()[0].expected_state(),
        ExecutionState::Interrupted
    );
    assert_eq!(
        observation.record().targets()[0].status(),
        forge_persistence::ExecutionStopTargetStatus::Pending
    );
    let store = WorkspaceStore::open_existing(&layout)?;
    assert_eq!(
        store
            .execution_native_closure_snapshot(fixture.execution_id)?
            .ok_or("snapshot missing")?
            .closure(),
        None
    );
    drop(store);
    stop_runtime(&mut runtime)?;
    fixture.finish()?;
    Ok(())
}

#[test]
fn owned_workspace_stop_rejects_legacy_execution_only_retention_without_upgrade()
-> Result<(), Box<dyn Error>> {
    let serial = NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let mut workspace = WaitWorkspace::new(serial)?;
    let request = stop_request(&workspace.scope, 0x8250 + u128::from(serial) * 4)?;
    let (mut runtime, _coordinator_client) =
        runtime_and_client_with_control(workspace.client.clone())?;
    let legacy = runtime.stop_workspace_durable(workspace.scope.clone(), request)?;
    assert_eq!(legacy.record().status(), ExecutionStopStatus::Pending);
    assert_eq!(legacy.record().target_count(), 0);

    let owner = ApprovalCleanupOwner::new();
    let permit = workspace.client.mint_approval_cleanup_permit(
        owner,
        workspace.scope.clone(),
        ApprovalCleanupSelector::Workspace,
    )?;
    let rejected = runtime.stop_owned_workspace_durable(permit, owner, request);
    assert!(matches!(
        rejected,
        Err(ForgeExecutionCoordinatorError::AttributionMismatch)
    ));

    let layout = WorkspaceStateLayout::inspect_existing(&workspace.workspace_root)?
        .ok_or("Workspace state disappeared")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    assert!(matches!(
        store.owned_workspace_stop_for_request(&request),
        Err(forge_persistence::WorkspaceStoreError::Approval(
            forge_persistence::ApprovalStoreError::CleanupPlanMismatch
        ))
    ));
    drop(store);
    let shutdown = runtime.teardown();
    workspace.worker.shutdown()?;
    fs::remove_dir_all(workspace.root)?;
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn owned_workspace_stop_queue_cancels_actual_fifo_and_replays_original_receipt()
-> Result<(), Box<dyn Error>> {
    let serial = NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let mut workspace = WaitWorkspace::new(serial)?;
    let activity_id = ActivityId::from_uuid(id(0x8300 + u128::from(serial)));
    let owner_id = RuntimeInstanceId::from_uuid(id(0x8400 + u128::from(serial)));
    let _activity = workspace.client.bootstrap_activity(
        workspace.scope.clone(),
        activity_id,
        owner_id,
        timestamp(3)?,
        timestamp(60_003)?,
    )?;
    let fifo = create_owned_stop_fifo(&workspace)?;
    let first_id = ExecutionId::from_uuid(id(0x8500 + u128::from(serial) * 4));
    let fresh_id = ExecutionId::from_uuid(id(first_id.into_uuid().as_u128() + 2));
    let first = approved_start(&workspace, activity_id, owner_id, first_id, &fifo)?;
    let fresh = approved_start(&workspace, activity_id, owner_id, fresh_id, &fifo)?;
    let owner = ApprovalCleanupOwner::new();
    let permit = workspace.client.mint_approval_cleanup_permit(
        owner,
        workspace.scope.clone(),
        ApprovalCleanupSelector::Workspace,
    )?;
    let request = stop_request(&workspace.scope, 0x8600 + u128::from(serial) * 4)?;
    let (runtime, client) = runtime_and_client_with_control(workspace.client.clone())?;
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    client.sender.send(CoordinatorRequest::Start {
        request: Box::new(first),
        response: started_tx,
    })?;
    let thread = thread::spawn(move || runtime.run());
    let mut producer = None;
    let flow = (|| -> Result<OwnedWorkspaceExecutionStopObservation, Box<dyn Error>> {
        let started = started_rx.recv()??;
        assert_eq!(started.disposition(), ExecutionStartDisposition::Created);
        producer = Some(spawn_owned_stop_producer(&fifo)?);
        wait_for_started_marker(&workspace, first_id)?;
        queue_owned_stop_retry(&client, permit, owner, request, fresh)
    })();
    let record_before_shutdown = workspace
        .client
        .execution_get(workspace.scope.clone(), first_id);
    client.sender.send(CoordinatorRequest::Shutdown)?;
    let shutdown = thread.join().map_err(|_| "owned stop owner panicked")?;
    join_fixture_producer(producer)?;
    let first_record = workspace
        .client
        .execution_get(workspace.scope.clone(), first_id)?;
    let fresh_record = workspace
        .client
        .execution_get(workspace.scope.clone(), fresh_id)?;
    workspace.worker.shutdown()?;
    fs::remove_dir_all(workspace.root)?;
    let observation = flow?;
    assert_eq!(observation.record().stop_id(), request.stop_id());
    assert_eq!(
        observation.record().status(),
        ExecutionStopStatus::Completed,
        "retry evidence: {observation:?}; execution before shutdown: {record_before_shutdown:?}"
    );
    assert_eq!(observation.authority().stop_id(), request.stop_id());
    assert!(observation.authority().target_count() > 0);
    assert!(
        observation.native_result().is_none(),
        "completed replay must not repeat native cancellation"
    );
    assert!(
        observation
            .native_quiescence()
            .map_err(ToString::to_string)?
            .is_none()
    );
    assert_eq!(
        first_record.ok_or("first execution missing")?.state(),
        ExecutionState::Cancelled
    );
    assert!(fresh_record.is_none());
    let _shutdown = shutdown?;
    Ok(())
}
