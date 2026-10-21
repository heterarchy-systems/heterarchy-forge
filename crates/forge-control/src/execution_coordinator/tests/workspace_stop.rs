//! Actual queue, SQLite and native process evidence for pending stop capture.

use super::super::{ApprovalActivityScope, RequestedExecutionPermissions};
use super::*;
use crate::{ControlClientError, ExecutionStartDisposition, ExecutionStartResult};
use forge_domain::ApprovalRequestId;
use forge_execution::execution_request_digest;
use forge_persistence::{ExecutionStopRequest, ExecutionStopStatus};

pub(super) fn stop_request(
    scope: &ResolvedWorkspaceScope,
    seed: u128,
) -> Result<ExecutionStopRequest, Box<dyn Error>> {
    Ok(ExecutionStopRequest::new(
        id(seed),
        scope.workspace_id(),
        id(seed + 1),
        RuntimeInstanceId::from_uuid(id(seed + 2)),
        [0x71; 32],
        timestamp(20)?,
    ))
}

pub(super) fn approved_start(
    workspace: &WaitWorkspace,
    activity_id: ActivityId,
    owner: RuntimeInstanceId,
    execution_id: ExecutionId,
    fifo: &Path,
) -> Result<ExecutionCoordinatorStartRequest, Box<dyn Error>> {
    let request = ExecutionRequest::new(
        ExecutionAttribution::new(execution_id, workspace.scope.workspace_id(), activity_id),
        ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from("/bin/cat"))?,
            arguments: vec![ExecutionArgument::new(fifo.as_os_str().to_os_string())?],
        },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(30_000)?,
            ExecutionOutputLimit::new(8192)?,
        ),
        ExecutionPermissions::new(true, false, false),
    )?;
    let authorization = ExecutionAuthorizationRequest::new(
        execution_id,
        workspace.scope.workspace_id(),
        activity_id,
        execution_request_digest(&request),
        ExecutionActionClass::DirectStructured,
        RequestedExecutionPermissions::new(request.permissions()),
    );
    let approval_id = ApprovalRequestId::from_uuid(execution_id.into_uuid());
    let observed_at = super::super::current_timestamp_millis()?;
    let expires_at = timestamp(observed_at.get() + 60_000)?;
    let pending = workspace
        .client
        .create_pending_approval(crate::ApprovalCreateRequest {
            scope: workspace.scope.clone(),
            activity: ApprovalActivityScope {
                activity_id,
                runtime_instance_id: owner,
                observed_at,
            },
            goal: None,
            approval_id,
            request: authorization,
            agent_binding: None,
            expires_at,
        })?;
    let (_approval, grant) = workspace.client.approve_once(crate::ApprovalOnceRequest {
        scope: workspace.scope.clone(),
        approval_id,
        expected_revision: pending.revision(),
        grant_id: ExecutionGrantId::from_uuid(id(execution_id.into_uuid().as_u128() + 1)),
        observed_at,
        // Each queued request rebases its clock; the grant window must remain
        // strictly inside the earlier approval window.
        grant_expires_at: timestamp(observed_at.get() + 30_000)?,
    })?;
    Ok(ExecutionCoordinatorStartRequest::new_explicit(
        workspace.scope.clone(),
        activity_id,
        owner,
        grant.id(),
        grant.revision(),
        authorization,
        request,
    ))
}

struct QueueStopFlow {
    started: ExecutionStartResult,
    retried: super::super::WorkspaceExecutionStopObservation,
    denied: Result<ExecutionStartResult, ForgeExecutionCoordinatorError>,
}

pub(super) fn wait_for_started_marker(
    workspace: &WaitWorkspace,
    execution_id: ExecutionId,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let output = workspace.client.execution_output_read(
            workspace.scope.clone(),
            ExecutionOutputCursor::initial(execution_id),
            8192,
            16,
        )?;
        let bytes = output
            .events()
            .iter()
            .filter_map(|event| match event {
                ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
                ExecutionOutputEvent::Gap(_) => None,
            })
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        if bytes
            .windows(b"stop-started".len())
            .any(|part| part == b"stop-started")
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("actual native child did not journal its started marker".into());
        }
        thread::yield_now();
    }
}

pub(super) fn join_fixture_producer(
    producer: Option<std::process::Child>,
) -> Result<(), Box<dyn Error>> {
    if let Some(mut producer) = producer {
        if producer.try_wait()?.is_none() {
            producer.kill()?;
        }
        let _status = producer.wait()?;
    }
    Ok(())
}

#[test]
fn durable_workspace_stop_queue_orders_actual_start_reply_loss_and_fresh_start_fence()
-> Result<(), Box<dyn Error>> {
    let serial = NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let mut workspace = WaitWorkspace::new(serial)?;
    let activity_id = ActivityId::from_uuid(id(0x7100 + u128::from(serial)));
    let owner_id = RuntimeInstanceId::from_uuid(id(0x7200 + u128::from(serial)));
    let _activity = workspace.client.bootstrap_activity(
        workspace.scope.clone(),
        activity_id,
        owner_id,
        timestamp(3)?,
        timestamp(60_003)?,
    )?;
    let fifo = workspace.workspace_root.join("stop-input.fifo");
    if !std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()?
        .success()
    {
        return Err("FIFO creation failed".into());
    }
    let first_id = ExecutionId::from_uuid(id(0x7300 + u128::from(serial) * 4));
    let fresh_id = ExecutionId::from_uuid(id(first_id.into_uuid().as_u128() + 2));
    let first = approved_start(&workspace, activity_id, owner_id, first_id, &fifo)?;
    let fresh = approved_start(&workspace, activity_id, owner_id, fresh_id, &fifo)?;
    let (runtime, client) = runtime_and_client_with_control(workspace.client.clone())?;
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    client.sender.send(CoordinatorRequest::Start {
        request: Box::new(first),
        response: started_tx,
    })?;
    let request = stop_request(&workspace.scope, 0x7400 + u128::from(serial) * 4)?;
    let thread = thread::spawn(move || runtime.run());
    let mut producer = None;
    let flow = (|| -> Result<QueueStopFlow, Box<dyn Error>> {
        let started = started_rx.recv()??;
        // One owned fixture process holds the FIFO open after emitting a marker.
        // It execs sleep in the same PID, so kill/wait below joins the whole owner.
        producer = Some(
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("exec 3>\"$1\"; printf stop-started >&3; exec /bin/sleep 30")
                .arg("stop-producer")
                .arg(&fifo)
                .spawn()?,
        );
        wait_for_started_marker(&workspace, first_id)?;
        let (lost_tx, lost_rx) = mpsc::sync_channel(1);
        let (retry_tx, retry_rx) = mpsc::sync_channel(1);
        let (fresh_tx, fresh_rx) = mpsc::sync_channel(1);
        client
            .sender
            .send(CoordinatorRequest::StopWorkspaceDurable {
                scope: workspace.scope.clone(),
                request: Box::new(request),
                response: lost_tx,
            })?;
        drop(lost_rx);
        client
            .sender
            .send(CoordinatorRequest::StopWorkspaceDurable {
                scope: workspace.scope.clone(),
                request: Box::new(request),
                response: retry_tx,
            })?;
        client.sender.send(CoordinatorRequest::Start {
            request: Box::new(fresh),
            response: fresh_tx,
        })?;
        Ok(QueueStopFlow {
            started,
            retried: retry_rx.recv()??,
            denied: fresh_rx.recv()?,
        })
    })();
    client.sender.send(CoordinatorRequest::Shutdown)?;
    let shutdown = thread.join().map_err(|_| "stop owner panicked")?;
    join_fixture_producer(producer)?;
    let first_record = workspace
        .client
        .execution_get(workspace.scope.clone(), first_id)?;
    let fresh_record = workspace
        .client
        .execution_get(workspace.scope.clone(), fresh_id)?;
    workspace.worker.shutdown()?;
    fs::remove_dir_all(workspace.root)?;
    // Process/control owners are joined before any result assertion or flow error.
    let flow = flow?;
    assert_eq!(
        flow.started.disposition(),
        ExecutionStartDisposition::Created
    );
    assert_eq!(flow.retried.record().stop_id(), request.stop_id());
    assert_eq!(flow.retried.record().status(), ExecutionStopStatus::Pending);
    assert_eq!(flow.retried.record().targets().len(), 1);
    assert_eq!(flow.retried.record().targets()[0].execution_id(), first_id);
    assert!(flow.retried.native_result().is_ok());
    assert!(flow.denied.is_err());
    assert!(fresh_record.is_none());
    assert_eq!(
        first_record.ok_or("first execution missing")?.state(),
        ExecutionState::Cancelled
    );
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn durable_workspace_stop_observes_actual_apply_response_drop_before_retry()
-> Result<(), Box<dyn Error>> {
    let (root, control, scope) = crate::approval_expiry::tests::worker_fixture()?;
    let (client, requests) = ForgeControlClient::journal_test_channel(8);
    let applies = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&applies);
    let readback_count = Arc::new(AtomicU64::new(0));
    let queries = Arc::clone(&readback_count);
    let service = thread::spawn(move || -> Result<(), String> {
        while let Ok(request) = requests.recv() {
            match request {
                crate::worker::ForgeControlRequest::ExecutionStopPrepare {
                    scope,
                    request,
                    response,
                } => {
                    let _ignored =
                        response.send(control.prepare_execution_stop_context(&scope, request));
                }
                crate::worker::ForgeControlRequest::ExecutionStopApply { context, response } => {
                    counted.fetch_add(1, Ordering::Relaxed);
                    let _actual = control
                        .apply_execution_stop_context(&context)
                        .map_err(|error| format!("actual capture failed: {error:?}"))?;
                    drop(response);
                }
                crate::worker::ForgeControlRequest::ExecutionStopObserve { context, response } => {
                    let actual = ForgeControl::observe_execution_stop_context(&context);
                    if queries.fetch_add(1, Ordering::Relaxed) == 0 {
                        let _record = actual
                            .map_err(|error| format!("actual readback failed: {error:?}"))?
                            .ok_or("actual readback did not contain capture")?;
                        drop(response);
                    } else {
                        let _ignored = response.send(actual);
                    }
                }
                _ => return Err("unexpected control request".to_owned()),
            }
        }
        Ok(())
    });
    let (mut runtime, _native_client) = runtime_and_client_with_control(client)?;
    let request = stop_request(&scope, 0x7500)?;
    let first = runtime.stop_workspace_durable(scope.clone(), request);
    let retry = ExecutionStopRequest::new(
        request.stop_id(),
        request.workspace_id(),
        request.request_id(),
        request.owner_runtime_instance_id(),
        *request.request_digest(),
        timestamp(30)?,
    );
    let lost_observe = runtime.stop_workspace_durable(scope.clone(), retry);
    let observed = runtime.stop_workspace_durable(scope, retry);
    let shutdown = runtime.teardown();
    drop(runtime);
    service
        .join()
        .map_err(|_| "capture service panicked")?
        .map_err(std::io::Error::other)?;
    fs::remove_dir_all(root)?;
    assert!(
        matches!(first, Err(ForgeExecutionCoordinatorError::WorkspaceStopCaptureAndExecution { capture, .. }) if matches!(capture.as_ref(), ControlClientError::ResponseDropped))
    );
    let observed = observed?;
    assert!(
        matches!(lost_observe, Err(ForgeExecutionCoordinatorError::WorkspaceStopCaptureAndExecution { capture, .. }) if matches!(capture.as_ref(), ControlClientError::ResponseDropped))
    );
    assert_eq!(observed.record().stop_id(), request.stop_id());
    assert_eq!(observed.record().status(), ExecutionStopStatus::Pending);
    assert_eq!(observed.record().created_at(), request.observed_at());
    assert_eq!(readback_count.load(Ordering::Relaxed), 2);
    assert_eq!(
        applies.load(Ordering::Relaxed),
        1,
        "readback must precede any Apply retry"
    );
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn durable_workspace_stop_known_apply_error_keeps_native_result_and_observes_before_retry()
-> Result<(), Box<dyn Error>> {
    let (root, mut control, scope) = crate::approval_expiry::tests::worker_fixture()?;
    let (client, requests) = ForgeControlClient::journal_test_channel(8);
    let writes = Arc::new(AtomicU64::new(0));
    let calls = Arc::clone(&writes);
    let reads = Arc::new(AtomicU64::new(0));
    let inspected = Arc::clone(&reads);
    let service = thread::spawn(move || -> Result<(), String> {
        while let Ok(request) = requests.recv() {
            match request {
                crate::worker::ForgeControlRequest::ExecutionStopPrepare {
                    scope,
                    request,
                    response,
                } => {
                    let _ignored =
                        response.send(control.prepare_execution_stop_context(&scope, request));
                }
                crate::worker::ForgeControlRequest::ExecutionStopApply { context, response } => {
                    if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                        let _disabled = control
                            .set_location_state(&forge_domain::SetLocationState::new(
                                context.scope().locator().location_id(),
                                LocationRevision::INITIAL,
                                forge_domain::LocationState::Disabled,
                                TimestampMillis::new(25).map_err(|error| error.to_string())?,
                            ))
                            .map_err(|error| format!("actual disable failed: {error:?}"))?;
                    }
                    let _ignored = response.send(control.apply_execution_stop_context(&context));
                }
                crate::worker::ForgeControlRequest::ExecutionStopObserve { context, response } => {
                    inspected.fetch_add(1, Ordering::Relaxed);
                    let _ignored =
                        response.send(ForgeControl::observe_execution_stop_context(&context));
                }
                _ => return Err("unexpected control request".to_owned()),
            }
        }
        Ok(())
    });
    let (mut runtime, _native_client) = runtime_and_client_with_control(client)?;
    let request = stop_request(&scope, 0x7600)?;
    let first = runtime.stop_workspace_durable(scope.clone(), request);
    let retry = runtime.stop_workspace_durable(scope, request);
    let retained = runtime.workspace_stops.len();
    let shutdown = runtime.teardown();
    drop(runtime);
    service
        .join()
        .map_err(|_| "capture service panicked")?
        .map_err(std::io::Error::other)?;
    fs::remove_dir_all(root)?;
    for result in [first, retry] {
        assert!(
            matches!(result, Err(ForgeExecutionCoordinatorError::WorkspaceStopCaptureAndExecution {
            capture, native: None, native_cancel_requested: Some(0), ..
        }) if matches!(capture.as_ref(), ControlClientError::Service(error)
            if matches!(error.code(), crate::ControlErrorCode::LocationRevisionConflict | crate::ControlErrorCode::LocationUnavailable)))
        );
    }
    assert_eq!(writes.load(Ordering::Relaxed), 2);
    assert_eq!(
        reads.load(Ordering::Relaxed),
        1,
        "known error must observe before retry"
    );
    assert_eq!(retained, 1);
    let _shutdown = shutdown?;
    Ok(())
}

#[test]
fn durable_workspace_stop_retention_bound_rejects_before_prepare_without_eviction()
-> Result<(), Box<dyn Error>> {
    let serial = NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let initial = WaitWorkspace::new(serial)?;
    let (mut runtime, _client) = runtime_and_client_with_control(initial.client.clone())?;
    let mut fixtures = vec![initial];
    for index in 0..super::super::workspace_stop::MAX_RETAINED_WORKSPACE_STOPS {
        if index > 0 {
            let serial = NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            fixtures.push(WaitWorkspace::new(serial)?);
        }
        let fixture = &fixtures[index];
        runtime.control = fixture.client.clone();
        let request = stop_request(&fixture.scope, 0x7800 + u128::try_from(index)? * 4)?;
        let observed = runtime.stop_workspace_durable(fixture.scope.clone(), request)?;
        assert_eq!(observed.record().status(), ExecutionStopStatus::Pending);
    }
    let serial = NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let mut excluded = WaitWorkspace::new(serial)?;
    let request = stop_request(&excluded.scope, 0x7900)?;
    let approval_owner = crate::approval_cleanup::ApprovalCleanupOwner::new();
    let approval_permit = excluded.client.mint_approval_cleanup_permit(
        approval_owner,
        excluded.scope.clone(),
        crate::approval_cleanup::ApprovalCleanupSelector::Workspace,
    )?;
    let (probe, requests) = ForgeControlClient::journal_test_channel(1);
    runtime.control = probe;
    let result = runtime.stop_workspace_durable(excluded.scope.clone(), request);
    let owned_result =
        runtime.stop_owned_workspace_durable(approval_permit, approval_owner, request);
    let reached_prepare = requests.try_recv();
    let retained = runtime.workspace_stops.len();
    let shutdown = runtime.teardown();
    let layout = WorkspaceStateLayout::inspect_existing(&excluded.workspace_root)?
        .ok_or("layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let excluded_capture = store.execution_stop_for_request(&request)?;
    drop(store);
    for mut fixture in fixtures {
        fixture.worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
    }
    excluded.worker.shutdown()?;
    fs::remove_dir_all(excluded.root)?;
    assert!(matches!(
        result,
        Err(ForgeExecutionCoordinatorError::QueueFull)
    ));
    assert!(matches!(
        owned_result,
        Err(ForgeExecutionCoordinatorError::QueueFull)
    ));
    assert!(matches!(reached_prepare, Err(mpsc::TryRecvError::Empty)));
    assert_eq!(
        retained,
        super::super::workspace_stop::MAX_RETAINED_WORKSPACE_STOPS
    );
    assert!(excluded_capture.is_none());
    let _shutdown = shutdown?;
    Ok(())
}
