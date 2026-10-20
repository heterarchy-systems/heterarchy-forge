//! Actual native preflight rejection and durable original-envelope evidence.

use super::*;
use crate::execution_coordinator::current_timestamp_millis;
use crate::execution_journal::JournalTerminalCommand;
use crate::worker::ForgeControlRequest;
use forge_domain::{NativeClosureLaunch, NativeClosureProcess, NativeClosureRuntime};
use forge_persistence::ExecutionNativeClosureSnapshot;
use std::time::Duration;

fn native_root_rejection(
    runtime: &mut CoordinatorRuntime,
    fixture: &WaitFixture,
    other: &WaitWorkspace,
) -> Result<(SupervisorStartIdentity, ExecutionSupervisorError), Box<dyn Error>> {
    let (identity, _original_layout, request) =
        install_pending_start_fixture(runtime, fixture, ExecutionLaunchKind::Baseline)?;
    let other_layout = WorkspaceStateLayout::inspect_existing(&other.workspace_root)?
        .ok_or("foreign native layout missing")?;
    let error = runtime
        .supervisor
        .client()
        .start_execution_with_identity(
            identity,
            other_layout,
            request,
            ExecutionLaunchKind::Baseline,
            None,
            None,
        )
        .err()
        .ok_or("native root mismatch did not reject before runner preparation")?;
    Ok((identity, error))
}

fn closure_snapshot(
    fixture: &WaitFixture,
) -> Result<ExecutionNativeClosureSnapshot, Box<dyn Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace.workspace_root)?
        .ok_or("original layout missing")?;
    WorkspaceStore::open_existing(&layout)?
        .execution_native_closure_snapshot(fixture.execution_id)?
        .ok_or_else(|| "original terminal snapshot missing".into())
}

fn finish_other(mut workspace: WaitWorkspace) -> Result<(), Box<dyn Error>> {
    workspace.worker.shutdown()?;
    fs::remove_dir_all(workspace.root)?;
    Ok(())
}

fn assert_rejection_snapshot(
    snapshot: &ExecutionNativeClosureSnapshot,
    before_revision: ExecutionRevision,
) -> Result<(), Box<dyn Error>> {
    let fact = snapshot
        .closure()
        .ok_or("positive native rejection fact missing")?;
    assert_eq!(snapshot.record().state(), ExecutionState::Failed);
    assert_eq!(fact.before_revision(), before_revision);
    assert_eq!(fact.after_revision(), before_revision.checked_next()?);
    assert_eq!(fact.after_revision(), snapshot.record().revision());
    assert_eq!(
        fact.observed_at(),
        snapshot.record().timestamps().updated_at()
    );
    assert_eq!(fact.launch(), NativeClosureLaunch::Baseline);
    assert_eq!(fact.process(), NativeClosureProcess::NoChildSpawned);
    assert_eq!(fact.runtime(), NativeClosureRuntime::NotApplicable);
    assert_eq!(fact.output_cursor().after_sequence(), 0);
    assert!(snapshot.manifest().is_none());
    Ok(())
}

#[test]
fn native_pre_spawn_rejection_reads_back_fact_before_start_receipt_ack()
-> Result<(), Box<dyn Error>> {
    let fixture = WaitFixture::new()?;
    let other = WaitWorkspace::new(NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed))?;
    let (mut runtime, _client) = runtime_and_client(&fixture)?;
    let (identity, error) = native_root_rejection(&mut runtime, &fixture, &other)?;
    assert!(runtime.process_supervisor_start_result(Err(error)).is_err());
    let retained = runtime
        .launch_failure
        .as_ref()
        .ok_or("failure envelope missing")?;
    assert_eq!(retained.state, JournalWorkState::Readback);
    assert!(retained.closure.is_some());
    assert!(runtime.pending_start.is_some());
    assert!(
        runtime
            .supervisor
            .client()
            .observe_start(&identity)?
            .is_some()
    );
    let snapshot = closure_snapshot(&fixture)?;
    assert_rejection_snapshot(&snapshot, fixture.running_revision)?;
    runtime.progress_pending_start();
    assert!(runtime.launch_failure.is_none());
    assert!(runtime.pending_start.is_none());
    assert!(
        runtime
            .supervisor
            .client()
            .observe_start(&identity)?
            .is_none()
    );
    assert_eq!(closure_snapshot(&fixture)?.closure(), snapshot.closure());
    stop_runtime(&mut runtime)?;
    finish_other(other)?;
    fixture.finish()?;
    Ok(())
}

fn serve_lossy_rejection_journal(
    requests: mpsc::Receiver<ForgeControlRequest>,
) -> std::thread::JoinHandle<Result<(), String>> {
    std::thread::spawn(move || {
        let first = requests
            .recv_timeout(Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        let ForgeControlRequest::ExecutionJournalFail {
            authority,
            command,
            closure,
            response,
        } = first
        else {
            return Err("first operation was not rejection terminal write".to_owned());
        };
        let original_fact = closure.ok_or("missing original native rejection fact")?;
        let written = ForgeControl::execution_journal_fail(&authority, command, closure)
            .map_err(|e| format!("actual rejection terminal write: {e:?}"))?;
        if written.revision() != original_fact.after_revision()
            || written.timestamps().updated_at() != command.observed_at()
        {
            return Err("actual write changed original rejection revision or timestamp".to_owned());
        }
        drop(response);
        for drop_readback in [true, false] {
            let next = requests
                .recv_timeout(Duration::from_secs(10))
                .map_err(|e| e.to_string())?;
            let ForgeControlRequest::ExecutionJournalReconcileTerminal {
                authority,
                before,
                command: observed_command,
                closure,
                response,
            } = next
            else {
                return Err("retry did not observe original terminal before any write".to_owned());
            };
            if closure != Some(original_fact)
                || *observed_command != (JournalTerminalCommand::Fail { command })
            {
                return Err("rejection readback changed original command or fact".to_owned());
            }
            let readback = ForgeControl::execution_journal_reconcile_terminal(
                &authority,
                &before,
                &observed_command,
                closure,
            )
            .map_err(|e| format!("actual rejection snapshot readback: {e:?}"))?;
            if readback != JournalReadback::Confirmed {
                return Err("actual rejection readback was not Confirmed".to_owned());
            }
            if drop_readback {
                drop(response);
            } else {
                response
                    .send(Ok(readback))
                    .map_err(|_| "readback receiver closed")?;
            }
        }
        Ok(())
    })
}

#[test]
fn dropped_pre_spawn_rejection_write_and_readback_reuse_fact_then_ack() -> Result<(), Box<dyn Error>>
{
    let fixture = WaitFixture::new()?;
    let other = WaitWorkspace::new(NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed))?;
    let (mut runtime, _client) = runtime_and_client(&fixture)?;
    let (identity, error) = native_root_rejection(&mut runtime, &fixture, &other)?;
    let (control, requests) = ForgeControlClient::journal_test_channel(1);
    let handler = serve_lossy_rejection_journal(requests);
    runtime.control = control;
    assert!(runtime.process_supervisor_start_result(Err(error)).is_err());
    let fact = runtime
        .launch_failure
        .as_ref()
        .and_then(|p| p.closure)
        .ok_or("original rejection fact lost")?;
    runtime.progress_pending_start();
    assert!(runtime.pending_start.is_some());
    assert_eq!(
        runtime.launch_failure.as_ref().and_then(|p| p.closure),
        Some(fact)
    );
    assert!(
        runtime
            .supervisor
            .client()
            .observe_start(&identity)?
            .is_some()
    );
    runtime.progress_pending_start();
    assert!(runtime.pending_start.is_none());
    assert!(runtime.launch_failure.is_none());
    handler
        .join()
        .map_err(|_| "rejection handler panicked")?
        .map_err(std::io::Error::other)?;
    runtime.control = fixture.workspace.client.clone();
    let snapshot = closure_snapshot(&fixture)?;
    assert_rejection_snapshot(&snapshot, fixture.running_revision)?;
    assert_eq!(snapshot.closure(), Some(fact));
    stop_runtime(&mut runtime)?;
    finish_other(other)?;
    fixture.finish()?;
    Ok(())
}

#[test]
fn pre_spawn_rejection_ack_reply_loss_preserves_confirmed_fact() -> Result<(), Box<dyn Error>> {
    let fixture = WaitFixture::new()?;
    let other = WaitWorkspace::new(NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed))?;
    let (mut runtime, _client) = runtime_and_client(&fixture)?;
    let (identity, error) = native_root_rejection(&mut runtime, &fixture, &other)?;
    assert!(runtime.process_supervisor_start_result(Err(error)).is_err());
    assert!(runtime.flush_launch_failure());
    let original = closure_snapshot(&fixture)?;
    assert_rejection_snapshot(&original, fixture.running_revision)?;
    let pending = runtime
        .pending_start
        .as_mut()
        .ok_or("rejected owner missing")?;
    let PendingStartOutcome::Rejected {
        failure_code, ack, ..
    } = pending.outcome
    else {
        return Err("original rejected outcome missing".into());
    };
    // The actual complete snapshot was Confirmed above, and the real ACK is
    // executed below. Only its response is represented as dropped.
    pending.outcome = PendingStartOutcome::Rejected {
        failure_code,
        journal_confirmed: true,
        ack,
    };
    assert!(runtime.supervisor.client().acknowledge_start(&identity)?);
    runtime.process_pending_start_ack_result(&Err(ExecutionSupervisorError::ReplyDropped));
    assert!(runtime.pending_start.is_some());
    runtime.progress_pending_start();
    assert!(runtime.pending_start.is_none());
    assert!(runtime.launch_failure.is_none());
    assert_eq!(closure_snapshot(&fixture)?.closure(), original.closure());
    assert_eq!(runtime.terminal_records, 1);
    stop_runtime(&mut runtime)?;
    finish_other(other)?;
    fixture.finish()?;
    Ok(())
}

#[test]
fn closed_rejection_proof_query_keeps_running_and_original_pending_start()
-> Result<(), Box<dyn Error>> {
    let fixture = WaitFixture::new()?;
    let other = WaitWorkspace::new(NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed))?;
    let (mut runtime, _client) = runtime_and_client(&fixture)?;
    let (identity, error) = native_root_rejection(&mut runtime, &fixture, &other)?;
    let _shutdown = runtime.supervisor.shutdown()?;
    assert!(runtime.process_supervisor_start_result(Err(error)).is_err());
    assert!(runtime.launch_failure.is_none());
    assert_eq!(
        runtime.pending_start.as_ref().map(|p| p.native_identity),
        Some(identity)
    );
    let snapshot = closure_snapshot(&fixture)?;
    assert_eq!(snapshot.record().state(), ExecutionState::Running);
    assert!(snapshot.closure().is_none());
    assert_eq!(runtime.terminal_records, 0);
    // The already closed native owner cannot produce current closure authority.
    // Preserve and report the expected teardown failure; do not synthesize one.
    assert!(runtime.teardown().is_err());
    finish_other(other)?;
    fixture.finish()?;
    Ok(())
}

#[test]
fn captured_running_pre_spawn_rejection_settles_stop_with_actual_fact() -> Result<(), Box<dyn Error>>
{
    use crate::approval_cleanup::{ApprovalCleanupOwner, ApprovalCleanupSelector};
    use forge_persistence::{ExecutionStopRequest, ExecutionStopStatus, ExecutionStopTargetStatus};

    let fixture = WaitFixture::new()?;
    let other = WaitWorkspace::new(NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed))?;
    let (mut runtime, _client) = runtime_and_client(&fixture)?;
    let owner = ApprovalCleanupOwner::new();
    let permit = fixture.workspace.client.mint_approval_cleanup_permit(
        owner,
        fixture.workspace.scope.clone(),
        ApprovalCleanupSelector::Workspace,
    )?;
    let request = ExecutionStopRequest::new(
        id(0xAD601),
        fixture.workspace.scope.workspace_id(),
        id(0xAD602),
        RuntimeInstanceId::from_uuid(id(0xAD603)),
        [0xAD; 32],
        current_timestamp_millis()?,
    );
    let context = fixture
        .workspace
        .client
        .prepare_owned_execution_stop_context(permit.clone(), owner, request)?;
    let capture = fixture
        .workspace
        .client
        .apply_owned_execution_stop_context(context)?;
    assert_eq!(capture.execution().record().targets().len(), 1);
    assert_eq!(
        capture.execution().record().targets()[0].expected_state(),
        ExecutionState::Running
    );
    let (_identity, error) = native_root_rejection(&mut runtime, &fixture, &other)?;
    assert!(runtime.process_supervisor_start_result(Err(error)).is_err());
    runtime.progress_pending_start();
    assert!(runtime.pending_start.is_none());
    assert_rejection_snapshot(&closure_snapshot(&fixture)?, fixture.running_revision)?;
    let stopped = runtime.stop_owned_workspace_durable(permit, owner, request)?;
    assert_eq!(stopped.record().status(), ExecutionStopStatus::Completed);
    assert_eq!(
        stopped.record().targets()[0].status(),
        ExecutionStopTargetStatus::Closed
    );
    assert!(
        stopped
            .native_quiescence()
            .map_err(|error| format!("quiescence: {error}"))?
            .is_some()
    );
    stop_runtime(&mut runtime)?;
    finish_other(other)?;
    fixture.finish()?;
    Ok(())
}

#[test]
fn mismatched_rejection_provenance_latches_identity_failure_without_write_or_ack()
-> Result<(), Box<dyn Error>> {
    let fixture = WaitFixture::new()?;
    let other = WaitWorkspace::new(NEXT_WAIT_FIXTURE.fetch_add(1, Ordering::Relaxed))?;
    let (mut runtime, _client) = runtime_and_client(&fixture)?;
    let (identity, error) = native_root_rejection(&mut runtime, &fixture, &other)?;
    runtime
        .pending_start
        .as_mut()
        .ok_or("original pending owner missing")?
        .owner
        .native_identity = None;
    assert!(runtime.process_supervisor_start_result(Err(error)).is_err());
    assert!(runtime.journal_failed);
    let failure = runtime
        .first_journal_failure
        .ok_or("typed identity failure missing")?;
    assert_eq!(failure.stage, JournalFailureStage::StartIdentity);
    assert_eq!(
        failure.code,
        Some(crate::ControlErrorCode::ExecutionConflict)
    );
    assert!(runtime.launch_failure.is_none());
    assert!(runtime.pending_start.is_some());
    assert!(
        runtime
            .supervisor
            .client()
            .observe_start(&identity)?
            .is_some()
    );
    let snapshot = closure_snapshot(&fixture)?;
    assert_eq!(snapshot.record().state(), ExecutionState::Running);
    assert!(snapshot.closure().is_none());
    assert!(runtime.teardown().is_err());
    finish_other(other)?;
    fixture.finish()?;
    Ok(())
}
