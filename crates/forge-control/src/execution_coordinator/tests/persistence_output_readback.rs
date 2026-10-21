//! Actual SQLite busy/readback evidence for the execution output journal.
//!
//! The first output write is blocked by a real BEGIN IMMEDIATE transaction
//! on the Workspace database. The resulting non-committed persistence error
//! must leave the exact output group in readback, then an Absent readback
//! must retry the same event bytes once before the native output receipt is
//! acknowledged.

use super::*;
use crate::ControlErrorCode;
use crate::execution_journal::JournalReadback;
use crate::worker::ForgeControlRequest;
use forge_domain::{ExecutionOutputEvent, ExecutionOutputStream, ExecutionState};
use forge_persistence::WorkspaceStore;
use forge_workspace::ExistingWorkspaceStateLayout;
use rusqlite::{Connection, TransactionBehavior};
use std::error::Error as StdError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

const HANDLER_RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);
const OUTPUT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Default)]
struct OutputReadbackCounts {
    output_attempts: AtomicU64,
    failed_writes: AtomicU64,
    successful_writes: AtomicU64,
    readbacks: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BusyErrorObservation {
    code: ControlErrorCode,
    committed: bool,
    has_sqlite_failure: bool,
}

fn error_has_sqlite_failure(error: &forge_persistence::WorkspaceStoreError) -> bool {
    match error {
        forge_persistence::WorkspaceStoreError::Sqlite(error)
        | forge_persistence::WorkspaceStoreError::Execution(
            forge_persistence::ExecutionStoreError::Sqlite(error),
        ) => error.sqlite_extended_error_code() == Some(5),
        _ => false,
    }
}

fn recv_request(requests: &Receiver<ForgeControlRequest>) -> Result<ForgeControlRequest, String> {
    requests
        .recv_timeout(HANDLER_RECEIVE_TIMEOUT)
        .map_err(|error| format!("journal handler request timeout or closure: {error}"))
}

fn spawn_busy_output_journal_handler(
    requests: Receiver<ForgeControlRequest>,
    layout: ExistingWorkspaceStateLayout,
    counts: std::sync::Arc<OutputReadbackCounts>,
    busy_error_tx: SyncSender<BusyErrorObservation>,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || {
        let ForgeControlRequest::ExecutionJournalOutput {
            authority: _,
            events,
            response,
        } = recv_request(&requests)?
        else {
            return Err("first journal request was not output write".to_owned());
        };
        let first_events = events.clone();
        counts.output_attempts.fetch_add(1, Ordering::Relaxed);

        // Keep the checked mutable Store open before taking the external
        // SQLite lock. The direct append below is the same persistence
        // primitive used by the canonical journal path, so the busy result
        // comes from append, not from opening the Store.
        let mut store = WorkspaceStore::open_existing(&layout).map_err(|error| {
            format!("pre-opened Workspace Store failed before busy lock: {error:?}")
        })?;

        let write_result = {
            let mut blocker = Connection::open(layout.database_path())
                .map_err(|error| format!("could not open SQLite blocker: {error}"))?;
            let _transaction = blocker
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| format!("could not acquire SQLite IMMEDIATE lock: {error}"))?;
            store.append_execution_output_events(&events)
        };
        let has_sqlite_failure = write_result
            .as_ref()
            .err()
            .is_some_and(error_has_sqlite_failure);
        let error = write_result
            .map_err(crate::service::map_activity_store_error)
            .err()
            .ok_or_else(|| "busy output write unexpectedly succeeded".to_owned())?;
        let observation = BusyErrorObservation {
            code: error.code(),
            committed: error.is_committed(),
            has_sqlite_failure,
        };
        busy_error_tx
            .send(observation)
            .map_err(|error| format!("busy error observation receiver dropped: {error}"))?;
        counts.failed_writes.fetch_add(1, Ordering::Relaxed);
        response
            .send(Err(error))
            .map_err(|_| "runtime dropped first output response".to_owned())?;

        let ForgeControlRequest::ExecutionJournalReconcileOutput {
            authority,
            before,
            events,
            response,
        } = recv_request(&requests)?
        else {
            return Err("second journal request was not output readback".to_owned());
        };
        counts.readbacks.fetch_add(1, Ordering::Relaxed);
        if events != first_events {
            return Err("output readback changed the retained event bytes".to_owned());
        }
        let readback =
            ForgeControl::execution_journal_reconcile_output(&authority, &before, &events);
        if !matches!(readback, Ok(JournalReadback::Absent)) {
            return Err(format!(
                "expected actual Absent output readback, got {readback:?}"
            ));
        }
        response
            .send(readback)
            .map_err(|_| "runtime dropped output readback response".to_owned())?;

        let ForgeControlRequest::ExecutionJournalOutput {
            authority,
            events: retry_events,
            response,
        } = recv_request(&requests)?
        else {
            return Err("third journal request was not retry output write".to_owned());
        };
        if retry_events != first_events {
            return Err("output retry changed the retained event bytes".to_owned());
        }
        counts.output_attempts.fetch_add(1, Ordering::Relaxed);
        let result = ForgeControl::execution_journal_output(&authority, retry_events);
        if result.is_err() {
            return Err(format!("exact output retry failed: {result:?}"));
        }
        counts.successful_writes.fetch_add(1, Ordering::Relaxed);
        response
            .send(result)
            .map_err(|_| "runtime dropped successful output response".to_owned())?;
        Ok(())
    })
}

fn install_native_output(
    fixture: &WaitFixture,
    control: ForgeControlClient,
    setup: ScriptedOutputSetup,
) -> Result<(CoordinatorRuntime, bool), Box<dyn StdError>> {
    let ScriptedOutputSetup {
        authority,
        before,
        layout,
        request,
        identity,
    } = setup;
    let (mut runtime, _coordinator_client) = runtime_and_client_with_control(control)?;
    let native_identity =
        SupervisorStartIdentity::capture(&layout, &request, ExecutionLaunchKind::Baseline, None)?;
    runtime
        .supervisor
        .client()
        .start_execution(layout, request)?;
    let native_start_acknowledged = runtime
        .supervisor
        .client()
        .acknowledge_start(&native_identity)?;
    runtime.active.insert(
        fixture.execution_id,
        ActiveExecution {
            workspace_id: fixture.workspace.scope.workspace_id(),
            activity_id: fixture.authority.activity_id,
            running: before.clone(),
            identity,
            native_identity: Some(native_identity),
            journal: authority,
            terminal_journaled: false,
        },
    );
    Ok((runtime, native_start_acknowledged))
}

#[test]
fn sqlite_busy_output_write_reads_back_absent_then_retries_exact_events_and_acks_native()
-> Result<(), Box<dyn StdError>> {
    let fixture = WaitFixture::new_output()?;
    let setup = scripted_output_setup(&fixture)?;
    let before = setup.before.clone();
    let (control, requests) = ForgeControlClient::journal_test_channel(1);
    let counts = std::sync::Arc::new(OutputReadbackCounts::default());
    let (busy_error_tx, busy_error_rx) = mpsc::sync_channel(1);
    let journal_handler = spawn_busy_output_journal_handler(
        requests,
        setup.layout.clone(),
        std::sync::Arc::clone(&counts),
        busy_error_tx,
    );
    let (mut runtime, native_start_acknowledged) = install_native_output(&fixture, control, setup)?;

    let mut progress = JournalProgress::default();
    let first_deadline = Instant::now() + OUTPUT_PROGRESS_TIMEOUT;
    while counts.failed_writes.load(Ordering::Acquire) == 0 {
        runtime.poll_and_persist_output(&mut progress);
        if Instant::now() >= first_deadline {
            return Err("actual busy output write did not complete within its bound".into());
        }
        thread::yield_now();
    }
    let busy_error = busy_error_rx.recv_timeout(HANDLER_RECEIVE_TIMEOUT)?;
    let first_error_requires_readback = !runtime.journal_failed;
    let first_group_state = runtime
        .pending_output
        .as_ref()
        .and_then(|pending| pending.groups.first())
        .map(|group| group.state);

    runtime.poll_and_persist_output(&mut progress);
    let readback_count = counts.readbacks.load(Ordering::Acquire);
    let readback_group_state = runtime
        .pending_output
        .as_ref()
        .and_then(|pending| pending.groups.first())
        .map(|group| group.state);

    runtime.poll_and_persist_output(&mut progress);
    let successful_write_count = counts.successful_writes.load(Ordering::Acquire);
    let output_pending_after_ack = runtime.pending_output.is_none();
    let output_progressed = progress.contains(fixture.execution_id);
    let native_output_pending = runtime
        .supervisor
        .client()
        .has_pending_output(fixture.execution_id)?;
    let running_after_journal = runtime
        .active
        .get(&fixture.execution_id)
        .map(|active| active.running.clone());

    let (durable_record, output) = read_wait_fixture_store(&fixture)?;
    let all_stdout = output.events().iter().all(|event| match event {
        ExecutionOutputEvent::Chunk(chunk) => chunk.stream() == ExecutionOutputStream::Stdout,
        ExecutionOutputEvent::Gap(_) => false,
    });
    let durable_bytes = output
        .events()
        .iter()
        .filter_map(|event| match event {
            ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
            ExecutionOutputEvent::Gap(_) => None,
        })
        .flatten()
        .copied()
        .collect::<Vec<_>>();

    let runtime_cleanup = stop_runtime(&mut runtime);
    let handler_result = journal_handler
        .join()
        .map_err(|_| "busy output journal handler panicked")?;
    let fixture_cleanup = fixture.finish();
    runtime_cleanup?;
    handler_result.map_err(std::io::Error::other)?;
    fixture_cleanup?;

    assert_eq!(busy_error.code, ControlErrorCode::PersistenceFailure);
    assert!(!busy_error.committed);
    assert!(busy_error.has_sqlite_failure);
    assert!(native_start_acknowledged);
    assert!(first_error_requires_readback);
    assert_eq!(first_group_state, Some(JournalWorkState::Readback));
    assert_eq!(readback_count, 1);
    assert_eq!(readback_group_state, Some(JournalWorkState::Write));
    assert_eq!(successful_write_count, 1);
    assert!(output_pending_after_ack);
    assert!(output_progressed);
    assert!(!native_output_pending);
    assert_eq!(running_after_journal, Some(before.clone()));
    assert_eq!(output.events().len(), 1);
    assert!(all_stdout);
    assert_eq!(durable_bytes, b"durable-output");
    assert_eq!(durable_record, before);
    assert_eq!(durable_record.state(), ExecutionState::Running);

    assert_eq!(counts.output_attempts.load(Ordering::Acquire), 2);
    assert_eq!(counts.failed_writes.load(Ordering::Acquire), 1);
    assert_eq!(counts.readbacks.load(Ordering::Acquire), 1);
    assert_eq!(counts.successful_writes.load(Ordering::Acquire), 1);
    Ok(())
}
