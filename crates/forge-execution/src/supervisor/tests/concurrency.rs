//! Real native cancellation with controlled supervisor-owner ordering.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rustix_process::fs::OFlags;
use rustix_process::io::Errno;

use super::*;

const PROGRESS_BOUND: Duration = Duration::from_secs(5);

fn gated_request(
    id: u128,
    workspace_id: WorkspaceId,
    script: &str,
) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
    Ok(ExecutionRequest::new(
        ExecutionAttribution::new(
            ExecutionId::from_uuid(Uuid::from_u128(id)),
            workspace_id,
            ActivityId::from_uuid(Uuid::from_u128(id + 1)),
        ),
        ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from("/bin/sh"))?,
            arguments: ["-c", script]
                .into_iter()
                .map(|value| ExecutionArgument::new(OsString::from(value)))
                .collect::<Result<_, _>>()?,
        },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(30_000)?,
            ExecutionOutputLimit::new(1024)?,
        ),
        ExecutionPermissions::new(true, false, false),
    )?)
}

fn create_gate(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(format!("native handoff gate creation failed: {status}").into());
    }
    Ok(())
}

fn wait_for_gate_reader(
    runtime: &mut SupervisorRuntime,
    execution_id: ExecutionId,
    path: &Path,
) -> Result<File, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + PROGRESS_BOUND;
    loop {
        match OpenOptions::new()
            .write(true)
            .custom_flags(i32::try_from(OFlags::NONBLOCK.bits())?)
            .open(path)
        {
            Ok(writer) => return Ok(writer),
            Err(error) if error.raw_os_error() == Some(Errno::NXIO.raw_os_error()) => {}
            Err(error) => return Err(error.into()),
        }
        runtime.poll_completions();
        if let Some(event) = runtime
            .events
            .iter()
            .find(|event| event.execution_id() == execution_id)
        {
            return Err(format!(
                "native child terminated before its gate: {:?}; output: {:?}",
                event.result(),
                runtime.output_events
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err("native child did not reach its handoff gate".into());
        }
        thread::yield_now();
    }
}

fn wait_for_terminal(
    runtime: &mut SupervisorRuntime,
    execution_id: ExecutionId,
) -> Result<ExecutionSupervisorEvent, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + PROGRESS_BOUND;
    loop {
        runtime.poll_completions();
        if let Some(event) = runtime
            .events
            .iter()
            .find(|event| event.execution_id() == execution_id)
        {
            return Ok(event.clone());
        }
        if Instant::now() >= deadline {
            return Err(format!("native handoff settlement missing for {execution_id}").into());
        }
        thread::yield_now();
    }
}

fn start_at_gate(
    runtime: &mut SupervisorRuntime,
    layout: &ExistingWorkspaceStateLayout,
    capability: &RustCiToolchainCapability,
    id: u128,
    workspace_id: WorkspaceId,
    gate: &Path,
    script: &str,
) -> Result<(ExecutionId, File), Box<dyn std::error::Error>> {
    let request = gated_request(id, workspace_id, script)?;
    let execution_id = request.id();
    let identity =
        SupervisorStartIdentity::capture(layout, &request, ExecutionLaunchKind::RustCi, None)?;
    assert_eq!(
        runtime.start_execution(
            layout,
            identity,
            request,
            ExecutionLaunchKind::RustCi,
            Some(capability),
            false,
            None,
        )?,
        execution_id
    );
    let writer = wait_for_gate_reader(runtime, execution_id, gate)?;
    Ok((execution_id, writer))
}

fn assert_settled_native(
    runtime: &mut SupervisorRuntime,
    execution_id: ExecutionId,
    expected: forge_domain::ExecutionCompletionStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    let event = wait_for_terminal(runtime, execution_id)?;
    let outcome = event.result().as_ref().map_err(|error| {
        std::io::Error::other(format!("native handoff execution failed: {error:?}"))
    })?;
    assert_eq!(outcome.status(), expected);
    if expected == forge_domain::ExecutionCompletionStatus::Exited {
        assert_eq!(outcome.exit_code(), Some(0));
    }
    let closure = runtime
        .observe_native_closure(event)?
        .ok_or("settled native execution has no closure proof")?;
    assert_eq!(
        closure.process_disposition(),
        ProcessDisposition::ProcessGroupReaped
    );
    assert_eq!(closure.runtime_disposition(), RuntimeDisposition::Cleaned);
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.execution_id() == execution_id)
            .count(),
        1
    );
    Ok(())
}

fn assert_replacement_rejected(
    runtime: &mut SupervisorRuntime,
    layout: &ExistingWorkspaceStateLayout,
    capability: &RustCiToolchainCapability,
    workspace_id: WorkspaceId,
    attempt: u128,
) -> Result<(), Box<dyn std::error::Error>> {
    let replacement = request(attempt, workspace_id, "/usr/bin/true", &[], 30_000)?;
    let identity =
        SupervisorStartIdentity::capture(layout, &replacement, ExecutionLaunchKind::RustCi, None)?;
    assert!(matches!(
        runtime.start_execution(
            layout,
            identity,
            replacement,
            ExecutionLaunchKind::RustCi,
            Some(capability),
            false,
            None,
        ),
        Err(ExecutionSupervisorError::RustCiWorkspaceCapacity(id)) if id == workspace_id
    ));
    Ok(())
}

#[test]
fn dropped_cancel_reply_retains_workspace_until_native_settlement()
-> Result<(), Box<dyn std::error::Error>> {
    if nested_sandbox_execution_is_unavailable() {
        eprintln!("SKIPPED native handoff: outer Rust CI profile requires the host native lane");
        return Ok(());
    }
    let (root, layout) = fixture()?;
    let _root_guard = FixtureRootGuard(root.clone());
    let first_gate = root.join("first-handoff.fifo");
    let successor_gate = root.join("successor-handoff.fifo");
    create_gate(&first_gate)?;
    create_gate(&successor_gate)?;
    let capability = rust_ci_capability(&root)?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xCE00));
    let first_id = ExecutionId::from_uuid(Uuid::from_u128(0xCE01));
    let first_runtime =
        capability.ensure_runtime_paths(workspace_id, layout.root_fingerprint()?, first_id)?;
    let (_sender, receiver) = mpsc::sync_channel(1);
    // Spare global capacity ensures the rejection below is Workspace-specific.
    let mut runtime = SupervisorRuntime::new(
        ExecutionRunner::new(2)?,
        receiver,
        Arc::new(AtomicBool::new(true)),
    );
    // A real FIFO reader proves that the sandboxed child has actually started.
    let (_, _first_writer) = start_at_gate(
        &mut runtime,
        &layout,
        &capability,
        0xCE01,
        workspace_id,
        &first_gate,
        "IFS= read -r value < first-handoff.fifo",
    )?;
    assert_replacement_rejected(&mut runtime, &layout, &capability, workspace_id, 0xCE00)?;

    let (reply, receiver) = mpsc::sync_channel(0);
    drop(receiver);
    runtime.handle_request(SupervisorRequest::Cancel {
        id: first_id,
        response: reply,
    });
    // Do not poll the owner between cancellation and this admission check.
    // The native worker may have finished, but the owner has no settlement proof.
    assert!(runtime.active_rust_ci_workspaces.contains(&workspace_id));
    assert!(
        runtime.active[&first_id]
            .handle
            .process_finalization()
            .is_none()
    );
    assert_replacement_rejected(&mut runtime, &layout, &capability, workspace_id, 0xCE02)?;
    assert!(
        !runtime
            .events
            .iter()
            .any(|event| event.execution_id() == first_id)
    );
    assert_settled_native(
        &mut runtime,
        first_id,
        forge_domain::ExecutionCompletionStatus::Cancelled,
    )?;
    assert!(!first_runtime.execution_root().exists());
    assert!(!first_runtime.target_dir().exists());
    assert!(
        runtime
            .ensure_rust_ci_workspace_available(workspace_id)
            .is_ok()
    );

    let (successor_id, mut successor_writer) = start_at_gate(
        &mut runtime,
        &layout,
        &capability,
        0xCE03,
        workspace_id,
        &successor_gate,
        "IFS= read -r value < successor-handoff.fifo; [ \"$value\" = release ]",
    )?;
    let (reply, receiver) = mpsc::sync_channel(1);
    runtime.handle_request(SupervisorRequest::Cancel {
        id: first_id,
        response: reply,
    });
    assert!(!receiver.recv_timeout(PROGRESS_BOUND)??);
    successor_writer.write_all(b"release\n")?;
    drop(successor_writer);
    // Natural exit, before RAII teardown, detects stale cancellation of the successor.
    assert_settled_native(
        &mut runtime,
        successor_id,
        forge_domain::ExecutionCompletionStatus::Exited,
    )?;
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.execution_id() == first_id)
            .count(),
        1
    );
    eprintln!("native cancellation handoff verified with real FIFO children and closure proofs");
    Ok(())
}
