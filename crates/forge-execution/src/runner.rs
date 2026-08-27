use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use forge_domain::{
    BoundedExecutionOutput, ExecutionCompletionStatus, ExecutionFailureCode, ExecutionKind,
    ExecutionOutcome, ExecutionRequest, ExecutionTermination,
};
use forge_workspace::ExistingWorkspaceStateLayout;
use rustix_process::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix_process::io::Errno;
use rustix_process::process::{Pid, Signal, kill_process_group, test_kill_process_group};
use thiserror::Error;

use crate::sandbox::{MacOsSandboxProfile, SANDBOX_EXEC_PATH, SandboxBackendError};

const MAX_CONCURRENT_EXECUTIONS: usize = 16;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const GROUP_REAP_GRACE: Duration = Duration::from_millis(250);
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const SHELL_PROGRAM: &str = "/bin/zsh";

#[derive(Clone)]
pub struct ExecutionRunner {
    admission: Arc<ExecutionAdmission>,
}

impl std::fmt::Debug for ExecutionRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionRunner")
            .field("maximum", &self.admission.maximum)
            .field("active", &self.admission.active.load(Ordering::Acquire))
            .finish()
    }
}

impl ExecutionRunner {
    pub fn new(maximum: usize) -> Result<Self, ExecutionError> {
        if maximum == 0 || maximum > MAX_CONCURRENT_EXECUTIONS {
            return Err(ExecutionError::InvalidConcurrency {
                actual: maximum,
                maximum: MAX_CONCURRENT_EXECUTIONS,
            });
        }
        Ok(Self {
            admission: Arc::new(ExecutionAdmission {
                active: AtomicUsize::new(0),
                maximum,
            }),
        })
    }

    pub fn spawn(
        &self,
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<RunningExecution, ExecutionError> {
        let permit = self.admission.try_acquire()?;
        let prepared = PreparedExecution::new(layout, request)?;
        let (cancel_sender, cancel_receiver) = mpsc::sync_channel(1);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let thread_name = format!("forge-execution-{}", prepared.request.id());
        let join = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let result = supervise(&prepared, &cancel_receiver);
                let _ignored = result_sender.send(result);
                drop(permit);
            })
            .map_err(ExecutionError::SpawnSupervisor)?;
        Ok(RunningExecution {
            cancel_sender,
            result_receiver,
            join: Some(join),
        })
    }

    pub fn active_count(&self) -> usize {
        self.admission.active.load(Ordering::Acquire)
    }
}

struct ExecutionAdmission {
    active: AtomicUsize,
    maximum: usize,
}

impl ExecutionAdmission {
    fn try_acquire(self: &Arc<Self>) -> Result<ExecutionPermit, ExecutionError> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.maximum {
                return Err(ExecutionError::Capacity {
                    maximum: self.maximum,
                });
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(ExecutionPermit {
                        admission: Arc::clone(self),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct ExecutionPermit {
    admission: Arc<ExecutionAdmission>,
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.admission.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct RunningExecution {
    cancel_sender: SyncSender<()>,
    result_receiver: Receiver<Result<ExecutionOutcome, ExecutionError>>,
    join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for RunningExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningExecution")
            .finish_non_exhaustive()
    }
}

impl RunningExecution {
    pub fn cancel(&self) -> Result<(), ExecutionError> {
        match self.cancel_sender.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => Err(ExecutionError::SupervisorClosed),
        }
    }

    pub fn wait(mut self) -> Result<ExecutionOutcome, ExecutionError> {
        let result = self
            .result_receiver
            .recv()
            .map_err(|_| ExecutionError::SupervisorClosed)?;
        self.join_supervisor()?;
        result
    }

    pub fn try_wait(&mut self) -> Result<Option<ExecutionOutcome>, ExecutionError> {
        match self.result_receiver.try_recv() {
            Ok(result) => {
                self.join_supervisor()?;
                result.map(Some)
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.join_supervisor()?;
                Err(ExecutionError::SupervisorClosed)
            }
        }
    }

    fn join_supervisor(&mut self) -> Result<(), ExecutionError> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.join().map_err(|_| ExecutionError::SupervisorPanicked)
    }
}

impl Drop for RunningExecution {
    fn drop(&mut self) {
        let _ignored = self.cancel_sender.try_send(());
        let _ignored = self.join_supervisor();
    }
}

struct PreparedExecution {
    request: ExecutionRequest,
    profile: MacOsSandboxProfile,
    workspace_root: PathBuf,
    cwd: PathBuf,
}

impl PreparedExecution {
    fn new(
        layout: &ExistingWorkspaceStateLayout,
        request: ExecutionRequest,
    ) -> Result<Self, ExecutionError> {
        let workspace_root = layout.workspace_root().to_path_buf();
        let cwd = resolve_cwd(&workspace_root, request.cwd())?;
        let profile = MacOsSandboxProfile::new(layout, request.permissions())?;
        Ok(Self {
            request,
            profile,
            workspace_root,
            cwd,
        })
    }
}

fn resolve_cwd(
    workspace_root: &Path,
    relative: Option<&forge_domain::WorkspaceRelativePath>,
) -> Result<PathBuf, ExecutionError> {
    let candidate = relative.map_or_else(
        || workspace_root.to_path_buf(),
        |relative| workspace_root.join(relative.as_path()),
    );
    let metadata = fs::symlink_metadata(&candidate).map_err(ExecutionError::InspectCwd)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ExecutionError::InvalidCwd);
    }
    let canonical = fs::canonicalize(&candidate).map_err(ExecutionError::InspectCwd)?;
    if canonical != candidate || !canonical.starts_with(workspace_root) {
        return Err(ExecutionError::InvalidCwd);
    }
    Ok(candidate)
}

fn supervise(
    prepared: &PreparedExecution,
    cancellation: &Receiver<()>,
) -> Result<ExecutionOutcome, ExecutionError> {
    let start = Instant::now();
    let mut command = sandboxed_command(prepared);
    let shell_script = match prepared.request.kind() {
        ExecutionKind::Shell { script } => Some(script.as_str().as_bytes().to_vec()),
        ExecutionKind::Structured { .. } => None,
    };
    let mut child = command.spawn().map_err(ExecutionError::SpawnProcess)?;
    let pid = Pid::from_child(&child);
    let output_cancellation = Arc::new(AtomicBool::new(false));
    let output_limit = prepared.request.output_limit().get();
    let (stdout_reader, stderr_reader) = prepare_process_io(
        &mut child,
        pid,
        shell_script,
        output_limit,
        &output_cancellation,
    )?;
    let (status, completion) = match wait_for_child(
        &mut child,
        pid,
        cancellation,
        prepared.request.timeout().get(),
    ) {
        Ok(result) => result,
        Err(error) => {
            return Err(cleanup_after_spawn(
                error,
                &mut child,
                pid,
                &output_cancellation,
                vec![stdout_reader, stderr_reader],
            ));
        }
    };
    if let Err(error) = cleanup_process_group(pid) {
        return Err(cleanup_after_spawn(
            error,
            &mut child,
            pid,
            &output_cancellation,
            vec![stdout_reader, stderr_reader],
        ));
    }
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    let duration_millis = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(ExecutionOutcome::new(
        prepared.request.id(),
        ExecutionTermination::new(completion, status.code(), status.signal()),
        duration_millis,
        stdout,
        stderr,
    ))
}

type OutputReader = JoinHandle<Result<BoundedExecutionOutput, ExecutionError>>;

fn prepare_process_io(
    child: &mut Child,
    pid: Pid,
    shell_script: Option<Vec<u8>>,
    output_limit: u64,
    output_cancellation: &Arc<AtomicBool>,
) -> Result<(OutputReader, OutputReader), ExecutionError> {
    if let Some(script) = shell_script {
        let Some(mut stdin) = child.stdin.take() else {
            return Err(cleanup_after_spawn(
                ExecutionError::MissingPipe,
                child,
                pid,
                output_cancellation,
                Vec::new(),
            ));
        };
        if let Err(source) = stdin.write_all(&script) {
            return Err(cleanup_after_spawn(
                ExecutionError::WriteStdin(source),
                child,
                pid,
                output_cancellation,
                Vec::new(),
            ));
        }
    }
    let pipes = match (child.stdout.take(), child.stderr.take()) {
        (Some(stdout), Some(stderr)) => (stdout, stderr),
        _ => {
            return Err(cleanup_after_spawn(
                ExecutionError::MissingPipe,
                child,
                pid,
                output_cancellation,
                Vec::new(),
            ));
        }
    };
    let stdout_reader = spawn_reader(
        "stdout",
        pipes.0,
        output_limit,
        Arc::clone(output_cancellation),
    )
    .map_err(|error| cleanup_after_spawn(error, child, pid, output_cancellation, Vec::new()))?;
    let stderr_reader = match spawn_reader(
        "stderr",
        pipes.1,
        output_limit,
        Arc::clone(output_cancellation),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            return Err(cleanup_after_spawn(
                error,
                child,
                pid,
                output_cancellation,
                vec![stdout_reader],
            ));
        }
    };
    Ok((stdout_reader, stderr_reader))
}

fn cleanup_after_spawn(
    original: ExecutionError,
    child: &mut Child,
    pid: Pid,
    output_cancellation: &AtomicBool,
    readers: Vec<OutputReader>,
) -> ExecutionError {
    let cleanup = emergency_cleanup(child, pid);
    output_cancellation.store(true, Ordering::Release);
    let mut reader_failure = None;
    for reader in readers {
        if let Err(error) = join_reader(reader)
            && reader_failure.is_none()
        {
            reader_failure = Some(error);
        }
    }
    if let Err(error) = cleanup {
        error
    } else if let Some(error) = reader_failure {
        error
    } else {
        original
    }
}

fn emergency_cleanup(child: &mut Child, pid: Pid) -> Result<(), ExecutionError> {
    if child
        .try_wait()
        .map_err(ExecutionError::WaitProcess)?
        .is_none()
    {
        let _terminated = terminate(child, pid, ExecutionCompletionStatus::Cancelled)?;
    }
    cleanup_process_group(pid)
}

fn sandboxed_command(prepared: &PreparedExecution) -> Command {
    let mut command = Command::new(SANDBOX_EXEC_PATH);
    command.arg("-p").arg(prepared.profile.as_str());
    match prepared.request.kind() {
        ExecutionKind::Structured { program, arguments } => {
            command.arg(program.as_path());
            command.args(
                arguments
                    .iter()
                    .map(forge_domain::ExecutionArgument::as_os_str),
            );
            command.stdin(Stdio::null());
        }
        ExecutionKind::Shell { .. } => {
            command.arg(SHELL_PROGRAM).arg("-f");
            command.stdin(Stdio::piped());
        }
    }
    command
        .current_dir(&prepared.cwd)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("HOME", &prepared.workspace_root)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    command
}

fn spawn_reader<R>(
    label: &'static str,
    reader: R,
    limit: u64,
    cancellation: Arc<AtomicBool>,
) -> Result<OutputReader, ExecutionError>
where
    R: Read + std::os::fd::AsFd + Send + 'static,
{
    let flags = fcntl_getfl(&reader).map_err(ExecutionError::ConfigureOutputPipe)?;
    fcntl_setfl(&reader, flags | OFlags::NONBLOCK).map_err(ExecutionError::ConfigureOutputPipe)?;
    thread::Builder::new()
        .name(format!("forge-execution-{label}"))
        .spawn(move || read_bounded(reader, limit, &cancellation))
        .map_err(ExecutionError::SpawnOutputReader)
}

fn read_bounded<R: Read>(
    mut reader: R,
    limit: u64,
    cancellation: &AtomicBool,
) -> Result<BoundedExecutionOutput, ExecutionError> {
    let capacity = usize::try_from(limit).map_err(|_| ExecutionError::OutputLimitOverflow)?;
    let mut retained = Vec::with_capacity(capacity);
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if cancellation.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(error) => return Err(ExecutionError::ReadOutput(error)),
        };
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let available = capacity.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(available)]);
    }
    Ok(BoundedExecutionOutput::new(retained, total, total > limit))
}

fn join_reader(
    reader: JoinHandle<Result<BoundedExecutionOutput, ExecutionError>>,
) -> Result<BoundedExecutionOutput, ExecutionError> {
    reader
        .join()
        .map_err(|_| ExecutionError::OutputReaderPanicked)?
}

fn wait_for_child(
    child: &mut Child,
    pid: Pid,
    cancellation: &Receiver<()>,
    timeout_millis: u64,
) -> Result<(ExitStatus, ExecutionCompletionStatus), ExecutionError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_millis);
    loop {
        if let Some(status) = child.try_wait().map_err(ExecutionError::WaitProcess)? {
            return Ok((status, ExecutionCompletionStatus::Exited));
        }
        match cancellation.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                return terminate(child, pid, ExecutionCompletionStatus::Cancelled);
            }
            Err(TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            return terminate(child, pid, ExecutionCompletionStatus::TimedOut);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn terminate(
    child: &mut Child,
    pid: Pid,
    completion: ExecutionCompletionStatus,
) -> Result<(ExitStatus, ExecutionCompletionStatus), ExecutionError> {
    signal_group(pid, Signal::TERM)?;
    let deadline = Instant::now() + TERMINATION_GRACE;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(ExecutionError::WaitProcess)? {
            signal_group(pid, Signal::KILL)?;
            return Ok((status, completion));
        }
        thread::sleep(POLL_INTERVAL);
    }
    signal_group(pid, Signal::KILL)?;
    let status = child.wait().map_err(ExecutionError::WaitProcess)?;
    Ok((status, completion))
}

fn cleanup_process_group(pid: Pid) -> Result<(), ExecutionError> {
    match test_kill_process_group(pid) {
        Ok(()) => signal_group(pid, Signal::KILL)?,
        Err(source) if source == Errno::SRCH => return Ok(()),
        Err(source) => return Err(ExecutionError::SignalProcessGroup(source)),
    }
    let deadline = Instant::now() + GROUP_REAP_GRACE;
    while Instant::now() < deadline {
        match test_kill_process_group(pid) {
            Err(source) if source == Errno::SRCH => return Ok(()),
            Ok(()) => thread::sleep(POLL_INTERVAL),
            Err(source) => return Err(ExecutionError::SignalProcessGroup(source)),
        }
    }
    Err(ExecutionError::ProcessGroupSurvived)
}

fn signal_group(pid: Pid, signal: Signal) -> Result<(), ExecutionError> {
    match kill_process_group(pid, signal) {
        Ok(()) => Ok(()),
        Err(source) if source == Errno::SRCH => Ok(()),
        Err(source) => Err(ExecutionError::SignalProcessGroup(source)),
    }
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("execution concurrency {actual} is outside 1..={maximum}")]
    InvalidConcurrency { actual: usize, maximum: usize },
    #[error("execution admission is at capacity {maximum}")]
    Capacity { maximum: usize },
    #[error(transparent)]
    Sandbox(#[from] SandboxBackendError),
    #[error("execution cwd inspection failed")]
    InspectCwd(#[source] std::io::Error),
    #[error("execution cwd is unavailable or escaped")]
    InvalidCwd,
    #[error("failed to spawn execution supervisor")]
    SpawnSupervisor(#[source] std::io::Error),
    #[error("failed to spawn sandboxed process")]
    SpawnProcess(#[source] std::io::Error),
    #[error("failed to spawn output reader")]
    SpawnOutputReader(#[source] std::io::Error),
    #[error("failed to configure output pipe")]
    ConfigureOutputPipe(#[source] Errno),
    #[error("sandboxed process pipe is missing")]
    MissingPipe,
    #[error("failed to write shell input")]
    WriteStdin(#[source] std::io::Error),
    #[error("failed to read process output")]
    ReadOutput(#[source] std::io::Error),
    #[error("execution output limit cannot be represented")]
    OutputLimitOverflow,
    #[error("failed to wait for sandboxed process")]
    WaitProcess(#[source] std::io::Error),
    #[error("failed to signal process group")]
    SignalProcessGroup(#[source] Errno),
    #[error("process group survived forced termination")]
    ProcessGroupSurvived,
    #[error("execution output reader panicked")]
    OutputReaderPanicked,
    #[error("execution supervisor panicked")]
    SupervisorPanicked,
    #[error("execution supervisor is closed")]
    SupervisorClosed,
}

impl ExecutionError {
    pub const fn failure_code(&self) -> ExecutionFailureCode {
        match self {
            Self::InvalidConcurrency { .. } | Self::Capacity { .. } => {
                ExecutionFailureCode::Admission
            }
            Self::Sandbox(SandboxBackendError::Unavailable) => {
                ExecutionFailureCode::SandboxUnavailable
            }
            Self::Sandbox(_) | Self::InspectCwd(_) | Self::InvalidCwd => {
                ExecutionFailureCode::InvalidWorkingDirectory
            }
            Self::SpawnSupervisor(_) | Self::SpawnProcess(_) => ExecutionFailureCode::ProcessSpawn,
            Self::SpawnOutputReader(_)
            | Self::ConfigureOutputPipe(_)
            | Self::MissingPipe
            | Self::WriteStdin(_)
            | Self::ReadOutput(_)
            | Self::OutputLimitOverflow
            | Self::WaitProcess(_)
            | Self::SignalProcessGroup(_)
            | Self::ProcessGroupSurvived
            | Self::OutputReaderPanicked
            | Self::SupervisorPanicked
            | Self::SupervisorClosed => ExecutionFailureCode::Supervision,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io;
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityId, ExecutionArgument, ExecutionAttribution, ExecutionId, ExecutionLimits,
        ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram, ExecutionScript,
        ExecutionTimeoutMillis, WorkspaceId,
    };
    use forge_workspace::WorkspaceStateLayout;
    use rustix_process::process::test_kill_process;
    use uuid::Uuid;

    use super::*;

    fn layout(
        label: &str,
    ) -> Result<(PathBuf, ExistingWorkspaceStateLayout), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-execution-{label}-{unique}"));
        fs::create_dir_all(&root)?;
        WorkspaceStateLayout::initialize(&root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        Ok((root, layout))
    }

    fn request(
        seed: u128,
        kind: ExecutionKind,
        permissions: ExecutionPermissions,
        timeout: u64,
        output_limit: u64,
    ) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(seed)),
                WorkspaceId::from_uuid(Uuid::from_u128(seed + 1)),
                ActivityId::from_uuid(Uuid::from_u128(seed + 2)),
            ),
            kind,
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(timeout)?,
                ExecutionOutputLimit::new(output_limit)?,
            ),
            permissions,
        )?)
    }

    fn structured(
        program: &str,
        arguments: &[&str],
    ) -> Result<ExecutionKind, Box<dyn std::error::Error>> {
        Ok(ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from(program))?,
            arguments: arguments
                .iter()
                .map(|value| ExecutionArgument::new(OsString::from(value)))
                .collect::<Result<_, _>>()?,
        })
    }

    fn shell(script: String) -> Result<ExecutionKind, Box<dyn std::error::Error>> {
        Ok(ExecutionKind::Shell {
            script: ExecutionScript::new(script)?,
        })
    }

    fn spawn_http_server(
        listener: TcpListener,
    ) -> Result<JoinHandle<Result<bool, io::Error>>, io::Error> {
        listener.set_nonblocking(true)?;
        thread::Builder::new()
            .name("forge-execution-test-http".to_owned())
            .spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
                            return Ok(true);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return Ok(false);
                            }
                            thread::sleep(POLL_INTERVAL);
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
    }

    #[test]
    fn structured_argv_is_literal_and_environment_is_allowlisted()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = layout("structured")?;
        let runner = ExecutionRunner::new(2)?;
        let injection = "literal; /usr/bin/touch should-not-exist";
        let outcome = runner
            .spawn(
                &layout,
                request(
                    10,
                    structured("/usr/bin/printf", &[injection])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_eq!(outcome.exit_code(), Some(0));
        assert_eq!(outcome.stdout().retained(), injection.as_bytes());
        assert!(!root.join("should-not-exist").exists());

        let environment = runner
            .spawn(
                &layout,
                request(
                    20,
                    structured("/usr/bin/env", &[])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        let environment = std::str::from_utf8(environment.stdout().retained())?;
        assert!(environment.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"));
        assert!(environment.contains("LANG=C"));
        assert!(!environment.contains("SSH_AUTH_SOCK"));
        assert!(!environment.contains("API_KEY"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn real_macos_sandbox_enforces_workspace_outside_and_state_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = layout("filesystem")?;
        let outside = root.with_extension("outside");
        let script = format!(
            "printf inside > \"$HOME/inside.txt\"; printf outside > '{}'",
            outside.display()
        );
        let runner = ExecutionRunner::new(1)?;
        let outcome = runner
            .spawn(
                &layout,
                request(
                    30,
                    shell(script)?,
                    ExecutionPermissions::new(true, true, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::Exited);
        assert_ne!(outcome.exit_code(), Some(0));
        assert_eq!(fs::read(root.join("inside.txt"))?, b"inside");
        assert!(!outside.exists());

        let outside_read = runner
            .spawn(
                &layout,
                request(
                    31,
                    structured("/bin/cat", &["/etc/hosts"])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        assert_ne!(outside_read.exit_code(), Some(0));
        assert!(outside_read.stdout().retained().is_empty());

        let state_secret = layout.state_root().join("execution-secret");
        fs::write(&state_secret, b"must-not-escape")?;
        let state_secret = state_secret.to_str().ok_or("state path is not UTF-8")?;
        let state_read = runner
            .spawn(
                &layout,
                request(
                    32,
                    structured("/bin/cat", &[state_secret])?,
                    ExecutionPermissions::new(true, false, false),
                    2_000,
                    8_192,
                )?,
            )?
            .wait()?;
        assert_ne!(state_read.exit_code(), Some(0));
        assert!(state_read.stdout().retained().is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn output_is_drained_but_retained_bytes_are_bounded() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, layout) = layout("output")?;
        let outcome = ExecutionRunner::new(1)?
            .spawn(
                &layout,
                request(
                    40,
                    structured("/usr/bin/yes", &["bounded"])?,
                    ExecutionPermissions::new(false, false, false),
                    200,
                    1_024,
                )?,
            )?
            .wait()?;
        assert_eq!(outcome.status(), ExecutionCompletionStatus::TimedOut);
        assert_eq!(outcome.stdout().retained().len(), 1_024);
        assert!(outcome.stdout().truncated());
        assert!(outcome.stdout().total_bytes() > 1_024);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn real_macos_sandbox_network_permission_is_enforced() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, layout) = layout("network")?;
        let runner = ExecutionRunner::new(1)?;
        let denied_listener = TcpListener::bind("127.0.0.1:0")?;
        let denied_port = denied_listener.local_addr()?.port();
        let denied_server = spawn_http_server(denied_listener)?;
        let denied_connect = format!("127.0.0.1:80:127.0.0.1:{denied_port}");
        let denied = runner
            .spawn(
                &layout,
                request(
                    45,
                    structured(
                        "/usr/bin/curl",
                        &[
                            "--silent",
                            "--max-time",
                            "1",
                            "http://127.0.0.1",
                            "--connect-to",
                            &denied_connect,
                        ],
                    )?,
                    ExecutionPermissions::new(false, false, false),
                    3_000,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_ne!(denied.exit_code(), Some(0));
        assert!(!denied_server.join().map_err(|_| "server panicked")??);

        let allowed_listener = TcpListener::bind("127.0.0.1:0")?;
        let allowed_port = allowed_listener.local_addr()?.port();
        let allowed_server = spawn_http_server(allowed_listener)?;
        let allowed_connect = format!("127.0.0.1:80:127.0.0.1:{allowed_port}");
        let allowed = runner
            .spawn(
                &layout,
                request(
                    46,
                    structured(
                        "/usr/bin/curl",
                        &[
                            "--silent",
                            "--max-time",
                            "1",
                            "http://127.0.0.1",
                            "--connect-to",
                            &allowed_connect,
                        ],
                    )?,
                    ExecutionPermissions::new(false, false, true),
                    3_000,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_eq!(
            allowed.exit_code(),
            Some(0),
            "stderr: {}",
            String::from_utf8_lossy(allowed.stderr().retained())
        );
        assert_eq!(allowed.stdout().retained(), b"ok");
        assert!(allowed_server.join().map_err(|_| "server panicked")??);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn cancellation_and_timeout_reap_process_groups_and_release_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout) = layout("cancel")?;
        let runner = ExecutionRunner::new(1)?;
        let running = runner.spawn(
            &layout,
            request(
                50,
                shell("printf ready > \"$HOME/ready\"; exec /bin/sleep 30".to_owned())?,
                ExecutionPermissions::new(true, true, false),
                30_000,
                4_096,
            )?,
        )?;
        assert!(matches!(
            runner.spawn(
                &layout,
                request(
                    60,
                    structured("/usr/bin/true", &[])?,
                    ExecutionPermissions::new(false, false, false),
                    1_000,
                    1_024,
                )?
            ),
            Err(ExecutionError::Capacity { maximum: 1 })
        ));
        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !root.join("ready").exists() && Instant::now() < ready_deadline {
            thread::sleep(POLL_INTERVAL);
        }
        assert!(root.join("ready").is_file());
        running.cancel()?;
        let cancelled = running.wait()?;
        assert_eq!(cancelled.status(), ExecutionCompletionStatus::Cancelled);
        assert_eq!(runner.active_count(), 0);

        let timed_out = runner
            .spawn(
                &layout,
                request(
                    70,
                    shell("/bin/sleep 30 & echo $! > \"$HOME/child.pid\"; wait".to_owned())?,
                    ExecutionPermissions::new(true, true, false),
                    300,
                    4_096,
                )?,
            )?
            .wait()?;
        assert_eq!(timed_out.status(), ExecutionCompletionStatus::TimedOut);
        let child_pid = fs::read_to_string(root.join("child.pid"))?;
        let child_pid = i32::from_str(child_pid.trim())?;
        let child_pid = Pid::from_raw(child_pid).ok_or("invalid child pid")?;
        let reap_deadline = Instant::now() + Duration::from_secs(1);
        while test_kill_process(child_pid).is_ok() && Instant::now() < reap_deadline {
            thread::sleep(POLL_INTERVAL);
        }
        assert_eq!(test_kill_process(child_pid), Err(Errno::SRCH));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
