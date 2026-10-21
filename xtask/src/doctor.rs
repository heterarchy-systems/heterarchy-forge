//! Owned, bounded probing and shutdown of the throwaway backend doctor.

use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use super::{
    DoctorRetention, DoctorSandbox, MAX_DOCTOR_OUTPUT_BYTES, MSRV_TOOLCHAIN,
    REQUIRED_CARGO_AUDIT_VERSION, REQUIRED_CARGO_DENY_VERSION, capture_process_with_env, cargo,
    cargo_target_directory, command, require_nonempty_file, require_tool_version, rules,
    unique_suffix, workspace_root,
};

pub(super) fn doctor() -> Result<(), String> {
    let root = workspace_root();
    let mut sandbox = DoctorSandbox::create()?;
    rules()?;
    command("rustc", &["--version"])?;
    command("cargo", &["--version"])?;
    command("cargo", &["fmt", "--version"])?;
    command("cargo", &["clippy", "--version"])?;
    command("rustup", &["run", MSRV_TOOLCHAIN, "rustc", "--version"])?;
    require_tool_version("cargo-deny", REQUIRED_CARGO_DENY_VERSION, &root)?;
    require_tool_version("cargo-audit", REQUIRED_CARGO_AUDIT_VERSION, &root)?;
    require_nonempty_file(&root.join("Cargo.lock"), "Cargo lockfile")?;
    cargo(&["build", "--locked", "-p", "forge-backend"])?;
    run_backend_doctor(&root, &mut sandbox)?;
    if !sandbox.registry_path().exists() {
        return Err(format!(
            "backend doctor did not create the durable sandbox registry {}",
            sandbox.registry_path().display()
        ));
    }
    sandbox.cleanup()?;
    println!("Heterarchy Forge Rust harness doctor passed");
    Ok(())
}

const BACKEND_DOCTOR_SESSION_AUTHORITY: &str = "127.0.0.1:9101";
const BACKEND_DOCTOR_BACKEND_ID: &str = "7b6c9d3e-1111-4222-8333-444455556666";
const BACKEND_DOCTOR_ISSUER_ID: &str = "2c4f6a8b-1111-4222-8333-444455556667";
const BACKEND_DOCTOR_DESTINATION_ID: &str = "5d7e9f0a-1111-4222-8333-444455556668";
const BACKEND_DOCTOR_POLL_INTERVAL: Duration = Duration::from_millis(100);
const BACKEND_DOCTOR_POLL_BUDGET: Duration = Duration::from_secs(15);
const BACKEND_DOCTOR_SHUTDOWN_BUDGET: Duration = Duration::from_secs(15);

/// Doctor the headless backend product path exactly as operations run it:
/// init-registry, serve on loopback with file-backed bearer secrets, prove
/// /healthz and /readyz over a real TCP connection, then prove bounded
/// graceful SIGTERM shutdown. Every path stays inside the throwaway doctor
/// sandbox; nothing here initializes or touches an operational registry.
fn run_backend_doctor(root: &Path, sandbox: &mut DoctorSandbox) -> Result<(), String> {
    let binary = cargo_target_directory(root)?
        .join("debug")
        .join("forge-backend");
    let binary_metadata = fs::metadata(&binary).map_err(|error| {
        format!(
            "debug forge-backend binary {} is unavailable: {error}",
            binary.display()
        )
    })?;
    if !binary_metadata.is_file() || binary_metadata.len() == 0 {
        return Err(format!(
            "debug forge-backend binary {} is not a non-empty regular file",
            binary.display()
        ));
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("backend doctor cannot reserve a loopback port: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("backend doctor cannot read its loopback port: {error}"))?
        .port();
    drop(listener);

    let config_path = write_doctor_config(sandbox, port)?;
    let environment = [
        (OsStr::new("HOME"), sandbox.home().as_os_str()),
        (OsStr::new("TMPDIR"), sandbox.root.as_os_str()),
    ];
    let registry_argument = sandbox.registry_path().display().to_string();
    let initialized = capture_process_with_env(
        &binary,
        &["init-registry", &registry_argument],
        root,
        MAX_DOCTOR_OUTPUT_BYTES,
        &environment,
    )?;
    if !initialized.status.success() {
        return Err(format!(
            "forge-backend init-registry exited with status {}: {}",
            initialized.status,
            String::from_utf8_lossy(&initialized.stderr)
        ));
    }
    if !initialized.stderr.is_empty() {
        eprint!(
            "forge-backend init-registry stderr:\n{}",
            String::from_utf8_lossy(&initialized.stderr)
        );
    }

    let (serve, stderr) = start_doctor_serve(root, &binary, &config_path, sandbox)?;
    supervise_doctor_serve(serve, stderr, port, sandbox, BACKEND_DOCTOR_POLL_BUDGET)?;
    println!("forge-backend-doctor health=ok ready=true shutdown=graceful");
    Ok(())
}

fn supervise_doctor_serve(
    mut serve: Child,
    stderr: UnixStream,
    port: u16,
    sandbox: &mut DoctorSandbox,
    probe_budget: Duration,
) -> Result<(), String> {
    thread::scope(|scope| {
        let (cancel, cancelled) = mpsc::sync_channel(1);
        let reader = match thread::Builder::new()
            .name("forge-doctor-stderr".to_owned())
            .spawn_scoped(scope, move || drain_doctor_stderr(stderr, &cancelled))
        {
            Ok(reader) => reader,
            Err(error) => {
                let cleanup = force_doctor_exit(&mut serve);
                if !serve.try_wait().is_ok_and(|status| status.is_some()) {
                    sandbox.retention = Some(DoctorRetention::UnreapedProcess(serve.id()));
                }
                return Err(format!(
                    "doctor stderr thread could not start: {error}; cleanup={cleanup:?}"
                ));
            }
        };
        let probe = probe_doctor_endpoints(&mut serve, port, probe_budget);
        let shutdown = stop_doctor_serve(&mut serve);
        let reaped = serve.try_wait().map(|status| status.is_some());
        if !matches!(reaped, Ok(true)) {
            sandbox.retention = Some(DoctorRetention::UnreapedProcess(serve.id()));
        }
        // Closing the sender cancels a live reader without an ignored send result.
        drop(cancel);
        let diagnostics = reader
            .join()
            .unwrap_or_else(|_| Err("doctor stderr reader panicked".to_owned()));
        if diagnostics.is_err() && sandbox.retention.is_none() {
            sandbox.retention = Some(DoctorRetention::DiagnosticsFailed);
        }
        if probe.is_err()
            || shutdown.is_err()
            || diagnostics.is_err()
            || !matches!(reaped, Ok(true))
        {
            return Err(format!(
                "backend doctor failed (pid={}, probe={probe:?}, shutdown={shutdown:?}, reaped={reaped:?}); serve stderr={diagnostics:?}",
                serve.id()
            ));
        }
        Ok(())
    })
}

/// Compose the throwaway doctor secrets and strict backend config, and prove
/// the two file secrets differ before anything is served.
fn write_doctor_config(sandbox: &DoctorSandbox, port: u16) -> Result<PathBuf, String> {
    let api_secret = sandbox.root.join("secrets").join("api.secret");
    let session_secret = sandbox.root.join("secrets").join("session.secret");
    fs::create_dir_all(sandbox.root.join("secrets"))
        .map_err(|error| format!("cannot create the backend doctor secrets directory: {error}"))?;
    fs::write(
        &api_secret,
        format!("{}\n", doctor_secret(b"forge-doctor-api")),
    )
    .map_err(|error| format!("cannot write the backend doctor api secret: {error}"))?;
    fs::write(
        &session_secret,
        format!("{}\n", doctor_secret(b"forge-doctor-session")),
    )
    .map_err(|error| format!("cannot write the backend doctor session secret: {error}"))?;
    if fs::read(&api_secret)
        .is_ok_and(|api| fs::read(&session_secret).is_ok_and(|session| api == session))
    {
        return Err("backend doctor api and session secrets must differ".to_owned());
    }
    let config_path = sandbox.root.join("forge-backend.json");
    let config = serde_json::json!({
        "listen": format!("127.0.0.1:{port}"),
        "registry_path": sandbox.registry_path().display().to_string(),
        "product_cache_root": sandbox.root.join("product-cache").display().to_string(),
        "backend_id": BACKEND_DOCTOR_BACKEND_ID,
        "issuer_id": BACKEND_DOCTOR_ISSUER_ID,
        "destination_id": BACKEND_DOCTOR_DESTINATION_ID,
        "api_bearer_file": api_secret.display().to_string(),
        "session_authority": BACKEND_DOCTOR_SESSION_AUTHORITY,
        "session_bearer_file": session_secret.display().to_string(),
    });
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config)
            .map_err(|error| format!("cannot serialize the backend doctor config: {error}"))?,
    )
    .map_err(|error| format!("cannot write the backend doctor config: {error}"))?;
    Ok(config_path)
}

fn start_doctor_serve(
    root: &Path,
    binary: &Path,
    config_path: &Path,
    sandbox: &DoctorSandbox,
) -> Result<(Child, UnixStream), String> {
    let (stderr, writer) = UnixStream::pair()
        .map_err(|error| format!("backend doctor cannot create stderr channel: {error}"))?;
    stderr
        .set_nonblocking(true)
        .map_err(|error| format!("backend doctor cannot bound stderr reads: {error}"))?;
    let config_argument = config_path.display().to_string();
    let serve = Command::new(binary)
        .args(["serve", &config_argument])
        .current_dir(root)
        .env("HOME", sandbox.home())
        .env("TMPDIR", sandbox.root.as_os_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .map_err(|error| format!("backend doctor cannot start forge-backend serve: {error}"))?;
    Ok((serve, stderr))
}

/// Drain throughout the live process, retaining bounded diagnostics while
/// discarding excess bytes so logging cannot block readiness or shutdown.
fn drain_doctor_stderr(mut stream: UnixStream, cancelled: &Receiver<()>) -> Result<String, String> {
    let mut retained = Vec::new();
    let mut total = 0_usize;
    let mut stopping = false;
    let mut deadline = Instant::now()
        + BACKEND_DOCTOR_POLL_BUDGET
        + BACKEND_DOCTOR_SHUTDOWN_BUDGET
        + Duration::from_secs(6);
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        if matches!(
            cancelled.try_recv(),
            Ok(()) | Err(TryRecvError::Disconnected)
        ) && !stopping
        {
            stopping = true;
            deadline = deadline.min(Instant::now() + BACKEND_DOCTOR_POLL_INTERVAL);
        }
        if Instant::now() >= deadline {
            return Err("doctor stderr did not close within its owned read deadline".to_owned());
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                let text = String::from_utf8_lossy(&retained).into_owned();
                return if total > MAX_DOCTOR_OUTPUT_BYTES {
                    Err(format!(
                        "doctor stderr exceeded {MAX_DOCTOR_OUTPUT_BYTES} bytes ({total} observed); capped diagnostics: {text}"
                    ))
                } else {
                    Ok(text)
                };
            }
            Ok(read) => {
                let keep = (MAX_DOCTOR_OUTPUT_BYTES - retained.len()).min(read);
                retained.extend_from_slice(&chunk[..keep]);
                total = total.saturating_add(read);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stopping {
                    return Err("doctor stderr remained open after server stop".to_owned());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("doctor stderr read failed: {error}")),
        }
    }
}

fn probe_doctor_endpoints(serve: &mut Child, port: u16, budget: Duration) -> Result<(), String> {
    let deadline = Instant::now() + budget;
    let health = wait_for_http_body(("127.0.0.1", port), "/healthz", "ok", deadline);
    let ready = wait_for_http_ready(("127.0.0.1", port), "/readyz", deadline);
    if health.is_err() || ready.is_err() {
        return Err(format!(
            "backend doctor probe failed (health={health:?}, ready={ready:?})"
        ));
    }
    if let Some(status) = serve.try_wait().map_err(|error| error.to_string())? {
        return Err(format!("backend doctor serve exited early with {status}"));
    }
    Ok(())
}

fn stop_doctor_serve(serve: &mut Child) -> Result<(), String> {
    stop_doctor_serve_until(serve, Instant::now() + BACKEND_DOCTOR_SHUTDOWN_BUDGET)
}

fn stop_doctor_serve_until(serve: &mut Child, deadline: Instant) -> Result<(), String> {
    match serve.try_wait() {
        Ok(Some(status)) => {
            return Err(format!(
                "backend doctor serve exited before SIGTERM with {status}"
            ));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(format!(
                "backend doctor cannot observe serve: {error}; emergency={:?}",
                force_doctor_exit(serve)
            ));
        }
    }
    let signal = Command::new("/bin/kill")
        .args(["-TERM", &serve.id().to_string()])
        .status();
    if !signal.as_ref().is_ok_and(std::process::ExitStatus::success) {
        return Err(format!(
            "backend doctor SIGTERM failed: {signal:?}; emergency={:?}",
            force_doctor_exit(serve)
        ));
    }
    match poll_doctor_exit(serve, deadline) {
        Ok(Some(status)) if status.success() => Ok(()),
        Ok(Some(status)) => Err(format!("backend doctor serve exited with status {status}")),
        outcome => Err(format!(
            "backend doctor graceful shutdown failed: {outcome:?}; emergency={:?}",
            force_doctor_exit(serve)
        )),
    }
}

fn force_doctor_exit(serve: &mut Child) -> Result<std::process::ExitStatus, String> {
    let signal = serve.kill();
    match poll_doctor_exit(serve, Instant::now() + Duration::from_secs(5)) {
        Ok(Some(status)) => Ok(status),
        outcome => Err(format!(
            "backend doctor pid {} unreaped after KILL (signal={signal:?}, outcome={outcome:?})",
            serve.id()
        )),
    }
}

fn poll_doctor_exit(
    serve: &mut Child,
    deadline: Instant,
) -> Result<Option<std::process::ExitStatus>, String> {
    loop {
        if let Some(status) = serve.try_wait().map_err(|error| error.to_string())? {
            return Ok(Some(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        thread::sleep(BACKEND_DOCTOR_POLL_INTERVAL.min(remaining));
    }
}

fn wait_for_http_body(
    address: (&str, u16),
    path: &str,
    expected: &str,
    deadline: Instant,
) -> Result<(), String> {
    while Instant::now() < deadline {
        if let Ok(response) = http_get_once(address.1, path, deadline)
            && http_body_matches(&response, expected)
        {
            return Ok(());
        }
        thread::sleep(
            BACKEND_DOCTOR_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    Err(format!("backend doctor {path} never returned {expected:?}"))
}

fn wait_for_http_ready(address: (&str, u16), path: &str, deadline: Instant) -> Result<(), String> {
    while Instant::now() < deadline {
        if let Ok(response) = http_get_once(address.1, path, deadline)
            && response.contains("\"ready\":true")
        {
            return Ok(());
        }
        thread::sleep(
            BACKEND_DOCTOR_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    Err(format!("backend doctor {path} never reported ready"))
}

fn http_get_once(port: u16, path: &str, deadline: Instant) -> io::Result<String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "doctor HTTP deadline elapsed",
        ));
    }
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, remaining.min(Duration::from_secs(2)))?;
    stream.set_nonblocking(true)?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "doctor HTTP deadline elapsed",
            ));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(String::from_utf8_lossy(&response).into_owned()),
            Ok(read) if response.len() + read <= MAX_DOCTOR_OUTPUT_BYTES => {
                response.extend_from_slice(&chunk[..read]);
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "doctor HTTP response exceeds limit",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10).min(remaining));
            }
            Err(error) => return Err(error),
        }
    }
}

fn http_body_matches(response: &str, expected: &str) -> bool {
    response
        .split_once("\r\n\r\n")
        .is_some_and(|(head, body)| head.starts_with("HTTP/1.1 200") && body.trim() == expected)
}

fn doctor_secret(label: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(unique_suffix().to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::new(), |out, byte| format!("{out}{byte:02x}"))
}

#[cfg(test)]
mod tests;
