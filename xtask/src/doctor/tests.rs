use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn failed_doctor_probe_returns_before_live_backend_stderr_eof() -> Result<(), String> {
    let child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|error| error.to_string())?;
    let child_id = child.id().to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    let probe = thread::spawn(move || {
        let mut child = child;
        let result = super::probe_doctor_endpoints(&mut child, 0, Duration::ZERO);
        let delivered = sender.send(result);
        (child, delivered)
    });
    let before_stop = receiver.recv_timeout(Duration::from_secs(2));
    // The child retains piped stdin in either the worker or its join result, so
    // cat cannot exit on EOF before this explicit, test-owned termination.
    let signaled = Command::new("/bin/kill")
        .args(["-TERM", &child_id])
        .status()
        .map_err(|error| error.to_string())?;
    let (mut child, delivered) = probe.join().map_err(|_| "doctor probe thread panicked")?;
    child.wait().map_err(|error| error.to_string())?;
    assert!(signaled.success());
    assert!(delivered.is_ok());
    assert!(
        before_stop.is_ok(),
        "probe waited for a live backend's stderr EOF"
    );
    assert!(before_stop.map_err(|error| error.to_string())?.is_err());
    Ok(())
}

#[test]
fn doctor_diagnostics_stop_without_waiting_for_an_unowned_writer() -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let (stream, mut writer) = UnixStream::pair().map_err(|error| error.to_string())?;
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    writer
        .write_all(b"tail")
        .map_err(|error| error.to_string())?;
    let (stop, cancelled) = mpsc::sync_channel(1);
    stop.send(()).map_err(|error| error.to_string())?;
    assert!(super::drain_doctor_stderr(stream, &cancelled).is_err());
    drop(writer);
    let (stream, mut writer) = UnixStream::pair().map_err(|error| error.to_string())?;
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    writer
        .write_all(b"tail")
        .map_err(|error| error.to_string())?;
    drop(writer);
    let (_stop, cancelled) = mpsc::sync_channel(1);
    assert_eq!(super::drain_doctor_stderr(stream, &cancelled)?, "tail");
    Ok(())
}

#[test]
fn doctor_stderr_drains_overflow_without_blocking_writer() -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let (stream, mut writer) = UnixStream::pair().map_err(|error| error.to_string())?;
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let (_stop, cancelled) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let producer = scope.spawn(move || {
            writer.write_all(&vec![b'x'; crate::MAX_DOCTOR_OUTPUT_BYTES + 32 * 1024])
        });
        let captured = super::drain_doctor_stderr(stream, &cancelled);
        producer
            .join()
            .map_err(|_| "stderr producer panicked")?
            .map_err(|error| error.to_string())?;
        assert!(captured.is_err_and(|error| error.contains("exceeded")));
        Ok(())
    })
}

#[test]
fn doctor_forces_and_reaps_a_term_resistant_owned_child() -> Result<(), String> {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;
    let (mut ready, writer) = UnixStream::pair().map_err(|error| error.to_string())?;
    ready
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let mut child = Command::new("/bin/sh")
        .args(["-c", "trap '' TERM; printf READY; exec /bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut bytes = [0_u8; 5];
    if let Err(error) = ready.read_exact(&mut bytes) {
        return Err(format!(
            "child preparation failed: {error}; cleanup={:?}",
            super::force_doctor_exit(&mut child)
        ));
    }
    let stopped = super::stop_doctor_serve_until(&mut child, Instant::now());
    assert!(
        stopped.is_err(),
        "forced shutdown must not claim graceful PASS"
    );
    assert!(
        child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
    );
    Ok(())
}

#[test]
fn doctor_sandbox_supplies_the_canonical_home_required_by_app_paths() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = super::DoctorSandbox::create()?;
    let canonical = std::fs::canonicalize(sandbox.home()).map_err(|error| error.to_string())?;
    assert_eq!(sandbox.home(), canonical);
    assert_eq!(
        std::fs::metadata(&sandbox.root)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    sandbox.cleanup()?;
    assert!(!sandbox.root.exists());
    Ok(())
}

#[test]
fn doctor_retains_sandbox_when_a_writer_outlives_the_reaped_server() -> Result<(), String> {
    use std::os::unix::net::UnixStream;
    let (stream, _writer) = UnixStream::pair().map_err(|error| error.to_string())?;
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut sandbox = super::DoctorSandbox::create()?;
    let root = sandbox.root.clone();
    let outcome = super::supervise_doctor_serve(child, stream, 0, &mut sandbox, Duration::ZERO);
    assert!(outcome.is_err());
    assert!(matches!(
        sandbox.retention,
        Some(super::DoctorRetention::DiagnosticsFailed)
    ));
    assert!(sandbox.cleanup().is_err());
    drop(sandbox);
    assert!(root.is_dir());
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())?;
    Ok(())
}
