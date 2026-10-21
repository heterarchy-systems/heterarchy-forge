//! Ignored cross-process proof for the standalone Forge host.
//!
//! This is a controlled fixture: the parent test creates the durable session,
//! Activity, Agent, Goal/DAG, approval, and grant through native Forge APIs.
//! The Orchestration process owns only the remote session reads during the
//! actual HTTP execution.  This does not prove live ingress or session
//! issuance migration.

use super::*;

#[path = "standalone/native_rust_ci.rs"]
pub(crate) mod native_rust_ci;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use forge_control::AgentSessionResolveRequest;
use forge_domain::AuthenticatedPrincipal;
use forge_persistence::{AgentSessionCatalog, GlobalRegistry};
use serde_json::json;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const CHILD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const STARTUP_LOG_BYTES: usize = 16 * 1024;
const SECRET_MODE: u32 = 0o600;
const SESSION_SERVICE_SECRET: &str = "standalone-session-service-secret";

#[path = "standalone/workspace_stop_outage.rs"]
mod workspace_stop_outage;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CARGO_BIN_EXE_forge-backend and FORGE_ORCHESTRATION_BACKEND_BIN"]
async fn standalone_processes_use_remote_session_authority_without_local_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let forge_binary = PathBuf::from(env!("CARGO_BIN_EXE_forge-backend"));
    let orchestration_binary = required_binary("FORGE_ORCHESTRATION_BACKEND_BIN")?;
    let fixture = prepare_fixture()?;
    let result = run_cross_process(&fixture, &forge_binary, &orchestration_binary).await;
    let result = result.map_err(|error| {
        let backend = native_rust_ci::generated_after_disable::redacted_fixture_stderr(
            &fixture.root,
            "standalone-backend.stderr",
        );
        let session = native_rust_ci::generated_after_disable::redacted_fixture_stderr(
            &fixture.root,
            "standalone-session.stderr",
        );
        format!("{error}; backend_stderr={backend}; session_stderr={session}")
    });
    let fixture_shutdown = fixture.shutdown();
    result.map_err(std::io::Error::other)?;
    fixture_shutdown?;
    Ok(())
}

async fn run_cross_process(
    fixture: &Fixture,
    forge_binary: &Path,
    orchestration_binary: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let catalog_path = observe_session_catalog(fixture).await?;
    let destination_id = delegated_destination_id(fixture)?;
    let session_secret_path = fixture.root.join("standalone-session.secret");
    let api_secret_path = fixture.root.join("standalone-api.secret");
    let config_path = fixture.root.join("standalone-backend.json");
    let session_log_path = fixture.root.join("standalone-session.stdout");
    let backend_log_path = fixture.root.join("standalone-backend.stdout");
    write_private_file(&session_secret_path, SESSION_SERVICE_SECRET.as_bytes())?;
    write_private_file(&api_secret_path, SECRET.as_bytes())?;

    let mut session_authority = ChildGuard::spawn(
        orchestration_binary,
        session_authority_arguments(&catalog_path, &session_secret_path),
        session_log_path,
    )?;
    let session_address = session_authority
        .wait_for_endpoint(STARTUP_TIMEOUT, parse_session_endpoint)
        .await?;

    let config = json!({
        "listen": "127.0.0.1:0",
        "registry_path": fixture.root.join("registry.sqlite3"),
        "backend_id": BACKEND_ID,
        "issuer_id": ISSUER_ID,
        "destination_id": destination_id,
        "api_bearer_file": api_secret_path,
        "product_cache_root": fixture.root.join("product-cache"),
        "session_authority": session_address,
        "session_bearer_file": session_secret_path,
    });
    write_private_file(&config_path, serde_json::to_string(&config)?.as_bytes())?;

    let mut backend = ChildGuard::spawn(
        forge_binary,
        vec![
            OsString::from("serve"),
            config_path.clone().into_os_string(),
        ],
        backend_log_path,
    )?;
    let backend_address = backend
        .wait_for_endpoint(STARTUP_TIMEOUT, parse_backend_endpoint)
        .await?;

    let approved = prepare_approved_shell(fixture)?;
    assert_http_execution(backend_address, &approved, fixture).await?;
    assert_http_snapshot(backend_address, fixture).await?;
    let diff_id =
        lease_readback::assert_http_lease_and_mutation_readback(backend_address, fixture).await?;
    readback_enrichment::assert_http_readback_enrichment(backend_address, fixture, diff_id).await?;
    let authority = approved.authority.clone();
    let read_payload = json!({
        "authority": authority.clone(),
        "after_sequence": 0,
        "max_bytes": forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
        "max_events": forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    });
    execution_waits::assert_http_execution_wait(backend_address, &approved, fixture).await?;
    assert_durable_output(fixture, approved)?;
    planning_writes::assert_http_planning(backend_address, fixture).await?;
    effect_fact_reads::assert_http_effect_fact_outbox(backend_address, fixture).await?;
    assert_admin_lease_available(backend_address, fixture).await?;

    // Both children are stopped before the parent fixture releases its
    // native control, execution, and approval owners.
    assert_remote_session_outage(
        backend_address,
        fixture,
        &catalog_path,
        session_authority,
        authority,
        read_payload,
    )
    .await?;
    backend.shutdown(CHILD_SHUTDOWN_TIMEOUT).await?;
    Ok(())
}

async fn assert_remote_session_outage(
    backend_address: SocketAddr,
    fixture: &Fixture,
    catalog_path: &Path,
    session_authority: ChildGuard,
    authority: Value,
    read_payload: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    // The Orchestration process is the only live session-read authority for
    // the child backend. Stopping it must fail every exact execution command.
    let cut = work_cut_outage::prepare_while_live(backend_address, fixture).await?;
    session_authority.shutdown(CHILD_SHUTDOWN_TIMEOUT).await?;
    work_cut_outage::assert_after_provider_shutdown(backend_address, fixture, &cut).await?;
    assert!(
        catalog_path.is_file(),
        "the controlled session catalog vanished"
    );
    let local_session = resolve_live_session(fixture).await?;
    assert_eq!(local_session.id(), fixture.session_id);
    // Lease administration is service-authenticated and does not query logical
    // Agent sessions. Outage must not invent a local session fallback or block
    // this independent durable owner; session-bound operations below fail closed.
    assert_admin_lease_available(backend_address, fixture).await?;

    workspace_stop_outage::assert_unavailable_stop_owner(backend_address, fixture).await?;

    let (status, failed_read) =
        post_command(backend_address, "execution.read", read_payload).await?;
    assert_ne!(
        status, 200,
        "remote session authority outage must fail closed"
    );
    assert_eq!(failed_read["ok"], false);
    assert_eq!(status, 503);
    assert_eq!(
        failed_read["error"]["code"],
        json!(forge_backend::ErrorCode::DependencyUnavailable.as_str())
    );
    let (status, failed_get) = post_command(
        backend_address,
        "execution.get",
        json!({"authority": authority.clone()}),
    )
    .await?;
    assert_eq!(status, 503);
    assert_eq!(
        failed_get["error"]["code"],
        json!(forge_backend::ErrorCode::DependencyUnavailable.as_str())
    );
    let (status, failed_wait) = post_command(
        backend_address,
        "execution.wait",
        execution_waits::wait_payload(&authority, 0, 0),
    )
    .await?;
    assert_eq!(status, 503);
    assert_eq!(
        failed_wait["error"]["code"],
        json!(forge_backend::ErrorCode::DependencyUnavailable.as_str())
    );
    let cancel_payload = json!({
        "authority": authority,
    });
    let (status, failed_cancel) =
        post_command(backend_address, "execution.cancel", cancel_payload).await?;
    assert_eq!(status, 503);
    assert_eq!(
        failed_cancel["error"]["code"],
        json!(forge_backend::ErrorCode::DependencyUnavailable.as_str())
    );
    for reply in [&failed_read, &failed_get, &failed_wait, &failed_cancel] {
        assert_eq!(reply["error"]["retryable"], true);
        assert_eq!(reply["error"]["recovery_action"], "retry_when_available");
        assert_eq!(reply["error"]["readback"], Value::Null);
    }
    Ok(())
}

async fn assert_admin_lease_available(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = super::lease_readback::scope_json(fixture);
    let (status, observed) = post_command(
        address,
        "activity.get",
        json!({
            "scope": scope.clone(), "activity_id": fixture.activity_id.into_uuid(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "standalone lease observation: {observed}");
    let revision = observed["result"]["activity"]["lease_revision"]
        .as_i64()
        .ok_or("standalone Activity lease revision missing")?;
    assert_eq!(
        observed["result"]["activity"]["lease_owner_id"],
        json!(fixture.runtime_instance_id.into_uuid())
    );
    let (status, renewed) = post_command(
        address,
        "activity.lease.renew",
        json!({
            "scope": scope, "activity_id": fixture.activity_id.into_uuid(),
            "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
            "expected_lease_revision": revision, "duration_ms": 60_000,
        }),
    )
    .await?;
    assert_eq!(
        status, 200,
        "standalone administrative lease renewal: {renewed}"
    );
    assert_eq!(renewed["result"]["status"], "renewed");
    assert_eq!(
        renewed["result"]["activity"]["lease_revision"],
        revision + 1
    );
    Ok(())
}

async fn observe_session_catalog(fixture: &Fixture) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let resolved = resolve_live_session(fixture).await?;
    assert_eq!(resolved.id(), fixture.session_id);
    let registry_path = fixture.root.join("registry.sqlite3");
    let registry = GlobalRegistry::open_existing(&registry_path)?;
    let catalog_path = registry
        .database_path()
        .with_file_name("agent-sessions.sqlite3");
    let session_id = fixture.session_id;
    let result = tokio::task::spawn_blocking(move || {
        let catalog = AgentSessionCatalog::open_existing(&catalog_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "the controlled Agent session catalog is missing".to_owned())?;
        if catalog
            .resolve(session_id, AuthenticatedPrincipal::TrustedStdio)
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err(
                "the live Agent session authority did not observe the seeded session".to_owned(),
            );
        }
        Ok::<_, String>(catalog.path().to_owned())
    })
    .await?;
    result.map_err(|error| std::io::Error::other(error).into())
}

async fn resolve_live_session(
    fixture: &Fixture,
) -> Result<forge_domain::RegisteredAgentSession, Box<dyn std::error::Error>> {
    let client = fixture.client.clone();
    let request = AgentSessionResolveRequest {
        session_id: fixture.session_id,
        principal: AuthenticatedPrincipal::TrustedStdio,
    };
    let result = tokio::task::spawn_blocking(move || {
        client
            .agent_session_resolve(request)
            .map_err(|error| error.to_string())
    })
    .await?;
    result.map_err(|error| std::io::Error::other(error).into())
}

fn required_binary(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required for the ignored standalone test"))?;
    if !path.is_absolute() || !path.is_file() {
        return Err(format!("{name} must name an existing absolute binary").into());
    }
    Ok(path)
}

/// The headless Orchestration Backend owns this read-only Session authority.
/// No retired MCP transport, local Forge catalog fallback, or live service.
fn session_authority_arguments(catalog: &Path, secret: &Path) -> Vec<OsString> {
    vec![
        OsString::from("session-authority"),
        OsString::from("--port"),
        OsString::from("0"),
        OsString::from("--catalog"),
        catalog.as_os_str().to_owned(),
        OsString::from("--issuer-secret-file"),
        secret.as_os_str().to_owned(),
    ]
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(SECRET_MODE)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct ChildGuard {
    child: Option<Child>,
    stdout_log: PathBuf,
}

impl ChildGuard {
    fn spawn(
        binary: &Path,
        arguments: Vec<OsString>,
        stdout_log: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let stdout = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(SECRET_MODE)
            .open(&stdout_log)?;
        let stderr = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(SECRET_MODE)
            .open(stdout_log.with_extension("stderr"))?;
        let child = Command::new(binary)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        Ok(Self {
            child: Some(child),
            stdout_log,
        })
    }

    async fn wait_for_endpoint(
        &mut self,
        timeout: Duration,
        parse: fn(&str) -> Option<SocketAddr>,
    ) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            let bytes = read_bounded_log(&self.stdout_log).await?;
            let text = String::from_utf8_lossy(&bytes);
            if let Some(address) = parse(&text) {
                return Ok(address);
            }
            if let Some(child) = self.child.as_mut()
                && let Some(status) = child.try_wait()?
            {
                return Err(format!("child exited before endpoint startup: {status}").into());
            }
            if Instant::now() >= deadline {
                return Err("child endpoint startup exceeded its bound".into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn shutdown(mut self, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
        let Some(child) = self.child.take() else {
            return Ok(());
        };
        let result = tokio::task::spawn_blocking(move || terminate_child(child, timeout))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        result.map_err(std::io::Error::other).map_err(Into::into)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            let _ = terminate_child(child, Duration::from_millis(500));
        }
    }
}

async fn read_bounded_log(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = path.to_owned();
    let result = tokio::task::spawn_blocking(move || {
        let file = File::open(path).map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        file.take(u64::try_from(STARTUP_LOG_BYTES + 1).map_err(|error| error.to_string())?)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > STARTUP_LOG_BYTES {
            return Err("child startup log exceeded its bound".to_owned());
        }
        Ok::<_, String>(bytes)
    })
    .await?;
    result.map_err(|error| std::io::Error::other(error).into())
}

fn terminate_child(mut child: Child, timeout: Duration) -> Result<(), String> {
    let pid = child.id().to_string();
    let _ = Command::new("/bin/kill")
        .args([OsStr::new("-INT"), OsStr::new(pid.as_str())])
        .status();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            if status.success() {
                return Ok(());
            }
            return Err(format!(
                "owned child exited unsuccessfully after SIGINT: {status}"
            ));
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill().map_err(|error| error.to_string())?;
    let kill_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("owned child required forced termination".to_owned());
        }
        if Instant::now() >= kill_deadline {
            return Err("owned child did not exit after bounded cleanup".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn parse_session_endpoint(output: &str) -> Option<SocketAddr> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("session_authority_endpoint=http://"))
        .and_then(|value| value.trim().parse().ok())
}

fn parse_backend_endpoint(output: &str) -> Option<SocketAddr> {
    output.lines().find_map(|line| line.trim().parse().ok())
}
