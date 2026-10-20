//! Ignored native-host proof for the standalone Rust CI capability.
//!
//! The test deliberately keeps the durable Activity/Agent/Goal/DAG/session
//! fixture in the parent module while the standalone backend owns the actual
//! project-command admission and Rust CI process.  It requires an operator
//! supplied real host home and the headless Orchestration Backend's independent
//! Session authority; no local execution fallback is accepted.

use super::*;

#[path = "generated_after_disable.rs"]
pub(super) mod generated_after_disable;

use forge_control::{
    AgentExecutionAuthorityRequest, FileActivityScope, ProjectCommandId, ProjectCommandListRequest,
    SubmitExecutionForApproval,
};
use forge_domain::{
    ExecutionCommandId, ExecutionOutputCursor, ExecutionOutputEvent, ProjectCommandEvidence,
};
use serde_json::{Value, json};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

const NATIVE_RUST_CI_HOME_ENV: &str = "FORGE_NATIVE_RUST_CI_HOME";
const NATIVE_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const NATIVE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const NATIVE_MARKER: &str = "native-rust-ci-marker";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a real host Rust CI home and FORGE_ORCHESTRATION_BACKEND_BIN"]
async fn standalone_native_rust_ci_project_command_reaches_verified_terminal()
-> Result<(), Box<dyn std::error::Error>> {
    run_native_fixture().await
}

async fn run_native_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let forge_binary = PathBuf::from(env!("CARGO_BIN_EXE_forge-backend"));
    let orchestration_binary = required_binary("FORGE_ORCHESTRATION_BACKEND_BIN")?;
    let host_home = required_canonical_host_home()?;
    let cache = NativeCacheGuard::new(&host_home)?;
    let fixture = prepare_fixture()?;
    let result = run_native_rust_ci(
        &fixture,
        &forge_binary,
        &orchestration_binary,
        &host_home,
        &cache,
    )
    .await;
    // Published input must remain sealed throughout the assertions above.
    // Restore only directories in this test's exact verification namespace
    // after its standalone child owners have joined, so fixture removal can
    // unlink those retained artifacts. Production retention is unchanged.
    let snapshot_cleanup = restore_fixture_verification_directories(
        &fixture
            .workspace_root
            .join(".heterarchy-forge/artifacts/verification"),
        0,
    );
    let fixture_shutdown = fixture.shutdown();
    let cache_shutdown = cache.remove();
    result?;
    snapshot_cleanup?;
    fixture_shutdown.map_err(|error| format!("native fixture shutdown failed: {error}"))?;
    cache_shutdown.map_err(|error| format!("native cache shutdown failed: {error}"))?;
    Ok(())
}

pub(crate) fn restore_fixture_verification_directories(
    path: &Path,
    depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    if depth > forge_workspace::MAX_FILE_PATH_COMPONENTS + 2 {
        return Err("native verification fixture cleanup exceeded its depth bound".into());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(());
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(metadata.permissions().mode() | 0o700),
    )?;
    for entry in fs::read_dir(path)? {
        restore_fixture_verification_directories(&entry?.path(), depth + 1)?;
    }
    Ok(())
}

pub(crate) struct NativeCacheGuard {
    namespace: PathBuf,
    local_cache_root: PathBuf,
    selected_cache_root: PathBuf,
}

impl NativeCacheGuard {
    pub(crate) fn new(host_home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let cache_base = host_home.join("Library").join("Caches");
        let metadata = fs::symlink_metadata(&cache_base)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("the native Rust CI cache base must be a real directory".into());
        }
        if fs::canonicalize(&cache_base)? != cache_base {
            return Err("the native Rust CI cache base must be canonical".into());
        }
        let namespace = cache_base.join(format!("forge-native-rust-ci-{}", Uuid::now_v7()));
        fs::create_dir(&namespace)?;
        let namespace = fs::canonicalize(namespace)?;
        let local_cache_root = namespace.join("rust-ci");
        let selected_cache_root = namespace.join("rust-ci-1.98.0-local");
        Ok(Self {
            namespace,
            local_cache_root,
            selected_cache_root,
        })
    }

    pub(crate) fn remove(self) -> Result<(), Box<dyn std::error::Error>> {
        fs::remove_dir_all(self.namespace)?;
        Ok(())
    }
}

async fn run_native_rust_ci(
    fixture: &Fixture,
    forge_binary: &Path,
    orchestration_binary: &Path,
    host_home: &Path,
    cache: &NativeCacheGuard,
) -> Result<(), Box<dyn std::error::Error>> {
    write_native_workspace_fixture(fixture)?;
    let original_source = ["Cargo.toml", "Cargo.lock", "Makefile", "src/main.rs"]
        .into_iter()
        .map(|path| fs::read(fixture.workspace_root.join(path)).map(|bytes| (path, bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    let runtime = start_native_backend(
        fixture,
        forge_binary,
        orchestration_binary,
        host_home,
        cache,
    )
    .await?;
    let backend_address = runtime.backend_address;
    let approved = prepare_native_project_approval(fixture)?;
    let begin = native_execution_begin_payload(&approved);
    let (status, response) = post_command(backend_address, "execution.begin", begin).await?;
    assert_eq!(status, 200, "native project begin response: {response}");
    assert_eq!(response["ok"], true);
    assert_eq!(
        response["result"]["execution_id"],
        json!(approved.execution_id.into_uuid())
    );
    wait_http_terminal(backend_address, &approved).await?;
    assert_native_output(fixture, &approved)?;
    wait_http_verification(backend_address, fixture, approved.execution_id).await?;
    assert_http_observation(backend_address, fixture, &approved).await?;
    assert_native_retention(fixture, cache, &original_source)?;

    runtime.shutdown().await?;
    Ok(())
}

pub(crate) struct NativeBackendRuntime {
    session_authority: ChildGuard,
    backend: ChildGuard,
    backend_address: SocketAddr,
}

impl NativeBackendRuntime {
    pub(crate) fn address(&self) -> SocketAddr {
        self.backend_address
    }

    pub(crate) async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let backend = self.backend.shutdown(CHILD_SHUTDOWN_TIMEOUT).await;
        let session = self
            .session_authority
            .shutdown(CHILD_SHUTDOWN_TIMEOUT)
            .await;
        backend?;
        session?;
        Ok(())
    }
}

pub(crate) async fn start_native_backend(
    fixture: &Fixture,
    forge_binary: &Path,
    orchestration_binary: &Path,
    host_home: &Path,
    cache: &NativeCacheGuard,
) -> Result<NativeBackendRuntime, Box<dyn std::error::Error>> {
    start_backend(
        fixture,
        forge_binary,
        orchestration_binary,
        "native-rust-ci",
        cache.selected_cache_root.clone(),
        Some((
            host_home,
            cache.local_cache_root.as_path(),
            cache.selected_cache_root.as_path(),
        )),
    )
    .await
}

pub(crate) async fn start_package_backend(
    fixture: &Fixture,
    forge_binary: &Path,
    orchestration_binary: &Path,
) -> Result<NativeBackendRuntime, Box<dyn std::error::Error>> {
    let product_cache_root = fixture.root.join("research-package-product-cache");
    fs::create_dir_all(&product_cache_root)?;
    start_backend(
        fixture,
        forge_binary,
        orchestration_binary,
        "research-package",
        product_cache_root,
        None,
    )
    .await
}

async fn start_backend(
    fixture: &Fixture,
    forge_binary: &Path,
    orchestration_binary: &Path,
    namespace: &str,
    product_cache_root: PathBuf,
    rust_ci: Option<(&Path, &Path, &Path)>,
) -> Result<NativeBackendRuntime, Box<dyn std::error::Error>> {
    let catalog_path = observe_session_catalog(fixture).await?;
    let destination_id = delegated_destination_id(fixture)?;
    let session_secret_path = fixture.root.join(format!("{namespace}-session.secret"));
    let api_secret_path = fixture.root.join(format!("{namespace}-api.secret"));
    let session_log_path = fixture.root.join(format!("{namespace}-session.stdout"));
    let backend_log_path = fixture.root.join(format!("{namespace}-backend.stdout"));
    let config_path = fixture.root.join(format!("{namespace}-backend.json"));
    write_private_file(&session_secret_path, SESSION_SERVICE_SECRET.as_bytes())?;
    write_private_file(&api_secret_path, SECRET.as_bytes())?;

    let mut session_authority = ChildGuard::spawn(
        orchestration_binary,
        session_authority_arguments(&catalog_path, &session_secret_path),
        session_log_path.clone(),
    )?;
    let session_address = match session_authority
        .wait_for_endpoint(STARTUP_TIMEOUT, parse_session_endpoint)
        .await
    {
        Ok(address) => address,
        Err(error) => {
            let stderr = fs::read_to_string(session_log_path.with_extension("stderr"))?;
            return Err(format!(
                "native session authority startup failed: {error}; stderr={stderr}"
            )
            .into());
        }
    };
    let mut config = json!({
        "listen": "127.0.0.1:0",
        "registry_path": fixture.root.join("registry.sqlite3"),
        "backend_id": BACKEND_ID,
        "issuer_id": ISSUER_ID,
        "destination_id": destination_id,
        "api_bearer_file": api_secret_path,
        "product_cache_root": product_cache_root.clone(),
        "session_authority": session_address,
        "session_bearer_file": session_secret_path,
    });
    if let Some((host_home, local_cache_root, _selected_cache_root)) = rust_ci {
        config["rust_ci"] = json!({
            "host_home": host_home,
            "local_cache_root": local_cache_root,
        });
    }
    write_private_file(&config_path, serde_json::to_string(&config)?.as_bytes())?;

    let mut backend = ChildGuard::spawn(
        forge_binary,
        vec![OsString::from("serve"), config_path.into_os_string()],
        backend_log_path.clone(),
    )?;
    let backend_address = match backend
        .wait_for_endpoint(STARTUP_TIMEOUT, parse_backend_endpoint)
        .await
    {
        Ok(address) => address,
        Err(error) => {
            let stderr = fs::read_to_string(backend_log_path.with_extension("stderr"))
                .unwrap_or_else(|read_error| format!("stderr unavailable: {read_error}"));
            return Err(format!(
                "{namespace} backend startup failed; capability preparation or authority admission was rejected: {error}; stderr={stderr}"
            )
            .into());
        }
    };
    if let Some((host_home, _local_cache_root, selected_cache_root)) = rust_ci {
        assert_selected_cache_paths(host_home, selected_cache_root)?;
    }
    Ok(NativeBackendRuntime {
        session_authority,
        backend,
        backend_address,
    })
}

async fn assert_http_observation(
    address: SocketAddr,
    fixture: &Fixture,
    approved: &NativeApprovedProject,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = json!({"scope":approved.authority["scope"],"activity_id":fixture.activity_id.into_uuid(),
        "goal":{"goal_id":approved.authority["goal_id"],"expected_revision":approved.authority["expected_goal_revision"]},"limit":256});
    let (status, inventory) = post_command(address, "execution.inventory", payload.clone()).await?;
    assert_eq!(status, 200, "inventory={inventory}");
    assert_eq!(inventory["ok"], true);
    assert_eq!(inventory["result"]["entry_count"], 1);
    assert_eq!(inventory["result"]["has_more"], false);
    let entry = &inventory["result"]["entries"][0];
    assert_eq!(
        entry["execution_id"],
        json!(approved.execution_id.into_uuid())
    );
    assert_eq!(entry["request_digest"], approved.expected_digest);
    assert_eq!(entry["verification"]["disposition"], "accepted");
    let _fingerprint = entry["verification"]["input"]["fingerprint"]
        .as_str()
        .ok_or("missing real input fingerprint")?;
    payload
        .as_object_mut()
        .ok_or("observation payload shape")?
        .remove("limit");
    payload["execution_id"] = json!(approved.execution_id.into_uuid());
    payload["after_sequence"] = json!(0);
    payload["max_bytes"] = json!(64 * 1024);
    payload["max_events"] = json!(128);
    let (status, observed) = post_command(address, "execution.observe", payload).await?;
    assert_eq!(status, 200, "observe={observed}");
    assert_eq!(observed["ok"], true);
    assert_eq!(&observed["result"]["record"], entry);
    assert!(
        observed["result"]["output"]["event_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    Ok(())
}

fn assert_native_retention(
    fixture: &Fixture,
    cache: &NativeCacheGuard,
    original: &[(&str, Vec<u8>)],
) -> Result<(), Box<dyn std::error::Error>> {
    for (path, bytes) in original {
        assert_eq!(&fs::read(fixture.workspace_root.join(path))?, bytes);
    }
    assert_eq!(
        fs::read_dir(cache.selected_cache_root.join("runtime/executions"))?.count(),
        0,
        "a terminal confirmed-reap launch must remove its ephemeral source replica"
    );
    Ok(())
}

fn write_native_workspace_fixture(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(fixture.workspace_root.join("src"))?;
    fs::write(
        fixture.workspace_root.join("Cargo.toml"),
        b"[package]\nname = \"native-rust-ci-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )?;
    fs::write(
        fixture.workspace_root.join("Cargo.lock"),
        b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"native-rust-ci-fixture\"\nversion = \"0.1.0\"\n",
    )?;
    fs::write(
        fixture.workspace_root.join("src/main.rs"),
        b"fn main() { println!(\"native-rust-ci-fixture\"); }\n",
    )?;
    fs::write(
        fixture.workspace_root.join("Makefile"),
        b".PHONY: ci\nci:\n\trustc --version\n\tcargo check --locked --offline\n\tprintf 'native-rust-ci-marker\\n'\n",
    )?;
    Ok(())
}

pub(crate) fn required_canonical_host_home() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = env::var_os(NATIVE_RUST_CI_HOME_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{NATIVE_RUST_CI_HOME_ENV} is required for native Rust CI"))?;
    if !path.is_absolute() {
        return Err(format!("{NATIVE_RUST_CI_HOME_ENV} must be absolute").into());
    }
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{NATIVE_RUST_CI_HOME_ENV} must be a real directory").into());
    }
    let canonical = fs::canonicalize(&path)?;
    if canonical != path {
        return Err(format!("{NATIVE_RUST_CI_HOME_ENV} must be canonical").into());
    }
    Ok(canonical)
}

fn assert_selected_cache_paths(
    host_home: &Path,
    selected_cache_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let selected = fs::canonicalize(selected_cache_root)?;
    assert_eq!(selected, selected_cache_root);
    assert!(selected.join("bin/rustup").exists());
    assert!(selected.join("rustup-home/settings.toml").exists());
    assert!(selected.join("cargo-home/registry").exists());
    let selected_device = fs::metadata(&selected)?.dev();
    let host_device = fs::metadata(host_home)?.dev();
    assert_eq!(selected_device, host_device);
    Ok(())
}

struct NativeApprovedProject {
    execution_id: forge_domain::ExecutionId,
    authority_request: AgentExecutionAuthorityRequest,
    authority: Value,
    command_id: ExecutionCommandId,
    catalog_fingerprint: String,
    grant: forge_domain::ExecutionGrant,
    issued_at: forge_domain::TimestampMillis,
    expected_digest: String,
    project_command: ProjectCommandEvidence,
}

fn prepare_native_project_approval(
    fixture: &Fixture,
) -> Result<NativeApprovedProject, Box<dyn std::error::Error>> {
    prepare_native_project_approval_for(fixture, "make:ci")
}

fn prepare_native_project_approval_for(
    fixture: &Fixture,
    project_command: &str,
) -> Result<NativeApprovedProject, Box<dyn std::error::Error>> {
    let execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
    let project_command_id = ProjectCommandId::new(project_command.to_owned())?;
    let command_id = ExecutionCommandId::new(project_command.to_owned())?;
    let snapshot = fixture
        .client
        .project_command_list(ProjectCommandListRequest {
            scope: fixture.scope.clone(),
            activity: FileActivityScope {
                activity_id: fixture.activity_id,
                runtime_instance_id: fixture.runtime_instance_id,
                observed_at: timestamp_now()?,
            },
        })?;
    let resolved = snapshot.resolve_execution(&project_command_id, execution_id)?;
    let evidence = ProjectCommandEvidence::new(resolved.class(), resolved.fingerprint());
    let authority_request = AgentExecutionAuthorityRequest {
        session_id: fixture.session_id,
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
        agent_id: fixture.agent_id,
        expected_revision: fixture.agent_revision,
        principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
        attribution: fixture.attribution,
        command_id: command_id.clone(),
    };
    let submission = fixture.approval.client().submit_execution(
        SubmitExecutionForApproval::project_command(
            fixture.scope.clone(),
            fixture.activity_id,
            fixture.runtime_instance_id,
            resolved.request().clone(),
            evidence,
        )?
        .with_goal_node(fixture.attribution)
        .with_agent_authority(authority_request.clone()),
    )?;
    assert_eq!(
        submission.status(),
        forge_control::ApprovalSubmissionStatus::Pending
    );
    let pending = fixture
        .client
        .approval_get(fixture.scope.clone(), submission.approval_id())?
        .map(|(approval, _)| approval)
        .ok_or("native project approval row missing")?;
    let issued_at = timestamp_now()?;
    let grant = fixture
        .client
        .approve_once(forge_control::ApprovalOnceRequest {
            scope: fixture.scope.clone(),
            approval_id: pending.id(),
            expected_revision: pending.revision(),
            grant_id: forge_domain::ExecutionGrantId::from_uuid(Uuid::now_v7()),
            observed_at: add_millis(issued_at, 1)?,
            grant_expires_at: add_millis(issued_at, 60_000)?,
        })?
        .1;
    Ok(NativeApprovedProject {
        execution_id,
        authority_request,
        authority: authority_json(fixture, execution_id, &command_id, issued_at),
        command_id,
        catalog_fingerprint: forge_backend::events::hex_encode(
            resolved.fingerprint().hash().as_bytes(),
        ),
        grant,
        issued_at,
        expected_digest: forge_backend::events::hex_encode(
            pending.request().request_digest().as_bytes(),
        ),
        project_command: evidence,
    })
}

fn native_execution_begin_payload(approved: &NativeApprovedProject) -> Value {
    json!({
        "authority": approved.authority.clone(),
        "grant_id": approved.grant.id().into_uuid(),
        "expected_grant_revision": approved.grant.revision().get(),
        "mode": {
            "kind": "sealed_project_command",
            "command_id": approved.command_id.as_str(),
            "expected_catalog_fingerprint": approved.catalog_fingerprint.clone(),
        },
        "admission": {
            "backend_id": BACKEND_ID,
            "issuer": ISSUER_ID,
            "expected_digest": approved.expected_digest.clone(),
            "issued_at_ms": approved.issued_at.get(),
            "expires_at_ms": approved.grant.expires_at().get(),
        }
    })
}

async fn wait_http_terminal(
    address: SocketAddr,
    approved: &NativeApprovedProject,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + NATIVE_WAIT_TIMEOUT;
    loop {
        let (status, response) = post_command(
            address,
            "execution.get",
            json!({"authority": approved.authority.clone()}),
        )
        .await?;
        assert_eq!(status, 200, "native execution.get response: {response}");
        assert_eq!(response["ok"], true);
        if response["result"]["terminal"] == json!(true) {
            if response["result"]["state"] != json!("completed") {
                let (_,output)=post_command(address,"execution.read",json!({"authority":approved.authority,
                    "after_sequence":0,"max_bytes":forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,"max_events":forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS})).await?;
                return Err(
                    format!("native Rust CI terminal: {response}; output: {output}").into(),
                );
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("native Rust CI execution did not reach terminal state".into());
        }
        sleep(NATIVE_POLL_INTERVAL).await;
    }
}

fn assert_native_output(
    fixture: &Fixture,
    approved: &NativeApprovedProject,
) -> Result<(), Box<dyn std::error::Error>> {
    let read = fixture.client.execution_read_authorized(
        approved.authority_request.clone(),
        approved.execution_id,
        ExecutionOutputCursor::initial(approved.execution_id),
        forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
        forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    )?;
    let mut output = Vec::new();
    for event in read.output().events() {
        if let ExecutionOutputEvent::Chunk(chunk) = event {
            output.extend_from_slice(chunk.bytes());
        }
    }
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("rustc 1.98.0"), "native output: {output}");
    assert!(
        output.contains("Checking native-rust-ci-fixture"),
        "native output: {output}"
    );
    assert!(output.contains(NATIVE_MARKER), "native output: {output}");
    let record = fixture
        .client
        .execution_get_authorized(approved.authority_request.clone(), approved.execution_id)?;
    assert_eq!(record.state(), forge_domain::ExecutionState::Completed);
    Ok(())
}

async fn wait_http_verification(
    address: SocketAddr,
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + NATIVE_WAIT_TIMEOUT;
    loop {
        let (status, response) = post_command(
            address,
            "verification.projection",
            json!({"scope": native_scope_json(fixture)}),
        )
        .await?;
        assert_eq!(status, 200, "native verification projection: {response}");
        assert_eq!(response["ok"], true);
        if let Some(entry) = response["result"]["entries"]
            .as_array()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry["execution_id"] == json!(execution_id.into_uuid()))
            })
        {
            assert_eq!(entry["command_id"], json!("make:ci"));
            assert_eq!(entry["state"], json!("passed"));
            assert_eq!(entry["disposition"], json!("accepted"));
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("native Rust CI verification did not reach accepted disposition".into());
        }
        sleep(NATIVE_POLL_INTERVAL).await;
    }
}

fn native_scope_json(fixture: &Fixture) -> Value {
    let locator = fixture.scope.locator();
    json!({
        "workspace_id": fixture.scope.workspace_id().into_uuid(),
        "workspace_revision": fixture.scope.workspace_revision().get(),
        "locator": {
            "location_id": locator.location_id().into_uuid(),
            "expected_revision": locator.expected_revision().get(),
            "relative_root": locator.relative_root().to_string_lossy(),
        }
    })
}
