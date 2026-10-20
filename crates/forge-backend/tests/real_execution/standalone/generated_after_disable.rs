//! Actual generated-package execution after a real Location disable.

use super::*;

use forge_domain::GeneratedPackageManifest;
use forge_execution::RustCiGeneratedPackageOutput;
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const PACKAGE_HELPER_ENV: &str = "FORGE_NATIVE_PACKAGE_HELPER";
const PACKAGE_STARTED_MARKER: &str = "generated-start.marker";
const PACKAGE_RELEASE_MARKER: &str = "release.marker";
const PACKAGE_STDOUT_MARKER: &str = "generated-after-disable-output";
const PACKAGE_BYTES: &[u8] = b"generated-package-after-disable\n";
type SourceSnapshot = Vec<(&'static str, Vec<u8>)>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires real host Rust CI, installed package helper, and Orchestration authority"]
async fn generated_package_execution_survives_location_disable()
-> Result<(), Box<dyn std::error::Error>> {
    let host_home = required_canonical_host_home()?;
    let cache = NativeCacheGuard::new(&host_home)?;
    let fixture = match prepare_fixture() {
        Ok(fixture) => fixture,
        Err(error) => {
            cache.remove()?;
            return Err(error);
        }
    };
    let result = run_generated_fixture(&fixture, &host_home, &cache).await;
    let snapshot_cleanup = super::restore_fixture_verification_directories(
        &fixture
            .workspace_root
            .join(".heterarchy-forge/artifacts/verification"),
        0,
    );
    let local_cleanup = super::super::super::admitted_journal::shutdown_disabled_fixture(fixture);
    let cache_cleanup = cache.remove();
    let failures: Vec<_> = [
        ("execution", result),
        ("snapshot cleanup", snapshot_cleanup),
        ("local cleanup", local_cleanup),
        ("cache cleanup", cache_cleanup),
    ]
    .into_iter()
    .filter_map(|(phase, result)| result.err().map(|error| format!("{phase}: {error}")))
    .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

async fn run_generated_fixture(
    fixture: &Fixture,
    host_home: &Path,
    cache: &NativeCacheGuard,
) -> Result<(), Box<dyn std::error::Error>> {
    write_generated_workspace_fixture(fixture)?;
    let original_source = capture_source(fixture)?;
    let forge_binary = PathBuf::from(env!("CARGO_BIN_EXE_forge-backend"));
    let orchestration_binary = required_binary("FORGE_ORCHESTRATION_BACKEND_BIN")?;
    let bundle_backend = copy_native_bundle(fixture, &forge_binary)?;
    let runtime = start_native_backend(
        fixture,
        &bundle_backend,
        &orchestration_binary,
        host_home,
        cache,
    )
    .await?;
    let result = generated_http_flow(fixture, cache, &original_source, &runtime).await;
    let shutdown = shutdown_generated_runtime(runtime).await;
    let diagnostics = if result.is_err() || shutdown.is_err() {
        format!(
            "backend_stderr={} session_stderr={}",
            redacted_fixture_stderr(&fixture.root, "native-rust-ci-backend.stderr"),
            redacted_fixture_stderr(&fixture.root, "native-rust-ci-session.stderr"),
        )
    } else {
        String::new()
    };
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => {
            Err(format!("{error}; {diagnostics}").into())
        }
        (Err(execution), Err(shutdown)) => Err(format!(
            "generated execution: {execution}; shutdown: {shutdown}; {diagnostics}"
        )
        .into()),
    }
}

pub(in super::super) fn redacted_fixture_stderr(fixture_root: &Path, name: &str) -> String {
    let tail = (|| -> std::io::Result<String> {
        let mut file = File::open(fixture_root.join(name))?;
        let start = file.metadata()?.len().saturating_sub(16 * 1024);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.take(16 * 1024).read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })();
    match tail {
        Ok(tail) => tail
            .replace(SECRET, "<redacted>")
            .replace(SESSION_SERVICE_SECRET, "<redacted>")
            .replace(fixture_root.to_string_lossy().as_ref(), "<fixture>"),
        Err(error) => format!("unavailable:{:?}", error.kind()),
    }
}

#[test]
fn generated_failure_stderr_is_bounded_and_redacts_fixture_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("forge-native-stderr-{}", Uuid::now_v7()));
    fs::create_dir(&root)?;
    let mut contents = "prefix-excluded".repeat(2_048);
    write!(
        contents,
        "\n{SECRET}\n{SESSION_SERVICE_SECRET}\n{}",
        root.display()
    )?;
    fs::write(root.join("backend.stderr"), contents)?;
    let tail = redacted_fixture_stderr(&root, "backend.stderr");
    let missing = redacted_fixture_stderr(&root, "missing.stderr");
    fs::remove_dir_all(&root)?;
    assert!(!tail.contains(SECRET));
    assert!(!tail.contains(SESSION_SERVICE_SECRET));
    assert!(!tail.contains(root.to_string_lossy().as_ref()));
    assert!(tail.len() <= 16 * 1024);
    assert!(tail.contains("<redacted>"));
    assert!(tail.contains("<fixture>"));
    assert_eq!(missing, "unavailable:NotFound");
    Ok(())
}

async fn shutdown_generated_runtime(
    runtime: NativeBackendRuntime,
) -> Result<(), Box<dyn std::error::Error>> {
    let NativeBackendRuntime {
        backend,
        session_authority,
        ..
    } = runtime;
    let backend_result = backend.shutdown(CHILD_SHUTDOWN_TIMEOUT).await;
    let session_result = session_authority.shutdown(CHILD_SHUTDOWN_TIMEOUT).await;
    match (backend_result, session_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(backend), Err(session)) => {
            Err(format!("backend shutdown: {backend}; session shutdown: {session}").into())
        }
    }
}

async fn generated_http_flow(
    fixture: &Fixture,
    cache: &NativeCacheGuard,
    original_source: &[(&str, Vec<u8>)],
    runtime: &NativeBackendRuntime,
) -> Result<(), Box<dyn std::error::Error>> {
    let approved = prepare_native_project_approval_for(fixture, "make:package")?;
    let (status, response) = post_command(
        runtime.backend_address,
        "execution.begin",
        native_execution_begin_payload(&approved),
    )
    .await?;
    if status != 200 || response["ok"] != true {
        return Err(format!("generated execution admission failed: {status} {response}").into());
    }

    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("generated fixture layout missing")?;
    let fingerprint = layout.root_fingerprint()?;
    let generated_output = wait_for_generated_output(
        fixture,
        cache,
        fixture.scope.workspace_id(),
        fingerprint,
        approved.execution_id,
    )
    .await?;
    wait_for_marker(
        &generated_output.root().join(PACKAGE_STARTED_MARKER),
        fixture,
        approved.execution_id,
    )
    .await?;
    assert_http_running(runtime.backend_address, &approved).await?;

    let stale = prepare_native_project_approval_for(fixture, "make:ci")?;
    disable_location(runtime.backend_address, fixture).await?;
    assert_stale_admission_has_no_row(runtime.backend_address, fixture, &stale).await?;
    write_synced_marker(
        &generated_output.root().join(PACKAGE_RELEASE_MARKER),
        b"release\n",
    )?;

    let (record, durable_output, manifest) = wait_for_local_terminal(
        &fixture.workspace_root,
        approved.execution_id,
        generated_output.root(),
    )
    .await?;
    if record.id() != approved.execution_id
        || record.workspace_id() != fixture.scope.workspace_id()
        || record.activity_id() != fixture.activity_id
        || forge_backend::events::hex_encode(record.request_digest().as_bytes())
            != approved.expected_digest
        || record.state() != forge_domain::ExecutionState::Completed
        || record
            .outcome()
            .and_then(forge_domain::ExecutionOutcome::exit_code)
            != Some(0)
    {
        return Err(format!(
            "generated execution was not successful: {:?}",
            record.state()
        )
        .into());
    }
    let manifest = manifest.ok_or("generated package manifest missing")?;
    assert_generated_provenance(&record, &approved)?;
    assert_manifest_identity(&manifest, fixture, approved.execution_id, &generated_output)?;
    assert_output_marker(&durable_output)?;
    assert_package_files(&generated_output, &manifest)?;
    assert_source_unchanged(fixture, original_source)?;
    assert_location_disabled(fixture)?;
    generated_output.cleanup_verified(
        *manifest.content_hash().as_bytes(),
        manifest.byte_count().get(),
    )?;
    Ok(())
}

fn assert_generated_provenance(
    record: &forge_domain::RegisteredExecution,
    approved: &NativeApprovedProject,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = record
        .provenance()
        .ok_or("generated execution provenance missing")?;
    let expected = &approved.authority_request;
    if actual.session_id() != Some(expected.session_id)
        || actual.agent_id() != expected.agent_id
        || actual.agent_revision() != expected.expected_revision
        || actual.principal() != expected.principal
        || actual.attribution() != expected.attribution
        || actual.command_id() != &expected.command_id
        || actual.project_command() != Some(approved.project_command)
    {
        return Err(
            "generated execution lost original Agent/session/Goal/DAG/command provenance".into(),
        );
    }
    Ok(())
}

fn write_generated_workspace_fixture(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    super::write_native_workspace_fixture(fixture)?;
    let mut makefile = OpenOptions::new()
        .append(true)
        .open(fixture.workspace_root.join("Makefile"))?;
    makefile.write_all(
        b"\n.PHONY: package\npackage:\n\t@mkdir -p \"$$FORGE_PACKAGE_OUTPUT_ROOT/dist\"\n\t@printf 'generated-package-started\\n' > \"$$FORGE_PACKAGE_OUTPUT_ROOT/generated-start.marker\"\n\t@tries=0; while [ ! -f \"$$FORGE_PACKAGE_OUTPUT_ROOT/release.marker\" ]; do tries=$$((tries+1)); if [ $$tries -gt 600 ]; then exit 77; fi; sleep 0.1; done\n\t@rm -f \"$$FORGE_PACKAGE_OUTPUT_ROOT/generated-start.marker\" \"$$FORGE_PACKAGE_OUTPUT_ROOT/release.marker\"\n\t@printf 'generated-package-after-disable\\n' > \"$$FORGE_PACKAGE_OUTPUT_ROOT/dist/Heterarchy-Forge.pkg\"\n\t@printf 'generated-after-disable-output\\n'\n",
    )?;
    makefile.sync_all()?;
    Ok(())
}

fn capture_source(fixture: &Fixture) -> Result<SourceSnapshot, Box<dyn std::error::Error>> {
    ["Cargo.toml", "Cargo.lock", "Makefile", "src/main.rs"]
        .into_iter()
        .map(|path| Ok((path, fs::read(fixture.workspace_root.join(path))?)))
        .collect()
}

fn copy_native_bundle(
    fixture: &Fixture,
    backend: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let helper = required_canonical_executable(PACKAGE_HELPER_ENV)?;
    let backend = fs::canonicalize(backend)?;
    verify_executable(&backend)?;
    let bundle = fixture.root.join("generated-package-bundle");
    fs::create_dir(&bundle)?;
    let bundle = fs::canonicalize(bundle)?;
    let copied_backend = bundle.join("forge-backend");
    let copied_helper = bundle.join("cloudflared");
    copy_verified(&backend, &copied_backend)?;
    copy_verified(&helper, &copied_helper)?;
    Ok(copied_backend)
}

fn required_canonical_executable(env_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = std::env::var_os(env_name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{env_name} is required"))?;
    if !path.is_absolute() {
        return Err(format!("{env_name} must be absolute").into());
    }
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(format!("{env_name} must be a real regular executable").into());
    }
    let canonical = fs::canonicalize(&path)?;
    if canonical != path || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("{env_name} must be canonical and executable").into());
    }
    Ok(canonical)
}

fn verify_executable(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o111 == 0
        || fs::canonicalize(path)? != path
    {
        return Err(format!("bundle executable identity is invalid: {}", path.display()).into());
    }
    Ok(())
}

fn copy_verified(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let source_digest = digest_file(source)?;
    fs::copy(source, destination)?;
    verify_executable(destination)?;
    if digest_file(destination)? != source_digest {
        return Err(format!("copied executable bytes differ: {}", destination.display()).into());
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<([u8; 32], u64), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read)?)
            .ok_or("copied executable byte count overflowed")?;
    }
    Ok((hasher.finalize().into(), bytes))
}

async fn wait_for_generated_output(
    fixture: &Fixture,
    cache: &NativeCacheGuard,
    workspace_id: forge_domain::WorkspaceId,
    fingerprint: forge_domain::WorkspaceRootFingerprint,
    execution_id: forge_domain::ExecutionId,
) -> Result<RustCiGeneratedPackageOutput, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(output) = RustCiGeneratedPackageOutput::open_existing(
            &cache.selected_cache_root,
            workspace_id,
            fingerprint,
            execution_id,
        )? {
            return Ok(output);
        }
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("Workspace layout missing before generated output")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let record = store
            .get_execution(execution_id)?
            .ok_or("execution missing before generated output")?;
        if record.state().is_terminal() || Instant::now() >= deadline {
            let output = store.read_execution_output_events(
                forge_domain::ExecutionOutputCursor::initial(execution_id),
                forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
                4,
            )?;
            let bytes: Vec<_> = output
                .events()
                .iter()
                .filter_map(|event| match event {
                    forge_domain::ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
                    forge_domain::ExecutionOutputEvent::Gap(_) => None,
                })
                .flatten()
                .copied()
                .collect();
            return Err(format!(
                "generated output unavailable: state={:?} failure={:?} exit={:?} output={}",
                record.state(),
                record.failure_code(),
                record
                    .outcome()
                    .and_then(forge_domain::ExecutionOutcome::exit_code),
                String::from_utf8_lossy(&bytes)
            )
            .into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_marker(
    path: &Path,
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(metadata) = fs::symlink_metadata(path)
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
        {
            let bytes = fs::read(path)?;
            if bytes.len() <= 256 && bytes == b"generated-package-started\n" {
                return Ok(());
            }
            if !bytes.is_empty() {
                return Err("generated start marker was malformed".into());
            }
        }
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("Workspace layout missing before generated marker")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let record = store
            .get_execution(execution_id)?
            .ok_or("execution missing before marker")?;
        if record.state().is_terminal() {
            let output = store.read_execution_output_events(
                forge_domain::ExecutionOutputCursor::initial(execution_id),
                forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
                4,
            )?;
            let bytes: Vec<_> = output
                .events()
                .iter()
                .filter_map(|event| match event {
                    forge_domain::ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
                    forge_domain::ExecutionOutputEvent::Gap(_) => None,
                })
                .flatten()
                .copied()
                .collect();
            return Err(format!("execution terminal before start marker: state={:?} failure={:?} exit={:?} output={}", record.state(), record.failure_code(), record.outcome().and_then(forge_domain::ExecutionOutcome::exit_code), String::from_utf8_lossy(&bytes)).into());
        }
        if Instant::now() >= deadline {
            return Err("generated start marker was not observed".into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn write_synced_marker(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

async fn assert_http_running(
    address: SocketAddr,
    approved: &NativeApprovedProject,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, response) = post_command(
        address,
        "execution.get",
        json!({"authority": approved.authority.clone()}),
    )
    .await?;
    if status != 200 || response["result"]["state"] != "running" {
        return Err(format!("generated execution was not running: {status} {response}").into());
    }
    Ok(())
}

async fn disable_location(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let location = fixture
        .client
        .location_list()?
        .into_iter()
        .find(|location| location.id() == fixture.scope.locator().location_id())
        .ok_or("generated fixture Location missing")?;
    let (status, response) = post_command(
        address,
        "location.state",
        json!({
            "location_id": location.id().into_uuid(),
            "expected_revision": location.revision().get(),
            "state": "disabled",
            "observed_at_ms": timestamp_now()?.get(),
        }),
    )
    .await?;
    if status != 200 || response["result"]["state"] != "disabled" {
        return Err(format!("Location disable failed: {status} {response}").into());
    }
    Ok(())
}

async fn assert_stale_admission_has_no_row(
    address: SocketAddr,
    fixture: &Fixture,
    stale: &NativeApprovedProject,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, response) = post_command(
        address,
        "execution.begin",
        native_execution_begin_payload(stale),
    )
    .await?;
    if status != 409 || response["error"]["code"] != "STALE_REVISION" {
        return Err(format!("stale admission was not fenced: {status} {response}").into());
    }
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("generated fixture layout missing during stale check")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    if store.get_execution(stale.execution_id)?.is_some() {
        return Err("stale admission created an execution row".into());
    }
    Ok(())
}

async fn wait_for_local_terminal(
    workspace_root: &Path,
    execution_id: forge_domain::ExecutionId,
    generated_root: &Path,
) -> Result<
    (
        forge_domain::RegisteredExecution,
        forge_domain::ExecutionOutputRead,
        Option<GeneratedPackageManifest>,
    ),
    Box<dyn std::error::Error>,
> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root)?
            .ok_or("generated fixture layout disappeared")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let record = store
            .get_execution(execution_id)?
            .ok_or("generated execution row missing")?;
        if record.state().is_terminal() {
            let output = store.read_execution_output_events(
                forge_domain::ExecutionOutputCursor::initial(execution_id),
                forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES,
                forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
            )?;
            let manifest = store.generated_package_manifest(execution_id)?;
            if record.state() == forge_domain::ExecutionState::Completed {
                assert_generated_closure(&store, &record, &output, manifest)?;
            }
            return Ok((record, output, manifest));
        }
        if Instant::now() >= deadline {
            let output = store.read_execution_output_events(
                forge_domain::ExecutionOutputCursor::initial(execution_id),
                forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
                4,
            )?;
            let bytes: Vec<_> = output
                .events()
                .iter()
                .filter_map(|event| match event {
                    forge_domain::ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
                    forge_domain::ExecutionOutputEvent::Gap(_) => None,
                })
                .flatten()
                .copied()
                .collect();
            let manifest = store.generated_package_manifest(execution_id)?;
            return Err(format!(
                "generated execution did not reach terminal state: state={:?} revision={} failure={:?} exit={:?} manifest={} output_events={} output_truncated={} start_marker={} release_marker={} package_file={} output={}",
                record.state(),
                record.revision().get(),
                record.failure_code(),
                record.outcome().and_then(forge_domain::ExecutionOutcome::exit_code),
                manifest.is_some(),
                output.events().len(),
                output.truncated(),
                generated_root.join(PACKAGE_STARTED_MARKER).is_file(),
                generated_root.join(PACKAGE_RELEASE_MARKER).is_file(),
                generated_root.join("dist/Heterarchy-Forge.pkg").is_file(),
                String::from_utf8_lossy(&bytes),
            ).into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn assert_generated_closure(
    store: &WorkspaceStore,
    record: &forge_domain::RegisteredExecution,
    output: &forge_domain::ExecutionOutputRead,
    manifest: Option<GeneratedPackageManifest>,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = store
        .execution_native_closure_snapshot(record.id())?
        .ok_or("generated closure snapshot missing")?;
    let fact = snapshot
        .closure()
        .ok_or("generated native closure missing")?;
    assert_eq!(snapshot.record(), record);
    assert_eq!(snapshot.manifest(), manifest);
    assert_eq!(
        fact.launch(),
        forge_domain::NativeClosureLaunch::GeneratedPackage
    );
    assert_eq!(fact.runtime(), forge_domain::NativeClosureRuntime::Cleaned);
    assert_eq!(
        fact.process(),
        forge_domain::NativeClosureProcess::ProcessGroupReaped
    );
    assert_eq!(fact.after_revision(), record.revision());
    assert_eq!(fact.request_digest(), record.request_digest());
    assert_eq!(fact.output_cursor(), output.next_cursor());
    Ok(())
}

fn assert_manifest_identity(
    manifest: &GeneratedPackageManifest,
    fixture: &Fixture,
    execution_id: forge_domain::ExecutionId,
    output: &RustCiGeneratedPackageOutput,
) -> Result<(), Box<dyn std::error::Error>> {
    if manifest.workspace_id() != fixture.scope.workspace_id()
        || manifest.execution_id() != execution_id
    {
        return Err("generated manifest identity mismatch".into());
    }
    output.revalidate()?;
    let package = output.open_stable_package()?;
    let mut bytes = Vec::new();
    package.take(64).read_to_end(&mut bytes)?;
    if bytes != PACKAGE_BYTES || manifest.byte_count().get() != u64::try_from(PACKAGE_BYTES.len())?
    {
        return Err("generated package bytes or manifest byte count mismatch".into());
    }
    Ok(())
}

fn assert_output_marker(
    output: &forge_domain::ExecutionOutputRead,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for event in output.events() {
        match event {
            forge_domain::ExecutionOutputEvent::Chunk(chunk) => match chunk.stream() {
                forge_domain::ExecutionOutputStream::Stdout => {
                    bytes.extend_from_slice(chunk.bytes());
                }
                forge_domain::ExecutionOutputStream::Stderr if chunk.bytes().is_empty() => {}
                forge_domain::ExecutionOutputStream::Stderr => {
                    return Err("generated execution emitted stderr".into());
                }
            },
            forge_domain::ExecutionOutputEvent::Gap(_) => {
                return Err("generated output contains a gap".into());
            }
        }
    }
    if bytes != format!("{PACKAGE_STDOUT_MARKER}\n").as_bytes() {
        return Err("generated package stdout marker missing".into());
    }
    Ok(())
}

fn assert_package_files(
    output: &RustCiGeneratedPackageOutput,
    manifest: &GeneratedPackageManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    if output.root().join(PACKAGE_STARTED_MARKER).exists()
        || output.root().join(PACKAGE_RELEASE_MARKER).exists()
    {
        return Err("generated synchronization markers survived capture".into());
    }
    let root_children = fs::read_dir(output.root())?.collect::<Result<Vec<_>, _>>()?;
    if root_children.len() != 1 || root_children[0].file_name() != "dist" {
        return Err("generated output root was not reduced to dist only".into());
    }
    let dist = output.root().join("dist");
    let dist_children = fs::read_dir(&dist)?.collect::<Result<Vec<_>, _>>()?;
    if dist_children.len() != 1 || dist_children[0].file_name() != "Heterarchy-Forge.pkg" {
        return Err("generated dist did not contain exactly the package file".into());
    }
    let metadata = fs::symlink_metadata(dist.join("Heterarchy-Forge.pkg"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err("generated package file identity was invalid".into());
    }
    if manifest.byte_count().get() == 0 {
        return Err("generated package manifest was empty".into());
    }
    Ok(())
}

fn assert_source_unchanged(
    fixture: &Fixture,
    original: &[(&str, Vec<u8>)],
) -> Result<(), Box<dyn std::error::Error>> {
    for (path, bytes) in original {
        if fs::read(fixture.workspace_root.join(path))? != *bytes {
            return Err(format!("source changed after generated execution: {path}").into());
        }
    }
    Ok(())
}

fn assert_location_disabled(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let location = fixture
        .client
        .location_list()?
        .into_iter()
        .find(|location| location.id() == fixture.scope.locator().location_id())
        .ok_or("generated fixture Location disappeared")?;
    if location.state() != forge_domain::LocationState::Disabled {
        return Err("generated fixture Location was re-enabled".into());
    }
    Ok(())
}
