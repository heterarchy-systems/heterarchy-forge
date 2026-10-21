//! Actual Linux confinement regressions; never use the outer-sandbox skip marker.

use super::{
    BWRAP_PATH, ExecutionLaunchKind, ExecutionPermissions, ExistingWorkspaceStateLayout,
    LinuxSandboxProfile, OsString, Path, RustCiToolchainCapability,
};
use forge_workspace::WorkspaceStateLayout;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(label: &str) -> TestResult<(std::path::PathBuf, ExistingWorkspaceStateLayout)> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("forge-linux-{label}-{unique}"));
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    WorkspaceStateLayout::initialize(&root)?;
    let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    Ok((root, layout))
}

#[test]
#[ignore = "requires a direct Linux sandbox host; run the explicit confinement gate"]
fn baseline_hides_durable_state_for_read_and_write_permissions() -> TestResult {
    for writable in [false, true] {
        let (root, layout) = fixture("state")?;
        let source = root.join("source.txt");
        let state = layout.state_root().join("sentinel");
        fs::write(&source, b"source")?;
        fs::write(&state, b"durable-original")?;
        let profile =
            LinuxSandboxProfile::new(&layout, ExecutionPermissions::new(true, writable, false))?;
        let script = "set -eu; test \"$(cat \"$1\")\" = source; if cat \"$2\" 2>/dev/null; then exit 17; fi; if (printf corrupt > \"$2\") 2>/dev/null; then exit 18; fi; if [ \"$3\" = writable ]; then printf changed > \"$1\"; else if (printf changed > \"$1\") 2>/dev/null; then exit 19; fi; fi";
        let output = Command::new(BWRAP_PATH)
            .args(profile.args())
            .args(["--", "/bin/sh", "-c", script, "probe"])
            .arg(&source)
            .arg(&state)
            .arg(if writable { "writable" } else { "readonly" })
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        assert!(
            output.status.success(),
            "state confinement: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&state)?, b"durable-original");
        assert_eq!(
            fs::read(&source)?,
            if writable {
                b"changed".as_slice()
            } else {
                b"source".as_slice()
            }
        );
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires a direct Linux sandbox host; run the explicit confinement gate"]
fn network_denial_and_explicit_grant_reach_only_the_selected_namespace() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (root, layout) = fixture("network")?;
    let executable = std::env::current_exe()?;
    for granted in [false, true] {
        let mut profile =
            LinuxSandboxProfile::new(&layout, ExecutionPermissions::new(false, false, granted))?;
        // Mount only the fixture binary, not any workspace/state, for the child probe.
        profile.args.extend([
            OsString::from("--ro-bind"),
            executable.as_os_str().to_owned(),
            executable.as_os_str().to_owned(),
        ]);
        let output = Command::new(BWRAP_PATH)
            .args(profile.args())
            .arg("--")
            .arg(&executable)
            .args([
                "--exact",
                "sandbox_linux::tests::network_probe_child",
                "--nocapture",
            ])
            .env_clear()
            .env("FORGE_TEST_NETWORK_ADDRESS", address.to_string())
            .env(
                "FORGE_TEST_NETWORK_GRANTED",
                if granted { "yes" } else { "no" },
            )
            .output()?;
        assert!(
            output.status.success(),
            "network grant={granted}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn network_probe_child() -> TestResult {
    let Ok(address) = std::env::var("FORGE_TEST_NETWORK_ADDRESS") else {
        return Ok(());
    };
    let address = address.parse()?;
    let connected = TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_ok();
    assert_eq!(
        connected,
        std::env::var("FORGE_TEST_NETWORK_GRANTED").as_deref() == Ok("yes")
    );
    Ok(())
}

#[test]
#[ignore = "requires a direct Linux sandbox host; run the explicit confinement gate"]
fn verification_mounts_exact_runtime_and_output_without_live_workspace() -> TestResult {
    let (root, layout) = fixture("verification")?;
    let host = root.with_extension("host");
    fs::create_dir_all(host.join(".cargo/bin"))?;
    fs::create_dir_all(host.join(".cargo/registry"))?;
    fs::create_dir_all(host.join(".rustup/toolchains").join(
        crate::rust_ci::pinned_toolchain_name(crate::RustCiHostArchitecture::Aarch64),
    ))?;
    fs::write(host.join(".cargo/bin/rustup"), b"capability-fixture")?;
    fs::write(host.join(".rustup/settings.toml"), b"version = 12\n")?;
    let cache = root.with_extension("cache");
    let input = crate::RustCiDiscoveryInput::new(
        host.clone(),
        cache.clone(),
        crate::RustCiHostArchitecture::Aarch64,
        forge_domain::RuntimeInstanceId::from_uuid(uuid::Uuid::now_v7()),
    )?;
    let capability = RustCiToolchainCapability::prepare(&input)?;
    let workspace = forge_domain::WorkspaceId::from_uuid(uuid::Uuid::now_v7());
    let execution = forge_domain::ExecutionId::from_uuid(uuid::Uuid::now_v7());
    let runtime =
        capability.ensure_runtime_paths(workspace, layout.root_fingerprint()?, execution)?;
    let output = capability.ensure_generated_package_output(
        workspace,
        layout.root_fingerprint()?,
        execution,
    )?;
    let source = runtime.execution_root().join("verification-source");
    fs::create_dir(&source)?;
    fs::write(source.join("input.txt"), b"frozen")?;
    fs::write(root.join("live.txt"), b"live-must-stay-hidden")?;
    let profile = LinuxSandboxProfile::for_verification_launch(
        &layout,
        &source,
        ExecutionLaunchKind::RustCiGeneratedPackage,
        &capability,
        &runtime,
        Some(&output),
        Some(Path::new("/usr/bin/true")),
    )?;
    let script = "set -eu; test \"$(cat \"$1/input.txt\")\" = frozen; if cat \"$2/live.txt\" 2>/dev/null; then exit 17; fi; shift 2; for directory in \"$@\"; do printf persisted > \"$directory/probe\"; done";
    let outcome = Command::new(BWRAP_PATH)
        .args(profile.args())
        .args(["--", "/bin/sh", "-c", script, "probe"])
        .arg(&source)
        .arg(&root)
        .arg(runtime.target_dir())
        .arg(runtime.temporary_dir())
        .arg(runtime.home_dir())
        .arg(runtime.cargo_home())
        .arg(output.root())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    assert!(
        outcome.status.success(),
        "verification mounts: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    for directory in [
        runtime.target_dir(),
        runtime.temporary_dir(),
        runtime.home_dir(),
        runtime.cargo_home(),
        output.root(),
    ] {
        assert_eq!(fs::read(directory.join("probe"))?, b"persisted");
    }
    assert_eq!(fs::read(root.join("live.txt"))?, b"live-must-stay-hidden");
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(host)?;
    fs::remove_dir_all(cache)?;
    Ok(())
}

fn prepare_cargo_probe_source(source: &Path) -> TestResult {
    fs::create_dir(source)?;
    fs::write(
        source.join("Cargo.toml"),
        "[package]\nname = \"confinement-proof\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[[bin]]\nname = \"confinement-proof\"\npath = \"main.rs\"\n",
    )?;
    fs::write(
        source.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"confinement-proof\"\nversion = \"0.0.0\"\n",
    )?;
    fs::write(
        source.join("main.rs"),
        "fn main() { let a: Vec<_> = std::env::args_os().collect(); assert!(std::fs::read(&a[1]).is_err()); assert!(std::fs::read(&a[2]).is_err()); std::fs::write(&a[3], b\"compiled-and-confined\").unwrap(); }\n",
    )?;
    Ok(())
}

fn compile_cargo_probe(
    profile: &LinuxSandboxProfile,
    source: &Path,
    capability: &RustCiToolchainCapability,
    runtime: &crate::RustCiRuntimePaths,
) -> TestResult {
    let result = Command::new(BWRAP_PATH)
        .args(profile.args())
        .arg("--")
        .arg(capability.view().rustup_path())
        .args([
            "run",
            capability.pinned_toolchain(),
            "cargo",
            "build",
            "--offline",
            "--locked",
        ])
        .current_dir(source)
        .env_clear()
        .env(
            "PATH",
            format!(
                "{}:{}/bin:/usr/bin:/bin",
                capability.view().bin_dir().display(),
                capability.view().toolchain_path().display()
            ),
        )
        .env("RUSTUP_HOME", capability.view().rustup_home())
        .env("RUSTUP_TOOLCHAIN", capability.pinned_toolchain())
        .env("CARGO_HOME", runtime.cargo_home())
        .env("CARGO_TARGET_DIR", runtime.target_dir())
        .env("HOME", runtime.home_dir())
        .env("TMPDIR", runtime.temporary_dir())
        .output()?;
    assert!(
        result.status.success(),
        "actual Cargo: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[test]
#[ignore = "requires a real pinned Linux toolchain; run the explicit confinement gate"]
fn verification_runs_real_cargo_and_persists_only_exact_execution_output() -> TestResult {
    let host = std::env::var_os("FORGE_TEST_RUST_CI_HOME")
        .ok_or("FORGE_TEST_RUST_CI_HOME is required for the real Cargo gate")?;
    let (root, layout) = fixture("actual-cargo")?;
    let cache = root.with_extension("cache");
    let input = crate::RustCiDiscoveryInput::new(
        fs::canonicalize(host)?,
        cache.clone(),
        crate::RustCiHostArchitecture::current().ok_or("unsupported architecture")?,
        forge_domain::RuntimeInstanceId::from_uuid(uuid::Uuid::now_v7()),
    )?;
    let capability = RustCiToolchainCapability::prepare(&input)?;
    let workspace = forge_domain::WorkspaceId::from_uuid(uuid::Uuid::now_v7());
    fs::write(root.join("live.txt"), b"live")?;
    let other_runtime = capability.ensure_runtime_paths(
        workspace,
        layout.root_fingerprint()?,
        forge_domain::ExecutionId::from_uuid(uuid::Uuid::now_v7()),
    )?;
    let sibling = other_runtime
        .temporary_dir()
        .join("unrelated-execution.txt");
    fs::write(&sibling, b"private")?;
    for kind in [
        ExecutionLaunchKind::RustCi,
        ExecutionLaunchKind::RustCiGeneratedPackage,
    ] {
        let execution = forge_domain::ExecutionId::from_uuid(uuid::Uuid::now_v7());
        let runtime =
            capability.ensure_runtime_paths(workspace, layout.root_fingerprint()?, execution)?;
        let output = capability.ensure_generated_package_output(
            workspace,
            layout.root_fingerprint()?,
            execution,
        )?;
        let source = runtime.execution_root().join("verification-source");
        prepare_cargo_probe_source(&source)?;
        let generated = kind == ExecutionLaunchKind::RustCiGeneratedPackage;
        let profile = LinuxSandboxProfile::for_verification_launch(
            &layout,
            &source,
            kind,
            &capability,
            &runtime,
            generated.then_some(&output),
            generated.then_some(Path::new("/usr/bin/true")),
        )?;
        compile_cargo_probe(&profile, &source, &capability, &runtime)?;
        let compiled = runtime.target_dir().join("debug/confinement-proof");
        let retained = if generated {
            output.root()
        } else {
            runtime.target_dir()
        }
        .join("proof.bin");
        let result = Command::new(BWRAP_PATH)
            .args(profile.args())
            .arg("--")
            .arg(&compiled)
            .arg(root.join("live.txt"))
            .arg(&sibling)
            .arg(&retained)
            .env_clear()
            .output()?;
        assert!(
            result.status.success(),
            "compiled probe: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&retained)?, b"compiled-and-confined");
        assert!(!source.join("target").exists());
    }
    assert_eq!(fs::read(root.join("live.txt"))?, b"live");
    assert_eq!(fs::read(&sibling)?, b"private");
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(cache)?;
    Ok(())
}
