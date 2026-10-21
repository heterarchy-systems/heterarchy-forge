//! Heterarchy Forge repository-local mechanical verification harness.
//!
//! This active Rust workspace uses `xtask` for source rules, local Harness,
//! locked metadata, formatting, build/test/Clippy, dependency, and doctor gates.

mod doctor;
mod package;
mod policy_package;
mod test_runner;

use doctor::doctor;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use toml::Value as TomlValue;

const HARNESS_DIR: &str = ".agents/rust_dev_harness";
const TASK_OWNERSHIP_RULE: &str = concat!("02-task-ownership-", "structured-concurrency-rules.md");
const FORGE_PERSISTENCE_RULE: &str = "10-forge-persistence-sql-rules.md";
const FORGE_PERSISTENCE_HARNESS: &str = "harness/forge-persistence/README.md";
const FORGE_PERSISTENCE_MANIFEST: &str = "crates/forge-persistence/Cargo.toml";
const FORBIDDEN_PERSISTENCE_DEPENDENCIES: &[&str] = &["diesel", "diesel-async", "sea-orm", "sqlx"];
const NORMAL_RULES: &[&str] = &[
    "README.md",
    "00-overview.md",
    "01-boundary.md",
    "02-workspace-crate-rules.md",
    "03-deterministic-state-machine-rules.md",
    "04-ffi-interop-boundary-rules.md",
    "05-error-panic-rules.md",
    "06-testing-verification-rules.md",
    "07-performance-memory-rules.md",
    "08-observability-operations-rules.md",
    "09-module-layout-rules.md",
    FORGE_PERSISTENCE_RULE,
];
const TYPE_RULES: &[&str] = &[
    "README.md",
    "01-domain-newtype-invariant-rules.md",
    "02-enum-state-sum-type-rules.md",
    "03-option-result-outcome-rules.md",
    "04-trait-generic-bound-rules.md",
    "05-ownership-borrow-lifetime-rules.md",
    "06-smart-pointer-interior-mutability-rules.md",
    "07-send-sync-thread-safety-type-rules.md",
    "08-conversion-parsing-cast-rules.md",
    "09-public-api-type-evolution-rules.md",
    "10-unsafe-type-invariant-rules.md",
];
const ASYNC_RULES: &[&str] = &[
    "README.md",
    "01-execution-model-runtime-rules.md",
    TASK_OWNERSHIP_RULE,
    "03-cancellation-timeout-select-rules.md",
    "04-bounded-concurrency-backpressure-rules.md",
    "05-shared-state-lock-channel-rules.md",
    "06-blocking-cpu-parallelism-rules.md",
    "07-send-sync-local-task-rules.md",
    "08-async-error-shutdown-rules.md",
    "09-async-testing-verification-rules.md",
    "10-async-observability-performance-rules.md",
];
const REQUIRED_SKILL: &str = "skills/rust-engineering/SKILL.md";
const SHARED_HARNESS_SOURCE_COUNT: usize = 73;
const FORBIDDEN_IMPLEMENTATION_EXTENSIONS: &[&str] = &[
    "py", "pyi", "js", "jsx", "ts", "tsx", "mjs", "cjs", "go", "java", "kt", "kts", "swift", "c",
    "cc", "cpp", "cxx", "m", "mm",
];
const WALK_SKIP_DIRS: &[&str] = &[
    ".git",
    ".agents",
    ".chatgpt2codex",
    ".heterarchy-forge",
    ".opencode",
    ".omx",
    "target",
];
const MAX_POLICY_TEXT_BYTES: usize = 1_048_576;
const MAX_DOCTOR_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_TOOL_VERSION_OUTPUT_BYTES: usize = 1_024;
const PROCESS_CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_CAPTURE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PROCESS_CAPTURE_STREAM_COUNT: usize = 2;
const REQUIRED_CARGO_DENY_VERSION: &str = "cargo-deny 0.20.2";
const REQUIRED_CARGO_AUDIT_VERSION: &str = "cargo-audit 0.22.2";
const MSRV_TOOLCHAIN: &str = "1.98.0";
const RUST_CI_SANDBOX_MARKER_ENV: &str = "HETERARCHY_FORGE_RUST_CI_SANDBOX";
const RUST_CI_SANDBOX_MARKER_VALUE: &str = "v1";
const RUST_CI_TEST_POLICY_ENV: &str = "HETERARCHY_FORGE_RUST_CI_TEST_POLICY";
const RUST_CI_TEST_POLICY_VALUE: &str = "outer-rust-ci-v1";
const FORGE_EXECUTION_PACKAGE: &str = "forge-execution";
const RUST_TEST_THREADS_ENV: &str = "RUST_TEST_THREADS";
const FORGE_EXECUTION_TEST_THREADS: &str = "1";
const OUTER_RUST_CI_PROFILE_NOTICE: &str = "Heterarchy Forge CI profile: PARTIAL (outer Rust CI sandbox); native sandbox/process/loopback coverage gaps are explicitly skipped. Canonical host CI remains required.";

fn main() {
    if env::args_os().nth(1).as_deref() == Some(OsStr::new(test_runner::COMMAND)) {
        test_runner::run(env::args_os().skip(2));
    }
    if let Err(error) = run() {
        eprintln!("cargo xtask: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match env::args().nth(1).as_deref().unwrap_or("help") {
        "rules" => rules(),
        "harness" => harness(),
        "fmt" => cargo(&["fmt", "--all", "--", "--check"]),
        "check" => check(),
        "test" => test(),
        "ci" => ci(),
        "doctor" => doctor(),
        "deps" => deps(),
        "supply-chain" => supply_chain(),
        "extended" => extended(),
        "perf" => perf(),
        "msrv" => msrv(),
        "persistence" => persistence(),
        "package" => package::run(&workspace_root()),
        "policy-package" => policy_package::run(&workspace_root(), env::args().skip(2)),
        "help" | "--help" | "-h" => {
            println!(
                "usage: cargo xtask <rules|harness|fmt|check|test|ci|doctor|deps|supply-chain|extended|perf|msrv|persistence|package|policy-package>"
            );
            Ok(())
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

fn ci() -> Result<(), String> {
    rules()?;
    require_nonempty_file(&workspace_root().join("Cargo.lock"), "Cargo lockfile")?;
    cargo(&["fmt", "--all", "--", "--check"])?;
    check()?;
    test()
}

fn check() -> Result<(), String> {
    cargo(&["check", "--locked", "--workspace", "--all-targets"])?;
    cargo(&[
        "clippy",
        "--locked",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ])
}

fn test() -> Result<(), String> {
    if outer_rust_ci_test_profile_enabled() {
        println!("{OUTER_RUST_CI_PROFILE_NOTICE}");
        test_workspace(
            true,
            &[(RUST_CI_TEST_POLICY_ENV, RUST_CI_TEST_POLICY_VALUE)],
        )
    } else {
        test_workspace(false, &[])
    }
}

fn test_workspace(quiet: bool, environment: &[(&str, &str)]) -> Result<(), String> {
    let mut workspace_arguments = vec!["test"];
    if quiet {
        workspace_arguments.push("--quiet");
    }
    workspace_arguments.extend([
        "--locked",
        "--workspace",
        "--all-targets",
        "--exclude",
        FORGE_EXECUTION_PACKAGE,
    ]);
    cargo_test_with_runner_policy(&workspace_arguments, environment)?;

    let mut execution_arguments = vec!["test"];
    if quiet {
        execution_arguments.push("--quiet");
    }
    execution_arguments.extend(["--locked", "-p", FORGE_EXECUTION_PACKAGE, "--all-targets"]);
    let mut execution_environment = environment.to_vec();
    execution_environment.push((RUST_TEST_THREADS_ENV, FORGE_EXECUTION_TEST_THREADS));
    cargo_test_with_runner_policy(&execution_arguments, &execution_environment)
}

fn outer_rust_ci_test_profile_enabled() -> bool {
    outer_rust_ci_test_profile_enabled_for(
        std::env::var(RUST_CI_SANDBOX_MARKER_ENV).ok().as_deref(),
        std::env::var(RUST_CI_TEST_POLICY_ENV).ok().as_deref(),
    )
}

fn outer_rust_ci_test_profile_enabled_for(
    sandbox_marker: Option<&str>,
    test_policy: Option<&str>,
) -> bool {
    sandbox_marker == Some(RUST_CI_SANDBOX_MARKER_VALUE)
        && test_policy == Some(RUST_CI_TEST_POLICY_VALUE)
}

fn persistence() -> Result<(), String> {
    let root = workspace_root();
    verify_forge_persistence_source_policy(&root)?;
    cargo(&[
        "check",
        "--locked",
        "-p",
        "forge-persistence",
        "--all-targets",
    ])?;
    cargo(&[
        "clippy",
        "--locked",
        "-p",
        "forge-persistence",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ])?;
    cargo(&[
        "test",
        "--locked",
        "-p",
        "forge-persistence",
        "--all-targets",
    ])?;
    println!("Heterarchy Forge persistence harness passed");
    Ok(())
}

enum DoctorRetention {
    UnreapedProcess(u32),
    DiagnosticsFailed,
}

impl fmt::Display for DoctorRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreapedProcess(pid) => write!(formatter, "unreaped process {pid}"),
            Self::DiagnosticsFailed => formatter.write_str("unconfirmed diagnostics"),
        }
    }
}

struct DoctorSandbox {
    root: PathBuf,
    home: PathBuf,
    registry: PathBuf,
    retention: Option<DoctorRetention>,
}

impl DoctorSandbox {
    fn create() -> Result<Self, String> {
        let root = env::temp_dir().join(format!(
            "heterarchy-forge-xtask-doctor-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let home = root.join("home");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|error| {
                format!(
                    "cannot create private doctor root {}: {error}",
                    root.display()
                )
            })?;
        let mut sandbox = Self {
            registry: root.join("support").join("registry.sqlite3"),
            root,
            home,
            retention: None,
        };
        fs::create_dir(&sandbox.home).map_err(|error| {
            format!(
                "cannot create isolated doctor HOME {}: {error}",
                sandbox.home.display()
            )
        })?;
        sandbox.home = fs::canonicalize(&sandbox.home)
            .map_err(|error| format!("cannot canonicalize isolated doctor home: {error}"))?;
        Ok(sandbox)
    }

    fn home(&self) -> &Path {
        &self.home
    }

    fn registry_path(&self) -> &Path {
        &self.registry
    }

    fn cleanup(&self) -> Result<(), String> {
        if let Some(reason) = &self.retention {
            return Err(format!(
                "doctor sandbox retained for {reason}: {}",
                self.root.display()
            ));
        }
        fs::remove_dir_all(&self.root).map_err(|error| {
            format!(
                "cannot clean doctor sandbox {}: {error}",
                self.root.display()
            )
        })
    }
}

impl Drop for DoctorSandbox {
    fn drop(&mut self) {
        if let Some(reason) = &self.retention {
            eprintln!(
                "doctor sandbox retained for {reason}: {}",
                self.root.display()
            );
            return;
        }
        if let Err(error) = fs::remove_dir_all(&self.root)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "cannot clean doctor sandbox {} on drop: {error}",
                self.root.display()
            );
        }
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn deps() -> Result<(), String> {
    let root = workspace_root();
    require_nonempty_file(&root.join("Cargo.lock"), "Cargo lockfile")?;
    require_nonempty_file(&root.join("deny.toml"), "cargo-deny policy")?;
    require_tool_version("cargo-deny", REQUIRED_CARGO_DENY_VERSION, &root)?;
    cargo(&["deny", "check"])
}

fn supply_chain() -> Result<(), String> {
    let root = workspace_root();
    deps()?;
    require_tool_version("cargo-audit", REQUIRED_CARGO_AUDIT_VERSION, &root)?;
    cargo(&["audit"])
}

fn extended() -> Result<(), String> {
    ci()?;
    msrv()?;
    supply_chain()?;
    cargo(&["test", "--locked", "--workspace", "--doc"])?;
    cargo(&[
        "--config",
        "build.rustdocflags=[\"-D\",\"warnings\"]",
        "doc",
        "--locked",
        "--workspace",
        "--no-deps",
    ])
}

fn msrv() -> Result<(), String> {
    command_in(
        "rustup",
        &[
            "run",
            MSRV_TOOLCHAIN,
            "cargo",
            "check",
            "--locked",
            "--workspace",
            "--all-targets",
        ],
        &workspace_root(),
    )
}

fn perf() -> Result<(), String> {
    if !workspace_has_bench_target()? {
        return Err(
            "performance command is unconfigured: no workspace benchmark target found".to_owned(),
        );
    }
    println!("running benchmarks as measurement evidence; no release-budget PASS is implied");
    cargo(&["bench", "--locked", "--workspace"])
}

fn require_tool_version(program: &str, expected: &str, root: &Path) -> Result<(), String> {
    let captured = capture_process(
        Path::new(program),
        &["--version"],
        root,
        MAX_TOOL_VERSION_OUTPUT_BYTES,
    )?;
    if !captured.status.success() {
        return Err(format!(
            "{program} --version exited with {}",
            captured.status
        ));
    }
    if captured.stdout_total > MAX_TOOL_VERSION_OUTPUT_BYTES
        || captured.stderr_total > MAX_TOOL_VERSION_OUTPUT_BYTES
    {
        return Err(format!(
            "{program} --version output exceeded the bounded policy"
        ));
    }
    let actual = String::from_utf8_lossy(&captured.stdout);
    if actual.trim() == expected {
        Ok(())
    } else {
        Err(format!(
            "{program} version mismatch: expected {expected:?}, observed {:?}",
            actual.trim()
        ))
    }
}

fn rules() -> Result<(), String> {
    let root = workspace_root();
    require_nonempty_file(&root.join("AGENTS.md"), "root agent instructions")?;
    verify_rust_only_sources(&root)?;
    verify_workspace_manifest(&root)?;
    verify_forge_persistence_source_policy(&root)?;
    let metadata = cargo_metadata(&root)?;
    verify_manifest_lints(&metadata)?;
    verify_locked_metadata(&metadata)?;
    policy_package::verify(&root)?;

    println!("Heterarchy Forge Rust rules verification passed");
    Ok(())
}

fn harness() -> Result<(), String> {
    verify_private_harness(&workspace_root())?;
    rules()?;
    println!("Heterarchy Forge local Rust Harness verification passed");
    Ok(())
}

fn verify_private_harness(root: &Path) -> Result<(), String> {
    let harness_root = root.join(HARNESS_DIR);
    require_nonempty_file(
        &harness_root.join("PROJECT_PROFILE.md"),
        "Rust project profile",
    )?;
    require_nonempty_file(&harness_root.join("README.md"), "Rust harness README")?;
    require_nonempty_file(
        &harness_root.join("HARNESS_MANIFEST.tsv"),
        "private Rust harness manifest",
    )?;
    let skill = read_bounded_text(&harness_root.join(REQUIRED_SKILL), "Rust engineering skill")
        .map_err(|error| error.to_string())?;
    if !skill.starts_with("---\n") || !skill.contains("\nname: rust-engineering\n") {
        return Err("rust-engineering skill frontmatter is invalid".to_owned());
    }

    verify_rule_group(&harness_root.join("rules/normal_dev_rules"), NORMAL_RULES)?;
    verify_rule_group(&harness_root.join("rules/type_dev_rules"), TYPE_RULES)?;
    verify_rule_group(&harness_root.join("rules/async_dev_rules"), ASYNC_RULES)?;
    verify_harness_manifest(&harness_root)?;
    verify_forge_persistence_harness_policy(&harness_root)
}

fn verify_rule_group(root: &Path, rules: &[&str]) -> Result<(), String> {
    for rule in rules {
        require_nonempty_file(&root.join(rule), "active Rust rule")?;
    }
    Ok(())
}

fn verify_forge_persistence_harness_policy(harness_root: &Path) -> Result<(), String> {
    require_nonempty_file(
        &harness_root
            .join("rules/normal_dev_rules")
            .join(FORGE_PERSISTENCE_RULE),
        "FORGE persistence SQL rule",
    )?;
    require_nonempty_file(
        &harness_root.join(FORGE_PERSISTENCE_HARNESS),
        "FORGE persistence harness",
    )?;

    let harness_manifest = read_bounded_text(
        &harness_root.join("HARNESS_MANIFEST.tsv"),
        "public harness manifest",
    )
    .map_err(|error| error.to_string())?;
    for local_asset in [
        format!("rules/normal_dev_rules/{FORGE_PERSISTENCE_RULE}"),
        FORGE_PERSISTENCE_HARNESS.to_owned(),
    ] {
        verify_forge_local_asset_not_shared_manifested(&harness_manifest, &local_asset)?;
    }

    Ok(())
}

fn verify_forge_persistence_source_policy(root: &Path) -> Result<(), String> {
    let workspace = read_toml_file(&root.join("Cargo.toml"), "workspace Cargo.toml")?;
    let persistence = read_toml_file(
        &root.join(FORGE_PERSISTENCE_MANIFEST),
        "forge-persistence Cargo.toml",
    )?;
    verify_forge_persistence_manifests(&workspace, &persistence)
}

fn verify_forge_local_asset_not_shared_manifested(
    harness_manifest: &str,
    local_asset: &str,
) -> Result<(), String> {
    let is_manifested = harness_manifest
        .lines()
        .filter(|line| !line.trim().is_empty())
        .any(|line| line.split('\t').nth(1) == Some(local_asset));
    if is_manifested {
        Err(format!(
            "FORGE-local harness asset must not be shared-manifested: {local_asset}"
        ))
    } else {
        Ok(())
    }
}

fn read_toml_file(path: &Path, label: &str) -> Result<TomlValue, String> {
    let body = read_bounded_text(path, label).map_err(|error| error.to_string())?;
    toml::from_str::<TomlValue>(&body)
        .map_err(|error| format!("invalid {}: {error}", path.display()))
}

fn verify_forge_persistence_manifests(
    workspace: &TomlValue,
    persistence: &TomlValue,
) -> Result<(), String> {
    let rusqlite = toml_at(workspace, &["workspace", "dependencies", "rusqlite"])
        .and_then(TomlValue::as_table)
        .ok_or_else(|| "workspace.dependencies.rusqlite must be a dependency table".to_owned())?;
    rusqlite
        .get("version")
        .and_then(TomlValue::as_str)
        .filter(|version| !version.trim().is_empty())
        .ok_or_else(|| "workspace rusqlite must declare an explicit registry version".to_owned())?;
    if rusqlite
        .get("default-features")
        .and_then(TomlValue::as_bool)
        != Some(false)
    {
        return Err("workspace rusqlite must keep default-features = false".to_owned());
    }
    let features = rusqlite
        .get("features")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| "workspace rusqlite features must be explicit".to_owned())?;
    if !features
        .iter()
        .any(|feature| feature.as_str() == Some("bundled"))
    {
        return Err("workspace rusqlite must keep the bundled SQLite feature".to_owned());
    }

    if toml_at(persistence, &["package", "name"]).and_then(TomlValue::as_str)
        != Some("forge-persistence")
    {
        return Err("FORGE persistence manifest package name changed unexpectedly".to_owned());
    }
    if toml_at(persistence, &["dependencies", "rusqlite", "workspace"]).and_then(TomlValue::as_bool)
        != Some(true)
    {
        return Err(
            "forge-persistence must inherit rusqlite from workspace dependencies".to_owned(),
        );
    }

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(dependencies) = persistence.get(section).and_then(TomlValue::as_table) else {
            continue;
        };
        for (dependency_key, declaration) in dependencies {
            let package_name = declaration
                .as_table()
                .and_then(|table| table.get("package"))
                .and_then(TomlValue::as_str)
                .unwrap_or(dependency_key);
            if FORBIDDEN_PERSISTENCE_DEPENDENCIES.contains(&package_name) {
                return Err(format!(
                    "forge-persistence directly depends on forbidden persistence framework {package_name:?}; update the FORGE-local architecture rule and harness intentionally before changing authority"
                ));
            }
        }
    }

    Ok(())
}

fn verify_harness_manifest(harness_root: &Path) -> Result<(), String> {
    let body = read_bounded_text(
        &harness_root.join("HARNESS_MANIFEST.tsv"),
        "public harness manifest",
    )
    .map_err(|error| error.to_string())?;
    let mut paths = std::collections::BTreeSet::new();
    let mut count = 0_usize;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split('\t');
        let body_hash = fields.next().unwrap_or_default();
        let relative = fields.next().unwrap_or_default();
        if fields.next().is_some() {
            return Err("public harness manifest row has unexpected extra fields".to_owned());
        }
        validate_harness_manifest_fields(body_hash, relative)?;
        if !paths.insert(relative.to_owned()) {
            return Err(format!("public harness manifest duplicates {relative:?}"));
        }
        let source_path = harness_root.join(relative);
        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            format!(
                "cannot inspect materialized harness source {}: {error}",
                source_path.display()
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "materialized harness source {} is not a regular file",
                source_path.display()
            ));
        }
        let source = read_bounded_text(&source_path, "materialized harness source")
            .map_err(|error| error.to_string())?;
        if source.trim().len() < 32 {
            return Err(format!(
                "materialized harness source {} is unexpectedly empty",
                source_path.display()
            ));
        }
        let actual_hash = format!("{:x}", Sha256::digest(source.as_bytes()));
        if actual_hash != body_hash {
            return Err(format!(
                "materialized harness source hash mismatch for {relative:?}"
            ));
        }
        count += 1;
    }
    if count != SHARED_HARNESS_SOURCE_COUNT {
        return Err(format!(
            "public harness manifest has {count} sources; expected {SHARED_HARNESS_SOURCE_COUNT}"
        ));
    }
    for retired in [
        "rules/00-overview.md",
        "rules/10-ownership-allocation-rules.md",
        "skills/rust-forge-application-engineering",
        "profiles/native-compute",
    ] {
        if fs::symlink_metadata(harness_root.join(retired)).is_ok() {
            return Err(format!(
                "retired Rust harness path remains active: {retired}"
            ));
        }
    }
    Ok(())
}

fn validate_harness_manifest_fields(body_hash: &str, relative: &str) -> Result<(), String> {
    if !is_lowercase_sha256(body_hash) || !is_safe_relative_path(relative) {
        return Err("public harness manifest row is malformed".to_owned());
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn verify_rust_only_sources(root: &Path) -> Result<(), String> {
    let mut forbidden = Vec::new();
    walk_forbidden_sources(root, root, &mut forbidden)?;
    if forbidden.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Rust-only invariant violated by implementation source files:\n- {}",
            forbidden.join("\n- ")
        ))
    }
}

fn walk_forbidden_sources(
    root: &Path,
    current: &Path,
    forbidden: &mut Vec<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(current)
        .map_err(|error| format!("cannot scan {}: {error}", current.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            let name = entry.file_name();
            if WALK_SKIP_DIRS.iter().any(|skip| name == *skip) {
                continue;
            }
            walk_forbidden_sources(root, &path, forbidden)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let extension = path.extension().and_then(|value| value.to_str());
        if extension.is_some_and(|value| FORBIDDEN_IMPLEMENTATION_EXTENSIONS.contains(&value)) {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            forbidden.push(relative.display().to_string());
        }
    }
    Ok(())
}

fn require_nonempty_file(path: &Path, label: &str) -> Result<(), String> {
    let body = read_bounded_text(path, label).map_err(|error| error.to_string())?;
    if body.trim().len() < 32 {
        return Err(format!("{label} {} is unexpectedly empty", path.display()));
    }
    Ok(())
}

fn verify_workspace_manifest(root: &Path) -> Result<(), String> {
    let body = read_bounded_text(&root.join("Cargo.toml"), "workspace Cargo.toml")
        .map_err(|error| error.to_string())?;
    let manifest = toml::from_str::<TomlValue>(&body)
        .map_err(|error| format!("invalid workspace Cargo.toml: {error}"))?;
    require_toml_str(&manifest, &["workspace", "resolver"], "3")?;
    require_toml_str(&manifest, &["workspace", "package", "edition"], "2024")?;
    require_toml_str(&manifest, &["workspace", "package", "rust-version"], "1.98")?;
    require_toml_str(
        &manifest,
        &["workspace", "lints", "rust", "unsafe_code"],
        "forbid",
    )?;
    for lint in ["unsafe_op_in_unsafe_fn", "unused_must_use"] {
        if toml_at(&manifest, &["workspace", "lints", "rust", lint]).is_none() {
            return Err(format!("workspace Rust lint {lint:?} is missing"));
        }
    }
    if toml_at(&manifest, &["workspace", "lints", "clippy"])
        .and_then(TomlValue::as_table)
        .is_none()
    {
        return Err("workspace Cargo.toml is missing [workspace.lints.clippy]".to_owned());
    }
    let toolchain_body = read_bounded_text(&root.join("rust-toolchain.toml"), "Rust toolchain")
        .map_err(|error| error.to_string())?;
    let toolchain = toml::from_str::<TomlValue>(&toolchain_body)
        .map_err(|error| format!("invalid rust-toolchain.toml: {error}"))?;
    require_toml_str(&toolchain, &["toolchain", "channel"], MSRV_TOOLCHAIN)?;
    Ok(())
}

fn require_toml_str(root: &TomlValue, path: &[&str], expected: &str) -> Result<(), String> {
    let actual = toml_at(root, path).and_then(TomlValue::as_str);
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(format!(
            "Cargo.toml field {} must be {expected:?}, got {actual:?}",
            path.join(".")
        ))
    }
}

fn toml_at<'a>(root: &'a TomlValue, path: &[&str]) -> Option<&'a TomlValue> {
    let mut current = root;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn verify_manifest_lints(metadata: &JsonValue) -> Result<(), String> {
    for manifest in workspace_member_manifest_paths(metadata)? {
        let body =
            read_bounded_text(&manifest, "crate manifest").map_err(|error| error.to_string())?;
        let parsed = toml::from_str::<TomlValue>(&body)
            .map_err(|error| format!("invalid manifest {}: {error}", manifest.display()))?;
        if !parsed
            .get("lints")
            .and_then(|lints| lints.get("workspace"))
            .and_then(TomlValue::as_bool)
            .unwrap_or(false)
        {
            return Err(format!(
                "active crate manifest {} does not opt into [lints] workspace = true",
                manifest.display()
            ));
        }
    }
    Ok(())
}

fn workspace_member_manifest_paths(metadata: &JsonValue) -> Result<Vec<PathBuf>, String> {
    let packages = metadata
        .get("packages")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "cargo metadata is missing packages".to_owned())?;
    let members = metadata
        .get("workspace_members")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "cargo metadata is missing workspace_members".to_owned())?;
    let mut manifests = Vec::with_capacity(members.len());
    for member in members {
        let member_id = member
            .as_str()
            .ok_or_else(|| "workspace member id is invalid".to_owned())?;
        let package = packages
            .iter()
            .find(|package| package.get("id").and_then(JsonValue::as_str) == Some(member_id))
            .ok_or_else(|| format!("workspace member {member_id:?} is missing metadata"))?;
        let manifest_path = package
            .get("manifest_path")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| format!("workspace member {member_id:?} is missing manifest_path"))?;
        manifests.push(PathBuf::from(manifest_path));
    }
    manifests.sort();
    manifests.dedup();
    Ok(manifests)
}

fn verify_locked_metadata(metadata: &JsonValue) -> Result<(), String> {
    let packages = metadata
        .get("packages")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "cargo metadata is missing packages".to_owned())?;
    let members = metadata
        .get("workspace_members")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "cargo metadata is missing workspace_members".to_owned())?;
    let mut xtask_found = false;
    for member in members {
        let member_id = member
            .as_str()
            .ok_or_else(|| "workspace member id is invalid".to_owned())?;
        let package = packages
            .iter()
            .find(|package| package.get("id").and_then(JsonValue::as_str) == Some(member_id))
            .ok_or_else(|| format!("workspace member {member_id:?} is missing metadata"))?;
        let name = package
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "workspace package is missing name".to_owned())?;
        xtask_found |= name == "xtask";
        if package.get("edition").and_then(JsonValue::as_str) != Some("2024") {
            return Err(format!("workspace package {name:?} is not Edition 2024"));
        }
    }
    if xtask_found {
        Ok(())
    } else {
        Err("workspace does not contain the xtask package".to_owned())
    }
}

fn cargo_metadata(root: &Path) -> Result<JsonValue, String> {
    let arguments =
        pinned_cargo_arguments(["metadata", "--locked", "--no-deps", "--format-version", "1"]);
    let pinned_path = pinned_toolchain_path(root, &[])?;
    let environment = [(OsStr::new("PATH"), pinned_path.as_os_str())];
    let captured = capture_process_with_env(
        Path::new("rustup"),
        &arguments,
        root,
        MAX_DOCTOR_OUTPUT_BYTES * 16,
        &environment,
    )?;
    if !captured.status.success() {
        return Err(format!(
            "cargo metadata failed with status {}",
            captured.status
        ));
    }
    serde_json::from_slice(&captured.stdout)
        .map_err(|error| format!("invalid cargo metadata JSON: {error}"))
}

fn cargo_target_directory(root: &Path) -> Result<PathBuf, String> {
    let metadata = cargo_metadata(root)?;
    let target = metadata
        .get("target_directory")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "cargo metadata is missing target_directory".to_owned())?;
    Ok(PathBuf::from(target))
}

fn workspace_has_bench_target() -> Result<bool, String> {
    let metadata = cargo_metadata(&workspace_root())?;
    let packages = metadata
        .get("packages")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "cargo metadata is missing packages".to_owned())?;
    Ok(packages.iter().any(|package| {
        package
            .get("targets")
            .and_then(JsonValue::as_array)
            .is_some_and(|targets| {
                targets.iter().any(|target| {
                    target
                        .get("kind")
                        .and_then(JsonValue::as_array)
                        .is_some_and(|kinds| {
                            kinds.iter().any(|kind| kind.as_str() == Some("bench"))
                        })
                })
            })
    }))
}

#[derive(Debug)]
struct BoundedCapture {
    bytes: Vec<u8>,
    total: usize,
}

#[derive(Debug)]
enum BoundedReadError {
    Io(io::Error),
    TooLarge { actual: usize, maximum: usize },
}

fn read_bounded<R: Read>(reader: R, maximum: usize) -> Result<Vec<u8>, BoundedReadError> {
    let capture = read_capped(reader, maximum)?;
    if capture.total > maximum {
        Err(BoundedReadError::TooLarge {
            actual: capture.total,
            maximum,
        })
    } else {
        Ok(capture.bytes)
    }
}

fn read_capped<R: Read>(mut reader: R, maximum: usize) -> Result<BoundedCapture, BoundedReadError> {
    let capacity = maximum.saturating_add(1);
    let mut bytes = Vec::with_capacity(capacity.min(64 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_usize;

    while total < capacity {
        let remaining = capacity - total;
        let requested = remaining.min(buffer.len());
        let read = reader
            .read(&mut buffer[..requested])
            .map_err(BoundedReadError::Io)?;
        if read == 0 {
            break;
        }
        total += read;
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(BoundedCapture { bytes, total })
}

#[derive(Debug)]
enum BoundedTextError {
    Read {
        label: String,
        path: PathBuf,
        source: io::Error,
    },
    TooLarge {
        label: String,
        path: PathBuf,
        actual: usize,
        maximum: usize,
    },
    InvalidUtf8 {
        label: String,
        path: PathBuf,
        source: std::string::FromUtf8Error,
    },
}

impl fmt::Display for BoundedTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read {
                label,
                path,
                source,
            } => {
                write!(
                    formatter,
                    "cannot read {label} {}: {source}",
                    path.display()
                )
            }
            Self::TooLarge {
                label,
                path,
                actual,
                maximum,
            } => write!(
                formatter,
                "{label} {} returned {actual} bytes; maximum is {maximum}",
                path.display()
            ),
            Self::InvalidUtf8 {
                label,
                path,
                source,
            } => write!(
                formatter,
                "{label} {} is not valid UTF-8: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for BoundedTextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::InvalidUtf8 { source, .. } => Some(source),
            Self::TooLarge { .. } => None,
        }
    }
}

fn read_bounded_text(path: &Path, label: &str) -> Result<String, BoundedTextError> {
    let file = fs::File::open(path).map_err(|source| BoundedTextError::Read {
        label: label.to_owned(),
        path: path.to_path_buf(),
        source,
    })?;
    let bytes = read_bounded(file, MAX_POLICY_TEXT_BYTES).map_err(|error| match error {
        BoundedReadError::Io(source) => BoundedTextError::Read {
            label: label.to_owned(),
            path: path.to_path_buf(),
            source,
        },
        BoundedReadError::TooLarge { actual, maximum } => BoundedTextError::TooLarge {
            label: label.to_owned(),
            path: path.to_path_buf(),
            actual,
            maximum,
        },
    })?;
    String::from_utf8(bytes).map_err(|source| BoundedTextError::InvalidUtf8 {
        label: label.to_owned(),
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug)]
struct CapturedProcess {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_total: usize,
    stderr_total: usize,
}

#[derive(Clone, Copy)]
enum CapturedStream {
    Stdout,
    Stderr,
}

enum ReaderOutcome {
    Complete(Result<BoundedCapture, BoundedReadError>),
    Panicked,
}

struct ProcessCaptureCompletion {
    status: Option<ExitStatus>,
    timed_out: bool,
    cleanup_failed: bool,
    stdout: ReaderOutcome,
    stderr: ReaderOutcome,
}

impl ReaderOutcome {
    fn requires_termination(&self, maximum: usize) -> bool {
        match self {
            Self::Complete(Ok(capture)) => capture.total > maximum,
            Self::Complete(Err(_)) | Self::Panicked => true,
        }
    }
}

fn capture_process(
    program: &Path,
    arguments: &[&str],
    cwd: &Path,
    maximum: usize,
) -> Result<CapturedProcess, String> {
    capture_process_with_env(program, arguments, cwd, maximum, &[])
}

fn capture_process_with_env(
    program: &Path,
    arguments: &[&str],
    cwd: &Path,
    maximum: usize,
    environment: &[(&OsStr, &OsStr)],
) -> Result<CapturedProcess, String> {
    capture_process_until_with_env(
        program,
        arguments,
        cwd,
        maximum,
        Instant::now() + PROCESS_CAPTURE_TIMEOUT,
        environment,
    )
}

#[cfg(test)]
fn capture_process_until(
    program: &Path,
    arguments: &[&str],
    cwd: &Path,
    maximum: usize,
    deadline: Instant,
) -> Result<CapturedProcess, String> {
    capture_process_until_with_env(program, arguments, cwd, maximum, deadline, &[])
}

fn capture_process_until_with_env(
    program: &Path,
    arguments: &[&str],
    cwd: &Path,
    maximum: usize,
    deadline: Instant,
    environment: &[(&OsStr, &OsStr)],
) -> Result<CapturedProcess, String> {
    let mut child = spawn_captured_process(program, arguments, cwd, environment)?;
    let Some(stdout) = child.stdout.take() else {
        let error = format!("{} stdout pipe was unavailable", program.display());
        return Err(terminate_then_report(&mut child, program, arguments, error));
    };
    let Some(stderr) = child.stderr.take() else {
        let error = format!("{} stderr pipe was unavailable", program.display());
        return Err(terminate_then_report(&mut child, program, arguments, error));
    };

    let mut status = None;
    let mut timed_out = false;
    let mut cleanup_failed = false;
    let (stdout_result, stderr_result) = thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(PROCESS_CAPTURE_STREAM_COUNT);
        let stdout_sender = sender.clone();
        let stdout_reader = scope.spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                read_capped(stdout, maximum)
            }))
            .map_or(ReaderOutcome::Panicked, ReaderOutcome::Complete);
            stdout_sender.send((CapturedStream::Stdout, outcome))
        });
        let stderr_reader = scope.spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                read_capped(stderr, maximum)
            }))
            .map_or(ReaderOutcome::Panicked, ReaderOutcome::Complete);
            sender.send((CapturedStream::Stderr, outcome))
        });

        let mut stdout_result = None;
        let mut stderr_result = None;
        while stdout_result.is_none() || stderr_result.is_none() {
            let now = Instant::now();
            if now >= deadline && status.is_none() {
                cleanup_failed |= !terminate_process_group(&mut child);
                status = Some(wait_for_child(&mut child, program, arguments)?);
                timed_out = true;
            }
            let wait = if status.is_some() {
                PROCESS_CAPTURE_POLL_INTERVAL
            } else {
                deadline
                    .saturating_duration_since(now)
                    .min(PROCESS_CAPTURE_POLL_INTERVAL)
            };
            let (stream, outcome) = match receiver.recv_timeout(wait) {
                Ok(result) => result,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(error) => {
                    return Err(terminate_then_report(
                        &mut child,
                        program,
                        arguments,
                        format!("{} output reader disconnected: {error}", program.display()),
                    ));
                }
            };
            let requires_termination = outcome.requires_termination(maximum);
            match stream {
                CapturedStream::Stdout => stdout_result = Some(outcome),
                CapturedStream::Stderr => stderr_result = Some(outcome),
            }
            if requires_termination && status.is_none() {
                cleanup_failed |= !terminate_process_group(&mut child);
                status = Some(wait_for_child(&mut child, program, arguments)?);
            }
        }

        stdout_reader
            .join()
            .map_err(|_| format!("{} stdout reader panicked", program.display()))?
            .map_err(|_| format!("{} stdout result delivery failed", program.display()))?;
        stderr_reader
            .join()
            .map_err(|_| format!("{} stderr reader panicked", program.display()))?
            .map_err(|_| format!("{} stderr result delivery failed", program.display()))?;

        let stdout_result = stdout_result
            .ok_or_else(|| format!("{} stdout result was unavailable", program.display()))?;
        let stderr_result = stderr_result
            .ok_or_else(|| format!("{} stderr result was unavailable", program.display()))?;
        Ok::<_, String>((stdout_result, stderr_result))
    })?;

    finalize_captured_process(
        &mut child,
        program,
        arguments,
        maximum,
        ProcessCaptureCompletion {
            status,
            timed_out,
            cleanup_failed,
            stdout: stdout_result,
            stderr: stderr_result,
        },
    )
}

fn spawn_captured_process(
    program: &Path,
    arguments: &[&str],
    cwd: &Path,
    environment: &[(&OsStr, &OsStr)],
) -> Result<Child, String> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(cwd)
        .envs(environment.iter().copied())
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.spawn().map_err(|error| {
        format!(
            "failed to start {} {arguments:?}: {error}",
            program.display()
        )
    })
}

fn finalize_captured_process(
    child: &mut Child,
    program: &Path,
    arguments: &[&str],
    maximum: usize,
    completion: ProcessCaptureCompletion,
) -> Result<CapturedProcess, String> {
    let status = match completion.status {
        Some(status) => status,
        None => wait_for_child(child, program, arguments)?,
    };
    if completion.cleanup_failed {
        return Err(format!(
            "failed to terminate process group for {} {arguments:?}",
            program.display()
        ));
    }
    if completion.timed_out {
        return Err(format!(
            "{} {arguments:?} exceeded the bounded capture timeout",
            program.display()
        ));
    }
    let stdout = map_capture_result(completion.stdout, program, "stdout", maximum)?;
    let stderr = map_capture_result(completion.stderr, program, "stderr", maximum)?;
    Ok(CapturedProcess {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_total: stdout.total,
        stderr_total: stderr.total,
    })
}

fn map_capture_result(
    result: ReaderOutcome,
    program: &Path,
    stream: &str,
    maximum: usize,
) -> Result<BoundedCapture, String> {
    match result {
        ReaderOutcome::Complete(Ok(capture)) if capture.total <= maximum => Ok(capture),
        ReaderOutcome::Complete(Ok(capture)) => Err(format!(
            "{} {stream} returned {} bytes; maximum is {maximum}",
            program.display(),
            capture.total
        )),
        ReaderOutcome::Complete(Err(BoundedReadError::Io(error))) => Err(format!(
            "failed to read {} {stream}: {error}",
            program.display()
        )),
        ReaderOutcome::Complete(Err(BoundedReadError::TooLarge { actual, maximum })) => {
            Err(format!(
                "{} {stream} returned {actual} bytes; maximum is {maximum}",
                program.display()
            ))
        }
        ReaderOutcome::Panicked => Err(format!("{} {stream} reader panicked", program.display())),
    }
}

fn terminate_and_reap(
    child: &mut std::process::Child,
    program: &Path,
    arguments: &[&str],
) -> Result<ExitStatus, String> {
    let termination = terminate_process_group(child);
    let status = wait_for_child(child, program, arguments)?;
    if !termination {
        return Err(format!(
            "failed to terminate {} {arguments:?} before reaping it with status {status}",
            program.display()
        ));
    }
    Ok(status)
}

fn terminate_process_group(child: &mut Child) -> bool {
    let pid = child.id();
    let _term_sent = run_group_signal(pid, "-TERM");
    let term_deadline = Instant::now() + Duration::from_millis(50);
    while Instant::now() < term_deadline {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => thread::sleep(PROCESS_CAPTURE_POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    let _kill_sent = run_group_signal(pid, "-KILL");
    let group_deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < group_deadline {
        if !run_group_signal(pid, "-0") {
            return true;
        }
        thread::sleep(PROCESS_CAPTURE_POLL_INTERVAL);
    }
    let _direct_kill = child.kill();
    !run_group_signal(pid, "-0")
}

fn run_group_signal(pid: u32, signal: &str) -> bool {
    let group = format!("-{pid}");
    let mut command = Command::new("/bin/kill");
    command
        .arg(signal)
        .arg("--")
        .arg(group)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut killer) = command.spawn() else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_millis(100);
    loop {
        match killer.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(PROCESS_CAPTURE_POLL_INTERVAL);
            }
            Ok(None) | Err(_) => {
                let _ignored = killer.kill();
                let _ignored = killer.wait();
                return false;
            }
        }
    }
}

fn terminate_then_report(
    child: &mut std::process::Child,
    program: &Path,
    arguments: &[&str],
    primary_error: String,
) -> String {
    match terminate_and_reap(child, program, arguments) {
        Ok(_) => primary_error,
        Err(cleanup_error) => format!("{primary_error}; {cleanup_error}"),
    }
}

fn wait_for_child(
    child: &mut std::process::Child,
    program: &Path,
    arguments: &[&str],
) -> Result<ExitStatus, String> {
    child.wait().map_err(|error| {
        format!(
            "failed to wait for {} {arguments:?}: {error}",
            program.display()
        )
    })
}

fn cargo(arguments: &[&str]) -> Result<(), String> {
    cargo_with_environment(arguments, &[])
}

fn cargo_with_environment(arguments: &[&str], environment: &[(&str, &str)]) -> Result<(), String> {
    cargo_with_optional_test_runner(arguments, environment, None)
}

fn cargo_test_with_runner_policy(
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> Result<(), String> {
    if outer_rust_ci_test_profile_enabled() {
        cargo_with_environment(arguments, environment)
    } else {
        let runner_config = test_runner::cargo_runner_config(&workspace_root())?;
        cargo_with_optional_test_runner(arguments, environment, Some(&runner_config))
    }
}

fn cargo_with_optional_test_runner(
    arguments: &[&str],
    environment: &[(&str, &str)],
    runner_config: Option<&str>,
) -> Result<(), String> {
    let temporary_config = verification_temp_config(env::var_os("FORGE_VERIFY_TMPDIR").as_deref())?;
    let mut pinned_arguments = pinned_cargo_arguments(arguments.iter().copied());
    if let Some(config) = runner_config {
        pinned_arguments.splice(3..3, ["--config", config]);
    }
    if let Some(config) = temporary_config.as_deref() {
        // Cargo [env] force=true can override the parent process's TMPDIR.
        // Carry this explicit verification-only setting to each child Cargo,
        // without modifying inherited, repository or product storage policy.
        pinned_arguments.splice(
            3..3,
            ["--config", config, "--config", "env.TMPDIR.force=true"],
        );
    }
    command_in_with_environment("rustup", &pinned_arguments, &workspace_root(), environment)
}

fn verification_temp_config(directory: Option<&OsStr>) -> Result<Option<String>, String> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    let directory = Path::new(directory);
    let directory = test_runner::validate_internal_directory(directory)?;
    let directory = directory
        .to_str()
        .ok_or_else(|| "FORGE_VERIFY_TMPDIR must be representable in Cargo TOML".to_owned())?;
    Ok(Some(format!(
        "env.TMPDIR.value={}",
        toml::Value::String(directory.to_owned())
    )))
}

fn pinned_cargo_arguments<'a>(arguments: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let iterator = arguments.into_iter();
    let (minimum, _) = iterator.size_hint();
    let mut pinned_arguments = Vec::with_capacity(minimum.saturating_add(3));
    pinned_arguments.extend(["run", MSRV_TOOLCHAIN, "cargo"]);
    pinned_arguments.extend(iterator);
    pinned_arguments
}

fn command(program: &str, arguments: &[&str]) -> Result<(), String> {
    command_in(program, arguments, &workspace_root())
}

fn command_in(program: impl AsRef<OsStr>, arguments: &[&str], cwd: &Path) -> Result<(), String> {
    command_in_with_environment(program, arguments, cwd, &[])
}

fn command_in_with_environment(
    program: impl AsRef<OsStr>,
    arguments: &[&str],
    cwd: &Path,
    environment: &[(&str, &str)],
) -> Result<(), String> {
    let program = program.as_ref();
    let pinned_path = pinned_toolchain_path(cwd, environment)?;
    let status = Command::new(program)
        .args(arguments)
        .current_dir(cwd)
        .envs(environment.iter().copied())
        .env("PATH", pinned_path)
        .status()
        .map_err(|error| {
            format!(
                "failed to start {} {arguments:?}: {error}",
                program.to_string_lossy()
            )
        })?;
    require_success(program, status, arguments)
}

fn require_success(program: &OsStr, status: ExitStatus, arguments: &[&str]) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {arguments:?} exited with status {status}",
            program.to_string_lossy()
        ))
    }
}

// `rustup run` selects Cargo but leaves child compiler lookup to PATH.
fn pinned_toolchain_path(cwd: &Path, environment: &[(&str, &str)]) -> Result<OsString, String> {
    let toolchain_bin = pinned_toolchain_bin(cwd)?;
    let inherited_path = environment
        .iter()
        .find_map(|(name, value)| (*name == "PATH").then(|| OsString::from(*value)))
        .or_else(|| env::var_os("PATH"))
        .ok_or_else(|| "pinned Rust commands require PATH".to_owned())?;
    env::join_paths(std::iter::once(toolchain_bin).chain(env::split_paths(&inherited_path)))
        .map_err(|error| format!("cannot prepend pinned Rust toolchain to PATH: {error}"))
}

fn pinned_toolchain_bin(cwd: &Path) -> Result<PathBuf, String> {
    let arguments = ["which", "--toolchain", MSRV_TOOLCHAIN, "rustc"];
    let captured = capture_process(
        Path::new("rustup"),
        &arguments,
        cwd,
        MAX_TOOL_VERSION_OUTPUT_BYTES,
    )?;
    if !captured.status.success() {
        return Err(format!(
            "rustup {arguments:?} exited with status {}",
            captured.status
        ));
    }
    let rustc = String::from_utf8(captured.stdout)
        .map_err(|error| format!("rustup returned a non-UTF-8 rustc path: {error}"))?;
    let rustc = PathBuf::from(rustc.trim());
    if !rustc.is_absolute() || rustc.file_name() != Some(OsStr::new("rustc")) {
        return Err(format!(
            "rustup returned an invalid pinned rustc path {}",
            rustc.display()
        ));
    }
    if !rustc.is_file() {
        return Err(format!(
            "pinned rustc path does not exist: {}",
            rustc.display()
        ));
    }
    rustc
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("pinned rustc path has no parent: {}", rustc.display()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        Path::to_path_buf,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Cursor, Read};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::{
        BoundedReadError, MAX_DOCTOR_OUTPUT_BYTES, capture_process, capture_process_until,
        is_lowercase_sha256, is_safe_relative_path, pinned_cargo_arguments, read_bounded,
        read_capped, toml_at, validate_harness_manifest_fields, verification_temp_config,
        verify_forge_local_asset_not_shared_manifested, verify_forge_persistence_manifests,
        workspace_member_manifest_paths,
    };
    use serde_json::json;
    use toml::Value as TomlValue;

    fn native_process_tests_are_unavailable() -> bool {
        super::outer_rust_ci_test_profile_enabled()
    }

    struct CountingReader {
        remaining: usize,
        consumed: Arc<AtomicUsize>,
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = buffer.len().min(self.remaining);
            buffer[..read].fill(b'x');
            self.remaining -= read;
            self.consumed.fetch_add(read, Ordering::Relaxed);
            Ok(read)
        }
    }

    #[test]
    fn cargo_subprocess_arguments_are_pinned_to_repository_toolchain() {
        assert_eq!(
            pinned_cargo_arguments(["check", "--locked"]),
            vec!["run", super::MSRV_TOOLCHAIN, "cargo", "check", "--locked"]
        );
    }

    #[test]
    fn verification_temp_config_preserves_absence_and_escapes_explicit_directory()
    -> Result<(), String> {
        assert_eq!(verification_temp_config(None)?, None);
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            PathBuf::from("/tmp")
        };
        let base = super::test_runner::validate_internal_directory(&base)?;
        let sandbox_root = base.join(format!(
            "heterarchy-forge-xtask-temp-config-{}-{}",
            std::process::id(),
            super::unique_suffix()
        ));
        fs::create_dir(&sandbox_root).map_err(|error| error.to_string())?;
        let directory = sandbox_root.join("tmp space 한글");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let config = verification_temp_config(Some(directory.as_os_str()))?
            .ok_or_else(|| "explicit temp configuration missing".to_owned())?;
        let parsed: TomlValue = toml::from_str(&format!("{config}\nenv.TMPDIR.force=true"))
            .map_err(|error| error.to_string())?;
        let canonical = fs::canonicalize(&directory).map_err(|error| error.to_string())?;
        assert_eq!(
            parsed["env"]["TMPDIR"]["value"].as_str(),
            canonical.to_str()
        );
        assert_eq!(parsed["env"]["TMPDIR"]["force"].as_bool(), Some(true));
        fs::remove_dir_all(&sandbox_root).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn verification_temp_config_rejects_relative_missing_file_and_symlink() -> Result<(), String> {
        assert!(verification_temp_config(Some(Path::new("relative").as_os_str())).is_err());
        let sandbox = super::DoctorSandbox::create()?;
        let missing = sandbox.root.join("missing");
        assert!(verification_temp_config(Some(missing.as_os_str())).is_err());
        let file = sandbox.root.join("file");
        fs::write(&file, b"temporary fixture").map_err(|error| error.to_string())?;
        assert!(verification_temp_config(Some(file.as_os_str())).is_err());
        let link = sandbox.root.join("link");
        symlink(&sandbox.root, &link).map_err(|error| error.to_string())?;
        assert!(verification_temp_config(Some(link.as_os_str())).is_err());
        Ok(())
    }

    #[test]
    fn pinned_cargo_uses_pinned_rustc_and_clippy_when_host_path_precedes_toolchain()
    -> Result<(), String> {
        if native_process_tests_are_unavailable() {
            return Ok(());
        }
        let sandbox = super::DoctorSandbox::create()?;
        let probe_root = sandbox.root.join("toolchain-probe");
        let source_root = probe_root.join("src");
        fs::create_dir_all(&source_root)
            .map_err(|error| format!("cannot create toolchain probe source: {error}"))?;
        fs::write(
            probe_root.join("Cargo.toml"),
            "[package]\nname = \"forge-toolchain-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .map_err(|error| format!("cannot write toolchain probe manifest: {error}"))?;
        fs::write(
            source_root.join("lib.rs"),
            "pub fn toolchain_probe() -> u32 { 92 }\n",
        )
        .map_err(|error| format!("cannot write toolchain probe source: {error}"))?;

        let hostile_bin = probe_root.join("host-bin");
        fs::create_dir_all(&hostile_bin)
            .map_err(|error| format!("cannot create hostile host bin: {error}"))?;
        symlink("/usr/bin/false", hostile_bin.join("rustc"))
            .map_err(|error| format!("cannot create hostile rustc: {error}"))?;
        symlink("/usr/bin/false", hostile_bin.join("clippy-driver"))
            .map_err(|error| format!("cannot create hostile clippy-driver: {error}"))?;

        let original_path =
            std::env::var_os("PATH").ok_or_else(|| "toolchain probe requires PATH".to_owned())?;
        let hostile_path = std::env::join_paths(
            std::iter::once(hostile_bin.clone()).chain(std::env::split_paths(&original_path)),
        )
        .map_err(|error| format!("cannot construct hostile PATH: {error}"))?;
        let hostile_path = hostile_path
            .to_str()
            .ok_or_else(|| "hostile PATH is not valid UTF-8".to_owned())?;
        let manifest = probe_root
            .join("Cargo.toml")
            .to_str()
            .ok_or_else(|| "toolchain probe manifest is not valid UTF-8".to_owned())?
            .to_owned();
        let target = probe_root
            .join("target")
            .to_str()
            .ok_or_else(|| "toolchain probe target is not valid UTF-8".to_owned())?
            .to_owned();
        let environment = [("PATH", hostile_path)];

        let check_arguments = pinned_cargo_arguments([
            "check",
            "--manifest-path",
            manifest.as_str(),
            "--target-dir",
            target.as_str(),
        ]);
        super::command_in_with_environment("rustup", &check_arguments, &probe_root, &environment)?;

        let clippy_arguments = pinned_cargo_arguments([
            "clippy",
            "--manifest-path",
            manifest.as_str(),
            "--target-dir",
            target.as_str(),
            "--",
            "-D",
            "warnings",
        ]);
        super::command_in_with_environment("rustup", &clippy_arguments, &probe_root, &environment)?;
        Ok(())
    }

    #[test]
    fn marker_only_production_selector_keeps_host_private_copy_runner()
    -> Result<(), Box<dyn std::error::Error>> {
        const PROBE_ENV: &str = "FORGE_RUST_CI_SELECTOR_CHILD_PROBE";
        if std::env::var_os(PROBE_ENV).is_some() {
            assert!(
                !super::outer_rust_ci_test_profile_enabled(),
                "marker-only environment selected the outer Rust-CI profile"
            );
            return Ok(());
        }

        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "tests::marker_only_production_selector_keeps_host_private_copy_runner",
                "--nocapture",
            ])
            .env(PROBE_ENV, "1")
            .env(
                super::RUST_CI_SANDBOX_MARKER_ENV,
                super::RUST_CI_SANDBOX_MARKER_VALUE,
            )
            .env_remove(super::RUST_CI_TEST_POLICY_ENV)
            .output()?;
        assert!(
            output.status.success(),
            "marker-only environment selected the outer Rust-CI profile: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    fn outer_rust_ci_test_profile_requires_both_exact_values() {
        assert!(!super::outer_rust_ci_test_profile_enabled_for(None, None));
        assert!(!super::outer_rust_ci_test_profile_enabled_for(
            Some(super::RUST_CI_SANDBOX_MARKER_VALUE),
            None,
        ));
        assert!(!super::outer_rust_ci_test_profile_enabled_for(
            None,
            Some(super::RUST_CI_TEST_POLICY_VALUE),
        ));
        assert!(!super::outer_rust_ci_test_profile_enabled_for(
            Some(super::RUST_CI_SANDBOX_MARKER_VALUE),
            Some("unexpected"),
        ));
        assert!(!super::outer_rust_ci_test_profile_enabled_for(
            Some("unexpected"),
            Some(super::RUST_CI_TEST_POLICY_VALUE),
        ));
        assert!(super::outer_rust_ci_test_profile_enabled_for(
            Some(super::RUST_CI_SANDBOX_MARKER_VALUE),
            Some(super::RUST_CI_TEST_POLICY_VALUE),
        ));
    }

    #[test]
    fn outer_rust_ci_notice_identifies_partial_coverage() {
        assert!(super::OUTER_RUST_CI_PROFILE_NOTICE.contains("PARTIAL"));
        assert!(super::OUTER_RUST_CI_PROFILE_NOTICE.contains("outer Rust CI sandbox"));
        assert!(super::OUTER_RUST_CI_PROFILE_NOTICE.contains("sandbox/process/loopback"));
        assert!(super::OUTER_RUST_CI_PROFILE_NOTICE.contains("Canonical host CI remains required"));
    }

    #[test]
    fn bounded_reader_rejects_oversized_text_without_unbounded_storage() {
        let result = read_bounded(Cursor::new(vec![b'x'; 9]), 8);
        assert!(matches!(
            result,
            Err(BoundedReadError::TooLarge {
                actual: 9,
                maximum: 8
            })
        ));
    }

    #[test]
    fn capped_reader_stops_after_observing_one_byte_beyond_the_limit() -> Result<(), String> {
        let consumed = Arc::new(AtomicUsize::new(0));
        let capture = read_capped(
            CountingReader {
                remaining: 64,
                consumed: Arc::clone(&consumed),
            },
            8,
        )
        .map_err(|error| format!("bounded read failed: {error:?}"))?;

        assert_eq!(capture.total, 9);
        assert_eq!(capture.bytes.len(), 9);
        assert_eq!(consumed.load(Ordering::Relaxed), 9);
        Ok(())
    }

    #[test]
    fn manifest_lint_opt_in_is_parsed_semantically() -> Result<(), String> {
        let manifest = toml::from_str::<TomlValue>("[lints]\nworkspace = true\n")
            .map_err(|error| error.to_string())?;
        assert_eq!(
            toml_at(&manifest, &["lints", "workspace"]).and_then(TomlValue::as_bool),
            Some(true)
        );
        let unrelated = toml::from_str::<TomlValue>("[lints.rust]\nunsafe_code = \"forbid\"\n")
            .map_err(|error| error.to_string())?;
        assert!(toml_at(&unrelated, &["lints", "workspace"]).is_none());
        Ok(())
    }

    #[test]
    fn forge_persistence_manifest_policy_accepts_rusqlite_and_rejects_orms() -> Result<(), String> {
        let workspace = toml::from_str::<TomlValue>(
            r#"
[workspace.dependencies]
rusqlite = { version = "=0.40.2", default-features = false, features = ["bundled"] }
"#,
        )
        .map_err(|error| error.to_string())?;
        let persistence = toml::from_str::<TomlValue>(
            r#"
[package]
name = "forge-persistence"

[dependencies]
rusqlite.workspace = true
thiserror = "2"
"#,
        )
        .map_err(|error| error.to_string())?;
        assert!(verify_forge_persistence_manifests(&workspace, &persistence).is_ok());

        let with_orm = toml::from_str::<TomlValue>(
            r#"
[package]
name = "forge-persistence"

[dependencies]
rusqlite.workspace = true
database = { package = "sea-orm", version = "2" }
"#,
        )
        .map_err(|error| error.to_string())?;
        assert!(verify_forge_persistence_manifests(&workspace, &with_orm).is_err());
        Ok(())
    }

    #[test]
    fn forge_persistence_source_policy_runs_without_private_harness() -> Result<(), String> {
        let sandbox = super::DoctorSandbox::create()?;
        let root = &sandbox.root;
        assert!(!root.join(super::HARNESS_DIR).exists());

        fs::create_dir_all(root.join("crates/forge-persistence"))
            .map_err(|error| format!("cannot create source-policy fixture: {error}"))?;
        fs::write(
            root.join("Cargo.toml"),
            r#"
[workspace.dependencies]
rusqlite = { version = "=0.40.2", default-features = false, features = ["bundled"] }
"#,
        )
        .map_err(|error| format!("cannot write workspace policy fixture: {error}"))?;
        let persistence_manifest = root.join(super::FORGE_PERSISTENCE_MANIFEST);
        fs::write(
            &persistence_manifest,
            r#"
[package]
name = "forge-persistence"

[dependencies]
rusqlite.workspace = true
"#,
        )
        .map_err(|error| format!("cannot write persistence policy fixture: {error}"))?;

        assert!(super::verify_forge_persistence_source_policy(root).is_ok());

        fs::write(
            &persistence_manifest,
            r#"
[package]
name = "forge-persistence"

[dependencies]
rusqlite.workspace = true
database = { package = "sea-orm", version = "2" }
"#,
        )
        .map_err(|error| format!("cannot write forbidden dependency fixture: {error}"))?;
        let Err(error) = super::verify_forge_persistence_source_policy(root) else {
            return Err(
                "public persistence policy must keep rejecting direct ORM dependencies".to_owned(),
            );
        };
        assert!(error.contains("forbidden persistence framework \"sea-orm\""));
        Ok(())
    }

    #[test]
    fn private_harness_validation_fails_when_the_tree_is_missing() -> Result<(), String> {
        let sandbox = super::DoctorSandbox::create()?;
        assert!(!sandbox.root.join(super::HARNESS_DIR).exists());
        let Err(error) = super::verify_private_harness(&sandbox.root) else {
            return Err("private Harness validation must fail when its tree is absent".to_owned());
        };
        assert!(error.contains("Rust project profile"));
        Ok(())
    }

    #[test]
    fn forge_persistence_assets_must_remain_outside_shared_harness_manifest() {
        let hash = "a".repeat(64);
        let shared = format!("{hash}\trules/normal_dev_rules/README.md\n");
        assert!(
            verify_forge_local_asset_not_shared_manifested(
                &shared,
                "rules/normal_dev_rules/10-forge-persistence-sql-rules.md"
            )
            .is_ok()
        );
        let incorrectly_manifested = format!(
            "{hash}	rules/normal_dev_rules/10-forge-persistence-sql-rules.md
"
        );
        assert!(
            verify_forge_local_asset_not_shared_manifested(
                &incorrectly_manifested,
                "rules/normal_dev_rules/10-forge-persistence-sql-rules.md"
            )
            .is_err()
        );
    }

    #[test]
    fn public_harness_manifest_fields_reject_noncanonical_hash_and_path() {
        let hash = "a".repeat(64);
        assert!(is_lowercase_sha256(&hash));
        assert!(is_safe_relative_path("rules/normal_dev_rules/README.md"));
        assert!(validate_harness_manifest_fields(&hash, "rules/README.md").is_ok());

        assert!(!is_lowercase_sha256(&"G".repeat(64)));
        assert!(!is_safe_relative_path("../rules/README.md"));
        assert!(!is_safe_relative_path("/rules/README.md"));
        assert!(validate_harness_manifest_fields(&hash, "../rules/README.md").is_err());
    }

    #[test]
    fn workspace_member_manifests_come_from_locked_metadata_not_directory_shape()
    -> Result<(), String> {
        let metadata = json!({
            "workspace_members": ["nested 0.1.0 (path+file:///workspace/tools/nested)"],
            "packages": [{
                "id": "nested 0.1.0 (path+file:///workspace/tools/nested)",
                "manifest_path": "/workspace/tools/nested/Cargo.toml"
            }]
        });

        assert_eq!(
            workspace_member_manifest_paths(&metadata)?,
            vec![std::path::PathBuf::from(
                "/workspace/tools/nested/Cargo.toml"
            )]
        );
        Ok(())
    }

    #[test]
    fn captured_process_rejects_large_output_at_the_per_stream_cap() {
        if native_process_tests_are_unavailable() {
            return;
        }
        let large = "x".repeat(MAX_DOCTOR_OUTPUT_BYTES + 1);
        let result = capture_process(
            Path::new("/usr/bin/printf"),
            &["%s", &large],
            Path::new("/"),
            MAX_DOCTOR_OUTPUT_BYTES,
        );
        assert!(result.is_err());
    }

    #[test]
    fn captured_process_kills_and_reaps_an_endless_oversized_producer() -> Result<(), String> {
        if native_process_tests_are_unavailable() {
            return Ok(());
        }
        let pid_path = std::env::temp_dir().join(format!(
            "heterarchy-forge-xtask-capture-{}-{}.pid",
            std::process::id(),
            line!()
        ));
        let pid_path_argument = pid_path
            .to_str()
            .ok_or_else(|| "temporary PID path was not valid UTF-8".to_owned())?;
        let script = concat!(
            "printf '%s' \"$$\" > \"$1\"; ",
            "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done"
        );

        let result = capture_process(
            Path::new("/bin/sh"),
            &["-c", script, "capture-test", pid_path_argument],
            Path::new("/"),
            1_024,
        );
        let pid = fs::read_to_string(&pid_path)
            .map_err(|error| format!("failed to read producer PID: {error}"))?;
        fs::remove_file(&pid_path)
            .map_err(|error| format!("failed to remove producer PID file: {error}"))?;

        let Err(error) = result else {
            return Err("endless oversized output unexpectedly succeeded".to_owned());
        };
        assert!(error.contains("stdout returned 1025 bytes; maximum is 1024"));
        let still_exists = Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("failed to inspect producer PID: {error}"))?
            .success();
        assert!(!still_exists, "producer remained alive or unreaped");
        Ok(())
    }

    #[test]
    fn captured_process_times_out_and_kills_pipe_holding_descendants() -> Result<(), String> {
        if native_process_tests_are_unavailable() {
            return Ok(());
        }
        let pid_path = std::env::temp_dir().join(format!(
            "heterarchy-forge-xtask-descendant-{}-{}.pid",
            std::process::id(),
            line!()
        ));
        let pid_path_argument = pid_path
            .to_str()
            .ok_or_else(|| "temporary descendant PID path was not valid UTF-8".to_owned())?;
        let script = "sleep 30 & child=$!; printf '%s' \"$child\" > \"$1\"; wait";
        let started = Instant::now();
        let result = capture_process_until(
            Path::new("/bin/sh"),
            &["-c", script, "capture-timeout", pid_path_argument],
            Path::new("/"),
            1_024,
            Instant::now() + Duration::from_millis(50),
        );
        let descendant = fs::read_to_string(&pid_path)
            .map_err(|error| format!("failed to read descendant PID: {error}"))?;
        fs::remove_file(&pid_path)
            .map_err(|error| format!("failed to remove descendant PID file: {error}"))?;

        let Err(error) = result else {
            return Err("silent pipe-holding descendant unexpectedly succeeded".to_owned());
        };
        assert!(error.contains("exceeded the bounded capture timeout"));
        assert!(started.elapsed() < Duration::from_secs(2));
        let still_exists = Command::new("/bin/kill")
            .args(["-0", descendant.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("failed to inspect descendant PID: {error}"))?
            .success();
        assert!(!still_exists, "pipe-holding descendant remained alive");
        Ok(())
    }
}
