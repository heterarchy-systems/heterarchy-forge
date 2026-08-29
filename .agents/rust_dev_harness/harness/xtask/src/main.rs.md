# xtask/src/main.rs

```rust
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const NORMAL_RULES: &[&str] = &[
    "README.md",
    "00-overview.md",
    "01-boundary.md",
    "02-workspace-crate-rules.md",
    concat!("03-deterministic-state-", "machine-rules.md"),
    "04-ffi-interop-boundary-rules.md",
    "05-error-panic-rules.md",
    "06-testing-verification-rules.md",
    "07-performance-memory-rules.md",
    "08-observability-operations-rules.md",
];

const TYPE_RULES: &[&str] = &[
    "README.md",
    "01-domain-newtype-invariant-rules.md",
    "02-enum-state-sum-type-rules.md",
    "03-option-result-outcome-rules.md",
    "04-trait-generic-bound-rules.md",
    "05-ownership-borrow-lifetime-rules.md",
    concat!("06-smart-pointer-interior-", "mutability-rules.md"),
    concat!("07-send-sync-thread-safety-", "type-rules.md"),
    "08-conversion-parsing-cast-rules.md",
    concat!("09-public-api-type-", "evolution-rules.md"),
    "10-unsafe-type-invariant-rules.md",
];

const ASYNC_RULES: &[&str] = &[
    "README.md",
    "01-execution-model-runtime-rules.md",
    concat!("02-task-ownership-", "structured-concurrency-rules.md"),
    "03-cancellation-timeout-select-rules.md",
    concat!("04-bounded-concurrency-", "backpressure-rules.md"),
    "05-shared-state-lock-channel-rules.md",
    "06-blocking-cpu-parallelism-rules.md",
    "07-send-sync-local-task-rules.md",
    "08-async-error-shutdown-rules.md",
    "09-async-testing-verification-rules.md",
    concat!("10-async-observability-", "performance-rules.md"),
];

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    let result = match command.as_str() {
        "rules" => rules(),
        "fmt" => fmt(),
        "check" => check(),
        "test" => test(),
        "ci" => ci(),
        "deps" => deps(),
        "doctor" => doctor(),
        "extended" => extended(),
        "perf" => perf(),
        "help" | "-h" | "--help" => {
            help();
            Ok(())
        }
        other => Err(format!("unknown xtask command: {other}")),
    };

    if let Err(error) = result {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn help() {
    println!(
        "cargo xtask <rules|fmt|check|test|ci|deps|doctor|extended|perf>"
    );
}

fn workspace_root() -> Result<PathBuf, String> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format", "plain"])
        .output()
        .map_err(|error| format!("failed to run cargo locate-project: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "cargo locate-project failed with status {}",
            output.status
        ));
    }

    let manifest = String::from_utf8(output.stdout)
        .map_err(|error| format!("cargo locate-project returned non-UTF8 output: {error}"))?;
    let manifest = PathBuf::from(manifest.trim());
    manifest
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "workspace Cargo.toml has no parent directory".to_owned())
}

fn harness_root(root: &Path) -> PathBuf {
    root.join(".agents").join("rust_dev_harness")
}

fn read_toml(path: &Path) -> Result<toml::Value, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    toml::from_str(&source)
        .map_err(|error| format!("invalid TOML {}: {error}", path.display()))
}

fn require_file(path: &Path) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("missing required file: {}", path.display()))
    }
}

fn verify_group(root: &Path, directory: &str, files: &[&str]) -> Result<(), String> {
    let directory = root.join("rules").join(directory);
    for file in files {
        require_file(&directory.join(file))?;
    }
    Ok(())
}

fn rules() -> Result<(), String> {
    let root = workspace_root()?;
    let harness = harness_root(&root);

    require_file(&harness.join("PROJECT_PROFILE.md"))?;
    require_file(&harness.join("rules").join("README.md"))?;
    require_file(
        &harness
            .join("skills")
            .join("rust-engineering")
            .join("SKILL.md"),
    )?;

    verify_group(&harness, "normal_dev_rules", NORMAL_RULES)?;
    verify_group(&harness, "type_dev_rules", TYPE_RULES)?;
    verify_group(&harness, "async_dev_rules", ASYNC_RULES)?;
    verify_cargo_baseline(&root)?;
    verify_workspace_members_inherit_lints(&root)?;

    println!("xtask rules: PASS");
    Ok(())
}

fn verify_cargo_baseline(root: &Path) -> Result<(), String> {
    let manifest_path = root.join("Cargo.toml");
    let manifest = read_toml(&manifest_path)?;

    let workspace = manifest
        .get("workspace")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "root Cargo.toml must define [workspace]".to_owned())?;

    if workspace.get("resolver").and_then(toml::Value::as_str) != Some("3") {
        return Err("workspace.resolver must be \"3\"".to_owned());
    }

    let package = workspace
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "root Cargo.toml must define [workspace.package]".to_owned())?;

    if package.get("edition").and_then(toml::Value::as_str) != Some("2024") {
        return Err("workspace.package.edition must be \"2024\"".to_owned());
    }

    if package.get("rust-version").and_then(toml::Value::as_str).is_none() {
        return Err("workspace.package.rust-version must be explicit".to_owned());
    }

    let rust_lints = workspace
        .get("lints")
        .and_then(toml::Value::as_table)
        .and_then(|lints| lints.get("rust"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "root Cargo.toml must define [workspace.lints.rust]".to_owned())?;

    if rust_lints.get("unsafe_code").and_then(toml::Value::as_str) != Some("forbid") {
        return Err("workspace.lints.rust.unsafe_code must be \"forbid\" by default".to_owned());
    }

    Ok(())
}

fn cargo_metadata(root: &Path) -> Result<serde_json::Value, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("failed to run cargo metadata: {error}"))?;

    if !output.status.success() {
        return Err(format!("cargo metadata failed with status {}", output.status));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata returned invalid JSON: {error}"))
}

fn verify_workspace_members_inherit_lints(root: &Path) -> Result<(), String> {
    let metadata = cargo_metadata(root)?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "cargo metadata has no packages array".to_owned())?;

    for package in packages {
        let manifest_path = package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "cargo metadata package missing manifest_path".to_owned())?;
        let manifest_path = Path::new(manifest_path);
        let manifest = read_toml(manifest_path)?;

        let workspace_lints = manifest
            .get("lints")
            .and_then(toml::Value::as_table)
            .and_then(|lints| lints.get("workspace"))
            .and_then(toml::Value::as_bool);

        if workspace_lints != Some(true) {
            return Err(format!(
                "workspace member must declare [lints] workspace = true: {}",
                manifest_path.display()
            ));
        }
    }

    Ok(())
}

fn status(command: &mut Command, label: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("failed to execute {label}: {error}"))?;
    require_success(status, label)
}

fn require_success(status: ExitStatus, label: &str) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed with status {status}"))
    }
}

fn fmt() -> Result<(), String> {
    let root = workspace_root()?;
    status(
        Command::new("cargo")
            .args(["fmt", "--all", "--", "--check"])
            .current_dir(root),
        "cargo fmt",
    )
}

fn check() -> Result<(), String> {
    let root = workspace_root()?;
    status(
        Command::new("cargo")
            .args(["check", "--workspace", "--all-targets"])
            .current_dir(&root),
        "cargo check",
    )?;
    status(
        Command::new("cargo")
            .args([
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ])
            .current_dir(root),
        "cargo clippy",
    )
}

fn test() -> Result<(), String> {
    let root = workspace_root()?;
    status(
        Command::new("cargo")
            .args(["test", "--workspace", "--all-targets"])
            .current_dir(root),
        "cargo test",
    )
}

fn ci() -> Result<(), String> {
    rules()?;
    fmt()?;
    check()?;
    test()
}

fn deps() -> Result<(), String> {
    let root = workspace_root()?;
    require_file(&root.join("deny.toml"))?;
    status(
        Command::new("cargo")
            .args(["deny", "check"])
            .current_dir(root),
        "cargo deny check",
    )
}

fn doctor() -> Result<(), String> {
    let root = workspace_root()?;
    println!("workspace: {}", root.display());

    for (program, args) in [
        ("rustc", vec!["--version"]),
        ("cargo", vec!["--version"]),
        ("cargo", vec!["fmt", "--version"]),
        ("cargo", vec!["clippy", "--version"]),
    ] {
        let status = Command::new(program)
            .args(args)
            .current_dir(&root)
            .status()
            .map_err(|error| format!("doctor could not execute {program}: {error}"))?;
        if !status.success() {
            return Err(format!("doctor required tool check failed: {program}"));
        }
    }

    for optional in ["deny", "miri"] {
        let status = Command::new("cargo")
            .args([optional, "--version"])
            .current_dir(&root)
            .status();
        match status {
            Ok(value) if value.success() => println!("optional tool available: cargo {optional}"),
            _ => println!("optional tool unavailable: cargo {optional}"),
        }
    }

    rules()
}

fn extended() -> Result<(), String> {
    ci()?;
    deps()?;
    let root = workspace_root()?;

    status(
        Command::new("cargo")
            .args(["test", "--workspace", "--doc"])
            .current_dir(&root),
        "cargo test --doc",
    )?;

    status(
        Command::new("cargo")
            .args([
                "--config",
                "build.rustdocflags=[\"-D\",\"warnings\"]",
                "doc",
                "--workspace",
                "--no-deps",
            ])
            .current_dir(root),
        "cargo doc",
    )
}

fn perf() -> Result<(), String> {
    let root = workspace_root()?;
    status(
        Command::new("cargo")
            .args(["bench", "--workspace"])
            .current_dir(root),
        "cargo bench",
    )
}
```

## Contract

`rules` now verifies all three canonical rule families. `normal_dev_rules` and `type_dev_rules` are semantic baseline; async applicability remains project-profile-driven even though the shared bundle assets themselves must stay complete.

The generic xtask intentionally does not attempt to infer semantic correctness of ownership, `Send`/`Sync`, public SemVer or unsafe proofs from source text. Those are verified by compiler/Clippy/tests and project-owned deeper tools/evidence rather than brittle custom source scanning.
