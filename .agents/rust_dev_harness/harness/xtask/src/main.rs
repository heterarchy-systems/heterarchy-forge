//! Heterarchy Forge repository-local mechanical harness template.
//!
//! Cargo and rustc remain the authorities for compilation and linting. The
//! root repository may copy/adapt this xtask when implementation begins.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const HARNESS_DIR: &str = ".agents/rust_dev_harness";
const REQUIRED_RULES: &[&str] = &[
    "README.md",
    "00-overview.md",
    "01-boundary.md",
    "02-workspace-crate-rules.md",
    "03-typed-domain-rules.md",
    "04-deterministic-state-machine-rules.md",
    "05-async-effect-boundary-rules.md",
    "06-error-panic-rules.md",
    "07-testing-verification-rules.md",
    "08-performance-memory-rules.md",
    "09-observability-operations-rules.md",
    "10-ownership-allocation-rules.md",
    "11-concurrency-cancellation-rules.md",
    "12-persistence-durability-rules.md",
    "13-unsafe-platform-boundary-rules.md",
    "14-security-capability-rules.md",
    "15-dependency-reproducibility-rules.md",
    "16-slint-ui-runtime-rules.md",
    "17-protocol-serialization-rules.md",
];
const REQUIRED_SKILL: &str = "skills/rust-forge-application-engineering/SKILL.md";
const FORBIDDEN_IMPLEMENTATION_EXTENSIONS: &[&str] = &[
    "py", "pyi", "js", "jsx", "ts", "tsx", "mjs", "cjs", "go", "java", "kt", "kts", "swift", "c",
    "cc", "cpp", "cxx", "m", "mm",
];
const WALK_SKIP_DIRS: &[&str] = &[
    ".git",
    ".agents",
    ".chatgpt2codex",
    ".heterarchy-forge",
    "target",
];

fn main() {
    if let Err(error) = run() {
        eprintln!("cargo xtask: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match env::args().nth(1).as_deref().unwrap_or("help") {
        "rules" => rules(),
        "fmt" => cargo(&["fmt", "--all", "--", "--check"]),
        "check" => check(),
        "test" => test(),
        "ci" => ci(),
        "doctor" => doctor(),
        "deps" => deps(),
        "supply-chain" => supply_chain(),
        "help" | "--help" | "-h" => {
            println!("usage: cargo xtask <rules|fmt|check|test|ci|doctor|deps|supply-chain>");
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
    cargo(&["test", "--locked", "--workspace"])
}

fn doctor() -> Result<(), String> {
    rules()?;
    command("rustc", &["--version"])?;
    command("cargo", &["--version"])?;
    require_nonempty_file(&workspace_root().join("Cargo.lock"), "Cargo lockfile")?;
    cargo(&["metadata", "--locked", "--no-deps", "--format-version", "1"])?;
    println!("Heterarchy Forge Rust harness doctor passed");
    Ok(())
}

fn deps() -> Result<(), String> {
    require_nonempty_file(&workspace_root().join("Cargo.lock"), "Cargo lockfile")?;
    cargo(&["tree", "--locked", "--workspace", "--duplicates"])
}

fn supply_chain() -> Result<(), String> {
    let root = workspace_root();
    require_nonempty_file(&root.join("Cargo.lock"), "Cargo lockfile")?;
    require_nonempty_file(&root.join("deny.toml"), "cargo-deny policy")?;
    cargo(&["deny", "check"])?;
    cargo(&["audit"])
}

fn rules() -> Result<(), String> {
    let root = workspace_root();
    let harness_root = root.join(HARNESS_DIR);
    let rules_root = harness_root.join("rules");

    require_nonempty_file(&root.join("AGENTS.md"), "root agent instructions")?;
    require_nonempty_file(
        &harness_root.join("PROJECT_PROFILE.md"),
        "Rust project profile",
    )?;
    require_nonempty_file(&harness_root.join("README.md"), "Rust harness README")?;
    require_nonempty_file(&harness_root.join(REQUIRED_SKILL), "Rust Forge skill")?;

    for file in REQUIRED_RULES {
        require_nonempty_file(&rules_root.join(file), "active Rust rule")?;
    }

    verify_rust_only_sources(&root)?;

    let cargo_manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("cannot read workspace Cargo.toml: {error}"))?;
    for required in [
        "resolver = \"3\"",
        "edition = \"2024\"",
        "[workspace.lints.rust]",
        "unsafe_code = \"deny\"",
        "unsafe_op_in_unsafe_fn = \"deny\"",
        "unused_must_use = \"deny\"",
        "[workspace.lints.clippy]",
        "undocumented_unsafe_blocks = \"deny\"",
        "await_holding_lock = \"deny\"",
    ] {
        if !cargo_manifest.contains(required) {
            return Err(format!(
                "workspace Cargo.toml is missing required policy {required}"
            ));
        }
    }

    println!("Heterarchy Forge Rust rules verification passed");
    Ok(())
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
    let body = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if body.trim().len() < 32 {
        return Err(format!("{label} {} is unexpectedly empty", path.display()));
    }
    Ok(())
}

fn cargo(arguments: &[&str]) -> Result<(), String> {
    command_in("cargo", arguments, &workspace_root())
}

fn command(program: &str, arguments: &[&str]) -> Result<(), String> {
    command_in(program, arguments, &workspace_root())
}

fn command_in(program: &str, arguments: &[&str], cwd: &Path) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .current_dir(cwd)
        .status()
        .map_err(|error| format!("failed to start {program} {arguments:?}: {error}"))?;
    require_success(program, status, arguments)
}

fn require_success(program: &str, status: ExitStatus, arguments: &[&str]) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {arguments:?} exited with status {status}"
        ))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        Path::to_path_buf,
    )
}
