//! Headless backend release packaging.
//!
//! The retired macOS `.app`/`.pkg` desktop installer pipeline was removed with
//! the GUI crates. The release artifact is now a bounded tarball of the locked
//! release `forge-backend` binary plus the operations guide, with a recorded
//! SHA-256 checksum.

use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use toml::Value as TomlValue;

const BACKEND_PACKAGE: &str = "forge-backend";
const OPERATIONS_DOC: &str = "docs/BACKEND_OPERATIONS.md";
const PACKAGE_OUTPUT_ROOT_ENV: &str = "FORGE_PACKAGE_OUTPUT_ROOT";
const MAX_DOC_BYTES: u64 = 256 * 1024;

pub(crate) fn run(root: &Path) -> Result<(), String> {
    let output_root = match env::var_os(PACKAGE_OUTPUT_ROOT_ENV) {
        Some(value) => {
            let path = PathBuf::from(&value);
            if !path.is_absolute() {
                return Err(format!(
                    "{PACKAGE_OUTPUT_ROOT_ENV} must be an absolute path: {}",
                    path.display()
                ));
            }
            path
        }
        None => root.join("dist"),
    };
    fs::create_dir_all(&output_root)
        .map_err(|error| format!("cannot create the package output root: {error}"))?;

    let version = workspace_version(root)?;
    let target = format!(
        "forge-backend-v{version}-{}-{}",
        env::consts::OS,
        env::consts::ARCH
    );
    let stage = output_root.join(&target);
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|error| {
            format!(
                "cannot refresh the package stage {}: {error}",
                stage.display()
            )
        })?;
    }
    fs::create_dir_all(&stage).map_err(|error| {
        format!(
            "cannot create the package stage {}: {error}",
            stage.display()
        )
    })?;

    super::cargo(&["build", "--locked", "--release", "-p", BACKEND_PACKAGE])?;
    let release_binary = super::cargo_target_directory(root)?
        .join("release")
        .join(BACKEND_PACKAGE);
    let staged_binary = stage.join(BACKEND_PACKAGE);
    fs::copy(&release_binary, &staged_binary).map_err(|error| {
        format!(
            "cannot copy the release backend binary {} into the package: {error}",
            release_binary.display()
        )
    })?;
    make_executable(&staged_binary)?;

    let operations = root.join(OPERATIONS_DOC);
    require_regular_nonempty_file(&operations, "backend operations guide")?;
    let staged_operations = stage.join("OPERATIONS.md");
    fs::copy(&operations, &staged_operations)
        .map_err(|error| format!("cannot copy the operations guide into the package: {error}"))?;
    let doc_length = fs::metadata(&staged_operations)
        .map_err(|error| format!("cannot stat the packaged operations guide: {error}"))?
        .len();
    if doc_length > MAX_DOC_BYTES {
        return Err(format!(
            "packaged operations guide exceeds the {MAX_DOC_BYTES}-byte bound"
        ));
    }

    let archive = output_root.join(format!("{target}.tar.gz"));
    if archive.exists() {
        fs::remove_file(&archive)
            .map_err(|error| format!("cannot refresh the package archive: {error}"))?;
    }
    let archive_argument = archive.display().to_string();
    let tar = Command::new("tar")
        .args([
            "-czf",
            &archive_argument,
            "-C",
            &output_root.display().to_string(),
            &target,
        ])
        .status()
        .map_err(|error| format!("cannot run tar for the backend package: {error}"))?;
    if !tar.success() {
        return Err(format!("tar exited with status {tar}"));
    }
    let checksum = sha256_file(&archive)?;
    let archive_name = archive
        .file_name()
        .ok_or_else(|| format!("package archive {} has no file name", archive.display()))?
        .to_string_lossy()
        .into_owned();
    let checksum_path = output_root.join(format!("{target}.tar.gz.sha256"));
    fs::write(&checksum_path, format!("{checksum}  {archive_name}\n"))
        .map_err(|error| format!("cannot write the package checksum: {error}"))?;

    println!("Heterarchy Forge backend package: {}", archive.display());
    println!("SHA-256: {checksum}");
    println!("Checksum file: {}", checksum_path.display());
    Ok(())
}

fn workspace_version(root: &Path) -> Result<String, String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("cannot read the workspace manifest: {error}"))?;
    let value = toml::from_str::<TomlValue>(&manifest)
        .map_err(|error| format!("cannot parse the workspace manifest: {error}"))?;
    value
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("version"))
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "workspace manifest is missing workspace.package.version".to_owned())
}

fn make_executable(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot stat the packaged backend binary: {error}"))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("cannot mark the packaged backend binary executable: {error}"))
}

fn require_regular_nonempty_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("{label} {} is unavailable: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{label} {} is not a regular file", path.display()));
    }
    if metadata.len() == 0 {
        return Err(format!("{label} {} is empty", path.display()));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open {} for hashing: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {} for hashing: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .fold(String::new(), |out, byte| format!("{out}{byte:02x}")))
}
