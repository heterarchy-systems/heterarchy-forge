//! Reproducible, bounded import of the independently built policy package.
//!
//! Policy source is edited in Orchestration. This directory is a Cargo package
//! projection included in Forge's sealed verification input, never a fork.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const NAME: &str = "heterarchy-orchestration-policy";
const IMPORT_PATH: &str = "vendor/heterarchy-orchestration-policy";
const INVENTORY: &str = ".forge-package.json";
const SOURCE_ARCHIVE: &str = ".forge-source.crate";
const MAX_FILES: usize = 128;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 8 * MAX_FILE_BYTES;

pub(super) fn run(root: &Path, arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let arguments: Vec<_> = arguments.take(4).collect();
    match arguments.as_slice() {
        [] => verify(root),
        [action, source] if action == "import" => import(root, Path::new(source)),
        _ => {
            Err("usage: cargo xtask policy-package [import <Orchestration repository>]".to_owned())
        }
    }
}

pub(super) fn verify(root: &Path) -> Result<(), String> {
    verify_directory(&root.join(IMPORT_PATH))?;
    verify_workspace_policy_binding(root)?;
    println!("Orchestration policy package inventory and standalone manifest verified");
    Ok(())
}

fn verify_workspace_policy_binding(root: &Path) -> Result<(), String> {
    let vendor = root.join(IMPORT_PATH);
    let vendor_manifest =
        super::read_toml_file(&vendor.join("Cargo.toml"), "vendor policy manifest")?;
    let version = super::toml_at(&vendor_manifest, &["package", "version"])
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("vendor policy package version is missing")?;
    let expected_requirement = format!("={version}");

    let workspace = super::read_toml_file(&root.join("Cargo.toml"), "Forge workspace Cargo.toml")?;
    let dependency = super::toml_at(&workspace, &["workspace", "dependencies", NAME])
        .and_then(toml::Value::as_table)
        .ok_or("Forge workspace policy dependency must be a table")?;
    if dependency.len() != 1
        || dependency.get("version").and_then(toml::Value::as_str)
            != Some(expected_requirement.as_str())
    {
        return Err(
            "Forge workspace policy dependency must be version-only and pinned to the vendor package"
                .to_owned(),
        );
    }

    let patch = super::toml_at(&workspace, &["patch", "crates-io", NAME])
        .and_then(toml::Value::as_table)
        .ok_or("Forge workspace must patch the policy package from its vendor root")?;
    if patch.len() != 1 || patch.get("path").and_then(toml::Value::as_str) != Some(IMPORT_PATH) {
        return Err("Forge policy patch must contain only the exact vendor policy path".to_owned());
    }

    for crate_path in [
        "crates/forge-control/Cargo.toml",
        "crates/forge-persistence/Cargo.toml",
    ] {
        let manifest = super::read_toml_file(&root.join(crate_path), crate_path)?;
        let inherited = super::toml_at(&manifest, &["dependencies", NAME])
            .and_then(toml::Value::as_table)
            .and_then(|table| table.get("workspace"))
            .and_then(toml::Value::as_bool);
        if inherited != Some(true) {
            return Err(format!(
                "{crate_path} must inherit the Forge workspace policy dependency"
            ));
        }
    }
    Ok(())
}

fn verify_directory(directory: &Path) -> Result<(), String> {
    let inventory = verify_preserved_files(directory)?;
    let manifest = super::read_toml_file(&directory.join("Cargo.toml"), "packaged manifest")?;
    let vcs = read_json(&directory.join(".cargo_vcs_info.json"))?;
    if inventory["version"].as_str()
        != super::toml_at(&manifest, &["package", "version"]).and_then(toml::Value::as_str)
        || inventory["canonicalRepository"] != "heterarchy-orchestration"
        || inventory["sourceGitHead"].as_str().is_none()
        || inventory["sourceGitHead"] != vcs["git"]["sha1"]
        || inventory["sourceCargoManifestSha256"]
            != hash(&read_file(&directory.join("Cargo.toml.orig"))?)
        || inventory["cargoArchiveSha256"] != hash(&read_file(&directory.join(SOURCE_ARCHIVE))?)
    {
        return Err(
            "policy package provenance differs from its packaged source/archive".to_owned(),
        );
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&read_file(path)?)
        .map_err(|error| format!("invalid policy package JSON: {error}"))
}

// Preservation checks also accept an older inventory without provenance
// fields, so an intentional re-import can upgrade the audit record. Canonical
// verification above always requires the complete current evidence.
fn verify_preserved_files(directory: &Path) -> Result<Value, String> {
    let body = read_file(&directory.join(INVENTORY))?;
    let inventory: Value = serde_json::from_slice(&body)
        .map_err(|error| format!("invalid policy package inventory: {error}"))?;
    if inventory["format"] != 1 || inventory["package"] != NAME {
        return Err("unsupported policy package inventory".to_owned());
    }
    let expected: BTreeMap<String, String> = serde_json::from_value(inventory["files"].clone())
        .map_err(|error| format!("invalid policy package file hashes: {error}"))?;
    if expected.is_empty() || expected.len() > MAX_FILES {
        return Err("policy package inventory exceeds its file bound".to_owned());
    }
    for path in expected.keys() {
        validate_relative(path)?;
    }
    let actual = collect_files(directory)?;
    let actual_hashes = hashes(&actual);
    if expected != actual_hashes {
        return Err("policy package differs from its imported inventory; preserve edits and re-import from canonical Orchestration source intentionally".to_owned());
    }
    validate_manifest(directory)?;
    Ok(inventory)
}

fn import(root: &Path, source: &Path) -> Result<(), String> {
    let source = fs::canonicalize(source)
        .map_err(|error| format!("cannot resolve Orchestration source: {error}"))?;
    let manifest = source.join("crates").join(NAME).join("Cargo.toml");
    let manifest_value = super::read_toml_file(&manifest, "canonical policy manifest")?;
    if super::toml_at(&manifest_value, &["package", "name"]).and_then(toml::Value::as_str)
        != Some(NAME)
    {
        return Err("source is not the canonical Orchestration policy package".to_owned());
    }
    let version = super::toml_at(&manifest_value, &["package", "version"])
        .and_then(toml::Value::as_str)
        .filter(|version| {
            !version.is_empty()
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        })
        .ok_or("policy package requires an explicit bounded version")?;
    if version.len() > 64 {
        return Err("policy package version is too long".to_owned());
    }
    let destination = root.join(IMPORT_PATH);
    if destination
        .try_exists()
        .map_err(|error| error.to_string())?
    {
        verify_preserved_files(&destination)?;
    }
    let before = source_inventory(&source)?;
    // Cargo normalizes workspace inheritance and verifies its own generated
    // archive. The resulting unpacked package is the sole import input.
    let generated = ensure_directory(&source, ".omx")?;
    let cache = ensure_directory(&generated, "policy-package")?;
    let target = cache.join(unique_suffix()?);
    fs::create_dir(&target).map_err(|error| error.to_string())?;
    let rustc = super::capture_process(
        Path::new("rustup"),
        &["which", "--toolchain", "1.98.0", "rustc"],
        &source,
        4096,
    )?;
    if !rustc.status.success() {
        return Err("Orchestration Rust 1.98 toolchain is unavailable".to_owned());
    }
    let rustc = String::from_utf8(rustc.stdout).map_err(|error| error.to_string())?;
    let status = std::process::Command::new("rustup")
        .args([
            "run",
            "1.98.0",
            "cargo",
            "package",
            "--allow-dirty",
            "--locked",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target)
        .env("RUSTC", rustc.trim())
        .current_dir(&source)
        .status()
        .map_err(|error| format!("cannot package policy: {error}"))?;
    if !status.success() {
        return Err(format!("policy Cargo packaging failed: {status}"));
    }
    let packaged = target.join("package").join(format!("{NAME}-{version}"));
    validate_manifest(&packaged)?;
    let mut files = collect_files(&packaged)?;
    let archive = target
        .join("package")
        .join(format!("{NAME}-{version}.crate"));
    let archive_bytes = read_file(&archive)?;
    let archive_hash = hash(&archive_bytes);
    files.insert(SOURCE_ARCHIVE.to_owned(), archive_bytes);
    if before != source_inventory(&source)? {
        return Err(
            "canonical policy inputs changed during Cargo packaging; no package was imported"
                .to_owned(),
        );
    }
    let vcs = read_json(&packaged.join(".cargo_vcs_info.json"))?;
    let inventory = json!({
        "format": 1,
        "package": NAME,
        "version": version,
        "canonicalRepository": "heterarchy-orchestration",
        "sourceGitHead": vcs["git"]["sha1"],
        "sourceCargoManifestSha256": hash(&read_file(&packaged.join("Cargo.toml.orig"))?),
        "cargoArchiveSha256": archive_hash,
        "files": hashes(&files),
    });
    activate_package(root, &files, &inventory)?;
    verify(root)
}

fn activate_package(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    inventory: &Value,
) -> Result<(), String> {
    let destination = root.join(IMPORT_PATH);
    let vendor = ensure_directory(root, "vendor")?;
    let _lock = ImportLock::acquire(&vendor)?;
    let generated = ensure_directory(root, ".omx")?;
    let backups = ensure_directory(&generated, "policy-package-backups")?;
    let suffix = unique_suffix()?;
    let staging = vendor.join(format!(".policy-import-{suffix}"));
    let backup = backups.join(suffix);
    fs::create_dir(&staging).map_err(|error| error.to_string())?;
    let prepared =
        write_package(&staging, files, inventory).and_then(|()| verify_directory(&staging));
    if let Err(error) = prepared {
        let _cleanup = fs::remove_dir_all(&staging);
        return Err(error);
    }
    // Recheck immediately before replacing a generated artifact, so a local
    // edit during Cargo packaging cannot silently disappear.
    let had_previous = destination
        .try_exists()
        .map_err(|error| error.to_string())?;
    if had_previous {
        verify_preserved_files(&destination)?;
        fs::rename(&destination, &backup).map_err(|error| error.to_string())?;
        if let Err(error) = verify_preserved_files(&backup) {
            fs::rename(&backup, &destination).map_err(|restore| {
                format!("package changed during activation: {error}; restore failed: {restore}")
            })?;
            return Err(error);
        }
    }
    if let Err(error) = fs::rename(&staging, &destination) {
        if had_previous {
            fs::rename(&backup, &destination).map_err(|restore| {
                format!(
                    "policy import failed: {error}; restore failed: {restore}; inspect {}",
                    backup.display()
                )
            })?;
        }
        return Err(format!("cannot activate policy package: {error}"));
    }
    if had_previous {
        // Retain the prior directory for recovery. Native editors do not take
        // our import lock; deleting it could lose a racing user edit.
        println!("Previous policy package retained at {}", backup.display());
    }
    Ok(())
}

struct ImportLock(std::path::PathBuf);

impl ImportLock {
    fn acquire(vendor: &Path) -> Result<Self, String> {
        let path = vendor.join(".policy-import.lock");
        fs::create_dir(&path).map_err(|error| {
            format!("policy import is locked or previous import needs inspection: {error}")
        })?;
        Ok(Self(path))
    }
}

impl Drop for ImportLock {
    fn drop(&mut self) {
        let _release = fs::remove_dir(&self.0);
    }
}

fn ensure_directory(parent: &Path, name: &str) -> Result<std::path::PathBuf, String> {
    let path = parent.join(name);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    if !fs::symlink_metadata(&path)
        .map_err(|error| error.to_string())?
        .is_dir()
    {
        return Err(format!(
            "package directory is not a real directory: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn unique_suffix() -> Result<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    Ok(format!("{}-{}", std::process::id(), now.as_nanos()))
}

fn source_inventory(source: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut inventory = hashes(&collect_files(&source.join("crates").join(NAME))?);
    for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        inventory.insert(
            format!("workspace/{name}"),
            hash(&read_file(&source.join(name))?),
        );
    }
    inventory.insert("git/HEAD".to_owned(), source_git_head(source)?);
    Ok(inventory)
}

fn source_git_head(source: &Path) -> Result<String, String> {
    let captured = super::capture_process(
        Path::new("git"),
        &["rev-parse", "--verify", "HEAD"],
        source,
        256,
    )?;
    let head = String::from_utf8(captured.stdout).map_err(|error| error.to_string())?;
    let head = head.trim();
    if !captured.status.success()
        || !matches!(head.len(), 40 | 64)
        || !head.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("cannot capture canonical source Git HEAD; dirty source bytes are separately inventoried".to_owned());
    }
    Ok(head.to_owned())
}

fn write_package(
    directory: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    inventory: &Value,
) -> Result<(), String> {
    for (relative, bytes) in files {
        let path = directory.join(relative);
        let parent = path.parent().ok_or("package path has no parent")?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        fs::write(path, bytes).map_err(|error| error.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(inventory).map_err(|error| error.to_string())?;
    fs::write(directory.join(INVENTORY), bytes).map_err(|error| error.to_string())
}

fn validate_manifest(directory: &Path) -> Result<(), String> {
    let manifest =
        super::read_toml_file(&directory.join("Cargo.toml"), "packaged policy manifest")?;
    if super::toml_at(&manifest, &["package", "name"]).and_then(toml::Value::as_str) != Some(NAME)
        || super::toml_at(&manifest, &["package", "rust-version"]).and_then(toml::Value::as_str)
            != Some("1.92")
        || super::toml_at(&manifest, &["package", "edition"]).and_then(toml::Value::as_str)
            != Some("2024")
        || manifest.get("workspace").is_some()
        || manifest.get("build-dependencies").is_some()
        || manifest.get("target").is_some()
        || manifest.get("patch").is_some()
        || manifest.get("replace").is_some()
        || super::toml_at(&manifest, &["package", "build"])
            .is_some_and(|value| value.as_bool() != Some(false))
        || directory.join("build.rs").exists()
    {
        return Err("policy package must be a standalone Rust1.92 pure library without workspace inheritance or build effects".to_owned());
    }
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or("policy package dependency table is missing")?;
    if dependencies.len() != 1 || !dependencies.contains_key("serde") {
        return Err("policy runtime dependencies must contain only serde".to_owned());
    }
    let serde = dependencies
        .get("serde")
        .ok_or("policy serde dependency is missing")?;
    validate_registry_dependency("serde", serde)?;
    if let Some(dependencies) = manifest.get("dev-dependencies") {
        let dependencies = dependencies
            .as_table()
            .ok_or("invalid policy test dependencies")?;
        if dependencies.len() > 1 || dependencies.keys().any(|name| name != "proptest") {
            return Err("policy test dependencies may contain only proptest".to_owned());
        }
        if let Some(dependency) = dependencies.get("proptest") {
            validate_registry_dependency("proptest", dependency)?;
        }
    }
    Ok(())
}

fn validate_registry_dependency(name: &str, dependency: &toml::Value) -> Result<(), String> {
    if ["path", "git", "workspace", "registry", "registry-index"]
        .iter()
        .any(|key| dependency.get(key).is_some())
        || dependency
            .get("package")
            .is_some_and(|value| value.as_str() != Some(name))
    {
        return Err(format!(
            "policy {name} must use its own default registry package"
        ));
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if !metadata.is_dir() {
        return Err("policy package root must be a real directory".to_owned());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    let mut bytes = 0_usize;
    let mut entries_seen = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            entries_seen += 1;
            if entries_seen > MAX_FILES * 2 {
                return Err("policy package directory entry bound exceeded".to_owned());
            }
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or("policy package paths must be UTF-8")?
                .to_owned();
            validate_relative(&relative)?;
            if relative == ".cargo" || relative.starts_with(".cargo/") {
                return Err(
                    "policy package must not carry Cargo source or build configuration".to_owned(),
                );
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                if relative == INVENTORY {
                    continue;
                }
                if result.len() >= MAX_FILES {
                    return Err("policy package file bound exceeded".to_owned());
                }
                let content = read_file(&path)?;
                bytes = bytes
                    .checked_add(content.len())
                    .ok_or("policy package size overflow")?;
                if bytes > MAX_TOTAL_BYTES {
                    return Err("policy package total byte bound exceeded".to_owned());
                }
                result.insert(relative, content);
            } else {
                return Err("policy package refuses symlinks and special files".to_owned());
            }
        }
    }
    Ok(result)
}

fn validate_relative(relative: &str) -> Result<(), String> {
    if relative.is_empty()
        || relative.len() > 512
        || relative.chars().any(char::is_control)
        || !Path::new(relative)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("invalid relative policy package path".to_owned());
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("policy package expected a regular file".to_owned());
    }
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    super::read_bounded(file, MAX_FILE_BYTES)
        .map_err(|error| format!("cannot read bounded policy package file: {error:?}"))
}

fn hashes(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|(path, bytes)| (path.clone(), hash(bytes)))
        .collect()
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Result<Self, String> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "forge-policy-package-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).map_err(|error| error.to_string())?;
            Ok(Self(path))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    fn package() -> (BTreeMap<String, Vec<u8>>, Value) {
        let manifest = b"[package]\nname='heterarchy-orchestration-policy'\nversion='0.1.0'\nrust-version='1.92'\nedition='2024'\n[dependencies.serde]\nversion='1.0'\n";
        let vcs = json!({"git":{"sha1":"1234567890123456789012345678901234567890"}});
        let files = BTreeMap::from([
            ("Cargo.toml".to_owned(), manifest.to_vec()),
            ("Cargo.toml.orig".to_owned(), manifest.to_vec()),
            (SOURCE_ARCHIVE.to_owned(), b"test archive bytes".to_vec()),
            (
                ".cargo_vcs_info.json".to_owned(),
                vcs.to_string().into_bytes(),
            ),
            ("src/lib.rs".to_owned(), b"pub struct Decision;\n".to_vec()),
        ]);
        let inventory = json!({"format":1,"package":NAME,"version":"0.1.0","canonicalRepository":"heterarchy-orchestration","sourceGitHead":vcs["git"]["sha1"],"sourceCargoManifestSha256":hash(manifest),"cargoArchiveSha256":hash(b"test archive bytes"),"files":hashes(&files)});
        (files, inventory)
    }

    fn write_workspace_binding_fixture(root: &Path) -> Result<(), String> {
        for crate_name in ["forge-control", "forge-persistence"] {
            let path = root.join("crates").join(crate_name).join("Cargo.toml");
            fs::create_dir_all(path.parent().ok_or("crate manifest parent missing")?)
                .map_err(|error| error.to_string())?;
            fs::write(
                path,
                format!(
                    "[package]\nname='{crate_name}'\nversion='0.1.0'\n[dependencies]\n{NAME}={{workspace=true}}\n"
                ),
            )
            .map_err(|error| error.to_string())?;
        }
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[workspace]\nmembers=['crates/forge-control','crates/forge-persistence']\n[workspace.dependencies]\n{NAME}={{version='=0.1.0'}}\n[patch.crates-io]\n{NAME}={{path='{IMPORT_PATH}'}}\n"
            ),
        )
        .map_err(|error| error.to_string())
    }

    #[test]
    fn workspace_policy_binding_requires_version_pin_vendor_patch_and_inheritance()
    -> Result<(), String> {
        let fixture = Fixture::new()?;
        let (files, inventory) = package();
        write_package(&fixture.0.join(IMPORT_PATH), &files, &inventory)?;
        for crate_name in ["forge-control", "forge-persistence"] {
            let path = fixture.0.join("crates").join(crate_name).join("Cargo.toml");
            fs::create_dir_all(path.parent().ok_or("crate manifest parent missing")?)
                .map_err(|error| error.to_string())?;
            fs::write(
                path,
                format!(
                    "[package]\nname='{crate_name}'\nversion='0.1.0'\n[dependencies]\n{NAME}={{workspace=true}}\n"
                ),
            )
            .map_err(|error| error.to_string())?;
        }
        let workspace = fixture.0.join("Cargo.toml");
        fs::write(
            &workspace,
            format!(
                "[workspace]\nmembers=['crates/forge-control','crates/forge-persistence']\n[workspace.dependencies]\n{NAME}={{version='=0.1.0'}}\n[patch.crates-io]\n{NAME}={{path='{IMPORT_PATH}'}}\n"
            ),
        )
        .map_err(|error| error.to_string())?;

        verify_workspace_policy_binding(&fixture.0)?;

        fs::write(
            &workspace,
            format!(
                "[workspace]\nmembers=['crates/forge-control','crates/forge-persistence']\n[workspace.dependencies]\n{NAME}={{version='=0.2.0'}}\n[patch.crates-io]\n{NAME}={{path='{IMPORT_PATH}'}}\n"
            ),
        )
        .map_err(|error| error.to_string())?;
        assert!(verify_workspace_policy_binding(&fixture.0).is_err());

        fs::write(
            &workspace,
            format!(
                "[workspace]\nmembers=['crates/forge-control','crates/forge-persistence']\n[workspace.dependencies]\n{NAME}={{version='=0.1.0'}}\n[patch.crates-io]\n{NAME}={{path='vendor/other-policy'}}\n"
            ),
        )
        .map_err(|error| error.to_string())?;
        assert!(verify_workspace_policy_binding(&fixture.0).is_err());
        Ok(())
    }
    #[test]
    fn inventory_paths_cannot_escape_or_hide_controls() {
        for path in [
            "",
            "../source.rs",
            "/source.rs",
            "src/../source.rs",
            "src/\n.rs",
        ] {
            assert!(validate_relative(path).is_err(), "{path:?}");
        }
        assert!(validate_relative("src/scheduler/queue.rs").is_ok());
    }

    #[test]
    fn import_reopens_and_refuses_to_replace_local_edits() -> Result<(), String> {
        let fixture = Fixture::new()?;
        let (files, inventory) = package();
        write_workspace_binding_fixture(&fixture.0)?;
        activate_package(&fixture.0, &files, &inventory)?;
        verify(&fixture.0)?;
        activate_package(&fixture.0, &files, &inventory)?;
        let source = fixture.0.join(IMPORT_PATH).join("src/lib.rs");
        fs::write(&source, b"user edit").map_err(|error| error.to_string())?;
        assert!(verify(&fixture.0).is_err());
        assert!(activate_package(&fixture.0, &files, &inventory).is_err());
        assert_eq!(read_file(&source)?, b"user edit");
        Ok(())
    }

    #[test]
    fn corrupt_manifest_and_extra_or_symbolic_files_are_rejected() -> Result<(), String> {
        let fixture = Fixture::new()?;
        let (files, inventory) = package();
        write_package(&fixture.0, &files, &inventory)?;
        verify_directory(&fixture.0)?;
        let extra = fixture.0.join("extra.rs");
        fs::write(&extra, b"extra").map_err(|error| error.to_string())?;
        assert!(verify_directory(&fixture.0).is_err());
        fs::remove_file(&extra).map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink("src/lib.rs", &extra).map_err(|error| error.to_string())?;
        assert!(collect_files(&fixture.0).is_err());
        fs::remove_file(&extra).map_err(|error| error.to_string())?;
        fs::write(fixture.0.join("Cargo.toml"), b"[unrelated]\nvalue=1\n")
            .map_err(|error| error.to_string())?;
        assert!(validate_manifest(&fixture.0).is_err());
        Ok(())
    }

    #[test]
    fn importer_serializes_activation_and_keeps_previous_bytes() -> Result<(), String> {
        let fixture = Fixture::new()?;
        let (files, inventory) = package();
        activate_package(&fixture.0, &files, &inventory)?;
        let vendor = fixture.0.join("vendor");
        let lock = ImportLock::acquire(&vendor)?;
        assert!(activate_package(&fixture.0, &files, &inventory).is_err());
        drop(lock);
        activate_package(&fixture.0, &files, &inventory)?;
        let backups = fs::read_dir(fixture.0.join(".omx/policy-package-backups"))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        assert_eq!(backups.len(), 1);
        verify_directory(&backups[0].path())?;
        Ok(())
    }

    #[test]
    fn policy_dependency_sources_cannot_hide_behind_serde_or_tests() -> Result<(), String> {
        let fixture = Fixture::new()?;
        let (files, _) = package();
        let original =
            String::from_utf8(files.get("Cargo.toml").ok_or("missing manifest")?.clone())
                .map_err(|error| error.to_string())?;
        for extra in [
            "registry='other'\n",
            "package='other'\n",
            "[patch.crates-io]\nserde={path='../other'}\n",
            "[dev-dependencies]\nother='1'\n",
        ] {
            fs::write(fixture.0.join("Cargo.toml"), format!("{original}{extra}"))
                .map_err(|error| error.to_string())?;
            assert!(validate_manifest(&fixture.0).is_err(), "{extra}");
        }
        let link = fixture.0.join(".omx");
        std::os::unix::fs::symlink("/tmp", &link).map_err(|error| error.to_string())?;
        assert!(ensure_directory(&fixture.0, ".omx").is_err());
        Ok(())
    }

    #[test]
    fn provenance_fields_are_checked_against_packaged_bytes() -> Result<(), String> {
        let fixture = Fixture::new()?;
        let (files, inventory) = package();
        for field in [
            "version",
            "sourceGitHead",
            "sourceCargoManifestSha256",
            "cargoArchiveSha256",
            "canonicalRepository",
        ] {
            let mut corrupt = inventory.clone();
            corrupt[field] = json!("tampered");
            write_package(&fixture.0, &files, &corrupt)?;
            assert!(verify_directory(&fixture.0).is_err(), "{field}");
        }
        Ok(())
    }
}
