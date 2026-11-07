//! Select and validate the Forge workspace used by every repository gate.
//!
//! Cargo runtime metadata and invocation paths are identity inputs; private
//! Harness assets are deliberately outside workspace identity.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use toml::Value as TomlValue;

use super::{read_bounded_text, toml_at};

const CARGO_MANIFEST_DIR_ENV: &str = "CARGO_MANIFEST_DIR";
const CARGO_MANIFEST_PATH_ENV: &str = "CARGO_MANIFEST_PATH";

pub(super) fn workspace_root() -> Result<PathBuf, String> {
    // Cargo's runtime pair identifies the selected xtask package; direct binary
    // use has no pair and may only infer a root from the nearest workspace in CWD.
    let invocation_directory = env::current_dir()
        .map_err(|error| format!("cannot read the xtask invocation directory: {error}"))?;
    let manifest_dir = env::var_os(CARGO_MANIFEST_DIR_ENV);
    let manifest_path = env::var_os(CARGO_MANIFEST_PATH_ENV);
    workspace_root_from_inputs(
        &invocation_directory,
        manifest_dir.as_deref(),
        manifest_path.as_deref(),
    )
}

fn workspace_root_from_inputs(
    invocation_directory: &Path,
    manifest_dir: Option<&OsStr>,
    manifest_path: Option<&OsStr>,
) -> Result<PathBuf, String> {
    let invocation_directory = canonical_directory(invocation_directory, "invocation directory")?;
    let runtime_root = match (manifest_dir, manifest_path) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            return Err(format!(
                "Cargo must provide both {CARGO_MANIFEST_DIR_ENV} and {CARGO_MANIFEST_PATH_ENV}; refusing to fall back to the invocation directory"
            ));
        }
        (Some(manifest_dir), Some(manifest_path)) => Some(workspace_root_from_manifest_pair(
            Path::new(manifest_dir),
            Path::new(manifest_path),
        )?),
    };

    match runtime_root {
        Some(root) => {
            if let Some(invocation_root) =
                forge_workspace_root_from_directory(&invocation_directory)?
                && invocation_root != root
            {
                return Err(format!(
                    "invocation directory resolves to Forge workspace {}, but Cargo selected {}",
                    invocation_root.display(),
                    root.display()
                ));
            }
            Ok(root)
        }
        None => forge_workspace_root_from_directory(&invocation_directory)?.ok_or_else(|| {
            format!(
                "invocation directory {} is not inside a validated Forge Cargo workspace",
                invocation_directory.display()
            )
        }),
    }
}

fn workspace_root_from_manifest_pair(
    manifest_dir: &Path,
    manifest_path: &Path,
) -> Result<PathBuf, String> {
    let manifest_dir = canonical_directory(manifest_dir, CARGO_MANIFEST_DIR_ENV)?;
    if !manifest_path.is_absolute() {
        return Err(format!(
            "{CARGO_MANIFEST_PATH_ENV} must be absolute: {}",
            manifest_path.display()
        ));
    }
    let manifest_path = fs::canonicalize(manifest_path).map_err(|error| {
        format!(
            "cannot resolve {CARGO_MANIFEST_PATH_ENV} {}: {error}",
            manifest_path.display()
        )
    })?;
    let package_manifest = manifest_dir.join("Cargo.toml");
    let package_manifest = fs::canonicalize(&package_manifest).map_err(|error| {
        format!(
            "cannot resolve xtask package manifest {}: {error}",
            package_manifest.display()
        )
    })?;
    if manifest_path != package_manifest {
        return Err(format!(
            "{CARGO_MANIFEST_PATH_ENV} {} does not match {CARGO_MANIFEST_DIR_ENV}/Cargo.toml {}",
            manifest_path.display(),
            package_manifest.display()
        ));
    }

    let root = manifest_dir
        .parent()
        .ok_or_else(|| "xtask package directory has no workspace parent".to_owned())?;
    let expected_xtask_dir = fs::canonicalize(root.join("xtask"))
        .map_err(|error| format!("cannot resolve Forge xtask package directory: {error}"))?;
    if manifest_dir != expected_xtask_dir {
        return Err(format!(
            "Cargo selected xtask package {} outside its expected Forge workspace location {}",
            manifest_dir.display(),
            expected_xtask_dir.display()
        ));
    }
    validate_forge_workspace_root(root)
}

fn forge_workspace_root_from_directory(directory: &Path) -> Result<Option<PathBuf>, String> {
    let directory = canonical_directory(directory, "invocation directory")?;
    for ancestor in directory.ancestors() {
        let manifest_path = ancestor.join("Cargo.toml");
        let metadata = match fs::symlink_metadata(&manifest_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "cannot inspect workspace manifest {}: {error}",
                    manifest_path.display()
                ));
            }
        };
        if !metadata.file_type().is_file() {
            return Err(format!(
                "workspace manifest is not a regular file: {}",
                manifest_path.display()
            ));
        }
        let manifest = read_manifest_toml(&manifest_path, "workspace Cargo.toml")?;
        let Some(_) = manifest.get("workspace") else {
            continue;
        };
        if !workspace_identifies_forge(&manifest)? {
            return Ok(None);
        }
        return validate_forge_workspace_root(ancestor).map(Some);
    }
    Ok(None)
}

fn validate_forge_workspace_root(root: &Path) -> Result<PathBuf, String> {
    let root = canonical_directory(root, "Forge workspace root")?;
    let manifest_path = root.join("Cargo.toml");
    require_regular_root_marker(&root, "Cargo.toml")?;
    let manifest = read_manifest_toml(&manifest_path, "Forge workspace Cargo.toml")?;
    if !workspace_identifies_forge(&manifest)? {
        return Err(
            "Forge Cargo.toml must list both xtask and crates/forge-backend as workspace members"
                .to_owned(),
        );
    }

    require_regular_root_marker(&root, "xtask/Cargo.toml")?;
    let xtask_manifest = read_manifest_toml(&root.join("xtask/Cargo.toml"), "xtask manifest")?;
    if toml_at(&xtask_manifest, &["package", "name"]).and_then(TomlValue::as_str) != Some("xtask") {
        return Err("Forge workspace xtask member is not named \"xtask\"".to_owned());
    }
    require_regular_root_marker(&root, "crates/forge-backend/Cargo.toml")?;
    let backend_manifest = read_manifest_toml(
        &root.join("crates/forge-backend/Cargo.toml"),
        "Forge backend manifest",
    )?;
    if toml_at(&backend_manifest, &["package", "name"]).and_then(TomlValue::as_str)
        != Some("forge-backend")
    {
        return Err("Forge workspace root marker is not the forge-backend package".to_owned());
    }
    require_regular_root_marker(&root, "Cargo.lock")?;
    require_regular_root_marker(&root, "AGENTS.md")?;
    Ok(root)
}

fn workspace_identifies_forge(manifest: &TomlValue) -> Result<bool, String> {
    let Some(workspace) = manifest.get("workspace") else {
        return Ok(false);
    };
    let workspace = workspace
        .as_table()
        .ok_or_else(|| "Cargo manifest [workspace] is not a table".to_owned())?;
    let Some(members) = workspace.get("members") else {
        return Ok(false);
    };
    let members = members
        .as_array()
        .ok_or_else(|| "Cargo manifest [workspace].members is not an array".to_owned())?;
    if members.iter().any(|member| member.as_str().is_none()) {
        return Err("Cargo manifest has an invalid [workspace].members entry".to_owned());
    }
    Ok(members
        .iter()
        .any(|member| member.as_str() == Some("xtask"))
        && members
            .iter()
            .any(|member| member.as_str() == Some("crates/forge-backend")))
}

fn require_regular_root_marker(root: &Path, marker: &str) -> Result<(), String> {
    let path = root.join(marker);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        format!(
            "cannot inspect Forge workspace root marker {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(format!(
            "Forge workspace root marker is not a regular file: {}",
            path.display()
        ))
    }
}

fn read_manifest_toml(path: &Path, label: &str) -> Result<TomlValue, String> {
    let body = read_bounded_text(path, label).map_err(|error| error.to_string())?;
    toml::from_str(&body).map_err(|error| format!("invalid {label} {}: {error}", path.display()))
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute: {}", path.display()));
    }
    let path = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", path.display()))?;
    if !path.is_dir() {
        return Err(format!("{label} is not a directory: {}", path.display()));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use crate::test_support::{WorkspaceRootFixtures, write_forge_workspace};
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::workspace_root_from_inputs;

    fn runtime_manifest_pair(root: &Path) -> (PathBuf, PathBuf) {
        let manifest_dir = root.join("xtask");
        let manifest_path = manifest_dir.join("Cargo.toml");
        (manifest_dir, manifest_path)
    }

    #[test]
    fn runtime_manifest_pair_selects_its_forge_workspace_and_rejects_a_conflicting_cwd()
    -> Result<(), String> {
        let fixtures = WorkspaceRootFixtures::new()?;
        let (manifest_dir, manifest_path) = runtime_manifest_pair(&fixtures.forge_b);
        let member_cwd = fixtures.forge_b.join("crates/forge-backend/src");
        let selected = workspace_root_from_inputs(
            &member_cwd,
            Some(manifest_dir.as_os_str()),
            Some(manifest_path.as_os_str()),
        )?;
        assert_eq!(
            selected,
            fs::canonicalize(&fixtures.forge_b).map_err(|error| error.to_string())?
        );

        let conflicting_cwd = fixtures.forge_a.join("crates/forge-backend/src");
        assert!(
            workspace_root_from_inputs(
                &conflicting_cwd,
                Some(manifest_dir.as_os_str()),
                Some(manifest_path.as_os_str()),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn runtime_manifest_pair_allows_unrelated_cwd_but_never_falls_back_from_invalid_pair()
    -> Result<(), String> {
        let fixtures = WorkspaceRootFixtures::new()?;
        let (manifest_dir, manifest_path) = runtime_manifest_pair(&fixtures.forge_b);
        let selected = workspace_root_from_inputs(
            &fixtures.unrelated,
            Some(manifest_dir.as_os_str()),
            Some(manifest_path.as_os_str()),
        )?;
        assert_eq!(
            selected,
            fs::canonicalize(&fixtures.forge_b).map_err(|error| error.to_string())?
        );

        let fallback_cwd = fixtures.forge_a.join("crates/forge-backend/src");
        assert!(
            workspace_root_from_inputs(&fallback_cwd, Some(manifest_dir.as_os_str()), None,)
                .is_err()
        );
        assert!(
            workspace_root_from_inputs(&fallback_cwd, None, Some(manifest_path.as_os_str()),)
                .is_err()
        );

        let wrong_manifest = fixtures.forge_a.join("xtask/Cargo.toml");
        assert!(
            workspace_root_from_inputs(
                &fixtures.unrelated,
                Some(manifest_dir.as_os_str()),
                Some(wrong_manifest.as_os_str()),
            )
            .is_err()
        );
        let invalid_pair_above_valid_cwd = workspace_root_from_inputs(
            &fallback_cwd,
            Some(manifest_dir.as_os_str()),
            Some(wrong_manifest.as_os_str()),
        )
        .err()
        .ok_or_else(|| "an invalid manifest pair must not use a valid cwd fallback".to_owned())?;
        assert!(invalid_pair_above_valid_cwd.contains("does not match"));
        Ok(())
    }

    #[test]
    fn cwd_fallback_uses_the_nearest_forge_workspace_and_rejects_unrelated_workspaces()
    -> Result<(), String> {
        let fixtures = WorkspaceRootFixtures::new()?;
        let forge_root = fs::canonicalize(&fixtures.forge_a).map_err(|error| error.to_string())?;
        let member_cwd = fixtures.forge_a.join("crates/forge-backend/src");
        assert_eq!(
            workspace_root_from_inputs(&member_cwd, None, None)?,
            forge_root
        );

        let nested_cwd = fixtures.nested_unrelated_workspace()?;
        assert!(workspace_root_from_inputs(&nested_cwd, None, None).is_err());

        let malformed_cwd = fixtures.malformed_nested_manifest()?;
        assert!(workspace_root_from_inputs(&malformed_cwd, None, None).is_err());
        assert!(workspace_root_from_inputs(&fixtures.unrelated, None, None).is_err());
        Ok(())
    }

    #[test]
    fn runtime_manifest_pair_requires_both_forge_members_and_package_names() -> Result<(), String> {
        let fixtures = WorkspaceRootFixtures::new()?;
        let (manifest_dir, manifest_path) = runtime_manifest_pair(&fixtures.forge_b);
        fs::write(
            fixtures.forge_b.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/forge-backend\"]\nresolver = \"3\"\n",
        )
        .map_err(|error| format!("cannot mutate isolated workspace fixture: {error}"))?;
        assert!(
            workspace_root_from_inputs(
                &fixtures.unrelated,
                Some(manifest_dir.as_os_str()),
                Some(manifest_path.as_os_str()),
            )
            .is_err()
        );

        write_forge_workspace(&fixtures.forge_b)?;
        fs::write(
            fixtures.forge_b.join("Cargo.toml"),
            "[workspace]\nmembers = [\"xtask\"]\nresolver = \"3\"\n",
        )
        .map_err(|error| format!("cannot mutate isolated workspace members: {error}"))?;
        assert!(
            workspace_root_from_inputs(
                &fixtures.unrelated,
                Some(manifest_dir.as_os_str()),
                Some(manifest_path.as_os_str()),
            )
            .is_err()
        );

        write_forge_workspace(&fixtures.forge_b)?;
        fs::write(
            fixtures.forge_b.join("xtask/Cargo.toml"),
            "[package]\nname = \"wrong-xtask\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .map_err(|error| format!("cannot mutate isolated xtask manifest: {error}"))?;
        assert!(
            workspace_root_from_inputs(
                &fixtures.unrelated,
                Some(manifest_dir.as_os_str()),
                Some(manifest_path.as_os_str()),
            )
            .is_err()
        );

        write_forge_workspace(&fixtures.forge_b)?;
        fs::write(
            fixtures.forge_b.join("crates/forge-backend/Cargo.toml"),
            "[package]\nname = \"wrong-backend\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .map_err(|error| format!("cannot mutate isolated backend manifest: {error}"))?;
        assert!(
            workspace_root_from_inputs(
                &fixtures.unrelated,
                Some(manifest_dir.as_os_str()),
                Some(manifest_path.as_os_str()),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn cwd_forge_identity_survives_missing_policy_files_and_rejects_marker_failures()
    -> Result<(), String> {
        let fixtures = WorkspaceRootFixtures::new()?;
        let (manifest_dir, manifest_path) = runtime_manifest_pair(&fixtures.forge_b);
        let forge_cwd = fixtures.forge_a.join("crates/forge-backend/src");
        let forge_root = fs::canonicalize(&fixtures.forge_a).map_err(|error| error.to_string())?;

        fs::remove_file(
            fixtures
                .forge_a
                .join(".agents/rust_dev_harness/PROJECT_PROFILE.md"),
        )
        .map_err(|error| format!("cannot remove isolated Harness profile: {error}"))?;
        assert_eq!(
            workspace_root_from_inputs(&forge_cwd, None, None)?,
            forge_root
        );
        let conflicting = workspace_root_from_inputs(
            &forge_cwd,
            Some(manifest_dir.as_os_str()),
            Some(manifest_path.as_os_str()),
        )
        .err()
        .ok_or_else(|| {
            "a different Forge root must not be hidden by a missing Harness profile".to_owned()
        })?;
        assert!(conflicting.contains("invocation directory resolves to Forge workspace"));

        fs::remove_file(fixtures.forge_a.join("Cargo.lock"))
            .map_err(|error| format!("cannot remove isolated Cargo lockfile: {error}"))?;
        let missing_lock = workspace_root_from_inputs(
            &forge_cwd,
            Some(manifest_dir.as_os_str()),
            Some(manifest_path.as_os_str()),
        )
        .err()
        .ok_or_else(|| {
            "an identified Forge root without Cargo.lock must fail validation".to_owned()
        })?;
        assert!(missing_lock.contains("Cargo.lock"));

        fs::write(
            fixtures.forge_a.join("Cargo.lock"),
            "# workspace-root fixture lockfile\n",
        )
        .map_err(|error| format!("cannot restore isolated Cargo lockfile: {error}"))?;
        fs::remove_file(fixtures.forge_a.join("AGENTS.md"))
            .map_err(|error| format!("cannot remove isolated AGENTS marker: {error}"))?;
        let missing_agents = workspace_root_from_inputs(
            &forge_cwd,
            Some(manifest_dir.as_os_str()),
            Some(manifest_path.as_os_str()),
        )
        .err()
        .ok_or_else(|| {
            "an identified Forge root without AGENTS.md must fail validation".to_owned()
        })?;
        assert!(missing_agents.contains("AGENTS.md"));
        Ok(())
    }
}
