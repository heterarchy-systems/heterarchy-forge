//! Shared, test-only Forge workspace fixtures for identity and Harness gates.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_WORKSPACE_ROOT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

pub(super) struct WorkspaceRootFixtures {
    root: PathBuf,
    pub(super) forge_a: PathBuf,
    pub(super) forge_b: PathBuf,
    pub(super) unrelated: PathBuf,
}

impl WorkspaceRootFixtures {
    pub(super) fn new() -> Result<Self, String> {
        let temporary_base = crate::test_runner::configured_temporary_base()?;
        let fixture_id = NEXT_WORKSPACE_ROOT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = temporary_base.join(format!(
            "heterarchy-forge-xtask-root-resolution-{}-{}",
            std::process::id(),
            fixture_id
        ));
        Self::create_at(root)
    }

    fn create_at(root: PathBuf) -> Result<Self, String> {
        // Cleanup ownership starts only after this call creates the root.
        fs::create_dir(&root)
            .map_err(|error| format!("cannot create workspace-root fixture directory: {error}"))?;
        let fixtures = Self {
            forge_a: root.join("forge-a"),
            forge_b: root.join("forge-b"),
            unrelated: root.join("unrelated"),
            root,
        };
        write_forge_workspace(&fixtures.forge_a)?;
        write_forge_workspace(&fixtures.forge_b)?;
        fs::create_dir(&fixtures.unrelated)
            .map_err(|error| format!("cannot create unrelated directory: {error}"))?;
        Ok(fixtures)
    }

    pub(super) fn nested_unrelated_workspace(&self) -> Result<PathBuf, String> {
        let root = self.forge_a.join("nested-unrelated");
        fs::create_dir(&root)
            .map_err(|error| format!("cannot create nested workspace fixture: {error}"))?;
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\nresolver = \"3\"\n",
        )
        .map_err(|error| format!("cannot write nested workspace manifest: {error}"))?;
        let member = root.join("member/src");
        fs::create_dir_all(&member)
            .map_err(|error| format!("cannot create nested member directory: {error}"))?;
        fs::write(
            root.join("member/Cargo.toml"),
            "[package]\nname = \"nested-member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .map_err(|error| format!("cannot write nested member manifest: {error}"))?;
        Ok(member)
    }

    pub(super) fn malformed_nested_manifest(&self) -> Result<PathBuf, String> {
        let root = self.forge_a.join("nested-malformed");
        fs::create_dir(&root)
            .map_err(|error| format!("cannot create malformed workspace fixture: {error}"))?;
        fs::write(root.join("Cargo.toml"), "[workspace\n")
            .map_err(|error| format!("cannot write malformed workspace manifest: {error}"))?;
        Ok(root)
    }
}

impl Drop for WorkspaceRootFixtures {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("cannot remove workspace-root test fixtures: {error}");
        }
    }
}

pub(super) fn write_forge_workspace(root: &Path) -> Result<(), String> {
    for directory in [root.join("xtask"), root.join("crates/forge-backend/src")] {
        fs::create_dir_all(directory)
            .map_err(|error| format!("cannot create Forge workspace fixture: {error}"))?;
    }
    fs::create_dir_all(root.join(".agents/rust_dev_harness"))
        .map_err(|error| format!("cannot create Forge harness fixture: {error}"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"xtask\", \"crates/forge-backend\"]\nresolver = \"3\"\n",
    )
    .map_err(|error| format!("cannot write Forge workspace manifest: {error}"))?;
    fs::write(
        root.join("Cargo.lock"),
        "# workspace-root fixture lockfile\n",
    )
    .map_err(|error| format!("cannot write Forge lockfile fixture: {error}"))?;
    fs::write(root.join("AGENTS.md"), "Forge workspace-root fixture\n")
        .map_err(|error| format!("cannot write Forge root marker: {error}"))?;
    fs::write(
        root.join(".agents/rust_dev_harness/PROJECT_PROFILE.md"),
        "Forge Rust project profile fixture\n",
    )
    .map_err(|error| format!("cannot write Forge profile fixture: {error}"))?;
    fs::write(
        root.join("xtask/Cargo.toml"),
        "[package]\nname = \"xtask\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .map_err(|error| format!("cannot write xtask manifest fixture: {error}"))?;
    fs::write(
        root.join("crates/forge-backend/Cargo.toml"),
        "[package]\nname = \"forge-backend\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .map_err(|error| format!("cannot write backend manifest fixture: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_fixture_creation_preserves_an_unowned_directory() -> Result<(), String> {
        let owner = WorkspaceRootFixtures::new()?;
        let occupied = owner.forge_a.join("occupied");
        fs::create_dir(&occupied).map_err(|error| error.to_string())?;
        let sentinel = occupied.join("preexisting-data");
        fs::write(&sentinel, b"preserve").map_err(|error| error.to_string())?;

        assert!(WorkspaceRootFixtures::create_at(occupied).is_err());
        assert_eq!(
            fs::read(&sentinel).map_err(|error| error.to_string())?,
            b"preserve"
        );
        Ok(())
    }
}
