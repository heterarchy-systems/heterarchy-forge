//! Whole-state removal must preserve unmatched Home archives as unresolved custody.
use super::*;

#[test]
fn unmatched_home_archive_blocks_state_removal_even_after_user_git_disappears()
-> Result<(), Box<dyn std::error::Error>> {
    use forge_domain::{
        AgentAssignmentId, AgentAssignmentRevision, HomeArtifactCaptureIntent, HomeArtifactId,
        WorkspaceRelativePath,
    };
    use forge_workspace::{
        FORGE_GIT_PROGRAM, GitCheckpointStore, HomeArtifactStore, WorkspaceStateExclusiveGate,
    };

    let root = unique_root("home-artifact-removal")?;
    let git = std::process::Command::new(FORGE_GIT_PROGRAM)
        .args(["init", "--quiet"])
        .arg(&root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()?;
    assert!(git.status.success(), "Git fixture initialization failed");
    let layout = WorkspaceStateLayout::initialize(&root)?;
    let workspace = workspace_id(0xAD73);
    let location = location_id(0xAD74);
    let store = WorkspaceStore::open(&layout, &command(&layout, workspace, location, 1)?)?;
    assert!(
        !crate::workspace_home_transfers::artifacts::blocks_state_removal(
            &store.connection,
            workspace
        )?
    );
    fs::write(root.join("retained.txt"), b"promised bytes")?;
    let intent = HomeArtifactCaptureIntent::new(
        HomeArtifactId::new(Uuid::from_u128(0xAD75))?,
        Uuid::from_u128(0xAD76),
        Uuid::from_u128(0xAD77),
        workspace,
        AgentAssignmentId::from_uuid(Uuid::from_u128(0xAD78)),
        AgentAssignmentRevision::INITIAL,
        AgentAssignmentId::from_uuid(Uuid::from_u128(0xAD78)),
        vec![WorkspaceRelativePath::new(PathBuf::from("retained.txt"))?],
    )?;
    // An intentionally unmatched low-level archive is not an authorized
    // handoff. It must nevertheless remain protected from destructive cleanup.
    let git_store = GitCheckpointStore::from_state_layout(&layout)?;
    let archive = HomeArtifactStore::new(&git_store).publish(&intent, TimestampMillis::new(2)?)?;
    drop(git_store);
    drop(store);
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    let gate = WorkspaceStateExclusiveGate::acquire(&root, layout.root_fingerprint()?)?;
    assert!(matches!(
        WorkspaceStore::preflight_state_removal_under_exclusive(&existing, &gate, location),
        Err(WorkspaceStoreError::StateRemovalBlocked(
            WorkspaceStateRemovalBlocker::RetainedHomeArtifact
        )),
    ));
    let git_store =
        GitCheckpointStore::open_existing_read_only(&existing)?.ok_or("archive store missing")?;
    assert_eq!(
        HomeArtifactStore::new(&git_store).read(&intent)?,
        Some(archive)
    );
    drop(git_store);
    fs::rename(root.join(".git"), root.join("detached-git-fixture"))?;
    assert!(matches!(
        WorkspaceStore::preflight_state_removal_under_exclusive(&existing, &gate, location),
        Err(WorkspaceStoreError::StateRemovalBlocked(
            WorkspaceStateRemovalBlocker::RetainedHomeArtifact
        )),
    ));
    assert!(existing.database_path().exists());
    assert!(existing.checkpoints().join("store.git").exists());
    assert_eq!(fs::read(root.join("retained.txt"))?, b"promised bytes");
    fs::rename(root.join("detached-git-fixture"), root.join(".git"))?;
    let loose_ref = existing
        .checkpoints()
        .join("store.git/refs/heterarchy-forge/home-artifacts")
        .join(intent.artifact_id().into_uuid().to_string());
    // Git can omit broken loose refs from successful enumeration output.
    // Neither a warning nor an empty stdout may authorize destructive removal.
    for broken in [
        b"".as_slice(),
        b"0000000000000000000000000000000000000000\n".as_slice(),
    ] {
        fs::write(&loose_ref, broken)?;
        assert!(
            WorkspaceStore::preflight_state_removal_under_exclusive(&existing, &gate, location)
                .is_err()
        );
        assert!(existing.database_path().exists());
        assert_eq!(fs::read(&loose_ref)?, broken);
    }
    drop(gate);
    fs::remove_dir_all(root)?;
    Ok(())
}
