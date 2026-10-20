use std::error::Error;
use std::fs::{self, Permissions, hard_link};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use forge_domain::{
    MAX_VERIFICATION_INPUT_FILE_BYTES, VerificationInputFingerprint, VerificationInputId,
    VerificationInputManifestError, WorkspaceRelativePath,
};
use uuid::Uuid;

use super::*;

fn temp_workspace(label: &str) -> Result<(PathBuf, ConfinedWorkspace), Box<dyn Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-verification-{label}-{}",
        Uuid::now_v7()
    ));
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    crate::WorkspaceStateLayout::initialize(&root)?;
    let layout = crate::WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
    let workspace = ConfinedWorkspace::open(&layout)?;
    Ok((root, workspace))
}

fn write_relative(root: &Path, relative: &str, content: &[u8]) -> Result<(), Box<dyn Error>> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn restore_permissions(path: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    let mode = metadata.permissions().mode();
    let restored = if metadata.is_dir() {
        mode | 0o700
    } else {
        mode | 0o600
    };
    fs::set_permissions(path, Permissions::from_mode(restored))?;
    if metadata.is_dir() {
        for child in fs::read_dir(path)? {
            restore_permissions(&child?.path())?;
        }
    }
    Ok(())
}

fn cleanup(root: PathBuf, workspace: ConfinedWorkspace) -> Result<(), Box<dyn Error>> {
    drop(workspace);
    restore_permissions(&root)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

fn pending_root(root: &Path, id: VerificationInputId) -> PathBuf {
    root.join(".heterarchy-forge")
        .join("artifacts")
        .join("verification")
        .join(format!(".pending-{id}"))
}

fn manifest_paths(manifest: &forge_domain::VerificationInputManifest) -> Vec<Vec<u8>> {
    manifest
        .entries()
        .iter()
        .map(|entry| {
            entry
                .path()
                .as_path()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        })
        .collect()
}

#[test]
fn execution_file_read_preserves_manifest_capacity_and_rejects_tampering()
-> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("execution-read")?;
    let bytes = vec![0x5a; MAX_FILE_READ_BYTES + 1];
    write_relative(&root, "large.rs", &bytes)?;
    let snapshot = workspace
        .stage_verification_input(
            VerificationInputId::from_uuid(Uuid::now_v7()),
            &NO_CANCELLATION,
        )?
        .publish()?;
    let path = WorkspaceRelativePath::new("large.rs".into())?;
    assert!(
        snapshot
            .read_file(&path, MAX_FILE_READ_BYTES, &NO_CANCELLATION)
            .is_err()
    );
    assert_eq!(
        snapshot.read_execution_file(&path, &NO_CANCELLATION)?,
        bytes
    );
    let leaf = snapshot.source_root().join("large.rs");
    fs::set_permissions(&leaf, Permissions::from_mode(0o600))?;
    fs::write(&leaf, vec![0x5b; bytes.len()])?;
    fs::set_permissions(&leaf, Permissions::from_mode(0o444))?;
    assert!(
        snapshot
            .read_execution_file(&path, &NO_CANCELLATION)
            .is_err()
    );
    drop(snapshot);
    cleanup(root, workspace)
}

fn has_path(manifest: &forge_domain::VerificationInputManifest, expected: &[u8]) -> bool {
    manifest_paths(manifest)
        .iter()
        .any(|path| path.as_slice() == expected)
}

fn path(value: &str) -> Result<WorkspaceRelativePath, Box<dyn Error>> {
    Ok(WorkspaceRelativePath::new(PathBuf::from(value))?)
}

#[test]
fn generic_v1_coverage_copies_binary_and_mixed_eol_and_excludes_generated_state()
-> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("coverage")?;
    write_relative(&root, "src/lib.rs", b"one\r\ntwo\nthree\r")?;
    write_relative(&root, "tests/integration.rs", b"#[test]\nfn smoke() {}\n")?;
    write_relative(
        &root,
        ".cargo/config.toml",
        b"[build]\ntarget-dir = \"target\"\n",
    )?;
    write_relative(&root, ".agents/team/config.bin", b"binary\0\xff\r\n")?;
    write_relative(&root, "build.rs", b"fn main() {}\n")?;
    write_relative(&root, "README.md", b"readme\n")?;
    write_relative(&root, "docs/guide.md", b"guide\n")?;
    write_relative(&root, ".codegraph/index", b"ignored")?;
    write_relative(&root, ".omx/runtime/state", b"ignored")?;
    write_relative(&root, ".chatgpt2codex/state", b"ignored")?;
    write_relative(&root, ".DS_Store", b"ignored")?;
    write_relative(&root, "target/debug/generated", b"ignored")?;
    write_relative(&root, "dist/release", b"ignored")?;

    let cancellation = AtomicBool::new(false);
    let observed = workspace.observe_verification_input(&cancellation)?;
    for expected in [
        b"src".as_slice(),
        b"src/lib.rs".as_slice(),
        b"tests".as_slice(),
        b"tests/integration.rs".as_slice(),
        b".cargo".as_slice(),
        b".cargo/config.toml".as_slice(),
        b".agents".as_slice(),
        b".agents/team".as_slice(),
        b".agents/team/config.bin".as_slice(),
        b"build.rs".as_slice(),
        b"README.md".as_slice(),
        b"docs".as_slice(),
        b"docs/guide.md".as_slice(),
    ] {
        assert!(has_path(&observed, expected), "missing {expected:?}");
    }
    for excluded in [
        b".codegraph".as_slice(),
        b".omx".as_slice(),
        b".chatgpt2codex".as_slice(),
        b".DS_Store".as_slice(),
        b"target".as_slice(),
        b"dist".as_slice(),
        b".heterarchy-forge".as_slice(),
    ] {
        assert!(!has_path(&observed, excluded), "included {excluded:?}");
    }

    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    let staged = workspace.stage_verification_input(id, &cancellation)?;
    assert_eq!(staged.manifest(), &observed);
    let published = staged.publish()?;
    write_relative(&root, "src/lib.rs", b"live replacement\n")?;
    write_relative(&root, ".agents/team/config.bin", b"changed\0")?;
    assert_eq!(
        published.read_file(&path("src/lib.rs")?, 32 * 1024, &cancellation)?,
        b"one\r\ntwo\nthree\r"
    );
    assert_eq!(
        published.read_file(&path(".agents/team/config.bin")?, 32 * 1024, &cancellation,)?,
        b"binary\0\xff\r\n"
    );
    published.validate()?;
    drop(published);
    drop(staged);
    cleanup(root, workspace)
}

#[test]
fn reopen_is_read_only_and_requires_exact_fingerprint() -> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("reopen")?;
    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    let cancellation = AtomicBool::new(false);
    let missing =
        workspace.open_verification_input(id, VerificationInputFingerprint::from_bytes([0; 32]));
    assert!(matches!(missing, Err(VerificationInputError::NotFound)));
    assert!(
        !root
            .join(".heterarchy-forge/artifacts/verification")
            .exists()
    );

    write_relative(&root, "Makefile", b"ci:\n\ttrue\n")?;
    let staged = workspace.stage_verification_input(id, &cancellation)?;
    let published = staged.publish()?;
    let expected = published.manifest().fingerprint();
    assert!(matches!(
        workspace.open_verification_input(id, VerificationInputFingerprint::from_bytes([9; 32])),
        Err(VerificationInputError::FingerprintMismatch)
    ));
    let reopened = workspace.open_verification_input(id, expected)?;
    assert_eq!(reopened.id(), id);
    assert_eq!(reopened.manifest(), published.manifest());
    drop(reopened);
    drop(published);
    drop(staged);
    cleanup(root, workspace)
}

#[test]
fn published_snapshot_rejects_content_and_mode_tampering() -> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("tamper")?;
    write_relative(&root, "Makefile", b"ci:\n\ttrue\n")?;
    let cancellation = AtomicBool::new(false);
    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    let staged = workspace.stage_verification_input(id, &cancellation)?;
    let published = staged.publish()?;
    let snapshot_file = published.source_root().join("Makefile");
    let mut permissions = fs::metadata(&snapshot_file)?.permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&snapshot_file, permissions)?;
    fs::write(&snapshot_file, b"tampered\n")?;
    assert!(matches!(
        published.validate(),
        Err(VerificationInputError::SnapshotInvalid | VerificationInputError::SnapshotStale)
    ));
    drop(published);
    drop(staged);
    cleanup(root, workspace)
}

#[test]
fn collision_preserves_original_and_abandon_preserves_replacement_sentinel()
-> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("collision")?;
    write_relative(&root, "Makefile", b"original\n")?;
    let cancellation = AtomicBool::new(false);
    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    let first = workspace.stage_verification_input(id, &cancellation)?;
    let published = first.publish()?;
    drop(first);

    let second = workspace.stage_verification_input(id, &cancellation)?;
    assert!(matches!(
        second.publish(),
        Err(VerificationInputError::Collision)
    ));
    let pending = pending_root(&root, id);
    restore_permissions(&pending)?;
    fs::remove_dir_all(&pending)?;
    fs::create_dir_all(&pending)?;
    write_relative(&pending, "sentinel", b"preserve me")?;
    assert!(matches!(
        second.abandon(),
        Err(VerificationInputError::SnapshotStale
            | VerificationInputError::Filesystem(ConfinedFilesystemError::PathChanged))
    ));
    assert_eq!(fs::read(pending.join("sentinel"))?, b"preserve me");

    assert_eq!(
        fs::read(published.source_root().join("Makefile"))?,
        b"original\n"
    );
    drop(published);
    cleanup(root, workspace)
}

#[test]
fn cancellation_caps_and_unsupported_entries_fail_without_published_partial_state()
-> Result<(), Box<dyn Error>> {
    let cancellation = AtomicBool::new(true);
    let (root, workspace) = temp_workspace("cancel")?;
    write_relative(&root, "source.txt", b"source")?;
    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    assert!(matches!(
        workspace.stage_verification_input(id, &cancellation),
        Err(VerificationInputError::Cancelled)
    ));
    cleanup(root, workspace)?;

    let (root, workspace) = temp_workspace("symlink")?;
    write_relative(&root, "outside.txt", b"outside")?;
    symlink(root.join("outside.txt"), root.join("link.txt"))?;
    let cancellation = AtomicBool::new(false);
    assert!(matches!(
        workspace.stage_verification_input(
            VerificationInputId::from_uuid(Uuid::now_v7()),
            &cancellation
        ),
        Err(VerificationInputError::Filesystem(
            ConfinedFilesystemError::SymlinkRejected
        ))
    ));
    cleanup(root, workspace)?;

    let (root, workspace) = temp_workspace("hardlink")?;
    write_relative(&root, "original.txt", b"same")?;
    hard_link(root.join("original.txt"), root.join("alias.txt"))?;
    assert!(matches!(
        workspace.stage_verification_input(
            VerificationInputId::from_uuid(Uuid::now_v7()),
            &cancellation
        ),
        Err(VerificationInputError::Filesystem(
            ConfinedFilesystemError::HardlinkRejected
        ))
    ));
    cleanup(root, workspace)?;

    let (root, workspace) = temp_workspace("special-mode")?;
    write_relative(&root, "setuid.txt", b"mode")?;
    fs::set_permissions(root.join("setuid.txt"), Permissions::from_mode(0o4644))?;
    assert!(matches!(
        workspace.stage_verification_input(
            VerificationInputId::from_uuid(Uuid::now_v7()),
            &cancellation
        ),
        Err(VerificationInputError::Manifest(
            VerificationInputManifestError::UnsupportedMode
        ))
    ));
    cleanup(root, workspace)?;

    let (root, workspace) = temp_workspace("file-cap")?;
    let oversized = vec![b'x'; usize::try_from(MAX_VERIFICATION_INPUT_FILE_BYTES)? + 1];
    write_relative(&root, "oversized.bin", &oversized)?;
    assert!(matches!(
        workspace.stage_verification_input(
            VerificationInputId::from_uuid(Uuid::now_v7()),
            &cancellation
        ),
        Err(VerificationInputError::Manifest(
            VerificationInputManifestError::FileCapacity
        ))
    ));
    cleanup(root, workspace)
}

#[test]
fn staging_preserves_state_gate_busy_source() -> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("state-gate-busy")?;
    write_relative(&root, "source.txt", b"source")?;
    let layout = crate::WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
    let fingerprint = layout.root_fingerprint()?;
    let exclusive = crate::WorkspaceStateExclusiveGate::acquire(&root, fingerprint)?;
    let cancellation = AtomicBool::new(false);
    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    let Err(error) = workspace.stage_verification_input(id, &cancellation) else {
        return Err("staging unexpectedly acquired a shared state gate".into());
    };
    assert!(matches!(
        error,
        VerificationInputError::StateGate(crate::WorkspaceStateGateError::Busy)
    ));
    drop(exclusive);
    cleanup(root, workspace)
}

#[test]
fn published_state_gate_blocks_exclusive_removal_until_handle_drop() -> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("state-gate")?;
    write_relative(&root, "source.txt", b"source")?;
    let cancellation = AtomicBool::new(false);
    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    let staged = workspace.stage_verification_input(id, &cancellation)?;
    let published = staged.publish()?;
    let layout = crate::WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
    let fingerprint = layout.root_fingerprint()?;
    assert!(matches!(
        crate::WorkspaceStateExclusiveGate::acquire(&root, fingerprint),
        Err(crate::WorkspaceStateGateError::Busy)
    ));
    drop(published);
    drop(staged);
    let exclusive = crate::WorkspaceStateExclusiveGate::acquire(&root, fingerprint)?;
    drop(exclusive);
    cleanup(root, workspace)
}

#[test]
fn published_input_purge_is_manifest_bound_and_preserves_neighbor() -> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("purge")?;
    write_relative(&root, "source.txt", b"source")?;
    write_relative(&root, "neighbor.txt", b"keep")?;
    let cancellation = AtomicBool::new(false);
    let id = VerificationInputId::from_uuid(Uuid::now_v7());
    let staged = workspace.stage_verification_input(id, &cancellation)?;
    let fingerprint = staged.manifest().fingerprint();
    let bytes = staged.manifest().total_bytes().get();
    let published = staged.publish()?;
    drop(published);
    drop(staged);
    let layout = crate::WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
    let root_fingerprint = layout.root_fingerprint()?;
    let gate = crate::WorkspaceStateExclusiveGate::acquire(&root, root_fingerprint)?;
    let guard = workspace.acquire_write_guard()?;
    assert!(matches!(
        workspace.purge_verification_input(
            &gate,
            &guard,
            id,
            VerificationInputFingerprint::from_bytes([0; 32]),
            bytes,
            &cancellation,
        ),
        Err(VerificationInputError::FingerprintMismatch)
    ));
    let status =
        workspace.purge_verification_input(&gate, &guard, id, fingerprint, bytes, &cancellation)?;
    assert_eq!(status, VerificationInputCleanupStatus::Deleted);
    assert!(
        !root
            .join(".heterarchy-forge/artifacts/verification")
            .join(id.to_string())
            .try_exists()?
    );
    assert_eq!(fs::read(root.join("neighbor.txt"))?, b"keep");
    drop(guard);
    drop(gate);
    cleanup(root, workspace)
}

#[test]
fn purge_retries_after_bounded_cleanup_faults() -> Result<(), Box<dyn Error>> {
    for (label, fault) in [
        ("after-chmod", VerificationInputCleanupFault::AfterChmod),
        (
            "after-file-delete",
            VerificationInputCleanupFault::AfterFileDelete,
        ),
        (
            "after-manifest-unlink",
            VerificationInputCleanupFault::AfterManifestUnlink,
        ),
    ] {
        let (root, workspace) = temp_workspace(label)?;
        write_relative(&root, "source.txt", b"source")?;
        write_relative(&root, "neighbor.txt", b"keep")?;
        let cancellation = AtomicBool::new(false);
        let id = VerificationInputId::from_uuid(Uuid::now_v7());
        let staged = workspace.stage_verification_input(id, &cancellation)?;
        let fingerprint = staged.manifest().fingerprint();
        let bytes = staged.manifest().total_bytes().get();
        let published = staged.publish()?;
        drop(published);
        drop(staged);
        let layout =
            crate::WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let root_fingerprint = layout.root_fingerprint()?;
        let gate = crate::WorkspaceStateExclusiveGate::acquire(&root, root_fingerprint)?;
        let guard = workspace.acquire_write_guard()?;
        assert!(matches!(
            workspace.purge_verification_input_with_fault(
                &gate,
                &guard,
                id,
                fingerprint,
                bytes,
                &cancellation,
                fault,
            ),
            Err(VerificationInputError::CleanupFailed)
        ));
        assert_eq!(
            workspace.purge_verification_input(
                &gate,
                &guard,
                id,
                fingerprint,
                bytes,
                &cancellation,
            )?,
            VerificationInputCleanupStatus::Deleted
        );
        assert_eq!(fs::read(root.join("neighbor.txt"))?, b"keep");
        drop(guard);
        drop(gate);
        cleanup(root, workspace)?;
    }
    Ok(())
}

#[test]
fn manifest_codec_rejects_truncation_header_and_unknown_records() -> Result<(), Box<dyn Error>> {
    let (root, workspace) = temp_workspace("codec")?;
    write_relative(&root, "README.md", b"manifest\n")?;
    let cancellation = AtomicBool::new(false);
    let manifest = workspace.observe_verification_input(&cancellation)?;
    let encoded = encode_manifest(&manifest)?;
    assert_eq!(decode_manifest(&encoded)?, manifest);

    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(matches!(
        decode_manifest(&truncated),
        Err(VerificationInputError::ManifestMalformed)
    ));
    let mut bad_header = encoded.clone();
    bad_header[0] = b'X';
    assert!(matches!(
        decode_manifest(&bad_header),
        Err(VerificationInputError::ManifestMalformed)
    ));
    let mut unknown = encoded;
    unknown.extend_from_slice(b"unknown\tvalue\n");
    assert!(matches!(
        decode_manifest(&unknown),
        Err(VerificationInputError::ManifestMalformed)
    ));
    cleanup(root, workspace)
}
