//! No-copy, no-replacement filesystem boundary for an exact same-device root.
use super::{Plan, RelocationError};
use forge_workspace::WorkspaceStateLayout;
use rustix::fs::{Mode, OFlags, RenameFlags, open, renameat_with};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub(super) fn read_private(path: &Path) -> Result<Vec<u8>, RelocationError> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.permissions().mode() & 0o077 != 0
        || m.uid() != rustix::process::getuid().as_raw()
        || m.len() > 65536
    {
        return Err(RelocationError::Conflict("unsafe relocation plan"));
    }
    let mut bytes = Vec::new();
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    File::from(descriptor).take(65537).read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn validate_plan(p: &Plan) -> Result<(), RelocationError> {
    if p.request_id.is_nil()
        || p.location_id.is_nil()
        || p.workspace_id.is_nil()
        || p.expected_location_revision < 1
        || p.expected_workspace_revision < 1
        || p.expected_location_revision == i64::MAX
        || p.expected_workspace_revision == i64::MAX
        || p.observed_at_ms < 0
        || !p.registry_path.is_absolute()
        || !p.source.is_absolute()
        || !p.destination.is_absolute()
        || p.source.starts_with(&p.destination)
        || p.destination.starts_with(&p.source)
    {
        return Err(RelocationError::Conflict("invalid plan fields"));
    }
    for path in [&p.registry_path, &p.source, &p.destination] {
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(RelocationError::Conflict("noncanonical plan path"));
        }
    }
    let destination_parent = p
        .destination
        .parent()
        .ok_or(RelocationError::Conflict("destination parent"))?;
    let source_parent = p
        .source
        .parent()
        .ok_or(RelocationError::Conflict("source parent"))?;
    for parent in [destination_parent, source_parent] {
        if fs::canonicalize(parent)? != parent || !fs::symlink_metadata(parent)?.is_dir() {
            return Err(RelocationError::Conflict("noncanonical parent"));
        }
    }
    if fs::metadata(destination_parent)?.dev() != fs::metadata(source_parent)?.dev() {
        return Err(RelocationError::Conflict(
            "cross-device relocation rejected",
        ));
    }
    Ok(())
}

pub(super) fn require_root(path: &Path, p: &Plan) -> Result<(), RelocationError> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || fs::canonicalize(path)? != path
        || WorkspaceStateLayout::observe_root_fingerprint(path)?.into_bytes() != p.root_fingerprint
    {
        return Err(RelocationError::Conflict("physical root identity changed"));
    }
    Ok(())
}

pub(super) fn rename(p: &Plan) -> Result<(), RelocationError> {
    let old = p
        .source
        .parent()
        .ok_or(RelocationError::Conflict("source parent"))?;
    let new = p
        .destination
        .parent()
        .ok_or(RelocationError::Conflict("destination parent"))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let from = open(old, flags, Mode::empty()).map_err(std::io::Error::from)?;
    let to = open(new, flags, Mode::empty()).map_err(std::io::Error::from)?;
    if fs::symlink_metadata(&p.destination).is_ok() {
        return Err(RelocationError::Conflict("destination exists"));
    }
    require_root(&p.source, p)?;
    renameat_with(
        &from,
        p.source
            .file_name()
            .ok_or(RelocationError::Conflict("source leaf"))?,
        &to,
        p.destination
            .file_name()
            .ok_or(RelocationError::Conflict("destination leaf"))?,
        RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    File::open(old)?.sync_all()?;
    File::open(new)?.sync_all()?;
    require_root(&p.destination, p)
}

pub(super) fn require_database(root: &Path, p: &Plan) -> Result<(), RelocationError> {
    let database = root.join(".heterarchy-forge/state.sqlite3");
    let metadata = fs::symlink_metadata(database)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.dev() != p.database_device
        || metadata.ino() != p.database_inode
    {
        return Err(RelocationError::Conflict(
            "database physical identity changed",
        ));
    }
    Ok(())
}

pub(super) fn require_single_workspace(root: &Path) -> Result<(), RelocationError> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut entries = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > 64 {
            return Err(RelocationError::Conflict("Workspace census depth exceeded"));
        }
        for child in fs::read_dir(&directory)? {
            let child = child?;
            entries += 1;
            if entries > 65_536 {
                return Err(RelocationError::Conflict("Workspace census bound exceeded"));
            }
            let kind = child.file_type()?;
            if kind.is_dir() {
                if child.file_name() == ".heterarchy-forge" {
                    if directory != root {
                        return Err(RelocationError::Conflict(
                            "additional nested Workspace state",
                        ));
                    }
                    continue;
                }
                pending.push((child.path(), depth + 1));
            }
        }
    }
    Ok(())
}
