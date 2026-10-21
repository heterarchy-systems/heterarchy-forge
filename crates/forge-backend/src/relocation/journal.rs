//! Private, synced intent and phase record beside the host Registry.
use super::{Plan, RelocationError};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Prepared,
    Renamed,
    WorkspaceRebound,
    RegistryRebound,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub plan: Plan,
    pub phase: Phase,
}

fn path(registry: &Path) -> PathBuf {
    let mut p = registry.as_os_str().to_os_string();
    p.push(".relocation.json");
    PathBuf::from(p)
}

pub(super) fn read(registry: &Path) -> Result<Option<Journal>, RelocationError> {
    let p = path(registry);
    match fs::symlink_metadata(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(m) => {
            if !m.is_file()
                || m.file_type().is_symlink()
                || m.permissions().mode() & 0o077 != 0
                || m.uid() != rustix::process::getuid().as_raw()
                || m.len() > 65536
            {
                return Err(RelocationError::Conflict("unsafe relocation journal"));
            }
            let mut bytes = Vec::new();
            let descriptor = rustix::fs::open(
                &p,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)?;
            File::from(descriptor).take(65537).read_to_end(&mut bytes)?;
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
    }
}

pub(super) fn write(journal: &Journal) -> Result<(), RelocationError> {
    let destination = path(&journal.plan.registry_path);
    let temporary = destination.with_extension(format!("pending-{}", uuid::Uuid::now_v7()));
    let bytes = serde_json::to_vec(journal)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &destination)?;
    File::open(
        destination
            .parent()
            .ok_or(RelocationError::Conflict("journal parent"))?,
    )?
    .sync_all()?;
    Ok(())
}
