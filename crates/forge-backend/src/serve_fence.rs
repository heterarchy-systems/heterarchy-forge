//! Exclusive serve fence for one Registry path.
//!
//! `forge-backend serve` is the canonical standalone owner of the Registry and
//! its Workspaces. The fence is an advisory `flock` on a dedicated sidecar
//! lock file (`<registry>.serve-lock`) held for the process lifetime: a second
//! `serve` process fails closed at startup instead of silently sharing mutable
//! execution authority. The fence deliberately never locks the Registry file
//! itself — SQLite holds POSIX `fcntl` locks there, which conflict with
//! `flock` on macOS. Legacy consumers from the desktop era do
//! not participate in this fence, so coexistence stays intact while duplicate
//! standalone ownership is prevented.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use rustix::io::Errno;
use thiserror::Error;

/// Held from successful acquisition until process exit or explicit drop.
#[derive(Debug)]
pub struct ServeFence {
    path: PathBuf,
    /// The locked descriptor itself is the fence: dropping it releases the
    /// advisory lock, so it must stay owned for the process lifetime.
    #[allow(dead_code)]
    descriptor: OwnedFd,
}

fn fence_path(registry_path: &Path) -> PathBuf {
    let mut path = registry_path.as_os_str().to_os_string();
    path.push(".serve-lock");
    PathBuf::from(path)
}

impl ServeFence {
    /// Take the exclusive non-blocking fence beside the exact Registry path.
    ///
    /// # Errors
    /// Fails when the fence sidecar cannot be created or opened, is a
    /// symbolic link, or is already fenced by another live `serve` process.
    pub fn acquire(registry_path: &Path) -> Result<Self, ServeFenceError> {
        let fence_path = fence_path(registry_path);
        let descriptor = open(
            &fence_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| ServeFenceError::Open {
            path: fence_path.clone(),
            source,
        })?;
        match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self {
                path: fence_path,
                descriptor,
            }),
            Err(source) if source == Errno::AGAIN || source == Errno::WOULDBLOCK => {
                Err(ServeFenceError::Busy {
                    path: registry_path.to_path_buf(),
                })
            }
            Err(source) => Err(ServeFenceError::Lock {
                path: fence_path,
                source,
            }),
        }
    }

    pub const fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Typed failures from the serve fence.
#[derive(Debug, Error)]
pub enum ServeFenceError {
    #[error("failed to open the serve fence {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: Errno,
    },
    #[error("another forge-backend serve process already owns the Registry {path}")]
    Busy { path: PathBuf },
    #[error("failed to lock the serve fence {path}")]
    Lock {
        path: PathBuf,
        #[source]
        source: Errno,
    },
}

#[cfg(test)]
mod tests {
    use super::ServeFence;
    use std::fs;

    #[test]
    fn second_serve_process_is_refused_until_the_first_releases()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-serve-fence-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let registry = root.join("registry.sqlite3");
        fs::write(&registry, b"registry placeholder")?;
        let registry = fs::canonicalize(&registry)?;

        let first = ServeFence::acquire(&registry)?;
        assert!(
            ServeFence::acquire(&registry).is_err(),
            "a second serve fence must fail closed while the first is live"
        );
        drop(first);
        let second = ServeFence::acquire(&registry)?;
        assert_eq!(
            second.path(),
            &registry.with_extension("sqlite3.serve-lock"),
            "the fence lives on its own sidecar lock file"
        );
        drop(second);

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn the_fence_never_conflicts_with_a_live_sqlite_registry_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-serve-fence-sqlite-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let registry = root.join("registry.sqlite3");
        let connection = rusqlite::Connection::open(&registry)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch("CREATE TABLE t (x)")?;

        let fence = ServeFence::acquire(&registry)?;
        drop(fence);

        drop(connection);
        fs::remove_dir_all(&root)?;
        Ok(())
    }
}
