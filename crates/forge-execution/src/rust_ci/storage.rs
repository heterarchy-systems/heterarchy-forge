//! Host-startup storage selection. Never retry or relocate a running execution.

use super::{
    FilesystemIdentity, RUST_CI_PINNED_VERSION, RustCiDiscoveryError, RustCiDiscoveryInput,
    RustCiSourceComponent, RustCiToolchainCapability, filesystem_identity_from_metadata,
    validate_directory,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const SSD_ATTEMPTS: u8 = 4;
const SSD_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_SSD_ROOT: &str = "/Volumes/256.SSD/RustBuild";

#[derive(Clone, PartialEq, Eq)]
pub(super) struct ToolHomes {
    pub(super) cargo: PathBuf,
    pub(super) rustup: PathBuf,
    external: Option<ExternalStorage>,
}

#[derive(Clone, PartialEq, Eq)]
struct ExternalStorage {
    root: PathBuf,
    identity: FilesystemIdentity,
}

impl ToolHomes {
    pub(super) fn local(host_home: &Path) -> Self {
        Self {
            cargo: host_home.join(".cargo"),
            rustup: host_home.join(".rustup"),
            external: None,
        }
    }

    pub(super) fn validate_cache_root(
        &self,
        cache: &Path,
        host_home: &Path,
    ) -> Result<(), RustCiDiscoveryError> {
        let actual = directory_identity(cache)?;
        let expected = match &self.external {
            Some(external) => {
                if !cache.starts_with(&external.root) {
                    return Err(RustCiDiscoveryError::ProductViewMismatch);
                }
                external.identity.device
            }
            None => directory_identity(host_home)?.device,
        };
        if actual.device != expected {
            return Err(RustCiDiscoveryError::ProductViewMismatch);
        }
        Ok(())
    }

    pub(super) fn validate(&self, host_home: &Path) -> Result<(), RustCiDiscoveryError> {
        validate_directory(&self.cargo, RustCiSourceComponent::CargoDirectory)?;
        validate_directory(&self.rustup, RustCiSourceComponent::RustupDirectory)?;
        if let Some(external) = &self.external {
            let current = external_identity(&external.root, host_home)?;
            if current != external.identity {
                return Err(RustCiDiscoveryError::ProductViewMismatch);
            }
            for path in [&self.cargo, &self.rustup] {
                if !path.starts_with(&external.root)
                    || directory_identity(path)?.device != current.device
                {
                    return Err(RustCiDiscoveryError::ProductViewMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Observed startup decision, not an execution-time fallback permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCiStorageSelection {
    Ssd { successful_attempt: u8 },
    LocalAfterFourSsdFailures,
}

/// A prepared, isolated capability plus the bounded SSD attempt evidence.
#[must_use]
#[derive(Debug)]
pub struct RustCiPreparedStorage {
    capability: RustCiToolchainCapability,
    selection: RustCiStorageSelection,
    ssd_failures: Vec<RustCiDiscoveryError>,
}

impl RustCiPreparedStorage {
    pub const fn selection(&self) -> RustCiStorageSelection {
        self.selection
    }

    pub fn ssd_failures(&self) -> &[RustCiDiscoveryError] {
        &self.ssd_failures
    }

    pub fn into_capability(self) -> RustCiToolchainCapability {
        self.capability
    }
}

/// Both validated candidates failed. No unrestricted runtime is substituted.
#[derive(Debug, Error)]
#[error("Rust CI SSD preparation failed four times and local preparation also failed: {local}")]
pub struct RustCiStorageError {
    ssd_failures: Vec<RustCiDiscoveryError>,
    #[source]
    local: RustCiDiscoveryError,
}

impl RustCiStorageError {
    pub fn ssd_failures(&self) -> &[RustCiDiscoveryError] {
        &self.ssd_failures
    }
}

impl RustCiToolchainCapability {
    /// Prepare the designated SSD pair first, with four total attempts and
    /// immediate success return; only then try the local pair once.
    ///
    /// `HETERARCHY_RUST_SSD_ROOT` is an optional host-startup root override.
    /// Its existing `cargo-home` and `rustup-home` directories are one pair.
    /// No directories are created to simulate an absent external disk, and
    /// no toolchains, credentials, caches or operational data are moved.
    /// Versioned product views keep the selected child `CARGO_HOME`/`RUSTUP_HOME`
    /// on that same storage, while preserving existing views and artifacts.
    ///
    /// Call on the owned blocking startup boundary, not an async/UI callback.
    /// Four attempts bound the retry count, not the OS filesystem latency.
    ///
    /// # Errors
    /// Returns all four SSD errors and the local error when neither candidate
    /// can produce the existing confined Rust CI capability.
    pub fn prepare_host_storage(
        local: &RustCiDiscoveryInput,
    ) -> Result<RustCiPreparedStorage, Box<RustCiStorageError>> {
        let root = std::env::var_os("HETERARCHY_RUST_SSD_ROOT")
            .map_or_else(|| PathBuf::from(DEFAULT_SSD_ROOT), PathBuf::from);
        prepare_with_attempts(
            || {
                let input = ssd_candidate(local, &root)?;
                Self::prepare(&input)
            },
            || Self::prepare(&local_candidate(local)?),
            || std::thread::sleep(SSD_RETRY_DELAY),
        )
    }
}

pub(super) fn prepare_with_attempts(
    mut ssd: impl FnMut() -> Result<RustCiToolchainCapability, RustCiDiscoveryError>,
    local: impl FnOnce() -> Result<RustCiToolchainCapability, RustCiDiscoveryError>,
    mut wait: impl FnMut(),
) -> Result<RustCiPreparedStorage, Box<RustCiStorageError>> {
    let mut failures = Vec::with_capacity(usize::from(SSD_ATTEMPTS));
    for attempt in 1..=SSD_ATTEMPTS {
        match ssd() {
            Ok(capability) => {
                return Ok(RustCiPreparedStorage {
                    capability,
                    selection: RustCiStorageSelection::Ssd {
                        successful_attempt: attempt,
                    },
                    ssd_failures: failures,
                });
            }
            Err(error) => failures.push(error),
        }
        if attempt < SSD_ATTEMPTS {
            wait();
        }
    }
    match local() {
        Ok(capability) => Ok(RustCiPreparedStorage {
            capability,
            selection: RustCiStorageSelection::LocalAfterFourSsdFailures,
            ssd_failures: failures,
        }),
        Err(local) => Err(Box::new(RustCiStorageError {
            ssd_failures: failures,
            local,
        })),
    }
}

pub(super) fn ssd_candidate(
    local: &RustCiDiscoveryInput,
    root: &Path,
) -> Result<RustCiDiscoveryInput, RustCiDiscoveryError> {
    let identity = external_identity(root, local.host_home())?;
    let mut input = local.clone();
    input.tool_homes = ToolHomes {
        cargo: root.join("cargo-home"),
        rustup: root.join("rustup-home"),
        external: Some(ExternalStorage {
            root: root.to_path_buf(),
            identity,
        }),
    };
    input.tool_homes.validate(local.host_home())?;
    input.product_cache_root = root.join(format!("heterarchy-rust-ci-{RUST_CI_PINNED_VERSION}"));
    Ok(input)
}

pub(super) fn local_candidate(
    local: &RustCiDiscoveryInput,
) -> Result<RustCiDiscoveryInput, RustCiDiscoveryError> {
    let mut input = local.clone();
    input.tool_homes = ToolHomes::local(local.host_home());
    let parent = local
        .product_cache_root()
        .parent()
        .ok_or(RustCiDiscoveryError::NonCanonical {
            component: RustCiSourceComponent::ProductCacheRoot,
        })?;
    if directory_identity(parent)?.device != directory_identity(local.host_home())?.device {
        return Err(RustCiDiscoveryError::ProductViewMismatch);
    }
    // Sibling view: do not mutate the previous version's root or artifacts.
    input.product_cache_root = parent.join(format!("rust-ci-{RUST_CI_PINNED_VERSION}-local"));
    Ok(input)
}

fn directory_identity(path: &Path) -> Result<FilesystemIdentity, RustCiDiscoveryError> {
    validate_directory(path, RustCiSourceComponent::ProductCacheRoot)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductCacheRoot,
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RustCiDiscoveryError::ProductViewMismatch);
    }
    let canonical = fs::canonicalize(path).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductCacheRoot,
        source,
    })?;
    if canonical.as_os_str() != path.as_os_str() {
        return Err(RustCiDiscoveryError::NonCanonical {
            component: RustCiSourceComponent::ProductCacheRoot,
        });
    }
    Ok(filesystem_identity_from_metadata(&metadata))
}

fn external_identity(
    root: &Path,
    host_home: &Path,
) -> Result<FilesystemIdentity, RustCiDiscoveryError> {
    let identity = directory_identity(root)?;
    let host = directory_identity(host_home)?;
    if identity.device == host.device {
        // A directory with an SSD-looking name on the local filesystem is not
        // the external storage selected by the operator.
        return Err(RustCiDiscoveryError::ProductViewMismatch);
    }
    Ok(identity)
}
