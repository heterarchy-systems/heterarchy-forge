//! Host-startup preparation for the isolated Rust CI capability.
//!
//! This adapter validates the operator-owned roots, delegates paired storage
//! selection to the existing execution capability, and verifies that the
//! selected product view is exactly the cache root declared by the backend.

use std::fs;
use std::path::{Path, PathBuf};

use forge_domain::RuntimeInstanceId;
use forge_execution::{
    RustCiDiscoveryInput, RustCiHostArchitecture, RustCiStorageError, RustCiStorageSelection,
    RustCiToolchainCapability,
};
use serde::Deserialize;
use thiserror::Error;

/// Explicit host paths used for startup Rust CI capability preparation.
#[must_use]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostRustCiConfig {
    pub(super) host_home: PathBuf,
    pub(super) local_cache_root: PathBuf,
}

/// Rust CI capability and the startup storage decision that produced it.
#[must_use]
#[derive(Debug)]
pub(super) struct PreparedHostToolchain {
    pub(super) capability: RustCiToolchainCapability,
    pub(super) selection: RustCiStorageSelection,
    pub(super) ssd_failures: usize,
}

/// Redacted host-toolchain preparation failures.
#[derive(Debug, Error)]
pub(super) enum HostToolchainError {
    #[error("the configured Rust CI host home is invalid")]
    InvalidHostHome,
    #[error("the configured local Rust CI cache root is invalid")]
    InvalidLocalCacheRoot,
    #[error("the current host architecture is unsupported for Rust CI")]
    UnsupportedHost,
    #[error("Rust CI host storage preparation failed after {ssd_failures} SSD failures")]
    PreparationFailed {
        ssd_failures: usize,
        #[source]
        source: Box<RustCiStorageError>,
    },
    #[error("the selected Rust CI product cache root does not match the declared cache root")]
    CacheRootMismatch,
}

pub(super) fn prepare(
    config: &HostRustCiConfig,
    declared_product_cache_root: &Path,
    boot_instance: RuntimeInstanceId,
) -> Result<PreparedHostToolchain, HostToolchainError> {
    let host_home = validate_host_home(&config.host_home)?;
    let local_cache_root = validate_local_cache_root(&config.local_cache_root)?;
    if !declared_product_cache_root.is_absolute() {
        return Err(HostToolchainError::CacheRootMismatch);
    }
    let architecture =
        RustCiHostArchitecture::current().ok_or(HostToolchainError::UnsupportedHost)?;
    let input =
        RustCiDiscoveryInput::from_roots(local_cache_root, host_home, architecture, boot_instance)
            .map_err(|_| HostToolchainError::InvalidLocalCacheRoot)?;
    let prepared = RustCiToolchainCapability::prepare_host_storage(&input).map_err(|source| {
        let ssd_failures = source.ssd_failures().len();
        HostToolchainError::PreparationFailed {
            ssd_failures,
            source,
        }
    })?;
    let selection = prepared.selection();
    let ssd_failures = prepared.ssd_failures().len();
    let capability = prepared.into_capability();
    let declared_root = validate_declared_cache_root(declared_product_cache_root)?;
    if capability.view().root() != declared_root {
        return Err(HostToolchainError::CacheRootMismatch);
    }
    Ok(PreparedHostToolchain {
        capability,
        selection,
        ssd_failures,
    })
}

fn validate_host_home(path: &Path) -> Result<PathBuf, HostToolchainError> {
    if !path.is_absolute() || !is_canonical_directory(path) {
        return Err(HostToolchainError::InvalidHostHome);
    }
    Ok(path.to_path_buf())
}

fn validate_local_cache_root(path: &Path) -> Result<PathBuf, HostToolchainError> {
    if !path.is_absolute() {
        return Err(HostToolchainError::InvalidLocalCacheRoot);
    }
    let parent = path
        .parent()
        .ok_or(HostToolchainError::InvalidLocalCacheRoot)?;
    if !is_canonical_directory(parent) {
        return Err(HostToolchainError::InvalidLocalCacheRoot);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.is_dir()
                && fs::canonicalize(path).ok().as_deref() == Some(path) =>
        {
            Ok(path.to_path_buf())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Ok(_) | Err(_) => Err(HostToolchainError::InvalidLocalCacheRoot),
    }
}

fn validate_declared_cache_root(path: &Path) -> Result<PathBuf, HostToolchainError> {
    if !path.is_absolute() || !is_canonical_directory(path) {
        return Err(HostToolchainError::CacheRootMismatch);
    }
    Ok(path.to_path_buf())
}

fn is_canonical_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_dir())
        && fs::canonicalize(path).ok().as_deref() == Some(path)
}

#[cfg(test)]
mod tests;
