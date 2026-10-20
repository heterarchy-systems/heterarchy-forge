//! Read-only access to retained generated package output.
//!
//! Durable execution rows remain the source of truth for ownership.  This
//! module only joins those rows with the exact product-cache namespace derived
//! from the Workspace root fingerprint.  It never creates, deletes, or
//! repairs an output directory.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use forge_domain::{
    ExecutionId, ExecutionListLimit, FileContentHash, GeneratedPackageManifest, WorkspaceId,
    WorkspaceRootFingerprint,
};
use forge_execution::{
    MAX_GENERATED_PACKAGE_BYTES, RustCiDiscoveryError, RustCiGeneratedPackageOutput,
};
use thiserror::Error;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_state_layout_error};

/// Maximum number of durable or filesystem rows returned by one local
/// generated-artifact observation.
pub const MAX_GENERATED_ARTIFACT_INVENTORY: usize = 64;

/// Maximum aggregate package bytes hashed by one inventory observation.  A
/// selected reveal/copy action uses the single-package ceiling instead.
pub const MAX_GENERATED_ARTIFACT_HASH_BYTES_PER_INVENTORY: u64 = 256 * 1024 * 1024;

const MAX_GENERATED_ARTIFACT_FS_SCAN: usize = MAX_GENERATED_ARTIFACT_INVENTORY + 1;

/// Bounded local inventory limit.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GeneratedArtifactInventoryLimit(usize);

impl GeneratedArtifactInventoryLimit {
    pub const DEFAULT: Self = Self(32);

    pub const fn new(value: usize) -> Result<Self, GeneratedArtifactAccessError> {
        if value == 0 || value > MAX_GENERATED_ARTIFACT_INVENTORY {
            Err(GeneratedArtifactAccessError::InvalidLimit)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> usize {
        self.0
    }
}

/// Caller-time health of one retained generated package.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GeneratedArtifactStatus {
    /// A successful generated execution has a matching package hash and size.
    OwnedValid,
    /// Durable successful execution evidence exists, but its package is gone.
    Missing,
    /// Durable evidence exists, but the derived output is unsafe or differs
    /// from the recorded hash/size.
    Conflict,
    /// A product-cache entry has no matching durable generated execution.
    Orphan,
    /// The package shape is safe, but this bounded inventory did not have
    /// enough hash budget to verify its contents.
    Unverified,
}

/// Bounded filesystem shape metadata.  Symlinks are reported without being
/// followed.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GeneratedArtifactNodeKind {
    Missing,
    Directory,
    RegularFile,
    Symlink,
    Other,
    Unknown,
}

/// One read-only generated-package observation.  `name` is a bounded child
/// name inside the product cache; it is never a caller-selected path.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedArtifactObservation {
    workspace_id: WorkspaceId,
    execution_id: Option<ExecutionId>,
    name: String,
    status: GeneratedArtifactStatus,
    node_kind: GeneratedArtifactNodeKind,
    manifest: Option<GeneratedPackageManifest>,
    observed_byte_count: Option<u64>,
    observed_content_hash: Option<FileContentHash>,
}

impl GeneratedArtifactObservation {
    fn from_manifest(
        workspace_id: WorkspaceId,
        root_fingerprint: WorkspaceRootFingerprint,
        manifest: GeneratedPackageManifest,
        status: GeneratedArtifactStatus,
        node_kind: GeneratedArtifactNodeKind,
        observed_byte_count: Option<u64>,
        observed_content_hash: Option<FileContentHash>,
    ) -> Self {
        Self {
            workspace_id,
            execution_id: Some(manifest.execution_id()),
            name: RustCiGeneratedPackageOutput::directory_name(
                workspace_id,
                root_fingerprint,
                manifest.execution_id(),
            ),
            status,
            node_kind,
            manifest: Some(manifest),
            observed_byte_count,
            observed_content_hash,
        }
    }

    fn orphan(
        workspace_id: WorkspaceId,
        name: String,
        node_kind: GeneratedArtifactNodeKind,
        observed_byte_count: Option<u64>,
    ) -> Self {
        Self {
            workspace_id,
            execution_id: None,
            name,
            status: GeneratedArtifactStatus::Orphan,
            node_kind,
            manifest: None,
            observed_byte_count,
            observed_content_hash: None,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn execution_id(&self) -> Option<ExecutionId> {
        self.execution_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn status(&self) -> GeneratedArtifactStatus {
        self.status
    }

    pub const fn node_kind(&self) -> GeneratedArtifactNodeKind {
        self.node_kind
    }

    pub const fn manifest(&self) -> Option<GeneratedPackageManifest> {
        self.manifest
    }

    pub const fn observed_byte_count(&self) -> Option<u64> {
        self.observed_byte_count
    }

    pub const fn observed_content_hash(&self) -> Option<FileContentHash> {
        self.observed_content_hash
    }
}

/// Bounded, deterministic read-only generated-output inventory.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedArtifactInventory {
    workspace_id: WorkspaceId,
    entries: Vec<GeneratedArtifactObservation>,
    truncated: bool,
}

impl GeneratedArtifactInventory {
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn entries(&self) -> &[GeneratedArtifactObservation] {
        &self.entries
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// A verified local handle for the exact package represented by one durable
/// manifest.  The path is retained only for the desktop reveal/copy action;
/// it is never a remote request field.
#[must_use]
pub struct GeneratedPackageAccess {
    manifest: GeneratedPackageManifest,
    output: RustCiGeneratedPackageOutput,
}

impl std::fmt::Debug for GeneratedPackageAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeneratedPackageAccess")
            .field("workspace_id", &self.manifest.workspace_id())
            .field("execution_id", &self.manifest.execution_id())
            .finish_non_exhaustive()
    }
}

impl GeneratedPackageAccess {
    pub const fn manifest(&self) -> GeneratedPackageManifest {
        self.manifest
    }

    /// Open the package through the descriptor-relative NOFOLLOW boundary.
    pub fn open(&self) -> Result<File, GeneratedArtifactAccessError> {
        self.output
            .open_stable_package()
            .map_err(GeneratedArtifactAccessError::Runtime)
    }

    /// Return the exact derived path for a local Finder/reveal operation.
    pub fn path(&self) -> Result<PathBuf, GeneratedArtifactAccessError> {
        self.output
            .stable_package_path()
            .map_err(GeneratedArtifactAccessError::Runtime)
    }
}

/// Errors from the read-only generated-artifact boundary.
#[derive(Debug, Error)]
pub enum GeneratedArtifactAccessError {
    #[error("generated-artifact inventory limit is outside the bounded range")]
    InvalidLimit,
    #[error("generated-artifact manifest belongs to another Workspace")]
    WorkspaceMismatch,
    #[error("generated package filesystem observation failed")]
    Runtime(#[source] RustCiDiscoveryError),
    #[error("generated package filesystem read failed")]
    Io(#[source] io::Error),
}

/// Observe one durable successful generated-package manifest against the
/// exact product-cache output derived from its Workspace identity.
fn observe_generated_package(
    product_cache_root: &Path,
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
    manifest: GeneratedPackageManifest,
) -> Result<GeneratedArtifactObservation, GeneratedArtifactAccessError> {
    if manifest.workspace_id() != workspace_id {
        return Err(GeneratedArtifactAccessError::WorkspaceMismatch);
    }
    let mut hash_budget = MAX_GENERATED_PACKAGE_BYTES;
    observe_generated_package_with_budget(
        product_cache_root,
        workspace_id,
        root_fingerprint,
        manifest,
        &mut hash_budget,
    )
}

fn observe_generated_package_with_budget(
    product_cache_root: &Path,
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
    manifest: GeneratedPackageManifest,
    hash_budget: &mut u64,
) -> Result<GeneratedArtifactObservation, GeneratedArtifactAccessError> {
    let output = RustCiGeneratedPackageOutput::open_existing(
        product_cache_root,
        workspace_id,
        root_fingerprint,
        manifest.execution_id(),
    )
    .map_err(GeneratedArtifactAccessError::Runtime);
    let output = match output {
        Ok(Some(output)) => output,
        Ok(None) => {
            return Ok(GeneratedArtifactObservation::from_manifest(
                workspace_id,
                root_fingerprint,
                manifest,
                GeneratedArtifactStatus::Missing,
                GeneratedArtifactNodeKind::Missing,
                None,
                None,
            ));
        }
        Err(GeneratedArtifactAccessError::Runtime(
            RustCiDiscoveryError::ProductRuntimeMismatch,
        )) => {
            return Ok(GeneratedArtifactObservation::from_manifest(
                workspace_id,
                root_fingerprint,
                manifest,
                GeneratedArtifactStatus::Conflict,
                GeneratedArtifactNodeKind::Unknown,
                None,
                None,
            ));
        }
        Err(error) => return Err(error),
    };

    let (node_kind, observed_byte_count, observed_content_hash) =
        match inspect_package(&output, manifest, hash_budget) {
            Ok((byte_count, content_hash)) => (
                GeneratedArtifactNodeKind::RegularFile,
                Some(byte_count),
                Some(content_hash),
            ),
            Err(GeneratedPackageObservationError::Missing) => {
                (GeneratedArtifactNodeKind::Missing, None, None)
            }
            Err(GeneratedPackageObservationError::Conflict { node_kind }) => {
                (node_kind, None, None)
            }
            Err(GeneratedPackageObservationError::BudgetLimited {
                observed_byte_count,
            }) => (
                GeneratedArtifactNodeKind::RegularFile,
                Some(observed_byte_count),
                None,
            ),
            Err(GeneratedPackageObservationError::Runtime(source)) => {
                return Err(GeneratedArtifactAccessError::Runtime(source));
            }
            Err(GeneratedPackageObservationError::Io(source)) => {
                return Err(GeneratedArtifactAccessError::Io(source));
            }
        };
    let status = if node_kind == GeneratedArtifactNodeKind::RegularFile
        && observed_byte_count == Some(manifest.byte_count().get())
        && observed_content_hash == Some(manifest.content_hash())
    {
        GeneratedArtifactStatus::OwnedValid
    } else if node_kind == GeneratedArtifactNodeKind::Missing {
        GeneratedArtifactStatus::Missing
    } else if observed_content_hash.is_none() && node_kind == GeneratedArtifactNodeKind::RegularFile
    {
        GeneratedArtifactStatus::Unverified
    } else {
        GeneratedArtifactStatus::Conflict
    };
    Ok(GeneratedArtifactObservation::from_manifest(
        workspace_id,
        root_fingerprint,
        manifest,
        status,
        node_kind,
        observed_byte_count,
        observed_content_hash,
    ))
}

/// Return a verified local package handle only when durable and filesystem
/// metadata agree.  Missing or conflicting output returns `Ok(None)` so the
/// UI can keep reveal/copy disabled without turning observation into repair.
fn open_verified_generated_package(
    product_cache_root: &Path,
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
    manifest: GeneratedPackageManifest,
) -> Result<Option<GeneratedPackageAccess>, GeneratedArtifactAccessError> {
    let observation =
        observe_generated_package(product_cache_root, workspace_id, root_fingerprint, manifest)?;
    if observation.status() != GeneratedArtifactStatus::OwnedValid {
        return Ok(None);
    }
    let output = RustCiGeneratedPackageOutput::open_existing(
        product_cache_root,
        workspace_id,
        root_fingerprint,
        manifest.execution_id(),
    )
    .map_err(GeneratedArtifactAccessError::Runtime)?
    .ok_or(GeneratedArtifactAccessError::Io(io::Error::new(
        io::ErrorKind::NotFound,
        "verified generated package disappeared",
    )))?;
    Ok(Some(GeneratedPackageAccess { manifest, output }))
}

/// Join bounded durable manifests with the exact product-cache namespace and
/// report unowned entries as read-only orphan observations.
fn inspect_generated_package_inventory(
    product_cache_root: &Path,
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
    manifests: &[GeneratedPackageManifest],
    limit: GeneratedArtifactInventoryLimit,
) -> Result<GeneratedArtifactInventory, GeneratedArtifactAccessError> {
    let mut durable = manifests
        .iter()
        .copied()
        .filter(|manifest| manifest.workspace_id() == workspace_id)
        .collect::<Vec<_>>();
    if durable.len() != manifests.len() {
        return Err(GeneratedArtifactAccessError::WorkspaceMismatch);
    }
    let mut seen = HashSet::with_capacity(durable.len());
    durable.retain(|manifest| seen.insert(manifest.execution_id()));

    let maximum = limit.get();
    let mut entries = Vec::with_capacity(maximum);
    let mut truncated = durable.len() > maximum;
    let mut hash_budget = MAX_GENERATED_ARTIFACT_HASH_BYTES_PER_INVENTORY;
    for manifest in durable.iter().take(maximum) {
        entries.push(observe_generated_package_with_budget(
            product_cache_root,
            workspace_id,
            root_fingerprint,
            *manifest,
            &mut hash_budget,
        )?);
    }

    // The extra durable row is the authoritative truncation signal. There is
    // no room for an additional filesystem orphan in this page, so avoid an
    // unbounded cache walk when the durable page is already incomplete.
    if truncated {
        return Ok(GeneratedArtifactInventory {
            workspace_id,
            entries,
            truncated,
        });
    }

    let Some(namespace) = RustCiGeneratedPackageOutput::existing_namespace(product_cache_root)
        .map_err(GeneratedArtifactAccessError::Runtime)?
    else {
        return Ok(GeneratedArtifactInventory {
            workspace_id,
            entries,
            truncated,
        });
    };
    let expected_names = durable
        .iter()
        .map(|manifest| {
            RustCiGeneratedPackageOutput::directory_name(
                workspace_id,
                root_fingerprint,
                manifest.execution_id(),
            )
        })
        .collect::<Vec<_>>();
    let workspace_prefix = format!(
        "{}-execution-",
        RustCiGeneratedPackageOutput::workspace_prefix(workspace_id, root_fingerprint)
    );
    let (filesystem_entries, scan_truncated) =
        generated_namespace_entries(&namespace, &workspace_prefix)?;
    truncated |= scan_truncated;
    for entry in filesystem_entries {
        let name = entry.file_name();
        if expected_names
            .iter()
            .any(|expected| OsStr::new(expected) == name.as_os_str())
        {
            continue;
        }
        if entries.len() >= maximum {
            truncated = true;
            break;
        }
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(GeneratedArtifactAccessError::Io)?;
        entries.push(GeneratedArtifactObservation::orphan(
            workspace_id,
            bounded_name(&name),
            node_kind(&metadata),
            Some(metadata.len()),
        ));
    }

    Ok(GeneratedArtifactInventory {
        workspace_id,
        entries,
        truncated,
    })
}

fn generated_namespace_entries(
    namespace: &Path,
    workspace_prefix: &str,
) -> Result<(Vec<fs::DirEntry>, bool), GeneratedArtifactAccessError> {
    let mut truncated = false;
    let mut filesystem_entries = Vec::with_capacity(MAX_GENERATED_ARTIFACT_FS_SCAN);
    // Bound directory I/O as well as memory. When the namespace is larger,
    // this is an explicitly truncated sample, never a complete orphan claim.
    for (scanned, result) in fs::read_dir(namespace)
        .map_err(GeneratedArtifactAccessError::Io)?
        .enumerate()
    {
        if scanned >= MAX_GENERATED_ARTIFACT_FS_SCAN {
            truncated = true;
            break;
        }
        let entry = result.map_err(GeneratedArtifactAccessError::Io)?;
        if entry
            .file_name()
            .as_os_str()
            .as_bytes()
            .starts_with(workspace_prefix.as_bytes())
        {
            filesystem_entries.push(entry);
        }
    }
    filesystem_entries.sort_by(|left, right| {
        left.file_name()
            .as_os_str()
            .as_bytes()
            .cmp(right.file_name().as_os_str().as_bytes())
    });
    Ok((filesystem_entries, truncated))
}

enum GeneratedPackageObservationError {
    Missing,
    Conflict {
        node_kind: GeneratedArtifactNodeKind,
    },
    BudgetLimited {
        observed_byte_count: u64,
    },
    Runtime(RustCiDiscoveryError),
    Io(io::Error),
}

fn inspect_package(
    output: &RustCiGeneratedPackageOutput,
    manifest: GeneratedPackageManifest,
    hash_budget: &mut u64,
) -> Result<(u64, FileContentHash), GeneratedPackageObservationError> {
    let dist = output.root().join("dist");
    let dist_metadata = fs::symlink_metadata(&dist).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            GeneratedPackageObservationError::Missing
        } else {
            GeneratedPackageObservationError::Io(source)
        }
    })?;
    if dist_metadata.file_type().is_symlink() {
        return Err(GeneratedPackageObservationError::Conflict {
            node_kind: GeneratedArtifactNodeKind::Symlink,
        });
    }
    if !dist_metadata.is_dir() {
        return Err(GeneratedPackageObservationError::Conflict {
            node_kind: node_kind(&dist_metadata),
        });
    }
    let path = dist.join(manifest.kind().file_name());
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(GeneratedPackageObservationError::Conflict {
                    node_kind: GeneratedArtifactNodeKind::Symlink,
                });
            }
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(GeneratedPackageObservationError::Conflict {
                    node_kind: node_kind(&metadata),
                });
            }
            if metadata.len() == 0 || metadata.len() > MAX_GENERATED_PACKAGE_BYTES {
                return Err(GeneratedPackageObservationError::Conflict {
                    node_kind: GeneratedArtifactNodeKind::RegularFile,
                });
            }
            if metadata.len() > *hash_budget {
                return Err(GeneratedPackageObservationError::BudgetLimited {
                    observed_byte_count: metadata.len(),
                });
            }
            *hash_budget -= metadata.len();
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(GeneratedPackageObservationError::Missing);
        }
        Err(source) => return Err(GeneratedPackageObservationError::Io(source)),
    }
    let mut file = output
        .open_stable_package()
        .map_err(GeneratedPackageObservationError::Runtime)?;
    let metadata = file
        .metadata()
        .map_err(GeneratedPackageObservationError::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(GeneratedPackageObservationError::Conflict {
            node_kind: GeneratedArtifactNodeKind::Other,
        });
    }
    let mut hasher = blake3::Hasher::new();
    let mut bytes = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    let reserved_byte_count = metadata.len();
    loop {
        let read = file
            .read(&mut bytes)
            .map_err(GeneratedPackageObservationError::Io)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| {
                GeneratedPackageObservationError::Io(io::Error::other("package size overflowed"))
            })?)
            .ok_or_else(|| {
                GeneratedPackageObservationError::Io(io::Error::other("package size overflowed"))
            })?;
        if total > reserved_byte_count || total > MAX_GENERATED_PACKAGE_BYTES {
            return Err(GeneratedPackageObservationError::Conflict {
                node_kind: GeneratedArtifactNodeKind::RegularFile,
            });
        }
        hasher.update(&bytes[..read]);
    }
    Ok((
        total,
        FileContentHash::from_bytes(*hasher.finalize().as_bytes()),
    ))
}

fn bounded_name(name: &OsStr) -> String {
    let bytes = name.as_bytes();
    String::from_utf8_lossy(&bytes[..bytes.len().min(128)]).into_owned()
}

fn node_kind(metadata: &fs::Metadata) -> GeneratedArtifactNodeKind {
    if metadata.file_type().is_symlink() {
        GeneratedArtifactNodeKind::Symlink
    } else if metadata.is_dir() {
        GeneratedArtifactNodeKind::Directory
    } else if metadata.is_file() {
        GeneratedArtifactNodeKind::RegularFile
    } else {
        GeneratedArtifactNodeKind::Other
    }
}

impl ForgeControl {
    /// Observe retained generated packages for one already-resolved Workspace.
    /// The cache root is supplied only by a trusted local desktop caller; this
    /// method is intentionally not a wire request and never accepts an
    /// arbitrary remote path.
    pub fn generated_artifact_inventory(
        &self,
        scope: &ResolvedWorkspaceScope,
        product_cache_root: &Path,
        limit: GeneratedArtifactInventoryLimit,
    ) -> Result<GeneratedArtifactInventory, ControlError> {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let root_fingerprint = layout.root_fingerprint().map_err(map_state_layout_error)?;
        let manifest_limit = ExecutionListLimit::new(
            u16::try_from(limit.get().saturating_add(1))
                .map_err(|_| ControlError::new(ControlErrorCode::InvalidInput))?,
        )
        .map_err(|source| ControlError::with_source(ControlErrorCode::InvalidInput, source))?;
        let manifests = store
            .list_generated_package_manifests(manifest_limit)
            .map_err(|source| {
                ControlError::with_source(ControlErrorCode::PersistenceFailure, source)
            })?;
        let result = inspect_generated_package_inventory(
            product_cache_root,
            fresh_scope.workspace_id(),
            root_fingerprint,
            &manifests,
            limit,
        )
        .map_err(|error| ControlError::with_source(ControlErrorCode::ExecutionConflict, error))?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    /// Return a local package handle only when its durable manifest and fresh
    /// exact-cache observation agree.  The handle is suitable for Finder
    /// reveal or descriptor-backed copy by the desktop layer.
    pub fn generated_package_access(
        &self,
        scope: &ResolvedWorkspaceScope,
        product_cache_root: &Path,
        execution_id: ExecutionId,
    ) -> Result<Option<GeneratedPackageAccess>, ControlError> {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let root_fingerprint = layout.root_fingerprint().map_err(map_state_layout_error)?;
        let Some(manifest) = store
            .generated_package_manifest(execution_id)
            .map_err(|source| {
                ControlError::with_source(ControlErrorCode::PersistenceFailure, source)
            })?
        else {
            if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
                return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
            }
            return Ok(None);
        };
        let result = open_verified_generated_package(
            product_cache_root,
            fresh_scope.workspace_id(),
            root_fingerprint,
            manifest,
        )
        .map_err(|error| ControlError::with_source(ControlErrorCode::ExecutionConflict, error))?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use forge_domain::{FileContentHash, WorkspaceRootFingerprint};
    use forge_execution::{RUST_CI_SANDBOX_MARKER_ENV, RUST_CI_SANDBOX_MARKER_VALUE};
    use uuid::Uuid;

    use super::*;

    const RUST_CI_TEST_POLICY_ENV: &str = "HETERARCHY_FORGE_RUST_CI_TEST_POLICY";
    const RUST_CI_TEST_POLICY_VALUE: &str = "outer-rust-ci-v1";

    fn outer_rust_ci_native_filesystem_checks_unavailable() -> bool {
        std::env::var(RUST_CI_SANDBOX_MARKER_ENV).as_deref() == Ok(RUST_CI_SANDBOX_MARKER_VALUE)
            && std::env::var(RUST_CI_TEST_POLICY_ENV).as_deref() == Ok(RUST_CI_TEST_POLICY_VALUE)
    }

    fn fixture_root() -> io::Result<PathBuf> {
        let path =
            std::env::temp_dir().join(format!("forge-generated-artifact-{}", Uuid::now_v7()));
        fs::create_dir(&path)?;
        fs::canonicalize(path)
    }

    fn workspace() -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(0x101))
    }

    fn fingerprint() -> WorkspaceRootFingerprint {
        WorkspaceRootFingerprint::from_bytes([0x10; 16])
    }

    fn execution(raw: u128) -> ExecutionId {
        ExecutionId::from_uuid(Uuid::from_u128(raw))
    }

    #[test]
    fn inventory_distinguishes_valid_missing_conflict_and_orphan_output()
    -> Result<(), Box<dyn std::error::Error>> {
        if outer_rust_ci_native_filesystem_checks_unavailable() {
            return Ok(());
        }
        let cache = fixture_root()?;
        fs::create_dir_all(&cache)?;
        let namespace = cache.join("generated-output");
        let valid_root = namespace.join(RustCiGeneratedPackageOutput::directory_name(
            workspace(),
            fingerprint(),
            execution(0x201),
        ));
        fs::create_dir_all(valid_root.join("dist"))?;
        let valid_bytes = b"valid package";
        fs::write(valid_root.join("dist/Heterarchy-Forge.pkg"), valid_bytes)?;
        let valid_manifest = GeneratedPackageManifest::new(
            workspace(),
            execution(0x201),
            FileContentHash::from_bytes(*blake3::hash(valid_bytes).as_bytes()),
            forge_domain::FileByteCount::new(u64::try_from(valid_bytes.len())?),
        );
        let missing_manifest = GeneratedPackageManifest::new(
            workspace(),
            execution(0x202),
            FileContentHash::from_bytes([0x22; FileContentHash::BYTE_LEN]),
            forge_domain::FileByteCount::new(22),
        );
        let conflict_root = namespace.join(RustCiGeneratedPackageOutput::directory_name(
            workspace(),
            fingerprint(),
            execution(0x203),
        ));
        fs::create_dir_all(conflict_root.join("dist"))?;
        fs::write(
            conflict_root.join("dist/Heterarchy-Forge.pkg"),
            b"different",
        )?;
        let conflict_manifest = GeneratedPackageManifest::new(
            workspace(),
            execution(0x203),
            FileContentHash::from_bytes([0x33; FileContentHash::BYTE_LEN]),
            forge_domain::FileByteCount::new(33),
        );
        fs::create_dir(namespace.join(RustCiGeneratedPackageOutput::directory_name(
            workspace(),
            fingerprint(),
            execution(0x204),
        )))?;

        let inventory = inspect_generated_package_inventory(
            &cache,
            workspace(),
            fingerprint(),
            &[valid_manifest, missing_manifest, conflict_manifest],
            GeneratedArtifactInventoryLimit::DEFAULT,
        )?;
        assert_eq!(inventory.entries().len(), 4);
        assert!(
            inventory
                .entries()
                .iter()
                .any(|entry| entry.status() == GeneratedArtifactStatus::OwnedValid)
        );
        assert!(
            inventory
                .entries()
                .iter()
                .any(|entry| entry.status() == GeneratedArtifactStatus::Missing)
        );
        assert!(
            inventory
                .entries()
                .iter()
                .any(|entry| entry.status() == GeneratedArtifactStatus::Conflict)
        );
        assert!(
            inventory
                .entries()
                .iter()
                .any(|entry| entry.status() == GeneratedArtifactStatus::Orphan)
        );
        let access =
            open_verified_generated_package(&cache, workspace(), fingerprint(), valid_manifest)?
                .ok_or("valid package access missing")?;
        assert_eq!(
            access.path()?.file_name(),
            Some(OsStr::new("Heterarchy-Forge.pkg"))
        );
        let mut bytes = Vec::new();
        access.open()?.read_to_end(&mut bytes)?;
        assert_eq!(bytes, valid_bytes);

        fs::remove_dir_all(cache)?;
        Ok(())
    }

    #[test]
    fn inventory_rejects_cross_workspace_manifest_without_observing_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let cache = fixture_root()?;
        let manifest = GeneratedPackageManifest::new(
            WorkspaceId::from_uuid(Uuid::from_u128(0x999)),
            execution(0x301),
            FileContentHash::from_bytes([0x44; FileContentHash::BYTE_LEN]),
            forge_domain::FileByteCount::new(44),
        );
        let result = inspect_generated_package_inventory(
            &cache,
            workspace(),
            fingerprint(),
            &[manifest],
            GeneratedArtifactInventoryLimit::DEFAULT,
        );
        assert!(matches!(
            result,
            Err(GeneratedArtifactAccessError::WorkspaceMismatch)
        ));
        fs::remove_dir_all(cache)?;
        Ok(())
    }

    #[test]
    fn inventory_bounds_filesystem_candidates_and_reports_truncation()
    -> Result<(), Box<dyn std::error::Error>> {
        if outer_rust_ci_native_filesystem_checks_unavailable() {
            return Ok(());
        }
        let cache = fixture_root()?;
        let namespace = cache.join("generated-output");
        fs::create_dir_all(&namespace)?;
        let prefix = format!(
            "{}-execution-",
            RustCiGeneratedPackageOutput::workspace_prefix(workspace(), fingerprint())
        );
        for index in 0..(MAX_GENERATED_ARTIFACT_FS_SCAN + 4) {
            fs::create_dir(namespace.join(format!("{prefix}orphan-{index:03}")))?;
        }
        let inventory = inspect_generated_package_inventory(
            &cache,
            workspace(),
            fingerprint(),
            &[],
            GeneratedArtifactInventoryLimit::new(MAX_GENERATED_ARTIFACT_INVENTORY)?,
        )?;
        assert_eq!(inventory.entries().len(), MAX_GENERATED_ARTIFACT_INVENTORY);
        assert!(inventory.truncated());
        fs::remove_dir_all(cache)?;
        Ok(())
    }
}
