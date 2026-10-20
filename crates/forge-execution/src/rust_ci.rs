//! Isolated, product-owned Rust CI toolchain capability.
//!
//! The host Rust installation is only an input to capability discovery.  A
//! successfully discovered capability contains paths inside the Forge cache
//! view, never paths into the user's Cargo or rustup trees.  The view is
//! deliberately small: the rustup executable, one pinned toolchain, its
//! settings, and the Cargo registry are the only host inputs exposed to a
//! Rust CI launch.

mod storage;
mod verification_source;
pub use storage::{RustCiPreparedStorage, RustCiStorageError, RustCiStorageSelection};
pub(crate) use verification_source::VerificationExecutionSource;
pub use verification_source::VerificationExecutionSourceError;

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use forge_domain::{ExecutionId, RuntimeInstanceId, WorkspaceId, WorkspaceRootFingerprint};
use rustix_process::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, fstat, open, openat, statat, unlinkat,
};
use thiserror::Error;

/// Rust version selected by the Forge Rust CI policy.
pub const RUST_CI_PINNED_VERSION: &str = "1.98.0";
/// Product-owned marker inherited only by commands already confined inside
/// the Rust CI Seatbelt profile. Test harnesses use it to avoid attempting a
/// second `sandbox_init`, which macOS rejects for a deny-default process.
pub const RUST_CI_SANDBOX_MARKER_ENV: &str = "HETERARCHY_FORGE_RUST_CI_SANDBOX";
/// Versioned value for [`RUST_CI_SANDBOX_MARKER_ENV`].
pub const RUST_CI_SANDBOX_MARKER_VALUE: &str = "v1";

/// Best-effort logical-byte ceiling monitored for one Rust CI launch.
///
/// This is an admission/termination policy, not a filesystem quota. The
/// runner samples writable capability roots at an adaptive bounded cadence
/// whose minimum is [`RUST_CI_DISK_MONITOR_INTERVAL`]; writes between samples
/// remain an explicit limitation of the policy.
pub const RUST_CI_MAX_LOGICAL_BYTES: u64 = 24 * 1024 * 1024 * 1024;
/// Maximum number of filesystem entries visited by one Rust CI disk sample.
pub const RUST_CI_MAX_ENTRIES: u64 = 250_000;
/// Minimum interval between Rust CI writable-root disk samples. The runner
/// lengthens this interval in proportion to the previous full-tree scan cost,
/// up to an internal ten-second ceiling, so the monitor cannot continuously
/// monopolize filesystem traversal while a large Cargo target is growing.
pub const RUST_CI_DISK_MONITOR_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Maximum size of the fixed-name generated package retained by Forge.
pub const MAX_GENERATED_PACKAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Runtime launch policy selected by the trusted execution caller.
///
/// `RustCi` is intentionally a unit variant: the capability is supplied to
/// the typed start API separately and cannot be smuggled in through a generic
/// environment map or a durable request field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionLaunchKind {
    Baseline,
    RustCi,
    /// A sealed local package command. It reads the selected Workspace but
    /// writes only an execution-specific Forge product-cache directory.
    RustCiGeneratedPackage,
}

const RUNTIME_DIRECTORY_NAME: &str = "runtime";
const GENERATED_OUTPUT_DIRECTORY_NAME: &str = "generated-output";
const GENERATED_PACKAGE_DIST_DIRECTORY: &str = "dist";
const GENERATED_PACKAGE_FILE_NAME: &str = "Heterarchy-Forge.pkg";
const TARGET_DIRECTORY_NAME: &str = "target";
const TEMP_DIRECTORY_NAME: &str = "tmp";
const HOME_DIRECTORY_NAME: &str = "home";
const BIN_DIRECTORY_NAME: &str = "bin";
const RUSTUP_DIRECTORY_NAME: &str = "rustup-home";
const CARGO_DIRECTORY_NAME: &str = "cargo-home";
const RUSTUP_FILE_NAME: &str = "rustup";
const SETTINGS_FILE_NAME: &str = "settings.toml";
const TOOLCHAINS_DIRECTORY_NAME: &str = "toolchains";
const REGISTRY_DIRECTORY_NAME: &str = "registry";
const MAX_RUST_CI_TRAVERSAL_DEPTH: usize = 128;

/// Host architectures for which the pinned macOS toolchain is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RustCiHostArchitecture {
    Aarch64,
    X86_64,
}

impl RustCiHostArchitecture {
    /// Return the Rust target-architecture component used in the toolchain
    /// directory name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::X86_64 => "x86_64",
        }
    }

    /// Return the architecture of the running host when it is supported by
    /// the product policy.
    pub const fn current() -> Option<Self> {
        #[cfg(target_arch = "aarch64")]
        {
            Some(Self::Aarch64)
        }
        #[cfg(target_arch = "x86_64")]
        {
            Some(Self::X86_64)
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            None
        }
    }
}

impl fmt::Display for RustCiHostArchitecture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Immutable paths supplied by the server-owned discovery boundary.
///
/// The values are shape-validated at construction and are revalidated against
/// the filesystem immediately before a capability is granted.  The input
/// intentionally carries no environment map or user Cargo path list.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct RustCiDiscoveryInput {
    host_home: PathBuf,
    tool_homes: storage::ToolHomes,
    product_cache_root: PathBuf,
    architecture: RustCiHostArchitecture,
    runtime_instance_id: RuntimeInstanceId,
}

impl fmt::Debug for RustCiDiscoveryInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustCiDiscoveryInput")
            .field("architecture", &self.architecture)
            .field("has_host_home", &true)
            .field("has_product_cache_root", &true)
            .field("has_runtime_instance_id", &true)
            .finish_non_exhaustive()
    }
}

impl RustCiDiscoveryInput {
    /// Construct a discovery input from the validated host home and the
    /// product-owned cache root. Host storage selection is explicit at startup.
    pub fn new(
        host_home: PathBuf,
        product_cache_root: PathBuf,
        architecture: RustCiHostArchitecture,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<Self, RustCiDiscoveryInputError> {
        validate_input_path(&host_home, RustCiInputPath::HostHome)?;
        validate_input_path(&product_cache_root, RustCiInputPath::ProductCacheRoot)?;
        Ok(Self {
            tool_homes: storage::ToolHomes::local(&host_home),
            host_home,
            product_cache_root,
            architecture,
            runtime_instance_id,
        })
    }

    /// Convenience constructor with cache root first, matching `AppPaths`
    /// accessors and path-oriented call sites.
    pub fn from_roots(
        product_cache_root: PathBuf,
        host_home: PathBuf,
        architecture: RustCiHostArchitecture,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<Self, RustCiDiscoveryInputError> {
        Self::new(
            host_home,
            product_cache_root,
            architecture,
            runtime_instance_id,
        )
    }

    pub fn host_home(&self) -> &Path {
        &self.host_home
    }

    pub fn product_cache_root(&self) -> &Path {
        &self.product_cache_root
    }

    pub const fn architecture(&self) -> RustCiHostArchitecture {
        self.architecture
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }
}

impl AsRef<RustCiDiscoveryInput> for RustCiDiscoveryInput {
    fn as_ref(&self) -> &RustCiDiscoveryInput {
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCiInputPath {
    HostHome,
    ProductCacheRoot,
}

impl fmt::Display for RustCiInputPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HostHome => "host home",
            Self::ProductCacheRoot => "product cache root",
        })
    }
}

fn validate_input_path(
    path: &Path,
    field: RustCiInputPath,
) -> Result<(), RustCiDiscoveryInputError> {
    if path.as_os_str().is_empty() {
        return Err(RustCiDiscoveryInputError::EmptyPath { field });
    }
    if !path.is_absolute() {
        return Err(RustCiDiscoveryInputError::RelativePath { field });
    }
    Ok(())
}

/// The exact source component being checked.  It is intentionally a finite
/// type so an error cannot accidentally disclose a caller-selected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCiSourceComponent {
    HostHome,
    CargoDirectory,
    CargoBinDirectory,
    RustupDirectory,
    RustupExecutable,
    RustupSettings,
    ToolchainsDirectory,
    PinnedToolchain,
    CargoRegistry,
    ProductCacheRoot,
    ProductView,
    ProductRuntime,
}

impl fmt::Display for RustCiSourceComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::HostHome => "host home",
            Self::CargoDirectory => "host Cargo directory",
            Self::CargoBinDirectory => "host Cargo bin directory",
            Self::RustupDirectory => "host rustup directory",
            Self::RustupExecutable => "host rustup executable",
            Self::RustupSettings => "host rustup settings",
            Self::ToolchainsDirectory => "host toolchains directory",
            Self::PinnedToolchain => "pinned Rust toolchain",
            Self::CargoRegistry => "host Cargo registry",
            Self::ProductCacheRoot => "product cache root",
            Self::ProductView => "product toolchain view",
            Self::ProductRuntime => "product runtime directories",
        };
        formatter.write_str(name)
    }
}

/// A typed result of server-owned capability discovery.
#[must_use]
#[derive(Debug)]
pub enum RustCiToolchainAvailability {
    Available(Box<RustCiToolchainCapability>),
    Unavailable(RustCiDiscoveryError),
}

impl RustCiToolchainAvailability {
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub const fn capability(&self) -> Option<&RustCiToolchainCapability> {
        match self {
            Self::Available(capability) => Some(capability),
            Self::Unavailable(_) => None,
        }
    }

    pub const fn error(&self) -> Option<&RustCiDiscoveryError> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable(error) => Some(error),
        }
    }
}

/// Product-cache paths that are allowed to be read by a Rust CI process.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct RustCiToolchainView {
    root: PathBuf,
    bin: PathBuf,
    rustup: PathBuf,
    rustup_home: PathBuf,
    settings: PathBuf,
    toolchain: PathBuf,
    cargo_home: PathBuf,
    registry: PathBuf,
}

impl fmt::Debug for RustCiToolchainView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustCiToolchainView")
            .field("entry_count", &3)
            .finish_non_exhaustive()
    }
}

impl RustCiToolchainView {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn bin_dir(&self) -> &Path {
        &self.bin
    }

    pub fn rustup_path(&self) -> &Path {
        &self.rustup
    }

    pub fn rustup_home(&self) -> &Path {
        &self.rustup_home
    }

    pub fn settings_path(&self) -> &Path {
        &self.settings
    }

    pub fn toolchain_path(&self) -> &Path {
        &self.toolchain
    }

    pub fn cargo_home(&self) -> &Path {
        &self.cargo_home
    }

    pub fn registry_path(&self) -> &Path {
        &self.registry
    }
}

/// Stable identity for a product-owned filesystem node.  Paths are only
/// names; cleanup and inspection keep this identity alongside the opened
/// descriptor so a replacement directory cannot silently become authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FilesystemIdentity {
    device: u64,
    inode: u64,
}

/// Product-owned writable paths for one Rust CI launch.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct RustCiRuntimePaths {
    root: PathBuf,
    workspace_namespace: PathBuf,
    execution_namespace: PathBuf,
    workspace_root: PathBuf,
    execution_root: PathBuf,
    target: PathBuf,
    temporary: PathBuf,
    home: PathBuf,
    cargo_home: PathBuf,
    registry_target: PathBuf,
    root_identity: FilesystemIdentity,
    workspace_namespace_identity: FilesystemIdentity,
    execution_namespace_identity: FilesystemIdentity,
    workspace_identity: FilesystemIdentity,
    execution_identity: FilesystemIdentity,
    target_identity: FilesystemIdentity,
    temporary_identity: FilesystemIdentity,
    home_identity: FilesystemIdentity,
    cargo_home_identity: FilesystemIdentity,
}

/// One execution-specific product-cache root retained after a successful
/// sealed package build. The child process is granted access only to this
/// exact root; no user Workspace or Forge Workspace state path is writable.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct RustCiGeneratedPackageOutput {
    namespace: PathBuf,
    root: PathBuf,
    namespace_identity: FilesystemIdentity,
    root_identity: FilesystemIdentity,
}

impl fmt::Debug for RustCiGeneratedPackageOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustCiGeneratedPackageOutput")
            .finish_non_exhaustive()
    }
}

impl RustCiGeneratedPackageOutput {
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the existing generated-output namespace after validating the
    /// product cache root and namespace as real, canonical directories.  No
    /// directory is created by this observation.
    pub fn existing_namespace(
        product_cache_root: &Path,
    ) -> Result<Option<PathBuf>, RustCiDiscoveryError> {
        let root = validate_product_cache_root(product_cache_root)?;
        let cache_identity = capture_runtime_directory_identity(&root)?;
        let namespace = root.join(GENERATED_OUTPUT_DIRECTORY_NAME);
        if optional_runtime_directory_identity(&namespace)?.is_none() {
            validate_directory_identity(
                &root,
                cache_identity,
                RustCiSourceComponent::ProductCacheRoot,
            )?;
            return Ok(None);
        }
        open_verified_directory_path(&namespace).map_err(|source| {
            RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            }
        })?;
        validate_directory_identity(
            &root,
            cache_identity,
            RustCiSourceComponent::ProductCacheRoot,
        )?;
        Ok(Some(namespace))
    }

    /// Derive the only accepted retained-output directory name for one
    /// Workspace/root-fingerprint/Execution tuple.
    pub fn directory_name(
        workspace_id: WorkspaceId,
        root_fingerprint: WorkspaceRootFingerprint,
        execution_id: ExecutionId,
    ) -> String {
        execution_scope_name(workspace_id, root_fingerprint, execution_id)
    }

    /// Derive the exact retained-output prefix for one Workspace root.  The
    /// generated-output namespace is shared by Workspaces, so callers must
    /// filter observations by this prefix before classifying an entry.
    pub fn workspace_prefix(
        workspace_id: WorkspaceId,
        root_fingerprint: WorkspaceRootFingerprint,
    ) -> String {
        workspace_scope_name(workspace_id, root_fingerprint)
    }

    /// Re-open one retained package-output directory by the server-selected
    /// Workspace and execution identities.  This is an observation-only
    /// lookup: it never creates cache directories and returns `None` when the
    /// derived output directory is absent beneath a present, unchanged product
    /// cache root. An unavailable cache root is an error, not missing-artifact
    /// evidence (for example, when its volume has disappeared).
    pub fn open_existing(
        product_cache_root: &Path,
        workspace_id: WorkspaceId,
        root_fingerprint: WorkspaceRootFingerprint,
        execution_id: ExecutionId,
    ) -> Result<Option<Self>, RustCiDiscoveryError> {
        let root = validate_product_cache_root(product_cache_root)?;
        let cache_identity = capture_runtime_directory_identity(&root)?;
        let namespace = root.join(GENERATED_OUTPUT_DIRECTORY_NAME);
        let Some(namespace_identity) = optional_runtime_directory_identity(&namespace)? else {
            validate_directory_identity(
                &root,
                cache_identity,
                RustCiSourceComponent::ProductCacheRoot,
            )?;
            return Ok(None);
        };
        let output = namespace.join(execution_scope_name(
            workspace_id,
            root_fingerprint,
            execution_id,
        ));
        let Some(root_identity) = optional_runtime_directory_identity(&output)? else {
            validate_directory_identity(
                &root,
                cache_identity,
                RustCiSourceComponent::ProductCacheRoot,
            )?;
            return Ok(None);
        };
        open_verified_directory_path(&output).map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        })?;
        validate_directory_identity(
            &root,
            cache_identity,
            RustCiSourceComponent::ProductCacheRoot,
        )?;
        Ok(Some(Self {
            namespace,
            root: output,
            namespace_identity,
            root_identity,
        }))
    }

    /// Revalidate the output root before grant, capture, or cleanup without
    /// following an attacker-installed symlink.
    pub fn revalidate(&self) -> Result<(), RustCiDiscoveryError> {
        validate_directory_identity(
            &self.namespace,
            self.namespace_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.root,
            self.root_identity,
            RustCiSourceComponent::ProductRuntime,
        )
    }

    /// Remove only this exact execution root. A changed identity fails closed
    /// and leaves an observable orphan instead of deleting a replacement.
    pub fn cleanup(&self) -> Result<(), RustCiDiscoveryError> {
        self.revalidate()?;
        remove_owned_directory(&self.root, self.root_identity, self.namespace_identity)
    }

    /// Verify the server-recorded package hash and byte count through the
    /// sealed descriptor before removing this exact execution root.
    pub fn cleanup_verified(
        &self,
        expected_hash: [u8; 32],
        expected_size: u64,
    ) -> Result<(), RustCiDiscoveryError> {
        let mut package = match self.open_stable_package() {
            Ok(package) => package,
            Err(RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            }) if source.kind() == io::ErrorKind::NotFound => {
                self.revalidate()?;
                if generated_output_has_only_empty_dist(&self.root)? {
                    return self.cleanup();
                }
                return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
            }
            Err(error) => return Err(error),
        };
        let actual_size = package
            .metadata()
            .map_err(|source| RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            })?
            .len();
        if actual_size != expected_size || actual_size > MAX_GENERATED_PACKAGE_BYTES {
            return Err(RustCiDiscoveryError::GeneratedPackageMismatch);
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read =
                package
                    .read(&mut buffer)
                    .map_err(|source| RustCiDiscoveryError::Inspect {
                        component: RustCiSourceComponent::ProductRuntime,
                        source,
                    })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        if hasher.finalize().as_bytes() != &expected_hash {
            return Err(RustCiDiscoveryError::GeneratedPackageMismatch);
        }
        drop(package);
        self.cleanup()
    }

    /// Open the one sealed package artifact relative to an already verified
    /// output directory. Both directory traversal and the leaf use NOFOLLOW,
    /// so an output symlink cannot redirect artifact capture.
    pub fn open_stable_package(&self) -> Result<File, RustCiDiscoveryError> {
        self.revalidate()?;
        let root = open_verified_directory_path(&self.root).map_err(|source| {
            RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            }
        })?;
        let dist = openat(
            &root,
            OsStr::new(GENERATED_PACKAGE_DIST_DIRECTORY),
            directory_open_flags(),
            Mode::empty(),
        )
        .map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        })?;
        let file = openat(
            &dist,
            OsStr::new(GENERATED_PACKAGE_FILE_NAME),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        })?;
        Ok(File::from(file))
    }

    /// Return the derived package path after opening it through the verified
    /// descriptor boundary.  Callers that need the bytes should retain and
    /// read the descriptor returned by [`Self::open_stable_package`]; this
    /// path is intended for local Finder/reveal affordances only.
    pub fn stable_package_path(&self) -> Result<PathBuf, RustCiDiscoveryError> {
        let _file = self.open_stable_package()?;
        Ok(self
            .root
            .join(GENERATED_PACKAGE_DIST_DIRECTORY)
            .join(GENERATED_PACKAGE_FILE_NAME))
    }
}

fn generated_output_has_only_empty_dist(root: &Path) -> Result<bool, RustCiDiscoveryError> {
    let root_fd =
        open_verified_directory_path(root).map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        })?;
    let stream = Dir::read_from(&root_fd).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source: source.into(),
    })?;
    for entry in stream {
        let entry = entry.map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        })?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if bytes != GENERATED_PACKAGE_DIST_DIRECTORY.as_bytes() {
            return Ok(false);
        }
        let dist =
            openat(&root_fd, name, directory_open_flags(), Mode::empty()).map_err(|source| {
                RustCiDiscoveryError::Inspect {
                    component: RustCiSourceComponent::ProductRuntime,
                    source: source.into(),
                }
            })?;
        let dist_stream =
            Dir::read_from(&dist).map_err(|source| RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source: source.into(),
            })?;
        for child in dist_stream {
            let child = child.map_err(|source| RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source: source.into(),
            })?;
            let child_name = child.file_name().to_bytes();
            if child_name != b"." && child_name != b".." {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

impl fmt::Debug for RustCiRuntimePaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustCiRuntimePaths")
            .field("directory_count", &8)
            .finish_non_exhaustive()
    }
}

impl RustCiRuntimePaths {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn target_dir(&self) -> &Path {
        &self.target
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn workspace_namespace(&self) -> &Path {
        &self.workspace_namespace
    }

    pub fn execution_root(&self) -> &Path {
        &self.execution_root
    }

    pub fn execution_namespace(&self) -> &Path {
        &self.execution_namespace
    }

    pub fn temporary_dir(&self) -> &Path {
        &self.temporary
    }

    pub fn home_dir(&self) -> &Path {
        &self.home
    }

    pub fn cargo_home(&self) -> &Path {
        &self.cargo_home
    }

    pub fn registry_path(&self) -> PathBuf {
        self.cargo_home.join(REGISTRY_DIRECTORY_NAME)
    }

    /// Validate the runtime tree without following writable-root symlinks.
    /// This is used immediately before process spawn and before cleanup.
    pub fn revalidate(&self) -> Result<(), RustCiDiscoveryError> {
        validate_directory_identity(
            &self.root,
            self.root_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.workspace_namespace,
            self.workspace_namespace_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.execution_namespace,
            self.execution_namespace_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.workspace_root,
            self.workspace_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.execution_root,
            self.execution_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.target,
            self.target_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.temporary,
            self.temporary_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.home,
            self.home_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_directory_identity(
            &self.cargo_home,
            self.cargo_home_identity,
            RustCiSourceComponent::ProductRuntime,
        )?;
        validate_link_target(
            &self.registry_path(),
            &self.registry_target,
            RustCiSourceComponent::CargoRegistry,
        )
    }

    /// Remove this launch's execution directories and its Workspace target
    /// using no-follow validation.  A changed or unexpected symlink fails
    /// closed and remains untouched.
    pub fn cleanup(&self) -> Result<(), RustCiDiscoveryError> {
        self.revalidate()?;
        verification_source::prepare_runtime_source_cleanup(self)?;
        remove_owned_directory(
            &self.execution_root,
            self.execution_identity,
            self.execution_namespace_identity,
        )?;
        remove_owned_directory(&self.target, self.target_identity, self.workspace_identity)?;
        remove_owned_directory_if_empty(
            &self.workspace_root,
            self.workspace_identity,
            self.workspace_namespace_identity,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustCiDiskUsage {
    logical_bytes: u64,
    entries: u64,
}

impl RustCiDiskUsage {
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }

    pub const fn entries(self) -> u64 {
        self.entries
    }
}

#[derive(Debug, Error)]
pub enum RustCiDiskError {
    #[error("Rust CI writable roots exceed the logical-byte policy")]
    LogicalBytesExceeded { logical_bytes: u64, maximum: u64 },
    #[error("Rust CI writable roots exceed the entry-count policy")]
    EntriesExceeded { entries: u64, maximum: u64 },
    #[error("Rust CI writable-root disk scan failed")]
    Inspect(#[source] io::Error),
    #[error("Rust CI writable-root disk scan overflowed")]
    Overflow,
}

/// Scan only product-owned Rust CI writable roots. Symlinks count as entries
/// but are never followed, so a source registry cannot bypass the policy.
pub fn inspect_rust_ci_disk(
    runtime: &RustCiRuntimePaths,
) -> Result<RustCiDiskUsage, RustCiDiskError> {
    inspect_rust_ci_disk_with_limits(
        runtime,
        None,
        RUST_CI_MAX_LOGICAL_BYTES,
        RUST_CI_MAX_ENTRIES,
    )
}

/// Scan ordinary Rust-CI writable roots plus the one retained package-output
/// root while a generated package command is running.
pub fn inspect_rust_ci_disk_with_generated_output(
    runtime: &RustCiRuntimePaths,
    output: &RustCiGeneratedPackageOutput,
) -> Result<RustCiDiskUsage, RustCiDiskError> {
    inspect_rust_ci_disk_with_limits(
        runtime,
        Some(output),
        RUST_CI_MAX_LOGICAL_BYTES,
        RUST_CI_MAX_ENTRIES,
    )
}

fn inspect_rust_ci_disk_with_limits(
    runtime: &RustCiRuntimePaths,
    generated_output: Option<&RustCiGeneratedPackageOutput>,
    maximum_logical_bytes: u64,
    maximum_entries: u64,
) -> Result<RustCiDiskUsage, RustCiDiskError> {
    let mut usage = DiskUsageAccumulator {
        logical_bytes: 0,
        entries: 0,
        maximum_logical_bytes,
        maximum_entries,
    };
    for (root, identity, parent_identity) in [
        (
            runtime.target_dir(),
            runtime.target_identity,
            runtime.workspace_identity,
        ),
        (
            runtime.temporary_dir(),
            runtime.temporary_identity,
            runtime.execution_identity,
        ),
        (
            runtime.home_dir(),
            runtime.home_identity,
            runtime.execution_identity,
        ),
        (
            runtime.cargo_home(),
            runtime.cargo_home_identity,
            runtime.execution_identity,
        ),
    ] {
        scan_rust_ci_tree(root, identity, parent_identity, &mut usage)?;
    }
    if let Some(output) = generated_output {
        scan_rust_ci_tree(
            output.root(),
            output.root_identity,
            output.namespace_identity,
            &mut usage,
        )?;
    }
    let usage = usage.finish();
    if usage.logical_bytes > maximum_logical_bytes {
        return Err(RustCiDiskError::LogicalBytesExceeded {
            logical_bytes: usage.logical_bytes,
            maximum: maximum_logical_bytes,
        });
    }
    if usage.entries > maximum_entries {
        return Err(RustCiDiskError::EntriesExceeded {
            entries: usage.entries,
            maximum: maximum_entries,
        });
    }
    Ok(usage)
}

struct DiskUsageAccumulator {
    logical_bytes: u64,
    entries: u64,
    maximum_logical_bytes: u64,
    maximum_entries: u64,
}

impl DiskUsageAccumulator {
    fn add_entry(&mut self, bytes: u64) -> Result<(), RustCiDiskError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(RustCiDiskError::Overflow)?;
        if self.entries > self.maximum_entries {
            return Err(RustCiDiskError::EntriesExceeded {
                entries: self.entries,
                maximum: self.maximum_entries,
            });
        }
        self.logical_bytes = self
            .logical_bytes
            .checked_add(bytes)
            .ok_or(RustCiDiskError::Overflow)?;
        if self.logical_bytes > self.maximum_logical_bytes {
            return Err(RustCiDiskError::LogicalBytesExceeded {
                logical_bytes: self.logical_bytes,
                maximum: self.maximum_logical_bytes,
            });
        }
        Ok(())
    }

    fn finish(self) -> RustCiDiskUsage {
        RustCiDiskUsage {
            logical_bytes: self.logical_bytes,
            entries: self.entries,
        }
    }
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn split_parent_and_name(path: &Path) -> Option<(&Path, &OsStr)> {
    Some((path.parent()?, path.file_name()?))
}

/// Open an absolute directory path one component at a time.  Every component
/// is opened relative to the previous descriptor with `NOFOLLOW`, so a
/// concurrent symlink replacement cannot redirect traversal to another tree.
fn open_directory_path(path: &Path) -> Result<OwnedFd, io::Error> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory path must be absolute",
        ));
    }
    let mut current =
        open(Path::new("/"), directory_open_flags(), Mode::empty()).map_err(io::Error::from)?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                current = openat(&current, name, directory_open_flags(), Mode::empty())
                    .map_err(io::Error::from)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime directory path contains an unsupported component",
                ));
            }
        }
    }
    Ok(current)
}

// Shared callers retain the fallible signed-device conversion on macOS.
// Linux's native device value is already u64; keep the same error contract.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::unnecessary_wraps,
        reason = "the shared signature preserves macOS negative-device rejection"
    )
)]
fn filesystem_identity_from_stat(
    stat: &rustix_process::fs::Stat,
) -> Result<FilesystemIdentity, io::Error> {
    #[cfg(target_os = "linux")]
    let device = stat.st_dev;
    #[cfg(not(target_os = "linux"))]
    let device = u64::try_from(stat.st_dev)
        .map_err(|_| io::Error::other("filesystem device identity overflowed"))?;
    let inode = stat.st_ino;
    Ok(FilesystemIdentity { device, inode })
}

fn filesystem_identity_from_fd(fd: &OwnedFd) -> Result<FilesystemIdentity, io::Error> {
    let stat = fstat(fd).map_err(io::Error::from)?;
    filesystem_identity_from_stat(&stat)
}

fn filesystem_identity_from_metadata(metadata: &fs::Metadata) -> FilesystemIdentity {
    FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn open_verified_directory_path(path: &Path) -> Result<OwnedFd, io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other("runtime parent is not a real directory"));
    }
    let expected = filesystem_identity_from_metadata(&metadata);
    let directory = open_directory_path(path)?;
    if filesystem_identity_from_fd(&directory)? != expected {
        return Err(io::Error::other("runtime parent changed during open"));
    }
    Ok(directory)
}

fn ensure_scan_entry_identity(
    parent: &OwnedFd,
    name: &OsStr,
    expected: FilesystemIdentity,
) -> Result<(), RustCiDiskError> {
    let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| RustCiDiskError::Inspect(source.into()))?;
    let actual = filesystem_identity_from_stat(&stat).map_err(RustCiDiskError::Inspect)?;
    if actual != expected {
        return Err(RustCiDiskError::Inspect(io::Error::other(
            "runtime scan entry changed during traversal",
        )));
    }
    Ok(())
}

fn ensure_scan_entry_identity_after_traversal(
    parent: &OwnedFd,
    name: &OsStr,
    expected: FilesystemIdentity,
) -> Result<(), RustCiDiskError> {
    let stat = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(source) if source == rustix_process::io::Errno::NOENT => return Ok(()),
        Err(source) => return Err(RustCiDiskError::Inspect(source.into())),
    };
    let actual = filesystem_identity_from_stat(&stat).map_err(RustCiDiskError::Inspect)?;
    if actual != expected {
        return Err(RustCiDiskError::Inspect(io::Error::other(
            "runtime scan entry changed after traversal",
        )));
    }
    Ok(())
}

fn require_cleanup_entry_identity(
    parent: &OwnedFd,
    name: &OsStr,
    expected: FilesystemIdentity,
) -> Result<(), RustCiDiscoveryError> {
    let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
        RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        }
    })?;
    let actual =
        filesystem_identity_from_stat(&stat).map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        })?;
    if actual != expected {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    Ok(())
}

#[derive(Default)]
struct CleanupBudget {
    entries: u64,
}

impl CleanupBudget {
    fn observe(&mut self) -> Result<(), RustCiDiscoveryError> {
        self.entries =
            self.entries
                .checked_add(1)
                .ok_or_else(|| RustCiDiscoveryError::Inspect {
                    component: RustCiSourceComponent::ProductRuntime,
                    source: io::Error::other("runtime cleanup entry count overflowed"),
                })?;
        if self.entries > RUST_CI_MAX_ENTRIES {
            return Err(RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source: io::Error::other("runtime cleanup entry limit exceeded"),
            });
        }
        Ok(())
    }
}

fn cleanup_directory_contents<F>(
    directory: &OwnedFd,
    hook: &mut F,
    budget: &mut CleanupBudget,
    depth: usize,
) -> Result<(), RustCiDiscoveryError>
where
    F: FnMut(&OwnedFd, &OsStr),
{
    let stream = Dir::read_from(directory).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source: source.into(),
    })?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        budget.observe()?;
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    for name in names {
        remove_directory_entry(directory, &name, hook, budget, depth)?;
    }
    Ok(())
}

fn remove_directory_entry<F>(
    parent: &OwnedFd,
    name: &OsStr,
    hook: &mut F,
    budget: &mut CleanupBudget,
    depth: usize,
) -> Result<(), RustCiDiscoveryError>
where
    F: FnMut(&OwnedFd, &OsStr),
{
    let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
        RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        }
    })?;
    let observed_identity =
        filesystem_identity_from_stat(&stat).map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        })?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    if file_type.is_dir() {
        if depth >= MAX_RUST_CI_TRAVERSAL_DEPTH {
            return Err(RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source: io::Error::other("runtime cleanup traversal depth limit exceeded"),
            });
        }
        let child =
            openat(parent, name, directory_open_flags(), Mode::empty()).map_err(|source| {
                RustCiDiscoveryError::Inspect {
                    component: RustCiSourceComponent::ProductRuntime,
                    source: source.into(),
                }
            })?;
        let child_identity = filesystem_identity_from_fd(&child).map_err(|source| {
            RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            }
        })?;
        if child_identity != observed_identity {
            return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
        }
        hook(parent, name);
        cleanup_directory_contents(&child, hook, budget, depth + 1)?;
        require_cleanup_entry_identity(parent, name, child_identity)?;
        unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(|source| {
            RustCiDiscoveryError::Materialize {
                component: RustCiSourceComponent::ProductRuntime,
                source: source.into(),
            }
        })?;
        return Ok(());
    }
    if file_type.is_file() || file_type.is_symlink() {
        require_cleanup_entry_identity(parent, name, observed_identity)?;
        unlinkat(parent, name, AtFlags::empty()).map_err(|source| {
            RustCiDiscoveryError::Materialize {
                component: RustCiSourceComponent::ProductRuntime,
                source: source.into(),
            }
        })?;
        return Ok(());
    }
    Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry)
}

fn scan_rust_ci_tree(
    root: &Path,
    expected_identity: FilesystemIdentity,
    expected_parent_identity: FilesystemIdentity,
    usage: &mut DiskUsageAccumulator,
) -> Result<(), RustCiDiskError> {
    let mut no_hook = |_parent: &std::os::fd::OwnedFd, _name: &OsStr| {};
    scan_rust_ci_tree_with_hook(
        root,
        expected_identity,
        expected_parent_identity,
        usage,
        &mut no_hook,
    )
}

fn scan_rust_ci_tree_with_hook<F>(
    root: &Path,
    expected_identity: FilesystemIdentity,
    expected_parent_identity: FilesystemIdentity,
    usage: &mut DiskUsageAccumulator,
    hook: &mut F,
) -> Result<(), RustCiDiskError>
where
    F: FnMut(&std::os::fd::OwnedFd, &OsStr),
{
    let metadata = fs::symlink_metadata(root).map_err(RustCiDiskError::Inspect)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RustCiDiskError::Inspect(io::Error::other(
            "runtime scan root is not a real directory",
        )));
    }
    if filesystem_identity_from_metadata(&metadata) != expected_identity {
        return Err(RustCiDiskError::Inspect(io::Error::other(
            "runtime scan root changed before traversal",
        )));
    }
    scan_rust_ci_entry_with_hook(
        root,
        &metadata,
        usage,
        false,
        0,
        Some(expected_parent_identity),
        hook,
    )
}

#[cfg(test)]
fn scan_rust_ci_entry(
    path: &Path,
    metadata: &fs::Metadata,
    usage: &mut DiskUsageAccumulator,
    allow_disappeared_directory: bool,
) -> Result<(), RustCiDiskError> {
    let mut no_hook = |_parent: &std::os::fd::OwnedFd, _name: &OsStr| {};
    scan_rust_ci_entry_with_hook(
        path,
        metadata,
        usage,
        allow_disappeared_directory,
        0,
        None,
        &mut no_hook,
    )
}

fn scan_rust_ci_entry_with_hook<F>(
    path: &Path,
    metadata: &fs::Metadata,
    usage: &mut DiskUsageAccumulator,
    allow_disappeared_directory: bool,
    depth: usize,
    expected_parent_identity: Option<FilesystemIdentity>,
    hook: &mut F,
) -> Result<(), RustCiDiskError>
where
    F: FnMut(&std::os::fd::OwnedFd, &OsStr),
{
    usage.add_entry(metadata.len())?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(RustCiDiskError::Inspect(io::Error::other(
            "unexpected runtime filesystem entry",
        )));
    }
    let (parent_path, name) = split_parent_and_name(path)
        .ok_or_else(|| RustCiDiskError::Inspect(io::Error::other("runtime path has no parent")))?;
    let parent = match open_verified_directory_path(parent_path) {
        Ok(parent) => parent,
        Err(error) if allow_disappeared_directory && error.kind() == io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => return Err(RustCiDiskError::Inspect(error)),
    };
    if let Some(expected_parent_identity) = expected_parent_identity {
        let actual_parent_identity =
            filesystem_identity_from_fd(&parent).map_err(RustCiDiskError::Inspect)?;
        if actual_parent_identity != expected_parent_identity {
            return Err(RustCiDiskError::Inspect(io::Error::other(
                "runtime scan parent changed before traversal",
            )));
        }
    }
    let expected_identity = filesystem_identity_from_metadata(metadata);
    match ensure_scan_entry_identity(&parent, name, expected_identity) {
        Ok(()) => {}
        Err(RustCiDiskError::Inspect(error))
            if allow_disappeared_directory && error.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    let directory = match openat(&parent, name, directory_open_flags(), Mode::empty()) {
        Ok(directory) => directory,
        Err(source)
            if allow_disappeared_directory && source == rustix_process::io::Errno::NOENT =>
        {
            return Ok(());
        }
        Err(source) => return Err(RustCiDiskError::Inspect(source.into())),
    };
    let opened_identity =
        filesystem_identity_from_fd(&directory).map_err(RustCiDiskError::Inspect)?;
    if opened_identity != expected_identity {
        return Err(RustCiDiskError::Inspect(io::Error::other(
            "runtime scan directory changed before traversal",
        )));
    }
    hook(&parent, name);
    scan_directory_fd(&directory, usage, depth, hook)?;
    match ensure_scan_entry_identity(&parent, name, opened_identity) {
        Ok(()) => Ok(()),
        Err(RustCiDiskError::Inspect(error))
            if allow_disappeared_directory && error.kind() == io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn scan_directory_fd<F>(
    directory: &std::os::fd::OwnedFd,
    usage: &mut DiskUsageAccumulator,
    depth: usize,
    hook: &mut F,
) -> Result<(), RustCiDiskError>
where
    F: FnMut(&std::os::fd::OwnedFd, &OsStr),
{
    let stream =
        Dir::read_from(directory).map_err(|source| RustCiDiskError::Inspect(source.into()))?;
    for entry in stream {
        let entry = entry.map_err(|source| RustCiDiskError::Inspect(source.into()))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = OsString::from_vec(bytes.to_vec());
        let stat = match statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(source) if source == rustix_process::io::Errno::NOENT => continue,
            Err(source) => return Err(RustCiDiskError::Inspect(source.into())),
        };
        let identity = filesystem_identity_from_stat(&stat).map_err(RustCiDiskError::Inspect)?;
        let size = u64::try_from(stat.st_size).map_err(|_| {
            RustCiDiskError::Inspect(io::Error::other("runtime scan size is negative"))
        })?;
        usage.add_entry(size)?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if file_type.is_symlink() || file_type.is_file() {
            continue;
        }
        if !file_type.is_dir() {
            return Err(RustCiDiskError::Inspect(io::Error::other(
                "unexpected runtime filesystem entry",
            )));
        }
        if depth >= MAX_RUST_CI_TRAVERSAL_DEPTH {
            return Err(RustCiDiskError::Inspect(io::Error::other(
                "runtime scan traversal depth limit exceeded",
            )));
        }

        let child = match openat(directory, &name, directory_open_flags(), Mode::empty()) {
            Ok(child) => child,
            Err(source) if source == rustix_process::io::Errno::NOENT => continue,
            Err(source) => return Err(RustCiDiskError::Inspect(source.into())),
        };
        let child_identity =
            filesystem_identity_from_fd(&child).map_err(RustCiDiskError::Inspect)?;
        if child_identity != identity {
            return Err(RustCiDiskError::Inspect(io::Error::other(
                "runtime scan directory changed before traversal",
            )));
        }
        hook(directory, &name);
        scan_directory_fd(&child, usage, depth + 1, hook)?;
        ensure_scan_entry_identity_after_traversal(directory, &name, child_identity)?;
    }
    Ok(())
}

fn remove_owned_directory(
    path: &Path,
    expected_identity: FilesystemIdentity,
    expected_parent_identity: FilesystemIdentity,
) -> Result<(), RustCiDiscoveryError> {
    let mut no_hook = |_parent: &std::os::fd::OwnedFd, _name: &OsStr| {};
    remove_owned_directory_with_hook(
        path,
        expected_identity,
        expected_parent_identity,
        &mut no_hook,
    )
}

fn remove_owned_directory_with_hook<F>(
    path: &Path,
    expected_identity: FilesystemIdentity,
    expected_parent_identity: FilesystemIdentity,
    hook: &mut F,
) -> Result<(), RustCiDiscoveryError>
where
    F: FnMut(&std::os::fd::OwnedFd, &OsStr),
{
    validate_directory(path, RustCiSourceComponent::ProductRuntime)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source,
    })?;
    if filesystem_identity_from_metadata(&metadata) != expected_identity {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    let (parent_path, name) =
        split_parent_and_name(path).ok_or(RustCiDiscoveryError::NonCanonical {
            component: RustCiSourceComponent::ProductRuntime,
        })?;
    let parent = open_verified_directory_path(parent_path).map_err(|source| {
        RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        }
    })?;
    let parent_identity =
        filesystem_identity_from_fd(&parent).map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        })?;
    if parent_identity != expected_parent_identity {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    let observed = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
        RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        }
    })?;
    if filesystem_identity_from_stat(&observed).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source,
    })? != expected_identity
    {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    let directory =
        openat(&parent, name, directory_open_flags(), Mode::empty()).map_err(|source| {
            RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source: source.into(),
            }
        })?;
    if filesystem_identity_from_fd(&directory).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source,
    })? != expected_identity
    {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    let mut budget = CleanupBudget::default();
    cleanup_directory_contents(&directory, hook, &mut budget, 0)?;
    require_cleanup_entry_identity(&parent, name, expected_identity)?;
    unlinkat(&parent, name, AtFlags::REMOVEDIR).map_err(|source| {
        RustCiDiscoveryError::Materialize {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        }
    })
}

fn remove_owned_directory_if_empty(
    path: &Path,
    expected_identity: FilesystemIdentity,
    expected_parent_identity: FilesystemIdentity,
) -> Result<(), RustCiDiscoveryError> {
    validate_directory(path, RustCiSourceComponent::ProductRuntime)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source,
    })?;
    if filesystem_identity_from_metadata(&metadata) != expected_identity {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    let (parent_path, name) =
        split_parent_and_name(path).ok_or(RustCiDiscoveryError::NonCanonical {
            component: RustCiSourceComponent::ProductRuntime,
        })?;
    let parent = open_verified_directory_path(parent_path).map_err(|source| {
        RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        }
    })?;
    if filesystem_identity_from_fd(&parent).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source,
    })? != expected_parent_identity
    {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    let directory =
        openat(&parent, name, directory_open_flags(), Mode::empty()).map_err(|source| {
            RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source: source.into(),
            }
        })?;
    if filesystem_identity_from_fd(&directory).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source,
    })? != expected_identity
    {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    let stream = Dir::read_from(&directory).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source: source.into(),
    })?;
    for entry in stream {
        let entry = entry.map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes != b"." && bytes != b".." {
            return Err(RustCiDiscoveryError::ProductRuntimeNotEmpty);
        }
    }
    require_cleanup_entry_identity(&parent, name, expected_identity)?;
    unlinkat(&parent, name, AtFlags::REMOVEDIR).map_err(|source| {
        RustCiDiscoveryError::Materialize {
            component: RustCiSourceComponent::ProductRuntime,
            source: source.into(),
        }
    })
}

/// Validated Rust CI capability.  It contains no user Cargo path and no
/// caller-provided environment map; all launch paths are product-owned.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct RustCiToolchainCapability {
    architecture: RustCiHostArchitecture,
    runtime_instance_id: RuntimeInstanceId,
    pinned_toolchain: String,
    view: RustCiToolchainView,
    source_input: RustCiDiscoveryInput,
    source_rustup: PathBuf,
    source_settings: PathBuf,
    source_toolchain: PathBuf,
    source_registry: PathBuf,
}

impl fmt::Debug for RustCiToolchainCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustCiToolchainCapability")
            .field("architecture", &self.architecture)
            .field("has_runtime_instance_id", &true)
            .field("pinned_toolchain", &self.pinned_toolchain)
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

impl RustCiToolchainCapability {
    /// Discover an already materialized product view without creating or
    /// repairing anything.
    pub fn discover(input: &RustCiDiscoveryInput) -> Result<Self, RustCiDiscoveryError> {
        let sources = SourceManifest::discover(input)?;
        let root = validate_product_cache_root(input.product_cache_root())?;
        Self::from_validated_root(&root, sources, input)
    }

    /// Materialize a missing product view from validated host inputs. An
    /// existing non-empty or mismatched view is never deleted or repaired.
    pub fn prepare(input: &RustCiDiscoveryInput) -> Result<Self, RustCiDiscoveryError> {
        let sources = SourceManifest::discover(input)?;
        let root = prepare_product_cache_root(input.product_cache_root())?;
        input
            .tool_homes
            .validate_cache_root(&root, input.host_home())?;
        if !product_view_has_entries(&root)? {
            materialize_product_view(&root, &sources)?;
        }
        Self::from_validated_root(&root, sources, input)
    }

    /// Return availability without turning a missing or malformed host setup
    /// into an ordinary process-launch fallback.
    pub fn availability(input: &RustCiDiscoveryInput) -> RustCiToolchainAvailability {
        match Self::discover(input) {
            Ok(capability) => RustCiToolchainAvailability::Available(Box::new(capability)),
            Err(error) => RustCiToolchainAvailability::Unavailable(error),
        }
    }

    /// Return the current host architecture encoded by this capability.
    pub const fn architecture(&self) -> RustCiHostArchitecture {
        self.architecture
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub fn pinned_toolchain(&self) -> &str {
        &self.pinned_toolchain
    }

    pub const fn view(&self) -> &RustCiToolchainView {
        &self.view
    }

    /// Revalidate this immutable capability against the current host inputs
    /// and product-owned view.
    ///
    /// This operation is observational only: it never repairs, refreshes, or
    /// replaces the capability.  A caller that receives an error must reject
    /// the launch instead of falling back to the baseline execution profile.
    pub fn revalidate_current(&self) -> Result<(), RustCiDiscoveryError> {
        if RustCiHostArchitecture::current() != Some(self.architecture) {
            return Err(RustCiDiscoveryError::ProductViewMismatch);
        }

        // Revalidate the selected pair; never reconstruct a HOME from rustup
        // settings, nor switch storage after execution admission.
        let sources = SourceManifest::discover(&self.source_input)?;
        if sources.rustup != self.source_rustup
            || sources.settings != self.source_settings
            || sources.toolchain != self.source_toolchain
            || sources.registry != self.source_registry
            || sources.pinned_toolchain != self.pinned_toolchain
        {
            return Err(RustCiDiscoveryError::ProductViewMismatch);
        }
        let root = validate_product_cache_root(&self.view.root)?;
        self.source_input
            .tool_homes
            .validate_cache_root(&root, self.source_input.host_home())?;
        let view = validate_existing_product_view(&root, &sources)?;
        if view == self.view {
            Ok(())
        } else {
            Err(RustCiDiscoveryError::ProductViewMismatch)
        }
    }

    pub(crate) fn source_rustup_path(&self) -> &Path {
        &self.source_rustup
    }

    pub(crate) fn source_settings_path(&self) -> &Path {
        &self.source_settings
    }

    pub(crate) fn source_toolchain_path(&self) -> &Path {
        &self.source_toolchain
    }

    pub(crate) fn source_registry_path(&self) -> &Path {
        &self.source_registry
    }

    /// Validate the view and create bounded writable runtime paths for one
    /// workspace/execution identity.  The target directory is stable for the
    /// Workspace root fingerprint; temporary, HOME, and Cargo bookkeeping
    /// directories are isolated per execution.
    pub fn ensure_runtime_paths(
        &self,
        workspace_id: WorkspaceId,
        root_fingerprint: WorkspaceRootFingerprint,
        execution_id: ExecutionId,
    ) -> Result<RustCiRuntimePaths, RustCiDiscoveryError> {
        let sources = SourceManifest {
            architecture: self.architecture,
            pinned_toolchain: self.pinned_toolchain.clone(),
            rustup: self.source_rustup.clone(),
            settings: self.source_settings.clone(),
            toolchain: self.source_toolchain.clone(),
            registry: self.source_registry.clone(),
        };
        let root = validate_product_cache_root(&self.view.root)?;
        let view = validate_existing_product_view(&root, &sources)?;
        if view != self.view {
            return Err(RustCiDiscoveryError::ProductViewMismatch);
        }
        let runtime_root = root.join(RUNTIME_DIRECTORY_NAME);
        let runtime_created = ensure_directory(&runtime_root, true)?;
        let workspaces_root = root.join(RUNTIME_DIRECTORY_NAME).join("workspaces");
        let execution_namespace = root.join(RUNTIME_DIRECTORY_NAME).join("executions");
        ensure_directory(&workspaces_root, runtime_created)?;
        ensure_directory(&execution_namespace, runtime_created)?;

        let workspace_runtime = workspaces_root.join(runtime_workspace_name(
            self.runtime_instance_id,
            workspace_id,
            root_fingerprint,
        ));
        let workspace_created = ensure_directory(&workspace_runtime, true)?;
        if !workspace_created
            && has_unexpected_entries(&workspace_runtime, &[TARGET_DIRECTORY_NAME])?
        {
            return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
        }
        let target = workspace_runtime.join(TARGET_DIRECTORY_NAME);
        ensure_directory(&target, workspace_created)?;

        let execution_dir = execution_namespace.join(runtime_execution_name(
            self.runtime_instance_id,
            workspace_id,
            root_fingerprint,
            execution_id,
        ));
        let execution_created = ensure_directory(&execution_dir, true)?;
        if !execution_created
            && has_unexpected_entries(
                &execution_dir,
                &[
                    TEMP_DIRECTORY_NAME,
                    HOME_DIRECTORY_NAME,
                    CARGO_DIRECTORY_NAME,
                ],
            )?
        {
            return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
        }
        let temporary = execution_dir.join(TEMP_DIRECTORY_NAME);
        ensure_directory(&temporary, execution_created)?;
        let home = execution_dir.join(HOME_DIRECTORY_NAME);
        ensure_directory(&home, execution_created)?;
        let cargo_home_path = execution_dir.join(CARGO_DIRECTORY_NAME);
        let cargo_home_created = ensure_directory(&cargo_home_path, execution_created)?;
        if !cargo_home_created
            && has_unexpected_entries(&cargo_home_path, &[REGISTRY_DIRECTORY_NAME])?
        {
            return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
        }
        let registry = cargo_home_path.join(REGISTRY_DIRECTORY_NAME);
        if cargo_home_created {
            symlink_checked(
                &self.view.registry,
                &registry,
                RustCiSourceComponent::CargoRegistry,
            )?;
        } else {
            validate_link_target(
                &registry,
                &self.source_registry,
                RustCiSourceComponent::CargoRegistry,
            )?;
        }
        Ok(RustCiRuntimePaths {
            root_identity: capture_runtime_directory_identity(&runtime_root)?,
            workspace_namespace_identity: capture_runtime_directory_identity(&workspaces_root)?,
            execution_namespace_identity: capture_runtime_directory_identity(&execution_namespace)?,
            workspace_identity: capture_runtime_directory_identity(&workspace_runtime)?,
            execution_identity: capture_runtime_directory_identity(&execution_dir)?,
            target_identity: capture_runtime_directory_identity(&target)?,
            temporary_identity: capture_runtime_directory_identity(&temporary)?,
            home_identity: capture_runtime_directory_identity(&home)?,
            cargo_home_identity: capture_runtime_directory_identity(&cargo_home_path)?,
            root: runtime_root,
            workspace_namespace: workspaces_root,
            execution_namespace,
            workspace_root: workspace_runtime,
            execution_root: execution_dir,
            target,
            temporary,
            home,
            cargo_home: cargo_home_path,
            registry_target: self.source_registry.clone(),
        })
    }

    /// Allocate one empty, execution-specific generated-output root outside
    /// the ephemeral Rust-CI runtime cleanup tree. Reuse is rejected so a
    /// retry cannot overwrite an earlier artifact or consume an orphan.
    pub fn ensure_generated_package_output(
        &self,
        workspace_id: WorkspaceId,
        root_fingerprint: WorkspaceRootFingerprint,
        execution_id: ExecutionId,
    ) -> Result<RustCiGeneratedPackageOutput, RustCiDiscoveryError> {
        self.revalidate_current()?;
        let root = validate_product_cache_root(&self.view.root)?;
        let namespace = root.join(GENERATED_OUTPUT_DIRECTORY_NAME);
        ensure_directory(&namespace, true)?;
        let output = namespace.join(execution_scope_name(
            workspace_id,
            root_fingerprint,
            execution_id,
        ));
        if !ensure_directory(&output, true)? {
            return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
        }
        Ok(RustCiGeneratedPackageOutput {
            namespace_identity: capture_runtime_directory_identity(&namespace)?,
            root_identity: capture_runtime_directory_identity(&output)?,
            namespace,
            root: output,
        })
    }

    fn from_validated_root(
        root: &Path,
        sources: SourceManifest,
        input: &RustCiDiscoveryInput,
    ) -> Result<Self, RustCiDiscoveryError> {
        input.tool_homes.validate(input.host_home())?;
        input
            .tool_homes
            .validate_cache_root(root, input.host_home())?;
        let view = validate_existing_product_view(root, &sources)?;
        validate_runtime_namespace_shape(root)?;
        Ok(Self {
            architecture: sources.architecture,
            runtime_instance_id: input.runtime_instance_id(),
            pinned_toolchain: sources.pinned_toolchain,
            view,
            source_input: input.clone(),
            source_rustup: sources.rustup,
            source_settings: sources.settings,
            source_toolchain: sources.toolchain,
            source_registry: sources.registry,
        })
    }
}

#[derive(Debug)]
struct SourceManifest {
    architecture: RustCiHostArchitecture,
    pinned_toolchain: String,
    rustup: PathBuf,
    settings: PathBuf,
    toolchain: PathBuf,
    registry: PathBuf,
}

impl SourceManifest {
    fn discover(input: &RustCiDiscoveryInput) -> Result<Self, RustCiDiscoveryError> {
        validate_host_home(input.host_home())?;
        input.tool_homes.validate(input.host_home())?;
        let pinned_toolchain = pinned_toolchain_name(input.architecture());
        let cargo = &input.tool_homes.cargo;
        let rustup_home = &input.tool_homes.rustup;
        // The trusted rustup bootstrap need not move with either data home.
        let bootstrap_cargo = input.host_home().join(".cargo");
        let cargo_bin = bootstrap_cargo.join("bin");
        let toolchains = rustup_home.join(TOOLCHAINS_DIRECTORY_NAME);
        let rustup = cargo_bin.join(RUSTUP_FILE_NAME);
        let settings = rustup_home.join(SETTINGS_FILE_NAME);
        let toolchain = toolchains.join(&pinned_toolchain);
        let registry = cargo.join(REGISTRY_DIRECTORY_NAME);

        validate_directory(&bootstrap_cargo, RustCiSourceComponent::CargoDirectory)?;
        validate_directory(&cargo_bin, RustCiSourceComponent::CargoBinDirectory)?;
        let rustup = validate_regular_file_allowing_safe_link(
            &rustup,
            RustCiSourceComponent::RustupExecutable,
            &bootstrap_cargo,
        )?;
        validate_regular_file(&settings, RustCiSourceComponent::RustupSettings)?;
        validate_directory(&toolchains, RustCiSourceComponent::ToolchainsDirectory)?;
        validate_directory(&toolchain, RustCiSourceComponent::PinnedToolchain)?;
        validate_directory(&registry, RustCiSourceComponent::CargoRegistry)?;

        Ok(Self {
            architecture: input.architecture(),
            pinned_toolchain,
            rustup,
            settings,
            toolchain,
            registry,
        })
    }
}

pub(crate) fn pinned_toolchain_name(architecture: RustCiHostArchitecture) -> String {
    #[cfg(target_os = "macos")]
    {
        format!(
            "{RUST_CI_PINNED_VERSION}-{}-apple-darwin",
            architecture.as_str()
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!(
            "{RUST_CI_PINNED_VERSION}-{}-unknown-linux-gnu",
            architecture.as_str()
        )
    }
}

fn validate_host_home(path: &Path) -> Result<PathBuf, RustCiDiscoveryError> {
    validate_directory(path, RustCiSourceComponent::HostHome)?;
    let canonical = fs::canonicalize(path).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::HostHome,
        source,
    })?;
    if canonical != path {
        return Err(RustCiDiscoveryError::NonCanonical {
            component: RustCiSourceComponent::HostHome,
        });
    }
    Ok(canonical)
}

fn validate_product_cache_root(path: &Path) -> Result<PathBuf, RustCiDiscoveryError> {
    validate_directory(path, RustCiSourceComponent::ProductCacheRoot)?;
    let canonical = fs::canonicalize(path).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductCacheRoot,
        source,
    })?;
    if canonical != path {
        return Err(RustCiDiscoveryError::NonCanonical {
            component: RustCiSourceComponent::ProductCacheRoot,
        });
    }
    Ok(canonical)
}

fn optional_runtime_directory_identity(
    path: &Path,
) -> Result<Option<FilesystemIdentity>, RustCiDiscoveryError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    Ok(Some(filesystem_identity_from_metadata(&metadata)))
}

fn prepare_product_cache_root(path: &Path) -> Result<PathBuf, RustCiDiscoveryError> {
    if path.exists() {
        return validate_product_cache_root(path);
    }
    let parent = path.parent().ok_or(RustCiDiscoveryError::NonCanonical {
        component: RustCiSourceComponent::ProductCacheRoot,
    })?;
    validate_directory(parent, RustCiSourceComponent::ProductCacheRoot)?;
    fs::create_dir(path).map_err(|source| RustCiDiscoveryError::Materialize {
        component: RustCiSourceComponent::ProductCacheRoot,
        source,
    })?;
    validate_product_cache_root(path)
}

fn product_view_has_entries(root: &Path) -> Result<bool, RustCiDiscoveryError> {
    let mut entries = fs::read_dir(root).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductView,
        source,
    })?;
    Ok(entries
        .next()
        .transpose()
        .map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductView,
            source,
        })?
        .is_some())
}

fn validate_runtime_namespace_shape(root: &Path) -> Result<(), RustCiDiscoveryError> {
    let runtime = root.join(RUNTIME_DIRECTORY_NAME);
    let metadata = match fs::symlink_metadata(&runtime) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    if has_unexpected_entries(&runtime, &["workspaces", "executions"])? {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    for name in ["workspaces", "executions"] {
        validate_directory(&runtime.join(name), RustCiSourceComponent::ProductRuntime)?;
    }
    Ok(())
}

fn materialize_product_view(
    root: &Path,
    sources: &SourceManifest,
) -> Result<(), RustCiDiscoveryError> {
    let bin = root.join(BIN_DIRECTORY_NAME);
    let rustup_home = root.join(RUSTUP_DIRECTORY_NAME);
    let toolchains = rustup_home.join(TOOLCHAINS_DIRECTORY_NAME);
    let cargo_home = root.join(CARGO_DIRECTORY_NAME);
    fs::create_dir(&bin)
        .map_err(|source| materialize_error(RustCiSourceComponent::ProductView, source))?;
    fs::create_dir(&rustup_home)
        .map_err(|source| materialize_error(RustCiSourceComponent::ProductView, source))?;
    fs::create_dir(&toolchains)
        .map_err(|source| materialize_error(RustCiSourceComponent::ProductView, source))?;
    fs::create_dir(&cargo_home)
        .map_err(|source| materialize_error(RustCiSourceComponent::ProductView, source))?;

    symlink_checked(
        &sources.rustup,
        &bin.join(RUSTUP_FILE_NAME),
        RustCiSourceComponent::RustupExecutable,
    )?;
    symlink_checked(
        &sources.settings,
        &rustup_home.join(SETTINGS_FILE_NAME),
        RustCiSourceComponent::RustupSettings,
    )?;
    symlink_checked(
        &sources.toolchain,
        &toolchains.join(&sources.pinned_toolchain),
        RustCiSourceComponent::PinnedToolchain,
    )?;
    symlink_checked(
        &sources.registry,
        &cargo_home.join(REGISTRY_DIRECTORY_NAME),
        RustCiSourceComponent::CargoRegistry,
    )?;
    Ok(())
}

fn materialize_error(component: RustCiSourceComponent, source: io::Error) -> RustCiDiscoveryError {
    RustCiDiscoveryError::Materialize { component, source }
}

fn symlink_checked(
    source: &Path,
    destination: &Path,
    component: RustCiSourceComponent,
) -> Result<(), RustCiDiscoveryError> {
    std::os::unix::fs::symlink(source, destination)
        .map_err(|source| RustCiDiscoveryError::Materialize { component, source })
}

fn validate_product_view(
    root: &Path,
    sources: &SourceManifest,
) -> Result<RustCiToolchainView, RustCiDiscoveryError> {
    validate_product_cache_root(root)?;
    let bin = root.join(BIN_DIRECTORY_NAME);
    let rustup_home = root.join(RUSTUP_DIRECTORY_NAME);
    let toolchains = rustup_home.join(TOOLCHAINS_DIRECTORY_NAME);
    let cargo_home = root.join(CARGO_DIRECTORY_NAME);
    validate_directory(&bin, RustCiSourceComponent::ProductView)?;
    validate_directory(&rustup_home, RustCiSourceComponent::ProductView)?;
    validate_directory(&toolchains, RustCiSourceComponent::ProductView)?;
    validate_directory(&cargo_home, RustCiSourceComponent::ProductView)?;
    if has_unexpected_entries(
        root,
        &[
            BIN_DIRECTORY_NAME,
            RUSTUP_DIRECTORY_NAME,
            CARGO_DIRECTORY_NAME,
            RUNTIME_DIRECTORY_NAME,
            GENERATED_OUTPUT_DIRECTORY_NAME,
        ],
    )? || has_unexpected_entries(&bin, &[RUSTUP_FILE_NAME])?
        || has_unexpected_entries(
            &rustup_home,
            &[SETTINGS_FILE_NAME, TOOLCHAINS_DIRECTORY_NAME],
        )?
        || has_unexpected_entries(&toolchains, &[sources.pinned_toolchain.as_str()])?
        || has_unexpected_entries(&cargo_home, &[REGISTRY_DIRECTORY_NAME])?
    {
        return Err(RustCiDiscoveryError::ProductViewMismatch);
    }

    let generated_output = root.join(GENERATED_OUTPUT_DIRECTORY_NAME);
    match fs::symlink_metadata(&generated_output) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RustCiDiscoveryError::Inspect {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            });
        }
    }

    let rustup = root.join(BIN_DIRECTORY_NAME).join(RUSTUP_FILE_NAME);
    let settings = rustup_home.join(SETTINGS_FILE_NAME);
    let toolchain = toolchains.join(&sources.pinned_toolchain);
    let registry = cargo_home.join(REGISTRY_DIRECTORY_NAME);
    validate_link_target(
        &rustup,
        &sources.rustup,
        RustCiSourceComponent::RustupExecutable,
    )?;
    validate_link_target(
        &settings,
        &sources.settings,
        RustCiSourceComponent::RustupSettings,
    )?;
    validate_link_target(
        &toolchain,
        &sources.toolchain,
        RustCiSourceComponent::PinnedToolchain,
    )?;
    validate_link_target(
        &registry,
        &sources.registry,
        RustCiSourceComponent::CargoRegistry,
    )?;

    Ok(RustCiToolchainView {
        root: root.to_path_buf(),
        bin: root.join(BIN_DIRECTORY_NAME),
        rustup,
        rustup_home,
        settings,
        toolchain,
        cargo_home,
        registry,
    })
}

fn validate_existing_product_view(
    root: &Path,
    sources: &SourceManifest,
) -> Result<RustCiToolchainView, RustCiDiscoveryError> {
    validate_product_view(root, sources).map_err(|error| match error {
        RustCiDiscoveryError::Missing { .. }
        | RustCiDiscoveryError::WrongType { .. }
        | RustCiDiscoveryError::NonCanonical { .. }
        | RustCiDiscoveryError::Inspect { .. } => RustCiDiscoveryError::ProductViewMismatch,
        other => other,
    })
}

fn validate_link_target(
    destination: &Path,
    expected: &Path,
    component: RustCiSourceComponent,
) -> Result<(), RustCiDiscoveryError> {
    let actual = fs::canonicalize(destination)
        .map_err(|source| RustCiDiscoveryError::Inspect { component, source })?;
    if actual != expected {
        return Err(RustCiDiscoveryError::ProductViewMismatch);
    }
    Ok(())
}

fn validate_directory(
    path: &Path,
    component: RustCiSourceComponent,
) -> Result<(), RustCiDiscoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            RustCiDiscoveryError::Missing { component }
        } else {
            RustCiDiscoveryError::Inspect { component, source }
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RustCiDiscoveryError::WrongType { component });
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    component: RustCiSourceComponent,
) -> Result<(), RustCiDiscoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            RustCiDiscoveryError::Missing { component }
        } else {
            RustCiDiscoveryError::Inspect { component, source }
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RustCiDiscoveryError::WrongType { component });
    }
    let canonical = fs::canonicalize(path)
        .map_err(|source| RustCiDiscoveryError::Inspect { component, source })?;
    if canonical != path {
        return Err(RustCiDiscoveryError::NonCanonical { component });
    }
    Ok(())
}

fn validate_regular_file_allowing_safe_link(
    path: &Path,
    component: RustCiSourceComponent,
    forbidden_root: &Path,
) -> Result<PathBuf, RustCiDiscoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            RustCiDiscoveryError::Missing { component }
        } else {
            RustCiDiscoveryError::Inspect { component, source }
        }
    })?;
    if metadata.file_type().is_symlink() {
        let canonical = fs::canonicalize(path)
            .map_err(|source| RustCiDiscoveryError::Inspect { component, source })?;
        let target = fs::symlink_metadata(&canonical)
            .map_err(|source| RustCiDiscoveryError::Inspect { component, source })?;
        if !target.is_file() {
            return Err(RustCiDiscoveryError::WrongType { component });
        }
        if canonical.starts_with(forbidden_root) {
            return Err(RustCiDiscoveryError::NonCanonical { component });
        }
        return Ok(canonical);
    }
    if !metadata.is_file() {
        return Err(RustCiDiscoveryError::WrongType { component });
    }
    Ok(path.to_path_buf())
}

fn capture_runtime_directory_identity(
    path: &Path,
) -> Result<FilesystemIdentity, RustCiDiscoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductRuntime,
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    Ok(filesystem_identity_from_metadata(&metadata))
}

fn validate_directory_identity(
    path: &Path,
    expected: FilesystemIdentity,
    component: RustCiSourceComponent,
) -> Result<(), RustCiDiscoveryError> {
    validate_directory(path, component)?;
    let actual = capture_runtime_directory_identity(path)?;
    if actual != expected {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    Ok(())
}

fn has_unexpected_entries(root: &Path, allowed: &[&str]) -> Result<bool, RustCiDiscoveryError> {
    let entries = fs::read_dir(root).map_err(|source| RustCiDiscoveryError::Inspect {
        component: RustCiSourceComponent::ProductView,
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductView,
            source,
        })?;
        let name = entry.file_name();
        if !allowed.iter().any(|allowed| name == *allowed) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_directory(path: &Path, allow_create: bool) -> Result<bool, RustCiDiscoveryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
            }
            Ok(false)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound && allow_create => {
            fs::create_dir(path).map_err(|source| RustCiDiscoveryError::Materialize {
                component: RustCiSourceComponent::ProductRuntime,
                source,
            })?;
            Ok(true)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(RustCiDiscoveryError::ProductRuntimeMismatch)
        }
        Err(source) => Err(RustCiDiscoveryError::Inspect {
            component: RustCiSourceComponent::ProductRuntime,
            source,
        }),
    }
}

fn workspace_scope_name(
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
) -> String {
    let mut fingerprint = String::with_capacity(32);
    for byte in root_fingerprint.into_bytes() {
        let _ = write!(&mut fingerprint, "{byte:02x}");
    }
    format!(
        "workspace-{}-{fingerprint}",
        workspace_id.into_uuid().simple()
    )
}

fn execution_scope_name(
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
    execution_id: ExecutionId,
) -> String {
    format!(
        "{}-execution-{}",
        workspace_scope_name(workspace_id, root_fingerprint),
        execution_id.into_uuid().simple()
    )
}

fn runtime_workspace_name(
    runtime_instance_id: RuntimeInstanceId,
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
) -> String {
    format!(
        "runtime-{}-{}",
        runtime_instance_id.into_uuid().simple(),
        workspace_scope_name(workspace_id, root_fingerprint)
    )
}

fn runtime_execution_name(
    runtime_instance_id: RuntimeInstanceId,
    workspace_id: WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
    execution_id: ExecutionId,
) -> String {
    format!(
        "runtime-{}-{}",
        runtime_instance_id.into_uuid().simple(),
        execution_scope_name(workspace_id, root_fingerprint, execution_id)
    )
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RustCiDiscoveryInputError {
    #[error("{field} path is empty")]
    EmptyPath { field: RustCiInputPath },
    #[error("{field} path must be absolute")]
    RelativePath { field: RustCiInputPath },
}

#[derive(Debug, Error)]
pub enum RustCiDiscoveryError {
    #[error(transparent)]
    InvalidInput(#[from] RustCiDiscoveryInputError),
    #[error("{component} is missing")]
    Missing { component: RustCiSourceComponent },
    #[error("{component} has the wrong type")]
    WrongType { component: RustCiSourceComponent },
    #[error("{component} is not canonical")]
    NonCanonical { component: RustCiSourceComponent },
    #[error("failed to inspect {component}")]
    Inspect {
        component: RustCiSourceComponent,
        #[source]
        source: io::Error,
    },
    #[error("failed to materialize {component}")]
    Materialize {
        component: RustCiSourceComponent,
        #[source]
        source: io::Error,
    },
    #[error("the existing product Rust CI view does not match the pinned capability")]
    ProductViewMismatch,
    #[error("the existing product Rust CI runtime directories do not match the capability")]
    ProductRuntimeMismatch,
    #[error("the product Rust CI runtime contains an unexpected filesystem entry")]
    ProductRuntimeUnexpectedEntry,
    #[error("the product Rust CI Workspace namespace was not empty after cleanup")]
    ProductRuntimeNotEmpty,
    #[error("the retained generated package hash or byte count does not match")]
    GeneratedPackageMismatch,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::fd::OwnedFd;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{ExecutionId, WorkspaceId, WorkspaceRootFingerprint};
    use uuid::Uuid;

    use super::*;

    struct Fixture {
        root: PathBuf,
        input: RustCiDiscoveryInput,
    }

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    const RUST_CI_TEST_POLICY_ENV: &str = "HETERARCHY_FORGE_RUST_CI_TEST_POLICY";
    const RUST_CI_TEST_POLICY_VALUE: &str = "outer-rust-ci-v1";

    fn outer_rust_ci_native_filesystem_checks_unavailable() -> bool {
        std::env::var(RUST_CI_SANDBOX_MARKER_ENV).as_deref() == Ok(RUST_CI_SANDBOX_MARKER_VALUE)
            && std::env::var(RUST_CI_TEST_POLICY_ENV).as_deref() == Ok(RUST_CI_TEST_POLICY_VALUE)
    }

    impl Fixture {
        fn new(architecture: RustCiHostArchitecture) -> Result<Self, Box<dyn std::error::Error>> {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let raw_root = std::env::temp_dir().join(format!(
                "forge-rust-ci-{}-{timestamp}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(&raw_root)?;
            let root = fs::canonicalize(raw_root)?;
            let host = root.join("host-home");
            let cargo = host.join(".cargo");
            let rustup = host.join(".rustup");
            fs::create_dir_all(cargo.join("bin"))?;
            fs::create_dir_all(cargo.join("registry"))?;
            fs::create_dir_all(
                rustup
                    .join("toolchains")
                    .join(pinned_toolchain_name(architecture)),
            )?;
            fs::write(cargo.join("bin").join("rustup"), b"rustup")?;
            fs::write(rustup.join("settings.toml"), b"version = 12\n")?;
            let cache = root.join("cache").join("rust-ci");
            fs::create_dir_all(cache.parent().ok_or("cache parent missing")?)?;
            let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(
                0xA000_0000_u128 + u128::from(serial),
            ));
            let input = RustCiDiscoveryInput::new(host, cache, architecture, runtime_instance_id)?;
            Ok(Self { root, input })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn exact_pinned_toolchain_is_selected_for_each_supported_architecture()
    -> Result<(), Box<dyn std::error::Error>> {
        for architecture in [
            RustCiHostArchitecture::Aarch64,
            RustCiHostArchitecture::X86_64,
        ] {
            let fixture = Fixture::new(architecture)?;
            let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
            assert_eq!(
                capability.pinned_toolchain(),
                pinned_toolchain_name(architecture),
                "the frozen per-OS triple must be projected verbatim"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_or_wrong_source_is_unavailable_without_a_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let availability = RustCiToolchainCapability::availability(&fixture.input);
        assert!(!availability.is_available());
        assert!(matches!(
            availability.error(),
            Some(RustCiDiscoveryError::Missing {
                component: RustCiSourceComponent::ProductCacheRoot
            })
        ));

        fs::create_dir_all(fixture.input.product_cache_root())?;
        fs::remove_file(fixture.input.host_home().join(".rustup/settings.toml"))?;
        let Err(error) = RustCiToolchainCapability::prepare(&fixture.input) else {
            return Err("missing settings was accepted".into());
        };
        assert!(matches!(
            error,
            RustCiDiscoveryError::Missing {
                component: RustCiSourceComponent::RustupSettings
            }
        ));
        fs::write(
            fixture.input.host_home().join(".rustup/settings.toml"),
            b"version = 12\n",
        )?;
        let cargo_credentials = fixture.input.host_home().join(".cargo/credentials.toml");
        fs::write(&cargo_credentials, b"secret")?;
        fs::remove_file(fixture.input.host_home().join(".cargo/bin/rustup"))?;
        std::os::unix::fs::symlink(
            &cargo_credentials,
            fixture.input.host_home().join(".cargo/bin/rustup"),
        )?;
        let Err(error) = RustCiToolchainCapability::prepare(&fixture.input) else {
            return Err("credential link was accepted".into());
        };
        assert!(matches!(
            error,
            RustCiDiscoveryError::NonCanonical {
                component: RustCiSourceComponent::RustupExecutable
            }
        ));
        Ok(())
    }

    #[test]
    fn noncanonical_host_and_wrong_source_types_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let host_alias = fixture.root.join("host-alias");
        std::os::unix::fs::symlink(fixture.input.host_home(), &host_alias)?;
        let aliased_input = RustCiDiscoveryInput::new(
            host_alias,
            fixture.input.product_cache_root().to_path_buf(),
            RustCiHostArchitecture::Aarch64,
            fixture.input.runtime_instance_id(),
        )?;
        let Err(error) = RustCiToolchainCapability::prepare(&aliased_input) else {
            return Err("noncanonical host was accepted".into());
        };
        assert!(matches!(
            error,
            RustCiDiscoveryError::WrongType {
                component: RustCiSourceComponent::HostHome
            } | RustCiDiscoveryError::NonCanonical {
                component: RustCiSourceComponent::HostHome
            }
        ));

        let settings = fixture.input.host_home().join(".rustup/settings.toml");
        fs::remove_file(&settings)?;
        fs::create_dir(&settings)?;
        let Err(error) = RustCiToolchainCapability::prepare(&fixture.input) else {
            return Err("directory settings source was accepted".into());
        };
        assert!(matches!(
            error,
            RustCiDiscoveryError::WrongType {
                component: RustCiSourceComponent::RustupSettings
            }
        ));
        Ok(())
    }

    #[test]
    fn product_view_contains_only_allowed_entries_and_excludes_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let host = fixture.input.host_home();
        fs::write(host.join(".cargo/credentials.toml"), b"secret")?;
        fs::write(host.join(".cargo/config.toml"), b"[net]\noffline = false\n")?;
        fs::create_dir_all(host.join(".git"))?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let root = capability.view().root();
        assert!(root.join("bin/rustup").exists());
        assert!(root.join("rustup-home/settings.toml").exists());
        assert!(root.join("cargo-home/registry").exists());
        assert!(!root.join("bin/config.toml").exists());
        assert!(!root.join("cargo-home/credentials.toml").exists());
        assert!(!root.join("cargo-home/config.toml").exists());
        assert!(!root.join("git").exists());
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(11)),
            WorkspaceRootFingerprint::from_bytes([11; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(12)),
        )?;
        assert!(runtime.target_dir().is_dir());
        assert!(runtime.temporary_dir().is_dir());
        assert!(runtime.home_dir().is_dir());
        Ok(())
    }

    #[test]
    fn mismatched_existing_view_is_typed_and_not_repaired() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        fs::create_dir_all(fixture.input.product_cache_root())?;
        let marker = fixture.input.product_cache_root().join("unexpected");
        fs::write(&marker, b"preserve")?;
        let Err(error) = RustCiToolchainCapability::prepare(&fixture.input) else {
            return Err("mismatched view was accepted".into());
        };
        assert!(matches!(error, RustCiDiscoveryError::ProductViewMismatch));
        assert_eq!(fs::read(marker)?, b"preserve");
        Ok(())
    }

    #[test]
    fn capability_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let debug = format!("{capability:?}");
        assert!(!debug.contains(fixture.input.host_home().to_string_lossy().as_ref()));
        assert!(
            !debug.contains(
                fixture
                    .input
                    .product_cache_root()
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert!(debug.contains("pinned_toolchain"));
        Ok(())
    }

    #[test]
    fn runtime_paths_isolate_workspaces_and_executions() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let first = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(101)),
            WorkspaceRootFingerprint::from_bytes([1; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(201)),
        )?;
        let first_retry = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(101)),
            WorkspaceRootFingerprint::from_bytes([1; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(202)),
        )?;
        let second_workspace = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(102)),
            WorkspaceRootFingerprint::from_bytes([2; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(203)),
        )?;
        let same_execution_id_other_workspace = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(102)),
            WorkspaceRootFingerprint::from_bytes([2; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(201)),
        )?;
        assert_eq!(first.target_dir(), first_retry.target_dir());
        assert_ne!(first.target_dir(), second_workspace.target_dir());
        assert_ne!(first.temporary_dir(), first_retry.temporary_dir());
        assert_ne!(first.home_dir(), first_retry.home_dir());
        assert_ne!(first.cargo_home(), first_retry.cargo_home());
        assert_ne!(first.workspace_root(), second_workspace.workspace_root());
        assert_ne!(
            first.execution_root(),
            same_execution_id_other_workspace.execution_root()
        );
        Ok(())
    }

    #[test]
    fn generated_package_output_is_execution_scoped_and_reuse_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(0x801));
        let fingerprint = WorkspaceRootFingerprint::from_bytes([0x80; 16]);
        let execution = ExecutionId::from_uuid(Uuid::from_u128(0x802));
        let output =
            capability.ensure_generated_package_output(workspace, fingerprint, execution)?;
        output.revalidate()?;
        assert!(output.root().is_dir());
        assert!(matches!(
            capability.ensure_generated_package_output(workspace, fingerprint, execution),
            Err(RustCiDiscoveryError::ProductRuntimeMismatch)
        ));
        output.cleanup()?;
        Ok(())
    }

    #[test]
    fn generated_package_cleanup_requires_exact_hash_and_size()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(0x803));
        let fingerprint = WorkspaceRootFingerprint::from_bytes([0x83; 16]);
        let execution = ExecutionId::from_uuid(Uuid::from_u128(0x804));
        let output =
            capability.ensure_generated_package_output(workspace, fingerprint, execution)?;
        let dist = output.root().join(GENERATED_PACKAGE_DIST_DIRECTORY);
        fs::create_dir(&dist)?;
        let package = dist.join(GENERATED_PACKAGE_FILE_NAME);
        let bytes = b"owned-package";
        fs::write(&package, bytes)?;
        let hash = *blake3::hash(bytes).as_bytes();
        assert!(matches!(
            output.cleanup_verified([0; 32], bytes.len() as u64),
            Err(RustCiDiscoveryError::GeneratedPackageMismatch)
        ));
        assert!(output.root().exists());
        fs::remove_file(&package)?;
        output.cleanup_verified(hash, bytes.len() as u64)?;
        assert!(!output.root().exists());
        Ok(())
    }

    #[test]
    fn retained_generated_package_output_can_be_reopened_without_materialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(0x811));
        let fingerprint = WorkspaceRootFingerprint::from_bytes([0x81; 16]);
        let execution = ExecutionId::from_uuid(Uuid::from_u128(0x812));
        let output =
            capability.ensure_generated_package_output(workspace, fingerprint, execution)?;
        let reopened = RustCiGeneratedPackageOutput::open_existing(
            fixture.input.product_cache_root(),
            workspace,
            fingerprint,
            execution,
        )?
        .ok_or("retained output was not found")?;
        assert_eq!(reopened.root(), output.root());
        assert_eq!(
            RustCiGeneratedPackageOutput::existing_namespace(fixture.input.product_cache_root())?,
            output.root().parent().map(Path::to_path_buf)
        );
        reopened.revalidate()?;
        output.cleanup()?;
        Ok(())
    }

    #[test]
    fn startup_accepts_preserved_runtime_orphans_without_reusing_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let first_capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(301));
        let fingerprint = WorkspaceRootFingerprint::from_bytes([3; 16]);
        let execution = ExecutionId::from_uuid(Uuid::from_u128(302));
        let first_runtime =
            first_capability.ensure_runtime_paths(workspace, fingerprint, execution)?;
        let first_workspace_root = first_runtime.workspace_root().to_path_buf();
        let first_execution_root = first_runtime.execution_root().to_path_buf();

        let second_input = RustCiDiscoveryInput::new(
            fixture.input.host_home().to_path_buf(),
            fixture.input.product_cache_root().to_path_buf(),
            fixture.input.architecture(),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA0FF)),
        )?;
        let second_capability = RustCiToolchainCapability::discover(&second_input)?;
        let second_runtime =
            second_capability.ensure_runtime_paths(workspace, fingerprint, execution)?;

        assert_ne!(
            first_runtime.workspace_root(),
            second_runtime.workspace_root()
        );
        assert_ne!(
            first_runtime.execution_root(),
            second_runtime.execution_root()
        );
        assert!(first_workspace_root.is_dir());
        assert!(first_execution_root.is_dir());
        assert!(second_runtime.workspace_root().is_dir());
        assert!(second_runtime.execution_root().is_dir());
        second_runtime.cleanup()?;
        first_runtime.cleanup()?;
        Ok(())
    }

    #[test]
    fn capability_revalidation_rejects_product_view_symlink_swap()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let replacement = fixture.root.join("replacement-rustup");
        fs::write(&replacement, b"replacement")?;
        fs::remove_file(capability.view().rustup_path())?;
        std::os::unix::fs::symlink(&replacement, capability.view().rustup_path())?;
        let Err(error) = capability.revalidate_current() else {
            return Err("product view symlink swap was accepted".into());
        };
        assert!(matches!(error, RustCiDiscoveryError::ProductViewMismatch));
        assert_eq!(fs::read(&replacement)?, b"replacement");
        Ok(())
    }

    #[test]
    fn disk_scan_counts_symlinks_without_following_their_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        if outer_rust_ci_native_filesystem_checks_unavailable() {
            return Ok(());
        }
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(401)),
            WorkspaceRootFingerprint::from_bytes([4; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(402)),
        )?;
        let before = inspect_rust_ci_disk(&runtime)?;
        let outside = fixture.root.join("outside-secret");
        fs::write(&outside, vec![b's'; 16 * 1024])?;
        let link = runtime.temporary_dir().join("outside-link");
        std::os::unix::fs::symlink(&outside, &link)?;
        let after = inspect_rust_ci_disk(&runtime)?;
        assert_eq!(after.entries(), before.entries() + 1);
        assert!(after.logical_bytes() < before.logical_bytes() + 16 * 1024);
        runtime.cleanup()?;
        assert_eq!(fs::read(&outside)?, vec![b's'; 16 * 1024]);
        assert!(!link.exists());
        Ok(())
    }

    #[test]
    fn disk_scan_rejects_top_level_real_directory_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(551)),
            WorkspaceRootFingerprint::from_bytes([5; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(552)),
        )?;
        let replacement = fixture.root.join("replacement-target");
        fs::create_dir(&replacement)?;
        let sentinel = replacement.join("sentinel");
        fs::write(&sentinel, b"must survive")?;
        fs::remove_dir(runtime.target_dir())?;
        fs::rename(&replacement, runtime.target_dir())?;

        let result = inspect_rust_ci_disk(&runtime);
        assert!(matches!(result, Err(RustCiDiskError::Inspect(_))));
        assert_eq!(
            fs::read(runtime.target_dir().join("sentinel"))?,
            b"must survive"
        );
        Ok(())
    }

    #[test]
    fn cleanup_rejects_directory_to_outside_symlink_swap() -> Result<(), Box<dyn std::error::Error>>
    {
        if outer_rust_ci_native_filesystem_checks_unavailable() {
            return Ok(());
        }
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(601)),
            WorkspaceRootFingerprint::from_bytes([6; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(602)),
        )?;
        let child = runtime.target_dir().join("swap-me");
        fs::create_dir(&child)?;
        let outside = fixture.root.join("cleanup-outside");
        fs::create_dir(&outside)?;
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"must survive")?;

        let mut hook_completed = false;
        let mut hook = |_: &OwnedFd, name: &OsStr| {
            if name == OsStr::new("swap-me") {
                hook_completed = fs::remove_dir(&child).is_ok()
                    && std::os::unix::fs::symlink(&outside, &child).is_ok();
            }
        };
        let result = remove_owned_directory_with_hook(
            runtime.target_dir(),
            runtime.target_identity,
            runtime.workspace_identity,
            &mut hook,
        );
        assert!(matches!(
            result,
            Err(RustCiDiscoveryError::ProductRuntimeMismatch)
        ));
        assert!(hook_completed);
        assert_eq!(fs::read(&sentinel)?, b"must survive");
        assert!(fs::symlink_metadata(&child)?.file_type().is_symlink());
        Ok(())
    }

    #[test]
    fn cleanup_and_disk_scan_reject_excessive_traversal_depth()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(651)),
            WorkspaceRootFingerprint::from_bytes([6; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(652)),
        )?;
        let mut nested = runtime.target_dir().to_path_buf();
        for _ in 0..=MAX_RUST_CI_TRAVERSAL_DEPTH {
            nested.push("d");
            fs::create_dir(&nested)?;
        }

        let scan_result = inspect_rust_ci_disk(&runtime);
        assert!(matches!(scan_result, Err(RustCiDiskError::Inspect(_))));
        let cleanup_result = runtime.cleanup();
        assert!(matches!(
            cleanup_result,
            Err(RustCiDiscoveryError::Inspect { .. })
        ));
        assert!(nested.is_dir());
        Ok(())
    }

    #[test]
    fn disk_scan_tolerates_nested_directory_removed_after_open()
    -> Result<(), Box<dyn std::error::Error>> {
        if outer_rust_ci_native_filesystem_checks_unavailable() {
            return Ok(());
        }
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(681)),
            WorkspaceRootFingerprint::from_bytes([68; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(682)),
        )?;
        let child = runtime.temporary_dir().join("remove-after-open");
        fs::create_dir(&child)?;

        let mut hook_completed = false;
        let mut hook = |_: &OwnedFd, name: &OsStr| {
            if name == OsStr::new("remove-after-open") {
                hook_completed = fs::remove_dir(&child).is_ok();
            }
        };
        let mut usage = DiskUsageAccumulator {
            logical_bytes: 0,
            entries: 0,
            maximum_logical_bytes: RUST_CI_MAX_LOGICAL_BYTES,
            maximum_entries: RUST_CI_MAX_ENTRIES,
        };
        scan_rust_ci_tree_with_hook(
            runtime.temporary_dir(),
            runtime.temporary_identity,
            runtime.execution_identity,
            &mut usage,
            &mut hook,
        )?;
        assert!(hook_completed);
        assert!(!child.exists());
        runtime.cleanup()?;
        Ok(())
    }

    #[test]
    fn disk_scan_rejects_directory_to_outside_symlink_swap_without_following()
    -> Result<(), Box<dyn std::error::Error>> {
        if outer_rust_ci_native_filesystem_checks_unavailable() {
            return Ok(());
        }
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(701)),
            WorkspaceRootFingerprint::from_bytes([7; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(702)),
        )?;
        let child = runtime.temporary_dir().join("swap-me");
        fs::create_dir(&child)?;
        let outside = fixture.root.join("scan-outside");
        fs::create_dir(&outside)?;
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"must survive")?;

        let mut hook_completed = false;
        let mut hook = |_: &OwnedFd, name: &OsStr| {
            if name == OsStr::new("swap-me") {
                hook_completed = fs::remove_dir(&child).is_ok()
                    && std::os::unix::fs::symlink(&outside, &child).is_ok();
            }
        };
        let mut usage = DiskUsageAccumulator {
            logical_bytes: 0,
            entries: 0,
            maximum_logical_bytes: RUST_CI_MAX_LOGICAL_BYTES,
            maximum_entries: RUST_CI_MAX_ENTRIES,
        };
        let result = scan_rust_ci_tree_with_hook(
            runtime.temporary_dir(),
            runtime.temporary_identity,
            runtime.execution_identity,
            &mut usage,
            &mut hook,
        );
        assert!(matches!(result, Err(RustCiDiskError::Inspect(_))));
        assert!(hook_completed);
        assert_eq!(fs::read(&sentinel)?, b"must survive");
        assert!(fs::symlink_metadata(&child)?.file_type().is_symlink());
        Ok(())
    }

    #[test]
    fn disk_scan_tolerates_disappeared_nested_entries_but_not_missing_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        if outer_rust_ci_native_filesystem_checks_unavailable() {
            return Ok(());
        }
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        let runtime = capability.ensure_runtime_paths(
            WorkspaceId::from_uuid(Uuid::from_u128(501)),
            WorkspaceRootFingerprint::from_bytes([5; 16]),
            ExecutionId::from_uuid(Uuid::from_u128(502)),
        )?;
        let disappeared = runtime.temporary_dir().join("transient-directory");
        fs::create_dir(&disappeared)?;
        let observed = fs::symlink_metadata(&disappeared)?;
        fs::remove_dir(&disappeared)?;
        let mut usage = DiskUsageAccumulator {
            logical_bytes: 0,
            entries: 0,
            maximum_logical_bytes: RUST_CI_MAX_LOGICAL_BYTES,
            maximum_entries: RUST_CI_MAX_ENTRIES,
        };

        scan_rust_ci_entry(&disappeared, &observed, &mut usage, true)?;
        assert!(matches!(
            scan_rust_ci_entry(&disappeared, &observed, &mut usage, false),
            Err(RustCiDiskError::Inspect(error))
                if error.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn ssd_attempts_stop_on_success_and_local_is_fifth_only()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::cell::Cell;

        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        let capability = RustCiToolchainCapability::prepare(&fixture.input)?;
        for successful_attempt in 1_u8..=4 {
            let attempts = Cell::new(0_u8);
            let waits = Cell::new(0_u8);
            let selected = storage::prepare_with_attempts(
                || {
                    attempts.set(attempts.get() + 1);
                    if attempts.get() == successful_attempt {
                        Ok(capability.clone())
                    } else {
                        Err(RustCiDiscoveryError::ProductViewMismatch)
                    }
                },
                || Err(RustCiDiscoveryError::ProductRuntimeMismatch),
                || waits.set(waits.get() + 1),
            )?;
            assert_eq!(attempts.get(), successful_attempt);
            assert_eq!(waits.get(), successful_attempt - 1);
            assert_eq!(
                selected.ssd_failures().len(),
                usize::from(successful_attempt - 1)
            );
            assert_eq!(
                selected.selection(),
                RustCiStorageSelection::Ssd { successful_attempt }
            );
        }
        let attempts = Cell::new(0_u8);
        let local_calls = Cell::new(0_u8);
        let waits = Cell::new(0_u8);
        let selected = storage::prepare_with_attempts(
            || {
                attempts.set(attempts.get() + 1);
                Err(RustCiDiscoveryError::ProductViewMismatch)
            },
            || {
                assert_eq!(attempts.get(), 4);
                local_calls.set(local_calls.get() + 1);
                Ok(capability)
            },
            || waits.set(waits.get() + 1),
        )?;
        assert_eq!((attempts.get(), local_calls.get(), waits.get()), (4, 1, 3));
        assert_eq!(selected.ssd_failures().len(), 4);
        assert_eq!(
            selected.selection(),
            RustCiStorageSelection::LocalAfterFourSsdFailures
        );
        let failed = storage::prepare_with_attempts(
            || Err(RustCiDiscoveryError::ProductViewMismatch),
            || Err(RustCiDiscoveryError::ProductRuntimeMismatch),
            || {},
        );
        let Err(error) = failed else {
            return Err("both unavailable candidates must remain unavailable".into());
        };
        assert_eq!(error.ssd_failures().len(), 4);
        Ok(())
    }

    #[test]
    fn selected_tool_homes_are_revalidated_without_deriving_a_fake_host_home()
    -> Result<(), Box<dyn std::error::Error>> {
        let architecture =
            RustCiHostArchitecture::current().unwrap_or(RustCiHostArchitecture::Aarch64);
        let fixture = Fixture::new(architecture)?;
        let mut input = fixture.input.clone();
        let cargo = fixture.root.join("separate-cargo-home");
        let rustup = fixture.root.join("separate-rustup-home");
        fs::create_dir(&cargo)?;
        fs::rename(
            input.host_home().join(".cargo/registry"),
            cargo.join("registry"),
        )?;
        fs::rename(input.host_home().join(".rustup"), &rustup)?;
        input.tool_homes.cargo = cargo.clone();
        input.tool_homes.rustup = rustup.clone();
        let capability = RustCiToolchainCapability::prepare(&input)?;
        assert_eq!(capability.source_registry_path(), cargo.join("registry"));
        assert_eq!(
            capability.source_settings_path(),
            rustup.join("settings.toml")
        );
        assert!(input.host_home().join(".cargo/bin/rustup").is_file());
        if RustCiHostArchitecture::current() == Some(architecture) {
            capability.revalidate_current()?;
        }
        fs::remove_file(rustup.join("settings.toml"))?;
        assert!(SourceManifest::discover(&capability.source_input).is_err());
        Ok(())
    }

    #[test]
    fn fallback_preserves_legacy_view_and_never_creates_a_fake_ssd()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(RustCiHostArchitecture::Aarch64)?;
        fs::create_dir(fixture.input.product_cache_root())?;
        let retained = fixture.input.product_cache_root().join("retained-artifact");
        fs::write(&retained, b"preserve old execution evidence")?;
        let local = storage::local_candidate(&fixture.input)?;
        assert_ne!(
            local.product_cache_root(),
            fixture.input.product_cache_root()
        );
        let _capability = RustCiToolchainCapability::prepare(&local)?;
        assert_eq!(fs::read(&retained)?, b"preserve old execution evidence");
        let absent = fixture.root.join("absent-ssd");
        assert!(storage::ssd_candidate(&fixture.input, &absent).is_err());
        assert!(!absent.exists());
        assert!(storage::ssd_candidate(&fixture.input, &fixture.root).is_err());
        let normalized = fixture.root.join("cache").join("..");
        assert!(matches!(
            storage::ssd_candidate(&fixture.input, &normalized),
            Err(RustCiDiscoveryError::NonCanonical { .. })
        ));
        let alias = fixture.root.join("root-alias");
        std::os::unix::fs::symlink(&fixture.root, &alias)?;
        assert!(matches!(
            storage::ssd_candidate(&fixture.input, &alias.join("cache")),
            Err(RustCiDiscoveryError::NonCanonical { .. })
        ));
        Ok(())
    }
}
