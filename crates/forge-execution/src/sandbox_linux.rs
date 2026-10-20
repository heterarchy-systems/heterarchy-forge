//! Linux sandbox backend: bubblewrap confinement with the same invariants
//! as the macOS prototype (frozen contract, `04` §6).
//!
//! Invariants mirrored from `sandbox.rs` (no sandbox/grant bypass):
//! deny-by-default, Workspace read/write exactly per `ExecutionPermissions`,
//! the state root is never mounted, a verification process sees only its
//! validated source replica, any profile artifact is bounded and redacted in
//! Debug, and a missing backend maps to the typed fail-closed
//! `SandboxUnavailable`. Bubblewrap is an external image package — no new
//! crate dependency — and its absence degrades to exactly the historical
//! fail-closed behavior.

use std::ffi::OsString;
use std::fmt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::sandbox::{MacOsSandboxProfile, SandboxBackendError, SandboxBackendStatus};
use crate::{
    ExecutionLaunchKind, PackageVExecutableCapability, RustCiGeneratedPackageOutput,
    RustCiToolchainCapability,
};
use forge_domain::ExecutionPermissions;
use forge_workspace::ExistingWorkspaceStateLayout;

pub(crate) const BWRAP_PATH: &str = "/usr/bin/bwrap";
const MAX_SANDBOX_ARGS_BYTES: usize = 32 * 1024;

/// The platform dispatch seam (frozen: Option 1 enum). Construction is keyed
/// on the compile-time target; both arms enforce the same invariant matrix.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum SandboxProfile {
    MacOs(MacOsSandboxProfile),
    Linux(LinuxSandboxProfile),
}

impl fmt::Debug for SandboxProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MacOs(profile) => formatter.debug_tuple("MacOs").field(profile).finish(),
            Self::Linux(profile) => formatter.debug_tuple("Linux").field(profile).finish(),
        }
    }
}

impl SandboxProfile {
    /// Platform dispatch probe; constructed profiles are created through the
    /// for_* constructors, so the macOS arm never calls this.
    #[allow(dead_code)]
    pub(crate) fn status() -> SandboxBackendStatus {
        match Self::platform() {
            Platform::MacOs => MacOsSandboxProfile::status(),
            Platform::Linux => LinuxSandboxProfile::status(),
        }
    }

    pub(crate) fn for_launch(
        layout: &ExistingWorkspaceStateLayout,
        permissions: ExecutionPermissions,
        launch_kind: ExecutionLaunchKind,
        capability: Option<&RustCiToolchainCapability>,
        runtime: Option<&crate::RustCiRuntimePaths>,
        generated_package_output: Option<&RustCiGeneratedPackageOutput>,
        package_cloudflared: Option<&Path>,
    ) -> Result<Self, SandboxBackendError> {
        match Self::platform() {
            Platform::MacOs => Ok(Self::MacOs(MacOsSandboxProfile::for_launch(
                layout,
                permissions,
                launch_kind,
                capability,
                runtime,
                generated_package_output,
                package_cloudflared,
            )?)),
            Platform::Linux => Ok(Self::Linux(LinuxSandboxProfile::for_launch(
                layout,
                permissions,
                launch_kind,
                capability,
                runtime,
                generated_package_output,
                package_cloudflared,
            )?)),
        }
    }

    pub(crate) fn for_verification_launch(
        layout: &ExistingWorkspaceStateLayout,
        source: &Path,
        launch_kind: ExecutionLaunchKind,
        capability: &RustCiToolchainCapability,
        runtime: &crate::RustCiRuntimePaths,
        generated_package_output: Option<&RustCiGeneratedPackageOutput>,
        package_cloudflared: Option<&Path>,
    ) -> Result<Self, SandboxBackendError> {
        match Self::platform() {
            Platform::MacOs => Ok(Self::MacOs(MacOsSandboxProfile::for_verification_launch(
                layout,
                source,
                launch_kind,
                capability,
                runtime,
                generated_package_output,
                package_cloudflared,
            )?)),
            Platform::Linux => Ok(Self::Linux(LinuxSandboxProfile::for_verification_launch(
                layout,
                source,
                launch_kind,
                capability,
                runtime,
                generated_package_output,
                package_cloudflared,
            )?)),
        }
    }

    pub(crate) fn for_package_verification_launch(
        layout: &ExistingWorkspaceStateLayout,
        source: &Path,
        capability: &PackageVExecutableCapability,
    ) -> Result<Self, SandboxBackendError> {
        match Self::platform() {
            Platform::MacOs => Ok(Self::MacOs(
                MacOsSandboxProfile::for_package_verification_launch(layout, source, capability)?,
            )),
            Platform::Linux => Ok(Self::Linux(
                LinuxSandboxProfile::for_package_verification_launch(layout, source, capability)?,
            )),
        }
    }

    /// Prepend the platform confinement wrapper to the child command.
    pub(crate) fn apply_to(&self, command: &mut std::process::Command) {
        match self {
            Self::MacOs(profile) => {
                command.arg("-p").arg(profile.as_str());
            }
            Self::Linux(profile) => {
                for argument in profile.args() {
                    command.arg(argument);
                }
            }
        }
    }

    fn platform() -> Platform {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }
}

enum Platform {
    MacOs,
    Linux,
}

/// Generated bubblewrap invocation for one execution. Debug never exposes
/// paths or arguments. Compiled on every target so the dispatch enum is
/// total; only the Linux arm constructs it.
#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxSandboxProfile {
    args: Vec<OsString>,
}

impl fmt::Debug for LinuxSandboxProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: usize = self.args.iter().map(|argument| argument.len()).sum();
        formatter
            .debug_struct("LinuxSandboxProfile")
            .field("bytes", &bytes)
            .finish()
    }
}

impl LinuxSandboxProfile {
    pub(crate) fn status() -> SandboxBackendStatus {
        if Path::new(BWRAP_PATH).is_file() && probe_namespace_backend() {
            SandboxBackendStatus::AvailableDeprecatedPrototype
        } else {
            SandboxBackendStatus::Unavailable
        }
    }

    #[allow(dead_code)]
    pub(crate) fn new(
        layout: &ExistingWorkspaceStateLayout,
        permissions: ExecutionPermissions,
    ) -> Result<Self, SandboxBackendError> {
        Self::for_launch(
            layout,
            permissions,
            ExecutionLaunchKind::Baseline,
            None,
            None,
            None,
            None,
        )
    }

    pub(crate) fn for_launch(
        layout: &ExistingWorkspaceStateLayout,
        permissions: ExecutionPermissions,
        launch_kind: ExecutionLaunchKind,
        capability: Option<&RustCiToolchainCapability>,
        runtime: Option<&crate::RustCiRuntimePaths>,
        generated_package_output: Option<&RustCiGeneratedPackageOutput>,
        package_cloudflared: Option<&Path>,
    ) -> Result<Self, SandboxBackendError> {
        if Self::status() == SandboxBackendStatus::Unavailable {
            return Err(SandboxBackendError::Unavailable);
        }
        let share_network = launch_kind == ExecutionLaunchKind::Baseline && permissions.network();
        let mut args = namespace_args(share_network);
        if ["/usr", "/etc/ssl", "/etc/alternatives", "/proc", "/dev"]
            .into_iter()
            .any(|root| Path::new(root).starts_with(layout.workspace_root()))
        {
            return Err(SandboxBackendError::VerificationSourceScope);
        }
        if launch_kind == ExecutionLaunchKind::Baseline {
            if permissions.workspace_read() || permissions.workspace_write() {
                push_bind(
                    &mut args,
                    layout.workspace_root(),
                    permissions.workspace_write(),
                );
                hide_path(&mut args, layout.state_root());
            } else {
                hide_path_with_mode(&mut args, layout.workspace_root(), "100");
            }
            if permissions.network() {
                for path in ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"] {
                    if Path::new(path).is_file() {
                        push_bind(&mut args, Path::new(path), false);
                    }
                }
            }
        } else {
            let capability = capability.ok_or(SandboxBackendError::RustCiCapabilityRequired)?;
            let runtime = runtime.ok_or(SandboxBackendError::RustCiRuntimeRequired)?;
            if launch_kind == ExecutionLaunchKind::RustCiGeneratedPackage
                && package_cloudflared.is_none()
            {
                return Err(SandboxBackendError::RustCiPackageHelperRequired);
            }
            append_rust_ci_mounts(
                &mut args,
                capability,
                runtime,
                generated_package_output,
                package_cloudflared,
            );
            // Debian's public compiler frontends are alternatives symlinks.
            // Bind only these exact read-only aliases, never the whole /etc tree.
            for path in [
                "/etc/alternatives/cc",
                "/etc/alternatives/c++",
                "/etc/alternatives/cpp",
            ] {
                if Path::new(path).is_file() {
                    match std::fs::read_link(path) {
                        Ok(target) => args.extend([
                            OsString::from("--symlink"),
                            target.into_os_string(),
                            OsString::from(path),
                        ]),
                        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                            push_bind(&mut args, Path::new(path), false);
                        }
                        Err(_) => return Err(SandboxBackendError::Unavailable),
                    }
                }
            }
            // Mask live source even when a fixed system mount is its ancestor.
            hide_path_with_mode(&mut args, layout.workspace_root(), "100");
        }
        let bytes: usize = args.iter().map(|argument| argument.len()).sum();
        if bytes > MAX_SANDBOX_ARGS_BYTES {
            return Err(SandboxBackendError::ProfileTooLarge {
                actual: bytes,
                maximum: MAX_SANDBOX_ARGS_BYTES,
            });
        }
        Ok(Self { args })
    }

    pub(crate) fn for_verification_launch(
        layout: &ExistingWorkspaceStateLayout,
        source: &Path,
        launch_kind: ExecutionLaunchKind,
        capability: &RustCiToolchainCapability,
        runtime: &crate::RustCiRuntimePaths,
        generated_package_output: Option<&RustCiGeneratedPackageOutput>,
        package_cloudflared: Option<&Path>,
    ) -> Result<Self, SandboxBackendError> {
        if launch_kind == ExecutionLaunchKind::Baseline {
            return Err(SandboxBackendError::VerificationSourceScope);
        }
        crate::sandbox::validate_verification_scope(layout, source, capability, runtime)?;
        let mut profile = Self::for_launch(
            layout,
            ExecutionPermissions::new(true, false, false),
            launch_kind,
            Some(capability),
            Some(runtime),
            generated_package_output,
            package_cloudflared,
        )?;
        push_bind(&mut profile.args, source, false);
        let bytes: usize = profile.args.iter().map(|argument| argument.len()).sum();
        if bytes > MAX_SANDBOX_ARGS_BYTES {
            return Err(SandboxBackendError::ProfileTooLarge {
                actual: bytes,
                maximum: MAX_SANDBOX_ARGS_BYTES,
            });
        }
        Ok(profile)
    }

    pub(crate) fn for_package_verification_launch(
        layout: &ExistingWorkspaceStateLayout,
        source: &Path,
        capability: &PackageVExecutableCapability,
    ) -> Result<Self, SandboxBackendError> {
        if Self::status() == SandboxBackendStatus::Unavailable {
            return Err(SandboxBackendError::Unavailable);
        }
        crate::sandbox::validate_package_verification_scope(layout, source, capability.path())?;
        let mut args = namespace_args(false);
        push_directory_scaffold(&mut args, source);
        if let Some(parent) = capability.path().parent() {
            push_directory_scaffold(&mut args, parent);
        }
        push_bind(&mut args, source, false);
        push_bind(&mut args, capability.path(), false);
        hide_path_with_mode(&mut args, layout.workspace_root(), "100");
        let bytes: usize = args.iter().map(|argument| argument.len()).sum();
        if bytes > MAX_SANDBOX_ARGS_BYTES {
            return Err(SandboxBackendError::ProfileTooLarge {
                actual: bytes,
                maximum: MAX_SANDBOX_ARGS_BYTES,
            });
        }
        Ok(Self { args })
    }

    pub(crate) fn args(&self) -> &[OsString] {
        &self.args
    }
}

fn namespace_args(share_network: bool) -> Vec<OsString> {
    let mut args = [
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    .map(OsString::from)
    .to_vec();
    if !share_network {
        args.push(OsString::from("--unshare-net"));
    }
    push_bind(&mut args, Path::new("/usr"), false);
    for (link, target) in [
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ] {
        args.extend([
            OsString::from("--symlink"),
            OsString::from(target),
            OsString::from(link),
        ]);
    }
    if Path::new("/etc/ssl").exists() {
        push_bind(&mut args, Path::new("/etc/ssl"), false);
    }
    args
}

fn probe_namespace_backend() -> bool {
    let Ok(mut child) = Command::new(BWRAP_PATH)
        .args(namespace_args(false))
        .args(["--chdir", "/", "--", "/usr/bin/true"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _kill = child.kill();
                let _join = child.wait();
                return false;
            }
        }
    }
}

fn push_bind(args: &mut Vec<OsString>, path: &Path, writable: bool) {
    args.push(OsString::from(if writable {
        "--bind"
    } else {
        "--ro-bind"
    }));
    args.push(path.as_os_str().to_owned());
    args.push(path.as_os_str().to_owned());
}

fn push_directory_scaffold(args: &mut Vec<OsString>, path: &Path) {
    let mut current = Path::new("/").to_path_buf();
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        args.extend([OsString::from("--dir"), current.as_os_str().to_owned()]);
    }
}

fn hide_path(args: &mut Vec<OsString>, path: &Path) {
    hide_path_with_mode(args, path, "000");
}

fn hide_path_with_mode(args: &mut Vec<OsString>, path: &Path, mode: &str) {
    args.extend([
        OsString::from("--perms"),
        OsString::from(mode),
        OsString::from("--tmpfs"),
    ]);
    args.push(path.as_os_str().to_owned());
    args.push(OsString::from("--remount-ro"));
    args.push(path.as_os_str().to_owned());
}

fn append_rust_ci_mounts(
    args: &mut Vec<OsString>,
    capability: &RustCiToolchainCapability,
    runtime: &crate::RustCiRuntimePaths,
    output: Option<&RustCiGeneratedPackageOutput>,
    package_cloudflared: Option<&Path>,
) {
    let view = capability.view();
    // Also fence a cache placed under a fixed system-read mount. The child
    // must never inherit sibling executions from that broader ancestor.
    args.push(OsString::from("--tmpfs"));
    args.push(view.root().as_os_str().to_owned());
    // The view root also owns unrelated execution/output namespaces. Only
    // immutable toolchain-view components belong in this child.
    for path in [view.bin_dir(), view.rustup_home(), view.cargo_home()] {
        push_bind(args, path, false);
    }
    for path in [
        capability.source_rustup_path(),
        capability.source_settings_path(),
        capability.source_toolchain_path(),
        capability.source_registry_path(),
    ] {
        push_bind(args, path, false);
    }
    for path in [
        runtime.cargo_home(),
        runtime.target_dir(),
        runtime.temporary_dir(),
        runtime.home_dir(),
    ] {
        push_bind(args, path, true);
    }
    // Keep the shared registry read-only after the writable per-execution home.
    push_bind(args, capability.source_registry_path(), false);
    if let Some(output) = output {
        push_bind(args, output.root(), true);
    }
    if let Some(helper) = package_cloudflared {
        push_bind(args, helper, false);
    }
    // Verification source is attached after this builder returns. Reserve its
    // exact destination before making the private cache scaffold read-only.
    args.push(OsString::from("--dir"));
    args.push(
        runtime
            .execution_root()
            .join("verification-source")
            .into_os_string(),
    );
    args.push(OsString::from("--remount-ro"));
    args.push(view.root().as_os_str().to_owned());
}

#[cfg(all(test, target_os = "linux"))]
#[path = "sandbox_linux/tests.rs"]
mod tests;
