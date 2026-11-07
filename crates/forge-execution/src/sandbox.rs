use std::fmt::{self, Write as _};
use std::path::Path;

use forge_domain::ExecutionPermissions;
use forge_workspace::ExistingWorkspaceStateLayout;
use thiserror::Error;

use crate::{
    ExecutionLaunchKind, PackageVExecutableCapability, RustCiGeneratedPackageOutput,
    RustCiToolchainCapability,
};

pub(crate) const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";
const MAX_SANDBOX_PROFILE_BYTES: usize = 32 * 1024;
const APPLE_DEVELOPER_READ_ROOTS: [&str; 2] = [
    "/Library/Developer/CommandLineTools",
    "/Applications/Xcode.app/Contents/Developer",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxBackendStatus {
    AvailableDeprecatedPrototype,
    Unavailable,
}

/// Generated Seatbelt profile passed directly to Apple's deprecated
/// `sandbox-exec` prototype. Debug never exposes paths or profile text.
#[derive(Clone, PartialEq, Eq)]
pub struct MacOsSandboxProfile {
    text: String,
}

#[derive(Clone, Copy)]
struct SandboxProfileInput<'a> {
    layout: &'a ExistingWorkspaceStateLayout,
    permissions: ExecutionPermissions,
    launch_kind: ExecutionLaunchKind,
    capability: Option<&'a RustCiToolchainCapability>,
    runtime: Option<&'a crate::RustCiRuntimePaths>,
    generated_package_output: Option<&'a RustCiGeneratedPackageOutput>,
    package_cloudflared: Option<&'a Path>,
    verification_source: Option<&'a Path>,
    package_executable: Option<&'a Path>,
}

impl fmt::Debug for MacOsSandboxProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacOsSandboxProfile")
            .field("bytes", &self.text.len())
            .finish()
    }
}

impl MacOsSandboxProfile {
    pub fn status() -> SandboxBackendStatus {
        if Path::new(SANDBOX_EXEC_PATH).is_file() {
            SandboxBackendStatus::AvailableDeprecatedPrototype
        } else {
            SandboxBackendStatus::Unavailable
        }
    }

    pub fn new(
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

    /// Build the sandbox for a trusted launch policy.  Baseline retains the
    /// historical permission projection; Rust CI uses only its validated
    /// product-cache capability and never widens Workspace writes/network.
    pub fn for_launch(
        layout: &ExistingWorkspaceStateLayout,
        permissions: ExecutionPermissions,
        launch_kind: ExecutionLaunchKind,
        capability: Option<&RustCiToolchainCapability>,
        runtime: Option<&crate::RustCiRuntimePaths>,
        generated_package_output: Option<&RustCiGeneratedPackageOutput>,
        package_cloudflared: Option<&Path>,
    ) -> Result<Self, SandboxBackendError> {
        Self::build(SandboxProfileInput {
            layout,
            permissions,
            launch_kind,
            capability,
            runtime,
            generated_package_output,
            package_cloudflared,
            verification_source: None,
            package_executable: None,
        })
    }

    /// The runner supplies only the root of its validated, retained snapshot.
    /// A verification process never receives live source or state access.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn for_verification_source(
        layout: &ExistingWorkspaceStateLayout,
        source: &Path,
        capability: &RustCiToolchainCapability,
        runtime: &crate::RustCiRuntimePaths,
    ) -> Result<Self, SandboxBackendError> {
        Self::for_verification_launch(
            layout,
            source,
            ExecutionLaunchKind::RustCi,
            capability,
            runtime,
            None,
            None,
        )
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
        validate_verification_scope(layout, source, capability, runtime)?;
        Self::build(SandboxProfileInput {
            layout,
            permissions: ExecutionPermissions::new(true, false, false),
            launch_kind,
            capability: Some(capability),
            runtime: Some(runtime),
            generated_package_output,
            package_cloudflared,
            verification_source: Some(source),
            package_executable: None,
        })
    }

    pub(crate) fn for_package_verification_launch(
        layout: &ExistingWorkspaceStateLayout,
        source: &Path,
        capability: &PackageVExecutableCapability,
    ) -> Result<Self, SandboxBackendError> {
        validate_package_verification_scope(layout, source, capability.path())?;
        Self::build(SandboxProfileInput {
            layout,
            permissions: ExecutionPermissions::new(true, false, false),
            launch_kind: ExecutionLaunchKind::Baseline,
            capability: None,
            runtime: None,
            generated_package_output: None,
            package_cloudflared: None,
            verification_source: Some(source),
            package_executable: Some(capability.path()),
        })
    }

    fn build(input: SandboxProfileInput<'_>) -> Result<Self, SandboxBackendError> {
        let SandboxProfileInput {
            layout,
            permissions,
            launch_kind,
            capability,
            runtime,
            generated_package_output,
            package_cloudflared,
            verification_source,
            package_executable,
        } = input;
        if Self::status() == SandboxBackendStatus::Unavailable {
            return Err(SandboxBackendError::Unavailable);
        }
        let workspace = scheme_path(layout.workspace_root())?;
        let state = scheme_path(layout.state_root())?;
        let mut text = String::from(
            "(version 1)\n(deny default)\n(import \"system.sb\")\n\
             (allow process-fork)\n(allow process-exec)\n\
             (allow file-read-metadata (subpath \"/\"))\n\
             (allow file-read* (subpath \"/private/etc/ssl\"))\n",
        );
        if let Some(source) = verification_source {
            let source = scheme_path(source)?;
            writeln!(&mut text, "(allow file-read* (subpath {source}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
            writeln!(&mut text, "(deny file-write* (subpath {source}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
            // Explicit exclusions also fence any broader system/toolchain
            // read rule. The sole exception is this execution's source tree.
            writeln!(
                &mut text,
                "(deny file-read-data (require-all (subpath {workspace}) (require-not (subpath {source}))))"
            )
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
            writeln!(&mut text, "(deny file-write* (subpath {workspace}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
            if let Some(executable) = package_executable {
                let executable = scheme_path(executable)?;
                writeln!(&mut text, "(allow file-read* (literal {executable}))")
                    .map_err(|_| SandboxBackendError::ProfileFormatting)?;
            }
        } else if permissions.workspace_read() || permissions.workspace_write() {
            writeln!(&mut text, "(allow file-read* (subpath {workspace}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        }
        if launch_kind == ExecutionLaunchKind::Baseline && permissions.workspace_write() {
            writeln!(&mut text, "(allow file-write* (subpath {workspace}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        }
        if verification_source.is_none() {
            writeln!(&mut text, "(deny file-read-data (subpath {state}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        }
        writeln!(&mut text, "(deny file-write* (subpath {state}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        match launch_kind {
            ExecutionLaunchKind::Baseline => {
                if package_executable.is_none()
                    && (permissions.workspace_read() || permissions.workspace_write())
                {
                    append_apple_git_runtime_rules(&mut text)?;
                }
                if package_executable.is_none() && permissions.network() {
                    text.push_str("(allow network*)\n");
                }
            }
            ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage => {
                let capability = capability.ok_or(SandboxBackendError::RustCiCapabilityRequired)?;
                let runtime = runtime.ok_or(SandboxBackendError::RustCiRuntimeRequired)?;
                let package_cloudflared =
                    if launch_kind == ExecutionLaunchKind::RustCiGeneratedPackage {
                        Some(
                            package_cloudflared
                                .ok_or(SandboxBackendError::RustCiPackageHelperRequired)?,
                        )
                    } else {
                        None
                    };
                append_rust_ci_rules(
                    &mut text,
                    capability,
                    runtime,
                    generated_package_output,
                    package_cloudflared,
                )?;
            }
        }
        if text.len() > MAX_SANDBOX_PROFILE_BYTES {
            return Err(SandboxBackendError::ProfileTooLarge {
                actual: text.len(),
                maximum: MAX_SANDBOX_PROFILE_BYTES,
            });
        }
        Ok(Self { text })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

pub(super) fn validate_verification_scope(
    layout: &ExistingWorkspaceStateLayout,
    source: &Path,
    capability: &RustCiToolchainCapability,
    runtime: &crate::RustCiRuntimePaths,
) -> Result<(), SandboxBackendError> {
    if source != runtime.execution_root().join("verification-source") {
        return Err(SandboxBackendError::VerificationSourceScope);
    }
    let workspace = layout.workspace_root();
    for root in [
        capability.view().root(),
        capability.source_rustup_path(),
        capability.source_settings_path(),
        capability.source_toolchain_path(),
        capability.source_registry_path(),
        runtime.workspace_root(),
        runtime.execution_root(),
    ]
    .into_iter()
    .chain(APPLE_DEVELOPER_READ_ROOTS.into_iter().map(Path::new))
    {
        if root.starts_with(workspace) || workspace.starts_with(root) {
            return Err(SandboxBackendError::VerificationSourceScope);
        }
    }
    Ok(())
}

pub(super) fn validate_package_verification_scope(
    layout: &ExistingWorkspaceStateLayout,
    source: &Path,
    executable: &Path,
) -> Result<(), SandboxBackendError> {
    if (source.starts_with(layout.workspace_root()) && !source.starts_with(layout.state_root()))
        || executable.starts_with(layout.workspace_root())
        || executable.starts_with(layout.state_root())
    {
        return Err(SandboxBackendError::VerificationSourceScope);
    }
    let executable_metadata = std::fs::symlink_metadata(executable)
        .map_err(|_| SandboxBackendError::VerificationSourceScope)?;
    if executable_metadata.file_type().is_symlink() || !executable_metadata.is_file() {
        return Err(SandboxBackendError::VerificationSourceScope);
    }
    Ok(())
}

fn append_rust_ci_rules(
    text: &mut String,
    capability: &RustCiToolchainCapability,
    runtime: &crate::RustCiRuntimePaths,
    generated_package_output: Option<&RustCiGeneratedPackageOutput>,
    package_cloudflared: Option<&Path>,
) -> Result<(), SandboxBackendError> {
    let view = capability.view();
    for path in [
        view.bin_dir(),
        view.rustup_home(),
        view.settings_path(),
        view.toolchain_path(),
        view.cargo_home(),
        view.registry_path(),
    ] {
        let path = scheme_path(path)?;
        writeln!(text, "(allow file-read* (subpath {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    }
    if let Some(output) = generated_package_output {
        let path = scheme_path(output.root())?;
        writeln!(text, "(allow file-read* (subpath {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        writeln!(text, "(allow file-write* (subpath {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    }
    if let Some(cloudflared) = package_cloudflared {
        let path = scheme_path(cloudflared)?;
        writeln!(text, "(allow file-read* (literal {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    }
    for path in [
        capability.source_rustup_path(),
        capability.source_settings_path(),
        capability.source_toolchain_path(),
        capability.source_registry_path(),
    ] {
        let path = scheme_path(path)?;
        writeln!(text, "(allow file-read* (subpath {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    }
    for path in APPLE_DEVELOPER_READ_ROOTS {
        let path = scheme_path(Path::new(path))?;
        writeln!(text, "(allow file-read* (subpath {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    }
    for path in [
        runtime.target_dir(),
        runtime.temporary_dir(),
        runtime.home_dir(),
    ] {
        let path = scheme_path(path)?;
        writeln!(text, "(allow file-read* (subpath {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        writeln!(text, "(allow file-write* (subpath {path}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    }
    let registry = scheme_path(view.registry_path())?;
    let runtime_cargo_home = scheme_path(runtime.cargo_home())?;
    let runtime_registry = scheme_path(&runtime.cargo_home().join("registry"))?;
    writeln!(text, "(allow file-read* (subpath {runtime_cargo_home}))")
        .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    writeln!(text, "(allow file-write* (subpath {runtime_cargo_home}))")
        .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    writeln!(text, "(deny file-write* (subpath {registry}))")
        .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    writeln!(text, "(deny file-write* (subpath {runtime_registry}))")
        .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    let source_registry = scheme_path(capability.source_registry_path())?;
    writeln!(text, "(deny file-write* (subpath {source_registry}))")
        .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    for service in [
        "com.apple.securityd",
        "com.apple.securityd.xpc",
        "com.apple.securityd.systemkeychain",
        "com.apple.SecurityAgent",
    ] {
        writeln!(text, "(deny mach-lookup (global-name \"{service}\"))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
    }
    text.push_str("(deny network*)\n");
    Ok(())
}

// Baseline Git reads need Apple's dispatch library and system Git configuration.
// Keep these fixed runtime dependencies literal-scoped: unlike Rust CI, a
// baseline shell must not gain read access to an entire developer installation.
fn append_apple_git_runtime_rules(text: &mut String) -> Result<(), SandboxBackendError> {
    for root in APPLE_DEVELOPER_READ_ROOTS {
        for relative in ["usr/lib/libxcrun.dylib", "usr/share/git-core/gitconfig"] {
            let path = scheme_path(&Path::new(root).join(relative))?;
            writeln!(text, "(allow file-read* (literal {path}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        }
    }
    Ok(())
}

fn scheme_path(path: &Path) -> Result<String, SandboxBackendError> {
    let value = path.to_str().ok_or(SandboxBackendError::NonUtf8Path)?;
    if value.chars().any(char::is_control) {
        return Err(SandboxBackendError::ControlCharacterPath);
    }
    let mut escaped = String::with_capacity(value.len().saturating_add(2));
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

#[derive(Debug, Error)]
pub enum SandboxBackendError {
    #[error("macOS sandbox-exec backend is unavailable")]
    Unavailable,
    #[error("sandbox profile path is not UTF-8")]
    NonUtf8Path,
    #[error("sandbox profile path contains a control character")]
    ControlCharacterPath,
    #[error("sandbox profile formatting failed")]
    ProfileFormatting,
    #[error("sandbox profile contains {actual} bytes; maximum is {maximum}")]
    ProfileTooLarge { actual: usize, maximum: usize },
    #[error("Rust CI launch requires a discovered toolchain capability")]
    RustCiCapabilityRequired,
    #[error("Rust CI launch requires prepared product runtime paths")]
    RustCiRuntimeRequired,
    #[error("verification source or toolchain/runtime roots overlap the Workspace authority")]
    VerificationSourceScope,
    #[error("Rust CI generated package launch requires a bundled cloudflared helper")]
    RustCiPackageHelperRequired,
    #[error("Rust CI toolchain capability is unavailable")]
    RustCiUnavailable(#[source] crate::RustCiDiscoveryError),
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::fs;
    use std::io::{self, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crate::{
        ExecutionLaunchKind, RustCiDiscoveryInput, RustCiHostArchitecture,
        RustCiToolchainCapability,
    };
    use forge_workspace::WorkspaceStateLayout;

    use super::*;

    const PACKAGE_SANDBOX_CHILD_ENV: &str = "FORGE_PACKAGE_V_SANDBOX_CHILD";
    const PACKAGE_SANDBOX_CHILD_MARKER: &str = "package-sandbox-child-v1";
    const PACKAGE_SANDBOX_SOURCE_ENV: &str = "FORGE_PACKAGE_V_SANDBOX_SOURCE";
    const PACKAGE_SANDBOX_LIVE_ENV: &str = "FORGE_PACKAGE_V_SANDBOX_LIVE";
    const PACKAGE_SANDBOX_SECRET_ENV: &str = "FORGE_PACKAGE_V_SANDBOX_SECRET";
    const PACKAGE_SANDBOX_SOCKET_ENV: &str = "FORGE_PACKAGE_V_SANDBOX_SOCKET";

    struct PackageSandboxFixture(std::path::PathBuf);

    impl Drop for PackageSandboxFixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    fn permission_denied<T>(result: io::Result<T>, operation: &str) -> io::Result<()> {
        match result {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("{operation} failed for an unexpected reason: {error}"),
            )),
            Ok(_) => Err(io::Error::other(format!(
                "{operation} was unexpectedly allowed"
            ))),
        }
    }

    fn stop_child(child: &mut std::process::Child) {
        let _ignored = child.kill();
        let _ignored = child.wait();
    }

    fn package_sandbox_child_probe() -> Result<(), Box<dyn std::error::Error>> {
        let required_path = |name| -> io::Result<std::path::PathBuf> {
            Ok(std::path::PathBuf::from(
                std::env::var_os(name).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("missing {name}"))
                })?,
            ))
        };
        let source = required_path(PACKAGE_SANDBOX_SOURCE_ENV)?;
        let live = required_path(PACKAGE_SANDBOX_LIVE_ENV)?;
        let secret = required_path(PACKAGE_SANDBOX_SECRET_ENV)?;
        assert_eq!(fs::read(&source)?, b"package-source-original\n");
        permission_denied(fs::read(&live), "live Workspace read")?;
        permission_denied(fs::read(&secret), "private state read")?;

        match fs::OpenOptions::new().write(true).open(&source) {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("source write open failed unexpectedly: {error}"),
                )
                .into());
            }
            Ok(mut file) => {
                permission_denied(file.write_all(b"package-source-tampered\n"), "source write")?;
            }
        }

        let socket: std::net::SocketAddr = std::env::var(PACKAGE_SANDBOX_SOCKET_ENV)?.parse()?;
        permission_denied(TcpStream::connect(socket), "loopback connection")?;
        println!("PACKAGE_V_SANDBOX_CHILD_OK");
        Ok(())
    }

    #[test]
    #[ignore = "requires an actual macOS Seatbelt child process"]
    #[allow(
        clippy::too_many_lines,
        reason = "The control and child denial assertions form one ordered sandbox proof."
    )]
    fn package_verification_sandbox_denies_out_of_scope_access()
    -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var(PACKAGE_SANDBOX_CHILD_ENV).as_deref() == Ok(PACKAGE_SANDBOX_CHILD_MARKER) {
            package_sandbox_child_probe()?;
            return Ok(());
        }

        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let temp_base = configured_tempdir()?;
        let root = temp_base.join(format!("forge-package-sandbox-{unique}"));
        fs::create_dir(&root)?;
        let fixture = PackageSandboxFixture(root.clone());
        let workspace_root = root.join("workspace");
        fs::create_dir(&workspace_root)?;
        WorkspaceStateLayout::initialize(&workspace_root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
            .ok_or("workspace state layout missing")?;
        let source_root = layout
            .state_root()
            .join("artifacts/verification/package-sandbox/source");
        fs::create_dir_all(&source_root)?;
        let source = source_root.join("input.txt");
        let live = workspace_root.join("live.txt");
        let secret = layout.state_root().join("private-secret.txt");
        fs::write(&source, b"package-source-original\n")?;
        fs::write(&live, b"live-workspace-secret\n")?;
        fs::write(&secret, b"private-state-secret\n")?;

        fs::write(&source, b"unsandboxed-control-write\n")?;
        assert_eq!(fs::read(&source)?, b"unsandboxed-control-write\n");
        fs::write(&source, b"package-source-original\n")?;
        assert_eq!(fs::read(&live)?, b"live-workspace-secret\n");
        assert_eq!(fs::read(&secret)?, b"private-state-secret\n");
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let socket = listener.local_addr()?;
        let control = TcpStream::connect(socket)?;
        let control_deadline = Instant::now() + Duration::from_secs(2);
        let (accepted, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= control_deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "unsandboxed loopback control connection was not accepted",
                        )
                        .into());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        };
        drop((control, accepted));

        let executable = root.join("package-sandbox-test-executable");
        fs::copy(std::env::current_exe()?, &executable)?;
        let mut permissions = fs::metadata(&executable)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions)?;
        let capability = PackageVExecutableCapability::prepare_at(&executable)?;
        let profile = MacOsSandboxProfile::for_package_verification_launch(
            &layout,
            &source_root,
            &capability,
        )?;
        let test_name = "sandbox::tests::package_verification_sandbox_denies_out_of_scope_access";
        let mut child = Command::new(SANDBOX_EXEC_PATH)
            .args(["-p", profile.as_str()])
            .arg(&executable)
            .args(["--ignored", "--exact", test_name, "--nocapture"])
            .current_dir(&source_root)
            .env_clear()
            .env("TMPDIR", &temp_base)
            .env(PACKAGE_SANDBOX_CHILD_ENV, PACKAGE_SANDBOX_CHILD_MARKER)
            .env(PACKAGE_SANDBOX_SOURCE_ENV, &source)
            .env(PACKAGE_SANDBOX_LIVE_ENV, &live)
            .env(PACKAGE_SANDBOX_SECRET_ENV, &secret)
            .env(PACKAGE_SANDBOX_SOCKET_ENV, socket.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut connected = false;
        let status = loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    connected = true;
                    drop(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    stop_child(&mut child);
                    return Err(error.into());
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    stop_child(&mut child);
                    return Err(error.into());
                }
            }
            if Instant::now() >= deadline {
                let _ignored = child.kill();
                let output = child.wait_with_output()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("PackageV sandbox child timed out: {output:?}"),
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        };
        let output = child.wait_with_output()?;
        assert!(status.success(), "sandbox child failed: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("PACKAGE_V_SANDBOX_CHILD_OK"),
            "sandbox child did not report its denial checks: {output:?}"
        );
        assert!(
            !connected,
            "sandbox child connected to the loopback listener"
        );
        assert_eq!(fs::read(&source)?, b"package-source-original\n");
        assert_eq!(fs::read(&live)?, b"live-workspace-secret\n");
        assert_eq!(fs::read(&secret)?, b"private-state-secret\n");
        drop(listener);
        drop(fixture);
        Ok(())
    }

    fn configured_tempdir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let configured = std::env::var_os("TMPDIR").ok_or("TMPDIR must be configured")?;
        let configured = std::path::PathBuf::from(configured);
        if !configured.is_absolute() {
            return Err("TMPDIR must be absolute".into());
        }
        let canonical = fs::canonicalize(&configured)?;
        if canonical != configured || !canonical.is_dir() {
            return Err("TMPDIR must be an existing canonical directory".into());
        }
        Ok(canonical)
    }

    #[test]
    fn package_verification_scope_accepts_configured_storage_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = configured_tempdir()?.join(format!("forge-package-scope-{unique}"));
        fs::create_dir(&root)?;
        let workspace_root = root.join("workspace");
        fs::create_dir(&workspace_root)?;
        WorkspaceStateLayout::initialize(&workspace_root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
            .ok_or("workspace state layout missing")?;
        let source = layout
            .state_root()
            .join("artifacts/verification/package-v/source");
        fs::create_dir_all(&source)?;
        let executable = root.join("package-v-backend");
        fs::write(&executable, b"backend")?;
        let mut permissions = fs::metadata(&executable)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions)?;

        validate_package_verification_scope(&layout, &source, &executable)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn profile_is_bounded_redacted_and_network_is_explicit()
    -> Result<(), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-sandbox-profile-{unique}"));
        fs::create_dir_all(&root)?;
        WorkspaceStateLayout::initialize(&root)?;
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let denied =
            MacOsSandboxProfile::new(&layout, ExecutionPermissions::new(true, true, false))?;
        assert!(!denied.as_str().contains("(allow network*)"));
        assert!(denied.as_str().contains("(deny file-write*"));
        assert!(!format!("{denied:?}").contains(root.to_string_lossy().as_ref()));
        for developer in APPLE_DEVELOPER_READ_ROOTS {
            for relative in ["usr/lib/libxcrun.dylib", "usr/share/git-core/gitconfig"] {
                assert!(denied.as_str().contains(&format!(
                    "(allow file-read* (literal \"{developer}/{relative}\"))"
                )));
                assert!(!denied.as_str().contains(&format!(
                    "(allow file-write* (literal \"{developer}/{relative}\"))"
                )));
            }
            assert!(
                !denied
                    .as_str()
                    .contains(&format!("(allow file-read* (subpath \"{developer}\"))"))
            );
            assert!(
                !denied
                    .as_str()
                    .contains(&format!("(allow file-write* (subpath \"{developer}\"))"))
            );
        }
        let state = scheme_path(layout.state_root())?;
        assert!(
            denied
                .as_str()
                .contains(&format!("(deny file-read-data (subpath {state}))"))
        );
        assert!(denied.as_str().len() <= MAX_SANDBOX_PROFILE_BYTES);
        let allowed =
            MacOsSandboxProfile::new(&layout, ExecutionPermissions::new(true, false, true))?;
        assert!(allowed.as_str().contains("(allow network*)"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn rust_ci_profile_is_read_only_for_workspace_and_uses_exact_capability_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root =
            fs::canonicalize(std::env::temp_dir().join(format!("forge-rust-ci-sandbox-{unique}")))
                .or_else(|_| {
                    let raw = std::env::temp_dir().join(format!("forge-rust-ci-sandbox-{unique}"));
                    fs::create_dir_all(&raw)?;
                    fs::canonicalize(raw)
                })?;
        fs::create_dir_all(&root)?;
        let workspace_root = root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        WorkspaceStateLayout::initialize(&workspace_root)?;
        let layout =
            WorkspaceStateLayout::inspect_existing(&workspace_root)?.ok_or("layout missing")?;

        let host = root.join("host-home");
        fs::create_dir_all(host.join(".cargo/bin"))?;
        fs::create_dir_all(host.join(".cargo/registry"))?;
        fs::create_dir_all(host.join(format!(
            ".rustup/toolchains/{}-aarch64-apple-darwin",
            crate::rust_ci::RUST_CI_PINNED_VERSION
        )))?;
        fs::write(host.join(".cargo/bin/rustup"), b"rustup")?;
        fs::write(host.join(".rustup/settings.toml"), b"version = 12\n")?;
        let host = fs::canonicalize(host)?;
        let cache = root.join("cache/rust-ci");
        fs::create_dir_all(cache.parent().ok_or("missing cache parent")?)?;
        let input = RustCiDiscoveryInput::new(
            host,
            cache,
            RustCiHostArchitecture::Aarch64,
            forge_domain::RuntimeInstanceId::from_uuid(uuid::Uuid::from_u128(0x5301)),
        )?;
        let capability = RustCiToolchainCapability::prepare(&input)?;
        let runtime = capability.ensure_runtime_paths(
            forge_domain::WorkspaceId::from_uuid(uuid::Uuid::from_u128(1)),
            forge_domain::WorkspaceRootFingerprint::from_bytes([1; 16]),
            forge_domain::ExecutionId::from_uuid(uuid::Uuid::from_u128(2)),
        )?;
        let profile = MacOsSandboxProfile::for_launch(
            &layout,
            ExecutionPermissions::new(true, true, true),
            ExecutionLaunchKind::RustCi,
            Some(&capability),
            Some(&runtime),
            None,
            None,
        )?;
        let text = profile.as_str();
        assert!(text.contains(&format!(
            "(allow file-read* (subpath \"{}\"))",
            capability.view().toolchain_path().display()
        )));
        assert!(text.contains(&format!(
            "(allow file-read* (subpath \"{}\"))",
            capability.view().registry_path().display()
        )));
        for path in APPLE_DEVELOPER_READ_ROOTS {
            assert!(text.contains(&format!("(allow file-read* (subpath \"{path}\"))")));
        }
        for path in [
            runtime.target_dir(),
            runtime.temporary_dir(),
            runtime.home_dir(),
            runtime.cargo_home(),
        ] {
            assert!(text.contains(&format!(
                "(allow file-read* (subpath \"{}\"))",
                path.display()
            )));
            assert!(text.contains(&format!(
                "(allow file-write* (subpath \"{}\"))",
                path.display()
            )));
        }
        assert!(!text.contains("(allow file-read-data (literal"));
        assert!(!text.contains(&format!(
            "(allow file-write* (subpath \"{}\"))",
            workspace_root.display()
        )));
        assert!(text.contains("(deny network*)"));
        assert!(!text.contains(".cargo/config"));
        assert!(!text.contains(".cargo/credentials"));
        assert!(!format!("{profile:?}").contains("host-home"));
        assert_verification_source_isolation(&layout, &capability, &runtime)?;
        runtime.cleanup()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn assert_verification_source_isolation(
        layout: &ExistingWorkspaceStateLayout,
        capability: &RustCiToolchainCapability,
        runtime: &crate::RustCiRuntimePaths,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The outer command already carries a Seatbelt sandbox; Apple's
        // prototype cannot create another one inside it.
        if std::env::var(crate::RUST_CI_SANDBOX_MARKER_ENV).as_deref()
            == Ok(crate::RUST_CI_SANDBOX_MARKER_VALUE)
            && std::env::var("HETERARCHY_FORGE_RUST_CI_TEST_POLICY").as_deref()
                == Ok("outer-rust-ci-v1")
        {
            return Ok(());
        }
        let source = runtime.execution_root().join("verification-source");
        fs::create_dir_all(&source)?;
        fs::write(source.join("input.txt"), b"frozen")?;
        let live = layout.workspace_root().join("input.txt");
        fs::write(&live, b"live")?;
        let state = layout.state_root().join("private-state");
        fs::write(&state, b"private")?;
        let sibling = layout
            .state_root()
            .join("artifacts/verification/other/source");
        fs::create_dir_all(&sibling)?;
        fs::write(sibling.join("input.txt"), b"other")?;
        let source_sibling = source.with_file_name("source-sibling");
        fs::create_dir(&source_sibling)?;
        fs::write(source_sibling.join("input.txt"), b"sibling")?;
        for invalid in [layout.workspace_root(), layout.state_root()] {
            assert!(matches!(
                MacOsSandboxProfile::for_verification_source(layout, invalid, capability, runtime,),
                Err(SandboxBackendError::VerificationSourceScope)
            ));
        }
        let encompassing_root = layout
            .workspace_root()
            .parent()
            .ok_or("fixture parent missing")?;
        WorkspaceStateLayout::initialize(encompassing_root)?;
        let encompassing = WorkspaceStateLayout::inspect_existing(encompassing_root)?
            .ok_or("encompassing layout missing")?;
        let overlapping_source = encompassing
            .state_root()
            .join("artifacts/verification/00000000-0000-0000-0000-000000000001/source");
        assert!(matches!(
            MacOsSandboxProfile::for_verification_source(
                &encompassing,
                &overlapping_source,
                capability,
                runtime,
            ),
            Err(SandboxBackendError::VerificationSourceScope)
        ));
        let profile =
            MacOsSandboxProfile::for_verification_source(layout, &source, capability, runtime)?;
        let output = std::process::Command::new(SANDBOX_EXEC_PATH)
            .args(["-p", profile.as_str(), "/bin/sh", "-c"])
            .arg(
                r#"
                set -eu
                test "$(/bin/cat input.txt)" = frozen
                if /bin/cat "$1" >/dev/null 2>&1; then exit 31; fi
                if /bin/cat "$2" >/dev/null 2>&1; then exit 32; fi
                if /bin/cat "$3" >/dev/null 2>&1; then exit 33; fi
                if /bin/cat "$7" >/dev/null 2>&1; then exit 36; fi
                if (printf changed > input.txt) 2>/dev/null; then exit 34; fi
                if (printf changed > "$1") 2>/dev/null; then exit 35; fi
                printf target > "$4/probe"
                printf temporary > "$5/probe"
                printf home > "$6/probe"
                printf isolated
            "#,
            )
            .arg("verification-source-probe")
            .arg(&live)
            .arg(&state)
            .arg(sibling.join("input.txt"))
            .arg(runtime.target_dir())
            .arg(runtime.temporary_dir())
            .arg(runtime.home_dir())
            .arg(source_sibling.join("input.txt"))
            .current_dir(&source)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        assert!(
            output.status.success(),
            "snapshot sandbox probe failed: {output:?}"
        );
        assert_eq!(output.stdout, b"isolated");
        assert_eq!(fs::read(source.join("input.txt"))?, b"frozen");
        assert_eq!(fs::read(&live)?, b"live");
        assert_eq!(fs::read(&state)?, b"private");
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn generated_package_profile_writes_only_its_exact_product_output_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-generated-package-profile-{unique}"));
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        let workspace_root = root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        WorkspaceStateLayout::initialize(&workspace_root)?;
        let layout =
            WorkspaceStateLayout::inspect_existing(&workspace_root)?.ok_or("layout missing")?;
        let host = root.join("host-home");
        fs::create_dir_all(host.join(".cargo/bin"))?;
        fs::create_dir_all(host.join(".cargo/registry"))?;
        fs::create_dir_all(host.join(format!(
            ".rustup/toolchains/{}-aarch64-apple-darwin",
            crate::rust_ci::RUST_CI_PINNED_VERSION
        )))?;
        fs::write(host.join(".cargo/bin/rustup"), b"rustup")?;
        fs::write(host.join(".rustup/settings.toml"), b"version = 12\n")?;
        let cache = root.join("cache/rust-ci");
        fs::create_dir_all(cache.parent().ok_or("cache parent missing")?)?;
        let capability = RustCiToolchainCapability::prepare(&RustCiDiscoveryInput::new(
            host,
            cache,
            RustCiHostArchitecture::Aarch64,
            forge_domain::RuntimeInstanceId::from_uuid(uuid::Uuid::from_u128(0x5302)),
        )?)?;
        let workspace = forge_domain::WorkspaceId::from_uuid(uuid::Uuid::from_u128(21));
        let fingerprint = forge_domain::WorkspaceRootFingerprint::from_bytes([21; 16]);
        let execution = forge_domain::ExecutionId::from_uuid(uuid::Uuid::from_u128(22));
        let runtime = capability.ensure_runtime_paths(workspace, fingerprint, execution)?;
        let output =
            capability.ensure_generated_package_output(workspace, fingerprint, execution)?;
        let profile = MacOsSandboxProfile::for_launch(
            &layout,
            ExecutionPermissions::new(true, false, false),
            ExecutionLaunchKind::RustCiGeneratedPackage,
            Some(&capability),
            Some(&runtime),
            Some(&output),
            Some(Path::new("/private/tmp/forge-bundled-cloudflared")),
        )?;
        let text = profile.as_str();
        assert!(text.contains(&format!(
            "(allow file-write* (subpath \"{}\"))",
            output.root().display()
        )));
        assert!(
            text.contains(
                "(allow file-read* (literal \"/private/tmp/forge-bundled-cloudflared\"))"
            )
        );
        assert!(!text.contains(&format!(
            "(allow file-write* (subpath \"{}\"))",
            workspace_root.display()
        )));
        output.cleanup()?;
        runtime.cleanup()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
