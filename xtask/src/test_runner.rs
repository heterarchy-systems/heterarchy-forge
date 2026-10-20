use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

pub(super) const COMMAND: &str = "test-runner";

const FORGE_VERIFY_TMPDIR: &str = "FORGE_VERIFY_TMPDIR";
const FORGE_PACKAGE_V_WORKSPACE_ROOT: &str = "FORGE_PACKAGE_V_WORKSPACE_ROOT";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const COPY_BUFFER_SIZE: usize = 16 * 1024;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0x20000;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const O_NOFOLLOW: i32 = 0x0100;

static NEXT_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

pub(super) fn cargo_runner_config(root: &Path) -> Result<String, String> {
    let host = rustc_host_target(root)?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot resolve the xtask executable: {error}"))?;
    let executable = fs::canonicalize(&executable)
        .map_err(|error| format!("cannot resolve the xtask executable path: {error}"))?;
    cargo_runner_config_for(&host, &executable)
}

fn rustc_host_target(root: &Path) -> Result<String, String> {
    let output = super::capture_process(
        Path::new("rustup"),
        &["run", super::MSRV_TOOLCHAIN, "rustc", "-vV"],
        root,
        super::MAX_TOOL_VERSION_OUTPUT_BYTES,
    )?;
    if !output.status.success()
        || output.stdout_total > super::MAX_TOOL_VERSION_OUTPUT_BYTES
        || output.stderr_total > super::MAX_TOOL_VERSION_OUTPUT_BYTES
    {
        return Err(format!(
            "pinned rustc -vV failed with status {}",
            output.status
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host:"))
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "pinned rustc -vV did not report a host target".to_owned())
}

fn cargo_runner_config_for(host: &str, executable: &Path) -> Result<String, String> {
    if !executable.is_absolute() {
        return Err("xtask test runner executable must be an absolute path".to_owned());
    }
    let executable = executable
        .to_str()
        .ok_or_else(|| "xtask test runner executable path must be valid UTF-8".to_owned())?;
    let runner = toml::Value::Array(vec![
        toml::Value::String(executable.to_owned()),
        toml::Value::String(COMMAND.to_owned()),
    ]);
    Ok(format!(
        "target.{}.runner={runner}",
        toml::Value::String(host.to_owned())
    ))
}

pub(super) fn validate_internal_directory(directory: &Path) -> Result<PathBuf, String> {
    if !directory.is_absolute() {
        return Err(format!(
            "{FORGE_VERIFY_TMPDIR} must be an absolute existing internal directory"
        ));
    }
    if is_external_volume_path(directory) {
        return Err(format!(
            "{FORGE_VERIFY_TMPDIR} must be on an internal filesystem outside /Volumes"
        ));
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot inspect {FORGE_VERIFY_TMPDIR}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{FORGE_VERIFY_TMPDIR} must be a real directory, not a file or symlink"
        ));
    }
    let canonical = fs::canonicalize(directory)
        .map_err(|error| format!("cannot resolve {FORGE_VERIFY_TMPDIR}: {error}"))?;
    if is_external_volume_path(&canonical) {
        return Err(format!(
            "{FORGE_VERIFY_TMPDIR} must be on an internal filesystem outside /Volumes"
        ));
    }
    Ok(canonical)
}

fn is_external_volume_path(path: &Path) -> bool {
    path.starts_with(Path::new("/Volumes"))
}

fn runner_temporary_base() -> Result<PathBuf, String> {
    let directory =
        env::var_os(FORGE_VERIFY_TMPDIR).map_or_else(default_temporary_directory, PathBuf::from);
    validate_internal_directory(&directory)
}

fn default_temporary_directory() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/private/tmp")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        env::temp_dir()
    }
}

pub(super) fn run(arguments: impl Iterator<Item = OsString>) -> ! {
    let mut arguments = arguments;
    let Some(executable) = arguments.next() else {
        eprintln!("cargo xtask test-runner: missing test executable");
        std::process::exit(2);
    };
    let arguments: Vec<_> = arguments.collect();
    let base = match runner_temporary_base() {
        Ok(base) => base,
        Err(error) => {
            eprintln!("cargo xtask test-runner: {error}");
            std::process::exit(1);
        }
    };
    match run_child(Path::new(&executable), &arguments, &base) {
        Ok(status) => propagate_status(status),
        Err(error) => {
            eprintln!("cargo xtask test-runner: {error}");
            std::process::exit(1);
        }
    }
}

fn run_child(executable: &Path, arguments: &[OsString], base: &Path) -> Result<ExitStatus, String> {
    let mut sandbox = TestRunnerSandbox::create(executable, base)?;
    let status = sandbox.command(arguments).status();
    let cleanup = sandbox.cleanup();
    let status = status.map_err(|error| format!("cannot start copied test executable: {error}"))?;
    cleanup?;
    Ok(status)
}

fn propagate_status(status: ExitStatus) -> ! {
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    if let Some(signal) = status.signal() {
        let signal_argument = format!("-{signal}");
        let process_id = std::process::id().to_string();
        if Command::new("/bin/kill")
            .args([signal_argument.as_str(), process_id.as_str()])
            .status()
            .is_ok_and(|kill_status| kill_status.success())
        {
            // A default-handled signal terminates this process before this fallback.
            std::process::exit(128 + signal);
        }
        eprintln!("cargo xtask test-runner: could not propagate signal {signal}");
    }
    std::process::exit(1)
}

struct TestRunnerSandbox {
    root: PrivateDirectory,
    executable: PathBuf,
    workspace_root: PathBuf,
    temporary_directory: PathBuf,
}

impl TestRunnerSandbox {
    fn create(executable: &Path, base: &Path) -> Result<Self, String> {
        let base = validate_internal_directory(base)?;
        let root = PrivateDirectory::create(&base, "heterarchy-forge-test-runner")?;
        let workspace_root = root.path.join("workspace");
        create_private_child_directory(&workspace_root)?;
        let temporary_directory = root.path.join("tmp");
        create_private_child_directory(&temporary_directory)?;
        let copied_executable = root.path.join("test-executable");
        copy_test_executable(executable, &copied_executable)?;
        Ok(Self {
            root,
            executable: copied_executable,
            workspace_root,
            temporary_directory,
        })
    }

    fn command(&self, arguments: &[OsString]) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .args(arguments)
            .env(FORGE_PACKAGE_V_WORKSPACE_ROOT, &self.workspace_root)
            .env("TMPDIR", &self.temporary_directory);
        command
    }

    fn cleanup(&mut self) -> Result<(), String> {
        self.root.cleanup()
    }
}

struct PrivateDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
    cleaned: bool,
}

impl PrivateDirectory {
    fn create(base: &Path, prefix: &str) -> Result<Self, String> {
        for _ in 0..128 {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("{prefix}-{}-{id}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            match builder.create(&path) {
                Ok(()) => {
                    let metadata = match fs::symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            let _ = fs::remove_dir(&path);
                            return Err(format!("cannot inspect private test directory: {error}"));
                        }
                    };
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        let _ = fs::remove_dir(&path);
                        return Err("private test directory identity is invalid".to_owned());
                    }
                    let directory = Self {
                        path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        cleaned: false,
                    };
                    fs::set_permissions(
                        &directory.path,
                        fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
                    )
                    .map_err(|error| format!("cannot secure private test directory: {error}"))?;
                    let canonical = fs::canonicalize(&directory.path).map_err(|error| {
                        format!("cannot resolve private test directory: {error}")
                    })?;
                    if canonical != directory.path {
                        return Err("private test directory identity is invalid".to_owned());
                    }
                    return Ok(directory);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!("cannot create private test directory: {error}"));
                }
            }
        }
        Err("cannot allocate a unique private test directory".to_owned())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.cleaned = true;
                return Ok(());
            }
            Err(error) => return Err(format!("cannot inspect private test directory: {error}")),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err("private test directory changed identity; refusing cleanup".to_owned());
        }
        fs::remove_dir_all(&self.path)
            .map_err(|error| format!("cannot remove private test directory: {error}"))?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("cargo xtask test-runner: {error}");
        }
    }
}

fn create_private_child_directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(PRIVATE_DIRECTORY_MODE);
    builder
        .create(path)
        .map_err(|error| format!("cannot create private test directory: {error}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
        .map_err(|error| format!("cannot secure private test directory: {error}"))
}

fn copy_test_executable(source: &Path, destination: &Path) -> Result<(), String> {
    let before = fs::symlink_metadata(source).map_err(|error| {
        format!(
            "cannot inspect test executable {}: {error}",
            source.display()
        )
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err("test executable must be a regular non-symlink file".to_owned());
    }
    let mut source_file = open_read_no_follow(source)?;
    let source_metadata = source_file
        .metadata()
        .map_err(|error| format!("cannot inspect opened test executable: {error}"))?;
    validate_executable_metadata(&source_metadata)?;
    if before.dev() != source_metadata.dev() || before.ino() != source_metadata.ino() {
        return Err("test executable changed identity while opening".to_owned());
    }

    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_DIRECTORY_MODE)
        .open(destination)
        .map_err(|error| format!("cannot create private test executable copy: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = source_file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read test executable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        destination_file
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot copy test executable: {error}"))?;
    }
    destination_file
        .flush()
        .map_err(|error| format!("cannot finish test executable copy: {error}"))?;
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
    )
    .map_err(|error| format!("cannot secure copied test executable: {error}"))?;
    drop(destination_file);

    let mut copied_file = open_read_no_follow(destination)?;
    validate_private_copy_metadata(
        &copied_file
            .metadata()
            .map_err(|error| format!("cannot inspect copied test executable: {error}"))?,
    )?;
    let copied_digest = hash_file(&mut copied_file)?;
    if digest.finalize().as_slice() != copied_digest {
        return Err("copied test executable SHA-256 does not match its source".to_owned());
    }
    Ok(())
}

fn validate_executable_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err("test executable must be a regular file with an execute bit".to_owned());
    }
    Ok(())
}

fn validate_private_copy_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    validate_executable_metadata(metadata)?;
    if metadata.nlink() != 1 {
        return Err("private test executable copy must have exactly one link".to_owned());
    }
    Ok(())
}

fn open_read_no_follow(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            format!(
                "cannot open {} without following symlinks: {error}",
                path.display()
            )
        })
}

fn hash_file(file: &mut File) -> Result<[u8; 32], String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash copied test executable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io::Write;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;

    use super::{
        COMMAND, PrivateDirectory, TestRunnerSandbox, cargo_runner_config_for,
        is_external_volume_path, run_child,
    };

    fn scratch_directory() -> Result<PrivateDirectory, String> {
        let base = super::validate_internal_directory(&super::default_temporary_directory())?;
        PrivateDirectory::create(&base, "heterarchy-forge-test-runner-test")
    }

    fn write_executable(path: &Path, body: &[u8]) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(super::PRIVATE_DIRECTORY_MODE)
            .open(path)
            .map_err(|error| error.to_string())?;
        file.write_all(body).map_err(|error| error.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())
    }

    #[test]
    fn cargo_runner_configuration_targets_only_the_native_host_runner() -> Result<(), String> {
        let executable = Path::new("/tmp/xtask path");
        let config = cargo_runner_config_for("aarch64-apple-darwin", executable)?;
        let parsed: toml::Value = toml::from_str(&config).map_err(|error| error.to_string())?;
        assert_eq!(
            parsed["target"]["aarch64-apple-darwin"]["runner"][0].as_str(),
            Some("/tmp/xtask path")
        );
        assert_eq!(
            parsed["target"]["aarch64-apple-darwin"]["runner"][1].as_str(),
            Some(COMMAND)
        );
        assert!(parsed["target"].get("x86_64-unknown-linux-gnu").is_none());
        assert!(cargo_runner_config_for("host", Path::new("relative/xtask")).is_err());
        Ok(())
    }

    #[test]
    fn external_temp_paths_are_refused_before_filesystem_access() {
        assert!(is_external_volume_path(Path::new("/Volumes/forge-tests")));
        assert!(!is_external_volume_path(Path::new(
            "/private/tmp/forge-tests"
        )));
        assert!(super::validate_internal_directory(Path::new("/Volumes/forge-tests")).is_err());
    }

    #[test]
    fn test_executable_copy_is_byte_identical_single_link_and_private() -> Result<(), String> {
        let scratch = scratch_directory()?;
        let source = scratch.path.join("test-executable-source");
        let contents = b"#!/bin/sh\nexit 0\n";
        write_executable(&source, contents)?;

        let sandbox = TestRunnerSandbox::create(&source, &scratch.path)?;
        let copied = fs::read(&sandbox.executable).map_err(|error| error.to_string())?;
        assert_eq!(copied, contents);
        let metadata =
            fs::symlink_metadata(&sandbox.executable).map_err(|error| error.to_string())?;
        assert!(metadata.is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_ne!(
            (
                fs::metadata(&source)
                    .map_err(|error| error.to_string())?
                    .dev(),
                fs::metadata(&source)
                    .map_err(|error| error.to_string())?
                    .ino()
            ),
            (metadata.dev(), metadata.ino())
        );
        let directory = sandbox.root.path.clone();
        drop(sandbox);
        assert!(!directory.exists());
        Ok(())
    }

    #[test]
    fn runner_preserves_raw_arguments_sets_local_roots_and_cleans_after_exit() -> Result<(), String>
    {
        let scratch = scratch_directory()?;
        let source = scratch.path.join("test-executable-source");
        write_executable(
            &source,
            b"#!/bin/sh\nprintf '%s\\000' \"$@\" > \"$FORGE_TEST_ARGS_FILE\"\nprintf '%s' \"$FORGE_PACKAGE_V_WORKSPACE_ROOT\" > \"$FORGE_TEST_WORKSPACE_FILE\"\nprintf '%s' \"$TMPDIR\" > \"$FORGE_TEST_TMP_FILE\"\npwd > \"$FORGE_TEST_CWD_FILE\"\nexit 37\n",
        )?;

        let args_file = scratch.path.join("args");
        let workspace_file = scratch.path.join("workspace");
        let tmp_file = scratch.path.join("tmp");
        let cwd_file = scratch.path.join("cwd");
        let arguments = [
            OsString::from("argument with spaces"),
            OsString::from_vec(vec![
                b'r', b'a', b'w', b'-', 0xff, b'-', b'b', b'y', b't', b'e',
            ]),
        ];
        let base = scratch.path.clone();
        let mut sandbox = TestRunnerSandbox::create(&source, &base)?;
        let root = sandbox.root.path.clone();
        let workspace_root = sandbox.workspace_root.clone();
        let temporary_directory = sandbox.temporary_directory.clone();
        let original_cwd = std::env::current_dir().map_err(|error| error.to_string())?;
        let mut command = sandbox.command(&arguments);
        command
            .env("FORGE_TEST_ARGS_FILE", &args_file)
            .env("FORGE_TEST_WORKSPACE_FILE", &workspace_file)
            .env("FORGE_TEST_TMP_FILE", &tmp_file)
            .env("FORGE_TEST_CWD_FILE", &cwd_file);
        let status = command.status().map_err(|error| error.to_string())?;
        assert_eq!(status.code(), Some(37));
        assert_eq!(fs::read(&args_file).map_err(|error| error.to_string())?, {
            let mut expected = Vec::new();
            for argument in &arguments {
                expected.extend_from_slice(argument.as_os_str().as_bytes());
                expected.push(0);
            }
            expected
        });
        assert_eq!(
            fs::read_to_string(&workspace_file).map_err(|error| error.to_string())?,
            workspace_root.to_string_lossy()
        );
        assert_eq!(
            fs::read_to_string(&tmp_file).map_err(|error| error.to_string())?,
            temporary_directory.to_string_lossy()
        );
        assert_eq!(
            fs::read_to_string(&cwd_file)
                .map_err(|error| error.to_string())?
                .trim(),
            original_cwd.to_string_lossy()
        );
        assert!(workspace_root.starts_with(&root));
        assert!(temporary_directory.starts_with(&root));
        assert_eq!(
            fs::metadata(&workspace_root)
                .map_err(|error| error.to_string())?
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&temporary_directory)
                .map_err(|error| error.to_string())?
                .mode()
                & 0o777,
            0o700
        );

        sandbox.cleanup()?;
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn symlinked_sources_are_refused_and_hard_linked_sources_are_copied_independently()
    -> Result<(), String> {
        let scratch = scratch_directory()?;
        let source = scratch.path.join("test-executable-source");
        write_executable(&source, b"#!/bin/sh\nexit 0\n")?;

        let symlink_path = scratch.path.join("test-executable-symlink");
        symlink(&source, &symlink_path).map_err(|error| error.to_string())?;
        assert!(TestRunnerSandbox::create(&symlink_path, &scratch.path).is_err());

        let hard_link = scratch.path.join("test-executable-hard-link");
        fs::hard_link(&source, &hard_link).map_err(|error| error.to_string())?;
        let sandbox = TestRunnerSandbox::create(&hard_link, &scratch.path)?;
        assert_eq!(
            fs::symlink_metadata(&source)
                .map_err(|error| error.to_string())?
                .nlink(),
            2
        );
        assert_eq!(
            fs::symlink_metadata(&sandbox.executable)
                .map_err(|error| error.to_string())?
                .nlink(),
            1
        );
        Ok(())
    }

    #[test]
    fn runner_cleanup_occurs_after_a_failing_child_exit() -> Result<(), String> {
        let scratch = scratch_directory()?;
        let source = scratch.path.join("test-executable-source");
        write_executable(&source, b"#!/bin/sh\nexit 127\n")?;
        let base = scratch.path.clone();
        let status = run_child(&source, &[], &base)?;
        assert_eq!(status.code(), Some(127));
        let remaining = fs::read_dir(&scratch.path)
            .map_err(|error| error.to_string())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("heterarchy-forge-test-runner-")
            })
            .count();
        assert_eq!(remaining, 0);
        Ok(())
    }

    #[test]
    fn runner_preserves_a_child_signal_status_and_cleans_its_directory() -> Result<(), String> {
        let scratch = scratch_directory()?;
        let source = scratch.path.join("test-executable-source");
        write_executable(&source, b"#!/bin/sh\nkill -TERM $$\nexit 1\n")?;
        let status = run_child(&source, &[], &scratch.path)?;
        assert_eq!(status.code(), None);
        assert_eq!(status.signal(), Some(15));
        let remaining = fs::read_dir(&scratch.path)
            .map_err(|error| error.to_string())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("heterarchy-forge-test-runner-")
            })
            .count();
        assert_eq!(remaining, 0);
        Ok(())
    }
}
