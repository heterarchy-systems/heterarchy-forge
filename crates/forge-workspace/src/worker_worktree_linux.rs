//! Linux worker-git confinement: bubblewrap wrapper generation with the
//! same invariants as the macOS Seatbelt prototype (frozen contract, `04`
//! §6 / 2c): pinned git only, read-only repository root plus exact Git
//! metadata, write access limited to the caller-declared exact paths,
//! network denied, durable state masked except for exact worker paths, and a
//! missing backend mapping to the typed fail-closed `SandboxUnavailable`.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::worker_worktree::WorkerWorktreeError;

pub(crate) const WORKER_BWRAP: &str = "/usr/bin/bwrap";

const MAX_WORKER_SANDBOX_ARG_BYTES: usize = 32 * 1024;

/// Build options for one bubblewrap invocation without serializing argv.
///
/// The returned values are options only.  The process boundary appends
/// `--` and the pinned Forge Git program exactly once at spawn time.
pub(crate) fn worker_git_bwrap_args(
    root: &Path,
    git_common_dir: &Path,
    write_paths: &[&Path],
    git_program: &str,
) -> Result<Vec<OsString>, WorkerWorktreeError> {
    super::worker_worktree::validate_write_paths(write_paths)?;
    if let Some(path) = write_paths.iter().find(|path| {
        let Ok(relative) = path.strip_prefix(root) else {
            return true;
        };
        relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    }) {
        return Err(WorkerWorktreeError::WorktreePathEscape {
            path: (*path).to_path_buf(),
        });
    }
    if !write_paths.is_empty() && !git_common_dir.starts_with(root) {
        return Err(WorkerWorktreeError::UnsupportedGitLayout);
    }
    let state_root = root.join(".heterarchy-forge");
    let mask_state_root = match fs::symlink_metadata(&state_root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(WorkerWorktreeError::SymlinkPath { path: state_root });
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(WorkerWorktreeError::UnsupportedGitLayout);
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(WorkerWorktreeError::Filesystem {
                operation: "inspect worker Git state root",
                path: state_root,
                source,
            });
        }
    };
    let mut args: Vec<OsString> = vec![
        OsString::from("--die-with-parent"),
        OsString::from("--unshare-net"),
        OsString::from("--unshare-pid"),
        OsString::from("--unshare-user"),
        OsString::from("--cap-drop"),
        OsString::from("ALL"),
        OsString::from("--disable-userns"),
        OsString::from("--proc"),
        OsString::from("/proc"),
        OsString::from("--dev"),
        OsString::from("/dev"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp"),
    ];
    // Merged-usr root plus the compatibility symlinks (a bind of a
    // symlinked path would break the dynamic loader).
    push_bind(&mut args, Path::new("/usr"), false);
    for (link, target) in [
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ] {
        args.push(OsString::from("--symlink"));
        args.push(OsString::from(target));
        args.push(OsString::from(link));
    }
    if Path::new("/etc/ssl").exists() {
        push_bind(&mut args, Path::new("/etc/ssl"), false);
    }

    // The repository bind necessarily includes Forge's durable state root.
    // Mask it with an empty read-only tmpfs before restoring only the exact
    // worker Git paths below; the SQLite authority never enters this process.
    push_bind(&mut args, root, false);
    if mask_state_root {
        args.push(OsString::from("--tmpfs"));
        args.push(state_root.as_os_str().to_os_string());
    }
    if git_common_dir != root {
        push_bind(&mut args, git_common_dir, false);
    }
    for path in write_paths {
        push_bind(&mut args, path, true);
    }
    // Parent scaffolding is created only inside the private empty mount;
    // remount its root read-only after attaching the precise child binds.
    if mask_state_root {
        args.push(OsString::from("--remount-ro"));
        args.push(state_root.as_os_str().to_os_string());
    }
    if let Some(git_dir) = Path::new(git_program).parent() {
        push_bind(&mut args, git_dir, false);
    }
    let bytes = args
        .iter()
        .map(|argument| argument.as_os_str().as_bytes().len())
        .try_fold(0usize, usize::checked_add)
        .and_then(|bytes| {
            bytes
                .checked_add(WORKER_BWRAP.len())
                .and_then(|bytes| bytes.checked_add(OsStr::new("--").as_bytes().len()))
                .and_then(|bytes| bytes.checked_add(git_program.len()))
        });
    if bytes.is_none_or(|bytes| bytes > MAX_WORKER_SANDBOX_ARG_BYTES) {
        return Err(WorkerWorktreeError::SandboxUnavailable);
    }
    Ok(args)
}

fn push_bind(args: &mut Vec<OsString>, path: &Path, writable: bool) {
    args.push(OsString::from(if writable {
        "--bind"
    } else {
        "--ro-bind"
    }));
    let path = path.as_os_str().to_os_string();
    args.push(path.clone());
    args.push(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    #[test]
    fn bwrap_options_preserve_raw_path_bytes_without_newline_serialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture_base = std::fs::canonicalize(std::env::temp_dir())?;
        let root = fixture_base.join(OsString::from_vec(b"forge-root\n\xff".to_vec()));
        let git_common_dir = root.join(".git");
        let write_path = root.join(OsString::from_vec(
            b".heterarchy-forge/worker\n\xfe".to_vec(),
        ));
        let arguments = worker_git_bwrap_args(
            &root,
            &git_common_dir,
            &[write_path.as_path()],
            "/usr/bin/git",
        )?;
        let raw_root = root.as_os_str().as_bytes();
        let raw_write_path = write_path.as_os_str().as_bytes();
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| argument.as_os_str().as_bytes() == raw_root)
                .count(),
            2,
            "read-only root bind must retain both raw path operands"
        );
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| argument.as_os_str().as_bytes() == raw_write_path)
                .count(),
            2,
            "writable path bind must retain both raw path operands"
        );
        assert!(!arguments.iter().any(|argument| {
            argument.as_os_str().as_bytes() == WORKER_BWRAP.as_bytes()
                || argument.as_os_str().as_bytes() == b"--"
        }));
        Ok(())
    }

    #[test]
    fn bwrap_options_mask_durable_state_and_keep_worker_policy_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = std::fs::canonicalize(std::env::temp_dir())?;
        let root = base.join(format!("forge-worker-linux-profile-{}", std::process::id()));
        let state_root = root.join(".heterarchy-forge");
        fs::create_dir_all(&state_root)?;
        let git_common_dir = root.join(".git");
        let write_path = root.join(".heterarchy-forge/team_teams/worker");
        let arguments = worker_git_bwrap_args(
            &root,
            &git_common_dir,
            &[write_path.as_path()],
            "/usr/bin/git",
        )?;
        let values = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for option in [
            "--unshare-net",
            "--unshare-pid",
            "--unshare-user",
            "--cap-drop",
            "ALL",
            "--disable-userns",
            "--remount-ro",
        ] {
            assert!(
                values.iter().any(|value| value == option),
                "missing {option}"
            );
        }
        let state_root = state_root.to_string_lossy().into_owned();
        let state_mount = values
            .windows(2)
            .any(|window| window[0] == "--tmpfs" && window[1] == state_root);
        assert!(
            state_mount,
            "durable state root must be masked by an empty tmpfs"
        );
        assert!(
            values
                .windows(2)
                .any(|window| { window[0] == "--remount-ro" && window[1] == state_root })
        );
        assert_eq!(
            values
                .iter()
                .filter(|value| value.as_str() == "/usr")
                .count(),
            2,
            "the merged-usr bind has no extra bare executable argument"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn external_common_dir_is_read_only_only_and_external_write_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = std::fs::canonicalize(std::env::temp_dir())?;
        let root = base.join(format!("forge-worker-linux-root-{}", std::process::id()));
        let external = base.join(format!("forge-worker-linux-common-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&external)?;
        let arguments = worker_git_bwrap_args(&root, &external, &[], "/usr/bin/git")?;
        assert!(!arguments.windows(2).any(|window| {
            window[0] == "--tmpfs"
                && window[1].as_os_str().as_bytes()
                    == root.join(".heterarchy-forge").as_os_str().as_bytes()
        }));
        let Err(error) =
            worker_git_bwrap_args(&root, &external, &[external.as_path()], "/usr/bin/git")
        else {
            return Err("an external writable path must be rejected".into());
        };
        assert!(matches!(
            error,
            WorkerWorktreeError::WorktreePathEscape { path } if path == external
        ));
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(external)?;
        Ok(())
    }
}
