use std::fmt::{self, Write as _};
use std::path::Path;

use forge_domain::ExecutionPermissions;
use forge_workspace::ExistingWorkspaceStateLayout;
use thiserror::Error;

pub(crate) const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";
const MAX_SANDBOX_PROFILE_BYTES: usize = 32 * 1024;

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
        if permissions.workspace_read() || permissions.workspace_write() {
            writeln!(&mut text, "(allow file-read* (subpath {workspace}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        }
        if permissions.workspace_write() {
            writeln!(&mut text, "(allow file-write* (subpath {workspace}))")
                .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        }
        writeln!(&mut text, "(deny file-read-data (subpath {state}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        writeln!(&mut text, "(deny file-write* (subpath {state}))")
            .map_err(|_| SandboxBackendError::ProfileFormatting)?;
        if permissions.network() {
            text.push_str("(allow network*)\n");
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
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_workspace::WorkspaceStateLayout;

    use super::*;

    #[test]
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
        let allowed =
            MacOsSandboxProfile::new(&layout, ExecutionPermissions::new(true, false, true))?;
        assert!(allowed.as_str().contains("(allow network*)"));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
