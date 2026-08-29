use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use directories::BaseDirs;
use thiserror::Error;

const APP_DIRECTORY_NAME: &str = "Heterarchy Forge";
const GLOBAL_REGISTRY_FILE_NAME: &str = "registry.sqlite3";
const HARNESS_CATALOG_FILE_NAME: &str = "harness-catalog.sqlite3";
const MCP_TOKEN_CATALOG_FILE_NAME: &str = "mcp-tokens.sqlite3";
const MCP_CONNECTION_SETTINGS_CATALOG_FILE_NAME: &str = "mcp-connection-settings.sqlite3";
const SAVED_HARNESS_BUNDLES_DIRECTORY_NAME: &str = "saved-harness-bundles";
const DIAGNOSTICS_DIRECTORY_NAME: &str = "diagnostics";

/// User-writable application directories resolved according to host conventions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    application_support: PathBuf,
    cache: PathBuf,
    logs: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self, AppPathError> {
        let base = BaseDirs::new().ok_or(AppPathError::BaseDirectoriesUnavailable)?;
        let application_support = base.data_local_dir().join(APP_DIRECTORY_NAME);
        let cache = base.cache_dir().join(APP_DIRECTORY_NAME);

        #[cfg(target_os = "macos")]
        let logs = base
            .home_dir()
            .join("Library")
            .join("Logs")
            .join(APP_DIRECTORY_NAME);

        #[cfg(not(target_os = "macos"))]
        let logs = application_support.join("logs");

        Ok(Self {
            application_support,
            cache,
            logs,
        })
    }

    pub fn ensure_exists(&self) -> Result<(), AppPathError> {
        for path in [&self.application_support, &self.cache, &self.logs] {
            create_directory(path)?;
        }
        Ok(())
    }

    pub fn application_support(&self) -> &Path {
        &self.application_support
    }

    pub fn cache(&self) -> &Path {
        &self.cache
    }

    pub fn logs(&self) -> &Path {
        &self.logs
    }

    pub fn global_registry_path(&self) -> PathBuf {
        self.application_support.join(GLOBAL_REGISTRY_FILE_NAME)
    }

    pub fn harness_catalog_path(&self) -> PathBuf {
        self.application_support.join(HARNESS_CATALOG_FILE_NAME)
    }

    /// App-global local MCP bearer-token metadata catalog.
    ///
    /// Path discovery never creates the database or the corresponding
    /// Keychain pepper; explicit connection management owns those effects.
    pub fn mcp_token_catalog_path(&self) -> PathBuf {
        self.application_support.join(MCP_TOKEN_CATALOG_FILE_NAME)
    }

    /// App-global durable MCP public endpoint and local-port settings.
    ///
    /// Path discovery never creates the database; explicit connection
    /// settings management owns that durable effect.
    pub fn mcp_connection_settings_catalog_path(&self) -> PathBuf {
        self.application_support
            .join(MCP_CONNECTION_SETTINGS_CATALOG_FILE_NAME)
    }

    /// Product-owned root for explicit `Save as Bundle` compositions.
    ///
    /// Discovery/boot does not create this directory. The explicit save action
    /// owns that effect so opening FORGE cannot fabricate user compositions.
    pub fn saved_harness_bundles_dir(&self) -> PathBuf {
        self.application_support
            .join(SAVED_HARNESS_BUNDLES_DIRECTORY_NAME)
    }

    /// Product-owned directory for explicit operator diagnostics exports.
    ///
    /// Discovery/boot does not create this directory; the explicit export
    /// action owns that effect so merely opening FORGE cannot create evidence
    /// files the operator did not request.
    pub fn diagnostics_dir(&self) -> PathBuf {
        self.application_support.join(DIAGNOSTICS_DIRECTORY_NAME)
    }

    #[cfg(test)]
    fn from_roots(application_support: PathBuf, cache: PathBuf, logs: PathBuf) -> Self {
        Self {
            application_support,
            cache,
            logs,
        }
    }
}

fn create_directory(path: &Path) -> Result<(), AppPathError> {
    fs::create_dir_all(path).map_err(|source| AppPathError::CreateDirectory {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum AppPathError {
    #[error("host base directories are unavailable")]
    BaseDirectoriesUnavailable,
    #[error("failed to create application directory {path}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::AppPaths;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn ensure_exists_creates_all_application_directories() -> Result<(), Box<dyn std::error::Error>>
    {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-path-test-{}-{serial}",
            std::process::id()
        ));
        let paths =
            AppPaths::from_roots(root.join("support"), root.join("cache"), root.join("logs"));

        paths.ensure_exists()?;

        assert!(paths.application_support().is_dir());
        assert!(paths.cache().is_dir());
        assert!(paths.logs().is_dir());
        assert_eq!(
            paths.global_registry_path(),
            paths.application_support().join("registry.sqlite3")
        );
        assert_eq!(
            paths.harness_catalog_path(),
            paths.application_support().join("harness-catalog.sqlite3")
        );
        assert_eq!(
            paths.mcp_token_catalog_path(),
            paths.application_support().join("mcp-tokens.sqlite3")
        );
        assert!(!paths.mcp_token_catalog_path().exists());
        assert_eq!(
            paths.mcp_connection_settings_catalog_path(),
            paths
                .application_support()
                .join("mcp-connection-settings.sqlite3")
        );
        assert!(!paths.mcp_connection_settings_catalog_path().exists());
        assert_eq!(
            paths.saved_harness_bundles_dir(),
            paths.application_support().join("saved-harness-bundles")
        );
        assert_eq!(
            paths.diagnostics_dir(),
            paths.application_support().join("diagnostics")
        );
        assert!(!paths.diagnostics_dir().exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }
}
