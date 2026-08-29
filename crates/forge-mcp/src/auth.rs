//! Owned local MCP token bootstrap for application consumers.
//!
//! The executable and the desktop composition layer must use the same
//! pepper/catalog policy.  Keeping that policy here prevents either caller
//! from accidentally creating a second token authority or bypassing the
//! recovery check for a missing Keychain pepper.

use forge_control::{
    McpTokenClient, McpTokenClientError, McpTokenIssueRequest, McpTokenIssued, McpTokenMetadata,
    McpTokenRotation, McpTokenService, McpTokenWorker, McpTokenWorkerError,
};
use forge_domain::{McpTokenId, McpTokenRevision, TimestampMillis};
use forge_persistence::McpTokenCatalog;
use forge_platform::{AppPaths, MacOsMcpTokenPepperStore, McpTokenPepper};
use thiserror::Error;

/// Persistence bootstrap policy for the app-global token authority.
///
/// Initializing an empty authority creates the catalog and Keychain pepper,
/// but it does not issue a bearer token or grant Workspace access.  With no
/// active token, the HTTP transport remains reachable only to return an
/// authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTokenBootstrapMode {
    /// Require an already initialized catalog and its existing pepper.
    ExistingAuthority,
    /// Permit explicit creation of an empty catalog and pepper.
    InitializeAuthority,
}

impl McpTokenBootstrapMode {
    const fn permits_initialization(self) -> bool {
        matches!(self, Self::InitializeAuthority)
    }
}

/// Public owner of the app-global MCP token worker.
///
/// The worker owns the `SQLite` catalog and the control service owns the
/// in-memory pepper.  Callers retain only a bounded cloneable client and must
/// call [`Self::shutdown`] when their component lifecycle ends.  `Drop` on
/// the underlying worker is a synchronous safety net for error paths.
#[must_use]
#[derive(Debug)]
pub struct McpTokenRuntime {
    client: McpTokenClient,
    worker: Option<McpTokenWorker<McpTokenCatalog>>,
}

impl McpTokenRuntime {
    /// Start the app-global token worker using the canonical bootstrap policy.
    ///
    /// A missing catalog is allowed only for explicit authority
    /// initialization.  A missing pepper with existing records is always a
    /// recovery error; the runtime never fabricates a replacement authority
    /// in that case.
    pub fn start(
        paths: &AppPaths,
        mode: McpTokenBootstrapMode,
    ) -> Result<Self, McpTokenRuntimeError> {
        let catalog_path = paths.mcp_token_catalog_path();
        if !mode.permits_initialization() && !catalog_path.is_file() {
            return Err(McpTokenRuntimeError::NotConfigured);
        }
        let catalog =
            McpTokenCatalog::open(&catalog_path).map_err(McpTokenRuntimeError::Catalog)?;
        let has_records = !catalog
            .list(1)
            .map_err(McpTokenRuntimeError::Catalog)?
            .is_empty();
        let store = MacOsMcpTokenPepperStore;
        let pepper = match store.load().map_err(McpTokenRuntimeError::Pepper)? {
            Some(pepper) => pepper,
            None if mode.permits_initialization() && !has_records => {
                let mut bytes = [0_u8; forge_domain::MCP_TOKEN_DIGEST_BYTES];
                getrandom::fill(&mut bytes).map_err(McpTokenRuntimeError::PepperRandomness)?;
                let candidate = McpTokenPepper::new(bytes);
                store
                    .store_if_absent(&candidate)
                    .map_err(McpTokenRuntimeError::Pepper)?;
                store
                    .load()
                    .map_err(McpTokenRuntimeError::Pepper)?
                    .ok_or(McpTokenRuntimeError::PepperWriteUnconfirmed)?
            }
            None => return Err(McpTokenRuntimeError::PepperRecoveryRequired),
        };
        let (client, worker) =
            McpTokenWorker::start(McpTokenService::new(pepper.into_bytes(), catalog))
                .map_err(McpTokenRuntimeError::Worker)?;
        Ok(Self {
            client,
            worker: Some(worker),
        })
    }

    /// Assemble an owner from an already-started worker.
    ///
    /// This is crate-visible so transport tests and other forge-mcp modules
    /// can exercise lifecycle ownership with an isolated catalog.  Production
    /// callers should use [`Self::start`] so the Keychain/catalog bootstrap
    /// policy remains centralized.
    #[cfg(test)]
    pub(crate) fn from_parts(
        client: McpTokenClient,
        worker: McpTokenWorker<McpTokenCatalog>,
    ) -> Self {
        Self {
            client,
            worker: Some(worker),
        }
    }

    /// Return a bounded cloneable client for token issue/authentication and
    /// lifecycle operations.
    pub fn client(&self) -> McpTokenClient {
        self.client.clone()
    }

    /// Issue a token through the owned worker.
    pub fn issue(
        &self,
        request: McpTokenIssueRequest,
    ) -> Result<McpTokenIssued, McpTokenClientError> {
        self.client.issue(request)
    }

    /// Rotate a token through the owned worker.
    pub fn rotate(
        &self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        rotated_at: TimestampMillis,
    ) -> Result<McpTokenRotation, McpTokenClientError> {
        self.client.rotate(id, expected_revision, rotated_at)
    }

    /// Revoke a token through the owned worker.
    pub fn revoke(
        &self,
        id: McpTokenId,
        expected_revision: McpTokenRevision,
        disabled_at: TimestampMillis,
    ) -> Result<McpTokenMetadata, McpTokenClientError> {
        self.client.revoke(id, expected_revision, disabled_at)
    }

    /// List non-secret token metadata through the owned worker.
    pub fn list(&self, limit: usize) -> Result<Vec<McpTokenMetadata>, McpTokenClientError> {
        self.client.list(limit)
    }

    /// Stop admission, drain the bounded worker, and join its owner thread.
    pub fn shutdown(&mut self) -> Result<(), McpTokenWorkerError> {
        self.worker
            .as_mut()
            .ok_or(McpTokenWorkerError::AlreadyShutdown)?
            .shutdown()?;
        self.worker = None;
        Ok(())
    }

    /// Whether the token worker still accepts requests.
    pub fn is_accepting(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(McpTokenWorker::is_accepting)
    }
}

impl Drop for McpTokenRuntime {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.as_mut() {
            let _ignored = worker.shutdown();
        }
        self.worker = None;
    }
}

/// Failure while bootstrapping the shared token worker.
#[derive(Debug, Error)]
pub enum McpTokenRuntimeError {
    #[error("MCP token connection is not configured")]
    NotConfigured,
    #[error("MCP token catalog failed")]
    Catalog(#[source] forge_persistence::McpTokenCatalogError),
    #[error("MCP token pepper Keychain operation failed")]
    Pepper(#[source] forge_platform::McpTokenPepperError),
    #[error("secure randomness for the MCP token pepper is unavailable")]
    PepperRandomness(#[source] getrandom::Error),
    #[error("MCP token pepper is missing while durable token records exist")]
    PepperRecoveryRequired,
    #[error("MCP token pepper write could not be confirmed")]
    PepperWriteUnconfirmed,
    #[error("MCP token worker lifecycle failed")]
    Worker(#[source] McpTokenWorkerError),
}

// Keep the module's ownership contract visible to compile-time consumers.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<McpTokenRuntime>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_error_does_not_expose_token_material() {
        let error = McpTokenRuntimeError::PepperRecoveryRequired;
        assert_eq!(
            error.to_string(),
            "MCP token pepper is missing while durable token records exist"
        );
    }

    #[test]
    fn worker_shutdown_error_remains_typed() {
        assert_eq!(
            McpTokenWorkerError::AlreadyShutdown.to_string(),
            "MCP token worker is already shut down"
        );
    }

    #[test]
    fn bootstrap_mode_names_empty_authority_initialization_explicitly() {
        assert!(!McpTokenBootstrapMode::ExistingAuthority.permits_initialization());
        assert!(McpTokenBootstrapMode::InitializeAuthority.permits_initialization());
    }
}
