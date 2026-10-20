//! Typed provenance for sealed project commands that can emit Forge-owned
//! generated artifacts.
//!
//! These values describe server-selected command semantics. They never carry
//! a program path, shell text, output directory, or caller-selected filename.

use crate::{ExecutionId, FileByteCount, FileContentHash, WorkspaceId};

/// Closed semantic class for one server-owned project command descriptor.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProjectCommandClass {
    /// A Rust verification target that reads the Workspace and produces only
    /// disposable Rust-CI runtime output.
    Verify,
    /// A local macOS installer package emitted into the Forge-owned generated
    /// output cache. It never writes the user Workspace or installs the app.
    GeneratedPackage,
}

/// Fixed-width digest of one exact discovered command catalog snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProjectCommandCatalogFingerprint(FileContentHash);

impl ProjectCommandCatalogFingerprint {
    pub const fn from_hash(value: FileContentHash) -> Self {
        Self(value)
    }

    pub const fn hash(self) -> FileContentHash {
        self.0
    }
}

/// Immutable evidence that an execution was resolved from one exact
/// server-owned project-command catalog snapshot.
///
/// The class and fingerprint are recorded together: a fingerprint without its
/// semantic class could otherwise be reinterpreted by a later command catalog.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectCommandEvidence {
    class: ProjectCommandClass,
    catalog_fingerprint: ProjectCommandCatalogFingerprint,
}

impl ProjectCommandEvidence {
    pub const fn new(
        class: ProjectCommandClass,
        catalog_fingerprint: ProjectCommandCatalogFingerprint,
    ) -> Self {
        Self {
            class,
            catalog_fingerprint,
        }
    }

    pub const fn class(self) -> ProjectCommandClass {
        self.class
    }

    pub const fn catalog_fingerprint(self) -> ProjectCommandCatalogFingerprint {
        self.catalog_fingerprint
    }
}

/// The only generated artifact admitted by the initial sealed package lane.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GeneratedArtifactKind {
    MacOsInstallerPackage,
}

impl GeneratedArtifactKind {
    /// Server-owned artifact filename below an execution output directory.
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::MacOsInstallerPackage => "Heterarchy-Forge.pkg",
        }
    }
}

/// Bounded manifest for one successfully captured generated package.
///
/// The output location is intentionally absent. Storage resolves the path
/// only from this exact Workspace/execution identity below its own product
/// cache root.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GeneratedPackageManifest {
    workspace_id: WorkspaceId,
    execution_id: ExecutionId,
    kind: GeneratedArtifactKind,
    content_hash: FileContentHash,
    byte_count: FileByteCount,
}

impl GeneratedPackageManifest {
    pub const fn new(
        workspace_id: WorkspaceId,
        execution_id: ExecutionId,
        content_hash: FileContentHash,
        byte_count: FileByteCount,
    ) -> Self {
        Self {
            workspace_id,
            execution_id,
            kind: GeneratedArtifactKind::MacOsInstallerPackage,
            content_hash,
            byte_count,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn kind(self) -> GeneratedArtifactKind {
        self.kind
    }

    pub const fn content_hash(self) -> FileContentHash {
        self.content_hash
    }

    pub const fn byte_count(self) -> FileByteCount {
        self.byte_count
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    fn generated_manifest_exposes_no_raw_path() {
        let manifest = GeneratedPackageManifest::new(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            ExecutionId::from_uuid(Uuid::from_u128(2)),
            FileContentHash::from_bytes([3; FileContentHash::BYTE_LEN]),
            FileByteCount::new(4),
        );
        assert_eq!(manifest.kind().file_name(), "Heterarchy-Forge.pkg");
        assert_eq!(manifest.byte_count().get(), 4);
    }
}
