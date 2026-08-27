//! Owner-approved Location discovery and explicit Workspace resolution.

mod confinement;
mod diff_artifact;
mod discovery;
mod git_safety;
mod harness;
mod service;
mod state_layout;

pub use confinement::{
    AppliedFileMutation, CapturedDiffSource, ConfinedFileRead, ConfinedFilesystemError,
    ConfinedWorkspace, ConfinedWorkspaceWriteGuard, FilesystemOperation, MAX_DIFF_SOURCE_BYTES,
    MAX_FILE_PATH_COMPONENTS, MAX_FILE_READ_BYTES, MAX_FILE_WRITE_BYTES, MAX_HASHED_FILE_BYTES,
    PreparedFileMutation, bounded_write_content_hash,
};
pub use diff_artifact::{
    DIFF_REDACTION_POLICY_VERSION, DIFF_RENDERER_VERSION, DIFF_ZSTD_LEVEL,
    DiffArtifactDeleteStatus, DiffArtifactExpectation, DiffArtifactInventory,
    DiffArtifactOperation, DiffArtifactStore, DiffArtifactStoreError, DiffRenderError,
    MAX_DIFF_COMPRESSED_BYTES, MAX_DIFF_RENDERED_BYTES, MAX_DIFF_SOURCE_LINES,
    PublishedDiffArtifact, RenderedDiffEvidence, RenderedTextDiff, StagedDiffArtifact,
    diff_path_label, render_diff_evidence,
};
pub use discovery::{
    WorkspaceCandidate, WorkspaceCandidateKey, WorkspaceCandidateKind, WorkspaceDiscovery,
    WorkspaceDiscoveryError, WorkspaceKeyResolveError, WorkspaceLocator, WorkspaceLocatorError,
    WorkspaceResolveError, WorkspaceSelector, WorkspaceSelectorError, WorkspaceSignals,
};
pub use git_safety::{
    CheckpointSide, GIT_CHECKPOINT_MAX_FILE_BYTES, GIT_CHECKPOINT_MAX_OUTPUT_BYTES,
    GIT_CHECKPOINT_OBJECT_VERIFY_MAX, GIT_CHECKPOINT_REF_INVENTORY_MAX, GIT_CHECKPOINT_REF_PREFIX,
    GitCheckpointAdapter, GitCheckpointObjectExpectation, GitCheckpointObjectVerification,
    GitCheckpointObjectVerificationStatus, GitCheckpointRefInventory,
    GitCheckpointRefInventoryEntry, GitCheckpointRefInventoryLimit, GitCheckpointStore,
    GitCheckpointStoreIntegrity, GitRetainedSnapshot, GitSafetyError,
};
pub use harness::{
    HARNESS_MANAGED_STATE_PATH, HARNESS_MANIFEST_FILE_NAME, HarnessBundleInspectionError,
    HarnessInstallPreview, HarnessManagedAsset, HarnessMaterializationError,
    HarnessMaterializationReceipt, HarnessPreviewDisposition, HarnessPreviewError,
    HarnessPreviewItem, HarnessPreviewKind, HarnessVerifierProgramError, HarnessVerifierSpec,
    InspectedHarnessBundle, MAX_HARNESS_MANAGED_FILE_BYTES, inspect_harness_bundle,
    materialize_harness_install, preview_harness_install, resolve_harness_verifier_program,
};
pub use service::{
    BoxedRepositoryError, LocationRepository, LocationRepositoryError, LocationService,
    LocationServiceError,
};
pub use state_layout::{
    ExistingWorkspaceStateLayout, GitLocalState, GitLocalStateDoctor, StateLayoutError,
    WorkspaceStateLayout,
};
