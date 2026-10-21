//! Owner-approved Location discovery and explicit Workspace resolution.

mod confinement;
mod diff_artifact;
mod discovery;
mod git_safety;
mod patch_review;
mod service;
mod state_gate;
mod state_layout;

pub use git_safety::worker_worktree::{
    WorkerDirtyEntry, WorkerSourceInspection, WorkerTeamName, WorkerWorktreeAdapter,
    WorkerWorktreeError, WorkerWorktreeInspection, WorkerWorktreeOwner,
    WorkerWorktreeProvisionOutcome, WorkerWorktreeProvisionReceipt,
};

pub use confinement::{
    AppliedFileMutation, AppliedSourceTreeTransaction, CapturedDiffSource, ConfinedFileRead,
    ConfinedFilesystemError, ConfinedWorkspace, ConfinedWorkspaceWriteGuard, FilesystemOperation,
    HarnessDirectoryObservation, MAX_BINARY_IMPORT_BYTES, MAX_DIFF_SOURCE_BYTES,
    MAX_FILE_LIST_SCAN_ENTRIES, MAX_FILE_PATH_COMPONENTS, MAX_FILE_READ_BYTES,
    MAX_FILE_WRITE_BYTES, MAX_HASHED_FILE_BYTES, MAX_SOURCE_PATCH_BYTES,
    MAX_SOURCE_TREE_PAYLOAD_BYTES, MAX_TEXT_SEARCH_FILE_BYTES,
    MAX_VERIFICATION_INPUT_MANIFEST_BYTES, MAX_WORKSPACE_HARNESS_AGENTS_ROOTS,
    MAX_WORKSPACE_HARNESS_DIRECTORIES, MAX_WORKSPACE_HARNESS_DIRECTORY_SCAN_ENTRIES,
    MAX_WORKSPACE_HARNESS_PATH_BYTES, MAX_WORKSPACE_HARNESS_PATH_COMPONENTS,
    MAX_WORKSPACE_HARNESS_SCAN_ENTRIES, MAX_WORKSPACE_HARNESS_TREE_ENTRIES, PreparedFileMutation,
    PreparedSourcePatch, PreparedSourceTreeTransaction, PublishedVerificationInput,
    SourceTreeApplyError, SourceTreeMutationPayload, SourceTreePayloadSet, StagedVerificationInput,
    TreeMutationObservation, VerificationInputError, WorkspaceHarnessObservation,
    WorkspaceHarnessObservationError, WorkspaceHarnessTree, WorkspaceHarnessTreeEntry,
    WorkspaceStateRemoval, bounded_binary_content_hash, bounded_write_content_hash,
    inspect_workspace_harness_directories, inspect_workspace_harness_tree,
};
pub use diff_artifact::{
    DIFF_REDACTION_POLICY_VERSION, DIFF_RENDERER_VERSION, DIFF_ZSTD_LEVEL,
    DiffArtifactDeleteStatus, DiffArtifactExpectation, DiffArtifactInventory,
    DiffArtifactOperation, DiffArtifactStore, DiffArtifactStoreError, DiffRenderError,
    MAX_DIFF_COMPRESSED_BYTES, MAX_DIFF_RENDERED_BYTES, MAX_DIFF_SOURCE_LINES,
    PublishedDiffArtifact, RenderedDiffEvidence, RenderedTextDiff, StagedDiffArtifact,
    diff_path_label, render_diff_evidence, render_patch_diff_evidence,
};
pub use discovery::{
    WorkspaceCandidate, WorkspaceCandidateKey, WorkspaceCandidateKind, WorkspaceDiscovery,
    WorkspaceDiscoveryDisposition, WorkspaceDiscoveryError, WorkspaceDiscoveryObservation,
    WorkspaceDiscoveryReason, WorkspaceKeyResolveError, WorkspaceLocator, WorkspaceLocatorError,
    WorkspaceResolveError, WorkspaceSelector, WorkspaceSelectorError, WorkspaceSignals,
};
pub use git_safety::{
    CheckpointSide, FORGE_GIT_PROGRAM, GIT_CHECKPOINT_MAX_FILE_BYTES,
    GIT_CHECKPOINT_MAX_OUTPUT_BYTES, GIT_CHECKPOINT_OBJECT_VERIFY_MAX,
    GIT_CHECKPOINT_REF_INVENTORY_MAX, GIT_CHECKPOINT_REF_PREFIX, GitCheckpointAdapter,
    GitCheckpointObjectExpectation, GitCheckpointObjectVerification,
    GitCheckpointObjectVerificationStatus, GitCheckpointRefInventory,
    GitCheckpointRefInventoryEntry, GitCheckpointRefInventoryLimit, GitCheckpointStore,
    GitCheckpointStoreIntegrity, GitRetainedSnapshot, GitSafetyError,
};
pub use patch_review::{
    MAX_PATCH_REVIEW_BYTES, PATCH_REVIEW_CONTEXT_LINES, PatchReview, PatchReviewDisposition,
    PatchReviewSide, PatchReviewWindow,
};
pub use service::{
    BoxedRepositoryError, LocationRepository, LocationRepositoryError, LocationService,
    LocationServiceError,
};
pub use state_gate::{
    WorkspaceStateExclusiveGate, WorkspaceStateGateError, WorkspaceStateSharedGate,
};
pub use state_layout::{
    ExistingWorkspaceStateLayout, GitLocalState, GitLocalStateDoctor, StateLayoutError,
    WorkspaceStateLayout,
};
