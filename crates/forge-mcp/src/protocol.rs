//! Bounded, strict MCP wire DTOs and conversions.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::str::FromStr;

use base64::Engine;
use forge_control::{
    ActivityBootstrap, ActivityBootstrapStatus, ControlErrorCode, DiffArtifactDoctorResult,
    DiffArtifactOwnershipStatus, DiffDoctorResult, DiffListResult, DiffReadResult,
    DiffRetentionPlanResult, FileMutationResult, FileMutationStatus, FileReadResult,
    ResolvedWorkspaceScope, WorkspaceCatalogEntry, WorkspaceCatalogStatus,
};
use forge_domain::{
    ActivityId, ActivityLeaseProjection, ActivityState, ChangeSetId, DiffArtifactHealth,
    DiffArtifactInventoryKind, DiffArtifactInventoryLimit, DiffChangeKind, DiffEvidenceState,
    DiffId, DiffListLimit, DiffPayloadProjection, DiffRenderKind, DiffRetentionKeepCount,
    DiffRetentionPlanLimit, FileContentHash, FileMutationId, FileMutationKind, FilePathState,
    LocationId, LocationRevision, RegisteredActivity, RegisteredDiffEvidence, TimestampMillis,
    WorkspaceId, WorkspaceRelativePath, WorkspaceRevision,
};
use forge_workspace::{WorkspaceCandidateKind, WorkspaceLocator};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

/// Maximum encoded JSON arguments accepted by one tool call.
pub const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
/// Maximum object members accepted in one tool call.
pub const MAX_ARGUMENT_FIELDS: usize = 16;
/// Maximum recursive JSON nodes accepted in one tool call.
pub const MAX_ARGUMENT_TREE_NODES: usize = 128;
/// Maximum bytes in a UUID-like wire field before typed parsing.
pub const MAX_ID_BYTES: usize = 64;
/// Maximum bytes in the caller `ActivityId` wire field.
pub const MAX_ACTIVITY_ID_BYTES: usize = MAX_ID_BYTES;
/// Maximum bytes in a `WorkspaceLocator` wire field.
pub const MAX_LOCATOR_BYTES: usize = 4_096;
/// Maximum canonical base64url bytes for one native relative file path.
pub(crate) const MAX_FILE_PATH_WIRE_BYTES: usize = 5_464;
/// Maximum canonical base64url bytes for one bounded 8KiB write body.
pub(crate) const MAX_FILE_CONTENT_WIRE_BYTES: usize = 10_924;
/// Maximum bytes in a tool name before dispatch.
pub const MAX_TOOL_NAME_BYTES: usize = 64;
/// Maximum Diff rows returned by one MCP list call.
pub(crate) const MAX_DIFF_LIST_RESULTS: u32 = 50;
pub(crate) const MAX_DIFF_ARTIFACT_DOCTOR_RESULTS: u32 = 256;
const MAX_DISPLAY_NAME_CHARS: usize = 512;
const MAX_ERROR_CODE_BYTES: usize = 64;

/// Wire representation of a Location id.
pub type LocationIdWire = String;
/// Wire representation of a Location revision.
pub type LocationRevisionWire = i64;

/// Strict input for `workspace_list`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceListInput {
    /// Explicit owner-approved Location identity.
    #[schemars(length(min = 1, max = 64))]
    pub location_id: LocationIdWire,
    /// Exact Location revision observed by the caller.
    #[schemars(range(min = 1))]
    pub expected_revision: LocationRevisionWire,
}

/// Strict input for `workspace_resolve`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceResolveInput {
    /// Explicit Location identity used to validate the locator.
    #[schemars(length(min = 1, max = 64))]
    pub location_id: LocationIdWire,
    /// Exact Location revision used to validate the locator.
    #[schemars(range(min = 1))]
    pub expected_revision: LocationRevisionWire,
    /// Durable Workspace identity observed by the caller.
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    /// Durable Workspace revision observed by the caller.
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    /// Relative, revision-bound Workspace locator.  This is correlation data,
    /// not a capability or a process-global current Workspace.
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
}

/// Strict input for `activity_bootstrap`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivityBootstrapInput {
    /// Explicit Location identity used to resolve the Workspace.
    #[schemars(length(min = 1, max = 64))]
    pub location_id: LocationIdWire,
    /// Exact Location revision used to resolve the Workspace.
    #[schemars(range(min = 1))]
    pub expected_revision: LocationRevisionWire,
    /// Durable Workspace identity observed by the caller.
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    /// Durable Workspace revision observed by the caller.
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    /// Explicit revision-bound Workspace locator.
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    /// Caller-selected durable Activity identity.  The transport id is never
    /// promoted to this field.
    #[schemars(length(min = 1, max = 64))]
    pub activity_id: String,
}

/// Strict input for `file_read`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileReadInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(length(min = 1, max = 64))]
    pub activity_id: String,
    /// Canonical base64url encoding of native Workspace-relative path bytes.
    #[schemars(length(min = 1, max = 5464))]
    pub path: String,
}

/// Strict input for `file_create`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileCreateInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(length(min = 1, max = 64))]
    pub activity_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub change_set_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub mutation_id: String,
    #[schemars(length(min = 1, max = 5464))]
    pub path: String,
    #[schemars(length(max = 10924))]
    pub content_base64: String,
}

/// Strict input for `file_replace`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileReplaceInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(length(min = 1, max = 64))]
    pub activity_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub change_set_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub mutation_id: String,
    #[schemars(length(min = 1, max = 5464))]
    pub path: String,
    #[schemars(length(min = 1, max = 96))]
    pub expected_hash: String,
    #[schemars(length(max = 10924))]
    pub content_base64: String,
}

/// Strict input for `file_delete`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileDeleteInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(length(min = 1, max = 64))]
    pub activity_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub change_set_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub mutation_id: String,
    #[schemars(length(min = 1, max = 5464))]
    pub path: String,
    #[schemars(length(min = 1, max = 96))]
    pub expected_hash: String,
}

/// Strict bounded input for `diff_list`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffListInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(length(min = 1, max = 64))]
    pub activity_id: String,
    #[schemars(range(min = 1, max = 50))]
    pub limit: u32,
}

/// Strict identity input for `diff_read`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffReadInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(length(min = 1, max = 64))]
    pub diff_id: String,
}

/// Strict identity input for `diff_doctor`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffDoctorInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(length(min = 1, max = 64))]
    pub diff_id: String,
}

/// Read-only explicit retention dry-run input.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffRetentionPlanInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(range(max = 10000))]
    pub keep_recent: u32,
    #[schemars(range(min = 1, max = 256))]
    pub limit: u32,
}

/// Read-only bounded Diff directory inventory input.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffArtifactDoctorInput {
    #[schemars(length(min = 1, max = 64))]
    pub location_id: String,
    #[schemars(range(min = 1))]
    pub expected_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub workspace_id: String,
    #[schemars(range(min = 1))]
    pub workspace_revision: i64,
    #[schemars(length(min = 1, max = 4096))]
    pub locator: String,
    #[schemars(range(min = 1, max = 256))]
    pub limit: u32,
}

/// Bounded output for `workspace_list`.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceListOutput {
    #[schemars(length(max = 256))]
    pub entries: Vec<WorkspaceCatalogEntryOutput>,
}

/// Remote-safe catalog entry.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceCatalogEntryOutput {
    pub locator: String,
    pub kind: WorkspaceCandidateKindWire,
    pub display_name: String,
    pub signals: WorkspaceSignalsOutput,
    pub status: WorkspaceCatalogStatusWire,
    /// Present for a Ready entry after read-only durable identity inspection.
    pub workspace_id: Option<String>,
    /// Present for a Ready entry after read-only durable identity inspection.
    pub workspace_revision: Option<i64>,
}

/// Stable wire category for a discovered candidate kind.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceCandidateKindWire {
    LocationRoot,
    DirectChild,
}

/// Bounded remote-safe discovery signals.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSignalsOutput {
    /// Present signal markers in fixed `cargo_workspace`, `git_repository`,
    /// `agent_instructions`, `forge_state` order.
    #[schemars(length(max = 4))]
    pub present: Vec<WorkspaceSignalWire>,
}

/// Typed marker describing one independent Workspace discovery signal.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSignalWire {
    CargoWorkspace,
    GitRepository,
    AgentInstructions,
    ForgeState,
}

/// Stable wire category for discovery state.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceCatalogStatusWire {
    Ready,
    Uninitialized,
    MigrationRequired,
    Unavailable { code: String },
}

/// Output after an explicit Workspace resolution.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceResolveOutput {
    pub scope: WorkspaceScopeOutput,
}

/// A durable Workspace scope projection.  It is not an effect capability.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceScopeOutput {
    pub workspace_id: String,
    pub workspace_revision: i64,
    pub locator: String,
}

/// Wire status for durable bootstrap.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityStatusWire {
    Created,
    ExpiredRecoveryRequired,
    UnleasedRecoveryRequired,
    AlreadyOwned,
    AlreadyLive,
    Terminal,
    CommittedButUnconfirmed,
}

/// Wire state for a durable Activity.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityStateWire {
    Open,
    Closed,
    Interrupted,
}

/// Remote-safe Activity projection.  Absolute roots and raw persistence data
/// are intentionally absent.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityOutput {
    pub activity_id: String,
    pub workspace_id: String,
    pub state: ActivityStateWire,
    pub revision: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub lease_until_ms: Option<i64>,
    pub lease_revision: i64,
}

/// Output for `activity_bootstrap`.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityBootstrapOutput {
    pub scope: WorkspaceScopeOutput,
    pub activity: Option<ActivityOutput>,
    pub status: ActivityStatusWire,
    pub committed: bool,
    /// Whether this process retained the lease for heartbeat/shutdown
    /// ownership.  A false value means recovery/idempotent retry is required.
    pub ownership_tracking: OwnershipTrackingWire,
}

/// Output for a bounded confined file read.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileReadOutput {
    pub scope: WorkspaceScopeOutput,
    pub activity_id: String,
    pub path: String,
    pub content_base64: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

/// Stable wire file mutation kind.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileMutationKindWire {
    Create,
    Replace,
    Delete,
}

/// Stable mutation lifecycle projection.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileMutationStatusWire {
    Applied,
    AlreadyApplied,
    RecoveryRequired,
    TerminalFailed,
    CommittedButUnconfirmed,
}

/// PRE/POST state without file content or absolute path.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileStateOutput {
    pub exists: bool,
    pub content_hash: Option<String>,
    pub size_bytes: Option<u64>,
}

/// Durable Activity-attributed result for create/replace/delete.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileMutationOutput {
    pub scope: WorkspaceScopeOutput,
    pub activity_id: String,
    pub change_set_id: String,
    pub mutation_id: String,
    pub path: String,
    pub kind: FileMutationKindWire,
    pub status: FileMutationStatusWire,
    pub pre_state: FileStateOutput,
    pub post_state: Option<FileStateOutput>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiffChangeKindWire {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiffEvidenceStateWire {
    Intent,
    Ready,
    SummaryOnly,
    Abandoned,
    PurgePending,
    Tombstoned,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiffRenderKindWire {
    Text,
    Binary,
    Oversized,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiffArtifactHealthWire {
    Available,
    NotApplicable,
    Archived,
    Missing,
    Corrupt,
}

/// Durable remote-safe Diff metadata. Artifact-internal paths are omitted.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiffEvidenceOutput {
    pub diff_id: String,
    pub workspace_id: String,
    pub activity_id: String,
    pub change_set_id: String,
    pub mutation_id: String,
    pub path: String,
    pub change_kind: DiffChangeKindWire,
    pub state: DiffEvidenceStateWire,
    pub render_kind: DiffRenderKindWire,
    pub additions: u32,
    pub deletions: u32,
    pub compressed_hash: Option<String>,
    pub uncompressed_hash: Option<String>,
    pub compressed_size_bytes: Option<u64>,
    pub uncompressed_size_bytes: Option<u64>,
    pub renderer_version: u32,
    pub redaction_policy_version: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiffListOutput {
    pub scope: WorkspaceScopeOutput,
    #[schemars(length(max = 50))]
    pub diffs: Vec<DiffEvidenceOutput>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiffReadOutput {
    pub scope: WorkspaceScopeOutput,
    pub diff: DiffEvidenceOutput,
    pub health: DiffArtifactHealthWire,
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiffDoctorOutput {
    pub scope: WorkspaceScopeOutput,
    pub diff: DiffEvidenceOutput,
    pub health: DiffArtifactHealthWire,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiffRetentionPlanOutput {
    pub scope: WorkspaceScopeOutput,
    pub keep_recent: u32,
    #[schemars(length(max = 256))]
    pub candidates: Vec<DiffEvidenceOutput>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiffArtifactInventoryKindWire {
    Pending,
    Final,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiffArtifactOwnershipWire {
    Owned,
    Orphan,
    Conflicting,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiffArtifactDiagnosticOutput {
    pub name_base64: String,
    pub path_label: String,
    pub kind: DiffArtifactInventoryKindWire,
    pub diff_id: Option<String>,
    pub compressed_hash: String,
    pub compressed_size_bytes: u64,
    pub ownership: DiffArtifactOwnershipWire,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiffArtifactDoctorOutput {
    pub scope: WorkspaceScopeOutput,
    #[schemars(length(max = 256))]
    pub entries: Vec<DiffArtifactDiagnosticOutput>,
    pub truncated: bool,
}

/// Process-local ownership tracking outcome.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipTrackingWire {
    Tracked,
    NotTrackedCapacity,
    NotTrackedShutdown,
    NotTrackedNotOwned,
}

/// Stable redacted control error projection used by unit tests and callers
/// that want a tool-level error instead of a JSON-RPC invalid-params error.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpToolErrorOutput {
    pub code: String,
    pub message: String,
    pub committed: bool,
}

/// Validation/conversion failures at the MCP ingress boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WireValidationError {
    #[error("tool arguments exceed the bounded input policy")]
    Oversized,
    #[error("tool arguments have too many fields or nested values")]
    TooManyValues,
    #[error("tool arguments do not match the strict schema")]
    Shape,
    #[error("tool argument contains an invalid typed identifier")]
    InvalidIdentifier,
    #[error("tool argument contains an invalid revision or timestamp")]
    InvalidNumber,
    #[error("tool argument contains an invalid Workspace locator")]
    InvalidLocator,
    #[error("tool argument contains an invalid Workspace-relative path")]
    InvalidPath,
    #[error("tool argument contains invalid canonical file content")]
    InvalidContent,
    #[error("tool argument contains an invalid content hash")]
    InvalidHash,
    #[error("tool argument identifiers do not match the locator")]
    MismatchedLocator,
}

type WorkspaceResolveTyped = (
    LocationId,
    LocationRevision,
    WorkspaceId,
    WorkspaceRevision,
    WorkspaceLocator,
);
type ActivityBootstrapTyped = (
    LocationId,
    LocationRevision,
    WorkspaceId,
    WorkspaceRevision,
    WorkspaceLocator,
    ActivityId,
);

#[derive(Debug)]
pub(crate) struct FileScopeTyped {
    pub(crate) location_id: LocationId,
    pub(crate) location_revision: LocationRevision,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) workspace_revision: WorkspaceRevision,
    pub(crate) locator: WorkspaceLocator,
    pub(crate) activity_id: ActivityId,
    pub(crate) path: WorkspaceRelativePath,
}

#[derive(Debug)]
pub(crate) struct FileMutationTyped {
    pub(crate) scope: FileScopeTyped,
    pub(crate) change_set_id: ChangeSetId,
    pub(crate) mutation_id: FileMutationId,
    pub(crate) expected_hash: Option<FileContentHash>,
    pub(crate) content: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(crate) struct DiffScopeTyped {
    pub(crate) location_id: LocationId,
    pub(crate) location_revision: LocationRevision,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) workspace_revision: WorkspaceRevision,
    pub(crate) locator: WorkspaceLocator,
}

#[derive(Debug, Clone)]
pub(crate) struct DiffListTyped {
    pub(crate) scope: DiffScopeTyped,
    pub(crate) activity_id: ActivityId,
    pub(crate) limit: DiffListLimit,
}

#[derive(Debug, Clone)]
pub(crate) struct DiffIdentityTyped {
    pub(crate) scope: DiffScopeTyped,
    pub(crate) diff_id: DiffId,
}

#[derive(Debug, Clone)]
pub(crate) struct DiffRetentionPlanTyped {
    pub(crate) scope: DiffScopeTyped,
    pub(crate) keep_recent: DiffRetentionKeepCount,
    pub(crate) limit: DiffRetentionPlanLimit,
}

#[derive(Debug, Clone)]
pub(crate) struct DiffArtifactDoctorTyped {
    pub(crate) scope: DiffScopeTyped,
    pub(crate) limit: DiffArtifactInventoryLimit,
}

#[derive(Clone, Copy)]
struct DiffScopeWireRefs<'a> {
    location_id: &'a str,
    expected_revision: i64,
    workspace_id: &'a str,
    workspace_revision: i64,
    locator: &'a str,
}

#[derive(Clone, Copy)]
struct FileScopeWireRefs<'a> {
    location_id: &'a str,
    expected_revision: i64,
    workspace_id: &'a str,
    workspace_revision: i64,
    locator: &'a str,
    activity_id: &'a str,
    path: &'a str,
}

impl WorkspaceListInput {
    pub fn into_typed(self) -> Result<(LocationId, LocationRevision), WireValidationError> {
        let location_id = parse_location_id(&self.location_id)?;
        let revision = LocationRevision::new(self.expected_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        Ok((location_id, revision))
    }
}

impl WorkspaceResolveInput {
    pub fn into_typed(self) -> Result<WorkspaceResolveTyped, WireValidationError> {
        let location_id = parse_location_id(&self.location_id)?;
        let revision = LocationRevision::new(self.expected_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let workspace_id = parse_workspace_id(&self.workspace_id)?;
        let workspace_revision = WorkspaceRevision::new(self.workspace_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let locator = decode_locator(&self.locator)?;
        if locator.location_id() != location_id || locator.expected_revision() != revision {
            return Err(WireValidationError::MismatchedLocator);
        }
        Ok((
            location_id,
            revision,
            workspace_id,
            workspace_revision,
            locator,
        ))
    }
}

impl ActivityBootstrapInput {
    pub fn into_typed(self) -> Result<ActivityBootstrapTyped, WireValidationError> {
        let location_id = parse_location_id(&self.location_id)?;
        let revision = LocationRevision::new(self.expected_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let workspace_id = parse_workspace_id(&self.workspace_id)?;
        let workspace_revision = WorkspaceRevision::new(self.workspace_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let locator = decode_locator(&self.locator)?;
        if locator.location_id() != location_id || locator.expected_revision() != revision {
            return Err(WireValidationError::MismatchedLocator);
        }
        let activity_id = parse_activity_id(&self.activity_id)?;
        Ok((
            location_id,
            revision,
            workspace_id,
            workspace_revision,
            locator,
            activity_id,
        ))
    }
}

impl FileReadInput {
    pub(crate) fn into_typed(self) -> Result<FileScopeTyped, WireValidationError> {
        parse_file_scope(FileScopeWireRefs {
            location_id: &self.location_id,
            expected_revision: self.expected_revision,
            workspace_id: &self.workspace_id,
            workspace_revision: self.workspace_revision,
            locator: &self.locator,
            activity_id: &self.activity_id,
            path: &self.path,
        })
    }
}

impl FileCreateInput {
    pub(crate) fn into_typed(self) -> Result<FileMutationTyped, WireValidationError> {
        let scope = parse_file_scope(FileScopeWireRefs {
            location_id: &self.location_id,
            expected_revision: self.expected_revision,
            workspace_id: &self.workspace_id,
            workspace_revision: self.workspace_revision,
            locator: &self.locator,
            activity_id: &self.activity_id,
            path: &self.path,
        })?;
        Ok(FileMutationTyped {
            scope,
            change_set_id: parse_change_set_id(&self.change_set_id)?,
            mutation_id: parse_mutation_id(&self.mutation_id)?,
            expected_hash: None,
            content: Some(decode_content(&self.content_base64)?),
        })
    }
}

impl FileReplaceInput {
    pub(crate) fn into_typed(self) -> Result<FileMutationTyped, WireValidationError> {
        let scope = parse_file_scope(FileScopeWireRefs {
            location_id: &self.location_id,
            expected_revision: self.expected_revision,
            workspace_id: &self.workspace_id,
            workspace_revision: self.workspace_revision,
            locator: &self.locator,
            activity_id: &self.activity_id,
            path: &self.path,
        })?;
        Ok(FileMutationTyped {
            scope,
            change_set_id: parse_change_set_id(&self.change_set_id)?,
            mutation_id: parse_mutation_id(&self.mutation_id)?,
            expected_hash: Some(parse_content_hash(&self.expected_hash)?),
            content: Some(decode_content(&self.content_base64)?),
        })
    }
}

impl FileDeleteInput {
    pub(crate) fn into_typed(self) -> Result<FileMutationTyped, WireValidationError> {
        let scope = parse_file_scope(FileScopeWireRefs {
            location_id: &self.location_id,
            expected_revision: self.expected_revision,
            workspace_id: &self.workspace_id,
            workspace_revision: self.workspace_revision,
            locator: &self.locator,
            activity_id: &self.activity_id,
            path: &self.path,
        })?;
        Ok(FileMutationTyped {
            scope,
            change_set_id: parse_change_set_id(&self.change_set_id)?,
            mutation_id: parse_mutation_id(&self.mutation_id)?,
            expected_hash: Some(parse_content_hash(&self.expected_hash)?),
            content: None,
        })
    }
}

impl DiffListInput {
    pub(crate) fn into_typed(self) -> Result<DiffListTyped, WireValidationError> {
        if self.limit > MAX_DIFF_LIST_RESULTS {
            return Err(WireValidationError::InvalidNumber);
        }
        Ok(DiffListTyped {
            scope: parse_diff_scope(DiffScopeWireRefs {
                location_id: &self.location_id,
                expected_revision: self.expected_revision,
                workspace_id: &self.workspace_id,
                workspace_revision: self.workspace_revision,
                locator: &self.locator,
            })?,
            activity_id: parse_activity_id(&self.activity_id)?,
            limit: DiffListLimit::new(self.limit)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

impl DiffReadInput {
    pub(crate) fn into_typed(self) -> Result<DiffIdentityTyped, WireValidationError> {
        parse_diff_identity(
            DiffScopeWireRefs {
                location_id: &self.location_id,
                expected_revision: self.expected_revision,
                workspace_id: &self.workspace_id,
                workspace_revision: self.workspace_revision,
                locator: &self.locator,
            },
            &self.diff_id,
        )
    }
}

impl DiffDoctorInput {
    pub(crate) fn into_typed(self) -> Result<DiffIdentityTyped, WireValidationError> {
        parse_diff_identity(
            DiffScopeWireRefs {
                location_id: &self.location_id,
                expected_revision: self.expected_revision,
                workspace_id: &self.workspace_id,
                workspace_revision: self.workspace_revision,
                locator: &self.locator,
            },
            &self.diff_id,
        )
    }
}

impl DiffRetentionPlanInput {
    pub(crate) fn into_typed(self) -> Result<DiffRetentionPlanTyped, WireValidationError> {
        Ok(DiffRetentionPlanTyped {
            scope: parse_diff_scope(DiffScopeWireRefs {
                location_id: &self.location_id,
                expected_revision: self.expected_revision,
                workspace_id: &self.workspace_id,
                workspace_revision: self.workspace_revision,
                locator: &self.locator,
            })?,
            keep_recent: DiffRetentionKeepCount::new(self.keep_recent)
                .map_err(|_| WireValidationError::InvalidNumber)?,
            limit: DiffRetentionPlanLimit::new(self.limit)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

impl DiffArtifactDoctorInput {
    pub(crate) fn into_typed(self) -> Result<DiffArtifactDoctorTyped, WireValidationError> {
        if self.limit > MAX_DIFF_ARTIFACT_DOCTOR_RESULTS {
            return Err(WireValidationError::InvalidNumber);
        }
        Ok(DiffArtifactDoctorTyped {
            scope: parse_diff_scope(DiffScopeWireRefs {
                location_id: &self.location_id,
                expected_revision: self.expected_revision,
                workspace_id: &self.workspace_id,
                workspace_revision: self.workspace_revision,
                locator: &self.locator,
            })?,
            limit: DiffArtifactInventoryLimit::new(self.limit)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

fn parse_diff_identity(
    scope: DiffScopeWireRefs<'_>,
    diff_id: &str,
) -> Result<DiffIdentityTyped, WireValidationError> {
    Ok(DiffIdentityTyped {
        scope: parse_diff_scope(scope)?,
        diff_id: parse_diff_id(diff_id)?,
    })
}

fn parse_diff_scope(input: DiffScopeWireRefs<'_>) -> Result<DiffScopeTyped, WireValidationError> {
    let location_id = parse_location_id(input.location_id)?;
    let location_revision = LocationRevision::new(input.expected_revision)
        .map_err(|_| WireValidationError::InvalidNumber)?;
    let workspace_id = parse_workspace_id(input.workspace_id)?;
    let workspace_revision = WorkspaceRevision::new(input.workspace_revision)
        .map_err(|_| WireValidationError::InvalidNumber)?;
    let locator = decode_locator(input.locator)?;
    if locator.location_id() != location_id || locator.expected_revision() != location_revision {
        return Err(WireValidationError::MismatchedLocator);
    }
    Ok(DiffScopeTyped {
        location_id,
        location_revision,
        workspace_id,
        workspace_revision,
        locator,
    })
}

fn parse_file_scope(input: FileScopeWireRefs<'_>) -> Result<FileScopeTyped, WireValidationError> {
    let location_id = parse_location_id(input.location_id)?;
    let location_revision = LocationRevision::new(input.expected_revision)
        .map_err(|_| WireValidationError::InvalidNumber)?;
    let workspace_id = parse_workspace_id(input.workspace_id)?;
    let workspace_revision = WorkspaceRevision::new(input.workspace_revision)
        .map_err(|_| WireValidationError::InvalidNumber)?;
    let locator = decode_locator(input.locator)?;
    if locator.location_id() != location_id || locator.expected_revision() != location_revision {
        return Err(WireValidationError::MismatchedLocator);
    }
    Ok(FileScopeTyped {
        location_id,
        location_revision,
        workspace_id,
        workspace_revision,
        locator,
        activity_id: parse_activity_id(input.activity_id)?,
        path: decode_relative_path(input.path)?,
    })
}

pub(crate) fn parse_arguments<T: for<'de> Deserialize<'de>>(
    arguments: Option<&Map<String, Value>>,
) -> Result<T, WireValidationError> {
    let Some(arguments) = arguments else {
        return Err(WireValidationError::Shape);
    };
    if arguments.len() > MAX_ARGUMENT_FIELDS {
        return Err(WireValidationError::TooManyValues);
    }
    let mut nodes = 0;
    let mut bytes = 0_usize;
    for (key, value) in arguments {
        if key.len() > MAX_TOOL_NAME_BYTES {
            return Err(WireValidationError::Oversized);
        }
        bytes = bytes.saturating_add(key.len());
        if bytes > MAX_ARGUMENT_BYTES {
            return Err(WireValidationError::Oversized);
        }
        bounded_value(value, 0, &mut nodes, &mut bytes)?;
    }
    let value = Value::Object(arguments.clone());
    serde_json::from_value(value).map_err(|_| WireValidationError::Shape)
}

fn bounded_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    bytes: &mut usize,
) -> Result<(), WireValidationError> {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_ARGUMENT_TREE_NODES || depth > 8 {
        return Err(WireValidationError::TooManyValues);
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            *bytes = bytes.saturating_add(8);
            Ok(())
        }
        Value::String(value) => {
            *bytes = bytes.saturating_add(value.len());
            if *bytes > MAX_ARGUMENT_BYTES {
                Err(WireValidationError::Oversized)
            } else {
                Ok(())
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_ARGUMENT_FIELDS {
                return Err(WireValidationError::TooManyValues);
            }
            for value in values {
                bounded_value(value, depth + 1, nodes, bytes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_ARGUMENT_FIELDS {
                return Err(WireValidationError::TooManyValues);
            }
            for (key, value) in values {
                if key.len() > MAX_TOOL_NAME_BYTES {
                    return Err(WireValidationError::Oversized);
                }
                *bytes = bytes.saturating_add(key.len());
                bounded_value(value, depth + 1, nodes, bytes)?;
            }
            Ok(())
        }
    }
}

fn parse_location_id(value: &str) -> Result<LocationId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = LocationId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_activity_id(value: &str) -> Result<ActivityId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = ActivityId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_workspace_id(value: &str) -> Result<WorkspaceId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed =
        WorkspaceId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_change_set_id(value: &str) -> Result<ChangeSetId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed =
        ChangeSetId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_diff_id(value: &str) -> Result<DiffId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = DiffId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_mutation_id(value: &str) -> Result<FileMutationId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed =
        FileMutationId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_content_hash(value: &str) -> Result<FileContentHash, WireValidationError> {
    if value.len() != FileContentHash::ENCODED_LEN {
        return Err(WireValidationError::InvalidHash);
    }
    FileContentHash::from_str(value).map_err(|_| WireValidationError::InvalidHash)
}

fn bounded_identifier(value: &str) -> Result<(), WireValidationError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        Err(WireValidationError::Oversized)
    } else {
        Ok(())
    }
}

fn decode_locator(value: &str) -> Result<WorkspaceLocator, WireValidationError> {
    if value.is_empty() || value.len() > MAX_LOCATOR_BYTES || value.chars().any(char::is_control) {
        return Err(WireValidationError::Oversized);
    }
    WorkspaceLocator::decode(value).map_err(|_| WireValidationError::InvalidLocator)
}

fn decode_relative_path(value: &str) -> Result<WorkspaceRelativePath, WireValidationError> {
    if value.is_empty() || value.len() > MAX_FILE_PATH_WIRE_BYTES {
        return Err(WireValidationError::InvalidPath);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WireValidationError::InvalidPath)?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(WireValidationError::InvalidPath);
    }
    WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(bytes)))
        .map_err(|_| WireValidationError::InvalidPath)
}

fn encode_relative_path(path: &WorkspaceRelativePath) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(path.as_path().as_os_str().as_bytes())
}

fn decode_content(value: &str) -> Result<Vec<u8>, WireValidationError> {
    if value.len() > MAX_FILE_CONTENT_WIRE_BYTES {
        return Err(WireValidationError::InvalidContent);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WireValidationError::InvalidContent)?;
    if bytes.len() > forge_workspace::MAX_FILE_WRITE_BYTES
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != value
    {
        return Err(WireValidationError::InvalidContent);
    }
    Ok(bytes)
}

pub(crate) fn scope_output(scope: &ResolvedWorkspaceScope) -> WorkspaceScopeOutput {
    WorkspaceScopeOutput {
        workspace_id: scope.workspace_id().to_string(),
        workspace_revision: scope.workspace_revision().get(),
        locator: scope.locator().encode(),
    }
}

pub(crate) fn catalog_output(entry: &WorkspaceCatalogEntry) -> WorkspaceCatalogEntryOutput {
    let display_name = bounded_display_name(entry.display_name());
    WorkspaceCatalogEntryOutput {
        locator: entry.locator().encode(),
        kind: match entry.kind() {
            WorkspaceCandidateKind::LocationRoot => WorkspaceCandidateKindWire::LocationRoot,
            WorkspaceCandidateKind::DirectChild => WorkspaceCandidateKindWire::DirectChild,
        },
        display_name,
        signals: WorkspaceSignalsOutput {
            present: {
                let signals = entry.signals();
                let mut present = Vec::with_capacity(4);
                if signals.cargo_workspace() {
                    present.push(WorkspaceSignalWire::CargoWorkspace);
                }
                if signals.git_repository() {
                    present.push(WorkspaceSignalWire::GitRepository);
                }
                if signals.agent_instructions() {
                    present.push(WorkspaceSignalWire::AgentInstructions);
                }
                if signals.forge_state() {
                    present.push(WorkspaceSignalWire::ForgeState);
                }
                present
            },
        },
        status: match entry.status() {
            WorkspaceCatalogStatus::Ready { .. } => WorkspaceCatalogStatusWire::Ready,
            WorkspaceCatalogStatus::Uninitialized => WorkspaceCatalogStatusWire::Uninitialized,
            WorkspaceCatalogStatus::MigrationRequired => {
                WorkspaceCatalogStatusWire::MigrationRequired
            }
            WorkspaceCatalogStatus::Unavailable(code) => WorkspaceCatalogStatusWire::Unavailable {
                code: bounded_code(code),
            },
        },
        workspace_id: entry.status().workspace_id().map(|id| id.to_string()),
        workspace_revision: entry
            .status()
            .workspace_revision()
            .map(WorkspaceRevision::get),
    }
}

pub(crate) fn bootstrap_output(
    result: &ActivityBootstrap,
    ownership_tracking: OwnershipTrackingWire,
) -> ActivityBootstrapOutput {
    ActivityBootstrapOutput {
        scope: scope_output(result.scope()),
        activity: result.activity().map(activity_output),
        status: bootstrap_status(result.status()),
        committed: result.is_committed(),
        ownership_tracking,
    }
}

pub(crate) fn activity_output(activity: &RegisteredActivity) -> ActivityOutput {
    let lease: &ActivityLeaseProjection = activity.lease();
    ActivityOutput {
        activity_id: activity.id().to_string(),
        workspace_id: activity.workspace_id().to_string(),
        state: match activity.state() {
            ActivityState::Open => ActivityStateWire::Open,
            ActivityState::Closed => ActivityStateWire::Closed,
            ActivityState::Interrupted => ActivityStateWire::Interrupted,
        },
        revision: activity.revision().get(),
        created_at_ms: activity.created_at().get(),
        updated_at_ms: activity.updated_at().get(),
        lease_until_ms: lease.lease_until().map(TimestampMillis::get),
        lease_revision: lease.revision().get(),
    }
}

pub(crate) fn file_read_output(result: &FileReadResult) -> FileReadOutput {
    FileReadOutput {
        scope: scope_output(result.scope()),
        activity_id: result.activity_id().to_string(),
        path: encode_relative_path(result.path()),
        content_base64: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(result.read().content()),
        content_hash: result.read().hash().to_string(),
        size_bytes: result.read().size().get(),
    }
}

pub(crate) fn file_mutation_output(result: &FileMutationResult) -> FileMutationOutput {
    let record = result.record();
    FileMutationOutput {
        scope: scope_output(result.scope()),
        activity_id: record.change_set().activity_id().to_string(),
        change_set_id: record.change_set().id().to_string(),
        mutation_id: record.mutation().id().to_string(),
        path: encode_relative_path(record.mutation().path()),
        kind: mutation_kind(record.mutation().kind()),
        status: mutation_status(result.status()),
        pre_state: file_state_output(record.mutation().pre_state()),
        post_state: record.mutation().post_state().map(file_state_output),
    }
}

pub(crate) fn diff_list_output(result: &DiffListResult) -> DiffListOutput {
    DiffListOutput {
        scope: scope_output(result.scope()),
        diffs: result.diffs().iter().map(diff_evidence_output).collect(),
    }
}

pub(crate) fn diff_read_output(result: &DiffReadResult) -> DiffReadOutput {
    DiffReadOutput {
        scope: scope_output(result.scope()),
        diff: diff_evidence_output(result.evidence()),
        health: diff_health(result.health()),
        content: result.content().map(str::to_owned),
    }
}

pub(crate) fn diff_doctor_output(result: &DiffDoctorResult) -> DiffDoctorOutput {
    DiffDoctorOutput {
        scope: scope_output(result.scope()),
        diff: diff_evidence_output(result.evidence()),
        health: diff_health(result.health()),
    }
}

pub(crate) fn diff_retention_plan_output(
    result: &DiffRetentionPlanResult,
) -> DiffRetentionPlanOutput {
    DiffRetentionPlanOutput {
        scope: scope_output(result.scope()),
        keep_recent: result.plan().keep_recent().get(),
        candidates: result
            .plan()
            .candidates()
            .iter()
            .map(diff_evidence_output)
            .collect(),
    }
}

pub(crate) fn diff_artifact_doctor_output(
    result: &DiffArtifactDoctorResult,
) -> DiffArtifactDoctorOutput {
    DiffArtifactDoctorOutput {
        scope: scope_output(result.scope()),
        entries: result
            .entries()
            .iter()
            .map(|entry| DiffArtifactDiagnosticOutput {
                name_base64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(entry.artifact().name().as_bytes()),
                path_label: entry.path_label().to_owned(),
                kind: match entry.artifact().kind() {
                    DiffArtifactInventoryKind::Pending => DiffArtifactInventoryKindWire::Pending,
                    DiffArtifactInventoryKind::Final => DiffArtifactInventoryKindWire::Final,
                    DiffArtifactInventoryKind::Unknown => DiffArtifactInventoryKindWire::Unknown,
                },
                diff_id: entry.artifact().diff_id().map(|id| id.to_string()),
                compressed_hash: entry.artifact().compressed_hash().to_string(),
                compressed_size_bytes: entry.artifact().compressed_size().get(),
                ownership: match entry.ownership() {
                    DiffArtifactOwnershipStatus::Owned => DiffArtifactOwnershipWire::Owned,
                    DiffArtifactOwnershipStatus::Orphan => DiffArtifactOwnershipWire::Orphan,
                    DiffArtifactOwnershipStatus::Conflicting => {
                        DiffArtifactOwnershipWire::Conflicting
                    }
                },
            })
            .collect(),
        truncated: result.truncated(),
    }
}

fn diff_evidence_output(value: &RegisteredDiffEvidence) -> DiffEvidenceOutput {
    let (compressed_hash, uncompressed_hash, compressed_size, uncompressed_size) =
        diff_payload_metadata(value.payload());
    DiffEvidenceOutput {
        diff_id: value.id().to_string(),
        workspace_id: value.workspace_id().to_string(),
        activity_id: value.activity_id().to_string(),
        change_set_id: value.change_set_id().to_string(),
        mutation_id: value.mutation_id().to_string(),
        path: encode_relative_path(value.file().path()),
        change_kind: match value.file().kind() {
            DiffChangeKind::Created => DiffChangeKindWire::Created,
            DiffChangeKind::Modified => DiffChangeKindWire::Modified,
            DiffChangeKind::Deleted => DiffChangeKindWire::Deleted,
        },
        state: match value.state() {
            DiffEvidenceState::Intent => DiffEvidenceStateWire::Intent,
            DiffEvidenceState::Ready => DiffEvidenceStateWire::Ready,
            DiffEvidenceState::SummaryOnly => DiffEvidenceStateWire::SummaryOnly,
            DiffEvidenceState::Abandoned => DiffEvidenceStateWire::Abandoned,
            DiffEvidenceState::PurgePending => DiffEvidenceStateWire::PurgePending,
            DiffEvidenceState::Tombstoned => DiffEvidenceStateWire::Tombstoned,
        },
        render_kind: match value.payload().render_kind() {
            DiffRenderKind::Text => DiffRenderKindWire::Text,
            DiffRenderKind::Binary => DiffRenderKindWire::Binary,
            DiffRenderKind::Oversized => DiffRenderKindWire::Oversized,
        },
        additions: value.file().additions().get(),
        deletions: value.file().deletions().get(),
        compressed_hash,
        uncompressed_hash,
        compressed_size_bytes: compressed_size,
        uncompressed_size_bytes: uncompressed_size,
        renderer_version: value.renderer_version().get(),
        redaction_policy_version: value.redaction_policy_version().get(),
        created_at_ms: value.created_at().get(),
        updated_at_ms: value.updated_at().get(),
        revision: value.revision().get(),
    }
}

type DiffPayloadMetadata = (Option<String>, Option<String>, Option<u64>, Option<u64>);

fn diff_payload_metadata(value: &DiffPayloadProjection) -> DiffPayloadMetadata {
    match value {
        DiffPayloadProjection::IntentText {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        }
        | DiffPayloadProjection::Ready {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        }
        | DiffPayloadProjection::PurgePending {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        } => (
            Some(compressed_hash.to_string()),
            Some(uncompressed_hash.to_string()),
            Some(compressed_size.get()),
            Some(uncompressed_size.get()),
        ),
        DiffPayloadProjection::IntentSummary { .. }
        | DiffPayloadProjection::SummaryOnly { .. }
        | DiffPayloadProjection::Abandoned { .. }
        | DiffPayloadProjection::Tombstoned { .. } => (None, None, None, None),
    }
}

const fn diff_health(value: DiffArtifactHealth) -> DiffArtifactHealthWire {
    match value {
        DiffArtifactHealth::Available => DiffArtifactHealthWire::Available,
        DiffArtifactHealth::NotApplicable => DiffArtifactHealthWire::NotApplicable,
        DiffArtifactHealth::Archived => DiffArtifactHealthWire::Archived,
        DiffArtifactHealth::Missing => DiffArtifactHealthWire::Missing,
        DiffArtifactHealth::Corrupt => DiffArtifactHealthWire::Corrupt,
    }
}

fn mutation_kind(value: FileMutationKind) -> FileMutationKindWire {
    match value {
        FileMutationKind::Create => FileMutationKindWire::Create,
        FileMutationKind::Replace => FileMutationKindWire::Replace,
        FileMutationKind::Delete => FileMutationKindWire::Delete,
    }
}

fn mutation_status(value: FileMutationStatus) -> FileMutationStatusWire {
    match value {
        FileMutationStatus::Applied => FileMutationStatusWire::Applied,
        FileMutationStatus::AlreadyApplied => FileMutationStatusWire::AlreadyApplied,
        FileMutationStatus::RecoveryRequired => FileMutationStatusWire::RecoveryRequired,
        FileMutationStatus::TerminalFailed => FileMutationStatusWire::TerminalFailed,
        FileMutationStatus::CommittedButUnconfirmed => {
            FileMutationStatusWire::CommittedButUnconfirmed
        }
    }
}

fn file_state_output(value: FilePathState) -> FileStateOutput {
    match value {
        FilePathState::Absent => FileStateOutput {
            exists: false,
            content_hash: None,
            size_bytes: None,
        },
        FilePathState::Regular { hash, size } => FileStateOutput {
            exists: true,
            content_hash: Some(hash.to_string()),
            size_bytes: Some(size.get()),
        },
    }
}

fn bootstrap_status(status: ActivityBootstrapStatus) -> ActivityStatusWire {
    match status {
        ActivityBootstrapStatus::Created => ActivityStatusWire::Created,
        ActivityBootstrapStatus::ExpiredRecoveryRequired => {
            ActivityStatusWire::ExpiredRecoveryRequired
        }
        ActivityBootstrapStatus::UnleasedRecoveryRequired => {
            ActivityStatusWire::UnleasedRecoveryRequired
        }
        ActivityBootstrapStatus::AlreadyOwned => ActivityStatusWire::AlreadyOwned,
        ActivityBootstrapStatus::AlreadyLive => ActivityStatusWire::AlreadyLive,
        ActivityBootstrapStatus::Terminal => ActivityStatusWire::Terminal,
        ActivityBootstrapStatus::CommittedButUnconfirmed => {
            ActivityStatusWire::CommittedButUnconfirmed
        }
    }
}

fn bounded_display_name(value: &str) -> String {
    value.chars().take(MAX_DISPLAY_NAME_CHARS).collect()
}

fn bounded_code(code: ControlErrorCode) -> String {
    code.as_str().chars().take(MAX_ERROR_CODE_BYTES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use forge_domain::LocationId;
    use serde_json::json;
    use uuid::Uuid;

    fn location() -> String {
        LocationId::from_uuid(Uuid::from_u128(1)).to_string()
    }

    fn locator() -> Result<String, Box<dyn std::error::Error>> {
        Ok(WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(1)),
            LocationRevision::INITIAL,
            ".",
        )?
        .encode())
    }

    #[test]
    fn strict_dto_rejects_unknown_fields_and_bad_locator_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let locator_wire = locator()?;
        let value = json!({
            "location_id": location(),
            "expected_revision": 1,
            "workspace_id": location(),
            "workspace_revision": 1,
            "locator": locator_wire,
            "unexpected": true,
        });
        assert!(serde_json::from_value::<WorkspaceResolveInput>(value).is_err());

        let value = WorkspaceResolveInput {
            location_id: LocationId::from_uuid(Uuid::from_u128(2)).to_string(),
            expected_revision: 1,
            workspace_id: LocationId::from_uuid(Uuid::from_u128(3)).to_string(),
            workspace_revision: 1,
            locator: locator()?,
        };
        assert_eq!(
            value.into_typed(),
            Err(WireValidationError::MismatchedLocator)
        );

        let missing_workspace_identity = json!({
            "location_id": location(),
            "expected_revision": 1,
            "locator": locator()?,
        });
        assert!(
            serde_json::from_value::<WorkspaceResolveInput>(missing_workspace_identity).is_err()
        );
        let missing_bootstrap_identity = json!({
            "location_id": location(),
            "expected_revision": 1,
            "locator": locator()?,
            "activity_id": location(),
        });
        assert!(
            serde_json::from_value::<ActivityBootstrapInput>(missing_bootstrap_identity).is_err()
        );
        let caller_clock = json!({
            "location_id": location(),
            "expected_revision": 1,
            "workspace_id": Uuid::from_u128(2).to_string(),
            "workspace_revision": 1,
            "locator": locator()?,
            "activity_id": Uuid::from_u128(3).to_string(),
            "observed_at_ms": i64::MAX,
        });
        assert!(serde_json::from_value::<ActivityBootstrapInput>(caller_clock).is_err());
        Ok(())
    }

    #[test]
    fn argument_bounds_reject_oversized_and_deep_values() {
        let mut object = Map::new();
        object.insert(
            "location_id".to_owned(),
            Value::String("x".repeat(MAX_ARGUMENT_BYTES + 1)),
        );
        assert_eq!(
            parse_arguments::<WorkspaceListInput>(Some(&object)),
            Err(WireValidationError::Oversized)
        );

        let mut oversized_key = Map::new();
        oversized_key.insert("x".repeat(MAX_TOOL_NAME_BYTES + 1), Value::Bool(true));
        assert_eq!(
            parse_arguments::<WorkspaceListInput>(Some(&oversized_key)),
            Err(WireValidationError::Oversized)
        );

        let mut nested = Value::String("leaf".to_owned());
        for _ in 0..10 {
            nested = Value::Array(vec![nested]);
        }
        let mut object = Map::new();
        object.insert("location_id".to_owned(), nested);
        assert_eq!(
            parse_arguments::<WorkspaceListInput>(Some(&object)),
            Err(WireValidationError::TooManyValues)
        );
    }

    #[test]
    fn file_dtos_preserve_native_path_bytes_and_reject_noncanonical_or_oversized_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let path_bytes = b"src/native-\xC3\xA9.rs";
        let path = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(path_bytes);
        let input = FileCreateInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            activity_id: Uuid::from_u128(3).to_string(),
            change_set_id: Uuid::from_u128(4).to_string(),
            mutation_id: Uuid::from_u128(5).to_string(),
            path,
            content_base64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"content"),
        };
        let typed = input.into_typed()?;
        assert_eq!(
            typed.scope.path.as_path().as_os_str().as_bytes(),
            path_bytes
        );
        assert_eq!(typed.content.as_deref(), Some(b"content".as_slice()));

        let traversal = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"../outside");
        assert_eq!(
            decode_relative_path(&traversal),
            Err(WireValidationError::InvalidPath)
        );
        let padded = format!(
            "{}=",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"file")
        );
        assert_eq!(
            decode_relative_path(&padded),
            Err(WireValidationError::InvalidPath)
        );
        let oversized = vec![0_u8; forge_workspace::MAX_FILE_WRITE_BYTES + 1];
        assert_eq!(
            decode_content(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(oversized)),
            Err(WireValidationError::InvalidContent)
        );
        let hash = FileContentHash::from_bytes([0xab; FileContentHash::BYTE_LEN]).to_string();
        assert!(parse_content_hash(&hash).is_ok());
        assert_eq!(
            parse_content_hash(&hash.to_uppercase()),
            Err(WireValidationError::InvalidHash)
        );
        let unknown = json!({
            "location_id": location(), "expected_revision": 1,
            "workspace_id": Uuid::from_u128(2).to_string(), "workspace_revision": 1,
            "locator": locator()?, "activity_id": Uuid::from_u128(3).to_string(),
            "path": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"file"),
            "unexpected": true
        });
        assert!(serde_json::from_value::<FileReadInput>(unknown).is_err());
        Ok(())
    }

    #[test]
    fn diff_dtos_are_scope_bound_and_list_limits_are_strict()
    -> Result<(), Box<dyn std::error::Error>> {
        let diff_id = Uuid::from_u128(9).to_string();
        let read = DiffReadInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            diff_id: diff_id.clone(),
        }
        .into_typed()?;
        assert_eq!(read.diff_id.to_string(), diff_id);
        let list = DiffListInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            activity_id: Uuid::from_u128(3).to_string(),
            limit: MAX_DIFF_LIST_RESULTS,
        }
        .into_typed()?;
        assert_eq!(list.limit.get(), MAX_DIFF_LIST_RESULTS);
        let oversized = DiffListInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            activity_id: Uuid::from_u128(3).to_string(),
            limit: MAX_DIFF_LIST_RESULTS + 1,
        };
        assert!(matches!(
            oversized.into_typed(),
            Err(WireValidationError::InvalidNumber)
        ));
        let retention = DiffRetentionPlanInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            keep_recent: 0,
            limit: 256,
        }
        .into_typed()?;
        assert_eq!(retention.keep_recent.get(), 0);
        assert_eq!(retention.limit.get(), 256);
        let artifact_doctor = DiffArtifactDoctorInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            limit: MAX_DIFF_ARTIFACT_DOCTOR_RESULTS + 1,
        };
        assert!(matches!(
            artifact_doctor.into_typed(),
            Err(WireValidationError::InvalidNumber)
        ));
        Ok(())
    }

    #[test]
    fn signal_projection_is_typed_bounded_and_orderable() -> Result<(), Box<dyn std::error::Error>>
    {
        let signals = WorkspaceSignalsOutput {
            present: vec![
                WorkspaceSignalWire::CargoWorkspace,
                WorkspaceSignalWire::GitRepository,
                WorkspaceSignalWire::AgentInstructions,
                WorkspaceSignalWire::ForgeState,
            ],
        };
        assert_eq!(
            serde_json::to_value(&signals)?,
            json!({
                "present": [
                    "cargo_workspace",
                    "git_repository",
                    "agent_instructions",
                    "forge_state"
                ]
            })
        );
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(WorkspaceSignalsOutput))?;
        assert_eq!(schema["properties"]["present"]["maxItems"], json!(4));
        Ok(())
    }
}
