//! Bounded, strict MCP wire DTOs and conversions.

use std::collections::BTreeMap;
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
    ActivityId, ActivityLeaseProjection, ActivityProjection, ActivityState, AgentAttachmentState,
    AgentContextProjection, AgentDagAuthoringGrant, AgentDagAuthoringGrantAvailability,
    AgentDagAuthoringGrantId, AgentDagAuthoringGrantRevision, AgentDagDraft,
    AgentDagReplanRequestId, AgentDeclaredRole, AgentDisplayName, AgentFocus, AgentFocusEvent,
    AgentFocusEventKind, AgentFocusNode, AgentInstanceId, AgentInstanceRevision, AgentListLimit,
    AgentTransportKind, AgentWorkPhase, AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateId,
    AgentWorkUpdateSequence, ChangeSetId, DagAcceptanceCriterion, DagEdge, DagLineageKind,
    DagNodeDefinition, DagNodeId, DagNodeLifecycle, DagNodeLineage, DagNodeObjective,
    DagNodeOrdinal, DagNodeRevision, DagNodeStatus, DagNodeTitle, DagRevision, DagRevisionId,
    DagRevisionNumber, DiffArtifactHealth, DiffArtifactInventoryKind, DiffArtifactInventoryLimit,
    DiffChangeKind, DiffEvidenceState, DiffId, DiffListLimit, DiffPayloadProjection,
    DiffRenderKind, DiffRetentionKeepCount, DiffRetentionPlanLimit, ExecutionId, FileContentHash,
    FileMutationId, FileMutationKind, FilePathState, GoalAttribution, GoalEvidenceRef, GoalId,
    GoalListLimit, GoalRevision, GoalStatus, GoalVerificationRequirement, LocationId,
    LocationRevision, RegisteredActivity, RegisteredDagNode, RegisteredDiffEvidence,
    RegisteredGoal, TimestampMillis, WorkspaceId, WorkspaceRelativePath, WorkspaceRevision,
};
use forge_persistence::{AgentDagReplanCommitResult, StoredDagRevision};
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
/// Larger but still HTTP-body-bounded envelope for a full immutable DAG draft.
pub(crate) const MAX_DAG_REPLAN_ARGUMENT_BYTES: usize = 60 * 1024;
/// Recursive JSON node ceiling for the full DAG-draft envelope.
pub(crate) const MAX_DAG_REPLAN_ARGUMENT_TREE_NODES: usize = 4_096;
/// Collection ceiling for the largest supported DAG edge/lineage arrays.
pub(crate) const MAX_DAG_REPLAN_COLLECTION_VALUES: usize = 512;
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

/// Strict input for `agent_attach`.  The Agent instance id and transport kind
/// are intentionally absent: Forge allocates the instance identity and the
/// MCP boundary derives transport kind from the actual stdio/HTTP adapter.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentAttachInput {
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
    #[schemars(length(min = 1, max = 128))]
    pub display_name: String,
    #[schemars(length(min = 1, max = 128))]
    pub declared_role: String,
}

/// Strict input for `agent_set_focus`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentSetFocusInput {
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
    pub agent_id: String,
    #[schemars(range(min = 1))]
    pub expected_agent_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub goal_id: Option<String>,
    #[schemars(range(min = 1))]
    pub goal_revision: Option<i64>,
    #[schemars(range(min = 1))]
    pub dag_revision: Option<i64>,
    #[schemars(length(min = 1, max = 64))]
    pub node_id: Option<String>,
    #[schemars(range(min = 1))]
    pub node_revision: Option<i64>,
}

/// Public evidence reference accepted by `agent_publish_work`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentEvidenceRefInput {
    pub kind: AgentEvidenceKindWire,
    #[schemars(length(min = 1, max = 64))]
    pub id: String,
}

/// Evidence categories that can be named by a public Agent update.  Payloads
/// such as command arguments, prompts, and raw transcripts are not modeled.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentEvidenceKindWire {
    ChangeSet,
    Execution,
    Approval,
    Checkpoint,
}

/// Strict input for `agent_publish_work`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentPublishWorkInput {
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
    pub agent_id: String,
    /// Caller-owned stable identity. Reusing the exact request after a lost
    /// response converges to the existing durable update.
    #[schemars(length(min = 1, max = 64))]
    pub update_id: String,
    #[schemars(range(min = 1))]
    pub sequence: i64,
    pub phase: AgentWorkPhaseWire,
    #[schemars(length(min = 1, max = 2048))]
    pub summary: String,
    #[schemars(length(max = 32))]
    pub evidence_refs: Vec<AgentEvidenceRefInput>,
    /// Caller-observed timestamp is part of the stable retry identity.
    #[schemars(range(min = 0))]
    pub observed_at_ms: i64,
}

/// Strict input for `agent_get_context`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentGetContextInput {
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
    pub agent_id: String,
    #[schemars(range(min = 1, max = 256))]
    pub focus_event_limit: u32,
    #[schemars(range(min = 1, max = 256))]
    pub work_update_limit: u32,
}

/// Strict input for `agent_detach`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentDetachInput {
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
    pub agent_id: String,
    #[schemars(range(min = 1))]
    pub expected_agent_revision: i64,
}

/// Strict input for `goal_list`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GoalListInput {
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
    #[schemars(range(min = 1, max = 100))]
    pub limit: u32,
}

/// Strict input for `goal_get`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GoalGetInput {
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
    pub goal_id: String,
}

/// Strict input for read-only `dag_get_current`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagGetCurrentInput {
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
    pub goal_id: String,
}

/// Discover the currently available one-shot grant for the authenticated
/// Agent and exact Goal/DAG head. No credential or unrelated grant is exposed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagAuthoringGrantDiscoverInput {
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
    pub agent_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub goal_id: String,
    #[schemars(range(min = 1))]
    pub goal_revision: i64,
    #[schemars(range(min = 1))]
    pub dag_revision: i64,
    #[schemars(range(min = 1))]
    pub head_revision: i64,
    #[schemars(range(min = 0))]
    pub observed_at_ms: i64,
}

/// One bounded DAG node definition in a successor revision draft. New
/// revision nodes always begin pending; execution lifecycle is not writable
/// through the replan surface.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagReplanNodeInput {
    #[schemars(length(min = 1, max = 64))]
    pub node_id: String,
    #[schemars(range(min = 0, max = 127))]
    pub ordinal: u16,
    #[schemars(length(min = 1, max = 256))]
    pub title: String,
    #[schemars(length(min = 1, max = 2048))]
    pub objective: String,
    #[schemars(length(min = 1, max = 32))]
    pub acceptance: Vec<String>,
    pub lifecycle: DagReplanNodeLifecycleInput,
}

/// Replan nodes are either new pending work or an exact immutable carry of a
/// completed parent node. Persistence compares every completed carry field to
/// the parent revision, so callers cannot forge or rewrite completed work.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DagReplanNodeLifecycleInput {
    Pending,
    Completed {
        #[schemars(range(min = 0))]
        created_at_ms: i64,
        #[schemars(range(min = 0))]
        updated_at_ms: i64,
        #[schemars(range(min = 1))]
        node_revision: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagReplanEdgeInput {
    #[schemars(length(min = 1, max = 64))]
    pub upstream: String,
    #[schemars(length(min = 1, max = 64))]
    pub downstream: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DagLineageKindWire {
    Split,
    Replace,
    Merge,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagReplanLineageInput {
    #[schemars(length(min = 1, max = 64))]
    pub prior_node_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub successor_node_id: String,
    pub kind: DagLineageKindWire,
}

/// Full immutable successor DAG. The parent must be the grant's exact head;
/// persistence validates that contract again in the commit transaction.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagReplanDraftInput {
    #[schemars(length(min = 1, max = 64))]
    pub revision_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub goal_id: String,
    #[schemars(range(min = 1))]
    pub goal_revision: i64,
    #[schemars(range(min = 2))]
    pub dag_revision: i64,
    #[schemars(range(min = 1))]
    pub parent_revision: i64,
    #[schemars(length(min = 1, max = 128))]
    pub nodes: Vec<DagReplanNodeInput>,
    #[schemars(length(max = 512))]
    pub edges: Vec<DagReplanEdgeInput>,
    #[schemars(length(max = 512))]
    pub lineage: Vec<DagReplanLineageInput>,
}

/// Strict one-shot input for `dag_replan_commit`. Credential identity and
/// Workspace scope are derived/verified by the transport and control plane.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagReplanCommitInput {
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
    pub agent_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub grant_id: String,
    #[schemars(range(min = 1))]
    pub expected_grant_revision: i64,
    #[schemars(length(min = 1, max = 64))]
    pub request_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub history_update_id: String,
    #[schemars(range(min = 1))]
    pub history_update_sequence: i64,
    #[schemars(range(min = 0))]
    pub observed_at_ms: i64,
    pub draft: DagReplanDraftInput,
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

/// Transport kind exposed for an attached Agent.  The MCP adapter only
/// creates `Stdio` or `StreamableHttp` records; descriptive metadata never
/// grants authority.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentTransportKindWire {
    Stdio,
    StreamableHttp,
    Mcp,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentAttachmentStateWire {
    Attached,
    Detached,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentWorkPhaseWire {
    Planning,
    Executing,
    Waiting,
    Verifying,
    Completed,
    Blocked,
    Failed,
}

impl AgentWorkPhaseWire {
    pub(crate) const fn into_domain(self) -> AgentWorkPhase {
        match self {
            Self::Planning => AgentWorkPhase::Planning,
            Self::Executing => AgentWorkPhase::Executing,
            Self::Waiting => AgentWorkPhase::Waiting,
            Self::Verifying => AgentWorkPhase::Verifying,
            Self::Completed => AgentWorkPhase::Completed,
            Self::Blocked => AgentWorkPhase::Blocked,
            Self::Failed => AgentWorkPhase::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentFocusEventKindWire {
    Attached,
    Changed,
    Detached,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentGoalFocusOutput {
    pub goal_id: String,
    pub expected_revision: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentNodeFocusOutput {
    pub node_id: String,
    pub expected_revision: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentFocusOutput {
    pub goal: Option<AgentGoalFocusOutput>,
    pub dag_revision: Option<i64>,
    pub node: Option<AgentNodeFocusOutput>,
}

/// Public metadata projection for one Agent instance.  No prompts,
/// transcripts, tool arguments, or private reasoning are representable.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentAttachmentOutput {
    pub agent_id: String,
    pub workspace_id: String,
    pub activity_id: String,
    pub display_name: String,
    pub declared_role: String,
    pub transport_kind: AgentTransportKindWire,
    pub attachment_state: AgentAttachmentStateWire,
    pub revision: i64,
    pub focus: AgentFocusOutput,
    pub activity: Option<ActivityOutput>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentEvidenceRefOutput {
    pub kind: AgentEvidenceKindWire,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentWorkOutput {
    pub update_id: String,
    pub agent_id: String,
    pub workspace_id: String,
    pub activity_id: String,
    pub sequence: i64,
    pub phase: AgentWorkPhaseWire,
    pub summary: String,
    #[schemars(length(max = 32))]
    pub evidence_refs: Vec<AgentEvidenceRefOutput>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentFocusEventOutput {
    pub agent_id: String,
    pub activity_id: String,
    pub sequence: i64,
    pub kind: AgentFocusEventKindWire,
    pub focus: AgentFocusOutput,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentContextOutput {
    pub attachment: AgentAttachmentOutput,
    #[schemars(length(max = 256))]
    pub focus_events: Vec<AgentFocusEventOutput>,
    #[schemars(length(max = 256))]
    pub work_updates: Vec<AgentWorkOutput>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GoalStatusOutput {
    pub kind: GoalStatusKindWire,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GoalStatusKindWire {
    Active,
    Paused,
    Blocked,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GoalVerificationKindWire {
    ExecutionSucceeded,
    FilePresent,
    ChangeSetSealed,
    CheckpointReady,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GoalVerificationOutput {
    pub kind: GoalVerificationKindWire,
    pub description: String,
}

/// Bounded public Goal summary.  Verification payloads are intentionally
/// reduced to kind/description and do not expose raw digests or prompts.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GoalOutput {
    pub goal_id: String,
    pub workspace_id: String,
    pub revision: i64,
    pub status: GoalStatusOutput,
    pub objective: String,
    #[schemars(length(max = 32))]
    pub success_criteria: Vec<String>,
    #[schemars(length(max = 32))]
    pub constraints: Vec<String>,
    #[schemars(length(max = 32))]
    pub out_of_scope: Vec<String>,
    #[schemars(length(max = 32))]
    pub verification_requirements: Vec<GoalVerificationOutput>,
    #[schemars(length(max = 32))]
    pub stop_conditions: Vec<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GoalListOutput {
    #[schemars(length(max = 100))]
    pub goals: Vec<GoalOutput>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagEdgeOutput {
    pub upstream: String,
    pub downstream: String,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DagNodeLifecycleWire {
    Pending,
    Active,
    Blocked,
    Completed,
    Failed,
    Skipped,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DagNodeStatusWire {
    Pending,
    Ready,
    Active,
    Blocked,
    Completed,
    Failed,
    Skipped,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagNodeOutput {
    pub node_id: String,
    pub ordinal: u16,
    pub title: String,
    pub objective: String,
    #[schemars(length(max = 32))]
    pub acceptance: Vec<String>,
    pub lifecycle: DagNodeLifecycleWire,
    pub status: DagNodeStatusWire,
    #[schemars(length(max = 128))]
    pub waiting_on: Vec<String>,
    pub revision: i64,
    pub evidence_count: u16,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Read-only current DAG projection for one explicit Goal.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagCurrentOutput {
    pub goal_id: String,
    pub revision_id: String,
    pub base_goal_revision: i64,
    pub dag_revision: i64,
    pub parent_revision: Option<i64>,
    pub created_at_ms: i64,
    pub head_revision: i64,
    pub head_updated_at_ms: i64,
    #[schemars(length(max = 128))]
    pub nodes: Vec<DagNodeOutput>,
    #[schemars(length(max = 512))]
    pub edges: Vec<DagEdgeOutput>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DagAuthoringGrantAvailabilityWire {
    Available,
    Expired,
    Consumed,
    Revoked,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagAuthoringGrantOutput {
    pub grant_id: String,
    pub grant_revision: i64,
    pub agent_id: String,
    pub activity_id: String,
    pub goal_id: String,
    pub goal_revision: i64,
    pub expected_dag_revision: i64,
    pub expected_head_revision: i64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub availability: DagAuthoringGrantAvailabilityWire,
}

/// Receipt plus the exact newly-current DAG projection. Exact retries return
/// the same receipt with `replayed = true` and do not consume another grant.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DagReplanCommitOutput {
    pub request_id: String,
    pub grant_id: String,
    pub draft_digest: String,
    pub committed_dag_revision_id: String,
    pub committed_dag_revision: i64,
    pub committed_at_ms: i64,
    pub replayed: bool,
    pub dag: DagCurrentOutput,
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
    #[error("tool argument contains invalid Agent focus fields")]
    InvalidFocus,
    #[error("tool argument contains invalid Agent metadata")]
    InvalidMetadata,
    #[error("tool argument contains invalid Agent public summary")]
    InvalidSummary,
    #[error("tool result contains an invalid persisted projection")]
    InvalidProjection,
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

#[derive(Debug, Clone)]
pub(crate) struct AgentScopeTyped {
    pub(crate) location_id: LocationId,
    pub(crate) location_revision: LocationRevision,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) workspace_revision: WorkspaceRevision,
    pub(crate) locator: WorkspaceLocator,
    pub(crate) activity_id: ActivityId,
}

#[derive(Debug)]
pub(crate) struct AgentAttachTyped {
    pub(crate) scope: AgentScopeTyped,
    pub(crate) display_name: AgentDisplayName,
    pub(crate) declared_role: AgentDeclaredRole,
}

#[derive(Debug)]
pub(crate) struct AgentSetFocusTyped {
    pub(crate) scope: AgentScopeTyped,
    pub(crate) agent_id: AgentInstanceId,
    pub(crate) expected_revision: AgentInstanceRevision,
    pub(crate) focus: AgentFocus,
}

#[derive(Debug)]
pub(crate) struct AgentPublishWorkTyped {
    pub(crate) scope: AgentScopeTyped,
    pub(crate) agent_id: AgentInstanceId,
    pub(crate) update_id: AgentWorkUpdateId,
    pub(crate) sequence: AgentWorkUpdateSequence,
    pub(crate) phase: AgentWorkPhase,
    pub(crate) summary: AgentWorkSummary,
    pub(crate) evidence_refs: Vec<GoalEvidenceRef>,
    pub(crate) observed_at: TimestampMillis,
}

#[derive(Debug)]
pub(crate) struct AgentGetContextTyped {
    pub(crate) scope: AgentScopeTyped,
    pub(crate) agent_id: AgentInstanceId,
    pub(crate) focus_event_limit: AgentListLimit,
    pub(crate) work_update_limit: AgentListLimit,
}

#[derive(Debug)]
pub(crate) struct AgentDetachTyped {
    pub(crate) scope: AgentScopeTyped,
    pub(crate) agent_id: AgentInstanceId,
    pub(crate) expected_revision: AgentInstanceRevision,
}

#[derive(Debug, Clone)]
pub(crate) struct GoalScopeTyped {
    pub(crate) location_id: LocationId,
    pub(crate) location_revision: LocationRevision,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) workspace_revision: WorkspaceRevision,
    pub(crate) locator: WorkspaceLocator,
}

#[derive(Debug)]
pub(crate) struct GoalListTyped {
    pub(crate) scope: GoalScopeTyped,
    pub(crate) limit: GoalListLimit,
}

#[derive(Debug)]
pub(crate) struct GoalIdentityTyped {
    pub(crate) scope: GoalScopeTyped,
    pub(crate) goal_id: GoalId,
}

#[derive(Debug)]
pub(crate) struct DagAuthoringGrantDiscoverTyped {
    pub(crate) scope: AgentScopeTyped,
    pub(crate) agent_id: AgentInstanceId,
    pub(crate) goal: GoalAttribution,
    pub(crate) expected_dag_revision: DagRevisionNumber,
    pub(crate) expected_head_revision: forge_domain::DagHeadRevision,
    pub(crate) observed_at: TimestampMillis,
}

#[derive(Debug)]
pub(crate) struct DagReplanCommitTyped {
    pub(crate) scope: AgentScopeTyped,
    pub(crate) agent_id: AgentInstanceId,
    pub(crate) grant_id: AgentDagAuthoringGrantId,
    pub(crate) expected_grant_revision: AgentDagAuthoringGrantRevision,
    pub(crate) request_id: AgentDagReplanRequestId,
    pub(crate) history_update_id: AgentWorkUpdateId,
    pub(crate) history_update_sequence: AgentWorkUpdateSequence,
    pub(crate) observed_at: TimestampMillis,
    pub(crate) draft: AgentDagDraft,
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

impl AgentAttachInput {
    pub(crate) fn into_typed(self) -> Result<AgentAttachTyped, WireValidationError> {
        let scope = parse_agent_scope(
            &self.location_id,
            self.expected_revision,
            &self.workspace_id,
            self.workspace_revision,
            &self.locator,
            &self.activity_id,
        )?;
        Ok(AgentAttachTyped {
            scope,
            display_name: AgentDisplayName::new(self.display_name)
                .map_err(|_| WireValidationError::InvalidMetadata)?,
            declared_role: AgentDeclaredRole::new(self.declared_role)
                .map_err(|_| WireValidationError::InvalidMetadata)?,
        })
    }
}

impl AgentSetFocusInput {
    pub(crate) fn into_typed(self) -> Result<AgentSetFocusTyped, WireValidationError> {
        let scope = parse_agent_scope(
            &self.location_id,
            self.expected_revision,
            &self.workspace_id,
            self.workspace_revision,
            &self.locator,
            &self.activity_id,
        )?;
        Ok(AgentSetFocusTyped {
            scope,
            agent_id: parse_agent_id(&self.agent_id)?,
            expected_revision: AgentInstanceRevision::new(self.expected_agent_revision)
                .map_err(|_| WireValidationError::InvalidNumber)?,
            focus: parse_agent_focus(
                self.goal_id.as_deref(),
                self.goal_revision,
                self.dag_revision,
                self.node_id.as_deref(),
                self.node_revision,
            )?,
        })
    }
}

impl AgentPublishWorkInput {
    pub(crate) fn into_typed(self) -> Result<AgentPublishWorkTyped, WireValidationError> {
        let scope = parse_agent_scope(
            &self.location_id,
            self.expected_revision,
            &self.workspace_id,
            self.workspace_revision,
            &self.locator,
            &self.activity_id,
        )?;
        let evidence_refs = self
            .evidence_refs
            .iter()
            .map(parse_agent_evidence_ref)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AgentPublishWorkTyped {
            scope,
            agent_id: parse_agent_id(&self.agent_id)?,
            update_id: parse_agent_work_update_id(&self.update_id)?,
            sequence: AgentWorkUpdateSequence::new(self.sequence)
                .map_err(|_| WireValidationError::InvalidNumber)?,
            phase: self.phase.into_domain(),
            summary: AgentWorkSummary::new(self.summary)
                .map_err(|_| WireValidationError::InvalidSummary)?,
            evidence_refs,
            observed_at: TimestampMillis::new(self.observed_at_ms)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

impl AgentGetContextInput {
    pub(crate) fn into_typed(self) -> Result<AgentGetContextTyped, WireValidationError> {
        let scope = parse_agent_scope(
            &self.location_id,
            self.expected_revision,
            &self.workspace_id,
            self.workspace_revision,
            &self.locator,
            &self.activity_id,
        )?;
        Ok(AgentGetContextTyped {
            scope,
            agent_id: parse_agent_id(&self.agent_id)?,
            focus_event_limit: AgentListLimit::new(self.focus_event_limit)
                .map_err(|_| WireValidationError::InvalidNumber)?,
            work_update_limit: AgentListLimit::new(self.work_update_limit)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

impl AgentDetachInput {
    pub(crate) fn into_typed(self) -> Result<AgentDetachTyped, WireValidationError> {
        let scope = parse_agent_scope(
            &self.location_id,
            self.expected_revision,
            &self.workspace_id,
            self.workspace_revision,
            &self.locator,
            &self.activity_id,
        )?;
        Ok(AgentDetachTyped {
            scope,
            agent_id: parse_agent_id(&self.agent_id)?,
            expected_revision: AgentInstanceRevision::new(self.expected_agent_revision)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

impl GoalListInput {
    pub(crate) fn into_typed(self) -> Result<GoalListTyped, WireValidationError> {
        Ok(GoalListTyped {
            scope: parse_goal_scope(
                &self.location_id,
                self.expected_revision,
                &self.workspace_id,
                self.workspace_revision,
                &self.locator,
            )?,
            limit: GoalListLimit::new(self.limit)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

impl GoalGetInput {
    pub(crate) fn into_typed(self) -> Result<GoalIdentityTyped, WireValidationError> {
        Ok(GoalIdentityTyped {
            scope: parse_goal_scope(
                &self.location_id,
                self.expected_revision,
                &self.workspace_id,
                self.workspace_revision,
                &self.locator,
            )?,
            goal_id: parse_goal_id(&self.goal_id)?,
        })
    }
}

impl DagGetCurrentInput {
    pub(crate) fn into_typed(self) -> Result<GoalIdentityTyped, WireValidationError> {
        Ok(GoalIdentityTyped {
            scope: parse_goal_scope(
                &self.location_id,
                self.expected_revision,
                &self.workspace_id,
                self.workspace_revision,
                &self.locator,
            )?,
            goal_id: parse_goal_id(&self.goal_id)?,
        })
    }
}

impl DagAuthoringGrantDiscoverInput {
    pub(crate) fn into_typed(self) -> Result<DagAuthoringGrantDiscoverTyped, WireValidationError> {
        Ok(DagAuthoringGrantDiscoverTyped {
            scope: parse_agent_scope(
                &self.location_id,
                self.expected_revision,
                &self.workspace_id,
                self.workspace_revision,
                &self.locator,
                &self.activity_id,
            )?,
            agent_id: parse_agent_id(&self.agent_id)?,
            goal: GoalAttribution::new(
                parse_goal_id(&self.goal_id)?,
                GoalRevision::new(self.goal_revision)
                    .map_err(|_| WireValidationError::InvalidNumber)?,
            ),
            expected_dag_revision: DagRevisionNumber::new(self.dag_revision)
                .map_err(|_| WireValidationError::InvalidNumber)?,
            expected_head_revision: forge_domain::DagHeadRevision::new(self.head_revision)
                .map_err(|_| WireValidationError::InvalidNumber)?,
            observed_at: TimestampMillis::new(self.observed_at_ms)
                .map_err(|_| WireValidationError::InvalidNumber)?,
        })
    }
}

impl DagReplanCommitInput {
    pub(crate) fn into_typed(self) -> Result<DagReplanCommitTyped, WireValidationError> {
        let scope = parse_agent_scope(
            &self.location_id,
            self.expected_revision,
            &self.workspace_id,
            self.workspace_revision,
            &self.locator,
            &self.activity_id,
        )?;
        let observed_at = TimestampMillis::new(self.observed_at_ms)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let draft = self.draft.into_typed(observed_at)?;
        Ok(DagReplanCommitTyped {
            scope,
            agent_id: parse_agent_id(&self.agent_id)?,
            grant_id: parse_agent_dag_grant_id(&self.grant_id)?,
            expected_grant_revision: AgentDagAuthoringGrantRevision::new(
                self.expected_grant_revision,
            )
            .map_err(|_| WireValidationError::InvalidNumber)?,
            request_id: parse_agent_dag_replan_request_id(&self.request_id)?,
            history_update_id: parse_agent_work_update_id(&self.history_update_id)?,
            history_update_sequence: AgentWorkUpdateSequence::new(self.history_update_sequence)
                .map_err(|_| WireValidationError::InvalidNumber)?,
            observed_at,
            draft,
        })
    }
}

impl DagReplanDraftInput {
    fn into_typed(
        self,
        observed_at: TimestampMillis,
    ) -> Result<AgentDagDraft, WireValidationError> {
        let goal_id = parse_goal_id(&self.goal_id)?;
        let goal_revision = GoalRevision::new(self.goal_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let dag_revision = DagRevisionNumber::new(self.dag_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let parent_revision = DagRevisionNumber::new(self.parent_revision)
            .map_err(|_| WireValidationError::InvalidNumber)?;
        let mut definitions = Vec::with_capacity(self.nodes.len());
        let mut lifecycles = BTreeMap::new();
        for node in self.nodes {
            let (definition, lifecycle) = parse_replan_node(node)?;
            if lifecycles.insert(definition.id(), lifecycle).is_some() {
                return Err(WireValidationError::Shape);
            }
            definitions.push(definition);
        }
        let edges = self
            .edges
            .into_iter()
            .map(|edge| {
                Ok(DagEdge::new(
                    parse_dag_node_id(&edge.upstream)?,
                    parse_dag_node_id(&edge.downstream)?,
                ))
            })
            .collect::<Result<Vec<_>, WireValidationError>>()?;
        let lineage = self
            .lineage
            .into_iter()
            .map(|item| {
                Ok(DagNodeLineage::new(
                    parse_dag_node_id(&item.prior_node_id)?,
                    parse_dag_node_id(&item.successor_node_id)?,
                    match item.kind {
                        DagLineageKindWire::Split => DagLineageKind::Split,
                        DagLineageKindWire::Replace => DagLineageKind::Replace,
                        DagLineageKindWire::Merge => DagLineageKind::Merge,
                    },
                ))
            })
            .collect::<Result<Vec<_>, WireValidationError>>()?;
        let revision = DagRevision::new(
            parse_dag_revision_id(&self.revision_id)?,
            goal_id,
            goal_revision,
            dag_revision,
            Some(parent_revision),
            definitions,
            edges,
            observed_at,
        )
        .map_err(|_| WireValidationError::Shape)?;
        let nodes = revision
            .nodes()
            .iter()
            .cloned()
            .map(|definition| {
                let lifecycle = lifecycles
                    .remove(&definition.id())
                    .ok_or(WireValidationError::Shape)?;
                match lifecycle {
                    DagReplanNodeLifecycleInput::Pending => Ok(RegisteredDagNode::create(
                        goal_id,
                        dag_revision,
                        definition,
                        observed_at,
                    )),
                    DagReplanNodeLifecycleInput::Completed {
                        created_at_ms,
                        updated_at_ms,
                        node_revision,
                    } => RegisteredDagNode::from_parts(
                        goal_id,
                        dag_revision,
                        definition,
                        DagNodeLifecycle::Completed,
                        TimestampMillis::new(created_at_ms)
                            .map_err(|_| WireValidationError::InvalidNumber)?,
                        TimestampMillis::new(updated_at_ms)
                            .map_err(|_| WireValidationError::InvalidNumber)?,
                        DagNodeRevision::new(node_revision)
                            .map_err(|_| WireValidationError::InvalidNumber)?,
                    )
                    .map_err(|_| WireValidationError::Shape),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        AgentDagDraft::new(revision, nodes, lineage).map_err(|_| WireValidationError::Shape)
    }
}

fn parse_replan_node(
    node: DagReplanNodeInput,
) -> Result<(DagNodeDefinition, DagReplanNodeLifecycleInput), WireValidationError> {
    let acceptance = node
        .acceptance
        .into_iter()
        .map(|criterion| {
            DagAcceptanceCriterion::new(criterion).map_err(|_| WireValidationError::InvalidMetadata)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let definition = DagNodeDefinition::new(
        parse_dag_node_id(&node.node_id)?,
        DagNodeOrdinal::new(node.ordinal).map_err(|_| WireValidationError::InvalidNumber)?,
        DagNodeTitle::new(node.title).map_err(|_| WireValidationError::InvalidMetadata)?,
        DagNodeObjective::new(node.objective).map_err(|_| WireValidationError::InvalidMetadata)?,
        acceptance,
    )
    .map_err(|_| WireValidationError::Shape)?;
    Ok((definition, node.lifecycle))
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

fn parse_agent_scope(
    location_id: &str,
    expected_revision: i64,
    workspace_id: &str,
    workspace_revision: i64,
    locator: &str,
    activity_id: &str,
) -> Result<AgentScopeTyped, WireValidationError> {
    let location_id_value = parse_location_id(location_id)?;
    let location_revision_value =
        LocationRevision::new(expected_revision).map_err(|_| WireValidationError::InvalidNumber)?;
    let workspace_id_value = parse_workspace_id(workspace_id)?;
    let workspace_revision_value = WorkspaceRevision::new(workspace_revision)
        .map_err(|_| WireValidationError::InvalidNumber)?;
    let locator_value = decode_locator(locator)?;
    if locator_value.location_id() != location_id_value
        || locator_value.expected_revision() != location_revision_value
    {
        return Err(WireValidationError::MismatchedLocator);
    }
    Ok(AgentScopeTyped {
        location_id: location_id_value,
        location_revision: location_revision_value,
        workspace_id: workspace_id_value,
        workspace_revision: workspace_revision_value,
        locator: locator_value,
        activity_id: parse_activity_id(activity_id)?,
    })
}

fn parse_goal_scope(
    location_id: &str,
    expected_revision: i64,
    workspace_id: &str,
    workspace_revision: i64,
    locator: &str,
) -> Result<GoalScopeTyped, WireValidationError> {
    let location_id_value = parse_location_id(location_id)?;
    let location_revision_value =
        LocationRevision::new(expected_revision).map_err(|_| WireValidationError::InvalidNumber)?;
    let workspace_id_value = parse_workspace_id(workspace_id)?;
    let workspace_revision_value = WorkspaceRevision::new(workspace_revision)
        .map_err(|_| WireValidationError::InvalidNumber)?;
    let locator_value = decode_locator(locator)?;
    if locator_value.location_id() != location_id_value
        || locator_value.expected_revision() != location_revision_value
    {
        return Err(WireValidationError::MismatchedLocator);
    }
    Ok(GoalScopeTyped {
        location_id: location_id_value,
        location_revision: location_revision_value,
        workspace_id: workspace_id_value,
        workspace_revision: workspace_revision_value,
        locator: locator_value,
    })
}

fn parse_agent_focus(
    goal_id: Option<&str>,
    goal_revision: Option<i64>,
    dag_revision: Option<i64>,
    node_id: Option<&str>,
    node_revision: Option<i64>,
) -> Result<AgentFocus, WireValidationError> {
    let goal = match (goal_id, goal_revision) {
        (Some(goal_id), Some(goal_revision)) => Some(GoalAttribution::new(
            parse_goal_id(goal_id)?,
            GoalRevision::new(goal_revision).map_err(|_| WireValidationError::InvalidNumber)?,
        )),
        (None, None) => None,
        _ => return Err(WireValidationError::InvalidFocus),
    };
    let dag_revision = dag_revision
        .map(|value| DagRevisionNumber::new(value).map_err(|_| WireValidationError::InvalidNumber))
        .transpose()?;
    let node = match (node_id, node_revision) {
        (Some(node_id), Some(node_revision)) => Some(AgentFocusNode::new(
            parse_dag_node_id(node_id)?,
            DagNodeRevision::new(node_revision).map_err(|_| WireValidationError::InvalidNumber)?,
        )),
        (None, None) => None,
        _ => return Err(WireValidationError::InvalidFocus),
    };
    AgentFocus::new(goal, dag_revision, node).map_err(|_| WireValidationError::InvalidFocus)
}

fn parse_agent_evidence_ref(
    value: &AgentEvidenceRefInput,
) -> Result<GoalEvidenceRef, WireValidationError> {
    Ok(match value.kind {
        AgentEvidenceKindWire::ChangeSet => {
            GoalEvidenceRef::ChangeSet(parse_change_set_id(&value.id)?)
        }
        AgentEvidenceKindWire::Execution => {
            GoalEvidenceRef::Execution(parse_execution_id(&value.id)?)
        }
        AgentEvidenceKindWire::Approval => GoalEvidenceRef::Approval(parse_approval_id(&value.id)?),
        AgentEvidenceKindWire::Checkpoint => {
            GoalEvidenceRef::Checkpoint(parse_checkpoint_id(&value.id)?)
        }
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
    parse_arguments_with_limits(
        arguments,
        ArgumentLimits {
            bytes: MAX_ARGUMENT_BYTES,
            nodes: MAX_ARGUMENT_TREE_NODES,
            collection_values: MAX_ARGUMENT_FIELDS,
        },
    )
}

pub(crate) fn parse_dag_replan_arguments<T: for<'de> Deserialize<'de>>(
    arguments: Option<&Map<String, Value>>,
) -> Result<T, WireValidationError> {
    parse_arguments_with_limits(
        arguments,
        ArgumentLimits {
            bytes: MAX_DAG_REPLAN_ARGUMENT_BYTES,
            nodes: MAX_DAG_REPLAN_ARGUMENT_TREE_NODES,
            collection_values: MAX_DAG_REPLAN_COLLECTION_VALUES,
        },
    )
}

#[derive(Clone, Copy)]
struct ArgumentLimits {
    bytes: usize,
    nodes: usize,
    collection_values: usize,
}

fn parse_arguments_with_limits<T: for<'de> Deserialize<'de>>(
    arguments: Option<&Map<String, Value>>,
    limits: ArgumentLimits,
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
        if bytes > limits.bytes {
            return Err(WireValidationError::Oversized);
        }
        bounded_value(value, 0, &mut nodes, &mut bytes, limits)?;
    }
    let value = Value::Object(arguments.clone());
    serde_json::from_value(value).map_err(|_| WireValidationError::Shape)
}

fn bounded_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    bytes: &mut usize,
    limits: ArgumentLimits,
) -> Result<(), WireValidationError> {
    *nodes = nodes.saturating_add(1);
    if *nodes > limits.nodes || depth > 8 {
        return Err(WireValidationError::TooManyValues);
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            *bytes = bytes.saturating_add(8);
            Ok(())
        }
        Value::String(value) => {
            *bytes = bytes.saturating_add(value.len());
            if *bytes > limits.bytes {
                Err(WireValidationError::Oversized)
            } else {
                Ok(())
            }
        }
        Value::Array(values) => {
            if values.len() > limits.collection_values {
                return Err(WireValidationError::TooManyValues);
            }
            for value in values {
                bounded_value(value, depth + 1, nodes, bytes, limits)?;
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
                bounded_value(value, depth + 1, nodes, bytes, limits)?;
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

fn parse_agent_id(value: &str) -> Result<AgentInstanceId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed =
        AgentInstanceId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_agent_work_update_id(value: &str) -> Result<AgentWorkUpdateId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed =
        AgentWorkUpdateId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_agent_dag_grant_id(value: &str) -> Result<AgentDagAuthoringGrantId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = AgentDagAuthoringGrantId::from_str(value)
        .map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_agent_dag_replan_request_id(
    value: &str,
) -> Result<AgentDagReplanRequestId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = AgentDagReplanRequestId::from_str(value)
        .map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_goal_id(value: &str) -> Result<GoalId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = GoalId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_dag_node_id(value: &str) -> Result<DagNodeId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = DagNodeId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_dag_revision_id(value: &str) -> Result<DagRevisionId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed =
        DagRevisionId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_execution_id(value: &str) -> Result<ExecutionId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed =
        ExecutionId::from_str(value).map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_approval_id(value: &str) -> Result<forge_domain::ApprovalRequestId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = forge_domain::ApprovalRequestId::from_str(value)
        .map_err(|_| WireValidationError::InvalidIdentifier)?;
    if parsed.to_string() != value {
        return Err(WireValidationError::InvalidIdentifier);
    }
    Ok(parsed)
}

fn parse_checkpoint_id(value: &str) -> Result<forge_domain::CheckpointId, WireValidationError> {
    bounded_identifier(value)?;
    let parsed = forge_domain::CheckpointId::from_str(value)
        .map_err(|_| WireValidationError::InvalidIdentifier)?;
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

pub(crate) fn agent_attachment_output(
    agent: &forge_domain::RegisteredAgentInstance,
    activity: Option<&ActivityProjection>,
) -> AgentAttachmentOutput {
    AgentAttachmentOutput {
        agent_id: agent.id().to_string(),
        workspace_id: agent.workspace_id().to_string(),
        activity_id: agent.activity_id().to_string(),
        display_name: agent.display_name().as_str().to_owned(),
        declared_role: agent.declared_role().as_str().to_owned(),
        transport_kind: agent_transport_kind(agent.transport_kind()),
        attachment_state: match agent.attachment_state() {
            AgentAttachmentState::Attached => AgentAttachmentStateWire::Attached,
            AgentAttachmentState::Detached => AgentAttachmentStateWire::Detached,
        },
        revision: agent.revision().get(),
        focus: agent_focus_output(agent.focus()),
        activity: activity.map(|projection| activity_output(projection.activity())),
    }
}

pub(crate) fn agent_context_output(result: &AgentContextProjection) -> AgentContextOutput {
    AgentContextOutput {
        attachment: agent_attachment_output(
            result.attachment().agent(),
            Some(result.attachment().activity()),
        ),
        focus_events: result
            .focus_events()
            .iter()
            .map(agent_focus_event_output)
            .collect(),
        work_updates: result
            .work_updates()
            .iter()
            .map(agent_work_output)
            .collect(),
    }
}

fn agent_transport_kind(value: AgentTransportKind) -> AgentTransportKindWire {
    match value {
        AgentTransportKind::Stdio => AgentTransportKindWire::Stdio,
        AgentTransportKind::StreamableHttp => AgentTransportKindWire::StreamableHttp,
        AgentTransportKind::Mcp => AgentTransportKindWire::Mcp,
        AgentTransportKind::Other => AgentTransportKindWire::Other,
    }
}

fn agent_focus_output(value: AgentFocus) -> AgentFocusOutput {
    AgentFocusOutput {
        goal: value.goal().map(|goal| AgentGoalFocusOutput {
            goal_id: goal.goal_id().to_string(),
            expected_revision: goal.expected_revision().get(),
        }),
        dag_revision: value.dag_revision().map(DagRevisionNumber::get),
        node: value.node().map(|node| AgentNodeFocusOutput {
            node_id: node.node_id().to_string(),
            expected_revision: node.expected_revision().get(),
        }),
    }
}

fn agent_focus_event_output(value: &AgentFocusEvent) -> AgentFocusEventOutput {
    AgentFocusEventOutput {
        agent_id: value.agent_id().to_string(),
        activity_id: value.activity_id().to_string(),
        sequence: value.sequence().get(),
        kind: match value.kind() {
            AgentFocusEventKind::Attached => AgentFocusEventKindWire::Attached,
            AgentFocusEventKind::Changed => AgentFocusEventKindWire::Changed,
            AgentFocusEventKind::Detached => AgentFocusEventKindWire::Detached,
        },
        focus: agent_focus_output(value.focus()),
        observed_at_ms: value.observed_at().get(),
    }
}

pub(crate) fn agent_work_output(value: &AgentWorkUpdate) -> AgentWorkOutput {
    AgentWorkOutput {
        update_id: value.id().to_string(),
        agent_id: value.agent_id().to_string(),
        workspace_id: value.workspace_id().to_string(),
        activity_id: value.activity_id().to_string(),
        sequence: value.sequence().get(),
        phase: match value.phase() {
            AgentWorkPhase::Planning => AgentWorkPhaseWire::Planning,
            AgentWorkPhase::Executing => AgentWorkPhaseWire::Executing,
            AgentWorkPhase::Waiting => AgentWorkPhaseWire::Waiting,
            AgentWorkPhase::Verifying => AgentWorkPhaseWire::Verifying,
            AgentWorkPhase::Completed => AgentWorkPhaseWire::Completed,
            AgentWorkPhase::Blocked => AgentWorkPhaseWire::Blocked,
            AgentWorkPhase::Failed => AgentWorkPhaseWire::Failed,
        },
        summary: value.summary().as_str().to_owned(),
        evidence_refs: value
            .evidence_refs()
            .iter()
            .map(agent_evidence_ref_output)
            .collect(),
        observed_at_ms: value.observed_at().get(),
    }
}

fn agent_evidence_ref_output(value: &GoalEvidenceRef) -> AgentEvidenceRefOutput {
    let (kind, id) = match value {
        GoalEvidenceRef::ChangeSet(id) => (AgentEvidenceKindWire::ChangeSet, id.to_string()),
        GoalEvidenceRef::Execution(id) => (AgentEvidenceKindWire::Execution, id.to_string()),
        GoalEvidenceRef::Approval(id) => (AgentEvidenceKindWire::Approval, id.to_string()),
        GoalEvidenceRef::Checkpoint(id) => (AgentEvidenceKindWire::Checkpoint, id.to_string()),
    };
    AgentEvidenceRefOutput { kind, id }
}

pub(crate) fn goal_list_output(values: &[RegisteredGoal]) -> GoalListOutput {
    GoalListOutput {
        goals: values.iter().map(goal_output).collect(),
    }
}

pub(crate) fn goal_output(value: &RegisteredGoal) -> GoalOutput {
    GoalOutput {
        goal_id: value.id().to_string(),
        workspace_id: value.workspace_id().to_string(),
        revision: value.revision().get(),
        status: goal_status_output(value.status()),
        objective: value.contract().objective().as_str().to_owned(),
        success_criteria: value
            .contract()
            .success_criteria()
            .iter()
            .map(|text| text.as_str().to_owned())
            .collect(),
        constraints: value
            .contract()
            .constraints()
            .iter()
            .map(|text| text.as_str().to_owned())
            .collect(),
        out_of_scope: value
            .contract()
            .out_of_scope()
            .iter()
            .map(|text| text.as_str().to_owned())
            .collect(),
        verification_requirements: value
            .contract()
            .verification_requirements()
            .iter()
            .map(goal_verification_output)
            .collect(),
        stop_conditions: value
            .contract()
            .stop_conditions()
            .iter()
            .map(|text| text.as_str().to_owned())
            .collect(),
        created_at_ms: value.timestamps().created_at().get(),
        updated_at_ms: value.timestamps().updated_at().get(),
    }
}

fn goal_status_output(value: &GoalStatus) -> GoalStatusOutput {
    let (kind, reason) = match value {
        GoalStatus::Active => (GoalStatusKindWire::Active, None),
        GoalStatus::Paused => (GoalStatusKindWire::Paused, None),
        GoalStatus::Blocked(blocker) => (
            GoalStatusKindWire::Blocked,
            Some(blocker.reason().as_str().to_owned()),
        ),
        GoalStatus::Completed => (GoalStatusKindWire::Completed, None),
        GoalStatus::Failed(failure) => (
            GoalStatusKindWire::Failed,
            Some(failure.reason().as_str().to_owned()),
        ),
        GoalStatus::Cancelled => (GoalStatusKindWire::Cancelled, None),
    };
    GoalStatusOutput { kind, reason }
}

fn goal_verification_output(value: &GoalVerificationRequirement) -> GoalVerificationOutput {
    let kind = match value {
        GoalVerificationRequirement::ExecutionSucceeded { .. } => {
            GoalVerificationKindWire::ExecutionSucceeded
        }
        GoalVerificationRequirement::FilePresent { .. } => GoalVerificationKindWire::FilePresent,
        GoalVerificationRequirement::ChangeSetSealed { .. } => {
            GoalVerificationKindWire::ChangeSetSealed
        }
        GoalVerificationRequirement::CheckpointReady { .. } => {
            GoalVerificationKindWire::CheckpointReady
        }
    };
    GoalVerificationOutput {
        kind,
        description: value.description().as_str().to_owned(),
    }
}

pub(crate) fn dag_current_output(
    value: &StoredDagRevision,
) -> Result<DagCurrentOutput, WireValidationError> {
    let projections = value
        .revision()
        .project(value.nodes())
        .map_err(|_| WireValidationError::InvalidProjection)?;
    let nodes = value
        .nodes()
        .iter()
        .map(|node| {
            let projection = projections
                .iter()
                .find(|projection| projection.node().id() == node.id())
                .ok_or(WireValidationError::InvalidProjection)?;
            let evidence_count = value
                .evidence()
                .iter()
                .find(|summary| summary.node_id() == node.id())
                .map_or(0, |summary| summary.count());
            Ok(DagNodeOutput {
                node_id: node.id().to_string(),
                ordinal: node.definition().ordinal().get(),
                title: node.definition().title().as_str().to_owned(),
                objective: node.definition().objective().as_str().to_owned(),
                acceptance: node
                    .definition()
                    .acceptance()
                    .iter()
                    .map(|text| text.as_str().to_owned())
                    .collect(),
                lifecycle: dag_node_lifecycle(node.lifecycle()),
                status: dag_node_status(projection.status()),
                waiting_on: projection
                    .waiting_on()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                revision: node.revision().get(),
                evidence_count,
                created_at_ms: node.created_at().get(),
                updated_at_ms: node.updated_at().get(),
            })
        })
        .collect::<Result<Vec<_>, WireValidationError>>()?;
    let edges = value
        .revision()
        .edges()
        .iter()
        .map(|edge| DagEdgeOutput {
            upstream: edge.upstream().to_string(),
            downstream: edge.downstream().to_string(),
        })
        .collect::<Vec<_>>();
    Ok(DagCurrentOutput {
        goal_id: value.revision().goal_id().to_string(),
        revision_id: value.revision().id().to_string(),
        base_goal_revision: value.revision().base_goal_revision().get(),
        dag_revision: value.revision().number().get(),
        parent_revision: value.revision().parent().map(DagRevisionNumber::get),
        created_at_ms: value.revision().created_at().get(),
        head_revision: value.head().revision().get(),
        head_updated_at_ms: value.head().updated_at().get(),
        nodes,
        edges,
    })
}

pub(crate) fn dag_replan_commit_output(
    value: &AgentDagReplanCommitResult,
) -> Result<DagReplanCommitOutput, WireValidationError> {
    let receipt = value.receipt();
    Ok(DagReplanCommitOutput {
        request_id: receipt.request_id().to_string(),
        grant_id: receipt.grant_id().to_string(),
        draft_digest: receipt.digest().to_string(),
        committed_dag_revision_id: receipt.dag_revision_id().to_string(),
        committed_dag_revision: receipt.dag_revision().get(),
        committed_at_ms: receipt.committed_at().get(),
        replayed: receipt.replayed(),
        dag: dag_current_output(value.revision())?,
    })
}

pub(crate) fn dag_authoring_grant_output(
    value: &AgentDagAuthoringGrant,
    now: TimestampMillis,
) -> DagAuthoringGrantOutput {
    let availability = match value.availability(now) {
        AgentDagAuthoringGrantAvailability::Available => {
            DagAuthoringGrantAvailabilityWire::Available
        }
        AgentDagAuthoringGrantAvailability::Expired => DagAuthoringGrantAvailabilityWire::Expired,
        AgentDagAuthoringGrantAvailability::Consumed => DagAuthoringGrantAvailabilityWire::Consumed,
        AgentDagAuthoringGrantAvailability::Revoked => DagAuthoringGrantAvailabilityWire::Revoked,
    };
    DagAuthoringGrantOutput {
        grant_id: value.id().to_string(),
        grant_revision: value.revision().get(),
        agent_id: value.agent_id().to_string(),
        activity_id: value.activity_id().to_string(),
        goal_id: value.goal().goal_id().to_string(),
        goal_revision: value.goal().expected_revision().get(),
        expected_dag_revision: value.expected_dag_revision().get(),
        expected_head_revision: value.expected_head_revision().get(),
        issued_at_ms: value.issued_at().get(),
        expires_at_ms: value.expires_at().get(),
        availability,
    }
}

fn dag_node_lifecycle(value: &DagNodeLifecycle) -> DagNodeLifecycleWire {
    match value {
        DagNodeLifecycle::Pending => DagNodeLifecycleWire::Pending,
        DagNodeLifecycle::Active => DagNodeLifecycleWire::Active,
        DagNodeLifecycle::Blocked(_) => DagNodeLifecycleWire::Blocked,
        DagNodeLifecycle::Completed => DagNodeLifecycleWire::Completed,
        DagNodeLifecycle::Failed(_) => DagNodeLifecycleWire::Failed,
        DagNodeLifecycle::Skipped(_) => DagNodeLifecycleWire::Skipped,
        DagNodeLifecycle::Cancelled => DagNodeLifecycleWire::Cancelled,
    }
}

fn dag_node_status(value: DagNodeStatus) -> DagNodeStatusWire {
    match value {
        DagNodeStatus::Pending => DagNodeStatusWire::Pending,
        DagNodeStatus::Ready => DagNodeStatusWire::Ready,
        DagNodeStatus::Active => DagNodeStatusWire::Active,
        DagNodeStatus::Blocked => DagNodeStatusWire::Blocked,
        DagNodeStatus::Completed => DagNodeStatusWire::Completed,
        DagNodeStatus::Failed => DagNodeStatusWire::Failed,
        DagNodeStatus::Skipped => DagNodeStatusWire::Skipped,
        DagNodeStatus::Cancelled => DagNodeStatusWire::Cancelled,
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
    #[allow(clippy::too_many_lines)]
    fn agent_goal_and_dag_inputs_are_strict_and_typed() -> Result<(), Box<dyn std::error::Error>> {
        let agent = AgentAttachInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            activity_id: Uuid::from_u128(3).to_string(),
            display_name: "Planner".to_owned(),
            declared_role: "planner".to_owned(),
        }
        .into_typed()?;
        assert_eq!(agent.display_name.as_str(), "Planner");
        assert_eq!(agent.declared_role.as_str(), "planner");

        let focus = AgentSetFocusInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            activity_id: Uuid::from_u128(3).to_string(),
            agent_id: Uuid::from_u128(4).to_string(),
            expected_agent_revision: 1,
            goal_id: None,
            goal_revision: None,
            dag_revision: None,
            node_id: None,
            node_revision: None,
        }
        .into_typed()?;
        assert!(focus.focus.is_unfocused());
        assert_eq!(focus.expected_revision.get(), 1);

        let work = AgentPublishWorkInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            activity_id: Uuid::from_u128(3).to_string(),
            agent_id: Uuid::from_u128(4).to_string(),
            update_id: Uuid::from_u128(5).to_string(),
            sequence: 1,
            phase: AgentWorkPhaseWire::Planning,
            summary: "Inspecting the selected node".to_owned(),
            evidence_refs: Vec::new(),
            observed_at_ms: 10,
        }
        .into_typed()?;
        assert_eq!(work.update_id.to_string(), Uuid::from_u128(5).to_string());
        assert_eq!(work.sequence.get(), 1);
        assert_eq!(work.summary.as_str(), "Inspecting the selected node");
        assert_eq!(work.observed_at.get(), 10);

        let goals = GoalListInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            limit: 10,
        }
        .into_typed()?;
        assert_eq!(goals.limit.get(), 10);

        let invalid_focus = AgentSetFocusInput {
            goal_id: Some(Uuid::from_u128(5).to_string()),
            ..AgentSetFocusInput {
                location_id: location(),
                expected_revision: 1,
                workspace_id: Uuid::from_u128(2).to_string(),
                workspace_revision: 1,
                locator: locator()?,
                activity_id: Uuid::from_u128(3).to_string(),
                agent_id: Uuid::from_u128(4).to_string(),
                expected_agent_revision: 1,
                goal_id: None,
                goal_revision: None,
                dag_revision: None,
                node_id: None,
                node_revision: None,
            }
        };
        assert!(matches!(
            invalid_focus.into_typed(),
            Err(WireValidationError::InvalidFocus)
        ));

        let unknown = json!({
            "location_id": location(),
            "expected_revision": 1,
            "workspace_id": Uuid::from_u128(2).to_string(),
            "workspace_revision": 1,
            "locator": locator()?,
            "activity_id": Uuid::from_u128(3).to_string(),
            "display_name": "Planner",
            "declared_role": "planner",
            "transport_kind": "stdio"
        });
        assert!(serde_json::from_value::<AgentAttachInput>(unknown).is_err());

        let private_field = json!({
            "location_id": location(),
            "expected_revision": 1,
            "workspace_id": Uuid::from_u128(2).to_string(),
            "workspace_revision": 1,
            "locator": locator()?,
            "activity_id": Uuid::from_u128(3).to_string(),
            "agent_id": Uuid::from_u128(4).to_string(),
            "update_id": Uuid::from_u128(5).to_string(),
            "sequence": 1,
            "phase": "planning",
            "summary": "public summary",
            "evidence_refs": [],
            "observed_at_ms": 10,
            "prompt": "must not be accepted"
        });
        assert!(serde_json::from_value::<AgentPublishWorkInput>(private_field).is_err());
        Ok(())
    }

    #[test]
    fn dag_replan_wire_accepts_a_bounded_full_draft_and_rejects_private_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let nodes = (0_u16..17)
            .map(|ordinal| DagReplanNodeInput {
                node_id: Uuid::from_u128(0x1000 + u128::from(ordinal)).to_string(),
                ordinal,
                title: format!("Step {ordinal}"),
                objective: format!("Observe step {ordinal}"),
                acceptance: vec![format!("Step {ordinal} is observable")],
                lifecycle: if ordinal == 0 {
                    DagReplanNodeLifecycleInput::Completed {
                        created_at_ms: 1,
                        updated_at_ms: 2,
                        node_revision: 2,
                    }
                } else {
                    DagReplanNodeLifecycleInput::Pending
                },
            })
            .collect::<Vec<_>>();
        let input = DagReplanCommitInput {
            location_id: location(),
            expected_revision: 1,
            workspace_id: Uuid::from_u128(2).to_string(),
            workspace_revision: 1,
            locator: locator()?,
            activity_id: Uuid::from_u128(3).to_string(),
            agent_id: Uuid::from_u128(4).to_string(),
            grant_id: Uuid::from_u128(5).to_string(),
            expected_grant_revision: 1,
            request_id: Uuid::from_u128(6).to_string(),
            history_update_id: Uuid::from_u128(7).to_string(),
            history_update_sequence: 1,
            observed_at_ms: 20,
            draft: DagReplanDraftInput {
                revision_id: Uuid::from_u128(8).to_string(),
                goal_id: Uuid::from_u128(9).to_string(),
                goal_revision: 1,
                dag_revision: 2,
                parent_revision: 1,
                nodes,
                edges: Vec::new(),
                lineage: Vec::new(),
            },
        };
        let Value::Object(arguments) = serde_json::to_value(&input)? else {
            return Err("replan input did not serialize to an object".into());
        };
        assert_eq!(
            parse_arguments::<DagReplanCommitInput>(Some(&arguments)),
            Err(WireValidationError::TooManyValues)
        );
        let parsed = parse_dag_replan_arguments::<DagReplanCommitInput>(Some(&arguments))?;
        let typed = parsed.into_typed()?;
        assert_eq!(typed.draft.nodes().len(), 17);
        assert_eq!(
            typed
                .draft
                .nodes()
                .iter()
                .filter(|node| matches!(node.lifecycle(), DagNodeLifecycle::Completed))
                .count(),
            1
        );
        assert_eq!(
            typed
                .draft
                .nodes()
                .iter()
                .filter(|node| matches!(node.lifecycle(), DagNodeLifecycle::Pending))
                .count(),
            16
        );

        let mut private = serde_json::to_value(input)?;
        private["draft"]["private_reasoning"] = Value::String("must not cross MCP".to_owned());
        let Value::Object(private) = private else {
            return Err("private replan input did not serialize to an object".into());
        };
        assert_eq!(
            parse_dag_replan_arguments::<DagReplanCommitInput>(Some(&private)),
            Err(WireValidationError::Shape)
        );
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
