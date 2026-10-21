//! Typed source-write HTTP adapter inputs and projections.
//!
//! This module converts the frozen wire contract into the existing
//! forge-control source-write request. Domain constructors remain the owner of
//! path, hash, range, patch, and hunk invariants; this adapter only owns wire
//! shape and error projection.

use std::str::FromStr;

use forge_control::{
    FileApplyPatchOperation, FileApplyPatchRequest, FileMutationStatus, ForgeControlClient,
};
use forge_domain::{
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, ChangeSetId, DagNodeId,
    FileContentHash, FileMutationId, FilePatch, FilePatchHunk, GoalId, GoalNodeAttribution,
    SourceLineRange, SourceRangeHash, WriterLeaseId, WriterLeaseRevision,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::execution::ExecutionActorDto;
use super::{ActivityDto, ScopeDto, decode_file_activity, decode_principal, decode_scope};
use crate::error::ForgeError;

const MAX_ADD_CONTENT_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyPatchBody {
    scope: ScopeDto,
    activity: ActivityDto,
    actor: ExecutionActorDto,
    goal_id: Uuid,
    expected_goal_revision: i64,
    expected_dag_revision: i64,
    node_id: Uuid,
    expected_node_revision: i64,
    writer_lease_id: Uuid,
    expected_writer_lease_revision: i64,
    change_set_id: Uuid,
    mutation_id: Uuid,
    operation: ApplyPatchOperationDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatchHunkDto {
    start_line: u64,
    end_line: u64,
    expected_range_hash: String,
    replacement: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ApplyPatchOperationDto {
    Add {
        path_base64: String,
        content: String,
    },
    Update {
        path_base64: String,
        expected_whole_file_hash: String,
        hunks: Vec<PatchHunkDto>,
    },
    Delete {
        path_base64: String,
        expected_whole_file_hash: String,
    },
}

/// Parse one fully attributed source mutation from the bounded HTTP payload.
pub(super) fn parse_apply_patch(value: &Value) -> Result<FileApplyPatchRequest, ForgeError> {
    let body: ApplyPatchBody = super::parse_body(value, "file.apply_patch payload is invalid")?;
    let attribution = decode_attribution(
        body.goal_id,
        body.expected_goal_revision,
        body.expected_dag_revision,
        body.node_id,
        body.expected_node_revision,
    )?;
    let context = decode_authority(
        &body.scope,
        &body.activity,
        &body.actor,
        attribution,
        body.writer_lease_id,
        body.expected_writer_lease_revision,
    )?;
    Ok(FileApplyPatchRequest {
        scope: context.scope,
        activity: context.activity,
        goal: Some(attribution.into()),
        write_authority: context.write_authority,
        change_set_id: ChangeSetId::from_uuid(require_id(body.change_set_id, "change set id")?),
        mutation_id: FileMutationId::from_uuid(require_id(body.mutation_id, "mutation id")?),
        operation: parse_operation(body.operation)?,
    })
}

pub(super) struct DecodedSourceAuthority {
    pub(super) scope: forge_control::ResolvedWorkspaceScope,
    pub(super) activity: forge_control::FileActivityScope,
    pub(super) write_authority: forge_domain::SourceWriteAuthority,
}

pub(super) fn decode_attribution(
    goal_id: Uuid,
    goal_revision: i64,
    dag_revision: i64,
    node_id: Uuid,
    node_revision: i64,
) -> Result<GoalNodeAttribution, ForgeError> {
    Ok(GoalNodeAttribution::new(
        GoalId::from_uuid(require_id(goal_id, "goal id")?),
        super::decode_goal_revision(goal_revision)?,
        super::decode_dag_revision(dag_revision)?,
        DagNodeId::from_uuid(require_id(node_id, "node id")?),
        super::decode_node_revision(node_revision)?,
    ))
}

pub(super) fn decode_authority(
    scope: &ScopeDto,
    activity: &ActivityDto,
    actor: &ExecutionActorDto,
    attribution: GoalNodeAttribution,
    writer_lease_id: Uuid,
    writer_lease_revision: i64,
) -> Result<DecodedSourceAuthority, ForgeError> {
    let workspace_id = require_id(scope.workspace_id, "scope workspace id")?;
    require_id(scope.locator.location_id, "scope location id")?;
    require_id(activity.activity_id, "activity id")?;
    require_id(activity.runtime_instance_id, "activity runtime instance id")?;
    if require_id(actor.workspace_id, "actor workspace id")? != workspace_id {
        return Err(ForgeError::invalid_input(
            "actor workspace does not match command scope",
        ));
    }
    Ok(DecodedSourceAuthority {
        scope: decode_scope(scope)?,
        activity: decode_file_activity(activity)?,
        write_authority: forge_domain::SourceWriteAuthority::new(
            AgentInstanceId::from_uuid(require_id(actor.agent_id, "agent id")?),
            AgentInstanceRevision::new(actor.expected_revision)
                .map_err(|_| ForgeError::invalid_input("agent revision is invalid"))?,
            decode_principal(&actor.principal)?,
            attribution,
            WriterLeaseId::from_uuid(require_id(writer_lease_id, "writer lease id")?),
            WriterLeaseRevision::new(writer_lease_revision)
                .map_err(|_| ForgeError::invalid_input("writer lease revision is invalid"))?,
            AgentSessionId::from_uuid(require_id(actor.session_id, "actor session id")?),
        ),
    })
}

fn parse_operation(
    operation: ApplyPatchOperationDto,
) -> Result<FileApplyPatchOperation, ForgeError> {
    match operation {
        ApplyPatchOperationDto::Add {
            path_base64,
            content,
        } => {
            if content.len() > MAX_ADD_CONTENT_BYTES || content.as_bytes().contains(&0) {
                return Err(ForgeError::invalid_input(
                    "file.apply_patch add content is invalid",
                ));
            }
            Ok(FileApplyPatchOperation::Add {
                path: super::source::decode_relative_path(&path_base64)?,
                content: content.into_bytes(),
            })
        }
        ApplyPatchOperationDto::Update {
            path_base64,
            expected_whole_file_hash,
            hunks,
        } => {
            let expected_whole_file_hash = parse_content_hash(&expected_whole_file_hash)?;
            let hunks = hunks
                .into_iter()
                .map(parse_hunk)
                .collect::<Result<Vec<_>, _>>()?;
            let patch = FilePatch::new(expected_whole_file_hash, hunks)
                .map_err(|_| ForgeError::invalid_input("file.apply_patch patch is invalid"))?;
            Ok(FileApplyPatchOperation::Update {
                path: super::source::decode_relative_path(&path_base64)?,
                patch,
            })
        }
        ApplyPatchOperationDto::Delete {
            path_base64,
            expected_whole_file_hash,
        } => Ok(FileApplyPatchOperation::Delete {
            path: super::source::decode_relative_path(&path_base64)?,
            expected_whole_file_hash: parse_content_hash(&expected_whole_file_hash)?,
        }),
    }
}

pub(super) fn parse_hunk(hunk: PatchHunkDto) -> Result<FilePatchHunk, ForgeError> {
    let range = SourceLineRange::new(hunk.start_line, hunk.end_line)
        .map_err(|_| ForgeError::invalid_input("source patch line range is invalid"))?;
    let expected_range_hash = SourceRangeHash::from_str(&hunk.expected_range_hash)
        .map_err(|_| ForgeError::invalid_input("source patch range hash is invalid"))?;
    FilePatchHunk::new(range, expected_range_hash, hunk.replacement.into_bytes())
        .map_err(|_| ForgeError::invalid_input("source patch hunk is invalid"))
}

pub(super) fn parse_content_hash(value: &str) -> Result<FileContentHash, ForgeError> {
    FileContentHash::from_str(value)
        .map_err(|_| ForgeError::invalid_input("source content hash is invalid"))
}

pub(super) fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}

/// Execute one source mutation and project its durable PRE/POST record.
pub(super) fn execute_apply_patch(
    client: &ForgeControlClient,
    request: &FileApplyPatchRequest,
) -> Result<Value, ForgeError> {
    let scope = super::source::scope_json(&request.scope)?;
    let result = client
        .file_apply_patch(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    let status = mutation_status(result.status())?;
    let record = result.record();
    let change_set = record.change_set();
    let mutation = record.mutation();
    Ok(json!({
        "scope": scope,
        "activity_id": change_set.activity_id().into_uuid(),
        "change_set_id": change_set.id().into_uuid(),
        "mutation_id": mutation.id().into_uuid(),
        "path_base64": super::source::encode_relative_path(mutation.path()),
        "kind": super::mutation::mutation_kind(mutation.kind()),
        "status": status,
        "change_set_state": super::mutation::change_set_state(change_set.state()),
        "pre_state": super::mutation::file_state_json(mutation.pre_state()),
        "post_state": mutation.post_state().map_or(Value::Null, super::mutation::file_state_json),
        "retry_authorized": false,
    }))
}

fn mutation_status(value: FileMutationStatus) -> Result<&'static str, ForgeError> {
    match value {
        FileMutationStatus::Applied => Ok("applied"),
        FileMutationStatus::AlreadyApplied => Ok("already_applied"),
        FileMutationStatus::RecoveryRequired => Ok("recovery_required"),
        FileMutationStatus::TerminalFailed => Ok("terminal_failed"),
        FileMutationStatus::CommittedButUnconfirmed => Err(ForgeError::unknown_outcome(None)),
    }
}
