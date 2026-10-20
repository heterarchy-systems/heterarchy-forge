//! Typed source-tree transaction and historical readback HTTP adapters.
//!
//! This module owns only the bounded wire conversion and the synchronous
//! `forge-control` calls. Source-tree authority, confinement, persistence, and
//! recovery semantics remain in their existing control and persistence owners.

use std::collections::HashSet;

use forge_control::{
    ForgeControlClient, SourceTreeMutationRequest, SourceTreeReadbackRequest,
    SourceTreeTransactionRequest, SourceTreeTransactionStatus,
};
use forge_domain::{
    ActivityId, ChangeSetId, MAX_TREE_CHANGESET_MUTATIONS, SourceTreeRequestDigest, TreeMutationId,
};
use forge_persistence::SourceTreeReadSnapshot;
use forge_workspace::MAX_FILE_WRITE_BYTES;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::execution::ExecutionActorDto;
use super::source_write::{
    PatchHunkDto, decode_attribution, decode_authority, parse_content_hash, parse_hunk, require_id,
};
use super::{ActivityDto, ScopeDto};
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyBody {
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
    mutations: Vec<TreeMutationDto>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TreeMutationDto {
    CreateDirectory {
        mutation_id: Uuid,
        path_base64: String,
    },
    CreateFile {
        mutation_id: Uuid,
        path_base64: String,
        content: String,
    },
    UpdateFile {
        mutation_id: Uuid,
        path_base64: String,
        expected_whole_file_hash: String,
        content: String,
    },
    PatchFile {
        mutation_id: Uuid,
        path_base64: String,
        expected_whole_file_hash: String,
        hunks: Vec<PatchHunkDto>,
    },
    DeleteFile {
        mutation_id: Uuid,
        path_base64: String,
        expected_whole_file_hash: String,
    },
    MoveFile {
        mutation_id: Uuid,
        source_base64: String,
        destination_base64: String,
        expected_whole_file_hash: String,
    },
    MoveDirectory {
        mutation_id: Uuid,
        source_base64: String,
        destination_base64: String,
    },
    DeleteDirectory {
        mutation_id: Uuid,
        path_base64: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackBody {
    scope: ScopeDto,
    activity_id: Uuid,
    change_set_id: Uuid,
    #[serde(default)]
    expected_request_digest: Option<String>,
}

/// Parse one fully attributed source-tree transaction from the bounded HTTP
/// payload and derive its durable request digest from the native mutations.
pub(super) fn parse_apply(value: &Value) -> Result<SourceTreeTransactionRequest, ForgeError> {
    let body: ApplyBody = super::parse_body(value, "source_tree.apply payload is invalid")?;
    let attribution = decode_attribution(
        body.goal_id,
        body.expected_goal_revision,
        body.expected_dag_revision,
        body.node_id,
        body.expected_node_revision,
    )?;
    let authority = decode_authority(
        &body.scope,
        &body.activity,
        &body.actor,
        attribution,
        body.writer_lease_id,
        body.expected_writer_lease_revision,
    )?;
    let mutations = parse_mutations(body.mutations)?;
    let request_digest = forge_control::source_tree_request_digest(&mutations);
    Ok(SourceTreeTransactionRequest {
        scope: authority.scope,
        activity: authority.activity,
        write_authority: authority.write_authority,
        change_set_id: ChangeSetId::from_uuid(require_id(body.change_set_id, "change set id")?),
        request_digest,
        mutations,
    })
}

fn parse_mutations(
    values: Vec<TreeMutationDto>,
) -> Result<Vec<SourceTreeMutationRequest>, ForgeError> {
    if values.is_empty() || values.len() > MAX_TREE_CHANGESET_MUTATIONS {
        return Err(ForgeError::invalid_input(
            "source tree mutation count is outside the supported bound",
        ));
    }
    let mut ids = HashSet::with_capacity(values.len());
    let mut mutations = Vec::with_capacity(values.len());
    for value in values {
        let mutation = parse_mutation(value)?;
        if !ids.insert(mutation.mutation_id()) {
            return Err(ForgeError::invalid_input(
                "source tree mutation ids must be unique",
            ));
        }
        mutations.push(mutation);
    }
    Ok(mutations)
}

fn parse_mutation(value: TreeMutationDto) -> Result<SourceTreeMutationRequest, ForgeError> {
    match value {
        TreeMutationDto::CreateDirectory {
            mutation_id,
            path_base64,
        } => Ok(SourceTreeMutationRequest::CreateDirectory {
            mutation_id: parse_mutation_id(mutation_id)?,
            path: super::source::decode_relative_path(&path_base64)?,
        }),
        TreeMutationDto::CreateFile {
            mutation_id,
            path_base64,
            content,
        } => Ok(SourceTreeMutationRequest::CreateFile {
            mutation_id: parse_mutation_id(mutation_id)?,
            path: super::source::decode_relative_path(&path_base64)?,
            content: parse_whole_content(content)?,
        }),
        TreeMutationDto::UpdateFile {
            mutation_id,
            path_base64,
            expected_whole_file_hash,
            content,
        } => Ok(SourceTreeMutationRequest::UpdateFile {
            mutation_id: parse_mutation_id(mutation_id)?,
            path: super::source::decode_relative_path(&path_base64)?,
            expected_whole_file_hash: parse_content_hash(&expected_whole_file_hash)?,
            content: parse_whole_content(content)?,
        }),
        TreeMutationDto::PatchFile {
            mutation_id,
            path_base64,
            expected_whole_file_hash,
            hunks,
        } => {
            let hunks = hunks
                .into_iter()
                .map(parse_hunk)
                .collect::<Result<Vec<_>, _>>()?;
            let patch =
                forge_domain::FilePatch::new(parse_content_hash(&expected_whole_file_hash)?, hunks)
                    .map_err(|_| ForgeError::invalid_input("source tree patch is invalid"))?;
            Ok(SourceTreeMutationRequest::PatchFile {
                mutation_id: parse_mutation_id(mutation_id)?,
                path: super::source::decode_relative_path(&path_base64)?,
                patch,
            })
        }
        TreeMutationDto::DeleteFile {
            mutation_id,
            path_base64,
            expected_whole_file_hash,
        } => Ok(SourceTreeMutationRequest::DeleteFile {
            mutation_id: parse_mutation_id(mutation_id)?,
            path: super::source::decode_relative_path(&path_base64)?,
            expected_whole_file_hash: parse_content_hash(&expected_whole_file_hash)?,
        }),
        TreeMutationDto::MoveFile {
            mutation_id,
            source_base64,
            destination_base64,
            expected_whole_file_hash,
        } => Ok(SourceTreeMutationRequest::MoveFile {
            mutation_id: parse_mutation_id(mutation_id)?,
            source: super::source::decode_relative_path(&source_base64)?,
            destination: super::source::decode_relative_path(&destination_base64)?,
            expected_whole_file_hash: parse_content_hash(&expected_whole_file_hash)?,
        }),
        TreeMutationDto::MoveDirectory {
            mutation_id,
            source_base64,
            destination_base64,
        } => Ok(SourceTreeMutationRequest::MoveDirectory {
            mutation_id: parse_mutation_id(mutation_id)?,
            source: super::source::decode_relative_path(&source_base64)?,
            destination: super::source::decode_relative_path(&destination_base64)?,
        }),
        TreeMutationDto::DeleteDirectory {
            mutation_id,
            path_base64,
        } => Ok(SourceTreeMutationRequest::DeleteDirectory {
            mutation_id: parse_mutation_id(mutation_id)?,
            path: super::source::decode_relative_path(&path_base64)?,
        }),
    }
}

fn parse_mutation_id(value: Uuid) -> Result<TreeMutationId, ForgeError> {
    Ok(TreeMutationId::from_uuid(require_id(value, "mutation id")?))
}

fn parse_whole_content(content: String) -> Result<Vec<u8>, ForgeError> {
    let content = content.into_bytes();
    if content.len() > MAX_FILE_WRITE_BYTES || content.contains(&0) {
        return Err(ForgeError::invalid_input(
            "source tree whole-file content is invalid",
        ));
    }
    Ok(content)
}

/// Parse one historical source-tree identity without granting retry authority.
pub(super) fn parse_readback(value: &Value) -> Result<SourceTreeReadbackRequest, ForgeError> {
    let body: ReadbackBody = super::parse_body(value, "source_tree.readback payload is invalid")?;
    require_id(body.scope.workspace_id, "scope workspace id")?;
    require_id(body.scope.locator.location_id, "scope location id")?;
    let activity_id = ActivityId::from_uuid(require_id(body.activity_id, "activity id")?);
    let change_set_id = ChangeSetId::from_uuid(require_id(body.change_set_id, "change set id")?);
    let expected_request_digest = body
        .expected_request_digest
        .as_deref()
        .map(parse_digest)
        .transpose()?;
    Ok(SourceTreeReadbackRequest {
        scope: super::decode_scope(&body.scope)?,
        activity_id,
        change_set_id,
        expected_request_digest,
    })
}

fn parse_digest(value: &str) -> Result<SourceTreeRequestDigest, ForgeError> {
    if value.len() != SourceTreeRequestDigest::BYTE_LEN * 2 {
        return Err(ForgeError::invalid_input(
            "source tree request digest is invalid",
        ));
    }
    let bytes = super::decode_hex(value)?;
    let bytes: [u8; SourceTreeRequestDigest::BYTE_LEN] = bytes
        .try_into()
        .map_err(|_| ForgeError::invalid_input("source tree request digest is invalid"))?;
    if super::encode_hex(&bytes) != value {
        return Err(ForgeError::invalid_input(
            "source tree request digest is not canonical",
        ));
    }
    Ok(SourceTreeRequestDigest::from_bytes(bytes))
}

/// Execute one source-tree transaction and project its durable result.
pub(super) fn execute_apply(
    client: &ForgeControlClient,
    request: &SourceTreeTransactionRequest,
) -> Result<Value, ForgeError> {
    let scope = super::source::scope_json(&request.scope)?;
    let result = client
        .source_tree_apply(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "request_digest": super::encode_hex(request.request_digest.as_bytes()),
        "scope": scope,
        "activity_id": request.activity.activity_id.into_uuid(),
        "change_set_id": result.change_set_id().into_uuid(),
        "status": transaction_status(result.status()),
        "applied_mutations": result.applied_mutations().iter().map(|id| id.into_uuid()).collect::<Vec<_>>(),
        "uncertain_mutation": result.uncertain_mutation().map(TreeMutationId::into_uuid),
        "retry_authorized": false,
    }))
}

fn transaction_status(value: SourceTreeTransactionStatus) -> &'static str {
    match value {
        SourceTreeTransactionStatus::Applied => "applied",
        SourceTreeTransactionStatus::AlreadyApplied => "already_applied",
        SourceTreeTransactionStatus::RecoveryRequired => "recovery_required",
        SourceTreeTransactionStatus::TerminalFailed => "terminal_failed",
    }
}

/// Execute one historical source-tree readback and preserve its durable
/// `ChangeSet`, digest, mutation, and optional Diff metadata.
pub(super) fn execute_readback(
    client: &ForgeControlClient,
    request: &SourceTreeReadbackRequest,
) -> Result<Value, ForgeError> {
    let snapshot = client
        .source_tree_readback(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    readback_json(request, snapshot.as_ref())
}

fn readback_json(
    request: &SourceTreeReadbackRequest,
    snapshot: Option<&SourceTreeReadSnapshot>,
) -> Result<Value, ForgeError> {
    let common = json!({
        "scope": super::source::scope_json(&request.scope)?,
        "activity_id": request.activity_id.into_uuid(),
        "change_set_id": request.change_set_id.into_uuid(),
        "retry_authorized": false,
        "request_equivalence_proven": false,
    });
    let Value::Object(mut response) = common else {
        return Err(ForgeError::internal());
    };
    let Some(snapshot) = snapshot else {
        response.insert("found".to_owned(), Value::Bool(false));
        return Ok(Value::Object(response));
    };
    let change_set = snapshot.change_set();
    response.insert("found".to_owned(), Value::Bool(true));
    response.insert(
        "workspace_id".to_owned(),
        json!(change_set.workspace_id().into_uuid()),
    );
    response.insert(
        "workspace_revision".to_owned(),
        json!(change_set.workspace_revision().get()),
    );
    response.insert(
        "runtime_instance_id".to_owned(),
        json!(change_set.runtime_instance_id().into_uuid()),
    );
    response.insert(
        "activity_lease_revision".to_owned(),
        json!(change_set.activity_lease_revision().get()),
    );
    response.insert(
        "change_set_revision".to_owned(),
        json!(change_set.revision().get()),
    );
    response.insert(
        "change_set_state".to_owned(),
        json!(super::mutation::change_set_state(change_set.state())),
    );
    response.insert(
        "failure_code".to_owned(),
        change_set.failure_code().map_or(Value::Null, |value| {
            json!(super::mutation::failure_code(value))
        }),
    );
    response.insert(
        "created_at_ms".to_owned(),
        json!(change_set.created_at().get()),
    );
    response.insert(
        "updated_at_ms".to_owned(),
        json!(change_set.updated_at().get()),
    );
    response.insert(
        "request_digest".to_owned(),
        json!(super::encode_hex(snapshot.request_digest().as_bytes())),
    );
    response.insert(
        "mutation_count".to_owned(),
        json!(snapshot.mutation_count()),
    );
    response.insert(
        "applied_mutations".to_owned(),
        json!(
            snapshot
                .applied_mutations()
                .iter()
                .map(|id| id.into_uuid())
                .collect::<Vec<_>>()
        ),
    );
    response.insert(
        "diff".to_owned(),
        snapshot
            .diff()
            .map_or(Value::Null, super::mutation::diff_json),
    );
    Ok(Value::Object(response))
}
