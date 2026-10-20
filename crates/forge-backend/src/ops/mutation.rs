//! Historical file-mutation readback over the typed Forge control boundary.
//!
//! This adapter is observational only. It reports the durable journal record
//! and never turns a missing or incomplete record into permission to retry a
//! source mutation.

use forge_control::{FileMutationReadbackRequest, ForgeControlClient};
use forge_domain::{
    ActivityId, ChangeSetId, ChangeSetState, DiffEvidenceState, DiffOrigin,
    FileMutationFailureCode, FileMutationId, FileMutationKind, FilePathState, FilePrecondition,
};
use forge_persistence::FileMutationReadSnapshot;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::ScopeDto;
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackBody {
    scope: ScopeDto,
    activity_id: Uuid,
    change_set_id: Uuid,
    mutation_id: Uuid,
}

/// Parse one exact historical mutation identity without admitting a new
/// source effect.
pub(super) fn parse_readback(value: &Value) -> Result<FileMutationReadbackRequest, ForgeError> {
    let body: ReadbackBody = super::parse_body(value, "file.mutation_readback payload is invalid")?;
    require_id(body.scope.workspace_id, "scope workspace id")?;
    require_id(body.scope.locator.location_id, "scope location id")?;
    let activity_id = ActivityId::from_uuid(require_id(body.activity_id, "activity id")?);
    let change_set_id = ChangeSetId::from_uuid(require_id(body.change_set_id, "change set id")?);
    let mutation_id = FileMutationId::from_uuid(require_id(body.mutation_id, "mutation id")?);
    Ok(FileMutationReadbackRequest {
        scope: super::decode_scope(&body.scope)?,
        activity_id,
        change_set_id,
        mutation_id,
    })
}

/// Execute one observational readback and preserve the journal's exact
/// attribution and PRE/POST state in the backend wire projection.
pub(super) fn execute_readback(
    client: &ForgeControlClient,
    request: &FileMutationReadbackRequest,
) -> Result<Value, ForgeError> {
    let snapshot = client
        .file_mutation_readback(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    readback_json(request, snapshot.as_ref())
}

fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}

fn readback_json(
    request: &FileMutationReadbackRequest,
    snapshot: Option<&FileMutationReadSnapshot>,
) -> Result<Value, ForgeError> {
    let scope = super::source::scope_json(&request.scope)?;
    let common = json!({
        "scope": scope,
        "activity_id": request.activity_id.into_uuid(),
        "change_set_id": request.change_set_id.into_uuid(),
        "mutation_id": request.mutation_id.into_uuid(),
        "retry_authorized": false,
        "request_equivalence_proven": false,
    });
    let Value::Object(mut common) = common else {
        return Err(ForgeError::internal());
    };

    let Some(snapshot) = snapshot else {
        common.insert("found".to_owned(), Value::Bool(false));
        return Ok(Value::Object(common));
    };

    let record = snapshot.record();
    let change_set = record.change_set();
    let mutation = record.mutation();
    let expected_hash = expected_hash(mutation.precondition());
    common.insert("found".to_owned(), Value::Bool(true));
    common.insert(
        "workspace_id".to_owned(),
        json!(change_set.workspace_id().into_uuid()),
    );
    common.insert(
        "workspace_revision".to_owned(),
        json!(change_set.workspace_revision().get()),
    );
    common.insert(
        "runtime_instance_id".to_owned(),
        json!(change_set.runtime_instance_id().into_uuid()),
    );
    common.insert(
        "activity_lease_revision".to_owned(),
        json!(change_set.activity_lease_revision().get()),
    );
    common.insert(
        "change_set_revision".to_owned(),
        json!(change_set.revision().get()),
    );
    common.insert(
        "change_set_state".to_owned(),
        json!(change_set_state(change_set.state())),
    );
    common.insert(
        "failure_code".to_owned(),
        change_set
            .failure_code()
            .map_or(Value::Null, |value| json!(failure_code(value))),
    );
    common.insert(
        "created_at_ms".to_owned(),
        json!(change_set.created_at().get()),
    );
    common.insert(
        "updated_at_ms".to_owned(),
        json!(change_set.updated_at().get()),
    );
    common.insert(
        "path_base64".to_owned(),
        json!(super::source::encode_relative_path(mutation.path())),
    );
    common.insert("kind".to_owned(), json!(mutation_kind(mutation.kind())));
    common.insert(
        "precondition".to_owned(),
        precondition_json(mutation.precondition()),
    );
    common.insert("expected_hash".to_owned(), expected_hash);
    common.insert(
        "intended_content_hash".to_owned(),
        mutation
            .intended_content_hash()
            .map_or(Value::Null, |value| json!(value.to_string())),
    );
    common.insert(
        "pre_state".to_owned(),
        file_state_json(mutation.pre_state()),
    );
    common.insert(
        "post_state".to_owned(),
        mutation.post_state().map_or(Value::Null, file_state_json),
    );
    common.insert(
        "mutation_revision".to_owned(),
        json!(mutation.revision().get()),
    );
    common.insert(
        "diff".to_owned(),
        snapshot.diff().map_or(Value::Null, diff_json),
    );
    Ok(Value::Object(common))
}

fn expected_hash(value: FilePrecondition) -> Value {
    match value {
        FilePrecondition::Absent => Value::Null,
        FilePrecondition::Matches(hash) => json!(hash.to_string()),
    }
}

fn precondition_json(value: FilePrecondition) -> Value {
    json!({
        "kind": match value {
            FilePrecondition::Absent => "absent",
            FilePrecondition::Matches(_) => "matches",
        },
        "expected_hash": expected_hash(value),
    })
}

pub(super) fn file_state_json(value: FilePathState) -> Value {
    match value {
        FilePathState::Absent => json!({
            "exists": false,
            "content_hash": Value::Null,
            "size_bytes": Value::Null,
        }),
        FilePathState::Regular { hash, size } => json!({
            "exists": true,
            "content_hash": hash.to_string(),
            "size_bytes": size.get(),
        }),
    }
}

pub(super) fn diff_json(value: &forge_domain::RegisteredDiffEvidence) -> Value {
    let (origin, origin_mutation_id) = match value.origin() {
        DiffOrigin::FileMutation(mutation_id) => ("file_mutation", Some(mutation_id.into_uuid())),
        DiffOrigin::TreeChangeSet => ("tree_change_set", None),
    };
    json!({
        "id": value.id().into_uuid(),
        "state": diff_state(value.state()),
        "revision": value.revision().get(),
        "origin": origin,
        "origin_mutation_id": origin_mutation_id,
    })
}

pub(super) fn change_set_state(value: ChangeSetState) -> &'static str {
    match value {
        ChangeSetState::Starting => "starting",
        ChangeSetState::Applied => "applied",
        ChangeSetState::Failed => "failed",
    }
}

pub(super) fn failure_code(value: FileMutationFailureCode) -> &'static str {
    match value {
        FileMutationFailureCode::InvalidPath => "invalid_path",
        FileMutationFailureCode::ProtectedPath => "protected_path",
        FileMutationFailureCode::PathConflict => "path_conflict",
        FileMutationFailureCode::StaleWrite => "stale_write",
        FileMutationFailureCode::CapacityExceeded => "capacity_exceeded",
        FileMutationFailureCode::IoFailure => "io_failure",
    }
}

pub(super) fn mutation_kind(value: FileMutationKind) -> &'static str {
    match value {
        FileMutationKind::Create => "create",
        FileMutationKind::Replace => "replace",
        FileMutationKind::Delete => "delete",
    }
}

fn diff_state(value: DiffEvidenceState) -> &'static str {
    match value {
        DiffEvidenceState::Intent => "intent",
        DiffEvidenceState::Ready => "ready",
        DiffEvidenceState::SummaryOnly => "summary_only",
        DiffEvidenceState::Abandoned => "abandoned",
        DiffEvidenceState::PurgePending => "purge_pending",
        DiffEvidenceState::Tombstoned => "tombstoned",
    }
}
