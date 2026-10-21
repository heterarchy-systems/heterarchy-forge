//! Exact Activity observation and privileged lease-lifecycle operations.
//!
//! This adapter owns strict wire decoding and bounded JSON projection only.
//! Workspace identity, Activity state, lease ownership, and CAS semantics
//! remain in forge-control and the existing `WorkspaceStore` owner.

use forge_control::{
    ActivityLeaseClient, ActivityOperationStatus, ActivityReadRequest, ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityId, ActivityLeaseRevision, ActivityState, CloseActivity, RegisteredActivity,
    RuntimeInstanceId, TimestampMillis,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error::ForgeError;

use super::{CommandOp, ScopeDto, decode_scope, parse_body};

/// One parsed Activity lifecycle request. The worker supplies observation time
/// for close, so no caller timestamp crosses this transport boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityLifecycleRequest {
    Read(ActivityReadRequest),
    Close(ActivityCloseRequest),
}

/// Caller-owned lease evidence required for one semantic Activity close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityCloseRequest {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) activity_id: ActivityId,
    pub(super) runtime_instance_id: RuntimeInstanceId,
    pub(super) expected_lease_revision: ActivityLeaseRevision,
}

/// Parse one exact Activity operation payload.
pub(super) fn parse(
    op: CommandOp,
    payload: &Value,
) -> Result<ActivityLifecycleRequest, ForgeError> {
    match op {
        CommandOp::ActivityGet => parse_read(payload),
        CommandOp::ActivityClose => parse_close(payload),
        _ => Err(ForgeError::internal()),
    }
}

fn parse_read(payload: &Value) -> Result<ActivityLifecycleRequest, ForgeError> {
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
    }

    let body: Body = parse_body(payload, "activity.get payload is invalid")?;
    let scope = decode_scope_checked(&body.scope, "activity.get")?;
    let activity_id = ActivityId::from_uuid(require_id(body.activity_id, "activity id")?);
    Ok(ActivityLifecycleRequest::Read(ActivityReadRequest {
        scope,
        activity_id,
    }))
}

fn parse_close(payload: &Value) -> Result<ActivityLifecycleRequest, ForgeError> {
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        runtime_instance_id: Uuid,
        expected_lease_revision: i64,
    }

    let body: Body = parse_body(payload, "activity.close payload is invalid")?;
    let scope = decode_scope_checked(&body.scope, "activity.close")?;
    let activity_id = ActivityId::from_uuid(require_id(body.activity_id, "activity id")?);
    let runtime_instance_id = RuntimeInstanceId::from_uuid(require_id(
        body.runtime_instance_id,
        "activity runtime instance id",
    )?);
    let expected_lease_revision = ActivityLeaseRevision::new(body.expected_lease_revision)
        .map_err(|_| ForgeError::invalid_input("activity lease revision is invalid"))?;
    Ok(ActivityLifecycleRequest::Close(ActivityCloseRequest {
        scope,
        activity_id,
        runtime_instance_id,
        expected_lease_revision,
    }))
}

fn decode_scope_checked(
    scope: &ScopeDto,
    operation: &str,
) -> Result<ResolvedWorkspaceScope, ForgeError> {
    require_id(scope.workspace_id, &format!("{operation} Workspace id"))?;
    require_id(
        scope.locator.location_id,
        &format!("{operation} Location id"),
    )?;
    decode_scope(scope)
}

fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}

/// Execute one parsed Activity operation through the existing control client.
pub(super) fn execute_on_lease(
    client: &ActivityLeaseClient,
    request: &ActivityLifecycleRequest,
) -> Result<Value, ForgeError> {
    match request {
        ActivityLifecycleRequest::Read(request) => execute_read(client, request),
        ActivityLifecycleRequest::Close(request) => execute_close(client, request),
    }
}

fn execute_read(
    client: &ActivityLeaseClient,
    request: &ActivityReadRequest,
) -> Result<Value, ForgeError> {
    let activities = client
        .observe_activity_leases(request.scope.clone(), vec![request.activity_id])
        .map_err(|error| super::forge_error_of_client(&error))?;
    if activities.len() > 1
        || activities.first().is_some_and(|activity| {
            activity.id() != request.activity_id
                || activity.workspace_id() != request.scope.workspace_id()
        })
    {
        return Err(ForgeError::resync_required(
            "Activity readback changed scope",
        ));
    }
    let activity = activities.first().map(registered_activity_json);
    Ok(json!({
        "scope": super::scope_json(&request.scope)?,
        "activity_id": request.activity_id.into_uuid(),
        "found": activity.is_some(),
        "activity": activity,
        "retry_authorized": false,
        "request_equivalence_proven": false,
    }))
}

fn execute_close(
    client: &ActivityLeaseClient,
    request: &ActivityCloseRequest,
) -> Result<Value, ForgeError> {
    let operation = client
        .close_owned_activity_batch(
            request.scope.clone(),
            vec![CloseActivity::new(
                request.activity_id,
                request.runtime_instance_id,
                request.expected_lease_revision,
                TimestampMillis::new(0).map_err(|_| ForgeError::internal())?,
            )],
        )
        .map_err(|error| {
            let mapped = super::forge_error_of_client(&error);
            if mapped.code() == crate::error::ErrorCode::UnknownOutcome {
                mapped.with_readback(Some(close_readback_hint(request)))
            } else {
                mapped
            }
        })?;

    if operation.is_committed_but_unconfirmed() {
        return Err(ForgeError::unknown_outcome(Some(close_readback_hint(
            request,
        ))));
    }
    let Some(activity) = operation.activities().first() else {
        return Err(ForgeError::unknown_outcome(Some(close_readback_hint(
            request,
        ))));
    };
    if operation.scope() != &request.scope
        || operation.activities().len() != 1
        || activity.id() != request.activity_id
        || activity.workspace_id() != request.scope.workspace_id()
        || operation.status() != ActivityOperationStatus::Closed
        || activity.state() != ActivityState::Closed
        || activity.lease_owner_id().is_some()
        || activity.lease_until_ms().is_some()
        || request.expected_lease_revision.checked_next().ok() != Some(activity.lease_revision())
    {
        return Err(ForgeError::unknown_outcome(Some(close_readback_hint(
            request,
        ))));
    }
    Ok(json!({
        "scope": super::scope_json(operation.scope())?,
        "activity_id": request.activity_id.into_uuid(),
        "status": activity_operation_status_name(operation.status()),
        "committed": operation.is_committed(),
        "unconfirmed": operation.is_committed_but_unconfirmed(),
        "activity": registered_activity_json(activity),
    }))
}

pub(super) fn close_readback_hint(request: &ActivityCloseRequest) -> crate::error::ReadbackHint {
    crate::error::ReadbackHint::ActivityLifecycle {
        workspace_id: request.scope.workspace_id().into_uuid(),
        activity_id: request.activity_id.into_uuid(),
        runtime_instance_id: request.runtime_instance_id.into_uuid(),
        expected_lease_revision: request.expected_lease_revision.get(),
    }
}

pub(super) fn registered_activity_json(activity: &RegisteredActivity) -> Value {
    json!({
        "activity_id": activity.id().into_uuid(),
        "workspace_id": activity.workspace_id().into_uuid(),
        "state": activity_state_name(activity.state()),
        "revision": activity.revision().get(),
        "created_at_ms": activity.created_at().get(),
        "updated_at_ms": activity.updated_at().get(),
        "lease_owner_id": activity.lease_owner_id().map(RuntimeInstanceId::into_uuid),
        "lease_until_ms": activity.lease_until_ms().map(forge_domain::TimestampMillis::get),
        "lease_revision": activity.lease_revision().get(),
    })
}

const fn activity_state_name(state: ActivityState) -> &'static str {
    match state {
        ActivityState::Open => "open",
        ActivityState::Closed => "closed",
        ActivityState::Interrupted => "interrupted",
    }
}

pub(super) const fn activity_operation_status_name(
    status: ActivityOperationStatus,
) -> &'static str {
    match status {
        ActivityOperationStatus::Renewed => "renewed",
        ActivityOperationStatus::Closed => "closed",
        ActivityOperationStatus::Released => "released",
        ActivityOperationStatus::AlreadyTerminal => "already_terminal",
        ActivityOperationStatus::Reconciled => "reconciled",
        ActivityOperationStatus::CommittedButUnconfirmed => "committed_but_unconfirmed",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn scope_payload() -> Value {
        json!({
            "workspace_id": Uuid::from_u128(1),
            "workspace_revision": 1,
            "locator": {
                "location_id": Uuid::from_u128(2),
                "expected_revision": 1,
                "relative_root": "workspace"
            }
        })
    }

    #[test]
    fn parser_requires_non_nil_identity_and_positive_lease_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let read_payload = json!({
            "scope": scope_payload(),
            "activity_id": Uuid::from_u128(3),
        });
        assert!(matches!(
            parse(CommandOp::ActivityGet, &read_payload)?,
            ActivityLifecycleRequest::Read(_)
        ));

        let mut nil_activity = read_payload.clone();
        nil_activity["activity_id"] = json!(Uuid::nil());
        assert!(parse(CommandOp::ActivityGet, &nil_activity).is_err());

        let close_payload = json!({
            "scope": scope_payload(),
            "activity_id": Uuid::from_u128(3),
            "runtime_instance_id": Uuid::from_u128(4),
            "expected_lease_revision": 1,
        });
        assert!(matches!(
            parse(CommandOp::ActivityClose, &close_payload)?,
            ActivityLifecycleRequest::Close(_)
        ));
        let mut zero_revision = close_payload.clone();
        zero_revision["expected_lease_revision"] = json!(0);
        assert!(parse(CommandOp::ActivityClose, &zero_revision).is_err());
        Ok(())
    }

    #[test]
    fn close_rejects_caller_observation_time_and_unknown_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut payload = json!({
            "scope": scope_payload(),
            "activity_id": Uuid::from_u128(3),
            "runtime_instance_id": Uuid::from_u128(4),
            "expected_lease_revision": 1,
        });
        payload["observed_at_ms"] = json!(10);
        assert!(parse(CommandOp::ActivityClose, &payload).is_err());
        payload
            .as_object_mut()
            .ok_or("close payload is not an object")?
            .remove("observed_at_ms");
        payload["unexpected"] = json!(true);
        assert!(parse(CommandOp::ActivityClose, &payload).is_err());
        Ok(())
    }
}
