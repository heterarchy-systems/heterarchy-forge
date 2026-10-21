//! Issuer-only, read-only Activity projection over the existing control owner.
//!
//! The request carries only a checked encoded Workspace locator, the expected
//! durable Workspace identity/revision, and a bounded row limit.  The server
//! supplies the observation timestamp immediately before invoking the existing
//! control projection operation; no lifecycle, lease, bootstrap, or recovery
//! mutation is performed here.

use std::time::{SystemTime, UNIX_EPOCH};

use forge_control::{
    ForgeControlClient, MAX_ACTIVITY_PROJECTION_RESULTS, WorkspaceActivityProjectionRequest,
};
use forge_domain::{
    ActivityListLimit, ActivityLiveness, ActivityState, LocationId, TimestampMillis, WorkspaceId,
    WorkspaceRevision,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error::ForgeError;

use super::{Command, ParseResult, decode_timestamp, forge_error_of_client};

pub(super) fn parse_activity_list(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        locator: String,
        workspace_id: Uuid,
        workspace_revision: i64,
        limit: u32,
    }

    let body: Body = super::parse_body(payload, "activity.list payload is invalid")?;
    if body.workspace_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "activity.list Workspace identity must not be nil",
        ));
    }
    let locator = forge_control::WorkspaceLocator::decode(&body.locator)
        .map_err(|_| ForgeError::invalid_input("activity.list locator is invalid"))?;
    if locator.location_id().into_uuid().is_nil() {
        return Err(ForgeError::invalid_input(
            "activity.list Location identity must not be nil",
        ));
    }
    if body.limit == 0
        || usize::try_from(body.limit).map_or(true, |limit| limit > MAX_ACTIVITY_PROJECTION_RESULTS)
    {
        return Err(ForgeError::invalid_input("activity.list limit is invalid"));
    }
    let workspace_revision = WorkspaceRevision::new(body.workspace_revision)
        .map_err(|_| ForgeError::invalid_input("activity.list Workspace revision is invalid"))?;
    let limit = ActivityListLimit::new(body.limit)
        .map_err(|_| ForgeError::invalid_input("activity.list limit is invalid"))?;

    // The request is completed with a server observation timestamp at bridge
    // execution.  Zero is a parse-time placeholder and never reaches control.
    let request = WorkspaceActivityProjectionRequest {
        location_id: LocationId::from_uuid(locator.location_id().into_uuid()),
        expected_location_revision: locator.expected_revision(),
        locator,
        expected_workspace_id: WorkspaceId::from_uuid(body.workspace_id),
        expected_workspace_revision: workspace_revision,
        now: decode_timestamp(0)?,
        limit,
    };
    Ok(Command::ActivityList {
        request_id,
        request: Box::new(request),
    })
}

pub(super) fn execute_activity_list(
    client: &ForgeControlClient,
    request: &WorkspaceActivityProjectionRequest,
) -> Result<Value, ForgeError> {
    let now = server_timestamp_now()?;
    let request = WorkspaceActivityProjectionRequest {
        now,
        ..request.clone()
    };
    let projection = client
        .list_workspace_activity_projections(request)
        .map_err(|error| forge_error_of_client(&error))?;
    let scope = projection.scope();
    let activities = projection
        .activities()
        .iter()
        .map(activity_projection_json)
        .collect::<Vec<_>>();
    Ok(json!({
        "scope": {
            "workspace_id": scope.workspace_id().into_uuid(),
            "workspace_revision": scope.workspace_revision().get(),
            "locator": scope.locator().encode(),
        },
        "activities": activities,
    }))
}

fn server_timestamp_now() -> Result<TimestampMillis, ForgeError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForgeError::internal())?
        .as_millis();
    let millis = i64::try_from(millis).map_err(|_| ForgeError::internal())?;
    decode_timestamp(millis)
}

fn activity_projection_json(projection: &forge_domain::ActivityProjection) -> Value {
    let activity = projection.activity();
    json!({
        "activity_id": activity.id().into_uuid(),
        "workspace_id": activity.workspace_id().into_uuid(),
        "state": activity_state_name(activity.state()),
        "liveness": activity_liveness_name(projection.liveness()),
        "revision": activity.revision().get(),
        "created_at_ms": activity.created_at().get(),
        "updated_at_ms": activity.updated_at().get(),
        "lease_owner_id": activity.lease_owner_id().map(forge_domain::RuntimeInstanceId::into_uuid),
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

const fn activity_liveness_name(liveness: ActivityLiveness) -> &'static str {
    match liveness {
        ActivityLiveness::Available => "available",
        ActivityLiveness::Live => "live",
        ActivityLiveness::Expired => "expired",
        ActivityLiveness::Closed => "closed",
        ActivityLiveness::Interrupted => "interrupted",
    }
}
