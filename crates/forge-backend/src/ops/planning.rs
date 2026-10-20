//! Coordinator planning authority decoded from the HTTP boundary.
//!
//! The transport carries the complete Activity-local Coordinator identity, but
//! does not authorize it.  Forge control revalidates the resolved Workspace,
//! session, attachment, principal, and Coordinator revision before applying a
//! planning command.

use forge_control::ResolvedWorkspaceScope;
use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentInstanceId,
    AgentSessionId, WorkspaceId,
};
use serde::Deserialize;
use uuid::Uuid;

use super::{PrincipalDto, ScopeDto, decode_principal, decode_scope};
use crate::error::ForgeError;

/// Exact Coordinator-authority fields shared by Goal and DAG planning
/// adapters.  The nested actor intentionally carries stable principal
/// identity, never a bearer token or other credential.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlanningAuthorityDto {
    pub(super) scope: ScopeDto,
    pub(super) activity_id: Uuid,
    pub(super) actor: CoordinatorActorDto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CoordinatorActorDto {
    pub(super) session_id: Uuid,
    pub(super) principal: PrincipalDto,
    pub(super) agent_id: Uuid,
    pub(super) expected_coordinator_revision: i64,
}

/// Decode one planning authority tuple into the transport-neutral typed
/// values consumed by Forge control.
pub(super) fn decode_authority(
    value: &PlanningAuthorityDto,
) -> Result<(ResolvedWorkspaceScope, ActivityCoordinatorActor), ForgeError> {
    let workspace_id = require_id(value.scope.workspace_id, "planning workspace id")?;
    require_id(value.scope.locator.location_id, "planning location id")?;
    let activity_id = require_id(value.activity_id, "planning activity id")?;
    let session_id = require_id(value.actor.session_id, "planning session id")?;
    let agent_id = require_id(value.actor.agent_id, "planning agent id")?;
    let scope = decode_scope(&value.scope)?;
    let actor = ActivityCoordinatorActor::new(
        WorkspaceId::from_uuid(workspace_id),
        ActivityId::from_uuid(activity_id),
        AgentInstanceId::from_uuid(agent_id),
        ActivityCoordinatorRevision::new(value.actor.expected_coordinator_revision)
            .map_err(|_| ForgeError::invalid_input("coordinator revision is invalid"))?,
        decode_principal(&value.actor.principal)?,
        AgentSessionId::from_uuid(session_id),
    );
    Ok((scope, actor))
}

fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}
