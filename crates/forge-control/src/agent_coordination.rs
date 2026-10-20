//! Exact Workspace-local participation and handoff application operations.

use forge_domain::{
    ActivityId, ActivityPresenceSnapshot, AgentEvent, AgentEventListLimit, AgentInboxListLimit,
    AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, InboxEntry,
};

use crate::agent::map_agent_store_error;
use crate::{
    AgentSessionResolveRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope,
};

#[derive(Debug, Clone)]
pub struct AgentCoordinationQuery {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
}

#[must_use]
#[derive(Debug, Clone)]
pub struct AgentCoordinationView {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub presence: ActivityPresenceSnapshot,
    pub events: Vec<AgentEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInboxListRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub limit: AgentInboxListLimit,
}

impl ForgeControl {
    pub fn agent_coordination_view(
        &self,
        request: &AgentCoordinationQuery,
    ) -> Result<AgentCoordinationView, ControlError> {
        let (scope, store) = self.open_agent_workspace(&request.scope)?;
        let events = store
            .list_agent_events(request.activity_id, AgentEventListLimit::DEFAULT)
            .map_err(map_agent_store_error)?;
        let presence = store
            .list_agent_presence(request.activity_id)
            .map_err(map_agent_store_error)?;
        if events.first().map(AgentEvent::membership_revision) != presence.membership_revision() {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(AgentCoordinationView {
            scope,
            activity_id: request.activity_id,
            presence,
            events,
        })
    }

    pub fn agent_inbox_list(
        &self,
        request: &AgentInboxListRequest,
    ) -> Result<Vec<InboxEntry>, ControlError> {
        let _session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, store) = self.open_agent_workspace(&request.scope)?;
        let agent = store
            .get_agent(request.agent_id)
            .map_err(map_agent_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
        if agent.activity_id() != request.activity_id
            || agent.principal() != request.principal
            || agent.session_id() != Some(request.session_id)
        {
            return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
        }
        let result = store
            .list_agent_inbox(request.agent_id, request.session_id, request.limit)
            .map_err(map_agent_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }
}
