//! Application control for Agent attachment, exact focus, and public work.
//!
//! The service deliberately accepts an explicit `ResolvedWorkspaceScope` and
//! `ActivityId` for every operation.  It reopens and revalidates that scope on
//! each call, then delegates durable authority to `WorkspaceStore`.

use forge_domain::{
    ActivityId, AgentAttachmentProjection, AgentContextProjection, AgentFocus, AgentInstanceId,
    AgentInstanceRevision, AgentListLimit, AgentWorkUpdate, McpTokenId, RegisteredAgentInstance,
    SetAgentFocus, TimestampMillis,
};
use forge_persistence::{AgentStoreError, WorkspaceStore, WorkspaceStoreError};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Maximum Agent attachment projections returned by one control request.
pub const MAX_AGENT_PROJECTION_RESULTS: usize = forge_domain::MAX_AGENT_LIST_RESULTS as usize;

/// Request to attach a newly created Agent instance to an existing Activity.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAttachRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent: RegisteredAgentInstance,
}

/// Request to set an Agent's exact Goal/DAG/node focus.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentFocusRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub expected_revision: AgentInstanceRevision,
    pub transport_principal: Option<McpTokenId>,
    pub focus: AgentFocus,
    pub observed_at: TimestampMillis,
}

/// Request to append one bounded operator-safe public work update.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkUpdateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub transport_principal: Option<McpTokenId>,
    pub update: AgentWorkUpdate,
}

/// Request to detach an Agent instance.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDetachRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub expected_revision: AgentInstanceRevision,
    pub transport_principal: Option<McpTokenId>,
    pub observed_at: TimestampMillis,
}

/// Request to list Agent attachment/liveness projections for one Activity.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentListRequest {
    pub scope: ResolvedWorkspaceScope,
    /// `None` lists all agents attached to the selected Workspace.  A value
    /// narrows the same bounded snapshot to one Activity when an adapter needs
    /// that view.
    pub activity_id: Option<ActivityId>,
    pub now: TimestampMillis,
    pub limit: AgentListLimit,
}

/// Request to load one bounded Agent context from one `SQLite` snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContextRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub now: TimestampMillis,
    pub focus_event_limit: AgentListLimit,
    pub work_update_limit: AgentListLimit,
}

impl ForgeControl {
    /// Attach the supplied application-bound Agent identity.
    pub fn agent_attach(
        &self,
        request: &AgentAttachRequest,
    ) -> Result<RegisteredAgentInstance, ControlError> {
        let (scope, mut store) = self.open_agent_workspace(&request.scope)?;
        if request.activity_id != request.agent.activity_id()
            || request.agent.workspace_id() != scope.workspace_id()
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        let result = store
            .attach_agent(&request.agent)
            .map_err(map_agent_store_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Set an exact focus. A stale DAG head or node revision is rejected by
    /// persistence; this method never remaps a focus after replanning.
    pub fn agent_set_focus(
        &self,
        request: &AgentFocusRequest,
    ) -> Result<RegisteredAgentInstance, ControlError> {
        let (scope, mut store) = self.open_agent_workspace(&request.scope)?;
        verify_agent_transport_principal(
            &store,
            request.agent_id,
            request.activity_id,
            request.transport_principal,
        )?;
        let command = SetAgentFocus::new(
            request.agent_id,
            request.activity_id,
            request.expected_revision,
            request.focus,
            request.observed_at,
        );
        let result = store
            .set_agent_focus(&command)
            .map_err(map_agent_store_error)?;
        if result.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Append one public Agent work update. Private reasoning, raw prompts,
    /// and transcripts are not representable by the domain type.
    pub fn agent_publish_work_update(
        &self,
        request: &AgentWorkUpdateRequest,
    ) -> Result<AgentWorkUpdate, ControlError> {
        let (scope, mut store) = self.open_agent_workspace(&request.scope)?;
        if request.activity_id != request.update.activity_id()
            || request.update.workspace_id() != scope.workspace_id()
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        verify_agent_transport_principal(
            &store,
            request.update.agent_id(),
            request.activity_id,
            request.transport_principal,
        )?;
        let result = store
            .publish_agent_work_update(&request.update)
            .map_err(map_agent_store_error)?;
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Detach one Agent instance through exact revision CAS.
    pub fn agent_detach(
        &self,
        request: &AgentDetachRequest,
    ) -> Result<RegisteredAgentInstance, ControlError> {
        let (scope, mut store) = self.open_agent_workspace(&request.scope)?;
        verify_agent_transport_principal(
            &store,
            request.agent_id,
            request.activity_id,
            request.transport_principal,
        )?;
        let command = forge_domain::DetachAgent::new(
            request.agent_id,
            request.activity_id,
            request.expected_revision,
            request.observed_at,
        );
        let result = store
            .detach_agent(&command)
            .map_err(map_agent_store_error)?;
        if result.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// List durable Agent attachments while deriving Activity lease/liveness
    /// from the existing Activity authority.
    pub fn agent_list(
        &self,
        request: &AgentListRequest,
    ) -> Result<Vec<AgentAttachmentProjection>, ControlError> {
        if usize::try_from(request.limit.get())
            .map_or(true, |value| value > MAX_AGENT_PROJECTION_RESULTS)
        {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }
        let (scope, store) = self.open_agent_workspace(&request.scope)?;
        let result = store
            .list_agent_attachments(request.activity_id, request.now, request.limit)
            .map_err(map_agent_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    /// Read one Agent context from a bounded single-snapshot projection.
    pub fn agent_get_context(
        &self,
        request: &AgentContextRequest,
    ) -> Result<Option<AgentContextProjection>, ControlError> {
        if usize::try_from(request.focus_event_limit.get())
            .map_or(true, |value| value > MAX_AGENT_PROJECTION_RESULTS)
            || usize::try_from(request.work_update_limit.get())
                .map_or(true, |value| value > MAX_AGENT_PROJECTION_RESULTS)
        {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }
        let (scope, store) = self.open_agent_workspace(&request.scope)?;
        let result = store
            .get_agent_context(
                request.agent_id,
                request.activity_id,
                request.now,
                request.focus_event_limit,
                request.work_update_limit,
            )
            .map_err(map_agent_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    fn open_agent_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
        let (fresh_scope, store) = self.open_resolved_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((fresh_scope, store))
    }

    fn confirm_agent_write(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> Result<(), ControlError> {
        if self.committed_scope_matches_with_store(scope, store) {
            Ok(())
        } else {
            Err(ControlError::committed())
        }
    }
}

fn verify_agent_transport_principal(
    store: &WorkspaceStore,
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
    transport_principal: Option<McpTokenId>,
) -> Result<(), ControlError> {
    let agent = store
        .get_agent(agent_id)
        .map_err(map_agent_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
    if agent.activity_id() != activity_id
        || agent.transport_principal() != transport_principal
        || !agent.attachment_state().is_attached()
    {
        return Err(ControlError::new(ControlErrorCode::AgentConflict));
    }
    Ok(())
}

pub(crate) fn map_agent_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::Agent(AgentStoreError::AgentNotFound(_)) => {
            ControlErrorCode::AgentNotFound
        }
        WorkspaceStoreError::Agent(
            AgentStoreError::FocusGoalMissing(_)
            | AgentStoreError::FocusDagMissing(_)
            | AgentStoreError::FocusNodeMissing(_)
            | AgentStoreError::FocusGoalRevisionConflict { .. }
            | AgentStoreError::FocusDagNotCurrent { .. }
            | AgentStoreError::FocusNodeRevisionConflict { .. }
            | AgentStoreError::FocusWorkspaceMismatch,
        ) => ControlErrorCode::AgentFocusConflict,
        WorkspaceStoreError::Agent(AgentStoreError::EvidenceMissing(_)) => {
            ControlErrorCode::AgentEvidenceConflict
        }
        WorkspaceStoreError::Agent(
            AgentStoreError::IdentityConflict
            | AgentStoreError::AgentDetached(_)
            | AgentStoreError::ActivityNotFound(_)
            | AgentStoreError::ActivityWorkspaceMismatch { .. }
            | AgentStoreError::ActivityAgentMismatch { .. }
            | AgentStoreError::WorkspaceMismatch { .. }
            | AgentStoreError::RevisionConflict { .. }
            | AgentStoreError::WorkSequenceConflict { .. }
            | AgentStoreError::Transition(_)
            | AgentStoreError::InvalidProjection(_)
            | AgentStoreError::IntegerOverflow,
        ) => ControlErrorCode::AgentConflict,
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::ExistingWorkspaceBindingMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
        | WorkspaceStoreError::WorkspaceRootCanonicalPathChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForgeControlWorker;
    use forge_domain::{
        AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentListLimit, AgentTransportKind,
        AgentWorkPhase, AgentWorkSummary, AgentWorkUpdate, AgentWorkUpdateId,
        AgentWorkUpdateSequence, EstablishWorkspace, LocationId, LocationRevision, McpTokenId,
        RuntimeInstanceId, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        control: ForgeControl,
        root: PathBuf,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "forge-control-agent-{}-{serial}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xB001));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xB002));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Agent Fixture",
            &location_root,
            TimestampMillis::new(1)?,
        )?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let command = EstablishWorkspace::new(
            workspace_id,
            location.id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(2)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        drop(store);
        drop(locations);
        let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
        let catalog = control.workspace_list(location_id, LocationRevision::INITIAL)?;
        let locator = catalog
            .iter()
            .find(|entry| entry.display_name() == "workspace")
            .ok_or("fixture Workspace catalog is empty")?
            .locator()
            .clone();
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xB003));
        let _ = control.bootstrap_activity(
            &scope,
            activity_id,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xB004)),
            TimestampMillis::new(3)?,
            TimestampMillis::new(100)?,
        )?;
        Ok(Fixture {
            control,
            root,
            scope,
            activity_id,
        })
    }

    fn agent(
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
    ) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentInstance::create(
            AgentInstanceId::from_uuid(Uuid::from_u128(0xB005)),
            scope.workspace_id(),
            activity_id,
            AgentDisplayName::new("Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::Mcp,
            TimestampMillis::new(4)?,
        ))
    }

    #[test]
    fn control_agent_lifecycle_projects_workspace_and_activity_liveness()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let agent = agent(&fixture.scope, fixture.activity_id)?;
        let attached = fixture.control.agent_attach(&AgentAttachRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent: agent.clone(),
        })?;
        assert_eq!(attached, agent);
        let listed = fixture.control.agent_list(&AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: None,
            now: TimestampMillis::new(5)?,
            limit: AgentListLimit::DEFAULT,
        })?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent().id(), agent.id());
        assert_eq!(
            listed[0].activity().liveness(),
            forge_domain::ActivityLiveness::Live
        );

        let focused = fixture.control.agent_set_focus(&AgentFocusRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: agent.id(),
            expected_revision: agent.revision(),
            transport_principal: None,
            focus: AgentFocus::unfocused(),
            observed_at: TimestampMillis::new(6)?,
        })?;
        let update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xB006)),
            agent.id(),
            fixture.scope.workspace_id(),
            fixture.activity_id,
            AgentWorkUpdateSequence::INITIAL,
            AgentWorkPhase::Planning,
            AgentWorkSummary::new("Planning the selected node".to_owned())?,
            Vec::new(),
            TimestampMillis::new(7)?,
        )?;
        assert_eq!(
            fixture
                .control
                .agent_publish_work_update(&AgentWorkUpdateRequest {
                    scope: fixture.scope.clone(),
                    activity_id: fixture.activity_id,
                    transport_principal: None,
                    update: update.clone(),
                })?,
            update
        );
        let detached = fixture.control.agent_detach(&AgentDetachRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: focused.id(),
            expected_revision: focused.revision(),
            transport_principal: None,
            observed_at: TimestampMillis::new(8)?,
        })?;
        assert!(detached.attachment_state().is_detached());
        let context = fixture
            .control
            .agent_get_context(&AgentContextRequest {
                scope: fixture.scope,
                activity_id: fixture.activity_id,
                agent_id: detached.id(),
                now: TimestampMillis::new(9)?,
                focus_event_limit: AgentListLimit::DEFAULT,
                work_update_limit: AgentListLimit::DEFAULT,
            })?
            .ok_or("control context missing")?;
        assert_eq!(context.work_updates(), std::slice::from_ref(&update));
        assert!(
            context
                .attachment()
                .agent()
                .attachment_state()
                .is_detached()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn control_rejects_a_different_transport_principal() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let principal = McpTokenId::from_uuid(Uuid::from_u128(0xB007));
        let other_principal = McpTokenId::from_uuid(Uuid::from_u128(0xB008));
        let agent = RegisteredAgentInstance::create_with_principal(
            AgentInstanceId::from_uuid(Uuid::from_u128(0xB009)),
            fixture.scope.workspace_id(),
            fixture.activity_id,
            AgentDisplayName::new("HTTP Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::StreamableHttp,
            Some(principal),
            TimestampMillis::new(4)?,
        );
        let _ = fixture.control.agent_attach(&AgentAttachRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent: agent.clone(),
        })?;

        let Err(error) = fixture.control.agent_set_focus(&AgentFocusRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: agent.id(),
            expected_revision: agent.revision(),
            transport_principal: Some(other_principal),
            focus: AgentFocus::unfocused(),
            observed_at: TimestampMillis::new(5)?,
        }) else {
            return Err("a different token principal controlled the Agent".into());
        };
        assert_eq!(error.code(), ControlErrorCode::AgentConflict);

        let focused = fixture.control.agent_set_focus(&AgentFocusRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: agent.id(),
            expected_revision: agent.revision(),
            transport_principal: Some(principal),
            focus: AgentFocus::unfocused(),
            observed_at: TimestampMillis::new(6)?,
        })?;
        assert_eq!(focused.revision().get(), 2);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn worker_agent_requests_are_owned_and_joined() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let agent = agent(&fixture.scope, fixture.activity_id)?;
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let _ = client.agent_attach(AgentAttachRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent,
        })?;
        let listed = client.agent_list(AgentListRequest {
            scope: fixture.scope,
            activity_id: None,
            now: TimestampMillis::new(5)?,
            limit: AgentListLimit::DEFAULT,
        })?;
        assert_eq!(listed.len(), 1);
        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
