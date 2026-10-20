//! Application control for Agent attachment, exact focus, and public work.
//!
//! The service deliberately accepts an explicit `ResolvedWorkspaceScope` and
//! `ActivityId` for every operation.  It reopens and revalidates that scope on
//! each call, then delegates durable authority to `WorkspaceStore`.

use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentAttachmentProjection, AgentContextProjection,
    AgentFocus, AgentInstanceId, AgentInstanceRevision, AgentListLimit, AgentWorkUpdate,
    AuthenticatedPrincipal, ExecutionAgentProvenance, ExecutionCommandId, ExecutionId,
    GoalNodeAttribution, RegisteredAgentInstance, SetAgentFocus, TimestampMillis,
};
use forge_persistence::{AgentStoreError, WorkspaceStore, WorkspaceStoreError};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Maximum Agent attachment projections returned by one control request.
pub const MAX_AGENT_PROJECTION_RESULTS: usize = forge_domain::MAX_AGENT_LIST_RESULTS as usize;

/// Request to set an Agent's exact Goal/DAG/node focus.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentFocusRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub actor: ActivityCoordinatorActor,
    pub agent_id: AgentInstanceId,
    pub expected_revision: AgentInstanceRevision,
    pub focus: AgentFocus,
    pub observed_at: TimestampMillis,
}

/// Exact Agent work authority required before an agent-originated execution
/// may enter the approval/execution pipeline.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentExecutionAuthorityRequest {
    pub session_id: forge_domain::AgentSessionId,
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub expected_revision: AgentInstanceRevision,
    pub principal: AuthenticatedPrincipal,
    pub attribution: GoalNodeAttribution,
    pub command_id: ExecutionCommandId,
}

impl AgentExecutionAuthorityRequest {
    pub(crate) fn provenance(&self, execution_id: ExecutionId) -> ExecutionAgentProvenance {
        ExecutionAgentProvenance::new(
            execution_id,
            self.agent_id,
            self.expected_revision,
            self.principal,
            self.attribution,
            self.command_id.clone(),
            self.session_id,
        )
    }
}

/// Request to append one bounded operator-safe public work update.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkUpdateRequest {
    pub session_id: forge_domain::AgentSessionId,
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub principal: AuthenticatedPrincipal,
    pub update: AgentWorkUpdate,
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
    /// Set an exact focus. A stale DAG head or node revision is rejected by
    /// persistence; this method never remaps a focus after replanning.
    pub(crate) fn agent_set_focus(
        &self,
        request: &AgentFocusRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredAgentInstance, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.actor.session_id(),
            principal: request.actor.principal(),
        })?;
        let (scope, mut store) = self.open_agent_workspace(&request.scope)?;
        if request.actor.activity_id() != request.activity_id {
            return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
        }
        let command = SetAgentFocus::new(
            request.agent_id,
            request.activity_id,
            request.expected_revision,
            request.focus,
            request.observed_at,
        );
        let result = store
            .set_agent_focus(request.actor, &command, admitted_at)
            .map_err(map_agent_store_error)?;
        if result.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        self.confirm_agent_write(&scope, &store)?;
        Ok(result)
    }

    /// Append one public Agent work update. Private reasoning, raw prompts,
    /// and transcripts are not representable by the domain type.
    pub(crate) fn agent_publish_work_update(
        &self,
        request: &AgentWorkUpdateRequest,
        admitted_at: TimestampMillis,
    ) -> Result<AgentWorkUpdate, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, mut store) = self.open_agent_workspace(&request.scope)?;
        if request.activity_id != request.update.activity_id()
            || request.update.workspace_id() != scope.workspace_id()
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        verify_agent_principal(
            &store,
            request.update.agent_id(),
            request.activity_id,
            request.principal,
            request.session_id,
        )?;
        let result = store
            .publish_agent_work_update(
                &request.update,
                request.session_id,
                request.principal,
                admitted_at,
            )
            .map_err(map_agent_store_error)?;
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

    /// Verify the exact attached Agent and Goal/DAG/node focus before an
    /// agent-originated process request is allowed to enter approval.
    pub fn verify_agent_execution_authority(
        &self,
        request: &AgentExecutionAuthorityRequest,
    ) -> Result<(), ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, store) = self.open_agent_workspace(&request.scope)?;
        let agent = store
            .get_agent(request.agent_id)
            .map_err(map_agent_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
        if agent.workspace_id() != scope.workspace_id()
            || agent.activity_id() != request.activity_id
            || agent.revision() != request.expected_revision
            || agent.principal() != request.principal
            || agent.session_id() != Some(request.session_id)
            || !agent.attachment_state().is_attached()
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }

        let focus = agent.focus();
        let goal = focus
            .goal()
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentFocusConflict))?;
        let dag_revision = focus
            .dag_revision()
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentFocusConflict))?;
        let node = focus
            .node()
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentFocusConflict))?;
        let attribution = request.attribution;
        if goal.goal_id() != attribution.goal_id()
            || goal.expected_revision() != attribution.expected_goal_revision()
            || dag_revision != attribution.dag_revision()
            || node.node_id() != attribution.node_id()
            || node.expected_revision() != attribution.expected_node_revision()
        {
            return Err(ControlError::new(ControlErrorCode::AgentFocusConflict));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(())
    }

    pub(crate) fn open_agent_workspace(
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

    pub(crate) fn confirm_agent_write(
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

    pub(crate) fn confirm_agent_read(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> Result<(), ControlError> {
        if self.committed_scope_matches_with_store(scope, store) {
            Ok(())
        } else {
            Err(ControlError::new(
                ControlErrorCode::ProjectionResyncRequired,
            ))
        }
    }
}

fn verify_agent_principal(
    store: &WorkspaceStore,
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
    principal: AuthenticatedPrincipal,
    session_id: forge_domain::AgentSessionId,
) -> Result<(), ControlError> {
    let agent = store
        .get_agent(agent_id)
        .map_err(map_agent_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
    if agent.activity_id() != activity_id
        || agent.principal() != principal
        || agent.session_id() != Some(session_id)
        || !agent.attachment_state().is_attached()
    {
        return Err(ControlError::new(ControlErrorCode::AgentConflict));
    }
    Ok(())
}

pub(crate) fn map_agent_store_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(&error, WorkspaceStoreError::Coordinator(_)) {
        return crate::coordinator::map_coordinator_store_error(error);
    }
    let code = match &error {
        WorkspaceStoreError::Agent(AgentStoreError::AgentNotFound(_)) => {
            ControlErrorCode::AgentNotFound
        }
        WorkspaceStoreError::Agent(
            AgentStoreError::SessionAttachmentConflict
            | AgentStoreError::SessionPrincipalConflict
            | AgentStoreError::SessionBindingConflict
            | AgentStoreError::PrincipalConflict,
        ) => ControlErrorCode::AgentSessionConflict,
        WorkspaceStoreError::Agent(AgentStoreError::UnresolvedLegacy(_)) => {
            ControlErrorCode::AgentSessionUnresolved
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
        WorkspaceStoreError::Agent(
            AgentStoreError::CurrentCoordinatorCannotDetach(_)
            | AgentStoreError::ActivityNotLive(_)
            | AgentStoreError::ActiveWriterLease(_)
            | AgentStoreError::ActiveExecution(_),
        ) => ControlErrorCode::CoordinatorConflict,
        WorkspaceStoreError::Agent(AgentStoreError::ActivityLeaseNotLive(_)) => {
            ControlErrorCode::ActivityLeaseConflict
        }
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
        AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentListLimit, AgentSessionId,
        AgentSessionOpenRequestId, AgentTransportKind, AgentWorkPhase, AgentWorkSummary,
        AgentWorkUpdate, AgentWorkUpdateId, AgentWorkUpdateSequence, DagNodeId, DagNodeRevision,
        DagRevisionNumber, DirectTokenId, EstablishWorkspace, ExecutionCommandId, GoalId,
        GoalNodeAttribution, GoalRevision, LocationId, LocationRevision, OpenAgentSession,
        RuntimeInstanceId, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{AgentSessionCatalog, GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn open_session(
        control: &ForgeControl,
        agent: &RegisteredAgentInstance,
    ) -> Result<AgentSessionId, Box<dyn std::error::Error>> {
        let session_id = agent
            .session_id()
            .ok_or("test Agent session is unresolved")?;
        let _session = control.agent_session_open(&OpenAgentSession::new(
            session_id,
            AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(
                agent.id().into_uuid().as_u128().wrapping_add(0x100),
            )),
            agent.principal(),
            agent.created_at(),
        ))?;
        Ok(session_id)
    }

    struct Fixture {
        control: ForgeControl,
        root: PathBuf,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
    }

    fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        Ok(TimestampMillis::new(millis)?)
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
        let catalog = control.workspace_discover(location_id, LocationRevision::INITIAL)?;
        let locator = catalog
            .iter()
            .find(|entry| entry.display_name() == "workspace")
            .ok_or("fixture Workspace catalog is empty")?
            .locator()
            .clone();
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xB003));
        let admitted_at = timestamp_now()?;
        let lease_until = TimestampMillis::new(admitted_at.get() + 60_000)?;
        let _ = control.bootstrap_activity(
            &scope,
            activity_id,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(0xB004)),
            admitted_at,
            lease_until,
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
        let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(0xB005));
        Ok(RegisteredAgentInstance::create_bound(
            agent_id,
            scope.workspace_id(),
            activity_id,
            AgentSessionId::from_uuid(agent_id.into_uuid()),
            AgentDisplayName::new("Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::Retired,
            AuthenticatedPrincipal::TrustedStdio,
            TimestampMillis::new(4)?,
        ))
    }

    #[test]
    fn binding_scope_fences_distinguish_read_resync_from_committed_uncertainty()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        let (_, store) = fixture.control.open_agent_workspace(&fixture.scope)?;
        assert!(
            fixture
                .control
                .confirm_agent_read(&fixture.scope, &store)
                .is_ok()
        );
        let _disabled =
            fixture
                .control
                .set_location_state(&forge_domain::SetLocationState::new(
                    fixture.scope.locator().location_id(),
                    fixture.scope.locator().expected_revision(),
                    forge_domain::LocationState::Disabled,
                    TimestampMillis::new(20)?,
                ))?;
        let read = fixture.control.confirm_agent_read(&fixture.scope, &store);
        assert!(
            matches!(read, Err(error) if error.code() == ControlErrorCode::ProjectionResyncRequired && !error.is_committed())
        );
        let write = fixture.control.confirm_agent_write(&fixture.scope, &store);
        assert!(matches!(write, Err(error) if error.is_committed()));
        drop(store);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn control_agent_lifecycle_projects_workspace_and_activity_liveness()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let agent = agent(&fixture.scope, fixture.activity_id)?;
        let session_id = open_session(&fixture.control, &agent)?;
        let attached = crate::legacy_agent_fixture::seed_agent(
            &fixture.control,
            &fixture.scope,
            &agent,
            forge_domain::AgentEventId::from_uuid(agent.id().into_uuid()),
        )?;
        assert_eq!(attached, agent);
        let coordinator = fixture.control.activity_coordinator_claim(
            &crate::CoordinatorClaimRequest {
                session_id,
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                agent_id: agent.id(),
                principal: AuthenticatedPrincipal::TrustedStdio,
                observed_at: TimestampMillis::new(5)?,
            },
            timestamp_now()?,
        )?;
        let actor = ActivityCoordinatorActor::new(
            fixture.scope.workspace_id(),
            fixture.activity_id,
            coordinator.agent_id(),
            coordinator.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            session_id,
        );
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

        let participant_id = AgentInstanceId::from_uuid(Uuid::from_u128(0xB00D));
        let participant = RegisteredAgentInstance::create_bound(
            participant_id,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            AgentSessionId::from_uuid(participant_id.into_uuid()),
            AgentDisplayName::new("Participant".to_owned())?,
            AgentDeclaredRole::new("worker".to_owned())?,
            AgentTransportKind::Retired,
            AuthenticatedPrincipal::TrustedStdio,
            TimestampMillis::new(4)?,
        );
        let participant_session_id = open_session(&fixture.control, &participant)?;
        let participant = crate::legacy_agent_fixture::seed_agent(
            &fixture.control,
            &fixture.scope,
            &participant,
            forge_domain::AgentEventId::from_uuid(participant_id.into_uuid()),
        )?;

        let focused = fixture.control.agent_set_focus(
            &AgentFocusRequest {
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                actor,
                agent_id: participant.id(),
                expected_revision: participant.revision(),
                focus: AgentFocus::unfocused(),
                observed_at: TimestampMillis::new(6)?,
            },
            timestamp_now()?,
        )?;
        let update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xB006)),
            participant.id(),
            fixture.scope.workspace_id(),
            fixture.activity_id,
            AgentWorkUpdateSequence::INITIAL,
            AgentWorkPhase::Planning,
            AgentWorkSummary::new("Planning the selected node".to_owned())?,
            Vec::new(),
            TimestampMillis::new(7)?,
        )?;
        assert_eq!(
            fixture.control.agent_publish_work_update(
                &AgentWorkUpdateRequest {
                    session_id: participant_session_id,
                    scope: fixture.scope.clone(),
                    activity_id: fixture.activity_id,
                    principal: AuthenticatedPrincipal::TrustedStdio,
                    update: update.clone(),
                },
                timestamp_now()?
            )?,
            update
        );
        let expired_at = TimestampMillis::new(timestamp_now()?.get() + 120_000)?;
        let expired_update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xB007)),
            participant.id(),
            fixture.scope.workspace_id(),
            fixture.activity_id,
            AgentWorkUpdateSequence::new(2)?,
            AgentWorkPhase::Verifying,
            AgentWorkSummary::new("Expired authority must identify lease recovery".to_owned())?,
            Vec::new(),
            TimestampMillis::new(7)?,
        )?;
        let expired_result = fixture.control.agent_publish_work_update(
            &AgentWorkUpdateRequest {
                session_id: participant_session_id,
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                principal: AuthenticatedPrincipal::TrustedStdio,
                update: expired_update,
            },
            expired_at,
        );
        assert!(matches!(
            expired_result,
            Err(error) if error.code() == ControlErrorCode::ActivityLeaseConflict
                && !error.is_committed()
        ));
        let context = fixture
            .control
            .agent_get_context(&AgentContextRequest {
                scope: fixture.scope,
                activity_id: fixture.activity_id,
                agent_id: focused.id(),
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
                .is_attached()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn closed_session_fences_focus_work_update_and_execution_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let agent = agent(&fixture.scope, fixture.activity_id)?;
        let session_id = open_session(&fixture.control, &agent)?;
        let attached = crate::legacy_agent_fixture::seed_agent(
            &fixture.control,
            &fixture.scope,
            &agent,
            forge_domain::AgentEventId::from_uuid(agent.id().into_uuid()),
        )?;
        let coordinator = fixture.control.activity_coordinator_claim(
            &crate::CoordinatorClaimRequest {
                session_id,
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                agent_id: agent.id(),
                principal: AuthenticatedPrincipal::TrustedStdio,
                observed_at: TimestampMillis::new(5)?,
            },
            timestamp_now()?,
        )?;
        let actor = ActivityCoordinatorActor::new(
            fixture.scope.workspace_id(),
            fixture.activity_id,
            coordinator.agent_id(),
            coordinator.revision(),
            AuthenticatedPrincipal::TrustedStdio,
            session_id,
        );
        let mut catalog = AgentSessionCatalog::open(fixture.root.join("agent-sessions.sqlite3"))?;
        let current = catalog
            .resolve(session_id, AuthenticatedPrincipal::TrustedStdio)?
            .ok_or("test Agent session was not issued")?;
        let _closed = catalog.close(
            session_id,
            AuthenticatedPrincipal::TrustedStdio,
            current.revision(),
            TimestampMillis::new(10)?,
        )?;
        let actor_lookup =
            fixture
                .control
                .activity_coordinator_actor(&crate::CoordinatorActorRequest {
                    scope: fixture.scope.clone(),
                    activity_id: fixture.activity_id,
                    principal: AuthenticatedPrincipal::TrustedStdio,
                })?;
        assert_eq!(actor_lookup, None);

        let focus_error = fixture.control.agent_set_focus(
            &AgentFocusRequest {
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                actor,
                agent_id: attached.id(),
                expected_revision: attached.revision(),
                focus: AgentFocus::unfocused(),
                observed_at: TimestampMillis::new(11)?,
            },
            timestamp_now()?,
        );
        assert!(matches!(
            focus_error,
            Err(error) if error.code() == ControlErrorCode::AgentSessionClosed
        ));

        let update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(0xB00A)),
            attached.id(),
            fixture.scope.workspace_id(),
            fixture.activity_id,
            AgentWorkUpdateSequence::INITIAL,
            AgentWorkPhase::Executing,
            AgentWorkSummary::new("closed session must not publish".to_owned())?,
            Vec::new(),
            TimestampMillis::new(11)?,
        )?;
        let update_error = fixture.control.agent_publish_work_update(
            &AgentWorkUpdateRequest {
                session_id,
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                principal: AuthenticatedPrincipal::TrustedStdio,
                update,
            },
            timestamp_now()?,
        );
        assert!(matches!(
            update_error,
            Err(error) if error.code() == ControlErrorCode::AgentSessionClosed
        ));

        let authority = AgentExecutionAuthorityRequest {
            session_id,
            scope: fixture.scope,
            activity_id: fixture.activity_id,
            agent_id: attached.id(),
            expected_revision: attached.revision(),
            principal: AuthenticatedPrincipal::TrustedStdio,
            attribution: GoalNodeAttribution::new(
                GoalId::from_uuid(Uuid::from_u128(0xB00B)),
                GoalRevision::INITIAL,
                DagRevisionNumber::INITIAL,
                DagNodeId::from_uuid(Uuid::from_u128(0xB00C)),
                DagNodeRevision::INITIAL,
            ),
            command_id: ExecutionCommandId::new("make:ci".to_owned())?,
        };
        let execution_error = fixture.control.verify_agent_execution_authority(&authority);
        assert!(matches!(
            execution_error,
            Err(error) if error.code() == ControlErrorCode::AgentSessionClosed
        ));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn control_rejects_a_different_transport_principal() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let principal = DirectTokenId::from_uuid(Uuid::from_u128(0xB007));
        let other_principal = DirectTokenId::from_uuid(Uuid::from_u128(0xB008));
        let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(0xB009));
        let session_id = AgentSessionId::from_uuid(agent_id.into_uuid());
        let agent = RegisteredAgentInstance::create_bound(
            agent_id,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            session_id,
            AgentDisplayName::new("HTTP Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::StreamableHttp,
            AuthenticatedPrincipal::DirectToken(principal),
            TimestampMillis::new(4)?,
        );
        let _ = open_session(&fixture.control, &agent)?;
        let _ = crate::legacy_agent_fixture::seed_agent(
            &fixture.control,
            &fixture.scope,
            &agent,
            forge_domain::AgentEventId::from_uuid(agent.id().into_uuid()),
        )?;
        let coordinator = fixture.control.activity_coordinator_claim(
            &crate::CoordinatorClaimRequest {
                session_id,
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                agent_id: agent.id(),
                principal: AuthenticatedPrincipal::DirectToken(principal),
                observed_at: TimestampMillis::new(5)?,
            },
            timestamp_now()?,
        )?;
        let bad_actor = ActivityCoordinatorActor::new(
            fixture.scope.workspace_id(),
            fixture.activity_id,
            coordinator.agent_id(),
            coordinator.revision(),
            AuthenticatedPrincipal::DirectToken(other_principal),
            session_id,
        );
        let actor = ActivityCoordinatorActor::new(
            fixture.scope.workspace_id(),
            fixture.activity_id,
            coordinator.agent_id(),
            coordinator.revision(),
            AuthenticatedPrincipal::DirectToken(principal),
            session_id,
        );

        let Err(error) = fixture.control.agent_set_focus(
            &AgentFocusRequest {
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                actor: bad_actor,
                agent_id: agent.id(),
                expected_revision: agent.revision(),
                focus: AgentFocus::unfocused(),
                observed_at: TimestampMillis::new(6)?,
            },
            timestamp_now()?,
        ) else {
            return Err("a different token principal controlled the Agent".into());
        };
        assert_eq!(error.code(), ControlErrorCode::AgentSessionNotFound);

        let focused = fixture.control.agent_set_focus(
            &AgentFocusRequest {
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                actor,
                agent_id: agent.id(),
                expected_revision: agent.revision(),
                focus: AgentFocus::unfocused(),
                observed_at: TimestampMillis::new(7)?,
            },
            timestamp_now()?,
        )?;
        assert_eq!(focused.revision().get(), 2);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn worker_agent_requests_are_owned_and_joined() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let agent = agent(&fixture.scope, fixture.activity_id)?;
        let _ = open_session(&fixture.control, &agent)?;
        let _ = crate::legacy_agent_fixture::seed_agent(
            &fixture.control,
            &fixture.scope,
            &agent,
            forge_domain::AgentEventId::from_uuid(agent.id().into_uuid()),
        )?;
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
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
