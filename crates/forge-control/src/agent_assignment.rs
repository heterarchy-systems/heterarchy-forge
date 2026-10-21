//! Control authority for durable connected-Agent assignments.
//!
//! This layer authenticates issued sessions and exact Activity attachments,
//! then delegates lifecycle CAS and Goal/DAG fences to `WorkspaceStore`. It does
//! not create provider Chats, launch workers, provision worktrees, or complete
//! canonical DAG nodes.

use forge_domain::{
    AcknowledgeAgentAssignmentCancellation, ActivityCoordinatorActor, ActivityId,
    AgentAssignmentId, AgentAssignmentSummary, AgentAssignmentTarget, AgentInstanceId,
    AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal, CancelAgentAssignment,
    ClaimAgentAssignment, InterruptAgentAssignment, OfferAgentAssignment,
    RegisteredAgentAssignment, ReviewAgentAssignment, SubmitAgentAssignment, TimestampMillis,
};
use forge_persistence::{
    AgentAssignmentOfferSealSnapshot, AgentAssignmentStoreError, WorkspaceStore,
    WorkspaceStoreError,
};

use crate::agent_session::AgentSessionResolveRequest;
use crate::{
    ControlError, ControlErrorCode, ForgeControl, GoalDeletionAuthority, ResolvedWorkspaceScope,
};

pub const MAX_ASSIGNMENT_LIST_RESULTS: u32 = 32;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentReadAuthority {
    pub session_id: AgentSessionId,
    pub agent_id: AgentInstanceId,
    pub expected_agent_revision: AgentInstanceRevision,
    pub principal: AuthenticatedPrincipal,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAssignmentMutation {
    Offer(OfferAgentAssignment),
    Claim(ClaimAgentAssignment),
    Submit(SubmitAgentAssignment),
    Accept(ReviewAgentAssignment),
    Reject(ReviewAgentAssignment),
    Cancel(CancelAgentAssignment),
    AcknowledgeCancellation(AcknowledgeAgentAssignmentCancellation),
    Interrupt {
        coordinator: ActivityCoordinatorActor,
        command: InterruptAgentAssignment,
    },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentMutationRequest {
    pub scope: ResolvedWorkspaceScope,
    pub mutation: AgentAssignmentMutation,
}

/// Exact Workspace/Activity key used to permanently seal or read back future
/// admission for one Assignment ID. HTTP adapters must always choose the
/// Coordinator authority variant; only native Rust callers may choose local.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentOfferSealRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub assignment_id: AgentAssignmentId,
    pub authority: GoalDeletionAuthority,
    pub observed_at: TimestampMillis,
}

impl AgentAssignmentOfferSealRequest {
    /// Build a request for the exact Workspace, Activity, Assignment key.
    pub const fn new(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        assignment_id: AgentAssignmentId,
        authority: GoalDeletionAuthority,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            scope,
            activity_id,
            assignment_id,
            authority,
            observed_at,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub assignment_id: AgentAssignmentId,
    pub authority: AgentAssignmentReadAuthority,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAssignmentListRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub target_agent_id: Option<AgentInstanceId>,
    pub limit: u32,
    pub authority: AgentAssignmentReadAuthority,
}

impl ForgeControl {
    pub(crate) fn agent_assignment_mutate(
        &self,
        request: &AgentAssignmentMutationRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredAgentAssignment, ControlError> {
        let (scope, mut store) = self.open_assignment_workspace(&request.scope)?;
        self.authenticate_assignment_mutation(&scope, &store, &request.mutation)?;
        let result = match &request.mutation {
            AgentAssignmentMutation::Offer(command) => {
                store.offer_agent_assignment(command, admitted_at)
            }
            AgentAssignmentMutation::Claim(command) => {
                store.claim_agent_assignment(command, admitted_at)
            }
            AgentAssignmentMutation::Submit(command) => {
                store.submit_agent_assignment(command, admitted_at)
            }
            AgentAssignmentMutation::Accept(command) => {
                store.accept_agent_assignment(command, admitted_at)
            }
            AgentAssignmentMutation::Reject(command) => {
                store.reject_agent_assignment(command, admitted_at)
            }
            AgentAssignmentMutation::Cancel(command) => store.cancel_agent_assignment(command),
            AgentAssignmentMutation::AcknowledgeCancellation(command) => {
                store.acknowledge_agent_assignment_cancellation(command)
            }
            AgentAssignmentMutation::Interrupt { command, .. } => {
                store.interrupt_agent_assignment(command)
            }
        }
        .map_err(map_assignment_store_error)?;
        self.confirm_assignment_write(&scope, &store)?;
        Ok(result)
    }

    /// Install or exactly replay one permanent offer seal, then return the
    /// current global Assignment observation in the same `SQLite` transaction.
    pub fn agent_assignment_offer_seal(
        &self,
        request: &AgentAssignmentOfferSealRequest,
    ) -> Result<AgentAssignmentOfferSealSnapshot, ControlError> {
        let (scope, mut store) = self.open_assignment_workspace(&request.scope)?;
        let snapshot = match request.authority {
            GoalDeletionAuthority::LocalOperator => store.seal_agent_assignment_offer_local(
                scope.workspace_id(),
                request.activity_id,
                request.assignment_id,
                request.observed_at,
            ),
            GoalDeletionAuthority::Coordinator(actor) => {
                self.prove_coordinator_session(actor)?;
                store.seal_agent_assignment_offer_authorized(
                    scope.workspace_id(),
                    request.activity_id,
                    request.assignment_id,
                    actor,
                    request.observed_at,
                )
            }
        }
        .map_err(map_assignment_store_error)?;
        self.confirm_assignment_write(&scope, &store)?;
        Ok(snapshot)
    }

    /// Read back one exact durable offer seal. `None` means the seal was not
    /// committed and is not a no-offer proof.
    pub fn agent_assignment_offer_seal_get(
        &self,
        request: &AgentAssignmentOfferSealRequest,
    ) -> Result<Option<AgentAssignmentOfferSealSnapshot>, ControlError> {
        let (scope, store) = self.open_assignment_workspace(&request.scope)?;
        let snapshot = match request.authority {
            GoalDeletionAuthority::LocalOperator => store.get_agent_assignment_offer_seal_local(
                scope.workspace_id(),
                request.activity_id,
                request.assignment_id,
            ),
            GoalDeletionAuthority::Coordinator(actor) => {
                self.prove_coordinator_session(actor)?;
                store.get_agent_assignment_offer_seal_authorized(
                    scope.workspace_id(),
                    request.activity_id,
                    request.assignment_id,
                    actor,
                    request.observed_at,
                )
            }
        }
        .map_err(map_assignment_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(snapshot)
    }

    pub fn agent_assignment_get(
        &self,
        request: &AgentAssignmentGetRequest,
    ) -> Result<Option<RegisteredAgentAssignment>, ControlError> {
        let (scope, store) = self.open_assignment_workspace(&request.scope)?;
        self.prove_assignment_get_read_authority(
            &scope,
            &store,
            &request.authority,
            request.activity_id,
        )?;
        let result = store
            .get_agent_assignment(request.assignment_id)
            .map_err(map_assignment_store_error)?;
        if result.as_ref().is_some_and(|assignment| {
            let target = assignment.target();
            assignment.workspace_id() != scope.workspace_id()
                || assignment.activity_id() != request.activity_id
                || target.agent_id() != request.authority.agent_id
                || target.session_id() != request.authority.session_id
                || target.principal() != request.authority.principal
                || target.agent_revision() != request.authority.expected_agent_revision
        }) {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    pub fn agent_assignment_list(
        &self,
        request: &AgentAssignmentListRequest,
    ) -> Result<Vec<AgentAssignmentSummary>, ControlError> {
        if request.limit == 0 || request.limit > MAX_ASSIGNMENT_LIST_RESULTS {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }
        let (scope, store) = self.open_assignment_workspace(&request.scope)?;
        self.prove_assignment_read_authority(&scope, &request.authority, request.activity_id)?;
        let target_agent_id = match request.target_agent_id {
            Some(target) if target != request.authority.agent_id => {
                return Err(ControlError::new(ControlErrorCode::AgentConflict));
            }
            Some(target) => Some(target),
            None => Some(request.authority.agent_id),
        };
        let result = store
            .list_agent_assignments_for_activity(
                scope.workspace_id(),
                request.activity_id,
                target_agent_id,
                request.limit,
            )
            .map_err(map_assignment_store_error)?;
        if result.iter().any(|summary| {
            summary.workspace_id() != scope.workspace_id()
                || summary.activity_id() != request.activity_id
        }) {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    fn open_assignment_workspace(
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

    fn confirm_assignment_write(
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

    fn prove_assignment_read_authority(
        &self,
        scope: &ResolvedWorkspaceScope,
        authority: &AgentAssignmentReadAuthority,
        activity_id: ActivityId,
    ) -> Result<(), ControlError> {
        let _ = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: authority.session_id,
            principal: authority.principal,
        })?;
        let _ = self.agent_session_prove(&crate::AgentSessionProofRequest {
            scope: scope.clone(),
            activity_id,
            agent_id: authority.agent_id,
            expected_agent_revision: authority.expected_agent_revision,
            session_id: authority.session_id,
            principal: authority.principal,
        })?;
        Ok(())
    }

    fn prove_assignment_get_read_authority(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
        authority: &AgentAssignmentReadAuthority,
        activity_id: ActivityId,
    ) -> Result<(), ControlError> {
        let session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: authority.session_id,
            principal: authority.principal,
        })?;
        let agent = store
            .get_agent(authority.agent_id)
            .map_err(map_assignment_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
        if agent.workspace_id() != scope.workspace_id()
            || agent.activity_id() != activity_id
            || agent.session_id() != Some(session.id())
            || agent.principal() != authority.principal
            || !agent.attachment_state().is_attached()
        {
            return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
        }
        Ok(())
    }

    fn authenticate_assignment_mutation(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
        mutation: &AgentAssignmentMutation,
    ) -> Result<(), ControlError> {
        match mutation {
            AgentAssignmentMutation::Offer(command) => {
                self.prove_coordinator_session(command.coordinator())?;
                self.prove_target_session(
                    scope,
                    command.coordinator().activity_id(),
                    command.target(),
                )?;
            }
            AgentAssignmentMutation::Claim(command) => {
                let activity_id = Self::assignment_activity(store, command.assignment_id())?;
                self.prove_target_session(scope, activity_id, command.target())?;
            }
            AgentAssignmentMutation::Submit(command) => {
                let activity_id = Self::assignment_activity(store, command.assignment_id())?;
                self.prove_target_session(scope, activity_id, command.target())?;
            }
            AgentAssignmentMutation::Accept(command) | AgentAssignmentMutation::Reject(command) => {
                self.prove_coordinator_session(command.coordinator())?;
                if Self::assignment_activity(store, command.assignment_id())?
                    != command.coordinator().activity_id()
                {
                    return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
                }
            }
            AgentAssignmentMutation::Cancel(command) => {
                self.prove_coordinator_session(command.coordinator())?;
                if Self::assignment_activity(store, command.assignment_id())?
                    != command.coordinator().activity_id()
                {
                    return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
                }
            }
            AgentAssignmentMutation::AcknowledgeCancellation(command) => {
                let activity_id = Self::assignment_activity(store, command.assignment_id())?;
                self.prove_target_session(scope, activity_id, command.target())?;
            }
            AgentAssignmentMutation::Interrupt {
                coordinator,
                command,
            } => {
                self.prove_coordinator_session(*coordinator)?;
                let activity_id = Self::assignment_activity(store, command.assignment_id())?;
                if activity_id != coordinator.activity_id() {
                    return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
                }
                Self::validate_current_coordinator(store, *coordinator)?;
            }
        }
        Ok(())
    }

    fn prove_coordinator_session(
        &self,
        coordinator: ActivityCoordinatorActor,
    ) -> Result<(), ControlError> {
        let _ = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: coordinator.session_id(),
            principal: coordinator.principal(),
        })?;
        Ok(())
    }

    fn prove_target_session(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
        target: AgentAssignmentTarget,
    ) -> Result<(), ControlError> {
        let _ = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: target.session_id(),
            principal: target.principal(),
        })?;
        let _ = self.agent_session_prove(&crate::AgentSessionProofRequest {
            scope: scope.clone(),
            activity_id,
            agent_id: target.agent_id(),
            expected_agent_revision: target.agent_revision(),
            session_id: target.session_id(),
            principal: target.principal(),
        })?;
        Ok(())
    }

    fn assignment_activity(
        store: &WorkspaceStore,
        assignment_id: AgentAssignmentId,
    ) -> Result<ActivityId, ControlError> {
        let assignment = store
            .get_agent_assignment(assignment_id)
            .map_err(map_assignment_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentConflict))?;
        if assignment.workspace_id() != store.workspace().map_err(map_assignment_store_error)?.id()
        {
            return Err(ControlError::new(ControlErrorCode::AgentConflict));
        }
        Ok(assignment.activity_id())
    }

    fn validate_current_coordinator(
        store: &WorkspaceStore,
        actor: ActivityCoordinatorActor,
    ) -> Result<(), ControlError> {
        let binding = store
            .get_activity_coordinator(actor.activity_id())
            .map_err(map_assignment_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::CoordinatorNotFound))?;
        if binding.workspace_id() != actor.workspace_id()
            || binding.activity_id() != actor.activity_id()
            || binding.agent_id() != actor.agent_id()
            || binding.revision() != actor.expected_revision()
        {
            return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
        }
        Ok(())
    }
}

fn map_assignment_store_error(error: WorkspaceStoreError) -> ControlError {
    if matches!(
        &error,
        WorkspaceStoreError::AgentAssignmentCommittedUnconfirmed { .. }
            | WorkspaceStoreError::AgentAssignment(
                AgentAssignmentStoreError::OfferSealCommitUnconfirmed { .. }
                    | AgentAssignmentStoreError::OfferCommitUnconfirmed { .. }
            )
    ) {
        return ControlError::committed();
    }
    let code = match &error {
        WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::AssignmentNotFound(_)
            | AgentAssignmentStoreError::Agent(_)
            | AgentAssignmentStoreError::WorkspaceMismatch
            | AgentAssignmentStoreError::ActivityMismatch
            | AgentAssignmentStoreError::TargetConflict
            | AgentAssignmentStoreError::TargetRevisionConflict
            | AgentAssignmentStoreError::CoordinatorTargetSameAgent
            | AgentAssignmentStoreError::OfferAdmissionSealed { .. }
            | AgentAssignmentStoreError::InvalidOfferSealIdentity
            | AgentAssignmentStoreError::RevisionConflict
            | AgentAssignmentStoreError::Transition(_)
            | AgentAssignmentStoreError::Focus(_),
        ) => ControlErrorCode::AgentConflict,
        WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::CoordinatorMissing
            | AgentAssignmentStoreError::CoordinatorFenceConflict,
        ) => ControlErrorCode::CoordinatorConflict,
        WorkspaceStoreError::AgentAssignment(AgentAssignmentStoreError::Coordinator(_)) => {
            ControlErrorCode::CoordinatorConflict
        }
        WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::Goal(_) | AgentAssignmentStoreError::GoalConflict,
        ) => ControlErrorCode::GoalConflict,
        WorkspaceStoreError::AgentAssignment(AgentAssignmentStoreError::Dag(_)) => {
            ControlErrorCode::DagConflict
        }
        WorkspaceStoreError::AgentAssignment(
            AgentAssignmentStoreError::DagConflict | AgentAssignmentStoreError::NodeConflict,
        ) => ControlErrorCode::DagConflict,
        WorkspaceStoreError::AgentAssignment(AgentAssignmentStoreError::ActiveLimit) => {
            ControlErrorCode::CapacityExceeded
        }
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::ExistingWorkspaceBindingMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityCoordinatorActor, ActivityId, AgentAssignmentId, AgentAssignmentResult,
        AgentAssignmentState, AgentAssignmentTarget, AgentDeclaredRole, AgentDisplayName,
        AgentSessionId, AgentTransportKind, AuthenticatedPrincipal, BootstrapActivity,
        ClaimActivityCoordinator, ClaimAgentAssignment, DagAcceptanceCriterion, DagHeadRevision,
        DagNodeDefinition, DagNodeId, DagNodeObjective, DagNodeOrdinal, DagNodeTitle, DagRevision,
        DagRevisionId, DagRevisionNumber, EstablishWorkspace, GoalContract, GoalId, GoalObjective,
        GoalStatement, LocationId, LocationRevision, OfferAgentAssignment,
        RegisteredAgentAssignment, RegisteredAgentInstance, RegisteredDagNode, RegisteredGoal,
        ReviewAgentAssignment, SubmitAgentAssignment, TimestampMillis, WorkspaceId,
        WorkspaceRevision, WorkspaceRoot,
    };
    use forge_persistence::{AgentOperationsFreezeRequest, GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use crate::{
        AgentAssignmentGetRequest, AgentAssignmentMutation, AgentAssignmentMutationRequest,
        AgentAssignmentReadAuthority, AgentOperationsDelegationRequest,
        EffectFactOutboxReadRequest, ForgeControl, ResolvedWorkspaceScope,
    };

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        Ok(TimestampMillis::new(millis)?)
    }

    struct Fixture {
        root: PathBuf,
        control: ForgeControl,
        scope: ResolvedWorkspaceScope,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        coordinator: ActivityCoordinatorActor,
        target: RegisteredAgentInstance,
        goal: RegisteredGoal,
        node: RegisteredDagNode,
    }

    fn bound_agent(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        seed: u128,
        observed_at: TimestampMillis,
        principal: AuthenticatedPrincipal,
    ) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentInstance::create_bound(
            forge_domain::AgentInstanceId::from_uuid(id(seed)),
            workspace_id,
            activity_id,
            AgentSessionId::from_uuid(id(seed + 0x100)),
            AgentDisplayName::new(format!("Connected {seed}"))?,
            AgentDeclaredRole::new("participant".to_owned())?,
            AgentTransportKind::Stdio,
            principal,
            observed_at,
        ))
    }

    fn seed_goal_and_node(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        coordinator: ActivityCoordinatorActor,
    ) -> Result<(RegisteredGoal, RegisteredDagNode), Box<dyn std::error::Error>> {
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(id(0xCA20)),
            workspace_id,
            activity_id,
            GoalContract::new(
                GoalObjective::new("Coordinate connected participant work".to_owned())?,
                vec![GoalStatement::new(
                    "The participant reports a bounded result".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(7)?,
        );
        let goal = store.insert_goal(coordinator, &goal, timestamp_now()?)?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(id(0xCA21)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Research A".to_owned())?,
            DagNodeObjective::new("Research one bounded source".to_owned())?,
            vec![DagAcceptanceCriterion::new("A report exists".to_owned())?],
        )?;
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(id(0xCA22)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(8)?,
        )?;
        let node = RegisteredDagNode::create(goal.id(), dag.number(), definition, timestamp(8)?);
        let _ = store.insert_dag_revision(&dag, std::slice::from_ref(&node), &[], None)?;
        Ok((goal, node))
    }

    fn seed_coordinator_and_target(
        layout: &WorkspaceStateLayout,
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        principal: AuthenticatedPrincipal,
    ) -> Result<(ActivityCoordinatorActor, RegisteredAgentInstance), Box<dyn std::error::Error>>
    {
        let coordinator_agent =
            bound_agent(workspace_id, activity_id, 0xCA10, timestamp(4)?, principal)?;
        let target = bound_agent(workspace_id, activity_id, 0xCA11, timestamp(5)?, principal)?;
        for agent in [&coordinator_agent, &target] {
            let _ = crate::legacy_agent_fixture::seed_agent_in_database(
                &layout.database_path(),
                agent,
                forge_domain::AgentEventId::for_transition(
                    agent.id(),
                    agent.revision(),
                    forge_domain::AgentEventKind::Joined,
                ),
            )?;
        }
        let session_id = coordinator_agent
            .session_id()
            .ok_or("coordinator session missing")?;
        let binding = store.claim_activity_coordinator(
            ClaimActivityCoordinator::new(
                workspace_id,
                activity_id,
                coordinator_agent.id(),
                principal,
                timestamp(6)?,
                session_id,
            ),
            timestamp_now()?,
        )?;
        let coordinator = ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            coordinator_agent.id(),
            binding.revision(),
            principal,
            session_id,
        );
        Ok((coordinator, target))
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-control-assignment-{label}-{unique}"));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let mut locations = LocationService::new(registry);
        let location_id = LocationId::from_uuid(id(0xCA00));
        locations.register_selected_path(location_id, "Location", &location_root, timestamp(1)?)?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let workspace_id = WorkspaceId::from_uuid(id(0xCA01));
        let activity_id = ActivityId::from_uuid(id(0xCA02));
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let mut store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                timestamp(2)?,
            ),
        )?;
        let admitted_at = timestamp_now()?;
        let lease_until = TimestampMillis::new(admitted_at.get() + 60_000)?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            forge_domain::RuntimeInstanceId::from_uuid(id(0xCA03)),
            lease_until,
            admitted_at,
        ))?;
        let (coordinator, target) =
            seed_coordinator_and_target(&layout, &mut store, workspace_id, activity_id, principal)?;
        let (goal, node) = seed_goal_and_node(&mut store, workspace_id, activity_id, coordinator)?;
        drop(store);

        let control =
            ForgeControl::from_location_service(locations, root.join("agent-sessions.sqlite3"));
        let locator = WorkspaceLocator::new(
            location_id,
            LocationRevision::INITIAL,
            Path::new("workspace"),
        )?;
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        let _ = control.agent_session_open(&forge_domain::OpenAgentSession::new(
            coordinator.session_id(),
            forge_domain::AgentSessionOpenRequestId::from_uuid(id(0xCA30)),
            principal,
            timestamp(10)?,
        ))?;
        let _ = control.agent_session_open(&forge_domain::OpenAgentSession::new(
            target.session_id().ok_or("target session missing")?,
            forge_domain::AgentSessionOpenRequestId::from_uuid(id(0xCA31)),
            principal,
            timestamp(10)?,
        ))?;
        Ok(Fixture {
            root,
            control,
            scope,
            workspace_id,
            activity_id,
            coordinator,
            target,
            goal,
            node,
        })
    }

    fn workspace_root(fixture: &Fixture) -> PathBuf {
        fixture.root.join("location/workspace")
    }

    fn offer_command(
        fixture: &Fixture,
        assignment_seed: u128,
        target_revision: forge_domain::AgentInstanceRevision,
    ) -> Result<OfferAgentAssignment, Box<dyn std::error::Error>> {
        Ok(OfferAgentAssignment::new(
            AgentAssignmentId::from_uuid(id(assignment_seed)),
            fixture.coordinator,
            AgentAssignmentTarget::new(
                fixture.target.id(),
                fixture
                    .target
                    .session_id()
                    .ok_or("target session missing")?,
                fixture.target.principal(),
                target_revision,
            ),
            fixture.goal.id(),
            fixture.goal.revision(),
            fixture.goal.timestamps().created_at(),
            fixture.node.dag_revision(),
            DagHeadRevision::INITIAL,
            fixture.node.id(),
            fixture.node.revision(),
            Some(forge_domain::WorkCreditBudget::Three),
            timestamp(20)?,
        ))
    }

    fn drive_assignment_to_submitted(
        fixture: &mut Fixture,
        assignment_id: AgentAssignmentId,
        target_revision: forge_domain::AgentInstanceRevision,
    ) -> Result<RegisteredAgentAssignment, Box<dyn std::error::Error>> {
        // The budget is frozen at offer time, before any work happens.
        let offered = fixture.control.agent_assignment_mutate(
            &AgentAssignmentMutationRequest {
                scope: fixture.scope.clone(),
                mutation: AgentAssignmentMutation::Offer(offer_command(
                    fixture,
                    0xCA40,
                    target_revision,
                )?),
            },
            timestamp_now()?,
        )?;
        assert_eq!(offered.state(), AgentAssignmentState::Offered);
        assert_eq!(
            offered.credit_budget(),
            Some(forge_domain::WorkCreditBudget::Three)
        );
        let claimed = fixture.control.agent_assignment_mutate(
            &AgentAssignmentMutationRequest {
                scope: fixture.scope.clone(),
                mutation: AgentAssignmentMutation::Claim(ClaimAgentAssignment::new(
                    assignment_id,
                    AgentAssignmentTarget::new(
                        fixture.target.id(),
                        fixture
                            .target
                            .session_id()
                            .ok_or("target session missing")?,
                        fixture.target.principal(),
                        target_revision,
                    ),
                    offered.revision(),
                    timestamp(21)?,
                )),
            },
            timestamp_now()?,
        )?;
        assert_eq!(claimed.state(), AgentAssignmentState::Running);
        // Claim sets the target's focus, which advances its instance revision.
        let claimed_target_revision = {
            let existing = WorkspaceStateLayout::inspect_existing(workspace_root(fixture))?
                .ok_or("layout missing")?;
            let store = WorkspaceStore::open_existing(&existing)?;
            let agent = store
                .get_agent(fixture.target.id())?
                .ok_or("target agent missing after claim")?;
            drop(store);
            agent.revision()
        };
        let submitted = fixture.control.agent_assignment_mutate(
            &AgentAssignmentMutationRequest {
                scope: fixture.scope.clone(),
                mutation: AgentAssignmentMutation::Submit(SubmitAgentAssignment::new(
                    assignment_id,
                    AgentAssignmentTarget::new(
                        fixture.target.id(),
                        fixture
                            .target
                            .session_id()
                            .ok_or("target session missing")?,
                        fixture.target.principal(),
                        claimed_target_revision,
                    ),
                    claimed.revision(),
                    AgentAssignmentResult::new(
                        "bounded participant report".to_owned(),
                        Vec::new(),
                        None,
                    )?,
                    timestamp(22)?,
                )),
            },
            timestamp_now()?,
        )?;
        assert_eq!(submitted.state(), AgentAssignmentState::Submitted);
        Ok(submitted)
    }

    fn install_delegation(
        fixture: &mut Fixture,
    ) -> Result<forge_persistence::AgentOperationsDelegation, Box<dyn std::error::Error>> {
        // Seal the source delegation exactly as trusted Orchestration does.
        let freeze = {
            let existing = WorkspaceStateLayout::inspect_existing(workspace_root(fixture))?
                .ok_or("layout missing")?;
            let mut store = WorkspaceStore::open_existing(&existing)?;
            store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
                id(0xCA50),
                id(0xCA51),
                timestamp(23)?,
            )?)?
        };
        fixture
            .control
            .delegate_agent_operations(&AgentOperationsDelegationRequest {
                scope: fixture.scope.clone(),
                freeze,
                manifest_digest: [0xBE; 32],
                observed_at: timestamp(24)?,
            })
            .map_err(Into::into)
    }

    fn assert_submitted_fact(
        fixture: &Fixture,
        effect_fact: &forge_persistence::EffectFact,
        assignment_id: AgentAssignmentId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let forge_persistence::EffectFact::AssignmentSubmitted(fact) = effect_fact else {
            return Err("the submitted lifecycle must emit an assignment-submitted fact".into());
        };
        assert_eq!(fact.assignment_id(), assignment_id);
        assert_eq!(fact.workspace_id(), fixture.workspace_id);
        assert_eq!(fact.activity_id(), fixture.activity_id);
        assert_eq!(fact.goal_id(), fixture.goal.id());
        assert_eq!(fact.node_id(), fixture.node.id());
        assert_eq!(fact.target_agent_id(), fixture.target.id());
        assert_eq!(fact.target_session_id(), fixture.target.session_id());
        assert_eq!(fact.source_count(), 0);
        assert_eq!(fact.source_kinds(), None);
        assert_eq!(fact.source_digests(), None);
        assert_eq!(
            fact.result_digest(),
            Some(Sha256::digest("bounded participant report".as_bytes()).into())
        );
        assert_eq!(fact.submitted_at(), timestamp(22)?);
        Ok(())
    }

    #[test]
    fn assignment_review_emits_assignment_reviewed_fact_through_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("review-fact")?;
        let assignment_id = AgentAssignmentId::from_uuid(id(0xCA40));
        let target_revision = fixture.target.revision();
        let delegated = install_delegation(&mut fixture)?;
        let submitted =
            drive_assignment_to_submitted(&mut fixture, assignment_id, target_revision)?;
        let accepted = fixture.control.agent_assignment_mutate(
            &AgentAssignmentMutationRequest {
                scope: fixture.scope.clone(),
                mutation: AgentAssignmentMutation::Accept(ReviewAgentAssignment::new(
                    assignment_id,
                    fixture.coordinator,
                    submitted.revision(),
                    timestamp(25)?,
                )),
            },
            timestamp_now()?,
        )?;
        assert_eq!(accepted.state(), AgentAssignmentState::Accepted);

        let facts = fixture
            .control
            .effect_fact_outbox(&EffectFactOutboxReadRequest {
                scope: fixture.scope.clone(),
                migration_id: delegated.migration_id(),
                destination_id: delegated.destination_id(),
                after: 0,
                limit: 64,
            })?;
        assert_eq!(facts.len(), 3, "offer + submit + review facts round-trip");
        assert_eq!(facts[0].migration_id(), delegated.migration_id());
        assert_eq!(facts[0].destination_id(), delegated.destination_id());
        assert_eq!(facts[0].workspace_id(), fixture.workspace_id);
        assert!(matches!(
            facts[0].fact(),
            forge_persistence::EffectFact::AssignmentOffered(_)
        ));
        assert_submitted_fact(&fixture, facts[1].fact(), assignment_id)?;
        match facts[2].fact() {
            forge_persistence::EffectFact::AssignmentReviewed(fact) => {
                assert_eq!(fact.assignment_id(), assignment_id);
                assert_eq!(fact.workspace_id(), fixture.workspace_id);
                assert_eq!(fact.activity_id(), fixture.activity_id);
                assert_eq!(fact.goal_id(), fixture.goal.id());
                assert_eq!(fact.node_id(), fixture.node.id());
                assert_eq!(fact.target_agent_id(), fixture.target.id());
                assert_eq!(fact.target_session_id(), fixture.target.session_id());
                assert_eq!(
                    fact.outcome(),
                    forge_persistence::AssignmentReviewedOutcome::Accepted
                );
                assert_eq!(
                    fact.credit_budget(),
                    Some(forge_domain::WorkCreditBudget::Three)
                );
                assert_eq!(fact.reviewer_agent_id(), fixture.coordinator.agent_id());
                assert_eq!(
                    fact.reviewer_session_id(),
                    Some(fixture.coordinator.session_id())
                );
                assert_eq!(
                    fact.result_digest(),
                    Some(Sha256::digest("bounded participant report".as_bytes()).into())
                );
                assert_eq!(fact.observed_at(), timestamp(25)?);
            }
            forge_persistence::EffectFact::ChangeSetTerminal(_) => {
                unreachable!("assignment review must not produce a ChangeSet fact")
            }
            forge_persistence::EffectFact::ExecutionTerminal(_) => {
                unreachable!("assignment review must not produce an execution fact")
            }
            forge_persistence::EffectFact::AssignmentOffered(_) => {
                unreachable!("assignment review must not produce an assignment-offer fact")
            }
            forge_persistence::EffectFact::AssignmentSubmitted(_) => {
                unreachable!("assignment review must not produce an assignment-submitted fact")
            }
        }
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn assignment_offer_emits_assignment_offered_fact_through_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("offer-fact")?;
        let delegated = install_delegation(&mut fixture)?;
        let assignment_id = AgentAssignmentId::from_uuid(id(0xCA41));
        let offered = fixture.control.agent_assignment_mutate(
            &AgentAssignmentMutationRequest {
                scope: fixture.scope.clone(),
                mutation: AgentAssignmentMutation::Offer(offer_command(
                    &fixture,
                    0xCA41,
                    fixture.target.revision(),
                )?),
            },
            timestamp_now()?,
        )?;
        assert_eq!(offered.state(), AgentAssignmentState::Offered);

        let facts = fixture
            .control
            .effect_fact_outbox(&EffectFactOutboxReadRequest {
                scope: fixture.scope.clone(),
                migration_id: delegated.migration_id(),
                destination_id: delegated.destination_id(),
                after: 0,
                limit: 64,
            })?;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].migration_id(), delegated.migration_id());
        assert_eq!(facts[0].destination_id(), delegated.destination_id());
        assert_eq!(facts[0].workspace_id(), fixture.workspace_id);
        match facts[0].fact() {
            forge_persistence::EffectFact::AssignmentOffered(fact) => {
                assert_eq!(fact.assignment_id(), assignment_id);
                assert_eq!(fact.workspace_id(), fixture.workspace_id);
                assert_eq!(fact.activity_id(), fixture.activity_id);
                assert_eq!(fact.goal_id(), fixture.goal.id());
                assert_eq!(fact.node_id(), fixture.node.id());
                assert_eq!(fact.target_agent_id(), fixture.target.id());
                assert_eq!(fact.target_session_id(), fixture.target.session_id());
                assert_eq!(
                    fact.credit_budget(),
                    Some(forge_domain::WorkCreditBudget::Three)
                );
                assert_eq!(fact.offered_at(), timestamp(20)?);
            }
            forge_persistence::EffectFact::AssignmentReviewed(_) => {
                unreachable!("assignment offer must not produce a review fact")
            }
            forge_persistence::EffectFact::ChangeSetTerminal(_) => {
                unreachable!("assignment offer must not produce a ChangeSet fact")
            }
            forge_persistence::EffectFact::ExecutionTerminal(_) => {
                unreachable!("assignment offer must not produce an execution fact")
            }
            forge_persistence::EffectFact::AssignmentSubmitted(_) => {
                unreachable!("assignment offer must not produce an assignment-submitted fact")
            }
        }
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn assignment_get_uses_immutable_offer_revision_after_claim_advances_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("get-after-claim")?;
        let assignment_id = AgentAssignmentId::from_uuid(id(0xCA40));
        let offered_target_revision = fixture.target.revision();
        let offered = fixture.control.agent_assignment_mutate(
            &AgentAssignmentMutationRequest {
                scope: fixture.scope.clone(),
                mutation: AgentAssignmentMutation::Offer(offer_command(
                    &fixture,
                    0xCA40,
                    offered_target_revision,
                )?),
            },
            timestamp_now()?,
        )?;
        let claimed = fixture.control.agent_assignment_mutate(
            &AgentAssignmentMutationRequest {
                scope: fixture.scope.clone(),
                mutation: AgentAssignmentMutation::Claim(ClaimAgentAssignment::new(
                    assignment_id,
                    AgentAssignmentTarget::new(
                        fixture.target.id(),
                        fixture
                            .target
                            .session_id()
                            .ok_or("target session missing")?,
                        fixture.target.principal(),
                        offered_target_revision,
                    ),
                    offered.revision(),
                    timestamp(21)?,
                )),
            },
            timestamp_now()?,
        )?;
        assert_eq!(claimed.state(), AgentAssignmentState::Running);

        let current_agent_revision = {
            let existing = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
                .ok_or("layout missing")?;
            let store = WorkspaceStore::open_existing(&existing)?;
            let agent = store
                .get_agent(fixture.target.id())?
                .ok_or("target agent missing after claim")?;
            agent.revision()
        };
        assert!(current_agent_revision > offered_target_revision);

        let original_assignment =
            fixture
                .control
                .agent_assignment_get(&AgentAssignmentGetRequest {
                    scope: fixture.scope.clone(),
                    activity_id: fixture.activity_id,
                    assignment_id,
                    authority: AgentAssignmentReadAuthority {
                        session_id: fixture
                            .target
                            .session_id()
                            .ok_or("target session missing")?,
                        agent_id: fixture.target.id(),
                        expected_agent_revision: offered_target_revision,
                        principal: fixture.target.principal(),
                    },
                })?;
        assert_eq!(original_assignment, Some(claimed.clone()));

        let changed_offer_revision =
            fixture
                .control
                .agent_assignment_get(&AgentAssignmentGetRequest {
                    scope: fixture.scope.clone(),
                    activity_id: fixture.activity_id,
                    assignment_id,
                    authority: AgentAssignmentReadAuthority {
                        session_id: fixture
                            .target
                            .session_id()
                            .ok_or("target session missing")?,
                        agent_id: fixture.target.id(),
                        expected_agent_revision: current_agent_revision,
                        principal: fixture.target.principal(),
                    },
                });
        assert!(changed_offer_revision.is_err());

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
