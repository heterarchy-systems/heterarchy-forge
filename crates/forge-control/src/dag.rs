use forge_domain::{
    ActivityId, AgentListLimit, AgentSessionId, AuthenticatedPrincipal, DagNodeId,
    DagNodeLifecycle, DagNodeRevision, DagRevisionNumber, GoalId, GoalRevision, GoalStatusKind,
    RegisteredDagNode, TimestampMillis,
};
use forge_persistence::{
    CoordinatorStoreError, DagNodeAssignmentSnapshot, DagNodeEvidenceScope, DagNodeTransition,
    DagStoreError, DagTransitionScope, StoredDagRevision, WorkspaceStore, WorkspaceStoreError,
};
use forge_workspace::{
    DagSettlementReceipt, ExistingWorkspaceStateLayout, NodeWorkspaceError, NodeWorkspaceReceipt,
    complete_and_handoff_node_workspace_in, inspect_node_workspace, provision_node_workspace_in,
    settle_dag_revision_workspace,
};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeStartRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub goal_id: GoalId,
    pub expected_goal_revision: GoalRevision,
    pub expected_dag_revision: DagRevisionNumber,
    pub node_id: DagNodeId,
    pub expected_revision: DagNodeRevision,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeCompleteRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub goal_id: GoalId,
    pub expected_goal_revision: GoalRevision,
    pub expected_dag_revision: DagRevisionNumber,
    pub node_id: DagNodeId,
    pub expected_revision: DagNodeRevision,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeUpdateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub node: RegisteredDagNode,
    pub expected_revision: DagNodeRevision,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagSettleRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub goal_id: GoalId,
    pub expected_goal_revision: GoalRevision,
    pub expected_dag_revision: DagRevisionNumber,
    pub settlement_id: uuid::Uuid,
    pub observed_at: TimestampMillis,
}

impl ForgeControl {
    pub fn dag_get_current(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<Option<StoredDagRevision>, ControlError> {
        self.read_dag(scope, |store| store.get_current_dag(goal_id))
    }

    /// Observe one exact node and its active assignment without granting work.
    ///
    /// # Errors
    /// Revalidates the Workspace root and propagates corrupt or unavailable state.
    pub fn dag_node_assignment_snapshot(
        &self,
        scope: &ResolvedWorkspaceScope,
        node_scope: DagNodeEvidenceScope,
    ) -> Result<Option<DagNodeAssignmentSnapshot>, ControlError> {
        self.read_dag(scope, |store| {
            store.dag_node_assignment_snapshot(node_scope)
        })
    }

    pub fn dag_get_revision(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
        number: DagRevisionNumber,
    ) -> Result<Option<StoredDagRevision>, ControlError> {
        self.read_dag(scope, |store| store.get_dag_revision(goal_id, number))
    }

    /// Inspect the isolated working tree receipt and handoff provenance for one
    /// DAG node without mutating Workspace or catalog state.
    ///
    /// # Errors
    /// Revalidates the Workspace root and propagates corrupt manifest or store state.
    pub fn dag_node_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    ) -> Result<Option<NodeWorkspaceReceipt>, ControlError> {
        let (fresh_scope, layout, store) = self.open_dag_workspace_with_layout(scope)?;
        let receipt = inspect_node_workspace(&layout, goal_id, dag_revision, node_id)
            .map_err(map_node_workspace_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(receipt)
    }

    pub(crate) fn dag_node_start(
        &self,
        request: &DagNodeStartRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, layout, mut store) = self.open_dag_workspace_with_layout(&request.scope)?;
        let node = store
            .start_dag_node_authorized(
                DagNodeTransition::new(
                    DagTransitionScope::new(
                        scope.workspace_id(),
                        request.activity_id,
                        request.goal_id,
                        request.expected_goal_revision,
                        request.expected_dag_revision,
                    ),
                    request.node_id,
                    request.expected_revision,
                    request.observed_at,
                ),
                request.session_id,
                request.principal,
                admitted_at,
            )
            .map_err(map_dag_store_error)?;
        if let Some(stored) = store
            .get_dag_revision(request.goal_id, request.expected_dag_revision)
            .map_err(map_dag_store_error)?
        {
            let upstreams = upstream_node_ids(&stored, request.node_id);
            let _receipt = provision_node_workspace_in(
                &layout,
                Some(&self.node_worktrees_root),
                Some(scope.workspace_id()),
                request.goal_id,
                request.expected_dag_revision,
                request.node_id,
                &upstreams,
                request.observed_at,
            )
            .map_err(map_node_workspace_error)?;
        }
        self.confirm_dag_write(&scope, &store)?;
        Ok(node)
    }

    pub(crate) fn dag_node_complete(
        &self,
        request: &DagNodeCompleteRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, layout, mut store) = self.open_dag_workspace_with_layout(&request.scope)?;
        let mut completed_in_fs = false;
        if can_prevalidate_authorized_node_completion(&store, &scope, request, admitted_at)?
            && let Some(stored) = store
                .get_dag_revision(request.goal_id, request.expected_dag_revision)
                .map_err(map_dag_store_error)?
        {
            let completed_upstreams = upstream_node_ids(&stored, request.node_id);
            let ready_downstreams = ready_downstream_nodes(&stored, request.node_id);
            let _completion = complete_and_handoff_node_workspace_in(
                &layout,
                Some(&self.node_worktrees_root),
                Some(scope.workspace_id()),
                request.goal_id,
                request.expected_dag_revision,
                request.node_id,
                &completed_upstreams,
                &ready_downstreams,
                request.observed_at,
            )
            .map_err(map_node_workspace_error)?;
            completed_in_fs = true;
        }
        let node = store
            .complete_dag_node_authorized(
                DagNodeTransition::new(
                    DagTransitionScope::new(
                        scope.workspace_id(),
                        request.activity_id,
                        request.goal_id,
                        request.expected_goal_revision,
                        request.expected_dag_revision,
                    ),
                    request.node_id,
                    request.expected_revision,
                    request.observed_at,
                ),
                request.session_id,
                request.principal,
                admitted_at,
            )
            .map_err(map_dag_store_error)?;
        if !completed_in_fs
            && let Some(stored) = store
                .get_dag_revision(request.goal_id, request.expected_dag_revision)
                .map_err(map_dag_store_error)?
        {
            let completed_upstreams = upstream_node_ids(&stored, request.node_id);
            let ready_downstreams = ready_downstream_nodes(&stored, request.node_id);
            let _completion = complete_and_handoff_node_workspace_in(
                &layout,
                Some(&self.node_worktrees_root),
                Some(scope.workspace_id()),
                request.goal_id,
                request.expected_dag_revision,
                request.node_id,
                &completed_upstreams,
                &ready_downstreams,
                request.observed_at,
            )
            .map_err(map_node_workspace_error)?;
        }
        self.confirm_dag_write(&scope, &store)?;
        Ok(node)
    }

    pub(crate) fn dag_node_update(
        &self,
        request: &DagNodeUpdateRequest,
        admitted_at: TimestampMillis,
    ) -> Result<RegisteredDagNode, ControlError> {
        let (scope, layout, mut store) = self.open_dag_workspace_with_layout(&request.scope)?;
        let mut completed_in_fs = false;
        if *request.node.lifecycle() == DagNodeLifecycle::Completed
            && let Some(stored) = store
                .get_current_dag(request.node.goal_id())
                .map_err(map_dag_store_error)?
            && stored.revision().number() == request.node.dag_revision()
            && stored.nodes().iter().any(|existing| {
                existing.id() == request.node.id()
                    && *existing.lifecycle() == DagNodeLifecycle::Active
                    && existing.revision() == request.expected_revision
            })
        {
            let upstreams = upstream_node_ids(&stored, request.node.id());
            let ready_downstreams = ready_downstream_nodes(&stored, request.node.id());
            let _completion = complete_and_handoff_node_workspace_in(
                &layout,
                Some(&self.node_worktrees_root),
                Some(scope.workspace_id()),
                request.node.goal_id(),
                request.node.dag_revision(),
                request.node.id(),
                &upstreams,
                &ready_downstreams,
                request.node.updated_at(),
            )
            .map_err(map_node_workspace_error)?;
            completed_in_fs = true;
        }
        let node = store
            .update_dag_node(&request.node, request.expected_revision, admitted_at)
            .map_err(map_dag_store_error)?;
        if matches!(
            node.lifecycle(),
            DagNodeLifecycle::Active | DagNodeLifecycle::Completed
        ) && let Some(stored) = store
            .get_dag_revision(node.goal_id(), node.dag_revision())
            .map_err(map_dag_store_error)?
        {
            let upstreams = upstream_node_ids(&stored, node.id());
            if *node.lifecycle() == DagNodeLifecycle::Completed {
                if !completed_in_fs {
                    let ready_downstreams = ready_downstream_nodes(&stored, node.id());
                    let _completion = complete_and_handoff_node_workspace_in(
                        &layout,
                        Some(&self.node_worktrees_root),
                        Some(scope.workspace_id()),
                        node.goal_id(),
                        node.dag_revision(),
                        node.id(),
                        &upstreams,
                        &ready_downstreams,
                        node.updated_at(),
                    )
                    .map_err(map_node_workspace_error)?;
                }
            } else {
                let _receipt = provision_node_workspace_in(
                    &layout,
                    Some(&self.node_worktrees_root),
                    Some(scope.workspace_id()),
                    node.goal_id(),
                    node.dag_revision(),
                    node.id(),
                    &upstreams,
                    node.updated_at(),
                )
                .map_err(map_node_workspace_error)?;
            }
        }
        self.confirm_dag_write(&scope, &store)?;
        Ok(node)
    }

    /// Explicitly settle all terminal sink node outputs of a completed DAG
    /// revision back into the canonical `<workspace_root>` via 3-way merge
    /// against the pinned revision baseline and a journaled `ConfinedWorkspace`
    /// CAS write.
    pub fn dag_settle(
        &self,
        request: &DagSettleRequest,
        admitted_at: TimestampMillis,
    ) -> Result<DagSettlementReceipt, ControlError> {
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, layout, mut store) = self.open_dag_workspace_with_layout(&request.scope)?;
        let attachments = store
            .list_agent_attachments(
                Some(request.activity_id),
                admitted_at,
                AgentListLimit::DEFAULT,
            )
            .map_err(crate::agent::map_agent_store_error)?;
        let coordinator_agent = attachments
            .iter()
            .find(|projection| {
                projection.agent().workspace_id() == scope.workspace_id()
                    && projection.agent().activity_id() == request.activity_id
                    && projection.agent().session_id() == Some(request.session_id)
                    && projection.agent().principal() == request.principal
                    && projection.agent().attachment_state().is_attached()
                    && projection.activity().liveness() == forge_domain::ActivityLiveness::Live
            })
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentSessionConflict))?;

        let goal = store
            .get_goal(request.goal_id)
            .map_err(crate::goal::map_goal_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::DagNotFound))?;
        if goal.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        if goal.activity_id() != request.activity_id
            || goal.revision() != request.expected_goal_revision
            || goal.status().kind() != GoalStatusKind::Active
        {
            return Err(ControlError::new(ControlErrorCode::DagConflict));
        }

        let stored = store
            .get_current_dag(request.goal_id)
            .map_err(map_dag_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::DagNotFound))?;
        if stored.revision().number() != request.expected_dag_revision {
            return Err(ControlError::new(ControlErrorCode::DagConflict));
        }
        if !stored
            .nodes()
            .iter()
            .all(|node| *node.lifecycle() == DagNodeLifecycle::Completed)
        {
            return Err(ControlError::new(ControlErrorCode::DagConflict));
        }

        let sinks = terminal_sink_node_ids(&stored);
        let settlement_id = request.settlement_id.to_string();
        let receipt = settle_dag_revision_workspace(
            &layout,
            &settlement_id,
            request.goal_id,
            request.expected_dag_revision,
            &sinks,
            request.observed_at,
        )
        .map_err(map_node_workspace_error)?;
        if receipt.state() == forge_workspace::DagSettlementJournalState::Applied {
            let fact = build_dag_settled_effect_fact(
                &receipt,
                scope.workspace_id(),
                request.activity_id,
                request.expected_goal_revision,
                coordinator_agent.agent().id(),
                request.session_id,
            )?;
            store
                .append_dag_settled_effect_fact(&fact)
                .map_err(map_dag_store_error)?;
        }
        self.confirm_dag_write(&scope, &store)?;
        Ok(receipt)
    }

    fn read_dag<T>(
        &self,
        scope: &ResolvedWorkspaceScope,
        read: impl FnOnce(&WorkspaceStore) -> Result<T, WorkspaceStoreError>,
    ) -> Result<T, ControlError> {
        let (fresh_scope, store) = self.open_dag_workspace(scope)?;
        let result = read(&store).map_err(map_dag_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    fn open_dag_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
        self.open_dag_workspace_with_layout(scope)
            .map(|(fresh_scope, _, store)| (fresh_scope, store))
    }

    fn open_dag_workspace_with_layout(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<
        (
            ResolvedWorkspaceScope,
            ExistingWorkspaceStateLayout,
            WorkspaceStore,
        ),
        ControlError,
    > {
        self.open_exact_workspace_with_layout(scope)
    }

    fn confirm_dag_write(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &WorkspaceStore,
    ) -> Result<(), ControlError> {
        self.confirm_scope_write(scope, store)
    }
}

fn can_prevalidate_authorized_node_completion(
    store: &WorkspaceStore,
    scope: &ResolvedWorkspaceScope,
    request: &DagNodeCompleteRequest,
    admitted_at: TimestampMillis,
) -> Result<bool, ControlError> {
    let Some(goal) = store
        .get_goal(request.goal_id)
        .map_err(map_dag_store_error)?
    else {
        return Ok(false);
    };
    if goal.workspace_id() != scope.workspace_id()
        || goal.activity_id() != request.activity_id
        || goal.revision() != request.expected_goal_revision
        || goal.status().kind() != GoalStatusKind::Active
    {
        return Ok(false);
    }
    let Some(stored) = store
        .get_current_dag(request.goal_id)
        .map_err(map_dag_store_error)?
    else {
        return Ok(false);
    };
    if stored.revision().number() != request.expected_dag_revision {
        return Ok(false);
    }
    let Some(node) = stored
        .nodes()
        .iter()
        .find(|node| node.id() == request.node_id)
    else {
        return Ok(false);
    };
    if *node.lifecycle() != DagNodeLifecycle::Active || node.revision() != request.expected_revision
    {
        return Ok(false);
    }
    let attachments = store
        .list_agent_attachments(
            Some(request.activity_id),
            admitted_at,
            AgentListLimit::DEFAULT,
        )
        .map_err(crate::agent::map_agent_store_error)?;
    let attached_and_live = attachments.iter().any(|projection| {
        projection.agent().workspace_id() == scope.workspace_id()
            && projection.agent().activity_id() == request.activity_id
            && projection.agent().session_id() == Some(request.session_id)
            && projection.agent().principal() == request.principal
            && projection.agent().attachment_state().is_attached()
            && projection.activity().liveness() == forge_domain::ActivityLiveness::Live
    });
    Ok(attached_and_live)
}

fn upstream_node_ids(stored: &StoredDagRevision, node_id: DagNodeId) -> Vec<DagNodeId> {
    let mut upstreams = stored
        .revision()
        .edges()
        .iter()
        .filter(|edge| edge.downstream() == node_id)
        .map(|edge| edge.upstream())
        .collect::<Vec<_>>();
    upstreams.sort_by_key(|id| id.into_uuid().as_u128());
    upstreams.dedup();
    upstreams
}

pub(crate) fn terminal_sink_node_ids(stored: &StoredDagRevision) -> Vec<DagNodeId> {
    let mut sinks = stored
        .nodes()
        .iter()
        .map(RegisteredDagNode::id)
        .filter(|candidate_id| {
            !stored
                .revision()
                .edges()
                .iter()
                .any(|edge| edge.upstream() == *candidate_id)
        })
        .collect::<Vec<_>>();
    sinks.sort_by_key(|id| id.into_uuid().as_u128());
    sinks.dedup();
    sinks
}

fn ready_downstream_nodes(
    stored: &StoredDagRevision,
    completed_node_id: DagNodeId,
) -> Vec<(DagNodeId, Vec<DagNodeId>)> {
    let mut direct_downstreams = stored
        .revision()
        .edges()
        .iter()
        .filter(|edge| edge.upstream() == completed_node_id)
        .map(|edge| edge.downstream())
        .collect::<Vec<_>>();
    direct_downstreams.sort_by_key(|id| id.into_uuid().as_u128());
    direct_downstreams.dedup();

    let mut ready = Vec::new();
    for downstream_id in direct_downstreams {
        let Some(downstream_node) = stored
            .nodes()
            .iter()
            .find(|node| node.id() == downstream_id)
        else {
            continue;
        };
        if *downstream_node.lifecycle() != DagNodeLifecycle::Pending {
            continue;
        }
        let upstreams = upstream_node_ids(stored, downstream_id);
        let all_upstreams_completed = upstreams.iter().all(|upstream_id| {
            *upstream_id == completed_node_id
                || stored
                    .nodes()
                    .iter()
                    .find(|node| node.id() == *upstream_id)
                    .is_some_and(|node| *node.lifecycle() == DagNodeLifecycle::Completed)
        });
        if all_upstreams_completed {
            ready.push((downstream_id, upstreams));
        }
    }
    ready
}

pub(crate) fn map_node_workspace_error(error: NodeWorkspaceError) -> ControlError {
    let code = match &error {
        NodeWorkspaceError::HandoffMergeConflict { .. }
        | NodeWorkspaceError::HandoffInputUnavailable { .. }
        | NodeWorkspaceError::WorkspaceNotProvisioned { .. }
        | NodeWorkspaceError::UpstreamSetMismatch { .. } => ControlErrorCode::DagConflict,
        NodeWorkspaceError::UnsupportedWorkspaceEntry { .. }
        | NodeWorkspaceError::InvalidRelativePath { .. } => ControlErrorCode::InvalidPathKind,
        NodeWorkspaceError::SettlementBaselineConflict { .. }
        | NodeWorkspaceError::SettlementRecoveryRequired { .. }
        | NodeWorkspaceError::StateLayout(_) => ControlErrorCode::WorkspaceRootConflict,
        NodeWorkspaceError::Io { .. }
        | NodeWorkspaceError::GitCommandFailed { .. }
        | NodeWorkspaceError::CorruptManifest { .. } => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

pub(crate) fn map_dag_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::Dag(
            DagStoreError::GoalMissing | DagStoreError::HeadMissing | DagStoreError::NodeMissing,
        ) => ControlErrorCode::DagNotFound,
        WorkspaceStoreError::Dag(DagStoreError::AgentAuthorizationConflict) => {
            ControlErrorCode::AgentSessionConflict
        }
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::ActivityNotLive(_)
            | CoordinatorStoreError::ActivityLeaseNotLive(_),
        )) => ControlErrorCode::ActivityLeaseConflict,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::ActivityNotFound(_),
        )) => ControlErrorCode::ActivityNotFound,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::ActivityWorkspaceMismatch,
        )) => ControlErrorCode::WorkspaceIdentityConflict,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(
            CoordinatorStoreError::CorruptRecord(_) | CoordinatorStoreError::Sqlite(_),
        )) => ControlErrorCode::PersistenceFailure,
        WorkspaceStoreError::Dag(DagStoreError::Coordinator(_)) => {
            ControlErrorCode::CoordinatorConflict
        }
        WorkspaceStoreError::Dag(
            DagStoreError::GoalConflict
            | DagStoreError::IdentityConflict
            | DagStoreError::HeadConflict
            | DagStoreError::ProjectionMismatch
            | DagStoreError::CompletedNodeDropped(_)
            | DagStoreError::CompletedNodeChanged(_)
            | DagStoreError::RevisionOverflow
            | DagStoreError::Transition(_)
            | DagStoreError::NodeConflict
            | DagStoreError::HistoricalRevisionImmutable
            | DagStoreError::GoalEvidenceMissing
            | DagStoreError::LineageConflict
            | DagStoreError::LineageMissing(_),
        ) => ControlErrorCode::DagConflict,
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

fn build_dag_settled_effect_fact(
    receipt: &DagSettlementReceipt,
    workspace_id: forge_domain::WorkspaceId,
    activity_id: forge_domain::ActivityId,
    goal_revision: forge_domain::GoalRevision,
    coordinator_agent_id: forge_domain::AgentInstanceId,
    coordinator_session_id: forge_domain::AgentSessionId,
) -> Result<forge_persistence::DagSettledEffectFact, ControlError> {
    let settlement_id = uuid::Uuid::parse_str(receipt.settlement_id())
        .map_err(|_| ControlError::new(ControlErrorCode::PersistenceFailure))?;
    let settled_tree_digest = decode_hex_digest(receipt.settled_tree_blake3())?;
    forge_persistence::DagSettledEffectFact::from_parts(
        forge_persistence::DagSettledEffectFactParts {
            settlement_id,
            workspace_id,
            activity_id,
            goal_id: receipt.goal_id(),
            goal_revision,
            dag_revision: receipt.dag_revision(),
            settled_file_count: receipt.settled_file_count(),
            settled_tree_digest,
            coordinator_agent_id,
            coordinator_session_id: Some(coordinator_session_id),
            settled_at: receipt.settled_at(),
        },
    )
    .map_err(|error| ControlError::with_source(ControlErrorCode::PersistenceFailure, error))
}

pub(crate) fn decode_hex_digest(hex: &str) -> Result<[u8; 32], ControlError> {
    if hex.len() != 64 {
        return Err(ControlError::new(ControlErrorCode::PersistenceFailure));
    }
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let chunk = &hex[index * 2..index * 2 + 2];
        *slot = u8::from_str_radix(chunk, 16)
            .map_err(|_| ControlError::new(ControlErrorCode::PersistenceFailure))?;
    }
    Ok(out)
}
