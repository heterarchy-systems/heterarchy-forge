use forge_domain::{
    ActivityId, ActivityLiveness, ActivityProjection, AgentInstanceId, AgentListLimit,
    AgentSessionId, AuthenticatedPrincipal, DagNodeId, DagNodeLifecycle, DagRevisionNumber, GoalId,
    GoalRevision, GoalStatusKind, SwarmMemberId, SwarmRunId, SwarmSettlementTarget,
    SwarmWorkspaceMode, TimestampMillis,
};
use forge_persistence::{
    EffectFactOutboxError, MAX_SWARM_SETTLED_QUERY_LIMIT, SwarmSettledEffectFact,
    SwarmSettledEffectFactParts, SwarmSettledOutboxEntry, WorkspaceStore, WorkspaceStoreError,
};
use forge_workspace::{
    SettlementJournalState, SwarmConvergenceOutcome, SwarmMemberOutputReceipt,
    SwarmSettlementReceipt, SwarmWorkspaceError, SwarmWorkspaceReceipt, capture_member_output,
    converge_swarm_candidates, inspect_swarm_member_workspace, inspect_swarm_settlement,
    materialize_dag_node_hybrid_swarm_workspace, provision_swarm_member_workspace_in,
    purge_swarm_workspaces, settle_standalone_swarm_workspace,
};

use crate::AgentSessionResolveRequest;
use crate::agent::map_agent_store_error;
use crate::dag::{decode_hex_digest, map_dag_store_error, map_node_workspace_error};
use crate::error::{ControlError, ControlErrorCode};
use crate::goal::map_goal_store_error;
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Maximum number of Swarm convergence candidates accepted in one request.
pub const MAX_SWARM_CONVERGENCE_CANDIDATES: usize = 64;
const MAX_SWARM_OUTBOX_SCAN_PAGES: usize = 1024;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmWorkspaceProvisionRequest {
    pub scope: ResolvedWorkspaceScope,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub swarm_run_id: SwarmRunId,
    pub member_id: SwarmMemberId,
    pub mode: SwarmWorkspaceMode,
    pub target: SwarmSettlementTarget,
    pub candidate_commit_oid: Option<String>,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmWorkspaceGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub swarm_run_id: SwarmRunId,
    pub member_id: SwarmMemberId,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmMemberCaptureRequest {
    pub scope: ResolvedWorkspaceScope,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub swarm_run_id: SwarmRunId,
    pub member_id: SwarmMemberId,
    pub captured_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmConvergenceCandidate {
    pub member_id: SwarmMemberId,
    pub expected_output_commit_oid: Option<String>,
    pub expected_diff_digest: Option<[u8; 32]>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmConvergeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub swarm_run_id: SwarmRunId,
    pub candidates: Vec<SwarmConvergenceCandidate>,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmSettleRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: Option<ActivityId>,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub coordinator_agent_id: AgentInstanceId,
    pub swarm_run_id: SwarmRunId,
    pub settlement_id: uuid::Uuid,
    pub converged_commit_oid: String,
    pub expected_diff_digest: Option<[u8; 32]>,
    pub settled_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmSettleOutcome {
    pub receipt: SwarmSettlementReceipt,
    pub outbox_sequence: Option<u64>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmMaterializeHybridRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub swarm_run_id: SwarmRunId,
    pub settlement_id: uuid::Uuid,
    pub goal_id: GoalId,
    pub expected_goal_revision: GoalRevision,
    pub expected_dag_revision: DagRevisionNumber,
    pub node_id: DagNodeId,
    pub converged_commit_oid: String,
    pub expected_diff_digest: Option<[u8; 32]>,
    pub settled_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmSettlementGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub swarm_run_id: SwarmRunId,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmSettlementView {
    pub receipt: Option<SwarmSettlementReceipt>,
    pub outbox_entry: Option<SwarmSettledOutboxEntry>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmPurgeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub swarm_run_id: SwarmRunId,
}

impl ForgeControl {
    /// Provision an isolated Swarm member workspace (`Inherit`, `Share`, or `Branch`)
    /// pinned to either `StandaloneSwarm` or `DagNodeHybrid` baseline state.
    ///
    /// # Errors
    /// Rejects unresolved/closed sessions, stale scopes, malformed OIDs/IDs,
    /// forbidden SSD roots, and conflicting re-provisioning.
    pub fn swarm_workspace_provision(
        &self,
        request: &SwarmWorkspaceProvisionRequest,
    ) -> Result<SwarmWorkspaceReceipt, ControlError> {
        require_non_nil(request.swarm_run_id.into_uuid())?;
        require_non_nil(request.member_id.into_uuid())?;
        if let SwarmSettlementTarget::DagNodeHybrid {
            goal_id, node_id, ..
        } = request.target
        {
            require_non_nil(goal_id.into_uuid())?;
            require_non_nil(node_id.into_uuid())?;
        }
        if let Some(ref oid) = request.candidate_commit_oid {
            validate_commit_oid(oid)?;
        }
        self.resolve_swarm_session(request.session_id, request.principal)?;
        let (scope, layout, store) = self.open_exact_workspace_with_layout(&request.scope)?;
        let receipt = provision_swarm_member_workspace_in(
            &layout,
            self.swarm_worktrees_root.as_deref(),
            Some(scope.workspace_id()),
            request.swarm_run_id,
            request.member_id,
            request.mode,
            request.target,
            request.candidate_commit_oid.as_deref(),
            request.observed_at,
        )
        .map_err(map_swarm_workspace_error)?;
        self.confirm_scope_write(&scope, &store)?;
        Ok(receipt)
    }

    /// Inspect one provisioned Swarm member workspace without side effects.
    ///
    /// # Errors
    /// Rejects malformed IDs, drifted scopes, and corrupt workspace manifests.
    pub fn swarm_workspace_get(
        &self,
        request: &SwarmWorkspaceGetRequest,
    ) -> Result<Option<SwarmWorkspaceReceipt>, ControlError> {
        require_non_nil(request.swarm_run_id.into_uuid())?;
        require_non_nil(request.member_id.into_uuid())?;
        let (scope, layout, store) = self.open_exact_workspace_with_layout(&request.scope)?;
        let receipt =
            inspect_swarm_member_workspace(&layout, request.swarm_run_id, request.member_id)
                .map_err(map_swarm_workspace_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(receipt)
    }

    /// Capture one Swarm member's completed snapshot, changed paths, and transition diff digest.
    ///
    /// # Errors
    /// Rejects unresolved/closed sessions, read-only `Inherit` mutations,
    /// unprovisioned members, and drifted workspace scopes.
    pub fn swarm_member_capture(
        &self,
        request: &SwarmMemberCaptureRequest,
    ) -> Result<SwarmMemberOutputReceipt, ControlError> {
        require_non_nil(request.swarm_run_id.into_uuid())?;
        require_non_nil(request.member_id.into_uuid())?;
        self.resolve_swarm_session(request.session_id, request.principal)?;
        let (scope, layout, store) = self.open_exact_workspace_with_layout(&request.scope)?;
        let receipt = capture_member_output(
            &layout,
            request.swarm_run_id,
            request.member_id,
            request.captured_at,
        )
        .map_err(map_swarm_workspace_error)?;
        self.confirm_scope_write(&scope, &store)?;
        Ok(receipt)
    }

    /// Deterministically 3-way merge ordered captured Swarm member outputs against the
    /// pinned Swarm run baseline without modifying `<workspace_root>`.
    ///
    /// # Errors
    /// Rejects unresolved/closed sessions, empty or oversized candidate lists,
    /// uncaptured members, candidate CAS mismatches, and duplicate members.
    pub fn swarm_converge(
        &self,
        request: &SwarmConvergeRequest,
    ) -> Result<SwarmConvergenceOutcome, ControlError> {
        require_non_nil(request.swarm_run_id.into_uuid())?;
        if request.candidates.is_empty()
            || request.candidates.len() > MAX_SWARM_CONVERGENCE_CANDIDATES
        {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        for candidate in &request.candidates {
            require_non_nil(candidate.member_id.into_uuid())?;
            if let Some(ref oid) = candidate.expected_output_commit_oid {
                validate_commit_oid(oid)?;
            }
        }
        self.resolve_swarm_session(request.session_id, request.principal)?;
        let (scope, layout, store) = self.open_exact_workspace_with_layout(&request.scope)?;
        let mut receipts = Vec::with_capacity(request.candidates.len());
        for candidate in &request.candidates {
            let member =
                inspect_swarm_member_workspace(&layout, request.swarm_run_id, candidate.member_id)
                    .map_err(map_swarm_workspace_error)?
                    .ok_or_else(|| ControlError::new(ControlErrorCode::DagConflict))?;
            let completed = member
                .completed()
                .ok_or_else(|| ControlError::new(ControlErrorCode::DagConflict))?;
            if let Some(ref expected_oid) = candidate.expected_output_commit_oid
                && completed.output_commit_oid() != expected_oid
            {
                return Err(ControlError::new(ControlErrorCode::DagConflict));
            }
            if let Some(expected_digest) = candidate.expected_diff_digest
                && completed.diff_digest() != expected_digest
            {
                return Err(ControlError::new(ControlErrorCode::DagConflict));
            }
            receipts.push(completed.clone());
        }
        let outcome = converge_swarm_candidates(
            &layout,
            request.swarm_run_id,
            &receipts,
            request.observed_at,
        )
        .map_err(map_swarm_workspace_error)?;
        self.confirm_scope_write(&scope, &store)?;
        Ok(outcome)
    }

    /// Atomically settle a converged `StandaloneSwarm` candidate into `<workspace_root>`
    /// and durably emit `SwarmSettledEffectFact` (`SWARM_SETTLED_KIND = 6`) when delegated.
    ///
    /// # Errors
    /// Rejects unresolved/closed sessions, coordinator authority conflicts, replay identity
    /// conflicts, baseline drift, digest mismatches, and unconfirmed post-commit scope drift.
    pub fn swarm_settle(
        &self,
        request: &SwarmSettleRequest,
        admitted_at: TimestampMillis,
    ) -> Result<SwarmSettleOutcome, ControlError> {
        require_non_nil(request.swarm_run_id.into_uuid())?;
        require_non_nil(request.settlement_id)?;
        require_non_nil(request.coordinator_agent_id.into_uuid())?;
        if let Some(activity_id) = request.activity_id {
            require_non_nil(activity_id.into_uuid())?;
        }
        validate_commit_oid(&request.converged_commit_oid)?;
        self.resolve_swarm_session(request.session_id, request.principal)?;
        let (scope, layout, mut store) = self.open_exact_workspace_with_layout(&request.scope)?;
        verify_swarm_settlement_authority(&store, &scope, request, admitted_at)?;

        let settlement_id = request.settlement_id.to_string();
        let receipt = settle_standalone_swarm_workspace(
            &layout,
            &settlement_id,
            request.swarm_run_id,
            &request.converged_commit_oid,
            request.expected_diff_digest,
            request.settled_at,
        )
        .map_err(map_swarm_workspace_error)?;
        if receipt.settlement_id() != settlement_id {
            return Err(ControlError::new(ControlErrorCode::AgentDagReplayConflict));
        }

        let outbox_sequence = if receipt.state() == SettlementJournalState::Applied {
            let fact = build_swarm_settled_effect_fact(
                &receipt,
                scope.workspace_id(),
                request.activity_id,
                request.coordinator_agent_id,
                request.session_id,
            )?;
            store
                .append_swarm_settled_effect_fact(&fact)
                .map_err(map_swarm_store_error)?
                .map(SwarmSettledOutboxEntry::sequence)
        } else {
            None
        };
        self.confirm_scope_write(&scope, &store)?;
        Ok(SwarmSettleOutcome {
            receipt,
            outbox_sequence,
        })
    }

    /// Materialize a converged `DagNodeHybrid` candidate into an active target DAG node worktree.
    ///
    /// # Errors
    /// Rejects unresolved/closed sessions, missing/non-active goals or DAG nodes, stale
    /// revisions, unauthorized agents, replay conflicts, and drifted scopes.
    pub fn swarm_materialize_hybrid(
        &self,
        request: &SwarmMaterializeHybridRequest,
        admitted_at: TimestampMillis,
    ) -> Result<SwarmSettlementReceipt, ControlError> {
        require_non_nil(request.activity_id.into_uuid())?;
        require_non_nil(request.swarm_run_id.into_uuid())?;
        require_non_nil(request.settlement_id)?;
        require_non_nil(request.goal_id.into_uuid())?;
        require_non_nil(request.node_id.into_uuid())?;
        validate_commit_oid(&request.converged_commit_oid)?;
        self.resolve_swarm_session(request.session_id, request.principal)?;
        let (scope, layout, store) = self.open_exact_workspace_with_layout(&request.scope)?;
        verify_hybrid_node_authority(&store, &scope, request, admitted_at)?;

        let settlement_id = request.settlement_id.to_string();
        let receipt = materialize_dag_node_hybrid_swarm_workspace(
            &layout,
            &settlement_id,
            request.swarm_run_id,
            request.goal_id,
            request.expected_dag_revision,
            request.node_id,
            &request.converged_commit_oid,
            request.expected_diff_digest,
            request.settled_at,
        )
        .map_err(map_swarm_workspace_error)?;
        if receipt.settlement_id() != settlement_id {
            return Err(ControlError::new(ControlErrorCode::AgentDagReplayConflict));
        }
        self.confirm_scope_write(&scope, &store)?;
        Ok(receipt)
    }

    /// Inspect one Swarm settlement journal and matching durable `SwarmSettled` outbox record.
    ///
    /// # Errors
    /// Rejects malformed IDs, drifted scopes, corrupt journals, or outbox read errors.
    pub fn swarm_settlement_get(
        &self,
        request: &SwarmSettlementGetRequest,
    ) -> Result<SwarmSettlementView, ControlError> {
        require_non_nil(request.swarm_run_id.into_uuid())?;
        let (scope, layout, store) = self.open_exact_workspace_with_layout(&request.scope)?;
        let receipt = inspect_swarm_settlement(&layout, request.swarm_run_id)
            .map_err(map_swarm_workspace_error)?;
        let outbox_entry = find_swarm_settled_outbox_entry(&store, request.swarm_run_id)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(SwarmSettlementView {
            receipt,
            outbox_entry,
        })
    }

    /// Purge ephemeral Swarm member worktrees, baseline/member manifests, and settlement journals
    /// while preserving committed Git snapshots and durable outbox entries.
    ///
    /// # Errors
    /// Rejects unresolved/closed sessions, malformed IDs, I/O errors, or drifted scopes.
    pub fn swarm_purge(&self, request: &SwarmPurgeRequest) -> Result<(), ControlError> {
        require_non_nil(request.swarm_run_id.into_uuid())?;
        self.resolve_swarm_session(request.session_id, request.principal)?;
        let (scope, layout, store) = self.open_exact_workspace_with_layout(&request.scope)?;
        purge_swarm_workspaces(
            &layout,
            self.swarm_worktrees_root.as_deref(),
            Some(scope.workspace_id()),
            request.swarm_run_id,
        )
        .map_err(map_swarm_workspace_error)?;
        self.confirm_scope_write(&scope, &store)
    }

    fn resolve_swarm_session(
        &self,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<(), ControlError> {
        require_non_nil(session_id.into_uuid())?;
        let _session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id,
            principal,
        })?;
        Ok(())
    }
}

fn verify_swarm_settlement_authority(
    store: &WorkspaceStore,
    scope: &ResolvedWorkspaceScope,
    request: &SwarmSettleRequest,
    admitted_at: TimestampMillis,
) -> Result<(), ControlError> {
    let agent = store
        .get_agent(request.coordinator_agent_id)
        .map_err(map_agent_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
    if agent.workspace_id() != scope.workspace_id() {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    if agent.session_id() != Some(request.session_id)
        || agent.principal() != request.principal
        || !agent.attachment_state().is_attached()
    {
        return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
    }
    if let Some(requested_activity) = request.activity_id
        && agent.activity_id() != requested_activity
    {
        return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
    }
    let activity_id = request.activity_id.unwrap_or_else(|| agent.activity_id());
    let activity = store
        .get_activity(activity_id)
        .map_err(map_dag_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityNotFound))?;
    if ActivityProjection::from_activity(activity, admitted_at).liveness() != ActivityLiveness::Live
    {
        return Err(ControlError::new(ControlErrorCode::ActivityLeaseConflict));
    }
    let coordinator = store
        .get_activity_coordinator(activity_id)
        .map_err(map_agent_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::CoordinatorNotFound))?;
    if coordinator.agent_id() != request.coordinator_agent_id {
        return Err(ControlError::new(ControlErrorCode::CoordinatorConflict));
    }
    Ok(())
}

fn verify_hybrid_node_authority(
    store: &WorkspaceStore,
    scope: &ResolvedWorkspaceScope,
    request: &SwarmMaterializeHybridRequest,
    admitted_at: TimestampMillis,
) -> Result<(), ControlError> {
    let goal = store
        .get_goal(request.goal_id)
        .map_err(map_goal_store_error)?
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
    let node = stored
        .nodes()
        .iter()
        .find(|node| node.id() == request.node_id)
        .ok_or_else(|| ControlError::new(ControlErrorCode::DagNotFound))?;
    if *node.lifecycle() != DagNodeLifecycle::Active {
        return Err(ControlError::new(ControlErrorCode::DagConflict));
    }

    require_live_activity_attachment(
        store,
        scope,
        request.activity_id,
        request.session_id,
        request.principal,
        None,
        admitted_at,
    )
}

fn require_live_activity_attachment(
    store: &WorkspaceStore,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    required_agent_id: Option<AgentInstanceId>,
    admitted_at: TimestampMillis,
) -> Result<(), ControlError> {
    let attachments = store
        .list_agent_attachments(Some(activity_id), admitted_at, AgentListLimit::DEFAULT)
        .map_err(map_agent_store_error)?;
    let authorized = attachments.iter().any(|projection| {
        let agent = projection.agent();
        required_agent_id.is_none_or(|id| agent.id() == id)
            && agent.workspace_id() == scope.workspace_id()
            && agent.activity_id() == activity_id
            && agent.session_id() == Some(session_id)
            && agent.principal() == principal
            && agent.attachment_state().is_attached()
            && projection.activity().liveness() == ActivityLiveness::Live
    });
    if !authorized {
        return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
    }
    Ok(())
}

fn find_swarm_settled_outbox_entry(
    store: &WorkspaceStore,
    swarm_run_id: SwarmRunId,
) -> Result<Option<SwarmSettledOutboxEntry>, ControlError> {
    let mut after = 0_u64;
    for _ in 0..MAX_SWARM_OUTBOX_SCAN_PAGES {
        let page = store
            .swarm_settled_effect_facts(after, MAX_SWARM_SETTLED_QUERY_LIMIT)
            .map_err(map_swarm_store_error)?;
        if let Some(found) = page
            .iter()
            .find(|entry| entry.fact().swarm_run_id() == swarm_run_id)
            .copied()
        {
            return Ok(Some(found));
        }
        let Some(last) = page.last() else {
            return Ok(None);
        };
        if u32::try_from(page.len()).ok() != Some(MAX_SWARM_SETTLED_QUERY_LIMIT) {
            return Ok(None);
        }
        after = last.sequence();
    }
    Err(ControlError::new(ControlErrorCode::CapacityExceeded))
}

fn build_swarm_settled_effect_fact(
    receipt: &SwarmSettlementReceipt,
    workspace_id: forge_domain::WorkspaceId,
    activity_id: Option<ActivityId>,
    coordinator_agent_id: AgentInstanceId,
    coordinator_session_id: AgentSessionId,
) -> Result<SwarmSettledEffectFact, ControlError> {
    let settlement_id = uuid::Uuid::parse_str(receipt.settlement_id())
        .map_err(|_| ControlError::new(ControlErrorCode::PersistenceFailure))?;
    let settled_tree_digest = decode_hex_digest(receipt.settled_tree_blake3())?;
    SwarmSettledEffectFact::from_parts(SwarmSettledEffectFactParts {
        settlement_id,
        workspace_id,
        activity_id,
        swarm_run_id: receipt.swarm_run_id(),
        settled_file_count: receipt.settled_file_count(),
        settled_tree_digest,
        converged_diff_digest: receipt.converged_diff_digest(),
        coordinator_agent_id,
        coordinator_session_id: Some(coordinator_session_id),
        settled_at: receipt.settled_at(),
    })
    .map_err(|error| ControlError::with_source(ControlErrorCode::PersistenceFailure, error))
}

fn require_non_nil(id: uuid::Uuid) -> Result<(), ControlError> {
    if id.is_nil() {
        return Err(ControlError::new(ControlErrorCode::InvalidInput));
    }
    Ok(())
}

pub(crate) fn validate_commit_oid(oid: &str) -> Result<(), ControlError> {
    if !(40..=64).contains(&oid.len()) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ControlError::new(ControlErrorCode::InvalidInput));
    }
    Ok(())
}

pub(crate) fn map_swarm_workspace_error(error: SwarmWorkspaceError) -> ControlError {
    if let SwarmWorkspaceError::NodeWorkspace(inner) = error {
        return map_node_workspace_error(inner);
    }
    let code = match &error {
        SwarmWorkspaceError::Io { .. }
        | SwarmWorkspaceError::GitCommandFailed { .. }
        | SwarmWorkspaceError::CorruptManifest { .. } => ControlErrorCode::PersistenceFailure,
        SwarmWorkspaceError::InvalidRelativePath { .. }
        | SwarmWorkspaceError::UnsupportedWorkspaceEntry { .. } => {
            ControlErrorCode::InvalidPathKind
        }
        SwarmWorkspaceError::ForbiddenSsdWorktreeRoot { .. }
        | SwarmWorkspaceError::WorktreeInsideWorkspaceRoot { .. }
        | SwarmWorkspaceError::InvalidExternalWorktreeRoot { .. } => ControlErrorCode::InvalidInput,
        SwarmWorkspaceError::BaselineNotPinned { .. }
        | SwarmWorkspaceError::TargetMismatch { .. }
        | SwarmWorkspaceError::MemberWorkspaceNotProvisioned { .. }
        | SwarmWorkspaceError::MemberModeMismatch { .. }
        | SwarmWorkspaceError::InheritWorkspaceMutated { .. }
        | SwarmWorkspaceError::InheritCannotContributeCandidate { .. }
        | SwarmWorkspaceError::EmptyConvergenceCandidates { .. }
        | SwarmWorkspaceError::DuplicateConvergenceMember { .. }
        | SwarmWorkspaceError::ConvergenceCandidateMismatch { .. }
        | SwarmWorkspaceError::HybridTargetNodeNotProvisioned { .. }
        | SwarmWorkspaceError::HybridTargetNodeAlreadySealed { .. }
        | SwarmWorkspaceError::SettlementDiffDigestMismatch { .. } => ControlErrorCode::DagConflict,
        SwarmWorkspaceError::SettlementBaselineConflict { .. }
        | SwarmWorkspaceError::SettlementRecoveryRequired { .. }
        | SwarmWorkspaceError::StateLayout(_) => ControlErrorCode::WorkspaceRootConflict,
        SwarmWorkspaceError::NodeWorkspace(_) => unreachable!("handled above"),
    };
    ControlError::with_source(code, error)
}

fn map_swarm_store_error(error: WorkspaceStoreError) -> ControlError {
    if let WorkspaceStoreError::EffectFactOutbox(ref outbox) = error {
        let code = match outbox {
            EffectFactOutboxError::ReplayConflict => ControlErrorCode::AgentDagReplayConflict,
            EffectFactOutboxError::InvalidCursor | EffectFactOutboxError::InvalidLimit { .. } => {
                ControlErrorCode::InvalidInput
            }
            EffectFactOutboxError::Delegation(_) => ControlErrorCode::AgentConflict,
            _ => ControlErrorCode::PersistenceFailure,
        };
        return ControlError::with_source(code, error);
    }
    map_dag_store_error(error)
}

#[cfg(test)]
mod tests;
