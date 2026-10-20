use forge_domain::{
    ActivityId, ApprovalAgentBindingDigest, ApprovalDecision, ApprovalRequestId,
    ApprovalRequestState, ApprovalRevision, AutoApprovalScope, BeginExecution,
    ExecutionActionClass, ExecutionAuthorizationRequest, ExecutionGrant, ExecutionGrantId,
    ExecutionGrantRevision, ExecutionListLimit, ExecutionPolicyDisposition, GoalWorkAttribution,
    PolicyRevision, ProjectCommandEvidence, RegisteredApprovalRequest, RuntimeInstanceId,
    TimestampMillis, WorkspacePolicy,
};
use forge_persistence::{
    AutoApprovalExecutionRecord, BeginExecutionRecord, ExecutionAdmissionContext,
};
use forge_workspace::ExistingWorkspaceStateLayout;

use crate::AgentExecutionAuthorityRequest;
use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::{authorize_activity, authorize_owned_live_activity};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalActivityScope {
    pub activity_id: ActivityId,
    pub runtime_instance_id: RuntimeInstanceId,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCreateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: ApprovalActivityScope,
    pub goal: Option<GoalWorkAttribution>,
    pub approval_id: ApprovalRequestId,
    pub request: ExecutionAuthorizationRequest,
    pub agent_binding: Option<ApprovalAgentBindingDigest>,
    pub expires_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalOnceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub approval_id: ApprovalRequestId,
    pub expected_revision: ApprovalRevision,
    pub grant_id: ExecutionGrantId,
    pub observed_at: TimestampMillis,
    pub grant_expires_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecisionRequest {
    pub scope: ResolvedWorkspaceScope,
    pub approval_id: ApprovalRequestId,
    pub decision: ApprovalDecision,
    pub expected_revision: ApprovalRevision,
    pub observed_at: TimestampMillis,
}

pub(crate) type ApprovalExecutionGrantReadback = Option<(
    RegisteredApprovalRequest,
    Option<forge_domain::RegisteredExecution>,
    Option<ExecutionGrant>,
)>;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePolicyReplaceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub policy: WorkspacePolicy,
    pub expected_revision: PolicyRevision,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovalScopeCreateRequest {
    pub scope: ResolvedWorkspaceScope,
    pub auto_scope: AutoApprovalScope,
    pub created_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovalScopeRevokeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub auto_scope_id: forge_domain::AutoApprovalScopeId,
    pub expected_revision: forge_domain::AutoApprovalScopeRevision,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrantConsumeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: ApprovalActivityScope,
    pub goal: Option<GoalWorkAttribution>,
    pub grant_id: ExecutionGrantId,
    pub expected_grant_revision: ExecutionGrantRevision,
    pub request: ExecutionAuthorizationRequest,
    pub begin: BeginExecution,
    pub agent_authority: Option<AgentExecutionAuthorityRequest>,
    pub project_command: Option<ProjectCommandEvidence>,
    pub verification: Option<forge_domain::VerificationInputEvidence>,
    /// Optional Orchestration-issued admission envelope joined into the same
    /// authoritative transaction as the grant consumption and execution begin.
    pub admission_envelope: Option<Box<ExecutionAdmissionEnvelope>>,
}

/// Caller-carried Orchestration admission envelope input. The exact request
/// fence is re-derived server-side from the executing command and interpreted
/// scope before validation; the caller never supplies the compared digest.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionAdmissionEnvelope {
    pub backend_id: forge_domain::ForgeBackendId,
    pub issuer: forge_domain::OrchestrationIssuerId,
    pub grant: forge_domain::ExecutionAdmissionGrant,
}

/// Local-only transfer from durable grant consumption to the process owner.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrantConsumeResult {
    scope: ResolvedWorkspaceScope,
    layout: ExistingWorkspaceStateLayout,
    grant: ExecutionGrant,
    begin: BeginExecutionRecord,
    journal: crate::execution_journal::ExecutionJournalAuthority,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovalConsumeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: ApprovalActivityScope,
    pub goal: Option<GoalWorkAttribution>,
    pub auto_scope_id: forge_domain::AutoApprovalScopeId,
    pub expected_scope_revision: forge_domain::AutoApprovalScopeRevision,
    pub approval_id: ApprovalRequestId,
    pub grant_id: ExecutionGrantId,
    pub request: ExecutionAuthorizationRequest,
    pub begin: BeginExecution,
    pub agent_authority: Option<AgentExecutionAuthorityRequest>,
    pub project_command: Option<ProjectCommandEvidence>,
    pub verification: Option<forge_domain::VerificationInputEvidence>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovalConsumeResult {
    scope: ResolvedWorkspaceScope,
    layout: ExistingWorkspaceStateLayout,
    record: AutoApprovalExecutionRecord,
    journal: crate::execution_journal::ExecutionJournalAuthority,
}

impl AutoApprovalConsumeResult {
    pub(crate) const fn journal(&self) -> &crate::execution_journal::ExecutionJournalAuthority {
        &self.journal
    }
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn layout(&self) -> &ExistingWorkspaceStateLayout {
        &self.layout
    }

    pub const fn record(&self) -> &AutoApprovalExecutionRecord {
        &self.record
    }
}

impl ApprovalGrantConsumeResult {
    pub(crate) const fn journal(&self) -> &crate::execution_journal::ExecutionJournalAuthority {
        &self.journal
    }
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn layout(&self) -> &ExistingWorkspaceStateLayout {
        &self.layout
    }

    pub const fn grant(&self) -> &ExecutionGrant {
        &self.grant
    }

    pub const fn begin(&self) -> &BeginExecutionRecord {
        &self.begin
    }
}

impl ForgeControl {
    pub fn ensure_workspace_policy(
        &self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
    ) -> Result<WorkspacePolicy, ControlError> {
        let (fresh_scope, mut store) = self.open_approval_workspace(scope)?;
        let policy = store
            .ensure_workspace_policy(observed_at)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(policy)
    }

    /// Read the current Workspace policy without creating a default policy.
    /// Auto Approval status uses this to distinguish policy drift from a live
    /// scope while keeping observation effect-free.
    pub fn get_workspace_policy(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<Option<WorkspacePolicy>, ControlError> {
        let (fresh_scope, store) = self.open_approval_workspace(scope)?;
        let policy = store
            .get_workspace_policy()
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(policy)
    }

    pub fn replace_workspace_policy(
        &self,
        request: &WorkspacePolicyReplaceRequest,
    ) -> Result<WorkspacePolicy, ControlError> {
        if request.policy.workspace_id() != request.scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let policy = store
            .replace_workspace_policy(
                &request.policy,
                request.expected_revision,
                request.observed_at,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(policy)
    }

    pub fn create_pending_approval(
        &self,
        request: &ApprovalCreateRequest,
    ) -> Result<RegisteredApprovalRequest, ControlError> {
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        let activity_scope = crate::FileActivityScope {
            activity_id: request.activity.activity_id,
            runtime_instance_id: request.activity.runtime_instance_id,
            observed_at: request.activity.observed_at,
        };
        if request.agent_binding.is_some() {
            authorize_activity(&store, activity_scope)?;
        } else {
            authorize_owned_live_activity(&store, activity_scope)?;
        }
        if request.request.workspace_id() != scope.workspace_id()
            || request.request.activity_id() != request.activity.activity_id
            || matches!(
                request.request.action(),
                ExecutionActionClass::DiscoveredProjectCommand
                    | ExecutionActionClass::AnalyzedShell
                    | ExecutionActionClass::GeneratedProjectCommand
            ) != request.agent_binding.is_some()
        {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        let policy = store
            .ensure_workspace_policy(request.activity.observed_at)
            .map_err(map_activity_store_error)?;
        let disposition = policy.evaluate(request.request.action(), request.request.requested());
        let approval = match disposition {
            ExecutionPolicyDisposition::Denied => RegisteredApprovalRequest::from_parts(
                request.approval_id,
                request.request,
                policy.revision(),
                ApprovalRequestState::Denied,
                request.activity.observed_at,
                request.expires_at,
                Some(request.activity.observed_at),
                ApprovalRevision::INITIAL,
            ),
            ExecutionPolicyDisposition::ApprovalRequired
            | ExecutionPolicyDisposition::AutoEligible => RegisteredApprovalRequest::pending(
                request.approval_id,
                request.request,
                policy.revision(),
                request.activity.observed_at,
                request.expires_at,
            ),
        }
        .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))?;
        let approval = match request.agent_binding {
            Some(binding) => approval.with_agent_binding(binding),
            None => approval,
        };
        let persisted = if approval.state() == ApprovalRequestState::Pending {
            store.insert_pending_approval_for_goal(&approval, request.goal)
        } else {
            store.insert_approval_audit_for_goal(&approval, request.goal)
        }
        .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(persisted)
    }

    pub fn list_pending_approvals(
        &self,
        scope: &ResolvedWorkspaceScope,
        limit: ExecutionListLimit,
    ) -> Result<Vec<RegisteredApprovalRequest>, ControlError> {
        let (fresh_scope, store) = self.open_approval_workspace(scope)?;
        let approvals = store
            .list_pending_approvals(scope.workspace_id(), limit)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(approvals)
    }

    /// Read one exact approval audit/request record and its optional durable
    /// execution from one Workspace snapshot. This is observational only.
    pub fn approval_get(
        &self,
        scope: &ResolvedWorkspaceScope,
        approval_id: ApprovalRequestId,
    ) -> Result<
        Option<(
            RegisteredApprovalRequest,
            Option<forge_domain::RegisteredExecution>,
        )>,
        ControlError,
    > {
        let (fresh_scope, store) = self.open_approval_workspace(scope)?;
        let Some((approval, execution)) = store
            .get_approval_request_with_execution(approval_id)
            .map_err(map_activity_store_error)?
        else {
            if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
                return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
            }
            return Ok(None);
        };
        let request = approval.request();
        if request.workspace_id() != fresh_scope.workspace_id()
            || execution
                .as_ref()
                .is_some_and(|record| !approval_execution_matches(&approval, record))
        {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(Some((approval, execution)))
    }

    /// Read one exact Approval, its optional durable Execution, and its
    /// optional local Execution Grant from one Workspace snapshot. The Grant
    /// is returned only when its durable Approval and request identity match
    /// the same row; this remains observation-only and never mints authority.
    pub fn approval_get_with_grant(
        &self,
        scope: &ResolvedWorkspaceScope,
        approval_id: ApprovalRequestId,
    ) -> Result<ApprovalExecutionGrantReadback, ControlError> {
        let (fresh_scope, store) = self.open_approval_workspace(scope)?;
        let Some((approval, execution, grant)) = store
            .get_approval_request_with_execution_and_grant(approval_id)
            .map_err(map_activity_store_error)?
        else {
            if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
                return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
            }
            return Ok(None);
        };
        let request = approval.request();
        let grant_matches = grant.as_ref().is_none_or(|grant| {
            grant.approval_id() == approval.id()
                && grant.request() == request
                && grant.request().workspace_id() == fresh_scope.workspace_id()
        });
        if request.workspace_id() != fresh_scope.workspace_id()
            || execution
                .as_ref()
                .is_some_and(|record| !approval_execution_matches(&approval, record))
            || !grant_matches
        {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(Some((approval, execution, grant)))
    }

    pub fn approve_once(
        &self,
        request: &ApprovalOnceRequest,
    ) -> Result<(RegisteredApprovalRequest, ExecutionGrant), ControlError> {
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let result = store
            .approve_once(
                request.approval_id,
                request.expected_revision,
                request.grant_id,
                request.observed_at,
                request.grant_expires_at,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(result)
    }

    pub fn decide_pending_approval(
        &self,
        request: &ApprovalDecisionRequest,
    ) -> Result<RegisteredApprovalRequest, ControlError> {
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let approval = store
            .decide_pending_approval(
                request.approval_id,
                request.decision,
                request.expected_revision,
                request.observed_at,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(approval)
    }

    pub fn create_auto_approval_scope(
        &self,
        request: &AutoApprovalScopeCreateRequest,
    ) -> Result<AutoApprovalScope, ControlError> {
        if request.auto_scope.workspace_id() != request.scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let policy = store
            .ensure_workspace_policy(request.created_at)
            .map_err(map_activity_store_error)?;
        if request.auto_scope.policy_revision() != policy.revision() {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        let scope = store
            .create_auto_approval_scope(&request.auto_scope, request.created_at)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(scope)
    }

    pub fn revoke_auto_approval_scope(
        &self,
        request: &AutoApprovalScopeRevokeRequest,
    ) -> Result<AutoApprovalScope, ControlError> {
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let scope = store
            .revoke_auto_approval_scope(
                request.auto_scope_id,
                request.expected_revision,
                request.observed_at,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(scope)
    }

    /// Read one exact Auto Approval scope without creating, renewing, or
    /// revoking authority. The caller owns the Workspace scope identity;
    /// persistence remains the source of TTL/quota/revision truth.
    pub fn get_auto_approval_scope(
        &self,
        scope: &ResolvedWorkspaceScope,
        id: forge_domain::AutoApprovalScopeId,
    ) -> Result<Option<AutoApprovalScope>, ControlError> {
        let (fresh_scope, store) = self.open_approval_workspace(scope)?;
        let result = store
            .get_auto_approval_scope(id)
            .map_err(map_activity_store_error)?;
        if result
            .as_ref()
            .is_some_and(|auto_scope| auto_scope.workspace_id() != fresh_scope.workspace_id())
        {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(result)
    }

    pub(crate) fn consume_execution_grant(
        &self,
        request: &ApprovalGrantConsumeRequest,
    ) -> Result<ApprovalGrantConsumeResult, ControlError> {
        self.require_open_provenance_session(request.begin.provenance())?;
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        if request.begin.provenance().is_none() {
            authorize_owned_live_activity(
                &store,
                crate::FileActivityScope {
                    activity_id: request.activity.activity_id,
                    runtime_instance_id: request.activity.runtime_instance_id,
                    observed_at: request.activity.observed_at,
                },
            )?;
        }
        if request.begin.observed_at() != request.activity.observed_at {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if !agent_provenance_matches(
            request.agent_authority.as_ref(),
            request.project_command,
            request.begin.provenance(),
        ) {
            return Err(ControlError::new(ControlErrorCode::ExecutionConflict));
        }
        let admission = ExecutionAdmissionContext::new(request.goal, request.verification);
        let admission_envelope = request
            .admission_envelope
            .as_deref()
            .map(|envelope| {
                // The compared admission request is server-derived: exact
                // workspace scope revision, activity, provenance actor fence,
                // execution identity, and the request digest of the executing
                // command itself.
                let provenance = request
                    .begin
                    .provenance()
                    .ok_or_else(|| ControlError::new(ControlErrorCode::ExecutionConflict))?;
                let session_id = provenance
                    .session_id()
                    .ok_or_else(|| ControlError::new(ControlErrorCode::ExecutionConflict))?;
                if provenance.execution_id() != request.request.execution_id() {
                    return Err(ControlError::new(ControlErrorCode::ExecutionConflict));
                }
                let actual = forge_domain::ExecutionAdmissionRequest::new(
                    forge_domain::ExecutionAdmissionScope::new(
                        envelope.backend_id,
                        request.scope.workspace_id(),
                        request.scope.workspace_revision(),
                    ),
                    request.request.activity_id(),
                    provenance.attribution(),
                    forge_domain::ExecutionAdmissionActor::new(
                        provenance.agent_id(),
                        provenance.agent_revision(),
                        session_id,
                    ),
                    request.request.execution_id(),
                    request.request.request_digest(),
                );
                Ok(forge_persistence::AdmissionEnvelopeConsumption::new(
                    envelope.issuer,
                    envelope.grant,
                    actual,
                    request.activity.observed_at,
                ))
            })
            .transpose()?;
        let (grant, begin) = store
            .consume_grant_and_begin_execution(
                request.grant_id,
                request.expected_grant_revision,
                request.request,
                &request.begin,
                request.activity.observed_at,
                admission,
                admission_envelope.as_ref(),
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::committed());
        }
        let journal = crate::execution_journal::ExecutionJournalAuthority::capture(
            &scope,
            &layout,
            &store,
            begin.record(),
        )
        .map_err(|_| ControlError::committed())?;
        Ok(ApprovalGrantConsumeResult {
            scope,
            layout,
            grant,
            begin,
            journal,
        })
    }

    pub(crate) fn consume_auto_approval(
        &self,
        request: &AutoApprovalConsumeRequest,
    ) -> Result<AutoApprovalConsumeResult, ControlError> {
        self.require_open_provenance_session(request.begin.provenance())?;
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        if request.begin.provenance().is_none() {
            authorize_owned_live_activity(
                &store,
                crate::FileActivityScope {
                    activity_id: request.activity.activity_id,
                    runtime_instance_id: request.activity.runtime_instance_id,
                    observed_at: request.activity.observed_at,
                },
            )?;
        }
        if request.begin.observed_at() != request.activity.observed_at {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if !agent_provenance_matches(
            request.agent_authority.as_ref(),
            request.project_command,
            request.begin.provenance(),
        ) {
            return Err(ControlError::new(ControlErrorCode::ExecutionConflict));
        }
        let record = store
            .consume_auto_scope_and_begin_execution(
                request.auto_scope_id,
                request.expected_scope_revision,
                request.approval_id,
                request.grant_id,
                request.request,
                &request.begin,
                request.activity.observed_at,
                request.goal,
                request.verification,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::committed());
        }
        let journal = crate::execution_journal::ExecutionJournalAuthority::capture(
            &scope,
            &layout,
            &store,
            record.begin().record(),
        )
        .map_err(|_| ControlError::committed())?;
        Ok(AutoApprovalConsumeResult {
            scope,
            layout,
            record,
            journal,
        })
    }

    /// An approval can remain pending after a logical Chat session closes.
    /// Resolve the catalog immediately before the Workspace transaction that
    /// consumes authority; a legacy/null provenance is never new authority.
    fn require_open_provenance_session(
        &self,
        provenance: Option<&forge_domain::ExecutionAgentProvenance>,
    ) -> Result<(), ControlError> {
        let Some(provenance) = provenance else {
            return Ok(());
        };
        let session_id = provenance
            .session_id()
            .ok_or_else(|| ControlError::new(ControlErrorCode::ExecutionConflict))?;
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id,
            principal: provenance.principal(),
        })?;
        Ok(())
    }

    fn open_approval_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, forge_persistence::WorkspaceStore), ControlError> {
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
}

fn approval_execution_matches(
    approval: &RegisteredApprovalRequest,
    execution: &forge_domain::RegisteredExecution,
) -> bool {
    let request = approval.request();
    let attribution_matches = execution.id() == request.execution_id()
        && execution.workspace_id() == request.workspace_id()
        && execution.activity_id() == request.activity_id()
        && execution.request_digest() == request.request_digest();
    let provenance_matches = match (approval.agent_binding(), execution.provenance()) {
        (None, None) => true,
        (Some(expected), Some(actual)) => {
            expected == ApprovalAgentBindingDigest::from_provenance(actual)
        }
        (Some(_), None) | (None, Some(_)) => false,
    };
    attribution_matches && provenance_matches
}

fn agent_provenance_matches(
    authority: Option<&AgentExecutionAuthorityRequest>,
    project_command: Option<ProjectCommandEvidence>,
    provenance: Option<&forge_domain::ExecutionAgentProvenance>,
) -> bool {
    match (authority, provenance) {
        (None, None) => true,
        (Some(authority), Some(provenance)) => {
            let expected = match project_command {
                Some(evidence) => authority
                    .provenance(provenance.execution_id())
                    .with_project_command(evidence),
                None => authority.provenance(provenance.execution_id()),
            };
            expected == *provenance
        }
        (Some(_), None) | (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        AgentInstanceId, AgentInstanceRevision, AgentSessionId, AgentSessionOpenRequestId,
        ApprovalRequestId, BeginExecution, ExecutionAgentProvenance, ExecutionAttribution,
        ExecutionCommandId, ExecutionLimits, ExecutionMode, ExecutionOutputLimit,
        ExecutionPermissions, ExecutionProgram, ExecutionRecordDefinition,
        ExecutionRecordLifecycle, ExecutionRequest, ExecutionRevision, ExecutionState,
        ExecutionTimeoutMillis, ExecutionTimestamps, GoalId, GoalNodeAttribution, GoalRevision,
        LocationId, LocationRevision, OpenAgentSession, PolicyRevision, RegisteredApprovalRequest,
        RegisteredExecution, RequestedExecutionPermissions, RuntimeInstanceId, TimestampMillis,
        WorkspaceId, WorkspaceRoot,
    };
    use forge_execution::execution_request_digest;
    use forge_persistence::{AgentSessionCatalog, GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::{
        AgentExecutionAuthorityRequest, ApprovalActivityScope, ApprovalAgentBindingDigest,
        ApprovalCreateRequest, ApprovalGrantConsumeRequest, ApprovalOnceRequest,
        ExecutionActionClass, ExecutionAuthorizationRequest, ForgeControl, ResolvedWorkspaceScope,
        approval_execution_matches,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    struct Fixture {
        root: PathBuf,
        layout: WorkspaceStateLayout,
        control: ForgeControl,
        scope: ResolvedWorkspaceScope,
        activity_id: forge_domain::ActivityId,
        runtime: RuntimeInstanceId,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "forge-control-approval-session-{nonce}-{}-{serial}",
            std::process::id(),
        ));
        fs::create_dir_all(&root)?;
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(id(1));
        let workspace_id = WorkspaceId::from_uuid(id(2));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Approval fixture",
            &location_root,
            forge_domain::TimestampMillis::new(1)?,
        )?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let establish = forge_domain::EstablishWorkspace::new(
            workspace_id,
            location.id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            forge_domain::TimestampMillis::new(2)?,
        );
        drop(WorkspaceStore::open(&layout, &establish)?);
        drop(locations);
        let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
        let locator = control
            .workspace_discover(location_id, LocationRevision::INITIAL)?
            .into_iter()
            .find(|entry| entry.display_name() == "workspace")
            .ok_or("Workspace discovery did not include the initialized root")?
            .locator()
            .clone();
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        let activity_id = forge_domain::ActivityId::from_uuid(id(3));
        let runtime = RuntimeInstanceId::from_uuid(id(4));
        let _activity = control.bootstrap_activity(
            &scope,
            activity_id,
            runtime,
            forge_domain::TimestampMillis::new(3)?,
            forge_domain::TimestampMillis::new(100)?,
        )?;
        Ok(Fixture {
            root,
            layout,
            control,
            scope,
            activity_id,
            runtime,
        })
    }

    fn bytes_or_empty(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
        match fs::read(path) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn approval_get_reads_pending_snapshot_and_rejects_mismatched_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let root = fixture.root.clone();
        let execution_id = forge_domain::ExecutionId::from_uuid(id(40));
        let approval_id = ApprovalRequestId::from_uuid(id(41));
        let request_digest = forge_domain::ExecutionRequestDigest::from_bytes([0xA1; 32]);
        let authorization = ExecutionAuthorizationRequest::new(
            execution_id,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            request_digest,
            ExecutionActionClass::DirectStructured,
            RequestedExecutionPermissions::new(ExecutionPermissions::new(true, false, false)),
        );
        let pending = fixture
            .control
            .create_pending_approval(&ApprovalCreateRequest {
                scope: fixture.scope.clone(),
                activity: ApprovalActivityScope {
                    activity_id: fixture.activity_id,
                    runtime_instance_id: fixture.runtime,
                    observed_at: forge_domain::TimestampMillis::new(4)?,
                },
                goal: None,
                approval_id,
                request: authorization,
                agent_binding: None,
                expires_at: forge_domain::TimestampMillis::new(20)?,
            })?;
        assert_eq!(pending.id(), approval_id);
        let observed = fixture
            .control
            .approval_get(&fixture.scope, approval_id)?
            .ok_or("pending Approval disappeared from read projection")?;
        assert_eq!(observed.0.id(), approval_id);
        assert!(observed.1.is_none());

        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                execution_id,
                fixture.scope.workspace_id(),
                fixture.activity_id,
            ),
            forge_domain::ExecutionKind::Structured {
                program: ExecutionProgram::new("/usr/bin/true".into())?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::DEFAULT,
            ),
            ExecutionPermissions::new(true, false, false),
        )?;
        let mismatched_begin = BeginExecution::from_request(
            &request,
            forge_domain::ExecutionRequestDigest::from_bytes([0xB2; 32]),
            forge_domain::TimestampMillis::new(5)?,
        );
        let existing_layout =
            WorkspaceStateLayout::inspect_existing(fixture.layout.workspace_root())?
                .ok_or("approval fixture Workspace state disappeared")?;
        let mut store = WorkspaceStore::open_existing(&existing_layout)?;
        let _ = store.begin_execution(&mismatched_begin)?;
        drop(store);
        let error = fixture
            .control
            .approval_get(&fixture.scope, approval_id)
            .err()
            .ok_or("mismatched Approval/Execution digest was exposed")?;
        assert_eq!(error.code(), crate::ControlErrorCode::ApprovalConflict);
        drop(fixture.control);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn approval_execution_read_rejects_same_request_with_foreign_agent_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = WorkspaceId::from_uuid(id(50));
        let activity_id = forge_domain::ActivityId::from_uuid(id(51));
        let execution_id = forge_domain::ExecutionId::from_uuid(id(52));
        let digest = forge_domain::ExecutionRequestDigest::from_bytes([0xA5; 32]);
        let request = ExecutionAuthorizationRequest::new(
            execution_id,
            workspace_id,
            activity_id,
            digest,
            ExecutionActionClass::DirectStructured,
            RequestedExecutionPermissions::new(ExecutionPermissions::new(true, false, false)),
        );
        let principal = forge_domain::AuthenticatedPrincipal::TrustedStdio;
        let provenance = |agent_value: u128,
                          session_value: u128|
         -> Result<ExecutionAgentProvenance, Box<dyn std::error::Error>> {
            Ok(ExecutionAgentProvenance::new(
                execution_id,
                AgentInstanceId::from_uuid(id(agent_value)),
                AgentInstanceRevision::INITIAL,
                principal,
                GoalNodeAttribution::new(
                    GoalId::from_uuid(id(53)),
                    GoalRevision::INITIAL,
                    forge_domain::DagRevisionNumber::INITIAL,
                    forge_domain::DagNodeId::from_uuid(id(54)),
                    forge_domain::DagNodeRevision::INITIAL,
                ),
                ExecutionCommandId::new("make:ci".to_owned())?,
                AgentSessionId::from_uuid(id(session_value)),
            ))
        };
        let expected_provenance = provenance(55, 56)?;
        let approval = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(id(57)),
            request,
            PolicyRevision::INITIAL,
            TimestampMillis::new(1)?,
            TimestampMillis::new(20)?,
        )?
        .with_agent_binding(ApprovalAgentBindingDigest::from_provenance(
            &expected_provenance,
        ));
        let execution =
            |actual_provenance| -> Result<RegisteredExecution, Box<dyn std::error::Error>> {
                Ok(RegisteredExecution::from_parts_with_provenance(
                    ExecutionAttribution::new(execution_id, workspace_id, activity_id),
                    ExecutionRecordDefinition::new(
                        ExecutionMode::Structured,
                        None,
                        ExecutionLimits::new(
                            ExecutionTimeoutMillis::new(1_000)?,
                            ExecutionOutputLimit::DEFAULT,
                        ),
                        request.requested().get(),
                        digest,
                    ),
                    ExecutionRecordLifecycle::new(
                        ExecutionState::Starting,
                        ExecutionTimestamps::initial(TimestampMillis::new(2)?),
                        ExecutionRevision::INITIAL,
                        None,
                        None,
                    ),
                    actual_provenance,
                )?)
            };
        let matching = execution(Some(expected_provenance.clone()))?;
        assert!(approval_execution_matches(&approval, &matching));
        let foreign = execution(Some(provenance(58, 59)?))?;
        assert!(!approval_execution_matches(&approval, &foreign));

        let native_approval = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(id(60)),
            request,
            PolicyRevision::INITIAL,
            TimestampMillis::new(1)?,
            TimestampMillis::new(20)?,
        )?;
        let native_execution = execution(None)?;
        assert!(approval_execution_matches(
            &native_approval,
            &native_execution
        ));
        assert!(!approval_execution_matches(&native_approval, &matching));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn closed_session_after_pending_approval_cannot_consume_grant_or_begin_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let root = fixture.root.clone();
        let execution_id = forge_domain::ExecutionId::from_uuid(id(5));
        let session_id = AgentSessionId::from_uuid(id(6));
        let principal = forge_domain::AuthenticatedPrincipal::TrustedStdio;
        let _opened = fixture.control.agent_session_open(&OpenAgentSession::new(
            session_id,
            AgentSessionOpenRequestId::from_uuid(id(7)),
            principal,
            forge_domain::TimestampMillis::new(4)?,
        ))?;
        let attribution = GoalNodeAttribution::new(
            GoalId::from_uuid(id(8)),
            GoalRevision::INITIAL,
            forge_domain::DagRevisionNumber::INITIAL,
            forge_domain::DagNodeId::from_uuid(id(9)),
            forge_domain::DagNodeRevision::INITIAL,
        );
        let authority = AgentExecutionAuthorityRequest {
            session_id,
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: AgentInstanceId::from_uuid(id(10)),
            expected_revision: AgentInstanceRevision::INITIAL,
            principal,
            attribution,
            command_id: ExecutionCommandId::new("make:package".to_owned())?,
        };
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                execution_id,
                fixture.scope.workspace_id(),
                fixture.activity_id,
            ),
            forge_domain::ExecutionKind::Structured {
                program: ExecutionProgram::new("/usr/bin/true".into())?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::DEFAULT,
            ),
            ExecutionPermissions::new(true, false, false),
        )?;
        let digest = execution_request_digest(&request);
        let authorization = ExecutionAuthorizationRequest::new(
            execution_id,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            digest,
            ExecutionActionClass::GeneratedProjectCommand,
            forge_domain::RequestedExecutionPermissions::new(request.permissions()),
        );
        let evidence = forge_domain::ProjectCommandEvidence::new(
            forge_domain::ProjectCommandClass::GeneratedPackage,
            forge_domain::ProjectCommandCatalogFingerprint::from_hash(
                forge_domain::FileContentHash::from_bytes([0xA5; 32]),
            ),
        );
        let provenance = authority
            .provenance(execution_id)
            .with_project_command(evidence);
        let approval_id = ApprovalRequestId::from_uuid(id(11));
        let pending = fixture
            .control
            .create_pending_approval(&ApprovalCreateRequest {
                scope: fixture.scope.clone(),
                activity: ApprovalActivityScope {
                    activity_id: fixture.activity_id,
                    runtime_instance_id: fixture.runtime,
                    observed_at: forge_domain::TimestampMillis::new(4)?,
                },
                goal: None,
                approval_id,
                request: authorization,
                agent_binding: Some(ApprovalAgentBindingDigest::from_provenance(&provenance)),
                expires_at: forge_domain::TimestampMillis::new(20)?,
            })?;
        let (_approved, grant) = fixture.control.approve_once(&ApprovalOnceRequest {
            scope: fixture.scope.clone(),
            approval_id,
            expected_revision: pending.revision(),
            grant_id: forge_domain::ExecutionGrantId::from_uuid(id(12)),
            observed_at: forge_domain::TimestampMillis::new(5)?,
            grant_expires_at: forge_domain::TimestampMillis::new(20)?,
        })?;
        let mut catalog = AgentSessionCatalog::open(fixture.root.join("agent-sessions.sqlite3"))?;
        let opened = catalog
            .resolve(session_id, principal)?
            .ok_or("session missing before close")?;
        let _closed = catalog.close(
            session_id,
            principal,
            opened.revision(),
            forge_domain::TimestampMillis::new(6)?,
        )?;

        let begin =
            BeginExecution::from_request(&request, digest, forge_domain::TimestampMillis::new(6)?)
                .with_runtime_owner(fixture.runtime)
                .with_provenance(provenance)?;
        let database = fixture.layout.database_path();
        let wal = database.with_file_name(format!(
            "{}-wal",
            database
                .file_name()
                .ok_or("Workspace database name missing")?
                .to_string_lossy()
        ));
        let database_before = bytes_or_empty(&database)?;
        let wal_before = bytes_or_empty(&wal)?;
        let error = fixture
            .control
            .consume_execution_grant(&ApprovalGrantConsumeRequest {
                scope: fixture.scope.clone(),
                activity: ApprovalActivityScope {
                    activity_id: fixture.activity_id,
                    runtime_instance_id: fixture.runtime,
                    observed_at: forge_domain::TimestampMillis::new(6)?,
                },
                goal: None,
                grant_id: grant.id(),
                expected_grant_revision: grant.revision(),
                request: authorization,
                begin,
                agent_authority: Some(authority),
                project_command: Some(evidence),
                verification: None,
                admission_envelope: None,
            })
            .err()
            .ok_or("closed session must fence approval consumption")?;
        assert_eq!(error.code(), crate::ControlErrorCode::AgentSessionClosed);
        assert_eq!(bytes_or_empty(&database)?, database_before);
        assert_eq!(bytes_or_empty(&wal)?, wal_before);
        assert_eq!(
            fixture
                .control
                .execution_get(&fixture.scope, execution_id)?,
            None
        );
        drop(catalog);
        drop(fixture.control);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
