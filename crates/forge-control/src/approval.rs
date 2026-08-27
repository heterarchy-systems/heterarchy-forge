use forge_domain::{
    ActivityId, ApprovalDecision, ApprovalRequestId, ApprovalRequestState, ApprovalRevision,
    AutoApprovalScope, BeginExecution, ExecutionAuthorizationRequest, ExecutionGrant,
    ExecutionGrantId, ExecutionGrantRevision, ExecutionListLimit, ExecutionPolicyDisposition,
    GoalWorkAttribution, PolicyRevision, RegisteredApprovalRequest, RuntimeInstanceId,
    TimestampMillis, WorkspacePolicy,
};
use forge_persistence::{
    ApprovalAuthorityCleanupReport, AutoApprovalExecutionRecord, BeginExecutionRecord,
    BeginExecutionStatus,
};
use forge_workspace::ExistingWorkspaceStateLayout;

use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::authorize_activity;
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
}

/// Local-only transfer from durable grant consumption to the process owner.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrantConsumeResult {
    scope: ResolvedWorkspaceScope,
    layout: ExistingWorkspaceStateLayout,
    grant: ExecutionGrant,
    begin: BeginExecutionRecord,
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
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovalConsumeResult {
    scope: ResolvedWorkspaceScope,
    layout: ExistingWorkspaceStateLayout,
    record: AutoApprovalExecutionRecord,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalReconcileRequest {
    pub scope: ResolvedWorkspaceScope,
    pub observed_at: TimestampMillis,
    pub limit: ExecutionListLimit,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCancelActivityRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub observed_at: TimestampMillis,
    pub limit: ExecutionListLimit,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCancelWorkspaceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub observed_at: TimestampMillis,
    pub limit: ExecutionListLimit,
}

impl AutoApprovalConsumeResult {
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
        authorize_activity(
            &store,
            crate::FileActivityScope {
                activity_id: request.activity.activity_id,
                runtime_instance_id: request.activity.runtime_instance_id,
                observed_at: request.activity.observed_at,
            },
        )?;
        if request.request.workspace_id() != scope.workspace_id()
            || request.request.activity_id() != request.activity.activity_id
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

    /// Read one exact approval audit/request record for trusted-local
    /// reconciliation. This remains outside the MCP surface.
    pub fn approval_get(
        &self,
        scope: &ResolvedWorkspaceScope,
        approval_id: ApprovalRequestId,
    ) -> Result<Option<RegisteredApprovalRequest>, ControlError> {
        let (fresh_scope, store) = self.open_approval_workspace(scope)?;
        let approval = store
            .get_approval_request(approval_id)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(approval)
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

    pub(crate) fn consume_execution_grant(
        &self,
        request: &ApprovalGrantConsumeRequest,
    ) -> Result<ApprovalGrantConsumeResult, ControlError> {
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        authorize_activity(
            &store,
            crate::FileActivityScope {
                activity_id: request.activity.activity_id,
                runtime_instance_id: request.activity.runtime_instance_id,
                observed_at: request.activity.observed_at,
            },
        )?;
        if request.begin.observed_at() != request.activity.observed_at {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        let (grant, begin) = store
            .consume_grant_and_begin_execution(
                request.grant_id,
                request.expected_grant_revision,
                request.request,
                &request.begin,
                request.activity.observed_at,
                request.goal,
            )
            .map_err(map_activity_store_error)?;
        if begin.status() != BeginExecutionStatus::Created {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(ApprovalGrantConsumeResult {
            scope,
            layout,
            grant,
            begin,
        })
    }

    pub(crate) fn consume_auto_approval(
        &self,
        request: &AutoApprovalConsumeRequest,
    ) -> Result<AutoApprovalConsumeResult, ControlError> {
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        authorize_activity(
            &store,
            crate::FileActivityScope {
                activity_id: request.activity.activity_id,
                runtime_instance_id: request.activity.runtime_instance_id,
                observed_at: request.activity.observed_at,
            },
        )?;
        if request.begin.observed_at() != request.activity.observed_at {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
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
            )
            .map_err(map_activity_store_error)?;
        if record.begin().status() != BeginExecutionStatus::Created {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(AutoApprovalConsumeResult {
            scope,
            layout,
            record,
        })
    }

    pub fn reconcile_expired_approval_authority(
        &self,
        request: &ApprovalReconcileRequest,
    ) -> Result<ApprovalAuthorityCleanupReport, ControlError> {
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let report = store
            .reconcile_expired_approval_authority(request.observed_at, request.limit)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(report)
    }

    pub fn cancel_activity_approval_authority(
        &self,
        request: &ApprovalCancelActivityRequest,
    ) -> Result<ApprovalAuthorityCleanupReport, ControlError> {
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let report = store
            .cancel_activity_approval_authority(
                request.activity_id,
                request.observed_at,
                request.limit,
            )
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(report)
    }

    pub fn cancel_workspace_approval_authority(
        &self,
        request: &ApprovalCancelWorkspaceRequest,
    ) -> Result<ApprovalAuthorityCleanupReport, ControlError> {
        let (fresh_scope, mut store) = self.open_approval_workspace(&request.scope)?;
        let report = store
            .cancel_workspace_approval_authority(request.observed_at, request.limit)
            .map_err(map_activity_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(report)
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
