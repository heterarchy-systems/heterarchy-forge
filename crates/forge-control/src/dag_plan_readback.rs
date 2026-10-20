//! Historical Coordinator DAG plan observation without replay authority.

use forge_domain::{ActivityId, AgentDagDraftDigest, AgentDagPlanRequestId, GoalId};
use forge_persistence::AgentDagPlanRecord;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Exact identity tuple used to read one historical Coordinator DAG plan.
///
/// This request is observational.  It does not require a live Activity lease,
/// session proof, Coordinator fence, or current Goal projection, and it never
/// grants permission to replay or mutate the plan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagPlanReadbackRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub goal_id: GoalId,
    pub plan_request_id: AgentDagPlanRequestId,
    pub expected_draft_digest: Option<AgentDagDraftDigest>,
}

impl ForgeControl {
    /// Read one durable Coordinator DAG plan record by its original request ID.
    pub fn dag_plan_readback(
        &self,
        request: &DagPlanReadbackRequest,
    ) -> Result<Option<AgentDagPlanRecord>, ControlError> {
        let (fresh_scope, mut store) = self.open_resolved_workspace(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }

        let record = store
            .agent_dag_plan_readback(request.plan_request_id)
            .map_err(crate::agent_dag::map_agent_dag_store_error)?;
        if record.as_ref().is_some_and(|record| {
            record.actor().workspace_id() != fresh_scope.workspace_id()
                || record.actor().activity_id() != request.activity_id
                || record.goal().goal_id() != request.goal_id
                || request
                    .expected_draft_digest
                    .is_some_and(|digest| digest != record.digest())
        }) {
            return Err(ControlError::new(ControlErrorCode::AgentDagPlanConflict));
        }

        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(record)
    }
}
