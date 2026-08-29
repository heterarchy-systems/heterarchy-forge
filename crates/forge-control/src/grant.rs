//! Control-plane admission for one-shot Agent DAG authoring.
//!
//! The grant is deliberately narrower than an execution or filesystem
//! capability: it binds one attached Agent, Activity, credential, Goal
//! revision, and current DAG head.  The persistence layer owns the atomic
//! consume/insert/ledger transaction; this module only resolves the selected
//! Workspace and maps the result into transport-safe control errors.

use forge_domain::{
    AgentDagAuthoringActor, AgentDagAuthoringGrant, AgentDagAuthoringGrantId,
    AgentDagAuthoringGrantRevision, AgentDagAuthoringGrantTtl, AgentDagReplanRequest,
    DagHeadRevision, DagRevisionNumber, GoalAttribution, TimestampMillis,
};
use forge_persistence::{AgentDagStoreError, WorkspaceStore, WorkspaceStoreError};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Request to issue one exact Agent DAG authoring grant.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagGrantIssueRequest {
    pub scope: ResolvedWorkspaceScope,
    pub grant_id: AgentDagAuthoringGrantId,
    pub actor: AgentDagAuthoringActor,
    pub goal: GoalAttribution,
    pub expected_dag_revision: DagRevisionNumber,
    pub expected_head_revision: DagHeadRevision,
    pub issued_at: TimestampMillis,
    pub ttl: AgentDagAuthoringGrantTtl,
}

/// Request to revoke one active Agent DAG authoring grant through revision CAS.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagGrantRevokeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub grant_id: AgentDagAuthoringGrantId,
    pub expected_revision: AgentDagAuthoringGrantRevision,
}

/// Request to read one Agent DAG authoring grant in an exact Workspace scope.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagGrantGetRequest {
    pub scope: ResolvedWorkspaceScope,
    pub grant_id: AgentDagAuthoringGrantId,
}

/// Request to discover an operator-issued grant from the authenticated Agent
/// principal.  The exact Goal/head tuple prevents one Agent from borrowing a
/// grant intended for another replan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagGrantDiscoverRequest {
    pub scope: ResolvedWorkspaceScope,
    pub actor: AgentDagAuthoringActor,
    pub goal: GoalAttribution,
    pub expected_dag_revision: DagRevisionNumber,
    pub expected_head_revision: DagHeadRevision,
    pub now: TimestampMillis,
}

/// Request to atomically commit one one-shot Agent DAG replan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDagReplanCommitRequest {
    pub scope: ResolvedWorkspaceScope,
    pub request: AgentDagReplanRequest,
}

impl ForgeControl {
    /// Issue and durably bind one authoring grant to the selected Workspace.
    pub fn agent_dag_grant_issue(
        &self,
        request: &AgentDagGrantIssueRequest,
    ) -> Result<AgentDagAuthoringGrant, ControlError> {
        ensure_actor_workspace(&request.scope, request.actor)?;
        let (scope, mut store) = open_grant_workspace(self, &request.scope)?;
        let grant = AgentDagAuthoringGrant::issue(
            request.grant_id,
            request.actor,
            request.goal,
            request.expected_dag_revision,
            request.expected_head_revision,
            request.issued_at,
            request.ttl,
        )
        .map_err(|error| {
            ControlError::with_source(ControlErrorCode::AgentDagGrantConflict, error)
        })?;
        let persisted = store
            .issue_agent_dag_authoring_grant(&grant)
            .map_err(map_agent_dag_store_error)?;
        confirm_grant_write(self, &scope, &store)?;
        Ok(persisted)
    }

    /// Revoke one active authoring grant through exact revision CAS.
    pub fn agent_dag_grant_revoke(
        &self,
        request: &AgentDagGrantRevokeRequest,
    ) -> Result<AgentDagAuthoringGrant, ControlError> {
        let (scope, mut store) = open_grant_workspace(self, &request.scope)?;
        let revoked = store
            .revoke_agent_dag_authoring_grant(request.grant_id, request.expected_revision)
            .map_err(map_agent_dag_store_error)?;
        if revoked.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::AgentDagGrantNotFound));
        }
        confirm_grant_write(self, &scope, &store)?;
        Ok(revoked)
    }

    /// Read one authoring grant without exposing grants from another Workspace.
    pub fn agent_dag_grant_get(
        &self,
        request: &AgentDagGrantGetRequest,
    ) -> Result<Option<AgentDagAuthoringGrant>, ControlError> {
        let (scope, store) = open_grant_workspace(self, &request.scope)?;
        let grant = store
            .get_agent_dag_authoring_grant(request.grant_id)
            .map_err(map_agent_dag_store_error)?;
        if grant
            .as_ref()
            .is_some_and(|value| value.workspace_id() != scope.workspace_id())
        {
            return Err(ControlError::new(ControlErrorCode::AgentDagGrantNotFound));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(grant)
    }

    /// Discover an active grant without requiring the Agent to receive a
    /// grant identifier out of band.
    pub fn agent_dag_grant_discover(
        &self,
        request: &AgentDagGrantDiscoverRequest,
    ) -> Result<Option<AgentDagAuthoringGrant>, ControlError> {
        ensure_actor_workspace(&request.scope, request.actor)?;
        let (scope, store) = open_grant_workspace(self, &request.scope)?;
        let grant = store
            .find_active_agent_dag_authoring_grant(
                request.actor,
                request.goal,
                request.expected_dag_revision,
                request.expected_head_revision,
                request.now,
            )
            .map_err(map_agent_dag_store_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(grant)
    }

    /// Commit the replan and consume its grant in one Workspace transaction.
    pub fn agent_dag_replan_commit(
        &self,
        request: &AgentDagReplanCommitRequest,
    ) -> Result<forge_persistence::AgentDagReplanCommitResult, ControlError> {
        ensure_actor_workspace(&request.scope, request.request.actor())?;
        let (scope, mut store) = open_grant_workspace(self, &request.scope)?;
        let result = store
            .commit_agent_dag_replan(&request.request)
            .map_err(map_agent_dag_store_error)?;
        confirm_grant_write(self, &scope, &store)?;
        Ok(result)
    }

    // Aliases keep the public control vocabulary usable by adapters that put
    // the operation before the resource name.
    pub fn agent_dag_issue_grant(
        &self,
        request: &AgentDagGrantIssueRequest,
    ) -> Result<AgentDagAuthoringGrant, ControlError> {
        self.agent_dag_grant_issue(request)
    }

    pub fn agent_dag_revoke_grant(
        &self,
        request: &AgentDagGrantRevokeRequest,
    ) -> Result<AgentDagAuthoringGrant, ControlError> {
        self.agent_dag_grant_revoke(request)
    }

    pub fn agent_dag_get_grant(
        &self,
        request: &AgentDagGrantGetRequest,
    ) -> Result<Option<AgentDagAuthoringGrant>, ControlError> {
        self.agent_dag_grant_get(request)
    }

    pub fn agent_dag_commit_replan(
        &self,
        request: &AgentDagReplanCommitRequest,
    ) -> Result<forge_persistence::AgentDagReplanCommitResult, ControlError> {
        self.agent_dag_replan_commit(request)
    }
}

fn ensure_actor_workspace(
    scope: &ResolvedWorkspaceScope,
    actor: AgentDagAuthoringActor,
) -> Result<(), ControlError> {
    if actor.workspace_id() == scope.workspace_id() {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ))
    }
}

fn open_grant_workspace(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
) -> Result<(ResolvedWorkspaceScope, WorkspaceStore), ControlError> {
    let (fresh_scope, store) = control.open_resolved_workspace(
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

fn confirm_grant_write(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    store: &WorkspaceStore,
) -> Result<(), ControlError> {
    if control.committed_scope_matches_with_store(scope, store) {
        Ok(())
    } else {
        Err(ControlError::committed())
    }
}

pub(crate) fn map_agent_dag_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::AgentDag(AgentDagStoreError::GrantNotFound(_)) => {
            ControlErrorCode::AgentDagGrantNotFound
        }
        WorkspaceStoreError::AgentDag(AgentDagStoreError::AgentNotFound(_)) => {
            ControlErrorCode::AgentNotFound
        }
        WorkspaceStoreError::AgentDag(AgentDagStoreError::RequestIdentityConflict) => {
            ControlErrorCode::AgentDagReplayConflict
        }
        WorkspaceStoreError::AgentDag(
            AgentDagStoreError::GrantIdentityConflict
            | AgentDagStoreError::ActiveGrantConflict(_)
            | AgentDagStoreError::GrantActorMismatch
            | AgentDagStoreError::ActorCredentialMissing
            | AgentDagStoreError::ActorCredentialMismatch
            | AgentDagStoreError::GrantRevisionConflict
            | AgentDagStoreError::GrantUnavailable(_)
            | AgentDagStoreError::GrantTransition(_)
            | AgentDagStoreError::ActorMismatch,
        ) => ControlErrorCode::AgentDagGrantConflict,
        WorkspaceStoreError::AgentDag(
            AgentDagStoreError::ActivityNotFound(_)
            | AgentDagStoreError::ActivityWorkspaceMismatch { .. }
            | AgentDagStoreError::ActivityNotLive(_)
            | AgentDagStoreError::GoalMissing(_)
            | AgentDagStoreError::GoalConflict
            | AgentDagStoreError::HeadMissing(_)
            | AgentDagStoreError::HeadConflict
            | AgentDagStoreError::DraftConflict
            | AgentDagStoreError::HistoryInvalid
            | AgentDagStoreError::Dag(_),
        ) => ControlErrorCode::AgentDagReplanConflict,
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
