//! A deletion connection cannot outlive its caller's exclusive Workspace gate.

use forge_domain::{ActivityCoordinatorActor, GoalDeletionRequest, TimestampMillis};
use forge_workspace::{ExistingWorkspaceStateLayout, WorkspaceStateExclusiveGate};
use rusqlite::TransactionBehavior;
use uuid::Uuid;

use super::{BUSY_TIMEOUT, WorkspaceStore, WorkspaceStoreError};
use crate::workspace_coordinators;
use crate::workspace_goal_deletion::{
    self, GoalDeletionArtifactProof, GoalDeletionCleanupOutcome, GoalDeletionCleanupReadback,
    GoalDeletionStage, GoalDeletionStoreError,
};

#[must_use]
pub struct GoalDeletionStore<'gate> {
    store: WorkspaceStore,
    gate: &'gate WorkspaceStateExclusiveGate,
}

impl std::fmt::Debug for GoalDeletionStore<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GoalDeletionStore")
            .finish_non_exhaustive()
    }
}

#[must_use]
#[derive(Debug)]
pub enum GoalDeletionAdmission {
    Staged(GoalDeletionStage),
    Resumed(GoalDeletionCleanupReadback),
}

impl WorkspaceStore {
    /// Open an effect-capable deletion connection under an existing exclusive
    /// gate. The returned owner retains a borrow of that exact gate.
    pub fn open_goal_deletion<'gate>(
        layout: &ExistingWorkspaceStateLayout,
        gate: &'gate WorkspaceStateExclusiveGate,
    ) -> Result<GoalDeletionStore<'gate>, WorkspaceStoreError> {
        let fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        gate.ensure_root_binding(layout.workspace_root(), fingerprint)?;
        let store =
            Self::open_existing_with_timeout_and_gate(layout, BUSY_TIMEOUT, None, || Ok(()))?;
        let owner = GoalDeletionStore { store, gate };
        owner.ensure_binding()?;
        Ok(owner)
    }
}

impl GoalDeletionStore<'_> {
    pub fn workspace(&self) -> Result<forge_domain::RegisteredWorkspace, WorkspaceStoreError> {
        self.ensure_binding()?;
        self.store.workspace()
    }

    fn ensure_binding(&self) -> Result<(), WorkspaceStoreError> {
        self.gate
            .ensure_root_binding(&self.store.workspace_root, self.store.root_fingerprint)?;
        self.store.ensure_live_binding()
    }

    /// Privileged native operator entry. Network adapters must use the
    /// Coordinator-authorized entry below and never deserialize this privilege.
    pub fn stage_local(
        &mut self,
        request: GoalDeletionRequest,
        observed_at: TimestampMillis,
    ) -> Result<GoalDeletionAdmission, WorkspaceStoreError> {
        self.stage(request, None, observed_at)
    }

    pub fn stage_authorized(
        &mut self,
        request: GoalDeletionRequest,
        actor: ActivityCoordinatorActor,
        observed_at: TimestampMillis,
    ) -> Result<GoalDeletionAdmission, WorkspaceStoreError> {
        if actor.workspace_id() != request.workspace_id()
            || actor.activity_id() != request.activity_id()
        {
            return Err(GoalDeletionStoreError::ActivityMismatch {
                goal_id: request.goal_id(),
            }
            .into());
        }
        self.stage(request, Some(actor), observed_at)
    }

    fn stage(
        &mut self,
        request: GoalDeletionRequest,
        actor: Option<ActivityCoordinatorActor>,
        observed_at: TimestampMillis,
    ) -> Result<GoalDeletionAdmission, WorkspaceStoreError> {
        self.ensure_binding()?;
        if self.store.workspace()?.id() != request.workspace_id() {
            return Err(GoalDeletionStoreError::WorkspaceMismatch {
                goal_id: request.goal_id(),
            }
            .into());
        }
        let transaction = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(actor) = actor {
            let _binding = workspace_coordinators::authorize_in_transaction(&transaction, actor)?;
        }
        let admission = if let Some(pending) =
            workspace_goal_deletion::load_pending_cleanup_for_request(&transaction, request)?
        {
            GoalDeletionAdmission::Resumed(pending)
        } else {
            GoalDeletionAdmission::Staged(workspace_goal_deletion::stage_delete_in_transaction(
                &transaction,
                request,
                observed_at,
                self.store.root_fingerprint,
            )?)
        };
        transaction.commit()?;
        self.confirm_commit()?;
        Ok(admission)
    }

    pub fn pending_for_request(
        &self,
        request: GoalDeletionRequest,
    ) -> Result<Option<GoalDeletionCleanupReadback>, WorkspaceStoreError> {
        self.ensure_binding()?;
        let transaction = self.store.connection.unchecked_transaction()?;
        let pending =
            workspace_goal_deletion::load_pending_cleanup_for_request(&transaction, request)?;
        transaction.commit()?;
        self.ensure_binding()?;
        Ok(pending)
    }

    /// Proofs are supplied only by the confined filesystem cleanup owner.
    /// No public transport may accept arbitrary proof values from its caller.
    pub fn finish_cleanup(
        &mut self,
        cleanup_id: Uuid,
        proofs: &[GoalDeletionArtifactProof],
    ) -> Result<GoalDeletionCleanupOutcome, WorkspaceStoreError> {
        self.ensure_binding()?;
        let result = workspace_goal_deletion::finish_cleanup(
            &mut self.store.connection,
            cleanup_id,
            proofs,
        )?;
        self.confirm_commit()?;
        Ok(result)
    }

    fn confirm_commit(&mut self) -> Result<(), WorkspaceStoreError> {
        self.store
            .capture_sidecar_identities()
            .and_then(|()| self.ensure_binding())
            .map_err(
                |source| WorkspaceStoreError::GoalDeletionCommittedUnconfirmed {
                    source: Box::new(source),
                },
            )
    }

    pub fn record_cleanup_progress(
        &mut self,
        cleanup_id: Uuid,
        proofs: &[GoalDeletionArtifactProof],
    ) -> Result<GoalDeletionCleanupOutcome, WorkspaceStoreError> {
        self.ensure_binding()?;
        let outcome = workspace_goal_deletion::record_cleanup_progress(
            &mut self.store.connection,
            cleanup_id,
            proofs,
        )?;
        self.confirm_commit()?;
        Ok(outcome)
    }
}
