//! Best-effort Git-backed checkpoint capture for confined file mutations.
//!
//! Capture is supplementary restore evidence: a mutation never fails because
//! the checkpoint layer is unavailable, and an incompletely captured
//! checkpoint remains honestly `Starting` so Doctor surfaces it.

use forge_domain::{CheckpointId, RegisteredCheckpoint, TimestampMillis, WorkspaceRelativePath};
use forge_persistence::{WorkspaceStore, WorkspaceStoreError};
use forge_workspace::{
    CheckpointSide, ExistingWorkspaceStateLayout, GitCheckpointStore, GitSafetyError,
};
use thiserror::Error;

use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::{FileActivityScope, authorize_owned_live_activity};
use crate::service::ForgeControl;

/// A PRE-retained mutation checkpoint awaiting its POST side.
pub(crate) struct MutationCheckpoint {
    adapter: GitCheckpointStore,
    starting: RegisteredCheckpoint,
}

impl MutationCheckpoint {
    pub(crate) const fn starting(&self) -> &RegisteredCheckpoint {
        &self.starting
    }

    pub(crate) const fn id(&self) -> CheckpointId {
        self.starting.id()
    }
}

/// The stage that prevented a persisted Starting checkpoint from becoming Ready.
#[derive(Debug, Error)]
pub(crate) enum CheckpointCompletionError {
    #[error("failed to retain the checkpoint POST snapshot")]
    CapturePost(#[source] GitSafetyError),
    #[error("failed to persist the checkpoint Ready projection")]
    PersistReady(#[source] WorkspaceStoreError),
}

/// Construct the adapter and retain the PRE state before any effect.
///
/// Any construction or retention failure returns `None`: the caller proceeds
/// with the mutation and no checkpoint row exists, matching the documented
/// availability-first policy (ChangeSet/Diff remain the primary evidence).
pub(crate) fn capture_pre(
    layout: &ExistingWorkspaceStateLayout,
    attribution: forge_domain::CheckpointAttribution,
    path: WorkspaceRelativePath,
    observed_at: TimestampMillis,
) -> Option<MutationCheckpoint> {
    let adapter = GitCheckpointStore::new(layout.workspace_root(), layout.checkpoints()).ok()?;
    let starting = adapter
        .begin_checkpoint(attribution, path, observed_at)
        .ok()?;
    Some(MutationCheckpoint { adapter, starting })
}

/// Persist the honest Starting row after successful PRE retention.
///
/// On persistence failure the retained PRE ref is deleted best-effort so no
/// orphan ref outlives the missing row; the caller proceeds without a
/// checkpoint either way.
pub(crate) fn persist_starting(
    checkpoint: &MutationCheckpoint,
    store: &mut WorkspaceStore,
) -> bool {
    if store.begin_checkpoint(checkpoint.starting()).is_ok() {
        return true;
    }
    drop(checkpoint.adapter.delete_snapshot(
        checkpoint.id(),
        CheckpointSide::Pre,
        checkpoint.starting().pre_commit(),
    ));
    false
}

/// Retain the POST state and compare-and-swap the row to Ready.
///
/// The terminal file mutation must already be durable before this function is
/// called because persistence validates the checkpoint against that POST state.
/// A failure leaves the Starting row in place for Doctor visibility while the
/// mutation result itself remains unaffected.
pub(crate) fn complete_post(
    checkpoint: &mut MutationCheckpoint,
    store: &mut WorkspaceStore,
    observed_at: TimestampMillis,
) -> Result<RegisteredCheckpoint, CheckpointCompletionError> {
    let ready = checkpoint
        .adapter
        .complete_checkpoint(&checkpoint.starting, observed_at)
        .map_err(CheckpointCompletionError::CapturePost)?;
    let expected_revision = checkpoint.starting.revision();
    store
        .complete_checkpoint(&ready, expected_revision)
        .map_err(CheckpointCompletionError::PersistReady)
}

/// Explicit transport-neutral restore request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRestoreRequest {
    pub scope: crate::service::ResolvedWorkspaceScope,
    pub checkpoint_id: CheckpointId,
    /// Runtime instance initiating this restore (owner provenance).
    pub initiator: forge_domain::RuntimeInstanceId,
    /// Live leased Activity authorizing the filesystem effect.
    pub activity_id: forge_domain::ActivityId,
    pub observed_at: TimestampMillis,
    /// Durable approval evidence associated with this restore, when present.
    pub approval_request_id: Option<forge_domain::ApprovalRequestId>,
}

/// Terminal outcome of one admitted checkpoint restore.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRestoreOutcome {
    pub restore_id: forge_domain::CheckpointRestoreId,
    pub state: forge_domain::CheckpointRestoreState,
    pub failure_code: Option<forge_domain::CheckpointRestoreFailureCode>,
}

impl ForgeControl {
    /// Restore one Ready checkpoint through the confined filesystem after
    /// journaling full provenance (initiator, Activity lease, optional approval evidence).
    ///
    /// Direct operator restores run outside the recovery-maintenance lease,
    /// so the journal records `maintenance_owner == None`.  Effect failures
    /// are journalled as typed `Failed` outcomes; only pre-admission problems
    /// return `Err`.
    #[allow(clippy::too_many_lines)]
    pub fn checkpoint_restore(
        &self,
        request: &CheckpointRestoreRequest,
    ) -> Result<CheckpointRestoreOutcome, ControlError> {
        use forge_domain::{CheckpointRestoreFailureCode, RestoreEffect};

        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        authorize_owned_live_activity(
            &store,
            FileActivityScope {
                activity_id: request.activity_id,
                runtime_instance_id: request.initiator,
                observed_at: request.observed_at,
            },
        )?;
        let Some(checkpoint) = store
            .get_checkpoint(request.checkpoint_id)
            .map_err(map_store)?
        else {
            return Err(ControlError::new(ControlErrorCode::CheckpointNotFound));
        };
        if checkpoint.workspace_id() != scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::CheckpointNotFound));
        }

        let confined = forge_workspace::ConfinedWorkspace::open(&layout).map_err(map_confined)?;
        let current = current_observed_state(&confined, checkpoint.path())?;
        let plan = match forge_domain::plan_restore(&checkpoint, current) {
            Ok(plan) => plan,
            Err(forge_domain::RestorePlanError::CheckpointNotReady) => {
                return Err(ControlError::new(ControlErrorCode::CheckpointNotFound));
            }
            Err(forge_domain::RestorePlanError::CurrentStateConflict) => {
                return Err(ControlError::new(ControlErrorCode::CheckpointStateConflict));
            }
        };

        let attribution = forge_domain::CheckpointRestoreAttribution::new(
            forge_domain::CheckpointRestoreId::from_uuid(uuid::Uuid::now_v7()),
            &plan,
            request.initiator,
            request.activity_id,
            request.approval_request_id,
            forge_domain::CheckpointRestoreFence::Direct,
        );
        let starting = forge_domain::RegisteredCheckpointRestore::starting(
            attribution,
            &plan,
            request.observed_at,
        );
        let _persisted_starting = store
            .begin_checkpoint_restore(&starting)
            .map_err(map_store)?;

        // Apply the inverse effect through the ordinary confined mutation
        // pipeline so locks, preconditions, and bounds stay identical.
        let mutation_plan = restore_mutation_plan(&plan);
        let content_bytes = match plan.effect() {
            RestoreEffect::Restore { blob, .. } => {
                let adapter =
                    GitCheckpointStore::new(layout.workspace_root(), layout.checkpoints())
                        .map_err(|_| ControlError::new(ControlErrorCode::CheckpointUnavailable))?;
                match adapter.read_blob(*blob) {
                    Ok(bytes) => Some(bytes),
                    Err(_) => {
                        return journal_failure(
                            &mut store,
                            &starting,
                            request.observed_at,
                            CheckpointRestoreFailureCode::MissingObject,
                        );
                    }
                }
            }
            RestoreEffect::Delete => None,
        };

        let Ok(prepared) = confined.prepare_mutation(&mutation_plan) else {
            return journal_failure(
                &mut store,
                &starting,
                request.observed_at,
                CheckpointRestoreFailureCode::PathConflict,
            );
        };
        let mutation_id =
            forge_domain::FileMutationId::from_uuid(starting.attribution().id().into_uuid());
        let apply_result = match plan.effect() {
            RestoreEffect::Delete => prepared.apply(mutation_id, None),
            RestoreEffect::Restore { mode, .. } => prepared.apply_restored_content(
                mutation_id,
                content_bytes
                    .as_deref()
                    .ok_or_else(|| ControlError::new(ControlErrorCode::Internal))?,
                *mode,
            ),
        };
        if apply_result.is_err() {
            return journal_failure(
                &mut store,
                &starting,
                request.observed_at,
                CheckpointRestoreFailureCode::IoFailure,
            );
        }

        // Verify the post state equals the checkpoint PRE evidence exactly,
        // including descriptor-observed mode.
        let verified =
            current_observed_state(&confined, plan.path())? == checkpoint.pre().observed();
        if !verified {
            return journal_failure(
                &mut store,
                &starting,
                request.observed_at,
                CheckpointRestoreFailureCode::ObjectHashMismatch,
            );
        }

        let restored = starting
            .restored(starting.revision(), request.observed_at)
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let _persisted_restored = store
            .complete_checkpoint_restore(&restored, starting.revision())
            .map_err(map_store)?;
        Ok(CheckpointRestoreOutcome {
            restore_id: restored.id(),
            state: restored.state(),
            failure_code: restored.failure_code(),
        })
    }
}

fn restore_mutation_plan(plan: &forge_domain::RestorePlan) -> forge_domain::FileMutationPlan {
    use forge_domain::{
        CheckpointObservedPathState, FileMutationKind, FileMutationPlan, FilePrecondition,
        RestoreEffect,
    };

    let (kind, precondition) = match (plan.effect(), plan.expected_post()) {
        (RestoreEffect::Delete, CheckpointObservedPathState::Regular { hash, .. }) => {
            (FileMutationKind::Delete, FilePrecondition::Matches(hash))
        }
        (RestoreEffect::Restore { .. }, CheckpointObservedPathState::Absent) => {
            (FileMutationKind::Create, FilePrecondition::Absent)
        }
        (RestoreEffect::Restore { .. }, CheckpointObservedPathState::Regular { hash, .. }) => {
            (FileMutationKind::Replace, FilePrecondition::Matches(hash))
        }
        (RestoreEffect::Delete, CheckpointObservedPathState::Absent) => {
            // A Ready checkpoint with PRE absent and POST absent cannot be
            // produced by the confined mutation contract. Preserve fail-closed
            // behavior if corrupted state reaches this boundary.
            (FileMutationKind::Delete, FilePrecondition::Absent)
        }
    };
    FileMutationPlan::new(plan.path().clone(), kind, precondition)
}

fn current_observed_state(
    confined: &forge_workspace::ConfinedWorkspace,
    path: &WorkspaceRelativePath,
) -> Result<forge_domain::CheckpointObservedPathState, ControlError> {
    confined.observe_checkpoint(path).map_err(map_confined)
}

fn map_confined(error: forge_workspace::ConfinedFilesystemError) -> ControlError {
    ControlError::with_source(ControlErrorCode::FileConflict, error)
}

fn map_store(error: forge_persistence::WorkspaceStoreError) -> ControlError {
    ControlError::with_source(ControlErrorCode::PersistenceFailure, error)
}

fn journal_failure(
    store: &mut forge_persistence::WorkspaceStore,
    starting: &forge_domain::RegisteredCheckpointRestore,
    observed_at: TimestampMillis,
    code: forge_domain::CheckpointRestoreFailureCode,
) -> Result<CheckpointRestoreOutcome, ControlError> {
    use forge_domain::CheckpointRestoreState;
    let failed = starting
        .failed(starting.revision(), code, observed_at)
        .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
    let _persisted_failed = store
        .complete_checkpoint_restore(&failed, starting.revision())
        .map_err(map_store)?;
    Ok(CheckpointRestoreOutcome {
        restore_id: failed.id(),
        state: CheckpointRestoreState::Failed,
        failure_code: Some(code),
    })
}
