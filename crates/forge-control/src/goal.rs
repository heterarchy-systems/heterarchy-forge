use std::collections::HashMap;

use forge_domain::{
    FilePathState, GoalBlocker, GoalCompletionBlocker, GoalFailure, GoalHardCheck, GoalId,
    GoalListLimit, GoalReview, GoalRevision, GoalStatusKind, GoalVerificationRequirement,
    RegisteredGoal, TimestampMillis,
};
use forge_persistence::{
    GoalCompletionReceipt, GoalStoreError, WorkspaceStore, WorkspaceStoreError,
};
use forge_workspace::{ConfinedFilesystemError, ConfinedWorkspace, ExistingWorkspaceStateLayout};
use uuid::Uuid;

use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::map_filesystem_error;
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

pub const MAX_GOAL_EVIDENCE_RESULTS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalLifecycleAction {
    Pause,
    Resume,
    Block(GoalBlocker),
    Fail(GoalFailure),
    Cancel,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalLifecycleRequest {
    pub scope: ResolvedWorkspaceScope,
    pub goal_id: GoalId,
    pub expected_revision: GoalRevision,
    pub observed_at: TimestampMillis,
    pub action: GoalLifecycleAction,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalCompletionRequest {
    pub scope: ResolvedWorkspaceScope,
    pub goal_id: GoalId,
    pub expected_revision: GoalRevision,
    pub review_id: Uuid,
    pub observed_at: TimestampMillis,
}

impl ForgeControl {
    pub fn goal_create(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal: &RegisteredGoal,
    ) -> Result<RegisteredGoal, ControlError> {
        if goal.workspace_id() != scope.workspace_id()
            || goal.status().kind() != GoalStatusKind::Active
            || goal.revision() != GoalRevision::INITIAL
        {
            return Err(ControlError::new(ControlErrorCode::GoalConflict));
        }
        self.update_goal_store(scope, |store| store.insert_goal(goal))
    }

    pub fn goal_get(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<Option<RegisteredGoal>, ControlError> {
        let (fresh_scope, store) = self.open_goal_workspace(scope)?;
        let goal = store.get_goal(goal_id).map_err(map_goal_store_error)?;
        if goal
            .as_ref()
            .is_some_and(|goal| goal.workspace_id() != fresh_scope.workspace_id())
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(goal)
    }

    pub fn goal_list(
        &self,
        scope: &ResolvedWorkspaceScope,
        limit: GoalListLimit,
    ) -> Result<Vec<RegisteredGoal>, ControlError> {
        let (fresh_scope, store) = self.open_goal_workspace(scope)?;
        let goals = store
            .list_goals(fresh_scope.workspace_id(), limit)
            .map_err(map_goal_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(goals)
    }

    pub fn goal_transition(
        &self,
        request: &GoalLifecycleRequest,
    ) -> Result<RegisteredGoal, ControlError> {
        let (fresh_scope, mut store) = self.open_goal_workspace(&request.scope)?;
        let current = goal_from_store(&store, request.goal_id, fresh_scope.workspace_id())?;
        let updated = match &request.action {
            GoalLifecycleAction::Pause => {
                current.pause(request.expected_revision, request.observed_at)
            }
            GoalLifecycleAction::Resume => {
                current.resume(request.expected_revision, request.observed_at)
            }
            GoalLifecycleAction::Block(blocker) => current.block(
                request.expected_revision,
                blocker.clone(),
                request.observed_at,
            ),
            GoalLifecycleAction::Fail(failure) => current.fail(
                request.expected_revision,
                failure.clone(),
                request.observed_at,
            ),
            GoalLifecycleAction::Cancel => {
                current.cancel(request.expected_revision, request.observed_at)
            }
        }
        .map_err(|error| ControlError::with_source(ControlErrorCode::GoalConflict, error))?;
        let updated = store
            .update_goal(&updated, request.expected_revision)
            .map_err(map_goal_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(updated)
    }

    pub fn goal_review(
        &self,
        scope: &ResolvedWorkspaceScope,
        goal_id: GoalId,
    ) -> Result<GoalReview, ControlError> {
        let (fresh_scope, layout, store) = self.open_goal_workspace_with_layout(scope)?;
        let goal = goal_from_store(&store, goal_id, fresh_scope.workspace_id())?;
        let review = review_goal_with_files(&store, &layout, &goal)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(review)
    }

    pub fn goal_complete(
        &self,
        request: &GoalCompletionRequest,
    ) -> Result<RegisteredGoal, ControlError> {
        let (fresh_scope, layout, mut store) =
            self.open_goal_workspace_with_layout(&request.scope)?;
        let current = goal_from_store(&store, request.goal_id, fresh_scope.workspace_id())?;
        let review = review_goal_with_files(&store, &layout, &current)?;
        if !review.can_complete() {
            return Err(ControlError::new(ControlErrorCode::GoalCompletionBlocked));
        }
        let completed = current
            .complete(request.expected_revision, &review, request.observed_at)
            .map_err(|error| {
                ControlError::with_source(ControlErrorCode::GoalCompletionBlocked, error)
            })?;
        let evidence_count = store
            .list_goal_evidence(current.id(), MAX_GOAL_EVIDENCE_RESULTS)
            .map_err(map_goal_store_error)?
            .len();
        let receipt = GoalCompletionReceipt::new(
            request.review_id,
            current.id(),
            request.expected_revision,
            request.observed_at,
            u16::try_from(review.hard_checks().len())
                .map_err(|_| ControlError::new(ControlErrorCode::CapacityExceeded))?,
            u16::try_from(evidence_count)
                .map_err(|_| ControlError::new(ControlErrorCode::CapacityExceeded))?,
        );
        let completed = store
            .complete_goal(&completed, request.expected_revision, &review, &receipt)
            .map_err(map_goal_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(completed)
    }

    fn update_goal_store(
        &self,
        scope: &ResolvedWorkspaceScope,
        update: impl FnOnce(&mut WorkspaceStore) -> Result<RegisteredGoal, WorkspaceStoreError>,
    ) -> Result<RegisteredGoal, ControlError> {
        let (fresh_scope, mut store) = self.open_goal_workspace(scope)?;
        let goal = update(&mut store).map_err(map_goal_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(goal)
    }

    fn open_goal_workspace(
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

    fn open_goal_workspace_with_layout(
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
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((fresh_scope, layout, store))
    }
}

fn goal_from_store(
    store: &WorkspaceStore,
    goal_id: GoalId,
    workspace_id: forge_domain::WorkspaceId,
) -> Result<RegisteredGoal, ControlError> {
    let goal = store
        .get_goal(goal_id)
        .map_err(map_goal_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::GoalNotFound))?;
    if goal.workspace_id() != workspace_id {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    Ok(goal)
}

fn review_goal_with_files(
    store: &WorkspaceStore,
    layout: &ExistingWorkspaceStateLayout,
    goal: &RegisteredGoal,
) -> Result<GoalReview, ControlError> {
    let durable = store.review_goal(goal.id()).map_err(map_goal_store_error)?;
    let file_requirements = goal
        .contract()
        .verification_requirements()
        .iter()
        .enumerate()
        .filter_map(|(index, requirement)| {
            let GoalVerificationRequirement::FilePresent {
                path,
                expected_hash,
                ..
            } = requirement
            else {
                return None;
            };
            u16::try_from(index)
                .ok()
                .map(|index| (index, path, expected_hash))
        })
        .collect::<Vec<_>>();
    if file_requirements.is_empty() {
        return Ok(durable);
    }
    let confined = ConfinedWorkspace::open(layout).map_err(map_filesystem_error)?;
    let mut observations = HashMap::with_capacity(file_requirements.len());
    for (index, path, expected_hash) in file_requirements {
        let check = match confined.observe(path) {
            Ok(FilePathState::Regular { hash, .. })
                if expected_hash.is_none_or(|value| value == hash) =>
            {
                GoalHardCheck::Passed {
                    requirement_index: index,
                }
            }
            Ok(FilePathState::Absent) | Err(ConfinedFilesystemError::NotFound) => {
                GoalHardCheck::Missing {
                    requirement_index: index,
                }
            }
            Ok(FilePathState::Regular { .. })
            | Err(
                ConfinedFilesystemError::ProtectedPath
                | ConfinedFilesystemError::InvalidPath
                | ConfinedFilesystemError::TooManyComponents
                | ConfinedFilesystemError::SymlinkRejected
                | ConfinedFilesystemError::NonDirectoryAncestor
                | ConfinedFilesystemError::NonRegularLeaf
                | ConfinedFilesystemError::HardlinkRejected
                | ConfinedFilesystemError::PathConflict
                | ConfinedFilesystemError::StaleWrite
                | ConfinedFilesystemError::FileTooLarge { .. }
                | ConfinedFilesystemError::WriteTooLarge { .. }
                | ConfinedFilesystemError::InvalidPayload
                | ConfinedFilesystemError::AtomicCreateUnsupported
                | ConfinedFilesystemError::LockBusy
                | ConfinedFilesystemError::PostStateMismatch,
            ) => GoalHardCheck::Failed {
                requirement_index: index,
            },
            Err(error) => return Err(map_filesystem_error(error)),
        };
        observations.insert(index, check);
    }
    let hard_checks = durable
        .hard_checks()
        .iter()
        .map(|check| {
            observations
                .get(&check.requirement_index())
                .cloned()
                .unwrap_or_else(|| check.clone())
        })
        .collect::<Vec<_>>();
    let blockers = durable
        .blockers()
        .iter()
        .copied()
        .filter(|blocker| match blocker {
            GoalCompletionBlocker::RequiredVerification { requirement_index } => observations
                .get(requirement_index)
                .is_none_or(|check| !check.is_passed()),
            GoalCompletionBlocker::PendingApproval(_)
            | GoalCompletionBlocker::ActiveExecution(_)
            | GoalCompletionBlocker::UnsealedEvidence(_) => true,
        })
        .collect::<Vec<_>>();
    GoalReview::new(
        durable.goal_id(),
        durable.goal_revision(),
        hard_checks,
        blockers,
        durable.manual_assessment_required(),
    )
    .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))
}

pub(crate) fn map_goal_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::Goal(GoalStoreError::RecordMissing) => ControlErrorCode::GoalNotFound,
        WorkspaceStoreError::Goal(
            GoalStoreError::IdentityConflict
            | GoalStoreError::RevisionConflict
            | GoalStoreError::RevisionOverflow
            | GoalStoreError::InvalidTransition
            | GoalStoreError::CompletionReceiptRequired
            | GoalStoreError::Contract(_)
            | GoalStoreError::Text(_)
            | GoalStoreError::Transition(_)
            | GoalStoreError::ContractEncoding,
        ) => ControlErrorCode::GoalConflict,
        WorkspaceStoreError::Goal(
            GoalStoreError::CompletionBlocked | GoalStoreError::ReviewMismatch,
        ) => ControlErrorCode::GoalCompletionBlocked,
        WorkspaceStoreError::Goal(
            GoalStoreError::EvidenceAssociationClosed
            | GoalStoreError::EvidenceMissing
            | GoalStoreError::EvidenceConflict
            | GoalStoreError::EvidenceTimestamp
            | GoalStoreError::EvidenceLimit { .. },
        ) => ControlErrorCode::GoalEvidenceConflict,
        WorkspaceStoreError::Goal(GoalStoreError::WorkspaceMismatch) => {
            ControlErrorCode::WorkspaceIdentityConflict
        }
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
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        EstablishWorkspace, GoalContract, GoalObjective, GoalStatement, LocationId,
        LocationRevision, WorkspaceId, WorkspaceRelativePath, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct GoalFixture {
        control: ForgeControl,
        registry_path: PathBuf,
        root: PathBuf,
        workspace_root: PathBuf,
        scope: ResolvedWorkspaceScope,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn fixture(label: &str) -> Result<GoalFixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-goal-{label}-{}-{serial}",
            std::process::id()
        ));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace-0");
        fs::create_dir_all(&workspace_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xA000 + u128::from(serial)));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Goal fixture",
            &location_root,
            timestamp(1)?,
        )?;
        drop(locations);
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let command = EstablishWorkspace::new(
            WorkspaceId::from_uuid(Uuid::from_u128(0xB000 + u128::from(serial))),
            location.id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(2)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        drop(store);
        let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
        let locator = control
            .workspace_list(location.id(), LocationRevision::INITIAL)?
            .into_iter()
            .find(|entry| entry.display_name() == "workspace-0")
            .ok_or("workspace locator missing")?
            .locator()
            .clone();
        let scope =
            control.resolve_workspace(location.id(), LocationRevision::INITIAL, &locator)?;
        Ok(GoalFixture {
            control,
            registry_path,
            root,
            workspace_root,
            scope,
        })
    }

    fn goal(
        scope: &ResolvedWorkspaceScope,
        id: u128,
        path: &str,
    ) -> Result<RegisteredGoal, Box<dyn std::error::Error>> {
        Ok(RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(id)),
            scope.workspace_id(),
            GoalContract::new(
                GoalObjective::new("Verify one durable Workspace artifact".to_owned())?,
                vec![GoalStatement::new("The required file exists".to_owned())?],
                Vec::new(),
                Vec::new(),
                vec![GoalVerificationRequirement::FilePresent {
                    path: WorkspaceRelativePath::new(path.into())?,
                    expected_hash: None,
                    description: GoalStatement::new(
                        "Observe the file through confinement".to_owned(),
                    )?,
                }],
                Vec::new(),
            )?,
            timestamp(10)?,
        ))
    }

    #[test]
    fn trusted_goal_lifecycle_file_review_completion_and_restart_are_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("lifecycle")?;
        fs::write(fixture.workspace_root.join("proof.txt"), b"durable proof")?;
        let goal = goal(&fixture.scope, 0xC001, "proof.txt")?;
        assert_eq!(fixture.control.goal_create(&fixture.scope, &goal)?, goal);
        assert_eq!(
            fixture
                .control
                .goal_list(&fixture.scope, GoalListLimit::DEFAULT)?,
            vec![goal.clone()]
        );
        let review = fixture.control.goal_review(&fixture.scope, goal.id())?;
        assert!(review.can_complete());
        let completed = fixture.control.goal_complete(&GoalCompletionRequest {
            scope: fixture.scope.clone(),
            goal_id: goal.id(),
            expected_revision: goal.revision(),
            review_id: Uuid::from_u128(0xC002),
            observed_at: timestamp(20)?,
        })?;
        assert_eq!(completed.status().kind(), GoalStatusKind::Completed);

        let restarted = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?);
        assert_eq!(
            restarted.goal_get(&fixture.scope, goal.id())?,
            Some(completed)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn missing_file_and_stale_lifecycle_revision_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("blocked")?;
        let goal = goal(&fixture.scope, 0xC101, "missing.txt")?;
        let _ = fixture.control.goal_create(&fixture.scope, &goal)?;
        let review = fixture.control.goal_review(&fixture.scope, goal.id())?;
        assert!(!review.can_complete());
        let Err(completion_error) = fixture.control.goal_complete(&GoalCompletionRequest {
            scope: fixture.scope.clone(),
            goal_id: goal.id(),
            expected_revision: goal.revision(),
            review_id: Uuid::from_u128(0xC102),
            observed_at: timestamp(20)?,
        }) else {
            return Err("missing file unexpectedly completed Goal".into());
        };
        assert_eq!(
            completion_error.code(),
            ControlErrorCode::GoalCompletionBlocked
        );
        let paused = fixture.control.goal_transition(&GoalLifecycleRequest {
            scope: fixture.scope.clone(),
            goal_id: goal.id(),
            expected_revision: goal.revision(),
            observed_at: timestamp(21)?,
            action: GoalLifecycleAction::Pause,
        })?;
        assert_eq!(paused.status().kind(), GoalStatusKind::Paused);
        let Err(stale_error) = fixture.control.goal_transition(&GoalLifecycleRequest {
            scope: fixture.scope.clone(),
            goal_id: goal.id(),
            expected_revision: goal.revision(),
            observed_at: timestamp(22)?,
            action: GoalLifecycleAction::Resume,
        }) else {
            return Err("stale Goal revision unexpectedly succeeded".into());
        };
        assert_eq!(stale_error.code(), ControlErrorCode::GoalConflict);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn bounded_control_worker_dispatches_goal_create_review_and_complete()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("worker")?;
        fs::write(fixture.workspace_root.join("worker-proof.txt"), b"proof")?;
        let goal = goal(&fixture.scope, 0xC201, "worker-proof.txt")?;
        let scope = fixture.scope.clone();
        let root = fixture.root.clone();
        let (client, mut worker) = fixture.control.start_worker()?;

        assert_eq!(client.goal_create(scope.clone(), goal.clone())?, goal);
        assert_eq!(
            client.goal_list(scope.clone(), GoalListLimit::DEFAULT)?,
            vec![goal.clone()]
        );
        assert!(client.goal_review(scope.clone(), goal.id())?.can_complete());
        let completed = client.goal_complete(GoalCompletionRequest {
            scope,
            goal_id: goal.id(),
            expected_revision: goal.revision(),
            review_id: Uuid::from_u128(0xC202),
            observed_at: timestamp(20)?,
        })?;
        assert_eq!(completed.status().kind(), GoalStatusKind::Completed);
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
