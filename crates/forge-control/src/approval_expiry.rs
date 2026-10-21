//! Private, transport-neutral authority for exact approval expiry.
//!
//! Expiry plans use the shared persistence cleanup engine in `ExpiredOnly`
//! mode. They retain the original logical scope and physical journal binding,
//! but never create an administrative cleanup owner or permit.

use std::fmt;

use forge_domain::{ExecutionListLimit, TimestampMillis};
use forge_persistence::{
    ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId, ApprovalCleanupMode,
    ApprovalCleanupPlan as PersistenceCleanupPlan,
    ApprovalCleanupSelector as PersistenceCleanupSelector, WorkspaceJournalBinding, WorkspaceStore,
};
use forge_workspace::ExistingWorkspaceStateLayout;

use crate::approval_cleanup::{ApprovalCleanupReadback, map_approval_cleanup_readback};
use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

/// Immutable expiry plan captured from one exact Workspace scope and journal.
///
/// The persistence plan carries all before/after images and the original
/// observation timestamp. The control envelope keeps the logical and physical
/// fences needed for later apply/readback without becoming an authority grant.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApprovalExpiryPlan {
    scope: ResolvedWorkspaceScope,
    layout: ExistingWorkspaceStateLayout,
    binding: WorkspaceJournalBinding,
    persistence: PersistenceCleanupPlan,
}

impl fmt::Debug for ApprovalExpiryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalExpiryPlan")
            .field("workspace_id", &self.scope.workspace_id())
            .field("workspace_revision", &self.scope.workspace_revision())
            .field("selector", &self.persistence.selector())
            .field("mode", &self.persistence.mode())
            .field("observed_at", &self.persistence.observed_at())
            .finish_non_exhaustive()
    }
}

impl ApprovalExpiryPlan {
    pub(crate) const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub(crate) const fn persistence(&self) -> &PersistenceCleanupPlan {
        &self.persistence
    }

    fn validate(&self) -> Result<(), ControlError> {
        if self.persistence.workspace_id() != self.scope.workspace_id()
            || self.persistence.selector() != PersistenceCleanupSelector::Workspace
            || self.persistence.mode() != ApprovalCleanupMode::ExpiredOnly
        {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(())
    }
}

impl ForgeControl {
    /// Capture one bounded `ExpiredOnly` plan from a fresh exact Workspace scope.
    pub(crate) fn prepare_approval_expiry_plan(
        &self,
        scope: &ResolvedWorkspaceScope,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<ApprovalExpiryPlan, ControlError> {
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
        let persistence = store
            .prepare_expired_approval_cleanup(
                PersistenceCleanupSelector::Workspace,
                observed_at,
                limit,
            )
            .map_err(map_activity_store_error)?;
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        let plan = ApprovalExpiryPlan {
            scope: fresh_scope,
            layout,
            binding,
            persistence,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Apply only the captured `ExpiredOnly` plan after fresh logical and
    /// physical validation. A post-commit logical mismatch is unknown.
    pub(crate) fn apply_approval_expiry_plan(
        &self,
        plan: &ApprovalExpiryPlan,
        attempt: ApprovalCleanupAttemptId,
    ) -> Result<ApprovalCleanupApplyOutcome, ControlError> {
        let mut store = self.open_exact_live_workspace(plan)?;
        let outcome = store
            .apply_approval_cleanup(plan.persistence(), attempt)
            .map_err(map_activity_store_error)?;
        match &outcome {
            ApprovalCleanupApplyOutcome::Applied(_) => {
                if !self.committed_scope_matches_with_store(plan.scope(), &store) {
                    return Err(ControlError::committed());
                }
            }
            ApprovalCleanupApplyOutcome::RejectedBeforeWrite(rejection) => {
                if !rejection.matches(plan.persistence(), attempt) {
                    return Err(ControlError::new(
                        ControlErrorCode::ExecutionProvenanceConflict,
                    ));
                }
            }
        }
        Ok(outcome)
    }

    /// Read exact before/after facts through the original binding. Logical
    /// Location disable therefore blocks apply but does not erase readback.
    pub(crate) fn observe_approval_expiry_plan(
        plan: &ApprovalExpiryPlan,
    ) -> Result<ApprovalCleanupReadback, ControlError> {
        plan.validate()?;
        let store = WorkspaceStore::open_existing_journal(&plan.layout, &plan.binding)
            .map_err(map_activity_store_error)?;
        Ok(map_approval_cleanup_readback(
            store
                .observe_approval_cleanup(plan.persistence())
                .map_err(map_activity_store_error)?,
        ))
    }

    fn open_exact_live_workspace(
        &self,
        plan: &ApprovalExpiryPlan,
    ) -> Result<WorkspaceStore, ControlError> {
        plan.validate()?;
        let (fresh_scope, layout, checked_store) = self.open_resolved_workspace_with_layout(
            plan.scope.locator().location_id(),
            plan.scope.locator().expected_revision(),
            plan.scope.locator(),
        )?;
        if fresh_scope != plan.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = checked_store
            .journal_binding()
            .map_err(map_activity_store_error)?;
        if layout != plan.layout || binding != plan.binding {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(checked_store)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityId, ApprovalRequestId, EstablishWorkspace, ExecutionActionClass, ExecutionId,
        ExecutionListLimit, ExecutionPermissions, ExecutionRequestDigest, LocationId,
        LocationRevision, LocationState, RegisteredApprovalRequest, RequestedExecutionPermissions,
        RuntimeInstanceId, SetLocationState, TimestampMillis, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{ApprovalCleanupMode, GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::{ApprovalExpiryPlan, ForgeControl};
    use crate::approval_cleanup::ApprovalCleanupReadback;
    use crate::error::ControlErrorCode;
    use crate::service::ResolvedWorkspaceScope;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct ExpiryFixture {
        root: PathBuf,
        workspace_root: PathBuf,
        location_id: LocationId,
        scope: ResolvedWorkspaceScope,
        expired_id: ApprovalRequestId,
        active_id: ApprovalRequestId,
        control: ForgeControl,
    }

    impl ExpiryFixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "forge-control-approval-expiry-{nonce}-{serial}-{}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            let location_root = root.join("location");
            let workspace_root = location_root.join("workspace");
            fs::create_dir_all(&workspace_root)?;
            let registry_path = root.join("registry.sqlite3");
            let location_id = LocationId::from_uuid(Uuid::from_u128(0xE101));
            let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xE102));
            let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
            let location = locations.register_selected_path(
                location_id,
                "Approval expiry fixture",
                &location_root,
                TimestampMillis::new(1)?,
            )?;
            let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
            let establish = EstablishWorkspace::new(
                workspace_id,
                location.id(),
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                TimestampMillis::new(2)?,
            );
            drop(WorkspaceStore::open(&layout, &establish)?);
            drop(locations);

            let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
            let locator = control
                .workspace_discover(location_id, LocationRevision::INITIAL)?
                .into_iter()
                .find(|entry| entry.display_name() == "workspace")
                .ok_or("initialized workspace was not discovered")?
                .locator()
                .clone();
            let scope =
                control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
            let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xE103));
            let _bootstrap = control.bootstrap_activity(
                &scope,
                activity_id,
                RuntimeInstanceId::from_uuid(Uuid::from_u128(0xE104)),
                TimestampMillis::new(3)?,
                TimestampMillis::new(100)?,
            )?;

            let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
                .ok_or("initialized Workspace layout disappeared")?;
            let mut store = WorkspaceStore::open_existing(&layout)?;
            let policy = store.ensure_workspace_policy(TimestampMillis::new(4)?)?;
            let expired_id = ApprovalRequestId::from_uuid(Uuid::from_u128(0xE105));
            let active_id = ApprovalRequestId::from_uuid(Uuid::from_u128(0xE106));
            for (approval_id, execution_id, expires_at) in
                [(expired_id, 0xE107, 10_i64), (active_id, 0xE108, 100_i64)]
            {
                let request = RegisteredApprovalRequest::pending(
                    approval_id,
                    forge_domain::ExecutionAuthorizationRequest::new(
                        ExecutionId::from_uuid(Uuid::from_u128(execution_id)),
                        workspace_id,
                        activity_id,
                        ExecutionRequestDigest::from_bytes([u8::try_from(expires_at)?; 32]),
                        ExecutionActionClass::DirectStructured,
                        RequestedExecutionPermissions::new(ExecutionPermissions::new(
                            true, false, false,
                        )),
                    ),
                    policy.revision(),
                    TimestampMillis::new(5)?,
                    TimestampMillis::new(expires_at)?,
                )?;
                let _inserted = store.insert_pending_approval(&request)?;
            }
            drop(store);

            Ok(Self {
                root,
                workspace_root,
                location_id,
                scope,
                expired_id,
                active_id,
                control,
            })
        }

        fn finish(self) -> Result<(), Box<dyn Error>> {
            let Self { root, control, .. } = self;
            drop(control);
            fs::remove_dir_all(root)?;
            Ok(())
        }

        fn read_states(
            &self,
        ) -> Result<
            (
                forge_domain::ApprovalRequestState,
                forge_domain::ApprovalRequestState,
            ),
            Box<dyn Error>,
        > {
            let layout = WorkspaceStateLayout::inspect_existing(&self.workspace_root)?
                .ok_or("Workspace layout missing")?;
            let store = WorkspaceStore::open_existing(&layout)?;
            let expired = store
                .get_approval_request(self.expired_id)?
                .ok_or("expired approval missing")?;
            let active = store
                .get_approval_request(self.active_id)?
                .ok_or("active approval missing")?;
            Ok((expired.state(), active.state()))
        }
    }

    pub(crate) fn worker_fixture()
    -> Result<(PathBuf, ForgeControl, ResolvedWorkspaceScope), Box<dyn Error>> {
        let fixture = ExpiryFixture::new()?;
        Ok((fixture.root, fixture.control, fixture.scope))
    }

    fn prepare(fixture: &ExpiryFixture) -> Result<ApprovalExpiryPlan, Box<dyn Error>> {
        Ok(fixture.control.prepare_approval_expiry_plan(
            &fixture.scope,
            TimestampMillis::new(50)?,
            ExecutionListLimit::DEFAULT,
        )?)
    }

    #[test]
    fn expiry_plan_preserves_active_authority_and_is_readback_settled() -> Result<(), Box<dyn Error>>
    {
        let fixture = ExpiryFixture::new()?;
        let plan = prepare(&fixture)?;
        assert_eq!(plan.persistence().report().approvals(), 1);
        assert_eq!(plan.persistence().mode(), ApprovalCleanupMode::ExpiredOnly);
        let outcome = fixture.control.apply_approval_expiry_plan(
            &plan,
            forge_persistence::ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7()),
        )?;
        assert!(matches!(
            outcome,
            forge_persistence::ApprovalCleanupApplyOutcome::Applied(report)
                if report.approvals() == 1
        ));
        assert_eq!(
            ForgeControl::observe_approval_expiry_plan(&plan)?,
            ApprovalCleanupReadback::SettledTargetState
        );
        assert_eq!(
            fixture.read_states()?,
            (
                forge_domain::ApprovalRequestState::Expired,
                forge_domain::ApprovalRequestState::Pending,
            )
        );
        fixture.finish()
    }

    #[test]
    fn disabled_location_blocks_expiry_apply_but_preserves_original_readback()
    -> Result<(), Box<dyn Error>> {
        let mut fixture = ExpiryFixture::new()?;
        let plan = prepare(&fixture)?;
        fixture.control.set_location_state(&SetLocationState::new(
            fixture.location_id,
            LocationRevision::INITIAL,
            LocationState::Disabled,
            TimestampMillis::new(51)?,
        ))?;
        let apply = fixture.control.apply_approval_expiry_plan(
            &plan,
            forge_persistence::ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7()),
        );
        assert!(matches!(
            apply,
            Err(error)
                if matches!(
                    error.code(),
                    ControlErrorCode::LocationUnavailable
                        | ControlErrorCode::LocationRevisionConflict
                )
        ));
        assert_eq!(
            ForgeControl::observe_approval_expiry_plan(&plan)?,
            ApprovalCleanupReadback::Absent
        );
        assert_eq!(
            fixture.read_states()?,
            (
                forge_domain::ApprovalRequestState::Pending,
                forge_domain::ApprovalRequestState::Pending,
            )
        );
        fixture.finish()
    }

    #[test]
    fn expiry_rejects_authority_cancellation_mode_confusion_before_effects()
    -> Result<(), Box<dyn Error>> {
        let fixture = ExpiryFixture::new()?;
        let expiry = prepare(&fixture)?;
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("Workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let administrative = store.prepare_approval_cleanup(
            forge_persistence::ApprovalCleanupSelector::Workspace,
            TimestampMillis::new(50)?,
            ExecutionListLimit::DEFAULT,
        )?;
        let confused = ApprovalExpiryPlan {
            scope: expiry.scope.clone(),
            layout: expiry.layout.clone(),
            binding: expiry.binding.clone(),
            persistence: administrative,
        };

        assert!(matches!(
            ForgeControl::apply_approval_expiry_plan(
                &fixture.control,
                &confused,
                forge_persistence::ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7()),
            ),
            Err(error) if error.code() == ControlErrorCode::ExecutionProvenanceConflict
        ));
        assert!(matches!(
            ForgeControl::observe_approval_expiry_plan(&confused),
            Err(error) if error.code() == ControlErrorCode::ExecutionProvenanceConflict
        ));
        assert_eq!(
            fixture.read_states()?,
            (
                forge_domain::ApprovalRequestState::Pending,
                forge_domain::ApprovalRequestState::Pending,
            )
        );
        fixture.finish()
    }
}
