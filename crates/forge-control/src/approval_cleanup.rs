//! Private, transport-neutral authority for exact approval cleanup.
//!
//! This module owns only the native owner, scope permit, selector, and frozen
//! plan fences. Durable plan capture/apply/readback remains a persistence
//! responsibility; the control boundary never manufactures SQL authority.

use std::fmt;

use forge_domain::{ActivityId, ExecutionListLimit, TimestampMillis};
use forge_persistence::{
    ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId,
    ApprovalCleanupMode as PersistenceCleanupMode, ApprovalCleanupPlan as PersistenceCleanupPlan,
    ApprovalCleanupReadback as PersistenceCleanupReadback,
    ApprovalCleanupSelector as PersistenceCleanupSelector, WorkspaceJournalBinding,
};
use forge_workspace::ExistingWorkspaceStateLayout;
use uuid::Uuid;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

const MAX_APPROVAL_CLEANUP_ROWS: u32 = 768;
const MAX_APPROVAL_CLEANUP_FAMILY_ROWS: usize = 256;

/// Opaque identity of one live `ApprovalCoordinator` owner.
///
/// This is deliberately non-serializable and redacted in diagnostics. It is
/// correlation/fencing data for the local owner, never a grant or HTTP token.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ApprovalCleanupOwner(Uuid);

impl ApprovalCleanupOwner {
    pub(crate) fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl fmt::Debug for ApprovalCleanupOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCleanupOwner")
            .field("id", &"<redacted>")
            .finish()
    }
}

/// Exact administrative cleanup selector. A Workspace permit may narrow to an
/// Activity; an Activity permit can never expand to Workspace scope.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ApprovalCleanupSelector {
    Workspace,
    Activity(ActivityId),
}

impl ApprovalCleanupSelector {
    fn is_subset_of(self, permit: Self) -> bool {
        match (permit, self) {
            (Self::Workspace, Self::Workspace | Self::Activity(_)) => true,
            (Self::Activity(expected), Self::Activity(actual)) => expected == actual,
            (Self::Activity(_), Self::Workspace) => false,
        }
    }

    const fn persistence(self) -> PersistenceCleanupSelector {
        match self {
            Self::Workspace => PersistenceCleanupSelector::Workspace,
            Self::Activity(activity_id) => PersistenceCleanupSelector::Activity(activity_id),
        }
    }
}

/// Cleanup-only purpose fence. There is intentionally no constructor for
/// approval/grant/session issuance or renewal through this authority.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ApprovalCleanupPurpose {
    AuthorityCancellation,
}

/// Exact permit minted only after a fresh resolved scope and live journal
/// binding have been checked by `ForgeControl`.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApprovalCleanupPermit {
    owner: ApprovalCleanupOwner,
    scope: ResolvedWorkspaceScope,
    selector: ApprovalCleanupSelector,
    purpose: ApprovalCleanupPurpose,
    layout: ExistingWorkspaceStateLayout,
    binding: WorkspaceJournalBinding,
}

impl fmt::Debug for ApprovalCleanupPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCleanupPermit")
            .field("owner", &self.owner)
            .field("workspace_id", &self.scope.workspace_id())
            .field("workspace_revision", &self.scope.workspace_revision())
            .field("selector", &self.selector)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

impl ApprovalCleanupPermit {
    fn new(
        owner: ApprovalCleanupOwner,
        scope: ResolvedWorkspaceScope,
        selector: ApprovalCleanupSelector,
        layout: ExistingWorkspaceStateLayout,
        binding: WorkspaceJournalBinding,
    ) -> Self {
        Self {
            owner,
            scope,
            selector,
            purpose: ApprovalCleanupPurpose::AuthorityCancellation,
            layout,
            binding,
        }
    }

    pub(crate) const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub(crate) const fn layout(&self) -> &ExistingWorkspaceStateLayout {
        &self.layout
    }

    pub(crate) const fn binding(&self) -> &WorkspaceJournalBinding {
        &self.binding
    }

    fn validate_prepare(
        &self,
        owner: ApprovalCleanupOwner,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<(), ControlError> {
        self.ensure_owner(owner)?;
        if !selector.is_subset_of(self.selector) {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        if usize::from(limit.get()) > MAX_APPROVAL_CLEANUP_FAMILY_ROWS
            || u32::from(limit.get()) > MAX_APPROVAL_CLEANUP_ROWS
        {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        let _ = observed_at;
        Ok(())
    }

    pub(crate) fn validate_workspace_stop(
        &self,
        owner: ApprovalCleanupOwner,
    ) -> Result<(), ControlError> {
        self.ensure_owner(owner)?;
        if !ApprovalCleanupSelector::Workspace.is_subset_of(self.selector) {
            return Err(ControlError::new(ControlErrorCode::ApprovalConflict));
        }
        Ok(())
    }

    pub(crate) fn ensure_owner(&self, owner: ApprovalCleanupOwner) -> Result<(), ControlError> {
        (self.owner == owner)
            .then_some(())
            .ok_or_else(|| ControlError::new(ControlErrorCode::ExecutionProvenanceConflict))
    }

    pub(crate) fn validate_reopen(
        &self,
        owner: ApprovalCleanupOwner,
        scope: &ResolvedWorkspaceScope,
        layout: &ExistingWorkspaceStateLayout,
        binding: &WorkspaceJournalBinding,
    ) -> Result<(), ControlError> {
        self.ensure_owner(owner)?;
        if scope != &self.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        if layout != &self.layout || binding != &self.binding {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(())
    }
}

/// Immutable control-side envelope for the persistence-owned exact plan.
/// Persistence adds the captured before images/target rows behind this opaque
/// boundary; these fields remain the local owner/scope/time fence.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApprovalCleanupPlan {
    owner: ApprovalCleanupOwner,
    permit: ApprovalCleanupPermit,
    selector: ApprovalCleanupSelector,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
    persistence: PersistenceCleanupPlan,
}

impl fmt::Debug for ApprovalCleanupPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCleanupPlan")
            .field("owner", &self.owner)
            .field("workspace_id", &self.permit.scope.workspace_id())
            .field("selector", &self.selector)
            .field("observed_at", &self.observed_at)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl ApprovalCleanupPlan {
    pub(crate) const fn permit(&self) -> &ApprovalCleanupPermit {
        &self.permit
    }

    pub(crate) const fn persistence(&self) -> &PersistenceCleanupPlan {
        &self.persistence
    }

    pub(crate) fn validate(&self, owner: ApprovalCleanupOwner) -> Result<(), ControlError> {
        self.permit.ensure_owner(owner)?;
        self.permit.validate_reopen(
            owner,
            self.permit.scope(),
            self.permit.layout(),
            self.permit.binding(),
        )?;
        if self.owner != owner || !self.selector.is_subset_of(self.permit.selector) {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        let persistence = self.persistence();
        if persistence.workspace_id() != self.permit.scope.workspace_id()
            || persistence.selector() != self.selector.persistence()
            || persistence.mode() != PersistenceCleanupMode::AuthorityCancellation
            || persistence.observed_at() != self.observed_at
        {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        let report = persistence.report();
        if report.approvals() > MAX_APPROVAL_CLEANUP_FAMILY_ROWS
            || report.grants() > MAX_APPROVAL_CLEANUP_FAMILY_ROWS
            || report.auto_scopes() > MAX_APPROVAL_CLEANUP_FAMILY_ROWS
            || report.total() > usize::try_from(MAX_APPROVAL_CLEANUP_ROWS).unwrap_or(usize::MAX)
        {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        Ok(())
    }
}

/// Persistence-owned readback classification retained by the control worker.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalCleanupReadback {
    Absent,
    SettledTargetState,
    Mismatch,
}

pub(crate) const fn map_approval_cleanup_readback(
    readback: PersistenceCleanupReadback,
) -> ApprovalCleanupReadback {
    match readback {
        PersistenceCleanupReadback::Absent => ApprovalCleanupReadback::Absent,
        PersistenceCleanupReadback::SettledTargetState => {
            ApprovalCleanupReadback::SettledTargetState
        }
        PersistenceCleanupReadback::Mismatch => ApprovalCleanupReadback::Mismatch,
    }
}

impl ForgeControl {
    /// Mint one cleanup permit from a fresh checked scope and live physical
    /// journal binding. This does not create or renew any approval authority.
    pub(crate) fn mint_approval_cleanup_permit(
        &self,
        owner: ApprovalCleanupOwner,
        scope: ResolvedWorkspaceScope,
        selector: ApprovalCleanupSelector,
    ) -> Result<ApprovalCleanupPermit, ControlError> {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        Ok(ApprovalCleanupPermit::new(
            owner, scope, selector, layout, binding,
        ))
    }

    pub(crate) fn prepare_approval_cleanup_plan(
        permit: &ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        selector: ApprovalCleanupSelector,
        observed_at: TimestampMillis,
        limit: ExecutionListLimit,
    ) -> Result<ApprovalCleanupPlan, ControlError> {
        permit.validate_prepare(owner, selector, observed_at, limit)?;
        let store = forge_persistence::WorkspaceStore::open_existing_journal(
            permit.layout(),
            permit.binding(),
        )
        .map_err(map_activity_store_error)?;
        let persistence = store
            .prepare_approval_cleanup(selector.persistence(), observed_at, limit)
            .map_err(map_activity_store_error)?;
        Ok(ApprovalCleanupPlan {
            owner,
            permit: permit.clone(),
            selector,
            observed_at,
            limit,
            persistence,
        })
    }

    pub(crate) fn apply_approval_cleanup_plan(
        owner: ApprovalCleanupOwner,
        plan: &ApprovalCleanupPlan,
        attempt: ApprovalCleanupAttemptId,
    ) -> Result<ApprovalCleanupApplyOutcome, ControlError> {
        plan.validate(owner)?;
        let mut store = forge_persistence::WorkspaceStore::open_existing_journal(
            plan.permit.layout(),
            plan.permit.binding(),
        )
        .map_err(map_activity_store_error)?;
        let outcome = store
            .apply_approval_cleanup(plan.persistence(), attempt)
            .map_err(map_activity_store_error)?;
        if let ApprovalCleanupApplyOutcome::RejectedBeforeWrite(rejection) = &outcome
            && !rejection.matches(plan.persistence(), attempt)
        {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        Ok(outcome)
    }

    pub(crate) fn observe_approval_cleanup_plan(
        owner: ApprovalCleanupOwner,
        plan: &ApprovalCleanupPlan,
    ) -> Result<ApprovalCleanupReadback, ControlError> {
        plan.validate(owner)?;
        let store = forge_persistence::WorkspaceStore::open_existing_journal(
            plan.permit.layout(),
            plan.permit.binding(),
        )
        .map_err(map_activity_store_error)?;
        Ok(map_approval_cleanup_readback(
            store
                .observe_approval_cleanup(plan.persistence())
                .map_err(map_activity_store_error)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityId, EstablishWorkspace, ExecutionListLimit, LocationId, LocationRevision,
        LocationState, RuntimeInstanceId, SetLocationState, TimestampMillis, WorkspaceId,
        WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::{
        ApprovalCleanupOwner, ApprovalCleanupReadback, ApprovalCleanupSelector, ForgeControl,
    };
    use crate::error::ControlErrorCode;
    use crate::service::ResolvedWorkspaceScope;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct CleanupFixture {
        root: PathBuf,
        workspace_root: PathBuf,
        location_id: LocationId,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        control: ForgeControl,
    }

    impl CleanupFixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "forge-control-approval-cleanup-{nonce}-{serial}-{}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            let location_root = root.join("location");
            let workspace_root = location_root.join("workspace");
            fs::create_dir_all(&workspace_root)?;
            let registry_path = root.join("registry.sqlite3");
            let location_id = LocationId::from_uuid(Uuid::from_u128(1));
            let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(2));
            let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
            let location = locations.register_selected_path(
                location_id,
                "Approval cleanup fixture",
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
            let activity_id = ActivityId::from_uuid(Uuid::from_u128(3));
            let _bootstrap = control.bootstrap_activity(
                &scope,
                activity_id,
                RuntimeInstanceId::from_uuid(Uuid::from_u128(4)),
                TimestampMillis::new(3)?,
                TimestampMillis::new(100)?,
            )?;
            Ok(Self {
                root,
                workspace_root,
                location_id,
                scope,
                activity_id,
                control,
            })
        }

        fn finish(self) -> Result<(), Box<dyn Error>> {
            let Self { root, control, .. } = self;
            drop(control);
            fs::remove_dir_all(root)?;
            Ok(())
        }
    }

    fn error_code<T>(result: Result<T, crate::error::ControlError>) -> Option<ControlErrorCode> {
        result.err().map(|error| error.code())
    }

    #[test]
    fn approval_cleanup_rejects_foreign_owner() -> Result<(), Box<dyn Error>> {
        let fixture = CleanupFixture::new()?;
        let owner = ApprovalCleanupOwner::new();
        let foreign_owner = ApprovalCleanupOwner::new();
        let permit = fixture.control.mint_approval_cleanup_permit(
            owner,
            fixture.scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        let error = ForgeControl::prepare_approval_cleanup_plan(
            &permit,
            foreign_owner,
            ApprovalCleanupSelector::Workspace,
            TimestampMillis::new(5)?,
            ExecutionListLimit::DEFAULT,
        );
        assert_eq!(
            error_code(error),
            Some(ControlErrorCode::ExecutionProvenanceConflict)
        );
        fixture.finish()
    }

    #[test]
    fn approval_cleanup_allows_activity_narrowing_and_rejects_workspace_broadening()
    -> Result<(), Box<dyn Error>> {
        let fixture = CleanupFixture::new()?;
        let owner = ApprovalCleanupOwner::new();
        let workspace_permit = fixture.control.mint_approval_cleanup_permit(
            owner,
            fixture.scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        let narrowed = ForgeControl::prepare_approval_cleanup_plan(
            &workspace_permit,
            owner,
            ApprovalCleanupSelector::Activity(fixture.activity_id),
            TimestampMillis::new(5)?,
            ExecutionListLimit::DEFAULT,
        )?;
        assert_eq!(
            narrowed.selector,
            ApprovalCleanupSelector::Activity(fixture.activity_id)
        );

        let activity_permit = fixture.control.mint_approval_cleanup_permit(
            owner,
            fixture.scope.clone(),
            ApprovalCleanupSelector::Activity(fixture.activity_id),
        )?;
        let error = ForgeControl::prepare_approval_cleanup_plan(
            &activity_permit,
            owner,
            ApprovalCleanupSelector::Workspace,
            TimestampMillis::new(6)?,
            ExecutionListLimit::DEFAULT,
        );
        assert_eq!(error_code(error), Some(ControlErrorCode::ApprovalConflict));
        fixture.finish()
    }

    #[test]
    fn approval_cleanup_rejects_captured_physical_binding_replacement() -> Result<(), Box<dyn Error>>
    {
        let fixture = CleanupFixture::new()?;
        let owner = ApprovalCleanupOwner::new();
        let permit = fixture.control.mint_approval_cleanup_permit(
            owner,
            fixture.scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        let state_root = fixture.workspace_root.join(".heterarchy-forge");
        let moved_state_root = fixture.workspace_root.join(".heterarchy-forge-original");
        fs::rename(&state_root, &moved_state_root)?;
        fs::create_dir(&state_root)?;
        let result = ForgeControl::prepare_approval_cleanup_plan(
            &permit,
            owner,
            ApprovalCleanupSelector::Workspace,
            TimestampMillis::new(5)?,
            ExecutionListLimit::DEFAULT,
        );
        fs::remove_dir_all(&state_root)?;
        fs::rename(&moved_state_root, &state_root)?;
        assert!(result.is_err());
        fixture.finish()
    }

    #[test]
    fn disabled_location_allows_captured_cleanup_without_new_command_authority()
    -> Result<(), Box<dyn Error>> {
        let mut fixture = CleanupFixture::new()?;
        let owner = ApprovalCleanupOwner::new();
        let permit = fixture.control.mint_approval_cleanup_permit(
            owner,
            fixture.scope.clone(),
            ApprovalCleanupSelector::Workspace,
        )?;
        fixture.control.set_location_state(&SetLocationState::new(
            fixture.location_id,
            LocationRevision::INITIAL,
            LocationState::Disabled,
            TimestampMillis::new(5)?,
        ))?;

        assert!(
            fixture
                .control
                .resolve_workspace(
                    fixture.location_id,
                    fixture.scope.locator().expected_revision(),
                    fixture.scope.locator(),
                )
                .is_err()
        );
        assert!(
            fixture
                .control
                .mint_approval_cleanup_permit(
                    ApprovalCleanupOwner::new(),
                    fixture.scope.clone(),
                    ApprovalCleanupSelector::Workspace,
                )
                .is_err()
        );

        let plan = ForgeControl::prepare_approval_cleanup_plan(
            &permit,
            owner,
            ApprovalCleanupSelector::Workspace,
            TimestampMillis::new(6)?,
            ExecutionListLimit::DEFAULT,
        )?;
        let outcome = ForgeControl::apply_approval_cleanup_plan(
            owner,
            &plan,
            forge_persistence::ApprovalCleanupAttemptId::from_uuid(Uuid::now_v7()),
        )?;
        assert!(matches!(
            outcome,
            forge_persistence::ApprovalCleanupApplyOutcome::Applied(report)
                if report.total() == 0
        ));
        assert_eq!(
            ForgeControl::observe_approval_cleanup_plan(owner, &plan)?,
            ApprovalCleanupReadback::Absent
        );
        fixture.finish()
    }
}
