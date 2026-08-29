//! Harness Library registration and read-only Workspace Harness projection.
//!
//! The app-global Library and Workspace-local applied state stay separate:
//! Library registration inspects owner-selected local Bundle sources before a
//! short catalog transaction, while Workspace projection resolves an exact
//! durable Workspace and reads only its applied Bundle snapshot.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use forge_domain::{
    AppliedHarness, AppliedHarnessError, HarnessBundleDescriptor, HarnessBundleId,
    HarnessContentHash, HarnessRevision, HarnessSkillId, HarnessSkillRevision,
    HarnessVerificationOutcome, HarnessVerifierRun, HarnessVerifierRunRevision, MAX_HARNESS_SKILLS,
    TimestampMillis,
};
use forge_persistence::{
    HarnessCatalog, HarnessCatalogEntry, HarnessCatalogError, HarnessSkillCatalogEntry,
    MAX_HARNESS_CATALOG_RESULTS,
};
use forge_workspace::{
    ConfinedWorkspace, HarnessCompositionError, HarnessCompositionIdentity, HarnessInstallPreview,
    HarnessLifecycleError, HarnessLifecyclePreview, HarnessMaterializationError,
    HarnessPreviewError, InspectedHarnessBundle, inspect_harness_skill,
    materialize_harness_install, materialize_harness_lifecycle, preview_harness_install,
    preview_harness_lifecycle, save_harness_composition,
};
use forge_workspace::{HarnessBundleInspectionError, inspect_harness_bundle};
use thiserror::Error;

use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_store_error};
use crate::{ControlError, ControlErrorCode};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessApplyRequest {
    pub scope: ResolvedWorkspaceScope,
    pub source_root: PathBuf,
    pub expected_preview: HarnessInstallPreview,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessVerifyRequest {
    pub scope: ResolvedWorkspaceScope,
    pub source_root: PathBuf,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessPreviewRequest {
    pub scope: ResolvedWorkspaceScope,
    pub source_root: PathBuf,
    pub expected_bundle: HarnessBundleDescriptor,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessLifecycleTarget {
    Bundle {
        source_root: PathBuf,
        expected_bundle: HarnessBundleDescriptor,
    },
    Remove,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessLifecyclePreviewRequest {
    pub scope: ResolvedWorkspaceScope,
    pub target: HarnessLifecycleTarget,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessLifecyclePreviewProjection {
    preview: HarnessLifecyclePreview,
    current_revision: HarnessRevision,
}

impl HarnessLifecyclePreviewProjection {
    pub const fn preview(&self) -> &HarnessLifecyclePreview {
        &self.preview
    }

    pub const fn current_revision(&self) -> HarnessRevision {
        self.current_revision
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessLifecycleApplyRequest {
    pub scope: ResolvedWorkspaceScope,
    pub target: HarnessLifecycleTarget,
    pub expected: HarnessLifecyclePreviewProjection,
    pub observed_at: TimestampMillis,
}

/// Exact Skill catalog state captured by a composition selection.
///
/// A selection is intentionally stronger than an id-only reference: a source
/// refresh must invalidate a pending Save-as-Bundle request even when the
/// selected Skill keeps the same durable identity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HarnessCompositionSkillSelection {
    id: HarnessSkillId,
    expected_revision: HarnessSkillRevision,
    expected_content_hash: HarnessContentHash,
}

impl HarnessCompositionSkillSelection {
    pub const fn new(
        id: HarnessSkillId,
        expected_revision: HarnessSkillRevision,
        expected_content_hash: HarnessContentHash,
    ) -> Self {
        Self {
            id,
            expected_revision,
            expected_content_hash,
        }
    }

    pub const fn id(self) -> HarnessSkillId {
        self.id
    }

    pub const fn expected_revision(self) -> HarnessSkillRevision {
        self.expected_revision
    }

    pub const fn expected_content_hash(self) -> HarnessContentHash {
        self.expected_content_hash
    }
}

/// Typed Save-as-Bundle request bound to exact catalog snapshots.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessCompositionRequest {
    base_bundle_id: HarnessBundleId,
    expected_base_revision: HarnessRevision,
    selected_skills: Vec<HarnessCompositionSkillSelection>,
    identity: HarnessCompositionIdentity,
    observed_at: TimestampMillis,
}

impl HarnessCompositionRequest {
    pub fn new(
        base_bundle_id: HarnessBundleId,
        expected_base_revision: HarnessRevision,
        selected_skills: Vec<HarnessCompositionSkillSelection>,
        identity: HarnessCompositionIdentity,
        observed_at: TimestampMillis,
    ) -> Result<Self, HarnessCompositionRequestError> {
        if selected_skills.len() > usize::from(MAX_HARNESS_SKILLS) {
            return Err(HarnessCompositionRequestError::SkillCapacity {
                actual: selected_skills.len(),
                maximum: MAX_HARNESS_SKILLS,
            });
        }
        Ok(Self {
            base_bundle_id,
            expected_base_revision,
            selected_skills,
            identity,
            observed_at,
        })
    }

    pub const fn base_bundle_id(&self) -> HarnessBundleId {
        self.base_bundle_id
    }

    pub const fn expected_base_revision(&self) -> HarnessRevision {
        self.expected_base_revision
    }

    pub fn selected_skills(&self) -> &[HarnessCompositionSkillSelection] {
        &self.selected_skills
    }

    pub const fn identity(&self) -> &HarnessCompositionIdentity {
        &self.identity
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HarnessCompositionRequestError {
    #[error("Harness composition selected {actual} Skills, exceeding the maximum {maximum}")]
    SkillCapacity { actual: usize, maximum: u16 },
}

#[derive(Debug)]
pub struct HarnessLibrary {
    catalog: HarnessCatalog,
    saved_harness_bundles_root: Option<PathBuf>,
}

impl HarnessLibrary {
    pub const fn new(catalog: HarnessCatalog) -> Self {
        Self {
            catalog,
            saved_harness_bundles_root: None,
        }
    }

    pub fn with_saved_harness_bundles_root(
        catalog: HarnessCatalog,
        saved_harness_bundles_root: PathBuf,
    ) -> Self {
        Self {
            catalog,
            saved_harness_bundles_root: Some(saved_harness_bundles_root),
        }
    }

    pub fn register_path(
        &mut self,
        source_root: &Path,
        observed_at: TimestampMillis,
    ) -> Result<HarnessCatalogEntry, HarnessLibraryError> {
        let inspected = inspect_harness_bundle(source_root)?;
        self.catalog
            .register(&inspected, observed_at)
            .map_err(HarnessLibraryError::from)
    }

    pub fn refresh_bundle(
        &mut self,
        id: HarnessBundleId,
        expected_revision: HarnessRevision,
        observed_at: TimestampMillis,
    ) -> Result<HarnessCatalogEntry, HarnessLibraryError> {
        let registered = self
            .catalog
            .get(id)?
            .ok_or(HarnessLibraryError::BundleNotFound(id))?;
        let inspected = inspect_harness_bundle(registered.source_root())?;
        if inspected.descriptor().id() != id {
            return Err(HarnessLibraryError::SourceIdentityMismatch);
        }
        self.catalog
            .refresh(&inspected, expected_revision, observed_at)
            .map_err(HarnessLibraryError::from)
    }

    pub fn get(
        &self,
        id: HarnessBundleId,
    ) -> Result<Option<HarnessCatalogEntry>, HarnessLibraryError> {
        self.catalog.get(id).map_err(HarnessLibraryError::from)
    }

    pub fn list(&self) -> Result<Vec<HarnessCatalogEntry>, HarnessLibraryError> {
        self.catalog
            .list(MAX_HARNESS_CATALOG_RESULTS)
            .map_err(HarnessLibraryError::from)
    }

    pub fn register_skill_path(
        &mut self,
        source_root: &Path,
        observed_at: TimestampMillis,
    ) -> Result<HarnessSkillCatalogEntry, HarnessLibraryError> {
        let id = HarnessSkillId::from_uuid(uuid::Uuid::now_v7());
        let inspected = inspect_harness_skill(source_root, id)?;
        self.catalog
            .register_skill(&inspected, observed_at)
            .map_err(HarnessLibraryError::from)
    }

    pub fn refresh_skill(
        &mut self,
        id: HarnessSkillId,
        expected_revision: HarnessSkillRevision,
        observed_at: TimestampMillis,
    ) -> Result<HarnessSkillCatalogEntry, HarnessLibraryError> {
        let registered = self
            .catalog
            .get_skill(id)?
            .ok_or(HarnessLibraryError::SkillNotFound(id))?;
        let inspected = inspect_harness_skill(registered.source_root(), id)?;
        self.catalog
            .refresh_skill(&inspected, expected_revision, observed_at)
            .map_err(HarnessLibraryError::from)
    }

    pub fn list_skills(&self) -> Result<Vec<HarnessSkillCatalogEntry>, HarnessLibraryError> {
        self.catalog
            .list_skills(MAX_HARNESS_CATALOG_RESULTS)
            .map_err(HarnessLibraryError::from)
    }

    /// Save a catalog-bound composition and register the resulting source as
    /// an ordinary Harness Bundle. Every catalog row and source is re-read
    /// before any destination filesystem effect is allowed.
    pub fn save_composition(
        &mut self,
        request: &HarnessCompositionRequest,
    ) -> Result<HarnessCatalogEntry, HarnessLibraryError> {
        let base_entry = self.catalog.get(request.base_bundle_id())?.ok_or(
            HarnessLibraryError::BundleNotFound(request.base_bundle_id()),
        )?;
        if base_entry.bundle().revision() != request.expected_base_revision() {
            return Err(HarnessLibraryError::CompositionStale);
        }
        let inspected_base = inspect_harness_bundle(base_entry.source_root())?;
        if inspected_base.descriptor() != base_entry.bundle().descriptor() {
            return Err(HarnessLibraryError::CompositionStale);
        }
        if self.catalog.get(request.base_bundle_id())?.as_ref() != Some(&base_entry) {
            return Err(HarnessLibraryError::CompositionStale);
        }

        let mut selected_skills = Vec::with_capacity(request.selected_skills().len());
        let mut selected_ids = BTreeSet::new();
        for selection in request.selected_skills() {
            if !selected_ids.insert(selection.id()) {
                return Err(HarnessLibraryError::DuplicateSkillSelection(selection.id()));
            }
            let entry = self
                .catalog
                .get_skill(selection.id())?
                .ok_or(HarnessLibraryError::SkillNotFound(selection.id()))?;
            if entry.skill().revision() != selection.expected_revision()
                || entry.skill().descriptor().content_hash() != selection.expected_content_hash()
            {
                return Err(HarnessLibraryError::CompositionStale);
            }
            let inspected = inspect_harness_skill(entry.source_root(), selection.id())?;
            if inspected.descriptor() != entry.skill().descriptor()
                || inspected.descriptor().content_hash() != selection.expected_content_hash()
            {
                return Err(HarnessLibraryError::CompositionStale);
            }
            if self.catalog.get_skill(selection.id())?.as_ref() != Some(&entry) {
                return Err(HarnessLibraryError::CompositionStale);
            }
            selected_skills.push(inspected);
        }

        if self.catalog.get(request.identity().id())?.is_some() {
            return Err(HarnessLibraryError::Catalog(
                HarnessCatalogError::BundleIdConflict(request.identity().id()),
            ));
        }

        let Some(destination_root) = self.saved_harness_bundles_root.as_deref() else {
            return Err(HarnessLibraryError::CompositionRootUnavailable);
        };
        ensure_saved_harness_bundles_root(destination_root)?;
        let saved = save_harness_composition(
            destination_root,
            request.identity(),
            &inspected_base,
            &selected_skills,
        )?;
        match self.catalog.register(&saved, request.observed_at()) {
            Ok(entry) => Ok(entry),
            Err(error) => {
                // The destination was created by this request and is not a
                // usable Library entry unless registration succeeds. Best
                // effort cleanup preserves that invariant without replacing
                // the original catalog failure with a misleading error.
                let _ignored = fs::remove_dir_all(saved.source_root());
                Err(HarnessLibraryError::Catalog(error))
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum HarnessLibraryError {
    #[error("Harness Bundle source inspection failed")]
    Inspection(#[from] HarnessBundleInspectionError),
    #[error("Harness Library persistence failed")]
    Catalog(#[from] HarnessCatalogError),
    #[error("Harness Bundle was not found: {0}")]
    BundleNotFound(HarnessBundleId),
    #[error("registered Harness source now declares a different Bundle identity")]
    SourceIdentityMismatch,
    #[error("Harness Skill source inspection failed")]
    SkillInspection(#[from] forge_workspace::HarnessSkillInspectionError),
    #[error("Harness Skill was not found: {0}")]
    SkillNotFound(HarnessSkillId),
    #[error("Harness composition request is stale")]
    CompositionStale,
    #[error("Harness composition request selected Skill more than once: {0}")]
    DuplicateSkillSelection(HarnessSkillId),
    #[error("Harness composition destination root is not configured")]
    CompositionRootUnavailable,
    #[error(transparent)]
    Composition(#[from] HarnessCompositionError),
}

fn ensure_saved_harness_bundles_root(path: &Path) -> Result<(), HarnessLibraryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(HarnessLibraryError::CompositionRootUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or(HarnessLibraryError::CompositionRootUnavailable)?;
            let parent_metadata = fs::symlink_metadata(parent)
                .map_err(HarnessCompositionError::Io)
                .map_err(HarnessLibraryError::Composition)?;
            if !parent_metadata.file_type().is_dir() {
                return Err(HarnessLibraryError::CompositionRootUnavailable);
            }
            fs::create_dir(path)
                .map_err(HarnessCompositionError::Io)
                .map_err(HarnessLibraryError::Composition)?;
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(HarnessCompositionError::Io)
                .map_err(HarnessLibraryError::Composition)?;
            Ok(())
        }
        Err(error) => Err(HarnessLibraryError::Composition(
            HarnessCompositionError::Io(error),
        )),
    }
}

impl ForgeControl {
    pub fn harness_get_applied(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<Option<AppliedHarness>, ControlError> {
        let (fresh_scope, store) = self.open_resolved_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(crate::ControlError::new(
                crate::ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let applied = store.get_applied_harness().map_err(map_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(crate::ControlError::new(
                crate::ControlErrorCode::WorkspaceRootConflict,
            ));
        }
        Ok(applied)
    }

    pub fn harness_verifier_get_latest(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<Option<HarnessVerifierRun>, ControlError> {
        let (fresh_scope, store) = self.open_harness_workspace(scope)?;
        let run = store
            .get_latest_harness_verifier_run()
            .map_err(map_harness_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(run)
    }

    pub fn harness_verifier_persist(
        &self,
        scope: &ResolvedWorkspaceScope,
        run: &HarnessVerifierRun,
        expected_revision: Option<HarnessVerifierRunRevision>,
    ) -> Result<HarnessVerifierRun, ControlError> {
        let (fresh_scope, mut store) = self.open_harness_workspace(scope)?;
        if run.workspace_id() != fresh_scope.workspace_id() {
            return Err(ControlError::new(ControlErrorCode::HarnessConflict));
        }
        let persisted = store
            .persist_harness_verifier_run(run, expected_revision)
            .map_err(map_harness_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::committed());
        }
        Ok(persisted)
    }

    pub fn harness_preview(
        &self,
        request: &HarnessPreviewRequest,
    ) -> Result<HarnessInstallPreview, ControlError> {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let inspected = inspect_harness_bundle(&request.source_root)
            .map_err(|error| ControlError::with_source(ControlErrorCode::HarnessConflict, error))?;
        if inspected.descriptor() != &request.expected_bundle {
            return Err(ControlError::new(ControlErrorCode::HarnessConflict));
        }
        let filesystem = ConfinedWorkspace::open(&layout)
            .map_err(|error| ControlError::with_source(ControlErrorCode::HarnessConflict, error))?;
        let preview =
            preview_harness_install(&filesystem, &inspected).map_err(map_harness_preview_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(preview)
    }

    pub fn harness_apply(
        &self,
        request: &HarnessApplyRequest,
    ) -> Result<AppliedHarness, ControlError> {
        let (fresh_scope, layout, mut store) = self.open_resolved_workspace_with_layout(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        self.ensure_non_overlapping_effect_scope(&fresh_scope, layout.workspace_root())?;
        let inspected = inspect_harness_bundle(&request.source_root)
            .map_err(|error| ControlError::with_source(ControlErrorCode::HarnessConflict, error))?;
        if inspected.descriptor() != request.expected_preview.descriptor() {
            return Err(ControlError::new(ControlErrorCode::HarnessConflict));
        }
        let current = store
            .get_applied_harness()
            .map_err(map_harness_store_error)?;
        if current
            .as_ref()
            .is_some_and(|applied| applied.bundle() != inspected.descriptor())
        {
            return Err(ControlError::new(ControlErrorCode::HarnessConflict));
        }
        let filesystem = ConfinedWorkspace::open(&layout)
            .map_err(|error| ControlError::with_source(ControlErrorCode::HarnessConflict, error))?;
        let _receipt =
            materialize_harness_install(&filesystem, &inspected, &request.expected_preview)
                .map_err(map_harness_materialization_error)?;
        if let Some(applied) = current.as_ref()
            && applied.bundle() == inspected.descriptor()
        {
            if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
                return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
            }
            return Ok(applied.clone());
        }
        let (next, expected_revision) = match current {
            Some(applied) => {
                let revision = applied.revision();
                let next = applied
                    .replace_bundle(
                        inspected.descriptor().clone(),
                        revision,
                        request.observed_at,
                    )
                    .map_err(map_harness_transition_error)?;
                (next, Some(revision))
            }
            None => (
                AppliedHarness::applied(
                    fresh_scope.workspace_id(),
                    inspected.descriptor().clone(),
                    request.observed_at,
                ),
                None,
            ),
        };
        let persisted = store
            .persist_applied_harness(&next, expected_revision)
            .map_err(map_harness_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::CommittedButUnconfirmed));
        }
        Ok(persisted)
    }

    pub fn harness_lifecycle_preview(
        &self,
        request: &HarnessLifecyclePreviewRequest,
    ) -> Result<HarnessLifecyclePreviewProjection, ControlError> {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let current = store
            .get_applied_harness()
            .map_err(map_harness_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::HarnessNotFound))?;
        let target = inspect_lifecycle_target(&request.target)?;
        let filesystem = ConfinedWorkspace::open(&layout)
            .map_err(|error| ControlError::with_source(ControlErrorCode::HarnessConflict, error))?;
        let preview = preview_harness_lifecycle(&filesystem, current.bundle(), target.as_ref())
            .map_err(map_harness_lifecycle_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(HarnessLifecyclePreviewProjection {
            preview,
            current_revision: current.revision(),
        })
    }

    pub fn harness_lifecycle_apply(
        &self,
        request: &HarnessLifecycleApplyRequest,
    ) -> Result<Option<AppliedHarness>, ControlError> {
        let (fresh_scope, layout, mut store) = self.open_resolved_workspace_with_layout(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        if fresh_scope != request.scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        self.ensure_non_overlapping_effect_scope(&fresh_scope, layout.workspace_root())?;
        let current = store
            .get_applied_harness()
            .map_err(map_harness_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::HarnessNotFound))?;
        if current.revision() != request.expected.current_revision()
            || current.bundle() != request.expected.preview().current_descriptor()
        {
            return Err(ControlError::new(ControlErrorCode::HarnessConflict));
        }
        let target = inspect_lifecycle_target(&request.target)?;
        let filesystem = ConfinedWorkspace::open(&layout)
            .map_err(|error| ControlError::with_source(ControlErrorCode::HarnessConflict, error))?;
        let _receipt = materialize_harness_lifecycle(
            &filesystem,
            current.bundle(),
            target.as_ref(),
            request.expected.preview(),
        )
        .map_err(map_harness_lifecycle_error)?;
        let revision = current.revision();
        let persisted = if let Some(target) = target {
            let next = current
                .replace_bundle(target.descriptor().clone(), revision, request.observed_at)
                .map_err(map_harness_transition_error)?;
            Some(
                store
                    .persist_applied_harness(&next, Some(revision))
                    .map_err(map_harness_store_error)?,
            )
        } else {
            store
                .delete_applied_harness(revision)
                .map_err(map_harness_store_error)?;
            None
        };
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::CommittedButUnconfirmed));
        }
        Ok(persisted)
    }

    pub fn harness_verify_source(
        &self,
        request: &HarnessVerifyRequest,
    ) -> Result<AppliedHarness, ControlError> {
        let (fresh_scope, mut store) = self.open_harness_workspace(&request.scope)?;
        let current = store
            .get_applied_harness()
            .map_err(map_harness_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::HarnessNotFound))?;
        let outcome = match inspect_harness_bundle(&request.source_root) {
            Ok(inspected) if inspected.descriptor() == current.bundle() => {
                HarnessVerificationOutcome::Ready
            }
            Ok(_) | Err(_) => HarnessVerificationOutcome::Failed,
        };
        let revision = current.revision();
        let verified = current
            .record_verification(outcome, revision, request.observed_at)
            .map_err(map_harness_transition_error)?;
        let persisted = store
            .persist_applied_harness(&verified, Some(revision))
            .map_err(map_harness_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::CommittedButUnconfirmed));
        }
        Ok(persisted)
    }

    fn open_harness_workspace(
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

fn inspect_lifecycle_target(
    target: &HarnessLifecycleTarget,
) -> Result<Option<InspectedHarnessBundle>, ControlError> {
    let HarnessLifecycleTarget::Bundle {
        source_root,
        expected_bundle,
    } = target
    else {
        return Ok(None);
    };
    let inspected = inspect_harness_bundle(source_root)
        .map_err(|error| ControlError::with_source(ControlErrorCode::HarnessConflict, error))?;
    if inspected.descriptor() != expected_bundle {
        return Err(ControlError::new(ControlErrorCode::HarnessConflict));
    }
    Ok(Some(inspected))
}

fn map_harness_transition_error(error: AppliedHarnessError) -> ControlError {
    ControlError::with_source(ControlErrorCode::HarnessConflict, error)
}

fn map_harness_store_error(error: forge_persistence::WorkspaceStoreError) -> ControlError {
    match &error {
        forge_persistence::WorkspaceStoreError::Harness(
            forge_persistence::HarnessStoreError::CompareAndSwapConflict
            | forge_persistence::HarnessStoreError::WorkspaceMismatch { .. },
        )
        | forge_persistence::WorkspaceStoreError::HarnessVerifier(
            forge_persistence::HarnessVerifierStoreError::CompareAndSwapConflict
            | forge_persistence::HarnessVerifierStoreError::WorkspaceMismatch { .. },
        ) => ControlError::with_source(ControlErrorCode::HarnessConflict, error),
        _ => map_store_error(error),
    }
}

fn map_harness_preview_error(error: HarnessPreviewError) -> ControlError {
    ControlError::with_source(ControlErrorCode::HarnessConflict, error)
}

fn map_harness_materialization_error(error: HarnessMaterializationError) -> ControlError {
    ControlError::with_source(ControlErrorCode::HarnessConflict, error)
}

fn map_harness_lifecycle_error(error: HarnessLifecycleError) -> ControlError {
    ControlError::with_source(ControlErrorCode::HarnessConflict, error)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        EstablishWorkspace, HarnessVerificationState, LocationId, LocationRevision, WorkspaceId,
        WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, HarnessCatalog, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct HarnessControlFixture {
        registry_path: PathBuf,
        root: PathBuf,
        scope: ResolvedWorkspaceScope,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn control_fixture(label: &str) -> Result<HarnessControlFixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-control-{label}-{}-{serial}",
            std::process::id()
        ));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace-0");
        fs::create_dir_all(&workspace_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::from_u128(0x4300 + u128::from(serial)));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Harness fixture",
            &location_root,
            timestamp(1)?,
        )?;
        drop(locations);
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let command = EstablishWorkspace::new(
            WorkspaceId::from_uuid(Uuid::from_u128(0x4400 + u128::from(serial))),
            location.id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(2)?,
        );
        drop(WorkspaceStore::open(&layout, &command)?);
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
        Ok(HarnessControlFixture {
            registry_path,
            root,
            scope,
        })
    }

    fn bundle_source() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-library-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("rules"))?;
        fs::write(root.join("rules/base.md"), b"# Rules\n")?;
        fs::write(
            root.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
            format!(
                "[harness]\nid = \"{}\"\nname = \"Rust Dev Harness\"\nversion = \"1.0.0\"\ninstall_root = \".agents/rust_dev_harness\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n",
                Uuid::from_u128(u128::from(serial) + 0x4100)
            ),
        )?;
        Ok(root)
    }

    fn skill_source() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-skill-library-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("references"))?;
        fs::write(root.join("SKILL.md"), b"# Optional Skill\n")?;
        fs::write(root.join("references/guide.md"), b"# Guide\n")?;
        Ok(root)
    }

    fn write_lifecycle_bundle(
        source: &std::path::Path,
        bundle_id: Uuid,
        version: &str,
        rules: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(source.join("rules"))?;
        fs::write(source.join("rules/base.md"), rules)?;
        fs::write(
            source.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
            format!(
                "[harness]\nid = \"{bundle_id}\"\nname = \"Lifecycle Harness\"\nversion = \"{version}\"\ninstall_root = \".agents/lifecycle_harness\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n"
            ),
        )?;
        Ok(())
    }

    #[test]
    fn workspace_harness_apply_verify_drift_and_restart_are_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = control_fixture("apply-verify")?;
        let source = fixture.root.join("bundle");
        fs::create_dir_all(source.join("rules"))?;
        fs::write(source.join("rules/base.md"), b"# Rules\n")?;
        fs::write(
            source.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
            format!(
                "[harness]\nid = \"{}\"\nname = \"Workspace Harness\"\nversion = \"1.0.0\"\ninstall_root = \".agents/workspace_harness\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n",
                Uuid::from_u128(0x4501)
            ),
        )?;
        let first_descriptor = inspect_harness_bundle(&source)?.descriptor().clone();
        let workspace_root = fixture.root.join("location/workspace-0");
        let (client, mut worker) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;
        let first_preview = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_bundle: first_descriptor.clone(),
        })?;
        assert_eq!(first_preview.creates(), 2);
        assert_eq!(first_preview.conflicts(), 0);
        let applied = client.harness_apply(HarnessApplyRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_preview: first_preview,
            observed_at: timestamp(10)?,
        })?;
        assert_eq!(applied.state(), HarnessVerificationState::Applied);
        assert_eq!(applied.revision().get(), 1);
        assert_eq!(
            fs::read(workspace_root.join(".agents/workspace_harness/rules/base.md"))?,
            b"# Rules\n"
        );
        assert!(
            workspace_root
                .join(forge_workspace::HARNESS_MANAGED_STATE_PATH)
                .is_file()
        );

        let retry_preview = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_bundle: first_descriptor,
        })?;
        assert_eq!(retry_preview.creates(), 0);
        assert_eq!(retry_preview.conflicts(), 0);
        let retry = client.harness_apply(HarnessApplyRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_preview: retry_preview.clone(),
            observed_at: timestamp(11)?,
        })?;
        assert_eq!(retry, applied);

        let ready = client.harness_verify_source(HarnessVerifyRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            observed_at: timestamp(12)?,
        })?;
        assert_eq!(ready.state(), HarnessVerificationState::Ready);
        assert_eq!(ready.revision().get(), 2);

        fs::write(source.join("rules/base.md"), b"# Drifted rules\n")?;
        let failed = client.harness_verify_source(HarnessVerifyRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            observed_at: timestamp(13)?,
        })?;
        assert_eq!(failed.state(), HarnessVerificationState::Failed);
        assert_eq!(failed.revision().get(), 3);

        let Err(stale_apply) = client.harness_apply(HarnessApplyRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_preview: retry_preview,
            observed_at: timestamp(14)?,
        }) else {
            return Err("source drift unexpectedly passed stale Harness Apply".into());
        };
        assert_eq!(stale_apply.code(), ControlErrorCode::HarnessConflict);
        assert_eq!(
            fs::read(workspace_root.join(".agents/workspace_harness/rules/base.md"))?,
            b"# Rules\n"
        );
        assert_eq!(
            client.harness_get_applied(fixture.scope.clone())?,
            Some(failed.clone())
        );

        worker.shutdown()?;
        let restarted = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?);
        assert_eq!(restarted.harness_get_applied(&fixture.scope)?, Some(failed));
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_harness_lifecycle_update_remove_is_revision_bound_and_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = control_fixture("lifecycle")?;
        let source = fixture.root.join("lifecycle-bundle");
        let bundle_id = Uuid::from_u128(0x4520);
        write_lifecycle_bundle(&source, bundle_id, "1.0.0", b"# Rules v1\n")?;
        let first = inspect_harness_bundle(&source)?.descriptor().clone();
        let (client, mut worker) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;
        let install_preview = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_bundle: first,
        })?;
        let applied = client.harness_apply(HarnessApplyRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_preview: install_preview,
            observed_at: timestamp(10)?,
        })?;
        assert_eq!(applied.revision().get(), 1);

        write_lifecycle_bundle(&source, bundle_id, "2.0.0", b"# Rules v2\n")?;
        let second = inspect_harness_bundle(&source)?.descriptor().clone();
        let target = HarnessLifecycleTarget::Bundle {
            source_root: source.clone(),
            expected_bundle: second.clone(),
        };
        let update_preview = client.harness_lifecycle_preview(HarnessLifecyclePreviewRequest {
            scope: fixture.scope.clone(),
            target: target.clone(),
        })?;
        assert_eq!(
            update_preview.preview().mode(),
            forge_workspace::HarnessLifecycleMode::Update
        );
        let updated = client
            .harness_lifecycle_apply(HarnessLifecycleApplyRequest {
                scope: fixture.scope.clone(),
                target,
                expected: update_preview,
                observed_at: timestamp(11)?,
            })?
            .ok_or("updated applied Harness missing")?;
        assert_eq!(updated.bundle(), &second);
        assert_eq!(updated.revision().get(), 2);

        let stale_remove = client.harness_lifecycle_preview(HarnessLifecyclePreviewRequest {
            scope: fixture.scope.clone(),
            target: HarnessLifecycleTarget::Remove,
        })?;
        let verified = client.harness_verify_source(HarnessVerifyRequest {
            scope: fixture.scope.clone(),
            source_root: source,
            observed_at: timestamp(12)?,
        })?;
        assert_eq!(verified.revision().get(), 3);
        let Err(stale_error) = client.harness_lifecycle_apply(HarnessLifecycleApplyRequest {
            scope: fixture.scope.clone(),
            target: HarnessLifecycleTarget::Remove,
            expected: stale_remove,
            observed_at: timestamp(13)?,
        }) else {
            return Err("stale lifecycle Preview unexpectedly removed Harness".into());
        };
        assert_eq!(stale_error.code(), ControlErrorCode::HarnessConflict);

        let remove_preview = client.harness_lifecycle_preview(HarnessLifecyclePreviewRequest {
            scope: fixture.scope.clone(),
            target: HarnessLifecycleTarget::Remove,
        })?;
        assert!(
            client
                .harness_lifecycle_apply(HarnessLifecycleApplyRequest {
                    scope: fixture.scope.clone(),
                    target: HarnessLifecycleTarget::Remove,
                    expected: remove_preview,
                    observed_at: timestamp(14)?,
                })?
                .is_none()
        );
        assert_eq!(client.harness_get_applied(fixture.scope.clone())?, None);
        let workspace_root = fixture.root.join("location/workspace-0");
        assert!(
            !workspace_root
                .join(forge_workspace::HARNESS_MANAGED_STATE_PATH)
                .exists()
        );
        assert!(
            !workspace_root
                .join(".agents/lifecycle_harness/rules/base.md")
                .exists()
        );

        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_harness_preview_is_worker_routed_read_only_and_drift_guarded()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = control_fixture("preview")?;
        let source = fixture.root.join("preview-bundle");
        fs::create_dir_all(source.join("rules"))?;
        fs::write(source.join("rules/base.md"), b"# Rules\n")?;
        fs::write(source.join("AGENTS.md.template"), b"Read managed rules.\n")?;
        fs::write(
            source.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
            format!(
                "[harness]\nid = \"{}\"\nname = \"Preview Harness\"\nversion = \"1.0.0\"\ninstall_root = \".agents/preview_harness\"\nagents_template = \"AGENTS.md.template\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n",
                Uuid::from_u128(0x4502)
            ),
        )?;
        let descriptor = inspect_harness_bundle(&source)?.descriptor().clone();
        let workspace_root = fixture.root.join("location/workspace-0");
        let (client, mut worker) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;

        let first = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_bundle: descriptor.clone(),
        })?;
        assert_eq!(first.creates(), 3);
        assert_eq!(first.unchanged(), 0);
        assert_eq!(first.conflicts(), 0);
        assert!(!workspace_root.join(".agents/preview_harness").exists());
        assert!(!workspace_root.join("AGENTS.md").exists());

        fs::write(
            workspace_root.join("AGENTS.md"),
            b"User-owned instructions.\n",
        )?;
        let conflicted = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: source.clone(),
            expected_bundle: descriptor.clone(),
        })?;
        assert_eq!(conflicted.creates(), 2);
        assert_eq!(conflicted.conflicts(), 0);
        assert!(conflicted.can_apply_with_agents_merge());
        assert_eq!(
            conflicted
                .items()
                .iter()
                .find(|item| item.kind() == forge_workspace::HarnessPreviewKind::AgentsFile)
                .map(forge_workspace::HarnessPreviewItem::disposition),
            Some(forge_workspace::HarnessPreviewDisposition::Merge)
        );
        assert_eq!(
            fs::read(workspace_root.join("AGENTS.md"))?,
            b"User-owned instructions.\n"
        );

        fs::write(source.join("rules/base.md"), b"# Drifted rules\n")?;
        let Err(error) = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope,
            source_root: source,
            expected_bundle: descriptor,
        }) else {
            return Err("source drift unexpectedly passed Preview".into());
        };
        assert_eq!(error.code(), ControlErrorCode::HarnessConflict);

        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn regular_apply_cannot_switch_durable_harness_after_marker_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = control_fixture("switch-guard")?;
        let workspace_root = fixture.root.join("location/workspace-0");
        let first_source = fixture.root.join("first-bundle");
        let second_source = fixture.root.join("second-bundle");
        for (source, id, install_root) in [
            (&first_source, 0x4510_u128, ".agents/first_harness"),
            (&second_source, 0x4511_u128, ".agents/second_harness"),
        ] {
            fs::create_dir_all(source.join("rules"))?;
            fs::write(source.join("rules/base.md"), b"# Rules\n")?;
            fs::write(
                source.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
                format!(
                    "[harness]\nid = \"{}\"\nname = \"Switch Guard Harness\"\nversion = \"1.0.0\"\ninstall_root = \"{install_root}\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n",
                    Uuid::from_u128(id)
                ),
            )?;
        }
        let first_descriptor = inspect_harness_bundle(&first_source)?.descriptor().clone();
        let second_descriptor = inspect_harness_bundle(&second_source)?.descriptor().clone();
        let (client, mut worker) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;
        let first_preview = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: first_source.clone(),
            expected_bundle: first_descriptor,
        })?;
        let applied = client.harness_apply(HarnessApplyRequest {
            scope: fixture.scope.clone(),
            source_root: first_source,
            expected_preview: first_preview,
            observed_at: timestamp(10)?,
        })?;
        fs::remove_file(workspace_root.join(forge_workspace::HARNESS_MANAGED_STATE_PATH))?;

        let second_preview = client.harness_preview(HarnessPreviewRequest {
            scope: fixture.scope.clone(),
            source_root: second_source.clone(),
            expected_bundle: second_descriptor,
        })?;
        assert!(second_preview.can_apply_without_merge());
        let Err(error) = client.harness_apply(HarnessApplyRequest {
            scope: fixture.scope.clone(),
            source_root: second_source,
            expected_preview: second_preview,
            observed_at: timestamp(11)?,
        }) else {
            return Err("regular Apply unexpectedly switched durable Harness".into());
        };
        assert_eq!(error.code(), ControlErrorCode::HarnessConflict);
        assert!(
            !workspace_root
                .join(".agents/second_harness/rules/base.md")
                .exists()
        );
        assert_eq!(
            client.harness_get_applied(fixture.scope.clone())?,
            Some(applied)
        );

        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn library_registers_lists_and_refreshes_local_bundle_without_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = bundle_source()?;
        let database = source
            .parent()
            .ok_or("fixture parent missing")?
            .join(format!(
                "harness-library-{}-{}.sqlite3",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        let mut library = HarnessLibrary::new(HarnessCatalog::open(&database)?);
        let first = library.register_path(&source, TimestampMillis::new(10)?)?;
        assert_eq!(library.list()?, vec![first.clone()]);
        fs::write(source.join("rules/base.md"), b"# Updated rules\n")?;
        let refreshed = library.refresh_bundle(
            first.bundle().descriptor().id(),
            first.bundle().revision(),
            TimestampMillis::new(11)?,
        )?;
        assert_eq!(refreshed.bundle().revision().get(), 2);
        assert_ne!(
            refreshed.bundle().descriptor().content_hash(),
            first.bundle().descriptor().content_hash()
        );
        drop(library);
        fs::remove_dir_all(source)?;
        fs::remove_file(database)?;
        Ok(())
    }

    struct CompositionLibraryFixture {
        base_source: PathBuf,
        skill_source: PathBuf,
        database: PathBuf,
        saved_root: PathBuf,
        library: HarnessLibrary,
        base: HarnessCatalogEntry,
        skill: HarnessSkillCatalogEntry,
    }

    impl CompositionLibraryFixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let base_source = bundle_source()?;
            let skill_source = skill_source()?;
            let temp_dir = std::env::temp_dir();
            let database = temp_dir.join(format!(
                "composition-catalog-{}-{}.sqlite3",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let saved_root = temp_dir.join(format!(
                "heterarchy-forge-saved-composition-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut library = HarnessLibrary::with_saved_harness_bundles_root(
                HarnessCatalog::open(&database)?,
                saved_root.clone(),
            );
            let base = library.register_path(&base_source, TimestampMillis::new(10)?)?;
            let skill = library.register_skill_path(&skill_source, TimestampMillis::new(10)?)?;
            Ok(Self {
                base_source,
                skill_source,
                database,
                saved_root,
                library,
                base,
                skill,
            })
        }

        fn request(
            &self,
            id: u128,
            name: &str,
            observed_at: i64,
        ) -> Result<HarnessCompositionRequest, Box<dyn std::error::Error>> {
            Ok(HarnessCompositionRequest::new(
                self.base.bundle().descriptor().id(),
                self.base.bundle().revision(),
                vec![HarnessCompositionSkillSelection::new(
                    self.skill.skill().descriptor().id(),
                    self.skill.skill().revision(),
                    self.skill.skill().descriptor().content_hash(),
                )],
                HarnessCompositionIdentity::new(
                    HarnessBundleId::from_uuid(Uuid::from_u128(id)),
                    forge_domain::HarnessName::new(name.to_owned())?,
                    forge_domain::HarnessVersion::new("1.0.0".to_owned())?,
                ),
                TimestampMillis::new(observed_at)?,
            )?)
        }

        fn cleanup(self) -> Result<(), Box<dyn std::error::Error>> {
            let Self {
                base_source,
                skill_source,
                database,
                saved_root,
                library,
                ..
            } = self;
            drop(library);
            fs::remove_dir_all(base_source)?;
            fs::remove_dir_all(skill_source)?;
            if saved_root.exists() {
                fs::remove_dir_all(saved_root)?;
            }
            fs::remove_file(database)?;
            Ok(())
        }
    }

    #[test]
    fn library_saves_and_registers_catalog_bound_composition()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = CompositionLibraryFixture::new()?;
        let request = fixture.request(0x4650, "Saved Composition", 11)?;
        let identity = request.identity().clone();
        let saved = fixture.library.save_composition(&request)?;
        assert_eq!(saved.bundle().descriptor().id(), identity.id());
        assert_eq!(fixture.library.get(identity.id())?, Some(saved.clone()));
        assert!(
            saved
                .source_root()
                .starts_with(fs::canonicalize(&fixture.saved_root)?)
        );
        assert_eq!(
            fs::read(
                saved
                    .source_root()
                    .join("skills")
                    .join(fixture.skill.skill().descriptor().name().as_str())
                    .join("SKILL.md")
            )?,
            b"# Optional Skill\n"
        );
        fixture.cleanup()?;
        Ok(())
    }

    #[test]
    fn composition_request_rejects_oversized_skill_selection_at_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = CompositionLibraryFixture::new()?;
        let request = fixture.request(0x4652, "Oversized Selection", 11)?;
        let oversized_request = HarnessCompositionRequest::new(
            fixture.base.bundle().descriptor().id(),
            fixture.base.bundle().revision(),
            vec![request.selected_skills()[0]; usize::from(forge_domain::MAX_HARNESS_SKILLS) + 1],
            request.identity().clone(),
            TimestampMillis::new(11)?,
        );
        assert!(matches!(
            oversized_request,
            Err(HarnessCompositionRequestError::SkillCapacity { .. })
        ));
        assert!(
            !fixture
                .saved_root
                .join(request.identity().id().to_string())
                .exists()
        );
        fixture.cleanup()?;
        Ok(())
    }

    #[test]
    fn library_fences_skill_source_drift_before_composition_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = CompositionLibraryFixture::new()?;
        let stale_request = fixture.request(0x4651, "Stale Composition", 12)?;
        fs::write(
            fixture.skill_source.join("references/guide.md"),
            b"# Drifted\n",
        )?;
        assert!(matches!(
            fixture.library.save_composition(&stale_request),
            Err(HarnessLibraryError::CompositionStale)
        ));
        assert!(
            !fixture
                .saved_root
                .join(stale_request.identity().id().to_string())
                .exists()
        );
        assert!(
            !fixture
                .saved_root
                .join(format!("{}{}", stale_request.identity().id(), ".staging"))
                .exists()
        );
        fixture.cleanup()?;
        Ok(())
    }
}
