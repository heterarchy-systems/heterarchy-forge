//! Read-only Workspace Doctor composition.
//!
//! Persistence owns `SQLite` consistency observations. Control owns the exact
//! Location/Workspace scope and revalidates the Workspace root around that
//! observation. This module never opens a write store or reconciles state.

mod checkpoint_store;
mod workspace_identity;

use checkpoint_store::observe_checkpoint_store;
pub use checkpoint_store::{
    WorkspaceCheckpointStoreAvailability, WorkspaceCheckpointStoreFinding,
    WorkspaceCheckpointStoreReport, WorkspaceCheckpointStoreStatus,
};
pub use workspace_identity::{
    WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS, WorkspaceIdentityDoctorOutcome,
    WorkspaceIdentityDoctorReport, WorkspaceIdentityDuplicateFinding,
    WorkspaceLocationMismatchFinding,
};

use std::collections::{BTreeMap, BTreeSet};

use forge_domain::{
    DiffArtifactHealth, DiffArtifactInvalidInventoryEntry, DiffArtifactInvalidReason,
    DiffArtifactInventoryEntry, DiffArtifactInventoryLimit, DiffEvidenceState, DiffId,
};
use forge_persistence::{
    DiffDoctorArtifactReference, DiffDoctorLifecycle, DiffDoctorReference, WorkspaceDoctorReport,
    WorkspaceStore,
};
use forge_workspace::{
    ConfinedWorkspace, DiffArtifactExpectation, DiffArtifactStore, GitLocalStateDoctor,
    WorkspaceStateLayout,
};

use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::{map_diff_artifact_error, map_filesystem_error};
use crate::service::{
    ForgeControl, ResolvedWorkspaceScope, map_location_error, map_state_layout_error,
    map_store_error,
};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDoctorRequest {
    pub scope: ResolvedWorkspaceScope,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDoctorResult {
    scope: ResolvedWorkspaceScope,
    report: WorkspaceDoctorReport,
    git_local_state: GitLocalStateDoctor,
    checkpoint_store: WorkspaceCheckpointStoreReport,
    diff_artifacts: WorkspaceDiffArtifactDoctorReport,
    observation_consistency: WorkspaceDoctorObservationConsistency,
    outcome: WorkspaceDoctorAggregateOutcome,
}

impl WorkspaceDoctorResult {
    fn new(
        scope: ResolvedWorkspaceScope,
        report: WorkspaceDoctorReport,
        git_local_state: GitLocalStateDoctor,
        checkpoint_store: WorkspaceCheckpointStoreReport,
        diff_artifacts: WorkspaceDiffArtifactDoctorReport,
        observation_consistency: WorkspaceDoctorObservationConsistency,
    ) -> Self {
        let outcome = aggregate_outcome(
            &report,
            git_local_state,
            &checkpoint_store,
            &diff_artifacts,
            observation_consistency,
        );
        Self {
            scope,
            report,
            git_local_state,
            checkpoint_store,
            diff_artifacts,
            observation_consistency,
            outcome,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn report(&self) -> &WorkspaceDoctorReport {
        &self.report
    }

    pub const fn git_local_state(&self) -> GitLocalStateDoctor {
        self.git_local_state
    }

    pub const fn checkpoint_store(&self) -> &WorkspaceCheckpointStoreReport {
        &self.checkpoint_store
    }

    pub const fn diff_artifacts(&self) -> &WorkspaceDiffArtifactDoctorReport {
        &self.diff_artifacts
    }

    pub const fn outcome(&self) -> WorkspaceDoctorAggregateOutcome {
        self.outcome
    }

    pub const fn observation_consistency(&self) -> WorkspaceDoctorObservationConsistency {
        self.observation_consistency
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDoctorAggregateOutcome {
    Healthy,
    RecoveryRequired,
    Damaged,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDoctorObservationConsistency {
    Stable,
    Changed,
}

const MAX_WORKSPACE_DIFF_FINDINGS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkspaceDiffArtifactStatus {
    OwnedAvailable,
    DatabaseMissing,
    Corrupt,
    InvalidSymlink,
    InvalidNonRegular,
    InvalidHardlink,
    Orphan,
    Conflicting,
    Pending,
    NotApplicable,
    Unverified,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceDiffArtifactFinding {
    diff_id: Option<DiffId>,
    status: WorkspaceDiffArtifactStatus,
}

impl WorkspaceDiffArtifactFinding {
    const fn new(diff_id: Option<DiffId>, status: WorkspaceDiffArtifactStatus) -> Self {
        Self { diff_id, status }
    }

    pub const fn diff_id(self) -> Option<DiffId> {
        self.diff_id
    }

    pub const fn status(self) -> WorkspaceDiffArtifactStatus {
        self.status
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDiffArtifactDoctorReport {
    findings: Vec<WorkspaceDiffArtifactFinding>,
    database_truncated: bool,
    filesystem_truncated: bool,
    findings_truncated: bool,
}

impl WorkspaceDiffArtifactDoctorReport {
    pub fn findings(&self) -> &[WorkspaceDiffArtifactFinding] {
        &self.findings
    }

    pub const fn database_truncated(&self) -> bool {
        self.database_truncated
    }

    pub const fn filesystem_truncated(&self) -> bool {
        self.filesystem_truncated
    }

    pub const fn findings_truncated(&self) -> bool {
        self.findings_truncated
    }

    pub const fn is_complete(&self) -> bool {
        !self.database_truncated && !self.filesystem_truncated && !self.findings_truncated
    }
}

fn doctor_observation_consistency(
    database_unchanged: bool,
    git_before: GitLocalStateDoctor,
    git_after: GitLocalStateDoctor,
    checkpoint_unchanged: bool,
    diff_inventory_unchanged: bool,
) -> WorkspaceDoctorObservationConsistency {
    if database_unchanged
        && git_before == git_after
        && checkpoint_unchanged
        && diff_inventory_unchanged
    {
        WorkspaceDoctorObservationConsistency::Stable
    } else {
        WorkspaceDoctorObservationConsistency::Changed
    }
}

fn aggregate_outcome(
    report: &WorkspaceDoctorReport,
    git: GitLocalStateDoctor,
    checkpoints: &WorkspaceCheckpointStoreReport,
    diffs: &WorkspaceDiffArtifactDoctorReport,
    observation_consistency: WorkspaceDoctorObservationConsistency,
) -> WorkspaceDoctorAggregateOutcome {
    if observation_consistency == WorkspaceDoctorObservationConsistency::Changed {
        return WorkspaceDoctorAggregateOutcome::Incomplete;
    }
    if report.is_damaged() {
        return WorkspaceDoctorAggregateOutcome::Damaged;
    }

    let git_damaged = matches!(
        git,
        GitLocalStateDoctor::MissingLocalExclude
            | GitLocalStateDoctor::TrackedStateConflict
            | GitLocalStateDoctor::StateVisibleToGit
    );
    let diff_damaged = diffs.findings().iter().any(|finding| {
        matches!(
            finding.status(),
            WorkspaceDiffArtifactStatus::DatabaseMissing
                | WorkspaceDiffArtifactStatus::Corrupt
                | WorkspaceDiffArtifactStatus::InvalidSymlink
                | WorkspaceDiffArtifactStatus::InvalidNonRegular
                | WorkspaceDiffArtifactStatus::InvalidHardlink
                | WorkspaceDiffArtifactStatus::Conflicting
        )
    });
    let checkpoint_damaged = checkpoints.findings().iter().any(|finding| {
        matches!(
            finding.status(),
            WorkspaceCheckpointStoreStatus::RefMissing
                | WorkspaceCheckpointStoreStatus::RefMismatch
                | WorkspaceCheckpointStoreStatus::ObjectMissing
                | WorkspaceCheckpointStoreStatus::ObjectTypeMismatch
                | WorkspaceCheckpointStoreStatus::Conflicting
                | WorkspaceCheckpointStoreStatus::Corrupt
                | WorkspaceCheckpointStoreStatus::StoreMissing
        )
    });
    if git_damaged || diff_damaged || checkpoint_damaged {
        return WorkspaceDoctorAggregateOutcome::Damaged;
    }

    let diff_recovery = diffs.findings().iter().any(|finding| {
        matches!(
            finding.status(),
            WorkspaceDiffArtifactStatus::Orphan | WorkspaceDiffArtifactStatus::Pending
        )
    });
    let checkpoint_recovery = checkpoints.findings().iter().any(|finding| {
        matches!(
            finding.status(),
            WorkspaceCheckpointStoreStatus::Starting | WorkspaceCheckpointStoreStatus::OrphanRef
        )
    });
    if report.requires_recovery() || diff_recovery || checkpoint_recovery {
        return WorkspaceDoctorAggregateOutcome::RecoveryRequired;
    }

    if matches!(git, GitLocalStateDoctor::Unavailable)
        || !report.dag_semantics().is_complete()
        || !checkpoints.is_complete()
        || checkpoints
            .findings()
            .iter()
            .any(|finding| finding.status() == WorkspaceCheckpointStoreStatus::Unverified)
        || !diffs.is_complete()
        || diffs
            .findings()
            .iter()
            .any(|finding| finding.status() == WorkspaceDiffArtifactStatus::Unverified)
    {
        return WorkspaceDoctorAggregateOutcome::Incomplete;
    }
    WorkspaceDoctorAggregateOutcome::Healthy
}

impl ForgeControl {
    /// Observe one exact Workspace without migration, reconciliation, or
    /// filesystem/database mutation.
    pub fn workspace_doctor(
        &self,
        request: &WorkspaceDoctorRequest,
    ) -> Result<WorkspaceDoctorResult, ControlError> {
        let expected = &request.scope;
        let locator = expected.locator();
        let candidate = self
            .locations
            .resolve_locator_current(locator)
            .map_err(map_location_error)?;
        let layout = WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
            .map_err(map_state_layout_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::WorkspaceNotInitialized))?;
        let root_before = layout.root_fingerprint().map_err(map_state_layout_error)?;
        let (report, database_source) =
            WorkspaceStore::doctor_existing_read_only_observed(&layout).map_err(map_store_error)?;
        let git_local_state = layout
            .inspect_git_local_state_read_only()
            .map_err(map_state_layout_error)?;
        let checkpoint_observation =
            observe_checkpoint_store(report.checkpoint_references(), git_local_state, &layout)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let inventory = artifacts
            .inventory(DiffArtifactInventoryLimit::DEFAULT)
            .map_err(map_diff_artifact_error)?;
        let diff_artifacts = compose_diff_artifact_report(
            report.diff_references(),
            &artifacts,
            inventory.entries(),
            inventory.invalid_entries(),
            inventory.truncated(),
        )?;

        // Cross-authority observation is intentionally not one transaction:
        // never hold SQLite state across Git/filesystem processes. Instead,
        // revalidate the exact bounded sources that produced the first pass.
        let git_local_state_after = layout
            .inspect_git_local_state_read_only()
            .map_err(map_state_layout_error)?;
        let checkpoint_unchanged =
            checkpoint_observation.source_is_unchanged(report.checkpoint_references(), &layout);
        let diff_inventory_unchanged = matches!(
            artifacts.inventory(DiffArtifactInventoryLimit::DEFAULT),
            Ok(current) if current == inventory
        );
        let observation_consistency = doctor_observation_consistency(
            database_source.is_unchanged(&layout),
            git_local_state,
            git_local_state_after,
            checkpoint_unchanged,
            diff_inventory_unchanged,
        );
        let checkpoint_store = checkpoint_observation.into_report();

        if report.location_id() != locator.location_id()
            || report.workspace_id() != expected.workspace_id()
            || report.workspace_revision() != expected.workspace_revision()
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }

        let candidate_after = self
            .locations
            .resolve_locator_current(locator)
            .map_err(map_location_error)?;
        let layout_after = WorkspaceStateLayout::inspect_existing(candidate_after.absolute_root())
            .map_err(map_state_layout_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::WorkspaceNotInitialized))?;
        let root_after = layout_after
            .root_fingerprint()
            .map_err(map_state_layout_error)?;
        if candidate_after.absolute_root() != candidate.absolute_root() || root_after != root_before
        {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }

        Ok(WorkspaceDoctorResult::new(
            expected.clone(),
            report,
            git_local_state,
            checkpoint_store,
            diff_artifacts,
            observation_consistency,
        ))
    }
}

fn compose_diff_artifact_report(
    database: &forge_persistence::DiffDoctorReport,
    artifacts: &DiffArtifactStore,
    inventory: &[DiffArtifactInventoryEntry],
    invalid_inventory: &[DiffArtifactInvalidInventoryEntry],
    filesystem_truncated: bool,
) -> Result<WorkspaceDiffArtifactDoctorReport, ControlError> {
    let database_by_id = database
        .references()
        .iter()
        .map(|reference| (reference.diff_id(), reference))
        .collect::<BTreeMap<_, _>>();
    let mut inventory_names_by_id = BTreeMap::<DiffId, Vec<_>>::new();
    for entry in inventory {
        if let Some(id) = entry.diff_id() {
            inventory_names_by_id
                .entry(id)
                .or_default()
                .push(entry.name().clone());
        }
    }
    let mut matched_names = BTreeSet::new();
    let mut findings = Vec::with_capacity(
        database
            .references()
            .len()
            .saturating_add(inventory.len())
            .saturating_add(invalid_inventory.len()),
    );

    for reference in database.references() {
        findings.push(WorkspaceDiffArtifactFinding::new(
            Some(reference.diff_id()),
            classify_database_reference(
                reference,
                artifacts,
                &inventory_names_by_id,
                &mut matched_names,
            )?,
        ));
    }
    for entry in inventory {
        if matched_names.contains(entry.name()) {
            continue;
        }
        let status = match entry.diff_id() {
            Some(id) if database_by_id.contains_key(&id) => {
                WorkspaceDiffArtifactStatus::Conflicting
            }
            Some(_) if database.truncated() => WorkspaceDiffArtifactStatus::Unverified,
            Some(_) | None => WorkspaceDiffArtifactStatus::Orphan,
        };
        findings.push(WorkspaceDiffArtifactFinding::new(entry.diff_id(), status));
    }
    for entry in invalid_inventory {
        let status = match entry.reason() {
            DiffArtifactInvalidReason::Symlink => WorkspaceDiffArtifactStatus::InvalidSymlink,
            DiffArtifactInvalidReason::NonRegular => WorkspaceDiffArtifactStatus::InvalidNonRegular,
            DiffArtifactInvalidReason::Hardlink => WorkspaceDiffArtifactStatus::InvalidHardlink,
        };
        findings.push(WorkspaceDiffArtifactFinding::new(entry.diff_id(), status));
    }

    findings.sort_by_key(|finding| (finding.diff_id(), finding.status()));
    let findings_truncated = findings.len() > MAX_WORKSPACE_DIFF_FINDINGS;
    findings.truncate(MAX_WORKSPACE_DIFF_FINDINGS);
    Ok(WorkspaceDiffArtifactDoctorReport {
        findings,
        database_truncated: database.truncated(),
        filesystem_truncated,
        findings_truncated,
    })
}

fn classify_database_reference(
    reference: &DiffDoctorReference,
    artifacts: &DiffArtifactStore,
    inventory_names_by_id: &BTreeMap<DiffId, Vec<forge_domain::DiffArtifactInventoryName>>,
    matched_names: &mut BTreeSet<forge_domain::DiffArtifactInventoryName>,
) -> Result<WorkspaceDiffArtifactStatus, ControlError> {
    let id = reference.diff_id();
    let same_id_names: &[forge_domain::DiffArtifactInventoryName] =
        inventory_names_by_id.get(&id).map_or(&[], Vec::as_slice);
    match reference.lifecycle() {
        DiffDoctorLifecycle::Legacy { .. } => {
            if same_id_names.is_empty() {
                Ok(WorkspaceDiffArtifactStatus::NotApplicable)
            } else {
                matched_names.extend(same_id_names.iter().cloned());
                Ok(WorkspaceDiffArtifactStatus::Conflicting)
            }
        }
        DiffDoctorLifecycle::Evidence { state, .. } => match state {
            DiffEvidenceState::Intent => classify_intent(reference, artifacts, matched_names),
            DiffEvidenceState::Ready => classify_final(
                id,
                reference.final_artifact(),
                artifacts,
                matched_names,
                false,
            ),
            DiffEvidenceState::PurgePending => classify_final(
                id,
                reference.final_artifact(),
                artifacts,
                matched_names,
                true,
            ),
            DiffEvidenceState::SummaryOnly
            | DiffEvidenceState::Abandoned
            | DiffEvidenceState::Tombstoned => {
                if same_id_names.is_empty() {
                    Ok(WorkspaceDiffArtifactStatus::NotApplicable)
                } else {
                    matched_names.extend(same_id_names.iter().cloned());
                    Ok(WorkspaceDiffArtifactStatus::Conflicting)
                }
            }
        },
    }
}

fn classify_intent(
    reference: &DiffDoctorReference,
    artifacts: &DiffArtifactStore,
    matched_names: &mut BTreeSet<forge_domain::DiffArtifactInventoryName>,
) -> Result<WorkspaceDiffArtifactStatus, ControlError> {
    let (Some(pending), Some(final_artifact)) =
        (reference.pending_artifact(), reference.final_artifact())
    else {
        return Ok(WorkspaceDiffArtifactStatus::NotApplicable);
    };
    matched_names.insert(pending.name().clone());
    matched_names.insert(final_artifact.name().clone());
    let pending_health = artifacts
        .doctor_pending(&artifact_expectation(reference.diff_id(), pending))
        .map_err(map_diff_artifact_error)?;
    let final_health = artifacts
        .doctor(&artifact_expectation(reference.diff_id(), final_artifact))
        .map_err(map_diff_artifact_error)?;
    Ok(match (pending_health, final_health) {
        (DiffArtifactHealth::Corrupt, _) | (_, DiffArtifactHealth::Corrupt) => {
            WorkspaceDiffArtifactStatus::Corrupt
        }
        (DiffArtifactHealth::Available, DiffArtifactHealth::Available) => {
            WorkspaceDiffArtifactStatus::Conflicting
        }
        (DiffArtifactHealth::Available, DiffArtifactHealth::Missing)
        | (DiffArtifactHealth::Missing, DiffArtifactHealth::Available) => {
            WorkspaceDiffArtifactStatus::Pending
        }
        (DiffArtifactHealth::Missing, DiffArtifactHealth::Missing) => {
            WorkspaceDiffArtifactStatus::DatabaseMissing
        }
        _ => WorkspaceDiffArtifactStatus::Conflicting,
    })
}

fn classify_final(
    id: DiffId,
    reference: Option<&DiffDoctorArtifactReference>,
    artifacts: &DiffArtifactStore,
    matched_names: &mut BTreeSet<forge_domain::DiffArtifactInventoryName>,
    purge_pending: bool,
) -> Result<WorkspaceDiffArtifactStatus, ControlError> {
    let Some(reference) = reference else {
        return Ok(WorkspaceDiffArtifactStatus::Conflicting);
    };
    matched_names.insert(reference.name().clone());
    let health = artifacts
        .doctor(&artifact_expectation(id, reference))
        .map_err(map_diff_artifact_error)?;
    Ok(match (health, purge_pending) {
        (DiffArtifactHealth::Available, false) => WorkspaceDiffArtifactStatus::OwnedAvailable,
        (DiffArtifactHealth::Missing, false) => WorkspaceDiffArtifactStatus::DatabaseMissing,
        (DiffArtifactHealth::Available | DiffArtifactHealth::Missing, true) => {
            WorkspaceDiffArtifactStatus::Pending
        }
        (DiffArtifactHealth::Corrupt, _) => WorkspaceDiffArtifactStatus::Corrupt,
        _ => WorkspaceDiffArtifactStatus::Conflicting,
    })
}

const fn artifact_expectation(
    id: DiffId,
    reference: &DiffDoctorArtifactReference,
) -> DiffArtifactExpectation {
    DiffArtifactExpectation::new(
        id,
        reference.compressed_hash(),
        reference.uncompressed_hash(),
        reference.compressed_size(),
        reference.uncompressed_size(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        ChangeSetId, CheckpointId, DagAcceptanceCriterion, DagNodeDefinition, DagNodeId,
        DagNodeObjective, DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId,
        DagRevisionNumber, DiffId, EstablishWorkspace, FileMutationId, FileMutationKind,
        FileMutationPlan, FilePrecondition, GoalContract, GoalId, GoalObjective, GoalStatement,
        LocationId, LocationRevision, RegisteredCheckpoint, RegisteredDagNode, RegisteredGoal,
        RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRelativePath, WorkspaceRevision,
        WorkspaceRoot,
    };
    use forge_persistence::{DAG_DOCTOR_MAX_CURRENT_DAGS, GlobalRegistry};
    use forge_workspace::{
        CheckpointSide, ExistingWorkspaceStateLayout, GitCheckpointRefInventoryLimit,
        GitCheckpointStore, GitCheckpointStoreIntegrity, LocationService, WorkspaceStateLayout,
    };
    use uuid::Uuid;

    use super::*;
    use crate::filesystem::{FileActivityScope, FileMutationRequest, FileMutationStatus};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: std::path::PathBuf,
        workspace_root: std::path::PathBuf,
        control: ForgeControl,
        scope: ResolvedWorkspaceScope,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-doctor-{label}-{}-{serial}",
            std::process::id()
        ));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace-0");
        fs::create_dir_all(&workspace_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xD000 + u128::from(serial)));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Doctor fixture",
            &location_root,
            timestamp(1)?,
        )?;
        drop(locations);
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let command = EstablishWorkspace::new(
            WorkspaceId::from_uuid(Uuid::from_u128(0xE000 + u128::from(serial))),
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
        Ok(Fixture {
            root,
            workspace_root,
            control,
            scope,
        })
    }

    fn initialize_git_fixture(
        fixture: &Fixture,
    ) -> Result<WorkspaceStateLayout, Box<dyn std::error::Error>> {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&fixture.workspace_root)
            .args(["init", "-q"])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        if !output.status.success() {
            return Err("failed to initialize Doctor Git fixture".into());
        }
        Ok(WorkspaceStateLayout::initialize(&fixture.workspace_root)?)
    }

    fn capture_git_checkpoint(
        fixture: &Fixture,
        seed: u128,
        name: &str,
    ) -> Result<(ExistingWorkspaceStateLayout, RegisteredCheckpoint), Box<dyn std::error::Error>>
    {
        let _layout = initialize_git_fixture(fixture)?;
        let activity_id = forge_domain::ActivityId::from_uuid(Uuid::from_u128(0xF200 + seed));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF300 + seed));
        let activity = fixture.control.bootstrap_activity(
            &fixture.scope,
            activity_id,
            runtime_id,
            timestamp(10)?,
            timestamp(1_000)?,
        )?;
        if activity.activity().is_none() {
            return Err("checkpoint Doctor Activity missing".into());
        }
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0xF400 + seed));
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: FileActivityScope {
                activity_id,
                runtime_instance_id: runtime_id,
                observed_at: timestamp(20)?,
            },
            goal: None,
            change_set_id,
            mutation_id: FileMutationId::from_uuid(Uuid::from_u128(0xF500 + seed)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(name.into())?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            content: Some(b"checkpoint doctor\n".to_vec()),
        };
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );
        let existing = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("checkpoint Doctor layout missing")?;
        let store = WorkspaceStore::open_existing(&existing)?;
        let checkpoint = store
            .list_checkpoints(fixture.scope.workspace_id(), 16)?
            .into_iter()
            .find(|checkpoint| checkpoint.change_set_id() == change_set_id)
            .ok_or("checkpoint Doctor row missing")?;
        Ok((existing, checkpoint))
    }

    #[test]
    fn exact_scope_doctor_is_healthy_and_cross_scope_identity_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("scope")?;
        let result = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(result.scope(), &fixture.scope);
        assert!(result.report().is_healthy());
        assert_eq!(
            result.git_local_state(),
            GitLocalStateDoctor::NotGitRepository
        );
        assert!(result.diff_artifacts().findings().is_empty());
        assert!(result.diff_artifacts().is_complete());
        assert_eq!(result.outcome(), WorkspaceDoctorAggregateOutcome::Healthy);

        let wrong = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(0xFFFF)),
            WorkspaceRevision::INITIAL,
            fixture.scope.locator().clone(),
        );
        assert!(matches!(
            fixture
                .control
                .workspace_doctor(&WorkspaceDoctorRequest { scope: wrong }),
            Err(error) if error.code() == ControlErrorCode::WorkspaceIdentityConflict
        ));

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_marks_truncated_current_dag_observation_incomplete()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("dag-truncated")?;
        let existing = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("Doctor Workspace layout missing")?;
        let mut store = WorkspaceStore::open_existing(&existing)?;
        for offset in 0..=DAG_DOCTOR_MAX_CURRENT_DAGS {
            let seed = u128::try_from(offset)?;
            let goal = RegisteredGoal::create(
                GoalId::from_uuid(Uuid::from_u128(0xDA00 + seed)),
                fixture.scope.workspace_id(),
                GoalContract::new(
                    GoalObjective::new(format!("Doctor DAG {offset}"))?,
                    vec![GoalStatement::new(
                        "Current DAG remains observable".to_owned(),
                    )?],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )?,
                timestamp(100 + i64::try_from(offset)?)?,
            );
            let _ = store.insert_goal(&goal)?;
            let definition = DagNodeDefinition::new(
                DagNodeId::from_uuid(Uuid::from_u128(0xDB00 + seed)),
                DagNodeOrdinal::new(0)?,
                DagNodeTitle::new(format!("Doctor node {offset}"))?,
                DagNodeObjective::new("Remain semantically valid".to_owned())?,
                vec![DagAcceptanceCriterion::new("DAG is valid".to_owned())?],
            )?;
            let dag = DagRevision::new(
                DagRevisionId::from_uuid(Uuid::from_u128(0xDC00 + seed)),
                goal.id(),
                goal.revision(),
                DagRevisionNumber::INITIAL,
                None,
                vec![definition.clone()],
                Vec::new(),
                timestamp(200 + i64::try_from(offset)?)?,
            )?;
            let nodes = vec![RegisteredDagNode::create(
                goal.id(),
                dag.number(),
                definition,
                dag.created_at(),
            )];
            let _ = store.insert_dag_revision(&dag, &nodes, &[], None)?;
        }
        drop(store);

        let result = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert!(result.report().dag_semantics().truncated());
        assert!(!result.report().dag_semantics().is_damaged());
        assert_eq!(
            result.outcome(),
            WorkspaceDoctorAggregateOutcome::Incomplete
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn bounded_worker_round_trips_workspace_doctor_and_joins()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("worker")?;
        let Fixture {
            root,
            workspace_root: _,
            control,
            scope,
        } = fixture;
        let (client, mut worker) = control.start_worker()?;
        let result = client.workspace_doctor(WorkspaceDoctorRequest {
            scope: scope.clone(),
        })?;
        assert_eq!(result.scope(), &scope);
        assert!(result.report().is_healthy());
        assert_eq!(
            result.observation_consistency(),
            WorkspaceDoctorObservationConsistency::Stable
        );
        assert_eq!(result.outcome(), WorkspaceDoctorAggregateOutcome::Healthy);
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_reports_unknown_filesystem_artifact_as_orphan()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("orphan")?;
        let artifact = fixture
            .workspace_root
            .join(".heterarchy-forge/diffs/orphan.bin");
        fs::write(&artifact, b"bounded orphan")?;
        let before = fs::read(&artifact)?;

        let result = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(result.diff_artifacts().findings().len(), 1);
        assert_eq!(
            result.diff_artifacts().findings()[0].status(),
            WorkspaceDiffArtifactStatus::Orphan
        );
        assert_eq!(result.diff_artifacts().findings()[0].diff_id(), None);
        assert_eq!(
            result.outcome(),
            WorkspaceDoctorAggregateOutcome::RecoveryRequired
        );
        assert_eq!(fs::read(&artifact)?, before);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_joins_ready_missing_and_corrupt_diff_artifact()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("diff-join")?;
        let activity_id = forge_domain::ActivityId::from_uuid(Uuid::from_u128(0xF100));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xF101));
        let activity = fixture.control.bootstrap_activity(
            &fixture.scope,
            activity_id,
            runtime_id,
            timestamp(10)?,
            timestamp(1_000)?,
        )?;
        let activity_scope = FileActivityScope {
            activity_id,
            runtime_instance_id: runtime_id,
            observed_at: timestamp(20)?,
        };
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0xF102));
        let mutation = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: activity_scope,
            goal: None,
            change_set_id,
            mutation_id: FileMutationId::from_uuid(Uuid::from_u128(0xF103)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new("doctor-diff.txt".into())?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            content: Some(b"doctor diff\n".to_vec()),
        };
        assert!(activity.activity().is_some());
        assert_eq!(
            fixture.control.file_mutate(&mutation)?.status(),
            FileMutationStatus::Applied
        );
        let diff_id = DiffId::for_change_set(change_set_id);
        let artifact = fixture
            .workspace_root
            .join(format!(".heterarchy-forge/diffs/diff_{diff_id}.diff.zst"));

        let available = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(
            finding_status(&available, diff_id),
            Some(WorkspaceDiffArtifactStatus::OwnedAvailable)
        );
        assert_eq!(
            available.outcome(),
            WorkspaceDoctorAggregateOutcome::Healthy
        );

        fs::write(&artifact, b"corrupt")?;
        let corrupt = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(
            finding_status(&corrupt, diff_id),
            Some(WorkspaceDiffArtifactStatus::Corrupt)
        );
        assert_eq!(corrupt.outcome(), WorkspaceDoctorAggregateOutcome::Damaged);

        fs::remove_file(&artifact)?;
        let missing = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(
            finding_status(&missing, diff_id),
            Some(WorkspaceDiffArtifactStatus::DatabaseMissing)
        );
        assert_eq!(missing.outcome(), WorkspaceDoctorAggregateOutcome::Damaged);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_projects_missing_git_local_exclude_without_repair()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("git-missing")?;
        let status = Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&fixture.workspace_root)
            .status()?;
        assert!(status.success());
        let exclude = fixture.workspace_root.join(".git/info/exclude");
        let before = fs::read(&exclude)?;

        let result = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(
            result.git_local_state(),
            GitLocalStateDoctor::MissingLocalExclude
        );
        assert_eq!(result.outcome(), WorkspaceDoctorAggregateOutcome::Damaged);
        assert_eq!(fs::read(&exclude)?, before);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_reports_invalid_diff_nodes_individually_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("invalid-diff-nodes")?;
        let diffs = fixture.workspace_root.join(".heterarchy-forge/diffs");
        let symlink_path = diffs.join("invalid-link");
        let directory_path = diffs.join("invalid-directory");
        let hardlink_path = diffs.join("invalid-hardlink");
        let hardlink_source = fixture.workspace_root.join("invalid-hardlink-source");
        symlink("missing-target", &symlink_path)?;
        fs::create_dir(&directory_path)?;
        fs::write(&hardlink_source, b"hardlink")?;
        fs::hard_link(&hardlink_source, &hardlink_path)?;

        let result = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        let statuses = result
            .diff_artifacts()
            .findings()
            .iter()
            .map(|finding| finding.status())
            .collect::<Vec<_>>();
        assert!(statuses.contains(&WorkspaceDiffArtifactStatus::InvalidSymlink));
        assert!(statuses.contains(&WorkspaceDiffArtifactStatus::InvalidNonRegular));
        assert!(statuses.contains(&WorkspaceDiffArtifactStatus::InvalidHardlink));
        assert!(
            result
                .diff_artifacts()
                .findings()
                .iter()
                .all(|finding| finding.diff_id().is_none())
        );
        assert_eq!(result.outcome(), WorkspaceDoctorAggregateOutcome::Damaged);
        assert!(
            fs::symlink_metadata(&symlink_path)?
                .file_type()
                .is_symlink()
        );
        assert!(directory_path.is_dir());
        assert!(hardlink_path.is_file());

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_does_not_initialize_an_absent_checkpoint_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("checkpoint-store-absent")?;
        let layout = initialize_git_fixture(&fixture)?;
        let store_path = layout.checkpoints().join("store.git");
        assert!(!store_path.exists());

        let result = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(result.git_local_state(), GitLocalStateDoctor::Verified);
        assert!(result.checkpoint_store().applicable());
        assert!(!result.checkpoint_store().store_present());
        assert!(result.checkpoint_store().findings().is_empty());
        assert!(result.checkpoint_store().is_complete());
        assert_eq!(result.outcome(), WorkspaceDoctorAggregateOutcome::Healthy);
        assert!(!store_path.exists());

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_joins_checkpoint_rows_refs_and_objects_read_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("checkpoint-store-ready")?;
        let (layout, checkpoint) = capture_git_checkpoint(&fixture, 0x10, "doctor-checkpoint.txt")?;
        let store = GitCheckpointStore::inspect_existing_read_only(&layout)?
            .ok_or("checkpoint store missing before Doctor")?;
        let before = store.inventory_refs_read_only(GitCheckpointRefInventoryLimit::DEFAULT)?;

        let result = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(result.git_local_state(), GitLocalStateDoctor::Verified);
        assert!(result.checkpoint_store().store_present());
        assert_eq!(
            result.checkpoint_store().store_integrity(),
            Some(GitCheckpointStoreIntegrity::Passed)
        );
        assert!(result.checkpoint_store().is_complete());
        assert_eq!(
            checkpoint_status(&result, checkpoint.id(), CheckpointSide::Pre),
            Some(WorkspaceCheckpointStoreStatus::OwnedAvailable)
        );
        assert_eq!(
            checkpoint_status(&result, checkpoint.id(), CheckpointSide::Post),
            Some(WorkspaceCheckpointStoreStatus::OwnedAvailable)
        );
        assert_eq!(result.outcome(), WorkspaceDoctorAggregateOutcome::Healthy);

        let after_store = GitCheckpointStore::inspect_existing_read_only(&layout)?
            .ok_or("checkpoint store missing after Doctor")?;
        let after =
            after_store.inventory_refs_read_only(GitCheckpointRefInventoryLimit::DEFAULT)?;
        assert_eq!(after, before);
        assert!(
            !fixture
                .workspace_root
                .join(".git/refs/heterarchy-forge")
                .exists()
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn workspace_doctor_classifies_orphan_and_missing_checkpoint_refs()
    -> Result<(), Box<dyn std::error::Error>> {
        let orphan_fixture = fixture("checkpoint-orphan-ref")?;
        let orphan_layout = initialize_git_fixture(&orphan_fixture)?;
        fs::write(
            orphan_fixture.workspace_root.join("orphan.txt"),
            b"orphan\n",
        )?;
        let orphan_store = GitCheckpointStore::from_state_layout(&orphan_layout)?;
        let orphan_id = CheckpointId::from_uuid(Uuid::from_u128(0xF900));
        let orphan_path = WorkspaceRelativePath::new("orphan.txt".into())?;
        let _retained = orphan_store.retain_snapshot(
            orphan_id,
            &orphan_path,
            CheckpointSide::Pre,
            timestamp(30)?,
            None,
        )?;
        let orphan = orphan_fixture
            .control
            .workspace_doctor(&WorkspaceDoctorRequest {
                scope: orphan_fixture.scope.clone(),
            })?;
        assert_eq!(
            checkpoint_status(&orphan, orphan_id, CheckpointSide::Pre),
            Some(WorkspaceCheckpointStoreStatus::OrphanRef)
        );
        assert_eq!(
            orphan.outcome(),
            WorkspaceDoctorAggregateOutcome::RecoveryRequired
        );
        fs::remove_dir_all(orphan_fixture.root)?;

        let missing_fixture = fixture("checkpoint-missing-ref")?;
        let (missing_layout, checkpoint) =
            capture_git_checkpoint(&missing_fixture, 0x20, "missing-ref.txt")?;
        let missing_store = GitCheckpointStore::inspect_existing_read_only(&missing_layout)?
            .ok_or("checkpoint store missing")?;
        missing_store.delete_snapshot(
            checkpoint.id(),
            CheckpointSide::Pre,
            checkpoint.pre_commit(),
        )?;
        let missing = missing_fixture
            .control
            .workspace_doctor(&WorkspaceDoctorRequest {
                scope: missing_fixture.scope.clone(),
            })?;
        assert_eq!(
            checkpoint_status(&missing, checkpoint.id(), CheckpointSide::Pre),
            Some(WorkspaceCheckpointStoreStatus::RefMissing)
        );
        assert_eq!(missing.outcome(), WorkspaceDoctorAggregateOutcome::Damaged);
        fs::remove_dir_all(missing_fixture.root)?;
        Ok(())
    }

    #[test]
    fn checkpoint_and_diff_source_observations_detect_mid_doctor_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("observation-source-change")?;
        let (layout, checkpoint) =
            capture_git_checkpoint(&fixture, 0x34, "observation-change.txt")?;
        let report = WorkspaceStore::doctor_existing_read_only(&layout)?;
        let git_state = layout.inspect_git_local_state_read_only()?;
        let checkpoint_observation =
            observe_checkpoint_store(report.checkpoint_references(), git_state, &layout)?;
        assert!(
            checkpoint_observation.source_is_unchanged(report.checkpoint_references(), &layout)
        );

        let checkpoint_store = GitCheckpointStore::inspect_existing_read_only(&layout)?
            .ok_or("checkpoint store missing")?;
        checkpoint_store.delete_snapshot(
            checkpoint.id(),
            CheckpointSide::Pre,
            checkpoint.pre_commit(),
        )?;
        assert!(
            !checkpoint_observation.source_is_unchanged(report.checkpoint_references(), &layout),
            "checkpoint ref mutation must invalidate the first Doctor source observation"
        );

        let filesystem = ConfinedWorkspace::open(&layout)?;
        let artifacts = filesystem.diff_artifact_store()?;
        let before = artifacts.inventory(DiffArtifactInventoryLimit::DEFAULT)?;
        fs::write(layout.diffs().join("late-observation-artifact"), b"late")?;
        let after = artifacts.inventory(DiffArtifactInventoryLimit::DEFAULT)?;
        assert_ne!(before, after);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn changed_cross_authority_observation_is_incomplete_for_an_intrinsically_healthy_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("observation-aggregate")?;
        let stable = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(stable.outcome(), WorkspaceDoctorAggregateOutcome::Healthy);
        let changed = WorkspaceDoctorResult::new(
            stable.scope().clone(),
            stable.report().clone(),
            stable.git_local_state(),
            stable.checkpoint_store().clone(),
            stable.diff_artifacts().clone(),
            WorkspaceDoctorObservationConsistency::Changed,
        );
        assert_eq!(
            changed.observation_consistency(),
            WorkspaceDoctorObservationConsistency::Changed
        );
        assert_eq!(
            changed.outcome(),
            WorkspaceDoctorAggregateOutcome::Incomplete
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn changed_cross_authority_observation_overrides_first_pass_damage()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("observation-damaged-aggregate")?;
        let (layout, checkpoint) =
            capture_git_checkpoint(&fixture, 0x35, "observation-damaged.txt")?;
        let store = GitCheckpointStore::inspect_existing_read_only(&layout)?
            .ok_or("checkpoint store missing")?;
        store.delete_snapshot(
            checkpoint.id(),
            CheckpointSide::Pre,
            checkpoint.pre_commit(),
        )?;
        let damaged = fixture.control.workspace_doctor(&WorkspaceDoctorRequest {
            scope: fixture.scope.clone(),
        })?;
        assert_eq!(damaged.outcome(), WorkspaceDoctorAggregateOutcome::Damaged);

        let changed = WorkspaceDoctorResult::new(
            damaged.scope().clone(),
            damaged.report().clone(),
            damaged.git_local_state(),
            damaged.checkpoint_store().clone(),
            damaged.diff_artifacts().clone(),
            WorkspaceDoctorObservationConsistency::Changed,
        );
        assert_eq!(
            changed.outcome(),
            WorkspaceDoctorAggregateOutcome::Incomplete
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    fn checkpoint_status(
        result: &WorkspaceDoctorResult,
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
    ) -> Option<WorkspaceCheckpointStoreStatus> {
        result
            .checkpoint_store()
            .findings()
            .iter()
            .find(|finding| {
                finding.checkpoint_id() == Some(checkpoint_id) && finding.side() == Some(side)
            })
            .map(|finding| finding.status())
    }

    fn finding_status(
        result: &WorkspaceDoctorResult,
        diff_id: DiffId,
    ) -> Option<WorkspaceDiffArtifactStatus> {
        result
            .diff_artifacts()
            .findings()
            .iter()
            .find(|finding| finding.diff_id() == Some(diff_id))
            .map(|finding| finding.status())
    }
}
