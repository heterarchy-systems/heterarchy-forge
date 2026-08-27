use std::collections::BTreeMap;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use forge_domain::{
    BeginDiffPurge, CompleteDiffPurge, DeleteOrphanDiffArtifact, DiffArtifactInvalidInventoryEntry,
    DiffArtifactInventoryEntry, DiffArtifactInventoryKind, DiffArtifactInventoryLimit,
    DiffArtifactInventoryName, DiffId, DiffPayloadProjection, DiffPurgeRecord, DiffPurgeStatus,
    DiffRetentionKeepCount, DiffRetentionPlan, DiffRetentionPlanLimit, DiffRevision,
    RegisteredDiffEvidence, TimestampMillis,
};
use forge_persistence::DiffDoctorReference;
use forge_workspace::{ConfinedWorkspace, DiffArtifactDeleteStatus, diff_path_label};

use crate::diff::artifact_expectation;
use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::{map_diff_artifact_error, map_filesystem_error};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRetentionPlanRequest {
    pub scope: ResolvedWorkspaceScope,
    pub keep_recent: DiffRetentionKeepCount,
    pub limit: DiffRetentionPlanLimit,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRetentionPlanResult {
    scope: ResolvedWorkspaceScope,
    plan: DiffRetentionPlan,
}

impl DiffRetentionPlanResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn plan(&self) -> &DiffRetentionPlan {
        &self.plan
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPurgeRequest {
    pub scope: ResolvedWorkspaceScope,
    pub diff_id: DiffId,
    pub expected_revision: DiffRevision,
    pub observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPurgeResult {
    scope: ResolvedWorkspaceScope,
    record: DiffPurgeRecord,
    artifact_status: DiffArtifactDeleteStatus,
}

impl DiffPurgeResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn record(&self) -> &DiffPurgeRecord {
        &self.record
    }

    pub const fn artifact_status(&self) -> DiffArtifactDeleteStatus {
        self.artifact_status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffArtifactOwnershipStatus {
    Owned,
    Orphan,
    Conflicting,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArtifactDiagnosticEntry {
    artifact: DiffArtifactInventoryEntry,
    ownership: DiffArtifactOwnershipStatus,
    path_label: String,
}

impl DiffArtifactDiagnosticEntry {
    pub fn artifact(&self) -> &DiffArtifactInventoryEntry {
        &self.artifact
    }

    pub const fn ownership(&self) -> DiffArtifactOwnershipStatus {
        self.ownership
    }

    pub fn path_label(&self) -> &str {
        &self.path_label
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArtifactDoctorRequest {
    pub scope: ResolvedWorkspaceScope,
    pub limit: DiffArtifactInventoryLimit,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArtifactDoctorResult {
    scope: ResolvedWorkspaceScope,
    entries: Vec<DiffArtifactDiagnosticEntry>,
    invalid_entries: Vec<DiffArtifactInvalidInventoryEntry>,
    truncated: bool,
}

impl DiffArtifactDoctorResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub fn entries(&self) -> &[DiffArtifactDiagnosticEntry] {
        &self.entries
    }

    pub fn invalid_entries(&self) -> &[DiffArtifactInvalidInventoryEntry] {
        &self.invalid_entries
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOrphanDiffArtifactRequest {
    pub scope: ResolvedWorkspaceScope,
    pub command: DeleteOrphanDiffArtifact,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOrphanDiffArtifactResult {
    scope: ResolvedWorkspaceScope,
    status: DiffArtifactDeleteStatus,
}

impl DeleteOrphanDiffArtifactResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn status(&self) -> DiffArtifactDeleteStatus {
        self.status
    }
}

impl ForgeControl {
    pub fn plan_diff_retention(
        &self,
        request: &DiffRetentionPlanRequest,
    ) -> Result<DiffRetentionPlanResult, ControlError> {
        let (scope, _layout, store) = self.open_diff_workspace(&request.scope)?;
        let plan = store
            .plan_diff_retention(request.keep_recent, request.limit)
            .map_err(map_activity_store_error)?;
        Ok(DiffRetentionPlanResult { scope, plan })
    }

    pub fn purge_diff(&self, request: &DiffPurgeRequest) -> Result<DiffPurgeResult, ControlError> {
        let (scope, layout, mut store) = self.open_diff_workspace(&request.scope)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let _guard = filesystem
            .acquire_write_guard()
            .map_err(map_filesystem_error)?;
        let artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let pending = store
            .begin_diff_purge(BeginDiffPurge::new(
                request.diff_id,
                request.expected_revision,
                request.observed_at,
            ))
            .map_err(map_activity_store_error)?;
        if matches!(
            pending.status(),
            DiffPurgeStatus::AlreadyTombstoned | DiffPurgeStatus::Tombstoned
        ) {
            return Ok(DiffPurgeResult {
                scope,
                record: pending,
                artifact_status: DiffArtifactDeleteStatus::AlreadyMissing,
            });
        }
        let expected = artifact_expectation(pending.evidence())?;
        let artifact_status = artifacts
            .delete_published(&expected)
            .map_err(map_diff_artifact_error)?;
        let record = store
            .complete_diff_purge(CompleteDiffPurge::new(
                request.diff_id,
                pending.evidence().revision(),
                request.observed_at,
            ))
            .map_err(map_activity_store_error)?;
        Ok(DiffPurgeResult {
            scope,
            record,
            artifact_status,
        })
    }

    pub fn diff_artifact_doctor(
        &self,
        request: &DiffArtifactDoctorRequest,
    ) -> Result<DiffArtifactDoctorResult, ControlError> {
        let (scope, layout, store) = self.open_diff_workspace(&request.scope)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let inventory = artifacts
            .inventory(request.limit)
            .map_err(map_diff_artifact_error)?;
        let database = store
            .list_diff_doctor_references()
            .map_err(map_activity_store_error)?;
        let database_by_id = database
            .references()
            .iter()
            .map(|reference| (reference.diff_id(), reference))
            .collect::<BTreeMap<_, _>>();
        let mut entries = Vec::with_capacity(inventory.entries().len());
        for artifact in inventory.entries() {
            entries.push(classify_artifact_from_references(
                artifact,
                &database_by_id,
                database.truncated(),
            ));
        }
        Ok(DiffArtifactDoctorResult {
            scope,
            entries,
            invalid_entries: inventory.invalid_entries().to_vec(),
            truncated: inventory.truncated() || database.truncated(),
        })
    }

    pub fn delete_orphan_diff_artifact(
        &self,
        request: &DeleteOrphanDiffArtifactRequest,
    ) -> Result<DeleteOrphanDiffArtifactResult, ControlError> {
        let (scope, layout, store) = self.open_diff_workspace(&request.scope)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let _guard = filesystem
            .acquire_write_guard()
            .map_err(map_filesystem_error)?;
        let artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let inventory =
            artifacts
                .inventory(DiffArtifactInventoryLimit::new(1_024).map_err(|error| {
                    ControlError::with_source(ControlErrorCode::Internal, error)
                })?)
                .map_err(map_diff_artifact_error)?;
        if inventory
            .invalid_entries()
            .iter()
            .any(|entry| entry.name() == request.command.name())
        {
            return Err(ControlError::new(ControlErrorCode::DiffUnavailable));
        }
        let Some(entry) = inventory
            .entries()
            .iter()
            .find(|entry| entry.name() == request.command.name())
        else {
            return Ok(DeleteOrphanDiffArtifactResult {
                scope,
                status: DiffArtifactDeleteStatus::AlreadyMissing,
            });
        };
        if entry.compressed_hash() != request.command.expected_hash()
            || entry.compressed_size() != request.command.expected_size()
        {
            return Err(ControlError::new(ControlErrorCode::FileConflict));
        }
        let diagnostic = classify_artifact(&store, entry)?;
        if diagnostic.ownership() != DiffArtifactOwnershipStatus::Orphan {
            return Err(ControlError::new(ControlErrorCode::DiffUnavailable));
        }
        let status = artifacts
            .delete_orphan(&request.command)
            .map_err(map_diff_artifact_error)?;
        Ok(DeleteOrphanDiffArtifactResult { scope, status })
    }
}

fn classify_artifact_from_references(
    artifact: &DiffArtifactInventoryEntry,
    database: &BTreeMap<DiffId, &DiffDoctorReference>,
    database_truncated: bool,
) -> DiffArtifactDiagnosticEntry {
    let ownership = match artifact.diff_id() {
        None => DiffArtifactOwnershipStatus::Orphan,
        Some(id) => match database.get(&id) {
            Some(reference) if artifact_matches_reference(artifact, reference) => {
                DiffArtifactOwnershipStatus::Owned
            }
            Some(_) => DiffArtifactOwnershipStatus::Conflicting,
            None if database_truncated => DiffArtifactOwnershipStatus::Conflicting,
            None => DiffArtifactOwnershipStatus::Orphan,
        },
    };
    DiffArtifactDiagnosticEntry {
        artifact: artifact.clone(),
        ownership,
        path_label: inventory_name_label(artifact.name()),
    }
}

fn artifact_matches_reference(
    artifact: &DiffArtifactInventoryEntry,
    reference: &DiffDoctorReference,
) -> bool {
    [reference.pending_artifact(), reference.final_artifact()]
        .into_iter()
        .flatten()
        .any(|expected| {
            expected.name() == artifact.name()
                && expected.compressed_hash() == artifact.compressed_hash()
                && expected.compressed_size() == artifact.compressed_size()
        })
}

fn classify_artifact(
    store: &forge_persistence::WorkspaceStore,
    artifact: &DiffArtifactInventoryEntry,
) -> Result<DiffArtifactDiagnosticEntry, ControlError> {
    let ownership = match artifact.diff_id() {
        None => DiffArtifactOwnershipStatus::Orphan,
        Some(id) => match store.get_diff(id).map_err(map_activity_store_error)? {
            Some(evidence) if artifact_matches_evidence(artifact, &evidence) => {
                DiffArtifactOwnershipStatus::Owned
            }
            Some(_) => DiffArtifactOwnershipStatus::Conflicting,
            None => {
                let change_set_id = forge_domain::ChangeSetId::from_uuid(id.into_uuid());
                if store
                    .get_file_mutation(change_set_id)
                    .map_err(map_activity_store_error)?
                    .is_some()
                {
                    DiffArtifactOwnershipStatus::Conflicting
                } else {
                    DiffArtifactOwnershipStatus::Orphan
                }
            }
        },
    };
    Ok(DiffArtifactDiagnosticEntry {
        artifact: artifact.clone(),
        ownership,
        path_label: inventory_name_label(artifact.name()),
    })
}

fn artifact_matches_evidence(
    artifact: &DiffArtifactInventoryEntry,
    evidence: &RegisteredDiffEvidence,
) -> bool {
    let payload = evidence.payload();
    let expected = match (artifact.kind(), payload) {
        (
            DiffArtifactInventoryKind::Pending,
            DiffPayloadProjection::IntentText {
                pending_relative_path,
                compressed_hash,
                compressed_size,
                ..
            },
        ) => Some((pending_relative_path, *compressed_hash, *compressed_size)),
        (
            DiffArtifactInventoryKind::Final,
            DiffPayloadProjection::IntentText {
                final_relative_path,
                compressed_hash,
                compressed_size,
                ..
            },
        ) => Some((final_relative_path, *compressed_hash, *compressed_size)),
        (
            DiffArtifactInventoryKind::Final,
            DiffPayloadProjection::Ready {
                relative_path,
                compressed_hash,
                compressed_size,
                ..
            }
            | DiffPayloadProjection::PurgePending {
                relative_path,
                compressed_hash,
                compressed_size,
                ..
            },
        ) => Some((relative_path, *compressed_hash, *compressed_size)),
        _ => None,
    };
    expected.is_some_and(|(path, hash, size)| {
        path.as_path()
            .file_name()
            .is_some_and(|name| name.as_bytes() == artifact.name().as_bytes())
            && hash == artifact.compressed_hash()
            && size == artifact.compressed_size()
    })
}

fn inventory_name_label(name: &DiffArtifactInventoryName) -> String {
    let path = forge_domain::WorkspaceRelativePath::new(std::path::PathBuf::from(
        std::ffi::OsString::from_vec(name.as_bytes().to_vec()),
    ));
    path.map_or_else(
        |_| format!(".native/{}", hex_name(name.as_bytes())),
        |path| diff_path_label(&path),
    )
}

fn hex_name(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len().saturating_mul(2));
    for byte in value {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        ActivityId, BootstrapActivity, ChangeSetId, FileMutationId, FileMutationKind,
        FileMutationPlan, FilePrecondition, LocationId, LocationRevision, RuntimeInstanceId,
        WorkspaceId, WorkspaceRelativePath, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;
    use crate::{FileActivityScope, FileMutationRequest, FileMutationResult, FileMutationStatus};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        control: ForgeControl,
        scope: ResolvedWorkspaceScope,
        activity: FileActivityScope,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("forge-retention-{}-{serial}", std::process::id()));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let mut locations = LocationService::new(registry);
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xE100));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xE101));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xE102));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xE103));
        let now = TimestampMillis::new(10)?;
        locations.register_selected_path(location_id, "Retention", &location_root, now)?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let mut store = WorkspaceStore::open(
            &layout,
            forge_domain::EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                now,
            ),
        )?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            runtime_id,
            TimestampMillis::new(1_000)?,
            TimestampMillis::new(20)?,
        ))?;
        drop(store);
        let control = ForgeControl::from_location_service(locations);
        let locator = WorkspaceLocator::new(
            location_id,
            LocationRevision::INITIAL,
            Path::new("workspace"),
        )?;
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        Ok(Fixture {
            root,
            control,
            scope,
            activity: FileActivityScope {
                activity_id,
                runtime_instance_id: runtime_id,
                observed_at: TimestampMillis::new(30)?,
            },
        })
    }

    fn apply_retained_diff(
        fixture: &Fixture,
        change_set_id: ChangeSetId,
    ) -> Result<FileMutationResult, ControlError> {
        fixture.control.file_mutate(&FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            change_set_id,
            mutation_id: FileMutationId::from_uuid(Uuid::from_u128(0xE111)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("retained.txt")).map_err(|error| {
                    ControlError::with_source(ControlErrorCode::InvalidInput, error)
                })?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            content: Some(b"retention evidence\n".to_vec()),
        })
    }

    #[test]
    fn invalid_diff_entry_is_diagnostic_only_and_never_orphan_delete_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let workspace_root = fixture.root.join("location/workspace");
        let invalid_path = workspace_root.join(".heterarchy-forge/diffs/invalid-link");
        symlink("missing-target", &invalid_path)?;

        let doctor = fixture
            .control
            .diff_artifact_doctor(&DiffArtifactDoctorRequest {
                scope: fixture.scope.clone(),
                limit: DiffArtifactInventoryLimit::new(10)?,
            })?;
        assert!(doctor.entries().is_empty());
        assert_eq!(doctor.invalid_entries().len(), 1);
        let invalid = &doctor.invalid_entries()[0];
        assert_eq!(invalid.name().as_bytes(), b"invalid-link");
        assert_eq!(
            invalid.reason(),
            forge_domain::DiffArtifactInvalidReason::Symlink
        );

        let refused =
            fixture
                .control
                .delete_orphan_diff_artifact(&DeleteOrphanDiffArtifactRequest {
                    scope: fixture.scope.clone(),
                    command: DeleteOrphanDiffArtifact::new(
                        invalid.name().clone(),
                        forge_domain::DiffPayloadHash::from_bytes([0_u8; 32]),
                        forge_domain::DiffByteCount::new(0),
                    ),
                });
        assert_eq!(
            refused.err().map(|error| error.code()),
            Some(ControlErrorCode::DiffUnavailable)
        );
        assert!(
            fs::symlink_metadata(&invalid_path)?
                .file_type()
                .is_symlink()
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn explicit_purge_and_orphan_cleanup_are_hash_bound_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0xE110));
        let mutation = apply_retained_diff(&fixture, change_set_id)?;
        assert_eq!(mutation.status(), FileMutationStatus::Applied);
        let plan = fixture
            .control
            .plan_diff_retention(&DiffRetentionPlanRequest {
                scope: fixture.scope.clone(),
                keep_recent: DiffRetentionKeepCount::new(0)?,
                limit: DiffRetentionPlanLimit::new(10)?,
            })?;
        assert_eq!(plan.plan().candidates().len(), 1);
        let candidate = &plan.plan().candidates()[0];
        let doctor = fixture
            .control
            .diff_artifact_doctor(&DiffArtifactDoctorRequest {
                scope: fixture.scope.clone(),
                limit: DiffArtifactInventoryLimit::new(10)?,
            })?;
        assert_eq!(doctor.entries().len(), 1);
        assert_eq!(
            doctor.entries()[0].ownership(),
            DiffArtifactOwnershipStatus::Owned
        );
        let (client, mut worker) = fixture.control.start_worker()?;
        let purge_request = DiffPurgeRequest {
            scope: fixture.scope.clone(),
            diff_id: candidate.id(),
            expected_revision: candidate.revision(),
            // The worker replaces this caller value with authority time.
            observed_at: TimestampMillis::new(0)?,
        };
        let purged = client.purge_diff(purge_request.clone())?;
        assert_eq!(purged.record().status(), DiffPurgeStatus::Tombstoned);
        assert_eq!(purged.artifact_status(), DiffArtifactDeleteStatus::Deleted);
        assert_eq!(
            client.purge_diff(purge_request)?.record().status(),
            DiffPurgeStatus::AlreadyTombstoned
        );

        let workspace_root = fixture.root.join("location/workspace");
        let conflicting_path = workspace_root.join(format!(
            ".heterarchy-forge/diffs/diff_{}.diff.zst",
            candidate.id()
        ));
        fs::write(&conflicting_path, b"conflicting artifact")?;
        let conflicting = client.diff_artifact_doctor(DiffArtifactDoctorRequest {
            scope: fixture.scope.clone(),
            limit: DiffArtifactInventoryLimit::new(10)?,
        })?;
        assert_eq!(
            conflicting.entries()[0].ownership(),
            DiffArtifactOwnershipStatus::Conflicting
        );
        let conflicting_entry = &conflicting.entries()[0];
        let refused = client.delete_orphan_diff_artifact(DeleteOrphanDiffArtifactRequest {
            scope: fixture.scope.clone(),
            command: DeleteOrphanDiffArtifact::new(
                conflicting_entry.artifact().name().clone(),
                conflicting_entry.artifact().compressed_hash(),
                conflicting_entry.artifact().compressed_size(),
            ),
        });
        assert_eq!(
            refused.err().map(|error| error.code()),
            Some(ControlErrorCode::DiffUnavailable)
        );
        assert!(conflicting_path.exists());
        fs::remove_file(conflicting_path)?;

        let orphan_path = workspace_root.join(".heterarchy-forge/diffs/orphan.bin");
        fs::write(&orphan_path, b"orphan")?;
        let doctor = client.diff_artifact_doctor(DiffArtifactDoctorRequest {
            scope: fixture.scope.clone(),
            limit: DiffArtifactInventoryLimit::new(10)?,
        })?;
        assert_eq!(doctor.entries().len(), 1);
        let orphan = &doctor.entries()[0];
        assert_eq!(orphan.ownership(), DiffArtifactOwnershipStatus::Orphan);
        let deleted = client.delete_orphan_diff_artifact(DeleteOrphanDiffArtifactRequest {
            scope: fixture.scope,
            command: DeleteOrphanDiffArtifact::new(
                orphan.artifact().name().clone(),
                orphan.artifact().compressed_hash(),
                orphan.artifact().compressed_size(),
            ),
        })?;
        assert_eq!(deleted.status(), DiffArtifactDeleteStatus::Deleted);
        assert!(!orphan_path.exists());
        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
