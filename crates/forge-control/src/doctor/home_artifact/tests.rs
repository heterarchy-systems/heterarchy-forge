use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use forge_domain::{
    AgentAssignmentId, AgentAssignmentRevision, GitCommitId, HomeArtifactArchive,
    HomeArtifactCaptureIntent, HomeArtifactId, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
};
use forge_workspace::{
    FORGE_GIT_PROGRAM, GitCheckpointStore, HomeArtifactRefInventoryEntry,
    HomeArtifactRefInventoryLimit, HomeArtifactRefIssue, HomeArtifactStore, WorkspaceStateLayout,
};
use uuid::Uuid;

use super::*;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    workspace_root: PathBuf,
    layout: WorkspaceStateLayout,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-home-artifact-doctor-{}-{serial}",
            std::process::id()
        ));
        let workspace_root = root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let output = Command::new(FORGE_GIT_PROGRAM)
            .args(["init", "-q"])
            .current_dir(&workspace_root)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        if !output.status.success() {
            return Err("failed to initialize Home artifact Doctor Git fixture".into());
        }
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        fs::write(workspace_root.join("handoff.txt"), b"retained Home bytes\n")?;
        Ok(Self {
            root,
            workspace_root,
            layout,
        })
    }

    fn publish(
        &self,
        artifact_id: HomeArtifactId,
        seed: u128,
    ) -> Result<HomeArtifactArchive, Box<dyn Error>> {
        let store = match GitCheckpointStore::inspect_existing_read_only(&self.existing_layout()?)?
        {
            Some(store) => store,
            None => GitCheckpointStore::from_state_layout(&self.layout)?,
        };
        let intent = HomeArtifactCaptureIntent::new(
            artifact_id,
            Uuid::from_u128(seed + 1),
            Uuid::from_u128(seed + 2),
            WorkspaceId::from_uuid(Uuid::from_u128(seed + 3)),
            AgentAssignmentId::from_uuid(Uuid::from_u128(seed + 4)),
            AgentAssignmentRevision::new(1)?,
            AgentAssignmentId::from_uuid(Uuid::from_u128(seed + 5)),
            vec![WorkspaceRelativePath::new(PathBuf::from("handoff.txt"))?],
        )?;
        Ok(HomeArtifactStore::new(&store)
            .publish(&intent, TimestampMillis::new(i64::try_from(seed + 10)?)?)?)
    }

    fn existing_layout(
        &self,
    ) -> Result<forge_workspace::ExistingWorkspaceStateLayout, Box<dyn Error>> {
        WorkspaceStateLayout::inspect_existing(&self.workspace_root)?
            .ok_or_else(|| "Home artifact Doctor fixture state is missing".into())
    }

    fn inventory(&self) -> Result<forge_workspace::HomeArtifactRefInventory, Box<dyn Error>> {
        let layout = self.existing_layout()?;
        let store = GitCheckpointStore::inspect_existing_read_only(&layout)?
            .ok_or("Home artifact Doctor fixture store is missing")?;
        Ok(HomeArtifactStore::new(&store)
            .inventory_refs_read_only(HomeArtifactRefInventoryLimit::DEFAULT)?)
    }

    fn add_malformed_ref(&self, commit_id: GitCommitId) -> Result<(), Box<dyn Error>> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let object_id = commit_id.object_id();
        let object = object_id.as_bytes();
        let mut hex = String::with_capacity(object.len().saturating_mul(2));
        for byte in object {
            hex.push(char::from(HEX[usize::from(byte >> 4)]));
            hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        let store_path = self.layout.checkpoints().join("store.git");
        let output = Command::new(FORGE_GIT_PROGRAM)
            .arg("--git-dir")
            .arg(store_path)
            .args([
                "update-ref",
                "refs/heterarchy-forge/home-artifacts/not-an-artifact-id",
                hex.as_str(),
            ])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        if !output.status.success() {
            return Err("failed to add malformed Home artifact ref fixture".into());
        }
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn artifact_id(value: u128) -> Result<HomeArtifactId, Box<dyn Error>> {
    Ok(HomeArtifactId::new(Uuid::from_u128(value))?)
}

fn database_reference(
    artifact_id: HomeArtifactId,
    expected_commit: Option<GitCommitId>,
) -> DatabaseReference {
    DatabaseReference {
        artifact_id,
        expected_commit,
    }
}

fn finding_status(
    report: &WorkspaceHomeArtifactDoctorReport,
    artifact_id: Option<HomeArtifactId>,
) -> Option<WorkspaceHomeArtifactStatus> {
    report
        .findings()
        .iter()
        .find(|finding| finding.artifact_id() == artifact_id)
        .map(|finding| finding.status())
}

#[test]
fn empty_legacy_inventory_is_complete_and_does_not_initialize_the_store()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let layout = fixture.existing_layout()?;
    let source = observe_store_source(&layout)?;
    let report = compose_home_artifact_report(&[], false, &[], false);

    assert_eq!(source, HomeArtifactStoreSource::Missing);
    assert!(report.findings().is_empty());
    assert!(report.is_complete());
    assert!(report.metadata_only());
    assert!(!fixture.layout.checkpoints().join("store.git").exists());
    Ok(())
}

#[test]
fn pending_sealed_and_published_refs_join_by_home_identity_and_commit() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let sealed_id = artifact_id(0xA101)?;
    let pending_published_id = artifact_id(0xA102)?;
    let pending_capture_id = artifact_id(0xA103)?;
    let sealed = fixture.publish(sealed_id, 0xA100)?;
    let _pending_published = fixture.publish(pending_published_id, 0xA200)?;
    let inventory = fixture.inventory()?;
    let database = [
        database_reference(sealed_id, Some(sealed.commit_id())),
        database_reference(pending_published_id, None),
        database_reference(pending_capture_id, None),
    ];

    let report =
        compose_home_artifact_report(&database, false, inventory.entries(), inventory.truncated());
    assert_eq!(
        finding_status(&report, Some(sealed_id)),
        Some(WorkspaceHomeArtifactStatus::RetainedRefMatched)
    );
    assert_eq!(
        finding_status(&report, Some(pending_published_id)),
        Some(WorkspaceHomeArtifactStatus::PublishedPendingSeal)
    );
    assert_eq!(
        finding_status(&report, Some(pending_capture_id)),
        Some(WorkspaceHomeArtifactStatus::PendingCapture)
    );
    assert!(report.requires_recovery());
    assert!(report.metadata_only());
    assert!(report.is_complete());
    Ok(())
}

#[test]
fn sealed_missing_and_wrong_commit_are_distinguished() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let retained_id = artifact_id(0xB101)?;
    let other_id = artifact_id(0xB102)?;
    let missing_id = artifact_id(0xB103)?;
    let retained = fixture.publish(retained_id, 0xB100)?;
    let other = fixture.publish(other_id, 0xB200)?;
    let inventory = fixture.inventory()?;
    let database = [
        database_reference(retained_id, Some(other.commit_id())),
        database_reference(missing_id, Some(retained.commit_id())),
        database_reference(other_id, Some(other.commit_id())),
    ];

    let report =
        compose_home_artifact_report(&database, false, inventory.entries(), inventory.truncated());
    assert_eq!(
        finding_status(&report, Some(retained_id)),
        Some(WorkspaceHomeArtifactStatus::Conflicting)
    );
    assert_eq!(
        finding_status(&report, Some(missing_id)),
        Some(WorkspaceHomeArtifactStatus::Missing)
    );
    assert_eq!(
        finding_status(&report, Some(other_id)),
        Some(WorkspaceHomeArtifactStatus::RetainedRefMatched)
    );
    assert!(report.has_damage());
    Ok(())
}

#[test]
fn unmatched_and_malformed_home_refs_remain_protected_unresolved() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let retained_id = artifact_id(0xC101)?;
    let retained = fixture.publish(retained_id, 0xC100)?;
    fixture.add_malformed_ref(retained.commit_id())?;
    let inventory = fixture.inventory()?;
    assert!(inventory.entries().iter().any(|entry| matches!(
        entry,
        HomeArtifactRefInventoryEntry::ProtectedUnknown {
            reason: HomeArtifactRefIssue::MalformedName,
            ..
        }
    )));

    let report =
        compose_home_artifact_report(&[], false, inventory.entries(), inventory.truncated());
    assert_eq!(
        finding_status(&report, Some(retained_id)),
        Some(WorkspaceHomeArtifactStatus::ProtectedUnresolved)
    );
    assert_eq!(
        finding_status(&report, None),
        Some(WorkspaceHomeArtifactStatus::ProtectedUnresolved)
    );
    assert!(report.requires_recovery());
    Ok(())
}

#[test]
fn home_ref_inventory_change_after_observation_marks_source_unstable() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let first_id = artifact_id(0xD101)?;
    let second_id = artifact_id(0xD102)?;
    let first = fixture.publish(first_id, 0xD100)?;
    assert_eq!(first.manifest().intent().artifact_id(), first_id);
    let layout = fixture.existing_layout()?;
    let observation = HomeArtifactObservation {
        report: compose_home_artifact_report(&[], false, &[], false),
        source: observe_store_source(&layout)?,
    };
    assert!(observation.source_is_unchanged(&layout));

    let second = fixture.publish(second_id, 0xD200)?;
    assert_eq!(second.manifest().intent().artifact_id(), second_id);
    assert!(!observation.source_is_unchanged(&layout));
    Ok(())
}

#[test]
fn truncated_home_reference_coverage_is_incomplete() {
    let report = compose_home_artifact_report(&[], false, &[], true);
    assert!(!report.is_complete());
    assert!(report.refs_truncated());
}
