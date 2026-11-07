//! Read-only composition of durable Home artifact references and their owned
//! Git namespace refs. This is metadata reconciliation only: archive manifests
//! and retained blobs are not opened or verified here.

use std::collections::BTreeMap;

use forge_domain::{GitCommitId, HomeArtifactId};
use forge_persistence::{HomeArtifactDoctorReference, HomeArtifactDoctorReport};
use forge_workspace::{
    ExistingWorkspaceStateLayout, GitCheckpointStore, HomeArtifactRefInventory,
    HomeArtifactRefInventoryEntry, HomeArtifactRefInventoryLimit, HomeArtifactStore,
    HomeArtifactStoreError,
};

use crate::error::{ControlError, ControlErrorCode};

const MAX_WORKSPACE_HOME_ARTIFACT_FINDINGS: usize = 768;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceHomeArtifactStatus {
    /// The sealed journal commit equals the canonical Home ref commit. This
    /// says nothing about the archive manifest or retained blob contents.
    RetainedRefMatched,
    /// A durable staged capture has published its ref but has not been sealed.
    PublishedPendingSeal,
    /// A durable staged capture does not yet have a Home namespace ref.
    PendingCapture,
    /// A sealed journal reference has no matching canonical Home ref.
    Missing,
    /// A sealed journal commit differs from the canonical Home ref commit.
    Conflicting,
    /// A retained Home ref is unmatched or its name/object cannot be trusted.
    ProtectedUnresolved,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceHomeArtifactFinding {
    artifact_id: Option<HomeArtifactId>,
    status: WorkspaceHomeArtifactStatus,
}

impl WorkspaceHomeArtifactFinding {
    pub const fn artifact_id(self) -> Option<HomeArtifactId> {
        self.artifact_id
    }

    pub const fn status(self) -> WorkspaceHomeArtifactStatus {
        self.status
    }
}

/// Bounded Home journal/ref observations. `metadata_only()` is always true:
/// matching IDs and commits do not prove archive content integrity.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceHomeArtifactDoctorReport {
    findings: Vec<WorkspaceHomeArtifactFinding>,
    database_truncated: bool,
    refs_truncated: bool,
    findings_truncated: bool,
}

impl WorkspaceHomeArtifactDoctorReport {
    pub fn findings(&self) -> &[WorkspaceHomeArtifactFinding] {
        &self.findings
    }

    pub const fn database_truncated(&self) -> bool {
        self.database_truncated
    }

    pub const fn refs_truncated(&self) -> bool {
        self.refs_truncated
    }

    pub const fn findings_truncated(&self) -> bool {
        self.findings_truncated
    }

    pub const fn is_complete(&self) -> bool {
        !self.database_truncated && !self.refs_truncated && !self.findings_truncated
    }

    pub const fn metadata_only(&self) -> bool {
        true
    }

    pub(super) fn has_damage(&self) -> bool {
        self.findings.iter().any(|finding| {
            matches!(
                finding.status(),
                WorkspaceHomeArtifactStatus::Missing | WorkspaceHomeArtifactStatus::Conflicting
            )
        })
    }

    pub(super) fn requires_recovery(&self) -> bool {
        self.findings.iter().any(|finding| {
            matches!(
                finding.status(),
                WorkspaceHomeArtifactStatus::PublishedPendingSeal
                    | WorkspaceHomeArtifactStatus::PendingCapture
                    | WorkspaceHomeArtifactStatus::ProtectedUnresolved
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DatabaseReference {
    artifact_id: HomeArtifactId,
    expected_commit: Option<GitCommitId>,
}

impl From<&HomeArtifactDoctorReference> for DatabaseReference {
    fn from(reference: &HomeArtifactDoctorReference) -> Self {
        Self {
            artifact_id: reference.artifact_id(),
            expected_commit: reference.expected_commit(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HomeArtifactStoreSource {
    Missing,
    Present(HomeArtifactRefInventory),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HomeArtifactObservation {
    report: WorkspaceHomeArtifactDoctorReport,
    source: HomeArtifactStoreSource,
}

impl HomeArtifactObservation {
    pub(super) fn into_report(self) -> WorkspaceHomeArtifactDoctorReport {
        self.report
    }

    /// Re-read the exact bounded namespace inventory observed on the first
    /// pass. Any open/inventory error makes the cross-authority observation
    /// unstable instead of turning an unknown state into an empty inventory.
    pub(super) fn source_is_unchanged(&self, layout: &ExistingWorkspaceStateLayout) -> bool {
        let Ok(current_store) = GitCheckpointStore::inspect_existing_read_only(layout) else {
            return false;
        };
        match (&self.source, current_store) {
            (HomeArtifactStoreSource::Missing, None) => true,
            (HomeArtifactStoreSource::Missing, Some(_))
            | (HomeArtifactStoreSource::Present(_), None) => false,
            (HomeArtifactStoreSource::Present(expected), Some(store)) => {
                matches!(
                    HomeArtifactStore::new(&store)
                        .inventory_refs_read_only(HomeArtifactRefInventoryLimit::DEFAULT),
                    Ok(current) if current == *expected
                )
            }
        }
    }
}

pub(super) fn observe_home_artifacts(
    database: &HomeArtifactDoctorReport,
    layout: &ExistingWorkspaceStateLayout,
) -> Result<HomeArtifactObservation, ControlError> {
    let references = database
        .references()
        .iter()
        .map(DatabaseReference::from)
        .collect::<Vec<_>>();
    let source = observe_store_source(layout)?;
    let (refs, refs_truncated) = match &source {
        HomeArtifactStoreSource::Missing => (&[][..], false),
        HomeArtifactStoreSource::Present(inventory) => (inventory.entries(), inventory.truncated()),
    };
    let report =
        compose_home_artifact_report(&references, database.truncated(), refs, refs_truncated);
    Ok(HomeArtifactObservation { report, source })
}

fn observe_store_source(
    layout: &ExistingWorkspaceStateLayout,
) -> Result<HomeArtifactStoreSource, ControlError> {
    let Some(store) =
        GitCheckpointStore::inspect_existing_read_only(layout).map_err(map_git_error)?
    else {
        return Ok(HomeArtifactStoreSource::Missing);
    };
    let inventory = HomeArtifactStore::new(&store)
        .inventory_refs_read_only(HomeArtifactRefInventoryLimit::DEFAULT)
        .map_err(map_home_artifact_error)?;
    Ok(HomeArtifactStoreSource::Present(inventory))
}

fn compose_home_artifact_report(
    database: &[DatabaseReference],
    database_truncated: bool,
    refs: &[HomeArtifactRefInventoryEntry],
    refs_truncated: bool,
) -> WorkspaceHomeArtifactDoctorReport {
    let mut refs_by_id = BTreeMap::<HomeArtifactId, Vec<GitCommitId>>::new();
    let mut protected_unknown_count = 0_usize;
    for entry in refs {
        match entry {
            HomeArtifactRefInventoryEntry::Retained {
                artifact_id,
                commit_id,
            } => refs_by_id.entry(*artifact_id).or_default().push(*commit_id),
            HomeArtifactRefInventoryEntry::ProtectedUnknown { .. } => {
                protected_unknown_count = protected_unknown_count.saturating_add(1);
            }
        }
    }

    let database_by_id = database
        .iter()
        .map(|reference| (reference.artifact_id, reference))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::with_capacity(
        database
            .len()
            .saturating_add(refs_by_id.len())
            .saturating_add(protected_unknown_count),
    );

    for reference in database {
        let actual_commits = refs_by_id.get(&reference.artifact_id);
        let status = match (reference.expected_commit, actual_commits.map(Vec::as_slice)) {
            (None, None) => WorkspaceHomeArtifactStatus::PendingCapture,
            (None, Some(_)) => WorkspaceHomeArtifactStatus::PublishedPendingSeal,
            (Some(_), None) => WorkspaceHomeArtifactStatus::Missing,
            (Some(expected), Some([actual])) if expected == *actual => {
                WorkspaceHomeArtifactStatus::RetainedRefMatched
            }
            (Some(_), Some(_)) => WorkspaceHomeArtifactStatus::Conflicting,
        };
        findings.push(WorkspaceHomeArtifactFinding {
            artifact_id: Some(reference.artifact_id),
            status,
        });
    }

    for entry in refs {
        match entry {
            HomeArtifactRefInventoryEntry::Retained { artifact_id, .. }
                if !database_by_id.contains_key(artifact_id) =>
            {
                findings.push(WorkspaceHomeArtifactFinding {
                    artifact_id: Some(*artifact_id),
                    status: WorkspaceHomeArtifactStatus::ProtectedUnresolved,
                });
            }
            HomeArtifactRefInventoryEntry::ProtectedUnknown { .. } => {
                findings.push(WorkspaceHomeArtifactFinding {
                    artifact_id: None,
                    status: WorkspaceHomeArtifactStatus::ProtectedUnresolved,
                });
            }
            HomeArtifactRefInventoryEntry::Retained { .. } => {}
        }
    }

    findings.sort_by_key(|finding| finding.artifact_id());
    let findings_truncated = findings.len() > MAX_WORKSPACE_HOME_ARTIFACT_FINDINGS;
    findings.truncate(MAX_WORKSPACE_HOME_ARTIFACT_FINDINGS);
    WorkspaceHomeArtifactDoctorReport {
        findings,
        database_truncated,
        refs_truncated,
        findings_truncated,
    }
}

fn map_git_error(error: forge_workspace::GitSafetyError) -> ControlError {
    ControlError::with_source(ControlErrorCode::WorkspaceStateUnavailable, error)
}

fn map_home_artifact_error(error: HomeArtifactStoreError) -> ControlError {
    ControlError::with_source(ControlErrorCode::WorkspaceStateUnavailable, error)
}

#[cfg(test)]
pub(super) fn incomplete_report_for_test() -> WorkspaceHomeArtifactDoctorReport {
    compose_home_artifact_report(&[], true, &[], false)
}

#[cfg(test)]
mod tests;
