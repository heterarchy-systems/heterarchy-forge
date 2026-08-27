//! Read-only composition of durable checkpoint rows and the Forge-owned Git store.

use std::collections::{BTreeMap, BTreeSet};

use forge_domain::{CheckpointId, CheckpointState};
use forge_persistence::{CheckpointDoctorReport, CheckpointDoctorSnapshotReference};
use forge_workspace::{
    CheckpointSide, ExistingWorkspaceStateLayout, GitCheckpointObjectExpectation,
    GitCheckpointObjectVerification, GitCheckpointObjectVerificationStatus,
    GitCheckpointRefInventory, GitCheckpointRefInventoryEntry, GitCheckpointRefInventoryLimit,
    GitCheckpointStore, GitCheckpointStoreIntegrity, GitLocalStateDoctor, GitSafetyError,
};

use crate::error::{ControlError, ControlErrorCode};

const MAX_WORKSPACE_CHECKPOINT_FINDINGS: usize = 1_024;
type RefKey = (CheckpointId, CheckpointSide);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkspaceCheckpointStoreStatus {
    OwnedAvailable,
    Starting,
    RefMissing,
    RefMismatch,
    ObjectMissing,
    ObjectTypeMismatch,
    OrphanRef,
    Conflicting,
    Corrupt,
    StoreMissing,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceCheckpointStoreAvailability {
    NotApplicable,
    Missing,
    Present {
        integrity: GitCheckpointStoreIntegrity,
    },
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceCheckpointStoreFinding {
    checkpoint_id: Option<CheckpointId>,
    side: Option<CheckpointSide>,
    status: WorkspaceCheckpointStoreStatus,
}

impl WorkspaceCheckpointStoreFinding {
    const fn new(
        checkpoint_id: Option<CheckpointId>,
        side: Option<CheckpointSide>,
        status: WorkspaceCheckpointStoreStatus,
    ) -> Self {
        Self {
            checkpoint_id,
            side,
            status,
        }
    }

    pub const fn checkpoint_id(self) -> Option<CheckpointId> {
        self.checkpoint_id
    }

    pub const fn side(self) -> Option<CheckpointSide> {
        self.side
    }

    pub const fn status(self) -> WorkspaceCheckpointStoreStatus {
        self.status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkspaceCheckpointStoreCoverage {
    database_truncated: bool,
    refs_truncated: bool,
    findings_truncated: bool,
}

impl WorkspaceCheckpointStoreCoverage {
    const fn is_complete(self) -> bool {
        !self.database_truncated && !self.refs_truncated && !self.findings_truncated
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCheckpointStoreReport {
    findings: Vec<WorkspaceCheckpointStoreFinding>,
    availability: WorkspaceCheckpointStoreAvailability,
    coverage: WorkspaceCheckpointStoreCoverage,
}

impl WorkspaceCheckpointStoreReport {
    pub fn findings(&self) -> &[WorkspaceCheckpointStoreFinding] {
        &self.findings
    }

    pub const fn availability(&self) -> WorkspaceCheckpointStoreAvailability {
        self.availability
    }

    pub const fn applicable(&self) -> bool {
        !matches!(
            self.availability,
            WorkspaceCheckpointStoreAvailability::NotApplicable
        )
    }

    pub const fn store_present(&self) -> bool {
        matches!(
            self.availability,
            WorkspaceCheckpointStoreAvailability::Present { .. }
        )
    }

    pub const fn store_integrity(&self) -> Option<GitCheckpointStoreIntegrity> {
        match self.availability {
            WorkspaceCheckpointStoreAvailability::Present { integrity } => Some(integrity),
            WorkspaceCheckpointStoreAvailability::NotApplicable
            | WorkspaceCheckpointStoreAvailability::Missing => None,
        }
    }

    pub const fn database_truncated(&self) -> bool {
        self.coverage.database_truncated
    }

    pub const fn refs_truncated(&self) -> bool {
        self.coverage.refs_truncated
    }

    pub const fn findings_truncated(&self) -> bool {
        self.coverage.findings_truncated
    }

    pub const fn is_complete(&self) -> bool {
        self.coverage.is_complete()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CheckpointStoreSourceObservation {
    NotApplicable,
    MissingNonGit,
    MissingOwnedStore,
    Present {
        inventory: GitCheckpointRefInventory,
        verifications: Vec<GitCheckpointObjectVerification>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CheckpointStoreObservation {
    report: WorkspaceCheckpointStoreReport,
    source: CheckpointStoreSourceObservation,
}

impl CheckpointStoreObservation {
    pub(super) fn into_report(self) -> WorkspaceCheckpointStoreReport {
        self.report
    }

    pub(super) fn source_is_unchanged(
        &self,
        database: &CheckpointDoctorReport,
        layout: &ExistingWorkspaceStateLayout,
    ) -> bool {
        match &self.source {
            CheckpointStoreSourceObservation::NotApplicable
            | CheckpointStoreSourceObservation::MissingNonGit => true,
            CheckpointStoreSourceObservation::MissingOwnedStore => {
                matches!(
                    GitCheckpointStore::inspect_existing_read_only(layout),
                    Ok(None)
                )
            }
            CheckpointStoreSourceObservation::Present {
                inventory,
                verifications,
            } => {
                let Ok(Some(store)) = GitCheckpointStore::inspect_existing_read_only(layout) else {
                    return false;
                };
                let Ok(current_inventory) =
                    store.inventory_refs_read_only(GitCheckpointRefInventoryLimit::DEFAULT)
                else {
                    return false;
                };
                if current_inventory != *inventory {
                    return false;
                }
                let expectations = collect_object_expectations(database);
                matches!(
                    store.verify_objects_read_only(&expectations),
                    Ok(current) if current == *verifications
                )
            }
        }
    }
}

pub(super) fn observe_checkpoint_store(
    database: &CheckpointDoctorReport,
    git_state: GitLocalStateDoctor,
    layout: &ExistingWorkspaceStateLayout,
) -> Result<CheckpointStoreObservation, ControlError> {
    if git_state == GitLocalStateDoctor::NotGitRepository {
        let report = if database.references().is_empty() {
            empty_report(
                WorkspaceCheckpointStoreAvailability::NotApplicable,
                database.truncated(),
            )
        } else {
            missing_store_report(database)
        };
        return Ok(CheckpointStoreObservation {
            report,
            source: if database.references().is_empty() {
                CheckpointStoreSourceObservation::NotApplicable
            } else {
                CheckpointStoreSourceObservation::MissingNonGit
            },
        });
    }
    let Some(store) = GitCheckpointStore::inspect_existing_read_only(layout)
        .map_err(map_checkpoint_store_error)?
    else {
        return Ok(CheckpointStoreObservation {
            report: missing_store_report(database),
            source: CheckpointStoreSourceObservation::MissingOwnedStore,
        });
    };
    observe_existing_store(database, &store)
}

fn observe_existing_store(
    database: &CheckpointDoctorReport,
    store: &GitCheckpointStore,
) -> Result<CheckpointStoreObservation, ControlError> {
    let inventory = store
        .inventory_refs_read_only(GitCheckpointRefInventoryLimit::DEFAULT)
        .map_err(map_checkpoint_store_error)?;
    let expectations = collect_object_expectations(database);
    let verifications = store
        .verify_objects_read_only(&expectations)
        .map_err(map_checkpoint_store_error)?;
    let mut composition = CheckpointComposition::new(database, &inventory, verifications.clone());
    composition.classify_database(database);
    composition.classify_unmatched_refs();
    composition.record_store_integrity(inventory.integrity());
    Ok(CheckpointStoreObservation {
        report: composition.finish(inventory.integrity()),
        source: CheckpointStoreSourceObservation::Present {
            inventory,
            verifications,
        },
    })
}

fn empty_report(
    availability: WorkspaceCheckpointStoreAvailability,
    database_truncated: bool,
) -> WorkspaceCheckpointStoreReport {
    WorkspaceCheckpointStoreReport {
        findings: Vec::new(),
        availability,
        coverage: WorkspaceCheckpointStoreCoverage {
            database_truncated,
            refs_truncated: false,
            findings_truncated: false,
        },
    }
}

fn missing_store_report(database: &CheckpointDoctorReport) -> WorkspaceCheckpointStoreReport {
    let findings = database
        .references()
        .iter()
        .map(|reference| {
            WorkspaceCheckpointStoreFinding::new(
                Some(reference.checkpoint_id()),
                None,
                WorkspaceCheckpointStoreStatus::StoreMissing,
            )
        })
        .collect::<Vec<_>>();
    finish_report(
        findings,
        WorkspaceCheckpointStoreAvailability::Missing,
        database.truncated(),
        false,
    )
}

struct CheckpointComposition {
    refs_by_key: BTreeMap<RefKey, GitCheckpointRefInventoryEntry>,
    object_statuses:
        BTreeMap<GitCheckpointObjectExpectation, GitCheckpointObjectVerificationStatus>,
    matched_refs: BTreeSet<RefKey>,
    findings: Vec<WorkspaceCheckpointStoreFinding>,
    database_truncated: bool,
    refs_truncated: bool,
}

impl CheckpointComposition {
    fn new(
        database: &CheckpointDoctorReport,
        inventory: &GitCheckpointRefInventory,
        verifications: Vec<GitCheckpointObjectVerification>,
    ) -> Self {
        let mut composition = Self {
            refs_by_key: BTreeMap::new(),
            object_statuses: verifications
                .into_iter()
                .map(|item| (item.expectation(), item.status()))
                .collect(),
            matched_refs: BTreeSet::new(),
            findings: Vec::with_capacity(
                database
                    .references()
                    .len()
                    .saturating_mul(3)
                    .saturating_add(inventory.entries().len()),
            ),
            database_truncated: database.truncated(),
            refs_truncated: inventory.truncated(),
        };
        composition.index_refs(inventory.entries());
        composition
    }

    fn index_refs(&mut self, entries: &[GitCheckpointRefInventoryEntry]) {
        for entry in entries.iter().copied() {
            let (Some(checkpoint_id), Some(side)) = (entry.checkpoint_id(), entry.side()) else {
                self.push(None, None, WorkspaceCheckpointStoreStatus::Corrupt);
                continue;
            };
            if self
                .refs_by_key
                .insert((checkpoint_id, side), entry)
                .is_some()
            {
                self.push(
                    Some(checkpoint_id),
                    Some(side),
                    WorkspaceCheckpointStoreStatus::Conflicting,
                );
            }
        }
    }

    fn classify_database(&mut self, database: &CheckpointDoctorReport) {
        for reference in database.references().iter().copied() {
            self.classify_expected_side(
                reference.checkpoint_id(),
                CheckpointSide::Pre,
                reference.pre(),
            );
            match reference.state() {
                CheckpointState::Starting => self.classify_starting(reference.checkpoint_id()),
                CheckpointState::Ready => match reference.post() {
                    Some(post) => self.classify_expected_side(
                        reference.checkpoint_id(),
                        CheckpointSide::Post,
                        post,
                    ),
                    None => self.push(
                        Some(reference.checkpoint_id()),
                        Some(CheckpointSide::Post),
                        WorkspaceCheckpointStoreStatus::Corrupt,
                    ),
                },
            }
        }
    }

    fn classify_starting(&mut self, checkpoint_id: CheckpointId) {
        let post_key = (checkpoint_id, CheckpointSide::Post);
        if let Some(entry) = self.refs_by_key.get(&post_key).copied() {
            self.matched_refs.insert(post_key);
            let status = match entry {
                // A retained POST ref with a durable Starting row is the honest
                // crash window where Git capture committed but the SQLite Ready
                // CAS did not. Recovery must inspect it; Doctor must not call it
                // corruption merely because the journal projection lagged.
                GitCheckpointRefInventoryEntry::Retained { .. } => {
                    WorkspaceCheckpointStoreStatus::Starting
                }
                GitCheckpointRefInventoryEntry::NonCommit { .. }
                | GitCheckpointRefInventoryEntry::Malformed => {
                    WorkspaceCheckpointStoreStatus::Corrupt
                }
            };
            self.push(Some(checkpoint_id), Some(CheckpointSide::Post), status);
        }
        self.push(
            Some(checkpoint_id),
            None,
            WorkspaceCheckpointStoreStatus::Starting,
        );
    }

    fn classify_expected_side(
        &mut self,
        checkpoint_id: CheckpointId,
        side: CheckpointSide,
        expected: CheckpointDoctorSnapshotReference,
    ) {
        let key = (checkpoint_id, side);
        let Some(entry) = self.refs_by_key.get(&key).copied() else {
            let status = if self.refs_truncated {
                WorkspaceCheckpointStoreStatus::Unverified
            } else {
                WorkspaceCheckpointStoreStatus::RefMissing
            };
            self.push(Some(checkpoint_id), Some(side), status);
            return;
        };
        self.matched_refs.insert(key);
        let status = match entry {
            GitCheckpointRefInventoryEntry::Malformed
            | GitCheckpointRefInventoryEntry::NonCommit { .. } => {
                WorkspaceCheckpointStoreStatus::Corrupt
            }
            GitCheckpointRefInventoryEntry::Retained { commit, .. }
                if commit != expected.commit() =>
            {
                WorkspaceCheckpointStoreStatus::RefMismatch
            }
            GitCheckpointRefInventoryEntry::Retained { .. } => {
                expected_object_status(expected, &self.object_statuses)
            }
        };
        self.push(Some(checkpoint_id), Some(side), status);
    }

    fn classify_unmatched_refs(&mut self) {
        let unmatched = self
            .refs_by_key
            .iter()
            .filter(|(key, _)| !self.matched_refs.contains(key))
            .map(|(key, entry)| (*key, *entry))
            .collect::<Vec<_>>();
        for ((checkpoint_id, side), entry) in unmatched {
            let status = if self.database_truncated {
                WorkspaceCheckpointStoreStatus::Unverified
            } else {
                match entry {
                    GitCheckpointRefInventoryEntry::Retained { .. } => {
                        WorkspaceCheckpointStoreStatus::OrphanRef
                    }
                    GitCheckpointRefInventoryEntry::NonCommit { .. }
                    | GitCheckpointRefInventoryEntry::Malformed => {
                        WorkspaceCheckpointStoreStatus::Corrupt
                    }
                }
            };
            self.push(Some(checkpoint_id), Some(side), status);
        }
    }

    fn record_store_integrity(&mut self, integrity: GitCheckpointStoreIntegrity) {
        if integrity == GitCheckpointStoreIntegrity::Damaged {
            self.push(None, None, WorkspaceCheckpointStoreStatus::Corrupt);
        }
    }

    fn push(
        &mut self,
        checkpoint_id: Option<CheckpointId>,
        side: Option<CheckpointSide>,
        status: WorkspaceCheckpointStoreStatus,
    ) {
        self.findings.push(WorkspaceCheckpointStoreFinding::new(
            checkpoint_id,
            side,
            status,
        ));
    }

    fn finish(self, integrity: GitCheckpointStoreIntegrity) -> WorkspaceCheckpointStoreReport {
        finish_report(
            self.findings,
            WorkspaceCheckpointStoreAvailability::Present { integrity },
            self.database_truncated,
            self.refs_truncated,
        )
    }
}

fn expected_object_status(
    expected: CheckpointDoctorSnapshotReference,
    statuses: &BTreeMap<GitCheckpointObjectExpectation, GitCheckpointObjectVerificationStatus>,
) -> WorkspaceCheckpointStoreStatus {
    let commit = statuses.get(&GitCheckpointObjectExpectation::Commit(expected.commit()));
    let blob = expected
        .blob()
        .map(|value| statuses.get(&GitCheckpointObjectExpectation::Blob(value)));
    if commit == Some(&GitCheckpointObjectVerificationStatus::Missing)
        || blob == Some(Some(&GitCheckpointObjectVerificationStatus::Missing))
    {
        WorkspaceCheckpointStoreStatus::ObjectMissing
    } else if commit == Some(&GitCheckpointObjectVerificationStatus::TypeMismatch)
        || blob == Some(Some(&GitCheckpointObjectVerificationStatus::TypeMismatch))
    {
        WorkspaceCheckpointStoreStatus::ObjectTypeMismatch
    } else if commit == Some(&GitCheckpointObjectVerificationStatus::Present)
        && blob.is_none_or(|status| status == Some(&GitCheckpointObjectVerificationStatus::Present))
    {
        WorkspaceCheckpointStoreStatus::OwnedAvailable
    } else {
        WorkspaceCheckpointStoreStatus::Unverified
    }
}

fn collect_object_expectations(
    database: &CheckpointDoctorReport,
) -> Vec<GitCheckpointObjectExpectation> {
    let mut expectations = BTreeSet::new();
    for reference in database.references().iter().copied() {
        insert_snapshot_expectations(&mut expectations, reference.pre());
        if let Some(post) = reference.post() {
            insert_snapshot_expectations(&mut expectations, post);
        }
    }
    expectations.into_iter().collect()
}

fn insert_snapshot_expectations(
    expectations: &mut BTreeSet<GitCheckpointObjectExpectation>,
    snapshot: CheckpointDoctorSnapshotReference,
) {
    expectations.insert(GitCheckpointObjectExpectation::Commit(snapshot.commit()));
    if let Some(blob) = snapshot.blob() {
        expectations.insert(GitCheckpointObjectExpectation::Blob(blob));
    }
}

fn finish_report(
    mut findings: Vec<WorkspaceCheckpointStoreFinding>,
    availability: WorkspaceCheckpointStoreAvailability,
    database_truncated: bool,
    refs_truncated: bool,
) -> WorkspaceCheckpointStoreReport {
    findings.sort_by_key(|finding| (finding.checkpoint_id(), finding.side(), finding.status()));
    let findings_truncated = findings.len() > MAX_WORKSPACE_CHECKPOINT_FINDINGS;
    findings.truncate(MAX_WORKSPACE_CHECKPOINT_FINDINGS);
    WorkspaceCheckpointStoreReport {
        findings,
        availability,
        coverage: WorkspaceCheckpointStoreCoverage {
            database_truncated,
            refs_truncated,
            findings_truncated,
        },
    }
}

fn map_checkpoint_store_error(error: GitSafetyError) -> ControlError {
    ControlError::with_source(ControlErrorCode::CheckpointUnavailable, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::GitCommitId;
    use uuid::Uuid;

    #[test]
    fn retained_post_for_starting_checkpoint_is_recovery_not_corruption() {
        let checkpoint_id = CheckpointId::from_uuid(Uuid::from_u128(0xCAFE));
        let key = (checkpoint_id, CheckpointSide::Post);
        let mut composition = CheckpointComposition {
            refs_by_key: BTreeMap::from([(
                key,
                GitCheckpointRefInventoryEntry::Retained {
                    checkpoint_id,
                    side: CheckpointSide::Post,
                    commit: GitCommitId::from_sha1_bytes([7; 20]),
                },
            )]),
            object_statuses: BTreeMap::new(),
            matched_refs: BTreeSet::new(),
            findings: Vec::new(),
            database_truncated: false,
            refs_truncated: false,
        };

        composition.classify_starting(checkpoint_id);

        assert!(composition.findings.iter().any(|finding| {
            finding.checkpoint_id() == Some(checkpoint_id)
                && finding.side() == Some(CheckpointSide::Post)
                && finding.status() == WorkspaceCheckpointStoreStatus::Starting
        }));
        assert!(!composition.findings.iter().any(|finding| {
            matches!(
                finding.status(),
                WorkspaceCheckpointStoreStatus::Conflicting
                    | WorkspaceCheckpointStoreStatus::Corrupt
            )
        }));
    }
}
