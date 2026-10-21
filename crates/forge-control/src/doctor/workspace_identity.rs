//! Bounded read-only aggregate Doctor for durable Workspace identity across registered Locations.

use std::collections::{BTreeMap, BTreeSet};

use forge_domain::{LocationId, LocationListLimit, LocationState, RegisteredLocation, WorkspaceId};
use forge_persistence::WorkspaceStore;
use forge_workspace::{WorkspaceCandidate, WorkspaceStateLayout};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, map_location_error};

pub const WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS: usize = 32;
const WORKSPACE_IDENTITY_DOCTOR_LOCATION_PROBE: usize = WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS + 1;
const WORKSPACE_IDENTITY_DOCTOR_MAX_FINDINGS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIdentityDoctorOutcome {
    Healthy,
    Damaged,
    Incomplete,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIdentityDuplicateFinding {
    workspace_id: WorkspaceId,
    location_ids: Vec<LocationId>,
    observation_count: usize,
}

impl WorkspaceIdentityDuplicateFinding {
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn location_ids(&self) -> &[LocationId] {
        &self.location_ids
    }

    pub const fn observation_count(&self) -> usize {
        self.observation_count
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkspaceLocationMismatchFinding {
    workspace: WorkspaceId,
    observed_location: LocationId,
    stored_location: LocationId,
}

impl WorkspaceLocationMismatchFinding {
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace
    }

    pub const fn observed_location_id(self) -> LocationId {
        self.observed_location
    }

    pub const fn stored_location_id(self) -> LocationId {
        self.stored_location
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIdentityDoctorReport {
    duplicates: Vec<WorkspaceIdentityDuplicateFinding>,
    location_mismatches: Vec<WorkspaceLocationMismatchFinding>,
    unavailable_locations: Vec<LocationId>,
    disabled_locations: Vec<LocationId>,
    unavailable_candidates: usize,
    scanned_locations: usize,
    scanned_candidates: usize,
    locations_truncated: bool,
    findings_truncated: bool,
    outcome: WorkspaceIdentityDoctorOutcome,
}

impl WorkspaceIdentityDoctorReport {
    pub fn duplicates(&self) -> &[WorkspaceIdentityDuplicateFinding] {
        &self.duplicates
    }

    pub fn location_mismatches(&self) -> &[WorkspaceLocationMismatchFinding] {
        &self.location_mismatches
    }

    pub fn unavailable_locations(&self) -> &[LocationId] {
        &self.unavailable_locations
    }

    pub fn disabled_locations(&self) -> &[LocationId] {
        &self.disabled_locations
    }

    pub const fn unavailable_candidates(&self) -> usize {
        self.unavailable_candidates
    }

    pub const fn scanned_locations(&self) -> usize {
        self.scanned_locations
    }

    pub const fn scanned_candidates(&self) -> usize {
        self.scanned_candidates
    }

    pub const fn locations_truncated(&self) -> bool {
        self.locations_truncated
    }

    pub const fn findings_truncated(&self) -> bool {
        self.findings_truncated
    }

    pub const fn outcome(&self) -> WorkspaceIdentityDoctorOutcome {
        self.outcome
    }

    pub fn is_complete(&self) -> bool {
        !self.locations_truncated
            && !self.findings_truncated
            && self.unavailable_locations.is_empty()
            && self.disabled_locations.is_empty()
            && self.unavailable_candidates == 0
    }
}

#[derive(Default)]
struct WorkspaceIdentityScan {
    observations: BTreeMap<WorkspaceId, Vec<LocationId>>,
    location_mismatches: BTreeSet<WorkspaceLocationMismatchFinding>,
    unavailable_locations: Vec<LocationId>,
    disabled_locations: Vec<LocationId>,
    unavailable_candidates: usize,
    scanned_locations: usize,
    scanned_candidates: usize,
}

impl WorkspaceIdentityScan {
    fn observe_location(&mut self, control: &ForgeControl, location: &RegisteredLocation) {
        if location.state() == LocationState::Disabled {
            self.disabled_locations.push(location.id());
            return;
        }
        let Ok(discovery) = control
            .locations
            .discover_current(location.id(), location.revision())
        else {
            self.unavailable_locations.push(location.id());
            return;
        };
        self.scanned_locations = self.scanned_locations.saturating_add(1);
        for candidate in discovery.candidates() {
            self.observe_candidate(location.id(), candidate);
        }
    }

    fn observe_candidate(&mut self, location_id: LocationId, candidate: &WorkspaceCandidate) {
        self.scanned_candidates = self.scanned_candidates.saturating_add(1);
        let layout = match WorkspaceStateLayout::inspect_existing(candidate.absolute_root()) {
            Ok(Some(layout)) => layout,
            Ok(None) => return,
            Err(_) => {
                self.unavailable_candidates = self.unavailable_candidates.saturating_add(1);
                return;
            }
        };
        let Ok(workspace) = WorkspaceStore::inspect_existing_identity_read_only(&layout) else {
            self.unavailable_candidates = self.unavailable_candidates.saturating_add(1);
            return;
        };
        self.observations
            .entry(workspace.id())
            .or_default()
            .push(location_id);
        if workspace.location_id() != location_id {
            self.location_mismatches
                .insert(WorkspaceLocationMismatchFinding {
                    workspace: workspace.id(),
                    observed_location: location_id,
                    stored_location: workspace.location_id(),
                });
        }
    }

    fn finish(mut self, locations_truncated: bool) -> WorkspaceIdentityDoctorReport {
        let mut duplicates = self
            .observations
            .into_iter()
            .filter(|(_, observations)| observations.len() > 1)
            .map(|(workspace_id, observations)| {
                let observation_count = observations.len();
                let location_ids = observations.into_iter().collect::<BTreeSet<_>>();
                WorkspaceIdentityDuplicateFinding {
                    workspace_id,
                    location_ids: location_ids.into_iter().collect(),
                    observation_count,
                }
            })
            .collect::<Vec<_>>();
        let mut location_mismatches = self.location_mismatches.into_iter().collect::<Vec<_>>();
        let finding_count = duplicates.len().saturating_add(location_mismatches.len());
        let findings_truncated = finding_count > WORKSPACE_IDENTITY_DOCTOR_MAX_FINDINGS;
        duplicates.truncate(WORKSPACE_IDENTITY_DOCTOR_MAX_FINDINGS);
        let remaining = WORKSPACE_IDENTITY_DOCTOR_MAX_FINDINGS.saturating_sub(duplicates.len());
        location_mismatches.truncate(remaining);
        self.unavailable_locations.sort_unstable();
        self.disabled_locations.sort_unstable();
        let damaged = !duplicates.is_empty() || !location_mismatches.is_empty();
        let incomplete = locations_truncated
            || findings_truncated
            || !self.unavailable_locations.is_empty()
            || !self.disabled_locations.is_empty()
            || self.unavailable_candidates != 0;
        let outcome = if damaged {
            WorkspaceIdentityDoctorOutcome::Damaged
        } else if incomplete {
            WorkspaceIdentityDoctorOutcome::Incomplete
        } else {
            WorkspaceIdentityDoctorOutcome::Healthy
        };
        WorkspaceIdentityDoctorReport {
            duplicates,
            location_mismatches,
            unavailable_locations: self.unavailable_locations,
            disabled_locations: self.disabled_locations,
            unavailable_candidates: self.unavailable_candidates,
            scanned_locations: self.scanned_locations,
            scanned_candidates: self.scanned_candidates,
            locations_truncated,
            findings_truncated,
            outcome,
        }
    }
}

impl ForgeControl {
    /// Scan registered Locations for duplicate durable Workspace identities.
    ///
    /// This operation is strictly observational. It never initializes a
    /// Workspace, migrates a database, changes Location state, or repairs a
    /// duplicate. Disabled Locations remain explicitly unobserved, making the
    /// report incomplete rather than pretending that all registered authority
    /// was checked.
    pub fn workspace_identity_doctor(&self) -> Result<WorkspaceIdentityDoctorReport, ControlError> {
        let limit_value = u32::try_from(WORKSPACE_IDENTITY_DOCTOR_LOCATION_PROBE)
            .map_err(|_| ControlError::new(ControlErrorCode::Internal))?;
        let limit = LocationListLimit::new(limit_value)
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let mut locations = self
            .locations
            .list_locations(limit)
            .map_err(map_location_error)?;
        let locations_truncated = locations.len() > WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS;
        locations.truncate(WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS);
        let mut scan = WorkspaceIdentityScan::default();
        for location in &locations {
            scan.observe_location(self, location);
        }
        Ok(scan.finish(locations_truncated))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        EstablishWorkspace, LocationId, LocationState, SetLocationState, TimestampMillis,
        WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::GlobalRegistry;
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: std::path::PathBuf,
        locations: LocationService<GlobalRegistry>,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-identity-doctor-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        Ok(Fixture {
            root,
            locations: LocationService::new(registry),
        })
    }

    fn register_location(
        fixture: &mut Fixture,
        seed: u128,
        root: &Path,
    ) -> Result<forge_domain::RegisteredLocation, Box<dyn std::error::Error>> {
        fs::create_dir_all(root)?;
        Ok(fixture.locations.register_selected_path(
            LocationId::from_uuid(Uuid::from_u128(seed)),
            format!("Location {seed}"),
            root,
            timestamp(1)?,
        )?)
    }

    fn establish_workspace(
        root: &Path,
        location_id: LocationId,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspaceStore, Box<dyn std::error::Error>> {
        fs::create_dir_all(root)?;
        let layout = WorkspaceStateLayout::initialize(root)?;
        Ok(WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                timestamp(2)?,
            ),
        )?)
    }

    #[test]
    fn bounded_worker_round_trips_workspace_identity_doctor()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("worker-round-trip")?;
        let control = ForgeControl::from_location_service(
            fixture.locations,
            fixture.root.join("agent-sessions.sqlite3"),
        );
        let (client, mut worker) = control.start_worker()?;

        let report = client.workspace_identity_doctor()?;
        assert_eq!(report.outcome(), WorkspaceIdentityDoctorOutcome::Healthy);
        assert!(report.is_complete());
        assert_eq!(report.scanned_locations(), 0);
        assert_eq!(report.scanned_candidates(), 0);

        worker.shutdown()?;
        drop(client);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn unique_workspace_identities_across_locations_are_healthy()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("healthy")?;
        let first_root = fixture.root.join("first");
        let second_root = fixture.root.join("second");
        let first = register_location(&mut fixture, 0xA100, &first_root)?;
        let second = register_location(&mut fixture, 0xA101, &second_root)?;
        let first_store = establish_workspace(
            &first_root.join("workspace"),
            first.id(),
            WorkspaceId::from_uuid(Uuid::from_u128(0xA200)),
        )?;
        let second_store = establish_workspace(
            &second_root.join("workspace"),
            second.id(),
            WorkspaceId::from_uuid(Uuid::from_u128(0xA201)),
        )?;
        let control = ForgeControl::from_location_service(
            fixture.locations,
            fixture.root.join("agent-sessions.sqlite3"),
        );

        let report = control.workspace_identity_doctor()?;
        assert_eq!(report.outcome(), WorkspaceIdentityDoctorOutcome::Healthy);
        assert!(report.is_complete());
        assert!(report.duplicates().is_empty());
        assert!(report.location_mismatches().is_empty());

        drop(control);
        drop(first_store);
        drop(second_store);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn overlapping_locations_surface_duplicate_and_stored_location_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("duplicate")?;
        let parent_root = fixture.root.join("parent");
        let workspace_root = parent_root.join("shared");
        let parent = register_location(&mut fixture, 0xB100, &parent_root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xB200));
        let store = establish_workspace(&workspace_root, parent.id(), workspace_id)?;
        let nested = register_location(&mut fixture, 0xB101, &workspace_root)?;
        let control = ForgeControl::from_location_service(
            fixture.locations,
            fixture.root.join("agent-sessions.sqlite3"),
        );

        let report = control.workspace_identity_doctor()?;
        assert_eq!(report.outcome(), WorkspaceIdentityDoctorOutcome::Damaged);
        assert_eq!(report.duplicates().len(), 1);
        assert_eq!(report.duplicates()[0].workspace_id(), workspace_id);
        assert_eq!(report.duplicates()[0].observation_count(), 2);
        assert_eq!(
            report.duplicates()[0].location_ids(),
            &[parent.id(), nested.id()]
        );
        assert!(report.location_mismatches().iter().any(|finding| {
            finding.workspace_id() == workspace_id
                && finding.observed_location_id() == nested.id()
                && finding.stored_location_id() == parent.id()
        }));

        drop(control);
        drop(store);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn duplicate_workspace_identity_inside_one_location_is_damaged()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("same-location-duplicate")?;
        let root = fixture.root.join("single-location");
        let location = register_location(&mut fixture, 0xB300, &root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xB400));
        let first_store = establish_workspace(&root.join("first"), location.id(), workspace_id)?;
        let second_store = establish_workspace(&root.join("second"), location.id(), workspace_id)?;
        let control = ForgeControl::from_location_service(
            fixture.locations,
            fixture.root.join("agent-sessions.sqlite3"),
        );

        let report = control.workspace_identity_doctor()?;
        assert_eq!(report.outcome(), WorkspaceIdentityDoctorOutcome::Damaged);
        assert_eq!(report.duplicates().len(), 1);
        assert_eq!(report.duplicates()[0].workspace_id(), workspace_id);
        assert_eq!(report.duplicates()[0].observation_count(), 2);
        assert_eq!(report.duplicates()[0].location_ids(), &[location.id()]);
        assert!(report.location_mismatches().is_empty());

        drop(control);
        drop(first_store);
        drop(second_store);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn disabled_registered_location_makes_global_coverage_incomplete()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("disabled")?;
        let root = fixture.root.join("disabled-location");
        let location = register_location(&mut fixture, 0xC100, &root)?;
        let disabled = fixture
            .locations
            .set_location_state(&SetLocationState::new(
                location.id(),
                location.revision(),
                LocationState::Disabled,
                timestamp(2)?,
            ))?;
        assert_eq!(disabled.state(), LocationState::Disabled);
        let control = ForgeControl::from_location_service(
            fixture.locations,
            fixture.root.join("agent-sessions.sqlite3"),
        );

        let report = control.workspace_identity_doctor()?;
        assert_eq!(report.outcome(), WorkspaceIdentityDoctorOutcome::Incomplete);
        assert_eq!(report.disabled_locations(), &[location.id()]);
        assert!(!report.is_complete());

        drop(control);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn location_probe_bound_marks_global_identity_scan_incomplete()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("location-bound")?;
        for offset in 0..=WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS {
            let seed = u128::try_from(offset)?;
            let root = fixture.root.join(format!("location-{offset}"));
            let _ = register_location(&mut fixture, 0xD100 + seed, &root)?;
        }
        let control = ForgeControl::from_location_service(
            fixture.locations,
            fixture.root.join("agent-sessions.sqlite3"),
        );

        let report = control.workspace_identity_doctor()?;
        assert_eq!(report.outcome(), WorkspaceIdentityDoctorOutcome::Incomplete);
        assert!(report.locations_truncated());
        assert_eq!(
            report.scanned_locations(),
            WORKSPACE_IDENTITY_DOCTOR_MAX_LOCATIONS
        );
        assert!(!report.is_complete());

        drop(control);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
