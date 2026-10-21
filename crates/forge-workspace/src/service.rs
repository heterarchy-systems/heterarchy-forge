use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use forge_domain::{
    LocationId, LocationListLimit, LocationName, LocationNameError, LocationRevision, LocationRoot,
    LocationRootError, RegisterLocation, RegisteredLocation, SetLocationState, TimestampMillis,
};
use thiserror::Error;

use crate::discovery::resolve_locator_candidate;
use crate::{
    WorkspaceCandidate, WorkspaceCandidateKey, WorkspaceDiscovery, WorkspaceDiscoveryError,
    WorkspaceKeyResolveError, WorkspaceLocator, WorkspaceLocatorError, WorkspaceResolveError,
    WorkspaceSelector,
};

pub type BoxedRepositoryError = Box<dyn Error + Send + Sync + 'static>;

/// Application-facing repository contract implemented by the durable registry adapter.
pub trait LocationRepository {
    fn register_location(
        &mut self,
        command: &RegisterLocation,
    ) -> Result<RegisteredLocation, LocationRepositoryError>;

    fn list_locations(
        &self,
        limit: LocationListLimit,
    ) -> Result<Vec<RegisteredLocation>, LocationRepositoryError>;

    fn get_location(
        &self,
        id: LocationId,
    ) -> Result<Option<RegisteredLocation>, LocationRepositoryError>;

    fn set_location_state(
        &mut self,
        command: &SetLocationState,
    ) -> Result<RegisteredLocation, LocationRepositoryError>;
}

#[derive(Debug, Error)]
pub enum LocationRepositoryError {
    #[error("Location root is already registered as {existing_id}")]
    AlreadyRegistered { existing_id: LocationId },
    #[error("Location identity already exists: {0}")]
    IdentityConflict(LocationId),
    #[error("Location was not found: {0}")]
    NotFound(LocationId),
    #[error("Location revision conflict for {id}: expected {expected}, actual {actual}")]
    RevisionConflict {
        id: LocationId,
        expected: LocationRevision,
        actual: LocationRevision,
    },
    #[error("Location revision overflow for {id} at {current}")]
    RevisionOverflow {
        id: LocationId,
        current: LocationRevision,
    },
    #[error("Location state commit for {id} requires durable readback")]
    CommittedUnconfirmed {
        id: LocationId,
        expected_revision: LocationRevision,
        desired_state: forge_domain::LocationState,
        #[source]
        source: BoxedRepositoryError,
    },
    #[error("Location repository operation {operation} failed")]
    Backend {
        operation: &'static str,
        #[source]
        source: BoxedRepositoryError,
    },
}

/// Owner-approved Location registration and Workspace discovery application service.
#[derive(Debug)]
pub struct LocationService<R> {
    repository: R,
}

impl<R> LocationService<R>
where
    R: LocationRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn register_selected_path(
        &mut self,
        id: LocationId,
        name: impl Into<String>,
        selected_path: impl AsRef<Path>,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredLocation, LocationServiceError> {
        let selected_path = selected_path.as_ref();
        let metadata = fs::metadata(selected_path).map_err(|source| {
            LocationServiceError::InspectSelectedPath {
                path: selected_path.to_path_buf(),
                source,
            }
        })?;
        if !metadata.is_dir() {
            return Err(LocationServiceError::SelectedPathIsNotDirectory(
                selected_path.to_path_buf(),
            ));
        }

        let canonical_path = fs::canonicalize(selected_path).map_err(|source| {
            LocationServiceError::CanonicalizeSelectedPath {
                path: selected_path.to_path_buf(),
                source,
            }
        })?;
        let command = RegisterLocation::new(
            id,
            LocationName::new(name)?,
            LocationRoot::from_canonical(canonical_path)?,
            observed_at,
        );
        self.repository
            .register_location(&command)
            .map_err(LocationServiceError::Repository)
    }

    pub fn list_locations(
        &self,
        limit: LocationListLimit,
    ) -> Result<Vec<RegisteredLocation>, LocationServiceError> {
        self.repository
            .list_locations(limit)
            .map_err(LocationServiceError::Repository)
    }

    pub fn get_location(
        &self,
        id: LocationId,
    ) -> Result<Option<RegisteredLocation>, LocationServiceError> {
        self.repository
            .get_location(id)
            .map_err(LocationServiceError::Repository)
    }

    pub fn get_current_location(
        &self,
        id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<RegisteredLocation, LocationServiceError> {
        let location = self
            .get_location(id)?
            .ok_or(LocationServiceError::Repository(
                LocationRepositoryError::NotFound(id),
            ))?;
        if location.revision() != expected_revision {
            return Err(LocationServiceError::Repository(
                LocationRepositoryError::RevisionConflict {
                    id,
                    expected: expected_revision,
                    actual: location.revision(),
                },
            ));
        }
        Ok(location)
    }

    pub fn discover_current(
        &self,
        id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<WorkspaceDiscovery, LocationServiceError> {
        let location = self.get_current_location(id, expected_revision)?;
        self.discover(&location)
    }

    pub fn resolve_candidate_current(
        &self,
        id: LocationId,
        expected_revision: LocationRevision,
        key: &WorkspaceCandidateKey,
    ) -> Result<WorkspaceCandidate, LocationServiceError> {
        let discovery = self.discover_current(id, expected_revision)?;
        discovery
            .resolve_key(key)
            .cloned()
            .map_err(LocationServiceError::WorkspaceKey)
    }

    /// Resolve a previously encoded locator against the current Location
    /// revision and exact bounded filesystem path.
    ///
    /// Unlike discovery and selector resolution, this operation never scans
    /// sibling candidates or inspects Forge-owned Workspace state. The locator
    /// remains correlation data: durable Workspace identity and fingerprint
    /// validation belong to the caller opening that registered Workspace.
    pub fn resolve_locator_current(
        &self,
        locator: &WorkspaceLocator,
    ) -> Result<WorkspaceCandidate, LocationServiceError> {
        let location =
            self.get_current_location(locator.location_id(), locator.expected_revision())?;
        resolve_locator_candidate(&location, locator)?
            .ok_or_else(|| WorkspaceKeyResolveError::NotFound {
                location_id: location.id(),
                relative_root: locator.relative_root().to_path_buf(),
            })
            .map_err(LocationServiceError::WorkspaceKey)
    }

    /// Resolve a user-facing selector using a fresh Location revision and
    /// discovery scan.  Ambiguity and absence remain explicit errors; no
    /// active/default Workspace is inferred.
    pub fn resolve_selector_current(
        &self,
        id: LocationId,
        expected_revision: LocationRevision,
        selector: &WorkspaceSelector,
    ) -> Result<WorkspaceCandidate, LocationServiceError> {
        let discovery = self.discover_current(id, expected_revision)?;
        discovery
            .resolve(selector)
            .cloned()
            .map_err(LocationServiceError::WorkspaceResolve)
    }

    pub fn set_location_state(
        &mut self,
        command: &SetLocationState,
    ) -> Result<RegisteredLocation, LocationServiceError> {
        self.repository
            .set_location_state(command)
            .map_err(LocationServiceError::Repository)
    }

    pub fn discover(
        &self,
        location: &RegisteredLocation,
    ) -> Result<WorkspaceDiscovery, LocationServiceError> {
        WorkspaceDiscovery::scan(location).map_err(LocationServiceError::Discovery)
    }
}

#[derive(Debug, Error)]
pub enum LocationServiceError {
    #[error("failed to inspect selected Location path {path}")]
    InspectSelectedPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("selected Location path is not a directory: {0}")]
    SelectedPathIsNotDirectory(PathBuf),
    #[error("failed to canonicalize selected Location path {path}")]
    CanonicalizeSelectedPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    InvalidName(#[from] LocationNameError),
    #[error(transparent)]
    InvalidRoot(#[from] LocationRootError),
    #[error(transparent)]
    Repository(#[from] LocationRepositoryError),
    #[error(transparent)]
    Discovery(#[from] WorkspaceDiscoveryError),
    #[error(transparent)]
    WorkspaceKey(#[from] WorkspaceKeyResolveError),
    #[error(transparent)]
    WorkspaceResolve(#[from] WorkspaceResolveError),
    #[error(transparent)]
    WorkspaceLocator(#[from] WorkspaceLocatorError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        LocationId, LocationListLimit, LocationRevision, LocationState, RegisterLocation,
        RegisteredLocation, SetLocationState, TimestampMillis,
    };

    use super::{
        LocationRepository, LocationRepositoryError, LocationService, LocationServiceError,
        WorkspaceDiscoveryError, WorkspaceKeyResolveError, WorkspaceLocator,
    };

    #[derive(Debug, Default)]
    struct MemoryLocationRepository {
        items: Vec<RegisteredLocation>,
    }

    impl LocationRepository for MemoryLocationRepository {
        fn register_location(
            &mut self,
            command: &RegisterLocation,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            if let Some(existing) = self.items.iter().find(|item| item.root() == command.root()) {
                return Err(LocationRepositoryError::AlreadyRegistered {
                    existing_id: existing.id(),
                });
            }
            if self.items.iter().any(|item| item.id() == command.id()) {
                return Err(LocationRepositoryError::IdentityConflict(command.id()));
            }

            let location = RegisteredLocation::from_parts_with_revision(
                command.id(),
                command.name().clone(),
                command.root().clone(),
                LocationState::Enabled,
                command.observed_at(),
                command.observed_at(),
                LocationRevision::INITIAL,
            );
            self.items.push(location.clone());
            Ok(location)
        }

        fn list_locations(
            &self,
            limit: LocationListLimit,
        ) -> Result<Vec<RegisteredLocation>, LocationRepositoryError> {
            let mut items = self.items.clone();
            items.sort_by(|left, right| {
                left.name()
                    .as_str()
                    .cmp(right.name().as_str())
                    .then_with(|| left.id().cmp(&right.id()))
            });
            let maximum = usize::try_from(limit.get()).map_err(|source| {
                LocationRepositoryError::Backend {
                    operation: "convert Location list limit",
                    source: Box::new(source),
                }
            })?;
            items.truncate(maximum);
            Ok(items)
        }

        fn get_location(
            &self,
            id: LocationId,
        ) -> Result<Option<RegisteredLocation>, LocationRepositoryError> {
            Ok(self.items.iter().find(|item| item.id() == id).cloned())
        }

        fn set_location_state(
            &mut self,
            command: &SetLocationState,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            let location = self
                .items
                .iter_mut()
                .find(|item| item.id() == command.id())
                .ok_or(LocationRepositoryError::NotFound(command.id()))?;
            let actual = location.revision();
            if actual != command.expected_revision() {
                return Err(LocationRepositoryError::RevisionConflict {
                    id: command.id(),
                    expected: command.expected_revision(),
                    actual,
                });
            }
            let revision =
                actual
                    .checked_next()
                    .map_err(|_| LocationRepositoryError::RevisionOverflow {
                        id: command.id(),
                        current: actual,
                    })?;
            *location = RegisteredLocation::from_parts_with_revision(
                location.id(),
                location.name().clone(),
                location.root().clone(),
                command.state(),
                location.created_at(),
                command.observed_at(),
                revision,
            );
            Ok(location.clone())
        }
    }

    #[test]
    fn service_registers_canonical_location_and_discovers_children()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("service")?;
        fs::create_dir_all(root.join("A"))?;
        fs::create_dir_all(root.join("B"))?;
        let selected = root.join("A/..");
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let location = service.register_selected_path(
            LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e")?,
            "Owner Location",
            selected,
            TimestampMillis::new(10)?,
        )?;

        assert_eq!(location.root().as_path(), fs::canonicalize(&root)?);
        let discovery = service.discover(&location)?;
        assert_eq!(discovery.candidates().len(), 3);
        assert_eq!(service.list_locations(LocationListLimit::DEFAULT)?.len(), 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn service_rejects_files_and_duplicate_roots() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("reject")?;
        fs::create_dir_all(&root)?;
        let file = root.join("not-a-location.txt");
        fs::write(&file, "not a directory")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let first_id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e")?;
        let second_id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215f")?;

        assert!(
            service
                .register_selected_path(first_id, "File", &file, TimestampMillis::new(1)?,)
                .is_err()
        );
        service.register_selected_path(first_id, "Location", &root, TimestampMillis::new(2)?)?;
        assert!(
            service
                .register_selected_path(second_id, "Duplicate", &root, TimestampMillis::new(3)?,)
                .is_err()
        );

        let current = service.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        let disabled = service.set_location_state(&SetLocationState::new(
            first_id,
            current.revision(),
            LocationState::Disabled,
            TimestampMillis::new(4)?,
        ))?;
        assert_eq!(disabled.state(), LocationState::Disabled);
        assert!(service.discover(&disabled).is_err());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn service_maps_stale_state_commands_to_revision_conflicts()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("revision-conflict")?;
        fs::create_dir_all(&root)?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12161")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered = service.register_selected_path(
            id,
            "Revisioned Location",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let updated = service.set_location_state(&SetLocationState::new(
            id,
            registered.revision(),
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ))?;
        assert_eq!(updated.revision().get(), 2);
        assert_eq!(updated.updated_at().get(), 2);

        let stale = service.set_location_state(&SetLocationState::new(
            id,
            LocationRevision::INITIAL,
            LocationState::Enabled,
            TimestampMillis::new(3)?,
        ));
        assert!(matches!(
            stale,
            Err(LocationServiceError::Repository(
                LocationRepositoryError::RevisionConflict {
                    id: conflict_id,
                    expected,
                    actual
                }
            )) if conflict_id == id
                && expected == LocationRevision::INITIAL
                && actual.get() == 2
        ));
        let unchanged = service.list_locations(LocationListLimit::DEFAULT)?[0].clone();
        assert_eq!(unchanged.state(), LocationState::Disabled);
        assert_eq!(unchanged.updated_at().get(), 2);
        assert_eq!(unchanged.revision().get(), 2);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn service_get_location_preserves_revision_and_reports_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("get-location")?;
        fs::create_dir_all(&root)?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12162")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered =
            service.register_selected_path(id, "Get Location", &root, TimestampMillis::new(1)?)?;
        assert_eq!(
            service
                .get_location(id)?
                .as_ref()
                .map(RegisteredLocation::revision),
            Some(registered.revision())
        );
        let missing_id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12165")?;
        assert!(service.get_location(missing_id)?.is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn discover_current_rejects_stale_revision_before_filesystem_scan()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("discover-current-stale")?;
        fs::create_dir_all(&root)?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12163")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered = service.register_selected_path(
            id,
            "Stale Discovery",
            &root,
            TimestampMillis::new(1)?,
        )?;
        service.set_location_state(&SetLocationState::new(
            id,
            registered.revision(),
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ))?;
        fs::remove_dir_all(&root)?;

        assert!(matches!(
            service.discover_current(id, registered.revision()),
            Err(LocationServiceError::Repository(
                LocationRepositoryError::RevisionConflict { actual, .. }
            )) if actual.get() == 2
        ));
        Ok(())
    }

    #[test]
    fn discover_current_scans_at_the_current_revision() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("discover-current")?;
        fs::create_dir_all(root.join("child"))?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12164")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered = service.register_selected_path(
            id,
            "Current Discovery",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let discovery = service.discover_current(id, registered.revision())?;
        assert_eq!(discovery.candidates().len(), 2);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn resolve_candidate_current_rejects_a_candidate_removed_after_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("resolve-current")?;
        let child = root.join("child");
        fs::create_dir_all(&child)?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12166")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered = service.register_selected_path(
            id,
            "Resolve Current",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let discovery = service.discover_current(id, registered.revision())?;
        let key = discovery.candidates()[1].key();
        fs::remove_dir_all(&child)?;

        assert!(matches!(
            service.resolve_candidate_current(id, registered.revision(), &key),
            Err(LocationServiceError::WorkspaceKey(
                crate::WorkspaceKeyResolveError::NotFound { .. }
            ))
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn resolve_locator_current_rechecks_revision_and_candidate_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("resolve-locator")?;
        let child = root.join("child");
        let replacement = root.join("replacement");
        fs::create_dir_all(&child)?;
        fs::create_dir_all(&replacement)?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12167")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered = service.register_selected_path(
            id,
            "Resolve Locator",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let discovery = service.discover_current(id, registered.revision())?;
        let key = discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.relative_root() == std::path::Path::new("child"))
            .ok_or("child candidate missing")?
            .key();
        let locator = key.locator(registered.revision())?;

        let resolved = service.resolve_locator_current(&locator)?;
        assert_eq!(resolved.relative_root(), std::path::Path::new("child"));

        fs::remove_dir_all(&child)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&replacement, &child)?;
        assert!(matches!(
            service.resolve_locator_current(&locator),
            Err(LocationServiceError::WorkspaceKey(
                WorkspaceKeyResolveError::NotFound { .. }
            ))
        ));

        let disabled = service.set_location_state(&SetLocationState::new(
            id,
            registered.revision(),
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ))?;
        assert!(matches!(
            service.resolve_locator_current(&locator),
            Err(LocationServiceError::Repository(
                LocationRepositoryError::RevisionConflict { actual, .. }
            )) if actual == disabled.revision()
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn locator_resolution_ignores_discovery_state_but_rejects_symlink_rebinding()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("registered-locator")?;
        let child = root.join("child");
        let replacement = root.join("replacement");
        fs::create_dir_all(child.join(".heterarchy-forge"))?;
        fs::create_dir_all(&replacement)?;
        fs::write(
            child.join(".heterarchy-forge/state.sqlite3-wal"),
            b"active-wal-observation",
        )?;
        let canonical_child = fs::canonicalize(&child)?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12169")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered = service.register_selected_path(
            id,
            "Registered Locator",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let locator = WorkspaceLocator::new(id, registered.revision(), Path::new("child"))?;

        assert_eq!(
            service.resolve_locator_current(&locator)?.absolute_root(),
            canonical_child.as_path()
        );

        fs::remove_dir_all(&child)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&replacement, &child)?;
        assert!(matches!(
            service.resolve_locator_current(&locator),
            Err(LocationServiceError::WorkspaceKey(
                WorkspaceKeyResolveError::NotFound { .. }
            ))
        ));

        let disabled = service.set_location_state(&SetLocationState::new(
            id,
            registered.revision(),
            LocationState::Disabled,
            TimestampMillis::new(2)?,
        ))?;
        let disabled_locator = WorkspaceLocator::new(id, disabled.revision(), Path::new("."))?;
        assert!(matches!(
            service.resolve_locator_current(&disabled_locator),
            Err(LocationServiceError::Discovery(
                WorkspaceDiscoveryError::LocationDisabled(disabled_id)
            )) if disabled_id == id
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn resolve_selector_current_requires_an_explicit_current_match()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("resolve-selector-current")?;
        fs::create_dir_all(root.join("child"))?;
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12168")?;
        let mut service = LocationService::new(MemoryLocationRepository::default());
        let registered = service.register_selected_path(
            id,
            "Resolve Selector",
            &root,
            TimestampMillis::new(1)?,
        )?;

        let selected = service.resolve_selector_current(
            id,
            registered.revision(),
            &crate::WorkspaceSelector::new("child")?,
        )?;
        assert_eq!(selected.relative_root(), std::path::Path::new("child"));
        assert!(matches!(
            service.resolve_selector_current(
                id,
                registered.revision(),
                &crate::WorkspaceSelector::new("missing")?
            ),
            Err(LocationServiceError::WorkspaceResolve(
                crate::WorkspaceResolveError::NotFound { .. }
            ))
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn service_registers_target_canonical_path_when_selected_through_symlink()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("symlink-selection")?;
        let target = root.join("target");
        let selected = root.join("selected");
        fs::create_dir_all(&target)?;
        symlink(&target, &selected)?;

        let mut service = LocationService::new(MemoryLocationRepository::default());
        let location = service.register_selected_path(
            LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12160")?,
            "Symlink Location",
            &selected,
            TimestampMillis::new(5)?,
        )?;

        assert_eq!(location.root().as_path(), fs::canonicalize(&target)?);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn unique_test_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("heterarchy-forge-{label}-{unique}")))
    }
}
