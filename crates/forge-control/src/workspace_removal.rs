//! Explicit native removal of a direct-root Location registration.

use forge_domain::{
    LocationId, LocationRevision, LocationState, RegisteredLocation, SetLocationState,
    TimestampMillis, WorkspaceId, WorkspaceRevision, WorkspaceRootFingerprint,
};
use forge_workspace::{
    ConfinedWorkspace, LocationRepository, LocationRepositoryError, LocationService,
    LocationServiceError, StateLayoutError, WorkspaceStateExclusiveGate, WorkspaceStateGateError,
    WorkspaceStateLayout, WorkspaceStateRemoval,
};
use thiserror::Error;

/// Exact state observation required before a destructive Location-root removal.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalStateExpectation {
    Absent,
    Uninitialized,
    Workspace {
        id: WorkspaceId,
        revision: WorkspaceRevision,
    },
}

/// Closed mutation request for one registered Location root.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationRemovalRequest {
    ListOnly {
        id: LocationId,
        expected_revision: LocationRevision,
    },
    DeleteState {
        id: LocationId,
        expected_revision: LocationRevision,
        expected_root_fingerprint: WorkspaceRootFingerprint,
        expected_state: RemovalStateExpectation,
    },
}

impl LocationRemovalRequest {
    pub const fn id(&self) -> LocationId {
        match self {
            Self::ListOnly { id, .. } | Self::DeleteState { id, .. } => *id,
        }
    }

    pub const fn expected_revision(&self) -> LocationRevision {
        match self {
            Self::ListOnly {
                expected_revision, ..
            }
            | Self::DeleteState {
                expected_revision, ..
            } => *expected_revision,
        }
    }

    pub const fn mode(&self) -> WorkspaceRemovalMode {
        match self {
            Self::ListOnly { .. } => WorkspaceRemovalMode::ListOnly,
            Self::DeleteState { .. } => WorkspaceRemovalMode::DeleteState,
        }
    }
}

/// Read-only current observation used to form a checked removal request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationRemovalProbe {
    pub location: RegisteredLocation,
    pub root_fingerprint: WorkspaceRootFingerprint,
    pub state: RemovalStateExpectation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRemovalMode {
    ListOnly,
    DeleteState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceRemovalCleanup {
    ListingOnly,
    StateRemoved,
    StateAlreadyAbsent,
    Incomplete(WorkspaceRemovalFailure),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{detail}")]
pub struct WorkspaceRemovalFailure {
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRemovalOutcome {
    pub location: RegisteredLocation,
    pub cleanup: WorkspaceRemovalCleanup,
}

#[derive(Debug, Error)]
pub enum WorkspaceRemovalError {
    #[error(transparent)]
    Location(#[from] LocationServiceError),
    #[error(transparent)]
    Layout(#[from] StateLayoutError),
    #[error(transparent)]
    Gate(#[from] WorkspaceStateGateError),
    #[error(transparent)]
    Store(#[from] forge_persistence::WorkspaceStoreError),
    #[error(transparent)]
    Filesystem(#[from] forge_workspace::ConfinedFilesystemError),
    #[error(
        "Location root fingerprint changed during removal: expected {expected:?}, actual {actual:?}"
    )]
    RootFingerprintConflict {
        expected: WorkspaceRootFingerprint,
        actual: WorkspaceRootFingerprint,
    },
    #[error("Location removal state expectation changed: expected {expected:?}, actual {actual:?}")]
    StateExpectationConflict {
        expected: RemovalStateExpectation,
        actual: RemovalStateExpectation,
    },
    #[error("Location observation changed during removal probe")]
    LocationObservationChanged,
    #[error("Location removal committed but its post-effect binding is unconfirmed: {detail}")]
    CommittedUnconfirmed { detail: String },
}

pub fn remove_workspace<R: LocationRepository>(
    service: &mut LocationService<R>,
    id: LocationId,
    revision: LocationRevision,
    mode: WorkspaceRemovalMode,
    observed_at: TimestampMillis,
) -> Result<WorkspaceRemovalOutcome, WorkspaceRemovalError> {
    let current = service.get_current_location(id, revision)?;
    match mode {
        WorkspaceRemovalMode::ListOnly => Ok(WorkspaceRemovalOutcome {
            location: disable_location(service, &current, observed_at)?,
            cleanup: WorkspaceRemovalCleanup::ListingOnly,
        }),
        WorkspaceRemovalMode::DeleteState => remove_state(service, &current, observed_at, None),
    }
}

/// Execute one checked native removal request through the sole effect owner.
pub fn native_execute_checked<R: LocationRepository>(
    service: &mut LocationService<R>,
    request: &LocationRemovalRequest,
    observed_at: TimestampMillis,
) -> Result<WorkspaceRemovalOutcome, WorkspaceRemovalError> {
    match request {
        LocationRemovalRequest::ListOnly { .. } => remove_workspace(
            service,
            request.id(),
            request.expected_revision(),
            WorkspaceRemovalMode::ListOnly,
            observed_at,
        ),
        LocationRemovalRequest::DeleteState {
            id,
            expected_revision,
            expected_root_fingerprint,
            expected_state,
        } => {
            let current = service.get_current_location(*id, *expected_revision)?;
            remove_state(
                service,
                &current,
                observed_at,
                Some((*expected_root_fingerprint, *expected_state)),
            )
        }
    }
}

/// Read the current root/state observation without initializing or migrating it.
pub fn probe_location_removal<R: LocationRepository>(
    service: &LocationService<R>,
    id: LocationId,
) -> Result<LocationRemovalProbe, WorkspaceRemovalError> {
    let location = service
        .get_location(id)?
        .ok_or(LocationServiceError::Repository(
            LocationRepositoryError::NotFound(id),
        ))?;
    let root = location.root().as_path();
    let before = WorkspaceStateLayout::observe_root_fingerprint(root)?;
    let layout = WorkspaceStateLayout::inspect_existing(root)?;
    let state = observe_removal_state(layout)?;
    let after = WorkspaceStateLayout::observe_root_fingerprint(root)?;
    if before != after {
        return Err(WorkspaceRemovalError::RootFingerprintConflict {
            expected: before,
            actual: after,
        });
    }
    let current = service
        .get_location(id)?
        .ok_or(LocationServiceError::Repository(
            LocationRepositoryError::NotFound(id),
        ))?;
    if current != location {
        return Err(WorkspaceRemovalError::LocationObservationChanged);
    }
    Ok(LocationRemovalProbe {
        location: current,
        root_fingerprint: before,
        state,
    })
}

fn observe_removal_state(
    layout: Option<forge_workspace::ExistingWorkspaceStateLayout>,
) -> Result<RemovalStateExpectation, WorkspaceRemovalError> {
    let Some(layout) = layout else {
        return Ok(RemovalStateExpectation::Absent);
    };
    match forge_persistence::WorkspaceStore::inspect_existing_identity_live_read_only(&layout) {
        Ok(workspace) => Ok(RemovalStateExpectation::Workspace {
            id: workspace.id(),
            revision: workspace.revision(),
        }),
        Err(forge_persistence::WorkspaceStoreError::MissingDatabase(_)) => {
            Ok(RemovalStateExpectation::Uninitialized)
        }
        Err(error) => Err(WorkspaceRemovalError::Store(error)),
    }
}

fn disable_location<R: LocationRepository>(
    service: &mut LocationService<R>,
    location: &RegisteredLocation,
    observed_at: TimestampMillis,
) -> Result<RegisteredLocation, LocationServiceError> {
    if location.state() == LocationState::Disabled {
        return Ok(location.clone());
    }
    service.set_location_state(&SetLocationState::new(
        location.id(),
        location.revision(),
        LocationState::Disabled,
        observed_at,
    ))
}

fn remove_state<R: LocationRepository>(
    service: &mut LocationService<R>,
    current: &RegisteredLocation,
    observed_at: TimestampMillis,
    expected: Option<(WorkspaceRootFingerprint, RemovalStateExpectation)>,
) -> Result<WorkspaceRemovalOutcome, WorkspaceRemovalError> {
    let root = current.root().as_path();
    let fingerprint = WorkspaceStateLayout::observe_root_fingerprint(root)?;
    if let Some((expected_fingerprint, _)) = expected
        && expected_fingerprint != fingerprint
    {
        return Err(WorkspaceRemovalError::RootFingerprintConflict {
            expected: expected_fingerprint,
            actual: fingerprint,
        });
    }
    let gate = WorkspaceStateExclusiveGate::acquire(root, fingerprint)?;
    // Revision admission is repeated after waiting for live connections.
    let current = service.get_current_location(current.id(), current.revision())?;
    if let Some((expected_fingerprint, _)) = expected {
        let actual = WorkspaceStateLayout::observe_root_fingerprint(root)?;
        if actual != expected_fingerprint {
            return Err(WorkspaceRemovalError::RootFingerprintConflict {
                expected: expected_fingerprint,
                actual,
            });
        }
    }
    let Some(layout) = WorkspaceStateLayout::inspect_existing(root)? else {
        gate.ensure_root_binding(root, fingerprint)?;
        if let Some((_, expected_state)) = expected {
            let actual_state = RemovalStateExpectation::Absent;
            if expected_state != actual_state {
                return Err(WorkspaceRemovalError::StateExpectationConflict {
                    expected: expected_state,
                    actual: actual_state,
                });
            }
        }
        let disabled = disable_location(service, &current, observed_at)?;
        if expected.is_some()
            && let Err(error) = gate.ensure_root_binding(root, fingerprint)
        {
            return Err(WorkspaceRemovalError::CommittedUnconfirmed {
                detail: error.to_string(),
            });
        }
        return Ok(WorkspaceRemovalOutcome {
            location: disabled,
            cleanup: WorkspaceRemovalCleanup::StateAlreadyAbsent,
        });
    };
    let workspace = forge_persistence::WorkspaceStore::preflight_state_removal_under_exclusive(
        &layout,
        &gate,
        current.id(),
    )?;
    if let Some((_, expected_state)) = expected {
        let actual_state = workspace.map_or(RemovalStateExpectation::Uninitialized, |workspace| {
            RemovalStateExpectation::Workspace {
                id: workspace.id(),
                revision: workspace.revision(),
            }
        });
        if expected_state != actual_state {
            return Err(WorkspaceRemovalError::StateExpectationConflict {
                expected: expected_state,
                actual: actual_state,
            });
        }
    }
    let filesystem = ConfinedWorkspace::open(&layout)?;
    let writer = filesystem.acquire_write_guard()?;
    filesystem.preflight_owned_state_removal(&gate, &writer)?;
    let disabled = disable_location(service, &current, observed_at)?;
    if expected.is_some()
        && let Err(error) = gate.ensure_root_binding(root, fingerprint)
    {
        return Err(WorkspaceRemovalError::CommittedUnconfirmed {
            detail: error.to_string(),
        });
    }
    // A failed filesystem effect cannot roll the Location back to Enabled:
    // some files may already be gone. The exact disabled revision is returned
    // to the same dialog so retry never re-enables a partially removed store.
    let cleanup = match filesystem.remove_owned_state_directory(&gate, &writer) {
        Ok(WorkspaceStateRemoval::Removed) => WorkspaceRemovalCleanup::StateRemoved,
        Ok(WorkspaceStateRemoval::AlreadyAbsent) => WorkspaceRemovalCleanup::StateAlreadyAbsent,
        Err(error) if expected.is_some() && error.effect_may_have_committed() => {
            return Err(WorkspaceRemovalError::CommittedUnconfirmed {
                detail: error.to_string(),
            });
        }
        Err(error) => WorkspaceRemovalCleanup::Incomplete(WorkspaceRemovalFailure {
            detail: error.to_string(),
        }),
    };
    Ok(WorkspaceRemovalOutcome {
        location: disabled,
        cleanup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{LocationListLimit, RegisterLocation, SetLocationState};
    use forge_persistence::GlobalRegistry;
    use forge_workspace::WorkspaceStateSharedGate;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    type RemovalFixture = (
        std::path::PathBuf,
        LocationService<GlobalRegistry>,
        RegisteredLocation,
        forge_domain::RegisteredWorkspace,
    );

    #[derive(Debug)]
    struct RenameAfterDisableRegistry {
        inner: GlobalRegistry,
        root: PathBuf,
        moved_root: PathBuf,
        armed: bool,
    }

    impl RenameAfterDisableRegistry {
        fn rename_after_disable(&mut self) -> Result<(), LocationRepositoryError> {
            fs::rename(&self.root, &self.moved_root).map_err(|source| {
                LocationRepositoryError::Backend {
                    operation: "test rename committed Location root",
                    source: Box::new(source),
                }
            })?;
            fs::create_dir(&self.root).map_err(|source| LocationRepositoryError::Backend {
                operation: "test create replacement Location root",
                source: Box::new(source),
            })?;
            fs::write(self.root.join("replacement-marker"), b"replacement").map_err(|source| {
                LocationRepositoryError::Backend {
                    operation: "test write replacement Location marker",
                    source: Box::new(source),
                }
            })?;
            Ok(())
        }
    }

    impl LocationRepository for RenameAfterDisableRegistry {
        fn register_location(
            &mut self,
            command: &RegisterLocation,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            LocationRepository::register_location(&mut self.inner, command)
        }

        fn list_locations(
            &self,
            limit: LocationListLimit,
        ) -> Result<Vec<RegisteredLocation>, LocationRepositoryError> {
            LocationRepository::list_locations(&self.inner, limit)
        }

        fn get_location(
            &self,
            id: LocationId,
        ) -> Result<Option<RegisteredLocation>, LocationRepositoryError> {
            LocationRepository::get_location(&self.inner, id)
        }

        fn set_location_state(
            &mut self,
            command: &SetLocationState,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            let location = LocationRepository::set_location_state(&mut self.inner, command)?;
            if self.armed && command.state() == LocationState::Disabled {
                self.armed = false;
                self.rename_after_disable()?;
            }
            Ok(location)
        }
    }

    type RenameRegistryFixture = (
        PathBuf,
        LocationService<RenameAfterDisableRegistry>,
        RegisteredLocation,
        PathBuf,
        PathBuf,
    );

    fn rename_registry_fixture(
        initialized: bool,
    ) -> Result<RenameRegistryFixture, Box<dyn std::error::Error>> {
        let temp = std::env::temp_dir().join(format!("forge-removal-drift-{}", Uuid::now_v7()));
        let root = temp.join("project");
        fs::create_dir_all(&root)?;
        let registry = GlobalRegistry::open(temp.join("registry.sqlite3"))?;
        let mut register = LocationService::new(registry);
        let location = register.register_selected_path(
            LocationId::from_uuid(Uuid::now_v7()),
            "Project",
            &root,
            TimestampMillis::new(1)?,
        )?;
        drop(register);
        if initialized {
            let layout = WorkspaceStateLayout::initialize(&root)?;
            let command = forge_domain::EstablishWorkspace::new(
                WorkspaceId::from_uuid(Uuid::now_v7()),
                location.id(),
                forge_domain::WorkspaceRoot::from_canonical(root.clone())?,
                layout.root_fingerprint()?,
                TimestampMillis::new(1)?,
            );
            drop(forge_persistence::WorkspaceStore::open(&layout, command)?);
        }
        let moved_root = temp.join("project-moved");
        let registry = GlobalRegistry::open_existing(temp.join("registry.sqlite3"))?;
        let service = LocationService::new(RenameAfterDisableRegistry {
            inner: registry,
            root: root.clone(),
            moved_root: moved_root.clone(),
            armed: true,
        });
        Ok((temp, service, location, root, moved_root))
    }

    fn fixture() -> Result<RemovalFixture, Box<dyn std::error::Error>> {
        let temp = std::env::temp_dir().join(format!(
            "forge-state-removal-integration-{}",
            Uuid::now_v7()
        ));
        let root = temp.join("project");
        fs::create_dir_all(&root)?;
        let mut service =
            LocationService::new(GlobalRegistry::open(temp.join("registry.sqlite3"))?);
        let location = service.register_selected_path(
            LocationId::from_uuid(Uuid::now_v7()),
            "Project",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let layout = WorkspaceStateLayout::initialize(location.root().as_path())?;
        let command = forge_domain::EstablishWorkspace::new(
            forge_domain::WorkspaceId::from_uuid(Uuid::now_v7()),
            location.id(),
            forge_domain::WorkspaceRoot::from_canonical(location.root().as_path().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(1)?,
        );
        let store = forge_persistence::WorkspaceStore::open(&layout, command)?;
        let workspace = store.workspace()?;
        drop(store);
        for directory in [".git", ".agents", "src"] {
            fs::create_dir(root.join(directory))?;
            fs::write(root.join(directory).join("preserved"), directory)?;
        }
        Ok((temp, service, location, workspace))
    }

    #[test]
    fn probe_reports_workspace_identity_and_root_fingerprint()
    -> Result<(), Box<dyn std::error::Error>> {
        let (temp, service, location, workspace) = fixture()?;
        let probe = probe_location_removal(&service, location.id())?;
        assert_eq!(probe.location, location);
        assert_eq!(
            probe.root_fingerprint,
            WorkspaceStateLayout::observe_root_fingerprint(location.root().as_path())?
        );
        assert_eq!(
            probe.state,
            RemovalStateExpectation::Workspace {
                id: workspace.id(),
                revision: workspace.revision(),
            }
        );
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn probe_distinguishes_absent_and_uninitialized_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = std::env::temp_dir().join(format!("forge-removal-probe-{}", Uuid::now_v7()));
        let root = temp.join("project");
        fs::create_dir_all(&root)?;
        let mut service =
            LocationService::new(GlobalRegistry::open(temp.join("registry.sqlite3"))?);
        let location = service.register_selected_path(
            LocationId::from_uuid(Uuid::now_v7()),
            "Project",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let absent = probe_location_removal(&service, location.id())?;
        assert_eq!(absent.state, RemovalStateExpectation::Absent);
        WorkspaceStateLayout::initialize(&root)?;
        let uninitialized = probe_location_removal(&service, location.id())?;
        assert_eq!(uninitialized.state, RemovalStateExpectation::Uninitialized);
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn checked_removal_rejects_physical_state_and_gate_fences()
    -> Result<(), Box<dyn std::error::Error>> {
        let (temp, mut service, location, workspace) = fixture()?;
        let probe = probe_location_removal(&service, location.id())?;
        let wrong_root = LocationRemovalRequest::DeleteState {
            id: location.id(),
            expected_revision: location.revision(),
            expected_root_fingerprint: WorkspaceRootFingerprint::from_bytes([0xFF; 16]),
            expected_state: probe.state,
        };
        assert!(matches!(
            native_execute_checked(&mut service, &wrong_root, TimestampMillis::new(2)?),
            Err(WorkspaceRemovalError::RootFingerprintConflict { .. })
        ));

        let wrong_state = LocationRemovalRequest::DeleteState {
            id: location.id(),
            expected_revision: location.revision(),
            expected_root_fingerprint: probe.root_fingerprint,
            expected_state: RemovalStateExpectation::Workspace {
                id: WorkspaceId::from_uuid(Uuid::now_v7()),
                revision: workspace.revision(),
            },
        };
        assert!(matches!(
            native_execute_checked(&mut service, &wrong_state, TimestampMillis::new(2)?),
            Err(WorkspaceRemovalError::StateExpectationConflict { .. })
        ));

        let _shared =
            WorkspaceStateSharedGate::acquire(location.root().as_path(), probe.root_fingerprint)?;
        let checked = LocationRemovalRequest::DeleteState {
            id: location.id(),
            expected_revision: location.revision(),
            expected_root_fingerprint: probe.root_fingerprint,
            expected_state: probe.state,
        };
        assert!(matches!(
            native_execute_checked(&mut service, &checked, TimestampMillis::new(2)?),
            Err(WorkspaceRemovalError::Gate(WorkspaceStateGateError::Busy))
        ));
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn checked_root_removal_preserves_direct_child_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let (temp, mut service, location, _) = fixture()?;
        let child = location.root().as_path().join("child");
        fs::create_dir(&child)?;
        WorkspaceStateLayout::initialize(&child)?;
        fs::write(child.join("child-marker"), "preserve")?;
        let probe = probe_location_removal(&service, location.id())?;
        let request = LocationRemovalRequest::DeleteState {
            id: location.id(),
            expected_revision: location.revision(),
            expected_root_fingerprint: probe.root_fingerprint,
            expected_state: probe.state,
        };
        let outcome = native_execute_checked(&mut service, &request, TimestampMillis::new(2)?)?;
        assert_eq!(outcome.cleanup, WorkspaceRemovalCleanup::StateRemoved);
        assert_eq!(fs::read_to_string(child.join("child-marker"))?, "preserve");
        assert!(child.join(".heterarchy-forge").is_dir());
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn checked_delete_reports_committed_unconfirmed_after_disable_root_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let (temp, mut service, location, root, moved_root) = rename_registry_fixture(true)?;
        let probe = probe_location_removal(&service, location.id())?;
        let request = LocationRemovalRequest::DeleteState {
            id: location.id(),
            expected_revision: location.revision(),
            expected_root_fingerprint: probe.root_fingerprint,
            expected_state: probe.state,
        };
        let result = native_execute_checked(&mut service, &request, TimestampMillis::new(2)?);
        assert!(matches!(
            result,
            Err(WorkspaceRemovalError::CommittedUnconfirmed { .. })
        ));
        let disabled = service.get_current_location(
            location.id(),
            LocationRevision::new(location.revision().get() + 1)?,
        )?;
        assert_eq!(disabled.state(), LocationState::Disabled);
        assert!(moved_root.join(".heterarchy-forge").is_dir());
        assert_eq!(
            fs::read_to_string(root.join("replacement-marker"))?,
            "replacement"
        );
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn checked_absent_delete_reports_committed_unconfirmed_after_disable_root_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let (temp, mut service, location, root, moved_root) = rename_registry_fixture(false)?;
        let probe = probe_location_removal(&service, location.id())?;
        assert_eq!(probe.state, RemovalStateExpectation::Absent);
        let request = LocationRemovalRequest::DeleteState {
            id: location.id(),
            expected_revision: location.revision(),
            expected_root_fingerprint: probe.root_fingerprint,
            expected_state: RemovalStateExpectation::Absent,
        };
        let result = native_execute_checked(&mut service, &request, TimestampMillis::new(2)?);
        assert!(matches!(
            result,
            Err(WorkspaceRemovalError::CommittedUnconfirmed { .. })
        ));
        let disabled = service.get_current_location(
            location.id(),
            LocationRevision::new(location.revision().get() + 1)?,
        )?;
        assert_eq!(disabled.state(), LocationState::Disabled);
        assert!(!moved_root.join(".heterarchy-forge").exists());
        assert_eq!(
            fs::read_to_string(root.join("replacement-marker"))?,
            "replacement"
        );
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn delete_state_removes_only_owned_state_and_supports_disabled_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let (temp, mut service, location, _) = fixture()?;
        let outcome = remove_workspace(
            &mut service,
            location.id(),
            location.revision(),
            WorkspaceRemovalMode::DeleteState,
            TimestampMillis::new(2)?,
        )?;
        assert_eq!(outcome.cleanup, WorkspaceRemovalCleanup::StateRemoved);
        assert_eq!(outcome.location.state(), LocationState::Disabled);
        assert!(!location.root().as_path().join(".heterarchy-forge").exists());
        for directory in [".git", ".agents", "src"] {
            assert_eq!(
                fs::read_to_string(location.root().as_path().join(directory).join("preserved"))?,
                directory
            );
        }
        let retry = remove_workspace(
            &mut service,
            location.id(),
            outcome.location.revision(),
            WorkspaceRemovalMode::DeleteState,
            TimestampMillis::new(3)?,
        )?;
        assert_eq!(retry.cleanup, WorkspaceRemovalCleanup::StateAlreadyAbsent);
        assert_eq!(retry.location.revision(), outcome.location.revision());
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn delete_state_with_open_activity_keeps_registration_and_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let (temp, mut service, location, workspace) = fixture()?;
        let layout = WorkspaceStateLayout::inspect_existing(location.root().as_path())?
            .ok_or("missing layout")?;
        let mut store = forge_persistence::WorkspaceStore::open_existing(&layout)?;
        let activity = forge_domain::CreateActivity::new(
            forge_domain::ActivityId::from_uuid(Uuid::now_v7()),
            workspace.id(),
            workspace.revision(),
            TimestampMillis::new(2)?,
        );
        store.create_activity(&activity)?;
        drop(store);
        let result = remove_workspace(
            &mut service,
            location.id(),
            location.revision(),
            WorkspaceRemovalMode::DeleteState,
            TimestampMillis::new(3)?,
        );
        assert!(
            matches!(result, Err(WorkspaceRemovalError::Store(_))),
            "{result:?}"
        );
        assert_eq!(
            service
                .get_current_location(location.id(), location.revision())?
                .state(),
            LocationState::Enabled
        );
        assert!(layout.database_path().is_file());
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn list_only_removal_preserves_all_files_and_rejects_stale_confirmation()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = std::env::temp_dir().join(format!("forge-workspace-removal-{}", Uuid::now_v7()));
        fs::create_dir(&temp)?;
        let root = temp.join("project");
        fs::create_dir(&root)?;
        for directory in [".heterarchy-forge", ".git", ".agents", "src"] {
            fs::create_dir(root.join(directory))?;
            fs::write(root.join(directory).join("preserved"), directory)?;
        }
        let mut service =
            LocationService::new(GlobalRegistry::open(temp.join("registry.sqlite3"))?);
        let location = service.register_selected_path(
            LocationId::from_uuid(Uuid::now_v7()),
            "Project",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let outcome = remove_workspace(
            &mut service,
            location.id(),
            location.revision(),
            WorkspaceRemovalMode::ListOnly,
            TimestampMillis::new(2)?,
        )?;
        assert_eq!(outcome.location.state(), LocationState::Disabled);
        assert_eq!(outcome.cleanup, WorkspaceRemovalCleanup::ListingOnly);
        for directory in [".heterarchy-forge", ".git", ".agents", "src"] {
            assert_eq!(
                fs::read_to_string(root.join(directory).join("preserved"))?,
                directory
            );
        }
        assert!(
            remove_workspace(
                &mut service,
                location.id(),
                location.revision(),
                WorkspaceRemovalMode::DeleteState,
                TimestampMillis::new(3)?,
            )
            .is_err()
        );
        drop(service);
        fs::remove_dir_all(temp)?;
        Ok(())
    }
}
