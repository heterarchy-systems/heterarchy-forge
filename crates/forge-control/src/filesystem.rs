use std::path::Path;

use forge_domain::{
    ActivityId, ActivityState, RuntimeInstanceId, TimestampMillis, WorkspaceRelativePath,
};
use forge_persistence::WorkspaceStore;
use forge_workspace::{
    ConfinedFileRead, ConfinedFilesystemError, ConfinedWorkspace, DiffArtifactStoreError,
    WorkspaceStateLayout,
};

use crate::error::{ControlError, ControlErrorCode, ControlErrorDetails};
use crate::service::{
    ForgeControl, ResolvedWorkspaceScope, map_activity_store_error, map_location_error,
    map_state_layout_error,
};

const MAX_EFFECT_LOCATIONS: u32 = 1_000;
const MAX_EFFECT_LOCATIONS_USIZE: usize = 1_000;

/// Live Activity attribution required for one file request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileActivityScope {
    pub activity_id: ActivityId,
    pub runtime_instance_id: RuntimeInstanceId,
    pub observed_at: TimestampMillis,
}

/// Explicit transport/UI-neutral request for one confined file read.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub path: WorkspaceRelativePath,
}

/// Confined read result. It exposes no absolute root or runtime lease owner.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadResult {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    path: WorkspaceRelativePath,
    read: ConfinedFileRead,
}

impl FileReadResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn read(&self) -> &ConfinedFileRead {
        &self.read
    }
}

impl ForgeControl {
    /// Read one regular file after exact Workspace and Open Activity validation.
    /// Read-only source observations use the selected descriptor-confined root;
    /// they do not claim exclusive effect ownership against other Workspaces.
    /// Mutation and execution paths retain the overlap fence. The transport
    /// authenticates the participant; heartbeat ownership remains observational.
    pub fn file_read(&self, request: &FileReadRequest) -> Result<FileReadResult, ControlError> {
        let (scope, layout, store) = self.open_effect_workspace(&request.scope)?;
        authorize_activity(&store, request.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let read = filesystem
            .read(&request.path)
            .map_err(map_filesystem_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(FileReadResult {
            scope,
            activity_id: request.activity.activity_id,
            path: request.path.clone(),
            read,
        })
    }

    pub(crate) fn open_effect_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<
        (
            ResolvedWorkspaceScope,
            forge_workspace::ExistingWorkspaceStateLayout,
            WorkspaceStore,
        ),
        ControlError,
    > {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((fresh_scope, layout, store))
    }

    pub(crate) fn ensure_non_overlapping_effect_scope(
        &self,
        scope: &ResolvedWorkspaceScope,
        selected_root: &Path,
    ) -> Result<(), ControlError> {
        let limit = forge_domain::LocationListLimit::new(MAX_EFFECT_LOCATIONS)
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let locations = self
            .locations
            .list_locations(limit)
            .map_err(map_location_error)?;
        validate_effect_location_count(locations.len())?;
        for location in locations {
            if location.id() == scope.locator().location_id()
                || location.state() != forge_domain::LocationState::Enabled
            {
                continue;
            }
            let location_root = location.root().as_path();
            if !paths_overlap(selected_root, location_root) {
                continue;
            }
            // Equal or nested Location roots still reserve an overlapping
            // effect boundary. A strictly outer discovery Location does not
            // own the selected repository merely by containing its path.
            if location_root.starts_with(selected_root) {
                return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
            }
            // Inspect every intervening ancestor, not only the Location root:
            // a Workspace initialized between that root and the selected
            // repository also owns these files under a different lease store.
            // This bounded path walk neither scans sibling repositories nor
            // weakens descriptor confinement inside the selected Workspace.
            for ancestor in selected_root
                .ancestors()
                .skip(1)
                .take_while(|ancestor| ancestor.starts_with(location_root))
            {
                if WorkspaceStateLayout::inspect_existing(ancestor)
                    .map_err(map_state_layout_error)?
                    .is_some()
                {
                    return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
                }
            }
        }

        let discovery = self
            .locations
            .discover_current(
                scope.locator().location_id(),
                scope.locator().expected_revision(),
            )
            .map_err(map_location_error)?;
        for candidate in discovery.candidates() {
            if candidate.absolute_root() == selected_root
                || !paths_overlap(selected_root, candidate.absolute_root())
            {
                continue;
            }
            if WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
                .map_err(map_state_layout_error)?
                .is_some()
            {
                return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
            }
        }
        Ok(())
    }
}

pub(crate) fn map_diff_artifact_error(error: DiffArtifactStoreError) -> ControlError {
    let code = match &error {
        DiffArtifactStoreError::Scope(source) => match source {
            ConfinedFilesystemError::WorkspaceUnavailable
            | ConfinedFilesystemError::PathChanged
            | ConfinedFilesystemError::CommittedPathChanged => {
                ControlErrorCode::WorkspaceRootConflict
            }
            ConfinedFilesystemError::FileTooLarge { .. }
            | ConfinedFilesystemError::WriteTooLarge { .. }
            | ConfinedFilesystemError::LockBusy => ControlErrorCode::FileCapacityExceeded,
            _ => ControlErrorCode::PersistenceFailure,
        },
        DiffArtifactStoreError::DirectoryPathChanged => ControlErrorCode::WorkspaceRootConflict,
        DiffArtifactStoreError::CompressedTooLarge { .. }
        | DiffArtifactStoreError::RenderedTooLarge { .. } => ControlErrorCode::FileCapacityExceeded,
        DiffArtifactStoreError::IdentityCollision => ControlErrorCode::FileConflict,
        DiffArtifactStoreError::AtomicPublishUnsupported
        | DiffArtifactStoreError::Missing
        | DiffArtifactStoreError::CorruptPayload
        | DiffArtifactStoreError::SizeOverflow
        | DiffArtifactStoreError::InvalidRelativePath(_)
        | DiffArtifactStoreError::InvalidInventoryName
        | DiffArtifactStoreError::Syscall { .. }
        | DiffArtifactStoreError::Io { .. } => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

pub(crate) fn authorize_activity(
    store: &WorkspaceStore,
    scope: FileActivityScope,
) -> Result<forge_domain::RegisteredActivity, ControlError> {
    let activity = store
        .get_activity(scope.activity_id)
        .map_err(map_activity_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityNotFound))?;
    if activity.state() != ActivityState::Open {
        return Err(ControlError::new(ControlErrorCode::ActivityConflict));
    }
    Ok(activity)
}

/// Authorize a native effect whose caller is not represented by a durable
/// Agent/session provenance record. These paths must still prove that the
/// supplied runtime owns the Activity heartbeat and that the lease is live at
/// the observation time; authenticated participant reads and Agent-attributed
/// mutations use [`authorize_activity`] instead.
pub(crate) fn authorize_owned_live_activity(
    store: &WorkspaceStore,
    scope: FileActivityScope,
) -> Result<forge_domain::RegisteredActivity, ControlError> {
    let activity = authorize_activity(store, scope)?;
    if activity.lease_owner_id() != Some(scope.runtime_instance_id)
        || activity
            .lease_until()
            .is_none_or(|until| until.get() <= scope.observed_at.get())
    {
        return Err(ControlError::new(ControlErrorCode::ActivityLeaseConflict));
    }
    Ok(activity)
}

fn validate_effect_location_count(count: usize) -> Result<(), ControlError> {
    if count >= MAX_EFFECT_LOCATIONS_USIZE {
        Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap))
    } else {
        Ok(())
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn map_filesystem_error(error: ConfinedFilesystemError) -> ControlError {
    let code = match &error {
        ConfinedFilesystemError::ProtectedPath
        | ConfinedFilesystemError::InvalidPath
        | ConfinedFilesystemError::TooManyComponents
        | ConfinedFilesystemError::GeneratedPath
        | ConfinedFilesystemError::SymlinkRejected
        | ConfinedFilesystemError::NonDirectoryAncestor
        | ConfinedFilesystemError::NonRegularLeaf
        | ConfinedFilesystemError::HardlinkRejected => ControlErrorCode::FilePathDenied,
        ConfinedFilesystemError::InvalidPathKind { .. } => ControlErrorCode::InvalidPathKind,
        ConfinedFilesystemError::NotFound => ControlErrorCode::FileNotFound,
        ConfinedFilesystemError::PathConflict
        | ConfinedFilesystemError::StaleWrite
        | ConfinedFilesystemError::PathChanged
        | ConfinedFilesystemError::CommittedPathChanged
        | ConfinedFilesystemError::CommittedObservationFailed
        | ConfinedFilesystemError::PostStateMismatch => ControlErrorCode::FileConflict,
        ConfinedFilesystemError::FileTooLarge { .. }
        | ConfinedFilesystemError::StateRemovalTooLarge { .. }
        | ConfinedFilesystemError::StateRemovalTooDeep { .. }
        | ConfinedFilesystemError::WriteTooLarge { .. }
        | ConfinedFilesystemError::LockBusy
        | ConfinedFilesystemError::OutputTooLarge { .. } => ControlErrorCode::FileCapacityExceeded,
        ConfinedFilesystemError::WorkspaceUnavailable
        | ConfinedFilesystemError::WorkspaceRootTooDeep => ControlErrorCode::WorkspaceRootConflict,
        ConfinedFilesystemError::InvalidPayload
        | ConfinedFilesystemError::AtomicCreateUnsupported
        | ConfinedFilesystemError::AtomicMoveUnsupported
        | ConfinedFilesystemError::Syscall { .. }
        | ConfinedFilesystemError::StdIo { .. } => ControlErrorCode::PersistenceFailure,
    };
    let details = match &error {
        ConfinedFilesystemError::InvalidPathKind { expected, actual } => {
            ControlErrorDetails::PathKind {
                expected: *expected,
                actual: *actual,
            }
        }
        _ => ControlErrorDetails::None,
    };
    ControlError::with_source(code, error).with_details(details)
}

#[cfg(test)]
#[path = "source_write_test_support.rs"]
pub(crate) mod source_write_test_support;

#[cfg(test)]
mod tests {
    mod binding_activation;
    mod binding_reservation;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        BootstrapActivity, EstablishWorkspace, LocationId, LocationRevision, RuntimeInstanceId,
        TimestampMillis, WorkspaceId, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_persistence::GlobalRegistry;
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;

    struct Fixture {
        root: PathBuf,
        control: ForgeControl,
        scope: ResolvedWorkspaceScope,
        activity: FileActivityScope,
        write_authority: forge_domain::SourceWriteAuthority,
    }

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        Ok(TimestampMillis::new(millis)?)
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let unique = Uuid::now_v7();
        let root = std::env::temp_dir().join(format!("forge-control-file-{label}-{unique}"));
        let location_root = root.join("location");
        fixture_at(root, &location_root)
    }

    fn fixture_at(
        root: PathBuf,
        location_root: &Path,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let mut locations = LocationService::new(registry);
        let location_id = LocationId::from_uuid(id(0xC100));
        locations.register_selected_path(location_id, "Location", location_root, timestamp(1)?)?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let workspace_id = WorkspaceId::from_uuid(id(0xC101));
        let activity_id = ActivityId::from_uuid(id(0xC102));
        let runtime_id = RuntimeInstanceId::from_uuid(id(0xC103));
        let lease_until = TimestampMillis::new(
            timestamp_now()?
                .get()
                .checked_add(60_000)
                .ok_or("Activity lease deadline overflow")?,
        )?;
        let mut store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                timestamp(2)?,
            ),
        )?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            runtime_id,
            lease_until,
            timestamp(3)?,
        ))?;
        drop(store);
        let control =
            ForgeControl::from_location_service(locations, root.join("agent-sessions.sqlite3"));
        let locator = WorkspaceLocator::new(
            location_id,
            LocationRevision::INITIAL,
            Path::new("workspace"),
        )?;
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        let observed_at = timestamp(10)?;
        let activity = FileActivityScope {
            activity_id,
            runtime_instance_id: runtime_id,
            observed_at,
        };
        let write_authority = source_write_test_support::seed_source_write_authority(
            &control,
            &scope,
            &source_write_test_support::SourceWriteTestRequest::new(
                activity_id,
                observed_at,
                0xC109,
                &["src/lib.rs"],
            ),
        )?;
        Ok(Fixture {
            root,
            control,
            scope,
            activity,
            write_authority,
        })
    }

    fn workspace_root(fixture: &Fixture) -> PathBuf {
        fixture.root.join("location/workspace")
    }

    #[test]
    fn control_file_read_requires_open_activity_and_redacts_scope_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("read")?;
        fs::write(workspace_root(&fixture).join("read.txt"), b"hello")?;
        let request = FileReadRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("read.txt"))?,
        };
        assert_eq!(
            fixture.control.file_read(&request)?.read().content(),
            b"hello"
        );
        let mut other_runtime = request;
        other_runtime.activity.runtime_instance_id = RuntimeInstanceId::from_uuid(id(0xFFFF));
        assert_eq!(
            fixture.control.file_read(&other_runtime)?.read().content(),
            b"hello"
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn truncated_location_scan_fails_closed_before_effect_authorization() {
        assert!(validate_effect_location_count(MAX_EFFECT_LOCATIONS_USIZE - 1).is_ok());
        assert_eq!(
            validate_effect_location_count(MAX_EFFECT_LOCATIONS_USIZE)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceScopeOverlap)
        );
    }
}
