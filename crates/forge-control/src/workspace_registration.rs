//! Explicit Workspace establishment and read-only registration observation.
//! The application owner is shared by native/Desktop and HTTP adapters.

use forge_domain::{
    EstablishWorkspace, RegisteredWorkspace, TimestampMillis, WorkspaceId, WorkspaceRoot,
    WorkspaceRootError, WorkspaceRootFingerprint,
};
use forge_persistence::{WorkspaceStore, WorkspaceStoreError};
use forge_workspace::{
    LocationRepository, LocationRepositoryError, LocationService, LocationServiceError,
    StateLayoutError, WorkspaceDiscoveryError, WorkspaceKeyResolveError, WorkspaceLocator,
    WorkspaceStateLayout,
};
use thiserror::Error;

use crate::{ControlError, ControlErrorCode, ForgeControl};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRegistrationRequest {
    locator: WorkspaceLocator,
    proposed_workspace_id: WorkspaceId,
    expected_root_fingerprint: WorkspaceRootFingerprint,
    observed_at: TimestampMillis,
}

impl WorkspaceRegistrationRequest {
    pub fn new(
        locator: WorkspaceLocator,
        proposed_workspace_id: WorkspaceId,
        expected_root_fingerprint: WorkspaceRootFingerprint,
        observed_at: TimestampMillis,
    ) -> Result<Self, WorkspaceRegistrationError> {
        if proposed_workspace_id.into_uuid().is_nil() {
            return Err(WorkspaceRegistrationError::InvalidIdentity);
        }
        Ok(Self {
            locator,
            proposed_workspace_id,
            expected_root_fingerprint,
            observed_at,
        })
    }
    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }
    pub const fn proposed_workspace_id(&self) -> WorkspaceId {
        self.proposed_workspace_id
    }
    pub const fn expected_root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.expected_root_fingerprint
    }
}

/// Current observation only; absence is not a historical non-commit receipt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRegistrationProbe {
    pub locator: WorkspaceLocator,
    pub root_fingerprint: WorkspaceRootFingerprint,
    pub workspace: Option<RegisteredWorkspace>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceRegistrationOutcome {
    Confirmed(RegisteredWorkspace),
    CommittedButUnconfirmed {
        workspace: RegisteredWorkspace,
        reason: WorkspaceRevalidationReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WorkspaceRevalidationReason {
    #[error("Location revision changed")]
    LocationRevisionChanged,
    #[error("Location is unavailable")]
    LocationUnavailable,
    #[error("Location is disabled")]
    LocationDisabled,
    #[error("Workspace candidate is stale")]
    CandidateStale,
    #[error("Workspace root changed")]
    CandidateRootChanged,
    #[error("Workspace root physical identity changed")]
    CandidateFingerprintChanged,
    #[error("Workspace layout could not be revalidated")]
    LayoutInvalid,
    #[error("the durable Workspace identity changed")]
    WorkspaceIdentityChanged,
}

#[derive(Debug, Error)]
pub enum WorkspaceRegistrationError {
    #[error("the proposed Workspace identity must not be nil")]
    InvalidIdentity,
    #[error("the Workspace root physical identity conflicts with the request")]
    FingerprintConflict,
    #[error("the Workspace root changed while initialization was in progress")]
    InitializationFingerprintConflict,
    #[error("the registered Workspace binding conflicts with the selected root")]
    BindingConflict,
    #[error(transparent)]
    Location(#[from] LocationServiceError),
    #[error(transparent)]
    Layout(#[from] StateLayoutError),
    #[error(transparent)]
    Store(#[from] WorkspaceStoreError),
    #[error(transparent)]
    Root(#[from] WorkspaceRootError),
}

/// Observe the current candidate and durable identity without creating state,
/// changing Git excludes, upgrading a schema or migrating a database.
pub fn probe_workspace_registration<R: LocationRepository>(
    service: &LocationService<R>,
    locator: &WorkspaceLocator,
) -> Result<WorkspaceRegistrationProbe, WorkspaceRegistrationError> {
    let candidate = service.resolve_candidate_current(
        locator.location_id(),
        locator.expected_revision(),
        &locator.candidate_key(),
    )?;
    let fingerprint = WorkspaceStateLayout::observe_root_fingerprint(candidate.absolute_root())?;
    let workspace = WorkspaceStateLayout::inspect_existing(candidate.absolute_root())?
        .map(|layout| WorkspaceStore::inspect_existing_identity_live_read_only(&layout))
        .transpose()?;
    if workspace.as_ref().is_some_and(|record| {
        record.location_id() != locator.location_id()
            || record.root().as_path() != candidate.absolute_root()
            || record.root_fingerprint() != fingerprint
    }) {
        return Err(WorkspaceRegistrationError::BindingConflict);
    }
    let current = service.resolve_candidate_current(
        locator.location_id(),
        locator.expected_revision(),
        &locator.candidate_key(),
    )?;
    if current.absolute_root() != candidate.absolute_root()
        || WorkspaceStateLayout::observe_root_fingerprint(current.absolute_root())? != fingerprint
    {
        return Err(WorkspaceRegistrationError::FingerprintConflict);
    }
    Ok(WorkspaceRegistrationProbe {
        locator: locator.clone(),
        root_fingerprint: fingerprint,
        workspace,
    })
}

/// Explicitly establish/open the selected physical root. A proposed identity
/// applies only to a fresh database; an existing durable identity is retained.
pub fn register_workspace<R: LocationRepository>(
    service: &mut LocationService<R>,
    request: &WorkspaceRegistrationRequest,
) -> Result<WorkspaceRegistrationOutcome, WorkspaceRegistrationError> {
    register_workspace_with_hook(service, request, |_| {})
}

fn register_workspace_with_hook<R: LocationRepository, Hook: FnOnce(&mut LocationService<R>)>(
    service: &mut LocationService<R>,
    request: &WorkspaceRegistrationRequest,
    after_store: Hook,
) -> Result<WorkspaceRegistrationOutcome, WorkspaceRegistrationError> {
    let candidate = service.resolve_candidate_current(
        request.locator.location_id(),
        request.locator.expected_revision(),
        &request.locator.candidate_key(),
    )?;
    if WorkspaceStateLayout::observe_root_fingerprint(candidate.absolute_root())?
        != request.expected_root_fingerprint
    {
        return Err(WorkspaceRegistrationError::FingerprintConflict);
    }
    let layout = WorkspaceStateLayout::initialize(candidate.absolute_root())?;
    let fingerprint = layout.root_fingerprint()?;
    if fingerprint != request.expected_root_fingerprint {
        return Err(WorkspaceRegistrationError::InitializationFingerprintConflict);
    }
    let command = EstablishWorkspace::new(
        request.proposed_workspace_id,
        request.locator.location_id(),
        WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
        fingerprint,
        request.observed_at,
    );
    let store = WorkspaceStore::open(&layout, &command)?;
    let committed = store.workspace()?;
    after_store(service);

    // Post-commit observation must never initialize a replacement directory.
    // The committed record stays explicit even when current selection fails.
    let confirmation = revalidate_committed(service, &request.locator, &committed);
    Ok(match confirmation {
        Ok(()) => WorkspaceRegistrationOutcome::Confirmed(committed),
        Err(reason) => WorkspaceRegistrationOutcome::CommittedButUnconfirmed {
            workspace: committed,
            reason,
        },
    })
}

fn revalidate_committed<R: LocationRepository>(
    service: &LocationService<R>,
    locator: &WorkspaceLocator,
    workspace: &RegisteredWorkspace,
) -> Result<(), WorkspaceRevalidationReason> {
    let current = service
        .resolve_candidate_current(
            locator.location_id(),
            locator.expected_revision(),
            &locator.candidate_key(),
        )
        .map_err(|error| revalidation_reason(&error))?;
    if current.absolute_root() != workspace.root().as_path() {
        return Err(WorkspaceRevalidationReason::CandidateRootChanged);
    }
    let fingerprint = WorkspaceStateLayout::observe_root_fingerprint(current.absolute_root())
        .map_err(|_| WorkspaceRevalidationReason::LayoutInvalid)?;
    if fingerprint != workspace.root_fingerprint() {
        return Err(WorkspaceRevalidationReason::CandidateFingerprintChanged);
    }
    let current_layout = WorkspaceStateLayout::inspect_existing(current.absolute_root())
        .map_err(|_| WorkspaceRevalidationReason::LayoutInvalid)?
        .ok_or(WorkspaceRevalidationReason::LayoutInvalid)?;
    let current_workspace =
        WorkspaceStore::inspect_existing_identity_live_read_only(&current_layout)
            .map_err(|_| WorkspaceRevalidationReason::LayoutInvalid)?;
    if current_workspace != *workspace {
        return Err(WorkspaceRevalidationReason::WorkspaceIdentityChanged);
    }
    Ok(())
}

fn revalidation_reason(error: &LocationServiceError) -> WorkspaceRevalidationReason {
    match error {
        LocationServiceError::Repository(LocationRepositoryError::RevisionConflict { .. }) => {
            WorkspaceRevalidationReason::LocationRevisionChanged
        }
        LocationServiceError::Repository(LocationRepositoryError::NotFound(_)) => {
            WorkspaceRevalidationReason::LocationUnavailable
        }
        LocationServiceError::Discovery(WorkspaceDiscoveryError::LocationDisabled(_)) => {
            WorkspaceRevalidationReason::LocationDisabled
        }
        LocationServiceError::Discovery(
            WorkspaceDiscoveryError::LocationIdentityMoved { .. }
            | WorkspaceDiscoveryError::LocationIsNotDirectory(_)
            | WorkspaceDiscoveryError::CanonicalizeLocation { .. },
        ) => WorkspaceRevalidationReason::CandidateRootChanged,
        LocationServiceError::WorkspaceKey(
            WorkspaceKeyResolveError::NotFound { .. }
            | WorkspaceKeyResolveError::LocationMismatch { .. },
        )
        | LocationServiceError::WorkspaceResolve(_)
        | LocationServiceError::WorkspaceLocator(_) => WorkspaceRevalidationReason::CandidateStale,
        _ => WorkspaceRevalidationReason::LocationUnavailable,
    }
}

impl ForgeControl {
    pub fn register_workspace(
        &mut self,
        request: &WorkspaceRegistrationRequest,
    ) -> Result<WorkspaceRegistrationOutcome, ControlError> {
        register_workspace(&mut self.locations, request).map_err(|error| {
            let may_have_effect = matches!(
                &error,
                WorkspaceRegistrationError::Layout(_)
                    | WorkspaceRegistrationError::InitializationFingerprintConflict
                    | WorkspaceRegistrationError::Store(_)
                    | WorkspaceRegistrationError::Root(_)
            );
            let mapped = map_registration_error(error);
            if may_have_effect {
                mapped.with_details(crate::ControlErrorDetails::WorkspaceRegistrationUnknown)
            } else {
                mapped
            }
        })
    }
    pub fn probe_workspace_registration(
        &self,
        locator: &WorkspaceLocator,
    ) -> Result<WorkspaceRegistrationProbe, ControlError> {
        probe_workspace_registration(&self.locations, locator).map_err(map_registration_error)
    }
}

fn map_registration_error(error: WorkspaceRegistrationError) -> ControlError {
    match error {
        WorkspaceRegistrationError::InvalidIdentity => {
            ControlError::new(ControlErrorCode::InvalidInput)
        }
        WorkspaceRegistrationError::FingerprintConflict
        | WorkspaceRegistrationError::InitializationFingerprintConflict => {
            ControlError::new(ControlErrorCode::WorkspaceRootConflict)
        }
        WorkspaceRegistrationError::BindingConflict => {
            ControlError::new(ControlErrorCode::WorkspaceIdentityConflict)
        }
        WorkspaceRegistrationError::Location(source) => crate::service::map_location_error(source),
        WorkspaceRegistrationError::Layout(source) => {
            crate::service::map_state_layout_error(source)
        }
        WorkspaceRegistrationError::Store(source) => crate::service::map_store_error(source),
        WorkspaceRegistrationError::Root(source) => {
            ControlError::with_source(ControlErrorCode::InvalidInput, source)
        }
    }
}

#[cfg(test)]
mod tests;
