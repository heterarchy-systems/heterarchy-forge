//! Owner-confirmed Workspace root-binding recovery orchestration.
//!
//! This module owns Location/candidate admission and post-commit revalidation;
//! SQLite identity, schema, authority fencing and the receipt/CAS remain in
//! `forge-persistence`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use forge_domain::{
    LocationId, LocationListLimit, LocationRevision, LocationState, RegisteredLocation,
    RegisteredWorkspace, WorkspaceId, WorkspaceRootFingerprint, WorkspaceRootRecoveryAuthorityMode,
    WorkspaceRootRecoveryDelegatedAuthority, WorkspaceRootRecoveryObservation,
    WorkspaceRootRecoveryRequest,
};
use forge_persistence::{
    RootRecoveryOperation, RootRecoveryReceipt, RootRecoveryStoreError, WorkspaceStore,
};
use forge_workspace::{
    ExistingWorkspaceStateLayout, WorkspaceCandidate, WorkspaceLocator,
    WorkspaceStateExclusiveGate, WorkspaceStateLayout,
};
use thiserror::Error;
use uuid::Uuid;

use crate::service::{ForgeControl, map_location_error, map_state_layout_error};
use crate::{ControlError, ControlErrorCode};

const MAX_RECOVERY_SCAN_LOCATIONS: usize = 32;
const RECOVERY_SCAN_LOCATION_PROBE: usize = MAX_RECOVERY_SCAN_LOCATIONS + 1;
const ROOT_FINGERPRINT_DEVICE_BYTES: usize = 8;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryProbeRequest {
    locator: WorkspaceLocator,
    expected_workspace_id: Option<WorkspaceId>,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

impl WorkspaceRootRecoveryProbeRequest {
    pub const fn new(
        locator: WorkspaceLocator,
        expected_workspace_id: Option<WorkspaceId>,
    ) -> Self {
        Self {
            locator,
            expected_workspace_id,
            authority_mode: WorkspaceRootRecoveryAuthorityMode::Quiescent,
        }
    }

    pub const fn new_preserving_delegated_freeze(
        locator: WorkspaceLocator,
        expected_workspace_id: Option<WorkspaceId>,
        authority: WorkspaceRootRecoveryDelegatedAuthority,
    ) -> Self {
        Self {
            locator,
            expected_workspace_id,
            authority_mode: WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority),
        }
    }

    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }

    pub const fn expected_workspace_id(&self) -> Option<WorkspaceId> {
        self.expected_workspace_id
    }

    pub const fn authority_mode(&self) -> WorkspaceRootRecoveryAuthorityMode {
        self.authority_mode
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryProbe {
    locator: WorkspaceLocator,
    location_revision: LocationRevision,
    workspace: RegisteredWorkspace,
    observation: WorkspaceRootRecoveryObservation,
    schema_version: i64,
    requires_schema_upgrade: bool,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

impl WorkspaceRootRecoveryProbe {
    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }

    pub const fn location_revision(&self) -> LocationRevision {
        self.location_revision
    }

    pub const fn workspace(&self) -> &RegisteredWorkspace {
        &self.workspace
    }

    pub const fn observation(&self) -> &WorkspaceRootRecoveryObservation {
        &self.observation
    }

    pub const fn schema_version(&self) -> i64 {
        self.schema_version
    }

    pub const fn requires_schema_upgrade(&self) -> bool {
        self.requires_schema_upgrade
    }

    pub const fn authority_mode(&self) -> WorkspaceRootRecoveryAuthorityMode {
        self.authority_mode
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryPrepareRequest {
    locator: WorkspaceLocator,
    expected_workspace: RegisteredWorkspace,
    observation: WorkspaceRootRecoveryObservation,
    operator_confirmed: bool,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

impl WorkspaceRootRecoveryPrepareRequest {
    pub const fn new(
        locator: WorkspaceLocator,
        expected_workspace: RegisteredWorkspace,
        observation: WorkspaceRootRecoveryObservation,
        operator_confirmed: bool,
    ) -> Self {
        Self {
            locator,
            expected_workspace,
            observation,
            operator_confirmed,
            authority_mode: WorkspaceRootRecoveryAuthorityMode::Quiescent,
        }
    }

    pub const fn new_preserving_delegated_freeze(
        locator: WorkspaceLocator,
        expected_workspace: RegisteredWorkspace,
        observation: WorkspaceRootRecoveryObservation,
        operator_confirmed: bool,
        authority: WorkspaceRootRecoveryDelegatedAuthority,
    ) -> Self {
        Self {
            locator,
            expected_workspace,
            observation,
            operator_confirmed,
            authority_mode: WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority),
        }
    }

    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }

    pub const fn expected_workspace(&self) -> &RegisteredWorkspace {
        &self.expected_workspace
    }

    pub const fn observation(&self) -> &WorkspaceRootRecoveryObservation {
        &self.observation
    }

    pub const fn operator_confirmed(&self) -> bool {
        self.operator_confirmed
    }

    pub const fn authority_mode(&self) -> WorkspaceRootRecoveryAuthorityMode {
        self.authority_mode
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryCommitRequest {
    locator: WorkspaceLocator,
    intent: WorkspaceRootRecoveryRequest,
    operator_confirmed: bool,
}

impl WorkspaceRootRecoveryCommitRequest {
    pub const fn new(
        locator: WorkspaceLocator,
        intent: WorkspaceRootRecoveryRequest,
        operator_confirmed: bool,
    ) -> Self {
        Self {
            locator,
            intent,
            operator_confirmed,
        }
    }

    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }

    pub const fn intent(&self) -> &WorkspaceRootRecoveryRequest {
        &self.intent
    }

    pub const fn operator_confirmed(&self) -> bool {
        self.operator_confirmed
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRootRecoveryReadbackRequest {
    locator: WorkspaceLocator,
    request_id: Uuid,
    intent: Option<WorkspaceRootRecoveryRequest>,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

impl WorkspaceRootRecoveryReadbackRequest {
    pub const fn new(
        locator: WorkspaceLocator,
        request_id: Uuid,
        intent: Option<WorkspaceRootRecoveryRequest>,
    ) -> Self {
        Self {
            locator,
            request_id,
            intent,
            authority_mode: WorkspaceRootRecoveryAuthorityMode::Quiescent,
        }
    }

    pub const fn new_preserving_delegated_freeze(
        locator: WorkspaceLocator,
        request_id: Uuid,
        intent: Option<WorkspaceRootRecoveryRequest>,
        authority: WorkspaceRootRecoveryDelegatedAuthority,
    ) -> Self {
        Self {
            locator,
            request_id,
            intent,
            authority_mode: WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority),
        }
    }

    pub const fn locator(&self) -> &WorkspaceLocator {
        &self.locator
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn intent(&self) -> Option<&WorkspaceRootRecoveryRequest> {
        self.intent.as_ref()
    }

    pub const fn authority_mode(&self) -> WorkspaceRootRecoveryAuthorityMode {
        self.authority_mode
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WorkspaceRootRecoveryRevalidationReason {
    #[error("the selected Location revision changed")]
    LocationRevisionChanged,
    #[error("the selected candidate root changed")]
    CandidateRootChanged,
    #[error("the selected root fingerprint changed")]
    CandidateFingerprintChanged,
    #[error("the durable Workspace identity changed")]
    WorkspaceIdentityChanged,
    #[error("the registered Workspace inventory could not confirm the result")]
    InventoryUnavailable,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceRootRecoveryCommitOutcome {
    Committed {
        receipt: RootRecoveryReceipt,
    },
    Replayed {
        receipt: RootRecoveryReceipt,
    },
    CommittedButUnconfirmed {
        receipt: RootRecoveryReceipt,
        reason: WorkspaceRootRecoveryRevalidationReason,
    },
}

impl ForgeControl {
    pub fn probe_workspace_root_recovery(
        &self,
        request: &WorkspaceRootRecoveryProbeRequest,
    ) -> Result<WorkspaceRootRecoveryProbe, ControlError> {
        let (location, candidate, layout) = self.resolve_recovery_candidate(request.locator())?;
        let identity = WorkspaceStore::inspect_existing_root_recovery_identity_read_only(&layout)
            .map_err(map_root_recovery_error)?;
        validate_selected_identity(
            &location,
            &candidate,
            identity.workspace(),
            request.expected_workspace_id(),
        )?;
        self.scan_recovery_identities(
            location.id(),
            candidate.absolute_root(),
            identity.workspace(),
        )?;
        let current_fingerprint = identity.current_root_fingerprint();
        let gate =
            WorkspaceStateExclusiveGate::acquire(candidate.absolute_root(), current_fingerprint)
                .map_err(|source| {
                    ControlError::with_source(ControlErrorCode::WorkspaceRootConflict, source)
                })?;
        let persistence_probe = match request.authority_mode() {
            WorkspaceRootRecoveryAuthorityMode::Quiescent => {
                WorkspaceStore::probe_root_recovery(&layout, &gate, identity.workspace())
            }
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) => {
                WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
                    &layout,
                    &gate,
                    identity.workspace(),
                    authority,
                )
            }
        }
        .map_err(map_root_recovery_error)?;
        drop(gate);
        self.revalidate_location_candidate(request.locator(), candidate.absolute_root())?;
        Ok(WorkspaceRootRecoveryProbe {
            locator: request.locator().clone(),
            location_revision: request.locator().expected_revision(),
            workspace: persistence_probe.workspace().clone(),
            observation: persistence_probe.observation().clone(),
            schema_version: persistence_probe.schema_version(),
            requires_schema_upgrade: persistence_probe.requires_schema_upgrade(),
            authority_mode: persistence_probe.authority_mode(),
        })
    }

    pub fn prepare_workspace_root_recovery(
        &self,
        request: &WorkspaceRootRecoveryPrepareRequest,
    ) -> Result<WorkspaceRootRecoveryProbe, ControlError> {
        if !request.operator_confirmed() {
            return Err(ControlError::new(ControlErrorCode::AuthorizationRequired));
        }
        let (location, candidate, layout) = self.resolve_recovery_candidate(request.locator())?;
        let identity = WorkspaceStore::inspect_existing_root_recovery_identity_read_only(&layout)
            .map_err(map_root_recovery_error)?;
        validate_selected_identity(
            &location,
            &candidate,
            identity.workspace(),
            Some(request.expected_workspace().id()),
        )?;
        if identity.workspace() != request.expected_workspace()
            || identity.current_root_fingerprint() != request.observation().fingerprint()
            || (matches!(
                request.authority_mode(),
                WorkspaceRootRecoveryAuthorityMode::Quiescent
            ) && identity.witness() != request.observation().witness())
        {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        validate_physical_transition(
            request.expected_workspace().root_fingerprint(),
            request.observation().fingerprint(),
        )?;
        self.scan_recovery_identities(
            location.id(),
            candidate.absolute_root(),
            identity.workspace(),
        )?;
        let current_fingerprint = identity.current_root_fingerprint();
        let gate =
            WorkspaceStateExclusiveGate::acquire(candidate.absolute_root(), current_fingerprint)
                .map_err(|source| {
                    ControlError::with_source(ControlErrorCode::WorkspaceRootConflict, source)
                })?;
        let initial = match request.authority_mode() {
            WorkspaceRootRecoveryAuthorityMode::Quiescent => {
                WorkspaceStore::probe_root_recovery(&layout, &gate, request.expected_workspace())
            }
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) => {
                WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
                    &layout,
                    &gate,
                    request.expected_workspace(),
                    authority,
                )
            }
        }
        .map_err(map_root_recovery_error)?;
        if initial.observation() != request.observation() {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        if initial.authority_mode() != request.authority_mode() {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        let prepared = WorkspaceStore::prepare_root_recovery(&layout, &gate, &initial)
            .map_err(map_root_recovery_error)?;
        if initial.schema_version() == prepared.schema_version()
            && prepared.observation() != request.observation()
        {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        drop(gate);
        self.revalidate_location_candidate(request.locator(), candidate.absolute_root())?;
        Ok(WorkspaceRootRecoveryProbe {
            locator: request.locator().clone(),
            location_revision: request.locator().expected_revision(),
            workspace: prepared.workspace().clone(),
            observation: prepared.observation().clone(),
            schema_version: prepared.schema_version(),
            requires_schema_upgrade: prepared.requires_schema_upgrade(),
            authority_mode: prepared.authority_mode(),
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "The exact replay, freshness fences and committed-uncertainty path stay visible in one transaction boundary."
    )]
    pub fn commit_workspace_root_recovery(
        &self,
        request: &WorkspaceRootRecoveryCommitRequest,
    ) -> Result<WorkspaceRootRecoveryCommitOutcome, ControlError> {
        if !request.operator_confirmed() {
            return Err(ControlError::new(ControlErrorCode::AuthorizationRequired));
        }
        if request.intent().location_revision() != request.locator().expected_revision() {
            return Err(ControlError::new(
                ControlErrorCode::LocationRevisionConflict,
            ));
        }
        let (location, candidate, layout) = self.resolve_recovery_candidate(request.locator())?;
        let current_fingerprint =
            WorkspaceStateLayout::observe_root_fingerprint(candidate.absolute_root())
                .map_err(map_state_layout_error)?;
        let gate =
            WorkspaceStateExclusiveGate::acquire(candidate.absolute_root(), current_fingerprint)
                .map_err(|source| {
                    ControlError::with_source(ControlErrorCode::WorkspaceRootConflict, source)
                })?;
        if let Some(receipt) = WorkspaceStore::root_recovery_receipt_for_request_under_gate(
            &layout,
            &gate,
            request.intent(),
        )
        .map_err(map_root_recovery_error)?
        {
            drop(gate);
            return Ok(self.confirm_recovery_result(request.locator(), receipt, true));
        }
        drop(gate);

        let identity = WorkspaceStore::inspect_existing_root_recovery_identity_read_only(&layout)
            .map_err(map_root_recovery_error)?;
        validate_selected_identity(
            &location,
            &candidate,
            identity.workspace(),
            Some(request.intent().expected().id()),
        )?;
        if identity.workspace() != request.intent().expected()
            || identity.current_root_fingerprint() != request.intent().observed().fingerprint()
            || (matches!(
                request.intent().authority_mode(),
                WorkspaceRootRecoveryAuthorityMode::Quiescent
            ) && identity.witness() != request.intent().observed().witness())
        {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        validate_physical_transition(
            request.intent().expected().root_fingerprint(),
            request.intent().observed().fingerprint(),
        )?;
        self.scan_recovery_identities(
            location.id(),
            candidate.absolute_root(),
            identity.workspace(),
        )?;
        let gate = WorkspaceStateExclusiveGate::acquire(
            candidate.absolute_root(),
            identity.current_root_fingerprint(),
        )
        .map_err(|source| {
            ControlError::with_source(ControlErrorCode::WorkspaceRootConflict, source)
        })?;
        let fresh = match request.intent().authority_mode() {
            WorkspaceRootRecoveryAuthorityMode::Quiescent => {
                WorkspaceStore::probe_root_recovery(&layout, &gate, request.intent().expected())
            }
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) => {
                WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
                    &layout,
                    &gate,
                    request.intent().expected(),
                    authority,
                )
            }
        }
        .map_err(map_root_recovery_error)?;
        if fresh.observation() != request.intent().observed() {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        let result = WorkspaceStore::recover_root_binding(&layout, &gate, &fresh, request.intent());
        match result {
            Ok(RootRecoveryOperation::Committed(receipt)) => {
                drop(gate);
                Ok(self.confirm_recovery_result(request.locator(), receipt, false))
            }
            Ok(RootRecoveryOperation::Replay(receipt)) => {
                drop(gate);
                Ok(self.confirm_recovery_result(request.locator(), receipt, true))
            }
            Err(error @ RootRecoveryStoreError::CommittedUnconfirmed { .. }) => {
                let Ok(Some(receipt)) =
                    WorkspaceStore::root_recovery_receipt_for_request_under_gate(
                        &layout,
                        &gate,
                        request.intent(),
                    )
                else {
                    return Err(ControlError::committed());
                };
                drop(gate);
                let mut outcome = self.confirm_recovery_result(request.locator(), receipt, false);
                if matches!(
                    outcome,
                    WorkspaceRootRecoveryCommitOutcome::Committed { .. }
                ) {
                    outcome = match outcome {
                        WorkspaceRootRecoveryCommitOutcome::Committed { receipt } => {
                            WorkspaceRootRecoveryCommitOutcome::CommittedButUnconfirmed {
                                receipt,
                                reason:
                                    WorkspaceRootRecoveryRevalidationReason::InventoryUnavailable,
                            }
                        }
                        other => other,
                    };
                }
                let _ = error;
                Ok(outcome)
            }
            Err(error) => Err(map_root_recovery_error(error)),
        }
    }

    pub fn readback_workspace_root_recovery(
        &self,
        request: &WorkspaceRootRecoveryReadbackRequest,
    ) -> Result<Option<RootRecoveryReceipt>, ControlError> {
        let (_location, _candidate, layout) = self.resolve_recovery_candidate(request.locator())?;
        let receipt = if let Some(intent) = request.intent() {
            WorkspaceStore::root_recovery_receipt_for_request(&layout, intent)
                .map_err(map_root_recovery_error)
        } else {
            WorkspaceStore::root_recovery_receipt(&layout, request.request_id())
                .map_err(map_root_recovery_error)
        }?;
        if receipt
            .as_ref()
            .is_some_and(|receipt| receipt.authority_mode() != request.authority_mode())
        {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceIdentityConflict,
            ));
        }
        Ok(receipt)
    }

    fn resolve_recovery_candidate(
        &self,
        locator: &WorkspaceLocator,
    ) -> Result<
        (
            RegisteredLocation,
            WorkspaceCandidate,
            ExistingWorkspaceStateLayout,
        ),
        ControlError,
    > {
        let location = self
            .locations
            .get_current_location(locator.location_id(), locator.expected_revision())
            .map_err(map_location_error)?;
        let candidate = self
            .locations
            .resolve_locator_current(locator)
            .map_err(map_location_error)?;
        let layout = WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
            .map_err(map_state_layout_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::WorkspaceNotInitialized))?;
        Ok((location, candidate, layout))
    }

    fn revalidate_location_candidate(
        &self,
        locator: &WorkspaceLocator,
        expected_root: &Path,
    ) -> Result<(), ControlError> {
        let candidate = self
            .locations
            .resolve_locator_current(locator)
            .map_err(map_location_error)?;
        if candidate.absolute_root() != expected_root {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(())
    }

    fn confirm_recovery_result(
        &self,
        locator: &WorkspaceLocator,
        receipt: RootRecoveryReceipt,
        replayed: bool,
    ) -> WorkspaceRootRecoveryCommitOutcome {
        match self.revalidate_recovery_commit(locator, &receipt) {
            Ok(()) => {
                if replayed {
                    WorkspaceRootRecoveryCommitOutcome::Replayed { receipt }
                } else {
                    WorkspaceRootRecoveryCommitOutcome::Committed { receipt }
                }
            }
            Err(reason) => {
                WorkspaceRootRecoveryCommitOutcome::CommittedButUnconfirmed { receipt, reason }
            }
        }
    }

    fn revalidate_recovery_commit(
        &self,
        locator: &WorkspaceLocator,
        receipt: &RootRecoveryReceipt,
    ) -> Result<(), WorkspaceRootRecoveryRevalidationReason> {
        let candidate = self
            .locations
            .resolve_locator_current(locator)
            .map_err(|_| WorkspaceRootRecoveryRevalidationReason::LocationRevisionChanged)?;
        if candidate.absolute_root() != receipt.workspace().root().as_path() {
            return Err(WorkspaceRootRecoveryRevalidationReason::CandidateRootChanged);
        }
        let layout = WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
            .map_err(|_| WorkspaceRootRecoveryRevalidationReason::InventoryUnavailable)?
            .ok_or(WorkspaceRootRecoveryRevalidationReason::InventoryUnavailable)?;
        let current = WorkspaceStore::inspect_existing_identity_live_read_only(&layout)
            .map_err(|_| WorkspaceRootRecoveryRevalidationReason::WorkspaceIdentityChanged)?;
        if current != *receipt.workspace() {
            return Err(WorkspaceRootRecoveryRevalidationReason::WorkspaceIdentityChanged);
        }
        let inventory = self
            .registered_workspace_inventory(locator.location_id(), locator.expected_revision())
            .map_err(|_| WorkspaceRootRecoveryRevalidationReason::InventoryUnavailable)?;
        if inventory.entries().iter().any(|entry| {
            entry.locator() == locator && entry.registered_workspace() == Some(receipt.workspace())
        }) {
            Ok(())
        } else {
            Err(WorkspaceRootRecoveryRevalidationReason::InventoryUnavailable)
        }
    }

    fn scan_recovery_identities(
        &self,
        selected_location_id: LocationId,
        selected_root: &Path,
        selected_workspace: &RegisteredWorkspace,
    ) -> Result<(), ControlError> {
        let limit = LocationListLimit::new(
            u32::try_from(RECOVERY_SCAN_LOCATION_PROBE)
                .map_err(|_| ControlError::new(ControlErrorCode::Internal))?,
        )
        .map_err(|_| ControlError::new(ControlErrorCode::Internal))?;
        let locations = self
            .locations
            .list_locations(limit)
            .map_err(map_location_error)?;
        if locations.len() > MAX_RECOVERY_SCAN_LOCATIONS {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceStateUnavailable,
            ));
        }
        let mut seen = HashMap::<WorkspaceId, (LocationId, PathBuf)>::new();
        for location in &locations {
            if location.state() == LocationState::Disabled {
                return Err(ControlError::new(ControlErrorCode::LocationUnavailable));
            }
            let discovery = self
                .locations
                .discover_current(location.id(), location.revision())
                .map_err(map_location_error)?;
            for candidate in discovery.candidates() {
                let is_selected = location.id() == selected_location_id
                    && candidate.absolute_root() == selected_root;
                let identity = if is_selected {
                    selected_workspace.clone()
                } else {
                    let Some(layout) =
                        WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
                            .map_err(map_state_layout_error)?
                    else {
                        continue;
                    };
                    WorkspaceStore::inspect_existing_root_recovery_identity_read_only(&layout)
                        .map_err(|_| {
                            ControlError::new(ControlErrorCode::WorkspaceStateUnavailable)
                        })?
                        .workspace()
                        .clone()
                };
                if identity.location_id() != location.id() {
                    return Err(ControlError::new(
                        ControlErrorCode::WorkspaceIdentityConflict,
                    ));
                }
                if seen
                    .insert(
                        identity.id(),
                        (location.id(), candidate.absolute_root().to_path_buf()),
                    )
                    .is_some()
                {
                    return Err(ControlError::new(
                        ControlErrorCode::WorkspaceIdentityConflict,
                    ));
                }
            }
            let _ = self
                .locations
                .get_current_location(location.id(), location.revision())
                .map_err(map_location_error)?;
        }
        Ok(())
    }
}

fn validate_selected_identity(
    location: &RegisteredLocation,
    candidate: &WorkspaceCandidate,
    workspace: &RegisteredWorkspace,
    expected_workspace_id: Option<WorkspaceId>,
) -> Result<(), ControlError> {
    if workspace.location_id() != location.id()
        || workspace.root().as_path() != candidate.absolute_root()
        || expected_workspace_id.is_some_and(|expected| expected != workspace.id())
    {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    Ok(())
}

/// Recovery accepts only the physical transition classified by the effect
/// layer: the selected canonical path and inode stay the same while the
/// device component changes.  `WorkspaceStateLayout` encodes fingerprints as
/// little-endian device bytes followed by little-endian inode bytes.  The
/// domain keeps this evidence opaque and never infers a historical remount.
fn validate_physical_transition(
    old: WorkspaceRootFingerprint,
    new: WorkspaceRootFingerprint,
) -> Result<(), ControlError> {
    let old = old.into_bytes();
    let new = new.into_bytes();
    if old[ROOT_FINGERPRINT_DEVICE_BYTES..] == new[ROOT_FINGERPRINT_DEVICE_BYTES..]
        && old[..ROOT_FINGERPRINT_DEVICE_BYTES] != new[..ROOT_FINGERPRINT_DEVICE_BYTES]
    {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict))
    }
}

fn map_root_recovery_error(error: RootRecoveryStoreError) -> ControlError {
    match error {
        RootRecoveryStoreError::Store(source) => crate::service::map_store_error(source),
        RootRecoveryStoreError::Intent(_) | RootRecoveryStoreError::ObservationChanged => {
            ControlError::new(ControlErrorCode::WorkspaceRootConflict)
        }
        RootRecoveryStoreError::WorkspaceChanged => {
            ControlError::new(ControlErrorCode::WorkspaceRevisionConflict)
        }
        RootRecoveryStoreError::SchemaUpgradeRequired { .. } => {
            ControlError::new(ControlErrorCode::WorkspaceSchemaOutdated)
        }
        RootRecoveryStoreError::ActiveAuthority(_) => {
            ControlError::new(ControlErrorCode::WorkspaceRemovalBlocked)
        }
        RootRecoveryStoreError::Doctor(_) | RootRecoveryStoreError::ObservationEncoding => {
            ControlError::new(ControlErrorCode::WorkspaceStateUnavailable)
        }
        RootRecoveryStoreError::RequestConflict => {
            ControlError::new(ControlErrorCode::WorkspaceIdentityConflict)
        }
        RootRecoveryStoreError::SchemaMigrationCommittedUnconfirmed { .. }
        | RootRecoveryStoreError::CommittedUnconfirmed { .. }
        | RootRecoveryStoreError::RollbackUnconfirmed { .. }
        | RootRecoveryStoreError::ReceiptReadbackMissing { .. } => ControlError::committed(),
    }
}

#[cfg(test)]
mod tests;
