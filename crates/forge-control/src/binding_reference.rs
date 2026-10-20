//! Reference based control composition for delegated Agent operations.
//!
//! The wire boundary carries stable scalar references, while the native
//! binding operations continue to receive the opaque persistence values they
//! own.  A reference is resolved against the current Workspace immediately
//! before the existing native owner is called; it never rehydrates or creates
//! a freeze or delegation.

use forge_domain::{AgentSessionId, AuthenticatedPrincipal, TimestampMillis};
use forge_persistence::{
    AgentOperationsDelegation, AgentOperationsFreeze, AgentOperationsFreezeState,
};
use uuid::Uuid;

use crate::{
    AgentBindingActivateRequest, AgentBindingReserveRequest, AgentDepartureReconcileRequest,
    AgentSessionReconcileRequest, ControlError, ControlErrorCode, ForgeControl,
    ResolvedWorkspaceScope,
};

const FREEZE_REFERENCE_MAX_REVISION: u64 = i64::MAX as u64;

/// Stable scalar reference to one durable source freeze.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentOperationsFreezeReference {
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub expected_revision: u64,
}

/// Stable scalar reference to one durable source delegation.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentOperationsDelegationReference {
    pub freeze: AgentOperationsFreezeReference,
    pub manifest_digest: [u8; 32],
}

/// Reference based request to seal a verified destination manifest against a
/// current source freeze.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsDelegateReferenceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub reference: AgentOperationsFreezeReference,
    pub manifest_digest: [u8; 32],
    pub observed_at: TimestampMillis,
}

/// Reference based request to reserve one future Agent binding.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingReserveReferenceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub reference: AgentOperationsFreezeReference,
    pub reservation: forge_persistence::AgentBindingReservationRequest,
    pub observed_at: TimestampMillis,
}

/// Reference based request to activate one reserved Agent binding.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingActivateReferenceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub reference: AgentOperationsDelegationReference,
    pub activation: forge_persistence::AgentBindingActivationRequest,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
    pub observed_at: TimestampMillis,
}

/// Reference based request to reconcile one Agent session for an exact
/// delegated destination.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionReconcileDestinationRequest {
    pub request: AgentSessionReconcileRequest,
    pub destination_id: Uuid,
}

/// Reference based request to reconcile one Agent departure for an exact
/// delegated destination.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDepartureReconcileDestinationRequest {
    pub request: AgentDepartureReconcileRequest,
    pub destination_id: Uuid,
}

impl ForgeControl {
    /// Resolve the exact frozen source operation before invoking the existing
    /// native delegation owner.
    pub fn delegate_agent_operations_ref(
        &self,
        request: &AgentOperationsDelegateReferenceRequest,
    ) -> Result<AgentOperationsDelegation, ControlError> {
        request.reference.validate()?;
        validate_digest(request.manifest_digest)?;
        let (scope, freeze) = resolve_freeze(self, &request.scope, request.reference)?;
        self.delegate_agent_operations(&crate::AgentOperationsDelegationRequest {
            scope,
            freeze,
            manifest_digest: request.manifest_digest,
            observed_at: request.observed_at,
        })
    }

    /// Resolve the exact frozen source operation before invoking the existing
    /// native reservation owner. Session admission precedes all authority
    /// reads so a closed or unavailable session cannot probe durable state.
    pub fn reserve_agent_binding_ref(
        &self,
        request: &AgentBindingReserveReferenceRequest,
    ) -> Result<forge_persistence::AgentBindingReservation, ControlError> {
        request.reference.validate()?;
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.reservation.session_id(),
            principal: request.reservation.principal(),
        })?;
        let (scope, freeze) = resolve_freeze(self, &request.scope, request.reference)?;
        self.reserve_agent_binding(&AgentBindingReserveRequest {
            scope,
            freeze,
            reservation: request.reservation.clone(),
            observed_at: request.observed_at,
        })
    }

    /// Resolve the exact current delegation before invoking the existing native
    /// activation owner. Session admission precedes the delegation read.
    pub fn activate_agent_binding_ref(
        &self,
        request: &AgentBindingActivateReferenceRequest,
    ) -> Result<forge_persistence::AgentBindingActivation, ControlError> {
        request.reference.validate()?;
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, delegation) = resolve_delegation(self, &request.scope, request.reference)?;
        self.activate_agent_binding(&AgentBindingActivateRequest {
            scope,
            delegation,
            activation: request.activation.clone(),
            session_id: request.session_id,
            principal: request.principal,
            observed_at: request.observed_at,
        })
    }

    /// Confirm the current destination delegation before invoking the existing
    /// native session reconciliation owner. The native owner resolves it again
    /// inside its own authority boundary.
    pub fn reconcile_agent_session_destination(
        &self,
        request: &AgentSessionReconcileDestinationRequest,
    ) -> Result<forge_persistence::AgentSessionReconciliation, ControlError> {
        validate_destination(request.destination_id)?;
        let command = request.request.reconciliation.command();
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: command.session_id(),
            principal: command.principal(),
        })?;
        let (scope, _delegation) =
            resolve_delegation_destination(self, &request.request.scope, request.destination_id)?;
        self.reconcile_agent_session(&AgentSessionReconcileRequest {
            scope,
            reconciliation: request.request.reconciliation,
        })
    }

    /// Confirm the current destination delegation before invoking the existing
    /// native departure reconciliation owner. The native owner resolves it
    /// again inside its own authority boundary.
    pub(crate) fn reconcile_agent_departure_destination(
        &self,
        request: &AgentDepartureReconcileDestinationRequest,
        admitted_at: forge_domain::TimestampMillis,
    ) -> Result<forge_persistence::AgentDepartureReconciliation, ControlError> {
        validate_destination(request.destination_id)?;
        let _session = self.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: request.request.reconciliation.session_id(),
            principal: request.request.reconciliation.principal(),
        })?;
        let (scope, _delegation) =
            resolve_delegation_destination(self, &request.request.scope, request.destination_id)?;
        self.reconcile_agent_departure(
            &AgentDepartureReconcileRequest {
                scope,
                reconciliation: request.request.reconciliation.clone(),
            },
            admitted_at,
        )
    }
}

impl AgentOperationsFreezeReference {
    fn validate(self) -> Result<(), ControlError> {
        if self.migration_id.is_nil()
            || self.destination_id.is_nil()
            || self.expected_revision == 0
            || self.expected_revision > FREEZE_REFERENCE_MAX_REVISION
        {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        Ok(())
    }
}

impl AgentOperationsDelegationReference {
    fn validate(self) -> Result<(), ControlError> {
        self.freeze.validate()?;
        validate_digest(self.manifest_digest)
    }
}

fn validate_digest(digest: [u8; 32]) -> Result<(), ControlError> {
    if digest.iter().all(|byte| *byte == 0) {
        Err(ControlError::new(ControlErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn validate_destination(destination_id: Uuid) -> Result<(), ControlError> {
    if destination_id.is_nil() {
        Err(ControlError::new(ControlErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn resolve_freeze(
    control: &ForgeControl,
    requested_scope: &ResolvedWorkspaceScope,
    reference: AgentOperationsFreezeReference,
) -> Result<(ResolvedWorkspaceScope, AgentOperationsFreeze), ControlError> {
    let (scope, store) = control.open_agent_workspace(requested_scope)?;
    let freeze = store
        .agent_operations_freeze(reference.migration_id)
        .map_err(crate::service::map_store_error)?;
    control.confirm_agent_read(&scope, &store)?;
    let Some(freeze) = freeze else {
        return Err(agent_conflict());
    };
    if freeze.workspace_id() != scope.workspace_id()
        || freeze.migration_id() != reference.migration_id
        || freeze.destination_id() != reference.destination_id
        || freeze.revision() != reference.expected_revision
        || freeze.state() != AgentOperationsFreezeState::Frozen
    {
        return Err(agent_conflict());
    }
    Ok((scope, freeze))
}

fn resolve_delegation(
    control: &ForgeControl,
    requested_scope: &ResolvedWorkspaceScope,
    reference: AgentOperationsDelegationReference,
) -> Result<(ResolvedWorkspaceScope, AgentOperationsDelegation), ControlError> {
    let (scope, store) = control.open_agent_workspace(requested_scope)?;
    let delegation = store
        .agent_operations_delegation()
        .map_err(crate::service::map_store_error)?;
    control.confirm_agent_read(&scope, &store)?;
    let Some(delegation) = delegation else {
        return Err(agent_conflict());
    };
    let freeze = delegation.freeze();
    if freeze.workspace_id() != scope.workspace_id()
        || freeze.migration_id() != reference.freeze.migration_id
        || freeze.destination_id() != reference.freeze.destination_id
        || freeze.revision() != reference.freeze.expected_revision
        || freeze.state() != AgentOperationsFreezeState::Frozen
        || delegation.manifest_digest() != reference.manifest_digest
    {
        return Err(agent_conflict());
    }
    Ok((scope, delegation))
}

fn resolve_delegation_destination(
    control: &ForgeControl,
    requested_scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
) -> Result<(ResolvedWorkspaceScope, AgentOperationsDelegation), ControlError> {
    let (scope, store) = control.open_agent_workspace(requested_scope)?;
    let delegation = store
        .agent_operations_delegation()
        .map_err(crate::service::map_store_error)?;
    control.confirm_agent_read(&scope, &store)?;
    let Some(delegation) = delegation else {
        return Err(agent_conflict());
    };
    if delegation.workspace_id() != scope.workspace_id()
        || delegation.destination_id() != destination_id
        || delegation.freeze().state() != AgentOperationsFreezeState::Frozen
    {
        return Err(agent_conflict());
    }
    Ok((scope, delegation))
}

fn agent_conflict() -> ControlError {
    ControlError::new(ControlErrorCode::AgentConflict)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        EstablishWorkspace, LocationId, LocationRevision, TimestampMillis, WorkspaceId,
        WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    #[test]
    fn freeze_reference_rejects_nil_and_out_of_range_values() {
        for reference in [
            AgentOperationsFreezeReference {
                migration_id: Uuid::nil(),
                destination_id: id(1),
                expected_revision: 1,
            },
            AgentOperationsFreezeReference {
                migration_id: id(1),
                destination_id: Uuid::nil(),
                expected_revision: 1,
            },
            AgentOperationsFreezeReference {
                migration_id: id(1),
                destination_id: id(2),
                expected_revision: 0,
            },
            AgentOperationsFreezeReference {
                migration_id: id(1),
                destination_id: id(2),
                expected_revision: i64::MAX as u64 + 1,
            },
        ] {
            assert_eq!(
                reference.validate().map_err(|error| error.code()),
                Err(ControlErrorCode::InvalidInput)
            );
        }
    }

    #[test]
    fn delegation_reference_rejects_zero_manifest_digest() {
        let reference = AgentOperationsDelegationReference {
            freeze: AgentOperationsFreezeReference {
                migration_id: id(1),
                destination_id: id(2),
                expected_revision: 1,
            },
            manifest_digest: [0; 32],
        };
        assert_eq!(
            reference.validate().map_err(|error| error.code()),
            Err(ControlErrorCode::InvalidInput)
        );
    }

    #[test]
    fn destination_reference_rejects_nil_destination() {
        assert_eq!(
            validate_destination(Uuid::nil()).map_err(|error| error.code()),
            Err(ControlErrorCode::InvalidInput)
        );
        assert_eq!(
            validate_destination(id(0xCAFE)).map_err(|error| error.code()),
            Ok(())
        );
    }

    #[test]
    fn freeze_reference_rejects_foreign_destination_and_stale_revision()
    -> Result<(), Box<dyn Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-binding-reference-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let location_root = root.join("location");
        fs::create_dir_all(&location_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(id(0xB100 + u128::from(serial)));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Binding Reference Fixture",
            &location_root,
            timestamp(1)?,
        )?;
        drop(locations);
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let workspace = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
        let command = EstablishWorkspace::new(
            WorkspaceId::from_uuid(id(0xB200 + u128::from(serial))),
            location.id(),
            workspace,
            layout.root_fingerprint()?,
            timestamp(2)?,
        );
        let mut store = WorkspaceStore::open(&layout, &command)?;
        let freeze = store.freeze_agent_operations(
            &forge_persistence::AgentOperationsFreezeRequest::new(
                id(0xB300 + u128::from(serial)),
                id(0xB400 + u128::from(serial)),
                timestamp(3)?,
            )?,
        )?;
        drop(store);

        let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
        let entry = control
            .workspace_discover(location.id(), LocationRevision::INITIAL)?
            .into_iter()
            .find(|entry| entry.display_name() == "workspace")
            .ok_or("workspace discovery entry missing")?;
        let scope =
            control.resolve_workspace(location.id(), LocationRevision::INITIAL, entry.locator())?;

        let foreign_destination = AgentOperationsFreezeReference {
            migration_id: freeze.migration_id(),
            destination_id: id(0xB500 + u128::from(serial)),
            expected_revision: freeze.revision(),
        };
        assert_eq!(
            resolve_freeze(&control, &scope, foreign_destination).map_err(|error| error.code()),
            Err(ControlErrorCode::AgentConflict)
        );

        let stale_revision = AgentOperationsFreezeReference {
            migration_id: freeze.migration_id(),
            destination_id: freeze.destination_id(),
            expected_revision: freeze.revision() + 1,
        };
        assert_eq!(
            resolve_freeze(&control, &scope, stale_revision).map_err(|error| error.code()),
            Err(ControlErrorCode::AgentConflict)
        );

        drop(control);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
