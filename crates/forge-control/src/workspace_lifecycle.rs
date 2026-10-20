//! Transport-neutral facade for the registered Location-root removal owner.

use forge_domain::{LocationId, TimestampMillis};

use crate::{
    ControlError, ControlErrorCode, ForgeControl, LocationRemovalProbe, LocationRemovalRequest,
    WorkspaceRemovalError, WorkspaceRemovalOutcome,
};

impl ForgeControl {
    pub fn location_removal_probe(
        &self,
        id: LocationId,
    ) -> Result<LocationRemovalProbe, ControlError> {
        crate::probe_location_removal(&self.locations, id).map_err(map_removal_error)
    }

    pub fn location_remove(
        &mut self,
        request: &LocationRemovalRequest,
        observed_at: TimestampMillis,
    ) -> Result<WorkspaceRemovalOutcome, ControlError> {
        crate::native_execute_checked(&mut self.locations, request, observed_at)
            .map_err(map_removal_error)
    }
}

fn map_removal_error(error: WorkspaceRemovalError) -> ControlError {
    match error {
        WorkspaceRemovalError::Location(error) => crate::service::map_location_error(error),
        WorkspaceRemovalError::Layout(error) => crate::service::map_state_layout_error(error),
        WorkspaceRemovalError::Gate(forge_workspace::WorkspaceStateGateError::Busy)
        | WorkspaceRemovalError::Filesystem(forge_workspace::ConfinedFilesystemError::LockBusy) => {
            ControlError::new(ControlErrorCode::WorkspaceRemovalBlocked)
        }
        WorkspaceRemovalError::Gate(error) => {
            ControlError::with_source(ControlErrorCode::WorkspaceRootConflict, error)
        }
        WorkspaceRemovalError::Store(
            forge_persistence::WorkspaceStoreError::StateRemovalBlocked(blocker),
        ) => ControlError::with_source(
            ControlErrorCode::WorkspaceRemovalBlocked,
            forge_persistence::WorkspaceStoreError::StateRemovalBlocked(blocker),
        ),
        WorkspaceRemovalError::Store(error) => crate::service::map_store_error(error),
        WorkspaceRemovalError::Filesystem(error) => {
            ControlError::with_source(ControlErrorCode::WorkspaceRootConflict, error)
        }
        WorkspaceRemovalError::RootFingerprintConflict { .. } => {
            ControlError::new(ControlErrorCode::WorkspaceRootConflict)
        }
        WorkspaceRemovalError::StateExpectationConflict { .. } => {
            ControlError::new(ControlErrorCode::WorkspaceIdentityConflict)
        }
        WorkspaceRemovalError::LocationObservationChanged => {
            ControlError::new(ControlErrorCode::LocationRevisionConflict)
        }
        WorkspaceRemovalError::CommittedUnconfirmed { .. } => ControlError::committed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_removal_phase_is_redacted_and_never_a_known_rejection() {
        let error = map_removal_error(WorkspaceRemovalError::CommittedUnconfirmed {
            detail: "private-original-root-and-filesystem-detail".to_owned(),
        });
        assert!(error.is_committed());
        assert_eq!(error.code(), ControlErrorCode::CommittedButUnconfirmed);
        assert!(!error.view().summary().contains("private-original-root"));
    }

    #[test]
    fn registry_commit_phase_propagates_through_the_location_facade() {
        let error = map_removal_error(WorkspaceRemovalError::Location(
            forge_workspace::LocationServiceError::Repository(
                forge_workspace::LocationRepositoryError::CommittedUnconfirmed {
                    id: LocationId::from_uuid(uuid::Uuid::from_u128(1)),
                    expected_revision: forge_domain::LocationRevision::INITIAL,
                    desired_state: forge_domain::LocationState::Disabled,
                    source: Box::new(std::io::Error::other("private-registry-cause")),
                },
            ),
        ));
        assert!(error.is_committed());
        assert_eq!(error.code(), ControlErrorCode::CommittedButUnconfirmed);
        assert!(!error.view().summary().contains("private-registry-cause"));
    }
}
