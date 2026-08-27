//! Workspace-scoped recovery-maintenance lease control operations.
//!
//! The control plane exposes the durable recovery fence as explicit typed
//! operations.  Every operation re-resolves the exact Workspace scope, never
//! mutates on a read path, and revalidates the committed binding after any
//! mutation before reporting success.

use forge_domain::{
    ActivityListLimit, ClaimRecoveryLease, ExecutionListLimit, ReconcileExpiredActivities,
    RecoveryLeaseDurationMillis, RecoveryLeaseTransitionError, RecoveryMaintenanceLease,
    RegisteredActivity, RegisteredExecution, ReleaseRecoveryLease, RenewRecoveryLease,
    RuntimeInstanceId, TimestampMillis,
};
use forge_persistence::{RecoveryLeaseClaimStatus, RecoveryStoreError, WorkspaceStoreError};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

/// Outcome classification of one recovery-lease claim attempt.
///
/// The classification and the returned lease snapshot are both observed from
/// the same short IMMEDIATE transaction.  `Busy` and `ClaimConflict` carry
/// the unchanged durable snapshot, making it explicit that neither outcome
/// performed a semantic mutation.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryLeaseAcquisition {
    /// A released or expired lease was acquired by this command.
    Acquired,
    /// The exact owner and expiry were already live; retrying is idempotent.
    AlreadyOwned,
    /// A different owner still holds a live lease.
    Busy,
    /// The same owner requested a different live expiry.
    ClaimConflict,
}

impl RecoveryLeaseAcquisition {
    /// Whether this attempt now owns the lease.
    pub const fn is_acquired(self) -> bool {
        matches!(self, Self::Acquired)
    }
}

impl From<RecoveryLeaseClaimStatus> for RecoveryLeaseAcquisition {
    fn from(status: RecoveryLeaseClaimStatus) -> Self {
        match status {
            RecoveryLeaseClaimStatus::Acquired => Self::Acquired,
            RecoveryLeaseClaimStatus::AlreadyOwned => Self::AlreadyOwned,
            RecoveryLeaseClaimStatus::Busy => Self::Busy,
            RecoveryLeaseClaimStatus::ClaimConflict => Self::ClaimConflict,
        }
    }
}

/// Result of one control-plane recovery-lease claim attempt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryLeaseClaimOperation {
    scope: ResolvedWorkspaceScope,
    acquisition: RecoveryLeaseAcquisition,
    lease: RecoveryMaintenanceLease,
}

impl RecoveryLeaseClaimOperation {
    pub(crate) const fn new(
        scope: ResolvedWorkspaceScope,
        acquisition: RecoveryLeaseAcquisition,
        lease: RecoveryMaintenanceLease,
    ) -> Self {
        Self {
            scope,
            acquisition,
            lease,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn acquisition(&self) -> RecoveryLeaseAcquisition {
        self.acquisition
    }

    pub const fn lease(&self) -> &RecoveryMaintenanceLease {
        &self.lease
    }

    pub const fn is_acquired(&self) -> bool {
        self.acquisition.is_acquired()
    }
}

/// Request for one explicit leased recovery-maintenance run.
///
/// All observations (owner identity, timestamps, bounds) are supplied by the
/// caller; the service never reads a clock or invents identity.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMaintenanceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub owner_id: RuntimeInstanceId,
    pub duration: RecoveryLeaseDurationMillis,
    pub claimed_at: TimestampMillis,
    pub classify_at: TimestampMillis,
    pub activity_limit: ActivityListLimit,
    pub execution_limit: ExecutionListLimit,
}

/// Outcome classification of one recovery-maintenance run.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryMaintenanceOutcome {
    /// The lease was acquired (or already owned) and classification ran.
    Completed,
    /// A different live owner holds the lease; nothing was classified.
    Busy,
    /// The same owner requested a conflicting live claim; nothing was
    /// classified and the existing lease is unchanged.
    ClaimConflict,
}

impl RecoveryMaintenanceOutcome {
    /// Whether durable classification ran during this request.
    pub const fn classified(self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// Report of one explicit leased recovery-maintenance run.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMaintenanceReport {
    scope: ResolvedWorkspaceScope,
    outcome: RecoveryMaintenanceOutcome,
    lease: RecoveryMaintenanceLease,
    reconciled_activities: Vec<RegisteredActivity>,
    reconciled_executions: Vec<RegisteredExecution>,
    binding_confirmed: bool,
    release_uncertain: bool,
}

impl RecoveryMaintenanceReport {
    pub(crate) const fn new(
        scope: ResolvedWorkspaceScope,
        outcome: RecoveryMaintenanceOutcome,
        lease: RecoveryMaintenanceLease,
    ) -> Self {
        Self {
            scope,
            outcome,
            lease,
            reconciled_activities: Vec::new(),
            reconciled_executions: Vec::new(),
            binding_confirmed: true,
            release_uncertain: false,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn outcome(&self) -> RecoveryMaintenanceOutcome {
        self.outcome
    }

    /// Lease snapshot observed at claim time, or after release when the run
    /// completed cleanly.
    pub const fn lease(&self) -> &RecoveryMaintenanceLease {
        &self.lease
    }

    pub fn reconciled_activities(&self) -> &[RegisteredActivity] {
        &self.reconciled_activities
    }

    pub fn reconciled_executions(&self) -> &[RegisteredExecution] {
        &self.reconciled_executions
    }

    /// Whether the Workspace/root binding still matched after classification.
    /// When false, committed classification could not be revalidated and must
    /// be treated as uncertain evidence.
    pub const fn binding_confirmed(&self) -> bool {
        self.binding_confirmed
    }

    /// Whether lease release could not be confirmed; the bounded TTL then
    /// expires the fence naturally instead of blocking other owners.
    pub const fn release_uncertain(&self) -> bool {
        self.release_uncertain
    }
}

impl ForgeControl {
    /// Run one explicit recovery-maintenance pass behind the Workspace
    /// recovery-maintenance lease.
    ///
    /// Ordering follows the accepted recovery-fence design: exact-scope
    /// preflight, one short IMMEDIATE lease claim, one deterministic bounded
    /// durable-only batch (expired-lease Activities, then Executions whose
    /// owning Activity lease expired), binding revalidation, and fenced
    /// release.  Live Activity ownership blocks Execution reconciliation, and
    /// unleased Activities remain untouched this slice.
    pub fn run_recovery_maintenance(
        &self,
        request: &RecoveryMaintenanceRequest,
    ) -> Result<RecoveryMaintenanceReport, ControlError> {
        if request.classify_at.get() < request.claimed_at.get() {
            return Err(ControlError::new(ControlErrorCode::InvalidInput));
        }
        let command = ClaimRecoveryLease::new(
            request.scope.workspace_id(),
            request.owner_id,
            request.duration,
            request.claimed_at,
        )
        .map_err(|source| ControlError::with_source(ControlErrorCode::InvalidInput, source))?;
        let (_fresh_scope, mut store) = self.open_recovery_workspace(&request.scope)?;
        let claim = store
            .claim_recovery_maintenance_lease(command)
            .map_err(map_recovery_store_error)?;
        let outcome = match claim.status() {
            RecoveryLeaseClaimStatus::Acquired | RecoveryLeaseClaimStatus::AlreadyOwned => {
                RecoveryMaintenanceOutcome::Completed
            }
            RecoveryLeaseClaimStatus::Busy => RecoveryMaintenanceOutcome::Busy,
            RecoveryLeaseClaimStatus::ClaimConflict => RecoveryMaintenanceOutcome::ClaimConflict,
        };
        let mut report =
            RecoveryMaintenanceReport::new(request.scope.clone(), outcome, claim.lease().clone());
        if !outcome.classified() {
            return Ok(report);
        }

        let claimed_lease = claim.into_lease();
        match classify_under_lease(&mut store, request) {
            Ok((activities, executions)) => {
                report.reconciled_activities = activities;
                report.reconciled_executions = executions;
                report.binding_confirmed =
                    self.committed_scope_matches_with_store(&request.scope, &store);
                if report.binding_confirmed {
                    let release = ReleaseRecoveryLease::new(
                        request.scope.workspace_id(),
                        request.owner_id,
                        claimed_lease.epoch(),
                        claimed_lease.revision(),
                        request.classify_at,
                    );
                    if let Ok(released) = store.release_recovery_maintenance_lease(release) {
                        report.lease = released;
                    } else {
                        report.release_uncertain = true;
                        tracing::warn!(
                            "recovery maintenance release compare-and-swap failed; \
                             TTL expiry will free the fence"
                        );
                    }
                } else {
                    report.release_uncertain = true;
                    tracing::warn!(
                        "recovery maintenance binding drifted after classification; \
                         release skipped and TTL expiry will free the fence"
                    );
                }
                Ok(report)
            }
            Err(error) => {
                // Classification failed before any observable commit effect;
                // best-effort release avoids pinning the fence until TTL.
                let release = ReleaseRecoveryLease::new(
                    request.scope.workspace_id(),
                    request.owner_id,
                    claimed_lease.epoch(),
                    claimed_lease.revision(),
                    request.classify_at,
                );
                if store.release_recovery_maintenance_lease(release).is_err() {
                    tracing::warn!(
                        "recovery maintenance release failed after a failed classification; \
                         TTL expiry will free the fence"
                    );
                }
                Err(error)
            }
        }
    }

    /// Observe the durable Workspace recovery-maintenance lease.
    ///
    /// This is an observational read: no liveness transition, takeover, or
    /// revision change is performed by this path.
    pub fn recovery_maintenance_lease(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<RecoveryMaintenanceLease, ControlError> {
        let (fresh_scope, store) = self.open_recovery_workspace(scope)?;
        let lease = store
            .get_recovery_maintenance_lease()
            .map_err(map_recovery_store_error)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(lease)
    }

    /// Claim or take over the Workspace recovery-maintenance lease.
    ///
    /// A released or expired lease is acquired in one bounded IMMEDIATE
    /// transaction; an exactly repeated live claim is idempotent; a different
    /// live owner is rejected as `Busy`; and a same-owner claim with a
    /// different live expiry is rejected as `ClaimConflict`.
    pub fn claim_recovery_maintenance_lease(
        &self,
        scope: &ResolvedWorkspaceScope,
        command: &ClaimRecoveryLease,
    ) -> Result<RecoveryLeaseClaimOperation, ControlError> {
        validate_recovery_command_scope(scope, command.workspace_id())?;
        let (fresh_scope, mut store) = self.open_recovery_workspace(scope)?;
        let result = store
            .claim_recovery_maintenance_lease(command)
            .map_err(map_recovery_store_error)?;
        let acquisition = RecoveryLeaseAcquisition::from(result.status());
        if acquisition.is_acquired() {
            self.confirm_recovery_write(scope, &store)?;
        } else if !self.committed_scope_matches_with_store(scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(RecoveryLeaseClaimOperation::new(
            fresh_scope,
            acquisition,
            result.into_lease(),
        ))
    }

    /// Renew the currently owned lease through exact owner, epoch, and
    /// revision fencing with a strictly forward expiry.
    pub fn renew_recovery_maintenance_lease(
        &self,
        scope: &ResolvedWorkspaceScope,
        command: &RenewRecoveryLease,
    ) -> Result<RecoveryMaintenanceLease, ControlError> {
        validate_recovery_command_scope(scope, command.workspace_id())?;
        let (_scope, mut store) = self.open_recovery_workspace(scope)?;
        let lease = store
            .renew_recovery_maintenance_lease(command)
            .map_err(map_recovery_store_error)?;
        self.confirm_recovery_write(scope, &store)?;
        Ok(lease)
    }

    /// Release the currently owned lease through exact owner, epoch, and
    /// revision fencing.
    ///
    /// A stale owner can neither release nor clear a newer lease; the fenced
    /// compare-and-swap fails closed instead.
    pub fn release_recovery_maintenance_lease(
        &self,
        scope: &ResolvedWorkspaceScope,
        command: &ReleaseRecoveryLease,
    ) -> Result<RecoveryMaintenanceLease, ControlError> {
        validate_recovery_command_scope(scope, command.workspace_id())?;
        let (_scope, mut store) = self.open_recovery_workspace(scope)?;
        let lease = store
            .release_recovery_maintenance_lease(command)
            .map_err(map_recovery_store_error)?;
        self.confirm_recovery_write(scope, &store)?;
        Ok(lease)
    }

    fn open_recovery_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(ResolvedWorkspaceScope, forge_persistence::WorkspaceStore), ControlError> {
        let (fresh_scope, store) = self.open_resolved_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((fresh_scope, store))
    }

    fn confirm_recovery_write(
        &self,
        scope: &ResolvedWorkspaceScope,
        store: &forge_persistence::WorkspaceStore,
    ) -> Result<(), ControlError> {
        if self.committed_scope_matches_with_store(scope, store) {
            Ok(())
        } else {
            Err(ControlError::committed())
        }
    }
}

fn validate_recovery_command_scope(
    scope: &ResolvedWorkspaceScope,
    command_workspace_id: forge_domain::WorkspaceId,
) -> Result<(), ControlError> {
    if command_workspace_id != scope.workspace_id() {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    Ok(())
}

fn classify_under_lease(
    store: &mut forge_persistence::WorkspaceStore,
    request: &RecoveryMaintenanceRequest,
) -> Result<(Vec<RegisteredActivity>, Vec<RegisteredExecution>), ControlError> {
    let reconcile = ReconcileExpiredActivities::new(request.classify_at);
    let activities = store
        .reconcile_expired_activities_limited(&reconcile, request.activity_limit)
        .map_err(map_activity_store_error)?;
    let executions = store
        .reconcile_expired_authority_executions(request.classify_at, request.execution_limit)
        .map_err(map_activity_store_error)?;
    Ok((activities, executions))
}

pub(crate) fn map_recovery_store_error(error: WorkspaceStoreError) -> ControlError {
    let code = match &error {
        WorkspaceStoreError::Recovery(RecoveryStoreError::Transition(
            RecoveryLeaseTransitionError::Busy
            | RecoveryLeaseTransitionError::ClaimConflict
            | RecoveryLeaseTransitionError::StaleOwner
            | RecoveryLeaseTransitionError::StaleEpoch
            | RecoveryLeaseTransitionError::StaleRevision
            | RecoveryLeaseTransitionError::Expired
            | RecoveryLeaseTransitionError::LeaseNotForward
            | RecoveryLeaseTransitionError::EpochOverflow { .. }
            | RecoveryLeaseTransitionError::RevisionOverflow { .. },
        )) => ControlErrorCode::RecoveryLeaseConflict,
        WorkspaceStoreError::Recovery(RecoveryStoreError::WorkspaceMismatch { .. }) => {
            ControlErrorCode::WorkspaceIdentityConflict
        }
        WorkspaceStoreError::WorkspaceRevisionConflict { .. } => {
            ControlErrorCode::WorkspaceRevisionConflict
        }
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. }
        | WorkspaceStoreError::ExistingWorkspaceBindingMismatch { .. }
        | WorkspaceStoreError::WorkspaceRootFingerprintChanged { .. }
        | WorkspaceStoreError::WorkspaceRootCanonicalPathChanged { .. } => {
            ControlErrorCode::WorkspaceRootConflict
        }
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        ActivityId, ActivityListLimit, BeginExecution, ClaimRecoveryLease, CreateActivity,
        EstablishWorkspace, ExecutionAttribution, ExecutionId, ExecutionKind, ExecutionLimits,
        ExecutionListLimit, ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram,
        ExecutionRequest, ExecutionRequestDigest, ExecutionState, ExecutionTimeoutMillis,
        LocationId, LocationRevision, ReleaseRecoveryLease, RenewRecoveryLease, RuntimeInstanceId,
        TimestampMillis, WorkspaceId, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::{
        ForgeControl, RecoveryLeaseAcquisition, RecoveryMaintenanceOutcome,
        RecoveryMaintenanceRequest, ResolvedWorkspaceScope,
    };
    use crate::error::ControlErrorCode;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        control: ForgeControl,
        registry_path: PathBuf,
        root: PathBuf,
        location_id: LocationId,
        workspace_id: WorkspaceId,
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn runtime_id(value: u128) -> RuntimeInstanceId {
        RuntimeInstanceId::from_uuid(Uuid::from_u128(value))
    }

    fn duration() -> Result<forge_domain::RecoveryLeaseDurationMillis, Box<dyn std::error::Error>> {
        Ok(forge_domain::RecoveryLeaseDurationMillis::new(1_000)?)
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-control-recovery-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace-0");
        fs::create_dir_all(&workspace_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::from_u128(0x1000 + u128::from(serial)));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x2000 + u128::from(serial)));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        locations.register_selected_path(
            location_id,
            "Recovery Fixture",
            &location_root,
            timestamp(1)?,
        )?;
        drop(locations);

        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let durable_root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            durable_root,
            layout.root_fingerprint()?,
            timestamp(2)?,
        );
        drop(WorkspaceStore::open(&layout, &command)?);

        Ok(Fixture {
            control: ForgeControl::new(GlobalRegistry::open(&registry_path)?),
            registry_path,
            root,
            location_id,
            workspace_id,
        })
    }

    /// Resolve the single ready Workspace scope for a fixture.
    ///
    /// The catalog deliberately reports a transient observation failure as
    /// `Unavailable` instead of guessing health.  Under heavily parallel test
    /// execution that conservative mapping can win a race against filesystem
    /// quiescence, so setup polls briefly for readiness; deterministic
    /// breakage still fails after the bounded window.
    fn resolved_scope(
        control: &ForgeControl,
        location_id: LocationId,
    ) -> Result<ResolvedWorkspaceScope, Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let entries = control.workspace_list(location_id, LocationRevision::INITIAL)?;
            if let Some(entry) = entries.iter().find(|entry| entry.status().is_ready()) {
                return Ok(control.resolve_workspace(
                    location_id,
                    LocationRevision::INITIAL,
                    entry.locator(),
                )?);
            }
            if std::time::Instant::now() >= deadline {
                return Err("ready workspace catalog entry missing".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn recovery_lease_contract_is_fenced_through_control_worker()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("lifecycle")?;
        let scope = resolved_scope(&fixture.control, fixture.location_id)?;
        let (client, mut worker) = fixture.control.start_worker()?;
        let owner_a = runtime_id(0xA001);
        let owner_b = runtime_id(0xB001);

        let initial = client.recovery_maintenance_lease(scope.clone())?;
        assert!(initial.is_released());
        assert_eq!(initial.epoch().get(), 0);

        // A released lease is acquired and the epoch advances exactly once.
        let first_command =
            ClaimRecoveryLease::new(fixture.workspace_id, owner_a, duration()?, timestamp(10)?)?;
        let first = client.claim_recovery_maintenance_lease(scope.clone(), first_command)?;
        assert_eq!(first.acquisition(), RecoveryLeaseAcquisition::Acquired);
        assert_eq!(first.lease().owner_id(), Some(owner_a));
        assert_eq!(first.lease().epoch().get(), 1);
        assert_eq!(first.lease().revision().get(), 2);
        assert_eq!(first.scope().workspace_id(), fixture.workspace_id);

        // The exact same owner and expiry is an idempotent retry.
        let retry = client.claim_recovery_maintenance_lease(scope.clone(), first_command)?;
        assert_eq!(retry.acquisition(), RecoveryLeaseAcquisition::AlreadyOwned);
        assert_eq!(retry.lease(), first.lease());

        // A different live owner is rejected without mutating the snapshot.
        let competing =
            ClaimRecoveryLease::new(fixture.workspace_id, owner_b, duration()?, timestamp(11)?)?;
        let busy = client.claim_recovery_maintenance_lease(scope.clone(), competing)?;
        assert_eq!(busy.acquisition(), RecoveryLeaseAcquisition::Busy);
        assert_eq!(busy.lease(), first.lease());

        // The same live owner with a different live expiry must renew exactly.
        let conflicting = ClaimRecoveryLease::new(
            fixture.workspace_id,
            owner_a,
            forge_domain::RecoveryLeaseDurationMillis::new(2_000)?,
            timestamp(12)?,
        )?;
        let conflict = client.claim_recovery_maintenance_lease(scope.clone(), conflicting)?;
        assert_eq!(
            conflict.acquisition(),
            RecoveryLeaseAcquisition::ClaimConflict
        );
        assert_eq!(conflict.lease(), first.lease());

        // Renewal with the exact fence moves the expiry strictly forward.
        let renewal = RenewRecoveryLease::new(
            fixture.workspace_id,
            owner_a,
            first.lease().epoch(),
            first.lease().revision(),
            duration()?,
            timestamp(50)?,
        )?;
        let renewed = client.renew_recovery_maintenance_lease(scope.clone(), renewal)?;
        assert_eq!(renewed.lease_until(), Some(timestamp(1_050)?));
        assert_eq!(renewed.revision().get(), 3);

        // A stale fence fails closed as a typed conflict.
        let stale_renewal = RenewRecoveryLease::new(
            fixture.workspace_id,
            owner_a,
            first.lease().epoch(),
            first.lease().revision(),
            duration()?,
            timestamp(60)?,
        )?;
        let stale_error = client
            .renew_recovery_maintenance_lease(scope.clone(), stale_renewal)
            .expect_err("stale renewal must fail");
        assert_eq!(stale_error.code(), ControlErrorCode::RecoveryLeaseConflict);

        // An expired lease can be taken over; the epoch advances again.
        let takeover = ClaimRecoveryLease::new(
            fixture.workspace_id,
            owner_b,
            duration()?,
            timestamp(1_050)?,
        )?;
        let taken = client.claim_recovery_maintenance_lease(scope.clone(), takeover)?;
        assert_eq!(taken.acquisition(), RecoveryLeaseAcquisition::Acquired);
        assert_eq!(taken.lease().owner_id(), Some(owner_b));
        assert_eq!(taken.lease().epoch().get(), 2);

        // The stale previous owner cannot release the newer lease.
        let stale_release = ReleaseRecoveryLease::new(
            fixture.workspace_id,
            owner_a,
            first.lease().epoch(),
            first.lease().revision(),
            timestamp(1_060)?,
        );
        let stale_release_error = client
            .release_recovery_maintenance_lease(scope.clone(), stale_release)
            .expect_err("stale release must fail");
        assert_eq!(
            stale_release_error.code(),
            ControlErrorCode::RecoveryLeaseConflict
        );

        // The exact current owner releases with its own fence only.
        let release_command = ReleaseRecoveryLease::new(
            fixture.workspace_id,
            owner_b,
            taken.lease().epoch(),
            taken.lease().revision(),
            timestamp(1_070)?,
        );
        let released = client.release_recovery_maintenance_lease(scope.clone(), release_command)?;
        assert!(released.is_released());
        assert_eq!(released.epoch(), taken.lease().epoch());
        assert_eq!(
            released.revision().get(),
            taken.lease().revision().get() + 1
        );

        // Reads stay observational after every transition.
        let observed_again = client.recovery_maintenance_lease(scope.clone())?;
        assert_eq!(observed_again, released);

        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn recovery_operations_fail_closed_on_scope_and_identity_conflicts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("fail-closed")?;
        let scope = resolved_scope(&fixture.control, fixture.location_id)?;
        let (client, mut worker) = fixture.control.start_worker()?;

        // A command naming a different Workspace fails closed before any I/O.
        let foreign_workspace = WorkspaceId::from_uuid(Uuid::from_u128(0xDEAD));
        let foreign_claim = ClaimRecoveryLease::new(
            foreign_workspace,
            runtime_id(0xC001),
            duration()?,
            timestamp(10)?,
        )?;
        let identity_error = client
            .claim_recovery_maintenance_lease(scope.clone(), foreign_claim)
            .expect_err("foreign Workspace claim must fail");
        assert_eq!(
            identity_error.code(),
            ControlErrorCode::WorkspaceIdentityConflict
        );
        let unchanged = client.recovery_maintenance_lease(scope.clone())?;
        assert!(unchanged.is_released());
        assert_eq!(unchanged.epoch().get(), 0);
        assert_eq!(unchanged.revision().get(), 1);

        // A committed scope observation from a stale revision fails closed.
        let stale_scope = ResolvedWorkspaceScope::from_observation(
            fixture.workspace_id,
            WorkspaceRevision::new(scope.workspace_revision().get() + 1)?,
            scope.locator().clone(),
        );
        let stale_claim = ClaimRecoveryLease::new(
            fixture.workspace_id,
            runtime_id(0xC002),
            duration()?,
            timestamp(11)?,
        )?;
        let revision_error = client
            .claim_recovery_maintenance_lease(stale_scope, stale_claim)
            .expect_err("stale scope claim must fail");
        assert_eq!(
            revision_error.code(),
            ControlErrorCode::WorkspaceRevisionConflict
        );

        let still_released = client.recovery_maintenance_lease(scope.clone())?;
        assert!(still_released.is_released());
        assert_eq!(still_released.revision().get(), 1);

        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn independent_control_workers_race_to_exactly_one_winner()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("race")?;

        // Two fully independent control services over the same Registry and
        // Workspace, each with its own bounded worker thread.
        let (client_a, mut worker_a) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;
        let (client_b, mut worker_b) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;
        let scope_a = resolved_scope(&fixture.control, fixture.location_id)?;
        let scope_b = resolved_scope(&fixture.control, fixture.location_id)?;

        let command_a = ClaimRecoveryLease::new(
            fixture.workspace_id,
            runtime_id(0xD001),
            duration()?,
            timestamp(5)?,
        )?;
        let command_b = ClaimRecoveryLease::new(
            fixture.workspace_id,
            runtime_id(0xD002),
            duration()?,
            timestamp(5)?,
        )?;

        let (first_joined, second_joined) = std::thread::scope(|threads| {
            let first = threads
                .spawn(move || client_a.claim_recovery_maintenance_lease(scope_a, command_a));
            let second = threads
                .spawn(move || client_b.claim_recovery_maintenance_lease(scope_b, command_b));
            (first.join(), second.join())
        });
        let first = first_joined
            .map_err(|_| std::io::Error::other("first recovery race thread must not panic"))??;
        let second = second_joined
            .map_err(|_| std::io::Error::other("second recovery race thread must not panic"))??;

        let statuses = [first.acquisition(), second.acquisition()];
        assert!(statuses.contains(&RecoveryLeaseAcquisition::Acquired));
        assert!(statuses.contains(&RecoveryLeaseAcquisition::Busy));

        let winner = if first.is_acquired() { &first } else { &second };
        assert_eq!(winner.lease().epoch().get(), 1);
        assert_eq!(winner.lease().revision().get(), 2);

        // An independent observational read confirms exactly one winner.
        let scope = resolved_scope(&fixture.control, fixture.location_id)?;
        let persisted = fixture.control.recovery_maintenance_lease(&scope)?;
        assert_eq!(persisted.owner_id(), winner.lease().owner_id());
        assert_eq!(persisted, *winner.lease());

        worker_a.shutdown()?;
        worker_b.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    fn seed_store(root: &std::path::Path) -> Result<WorkspaceStore, Box<dyn std::error::Error>> {
        let workspace_root = root.join("location").join("workspace-0");
        let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
            .ok_or("workspace layout missing")?;
        Ok(WorkspaceStore::open_existing(&layout)?)
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_running_execution(
        store: &mut WorkspaceStore,
        raw_id: u128,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> Result<ExecutionId, Box<dyn std::error::Error>> {
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(raw_id)),
                workspace_id,
                activity_id,
            ),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(16)?,
            ),
            ExecutionPermissions::new(true, false, false),
        )?;
        let record = store.begin_execution(&BeginExecution::from_request(
            &request,
            ExecutionRequestDigest::from_bytes([u8::try_from(raw_id).unwrap_or(u8::MAX); 32]),
            timestamp(10)?,
        ))?;
        Ok(record.record().id())
    }

    #[allow(clippy::too_many_lines)]
    fn maintenance_request(
        scope: &ResolvedWorkspaceScope,
        owner_value: u128,
        claimed_at: i64,
    ) -> Result<RecoveryMaintenanceRequest, Box<dyn std::error::Error>> {
        Ok(RecoveryMaintenanceRequest {
            scope: scope.clone(),
            owner_id: runtime_id(owner_value),
            duration: duration()?,
            claimed_at: timestamp(claimed_at)?,
            classify_at: timestamp(claimed_at)?,
            activity_limit: ActivityListLimit::DEFAULT,
            execution_limit: ExecutionListLimit::DEFAULT,
        })
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn leased_maintenance_classifies_only_expired_authority_and_releases()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("maint")?;
        let scope = resolved_scope(&fixture.control, fixture.location_id)?;
        let expired_activity = ActivityId::from_uuid(Uuid::from_u128(0xA11));
        let live_activity = ActivityId::from_uuid(Uuid::from_u128(0xB22));
        let _bootstrapped = fixture.control.bootstrap_activity(
            &scope,
            expired_activity,
            runtime_id(0x771),
            timestamp(1)?,
            timestamp(5)?,
        )?;
        let _bootstrapped = fixture.control.bootstrap_activity(
            &scope,
            live_activity,
            runtime_id(0x772),
            timestamp(1)?,
            timestamp(5_000)?,
        )?;
        let unleased_activity = ActivityId::from_uuid(Uuid::from_u128(0xC33));
        {
            let mut store = seed_store(&fixture.root)?;
            store.create_activity(&CreateActivity::new(
                unleased_activity,
                fixture.workspace_id,
                WorkspaceRevision::INITIAL,
                timestamp(2)?,
            ))?;
            insert_running_execution(&mut store, 0x51, fixture.workspace_id, expired_activity)?;
            insert_running_execution(&mut store, 0x52, fixture.workspace_id, live_activity)?;
            insert_running_execution(&mut store, 0x53, fixture.workspace_id, unleased_activity)?;
        }

        let (client, mut worker) = fixture.control.start_worker()?;
        let request = maintenance_request(&scope, 0x999, 100)?;
        let report = client.run_recovery_maintenance(request.clone())?;

        assert_eq!(report.outcome(), RecoveryMaintenanceOutcome::Completed);
        assert!(report.binding_confirmed());
        assert!(!report.release_uncertain());
        assert_eq!(report.reconciled_activities().len(), 1);
        assert_eq!(report.reconciled_activities()[0].id(), expired_activity);
        assert_eq!(report.reconciled_executions().len(), 1);
        assert_eq!(
            report.reconciled_executions()[0].id(),
            ExecutionId::from_uuid(Uuid::from_u128(0x51))
        );
        assert!(report.lease().is_released());
        assert_eq!(report.lease().epoch().get(), 1);

        // Live-lease and unleased executions stay Starting.
        let store = seed_store(&fixture.root)?;
        for untouched in [0x52_u128, 0x53] {
            let record = store
                .get_execution(ExecutionId::from_uuid(Uuid::from_u128(untouched)))?
                .ok_or("untouched execution missing")?;
            assert_eq!(record.state(), ExecutionState::Starting, "{untouched}");
        }
        drop(store);

        // A second run is idempotent: nothing remains to classify.
        let second = client.run_recovery_maintenance(request)?;
        assert_eq!(second.outcome(), RecoveryMaintenanceOutcome::Completed);
        assert!(second.reconciled_activities().is_empty());
        assert!(second.reconciled_executions().is_empty());
        assert_eq!(second.lease().epoch().get(), 2);

        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn foreign_live_owner_blocks_all_classification() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("maint-busy")?;
        let scope = resolved_scope(&fixture.control, fixture.location_id)?;
        let expired_activity = ActivityId::from_uuid(Uuid::from_u128(0xA44));
        let _bootstrapped = fixture.control.bootstrap_activity(
            &scope,
            expired_activity,
            runtime_id(0x773),
            timestamp(1)?,
            timestamp(5)?,
        )?;
        {
            let mut store = seed_store(&fixture.root)?;
            insert_running_execution(&mut store, 0x54, fixture.workspace_id, expired_activity)?;
        }

        let (client, mut worker) = fixture.control.start_worker()?;
        // A different live owner claims the fence first.
        let foreign_claim = ClaimRecoveryLease::new(
            fixture.workspace_id,
            runtime_id(0xF01),
            duration()?,
            timestamp(50)?,
        )?;
        let claimed = client.claim_recovery_maintenance_lease(scope.clone(), foreign_claim)?;
        assert_eq!(claimed.acquisition(), RecoveryLeaseAcquisition::Acquired);

        let report = client.run_recovery_maintenance(maintenance_request(&scope, 0x999, 60)?)?;
        assert_eq!(report.outcome(), RecoveryMaintenanceOutcome::Busy);
        assert!(!report.outcome().classified());
        assert_eq!(report.lease().owner_id(), Some(runtime_id(0xF01)));
        assert!(report.reconciled_activities().is_empty());
        assert!(report.reconciled_executions().is_empty());

        // Durable rows were not touched while the fence was held.
        let store = seed_store(&fixture.root)?;
        let record = store
            .get_execution(ExecutionId::from_uuid(Uuid::from_u128(0x54)))?
            .ok_or("seeded execution missing")?;
        assert_eq!(record.state(), ExecutionState::Starting);
        drop(store);

        // After the foreign owner releases, the same run classifies.
        let foreign_release = ReleaseRecoveryLease::new(
            fixture.workspace_id,
            runtime_id(0xF01),
            claimed.lease().epoch(),
            claimed.lease().revision(),
            timestamp(70)?,
        );
        let _released =
            client.release_recovery_maintenance_lease(scope.clone(), foreign_release)?;
        let report = client.run_recovery_maintenance(maintenance_request(&scope, 0x999, 80)?)?;
        assert_eq!(report.outcome(), RecoveryMaintenanceOutcome::Completed);
        assert_eq!(report.reconciled_executions().len(), 1);
        assert!(report.lease().is_released());

        worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn held_fence_blocks_concurrent_maintenance_workers() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture("maint-race")?;
        let scope = resolved_scope(&fixture.control, fixture.location_id)?;
        let expired_activity = ActivityId::from_uuid(Uuid::from_u128(0xA55));
        let _bootstrapped = fixture.control.bootstrap_activity(
            &scope,
            expired_activity,
            runtime_id(0x774),
            timestamp(1)?,
            timestamp(5)?,
        )?;
        let seeded = {
            let mut store = seed_store(&fixture.root)?;
            let first =
                insert_running_execution(&mut store, 0x61, fixture.workspace_id, expired_activity)?;
            let second =
                insert_running_execution(&mut store, 0x62, fixture.workspace_id, expired_activity)?;
            [first, second]
        };

        let (client_a, mut worker_a) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;
        let (client_b, mut worker_b) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;

        // A third live owner holds the fence for the whole contention window.
        let holder_claim = ClaimRecoveryLease::new(
            fixture.workspace_id,
            runtime_id(0xF10),
            duration()?,
            timestamp(90)?,
        )?;
        let (client_holder, mut worker_holder) =
            ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?).start_worker()?;
        let held = client_holder.claim_recovery_maintenance_lease(scope.clone(), holder_claim)?;
        assert_eq!(held.acquisition(), RecoveryLeaseAcquisition::Acquired);

        // Two independent maintenance workers race while the fence is held.
        let request_a = maintenance_request(&scope, 0xE01, 95)?;
        let request_b = maintenance_request(&scope, 0xE02, 95)?;
        let (first_joined, second_joined) = std::thread::scope(|threads| {
            let first = threads.spawn(move || client_a.run_recovery_maintenance(request_a));
            let second = threads.spawn(move || client_b.run_recovery_maintenance(request_b));
            (first.join(), second.join())
        });
        let first = first_joined
            .map_err(|_| std::io::Error::other("first maintenance thread must not panic"))??;
        let second = second_joined
            .map_err(|_| std::io::Error::other("second maintenance thread must not panic"))??;

        // Neither worker may classify under someone else's fence.
        assert!(!first.outcome().classified());
        assert!(!second.outcome().classified());
        assert_eq!(
            first.reconciled_executions().len() + second.reconciled_executions().len(),
            0
        );

        // Durable rows are untouched and the holder's lease is unchanged.
        let store = seed_store(&fixture.root)?;
        for raw_id in [0x61_u128, 0x62] {
            let record = store
                .get_execution(ExecutionId::from_uuid(Uuid::from_u128(raw_id)))?
                .ok_or("seeded execution missing")?;
            assert_eq!(record.state(), ExecutionState::Starting, "{raw_id}");
        }
        drop(store);
        let observed = client_holder.recovery_maintenance_lease(scope.clone())?;
        assert_eq!(observed.owner_id(), Some(runtime_id(0xF10)));
        assert_eq!(observed.epoch().get(), 1);

        // Once the holder releases, one worker classifies the full batch.
        let holder_release = ReleaseRecoveryLease::new(
            fixture.workspace_id,
            runtime_id(0xF10),
            held.lease().epoch(),
            held.lease().revision(),
            timestamp(120)?,
        );
        let _released =
            client_holder.release_recovery_maintenance_lease(scope.clone(), holder_release)?;
        let report =
            client_holder.run_recovery_maintenance(maintenance_request(&scope, 0xE03, 130)?)?;
        assert_eq!(report.outcome(), RecoveryMaintenanceOutcome::Completed);
        assert_eq!(report.reconciled_executions().len(), seeded.len());
        assert!(report.lease().is_released());

        worker_a.shutdown()?;
        worker_b.shutdown()?;
        worker_holder.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
