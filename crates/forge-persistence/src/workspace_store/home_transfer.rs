//! Live-Workspace facade for the distinct Home source journal.
use super::{WorkspaceStore, WorkspaceStoreError};
use crate::{
    HomeTransferReservationRetirementOutcome, HomeTransferReservationRetirementRecord,
    HomeTransferSourceOutcome, HomeTransferSourceRecord, HomeTransferStoreError,
    workspace_home_transfers,
};
use forge_domain::{
    ForgeBackendId, HomeTransferReservationRetirementGrant,
    HomeTransferReservationRetirementRequest, HomeTransferSourceAction, HomeTransferSourceGrant,
    HomeTransferSourceRequest, OrchestrationIssuerId, TimestampMillis,
};
use uuid::Uuid;

impl WorkspaceStore {
    /// Retire one exact unused reservation under an authenticated Source grant.
    /// This does not settle broader work, remove the preparation fence, or
    /// change Home membership. Source time is sampled in the owner transaction.
    ///
    /// # Errors
    /// Rejects stale scope, changed parent/provenance, used or terminated
    /// reservations, corrupt storage, and uncertain commit/binding outcomes.
    pub fn retire_home_transfer_unused_reservation<C>(
        &mut self,
        request: &HomeTransferReservationRetirementRequest,
        grant: HomeTransferReservationRetirementGrant,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
        sample_clock: C,
    ) -> Result<HomeTransferReservationRetirementOutcome, WorkspaceStoreError>
    where
        C: FnOnce() -> Result<TimestampMillis, HomeTransferStoreError>,
    {
        self.ensure_live_binding()?;
        let outcome = workspace_home_transfers::retirements::retire(
            &mut self.connection,
            request,
            grant,
            issuer,
            backend,
            destination,
            sample_clock,
        )?;
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(
                |source| WorkspaceStoreError::HomeReservationRetirementReadbackRequired {
                    preparation_id: request.preparation_id(),
                    reservation_request_id: request.reservation_request_id(),
                    source: Box::new(source),
                },
            )?;
        Ok(outcome)
    }

    /// Read one immutable terminal retirement under its original service pins.
    /// A missing record is not proof that an in-flight mutation cannot commit.
    ///
    /// # Errors
    /// Rejects changed service identity, malformed or contradictory evidence,
    /// storage failure, and loss of the exact live Workspace binding.
    pub fn get_home_transfer_reservation_retirement(
        &self,
        preparation_id: Uuid,
        reservation_request_id: Uuid,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
    ) -> Result<Option<HomeTransferReservationRetirementRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let record = workspace_home_transfers::retirements::get(
            &self.connection,
            preparation_id,
            reservation_request_id,
        )?;
        if record.as_ref().is_some_and(|record| {
            record.issuer() != issuer
                || record.request().scope().backend_id() != backend
                || record.request().scope().destination_id() != destination
        }) {
            return Err(
                HomeTransferStoreError::Conflict("retirement history service scope").into(),
            );
        }
        self.ensure_live_binding()?;
        Ok(record)
    }

    /// Authenticate the configured service before calling. Source time is sampled
    /// inside the write transaction after capture, not before lock acquisition.
    pub fn prepare_home_transfer_source<C>(
        &mut self,
        request: &HomeTransferSourceRequest,
        grant: HomeTransferSourceGrant,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
        sample_clock: C,
    ) -> Result<HomeTransferSourceOutcome, WorkspaceStoreError>
    where
        C: FnOnce() -> Result<TimestampMillis, HomeTransferStoreError>,
    {
        self.apply_home_transfer_source(
            request,
            HomeTransferSourceAction::Prepare,
            grant,
            issuer,
            backend,
            destination,
            sample_clock,
        )
    }

    /// Absent -> immutable `AbortedUnstarted`. Existing Prepared is returned
    /// unchanged; this operation never releases a source fence.
    pub fn abort_unstarted_home_transfer_source<C>(
        &mut self,
        request: &HomeTransferSourceRequest,
        grant: HomeTransferSourceGrant,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
        sample_clock: C,
    ) -> Result<HomeTransferSourceOutcome, WorkspaceStoreError>
    where
        C: FnOnce() -> Result<TimestampMillis, HomeTransferStoreError>,
    {
        self.apply_home_transfer_source(
            request,
            HomeTransferSourceAction::AbortUnstarted,
            grant,
            issuer,
            backend,
            destination,
            sample_clock,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "explicit service scope and action at one owner"
    )]
    fn apply_home_transfer_source<C>(
        &mut self,
        request: &HomeTransferSourceRequest,
        action: HomeTransferSourceAction,
        grant: HomeTransferSourceGrant,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
        sample_clock: C,
    ) -> Result<HomeTransferSourceOutcome, WorkspaceStoreError>
    where
        C: FnOnce() -> Result<TimestampMillis, HomeTransferStoreError>,
    {
        self.ensure_live_binding()?;
        let preparation_id = request.witness().preparation_id();
        let outcome = workspace_home_transfers::apply(
            &mut self.connection,
            request,
            action,
            grant,
            issuer,
            backend,
            destination,
            sample_clock,
        )?;
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| WorkspaceStoreError::HomeTransferReadbackRequired {
                preparation_id,
                source: Box::new(source),
            })?;
        Ok(outcome)
    }

    /// Exact immutable history under the original authenticated service scope.
    /// None is not proof that a concurrently submitted Prepare cannot commit.
    pub fn get_home_transfer_source(
        &self,
        preparation_id: Uuid,
        issuer: OrchestrationIssuerId,
        backend: ForgeBackendId,
        destination: Uuid,
    ) -> Result<Option<HomeTransferSourceRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let result = workspace_home_transfers::get(&self.connection, preparation_id)?;
        if result.as_ref().is_some_and(|record| {
            record.issuer() != issuer
                || record.request().scope().backend_id() != backend
                || record.request().scope().destination_id() != destination
        }) {
            return Err(
                HomeTransferStoreError::Conflict("configured history service scope").into(),
            );
        }
        self.ensure_live_binding()?;
        Ok(result)
    }
}
