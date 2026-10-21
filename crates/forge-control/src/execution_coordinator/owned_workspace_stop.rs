//! Same-owner Workspace stop ordering for an approval-scoped authority stop.
//!
//! The retained context and administrative permit are immutable correlation
//! fences.  They do not prove native process closure, release an approval
//! owner, or terminalize any execution.  Durable capture must be observed
//! before this coordinator can return a successful receipt.

use forge_domain::WorkspaceId;
use forge_persistence::{
    AuthorityStopReceipt, ExecutionStopRecord, ExecutionStopRequest, OwnedWorkspaceStopCapture,
};

use super::{CoordinatorRuntime, ForgeExecutionCoordinatorError};
use crate::approval_cleanup::{ApprovalCleanupOwner, ApprovalCleanupPermit};
use crate::execution_stop::owned::{OwnedExecutionStopContext, OwnedExecutionStopSettlement};
use crate::{ControlClientError, ControlError, ControlErrorCode};

/// One retained approval-scoped stop context.
///
/// The permit and owner remain alongside the immutable worker context so an
/// identical retry cannot replace the original administrative authority
/// envelope after a response loss.
#[derive(Debug)]
pub(super) struct PendingOwnedWorkspaceStop {
    permit: ApprovalCleanupPermit,
    owner: ApprovalCleanupOwner,
    original_request: ExecutionStopRequest,
    context: Option<OwnedExecutionStopContext>,
    must_observe: bool,
    settlement: Option<OwnedExecutionStopSettlement>,
}

/// A captured durable execution stop, authority receipt, and separate native
/// cancellation/journal result.  A successful native count does not establish
/// completion of the durable stop; callers must retain and observe both parts.
#[must_use]
#[derive(Debug)]
pub struct OwnedWorkspaceExecutionStopObservation {
    record: ExecutionStopRecord,
    authority: AuthorityStopReceipt,
    native: Option<Result<usize, Box<ForgeExecutionCoordinatorError>>>,
    quiescence: Result<
        Option<forge_execution::NativeWorkspaceQuiescence>,
        Box<ForgeExecutionCoordinatorError>,
    >,
}

impl OwnedWorkspaceExecutionStopObservation {
    pub const fn record(&self) -> &ExecutionStopRecord {
        &self.record
    }

    pub const fn authority(&self) -> &AuthorityStopReceipt {
        &self.authority
    }

    pub fn native_result(&self) -> Option<Result<usize, &ForgeExecutionCoordinatorError>> {
        self.native
            .as_ref()
            .map(|result| result.as_ref().copied().map_err(Box::as_ref))
    }

    /// This is a live owner observation; durable targets and authority still
    /// require validation before any fence release can be recorded.
    pub fn native_quiescence(
        &self,
    ) -> Result<Option<&forge_execution::NativeWorkspaceQuiescence>, &ForgeExecutionCoordinatorError>
    {
        self.quiescence
            .as_ref()
            .map(Option::as_ref)
            .map_err(Box::as_ref)
    }
}

impl CoordinatorRuntime {
    pub(super) fn stop_owned_workspace_durable(
        &mut self,
        permit: ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: ExecutionStopRequest,
    ) -> Result<OwnedWorkspaceExecutionStopObservation, ForgeExecutionCoordinatorError> {
        let workspace_id = permit.scope().workspace_id();
        if request.workspace_id() != workspace_id {
            return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
        }
        permit
            .ensure_owner(owner)
            .map_err(ControlClientError::Service)?;

        if self.workspace_stops.contains_key(&workspace_id) {
            // A legacy execution-only retention cannot be upgraded into an
            // authority-owned stop or share its retry identity.
            return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
        }
        if !self.owned_workspace_stops.contains_key(&workspace_id)
            && self.workspace_stops.len() + self.owned_workspace_stops.len()
                >= super::workspace_stop::MAX_RETAINED_WORKSPACE_STOPS
        {
            return Err(ForgeExecutionCoordinatorError::QueueFull);
        }
        if let Some(observation) = self.completed_owned_stop_replay(&permit, owner, request)? {
            return Ok(observation);
        }

        if let Some(retained) = self.owned_workspace_stops.get(&workspace_id) {
            if retained.permit != permit
                || retained.owner != owner
                || retained.permit.scope() != permit.scope()
                || !same_request_identity(&retained.original_request, &request)
            {
                return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
            }
        } else {
            let retained = self.workspace_stops.len() + self.owned_workspace_stops.len();
            if retained >= super::workspace_stop::MAX_RETAINED_WORKSPACE_STOPS {
                return Err(ForgeExecutionCoordinatorError::QueueFull);
            }
            self.owned_workspace_stops.insert(
                workspace_id,
                PendingOwnedWorkspaceStop {
                    permit,
                    owner,
                    original_request: request,
                    context: None,
                    must_observe: false,
                    settlement: None,
                },
            );
        }

        // Retain the immutable retry identity before the read-only prepare
        // request. A dropped prepare reply must not lose the owner fence or
        // permit and must never be mistaken for a durable Apply.
        let context = {
            let retained = self
                .owned_workspace_stops
                .get(&workspace_id)
                .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?;
            if let Some(context) = retained.context.as_ref() {
                context.clone()
            } else {
                let permit = retained.permit.clone();
                let owner = retained.owner;
                let request = retained.original_request;
                let context = self
                    .control
                    .prepare_owned_execution_stop_context(permit, owner, request)?;
                self.owned_workspace_stops
                    .get_mut(&workspace_id)
                    .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?
                    .context = Some(context.clone());
                context
            }
        };

        if self
            .owned_workspace_stops
            .get(&workspace_id)
            .is_some_and(|retained| retained.settlement.is_some())
        {
            return self.resume_owned_stop_settlement(&context);
        }

        let capture = self.observe_or_capture_owned_stop(&context);

        // Native cancellation is attempted exactly once after a context has
        // been prepared, even when durable apply/readback returns an error.
        let native = self.stop_workspace_and_journal(workspace_id);
        let quiescence = self.native_stop_quiescence(workspace_id);
        match capture {
            Ok((record, authority)) => {
                self.finish_owned_stop_settlement(&context, &record, &authority, native, quiescence)
            }
            Err(capture) => {
                let (native_cancel_requested, native) = match native {
                    Ok(count) => (Some(count), None),
                    Err(error) => (None, Some(Box::new(error))),
                };
                Err(
                    ForgeExecutionCoordinatorError::WorkspaceStopCaptureAndExecution {
                        stop_id: request.stop_id(),
                        request_id: request.request_id(),
                        capture: Box::new(capture),
                        native,
                        native_cancel_requested,
                    },
                )
            }
        }
    }

    fn observe_or_capture_owned_stop(
        &mut self,
        context: &OwnedExecutionStopContext,
    ) -> Result<(ExecutionStopRecord, AuthorityStopReceipt), ControlClientError> {
        // No map borrow crosses the worker Apply/Observe or native supervisor call.
        let retained = self
            .owned_workspace_stops
            .get(&context.scope().workspace_id())
            .ok_or_else(|| {
                ControlClientError::Service(ControlError::new(ControlErrorCode::Internal))
            })?;
        let must_observe = retained.must_observe;
        if must_observe {
            match self
                .control
                .observe_owned_execution_stop_context(context.clone())
            {
                Ok(Some(receipt)) => Ok(receipt),
                Ok(None) => self.apply_owned_stop_capture(context),
                Err(error) => Err(error),
            }
        } else {
            self.apply_owned_stop_capture(context)
        }
    }

    fn completed_owned_stop_replay(
        &mut self,
        permit: &ApprovalCleanupPermit,
        owner: ApprovalCleanupOwner,
        request: ExecutionStopRequest,
    ) -> Result<Option<OwnedWorkspaceExecutionStopObservation>, ForgeExecutionCoordinatorError>
    {
        let Some((record, authority)) = self
            .control
            .observe_owned_stop_history(permit.clone(), owner, request)
            .map_err(|error| match error {
                ControlClientError::Service(ref service)
                    if matches!(
                        service.code(),
                        crate::ControlErrorCode::ExecutionConflict
                            | crate::ControlErrorCode::ExecutionProvenanceConflict
                    ) =>
                {
                    // This read-only history check precedes capture and
                    // native dispatch; an identity conflict has no effects.
                    ForgeExecutionCoordinatorError::AttributionMismatch
                }
                other => ForgeExecutionCoordinatorError::Control(other),
            })?
        else {
            return Ok(None);
        };
        if record.status() != forge_persistence::ExecutionStopStatus::Completed {
            return Ok(None);
        }
        if self
            .owned_workspace_stops
            .get(&request.workspace_id())
            .is_some_and(|retained| same_request_identity(&retained.original_request, &request))
        {
            let _removed = self.owned_workspace_stops.remove(&request.workspace_id());
        }
        Ok(Some(OwnedWorkspaceExecutionStopObservation {
            record,
            authority,
            native: None,
            quiescence: Ok(None),
        }))
    }

    fn finish_owned_stop_settlement(
        &mut self,
        context: &OwnedExecutionStopContext,
        record: &ExecutionStopRecord,
        authority: &AuthorityStopReceipt,
        native: Result<usize, ForgeExecutionCoordinatorError>,
        quiescence: Result<
            Option<forge_execution::NativeWorkspaceQuiescence>,
            Box<ForgeExecutionCoordinatorError>,
        >,
    ) -> Result<OwnedWorkspaceExecutionStopObservation, ForgeExecutionCoordinatorError> {
        let proof = quiescence.as_ref().ok().and_then(Option::as_ref).cloned();
        let settlement = OwnedExecutionStopSettlement::new(
            context.clone(),
            proof,
            &self.supervisor.client(),
            super::current_timestamp_millis()?,
        )
        .map_err(ControlClientError::Service)?;
        self.owned_workspace_stops
            .get_mut(&context.scope().workspace_id())
            .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?
            .settlement = Some(settlement.clone());
        let pair = match self.apply_owned_stop_settlement(context, settlement) {
            Ok(pair) => pair,
            Err(settlement) => {
                let (native_cancel_requested, native) = match native {
                    Ok(count) => (Some(count), None),
                    Err(error) => (None, Some(Box::new(error))),
                };
                return Err(
                    ForgeExecutionCoordinatorError::WorkspaceStopSettlementAndExecution {
                        settlement: Box::new(settlement),
                        native,
                        native_cancel_requested,
                    },
                );
            }
        };
        if &pair.1 != authority {
            return Err(ForgeExecutionCoordinatorError::JournalFailed);
        }
        if pair.0.stop_id() != record.stop_id() {
            return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
        }
        self.release_settled_retention(context, &pair.0)?;
        Ok(OwnedWorkspaceExecutionStopObservation {
            record: pair.0,
            authority: pair.1,
            native: Some(native.map_err(Box::new)),
            quiescence,
        })
    }

    fn resume_owned_stop_settlement(
        &mut self,
        context: &OwnedExecutionStopContext,
    ) -> Result<OwnedWorkspaceExecutionStopObservation, ForgeExecutionCoordinatorError> {
        // Read back BEFORE retrying or cancelling. An earlier unknown release
        // may already have admitted a later execution.
        let pair = self
            .control
            .observe_owned_execution_stop_context(context.clone())?
            .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?;
        if pair.0.status() == forge_persistence::ExecutionStopStatus::Completed {
            self.release_settled_retention(context, &pair.0)?;
            return Ok(OwnedWorkspaceExecutionStopObservation {
                record: pair.0,
                authority: pair.1,
                native: None,
                quiescence: Ok(None),
            });
        }
        let settlement = self
            .owned_workspace_stops
            .get(&context.scope().workspace_id())
            .and_then(|retained| retained.settlement.clone())
            .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?;
        settlement
            .ensure_live_owner(&self.supervisor.client())
            .map_err(ControlClientError::Service)?;
        let (record, authority) = self.apply_owned_stop_settlement(context, settlement)?;
        self.release_settled_retention(context, &record)?;
        Ok(OwnedWorkspaceExecutionStopObservation {
            record,
            authority,
            native: None,
            quiescence: Ok(None),
        })
    }

    fn apply_owned_stop_settlement(
        &self,
        context: &OwnedExecutionStopContext,
        settlement: OwnedExecutionStopSettlement,
    ) -> Result<(ExecutionStopRecord, AuthorityStopReceipt), ControlClientError> {
        let expected = self
            .control
            .settle_owned_execution_stop_context(settlement)?;
        match self
            .control
            .observe_owned_execution_stop_context(context.clone())?
        {
            Some(pair) if pair == expected => Ok(pair),
            _ => Err(ControlClientError::Service(ControlError::committed())),
        }
    }

    fn release_settled_retention(
        &mut self,
        context: &OwnedExecutionStopContext,
        record: &ExecutionStopRecord,
    ) -> Result<(), ForgeExecutionCoordinatorError> {
        if record.status() == forge_persistence::ExecutionStopStatus::Completed {
            let _removed = self
                .owned_workspace_stops
                .remove(&context.scope().workspace_id());
        } else {
            self.owned_workspace_stops
                .get_mut(&context.scope().workspace_id())
                .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?
                .settlement = None;
        }
        Ok(())
    }

    fn native_stop_quiescence(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<
        Option<forge_execution::NativeWorkspaceQuiescence>,
        Box<ForgeExecutionCoordinatorError>,
    > {
        let client = self.supervisor.client();
        let proof = client
            .observe_workspace_quiescence(workspace_id)
            .map_err(ForgeExecutionCoordinatorError::from)
            .map_err(Box::new)?;
        if proof.as_ref().is_some_and(|proof| {
            proof.workspace_id() != workspace_id || !client.owns_workspace_quiescence(proof)
        }) {
            return Err(Box::new(
                ForgeExecutionCoordinatorError::AttributionMismatch,
            ));
        }
        Ok(proof)
    }

    fn apply_owned_stop_capture(
        &mut self,
        context: &OwnedExecutionStopContext,
    ) -> Result<(ExecutionStopRecord, AuthorityStopReceipt), ControlClientError> {
        let retained = self
            .owned_workspace_stops
            .get_mut(&context.scope().workspace_id())
            .ok_or_else(|| {
                ControlClientError::Service(ControlError::new(ControlErrorCode::Internal))
            })?;
        // Observe is mandatory after every positive or known-error Apply.  A
        // subsequent retry is admitted only after a durable None readback.
        retained.must_observe = true;
        let capture: OwnedWorkspaceStopCapture = self
            .control
            .apply_owned_execution_stop_context(context.clone())?;
        match self
            .control
            .observe_owned_execution_stop_context(context.clone())?
        {
            Some((record, authority))
                if &record == capture.execution().record() && &authority == capture.authority() =>
            {
                Ok((record, authority))
            }
            _ => Err(ControlClientError::Service(ControlError::committed())),
        }
    }
}

fn same_request_identity(left: &ExecutionStopRequest, right: &ExecutionStopRequest) -> bool {
    left.stop_id() == right.stop_id()
        && left.workspace_id() == right.workspace_id()
        && left.request_id() == right.request_id()
        && left.owner_runtime_instance_id() == right.owner_runtime_instance_id()
        && left.request_digest() == right.request_digest()
}
