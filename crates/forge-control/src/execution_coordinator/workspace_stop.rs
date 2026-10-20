//! Same-owner Start/stop ordering with retained durable capture recovery.

use forge_persistence::{ExecutionStopRecord, ExecutionStopRequest};

use super::{CoordinatorRuntime, ForgeExecutionCoordinatorError};
use crate::execution_stop::ExecutionStopContext;
use crate::{ControlClientError, ControlError, ControlErrorCode, ResolvedWorkspaceScope};

pub(super) const MAX_RETAINED_WORKSPACE_STOPS: usize = 32;

#[derive(Debug)]
pub(super) struct PendingWorkspaceStop {
    context: ExecutionStopContext,
    must_observe: bool,
}

/// A captured pending receipt and the separate native cancellation/journal result.
/// Neither a count nor an empty live owner proves complete Workspace settlement.
#[must_use]
#[derive(Debug)]
pub struct WorkspaceExecutionStopObservation {
    record: ExecutionStopRecord,
    native: Result<usize, Box<ForgeExecutionCoordinatorError>>,
}

impl WorkspaceExecutionStopObservation {
    pub const fn record(&self) -> &ExecutionStopRecord {
        &self.record
    }

    pub fn native_result(&self) -> Result<usize, &ForgeExecutionCoordinatorError> {
        self.native.as_ref().copied().map_err(Box::as_ref)
    }
}

impl CoordinatorRuntime {
    pub(super) fn stop_workspace_durable(
        &mut self,
        scope: ResolvedWorkspaceScope,
        request: ExecutionStopRequest,
    ) -> Result<WorkspaceExecutionStopObservation, ForgeExecutionCoordinatorError> {
        let workspace_id = scope.workspace_id();
        if request.workspace_id() != workspace_id {
            return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
        }
        if self.owned_workspace_stops.contains_key(&workspace_id) {
            return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
        }
        if let Some(retained) = self.workspace_stops.get(&workspace_id) {
            if retained.context.scope() != &scope
                || !same_request_identity(retained.context.request(), &request)
            {
                return Err(ForgeExecutionCoordinatorError::AttributionMismatch);
            }
        } else {
            if self.workspace_stops.len() + self.owned_workspace_stops.len()
                >= MAX_RETAINED_WORKSPACE_STOPS
            {
                return Err(ForgeExecutionCoordinatorError::QueueFull);
            }
            let context = self
                .control
                .prepare_execution_stop_context(scope, request)?;
            self.workspace_stops.insert(
                workspace_id,
                PendingWorkspaceStop {
                    context,
                    must_observe: false,
                },
            );
        }
        // Clone the immutable envelope, not live capabilities. No map borrow is
        // held across the bounded worker or supervisor call.
        let retained = self
            .workspace_stops
            .get(&workspace_id)
            .ok_or(ForgeExecutionCoordinatorError::JournalFailed)?;
        let context = retained.context.clone();
        let must_observe = retained.must_observe;
        let capture = if must_observe {
            match self.control.observe_execution_stop_context(context.clone()) {
                Ok(Some(record)) => Ok(record),
                Ok(None) => self.apply_stop_capture(&context),
                Err(error) => Err(error),
            }
        } else {
            self.apply_stop_capture(&context)
        };
        // This native client already owns its supervisor. The context creates
        // no additional permission. Capture/readback failure cannot suppress
        // cancellation and journal observation of this owner's existing work.
        let native = self.stop_workspace_and_journal(workspace_id);
        match capture {
            Ok(record) => Ok(WorkspaceExecutionStopObservation {
                record,
                native: native.map_err(Box::new),
            }),
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

    fn apply_stop_capture(
        &mut self,
        context: &ExecutionStopContext,
    ) -> Result<ExecutionStopRecord, ControlClientError> {
        let retained = self
            .workspace_stops
            .get_mut(&context.scope().workspace_id())
            .ok_or_else(|| {
                ControlClientError::Service(ControlError::new(ControlErrorCode::Internal))
            })?;
        // Set Observe before admission, including positive replies and known
        // errors. Only durable absence can permit a later identical retry.
        retained.must_observe = true;
        let capture = self.control.apply_execution_stop_context(context.clone())?;
        match self
            .control
            .observe_execution_stop_context(context.clone())?
        {
            Some(record) if &record == capture.record() => Ok(record),
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
