//! Request-owned wait lifecycle; no bridge worker or detached producer.

use axum::response::Response;
use uuid::Uuid;

use super::{AppState, ok, reject};
use crate::error::{ForgeError, ReadbackHint};
use crate::ops::execution_wait::{ExecutionWaitCommand, project};

pub(super) async fn handle(
    state: &AppState,
    request_id: Uuid,
    request: &ExecutionWaitCommand,
) -> Response {
    let admitted = (|| {
        let _admission = state.admission_read()?;
        let permit = state
            .execution_waits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeError::capacity_exceeded("execution wait admission"))?;
        let handle = state.executor.begin_wait(request.parameters()?)?;
        Ok::<_, ForgeError>((permit, handle))
    })();
    let (_permit, handle) = match admitted {
        Ok(admitted) => admitted,
        Err(error) => return reject(Some(request_id), &error),
    };
    // The native budget ends with a final durable read. This additional
    // response-delivery budget bounds queue/authority stalls, not execution.
    let deadline = request
        .timeout()
        .saturating_add(state.config().command_deadline());
    tokio::select! {
        () = state.shutdown.cancelled() => reject(
            Some(request_id), &ForgeError::capacity_exceeded("execution wait shutting down"),
        ),
        result = tokio::time::timeout(deadline, handle) => match result {
            Ok(Ok(result)) => ok(request_id, project(request.execution_id(), &result)),
            Ok(Err(error)) => reject(Some(request_id), &ForgeError::from_control_view(&error.view())),
            Err(_) => reject(Some(request_id), &ForgeError::unknown_outcome(Some(
                ReadbackHint::Execution { execution_id: request.execution_id().into_uuid() },
            ))),
        },
    }
}
