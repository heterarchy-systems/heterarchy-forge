//! Fast-lane execution cancellation.
//!
//! Cancellation is a control instruction, not ordinary work: it must not wait
//! behind a saturated command bridge while the child process keeps running.
//! The request goes straight to the execution coordinator's own bounded lane,
//! gated by the same admission boundary and a small dedicated permit pool.

use std::sync::Arc;

use axum::response::Response;
use uuid::Uuid;

use super::{AppState, ok, reject};
use crate::error::{ForgeError, ReadbackHint};
use crate::ops::execution::ExecutionCancelCommand;

/// Concurrent coordinator-bound cancellations. Deliberately small: a cancel
/// is an immediate coordinator dispatch, not queued work.
pub(super) const CANCEL_FAST_LANE_PERMITS: usize = 4;

pub(super) async fn handle(
    state: &AppState,
    request_id: Uuid,
    request: Box<ExecutionCancelCommand>,
) -> Response {
    let execution = match state.execution_fast_lane.get() {
        Some(execution) => Arc::clone(execution),
        None => {
            return reject(
                Some(request_id),
                &ForgeError::capacity_exceeded("execution cancel fast lane"),
            );
        }
    };
    let admitted = (|| {
        let _admission = state.admission_read()?;
        let permit = state
            .cancel_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeError::capacity_exceeded("execution cancel fast lane"))?;
        let task_token = state.event_tasks.token();
        Ok::<_, ForgeError>((permit, task_token))
    })();
    let (permit, task_token) = match admitted {
        Ok(admitted) => admitted,
        Err(error) => return reject(Some(request_id), &error),
    };
    let execution_id = request.authority.execution_id;
    // The blocking coordinator dispatch keeps running past the response
    // budget: a lost reply never proves that the child still runs, and the
    // coordinator lane owns the durable cancel request.
    let deadline = state.config().command_deadline();
    match tokio::time::timeout(
        deadline,
        tokio::task::spawn_blocking(move || {
            // The admitted work owns both limits until it settles, even if
            // the HTTP observer times out or disconnects. Shutdown tracks it.
            let (_permit, _task_token) = (permit, task_token);
            crate::ops::execution::execute_cancel(&execution, &request)
        }),
    )
    .await
    {
        Ok(Ok(Ok(result))) => ok(request_id, result),
        Ok(Ok(Err(error))) => reject(Some(request_id), &error),
        Ok(Err(_)) => reject(Some(request_id), &ForgeError::internal()),
        Err(_) => reject(
            Some(request_id),
            &ForgeError::unknown_outcome(Some(ReadbackHint::Execution {
                execution_id: execution_id.into_uuid(),
            })),
        ),
    }
}
