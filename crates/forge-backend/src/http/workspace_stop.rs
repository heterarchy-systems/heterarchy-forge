//! Bounded HTTP owner lane for Workspace-stop requests.
//!
//! The handler admits one request to the existing `ApprovalCoordinator` while
//! holding the HTTP admission read guard, then waits for the already admitted
//! response in a bounded blocking task.  A timeout or disconnected observer
//! drops only the `JoinHandle`: the blocking task keeps the owner receiver,
//! semaphore permit, and `TaskTracker` token until the coordinator replies.

use axum::response::Response;
use uuid::Uuid;

use super::{AppState, ok, reject};
use crate::error::ForgeError;
use crate::ops::workspace_stop::{WorkspaceStopCommand, readback_hint, submit};

/// Bounded concurrent owner submissions for stop and exact readback calls.
pub(super) const STOP_PERMITS: usize = 4;

/// Configured service identity and the sole `ApprovalCoordinator` owner used by
/// this HTTP lane.  The owner contains no native fallback or independent
/// permit authority.
#[derive(Debug)]
pub(super) struct Owner {
    actual_service: forge_control::WorkspaceStopServiceIdentity,
    approval: forge_control::ForgeApprovalCoordinatorClient,
}

impl Owner {
    pub(super) fn new(
        actual_service: forge_control::WorkspaceStopServiceIdentity,
        approval: forge_control::ForgeApprovalCoordinatorClient,
    ) -> Self {
        Self {
            actual_service,
            approval,
        }
    }
}

/// Admit and await one Workspace-stop operation on the bounded owner lane.
pub(super) async fn handle(
    state: &AppState,
    request_id: Uuid,
    request: Box<WorkspaceStopCommand>,
) -> Response {
    let Some(owner) = state.workspace_stop_owner.get() else {
        return reject(
            Some(request_id),
            &ForgeError::capacity_exceeded("Workspace stop owner"),
        );
    };

    let command = *request;
    let readback = readback_hint(&command);
    let admitted = (|| {
        let _admission = state.admission_read()?;
        let permit = state
            .stop_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeError::capacity_exceeded("Workspace stop HTTP lane"))?;
        let task_token = state.event_tasks.token();
        let pending = submit(&owner.approval, &owner.actual_service, &command)?;
        Ok::<_, ForgeError>((pending, permit, task_token))
    })();
    let (pending, permit, task_token) = match admitted {
        Ok(admitted) => admitted,
        Err(error) => return reject(Some(request_id), &error),
    };

    let deadline = state.config().command_deadline();
    let join = tokio::task::spawn_blocking(move || {
        // These values remain owned by the blocking operation after an HTTP
        // timeout or disconnect.  Shutdown observes the TaskTracker token and
        // therefore waits for the owner receiver to settle before reporting a
        // complete drain.
        let (_permit, _task_token) = (permit, task_token);
        pending.recv(&command)
    });
    match tokio::time::timeout(deadline, join).await {
        Ok(Ok(Ok(result))) => ok(request_id, result),
        Ok(Ok(Err(error))) => reject(Some(request_id), &error),
        Ok(Err(_)) | Err(_) => reject(
            Some(request_id),
            &ForgeError::unknown_outcome(Some(readback)),
        ),
    }
}
