//! Production semantic-event query adapter over the bounded forge-control
//! worker.
//!
//! The adapter contains no persistence access.  `forge-control` remains the
//! scope validator and durable read owner; this module only projects the
//! canonical records into the existing bounded backend wire shape.

use forge_control::{
    ControlClientError, ControlErrorCode, ForgeControlClient, ResolvedWorkspaceScope,
    SemanticEventsPageRequest, WorkspaceSemanticSnapshotRequest,
};
use serde_json::json;

use super::{EventPage, EventQuery, EventQueryError, EventRecord, Subjects};

/// Production event/snapshot provider backed by the single-owner control
/// worker.  The client is a cheap cloneable handle; all durable reads remain
/// inside forge-control and its Workspace `SQLite` authority.
#[derive(Debug, Clone)]
pub struct ControlEventQuery {
    client: ForgeControlClient,
}

impl ControlEventQuery {
    /// Build a provider around the existing bounded control client.
    #[must_use]
    pub fn new(client: ForgeControlClient) -> Self {
        Self { client }
    }
}

impl EventQuery for ControlEventQuery {
    fn page(
        &self,
        scope: &ResolvedWorkspaceScope,
        after: u64,
        limit: u32,
    ) -> Result<EventPage, EventQueryError> {
        let result = self
            .client
            .semantic_events_page(SemanticEventsPageRequest {
                scope: scope.clone(),
                after,
                limit,
            })
            .map_err(map_control_error)?;
        if result.scope() != scope {
            return Err(EventQueryError::ResyncRequired);
        }
        let page = result.page();
        Ok(EventPage {
            events: page
                .events()
                .iter()
                .map(|record| {
                    let event = record.event();
                    let subjects = event.subjects();
                    let subjects = Subjects {
                        goal_id: subjects.goal_id.map(forge_domain::GoalId::into_uuid),
                        dag_revision: subjects
                            .dag_revision
                            .map(forge_domain::DagRevisionNumber::get),
                        node_id: subjects.node_id.map(forge_domain::DagNodeId::into_uuid),
                        execution_id: subjects
                            .execution_id
                            .map(forge_domain::ExecutionId::into_uuid),
                        change_set_id: subjects
                            .change_set_id
                            .map(forge_domain::ChangeSetId::into_uuid),
                        diff_id: subjects.diff_id.map(forge_domain::DiffId::into_uuid),
                        verification: subjects
                            .verification
                            .map(forge_domain::VerificationInputId::into_uuid),
                    };
                    EventRecord {
                        sequence: record.sequence(),
                        kind: event.kind().as_str().to_owned(),
                        revision: event.revision(),
                        observed_at_ms: event.observed_at().get(),
                        digest: event.payload_digest(),
                        subjects: (subjects.goal_id.is_some()
                            || subjects.dag_revision.is_some()
                            || subjects.node_id.is_some()
                            || subjects.execution_id.is_some()
                            || subjects.change_set_id.is_some()
                            || subjects.diff_id.is_some()
                            || subjects.verification.is_some())
                        .then_some(subjects),
                    }
                })
                .collect(),
            high_water: page.high_water(),
            retained_low: page.retained_low(),
        })
    }

    fn snapshot(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(u64, u64, serde_json::Value), EventQueryError> {
        let result = self
            .client
            .workspace_semantic_snapshot(WorkspaceSemanticSnapshotRequest {
                scope: scope.clone(),
            })
            .map_err(map_control_error)?;
        if result.scope() != scope {
            return Err(EventQueryError::ResyncRequired);
        }
        let snapshot = result.snapshot();
        let goals = snapshot
            .goals()
            .iter()
            .map(|goal| {
                json!({
                    "goal_id": goal.goal_id.into_uuid(),
                    "activity_id": goal.activity_id.into_uuid(),
                    "revision": goal.revision,
                    "state": goal.state.as_str(),
                    "current_dag_revision": goal
                        .current_dag_revision
                        .map(forge_domain::DagRevisionNumber::get),
                    "current_node_count": goal.current_node_count,
                })
            })
            .collect::<Vec<_>>();
        Ok((
            snapshot.watermark_seq(),
            snapshot.retained_low(),
            json!({
                "goal_count": goals.len(),
                "goals_truncated": snapshot.goals_truncated(),
                "goals": goals,
            }),
        ))
    }
}

fn map_control_error(error: ControlClientError) -> EventQueryError {
    match error {
        ControlClientError::QueueFull => EventQueryError::CapacityExceeded,
        ControlClientError::Service(error) => match error.code() {
            ControlErrorCode::WorkspaceNotFound
            | ControlErrorCode::WorkspaceNotInitialized
            | ControlErrorCode::LocationNotFound => EventQueryError::UnknownWorkspace,
            ControlErrorCode::LocationRevisionConflict
            | ControlErrorCode::WorkspaceRevisionConflict
            | ControlErrorCode::WorkspaceRootConflict
            | ControlErrorCode::WorkspaceIdentityConflict
            | ControlErrorCode::ProjectionResyncRequired => EventQueryError::ResyncRequired,
            ControlErrorCode::CapacityExceeded => EventQueryError::CapacityExceeded,
            _ => EventQueryError::Failed,
        },
        ControlClientError::WorkerClosed
        | ControlClientError::WorkerShuttingDown
        | ControlClientError::ResponseDropped => EventQueryError::Failed,
    }
}
