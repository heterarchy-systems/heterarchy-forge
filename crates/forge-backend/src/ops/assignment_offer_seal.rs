//! Coordinator-authorized permanent Assignment offer-seal transport.
//!
//! The seal is a future-admission fence. Readback reports only the bounded
//! current Assignment metadata; it never infers historical completion.

use forge_control::{
    AgentAssignmentOfferSealRequest, ForgeControlClient, GoalDeletionAuthority,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityId, AgentAssignmentId, AgentAssignmentState, TimestampMillis,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::planning::{PlanningAuthorityDto, decode_authority};
use crate::error::ForgeError;

/// Parsed exact-key Assignment offer-seal command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentOfferSealCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) activity_id: ActivityId,
    pub(super) assignment_id: AgentAssignmentId,
    pub(super) actor: ActivityCoordinatorActor,
    pub(super) observed_at: TimestampMillis,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    authority: PlanningAuthorityDto,
    assignment_id: Uuid,
    observed_at_ms: i64,
}

/// Parse one strict Coordinator-scoped seal or exact seal readback request.
pub(super) fn parse(value: &Value) -> Result<AssignmentOfferSealCommand, ForgeError> {
    let body: Body = super::parse_body(value, "Assignment offer-seal payload is invalid")?;
    let (scope, actor) = decode_authority(&body.authority)?;
    if body.assignment_id.is_nil() {
        return Err(ForgeError::invalid_input("Assignment ID must not be nil"));
    }
    let observed_at = TimestampMillis::new(body.observed_at_ms)
        .map_err(|_| ForgeError::invalid_input("Assignment seal timestamp is invalid"))?;
    Ok(AssignmentOfferSealCommand {
        scope,
        activity_id: actor.activity_id(),
        assignment_id: AgentAssignmentId::from_uuid(body.assignment_id),
        actor,
        observed_at,
    })
}

pub(super) fn execute_seal(
    client: &ForgeControlClient,
    command: &AssignmentOfferSealCommand,
) -> Result<Value, ForgeError> {
    let snapshot = client
        .agent_assignment_offer_seal(control_request(command))
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(snapshot_json(&snapshot))
}

pub(super) fn execute_get(
    client: &ForgeControlClient,
    command: &AssignmentOfferSealCommand,
) -> Result<Value, ForgeError> {
    let snapshot = client
        .agent_assignment_offer_seal_get(control_request(command))
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(snapshot.map_or_else(
        || json!({"found": false}),
        |snapshot| snapshot_json(&snapshot),
    ))
}

fn control_request(command: &AssignmentOfferSealCommand) -> AgentAssignmentOfferSealRequest {
    AgentAssignmentOfferSealRequest::new(
        command.scope.clone(),
        command.activity_id,
        command.assignment_id,
        GoalDeletionAuthority::Coordinator(command.actor),
        command.observed_at,
    )
}

fn snapshot_json(snapshot: &forge_persistence::AgentAssignmentOfferSealSnapshot) -> Value {
    let seal_authority = match snapshot.seal_authority() {
        forge_persistence::AgentAssignmentOfferSealAuthority::LocalOperator => json!({
            "authority_kind": "local_operator",
            "coordinator_agent_id": null,
            "coordinator_session_id": null,
            "expected_coordinator_revision": null,
        }),
        forge_persistence::AgentAssignmentOfferSealAuthority::Coordinator {
            agent_id,
            session_id,
            expected_coordinator_revision,
        } => json!({
            "authority_kind": "coordinator",
            "coordinator_agent_id": agent_id.into_uuid(),
            "coordinator_session_id": session_id.into_uuid(),
            "expected_coordinator_revision": expected_coordinator_revision.get(),
        }),
    };
    let present = snapshot.current_assignment().map(|assignment| {
        let state = match assignment.state() {
            AgentAssignmentState::Offered => "offered",
            AgentAssignmentState::Running => "running",
            AgentAssignmentState::Submitted => "submitted",
            AgentAssignmentState::Accepted => "accepted",
            AgentAssignmentState::Rejected => "rejected",
            AgentAssignmentState::Cancelled => "cancelled",
            AgentAssignmentState::Interrupted => "interrupted",
        };
        json!({
            "assignment_id": assignment.id().into_uuid(),
            "workspace_id": assignment.workspace_id().into_uuid(),
            "activity_id": assignment.activity_id().into_uuid(),
            "activity_relation": if assignment.activity_id() == snapshot.requested_activity_id() {
                "same_activity"
            } else {
                "foreign_activity"
            },
            "goal_id": assignment.goal_id().into_uuid(),
            "goal_created_at_ms": assignment.goal_created_at().get(),
            "goal_revision": assignment.goal_revision().get(),
            "dag_revision": assignment.dag_revision().get(),
            "dag_head_revision": assignment.dag_head_revision().get(),
            "node_id": assignment.node_id().into_uuid(),
            "node_revision": assignment.node_revision().get(),
            "target_agent_id": assignment.target().agent_id().into_uuid(),
            "target_session_id": assignment.target().session_id().into_uuid(),
            "state": state,
            "cancellation_requested": assignment.cancellation_requested(),
            "has_result": assignment.result().is_some(),
            "revision": assignment.revision().get(),
        })
    });
    json!({
        "found": true,
        "sealed": true,
        "workspace_id": snapshot.workspace_id().into_uuid(),
        "requested_activity_id": snapshot.requested_activity_id().into_uuid(),
        "assignment_id": snapshot.assignment_id().into_uuid(),
        "sealed_at_ms": snapshot.sealed_at().get(),
        "seal_authority": seal_authority,
        "state": if present.is_some() {
            "present_registered_assignment"
        } else {
            "absent_now_sealed"
        },
        "present_registered_assignment": present,
    })
}

#[cfg(test)]
mod tests {
    use crate::ops::CommandOp;

    #[test]
    fn offer_seal_operations_are_session_bound_and_registered() {
        assert_eq!(
            CommandOp::parse("agent.assignment_offer_seal"),
            Some(CommandOp::AgentAssignmentOfferSeal)
        );
        assert_eq!(
            CommandOp::parse("agent.assignment_offer_seal_get"),
            Some(CommandOp::AgentAssignmentOfferSealGet)
        );
        assert!(CommandOp::ALL.contains(&CommandOp::AgentAssignmentOfferSeal));
        assert!(CommandOp::ALL.contains(&CommandOp::AgentAssignmentOfferSealGet));
        assert!(CommandOp::AgentAssignmentOfferSeal.requires_session_authority());
        assert!(CommandOp::AgentAssignmentOfferSealGet.requires_session_authority());
    }
}
