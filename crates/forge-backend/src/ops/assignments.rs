//! Agent Assignment lifecycle ops. `agent.assignment.mutate` is the single
//! tagged entry point over the closed `AgentAssignmentMutation` family
//! (offer/claim/submit/review/cancel+acknowledge); `agent.assignment.get` and
//! `agent.assignment.list` are the bounded read projections. The mutation and
//! read authority carry the exact session identity, which forge-control
//! revalidates internally; the adapter only decodes bounded wire values.

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use forge_control::{ForgeControlClient, ResolvedWorkspaceScope};
use forge_domain::{ActivityId, AgentAssignmentId, AgentInstanceId, AgentSessionId};

use crate::error::ForgeError;

use super::{
    Command, ParseResult, PrincipalDto, ScopeDto, decode_principal, decode_scope, decode_timestamp,
};

fn assignment_id_from_wire(value: Uuid) -> AgentAssignmentId {
    AgentAssignmentId::from_uuid(value)
}

fn assignment_record_json(assignment: &forge_domain::RegisteredAgentAssignment) -> Value {
    let target = assignment.target();
    let result = assignment.result();
    json!({
        "assignment_id": assignment.id().into_uuid(),
        "origin": format!("{:?}", assignment.origin()).to_ascii_lowercase(),
        "workspace_id": assignment.workspace_id().into_uuid(),
        "activity_id": assignment.activity_id().into_uuid(),
        "goal_id": assignment.goal_id().into_uuid(),
        "goal_created_at_ms": assignment.goal_created_at().get(),
        "goal_revision": assignment.goal_revision().get(),
        "dag_revision": assignment.dag_revision().get(),
        "dag_head_revision": assignment.dag_head_revision().get(),
        "node_id": assignment.node_id().into_uuid(),
        "node_revision": assignment.node_revision().get(),
        "target": {
            "agent_id": target.agent_id().into_uuid(),
            "session_id": target.session_id().into_uuid(),
            "agent_revision": target.agent_revision().get(),
        },
        "state": format!("{:?}", assignment.state()).to_ascii_lowercase(),
        "cancellation_requested": assignment.cancellation_requested(),
        "has_result": assignment.result().is_some(),
        "source_count": result.map_or(0, |value| value.sources().len()),
        "report": result.map(forge_domain::AgentAssignmentResult::report),
        "created_at_ms": assignment.created_at().get(),
        "updated_at_ms": assignment.updated_at().get(),
        "revision": assignment.revision().get(),
    })
}

fn assignment_summary_json(summary: &forge_domain::AgentAssignmentSummary) -> Value {
    json!({
        "assignment_id": summary.id().into_uuid(),
        "origin": format!("{:?}", summary.origin()).to_ascii_lowercase(),
        "workspace_id": summary.workspace_id().into_uuid(),
        "activity_id": summary.activity_id().into_uuid(),
        "goal_id": summary.goal_id().into_uuid(),
        "goal_revision": summary.goal_revision().get(),
        "dag_revision": summary.dag_revision().get(),
        "dag_head_revision": summary.dag_head_revision().get(),
        "node_id": summary.node_id().into_uuid(),
        "node_revision": summary.node_revision().get(),
        "target_agent_id": summary.target_agent_id().into_uuid(),
        "target_session_id": summary.target_session_id().into_uuid(),
        "state": format!("{:?}", summary.state()).to_ascii_lowercase(),
        "cancellation_requested": summary.cancellation_requested(),
        "has_result": summary.has_result(),
        "source_count": summary.source_count(),
        "created_at_ms": summary.created_at().get(),
        "updated_at_ms": summary.updated_at().get(),
        "revision": summary.revision().get(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorDto {
    session_id: Uuid,
    agent_id: Uuid,
    expected_revision: i64,
    principal: PrincipalDto,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetDto {
    agent_id: Uuid,
    session_id: Uuid,
    expected_revision: i64,
    principal: PrincipalDto,
}

impl CoordinatorDto {
    fn into_actor(
        self,
        scope: &ResolvedWorkspaceScope,
        activity_id: ActivityId,
    ) -> Result<forge_domain::ActivityCoordinatorActor, ForgeError> {
        Ok(forge_domain::ActivityCoordinatorActor::new(
            scope.workspace_id(),
            activity_id,
            AgentInstanceId::from_uuid(self.agent_id),
            forge_domain::ActivityCoordinatorRevision::new(self.expected_revision)
                .map_err(|_| ForgeError::invalid_input("the coordinator revision is invalid"))?,
            decode_principal(&self.principal)?,
            AgentSessionId::from_uuid(self.session_id),
        ))
    }
}

impl TargetDto {
    fn into_target(self) -> Result<forge_domain::AgentAssignmentTarget, ForgeError> {
        Ok(forge_domain::AgentAssignmentTarget::new(
            AgentInstanceId::from_uuid(self.agent_id),
            AgentSessionId::from_uuid(self.session_id),
            decode_principal(&self.principal)?,
            forge_domain::AgentInstanceRevision::new(self.expected_revision)
                .map_err(|_| ForgeError::invalid_input("the agent revision is invalid"))?,
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationBody {
    scope: ScopeDto,
    activity_id: Uuid,
    assignment_id: Uuid,
    observed_at_ms: i64,
    action: ActionDto,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ActionDto {
    Offer {
        coordinator: CoordinatorDto,
        target: TargetDto,
        goal_id: Uuid,
        expected_goal_revision: i64,
        expected_goal_created_at_ms: i64,
        dag_revision: i64,
        expected_head_revision: i64,
        node_id: Uuid,
        expected_node_revision: i64,
        #[serde(default)]
        credit_budget: Option<i64>,
    },
    Claim {
        target: TargetDto,
        expected_assignment_revision: i64,
    },
    Submit {
        target: TargetDto,
        expected_assignment_revision: i64,
        report: String,
        #[serde(default)]
        sources: Vec<String>,
    },
    ReviewAccept {
        coordinator: CoordinatorDto,
        expected_assignment_revision: i64,
    },
    ReviewReject {
        coordinator: CoordinatorDto,
        expected_assignment_revision: i64,
    },
    CancelRequest {
        coordinator: CoordinatorDto,
        expected_assignment_revision: i64,
    },
    CancelAcknowledge {
        target: TargetDto,
        expected_assignment_revision: i64,
    },
}

#[allow(
    clippy::too_many_lines,
    reason = "One arm per mutation keeps the closed action dispatch reviewable."
)]
pub(super) fn parse_agent_assignment_mutate(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: MutationBody =
        super::parse_body(payload, "agent.assignment.mutate payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let assignment_id = assignment_id_from_wire(body.assignment_id);
    let observed_at = decode_timestamp(body.observed_at_ms)?;
    let mutation = match body.action {
        ActionDto::Offer {
            coordinator,
            target,
            goal_id,
            expected_goal_revision,
            expected_goal_created_at_ms,
            dag_revision,
            expected_head_revision,
            node_id,
            expected_node_revision,
            credit_budget,
        } => {
            let invalid = || ForgeError::invalid_input("an assignment fence value is invalid");
            forge_control::AgentAssignmentMutation::Offer(forge_domain::OfferAgentAssignment::new(
                assignment_id,
                coordinator.into_actor(&scope, ActivityId::from_uuid(body.activity_id))?,
                target.into_target()?,
                forge_domain::GoalId::from_uuid(goal_id),
                forge_domain::GoalRevision::new(expected_goal_revision).map_err(|_| invalid())?,
                decode_timestamp(expected_goal_created_at_ms)?,
                forge_domain::DagRevisionNumber::new(dag_revision).map_err(|_| invalid())?,
                forge_domain::DagHeadRevision::new(expected_head_revision)
                    .map_err(|_| invalid())?,
                forge_domain::DagNodeId::from_uuid(node_id),
                forge_domain::DagNodeRevision::new(expected_node_revision)
                    .map_err(|_| invalid())?,
                credit_budget
                    .map(forge_domain::WorkCreditBudget::try_from_i64)
                    .transpose()
                    .map_err(|_| ForgeError::invalid_input("the credit budget is out of range"))?,
                observed_at,
            ))
        }
        ActionDto::Claim {
            target,
            expected_assignment_revision,
        } => {
            forge_control::AgentAssignmentMutation::Claim(forge_domain::ClaimAgentAssignment::new(
                assignment_id,
                target.into_target()?,
                revision_for(expected_assignment_revision)?,
                observed_at,
            ))
        }
        ActionDto::Submit {
            target,
            expected_assignment_revision,
            report,
            sources,
        } => {
            let sources = sources
                .into_iter()
                .map(|value| {
                    forge_domain::AgentAssignmentSourceUrl::new(value)
                        .map(forge_domain::AgentAssignmentSourceRef::Url)
                        .map_err(|_| {
                            ForgeError::invalid_input("an assignment source URL is invalid")
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let result = forge_domain::AgentAssignmentResult::new(report, sources, None)
                .map_err(|_| ForgeError::invalid_input("the assignment report is invalid"))?;
            forge_control::AgentAssignmentMutation::Submit(
                forge_domain::SubmitAgentAssignment::new(
                    assignment_id,
                    target.into_target()?,
                    revision_for(expected_assignment_revision)?,
                    result,
                    observed_at,
                ),
            )
        }
        ActionDto::ReviewAccept {
            coordinator,
            expected_assignment_revision,
        } => forge_control::AgentAssignmentMutation::Accept(
            forge_domain::ReviewAgentAssignment::new(
                assignment_id,
                coordinator.into_actor(&scope, ActivityId::from_uuid(body.activity_id))?,
                revision_for(expected_assignment_revision)?,
                observed_at,
            ),
        ),
        ActionDto::ReviewReject {
            coordinator,
            expected_assignment_revision,
        } => forge_control::AgentAssignmentMutation::Reject(
            forge_domain::ReviewAgentAssignment::new(
                assignment_id,
                coordinator.into_actor(&scope, ActivityId::from_uuid(body.activity_id))?,
                revision_for(expected_assignment_revision)?,
                observed_at,
            ),
        ),
        ActionDto::CancelRequest {
            coordinator,
            expected_assignment_revision,
        } => forge_control::AgentAssignmentMutation::Cancel(
            forge_domain::CancelAgentAssignment::new(
                assignment_id,
                coordinator.into_actor(&scope, ActivityId::from_uuid(body.activity_id))?,
                revision_for(expected_assignment_revision)?,
                observed_at,
            ),
        ),
        ActionDto::CancelAcknowledge {
            target,
            expected_assignment_revision,
        } => forge_control::AgentAssignmentMutation::AcknowledgeCancellation(
            forge_domain::AcknowledgeAgentAssignmentCancellation::new(
                assignment_id,
                target.into_target()?,
                revision_for(expected_assignment_revision)?,
                observed_at,
            ),
        ),
    };
    Ok(Command::AgentAssignmentMutate {
        request_id,
        request: Box::new(forge_control::AgentAssignmentMutationRequest { scope, mutation }),
    })
}

fn revision_for(value: i64) -> Result<forge_domain::AgentAssignmentRevision, ForgeError> {
    forge_domain::AgentAssignmentRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("the assignment revision is invalid"))
}

pub(super) fn execute_agent_assignment_mutate(
    client: &ForgeControlClient,
    request: forge_control::AgentAssignmentMutationRequest,
) -> Result<Value, ForgeError> {
    let assignment = client
        .agent_assignment_mutate(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "assignment": assignment_record_json(&assignment),
    }))
}

pub(super) fn parse_agent_assignment_get(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        assignment_id: Uuid,
        session_id: Uuid,
        agent_id: Uuid,
        expected_agent_revision: i64,
        principal: PrincipalDto,
    }
    let body: Body = super::parse_body(payload, "agent.assignment.get payload is invalid")?;
    Ok(Command::AgentAssignmentGet {
        request_id,
        request: Box::new(forge_control::AgentAssignmentGetRequest {
            scope: decode_scope(&body.scope)?,
            activity_id: ActivityId::from_uuid(body.activity_id),
            assignment_id: assignment_id_from_wire(body.assignment_id),
            authority: forge_control::AgentAssignmentReadAuthority {
                session_id: AgentSessionId::from_uuid(body.session_id),
                agent_id: AgentInstanceId::from_uuid(body.agent_id),
                expected_agent_revision: forge_domain::AgentInstanceRevision::new(
                    body.expected_agent_revision,
                )
                .map_err(|_| ForgeError::invalid_input("the agent revision is invalid"))?,
                principal: decode_principal(&body.principal)?,
            },
        }),
    })
}

pub(super) fn execute_agent_assignment_get(
    client: &ForgeControlClient,
    request: forge_control::AgentAssignmentGetRequest,
) -> Result<Value, ForgeError> {
    let found = client
        .agent_assignment_get(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some(assignment) = found else {
        return Ok(json!({ "found": false }));
    };
    Ok(json!({
        "found": true,
        "assignment": assignment_record_json(&assignment),
    }))
}

pub(super) fn parse_agent_assignment_list(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        session_id: Uuid,
        agent_id: Uuid,
        expected_agent_revision: i64,
        principal: PrincipalDto,
        #[serde(default)]
        target_agent_id: Option<Uuid>,
        #[serde(default)]
        limit: Option<u32>,
    }
    let body: Body = super::parse_body(payload, "agent.assignment.list payload is invalid")?;
    let limit = body.limit.unwrap_or(crate::config::MAX_EVENT_PAGE_ROWS);
    if limit == 0 || limit > forge_control::MAX_ASSIGNMENT_LIST_RESULTS {
        return Err(ForgeError::invalid_input(
            "the assignment list limit is out of range",
        ));
    }
    Ok(Command::AgentAssignmentList {
        request_id,
        request: Box::new(forge_control::AgentAssignmentListRequest {
            scope: decode_scope(&body.scope)?,
            activity_id: ActivityId::from_uuid(body.activity_id),
            target_agent_id: body.target_agent_id.map(AgentInstanceId::from_uuid),
            limit,
            authority: forge_control::AgentAssignmentReadAuthority {
                session_id: AgentSessionId::from_uuid(body.session_id),
                agent_id: AgentInstanceId::from_uuid(body.agent_id),
                expected_agent_revision: forge_domain::AgentInstanceRevision::new(
                    body.expected_agent_revision,
                )
                .map_err(|_| ForgeError::invalid_input("the agent revision is invalid"))?,
                principal: decode_principal(&body.principal)?,
            },
        }),
    })
}

pub(super) fn execute_agent_assignment_list(
    client: &ForgeControlClient,
    request: forge_control::AgentAssignmentListRequest,
) -> Result<Value, ForgeError> {
    let entries = client
        .agent_assignment_list(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    let assignments = entries
        .iter()
        .map(assignment_summary_json)
        .collect::<Vec<_>>();
    Ok(json!({
        "assignments": assignments,
        "assignment_count": assignments.len(),
    }))
}
