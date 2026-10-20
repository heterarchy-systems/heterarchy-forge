//! Agent participation and coordination observability ops: successor
//! relations, coordinator binding, coordination view, inbox, and the bounded
//! Agent list/context projections. Each op forwards one parsed payload to
//! exactly one forge-control capability. Mutations that resolve durable
//! sessions (successor create, coordinator claim, inbox) are session-bound;
//! pure projections are issuer-only.

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use forge_control::{ForgeControlClient, ResolvedWorkspaceScope};
use forge_domain::{
    ActivityId, ActivityRevision, AgentInboxListLimit, AgentInstanceId, AgentListLimit,
    AgentSessionId, RuntimeInstanceId, TimestampMillis, WorkspaceRevision,
};

use crate::error::ForgeError;

use super::{
    Command, ParseResult, PrincipalDto, ScopeDto, decode_principal, decode_scope, decode_timestamp,
};

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    decode_timestamp(i64::try_from(millis).unwrap_or(0))
}

fn agent_summary(agent: &forge_domain::RegisteredAgentInstance) -> Value {
    json!({
        "agent_id": agent.id().into_uuid(),
        "workspace_id": agent.workspace_id().into_uuid(),
        "activity_id": agent.activity_id().into_uuid(),
        "display_name": agent.display_name().as_str(),
        "attachment_state": format!("{:?}", agent.attachment_state()).to_ascii_lowercase(),
        "revision": agent.revision().get(),
    })
}

fn activity_summary(activity: &forge_domain::RegisteredActivity) -> Value {
    json!({
        "activity_id": activity.id().into_uuid(),
        "workspace_id": activity.workspace_id().into_uuid(),
        "state": format!("{:?}", activity.state()).to_ascii_lowercase(),
        "revision": activity.revision().get(),
        "created_at_ms": activity.created_at().get(),
        "updated_at_ms": activity.updated_at().get(),
    })
}

pub(super) fn parse_activity_successor_create(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        expected_workspace_revision: i64,
        predecessor_activity_id: Uuid,
        predecessor_activity_revision: i64,
        successor_activity_id: Uuid,
        initiating_session_id: Uuid,
        runtime_instance_id: Uuid,
        principal: PrincipalDto,
        observed_at_ms: i64,
    }
    let body: Body = super::parse_body(payload, "activity.successor_create payload is invalid")?;
    let expected_workspace_revision = WorkspaceRevision::new(body.expected_workspace_revision)
        .map_err(|_| ForgeError::invalid_input("workspace revision is invalid"))?;
    let predecessor_activity_revision =
        ActivityRevision::new(body.predecessor_activity_revision)
            .map_err(|_| ForgeError::invalid_input("predecessor activity revision is invalid"))?;
    Ok(Command::ActivitySuccessorCreate {
        request_id,
        scope: decode_scope(&body.scope)?,
        command: Box::new(
            forge_domain::CreateActivitySuccessor::new(
                forge_domain::WorkspaceId::from_uuid(body.scope.workspace_id),
                expected_workspace_revision,
                ActivityId::from_uuid(body.predecessor_activity_id),
                predecessor_activity_revision,
                ActivityId::from_uuid(body.successor_activity_id),
                AgentSessionId::from_uuid(body.initiating_session_id),
                RuntimeInstanceId::from_uuid(body.runtime_instance_id),
                decode_timestamp(body.observed_at_ms)?,
            )
            .map_err(|_| ForgeError::invalid_input("the successor command is invalid"))?,
        ),
        principal: decode_principal(&body.principal)?,
    })
}

pub(super) fn execute_activity_successor_create(
    client: &ForgeControlClient,
    request: forge_control::ActivitySuccessorCreateRequest,
) -> Result<Value, ForgeError> {
    let result = client
        .activity_successor_create(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    let relation = result.relation();
    Ok(json!({
        "created": result.created(),
        "relation": {
            "workspace_id": relation.workspace_id().into_uuid(),
            "predecessor_activity_id": relation.predecessor_activity_id().into_uuid(),
            "predecessor_activity_revision": relation.predecessor_activity_revision().get(),
            "successor_activity_id": relation.successor_activity_id().into_uuid(),
            "initiating_session_id": relation.initiating_session_id().into_uuid(),
            "created_at_ms": relation.created_at().get(),
        },
        "successor": activity_summary(result.successor()),
    }))
}

pub(super) fn parse_activity_successor_get(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        predecessor_activity_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "activity.successor_get payload is invalid")?;
    Ok(Command::ActivitySuccessorGet {
        request_id,
        scope: decode_scope(&body.scope)?,
        predecessor_activity_id: ActivityId::from_uuid(body.predecessor_activity_id),
    })
}

pub(super) fn execute_activity_successor_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    predecessor_activity_id: ActivityId,
) -> Result<Value, ForgeError> {
    let found = client
        .activity_successor_get(scope.clone(), predecessor_activity_id)
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some((relation, successor)) = found else {
        return Ok(json!({ "found": false }));
    };
    Ok(json!({
        "found": true,
        "relation": {
            "workspace_id": relation.workspace_id().into_uuid(),
            "predecessor_activity_id": relation.predecessor_activity_id().into_uuid(),
            "predecessor_activity_revision": relation.predecessor_activity_revision().get(),
            "successor_activity_id": relation.successor_activity_id().into_uuid(),
            "initiating_session_id": relation.initiating_session_id().into_uuid(),
            "created_at_ms": relation.created_at().get(),
        },
        "successor": activity_summary(&successor),
    }))
}

pub(super) fn parse_activity_coordinator_get(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "activity.coordinator_get payload is invalid")?;
    Ok(Command::ActivityCoordinatorGet {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
    })
}

pub(super) fn execute_activity_coordinator_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
) -> Result<Value, ForgeError> {
    let found = client
        .activity_coordinator_get(forge_control::CoordinatorGetRequest {
            scope: scope.clone(),
            activity_id,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some(binding) = found else {
        return Ok(json!({ "found": false }));
    };
    Ok(json!({
        "found": true,
        "coordinator": coordinator_json(&binding),
    }))
}

pub(super) fn parse_activity_coordinator_actor_get(
    request_id: Uuid,
    payload: &Value,
) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        principal: PrincipalDto,
    }
    let body: Body =
        super::parse_body(payload, "activity.coordinator_actor_get payload is invalid")?;
    if body.activity_id.is_nil() {
        return Err(ForgeError::invalid_input("activity id must not be nil"));
    }
    Ok(Command::ActivityCoordinatorActorGet {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
        principal: decode_principal(&body.principal)?,
    })
}

pub(super) fn execute_activity_coordinator_actor_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    principal: forge_domain::AuthenticatedPrincipal,
) -> Result<Value, ForgeError> {
    let actor = client
        .activity_coordinator_actor(forge_control::CoordinatorActorRequest {
            scope: scope.clone(),
            activity_id,
            principal,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some(actor) = actor else {
        return Ok(json!({ "found": false }));
    };
    Ok(json!({
        "found": true,
        "actor": {
            "workspace_id": actor.workspace_id().into_uuid(),
            "activity_id": actor.activity_id().into_uuid(),
            "agent_id": actor.agent_id().into_uuid(),
            "expected_coordinator_revision": actor.expected_revision().get(),
            "principal": super::goals::principal_json(actor.principal()),
            "session_id": actor.session_id().into_uuid(),
        },
    }))
}

fn coordinator_json(binding: &forge_domain::ActivityCoordinatorBinding) -> Value {
    json!({
        "workspace_id": binding.workspace_id().into_uuid(),
        "activity_id": binding.activity_id().into_uuid(),
        "agent_id": binding.agent_id().into_uuid(),
        "revision": binding.revision().get(),
        "updated_at_ms": binding.updated_at().get(),
    })
}

pub(super) fn parse_activity_coordinator_claim_payload(
    payload: &Value,
) -> Result<forge_control::CoordinatorClaimRequest, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        session_id: Uuid,
        agent_id: Uuid,
        principal: PrincipalDto,
        observed_at_ms: i64,
    }
    let body: Body = super::parse_body(payload, "activity.coordinator_claim payload is invalid")?;
    Ok(forge_control::CoordinatorClaimRequest {
        session_id: AgentSessionId::from_uuid(body.session_id),
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
        agent_id: AgentInstanceId::from_uuid(body.agent_id),
        principal: decode_principal(&body.principal)?,
        observed_at: decode_timestamp(body.observed_at_ms)?,
    })
}

pub(super) fn execute_activity_coordinator_claim(
    client: &ForgeControlClient,
    request: forge_control::CoordinatorClaimRequest,
) -> Result<Value, ForgeError> {
    let binding = client
        .activity_coordinator_claim(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "coordinator": coordinator_json(&binding),
    }))
}

pub(super) fn parse_agent_list(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "agent.list payload is invalid")?;
    Ok(Command::AgentList {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
    })
}

pub(super) fn execute_agent_list(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
) -> Result<Value, ForgeError> {
    let entries = client
        .agent_list(forge_control::AgentListRequest {
            scope: scope.clone(),
            activity_id: Some(activity_id),
            now: current_timestamp_millis()?,
            limit: AgentListLimit::DEFAULT,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let agents = entries
        .iter()
        .map(|entry| {
            let agent = entry.agent();
            json!({
                "agent_id": agent.id().into_uuid(),
                "display_name": agent.display_name().as_str(),
                "attachment_state": format!("{:?}", agent.attachment_state()).to_ascii_lowercase(),
                "activity_revision": entry.activity().activity().revision().get(),
                "activity_liveness": format!("{:?}", entry.activity().liveness()).to_ascii_lowercase(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "agents": agents,
        "agent_count": agents.len(),
    }))
}

pub(super) fn parse_agent_get_context(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        agent_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "agent.get_context payload is invalid")?;
    Ok(Command::AgentGetContext {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
        agent_id: AgentInstanceId::from_uuid(body.agent_id),
    })
}

pub(super) fn execute_agent_get_context(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
) -> Result<Value, ForgeError> {
    let found = client
        .agent_get_context(forge_control::AgentContextRequest {
            scope: scope.clone(),
            activity_id,
            agent_id,
            now: current_timestamp_millis()?,
            focus_event_limit: AgentListLimit::DEFAULT,
            work_update_limit: AgentListLimit::DEFAULT,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some(context) = found else {
        return Ok(json!({ "found": false }));
    };
    let attachment = context.attachment();
    let work_updates = context
        .work_updates()
        .iter()
        .map(|update| {
            json!({
                "update_id": update.id().into_uuid(),
                "sequence": update.sequence().get(),
                "phase": format!("{:?}", update.phase()).to_ascii_lowercase(),
                "summary": update.summary().as_str(),
                "observed_at_ms": update.observed_at().get(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "found": true,
        "agent": agent_summary(attachment.agent()),
        "activity_revision": attachment.activity().activity().revision().get(),
        "activity_liveness": format!("{:?}", attachment.activity().liveness()).to_ascii_lowercase(),
        "work_updates": work_updates,
        "work_update_count": work_updates.len(),
        "focus_event_count": context.focus_events().len(),
    }))
}

pub(super) fn parse_agent_coordination_get(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "agent.coordination_get payload is invalid")?;
    Ok(Command::AgentCoordinationGet {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
    })
}

pub(super) fn execute_agent_coordination_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
) -> Result<Value, ForgeError> {
    let view = client
        .agent_coordination_view(forge_control::AgentCoordinationQuery {
            scope: scope.clone(),
            activity_id,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let coordinator = view.presence.coordinator();
    let counts = view.presence.counts();
    let participants = view
        .presence
        .participants()
        .iter()
        .map(|participant| {
            json!({
                "agent_id": participant.agent_id().into_uuid(),
                "session_id": participant.session_id().map(forge_domain::AgentSessionId::into_uuid),
            })
        })
        .collect::<Vec<_>>();
    let events = view.events.iter().map(agent_event_json).collect::<Vec<_>>();
    Ok(json!({
        "activity_id": view.activity_id.into_uuid(),
        "coordinator": {
            "agent_id": coordinator.agent_id().map(forge_domain::AgentInstanceId::into_uuid),
            "session_id": coordinator.session_id().map(forge_domain::AgentSessionId::into_uuid),
            "revision": coordinator.revision().map(forge_domain::ActivityCoordinatorRevision::get),
        },
        "counts": {
            "current_coordinator": counts.current_coordinator(),
            "attached_participants": counts.attached_participants(),
            "closed_activity": counts.closed_activity(),
            "handed_off": counts.handed_off(),
            "detached": counts.detached(),
            "unresolved_legacy": counts.unresolved_legacy(),
        },
        "participants": participants,
        "events": events,
        "event_count": events.len(),
    }))
}

fn agent_event_json(event: &forge_domain::AgentEvent) -> Value {
    json!({
        "event_id": event.id().into_uuid(),
        "kind": format!("{:?}", event.kind()).to_ascii_lowercase(),
        "membership_revision": event.membership_revision().get(),
    })
}

pub(super) fn parse_agent_inbox_list_payload(
    payload: &Value,
) -> Result<forge_control::AgentInboxListRequest, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        agent_id: Uuid,
        session_id: Uuid,
        principal: PrincipalDto,
    }
    let body: Body = super::parse_body(payload, "agent.inbox_list payload is invalid")?;
    Ok(forge_control::AgentInboxListRequest {
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
        agent_id: AgentInstanceId::from_uuid(body.agent_id),
        session_id: AgentSessionId::from_uuid(body.session_id),
        principal: decode_principal(&body.principal)?,
        limit: AgentInboxListLimit::DEFAULT,
    })
}

pub(super) fn execute_agent_inbox_list(
    client: &ForgeControlClient,
    request: forge_control::AgentInboxListRequest,
) -> Result<Value, ForgeError> {
    let entries = client
        .agent_inbox_list(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    let inbox = entries
        .iter()
        .map(|entry| agent_event_json(entry.event()))
        .collect::<Vec<_>>();
    Ok(json!({
        "inbox": inbox,
        "entry_count": inbox.len(),
    }))
}

fn parse_focus(
    goal_id: Option<Uuid>,
    goal_revision: Option<i64>,
    dag_revision: Option<i64>,
    node_id: Option<Uuid>,
    node_revision: Option<i64>,
) -> Result<forge_domain::AgentFocus, ForgeError> {
    use forge_domain::{
        AgentFocus, AgentFocusNode, DagNodeRevision, DagRevisionNumber, GoalAttribution,
        GoalRevision,
    };
    let invalid = || ForgeError::invalid_input("the agent focus tuple is invalid");
    let goal = match (goal_id, goal_revision) {
        (Some(goal_id), Some(goal_revision)) => Some(GoalAttribution::new(
            forge_domain::GoalId::from_uuid(goal_id),
            GoalRevision::new(goal_revision).map_err(|_| invalid())?,
        )),
        (None, None) => None,
        _ => return Err(invalid()),
    };
    let dag_revision = dag_revision
        .map(DagRevisionNumber::new)
        .transpose()
        .map_err(|_| invalid())?;
    let node = match (node_id, node_revision) {
        (Some(node_id), Some(node_revision)) => Some(AgentFocusNode::new(
            forge_domain::DagNodeId::from_uuid(node_id),
            DagNodeRevision::new(node_revision).map_err(|_| invalid())?,
        )),
        (None, None) => None,
        _ => return Err(invalid()),
    };
    AgentFocus::new(goal, dag_revision, node).map_err(|_| invalid())
}

pub(super) fn parse_agent_set_focus(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        coordinator_session_id: Uuid,
        coordinator_agent_id: Uuid,
        expected_coordinator_revision: i64,
        principal: PrincipalDto,
        agent_id: Uuid,
        expected_agent_revision: i64,
        goal_id: Option<Uuid>,
        goal_revision: Option<i64>,
        dag_revision: Option<i64>,
        node_id: Option<Uuid>,
        node_revision: Option<i64>,
        observed_at_ms: i64,
    }
    let body: Body = super::parse_body(payload, "agent.set_focus payload is invalid")?;
    let invalid = || ForgeError::invalid_input("an agent focus revision is invalid");
    let actor = forge_domain::ActivityCoordinatorActor::new(
        forge_domain::WorkspaceId::from_uuid(body.scope.workspace_id),
        ActivityId::from_uuid(body.activity_id),
        AgentInstanceId::from_uuid(body.coordinator_agent_id),
        forge_domain::ActivityCoordinatorRevision::new(body.expected_coordinator_revision)
            .map_err(|_| invalid())?,
        decode_principal(&body.principal)?,
        AgentSessionId::from_uuid(body.coordinator_session_id),
    );
    Ok(Command::AgentSetFocus {
        request_id,
        request: Box::new(forge_control::AgentFocusRequest {
            scope: decode_scope(&body.scope)?,
            activity_id: ActivityId::from_uuid(body.activity_id),
            actor,
            agent_id: AgentInstanceId::from_uuid(body.agent_id),
            expected_revision: forge_domain::AgentInstanceRevision::new(
                body.expected_agent_revision,
            )
            .map_err(|_| invalid())?,
            focus: parse_focus(
                body.goal_id,
                body.goal_revision,
                body.dag_revision,
                body.node_id,
                body.node_revision,
            )?,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        }),
    })
}

pub(super) fn execute_agent_set_focus(
    client: &ForgeControlClient,
    request: forge_control::AgentFocusRequest,
) -> Result<Value, ForgeError> {
    let agent = client
        .agent_set_focus(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    let focus = agent.focus();
    Ok(json!({
        "agent": agent_summary(&agent),
        "session_id": agent.session_id().map(forge_domain::AgentSessionId::into_uuid),
        "focus": {
            "goal_id": focus.goal().map(|goal| goal.goal_id().into_uuid()),
            "goal_revision": focus.goal().map(|goal| goal.expected_revision().get()),
            "dag_revision": focus.dag_revision().map(forge_domain::DagRevisionNumber::get),
            "node_id": focus.node().map(|node| node.node_id().into_uuid()),
            "node_revision": focus.node().map(|node| node.expected_revision().get()),
        },
    }))
}

fn parse_work_phase(value: &str) -> Result<forge_domain::AgentWorkPhase, ForgeError> {
    let phase = match value {
        "planning" => forge_domain::AgentWorkPhase::Planning,
        "executing" => forge_domain::AgentWorkPhase::Executing,
        "waiting" => forge_domain::AgentWorkPhase::Waiting,
        "verifying" => forge_domain::AgentWorkPhase::Verifying,
        "completed" => forge_domain::AgentWorkPhase::Completed,
        "blocked" => forge_domain::AgentWorkPhase::Blocked,
        "failed" => forge_domain::AgentWorkPhase::Failed,
        _ => {
            return Err(ForgeError::invalid_input(
                "the work phase is not a known phase",
            ));
        }
    };
    Ok(phase)
}

fn parse_evidence_ref(kind: &str, id: Uuid) -> Result<forge_domain::GoalEvidenceRef, ForgeError> {
    let reference = match kind {
        "change_set" => {
            forge_domain::GoalEvidenceRef::ChangeSet(forge_domain::ChangeSetId::from_uuid(id))
        }
        "execution" => {
            forge_domain::GoalEvidenceRef::Execution(forge_domain::ExecutionId::from_uuid(id))
        }
        "approval" => {
            forge_domain::GoalEvidenceRef::Approval(forge_domain::ApprovalRequestId::from_uuid(id))
        }
        "checkpoint" => {
            forge_domain::GoalEvidenceRef::Checkpoint(forge_domain::CheckpointId::from_uuid(id))
        }
        _ => {
            return Err(ForgeError::invalid_input(
                "the evidence reference kind is not known",
            ));
        }
    };
    Ok(reference)
}

pub(super) fn parse_agent_publish_work(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvidenceRefDto {
        kind: String,
        id: Uuid,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        session_id: Uuid,
        principal: PrincipalDto,
        agent_id: Uuid,
        update_id: Uuid,
        sequence: i64,
        phase: String,
        summary: String,
        evidence_refs: Vec<EvidenceRefDto>,
        observed_at_ms: i64,
    }
    let body: Body = super::parse_body(payload, "agent.publish_work payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let evidence_refs = body
        .evidence_refs
        .iter()
        .map(|reference| parse_evidence_ref(reference.kind.as_str(), reference.id))
        .collect::<Result<Vec<_>, _>>()?;
    let update = forge_domain::AgentWorkUpdate::new(
        forge_domain::AgentWorkUpdateId::from_uuid(body.update_id),
        AgentInstanceId::from_uuid(body.agent_id),
        forge_domain::WorkspaceId::from_uuid(body.scope.workspace_id),
        ActivityId::from_uuid(body.activity_id),
        forge_domain::AgentWorkUpdateSequence::new(body.sequence)
            .map_err(|_| ForgeError::invalid_input("the work update sequence is invalid"))?,
        parse_work_phase(body.phase.as_str())?,
        forge_domain::AgentWorkSummary::new(body.summary)
            .map_err(|_| ForgeError::invalid_input("the work summary must not be empty"))?,
        evidence_refs,
        decode_timestamp(body.observed_at_ms)?,
    )
    .map_err(|_| ForgeError::invalid_input("the work update is invalid"))?;
    Ok(Command::AgentPublishWork {
        request_id,
        request: Box::new(forge_control::AgentWorkUpdateRequest {
            session_id: AgentSessionId::from_uuid(body.session_id),
            scope,
            activity_id: ActivityId::from_uuid(body.activity_id),
            principal: decode_principal(&body.principal)?,
            update,
        }),
    })
}

pub(super) fn execute_agent_publish_work(
    client: &ForgeControlClient,
    request: forge_control::AgentWorkUpdateRequest,
) -> Result<Value, ForgeError> {
    let update = client
        .agent_publish_work_update(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "update_id": update.id().into_uuid(),
        "agent_id": update.agent_id().into_uuid(),
        "sequence": update.sequence().get(),
        "phase": format!("{:?}", update.phase()).to_ascii_lowercase(),
        "summary": update.summary().as_str(),
        "evidence_ref_count": update.evidence_refs().len(),
        "observed_at_ms": update.observed_at().get(),
    }))
}
