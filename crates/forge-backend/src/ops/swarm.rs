//! Closed wire parsers, readback hints, and `ForgeControlClient` dispatch for
//! Swarm workspace isolation, capture, convergence, materialization, settlement,
//! and purge commands.

use forge_control::{
    ForgeControlClient, SwarmConvergeRequest, SwarmConvergenceCandidate,
    SwarmMaterializeHybridRequest, SwarmMemberCaptureRequest, SwarmPurgeRequest,
    SwarmSettleRequest, SwarmSettlementGetRequest, SwarmWorkspaceGetRequest,
    SwarmWorkspaceProvisionRequest,
};
use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, DagNodeId, GoalId, SwarmMemberId, SwarmRunId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::{
    CommandOp, ScopeDto, SessionActorDto, decode_dag_revision, decode_goal_revision, decode_hex,
    decode_principal, decode_scope, decode_timestamp, forge_error_of_client, parse_body,
};
use crate::error::{ForgeError, ReadbackHint};

pub mod wire;
pub use wire::{
    SettlementJournalStateWire, SwarmConvergenceOutcomeWire, SwarmMemberOutputWire, SwarmPurgeWire,
    SwarmSettleWire, SwarmSettledOutboxEntryWire, SwarmSettlementGetWire,
    SwarmSettlementReceiptWire, SwarmTargetWire, SwarmWorkspaceGetWire, SwarmWorkspaceModeWire,
    SwarmWorkspaceReceiptWire,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmCommand {
    WorkspaceProvision(SwarmWorkspaceProvisionRequest),
    WorkspaceGet(SwarmWorkspaceGetRequest),
    MemberCapture(SwarmMemberCaptureRequest),
    Converge(SwarmConvergeRequest),
    Settle(SwarmSettleRequest),
    MaterializeHybrid(SwarmMaterializeHybridRequest),
    SettlementGet(SwarmSettlementGetRequest),
    Purge(SwarmPurgeRequest),
}

impl SwarmCommand {
    pub const fn op(&self) -> CommandOp {
        match self {
            Self::WorkspaceProvision(_) => CommandOp::SwarmWorkspaceProvision,
            Self::WorkspaceGet(_) => CommandOp::SwarmWorkspaceGet,
            Self::MemberCapture(_) => CommandOp::SwarmMemberCapture,
            Self::Converge(_) => CommandOp::SwarmConverge,
            Self::Settle(_) => CommandOp::SwarmSettle,
            Self::MaterializeHybrid(_) => CommandOp::SwarmMaterializeHybrid,
            Self::SettlementGet(_) => CommandOp::SwarmSettlementGet,
            Self::Purge(_) => CommandOp::SwarmPurge,
        }
    }
}

pub(super) fn readback_hint(command: &SwarmCommand) -> Option<ReadbackHint> {
    match command {
        SwarmCommand::WorkspaceProvision(request) => Some(ReadbackHint::SwarmWorkspace {
            workspace_id: request.scope.workspace_id().into_uuid(),
            swarm_run_id: request.swarm_run_id.into_uuid(),
            member_id: request.member_id.into_uuid(),
        }),
        SwarmCommand::MemberCapture(request) => Some(ReadbackHint::SwarmWorkspace {
            workspace_id: request.scope.workspace_id().into_uuid(),
            swarm_run_id: request.swarm_run_id.into_uuid(),
            member_id: request.member_id.into_uuid(),
        }),
        SwarmCommand::Settle(request) => Some(ReadbackHint::SwarmSettlement {
            workspace_id: request.scope.workspace_id().into_uuid(),
            swarm_run_id: request.swarm_run_id.into_uuid(),
            settlement_id: request.settlement_id,
        }),
        SwarmCommand::MaterializeHybrid(request) => Some(ReadbackHint::SwarmSettlement {
            workspace_id: request.scope.workspace_id().into_uuid(),
            swarm_run_id: request.swarm_run_id.into_uuid(),
            settlement_id: request.settlement_id,
        }),
        SwarmCommand::WorkspaceGet(_)
        | SwarmCommand::Converge(_)
        | SwarmCommand::SettlementGet(_)
        | SwarmCommand::Purge(_) => None,
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SwarmConvergenceCandidateDto {
    pub member_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_output_commit_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_diff_digest: Option<String>,
}

pub(super) fn parse(op: CommandOp, payload: &Value) -> Result<SwarmCommand, ForgeError> {
    match op {
        CommandOp::SwarmWorkspaceProvision => parse_workspace_provision(payload),
        CommandOp::SwarmWorkspaceGet => parse_workspace_get(payload),
        CommandOp::SwarmMemberCapture => parse_member_capture(payload),
        CommandOp::SwarmConverge => parse_converge(payload),
        CommandOp::SwarmSettle => parse_settle(payload),
        CommandOp::SwarmMaterializeHybrid => parse_materialize_hybrid(payload),
        CommandOp::SwarmSettlementGet => parse_settlement_get(payload),
        CommandOp::SwarmPurge => parse_purge(payload),
        _ => Err(ForgeError::invalid_input("unsupported swarm operation")),
    }
}

pub(super) fn execute(
    client: &ForgeControlClient,
    command: &SwarmCommand,
) -> Result<Value, ForgeError> {
    match command {
        SwarmCommand::WorkspaceProvision(request) => {
            let receipt = client
                .swarm_workspace_provision(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmWorkspaceReceiptWire::from_domain(&receipt))
        }
        SwarmCommand::WorkspaceGet(request) => {
            let receipt = client
                .swarm_workspace_get(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmWorkspaceGetWire {
                workspace_id: request.scope.workspace_id().into_uuid(),
                swarm_run_id: request.swarm_run_id.into_uuid(),
                member_id: request.member_id.into_uuid(),
                found: receipt.is_some(),
                receipt: receipt.as_ref().map(SwarmWorkspaceReceiptWire::from_domain),
            })
        }
        SwarmCommand::MemberCapture(request) => {
            let receipt = client
                .swarm_member_capture(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmMemberOutputWire::from_domain(&receipt))
        }
        SwarmCommand::Converge(request) => {
            let outcome = client
                .swarm_converge(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmConvergenceOutcomeWire::from_domain(
                request.swarm_run_id.into_uuid(),
                &outcome,
            ))
        }
        SwarmCommand::Settle(request) => {
            let outcome = client
                .swarm_settle(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmSettleWire::from_domain(&outcome))
        }
        SwarmCommand::MaterializeHybrid(request) => {
            let receipt = client
                .swarm_materialize_hybrid(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmSettlementReceiptWire::from_domain(&receipt))
        }
        SwarmCommand::SettlementGet(request) => {
            let view = client
                .swarm_settlement_get(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmSettlementGetWire::from_domain(
                request.scope.workspace_id().into_uuid(),
                request.swarm_run_id.into_uuid(),
                &view,
            ))
        }
        SwarmCommand::Purge(request) => {
            client
                .swarm_purge(request.clone())
                .map_err(|error| forge_error_of_client(&error))?;
            serialize_wire(&SwarmPurgeWire {
                workspace_id: request.scope.workspace_id().into_uuid(),
                swarm_run_id: request.swarm_run_id.into_uuid(),
                purged: true,
            })
        }
    }
}

fn parse_workspace_provision(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        actor: SessionActorDto,
        swarm_run_id: Uuid,
        member_id: Uuid,
        mode: SwarmWorkspaceModeWire,
        target: SwarmTargetWire,
        #[serde(default)]
        candidate_commit_oid: Option<String>,
        observed_at_ms: i64,
    }
    let body: Body = parse_body(payload, "swarm.workspace_provision payload is invalid")?;
    ensure_actor_matches_scope(&body.actor, &body.scope)?;
    Ok(SwarmCommand::WorkspaceProvision(
        SwarmWorkspaceProvisionRequest {
            scope: decode_scope(&body.scope)?,
            session_id: AgentSessionId::from_uuid(body.actor.session_id),
            principal: decode_principal(&body.actor.principal)?,
            swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
            member_id: SwarmMemberId::from_uuid(body.member_id),
            mode: body.mode.into_domain(),
            target: body.target.into_domain()?,
            candidate_commit_oid: body.candidate_commit_oid,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        },
    ))
}

fn parse_workspace_get(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        swarm_run_id: Uuid,
        member_id: Uuid,
    }
    let body: Body = parse_body(payload, "swarm.workspace_get payload is invalid")?;
    Ok(SwarmCommand::WorkspaceGet(SwarmWorkspaceGetRequest {
        scope: decode_scope(&body.scope)?,
        swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
        member_id: SwarmMemberId::from_uuid(body.member_id),
    }))
}

fn parse_member_capture(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        actor: SessionActorDto,
        swarm_run_id: Uuid,
        member_id: Uuid,
        captured_at_ms: i64,
    }
    let body: Body = parse_body(payload, "swarm.member_capture payload is invalid")?;
    ensure_actor_matches_scope(&body.actor, &body.scope)?;
    Ok(SwarmCommand::MemberCapture(SwarmMemberCaptureRequest {
        scope: decode_scope(&body.scope)?,
        session_id: AgentSessionId::from_uuid(body.actor.session_id),
        principal: decode_principal(&body.actor.principal)?,
        swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
        member_id: SwarmMemberId::from_uuid(body.member_id),
        captured_at: decode_timestamp(body.captured_at_ms)?,
    }))
}

fn parse_converge(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        actor: SessionActorDto,
        swarm_run_id: Uuid,
        candidates: Vec<SwarmConvergenceCandidateDto>,
        observed_at_ms: i64,
    }
    let body: Body = parse_body(payload, "swarm.converge payload is invalid")?;
    ensure_actor_matches_scope(&body.actor, &body.scope)?;
    if body.candidates.len() > forge_control::MAX_SWARM_CONVERGENCE_CANDIDATES {
        return Err(ForgeError::invalid_input(
            "swarm convergence candidate list exceeds bound",
        ));
    }
    let candidates = body
        .candidates
        .into_iter()
        .map(|candidate| {
            Ok(SwarmConvergenceCandidate {
                member_id: SwarmMemberId::from_uuid(candidate.member_id),
                expected_output_commit_oid: candidate.expected_output_commit_oid,
                expected_diff_digest: decode_optional_digest_32(
                    candidate.expected_diff_digest.as_deref(),
                    "expected_diff_digest",
                )?,
            })
        })
        .collect::<Result<Vec<_>, ForgeError>>()?;
    Ok(SwarmCommand::Converge(SwarmConvergeRequest {
        scope: decode_scope(&body.scope)?,
        session_id: AgentSessionId::from_uuid(body.actor.session_id),
        principal: decode_principal(&body.actor.principal)?,
        swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
        candidates,
        observed_at: decode_timestamp(body.observed_at_ms)?,
    }))
}

fn parse_settle(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        #[serde(default)]
        activity_id: Option<Uuid>,
        actor: SessionActorDto,
        coordinator_agent_id: Uuid,
        swarm_run_id: Uuid,
        settlement_id: Uuid,
        converged_commit_oid: String,
        #[serde(default)]
        expected_diff_digest: Option<String>,
        settled_at_ms: i64,
    }
    let body: Body = parse_body(payload, "swarm.settle payload is invalid")?;
    ensure_actor_matches_scope(&body.actor, &body.scope)?;
    Ok(SwarmCommand::Settle(SwarmSettleRequest {
        scope: decode_scope(&body.scope)?,
        activity_id: body.activity_id.map(ActivityId::from_uuid),
        session_id: AgentSessionId::from_uuid(body.actor.session_id),
        principal: decode_principal(&body.actor.principal)?,
        coordinator_agent_id: AgentInstanceId::from_uuid(body.coordinator_agent_id),
        swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
        settlement_id: body.settlement_id,
        converged_commit_oid: body.converged_commit_oid,
        expected_diff_digest: decode_optional_digest_32(
            body.expected_diff_digest.as_deref(),
            "expected_diff_digest",
        )?,
        settled_at: decode_timestamp(body.settled_at_ms)?,
    }))
}

fn parse_materialize_hybrid(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        actor: SessionActorDto,
        swarm_run_id: Uuid,
        settlement_id: Uuid,
        goal_id: Uuid,
        expected_goal_revision: i64,
        expected_dag_revision: i64,
        node_id: Uuid,
        converged_commit_oid: String,
        #[serde(default)]
        expected_diff_digest: Option<String>,
        settled_at_ms: i64,
    }
    let body: Body = parse_body(payload, "swarm.materialize_hybrid payload is invalid")?;
    ensure_actor_matches_scope(&body.actor, &body.scope)?;
    Ok(SwarmCommand::MaterializeHybrid(
        SwarmMaterializeHybridRequest {
            scope: decode_scope(&body.scope)?,
            activity_id: ActivityId::from_uuid(body.activity_id),
            session_id: AgentSessionId::from_uuid(body.actor.session_id),
            principal: decode_principal(&body.actor.principal)?,
            swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
            settlement_id: body.settlement_id,
            goal_id: GoalId::from_uuid(body.goal_id),
            expected_goal_revision: decode_goal_revision(body.expected_goal_revision)?,
            expected_dag_revision: decode_dag_revision(body.expected_dag_revision)?,
            node_id: DagNodeId::from_uuid(body.node_id),
            converged_commit_oid: body.converged_commit_oid,
            expected_diff_digest: decode_optional_digest_32(
                body.expected_diff_digest.as_deref(),
                "expected_diff_digest",
            )?,
            settled_at: decode_timestamp(body.settled_at_ms)?,
        },
    ))
}

fn parse_settlement_get(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        swarm_run_id: Uuid,
    }
    let body: Body = parse_body(payload, "swarm.settlement_get payload is invalid")?;
    Ok(SwarmCommand::SettlementGet(SwarmSettlementGetRequest {
        scope: decode_scope(&body.scope)?,
        swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
    }))
}

fn parse_purge(payload: &Value) -> Result<SwarmCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        actor: SessionActorDto,
        swarm_run_id: Uuid,
    }
    let body: Body = parse_body(payload, "swarm.purge payload is invalid")?;
    ensure_actor_matches_scope(&body.actor, &body.scope)?;
    Ok(SwarmCommand::Purge(SwarmPurgeRequest {
        scope: decode_scope(&body.scope)?,
        session_id: AgentSessionId::from_uuid(body.actor.session_id),
        principal: decode_principal(&body.actor.principal)?,
        swarm_run_id: SwarmRunId::from_uuid(body.swarm_run_id),
    }))
}

fn ensure_actor_matches_scope(actor: &SessionActorDto, scope: &ScopeDto) -> Result<(), ForgeError> {
    if actor.workspace_id != scope.workspace_id {
        return Err(ForgeError::invalid_input(
            "actor Workspace does not match command scope",
        ));
    }
    Ok(())
}

fn decode_optional_digest_32(
    hex_value: Option<&str>,
    field: &'static str,
) -> Result<Option<[u8; 32]>, ForgeError> {
    let Some(hex_str) = hex_value else {
        return Ok(None);
    };
    let bytes = decode_hex(hex_str)?;
    let Ok(digest) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return Err(ForgeError::invalid_input(format!(
            "{field} must be 64 hex characters"
        )));
    };
    Ok(Some(digest))
}

fn serialize_wire<T: Serialize>(value: &T) -> Result<Value, ForgeError> {
    serde_json::to_value(value).map_err(|_| ForgeError::internal())
}
