//! HTTP adapter for the bounded, attested leadership Work Cut operations.
//!
//! The adapter decodes checked domain envelopes, validates the configured
//! service echo, forwards to the Control owner, and projects durable inventory,
//! cut, and drain observations. It never authenticates a grant from its UUID,
//! mints custody, releases leases, or falls back to a local provider.

use forge_control::{
    ResolvedWorkspaceScope, WorkCutCommand as ControlWorkCutCommand,
    WorkCutOperation as ControlWorkCutOperation, WorkCutResponse as ControlWorkCutResponse,
    WorkCutService,
};
use forge_domain::{
    ActivityId, AgentAssignmentState, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal,
    DagNodeId, DagNodeStatus, DagRevisionNumber, ForgeBackendId, GoalId, GoalRevision,
    OrchestrationIssuerId, TimestampMillis, WorkCutBinding, WorkCutGrant, WorkCutNodeScope,
    WorkCutParty, WorkCutRequest, WorkCutRequestDigest, WorkCutScope, WorkCutSession, WorkCutSide,
    WorkspaceId,
};
use forge_persistence::{
    WorkCutDrainObservation, WorkCutEffectKind, WorkCutEffectProgress, WorkCutEffectSettlement,
    WorkCutInventory, WorkCutPrepareOutcome, WorkCutRecord, WorkInventoryAgent, WorkInventoryNode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    BridgeClients, CommandOp, PrincipalDto, ScopeDto, decode_principal, decode_scope, parse_body,
};
use crate::error::{ForgeError, ReadbackHint};

const DIGEST_BYTES: usize = 32;

/// One strictly decoded Work Cut HTTP command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCutCommand {
    scope: ResolvedWorkspaceScope,
    service: WorkCutService,
    operation: WorkCutHttpOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkCutHttpOperation {
    Inventory {
        request: WorkCutRequest,
    },
    Prepare {
        request: WorkCutRequest,
        grant: WorkCutGrant,
    },
    Get {
        cut_id: Uuid,
        request_digest: WorkCutRequestDigest,
    },
    Drain {
        cut_id: Uuid,
        request_digest: WorkCutRequestDigest,
        expected_revision: i64,
    },
}

impl WorkCutCommand {
    pub(crate) const fn op(&self) -> CommandOp {
        match &self.operation {
            WorkCutHttpOperation::Inventory { .. } => CommandOp::WorkCutInventory,
            WorkCutHttpOperation::Prepare { .. } => CommandOp::WorkCutPrepare,
            WorkCutHttpOperation::Get { .. } => CommandOp::WorkCutGet,
            WorkCutHttpOperation::Drain { .. } => CommandOp::WorkCutDrain,
        }
    }

    pub(crate) const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub(crate) fn readback_hint(&self) -> Option<ReadbackHint> {
        match &self.operation {
            WorkCutHttpOperation::Prepare { request, .. } => Some(ReadbackHint::WorkCut {
                workspace_id: request.workspace_id().into_uuid(),
                cut_id: request.cut_id(),
                request_digest: super::encode_hex(request.request_digest().as_bytes()),
            }),
            WorkCutHttpOperation::Inventory { .. }
            | WorkCutHttpOperation::Get { .. }
            | WorkCutHttpOperation::Drain { .. } => None,
        }
    }

    fn request_digest(&self) -> WorkCutRequestDigest {
        match &self.operation {
            WorkCutHttpOperation::Inventory { request }
            | WorkCutHttpOperation::Prepare { request, .. } => request.request_digest(),
            WorkCutHttpOperation::Get { request_digest, .. }
            | WorkCutHttpOperation::Drain { request_digest, .. } => *request_digest,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryBody {
    scope: ScopeDto,
    service: ServiceBody,
    request: WorkCutRequestBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareBody {
    scope: ScopeDto,
    service: ServiceBody,
    request: WorkCutRequestBody,
    grant: WorkCutGrantBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
    service: ServiceBody,
    cut_id: Uuid,
    request_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainBody {
    scope: ScopeDto,
    service: ServiceBody,
    cut_id: Uuid,
    request_digest: String,
    expected_revision: i64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceBody {
    backend_id: Uuid,
    issuer: Uuid,
    destination_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkCutRequestBody {
    cut_id: Uuid,
    election_id: Uuid,
    destination_id: Uuid,
    backend_id: Uuid,
    workspace_id: Uuid,
    workspace_revision: i64,
    leadership_revision: i64,
    roster_digest: String,
    parties: PartiesBody,
    sessions: Vec<SessionBody>,
    bindings: Vec<BindingBody>,
    scope: WorkCutScopeBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartiesBody {
    incumbent: PartyBody,
    elected: PartyBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartyBody {
    participation_id: Uuid,
    profile_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionBody {
    side: WorkCutSideBody,
    session_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingBody {
    side: WorkCutSideBody,
    activity_id: Uuid,
    agent_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkCutGrantBody {
    issuer: Uuid,
    request_digest: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WorkCutScopeBody {
    Workspace,
    Team {
        team_id: Uuid,
        nodes: Vec<WorkCutNodeBody>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkCutNodeBody {
    activity_id: Uuid,
    goal_id: Uuid,
    goal_created_at_ms: i64,
    dag_base_goal_revision: i64,
    dag_revision: i64,
    node_id: Uuid,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkCutSideBody {
    Incumbent,
    Elected,
}

pub(super) fn parse(operation: CommandOp, payload: &Value) -> Result<WorkCutCommand, ForgeError> {
    match operation {
        CommandOp::WorkCutInventory => {
            let body: InventoryBody = parse_body(payload, "work_cut.inventory payload is invalid")?;
            let (scope, service) = decode_scope_service(&body.scope, body.service)?;
            Ok(WorkCutCommand {
                scope: scope.clone(),
                service,
                operation: WorkCutHttpOperation::Inventory {
                    request: decode_request(body.request, &scope, service)?,
                },
            })
        }
        CommandOp::WorkCutPrepare => {
            let body: PrepareBody = parse_body(payload, "work_cut.prepare payload is invalid")?;
            let (scope, service) = decode_scope_service(&body.scope, body.service)?;
            let request = decode_request(body.request, &scope, service)?;
            let grant = decode_grant(&body.grant)?;
            if grant.request_digest() != request.request_digest() {
                return Err(ForgeError::invalid_input(
                    "work-cut grant digest does not match request",
                ));
            }
            Ok(WorkCutCommand {
                scope,
                service,
                operation: WorkCutHttpOperation::Prepare { request, grant },
            })
        }
        CommandOp::WorkCutGet => {
            let body: GetBody = parse_body(payload, "work_cut.get payload is invalid")?;
            let (scope, service) = decode_scope_service(&body.scope, body.service)?;
            Ok(WorkCutCommand {
                scope,
                service,
                operation: WorkCutHttpOperation::Get {
                    cut_id: require_non_nil(body.cut_id, "work-cut id")?,
                    request_digest: WorkCutRequestDigest::from_bytes(decode_digest(
                        &body.request_digest,
                    )?),
                },
            })
        }
        CommandOp::WorkCutDrain => {
            let body: DrainBody = parse_body(payload, "work_cut.drain payload is invalid")?;
            let (scope, service) = decode_scope_service(&body.scope, body.service)?;
            if body.expected_revision < 1 {
                return Err(ForgeError::invalid_input(
                    "work-cut drain expected revision must be at least 1",
                ));
            }
            Ok(WorkCutCommand {
                scope,
                service,
                operation: WorkCutHttpOperation::Drain {
                    cut_id: require_non_nil(body.cut_id, "work-cut id")?,
                    request_digest: WorkCutRequestDigest::from_bytes(decode_digest(
                        &body.request_digest,
                    )?),
                    expected_revision: body.expected_revision,
                },
            })
        }
        _ => Err(ForgeError::invalid_input(
            "operation is not a Work Cut operation",
        )),
    }
}

pub(super) fn execute(
    clients: &BridgeClients,
    command: &WorkCutCommand,
) -> Result<Value, ForgeError> {
    if command.service.backend_id != clients.backend_id
        || command.service.issuer != clients.issuer
        || command.service.destination_id != clients.destination_id
    {
        return Err(ForgeError::auth_failed());
    }
    let operation = match &command.operation {
        WorkCutHttpOperation::Inventory { request } => ControlWorkCutOperation::Inventory {
            request: request.clone(),
        },
        WorkCutHttpOperation::Prepare { request, grant } => ControlWorkCutOperation::Prepare {
            request: request.clone(),
            grant: *grant,
        },
        WorkCutHttpOperation::Get {
            cut_id,
            request_digest,
        } => ControlWorkCutOperation::Get {
            cut_id: *cut_id,
            request_digest: *request_digest,
        },
        WorkCutHttpOperation::Drain {
            cut_id,
            request_digest,
            expected_revision,
        } => ControlWorkCutOperation::Drain {
            cut_id: *cut_id,
            request_digest: *request_digest,
            expected_revision: *expected_revision,
        },
    };
    let response = clients
        .control
        .leadership_work_cut(ControlWorkCutCommand {
            scope: command.scope.clone(),
            service: WorkCutService {
                issuer: clients.issuer,
                backend_id: clients.backend_id,
                destination_id: clients.destination_id,
            },
            operation,
        })
        .map_err(|error| map_control_error(command, &error))?;
    project_response(command, response)
}

fn project_response(
    command: &WorkCutCommand,
    response: ControlWorkCutResponse,
) -> Result<Value, ForgeError> {
    match response {
        ControlWorkCutResponse::Inventory(inventory) => {
            validate_inventory(command, &inventory)?;
            Ok(json!({
                "kind": "inventory",
                "scope": super::scope_json(command.scope())?,
                "request_digest": digest_hex(inventory.request_digest().as_bytes()),
                "inventory": inventory_json(&inventory),
            }))
        }
        ControlWorkCutResponse::Prepared(outcome) => {
            let record = match &outcome {
                WorkCutPrepareOutcome::Prepared(record)
                | WorkCutPrepareOutcome::Existing(record) => record,
            };
            validate_record(command, record)?;
            Ok(json!({
                "kind": "prepared",
                "status": match outcome {
                    WorkCutPrepareOutcome::Prepared(_) => "prepared",
                    WorkCutPrepareOutcome::Existing(_) => "existing",
                },
                "scope": super::scope_json(command.scope())?,
                "record": record_json(record),
            }))
        }
        ControlWorkCutResponse::Record(record) => {
            let Some(record) = record else {
                let WorkCutHttpOperation::Get {
                    cut_id,
                    request_digest,
                } = &command.operation
                else {
                    return Err(ForgeError::resync_required(
                        "unexpected Work Cut record response",
                    ));
                };
                return Ok(json!({
                    "kind": "record",
                    "found": false,
                    "status": "absent_now",
                    "cut_id": cut_id,
                    "request_digest": digest_hex(request_digest.as_bytes()),
                    "scope": super::scope_json(command.scope())?,
                }));
            };
            validate_record(command, &record)?;
            Ok(json!({
                "kind": "record",
                "found": true,
                "status": "historical",
                "scope": super::scope_json(command.scope())?,
                "record": record_json(&record),
            }))
        }
        ControlWorkCutResponse::Drain(observation) => {
            validate_drain(command, &observation)?;
            Ok(json!({
                "kind": "drain",
                "cut_id": observation.cut_id(),
                "cut_revision": observation.cut_revision(),
                "snapshot_digest": digest_hex(observation.snapshot_digest()),
                "observed_at_ms": observation.observed_at().get(),
                "effects_drained": observation.effects_drained(),
                "effects": observation.effects().iter().map(effect_progress_json).collect::<Vec<_>>(),
                "custody_released": false,
            }))
        }
    }
}

fn validate_inventory(
    command: &WorkCutCommand,
    inventory: &WorkCutInventory,
) -> Result<(), ForgeError> {
    let expected = command.request_digest();
    if inventory.request_digest() != expected {
        return Err(ForgeError::resync_required(
            "Work Cut inventory request digest changed",
        ));
    }
    Ok(())
}

fn validate_record(command: &WorkCutCommand, record: &WorkCutRecord) -> Result<(), ForgeError> {
    let request = record.request();
    let expected_cut = match &command.operation {
        WorkCutHttpOperation::Get { cut_id, .. } | WorkCutHttpOperation::Drain { cut_id, .. } => {
            *cut_id
        }
        WorkCutHttpOperation::Inventory { request }
        | WorkCutHttpOperation::Prepare { request, .. } => request.cut_id(),
    };
    if request.cut_id() != expected_cut
        || request.workspace_id() != command.scope.workspace_id()
        || request.workspace_revision() != command.scope.workspace_revision()
        || record.issuer() != command.service.issuer
        || request.backend_id() != command.service.backend_id
        || request.destination_id() != command.service.destination_id
        || command.request_digest() != request.request_digest()
    {
        return Err(ForgeError::resync_required(
            "Work Cut record identity changed",
        ));
    }
    Ok(())
}

fn validate_drain(
    command: &WorkCutCommand,
    observation: &WorkCutDrainObservation,
) -> Result<(), ForgeError> {
    let WorkCutHttpOperation::Drain {
        cut_id,
        expected_revision,
        ..
    } = &command.operation
    else {
        return Err(ForgeError::resync_required(
            "unexpected Work Cut drain response",
        ));
    };
    if observation.cut_id() != *cut_id || observation.cut_revision() != *expected_revision {
        return Err(ForgeError::resync_required(
            "Work Cut drain readback identity changed",
        ));
    }
    Ok(())
}

fn record_json(record: &WorkCutRecord) -> Value {
    json!({
        "request": request_json(record.request()),
        "inventory": inventory_json(record.inventory()),
        "effects": record.effects().iter().map(effect_json).collect::<Vec<_>>(),
        "issuer": record.issuer().into_uuid(),
        "prepared_at_ms": record.prepared_at().get(),
        "authorization_issued_at_ms": record.authorization_issued_at().get(),
        "authorization_expires_at_ms": record.authorization_expires_at().get(),
        "snapshot_digest": digest_hex(record.snapshot_digest()),
        "state": cut_state_name(record.state()),
        "revision": record.revision(),
        "updated_at_ms": record.updated_at().get(),
    })
}

fn request_json(request: &WorkCutRequest) -> Value {
    json!({
        "cut_id": request.cut_id(),
        "election_id": request.election_id(),
        "destination_id": request.destination_id(),
        "backend_id": request.backend_id().into_uuid(),
        "workspace_id": request.workspace_id().into_uuid(),
        "workspace_revision": request.workspace_revision().get(),
        "leadership_revision": request.leadership_revision(),
        "roster_digest": digest_hex(request.roster_digest()),
        "request_digest": digest_hex(request.request_digest().as_bytes()),
        "parties": {
            "incumbent": party_json(request.parties()[0]),
            "elected": party_json(request.parties()[1]),
        },
        "sessions": request.sessions().iter().map(session_json).collect::<Vec<_>>(),
        "bindings": request.bindings().iter().map(binding_json).collect::<Vec<_>>(),
        "scope": work_cut_scope_json(request.scope()),
    })
}

fn inventory_json(inventory: &WorkCutInventory) -> Value {
    json!({
        "request_digest": digest_hex(inventory.request_digest().as_bytes()),
        "agents": inventory.agents().iter().map(inventory_agent_json).collect::<Vec<_>>(),
        "nodes": inventory.nodes().iter().map(inventory_node_json).collect::<Vec<_>>(),
    })
}

fn inventory_agent_json(agent: &WorkInventoryAgent) -> Value {
    let binding = agent.binding();
    let focus = agent.focus();
    json!({
        "binding": binding_json(&binding),
        "revision": agent.revision().get(),
        "focus": {
            "goal": focus.goal().map(|goal| json!({
                "goal_id": goal.goal_id().into_uuid(),
                "expected_revision": goal.expected_revision().get(),
            })),
            "dag_revision": focus.dag_revision().map(forge_domain::DagRevisionNumber::get),
            "node": focus.node().map(|node| json!({
                "node_id": node.node_id().into_uuid(),
                "expected_revision": node.expected_revision().get(),
            })),
        },
    })
}

fn inventory_node_json(node: &WorkInventoryNode) -> Value {
    json!({
        "agent_id": node.agent_id().into_uuid(),
        "scope": node_scope_json(&node.scope()),
        "goal_revision": node.goal_revision().get(),
        "head_dag_revision": node.head_dag_revision().get(),
        "head_revision": node.head_revision().get(),
        "node_revision": node.node_revision().get(),
        "node_state": dag_node_status_name(node.node_state()),
        "direct_focus": node.direct_focus(),
        "assignment": node.assignment().map(|assignment| json!({
            "assignment_id": assignment.assignment_id().into_uuid(),
            "revision": assignment.revision().get(),
            "state": assignment_state_name(assignment.state()),
            "cancellation_requested": assignment.cancellation_requested(),
        })),
    })
}

fn effect_json(effect: &forge_persistence::WorkCutEffect) -> Value {
    json!({
        "kind": effect_kind_name(effect.kind()),
        "id": effect.id(),
        "revision": effect.revision(),
        "state": effect.state(),
        "activity_id": effect.activity_id().into_uuid(),
        "agent_id": effect.agent_id().map(AgentInstanceId::into_uuid),
        "node_scope": effect
            .node_scope()
            .map(|scope| node_scope_json(&scope)),
    })
}

fn effect_progress_json(progress: &WorkCutEffectProgress) -> Value {
    json!({
        "kind": effect_kind_name(progress.kind()),
        "id": progress.id(),
        "revision": progress.revision(),
        "settlement": effect_settlement_name(progress.settlement()),
    })
}

fn party_json(party: WorkCutParty) -> Value {
    json!({
        "participation_id": party.participation_id(),
        "profile_id": party.profile_id(),
    })
}

fn session_json(session: &WorkCutSession) -> Value {
    json!({
        "side": side_name(session.side()),
        "session_id": session.session_id().into_uuid(),
    })
}

fn binding_json(binding: &WorkCutBinding) -> Value {
    json!({
        "side": side_name(binding.side()),
        "activity_id": binding.activity_id().into_uuid(),
        "agent_id": binding.agent_id().into_uuid(),
        "session_id": binding.session_id().into_uuid(),
        "principal": principal_json(binding.principal()),
    })
}

fn work_cut_scope_json(scope: &WorkCutScope) -> Value {
    match scope {
        WorkCutScope::Workspace => json!({"kind": "workspace"}),
        WorkCutScope::Team { team_id, nodes } => json!({
            "kind": "team",
            "team_id": team_id,
            "nodes": nodes.iter().map(node_scope_json).collect::<Vec<_>>(),
        }),
    }
}

fn node_scope_json(scope: &WorkCutNodeScope) -> Value {
    json!({
        "activity_id": scope.activity_id().into_uuid(),
        "goal_id": scope.goal_id().into_uuid(),
        "goal_created_at_ms": scope.goal_created_at().get(),
        "dag_base_goal_revision": scope.dag_base_goal_revision().get(),
        "dag_revision": scope.dag_revision().get(),
        "node_id": scope.node_id().into_uuid(),
    })
}

fn principal_json(principal: AuthenticatedPrincipal) -> Value {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => json!({"kind": "trusted_stdio"}),
        AuthenticatedPrincipal::DirectToken(id) => {
            json!({"kind": "direct_token", "token_id": id.into_uuid()})
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            json!({"kind": "oauth_grant", "grant_id": id.into_uuid()})
        }
    }
}

fn side_name(side: WorkCutSide) -> &'static str {
    match side {
        WorkCutSide::Incumbent => "incumbent",
        WorkCutSide::Elected => "elected",
    }
}

fn effect_kind_name(kind: WorkCutEffectKind) -> &'static str {
    match kind {
        WorkCutEffectKind::WriterLease => "writer_lease",
        WorkCutEffectKind::Execution => "execution",
        WorkCutEffectKind::ChangeSet => "change_set",
    }
}

fn effect_settlement_name(settlement: WorkCutEffectSettlement) -> &'static str {
    match settlement {
        WorkCutEffectSettlement::Pending => "pending",
        WorkCutEffectSettlement::Settled => "settled",
    }
}

fn cut_state_name(state: forge_persistence::WorkCutState) -> &'static str {
    match state {
        forge_persistence::WorkCutState::Held => "held",
        forge_persistence::WorkCutState::Released => "released",
    }
}

fn assignment_state_name(state: AgentAssignmentState) -> &'static str {
    match state {
        AgentAssignmentState::Offered => "offered",
        AgentAssignmentState::Running => "running",
        AgentAssignmentState::Submitted => "submitted",
        AgentAssignmentState::Accepted => "accepted",
        AgentAssignmentState::Rejected => "rejected",
        AgentAssignmentState::Cancelled => "cancelled",
        AgentAssignmentState::Interrupted => "interrupted",
    }
}

fn dag_node_status_name(status: DagNodeStatus) -> &'static str {
    match status {
        DagNodeStatus::Pending => "pending",
        DagNodeStatus::Ready => "ready",
        DagNodeStatus::Active => "active",
        DagNodeStatus::Blocked => "blocked",
        DagNodeStatus::Completed => "completed",
        DagNodeStatus::Failed => "failed",
        DagNodeStatus::Skipped => "skipped",
        DagNodeStatus::Cancelled => "cancelled",
    }
}

fn decode_scope_service(
    scope: &ScopeDto,
    service: ServiceBody,
) -> Result<(ResolvedWorkspaceScope, WorkCutService), ForgeError> {
    if scope.workspace_id.is_nil() || scope.locator.location_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "Work Cut scope identifiers must not be nil",
        ));
    }
    let scope = decode_scope(scope)?;
    let service = WorkCutService {
        issuer: OrchestrationIssuerId::from_uuid(require_non_nil(service.issuer, "issuer")?),
        backend_id: ForgeBackendId::from_uuid(require_non_nil(service.backend_id, "backend id")?),
        destination_id: require_non_nil(service.destination_id, "destination id")?,
    };
    Ok((scope, service))
}

fn decode_request(
    body: WorkCutRequestBody,
    scope: &ResolvedWorkspaceScope,
    service: WorkCutService,
) -> Result<WorkCutRequest, ForgeError> {
    if body.sessions.len() > forge_domain::MAX_WORK_CUT_SESSIONS
        || body.bindings.len() > forge_domain::MAX_WORK_CUT_BINDINGS
    {
        return Err(ForgeError::invalid_input("Work Cut roster bounds exceeded"));
    }
    let workspace_id = require_non_nil(body.workspace_id, "Work Cut Workspace id")?;
    if workspace_id != scope.workspace_id().into_uuid()
        || body.backend_id != service.backend_id.into_uuid()
        || body.destination_id != service.destination_id
    {
        return Err(ForgeError::auth_failed());
    }
    if body.workspace_revision != scope.workspace_revision().get() {
        return Err(ForgeError::resync_required(
            "Work Cut Workspace revision does not match scope",
        ));
    }
    let workspace_revision = forge_domain::WorkspaceRevision::new(body.workspace_revision)
        .map_err(|_| ForgeError::invalid_input("Work Cut Workspace revision is invalid"))?;
    let parties = [
        WorkCutParty::new(
            require_non_nil(
                body.parties.incumbent.participation_id,
                "incumbent participation",
            )?,
            require_non_nil(body.parties.incumbent.profile_id, "incumbent profile")?,
        )
        .map_err(|_| ForgeError::invalid_input("incumbent party is invalid"))?,
        WorkCutParty::new(
            require_non_nil(
                body.parties.elected.participation_id,
                "elected participation",
            )?,
            require_non_nil(body.parties.elected.profile_id, "elected profile")?,
        )
        .map_err(|_| ForgeError::invalid_input("elected party is invalid"))?,
    ];
    let sessions = body
        .sessions
        .into_iter()
        .map(|session| {
            WorkCutSession::new(
                decode_side(session.side),
                AgentSessionId::from_uuid(require_non_nil(session.session_id, "session id")?),
            )
            .map_err(|_| ForgeError::invalid_input("Work Cut session is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bindings = body
        .bindings
        .into_iter()
        .map(|binding| {
            WorkCutBinding::new(
                decode_side(binding.side),
                ActivityId::from_uuid(require_non_nil(binding.activity_id, "activity id")?),
                AgentInstanceId::from_uuid(require_non_nil(binding.agent_id, "agent id")?),
                AgentSessionId::from_uuid(require_non_nil(binding.session_id, "session id")?),
                decode_principal(&binding.principal)?,
            )
            .map_err(|_| ForgeError::invalid_input("Work Cut binding is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let scope_value = decode_cut_scope(body.scope)?;
    WorkCutRequest::new(
        require_non_nil(body.cut_id, "cut id")?,
        require_non_nil(body.election_id, "election id")?,
        require_non_nil(body.destination_id, "destination id")?,
        ForgeBackendId::from_uuid(require_non_nil(body.backend_id, "backend id")?),
        WorkspaceId::from_uuid(workspace_id),
        workspace_revision,
        body.leadership_revision,
        decode_digest(&body.roster_digest)?,
        parties,
        sessions,
        bindings,
        scope_value,
    )
    .map_err(|_| ForgeError::invalid_input("Work Cut request is invalid"))
}

fn decode_grant(body: &WorkCutGrantBody) -> Result<WorkCutGrant, ForgeError> {
    WorkCutGrant::new(
        OrchestrationIssuerId::from_uuid(require_non_nil(body.issuer, "grant issuer")?),
        WorkCutRequestDigest::from_bytes(decode_digest(&body.request_digest)?),
        decode_timestamp(body.issued_at_ms)?,
        decode_timestamp(body.expires_at_ms)?,
    )
    .map_err(|_| ForgeError::invalid_input("Work Cut grant is invalid"))
}

fn decode_cut_scope(body: WorkCutScopeBody) -> Result<WorkCutScope, ForgeError> {
    match body {
        WorkCutScopeBody::Workspace => Ok(WorkCutScope::Workspace),
        WorkCutScopeBody::Team { nodes, .. }
            if nodes.len() > forge_domain::MAX_WORK_CUT_TEAM_NODES =>
        {
            Err(ForgeError::invalid_input(
                "Work Cut team node bounds exceeded",
            ))
        }
        WorkCutScopeBody::Team { team_id, nodes } => Ok(WorkCutScope::Team {
            team_id: require_non_nil(team_id, "team id")?,
            nodes: nodes
                .into_iter()
                .map(|node| {
                    WorkCutNodeScope::new(
                        ActivityId::from_uuid(require_non_nil(node.activity_id, "node activity")?),
                        GoalId::from_uuid(require_non_nil(node.goal_id, "node Goal")?),
                        decode_timestamp(node.goal_created_at_ms)?,
                        GoalRevision::new(node.dag_base_goal_revision).map_err(|_| {
                            ForgeError::invalid_input("node Goal revision is invalid")
                        })?,
                        DagRevisionNumber::new(node.dag_revision).map_err(|_| {
                            ForgeError::invalid_input("node DAG revision is invalid")
                        })?,
                        DagNodeId::from_uuid(require_non_nil(node.node_id, "node id")?),
                    )
                    .map_err(|_| ForgeError::invalid_input("Work Cut node scope is invalid"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        }),
    }
}

fn decode_side(side: WorkCutSideBody) -> WorkCutSide {
    match side {
        WorkCutSideBody::Incumbent => WorkCutSide::Incumbent,
        WorkCutSideBody::Elected => WorkCutSide::Elected,
    }
}

fn decode_digest(value: &str) -> Result<[u8; DIGEST_BYTES], ForgeError> {
    let bytes = super::decode_hex(value)?;
    let digest = bytes
        .try_into()
        .map_err(|_| ForgeError::invalid_input("Work Cut digest must be 64 hex characters"))?;
    if digest == [0; DIGEST_BYTES] {
        return Err(ForgeError::invalid_input("Work Cut digest must be nonzero"));
    }
    Ok(digest)
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, ForgeError> {
    TimestampMillis::new(value).map_err(|_| ForgeError::invalid_input("timestamp is invalid"))
}

fn require_non_nil(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be non-nil"
        )));
    }
    Ok(value)
}

fn digest_hex(value: &[u8]) -> String {
    super::encode_hex(value)
}

fn map_control_error(
    command: &WorkCutCommand,
    error: &forge_control::ControlClientError,
) -> ForgeError {
    let mapped = super::forge_error_of_client(error);
    if mapped.code() == crate::error::ErrorCode::UnknownOutcome {
        mapped.with_readback(command.readback_hint())
    } else {
        mapped
    }
}
