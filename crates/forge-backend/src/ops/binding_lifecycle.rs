//! HTTP DTOs and projections for delegated Agent lifecycle operations.
//!
//! This module is deliberately a wire adapter.  The existing Forge control
//! reference facade resolves the durable freeze/delegation and then invokes
//! the native mutation owner.  No opaque persistence value is constructed in
//! this module and no receipt is treated as a work grant.

use forge_control::{
    AgentBindingActivateReferenceRequest, AgentBindingReservationReadRequest,
    AgentBindingReserveReferenceRequest, AgentDepartureReconcileDestinationRequest,
    AgentDepartureReconcileReadRequest, AgentDepartureReconcileRequest,
    AgentOperationsDelegateReferenceRequest, AgentOperationsDelegationReadRequest,
    AgentOperationsDelegationReference, AgentOperationsFreezeReference,
    AgentSessionReconcileDestinationRequest, AgentSessionReconcileReadRequest,
    AgentSessionReconcileRequest, ForgeControlClient, ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentDeclaredRole,
    AgentDisplayName, AgentEventId, AgentFocusNode, AgentHandoff, AgentInstanceId,
    AgentInstanceRevision, AgentSessionId, AgentTransportKind, AuthenticatedPrincipal,
    BindExistingAgentSession, CoordinationSnapshot, DagHeadRevision, DagNodeId, DagNodeRevision,
    DagRevisionNumber, GoalAttribution, GoalId, GoalRevision, OrchestrationIssuerId,
    TimestampMillis, WorkspaceId,
};
use forge_persistence::{
    AgentBindingActivation, AgentBindingActivationRequest, AgentBindingReservation,
    AgentBindingReservationRequest, AgentDepartureCommand, AgentDepartureKind,
    AgentDepartureReconciliation, AgentDepartureReconciliationRequest, AgentOperationsDelegation,
    AgentOperationsFreezeState, AgentSessionReconciliation, AgentSessionReconciliationRequest,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{CommandOp, PrincipalDto, ScopeDto, decode_principal, decode_scope};
use crate::error::ForgeError;

const DIGEST_BYTES: usize = 32;
const MAX_FREEZE_REVISION: i64 = i64::MAX;

/// Parsed delegated Agent lifecycle command.  The trusted issuer and
/// destination are retained from the request so the bridge can compare them
/// before any control call is admitted.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingLifecycleCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) issuer_id: OrchestrationIssuerId,
    pub(super) destination_id: Uuid,
    pub(super) request: BindingLifecycleRequest,
}

impl BindingLifecycleCommand {
    /// Return the frozen operation identity for dispatch and readback routing.
    pub const fn op(&self) -> CommandOp {
        self.request.op()
    }
}

/// The closed ten-operation request family used by the binding lifecycle
/// adapter.  Native persistence requests remain behind forge-control.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingLifecycleRequest {
    AgentOperationsDelegate {
        reference: AgentOperationsFreezeReference,
        manifest_digest: [u8; DIGEST_BYTES],
        observed_at: TimestampMillis,
    },
    AgentOperationsDelegationGet {
        reference: AgentOperationsDelegationReference,
    },
    AgentBindingReserve {
        reference: AgentOperationsFreezeReference,
        reservation: AgentBindingReservationRequest,
        observed_at: TimestampMillis,
    },
    AgentBindingReservationGet {
        request_id: Uuid,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    },
    AgentBindingActivate {
        reference: AgentOperationsDelegationReference,
        activation: AgentBindingActivationRequest,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        observed_at: TimestampMillis,
    },
    AgentBindingActivationGet {
        request_id: Uuid,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    },
    AgentSessionReconcile {
        reconciliation: AgentSessionReconciliationRequest,
    },
    AgentSessionReconciliationGet {
        request_id: Uuid,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    },
    AgentDepartureReconcile {
        reconciliation: AgentDepartureReconciliationRequest,
    },
    AgentDepartureReconciliationGet {
        request_id: Uuid,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    },
}

impl BindingLifecycleRequest {
    /// Return the frozen operation identity for this parsed request.
    pub const fn op(&self) -> CommandOp {
        match self {
            Self::AgentOperationsDelegate { .. } => CommandOp::AgentOperationsDelegate,
            Self::AgentOperationsDelegationGet { .. } => CommandOp::AgentOperationsDelegationGet,
            Self::AgentBindingReserve { .. } => CommandOp::AgentBindingReserve,
            Self::AgentBindingReservationGet { .. } => CommandOp::AgentBindingReservationGet,
            Self::AgentBindingActivate { .. } => CommandOp::AgentBindingActivate,
            Self::AgentBindingActivationGet { .. } => CommandOp::AgentBindingActivationGet,
            Self::AgentSessionReconcile { .. } => CommandOp::AgentSessionReconcile,
            Self::AgentSessionReconciliationGet { .. } => CommandOp::AgentSessionReconciliationGet,
            Self::AgentDepartureReconcile { .. } => CommandOp::AgentDepartureReconcile,
            Self::AgentDepartureReconciliationGet { .. } => {
                CommandOp::AgentDepartureReconciliationGet
            }
        }
    }
}

/// Result type shared by each closed operation arm.
pub(super) type ValueResult = Result<Value, ForgeError>;

/// Return durable readback identity only for admitted mutation commands.
/// Read operations never authorize a retry and retain no caller principal in
/// this hint; the native receipt read remains session-bound.
pub(super) fn readback_hint(
    command: &BindingLifecycleCommand,
) -> Option<crate::error::ReadbackHint> {
    let workspace_id = command.scope.workspace_id().into_uuid();
    let destination_id = command.destination_id;
    match &command.request {
        BindingLifecycleRequest::AgentOperationsDelegate {
            reference,
            manifest_digest,
            ..
        } => Some(crate::error::ReadbackHint::AgentDelegation {
            workspace_id,
            migration_id: reference.migration_id,
            destination_id: reference.destination_id,
            expected_freeze_revision: reference.expected_revision,
            manifest_digest: encode_digest(*manifest_digest),
        }),
        BindingLifecycleRequest::AgentBindingReserve { reservation, .. } => {
            Some(crate::error::ReadbackHint::AgentBindingReservation {
                workspace_id,
                destination_id,
                request_id: reservation.request_id(),
                session_id: reservation.session_id().into_uuid(),
            })
        }
        BindingLifecycleRequest::AgentBindingActivate {
            activation,
            session_id,
            ..
        } => Some(crate::error::ReadbackHint::AgentBindingActivation {
            workspace_id,
            destination_id,
            request_id: activation.request_id(),
            session_id: (*session_id).into_uuid(),
        }),
        BindingLifecycleRequest::AgentSessionReconcile { reconciliation } => {
            let command = reconciliation.command();
            Some(crate::error::ReadbackHint::AgentSessionReconciliation {
                workspace_id,
                destination_id,
                request_id: reconciliation.request_id(),
                session_id: command.session_id().into_uuid(),
            })
        }
        BindingLifecycleRequest::AgentDepartureReconcile { reconciliation } => {
            Some(crate::error::ReadbackHint::AgentDepartureReconciliation {
                workspace_id,
                destination_id,
                request_id: reconciliation.request_id(),
                session_id: reconciliation.session_id().into_uuid(),
            })
        }
        BindingLifecycleRequest::AgentOperationsDelegationGet { .. }
        | BindingLifecycleRequest::AgentBindingReservationGet { .. }
        | BindingLifecycleRequest::AgentBindingActivationGet { .. }
        | BindingLifecycleRequest::AgentSessionReconciliationGet { .. }
        | BindingLifecycleRequest::AgentDepartureReconciliationGet { .. } => None,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeReferenceDto {
    migration_id: Uuid,
    expected_freeze_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationReferenceDto {
    migration_id: Uuid,
    expected_freeze_revision: i64,
    manifest_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationDto {
    request_id: Uuid,
    activity_id: Uuid,
    agent_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
    requested_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationDto {
    request_id: Uuid,
    membership_digest: String,
    display_name: String,
    declared_role: String,
    transport: TransportDto,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportDto {
    /// Retired transport; the wire value stays `mcp` for decode
    /// compatibility with existing callers and persisted rows.
    #[serde(rename = "mcp")]
    Retired,
    Stdio,
    StreamableHttp,
    Other,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegateBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    reference: FreezeReferenceDto,
    manifest_digest: String,
    observed_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationGetBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    reference: DelegationReferenceDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    reference: FreezeReferenceDto,
    reservation: ReservationDto,
    observed_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationGetBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    reference: DelegationReferenceDto,
    activation: ActivationDto,
    session_id: Uuid,
    principal: PrincipalDto,
    observed_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationGetBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReconcileBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    reconciliation: SessionReconciliationDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReconciliationDto {
    request_id: Uuid,
    activity_id: Uuid,
    agent_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
    expected_agent_revision: i64,
    observed_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReconciliationGetBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepartureReconcileBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    reconciliation: DepartureReconciliationDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepartureReconciliationDto {
    request_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
    identity_digest: String,
    command: DepartureCommandDto,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DepartureCommandDto {
    Detach {
        activity_id: Uuid,
        agent_id: Uuid,
        expected_agent_revision: i64,
        observed_at_ms: i64,
    },
    Handoff {
        activity_id: Uuid,
        agent_id: Uuid,
        expected_coordinator_revision: i64,
        expected_source_agent_revision: i64,
        target_agent_id: Uuid,
        target_session_id: Uuid,
        target_principal: PrincipalDto,
        expected_target_revision: i64,
        expected_coordination: CoordinationSnapshotDto,
        event_id: Uuid,
        observed_at_ms: i64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinationSnapshotDto {
    #[serde(default)]
    goal: Option<GoalAttributionDto>,
    #[serde(default)]
    dag_revision: Option<i64>,
    #[serde(default)]
    dag_head_revision: Option<i64>,
    #[serde(default)]
    node: Option<FocusNodeDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoalAttributionDto {
    goal_id: Uuid,
    expected_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FocusNodeDto {
    node_id: Uuid,
    expected_revision: i64,
}

/// Parse one of the ten frozen Agent lifecycle operation payloads.
pub(super) fn parse(op: CommandOp, payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    match op {
        CommandOp::AgentOperationsDelegate => parse_delegate(payload),
        CommandOp::AgentOperationsDelegationGet => parse_delegation_get(payload),
        CommandOp::AgentBindingReserve => parse_reserve(payload),
        CommandOp::AgentBindingReservationGet => parse_reservation_get(payload),
        CommandOp::AgentBindingActivate => parse_activate(payload),
        CommandOp::AgentBindingActivationGet => parse_activation_get(payload),
        CommandOp::AgentSessionReconcile => parse_session_reconcile(payload),
        CommandOp::AgentSessionReconciliationGet => parse_session_reconciliation_get(payload),
        CommandOp::AgentDepartureReconcile => parse_departure_reconcile(payload),
        CommandOp::AgentDepartureReconciliationGet => parse_departure_reconciliation_get(payload),
        _ => Err(ForgeError::invalid_input(
            "operation is not an Agent lifecycle operation",
        )),
    }
}

fn parse_delegate(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: DelegateBody =
        super::parse_body(payload, "agent.operations.delegate payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    let reference = decode_freeze_reference(&body.reference, destination_id)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentOperationsDelegate {
            reference,
            manifest_digest: decode_digest(&body.manifest_digest, "manifest digest")?,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        },
    })
}

fn parse_delegation_get(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: DelegationGetBody = super::parse_body(
        payload,
        "agent.operations.delegation_get payload is invalid",
    )?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentOperationsDelegationGet {
            reference: decode_delegation_reference(&body.reference, destination_id)?,
        },
    })
}

fn parse_reserve(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: ReserveBody = super::parse_body(payload, "agent.binding.reserve payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    let reference = decode_freeze_reference(&body.reference, destination_id)?;
    let reservation = decode_reservation(&body.reservation)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentBindingReserve {
            reference,
            reservation,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        },
    })
}

fn parse_reservation_get(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: ReservationGetBody =
        super::parse_body(payload, "agent.binding.reservation_get payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentBindingReservationGet {
            request_id: require_id(body.request_id, "reservation request id")?,
            session_id: decode_session_id(body.session_id, "reservation session id")?,
            principal: decode_principal(&body.principal)?,
        },
    })
}

fn parse_activate(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: ActivateBody =
        super::parse_body(payload, "agent.binding.activate payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    let reference = decode_delegation_reference(&body.reference, destination_id)?;
    let session_id = decode_session_id(body.session_id, "activation session id")?;
    let principal = decode_principal(&body.principal)?;
    let activation = decode_activation(body.activation)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentBindingActivate {
            reference,
            activation,
            session_id,
            principal,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        },
    })
}

fn parse_activation_get(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: ActivationGetBody =
        super::parse_body(payload, "agent.binding.activation_get payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentBindingActivationGet {
            request_id: require_id(body.request_id, "activation request id")?,
            session_id: decode_session_id(body.session_id, "activation session id")?,
            principal: decode_principal(&body.principal)?,
        },
    })
}

fn parse_session_reconcile(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: SessionReconcileBody =
        super::parse_body(payload, "agent.session.reconcile payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    let reconciliation = decode_session_reconciliation(&body.reconciliation, scope.workspace_id())?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentSessionReconcile { reconciliation },
    })
}

fn parse_session_reconciliation_get(
    payload: &Value,
) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: SessionReconciliationGetBody = super::parse_body(
        payload,
        "agent.session.reconciliation_get payload is invalid",
    )?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentSessionReconciliationGet {
            request_id: require_id(body.request_id, "session reconciliation request id")?,
            session_id: decode_session_id(body.session_id, "reconciliation session id")?,
            principal: decode_principal(&body.principal)?,
        },
    })
}

fn parse_departure_reconcile(payload: &Value) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: DepartureReconcileBody =
        super::parse_body(payload, "agent.departure.reconcile payload is invalid")?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    let reconciliation =
        decode_departure_reconciliation(body.reconciliation, scope.workspace_id())?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentDepartureReconcile { reconciliation },
    })
}

fn parse_departure_reconciliation_get(
    payload: &Value,
) -> Result<BindingLifecycleCommand, ForgeError> {
    let body: DepartureReconciliationGetBody = super::parse_body(
        payload,
        "agent.departure.reconciliation_get payload is invalid",
    )?;
    let (scope, issuer_id, destination_id) =
        decode_common(&body.scope, body.issuer_id, body.destination_id)?;
    Ok(BindingLifecycleCommand {
        scope,
        issuer_id,
        destination_id,
        request: BindingLifecycleRequest::AgentDepartureReconciliationGet {
            request_id: require_id(body.request_id, "departure reconciliation request id")?,
            session_id: decode_session_id(body.session_id, "departure session id")?,
            principal: decode_principal(&body.principal)?,
        },
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepartureReconciliationGetBody {
    scope: ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: Uuid,
    principal: PrincipalDto,
}

fn decode_common(
    scope: &ScopeDto,
    issuer_id: Uuid,
    destination_id: Uuid,
) -> Result<(ResolvedWorkspaceScope, OrchestrationIssuerId, Uuid), ForgeError> {
    require_id(scope.workspace_id, "scope workspace id")?;
    require_id(scope.locator.location_id, "scope location id")?;
    let issuer_id = require_id(issuer_id, "issuer id")?;
    let destination_id = require_id(destination_id, "destination id")?;
    Ok((
        decode_scope(scope)?,
        OrchestrationIssuerId::from_uuid(issuer_id),
        destination_id,
    ))
}

fn decode_freeze_reference(
    value: &FreezeReferenceDto,
    destination_id: Uuid,
) -> Result<AgentOperationsFreezeReference, ForgeError> {
    let expected_revision = decode_freeze_revision(value.expected_freeze_revision)?;
    Ok(AgentOperationsFreezeReference {
        migration_id: require_id(value.migration_id, "migration id")?,
        destination_id,
        expected_revision,
    })
}

fn decode_delegation_reference(
    value: &DelegationReferenceDto,
    destination_id: Uuid,
) -> Result<AgentOperationsDelegationReference, ForgeError> {
    Ok(AgentOperationsDelegationReference {
        freeze: AgentOperationsFreezeReference {
            migration_id: require_id(value.migration_id, "migration id")?,
            destination_id,
            expected_revision: decode_freeze_revision(value.expected_freeze_revision)?,
        },
        manifest_digest: decode_digest(&value.manifest_digest, "manifest digest")?,
    })
}

fn decode_reservation(
    value: &ReservationDto,
) -> Result<AgentBindingReservationRequest, ForgeError> {
    AgentBindingReservationRequest::new(
        require_id(value.request_id, "reservation request id")?,
        decode_activity_id(value.activity_id, "reservation activity id")?,
        decode_agent_id(value.agent_id, "reservation agent id")?,
        decode_session_id(value.session_id, "reservation session id")?,
        decode_principal(&value.principal)?,
        decode_timestamp(value.requested_at_ms)?,
    )
    .map_err(|_| ForgeError::invalid_input("agent binding reservation is invalid"))
}

fn decode_activation(value: ActivationDto) -> Result<AgentBindingActivationRequest, ForgeError> {
    AgentBindingActivationRequest::new(
        require_id(value.request_id, "activation request id")?,
        decode_digest(&value.membership_digest, "membership digest")?,
        AgentDisplayName::new(value.display_name)
            .map_err(|_| ForgeError::invalid_input("activation display name is invalid"))?,
        AgentDeclaredRole::new(value.declared_role)
            .map_err(|_| ForgeError::invalid_input("activation declared role is invalid"))?,
        decode_transport(value.transport),
    )
    .map_err(|_| ForgeError::invalid_input("agent binding activation is invalid"))
}

fn decode_session_reconciliation(
    value: &SessionReconciliationDto,
    workspace_id: WorkspaceId,
) -> Result<AgentSessionReconciliationRequest, ForgeError> {
    let command = BindExistingAgentSession::new(
        workspace_id,
        decode_activity_id(value.activity_id, "session reconciliation activity id")?,
        decode_agent_id(value.agent_id, "session reconciliation agent id")?,
        decode_session_id(value.session_id, "session reconciliation session id")?,
        decode_principal(&value.principal)?,
        decode_agent_revision(value.expected_agent_revision)?,
        decode_timestamp(value.observed_at_ms)?,
    );
    AgentSessionReconciliationRequest::new(
        require_id(value.request_id, "session reconciliation request id")?,
        command,
    )
    .map_err(|_| ForgeError::invalid_input("agent session reconciliation is invalid"))
}

fn decode_departure_reconciliation(
    value: DepartureReconciliationDto,
    workspace_id: WorkspaceId,
) -> Result<AgentDepartureReconciliationRequest, ForgeError> {
    let session_id = decode_session_id(value.session_id, "departure session id")?;
    let principal = decode_principal(&value.principal)?;
    let identity_digest = decode_digest(&value.identity_digest, "departure identity digest")?;
    let command = match value.command {
        DepartureCommandDto::Detach {
            activity_id,
            agent_id,
            expected_agent_revision,
            observed_at_ms,
        } => AgentDepartureCommand::Detach(forge_domain::DetachAgent::new(
            decode_agent_id(agent_id, "detach agent id")?,
            decode_activity_id(activity_id, "detach activity id")?,
            decode_agent_revision(expected_agent_revision)?,
            decode_timestamp(observed_at_ms)?,
        )),
        DepartureCommandDto::Handoff {
            activity_id,
            agent_id,
            expected_coordinator_revision,
            expected_source_agent_revision,
            target_agent_id,
            target_session_id,
            target_principal,
            expected_target_revision,
            expected_coordination,
            event_id,
            observed_at_ms,
        } => {
            let activity_id = decode_activity_id(activity_id, "handoff activity id")?;
            let agent_id = decode_agent_id(agent_id, "handoff source agent id")?;
            let actor = ActivityCoordinatorActor::new(
                workspace_id,
                activity_id,
                agent_id,
                decode_coordinator_revision(expected_coordinator_revision)?,
                principal,
                session_id,
            );
            AgentDepartureCommand::Handoff(Box::new(AgentHandoff::new(
                actor,
                decode_agent_revision(expected_source_agent_revision)?,
                decode_agent_id(target_agent_id, "handoff target agent id")?,
                decode_session_id(target_session_id, "handoff target session id")?,
                decode_principal(&target_principal)?,
                decode_agent_revision(expected_target_revision)?,
                decode_coordination_snapshot(expected_coordination)?,
                AgentEventId::from_uuid(require_id(event_id, "handoff event id")?),
                decode_timestamp(observed_at_ms)?,
            )))
        }
    };
    AgentDepartureReconciliationRequest::new(
        require_id(value.request_id, "departure reconciliation request id")?,
        command,
        session_id,
        principal,
        identity_digest,
    )
    .map_err(|_| ForgeError::invalid_input("agent departure reconciliation is invalid"))
}

fn decode_coordination_snapshot(
    value: CoordinationSnapshotDto,
) -> Result<CoordinationSnapshot, ForgeError> {
    let goal = value
        .goal
        .map(|goal| {
            Ok(GoalAttribution::new(
                GoalId::from_uuid(require_id(goal.goal_id, "coordination goal id")?),
                GoalRevision::new(goal.expected_revision).map_err(|_| {
                    ForgeError::invalid_input("coordination goal revision is invalid")
                })?,
            ))
        })
        .transpose()?;
    let dag_revision = value
        .dag_revision
        .map(|revision| {
            DagRevisionNumber::new(revision)
                .map_err(|_| ForgeError::invalid_input("coordination DAG revision is invalid"))
        })
        .transpose()?;
    let dag_head_revision = value
        .dag_head_revision
        .map(|revision| {
            DagHeadRevision::new(revision)
                .map_err(|_| ForgeError::invalid_input("coordination DAG head revision is invalid"))
        })
        .transpose()?;
    let node = value
        .node
        .map(|node| {
            Ok(AgentFocusNode::new(
                DagNodeId::from_uuid(require_id(node.node_id, "coordination node id")?),
                DagNodeRevision::new(node.expected_revision).map_err(|_| {
                    ForgeError::invalid_input("coordination node revision is invalid")
                })?,
            ))
        })
        .transpose()?;
    CoordinationSnapshot::new(goal, dag_revision, dag_head_revision, node)
        .map_err(|_| ForgeError::invalid_input("coordination snapshot is invalid"))
}

fn decode_transport(value: TransportDto) -> AgentTransportKind {
    match value {
        TransportDto::Retired => AgentTransportKind::Retired,
        TransportDto::Stdio => AgentTransportKind::Stdio,
        TransportDto::StreamableHttp => AgentTransportKind::StreamableHttp,
        TransportDto::Other => AgentTransportKind::Other,
    }
}

fn decode_freeze_revision(value: i64) -> Result<u64, ForgeError> {
    if !(1..=MAX_FREEZE_REVISION).contains(&value) {
        return Err(ForgeError::invalid_input(
            "freeze revision must be within 1..=i64::MAX",
        ));
    }
    u64::try_from(value).map_err(|_| ForgeError::invalid_input("freeze revision is invalid"))
}

fn decode_activity_id(value: Uuid, label: &'static str) -> Result<ActivityId, ForgeError> {
    Ok(ActivityId::from_uuid(require_id(value, label)?))
}

fn decode_agent_id(value: Uuid, label: &'static str) -> Result<AgentInstanceId, ForgeError> {
    Ok(AgentInstanceId::from_uuid(require_id(value, label)?))
}

fn decode_session_id(value: Uuid, label: &'static str) -> Result<AgentSessionId, ForgeError> {
    Ok(AgentSessionId::from_uuid(require_id(value, label)?))
}

fn decode_agent_revision(value: i64) -> Result<AgentInstanceRevision, ForgeError> {
    AgentInstanceRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("agent revision is invalid"))
}

fn decode_coordinator_revision(value: i64) -> Result<ActivityCoordinatorRevision, ForgeError> {
    ActivityCoordinatorRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("coordinator revision is invalid"))
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, ForgeError> {
    TimestampMillis::new(value).map_err(|_| ForgeError::invalid_input("timestamp is invalid"))
}

fn decode_digest(value: &str, label: &'static str) -> Result<[u8; DIGEST_BYTES], ForgeError> {
    if value.len() != DIGEST_BYTES * 2
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be canonical lowercase 64-character hex"
        )));
    }
    let mut digest = [0_u8; DIGEST_BYTES];
    let pairs = value.as_bytes().as_chunks::<2>().0;
    for (index, pair) in pairs.iter().enumerate() {
        let high = hex_nibble(pair[0]);
        let low = hex_nibble(pair[1]);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(ForgeError::invalid_input(format!("{label} is invalid")));
        };
        digest[index] = (high << 4) | low;
    }
    if digest.iter().all(|byte| *byte == 0) {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be non-zero"
        )));
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn require_id(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}

/// Execute one parsed lifecycle command through the existing control facade.
/// Trusted identity comparison happens before the first control call.
pub(super) fn execute(
    client: &ForgeControlClient,
    trusted_issuer: OrchestrationIssuerId,
    trusted_destination: Uuid,
    command: &BindingLifecycleCommand,
) -> ValueResult {
    if trusted_issuer.into_uuid().is_nil()
        || trusted_destination.is_nil()
        || command.issuer_id != trusted_issuer
        || command.destination_id != trusted_destination
    {
        return Err(ForgeError::auth_failed());
    }
    execute_request(client, trusted_destination, command)
}

fn execute_request(
    client: &ForgeControlClient,
    trusted_destination: Uuid,
    command: &BindingLifecycleCommand,
) -> ValueResult {
    match &command.request {
        BindingLifecycleRequest::AgentOperationsDelegate {
            reference,
            manifest_digest,
            observed_at,
        } => execute_delegate(
            client,
            &command.scope,
            trusted_destination,
            *reference,
            *manifest_digest,
            *observed_at,
        ),
        BindingLifecycleRequest::AgentOperationsDelegationGet { reference } => {
            execute_delegation_get(client, &command.scope, trusted_destination, *reference)
        }
        BindingLifecycleRequest::AgentBindingReserve {
            reference,
            reservation,
            observed_at,
        } => execute_reserve(
            client,
            &command.scope,
            trusted_destination,
            *reference,
            reservation,
            *observed_at,
        ),
        BindingLifecycleRequest::AgentBindingReservationGet {
            request_id,
            session_id,
            principal,
        } => execute_reservation_get(
            client,
            &command.scope,
            trusted_destination,
            *request_id,
            *session_id,
            *principal,
        ),
        BindingLifecycleRequest::AgentBindingActivate {
            reference,
            activation,
            session_id,
            principal,
            observed_at,
        } => execute_activate(
            client,
            &command.scope,
            trusted_destination,
            *reference,
            activation,
            (*session_id, *principal),
            *observed_at,
        ),
        BindingLifecycleRequest::AgentBindingActivationGet {
            request_id,
            session_id,
            principal,
        } => execute_activation_get(
            client,
            &command.scope,
            trusted_destination,
            *request_id,
            *session_id,
            *principal,
        ),
        BindingLifecycleRequest::AgentSessionReconcile { reconciliation } => {
            execute_session_reconcile(client, &command.scope, trusted_destination, *reconciliation)
        }
        BindingLifecycleRequest::AgentSessionReconciliationGet {
            request_id,
            session_id,
            principal,
        } => execute_session_reconciliation_get(
            client,
            &command.scope,
            trusted_destination,
            *request_id,
            *session_id,
            *principal,
        ),
        BindingLifecycleRequest::AgentDepartureReconcile { reconciliation } => {
            execute_departure_reconcile(client, &command.scope, trusted_destination, reconciliation)
        }
        BindingLifecycleRequest::AgentDepartureReconciliationGet {
            request_id,
            session_id,
            principal,
        } => execute_departure_reconciliation_get(
            client,
            &command.scope,
            trusted_destination,
            *request_id,
            *session_id,
            *principal,
        ),
    }
}

fn execute_delegate(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    reference: AgentOperationsFreezeReference,
    manifest_digest: [u8; DIGEST_BYTES],
    observed_at: TimestampMillis,
) -> ValueResult {
    let receipt = client
        .delegate_agent_operations_ref(AgentOperationsDelegateReferenceRequest {
            scope: scope.clone(),
            reference,
            manifest_digest,
            observed_at,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    project_delegation(scope, destination_id, &receipt)
}

fn execute_delegation_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    reference: AgentOperationsDelegationReference,
) -> ValueResult {
    let receipt = client
        .agent_operations_delegation(AgentOperationsDelegationReadRequest {
            scope: scope.clone(),
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some(receipt) = receipt else {
        return not_found(scope, destination_id);
    };
    verify_delegation_reference(&receipt, reference, scope, destination_id)?;
    project_delegation(scope, destination_id, &receipt)
}

fn execute_reserve(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    reference: AgentOperationsFreezeReference,
    reservation: &AgentBindingReservationRequest,
    observed_at: TimestampMillis,
) -> ValueResult {
    let receipt = client
        .reserve_agent_binding_ref(AgentBindingReserveReferenceRequest {
            scope: scope.clone(),
            reference,
            reservation: reservation.clone(),
            observed_at,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    project_reservation(scope, destination_id, &receipt)
}

fn execute_reservation_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> ValueResult {
    let receipt = client
        .agent_binding_reservation(AgentBindingReservationReadRequest {
            scope: scope.clone(),
            request_id,
            session_id,
            principal,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    match receipt {
        Some(receipt) => project_reservation(scope, destination_id, &receipt),
        None => not_found(scope, destination_id),
    }
}

fn execute_activate(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    reference: AgentOperationsDelegationReference,
    activation: &AgentBindingActivationRequest,
    (session_id, principal): (AgentSessionId, AuthenticatedPrincipal),
    observed_at: TimestampMillis,
) -> ValueResult {
    let receipt = client
        .activate_agent_binding_ref(AgentBindingActivateReferenceRequest {
            scope: scope.clone(),
            reference,
            activation: activation.clone(),
            session_id,
            principal,
            observed_at,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    project_activation(scope, destination_id, &receipt)
}

fn execute_activation_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> ValueResult {
    let receipt = client
        .agent_binding_activation(forge_control::AgentBindingActivationReadRequest {
            scope: scope.clone(),
            request_id,
            session_id,
            principal,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    match receipt {
        Some(receipt) => project_activation(scope, destination_id, &receipt),
        None => not_found(scope, destination_id),
    }
}

fn execute_session_reconcile(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    reconciliation: AgentSessionReconciliationRequest,
) -> ValueResult {
    let receipt = client
        .reconcile_agent_session_destination(AgentSessionReconcileDestinationRequest {
            request: AgentSessionReconcileRequest {
                scope: scope.clone(),
                reconciliation,
            },
            destination_id,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    project_session_reconciliation(scope, destination_id, &receipt)
}

fn execute_session_reconciliation_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> ValueResult {
    let receipt = client
        .agent_session_reconciliation(AgentSessionReconcileReadRequest {
            scope: scope.clone(),
            request_id,
            session_id,
            principal,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    match receipt {
        Some(receipt) => project_session_reconciliation(scope, destination_id, &receipt),
        None => not_found(scope, destination_id),
    }
}

fn execute_departure_reconcile(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    reconciliation: &AgentDepartureReconciliationRequest,
) -> ValueResult {
    let receipt = client
        .reconcile_agent_departure_destination(AgentDepartureReconcileDestinationRequest {
            request: AgentDepartureReconcileRequest {
                scope: scope.clone(),
                reconciliation: reconciliation.clone(),
            },
            destination_id,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    project_departure_reconciliation(scope, destination_id, &receipt)
}

fn execute_departure_reconciliation_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    request_id: Uuid,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> ValueResult {
    let receipt = client
        .agent_departure_reconciliation(AgentDepartureReconcileReadRequest {
            scope: scope.clone(),
            request_id,
            session_id,
            principal,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    match receipt {
        Some(receipt) => project_departure_reconciliation(scope, destination_id, &receipt),
        None => not_found(scope, destination_id),
    }
}

fn not_found(scope: &ResolvedWorkspaceScope, destination_id: Uuid) -> ValueResult {
    Ok(Value::Object(base_projection(
        scope,
        destination_id,
        false,
    )?))
}

fn base_projection(
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    found: bool,
) -> Result<Map<String, Value>, ForgeError> {
    let mut result = Map::new();
    result.insert("scope".to_owned(), super::scope_json(scope)?);
    result.insert("destination_id".to_owned(), json!(destination_id));
    result.insert("found".to_owned(), json!(found));
    result.insert("retry_authorized".to_owned(), json!(false));
    result.insert("request_equivalence_proven".to_owned(), json!(false));
    Ok(result)
}

fn project_delegation(
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    receipt: &AgentOperationsDelegation,
) -> ValueResult {
    ensure_workspace(scope, receipt.workspace_id())?;
    ensure_destination(receipt.destination_id(), destination_id)?;
    let freeze = receipt.freeze();
    let mut result = base_projection(scope, destination_id, true)?;
    result.insert(
        "workspace_id".to_owned(),
        json!(receipt.workspace_id().into_uuid()),
    );
    result.insert("migration_id".to_owned(), json!(receipt.migration_id()));
    result.insert(
        "freeze_destination_id".to_owned(),
        json!(freeze.destination_id()),
    );
    result.insert("freeze_revision".to_owned(), json!(freeze.revision()));
    result.insert(
        "freeze_state".to_owned(),
        json!(freeze_state(freeze.state())),
    );
    result.insert(
        "freeze_created_at_ms".to_owned(),
        json!(freeze.created_at().get()),
    );
    result.insert(
        "freeze_updated_at_ms".to_owned(),
        json!(freeze.updated_at().get()),
    );
    result.insert(
        "manifest_digest".to_owned(),
        json!(encode_digest(receipt.manifest_digest())),
    );
    result.insert(
        "delegated_at_ms".to_owned(),
        json!(receipt.delegated_at().get()),
    );
    Ok(Value::Object(result))
}

fn project_reservation(
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    receipt: &AgentBindingReservation,
) -> ValueResult {
    ensure_workspace(scope, receipt.workspace_id())?;
    ensure_destination(receipt.destination_id(), destination_id)?;
    let request = receipt.request();
    let mut result = base_projection(scope, destination_id, true)?;
    result.insert(
        "workspace_id".to_owned(),
        json!(receipt.workspace_id().into_uuid()),
    );
    result.insert("migration_id".to_owned(), json!(receipt.migration_id()));
    result.insert(
        "freeze_revision".to_owned(),
        json!(receipt.freeze_revision()),
    );
    result.insert("request_id".to_owned(), json!(request.request_id()));
    result.insert(
        "activity_id".to_owned(),
        json!(request.activity_id().into_uuid()),
    );
    result.insert("agent_id".to_owned(), json!(request.agent_id().into_uuid()));
    result.insert(
        "session_id".to_owned(),
        json!(request.session_id().into_uuid()),
    );
    result.insert("principal".to_owned(), principal_json(request.principal()));
    result.insert(
        "requested_at_ms".to_owned(),
        json!(request.requested_at().get()),
    );
    result.insert(
        "reserved_at_ms".to_owned(),
        json!(receipt.reserved_at().get()),
    );
    Ok(Value::Object(result))
}

fn project_activation(
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    receipt: &AgentBindingActivation,
) -> ValueResult {
    ensure_workspace(scope, receipt.workspace_id())?;
    ensure_destination(receipt.reservation().destination_id(), destination_id)?;
    let reservation = receipt.reservation();
    let request = reservation.request();
    let mut result = base_projection(scope, destination_id, true)?;
    result.insert(
        "workspace_id".to_owned(),
        json!(receipt.workspace_id().into_uuid()),
    );
    result.insert("migration_id".to_owned(), json!(reservation.migration_id()));
    result.insert(
        "freeze_revision".to_owned(),
        json!(reservation.freeze_revision()),
    );
    result.insert("request_id".to_owned(), json!(receipt.request_id()));
    result.insert(
        "activity_id".to_owned(),
        json!(request.activity_id().into_uuid()),
    );
    result.insert("agent_id".to_owned(), json!(request.agent_id().into_uuid()));
    result.insert(
        "session_id".to_owned(),
        json!(request.session_id().into_uuid()),
    );
    result.insert("principal".to_owned(), principal_json(request.principal()));
    result.insert(
        "requested_at_ms".to_owned(),
        json!(request.requested_at().get()),
    );
    result.insert(
        "reserved_at_ms".to_owned(),
        json!(reservation.reserved_at().get()),
    );
    result.insert(
        "membership_digest".to_owned(),
        json!(encode_digest(receipt.membership_digest())),
    );
    result.insert(
        "display_name".to_owned(),
        json!(receipt.display_name().as_str()),
    );
    result.insert(
        "declared_role".to_owned(),
        json!(receipt.declared_role().as_str()),
    );
    result.insert(
        "transport".to_owned(),
        json!(transport_name(receipt.transport())),
    );
    result.insert(
        "activated_at_ms".to_owned(),
        json!(receipt.activated_at().get()),
    );
    Ok(Value::Object(result))
}

fn project_session_reconciliation(
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    receipt: &AgentSessionReconciliation,
) -> ValueResult {
    ensure_workspace(scope, receipt.workspace_id())?;
    ensure_destination(receipt.destination_id(), destination_id)?;
    let mut result = base_projection(scope, destination_id, true)?;
    result.insert(
        "workspace_id".to_owned(),
        json!(receipt.workspace_id().into_uuid()),
    );
    result.insert("migration_id".to_owned(), json!(receipt.migration_id()));
    result.insert("request_id".to_owned(), json!(receipt.request_id()));
    result.insert(
        "activity_id".to_owned(),
        json!(receipt.activity_id().into_uuid()),
    );
    result.insert("agent_id".to_owned(), json!(receipt.agent_id().into_uuid()));
    result.insert(
        "session_id".to_owned(),
        json!(receipt.session_id().into_uuid()),
    );
    result.insert(
        "expected_agent_revision".to_owned(),
        json!(receipt.expected_agent_revision().get()),
    );
    result.insert(
        "result_agent_revision".to_owned(),
        json!(receipt.result_agent_revision().get()),
    );
    result.insert(
        "reconciled_at_ms".to_owned(),
        json!(receipt.reconciled_at().get()),
    );
    Ok(Value::Object(result))
}

fn project_departure_reconciliation(
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
    receipt: &AgentDepartureReconciliation,
) -> ValueResult {
    ensure_workspace(scope, receipt.workspace_id())?;
    ensure_destination(receipt.destination_id(), destination_id)?;
    let mut result = base_projection(scope, destination_id, true)?;
    result.insert(
        "workspace_id".to_owned(),
        json!(receipt.workspace_id().into_uuid()),
    );
    result.insert("migration_id".to_owned(), json!(receipt.migration_id()));
    result.insert("request_id".to_owned(), json!(receipt.request_id()));
    result.insert(
        "activity_id".to_owned(),
        json!(receipt.activity_id().into_uuid()),
    );
    result.insert("kind".to_owned(), json!(departure_kind(receipt.kind())));
    result.insert("agent_id".to_owned(), json!(receipt.agent_id().into_uuid()));
    result.insert(
        "session_id".to_owned(),
        json!(receipt.session_id().into_uuid()),
    );
    result.insert(
        "expected_agent_revision".to_owned(),
        json!(receipt.expected_agent_revision().get()),
    );
    result.insert(
        "result_agent_revision".to_owned(),
        json!(receipt.result_agent_revision().get()),
    );
    result.insert(
        "target_agent_id".to_owned(),
        json!(receipt.target_agent_id().map(AgentInstanceId::into_uuid)),
    );
    result.insert(
        "target_session_id".to_owned(),
        json!(receipt.target_session_id().map(AgentSessionId::into_uuid)),
    );
    result.insert(
        "result_coordinator_revision".to_owned(),
        json!(
            receipt
                .result_coordinator_revision()
                .map(ActivityCoordinatorRevision::get)
        ),
    );
    result.insert(
        "identity_digest".to_owned(),
        json!(encode_digest(receipt.identity_digest())),
    );
    result.insert(
        "reconciled_at_ms".to_owned(),
        json!(receipt.reconciled_at().get()),
    );
    Ok(Value::Object(result))
}

fn verify_delegation_reference(
    receipt: &AgentOperationsDelegation,
    reference: AgentOperationsDelegationReference,
    scope: &ResolvedWorkspaceScope,
    destination_id: Uuid,
) -> Result<(), ForgeError> {
    ensure_workspace(scope, receipt.workspace_id())?;
    ensure_destination(receipt.destination_id(), destination_id)?;
    let freeze = receipt.freeze();
    if freeze.migration_id() != reference.freeze.migration_id
        || freeze.destination_id() != reference.freeze.destination_id
        || freeze.revision() != reference.freeze.expected_revision
        || receipt.manifest_digest() != reference.manifest_digest
    {
        return Err(ForgeError::resync_required(
            "delegation readback does not match the requested identity",
        ));
    }
    Ok(())
}

fn ensure_workspace(
    scope: &ResolvedWorkspaceScope,
    workspace_id: WorkspaceId,
) -> Result<(), ForgeError> {
    if scope.workspace_id() != workspace_id {
        return Err(ForgeError::resync_required(
            "binding lifecycle readback changed Workspace scope",
        ));
    }
    Ok(())
}

fn ensure_destination(actual: Uuid, expected: Uuid) -> Result<(), ForgeError> {
    if actual != expected {
        return Err(ForgeError::resync_required(
            "binding lifecycle readback changed destination scope",
        ));
    }
    Ok(())
}

fn freeze_state(value: AgentOperationsFreezeState) -> &'static str {
    match value {
        AgentOperationsFreezeState::Frozen => "frozen",
        AgentOperationsFreezeState::Released => "released",
    }
}

fn departure_kind(value: AgentDepartureKind) -> &'static str {
    match value {
        AgentDepartureKind::Detach => "detach",
        AgentDepartureKind::Handoff => "handoff",
    }
}

fn transport_name(value: AgentTransportKind) -> &'static str {
    match value {
        AgentTransportKind::Retired => "mcp",
        AgentTransportKind::Stdio => "stdio",
        AgentTransportKind::StreamableHttp => "streamable_http",
        AgentTransportKind::Other => "other",
    }
}

fn principal_json(value: AuthenticatedPrincipal) -> Value {
    match value {
        AuthenticatedPrincipal::TrustedStdio => json!({ "kind": "trusted_stdio" }),
        AuthenticatedPrincipal::DirectToken(id) => json!({
            "kind": "direct_token",
            "token_id": id.into_uuid(),
        }),
        AuthenticatedPrincipal::OAuthGrant(id) => json!({
            "kind": "oauth_grant",
            "grant_id": id.into_uuid(),
        }),
    }
}

fn encode_digest(value: [u8; DIGEST_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(DIGEST_BYTES * 2);
    for byte in value {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use serde_json::json;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn scope_json() -> Value {
        json!({
            "workspace_id": id(1),
            "workspace_revision": 1,
            "locator": {
                "location_id": id(2),
                "expected_revision": 1,
                "relative_root": "."
            }
        })
    }

    fn common() -> Value {
        json!({
            "scope": scope_json(),
            "issuer_id": id(3),
            "destination_id": id(4)
        })
    }

    #[test]
    fn parser_rejects_unknown_fields_and_noncanonical_digests() {
        let mut payload = common();
        payload["reference"] = json!({
            "migration_id": id(5),
            "expected_freeze_revision": 1
        });
        payload["manifest_digest"] = json!("AA".repeat(32));
        payload["observed_at_ms"] = json!(10);
        assert!(parse(CommandOp::AgentOperationsDelegate, &payload).is_err());

        payload["manifest_digest"] = json!("aa".repeat(32));
        payload["unexpected"] = json!(true);
        assert!(parse(CommandOp::AgentOperationsDelegate, &payload).is_err());
    }

    #[test]
    fn parser_rejects_nil_and_out_of_range_reference_ids() {
        let mut payload = common();
        payload["reference"] = json!({
            "migration_id": Uuid::nil(),
            "expected_freeze_revision": 0
        });
        payload["manifest_digest"] = json!("aa".repeat(32));
        payload["observed_at_ms"] = json!(10);
        assert!(parse(CommandOp::AgentOperationsDelegate, &payload).is_err());

        payload["reference"] = json!({
            "migration_id": id(5),
            "expected_freeze_revision": i64::MAX
        });
        assert!(parse(CommandOp::AgentOperationsDelegate, &payload).is_ok());
    }

    #[test]
    fn readback_hints_cover_mutations_only_and_retain_exact_ids() -> Result<(), Box<dyn Error>> {
        let mut payload = common();
        payload["reference"] = json!({
            "migration_id": id(5),
            "expected_freeze_revision": 7
        });
        payload["manifest_digest"] = json!("ab".repeat(32));
        payload["observed_at_ms"] = json!(10);
        let command = parse(CommandOp::AgentOperationsDelegate, &payload)?;
        assert_eq!(command.op(), CommandOp::AgentOperationsDelegate);
        assert_eq!(
            readback_hint(&command),
            Some(crate::error::ReadbackHint::AgentDelegation {
                workspace_id: id(1),
                migration_id: id(5),
                destination_id: id(4),
                expected_freeze_revision: 7,
                manifest_digest: "ab".repeat(32),
            })
        );

        let mut read_payload = common();
        read_payload["reference"] = json!({
            "migration_id": id(5),
            "expected_freeze_revision": 7,
            "manifest_digest": "ab".repeat(32)
        });
        let read_command = parse(CommandOp::AgentOperationsDelegationGet, &read_payload)?;
        assert_eq!(readback_hint(&read_command), None);
        Ok(())
    }

    #[test]
    fn projection_metadata_is_readback_only() -> Result<(), Box<dyn Error>> {
        let scope = forge_control::ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(id(1)),
            forge_domain::WorkspaceRevision::new(1)?,
            forge_control::WorkspaceLocator::new(
                forge_domain::LocationId::from_uuid(id(2)),
                forge_domain::LocationRevision::new(1)?,
                std::path::Path::new("."),
            )?,
        );
        let projection = base_projection(&scope, id(4), false)?;
        assert_eq!(projection.get("found"), Some(&json!(false)));
        assert_eq!(projection.get("retry_authorized"), Some(&json!(false)));
        assert_eq!(
            projection.get("request_equivalence_proven"),
            Some(&json!(false))
        );
        assert!(!projection.contains_key("grant"));
        Ok(())
    }
}
