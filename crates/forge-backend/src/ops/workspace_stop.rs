//! Authenticated Workspace-stop wire decoding and owner dispatch.
//!
//! This adapter carries a complete service identity and propagated logical
//! session into the existing `ApprovalCoordinator` owner.  It does not mint a
//! permit, attach a session, or interpret a native cancellation count as
//! durable settlement.  The owner returns a Pending execution/authority pair;
//! the native result is projected beside that pair so a failed native request
//! cannot hide the durable readback identity.

use forge_control::{
    ForgeApprovalCoordinatorError, WorkspaceStopIntent, WorkspaceStopServiceIdentity,
};
use forge_domain::{AgentSessionId, ForgeBackendId, OrchestrationIssuerId, RuntimeInstanceId};
use forge_persistence::{
    AuthorityStopReceipt, AuthorityStopTargetKind, ExecutionStopRecord, ExecutionStopStatus,
    ExecutionStopTargetStatus,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{BridgeClients, CommandOp, PrincipalDto, ScopeDto, decode_principal, decode_scope};
use crate::error::{ForgeError, ReadbackHint};

/// Whether a Workspace-stop command mutates the owner queue or only observes
/// the exact retained durable identity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceStopKind {
    Stop,
    Get,
}

/// One strictly decoded Workspace-stop request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStopCommand {
    kind: WorkspaceStopKind,
    intent: WorkspaceStopIntent,
}

impl WorkspaceStopCommand {
    /// Return the closed operation represented by this validated command.
    pub(crate) const fn op(&self) -> CommandOp {
        match self.kind {
            WorkspaceStopKind::Stop => CommandOp::WorkspaceStop,
            WorkspaceStopKind::Get => CommandOp::WorkspaceStopGet,
        }
    }

    pub(crate) const fn service(&self) -> &WorkspaceStopServiceIdentity {
        self.intent.service()
    }

    pub(crate) const fn stop_id(&self) -> Uuid {
        self.intent.stop_id()
    }

    pub(crate) const fn durable_request_id(&self) -> Uuid {
        self.intent.request_id()
    }
}

type WorkspaceStopReadback = Option<(ExecutionStopRecord, AuthorityStopReceipt)>;

/// One admitted owner request retained across the HTTP response boundary.
///
/// The approval worker owns the actual operation.  This enum deliberately
/// stores its pending receiver rather than a native fallback or a second
/// command queue, so a dropped HTTP observer cannot release the owner permit
/// before the coordinator has delivered its result.
#[must_use]
#[derive(Debug)]
pub(crate) enum PendingWorkspaceStop {
    Stop(forge_control::PendingApproval<forge_control::OwnedWorkspaceExecutionStopObservation>),
    Get(forge_control::PendingApproval<WorkspaceStopReadback>),
}

impl PendingWorkspaceStop {
    /// Wait for the already admitted owner response and project its result.
    pub(crate) fn recv(self, command: &WorkspaceStopCommand) -> Result<Value, ForgeError> {
        match self {
            Self::Stop(pending) => pending
                .recv()
                .map(|observation| observation_json(command, &observation))
                .map_err(|error| map_approval_error(command, &error)),
            Self::Get(pending) => pending
                .recv()
                .map(|observation| readback_json(command, observation.as_ref()))
                .map_err(|error| map_approval_error(command, &error)),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    scope: ScopeDto,
    stop_id: Uuid,
    durable_request_id: Uuid,
    service: ServiceDto,
    actor: ActorDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDto {
    backend_id: Uuid,
    issuer: Uuid,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorDto {
    session_id: Uuid,
    principal: PrincipalDto,
}

/// Decode one of the two Workspace-stop operation payloads.
pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<WorkspaceStopCommand, ForgeError> {
    let kind = match operation {
        CommandOp::WorkspaceStop => WorkspaceStopKind::Stop,
        CommandOp::WorkspaceStopGet => WorkspaceStopKind::Get,
        _ => {
            return Err(ForgeError::invalid_input(
                "operation is not a Workspace stop operation",
            ));
        }
    };
    let body: Body = super::parse_body(payload, operation.as_str())?;
    require_non_nil(body.scope.workspace_id, "stop workspace id")?;
    require_non_nil(body.scope.locator.location_id, "stop location id")?;
    let stop_id = require_non_nil(body.stop_id, "stop id")?;
    let durable_request_id = require_non_nil(body.durable_request_id, "durable stop request id")?;
    let backend_id = ForgeBackendId::from_uuid(require_non_nil(
        body.service.backend_id,
        "stop service backend id",
    )?);
    let issuer = OrchestrationIssuerId::from_uuid(require_non_nil(
        body.service.issuer,
        "stop service issuer",
    )?);
    let destination_id = require_non_nil(body.service.destination_id, "stop destination id")?;
    let runtime_instance_id = RuntimeInstanceId::from_uuid(require_non_nil(
        body.service.runtime_instance_id,
        "stop service boot identity",
    )?);
    let session_id =
        AgentSessionId::from_uuid(require_non_nil(body.actor.session_id, "stop session id")?);
    let scope = decode_scope(&body.scope)?;
    let principal = decode_principal(&body.actor.principal)?;
    let service =
        WorkspaceStopServiceIdentity::new(backend_id, issuer, destination_id, runtime_instance_id)
            .map_err(|error| ForgeError::from_control_view(&error.view()))?;
    let intent = WorkspaceStopIntent::new(
        scope,
        stop_id,
        durable_request_id,
        service,
        session_id,
        principal,
    )
    .map_err(|error| ForgeError::from_control_view(&error.view()))?;
    Ok(WorkspaceStopCommand { kind, intent })
}

fn require_non_nil(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be non-nil"
        )));
    }
    Ok(value)
}

/// Build readback guidance from the canonical Control-owned intent digest.
pub(crate) fn readback_hint(command: &WorkspaceStopCommand) -> ReadbackHint {
    let intent = &command.intent;
    ReadbackHint::WorkspaceStop {
        workspace_id: intent.scope().workspace_id().into_uuid(),
        stop_id: intent.stop_id(),
        durable_request_id: intent.request_id(),
        request_digest: encode_hex(intent.request_digest()),
        runtime_instance_id: intent.service().runtime_instance_id().into_uuid(),
    }
}

/// Submit one stop or readback request to the bounded `ApprovalCoordinator`
/// owner without waiting on its worker.  The configured service identity is
/// checked before the nonblocking queue send, so an untrusted echo cannot
/// consume owner capacity or reach session/permit admission.
pub(crate) fn submit(
    approval: &forge_control::ForgeApprovalCoordinatorClient,
    expected_service: &WorkspaceStopServiceIdentity,
    command: &WorkspaceStopCommand,
) -> Result<PendingWorkspaceStop, ForgeError> {
    if command.service() != expected_service {
        return Err(ForgeError::auth_failed());
    }
    let intent = command.intent.clone();
    match command.kind {
        WorkspaceStopKind::Stop => approval
            .submit_stop_workspace_intent(intent)
            .map(PendingWorkspaceStop::Stop)
            .map_err(|error| map_approval_error(command, &error)),
        WorkspaceStopKind::Get => approval
            .submit_observe_workspace_stop_intent(intent)
            .map(PendingWorkspaceStop::Get)
            .map_err(|error| map_approval_error(command, &error)),
    }
}

/// Dispatch through the configured owner and project the exact Pending pair.
pub(super) fn execute(
    clients: &BridgeClients,
    command: &WorkspaceStopCommand,
) -> Result<Value, ForgeError> {
    let expected_service = WorkspaceStopServiceIdentity::new(
        clients.backend_id,
        clients.issuer,
        clients.destination_id,
        clients.runtime_instance_id,
    )
    .map_err(|error| ForgeError::from_control_view(&error.view()))?;
    submit(&clients.approval, &expected_service, command)?.recv(command)
}

pub(crate) fn map_approval_error(
    command: &WorkspaceStopCommand,
    error: &ForgeApprovalCoordinatorError,
) -> ForgeError {
    use ForgeApprovalCoordinatorError as ApprovalError;

    let mapped = match error {
        ApprovalError::WorkspaceStopValidation(validation) => {
            let view = validation.view();
            if matches!(
                view.code(),
                forge_control::ControlErrorCode::AgentSessionClosed
                    | forge_control::ControlErrorCode::AgentSessionNotFound
            ) {
                ForgeError::auth_failed()
            } else {
                ForgeError::from_control_view(&forge_control::ControlErrorView::not_admitted(
                    view.code(),
                ))
            }
        }
        ApprovalError::AttributionMismatch
        | ApprovalError::Execution(
            forge_control::ForgeExecutionCoordinatorError::AttributionMismatch,
        ) => ForgeError::auth_failed(),
        ApprovalError::CleanupIncomplete
        | ApprovalError::Clock
        | ApprovalError::InternalInvariant => ForgeError::from_control_view(
            &forge_control::ControlErrorView::not_admitted(error.view().code()),
        ),
        ApprovalError::ApprovalCleanupAndExecution { .. } => {
            ForgeError::from_admitted_execution_view(&error.view())
        }
        ApprovalError::Execution(forge_control::ForgeExecutionCoordinatorError::QueueFull) => {
            ForgeError::capacity_exceeded("Workspace stop native owner queue")
        }
        ApprovalError::Execution(forge_control::ForgeExecutionCoordinatorError::Closed) => {
            ForgeError::from_control_view(&forge_control::ControlErrorView::not_admitted(
                forge_control::ControlErrorCode::WorkerClosed,
            ))
        }
        ApprovalError::Control(forge_control::ControlClientError::QueueFull) => {
            ForgeError::capacity_exceeded("Workspace stop provider queue")
        }
        ApprovalError::Control(
            closed @ (forge_control::ControlClientError::WorkerClosed
            | forge_control::ControlClientError::WorkerShuttingDown),
        ) => ForgeError::from_control_client_error(closed),
        ApprovalError::Execution(forge_control::ForgeExecutionCoordinatorError::Control(
            forge_control::ControlClientError::QueueFull,
        )) => ForgeError::capacity_exceeded("Workspace stop preparation queue"),
        ApprovalError::Execution(forge_control::ForgeExecutionCoordinatorError::Control(
            preparation @ (forge_control::ControlClientError::WorkerClosed
            | forge_control::ControlClientError::WorkerShuttingDown),
        )) => ForgeError::from_control_client_error(preparation),
        // These outcomes are proven before the approval request enters the
        // owner queue and therefore carry no admitted-effect readback.
        ApprovalError::QueueFull | ApprovalError::Closed => {
            ForgeError::from_control_view(&error.view())
        }
        // The owner accepted the command, but its response or an inner owner
        // dispatch failed after admission.  Preserve uncertainty and the
        // exact stop identity for durable readback.
        ApprovalError::ResponseDropped
        | ApprovalError::AlreadyShutdown
        | ApprovalError::ThreadPanicked
        | ApprovalError::SpawnThread(_)
        | ApprovalError::Control(_)
        | ApprovalError::Execution(_) => ForgeError::from_admitted_execution_view(&error.view()),
        // Semantic owner rejections have an explicit redacted control view;
        // they do not become a fabricated Pending success.
        _ => ForgeError::from_control_view(&error.view()),
    };
    if mapped.code() == crate::error::ErrorCode::UnknownOutcome {
        mapped.with_readback(Some(readback_hint(command)))
    } else {
        mapped
    }
}

fn observation_json(
    command: &WorkspaceStopCommand,
    observation: &forge_control::OwnedWorkspaceExecutionStopObservation,
) -> Value {
    let mut result = readback_json_with_native(
        command,
        Some((observation.record(), observation.authority())),
        observation.native_result(),
    );
    if observation.native_result().is_none() {
        result["native"] = json!({ "status": "not_attempted", "owner_operation_attempted": false,
            "cancellation_requested": false, "count": Value::Null, "error": Value::Null });
    }
    result["owner_quiescence"] = match observation.native_quiescence() {
        Ok(Some(proof)) => {
            json!({ "status": "observed", "workspace_id": proof.workspace_id().into_uuid() })
        }
        Ok(None) => json!({ "status": "not_observed" }),
        Err(error) => {
            json!({ "status": "unknown", "error": ForgeError::from_admitted_execution_view(&error.view()).with_readback(Some(readback_hint(command))) })
        }
    };
    result
}

fn readback_json(
    command: &WorkspaceStopCommand,
    observation: Option<&(ExecutionStopRecord, AuthorityStopReceipt)>,
) -> Value {
    readback_json_with_native(command, observation.map(|pair| (&pair.0, &pair.1)), None)
}

fn readback_json_with_native(
    command: &WorkspaceStopCommand,
    observation: Option<(&ExecutionStopRecord, &AuthorityStopReceipt)>,
    native: Option<Result<usize, &forge_control::ForgeExecutionCoordinatorError>>,
) -> Value {
    let Some((record, authority)) = observation else {
        return json!({
            "found": false,
            "status": "absent_now",
            "durable_status": "absent_now",
            "stop_id": command.stop_id(),
            "workspace_id": command.intent.scope().workspace_id().into_uuid(),
            "durable_request_id": command.durable_request_id(),
            "native": Value::Null,
            "owner_quiescence": Value::Null,
        });
    };

    let execution = execution_record_json(record);
    let authority = authority_receipt_json(authority);
    let native = native.map_or(Value::Null, |result| native_result_json(command, result));
    json!({
        "found": true,
        "status": execution_stop_status(record.status()),
        "durable_status": execution_stop_status(record.status()),
        "admission_fence_released": record.status() == ExecutionStopStatus::Completed,
        "stop_id": record.stop_id(),
        "workspace_id": record.workspace_id().into_uuid(),
        "durable_request_id": record.request_id(),
        "execution": execution,
        "authority": authority,
        "native": native,
        "owner_quiescence": Value::Null,
    })
}

fn execution_record_json(record: &ExecutionStopRecord) -> Value {
    json!({
        "stop_id": record.stop_id(),
        "workspace_id": record.workspace_id().into_uuid(),
        "durable_request_id": record.request_id(),
        "owner_runtime_instance_id": record.owner_runtime_instance_id().into_uuid(),
        "request_digest": encode_hex(record.request_digest()),
        "binding_digest": encode_hex(record.binding_digest()),
        "target_count": record.target_count(),
        "cohort_digest": encode_hex(record.cohort_digest()),
        "created_at_ms": record.created_at().get(),
        "status": execution_stop_status(record.status()),
        "targets": record.targets().iter().map(execution_target_json).collect::<Vec<_>>(),
    })
}

fn execution_target_json(target: &forge_persistence::ExecutionStopTarget) -> Value {
    json!({
        "ordinal": target.ordinal(),
        "execution_id": target.execution_id().into_uuid(),
        "expected_revision": target.expected_revision().get(),
        "expected_state": super::execution_evidence::execution_state_name(target.expected_state()),
        "request_digest": encode_hex(target.request_digest()),
        "status": execution_target_status(target.status()),
    })
}

fn authority_receipt_json(receipt: &AuthorityStopReceipt) -> Value {
    json!({
        "stop_id": receipt.stop_id(),
        "workspace_id": receipt.workspace_id().into_uuid(),
        "observed_at_ms": receipt.observed_at().get(),
        "target_count": receipt.target_count(),
        "cohort_digest": encode_hex(receipt.cohort_digest()),
        "targets": receipt.targets().iter().map(authority_target_json).collect::<Vec<_>>(),
    })
}

fn authority_target_json(target: &forge_persistence::AuthorityStopTarget) -> Value {
    json!({
        "ordinal": target.ordinal(),
        "kind": authority_target_kind(target.kind()),
        "target_id": target.target_id(),
        "before_revision": target.before_revision(),
        "after_revision": target.after_revision(),
        "before_state": target.before_state(),
        "after_state": target.after_state(),
        "before_digest": encode_hex(target.before_digest()),
        "after_digest": encode_hex(target.after_digest()),
    })
}

fn native_result_json(
    command: &WorkspaceStopCommand,
    result: Result<usize, &forge_control::ForgeExecutionCoordinatorError>,
) -> Value {
    match result {
        Ok(count) => json!({
            "status": if count == 0 {"no_owned_execution"} else {"requested"},
            "owner_operation_attempted": true,
            "cancellation_requested": count > 0,
            "count": count,
            "error": Value::Null,
        }),
        Err(error) => {
            let mapped = ForgeError::from_admitted_execution_view(&error.view())
                .with_readback(Some(readback_hint(command)));
            json!({
                "status": "unknown",
                "owner_operation_attempted": true,
                "cancellation_requested": Value::Null,
                "count": Value::Null,
                "error": mapped,
            })
        }
    }
}

const fn execution_stop_status(status: ExecutionStopStatus) -> &'static str {
    match status {
        ExecutionStopStatus::Pending => "pending",
        ExecutionStopStatus::Completed => "completed",
    }
}

const fn execution_target_status(status: ExecutionStopTargetStatus) -> &'static str {
    match status {
        ExecutionStopTargetStatus::Pending => "pending",
        ExecutionStopTargetStatus::Closed => "closed",
    }
}

const fn authority_target_kind(kind: AuthorityStopTargetKind) -> &'static str {
    match kind {
        AuthorityStopTargetKind::Approval => "approval",
        AuthorityStopTargetKind::Grant => "grant",
        AuthorityStopTargetKind::AutoScope => "auto_scope",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload() -> Value {
        json!({
            "scope": {
                "workspace_id": "00000000-0000-0000-0000-000000000001",
                "workspace_revision": 1,
                "locator": {
                    "location_id": "00000000-0000-0000-0000-000000000002",
                    "expected_revision": 1,
                    "relative_root": "workspace"
                }
            },
            "stop_id": "00000000-0000-0000-0000-000000000003",
            "durable_request_id": "00000000-0000-0000-0000-000000000004",
            "service": {
                "backend_id": "00000000-0000-0000-0000-000000000005",
                "issuer": "00000000-0000-0000-0000-000000000006",
                "destination_id": "00000000-0000-0000-0000-000000000007",
                "runtime_instance_id": "00000000-0000-0000-0000-000000000008"
            },
            "actor": {
                "session_id": "00000000-0000-0000-0000-000000000009",
                "principal": {"kind": "trusted_stdio"}
            }
        })
    }

    #[test]
    fn strict_stop_and_get_payloads_decode_to_distinct_operations() -> Result<(), ForgeError> {
        let stop = parse(CommandOp::WorkspaceStop, &payload())?;
        let get = parse(CommandOp::WorkspaceStopGet, &payload())?;
        assert_eq!(stop.op(), CommandOp::WorkspaceStop);
        assert_eq!(get.op(), CommandOp::WorkspaceStopGet);
        assert_eq!(stop.kind, WorkspaceStopKind::Stop);
        assert_eq!(get.kind, WorkspaceStopKind::Get);
        assert_eq!(readback_hint(&stop), readback_hint(&get));
        Ok(())
    }

    #[test]
    fn unknown_fields_and_nil_identities_are_rejected() {
        let mut unknown = payload();
        unknown["unexpected"] = json!(true);
        assert!(parse(CommandOp::WorkspaceStop, &unknown).is_err());

        let mut nil_stop = payload();
        nil_stop["stop_id"] = json!(Uuid::nil());
        assert!(parse(CommandOp::WorkspaceStop, &nil_stop).is_err());

        let mut malformed_principal = payload();
        malformed_principal["actor"]["principal"] = json!({
            "kind": "direct_token",
            "token_id": Uuid::nil()
        });
        assert!(parse(CommandOp::WorkspaceStop, &malformed_principal).is_err());
    }

    #[test]
    fn pre_admission_stop_failures_do_not_claim_unknown_or_readback() -> Result<(), ForgeError> {
        let command = parse(CommandOp::WorkspaceStop, &payload())?;
        let errors = [
            ForgeApprovalCoordinatorError::Closed,
            ForgeApprovalCoordinatorError::QueueFull,
            ForgeApprovalCoordinatorError::AttributionMismatch,
            ForgeApprovalCoordinatorError::Execution(
                forge_control::ForgeExecutionCoordinatorError::QueueFull,
            ),
            ForgeApprovalCoordinatorError::Execution(
                forge_control::ForgeExecutionCoordinatorError::Closed,
            ),
            ForgeApprovalCoordinatorError::Control(forge_control::ControlClientError::QueueFull),
            ForgeApprovalCoordinatorError::Execution(
                forge_control::ForgeExecutionCoordinatorError::Control(
                    forge_control::ControlClientError::QueueFull,
                ),
            ),
        ];
        for error in errors {
            let mapped = map_approval_error(&command, &error);
            assert_ne!(mapped.code(), crate::error::ErrorCode::UnknownOutcome);
            assert!(mapped.readback().is_none());
        }
        Ok(())
    }

    #[test]
    fn admitted_reply_loss_and_capture_combo_keep_exact_readback() -> Result<(), ForgeError> {
        let command = parse(CommandOp::WorkspaceStop, &payload())?;
        let combo = ForgeApprovalCoordinatorError::ApprovalCleanupAndExecution {
            cleanup: Box::new(ForgeApprovalCoordinatorError::CleanupIncomplete),
            execution: Box::new(forge_control::ForgeExecutionCoordinatorError::ResponseDropped),
        };
        for error in [
            ForgeApprovalCoordinatorError::ResponseDropped,
            ForgeApprovalCoordinatorError::Execution(
                forge_control::ForgeExecutionCoordinatorError::ResponseDropped,
            ),
            combo,
        ] {
            let mapped = map_approval_error(&command, &error);
            assert_eq!(mapped.code(), crate::error::ErrorCode::UnknownOutcome);
            assert_eq!(mapped.readback(), Some(&readback_hint(&command)));
        }
        Ok(())
    }
}
