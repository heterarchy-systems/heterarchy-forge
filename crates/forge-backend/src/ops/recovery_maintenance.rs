//! Typed HTTP adapter for durable recovery-maintenance run/get.
//!
//! This module owns only wire decoding, the request identity digest, configured
//! service-echo validation, and bounded JSON projection. Durable claiming,
//! classification, lease release, clocks, and historical receipt authority
//! remain in forge-control/forge-persistence.

use forge_control::{RecoveryMaintenanceOutcome, ResolvedWorkspaceScope};
use forge_domain::{
    ActivityListLimit, ActivityState, ExecutionListLimit, ForgeBackendId, OrchestrationIssuerId,
    RecoveryLeaseDurationMillis, RecoveryMaintenanceLease, RuntimeInstanceId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{BridgeClients, CommandOp, ScopeDto, decode_scope, parse_body};
use crate::error::{ForgeError, ReadbackHint};

const DIGEST_BYTES: usize = 32;
const DIGEST_VERSION: &[u8] = b"forge-recovery-maintenance/v1";
const MAX_FACT_LIMIT: u32 = 256;

/// One validated recovery-maintenance wire command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMaintenanceCommand {
    scope: ResolvedWorkspaceScope,
    request: RecoveryMaintenanceRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryMaintenanceRequest {
    Run {
        request_id: Uuid,
        service: RecoveryMaintenanceService,
        duration: RecoveryLeaseDurationMillis,
        activity_limit: ActivityListLimit,
        execution_limit: ExecutionListLimit,
    },
    Get {
        request_id: Uuid,
        request_digest: [u8; DIGEST_BYTES],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryMaintenanceService {
    backend_id: ForgeBackendId,
    issuer: OrchestrationIssuerId,
    destination_id: Uuid,
    runtime_instance_id: RuntimeInstanceId,
}

impl RecoveryMaintenanceCommand {
    pub(crate) const fn op(&self) -> CommandOp {
        match self.request {
            RecoveryMaintenanceRequest::Run { .. } => CommandOp::RecoveryMaintenanceRun,
            RecoveryMaintenanceRequest::Get { .. } => CommandOp::RecoveryMaintenanceGet,
        }
    }

    pub(crate) const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub(crate) fn readback_hint(&self) -> ReadbackHint {
        ReadbackHint::RecoveryMaintenance {
            workspace_id: self.scope.workspace_id().into_uuid(),
            request_id: self.request_id(),
            request_digest: super::encode_hex(&self.request_digest()),
        }
    }

    fn request_id(&self) -> Uuid {
        match self.request {
            RecoveryMaintenanceRequest::Run { request_id, .. }
            | RecoveryMaintenanceRequest::Get { request_id, .. } => request_id,
        }
    }

    fn request_digest(&self) -> [u8; DIGEST_BYTES] {
        match &self.request {
            RecoveryMaintenanceRequest::Run {
                request_id,
                service,
                duration,
                activity_limit,
                execution_limit,
            } => canonical_request_digest(
                &self.scope,
                *request_id,
                *service,
                *duration,
                *activity_limit,
                *execution_limit,
            ),
            RecoveryMaintenanceRequest::Get { request_digest, .. } => *request_digest,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunBody {
    scope: ScopeDto,
    request_id: Uuid,
    service: ServiceBody,
    duration_ms: i64,
    activity_limit: u32,
    execution_limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
    request_id: Uuid,
    request_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceBody {
    backend_id: Uuid,
    issuer: Uuid,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
}

/// Parse one recovery-maintenance run/get payload.
pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<RecoveryMaintenanceCommand, ForgeError> {
    match operation {
        CommandOp::RecoveryMaintenanceRun => {
            let body: RunBody = parse_body(payload, "recovery.maintenance.run payload is invalid")?;
            let scope = decode_scope_checked(&body.scope)?;
            let request_id = require_non_nil(body.request_id, "recovery maintenance request id")?;
            let service = decode_service(&body.service)?;
            let duration = RecoveryLeaseDurationMillis::new(body.duration_ms).map_err(|_| {
                ForgeError::invalid_input("recovery maintenance duration is invalid")
            })?;
            if body.activity_limit == 0
                || body.activity_limit > 1_000
                || body.execution_limit == 0
                || body.execution_limit > MAX_FACT_LIMIT
            {
                return Err(ForgeError::invalid_input(
                    "recovery maintenance limits exceed Activity 1000 or Execution 256",
                ));
            }
            let activity_limit = ActivityListLimit::new(body.activity_limit).map_err(|_| {
                ForgeError::invalid_input("recovery maintenance Activity limit is invalid")
            })?;
            let execution_limit = ExecutionListLimit::new(
                u16::try_from(body.execution_limit)
                    .map_err(|_| ForgeError::invalid_input("execution limit overflow"))?,
            )
            .map_err(|_| {
                ForgeError::invalid_input("recovery maintenance Execution limit is invalid")
            })?;
            Ok(RecoveryMaintenanceCommand {
                scope,
                request: RecoveryMaintenanceRequest::Run {
                    request_id,
                    service,
                    duration,
                    activity_limit,
                    execution_limit,
                },
            })
        }
        CommandOp::RecoveryMaintenanceGet => {
            let body: GetBody = parse_body(payload, "recovery.maintenance.get payload is invalid")?;
            let scope = decode_scope_checked(&body.scope)?;
            let request_id = require_non_nil(body.request_id, "recovery maintenance request id")?;
            let request_digest = decode_digest(&body.request_digest)?;
            Ok(RecoveryMaintenanceCommand {
                scope,
                request: RecoveryMaintenanceRequest::Get {
                    request_id,
                    request_digest,
                },
            })
        }
        _ => Err(ForgeError::invalid_input(
            "operation is not a recovery maintenance operation",
        )),
    }
}

/// Execute one run/get request through the configured Control owner.
pub(super) fn execute(
    clients: &BridgeClients,
    command: &RecoveryMaintenanceCommand,
) -> Result<Value, ForgeError> {
    match &command.request {
        RecoveryMaintenanceRequest::Run {
            request_id,
            service,
            duration,
            activity_limit,
            execution_limit,
        } => {
            validate_configured_service(clients, *service)?;
            let request = forge_control::DurableRecoveryMaintenanceRequest {
                scope: command.scope.clone(),
                request_id: *request_id,
                original_owner_id: service.runtime_instance_id,
                configured_owner_id: clients.runtime_instance_id,
                request_digest: command.request_digest(),
                duration: *duration,
                activity_limit: *activity_limit,
                execution_limit: *execution_limit,
            };
            let report = clients
                .control
                .run_durable_recovery_maintenance(request)
                .map_err(|error| map_control_error(command, &error))?;
            project_run(command, &report)
        }
        RecoveryMaintenanceRequest::Get {
            request_id,
            request_digest,
        } => {
            let receipt = clients
                .control
                .recovery_maintenance_get(command.scope.clone(), *request_id, *request_digest)
                .map_err(|error| map_control_error(command, &error))?;
            project_get(command, receipt.as_ref())
        }
    }
}

fn validate_configured_service(
    clients: &BridgeClients,
    service: RecoveryMaintenanceService,
) -> Result<(), ForgeError> {
    if service.backend_id != clients.backend_id
        || service.issuer != clients.issuer
        || service.destination_id != clients.destination_id
    {
        return Err(ForgeError::auth_failed());
    }
    Ok(())
}

fn project_run(
    command: &RecoveryMaintenanceCommand,
    report: &forge_control::RecoveryMaintenanceReport,
) -> Result<Value, ForgeError> {
    let scope = super::scope_json(command.scope())?;
    match report.outcome() {
        RecoveryMaintenanceOutcome::Busy | RecoveryMaintenanceOutcome::ClaimConflict => Ok(json!({
            "found": false,
            "status": recovery_outcome_name(report.outcome()),
            "scope": scope,
            "request_id": command.request_id(),
            "request_digest": super::encode_hex(&command.request_digest()),
            "receipt": Value::Null,
            "lease": lease_json(report.lease()),
            "activity_count": 0,
            "execution_count": 0,
            "replayed": false,
        })),
        RecoveryMaintenanceOutcome::Completed => {
            let Some(receipt) = report.receipt() else {
                return Err(ForgeError::unknown_outcome(Some(command.readback_hint())));
            };
            validate_receipt(command, receipt)?;
            Ok(json!({
                "found": true,
                "status": if report.replayed() { "replay" } else { "recorded" },
                "scope": scope,
                "request_id": command.request_id(),
                "request_digest": super::encode_hex(&command.request_digest()),
                "receipt": receipt_json(receipt),
                "lease": lease_json(receipt.released_lease()),
                "activity_count": report.activity_count(),
                "execution_count": report.execution_count(),
                "replayed": report.replayed(),
            }))
        }
    }
}

fn project_get(
    command: &RecoveryMaintenanceCommand,
    receipt: Option<&forge_persistence::RecoveryRunReceipt>,
) -> Result<Value, ForgeError> {
    let scope = super::scope_json(command.scope())?;
    let Some(receipt) = receipt else {
        return Ok(json!({
            "found": false,
            "status": "absent_now",
            "scope": scope,
            "request_id": command.request_id(),
            "request_digest": super::encode_hex(&command.request_digest()),
            "receipt": Value::Null,
            "lease": Value::Null,
        }));
    };
    validate_receipt(command, receipt)?;
    Ok(json!({
        "found": true,
        "status": "historical",
        "scope": scope,
        "request_id": command.request_id(),
        "request_digest": super::encode_hex(&command.request_digest()),
        "receipt": receipt_json(receipt),
        "lease": lease_json(receipt.released_lease()),
    }))
}

fn validate_receipt(
    command: &RecoveryMaintenanceCommand,
    receipt: &forge_persistence::RecoveryRunReceipt,
) -> Result<(), ForgeError> {
    let request = receipt.request();
    let owner_matches = match &command.request {
        RecoveryMaintenanceRequest::Run { service, .. } => {
            request.owner_id == service.runtime_instance_id
        }
        RecoveryMaintenanceRequest::Get { .. } => true,
    };
    if request.request_id != command.request_id()
        || request.workspace_id != command.scope.workspace_id()
        || request.request_digest != command.request_digest()
        || !owner_matches
    {
        return Err(ForgeError::resync_required(
            "recovery maintenance receipt identity changed",
        ));
    }
    Ok(())
}

fn receipt_json(receipt: &forge_persistence::RecoveryRunReceipt) -> Value {
    let request = receipt.request();
    json!({
        "request": {
            "request_id": request.request_id,
            "workspace_id": request.workspace_id.into_uuid(),
            "owner_id": request.owner_id.into_uuid(),
            "request_digest": super::encode_hex(&request.request_digest),
            "binding_digest": super::encode_hex(&request.binding_digest),
            "duration_ms": request.duration.get(),
            "claimed_at_ms": request.claimed_at.get(),
            "classify_at_ms": request.classify_at.get(),
            "activity_limit": request.activity_limit.get(),
            "execution_limit": request.execution_limit.get(),
        },
        "claimed_lease": lease_json(receipt.claimed_lease()),
        "released_lease": lease_json(receipt.released_lease()),
        "activities": receipt.activities().iter().map(activity_fact_json).collect::<Vec<_>>(),
        "executions": receipt.executions().iter().map(execution_fact_json).collect::<Vec<_>>(),
        "activity_count": receipt.activities().len(),
        "execution_count": receipt.executions().len(),
        "receipt_digest": super::encode_hex(receipt.receipt_digest()),
    })
}

fn lease_json(lease: &RecoveryMaintenanceLease) -> Value {
    json!({
        "workspace_id": lease.workspace_id().into_uuid(),
        "owner_id": lease.owner_id().map(RuntimeInstanceId::into_uuid),
        "lease_until_ms": lease.lease_until().map(forge_domain::TimestampMillis::get),
        "epoch": lease.epoch().get(),
        "revision": lease.revision().get(),
        "updated_at_ms": lease.updated_at().get(),
    })
}

fn activity_fact_json(fact: &forge_persistence::RecoveryActivityFact) -> Value {
    json!({
        "ordinal": fact.ordinal(),
        "activity_id": fact.activity_id().into_uuid(),
        "workspace_id": fact.workspace_id().into_uuid(),
        "before_state": activity_state_name(fact.before_state()),
        "before_revision": fact.before_revision().get(),
        "before_created_at_ms": fact.before_created_at().get(),
        "before_updated_at_ms": fact.before_updated_at().get(),
        "before_lease_owner_id": fact.before_lease_owner().into_uuid(),
        "before_lease_until_ms": fact.before_lease_until().get(),
        "before_lease_revision": fact.before_lease_revision().get(),
        "after_revision": fact.after_revision().get(),
        "after_updated_at_ms": fact.after_updated_at().get(),
        "after_lease_revision": fact.after_lease_revision().get(),
    })
}

fn execution_fact_json(fact: &forge_persistence::RecoveryExecutionFact) -> Value {
    json!({
        "ordinal": fact.ordinal(),
        "execution_id": fact.execution_id().into_uuid(),
        "workspace_id": fact.workspace_id().into_uuid(),
        "activity_id": fact.activity_id().into_uuid(),
        "request_digest": super::encode_hex(fact.request_digest().as_bytes()),
        "before_state": super::execution_evidence::execution_state_name(fact.before_state()),
        "before_revision": fact.before_revision().get(),
        "before_updated_at_ms": fact.before_updated_at().get(),
        "after_revision": fact.after_revision().get(),
        "after_updated_at_ms": fact.after_updated_at().get(),
        "eligibility_activity_id": fact.eligibility_activity_id().into_uuid(),
        "eligibility_activity_state": activity_state_name(fact.eligibility_activity_state()),
        "eligibility_activity_revision": fact.eligibility_activity_revision().get(),
        "eligibility_activity_updated_at_ms": fact.eligibility_activity_updated_at().get(),
        "eligibility_activity_lease_owner_id": fact.eligibility_activity_lease_owner().map(RuntimeInstanceId::into_uuid),
        "eligibility_activity_lease_until_ms": fact.eligibility_activity_lease_until().map(forge_domain::TimestampMillis::get),
        "eligibility_activity_lease_revision": fact.eligibility_activity_lease_revision().get(),
        "terminal_semantic_sequence": fact.terminal_semantic_sequence(),
        "effect_outbox_sequence": fact.effect_outbox_sequence(),
    })
}

const fn activity_state_name(state: ActivityState) -> &'static str {
    match state {
        ActivityState::Open => "open",
        ActivityState::Closed => "closed",
        ActivityState::Interrupted => "interrupted",
    }
}

fn recovery_outcome_name(outcome: RecoveryMaintenanceOutcome) -> &'static str {
    match outcome {
        RecoveryMaintenanceOutcome::Completed => "completed",
        RecoveryMaintenanceOutcome::Busy => "busy",
        RecoveryMaintenanceOutcome::ClaimConflict => "claim_conflict",
    }
}

fn map_control_error(
    command: &RecoveryMaintenanceCommand,
    error: &forge_control::ControlClientError,
) -> ForgeError {
    let mapped = super::forge_error_of_client(error);
    if command.op() == CommandOp::RecoveryMaintenanceRun
        && mapped.code() == crate::error::ErrorCode::UnknownOutcome
    {
        mapped.with_readback(Some(command.readback_hint()))
    } else {
        mapped
    }
}

fn decode_scope_checked(scope: &ScopeDto) -> Result<ResolvedWorkspaceScope, ForgeError> {
    if scope.workspace_id.is_nil() || scope.locator.location_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "recovery maintenance scope identifiers must not be nil",
        ));
    }
    decode_scope(scope)
}

fn decode_service(body: &ServiceBody) -> Result<RecoveryMaintenanceService, ForgeError> {
    Ok(RecoveryMaintenanceService {
        backend_id: ForgeBackendId::from_uuid(require_non_nil(
            body.backend_id,
            "recovery maintenance service backend id",
        )?),
        issuer: OrchestrationIssuerId::from_uuid(require_non_nil(
            body.issuer,
            "recovery maintenance service issuer",
        )?),
        destination_id: require_non_nil(
            body.destination_id,
            "recovery maintenance service destination id",
        )?,
        runtime_instance_id: RuntimeInstanceId::from_uuid(require_non_nil(
            body.runtime_instance_id,
            "recovery maintenance service boot identity",
        )?),
    })
}

fn require_non_nil(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be non-nil"
        )));
    }
    Ok(value)
}

fn decode_digest(value: &str) -> Result<[u8; DIGEST_BYTES], ForgeError> {
    let bytes = super::decode_hex(value)?;
    let Ok(digest) = <[u8; DIGEST_BYTES]>::try_from(bytes.as_slice()) else {
        return Err(ForgeError::invalid_input(
            "recovery maintenance request digest must be 64 lowercase hex characters",
        ));
    };
    if super::encode_hex(&digest) != value {
        return Err(ForgeError::invalid_input(
            "recovery maintenance request digest must be lowercase hex",
        ));
    }
    Ok(digest)
}

fn canonical_request_digest(
    scope: &ResolvedWorkspaceScope,
    request_id: Uuid,
    service: RecoveryMaintenanceService,
    duration: RecoveryLeaseDurationMillis,
    activity_limit: ActivityListLimit,
    execution_limit: ExecutionListLimit,
) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    update_bytes(&mut hasher, 1, DIGEST_VERSION);
    update_uuid(&mut hasher, 2, request_id);
    update_uuid(&mut hasher, 3, scope.workspace_id().into_uuid());
    update_i64(&mut hasher, 4, scope.workspace_revision().get());
    update_uuid(&mut hasher, 5, scope.locator().location_id().into_uuid());
    update_i64(&mut hasher, 6, scope.locator().expected_revision().get());
    update_bytes(&mut hasher, 7, scope.locator().relative_root_bytes());
    update_uuid(&mut hasher, 8, service.backend_id.into_uuid());
    update_uuid(&mut hasher, 9, service.issuer.into_uuid());
    update_uuid(&mut hasher, 10, service.destination_id);
    update_uuid(&mut hasher, 11, service.runtime_instance_id.into_uuid());
    update_i64(&mut hasher, 12, duration.get());
    update_u32(&mut hasher, 13, activity_limit.get());
    update_u32(&mut hasher, 14, u32::from(execution_limit.get()));
    hasher.finalize().into()
}

fn update_uuid(hasher: &mut Sha256, tag: u8, value: Uuid) {
    update_bytes(hasher, tag, value.as_bytes());
}

fn update_i64(hasher: &mut Sha256, tag: u8, value: i64) {
    update_bytes(hasher, tag, &value.to_le_bytes());
}

fn update_u32(hasher: &mut Sha256, tag: u8, value: u32) {
    update_bytes(hasher, tag, &value.to_le_bytes());
}

fn update_bytes(hasher: &mut Sha256, tag: u8, value: &[u8]) {
    hasher.update([tag]);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}
