//! Typed HTTP adapter for expired Activity successor recovery.
//!
//! The adapter owns only the v1 JSON shape, canonical request identity and
//! projections. Session, boot-owner, replay, lease, blocker and receipt
//! authority remain in forge-control/forge-persistence.

use std::fmt::Write as _;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use forge_control::{
    DurableExpiredActivityRecoveryRequest, ExpiredActivityRecoveryGetRequest,
    ExpiredActivityRecoveryProbeRequest, ExpiredActivityRecoveryReport,
};
use forge_domain::{
    ActivityId, ActivityLeaseRevision, ActivityRevision, ActivityState, AgentAttachmentState,
    AgentInstanceId, AgentSessionId, AgentTransportKind, AuthenticatedPrincipal,
    ExpectedActivityCoordinator, ExpectedExpiredActivity, ExpiredActivityRecoveryAgentSnapshot,
    ExpiredActivityRecoveryBlocker, ExpiredActivityRecoveryDelegationFence,
    ExpiredActivityRecoveryExpectation, ExpiredActivityRecoveryFreezeState,
    RecoveryLeaseDurationMillis, RuntimeInstanceId, TimestampMillis, WorkspaceRootFingerprint,
};

use super::BridgeClients;
use super::{
    Command, ParseResult, PrincipalDto, ScopeDto, decode_principal, decode_scope, decode_timestamp,
    parse_body,
};
use crate::error::{ForgeError, ReadbackHint};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"forge.activity.expired-successor-recovery.request.v1\0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    scope: ScopeDto,
    predecessor_activity_id: Uuid,
}

pub(super) fn parse_probe(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: ProbeBody = parse_body(
        payload,
        "expired Activity recovery probe payload is invalid",
    )?;
    require_non_nil(body.scope.workspace_id, "scope workspace identity")?;
    require_non_nil(body.scope.locator.location_id, "scope location identity")?;
    require_non_nil(
        body.predecessor_activity_id,
        "predecessor Activity identity",
    )?;
    Ok(Command::ActivityExpiredSuccessorRecoveryProbe {
        request_id,
        request: Box::new(ExpiredActivityRecoveryProbeRequest {
            scope: decode_scope(&body.scope)?,
            predecessor_activity_id: ActivityId::from_uuid(body.predecessor_activity_id),
            observed_at: current_timestamp_millis()?,
        }),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
    request_id: Uuid,
    request_digest: String,
}

pub(super) fn parse_get(envelope_request_id: Uuid, payload: &Value) -> ParseResult {
    let body: GetBody = parse_body(payload, "expired Activity recovery get payload is invalid")?;
    if body.request_id != envelope_request_id {
        return Err(ForgeError::invalid_input(
            "request_id must match the envelope request id",
        ));
    }
    require_non_nil(body.scope.workspace_id, "scope workspace identity")?;
    require_non_nil(body.scope.locator.location_id, "scope location identity")?;
    require_non_nil(body.request_id, "request identity")?;
    Ok(Command::ActivityExpiredSuccessorRecoveryGet {
        request_id: body.request_id,
        request: Box::new(ExpiredActivityRecoveryGetRequest {
            scope: decode_scope(&body.scope)?,
            request_id: body.request_id,
            request_digest: decode_hex_digest(&body.request_digest)?,
        }),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceBody {
    backend_id: Uuid,
    issuer: Uuid,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationBody {
    migration_id: Uuid,
    destination_id: Uuid,
    freeze_revision: u64,
    freeze_created_at_ms: i64,
    freeze_updated_at_ms: i64,
    manifest_digest: String,
    delegated_at_ms: i64,
    delegation_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PredecessorBody {
    activity_id: Uuid,
    expected_revision: i64,
    expected_created_at_ms: i64,
    expected_updated_at_ms: i64,
    expected_lease_owner_id: Uuid,
    expected_lease_until_ms: i64,
    expected_lease_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorBody {
    agent_id: Uuid,
    revision: i64,
    updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverBody {
    scope: ScopeDto,
    request_id: Uuid,
    service: ServiceBody,
    expected_workspace_root_fingerprint: String,
    expected_binding_digest: String,
    expected_delegation: DelegationBody,
    probe_observed_at_ms: i64,
    expected_probe_digest: String,
    predecessor: PredecessorBody,
    successor_activity_id: Uuid,
    initiating_session_id: Uuid,
    principal: PrincipalDto,
    expected_agent_count: u16,
    expected_agent_digest: String,
    expected_coordinator: Option<CoordinatorBody>,
    duration_ms: i64,
}

#[allow(
    clippy::too_many_lines,
    reason = "The strict recovery DTO is one closed source wire contract."
)]
pub(super) fn parse_recover(envelope_request_id: Uuid, payload: &Value) -> ParseResult {
    let body: RecoverBody = parse_body(payload, "expired Activity recovery payload is invalid")?;
    if body.request_id != envelope_request_id {
        return Err(ForgeError::invalid_input(
            "request_id must match the envelope request id",
        ));
    }
    require_non_nil(body.scope.workspace_id, "scope workspace identity")?;
    require_non_nil(body.scope.locator.location_id, "scope location identity")?;
    require_non_nil(body.request_id, "request identity")?;
    require_non_nil(body.service.backend_id, "service backend identity")?;
    require_non_nil(body.service.issuer, "service issuer identity")?;
    require_non_nil(body.service.destination_id, "service destination identity")?;
    require_non_nil(body.service.runtime_instance_id, "service runtime identity")?;
    require_non_nil(
        body.expected_delegation.migration_id,
        "delegation migration identity",
    )?;
    require_non_nil(
        body.expected_delegation.destination_id,
        "delegation destination identity",
    )?;
    require_non_nil(
        body.predecessor.activity_id,
        "predecessor Activity identity",
    )?;
    require_non_nil(
        body.predecessor.expected_lease_owner_id,
        "predecessor lease owner identity",
    )?;
    require_non_nil(body.successor_activity_id, "successor Activity identity")?;
    require_non_nil(body.initiating_session_id, "initiating Session identity")?;

    let scope = decode_scope(&body.scope)?;
    let principal = decode_principal(&body.principal)?;
    let predecessor = ExpectedExpiredActivity::new(
        ActivityId::from_uuid(body.predecessor.activity_id),
        ActivityRevision::new(body.predecessor.expected_revision)
            .map_err(|_| ForgeError::invalid_input("predecessor revision is invalid"))?,
        decode_timestamp(body.predecessor.expected_created_at_ms)?,
        decode_timestamp(body.predecessor.expected_updated_at_ms)?,
        RuntimeInstanceId::from_uuid(body.predecessor.expected_lease_owner_id),
        decode_timestamp(body.predecessor.expected_lease_until_ms)?,
        ActivityLeaseRevision::new(body.predecessor.expected_lease_revision)
            .map_err(|_| ForgeError::invalid_input("predecessor lease revision is invalid"))?,
    )
    .map_err(|_| ForgeError::invalid_input("predecessor fence is invalid"))?;
    let coordinator = body
        .expected_coordinator
        .as_ref()
        .map(|value| {
            require_non_nil(value.agent_id, "coordinator Agent identity")?;
            ExpectedActivityCoordinator::new(
                AgentInstanceId::from_uuid(value.agent_id),
                value.revision,
                decode_timestamp(value.updated_at_ms)?,
            )
            .map_err(|_| ForgeError::invalid_input("coordinator fence is invalid"))
        })
        .transpose()?;
    let expected_agent_digest = decode_hex_digest(&body.expected_agent_digest)?;
    let probe_digest = decode_hex_digest(&body.expected_probe_digest)?;
    let binding_digest = decode_hex_digest(&body.expected_binding_digest)?;
    let delegation_digest = decode_hex_digest(&body.expected_delegation.delegation_digest)?;
    let root_fingerprint = decode_fingerprint(&body.expected_workspace_root_fingerprint)?;
    let expectation = ExpiredActivityRecoveryExpectation::new(
        predecessor,
        ActivityId::from_uuid(body.successor_activity_id),
        AgentSessionId::from_uuid(body.initiating_session_id),
        principal,
        body.expected_agent_count,
        expected_agent_digest,
        coordinator,
    )
    .map_err(|_| ForgeError::invalid_input("recovery expectation is invalid"))?;
    let delegation = ExpiredActivityRecoveryDelegationFence::new(
        body.expected_delegation.migration_id,
        forge_domain::WorkspaceId::from_uuid(body.scope.workspace_id),
        body.expected_delegation.destination_id,
        ExpiredActivityRecoveryFreezeState::Frozen,
        body.expected_delegation.freeze_revision,
        decode_timestamp(body.expected_delegation.freeze_created_at_ms)?,
        decode_timestamp(body.expected_delegation.freeze_updated_at_ms)?,
        decode_hex_digest(&body.expected_delegation.manifest_digest)?,
        decode_timestamp(body.expected_delegation.delegated_at_ms)?,
    )
    .map_err(|_| ForgeError::invalid_input("delegation fence is invalid"))?;
    if delegation.destination_id() != body.service.destination_id {
        return Err(ForgeError::invalid_input(
            "service and delegation destinations must match",
        ));
    }
    let request_digest = canonical_request_digest(
        &body,
        root_fingerprint,
        binding_digest,
        delegation,
        delegation_digest,
        probe_digest,
        expected_agent_digest,
        &expectation,
    );
    Ok(Command::ActivityExpiredSuccessorRecover {
        request_id: body.request_id,
        request: Box::new(DurableExpiredActivityRecoveryRequest {
            scope,
            request_id: body.request_id,
            original_owner_id: RuntimeInstanceId::from_uuid(body.service.runtime_instance_id),
            configured_owner_id: RuntimeInstanceId::from_uuid(body.service.runtime_instance_id),
            service_backend_id: forge_domain::ForgeBackendId::from_uuid(body.service.backend_id),
            service_issuer: forge_domain::OrchestrationIssuerId::from_uuid(body.service.issuer),
            service_destination_id: body.service.destination_id,
            request_digest,
            expected_workspace_root_fingerprint: root_fingerprint,
            expected_binding_digest: binding_digest,
            expected_delegation: delegation,
            expected_delegation_digest: delegation_digest,
            probe_observed_at: decode_timestamp(body.probe_observed_at_ms)?,
            expected_probe_digest: probe_digest,
            duration: RecoveryLeaseDurationMillis::new(body.duration_ms)
                .map_err(|_| ForgeError::invalid_input("duration is invalid"))?,
            expectation,
        }),
    })
}

pub(super) fn execute_probe(
    clients: &BridgeClients,
    request: &ExpiredActivityRecoveryProbeRequest,
) -> Result<Value, ForgeError> {
    let probe = clients
        .control
        .expired_activity_recovery_probe(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    if probe.delegation().destination_id() != clients.destination_id {
        return Err(ForgeError::invalid_input(
            "recovery delegation destination does not match the executing service",
        ));
    }
    Ok(probe_json(&probe, clients))
}

pub(super) fn execute_recover(
    clients: &BridgeClients,
    request: &DurableExpiredActivityRecoveryRequest,
) -> Result<Value, ForgeError> {
    if request.service_backend_id != clients.backend_id
        || request.service_issuer != clients.issuer
        || request.service_destination_id != clients.destination_id
    {
        return Err(ForgeError::invalid_input(
            "recovery service identity does not match the executing BridgeClients",
        ));
    }
    // Control owns replay-first ordering, but the transport must not reject a
    // historical receipt merely because Forge restarted with a new boot
    // identity. A validated receipt keeps its original owner for replay;
    // an absent receipt receives the current BridgeClients owner and therefore
    // fails closed in Control when the request echoed a stale boot identity.
    let receipt = clients
        .control
        .expired_activity_recovery_get(ExpiredActivityRecoveryGetRequest {
            scope: request.scope.clone(),
            request_id: request.request_id,
            request_digest: request.request_digest,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let mut control_request = request.clone();
    control_request.configured_owner_id =
        configured_owner_for_run(request, receipt.is_some(), clients.runtime_instance_id);
    let report = clients
        .control
        .expired_activity_recovery_run(control_request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    report_json(&report)
}

pub(super) fn execute_get(
    clients: &BridgeClients,
    request: &ExpiredActivityRecoveryGetRequest,
) -> Result<Value, ForgeError> {
    let readback = clients
        .control
        .expired_activity_recovery_get(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some(readback) = readback else {
        return Ok(json!({
            "status": "absent_now",
            "found": false,
            "receipt": null,
        }));
    };
    Ok(json!({
        "status": "recorded",
        "found": true,
        "receipt": receipt_json(readback.receipt()),
        "current_predecessor": activity_json(readback.current_predecessor()),
        "current_successor": activity_json(readback.current_successor()),
        "relation": relation_json(&readback.relation()),
    }))
}

pub(super) fn readback_hint(request: &DurableExpiredActivityRecoveryRequest) -> ReadbackHint {
    ReadbackHint::ExpiredActivityRecovery {
        workspace_id: request.scope.workspace_id().into_uuid(),
        request_id: request.request_id,
        request_digest: hex(&request.request_digest),
        workspace_root_fingerprint: hex(&request.expected_workspace_root_fingerprint.into_bytes()),
        binding_digest: hex(&request.expected_binding_digest),
        delegation_migration_id: request.expected_delegation.migration_id(),
        delegation_destination_id: request.expected_delegation.destination_id(),
        delegation_freeze_revision: request.expected_delegation.revision(),
        delegation_digest: hex(&request.expected_delegation_digest),
        service_backend_id: request.service_backend_id.into_uuid(),
        service_issuer_id: request.service_issuer.into_uuid(),
        service_runtime_instance_id: request.configured_owner_id.into_uuid(),
        predecessor_activity_id: request.expectation.predecessor().activity_id().into_uuid(),
        successor_activity_id: request.expectation.successor_activity_id().into_uuid(),
    }
}

fn configured_owner_for_run(
    request: &DurableExpiredActivityRecoveryRequest,
    receipt_found: bool,
    current_owner: RuntimeInstanceId,
) -> RuntimeInstanceId {
    configured_owner_from_original(receipt_found, request.original_owner_id, current_owner)
}

fn configured_owner_from_original(
    receipt_found: bool,
    original_owner: RuntimeInstanceId,
    current_owner: RuntimeInstanceId,
) -> RuntimeInstanceId {
    if receipt_found {
        original_owner
    } else {
        current_owner
    }
}

fn probe_json(
    probe: &forge_domain::ExpiredActivityRecoveryProbe,
    clients: &BridgeClients,
) -> Value {
    let predecessor = probe.predecessor();
    json!({
        "scope": scope_json(probe.scope()),
        "service": {
            "backend_id": clients.backend_id.into_uuid(),
            "issuer": clients.issuer.into_uuid(),
            "destination_id": clients.destination_id,
            "runtime_instance_id": clients.runtime_instance_id.into_uuid(),
        },
        "workspace_root_fingerprint": hex(&probe.scope().root_fingerprint().into_bytes()),
        "binding_digest": hex(probe.scope().binding_digest()),
        "delegation": delegation_json(probe.delegation(), probe.delegation_digest()),
        "predecessor": probe_predecessor_json(predecessor),
        "agent_count": probe.agent_count(),
        "agent_digest": hex(probe.agent_digest()),
        "coordinator": probe.coordinator().map(coordinator_json),
        "probe_observed_at_ms": probe.probe_observed_at().get(),
        "probe_digest": hex(probe.probe_digest()),
        "expired_at_observation": probe.expired_at_observation(),
        "recoverable_now": probe.recoverable_now(),
        "blocker": probe.blocker().map(blocker_json),
    })
}

fn report_json(report: &ExpiredActivityRecoveryReport) -> Result<Value, ForgeError> {
    if let Some(receipt) = report.receipt() {
        let current_predecessor = report
            .current_predecessor()
            .ok_or_else(ForgeError::internal)?;
        let current_successor = report
            .current_successor()
            .ok_or_else(ForgeError::internal)?;
        let relation = report.relation().ok_or_else(ForgeError::internal)?;
        Ok(json!({
            "status": if report.replayed() { "replay" } else { "recorded" },
            "committed": true,
            "unconfirmed": false,
            "replayed": report.replayed(),
            "receipt": receipt_json(receipt),
            "current_predecessor": activity_json(current_predecessor),
            "current_successor": activity_json(current_successor),
            "relation": relation_json(&relation),
        }))
    } else {
        Ok(json!({
            "status": if report.claim_conflict() { "claim_conflict" } else { "busy" },
            "committed": false,
            "unconfirmed": false,
            "replayed": false,
            "found": false,
            "receipt": null,
            "lease": report.lease().map(lease_json),
        }))
    }
}

fn receipt_json(receipt: &forge_persistence::ExpiredActivityRecoveryReceipt) -> Value {
    let before = receipt.expectation().predecessor();
    json!({
        "request_id": receipt.request_id(),
        "request_digest": hex(&receipt.request_digest()),
        "scope": scope_json(receipt.probe_scope()),
        "workspace_root_fingerprint": hex(&receipt.probe_scope().root_fingerprint().into_bytes()),
        "binding_digest": hex(receipt.probe_scope().binding_digest()),
        "probe_observed_at_ms": receipt.probe_observed_at().get(),
        "probe_digest": hex(&receipt.probe_digest()),
        "delegation": delegation_json(receipt.delegation(), &receipt.delegation_digest()),
        "service": {
            "backend_id": receipt.service_backend_id().into_uuid(),
            "issuer": receipt.service_issuer().into_uuid(),
            "destination_id": receipt.service_destination_id(),
            "runtime_instance_id": receipt.owner_id().into_uuid(),
        },
        "duration_ms": receipt.duration().get(),
        "recovered_at_ms": receipt.recovered_at().get(),
        "claimed_lease_until_ms": receipt.claimed_lease_until().get(),
        "claimed_epoch": receipt.claimed_epoch(),
        "claimed_revision": receipt.claimed_revision(),
        "released_epoch": receipt.released_epoch(),
        "released_revision": receipt.released_revision(),
        "released_updated_at_ms": receipt.released_updated_at().get(),
        "session": {
            "session_id": receipt.session().session_id().into_uuid(),
            "principal": principal_json(receipt.session().principal()),
            "session_revision": receipt.session().session_revision(),
            "session_updated_at_ms": receipt.session().session_updated_at().get(),
        },
        "predecessor_before": predecessor_json(before),
        "predecessor_after": activity_json(receipt.predecessor_after()),
        "successor": activity_json(receipt.successor()),
        "relation": relation_json(&receipt.relation()),
        "agent_count": receipt.agents().len(),
        "agent_digest": hex(receipt.expectation().expected_agent_digest()),
        "agents": receipt.agents().iter().map(agent_snapshot_json).collect::<Vec<_>>(),
        "coordinator": receipt.expectation().expected_coordinator().map(coordinator_json),
        "coordinator_digest": hex(&receipt.coordinator_digest()),
        "relation_digest": hex(&receipt.relation_digest()),
        "receipt_digest": hex(&receipt.receipt_digest()),
    })
}

fn predecessor_json(value: ExpectedExpiredActivity) -> Value {
    json!({
        "activity_id": value.activity_id().into_uuid(),
        "revision": value.revision().get(),
        "created_at_ms": value.created_at().get(),
        "updated_at_ms": value.updated_at().get(),
        "lease_owner_id": value.lease_owner_id().into_uuid(),
        "lease_until_ms": value.lease_until().get(),
        "lease_revision": value.lease_revision().get(),
    })
}

fn probe_predecessor_json(value: ExpectedExpiredActivity) -> Value {
    json!({
        "activity_id": value.activity_id().into_uuid(),
        "expected_revision": value.revision().get(),
        "expected_created_at_ms": value.created_at().get(),
        "expected_updated_at_ms": value.updated_at().get(),
        "expected_lease_owner_id": value.lease_owner_id().into_uuid(),
        "expected_lease_until_ms": value.lease_until().get(),
        "expected_lease_revision": value.lease_revision().get(),
    })
}

fn coordinator_json(value: ExpectedActivityCoordinator) -> Value {
    json!({
        "agent_id": value.agent_id().into_uuid(),
        "revision": value.revision(),
        "updated_at_ms": value.updated_at().get(),
    })
}

fn principal_json(value: AuthenticatedPrincipal) -> Value {
    match value {
        AuthenticatedPrincipal::TrustedStdio => json!({
            "kind": "trusted_stdio",
            "token_id": null,
            "grant_id": null,
        }),
        AuthenticatedPrincipal::DirectToken(id) => json!({
            "kind": "direct_token",
            "token_id": id.into_uuid(),
            "grant_id": null,
        }),
        AuthenticatedPrincipal::OAuthGrant(id) => json!({
            "kind": "oauth_grant",
            "token_id": null,
            "grant_id": id.into_uuid(),
        }),
    }
}

fn blocker_json(value: ExpiredActivityRecoveryBlocker) -> &'static str {
    match value {
        ExpiredActivityRecoveryBlocker::PendingWorkspaceStop => "pending_workspace_stop",
        ExpiredActivityRecoveryBlocker::ActiveWorkCut => "active_work_cut",
        ExpiredActivityRecoveryBlocker::PendingBindingActivation => "pending_binding_activation",
        ExpiredActivityRecoveryBlocker::PendingGoalDeletion => "pending_goal_deletion",
        ExpiredActivityRecoveryBlocker::NonterminalGoal => "nonterminal_goal",
        ExpiredActivityRecoveryBlocker::NonterminalCurrentDagNode => "nonterminal_current_dag_node",
        ExpiredActivityRecoveryBlocker::ActiveExecution => "active_execution",
        ExpiredActivityRecoveryBlocker::ActiveWriterLease => "active_writer_lease",
        ExpiredActivityRecoveryBlocker::StartingCheckpoint => "starting_checkpoint",
        ExpiredActivityRecoveryBlocker::UnsettledCheckpointRestore => {
            "unsettled_checkpoint_restore"
        }
        ExpiredActivityRecoveryBlocker::StartingChangeSet => "starting_change_set",
        ExpiredActivityRecoveryBlocker::PendingDiffEvidence => "pending_diff_evidence",
        ExpiredActivityRecoveryBlocker::StartingVerification => "starting_verification",
        ExpiredActivityRecoveryBlocker::PendingApproval => "pending_approval",
        ExpiredActivityRecoveryBlocker::ActiveExecutionGrant => "active_execution_grant",
        ExpiredActivityRecoveryBlocker::ActiveAutoApprovalScope => "active_auto_approval_scope",
        ExpiredActivityRecoveryBlocker::NonterminalAssignment => "nonterminal_assignment",
    }
}

fn activity_json(activity: &forge_domain::RegisteredActivity) -> Value {
    json!({
        "activity_id": activity.id().into_uuid(),
        "workspace_id": activity.workspace_id().into_uuid(),
        "state": activity_state_json(activity.state()),
        "revision": activity.revision().get(),
        "created_at_ms": activity.created_at().get(),
        "updated_at_ms": activity.updated_at().get(),
        "lease_owner_id": activity.lease_owner_id().map(RuntimeInstanceId::into_uuid),
        "lease_until_ms": activity.lease_until().map(TimestampMillis::get),
        "lease_revision": activity.lease_revision().get(),
    })
}

fn activity_state_json(value: ActivityState) -> &'static str {
    match value {
        ActivityState::Open => "open",
        ActivityState::Closed => "closed",
        ActivityState::Interrupted => "interrupted",
    }
}

fn relation_json(relation: &forge_domain::ActivitySuccessor) -> Value {
    json!({
        "workspace_id": relation.workspace_id().into_uuid(),
        "predecessor_activity_id": relation.predecessor_activity_id().into_uuid(),
        "predecessor_activity_revision": relation.predecessor_activity_revision().get(),
        "successor_activity_id": relation.successor_activity_id().into_uuid(),
        "initiating_session_id": relation.initiating_session_id().into_uuid(),
        "runtime_instance_id": relation.runtime_instance_id().into_uuid(),
        "created_at_ms": relation.created_at().get(),
    })
}

fn agent_snapshot_json(agent: &ExpiredActivityRecoveryAgentSnapshot) -> Value {
    json!({
        "agent_id": agent.agent_id().into_uuid(),
        "workspace_id": agent.workspace_id().into_uuid(),
        "activity_id": agent.activity_id().into_uuid(),
        "session_id": agent.session_id().map(AgentSessionId::into_uuid),
        "display_name": agent.display_name().as_str(),
        "declared_role": agent.declared_role().as_str(),
        "transport_kind": transport_json(agent.transport_kind()),
        "principal": principal_json(agent.principal()),
        "attachment_state": attachment_json(agent.attachment_state()),
        "focus_goal_id": agent.focus_goal_id().map(forge_domain::GoalId::into_uuid),
        "focus_goal_revision": agent.focus_goal_revision().map(forge_domain::GoalRevision::get),
        "focus_dag_revision": agent.focus_dag_revision().map(forge_domain::DagRevisionNumber::get),
        "focus_node_id": agent.focus_node_id().map(forge_domain::DagNodeId::into_uuid),
        "focus_node_revision": agent.focus_node_revision().map(forge_domain::DagNodeRevision::get),
        "created_at_ms": agent.created_at().get(),
        "updated_at_ms": agent.updated_at().get(),
        "revision": agent.revision().get(),
    })
}

fn transport_json(value: AgentTransportKind) -> &'static str {
    match value {
        AgentTransportKind::Retired => "mcp",
        AgentTransportKind::Stdio => "stdio",
        AgentTransportKind::StreamableHttp => "streamable_http",
        AgentTransportKind::Other => "other",
    }
}

fn attachment_json(value: AgentAttachmentState) -> &'static str {
    match value {
        AgentAttachmentState::Attached => "attached",
        AgentAttachmentState::Detached => "detached",
    }
}

fn lease_json(lease: &forge_domain::RecoveryMaintenanceLease) -> Value {
    json!({
        "workspace_id": lease.workspace_id().into_uuid(),
        "owner_id": lease.owner_id().map(RuntimeInstanceId::into_uuid),
        "lease_until_ms": lease.lease_until().map(TimestampMillis::get),
        "epoch": lease.epoch().get(),
        "updated_at_ms": lease.updated_at().get(),
        "revision": lease.revision().get(),
    })
}

fn delegation_json(delegation: ExpiredActivityRecoveryDelegationFence, digest: &[u8; 32]) -> Value {
    json!({
        "migration_id": delegation.migration_id(),
        "destination_id": delegation.destination_id(),
        "freeze_revision": delegation.revision(),
        "freeze_created_at_ms": delegation.created_at().get(),
        "freeze_updated_at_ms": delegation.updated_at().get(),
        "manifest_digest": hex(&delegation.manifest_digest()),
        "delegated_at_ms": delegation.delegated_at().get(),
        "delegation_digest": hex(digest),
    })
}

fn scope_json(scope: &forge_domain::ExpiredActivityRecoveryProbeScope) -> Value {
    json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "locator": {
            "location_id": scope.location_id().into_uuid(),
            "expected_revision": scope.location_revision().get(),
            "relative_root": String::from_utf8_lossy(scope.locator()),
        },
    })
}

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ForgeError::invalid_input("clock unavailable"))?
        .as_millis();
    let millis = i64::try_from(millis).map_err(|_| ForgeError::invalid_input("clock overflow"))?;
    decode_timestamp(millis)
}

#[allow(
    clippy::too_many_arguments,
    reason = "The canonical digest order mirrors the frozen request ABI."
)]
fn canonical_request_digest(
    body: &RecoverBody,
    root_fingerprint: WorkspaceRootFingerprint,
    binding_digest: [u8; 32],
    delegation: ExpiredActivityRecoveryDelegationFence,
    delegation_digest: [u8; 32],
    probe_digest: [u8; 32],
    agent_digest: [u8; 32],
    expectation: &ExpiredActivityRecoveryExpectation,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hash_uuid(&mut hasher, body.request_id);
    hash_uuid(&mut hasher, body.scope.workspace_id);
    hash_i64(&mut hasher, body.scope.workspace_revision);
    hash_uuid(&mut hasher, body.scope.locator.location_id);
    hash_i64(&mut hasher, body.scope.locator.expected_revision);
    hash_bytes(&mut hasher, body.scope.locator.relative_root.as_bytes());
    hasher.update(root_fingerprint.into_bytes());
    hasher.update(binding_digest);
    hash_delegation(&mut hasher, delegation);
    hasher.update(delegation_digest);
    hash_i64(&mut hasher, body.probe_observed_at_ms);
    hasher.update(probe_digest);
    hash_uuid(&mut hasher, body.service.backend_id);
    hash_uuid(&mut hasher, body.service.issuer);
    hash_uuid(&mut hasher, body.service.destination_id);
    hash_uuid(&mut hasher, body.service.runtime_instance_id);
    hash_expected(&mut hasher, expectation.predecessor());
    hash_uuid(&mut hasher, expectation.successor_activity_id().into_uuid());
    hash_uuid(&mut hasher, expectation.initiating_session_id().into_uuid());
    hash_principal(&mut hasher, expectation.principal());
    hash_u16(&mut hasher, expectation.expected_agent_count());
    hasher.update(agent_digest);
    match expectation.expected_coordinator() {
        Some(value) => {
            hash_u8(&mut hasher, 1);
            hash_uuid(&mut hasher, value.agent_id().into_uuid());
            hash_i64(&mut hasher, value.revision());
            hash_i64(&mut hasher, value.updated_at().get());
        }
        None => hash_u8(&mut hasher, 0),
    }
    hash_i64(&mut hasher, body.duration_ms);
    hasher.finalize().into()
}

fn decode_hex_digest(value: &str) -> Result<[u8; 32], ForgeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ForgeError::invalid_input(
            "digest must be 64 lowercase hex characters",
        ));
    }
    let mut out = [0_u8; 32];
    #[allow(
        clippy::chunks_exact_to_as_chunks,
        reason = "The validated fixed-width hex input has exactly 32 byte pairs."
    )]
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    if out == [0; 32] {
        return Err(ForgeError::invalid_input("digest must be non-zero"));
    }
    Ok(out)
}

fn decode_fingerprint(value: &str) -> Result<WorkspaceRootFingerprint, ForgeError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ForgeError::invalid_input(
            "root fingerprint must be 32 lowercase hex characters",
        ));
    }
    let mut out = [0_u8; 16];
    #[allow(
        clippy::chunks_exact_to_as_chunks,
        reason = "The validated fixed-width hex input has exactly 16 byte pairs."
    )]
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(WorkspaceRootFingerprint::from_bytes(out))
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn hex<T>(value: &T) -> String
where
    T: AsRef<[u8]> + ?Sized,
{
    let mut output = String::with_capacity(value.as_ref().len() * 2);
    for byte in value.as_ref() {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn hash_uuid(hasher: &mut Sha256, value: Uuid) {
    hasher.update(value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn hash_expected(hasher: &mut Sha256, value: ExpectedExpiredActivity) {
    hash_uuid(hasher, value.activity_id().into_uuid());
    hash_i64(hasher, value.revision().get());
    hash_i64(hasher, value.created_at().get());
    hash_i64(hasher, value.updated_at().get());
    hash_uuid(hasher, value.lease_owner_id().into_uuid());
    hash_i64(hasher, value.lease_until().get());
    hash_i64(hasher, value.lease_revision().get());
}

fn hash_delegation(hasher: &mut Sha256, value: ExpiredActivityRecoveryDelegationFence) {
    hash_uuid(hasher, value.migration_id());
    hash_uuid(hasher, value.workspace_id().into_uuid());
    hash_uuid(hasher, value.destination_id());
    hash_u8(hasher, 0);
    hash_u64(hasher, value.revision());
    hash_i64(hasher, value.created_at().get());
    hash_i64(hasher, value.updated_at().get());
    hasher.update(value.manifest_digest());
    hash_i64(hasher, value.delegated_at().get());
}

fn hash_principal(hasher: &mut Sha256, value: AuthenticatedPrincipal) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => hash_u8(hasher, 0),
        AuthenticatedPrincipal::DirectToken(id) => {
            hash_u8(hasher, 1);
            hash_uuid(hasher, id.into_uuid());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            hash_u8(hasher, 2);
            hash_uuid(hasher, id.into_uuid());
        }
    }
}

fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_le_bytes());
}

fn hash_u16(hasher: &mut Sha256, value: u16) {
    hasher.update(value.to_le_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn require_non_nil(value: Uuid, label: &'static str) -> Result<(), ForgeError> {
    if value.is_nil() {
        Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn principal_wire_shape_is_structured_and_closed() {
        let direct = principal_json(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(Uuid::from_u128(7)),
        ));
        assert_eq!(direct["kind"], "direct_token");
        assert_eq!(direct["grant_id"], Value::Null);
        assert_eq!(direct["token_id"], Uuid::from_u128(7).to_string());
    }

    #[test]
    fn blocker_wire_names_preserve_the_source_vocabulary() {
        assert_eq!(
            blocker_json(ExpiredActivityRecoveryBlocker::NonterminalCurrentDagNode),
            "nonterminal_current_dag_node"
        );
        assert_eq!(
            blocker_json(ExpiredActivityRecoveryBlocker::PendingWorkspaceStop),
            "pending_workspace_stop"
        );
    }

    #[test]
    fn probe_predecessor_uses_expected_fence_field_names() {
        let predecessor = ExpectedExpiredActivity::new(
            forge_domain::ActivityId::from_uuid(Uuid::from_u128(1)),
            forge_domain::ActivityRevision::INITIAL,
            TimestampMillis::new(1).unwrap_or_else(|_| unreachable!()),
            TimestampMillis::new(2).unwrap_or_else(|_| unreachable!()),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(2)),
            TimestampMillis::new(3).unwrap_or_else(|_| unreachable!()),
            forge_domain::ActivityLeaseRevision::INITIAL,
        )
        .unwrap_or_else(|_| unreachable!());
        let wire = probe_predecessor_json(predecessor);
        assert_eq!(wire["expected_revision"], 1);
        assert_eq!(wire["expected_created_at_ms"], 1);
        assert_eq!(wire["expected_updated_at_ms"], 2);
        assert_eq!(
            wire["expected_lease_owner_id"],
            Uuid::from_u128(2).to_string()
        );
        assert!(wire.get("revision").is_none());
        assert!(wire.get("created_at_ms").is_none());
    }

    #[test]
    fn replay_keeps_historical_owner_but_new_mutation_uses_current_boot_owner() {
        let original = RuntimeInstanceId::from_uuid(Uuid::from_u128(1));
        let current = RuntimeInstanceId::from_uuid(Uuid::from_u128(2));
        assert_eq!(
            configured_owner_from_original(true, original, current),
            original
        );
        assert_eq!(
            configured_owner_from_original(false, original, current),
            current
        );
    }

    #[test]
    fn request_digest_known_vector_uses_raw_fixed_width_uuids() {
        let payload = json!({
            "scope": {
                "workspace_id": "00000000-0000-0000-0000-000000000001",
                "workspace_revision": 1,
                "locator": {
                    "location_id": "00000000-0000-0000-0000-000000000002",
                    "expected_revision": 1,
                    "relative_root": "."
                }
            },
            "request_id": "00000000-0000-0000-0000-00000000000d",
            "service": {
                "backend_id": "00000000-0000-0000-0000-000000000009",
                "issuer": "00000000-0000-0000-0000-00000000000a",
                "destination_id": "00000000-0000-0000-0000-000000000008",
                "runtime_instance_id": "00000000-0000-0000-0000-00000000000b"
            },
            "expected_workspace_root_fingerprint": "00000000000000000000000000000000",
            "expected_binding_digest": "11".repeat(32),
            "expected_delegation": {
                "migration_id": "00000000-0000-0000-0000-000000000007",
                "destination_id": "00000000-0000-0000-0000-000000000008",
                "freeze_revision": 1,
                "freeze_created_at_ms": 10,
                "freeze_updated_at_ms": 10,
                "manifest_digest": "22".repeat(32),
                "delegated_at_ms": 11,
                "delegation_digest": "33".repeat(32)
            },
            "probe_observed_at_ms": 20,
            "expected_probe_digest": "44".repeat(32),
            "predecessor": {
                "activity_id": "00000000-0000-0000-0000-000000000003",
                "expected_revision": 1,
                "expected_created_at_ms": 1,
                "expected_updated_at_ms": 2,
                "expected_lease_owner_id": "00000000-0000-0000-0000-000000000004",
                "expected_lease_until_ms": 3,
                "expected_lease_revision": 1
            },
            "successor_activity_id": "00000000-0000-0000-0000-000000000005",
            "initiating_session_id": "00000000-0000-0000-0000-000000000006",
            "principal": {"kind": "trusted_stdio", "token_id": null, "grant_id": null},
            "expected_agent_count": 1,
            "expected_agent_digest": "55".repeat(32),
            "expected_coordinator": null,
            "duration_ms": 1000
        });
        let command = parse_recover(Uuid::from_u128(13), &payload).expect("vector parses");
        let Command::ActivityExpiredSuccessorRecover { request, .. } = command else {
            panic!("vector did not produce the recovery command");
        };
        assert_eq!(
            hex(&request.request_digest),
            "5e6976c18d2f786607b74e2e652353f29addd8b699eeeeae370dd267f5a5cdf4"
        );
    }
}
