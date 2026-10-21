//! HTTP wire contract for same-Activity continuation of expired unstarted work.
//!
//! The caller supplies only immutable probe/CAS evidence. The current trusted
//! Forge service identity is injected from [`BridgeClients`] at dispatch. It
//! fences the Source probe and fresh continuation, while the caller-intent
//! request digest remains service-independent for exact historical readback.

use std::fmt::Write as _;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use forge_control::{
    DurableUnstartedActivityContinuationRequest, UnstartedActivityContinuationGetRequest,
    UnstartedActivityContinuationProbeRequest,
};
use forge_domain::{
    ActivityId, ActivityLeaseRevision, ActivityRevision, AgentInstanceId, AgentSessionId,
    AuthenticatedPrincipal, ExpectedActivityCoordinator, ExpectedExpiredActivity,
    ExpiredActivityRecoveryDelegationFence, ExpiredActivityRecoveryFreezeState,
    RecoveryLeaseDurationMillis, TimestampMillis, UnstartedActivityContinuationExpectation,
    UnstartedActivityContinuationRequestId, UnstartedActivityContinuationServiceIdentity,
    WorkspaceRootFingerprint,
};

use super::BridgeClients;
use super::{
    Command, ParseResult, PrincipalDto, ScopeDto, decode_principal, decode_scope, decode_timestamp,
    parse_body,
};
use crate::error::{ForgeError, ReadbackHint};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"forge.activity.unstarted-continuation.request.v1\0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    scope: ScopeDto,
    activity_id: Uuid,
    initiating_session_id: Uuid,
    principal: PrincipalDto,
}

pub(super) fn parse_probe(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: ProbeBody = parse_body(payload, "unstarted Activity continuation probe is invalid")?;
    require_non_nil(body.scope.workspace_id, "scope workspace identity")?;
    require_non_nil(body.scope.locator.location_id, "scope location identity")?;
    require_non_nil(body.activity_id, "Activity identity")?;
    require_non_nil(body.initiating_session_id, "initiating Session identity")?;
    Ok(Command::ActivityUnstartedContinuationProbe {
        request_id,
        command: Box::new(ProbeCommand {
            scope: decode_scope(&body.scope)?,
            activity_id: ActivityId::from_uuid(body.activity_id),
            initiating_session_id: AgentSessionId::from_uuid(body.initiating_session_id),
            principal: decode_principal(&body.principal)?,
        }),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCommand {
    scope: forge_control::ResolvedWorkspaceScope,
    activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
    request_id: Uuid,
    request_digest: String,
}

pub(super) fn parse_get(envelope_request_id: Uuid, payload: &Value) -> ParseResult {
    let body: GetBody = parse_body(payload, "unstarted Activity continuation get is invalid")?;
    if body.request_id != envelope_request_id {
        return Err(ForgeError::invalid_input(
            "request_id must match the envelope request id",
        ));
    }
    require_non_nil(body.scope.workspace_id, "scope workspace identity")?;
    require_non_nil(body.scope.locator.location_id, "scope location identity")?;
    let request_id = continuation_request_id(body.request_id)?;
    Ok(Command::ActivityUnstartedContinuationGet {
        request_id: body.request_id,
        request: Box::new(UnstartedActivityContinuationGetRequest {
            scope: decode_scope(&body.scope)?,
            request_id,
            request_digest: decode_hex_digest(&body.request_digest)?,
        }),
    })
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityBody {
    activity_id: Uuid,
    expected_revision: i64,
    expected_created_at_ms: i64,
    expected_updated_at_ms: i64,
    expected_lease_owner_id: Uuid,
    expected_lease_until_ms: i64,
    expected_lease_revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorBody {
    agent_id: Uuid,
    revision: i64,
    updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunBody {
    scope: ScopeDto,
    request_id: Uuid,
    expected_workspace_root_fingerprint: String,
    expected_binding_digest: String,
    expected_delegation: DelegationBody,
    probe_observed_at_ms: i64,
    expected_probe_digest: String,
    census_version: u16,
    activity: ActivityBody,
    initiating_session_id: Uuid,
    principal: PrincipalDto,
    expected_agent_count: u16,
    expected_agent_digest: String,
    expected_plan_digest: String,
    expected_coordinator: Option<CoordinatorBody>,
    duration_ms: i64,
}

/// Parsed caller intent before the trusted current service tuple is injected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommand {
    scope: forge_control::ResolvedWorkspaceScope,
    request_id: UnstartedActivityContinuationRequestId,
    root_fingerprint: WorkspaceRootFingerprint,
    binding_digest: [u8; 32],
    delegation: ExpiredActivityRecoveryDelegationFence,
    delegation_digest: [u8; 32],
    probe_observed_at: TimestampMillis,
    probe_digest: [u8; 32],
    census_version: u16,
    expectation: UnstartedActivityContinuationExpectation,
    duration: RecoveryLeaseDurationMillis,
}

pub(super) fn parse_run(envelope_request_id: Uuid, payload: &Value) -> ParseResult {
    let body: RunBody = parse_body(payload, "unstarted Activity continuation run is invalid")?;
    if body.request_id != envelope_request_id {
        return Err(ForgeError::invalid_input(
            "request_id must match the envelope request id",
        ));
    }
    require_non_nil(body.scope.workspace_id, "scope workspace identity")?;
    require_non_nil(body.scope.locator.location_id, "scope location identity")?;
    require_non_nil(body.activity.activity_id, "Activity identity")?;
    require_non_nil(
        body.activity.expected_lease_owner_id,
        "expired lease owner identity",
    )?;
    require_non_nil(body.initiating_session_id, "initiating Session identity")?;
    if body.census_version != forge_domain::UNSTARTED_ACTIVITY_CONTINUATION_CENSUS_VERSION {
        return Err(ForgeError::invalid_input(
            "continuation census version is unsupported",
        ));
    }
    require_non_nil(
        body.expected_delegation.migration_id,
        "delegation migration identity",
    )?;
    require_non_nil(
        body.expected_delegation.destination_id,
        "delegation destination identity",
    )?;

    let activity = ExpectedExpiredActivity::new(
        ActivityId::from_uuid(body.activity.activity_id),
        ActivityRevision::new(body.activity.expected_revision)
            .map_err(|_| ForgeError::invalid_input("Activity revision is invalid"))?,
        decode_timestamp(body.activity.expected_created_at_ms)?,
        decode_timestamp(body.activity.expected_updated_at_ms)?,
        forge_domain::RuntimeInstanceId::from_uuid(body.activity.expected_lease_owner_id),
        decode_timestamp(body.activity.expected_lease_until_ms)?,
        ActivityLeaseRevision::new(body.activity.expected_lease_revision)
            .map_err(|_| ForgeError::invalid_input("Activity lease revision is invalid"))?,
    )
    .map_err(|_| ForgeError::invalid_input("Activity fence is invalid"))?;
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
    let expectation = UnstartedActivityContinuationExpectation::new(
        activity,
        AgentSessionId::from_uuid(body.initiating_session_id),
        decode_principal(&body.principal)?,
        body.expected_agent_count,
        decode_hex_digest(&body.expected_agent_digest)?,
        decode_hex_digest(&body.expected_plan_digest)?,
        coordinator,
    )
    .map_err(|_| ForgeError::invalid_input("continuation expectation is invalid"))?;
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
    Ok(Command::ActivityUnstartedContinuationRun {
        request_id: body.request_id,
        command: Box::new(RunCommand {
            scope: decode_scope(&body.scope)?,
            request_id: continuation_request_id(body.request_id)?,
            root_fingerprint: decode_fingerprint(&body.expected_workspace_root_fingerprint)?,
            binding_digest: decode_hex_digest(&body.expected_binding_digest)?,
            delegation,
            delegation_digest: decode_hex_digest(&body.expected_delegation.delegation_digest)?,
            probe_observed_at: decode_timestamp(body.probe_observed_at_ms)?,
            probe_digest: decode_hex_digest(&body.expected_probe_digest)?,
            census_version: body.census_version,
            expectation,
            duration: RecoveryLeaseDurationMillis::new(body.duration_ms)
                .map_err(|_| ForgeError::invalid_input("duration is invalid"))?,
        }),
    })
}

pub(super) fn execute_probe(
    clients: &BridgeClients,
    command: &ProbeCommand,
) -> Result<Value, ForgeError> {
    let service = current_service(clients)?;
    let request = UnstartedActivityContinuationProbeRequest {
        scope: command.scope.clone(),
        activity_id: command.activity_id,
        initiating_session_id: command.initiating_session_id,
        principal: command.principal,
        service,
        observed_at: current_timestamp_millis()?,
    };
    let probe = clients
        .control
        .unstarted_activity_continuation_probe(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    if probe.delegation().destination_id() != clients.destination_id {
        return Err(ForgeError::invalid_input(
            "continuation delegation destination does not match this service",
        ));
    }
    Ok(probe_json(&probe))
}

pub(super) fn execute_run(
    clients: &BridgeClients,
    command: &RunCommand,
) -> Result<Value, ForgeError> {
    let request_digest = canonical_request_digest(command);
    let readback = clients
        .control
        .unstarted_activity_continuation_get(UnstartedActivityContinuationGetRequest {
            scope: command.scope.clone(),
            request_id: command.request_id,
            request_digest,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let fresh_service = select_current_service_for_run(
        readback.is_some(),
        clients.backend_id,
        clients.issuer,
        clients.runtime_instance_id,
    )?;
    if let Some(readback) = readback {
        return Ok(json!({
            "status": "replay",
            "replayed": true,
            "claim_conflict": false,
            "retry_authorized": false,
            "receipt": receipt_json(readback.receipt()),
            "current_activity": activity_json(readback.current_activity()),
        }));
    }
    let service = fresh_service.ok_or_else(ForgeError::internal)?;
    let request = DurableUnstartedActivityContinuationRequest {
        scope: command.scope.clone(),
        request_id: command.request_id,
        request_digest,
        expected_workspace_root_fingerprint: command.root_fingerprint,
        expected_binding_digest: command.binding_digest,
        expected_delegation: command.delegation,
        expected_delegation_digest: command.delegation_digest,
        probe_observed_at: command.probe_observed_at,
        expected_probe_digest: command.probe_digest,
        duration: command.duration,
        expectation: command.expectation.clone(),
        service,
        service_destination_id: command.delegation.destination_id(),
    };
    let report = clients
        .control
        .unstarted_activity_continuation_run(request)
        .map_err(|error| super::forge_error_of_client(&error))?;
    report_json(&report)
}

pub(super) fn execute_get(
    clients: &BridgeClients,
    request: &UnstartedActivityContinuationGetRequest,
) -> Result<Value, ForgeError> {
    let readback = clients
        .control
        .unstarted_activity_continuation_get(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some(readback) = readback else {
        return Ok(json!({
            "status": "absent_now",
            "found": false,
            "receipt": null,
            "current_activity": null,
            "retry_authorized": false,
        }));
    };
    Ok(json!({
        "status": "recorded",
        "found": true,
        "receipt": receipt_json(readback.receipt()),
        "current_activity": activity_json(readback.current_activity()),
        "retry_authorized": false,
    }))
}

pub(super) fn readback_hint(command: &RunCommand) -> ReadbackHint {
    ReadbackHint::UnstartedActivityContinuation {
        workspace_id: command.scope.workspace_id().into_uuid(),
        request_id: command.request_id.into_uuid(),
        request_digest: hex(&canonical_request_digest(command)),
        activity_id: command.expectation.activity().activity_id().into_uuid(),
    }
}

fn current_service(
    clients: &BridgeClients,
) -> Result<UnstartedActivityContinuationServiceIdentity, ForgeError> {
    UnstartedActivityContinuationServiceIdentity::new(
        clients.backend_id,
        clients.issuer,
        clients.runtime_instance_id,
    )
    .map_err(|_| ForgeError::invalid_input("current Forge service identity is invalid"))
}

fn select_current_service_for_run(
    historical_receipt_found: bool,
    backend_id: forge_domain::ForgeBackendId,
    issuer: forge_domain::OrchestrationIssuerId,
    runtime_instance_id: forge_domain::RuntimeInstanceId,
) -> Result<Option<UnstartedActivityContinuationServiceIdentity>, ForgeError> {
    if historical_receipt_found {
        return Ok(None);
    }
    UnstartedActivityContinuationServiceIdentity::new(backend_id, issuer, runtime_instance_id)
        .map(Some)
        .map_err(|_| ForgeError::invalid_input("current Forge service identity is invalid"))
}

fn require_current_activity(
    current_activity: Option<&forge_domain::RegisteredActivity>,
) -> Result<&forge_domain::RegisteredActivity, ForgeError> {
    current_activity.ok_or_else(ForgeError::internal)
}

fn probe_json(probe: &forge_domain::UnstartedActivityContinuationProbe) -> Value {
    let expectation = probe.expectation();
    json!({
        "scope": probe_scope_json(probe.scope()),
        "service": service_identity_json(probe.service()),
        "workspace_root_fingerprint": hex(&probe.scope().root_fingerprint().into_bytes()),
        "binding_digest": hex(probe.scope().binding_digest()),
        "delegation": delegation_json(probe.delegation(), probe.delegation_digest()),
        "activity": expected_activity_json(expectation.activity()),
        "initiating_session_id": expectation.initiating_session_id().into_uuid(),
        "principal": principal_json(expectation.principal()),
        "agent_count": expectation.expected_agent_count(),
        "agent_digest": hex(&expectation.expected_agent_digest()),
        "plan_digest": hex(&expectation.expected_plan_digest()),
        "coordinator": expectation.expected_coordinator().map(coordinator_json),
        "census_version": probe.census_version(),
        "probe_observed_at_ms": probe.observed_at().get(),
        "probe_digest": hex(&probe.probe_digest()),
        "continuable_now": probe.continuable_now(),
        "blocker": probe.blocker().map(blocker_json),
        "session_readiness_certified": false,
        "physical_effect_completion_certified": false,
    })
}

fn report_json(
    report: &forge_control::UnstartedActivityContinuationReport,
) -> Result<Value, ForgeError> {
    if let Some(receipt) = report.receipt() {
        let current_activity = require_current_activity(report.current_activity())?;
        return Ok(json!({
            "status": if report.replayed() { "replay" } else { "recorded" },
            "replayed": report.replayed(),
            "claim_conflict": false,
            "retry_authorized": false,
            "receipt": receipt_json(receipt),
            "current_activity": activity_json(current_activity),
        }));
    }
    let lease = report
        .maintenance_lease()
        .ok_or_else(ForgeError::internal)?;
    Ok(json!({
        "status": if report.claim_conflict() { "claim_conflict" } else { "maintenance_busy" },
        "replayed": false,
        "claim_conflict": report.claim_conflict(),
        "retry_authorized": false,
        "receipt": null,
        "current_activity": null,
        "maintenance_lease": maintenance_lease_json(lease),
    }))
}

fn receipt_json(receipt: &forge_persistence::UnstartedActivityContinuationReceipt) -> Value {
    let expectation = receipt.expectation();
    json!({
        "request_id": receipt.request_id().into_uuid(),
        "request_digest": hex(&receipt.request_digest()),
        "scope": probe_scope_json(receipt.probe_scope()),
        "workspace_root_fingerprint": hex(&receipt.probe_scope().root_fingerprint().into_bytes()),
        "binding_digest": hex(receipt.probe_scope().binding_digest()),
        "service": service_identity_json(receipt.service()),
        "delegation": delegation_json(receipt.delegation(), receipt.delegation_digest()),
        "probe_observed_at_ms": receipt.probe_observed_at().get(),
        "probe_digest": hex(&receipt.probe_digest()),
        "census_version": forge_domain::UNSTARTED_ACTIVITY_CONTINUATION_CENSUS_VERSION,
        "activity_before": expected_activity_json(expectation.activity()),
        "initiating_session_id": expectation.initiating_session_id().into_uuid(),
        "principal": principal_json(expectation.principal()),
        "agent_count": expectation.expected_agent_count(),
        "agent_digest": hex(&expectation.expected_agent_digest()),
        "plan_digest": hex(&expectation.expected_plan_digest()),
        "coordinator": expectation.expected_coordinator().map(coordinator_json),
        "continued_at_ms": receipt.continued_at().get(),
        "lease_gap_ms": receipt.lease_gap_ms(),
        "activity_after": activity_json(receipt.activity_after()),
        "receipt_digest": hex(&receipt.receipt_digest()),
        "same_activity": true,
        "session_readiness_certified": false,
        "physical_effect_completion_certified": false,
    })
}

fn service_json(
    backend_id: forge_domain::ForgeBackendId,
    issuer: forge_domain::OrchestrationIssuerId,
    runtime_instance_id: forge_domain::RuntimeInstanceId,
) -> Value {
    json!({
        "backend_id": backend_id.into_uuid(),
        "issuer": issuer.into_uuid(),
        "runtime_instance_id": runtime_instance_id.into_uuid(),
    })
}

fn service_identity_json(value: UnstartedActivityContinuationServiceIdentity) -> Value {
    service_json(
        value.backend_id(),
        value.issuer(),
        value.runtime_instance_id(),
    )
}

fn expected_activity_json(value: ExpectedExpiredActivity) -> Value {
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

fn activity_json(value: &forge_domain::RegisteredActivity) -> Value {
    json!({
        "activity_id": value.id().into_uuid(),
        "state": match value.state() {
            forge_domain::ActivityState::Open => "open",
            forge_domain::ActivityState::Closed => "closed",
            forge_domain::ActivityState::Interrupted => "interrupted",
        },
        "revision": value.revision().get(),
        "created_at_ms": value.created_at().get(),
        "updated_at_ms": value.updated_at().get(),
        "lease_owner_id": value.lease_owner_id().map(forge_domain::RuntimeInstanceId::into_uuid),
        "lease_until_ms": value.lease_until().map(TimestampMillis::get),
        "lease_revision": value.lease_revision().get(),
    })
}

fn delegation_json(value: ExpiredActivityRecoveryDelegationFence, digest: [u8; 32]) -> Value {
    json!({
        "migration_id": value.migration_id(),
        "destination_id": value.destination_id(),
        "freeze_revision": value.revision(),
        "freeze_created_at_ms": value.created_at().get(),
        "freeze_updated_at_ms": value.updated_at().get(),
        "manifest_digest": hex(&value.manifest_digest()),
        "delegated_at_ms": value.delegated_at().get(),
        "delegation_digest": hex(&digest),
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
        AuthenticatedPrincipal::TrustedStdio => {
            json!({"kind":"trusted_stdio","token_id":null,"grant_id":null})
        }
        AuthenticatedPrincipal::DirectToken(id) => {
            json!({"kind":"direct_token","token_id":id.into_uuid(),"grant_id":null})
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            json!({"kind":"oauth_grant","token_id":null,"grant_id":id.into_uuid()})
        }
    }
}

fn blocker_json(value: forge_domain::UnstartedActivityContinuationBlocker) -> &'static str {
    use forge_domain::UnstartedActivityContinuationBlocker as Blocker;
    match value {
        Blocker::ActivityNotOpen => "activity_not_open",
        Blocker::LeaseNotExpired => "lease_not_expired",
        Blocker::GoalNotActive => "goal_not_active",
        Blocker::DagNotPendingInitial => "dag_not_pending_initial",
        Blocker::DagEvidencePresent => "dag_evidence_present",
        Blocker::AssignmentNotOffered => "assignment_not_offered",
        Blocker::AssignmentEvidencePresent => "assignment_evidence_present",
        Blocker::ArbitraryWorkHistory => "arbitrary_work_history",
        Blocker::ExecutionPresent => "execution_present",
        Blocker::WriterLeasePresent => "writer_lease_present",
        Blocker::PhysicalEffectPresent => "physical_effect_present",
        Blocker::PendingActivation => "pending_activation",
        Blocker::OrphanRecord => "orphan_record",
        Blocker::UnclassifiedSchemaObject => "unclassified_schema_object",
    }
}

fn probe_scope_json(scope: &forge_domain::ExpiredActivityRecoveryProbeScope) -> Value {
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

fn maintenance_lease_json(value: &forge_domain::RecoveryMaintenanceLease) -> Value {
    json!({
        "workspace_id": value.workspace_id().into_uuid(),
        "owner_id": value.owner_id().map(forge_domain::RuntimeInstanceId::into_uuid),
        "revision": value.revision().get(),
        "lease_until_ms": value.lease_until().map(TimestampMillis::get),
        "epoch": value.epoch().get(),
        "updated_at_ms": value.updated_at().get(),
    })
}

fn canonical_request_digest(command: &RunCommand) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hash_uuid(&mut hasher, command.request_id.into_uuid());
    hash_uuid(&mut hasher, command.scope.workspace_id().into_uuid());
    hash_i64(&mut hasher, command.scope.workspace_revision().get());
    hash_uuid(
        &mut hasher,
        command.scope.locator().location_id().into_uuid(),
    );
    hash_i64(
        &mut hasher,
        command.scope.locator().expected_revision().get(),
    );
    hash_bytes(&mut hasher, command.scope.locator().relative_root_bytes());
    hasher.update(command.root_fingerprint.into_bytes());
    hasher.update(command.binding_digest);
    hash_delegation(&mut hasher, command.delegation);
    hasher.update(command.delegation_digest);
    hash_i64(&mut hasher, command.probe_observed_at.get());
    hasher.update(command.probe_digest);
    hash_u16(&mut hasher, command.census_version);
    hash_expected(&mut hasher, command.expectation.activity());
    hash_uuid(
        &mut hasher,
        command.expectation.initiating_session_id().into_uuid(),
    );
    hash_principal(&mut hasher, command.expectation.principal());
    hash_u16(&mut hasher, command.expectation.expected_agent_count());
    hasher.update(command.expectation.expected_agent_digest());
    hasher.update(command.expectation.expected_plan_digest());
    match command.expectation.expected_coordinator() {
        Some(value) => {
            hash_u8(&mut hasher, 1);
            hash_uuid(&mut hasher, value.agent_id().into_uuid());
            hash_i64(&mut hasher, value.revision());
            hash_i64(&mut hasher, value.updated_at().get());
        }
        None => hash_u8(&mut hasher, 0),
    }
    hash_i64(&mut hasher, command.duration.get());
    hasher.finalize().into()
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

fn hash_expected(hasher: &mut Sha256, value: ExpectedExpiredActivity) {
    hash_uuid(hasher, value.activity_id().into_uuid());
    hash_i64(hasher, value.revision().get());
    hash_i64(hasher, value.created_at().get());
    hash_i64(hasher, value.updated_at().get());
    hash_uuid(hasher, value.lease_owner_id().into_uuid());
    hash_i64(hasher, value.lease_until().get());
    hash_i64(hasher, value.lease_revision().get());
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

fn continuation_request_id(
    value: Uuid,
) -> Result<UnstartedActivityContinuationRequestId, ForgeError> {
    UnstartedActivityContinuationRequestId::new(value)
        .map_err(|_| ForgeError::invalid_input("request identity is invalid"))
}

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ForgeError::invalid_input("clock unavailable"))?
        .as_millis();
    let millis = i64::try_from(millis).map_err(|_| ForgeError::invalid_input("clock overflow"))?;
    decode_timestamp(millis)
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

fn require_non_nil(value: Uuid, name: &str) -> Result<(), ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!("{name} must be non-nil")));
    }
    Ok(())
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
fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_le_bytes());
}
fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
fn hash_u16(hasher: &mut Sha256, value: u16) {
    hasher.update(value.to_le_bytes());
}
fn hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_payload() -> Value {
        json!({
            "scope": {
                "workspace_id": "00000000-0000-0000-0000-000000000001",
                "workspace_revision": 2,
                "locator": {
                    "location_id": "00000000-0000-0000-0000-000000000002",
                    "expected_revision": 3,
                    "relative_root": "repo"
                }
            },
            "request_id": "00000000-0000-0000-0000-000000000003",
            "expected_workspace_root_fingerprint": "101112131415161718191a1b1c1d1e1f",
            "expected_binding_digest": "20".repeat(32),
            "expected_delegation": {
                "migration_id": "00000000-0000-0000-0000-000000000004",
                "destination_id": "00000000-0000-0000-0000-000000000005",
                "freeze_revision": 1,
                "freeze_created_at_ms": 7,
                "freeze_updated_at_ms": 7,
                "manifest_digest": "30".repeat(32),
                "delegated_at_ms": 9,
                "delegation_digest": "40".repeat(32)
            },
            "probe_observed_at_ms": 10,
            "expected_probe_digest": "50".repeat(32),
            "census_version": 1,
            "activity": {
                "activity_id": "00000000-0000-0000-0000-000000000006",
                "expected_revision": 11,
                "expected_created_at_ms": 12,
                "expected_updated_at_ms": 13,
                "expected_lease_owner_id": "00000000-0000-0000-0000-000000000007",
                "expected_lease_until_ms": 14,
                "expected_lease_revision": 15
            },
            "initiating_session_id": "00000000-0000-0000-0000-000000000008",
            "principal": {"kind":"trusted_stdio","token_id":null,"grant_id":null},
            "expected_agent_count": 1,
            "expected_agent_digest": "60".repeat(32),
            "expected_plan_digest": "70".repeat(32),
            "expected_coordinator": {
                "agent_id": "00000000-0000-0000-0000-000000000009",
                "revision": 16,
                "updated_at_ms": 17
            },
            "duration_ms": 30000
        })
    }

    #[test]
    fn canonical_digest_is_stable_caller_intent_before_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let request_id = Uuid::from_u128(3);
        let command = parse_run(request_id, &run_payload())?;
        let Command::ActivityUnstartedContinuationRun { command, .. } = command else {
            return Err("wrong command".into());
        };
        assert_eq!(
            hex(&canonical_request_digest(&command)),
            "e70d8e43db0806f602dd13b73039ad684058c518ec425c5fa5d9bd22e579ec2d"
        );
        Ok(())
    }

    #[test]
    fn caller_cannot_supply_current_service_identity() {
        let request_id = Uuid::from_u128(3);
        let mut payload = run_payload();
        payload["service"] = json!({
            "backend_id": Uuid::from_u128(10),
            "issuer": Uuid::from_u128(11),
            "runtime_instance_id": Uuid::from_u128(12),
        });
        assert!(parse_run(request_id, &payload).is_err());
    }

    #[test]
    fn historical_replay_does_not_validate_unavailable_current_service_metadata() {
        let selected = select_current_service_for_run(
            true,
            forge_domain::ForgeBackendId::from_uuid(Uuid::nil()),
            forge_domain::OrchestrationIssuerId::from_uuid(Uuid::nil()),
            forge_domain::RuntimeInstanceId::from_uuid(Uuid::nil()),
        );
        assert_eq!(selected, Ok(None));
        assert!(
            select_current_service_for_run(
                false,
                forge_domain::ForgeBackendId::from_uuid(Uuid::nil()),
                forge_domain::OrchestrationIssuerId::from_uuid(Uuid::nil()),
                forge_domain::RuntimeInstanceId::from_uuid(Uuid::nil()),
            )
            .is_err()
        );
    }

    #[test]
    fn recorded_or_replay_without_current_activity_fails_closed() {
        assert!(require_current_activity(None).is_err());
    }
}
