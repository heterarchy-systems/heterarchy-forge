//! Activity bootstrap and read-only observability ops: approval evidence and
//! the Diff doctor/retention family. Each op forwards one parsed DTO to
//! exactly one forge-control capability and projects the typed result into a
//! bounded JSON readback. All are issuer-only in this slice; where the control
//! capability consults durable session provenance (approval evidence), it
//! does so fail-closed internally.

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use forge_control::{ForgeControlClient, ResolvedWorkspaceScope};
use forge_domain::{
    ActivityId, ApprovalRequestId, DiffId, DiffListLimit, DiffRetentionKeepCount,
    RegisteredApprovalRequest, RuntimeInstanceId, TimestampMillis,
};

use crate::error::ForgeError;

use super::{Command, ParseResult, ScopeDto, decode_scope, decode_timestamp};

pub(super) fn bootstrap_readback_hint(
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
) -> crate::error::ReadbackHint {
    crate::error::ReadbackHint::ActivityBootstrap {
        workspace_id: scope.workspace_id().into_uuid(),
        activity_id: activity_id.into_uuid(),
        runtime_instance_id: runtime_instance_id.into_uuid(),
    }
}

pub(super) fn parse_activity_bootstrap(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        runtime_instance_id: Uuid,
        observed_at_ms: i64,
        lease_until_ms: i64,
    }
    let body: Body = super::parse_body(payload, "activity.bootstrap payload is invalid")?;
    if body.activity_id.is_nil()
        || body.runtime_instance_id.is_nil()
        || body.scope.workspace_id.is_nil()
        || body.scope.locator.location_id.is_nil()
    {
        return Err(ForgeError::invalid_input(
            "activity.bootstrap identities must not be nil",
        ));
    }
    let observed_at = decode_timestamp(body.observed_at_ms)?;
    let lease_until = decode_timestamp(body.lease_until_ms)?;
    if lease_until.get() <= observed_at.get() {
        return Err(ForgeError::invalid_input(
            "the activity lease must outlive its observation",
        ));
    }
    Ok(Command::ActivityBootstrap {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
        runtime_instance_id: RuntimeInstanceId::from_uuid(body.runtime_instance_id),
        observed_at,
        lease_until,
    })
}

pub(super) fn execute_activity_bootstrap(
    client: &forge_control::ActivityLeaseClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    observed_at: TimestampMillis,
    lease_until: TimestampMillis,
) -> Result<Value, ForgeError> {
    let bootstrap = client
        .bootstrap_activity(
            scope.clone(),
            activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
        )
        .map_err(|error| super::forge_error_of_client(&error))?;
    if bootstrap.status() == forge_control::ActivityBootstrapStatus::CommittedButUnconfirmed
        || bootstrap.status().is_committed()
            && bootstrap.activity().is_none_or(|activity| {
                activity.id() != activity_id
                    || activity.workspace_id() != scope.workspace_id()
                    || activity.lease_owner_id() != Some(runtime_instance_id)
                    || activity.lease_until().is_none()
            })
    {
        return Err(ForgeError::unknown_outcome(Some(
            crate::error::ReadbackHint::ActivityBootstrap {
                workspace_id: scope.workspace_id().into_uuid(),
                activity_id: activity_id.into_uuid(),
                runtime_instance_id: runtime_instance_id.into_uuid(),
            },
        )));
    }
    let activity = bootstrap
        .activity()
        .map(super::activity_lifecycle::registered_activity_json);
    Ok(json!({
        "status": bootstrap_status_name(bootstrap.status()),
        "committed": bootstrap.status().is_committed(),
        "activity": activity,
    }))
}

const fn bootstrap_status_name(status: forge_control::ActivityBootstrapStatus) -> &'static str {
    match status {
        forge_control::ActivityBootstrapStatus::Created => "created",
        forge_control::ActivityBootstrapStatus::Resumed => "resumed",
        forge_control::ActivityBootstrapStatus::ExpiredRecoveryRequired => {
            "expired_recovery_required"
        }
        forge_control::ActivityBootstrapStatus::UnleasedRecoveryRequired => {
            "unleased_recovery_required"
        }
        forge_control::ActivityBootstrapStatus::AlreadyOwned => "already_owned",
        forge_control::ActivityBootstrapStatus::AlreadyLive => "already_live",
        forge_control::ActivityBootstrapStatus::Terminal => "terminal",
        forge_control::ActivityBootstrapStatus::CommittedButUnconfirmed => {
            "committed_but_unconfirmed"
        }
    }
}

pub(super) fn parse_approval_pending(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
    }
    let body: Body = super::parse_body(payload, "approval.pending payload is invalid")?;
    Ok(Command::ApprovalPending {
        request_id,
        scope: decode_scope(&body.scope)?,
    })
}

pub(super) fn execute_approval_pending(
    approval: &forge_control::ForgeApprovalCoordinatorClient,
    scope: &ResolvedWorkspaceScope,
) -> Result<Value, ForgeError> {
    let pending = approval
        .list_pending(scope.clone())
        .map_err(|error| ForgeError::from_control_view(&error.view()))?;
    let projections: Vec<_> = pending
        .into_iter()
        .map(|record| {
            json!({
                "approval_id": record.approval_id().into_uuid(),
                "workspace_id": record.workspace_id().into_uuid(),
                "activity_id": record.activity_id().into_uuid(),
                "execution_id": record.execution_id().into_uuid(),
                "action_class": super::execution::action_class_name(record.action()),
                "expires_at_ms": record.expires_at().get(),
                "local_payload_available": record.actionable(),
            })
        })
        .collect();
    Ok(json!({ "pending": projections, "limit": 256, "bounded": true }))
}

pub(super) fn parse_approval_get(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        approval_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "approval.get payload is invalid")?;
    Ok(Command::ApprovalGet {
        request_id,
        scope: decode_scope(&body.scope)?,
        approval_id: ApprovalRequestId::from_uuid(body.approval_id),
    })
}

pub(super) fn execute_approval_get(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    approval_id: ApprovalRequestId,
) -> Result<Value, ForgeError> {
    let found = client
        .approval_get_with_grant(scope.clone(), approval_id)
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some((approval, execution, grant)) = found else {
        return Ok(json!({ "found": false }));
    };
    Ok(approval_projection_json(
        &approval,
        execution.as_ref(),
        grant.as_ref(),
    ))
}

pub(super) fn approval_projection_json(
    approval: &RegisteredApprovalRequest,
    execution: Option<&forge_domain::RegisteredExecution>,
    grant: Option<&forge_domain::ExecutionGrant>,
) -> Value {
    let request = approval.request();
    let permissions = request.requested();
    json!({
        "found": true,
        "approval_id": approval.id().into_uuid(),
        "state": approval_state_name(approval.state()),
        "policy_revision": approval.policy_revision().get(),
        "created_at_ms": approval.created_at().get(),
        "expires_at_ms": approval.expires_at().get(),
        "decided_at_ms": approval.decided_at().map(forge_domain::TimestampMillis::get),
        "revision": approval.revision().get(),
        "agent_binding_present": approval.agent_binding().is_some(),
        "request": {
            "execution_id": request.execution_id().into_uuid(),
            "workspace_id": request.workspace_id().into_uuid(),
            "activity_id": request.activity_id().into_uuid(),
            "request_digest": super::encode_hex(request.request_digest().as_bytes()),
            "action_class": super::execution::action_class_name(request.action()),
            "permissions": {
                "workspace_read": permissions.get().workspace_read(),
                "workspace_write": permissions.get().workspace_write(),
                "network": permissions.get().network(),
            },
        },
        "execution": execution.map(|record| json!({
            "execution_id": record.id().into_uuid(),
            "state": super::execution_evidence::execution_state_name(record.state()),
        })),
        "grant": grant.map(|grant| json!({
            "grant_id": grant.id().into_uuid(),
            "approval_id": grant.approval_id().into_uuid(),
            "request_digest": super::encode_hex(grant.request().request_digest().as_bytes()),
            "state": execution_grant_state_name(grant.state()),
            "revision": grant.revision().get(),
            "expires_at_ms": grant.expires_at().get(),
        })),
    })
}

const fn approval_state_name(state: forge_domain::ApprovalRequestState) -> &'static str {
    match state {
        forge_domain::ApprovalRequestState::Pending => "pending",
        forge_domain::ApprovalRequestState::Approved => "approved",
        forge_domain::ApprovalRequestState::Rejected => "rejected",
        forge_domain::ApprovalRequestState::AutoApproved => "auto_approved",
        forge_domain::ApprovalRequestState::Denied => "denied",
        forge_domain::ApprovalRequestState::Cancelled => "cancelled",
        forge_domain::ApprovalRequestState::Expired => "expired",
        forge_domain::ApprovalRequestState::Superseded => "superseded",
    }
}

const fn execution_grant_state_name(state: forge_domain::ExecutionGrantState) -> &'static str {
    match state {
        forge_domain::ExecutionGrantState::Active => "active",
        forge_domain::ExecutionGrantState::Consumed => "consumed",
        forge_domain::ExecutionGrantState::Revoked => "revoked",
        forge_domain::ExecutionGrantState::Expired => "expired",
    }
}

pub(super) fn parse_diff_list(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "diff.list payload is invalid")?;
    Ok(Command::DiffList {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
    })
}

pub(super) fn execute_diff_list(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
) -> Result<Value, ForgeError> {
    let result = client
        .diff_list(forge_control::DiffListRequest {
            scope: scope.clone(),
            activity_id,
            limit: DiffListLimit::DEFAULT,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let diffs = result
        .diffs()
        .iter()
        .map(super::diff_evidence_json)
        .collect::<Vec<_>>();
    Ok(json!({
        "diffs": diffs,
        "diff_count": diffs.len(),
        "scope": super::source::scope_json(result.scope())?,
        "activity_id":activity_id.into_uuid(),
    }))
}

pub(super) fn parse_diff_doctor(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        diff_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "diff.doctor payload is invalid")?;
    Ok(Command::DiffDoctor {
        request_id,
        scope: decode_scope(&body.scope)?,
        diff_id: DiffId::from_uuid(body.diff_id),
    })
}

pub(super) fn execute_diff_doctor(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    diff_id: DiffId,
) -> Result<Value, ForgeError> {
    let result = client
        .diff_doctor(forge_control::DiffDoctorRequest {
            scope: scope.clone(),
            diff_id,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "diff_id": result.evidence().id().into_uuid(),
        "health": super::diff_health_json(result.health()),
        "evidence": super::diff_evidence_json(result.evidence()),
    }))
}

pub(super) fn parse_diff_retention_plan(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        keep_recent: u32,
    }
    let body: Body = super::parse_body(payload, "diff.retention_plan payload is invalid")?;
    let keep_recent = DiffRetentionKeepCount::new(body.keep_recent)
        .map_err(|_| ForgeError::invalid_input("the retention keep count is out of range"))?;
    Ok(Command::DiffRetentionPlan {
        request_id,
        scope: decode_scope(&body.scope)?,
        keep_recent,
    })
}

pub(super) fn execute_diff_retention_plan(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    keep_recent: DiffRetentionKeepCount,
) -> Result<Value, ForgeError> {
    let result = client
        .plan_diff_retention(forge_control::DiffRetentionPlanRequest {
            scope: scope.clone(),
            keep_recent,
            limit: forge_domain::DiffRetentionPlanLimit::DEFAULT,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let plan = result.plan();
    let candidates = plan
        .candidates()
        .iter()
        .map(super::diff_evidence_json)
        .collect::<Vec<_>>();
    Ok(json!({
        "keep_recent": plan.keep_recent().get(),
        "candidate_count": candidates.len(),
        "candidates": candidates,
    }))
}

pub(super) fn parse_diff_artifact_doctor(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
    }
    let body: Body = super::parse_body(payload, "diff.artifact_doctor payload is invalid")?;
    Ok(Command::DiffArtifactDoctor {
        request_id,
        scope: decode_scope(&body.scope)?,
    })
}

pub(super) fn execute_diff_artifact_doctor(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
) -> Result<Value, ForgeError> {
    let result = client
        .diff_artifact_doctor(forge_control::DiffArtifactDoctorRequest {
            scope: scope.clone(),
            limit: forge_domain::DiffArtifactInventoryLimit::DEFAULT,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let entries = result
        .entries()
        .iter()
        .map(|entry| {
            json!({
                "diff_id": entry.artifact().diff_id().map(forge_domain::DiffId::into_uuid),
                "kind": format!("{:?}", entry.artifact().kind()).to_ascii_lowercase(),
                "ownership": format!("{:?}", entry.ownership()).to_ascii_lowercase(),
                "path_label": entry.path_label(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "entries": entries,
        "entry_count": entries.len(),
        "invalid_entry_count": result.invalid_entries().len(),
        "truncated": result.truncated(),
    }))
}
