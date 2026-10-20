//! Typed local Approval mutations over the Forge control authority.
//!
//! These operations deliberately call [`ForgeControlClient`] directly. The
//! process-level approval coordinator owns retained pending payload cleanup;
//! its `approve_once` path also starts execution and therefore cannot be used
//! for the local grant handoff.

use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use forge_control::{ApprovalDecisionRequest, ApprovalOnceRequest, ForgeControlClient};
use forge_domain::{ApprovalDecision, ApprovalRequestId, ApprovalRevision, ExecutionGrantId};

use super::{Command, ParseResult, ScopeDto, decode_scope, decode_timestamp, parse_body};
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveOnceBody {
    scope: ScopeDto,
    approval_id: Uuid,
    expected_revision: i64,
    grant_id: Uuid,
    observed_at_ms: i64,
    grant_expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectBody {
    scope: ScopeDto,
    approval_id: Uuid,
    expected_revision: i64,
    observed_at_ms: i64,
}

pub(super) fn parse_approve_once(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: ApproveOnceBody = parse_body(payload, "approval.approve_once payload is invalid")?;
    let approval_id = ApprovalRequestId::from_uuid(require_id(body.approval_id, "approval id")?);
    let expected_revision = ApprovalRevision::new(body.expected_revision)
        .map_err(|_| ForgeError::invalid_input("approval revision is invalid"))?;
    let grant_id = ExecutionGrantId::from_uuid(require_id(body.grant_id, "grant id")?);
    Ok(Command::ApprovalApproveOnce {
        request_id,
        request: Box::new(ApprovalOnceRequest {
            scope: decode_scope(&body.scope)?,
            approval_id,
            expected_revision,
            grant_id,
            observed_at: decode_timestamp(body.observed_at_ms)?,
            grant_expires_at: decode_timestamp(body.grant_expires_at_ms)?,
        }),
    })
}

pub(super) fn parse_reject(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: RejectBody = parse_body(payload, "approval.reject payload is invalid")?;
    let approval_id = ApprovalRequestId::from_uuid(require_id(body.approval_id, "approval id")?);
    let expected_revision = ApprovalRevision::new(body.expected_revision)
        .map_err(|_| ForgeError::invalid_input("approval revision is invalid"))?;
    Ok(Command::ApprovalReject {
        request_id,
        request: Box::new(ApprovalDecisionRequest {
            scope: decode_scope(&body.scope)?,
            approval_id,
            decision: ApprovalDecision::Reject,
            expected_revision,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        }),
    })
}

pub(super) fn execute_approve_once(
    client: &ForgeControlClient,
    request: &ApprovalOnceRequest,
) -> Result<Value, ForgeError> {
    let (approval, grant) = client
        .approve_once(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(super::observability::approval_projection_json(
        &approval,
        None,
        Some(&grant),
    ))
}

pub(super) fn execute_reject(
    client: &ForgeControlClient,
    request: &ApprovalDecisionRequest,
) -> Result<Value, ForgeError> {
    let approval = client
        .decide_pending_approval(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(super::observability::approval_projection_json(
        &approval, None, None,
    ))
}

fn require_id(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        Err(ForgeError::invalid_input(format!(
            "{label} must be non-nil"
        )))
    } else {
        Ok(value)
    }
}
