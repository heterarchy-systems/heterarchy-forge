//! Read-only queue status and Workspace queue-preference projections.
//!
//! Queue admission and Workspace preference ownership remain in
//! `forge-control`. This module only validates the closed transport payload,
//! invokes the existing observation capabilities, and renders their typed
//! results without creating a second queue or preference authority.

use forge_control::{
    ForgeControlClient, QueueCapacity, QueueCapacitySource, QueueRuntimeError, QueueStatus,
    ResolvedWorkspaceScope,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CommandOp, ScopeDto};
use crate::error::ForgeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueObservationRequest {
    GlobalStatus,
    WorkspaceStatus { scope: ResolvedWorkspaceScope },
    WorkspaceSettings { scope: ResolvedWorkspaceScope },
}

impl QueueObservationRequest {
    pub(super) const fn op(&self) -> CommandOp {
        match self {
            Self::GlobalStatus => CommandOp::QueueStatus,
            Self::WorkspaceStatus { .. } => CommandOp::WorkspaceQueueStatus,
            Self::WorkspaceSettings { .. } => CommandOp::WorkspaceQueueSettings,
        }
    }
}

/// Parse one of the closed queue observation payloads.
pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<QueueObservationRequest, ForgeError> {
    match operation {
        CommandOp::QueueStatus => {
            parse_empty_payload(payload, "queue.status payload is invalid")?;
            Ok(QueueObservationRequest::GlobalStatus)
        }
        CommandOp::WorkspaceQueueStatus => Ok(QueueObservationRequest::WorkspaceStatus {
            scope: parse_scope(payload, "workspace.queue.status payload is invalid")?,
        }),
        CommandOp::WorkspaceQueueSettings => Ok(QueueObservationRequest::WorkspaceSettings {
            scope: parse_scope(payload, "workspace.queue.settings payload is invalid")?,
        }),
        _ => Err(ForgeError::invalid_input(
            "operation is not a queue observation",
        )),
    }
}

/// Execute one queue observation through the existing control client.
pub(super) fn execute(
    client: &ForgeControlClient,
    request: &QueueObservationRequest,
) -> Result<Value, ForgeError> {
    match request {
        QueueObservationRequest::GlobalStatus => client
            .queue_status()
            .map(queue_status_json)
            .map_err(|error| queue_runtime_error(&error)),
        QueueObservationRequest::WorkspaceStatus { scope } => {
            let _ = client
                .workspace_queue_settings(scope.clone())
                .map_err(|error| super::forge_error_of_client(&error))?;
            let status = client
                .workspace_queue_status(scope.workspace_id())
                .map_err(|error| queue_runtime_error(&error))?;
            let _ = client
                .workspace_queue_settings(scope.clone())
                .map_err(|error| super::forge_error_of_client(&error))?;
            let mut response = object(queue_status_json(status))?;
            response.insert("scope".to_owned(), super::source::scope_json(scope)?);
            Ok(Value::Object(response))
        }
        QueueObservationRequest::WorkspaceSettings { scope } => {
            // These are deliberately separate reads. The preference capability
            // revalidates the exact scope through forge-control; no adapter
            // claims that it and the runtime snapshot are one atomic view.
            let saved = client
                .workspace_queue_settings(scope.clone())
                .map_err(|error| super::forge_error_of_client(&error))?;
            let effective = client
                .workspace_queue_status(scope.workspace_id())
                .map_err(|error| queue_runtime_error(&error))?;
            let _ = client
                .workspace_queue_settings(scope.clone())
                .map_err(|error| super::forge_error_of_client(&error))?;
            Ok(json!({
                "scope": super::source::scope_json(scope)?,
                "saved_preference": saved.as_ref().map(saved_preference_json),
                "effective_runtime": queue_status_json(effective),
                "observation": "separate_non_atomic_reads",
                "retry_authorized": false,
                "request_equivalence_proven": false,
            }))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopedPayload {
    scope: ScopeDto,
}

fn parse_empty_payload(payload: &Value, message: &'static str) -> Result<(), ForgeError> {
    super::parse_body::<EmptyPayload>(payload, message).map(|_| ())
}

fn parse_scope(
    payload: &Value,
    message: &'static str,
) -> Result<ResolvedWorkspaceScope, ForgeError> {
    let body: ScopedPayload = super::parse_body(payload, message)?;
    if body.scope.workspace_id.is_nil() || body.scope.locator.location_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "queue observation scope identities must not be nil",
        ));
    }
    super::decode_scope(&body.scope)
}

fn object(value: Value) -> Result<serde_json::Map<String, Value>, ForgeError> {
    match value {
        Value::Object(value) => Ok(value),
        _ => Err(ForgeError::internal()),
    }
}

pub(super) fn queue_runtime_error(error: &QueueRuntimeError) -> ForgeError {
    match error {
        QueueRuntimeError::Closed => ForgeError::dependency_unavailable(),
        QueueRuntimeError::PartitionLimit
        | QueueRuntimeError::Policy(_)
        | QueueRuntimeError::CounterOverflow
        | QueueRuntimeError::Poisoned => ForgeError::internal(),
    }
}

pub(super) fn queue_status_json(status: QueueStatus) -> Value {
    let depths = status.depths();
    let ages = status.oldest_age_micros();
    json!({
        "capacity": status.target_capacity().slots(),
        "capacity_preset": capacity_name(status.target_capacity()),
        "source": capacity_source_name(status.source()),
        "active": status.active_worker(),
        "pending": depths.total(),
        "per_lane": {
            "liveness": depths.liveness,
            "authority_control": depths.authority_control,
            "interactive": depths.interactive,
            "work": depths.work,
            "background": depths.background,
        },
        "generation": status.config_revision(),
        "draining": status.draining(),
        "oldest_age_micros": {
            "liveness": ages[0],
            "authority_control": ages[1],
            "interactive": ages[2],
            "work": ages[3],
            "background": ages[4],
        },
        "rejected_count": status.rejected_count(),
        "high_water": status.high_water(),
        "aging_count": status.aging_count(),
        "initialized": status.initialized(),
        "global": {
            "capacity": status.global_capacity().slots(),
            "capacity_preset": capacity_name(status.global_capacity()),
            "pending": status.global_depth(),
            "rejected_count": status.global_rejected_count(),
            "high_water": status.global_high_water(),
        },
        "persisted_revision": status.persisted_revision(),
    })
}

pub(super) fn saved_preference_json(saved: &forge_persistence::RegisteredQueueSettings) -> Value {
    json!({
        "capacity": saved.capacity().slots(),
        "capacity_preset": capacity_name(saved.capacity()),
        "revision": saved.revision().get(),
        "created_at_ms": saved.created_at().get(),
        "updated_at_ms": saved.updated_at().get(),
    })
}

const fn capacity_name(capacity: QueueCapacity) -> &'static str {
    match capacity {
        QueueCapacity::C32 => "c32",
        QueueCapacity::C64 => "c64",
        QueueCapacity::C128 => "c128",
        QueueCapacity::C256 => "c256",
    }
}

const fn capacity_source_name(source: QueueCapacitySource) -> &'static str {
    match source {
        QueueCapacitySource::Default => "default",
        QueueCapacitySource::UserProvided => "user_provided",
    }
}

#[cfg(test)]
mod tests;
