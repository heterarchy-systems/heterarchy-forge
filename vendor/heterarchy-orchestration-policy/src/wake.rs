//! Deterministic reusable wake-target state transitions.
//!
//! Presence, connector capability checks, delivery leases, locks, persistence,
//! and provider/runtime effects are explicit observations owned outside this
//! pure policy module. This module only derives a revisioned next state from a
//! typed target snapshot and explicit command values.

use serde::{Deserialize, Serialize};

use crate::{DomainError, ErrorCode, Revision, TimestampMicros};

/// Maximum bytes for one wake-target/project/Slot identity.
pub const MAX_WAKE_ID_BYTES: usize = 512;

/// Durable local wake-target lifecycle used only by the wake transition engine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeTargetStatus {
    /// Target is available for an activation action.
    Idle,
    /// A provider activation delivery is in flight.
    Waking,
    /// A Worker is claiming work after an activation delivery.
    Claiming,
    /// Target owns an active Broker assignment.
    Busy,
}

/// Current durable wake-target snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WakeTargetSnapshot {
    /// Persisted wake-target schema version.
    pub schema_version: u32,
    /// Opaque physical wake-target identity.
    pub wake_target_id: String,
    /// Canonical project identity.
    pub project_id: String,
    /// Connector epoch recorded at registration.
    pub registered_connector_epoch: u64,
    /// Current local target lifecycle status.
    pub status: WakeTargetStatus,
    /// Optional reusable Worker Slot binding.
    pub bound_slot_id: Option<String>,
    /// Current wake-delivery revision.
    pub wake_revision: Revision,
    /// Current target CAS revision.
    pub revision: Revision,
    /// Original registration timestamp.
    pub created_at_micros: TimestampMicros,
    /// Current persisted update timestamp.
    pub updated_at_micros: TimestampMicros,
}

/// Explicit next-state command for one wake target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionWakeTargetCommand {
    /// Caller-observed target revision used by the external CAS boundary.
    pub expected_revision: Revision,
    /// Next target lifecycle status.
    pub status: WakeTargetStatus,
    /// Next optional reusable Slot binding.
    pub bound_slot_id: Option<String>,
    /// Next wake-delivery revision.
    pub wake_revision: Revision,
    /// Caller-provided UTC update timestamp.
    pub updated_at_micros: TimestampMicros,
}

/// Wake command family nested under the coarse engine command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum WakeCommand {
    /// Calculate one immutable next target state.
    Transition(TransitionWakeTargetCommand),
}

/// Full immutable next wake-target state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WakeTargetTransitionDecision {
    /// Complete next target state.
    pub state: WakeTargetSnapshot,
}

/// Wake decision family returned by the engine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum WakeDecision {
    /// One calculated next target state.
    Transition(WakeTargetTransitionDecision),
}

/// Calculate one wake-target transition without performing effects.
/// Evaluate one explicit wake-target transition.
///
/// # Errors
///
/// Returns a typed policy error when the snapshot, revision fence, timestamp,
/// or transition command is invalid.
pub fn evaluate_wake(
    operation: &str,
    command: WakeCommand,
    mut snapshot: WakeTargetSnapshot,
) -> Result<WakeDecision, DomainError> {
    validate_snapshot(operation, &snapshot)?;
    match command {
        WakeCommand::Transition(command) => {
            if let Some(slot_id) = &command.bound_slot_id
                && (slot_id.is_empty() || slot_id.len() > MAX_WAKE_ID_BYTES)
            {
                return Err(invalid_command(
                    operation,
                    &snapshot.wake_target_id,
                    "Wake target Slot identity is empty or exceeds the bounded size.",
                ));
            }
            if snapshot.revision != command.expected_revision {
                return Err(DomainError {
                    code: ErrorCode::RevisionConflict,
                    operation: operation.to_owned(),
                    resource_id: snapshot.wake_target_id.clone(),
                    message: "Wake target revision does not match the expected revision."
                        .to_owned(),
                    current_revision: Some(snapshot.revision),
                });
            }
            snapshot.revision = snapshot
                .revision
                .0
                .checked_add(1)
                .map(Revision)
                .ok_or_else(|| DomainError {
                    code: ErrorCode::WakeRevisionOverflow,
                    operation: operation.to_owned(),
                    resource_id: snapshot.wake_target_id.clone(),
                    message: "Wake target revision cannot advance beyond the u64 limit.".to_owned(),
                    current_revision: Some(snapshot.revision),
                })?;
            snapshot.status = command.status;
            snapshot.bound_slot_id = command.bound_slot_id;
            snapshot.wake_revision = command.wake_revision;
            snapshot.updated_at_micros = command.updated_at_micros;
            Ok(WakeDecision::Transition(WakeTargetTransitionDecision {
                state: snapshot,
            }))
        }
    }
}

fn validate_snapshot(operation: &str, snapshot: &WakeTargetSnapshot) -> Result<(), DomainError> {
    for (field, value) in [
        ("wake_target_id", snapshot.wake_target_id.as_str()),
        ("project_id", snapshot.project_id.as_str()),
    ] {
        if value.is_empty() || value.len() > MAX_WAKE_ID_BYTES {
            return Err(DomainError {
                code: ErrorCode::WakeInvalidSnapshot,
                operation: operation.to_owned(),
                resource_id: field.to_owned(),
                message: "Wake target identity is empty or exceeds the bounded size.".to_owned(),
                current_revision: Some(snapshot.revision),
            });
        }
    }
    if let Some(slot_id) = &snapshot.bound_slot_id
        && (slot_id.is_empty() || slot_id.len() > MAX_WAKE_ID_BYTES)
    {
        return Err(DomainError {
            code: ErrorCode::WakeInvalidSnapshot,
            operation: operation.to_owned(),
            resource_id: snapshot.wake_target_id.clone(),
            message: "Wake target Slot identity is empty or exceeds the bounded size.".to_owned(),
            current_revision: Some(snapshot.revision),
        });
    }
    Ok(())
}

fn invalid_command(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::WakeInvalidCommand,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}
