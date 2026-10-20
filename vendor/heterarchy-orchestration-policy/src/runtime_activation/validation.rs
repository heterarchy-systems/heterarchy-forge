//! Validation for bounded provider-neutral runtime activation observations.

use std::collections::HashSet;

use crate::{DomainError, ErrorCode};

use super::types::{
    MAX_RUNTIME_ACTIVATION_DESIRED_CAPACITY, MAX_RUNTIME_ACTIVATION_ID_BYTES,
    MAX_RUNTIME_ACTIVATION_RUNTIMES, RuntimeActivationAvailability, RuntimeActivationObservation,
    RuntimeActivationSnapshot, RuntimeActivationStatus,
};

pub(super) fn validate_snapshot(
    operation: &str,
    snapshot: &RuntimeActivationSnapshot,
) -> Result<(), DomainError> {
    validate_id(operation, "project_id", &snapshot.project_id, "project_id")?;
    if snapshot.project_max_runtimes == 0
        || snapshot.project_max_runtimes > MAX_RUNTIME_ACTIVATION_DESIRED_CAPACITY
    {
        return Err(invalid_snapshot(
            operation,
            &snapshot.project_id,
            "project_max_runtimes must be positive and within the bounded runtime activation limit.",
        ));
    }
    if snapshot.global_max_runtimes == 0
        || snapshot.global_max_runtimes > MAX_RUNTIME_ACTIVATION_DESIRED_CAPACITY
    {
        return Err(invalid_snapshot(
            operation,
            &snapshot.project_id,
            "global_max_runtimes must be positive and within the bounded runtime activation limit.",
        ));
    }
    if snapshot.runtimes.len() > MAX_RUNTIME_ACTIVATION_RUNTIMES {
        return Err(invalid_snapshot(
            operation,
            &snapshot.project_id,
            "Runtime activation snapshot exceeds its bounded runtime limit.",
        ));
    }
    if snapshot.global_activated_runtime_count > snapshot.global_recoverable_runtime_count {
        return Err(invalid_snapshot(
            operation,
            &snapshot.project_id,
            "Global activated runtime count cannot exceed recoverable runtime count.",
        ));
    }
    let binding = &snapshot.provider_binding;
    if binding.project_id != snapshot.project_id {
        return Err(invalid_snapshot(
            operation,
            &binding.binding_id,
            "Provider binding project_id must equal the activation snapshot project_id.",
        ));
    }
    validate_id(operation, "binding_id", &binding.binding_id, "binding_id")?;

    let mut runtime_ids = HashSet::with_capacity(snapshot.runtimes.len());
    for runtime in &snapshot.runtimes {
        validate_runtime(operation, snapshot, runtime, &mut runtime_ids)?;
    }
    Ok(())
}

fn validate_runtime(
    operation: &str,
    snapshot: &RuntimeActivationSnapshot,
    runtime: &RuntimeActivationObservation,
    runtime_ids: &mut HashSet<String>,
) -> Result<(), DomainError> {
    validate_id(operation, "runtime_id", &runtime.runtime_id, "runtime_id")?;
    if !runtime_ids.insert(runtime.runtime_id.clone()) {
        return Err(invalid_snapshot(
            operation,
            &runtime.runtime_id,
            "Runtime activation snapshot contains a duplicate runtime_id.",
        ));
    }
    if runtime.project_id != snapshot.project_id {
        return Err(invalid_snapshot(
            operation,
            &runtime.runtime_id,
            "Runtime observation crosses the activation snapshot project boundary.",
        ));
    }
    if runtime.binding_id != snapshot.provider_binding.binding_id
        || runtime.binding_revision != snapshot.provider_binding.revision
    {
        return Err(invalid_snapshot(
            operation,
            &runtime.runtime_id,
            "Runtime observation does not match the current ProviderBinding fence.",
        ));
    }
    if runtime.maintenance_eligibility.park_eligible
        && (runtime.status != RuntimeActivationStatus::Idle
            || runtime.availability != RuntimeActivationAvailability::Active)
    {
        return Err(invalid_snapshot(
            operation,
            &runtime.runtime_id,
            "Only active idle runtimes can be eligible for parking.",
        ));
    }
    if runtime.maintenance_eligibility.retire_eligible
        && runtime.status != RuntimeActivationStatus::Idle
    {
        return Err(invalid_snapshot(
            operation,
            &runtime.runtime_id,
            "Only idle runtimes can be eligible for retirement.",
        ));
    }
    if runtime.delivery_state.delivery_lease_expired
        && !matches!(
            runtime.status,
            RuntimeActivationStatus::Waking | RuntimeActivationStatus::Claiming
        )
    {
        return Err(invalid_snapshot(
            operation,
            &runtime.runtime_id,
            "Only waking or claiming runtimes may report an expired delivery lease.",
        ));
    }
    Ok(())
}

pub(super) fn invalid_snapshot(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::RuntimeActivationInvalidSnapshot,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}

fn validate_id(
    operation: &str,
    resource_id: &str,
    value: &str,
    field: &str,
) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > MAX_RUNTIME_ACTIVATION_ID_BYTES {
        return Err(invalid_snapshot(
            operation,
            resource_id,
            &format!("{field} must be non-empty and within the bounded identifier length."),
        ));
    }
    Ok(())
}
