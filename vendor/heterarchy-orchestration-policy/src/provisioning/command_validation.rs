//! Bounded command validation before a provisioning state transition mutates a
//! cloned durable snapshot.

#![allow(clippy::wildcard_imports)]

use super::*;

/// Reject oversized caller-owned command collections and strings before the
/// state machine allocates, sorts, or appends them.
pub(super) fn validate_bounds(
    command: &ProvisioningCommand,
    operation: &str,
) -> Result<(), DomainError> {
    match command {
        ProvisioningCommand::SynchronizeDemand(command) => validate_synchronize(command, operation),
        ProvisioningCommand::ApplyCapacityReservation(command) => {
            validate_capacity_reservation(command, operation)
        }
        ProvisioningCommand::AdmitNext(command) => validate_admission(command, operation),
        ProvisioningCommand::ProgressRequest(command) => {
            validate_id(operation, "request_id", &command.request_id, "request_id")
        }
        ProvisioningCommand::RecordFailure(command) => validate_failure(command, operation),
        ProvisioningCommand::ConfirmRegistration(command) => {
            validate_registration(command, operation)
        }
        ProvisioningCommand::CancelRequest(command) => validate_cancellation(command, operation),
        ProvisioningCommand::CancelRegistrationFailure(command) => {
            validate_registration_cancellation(command, operation)
        }
        ProvisioningCommand::RetryOperatorBlocked(command) => validate_retry(command, operation),
        ProvisioningCommand::RetireRuntimeOwnership(command) => {
            validate_retirement(command, operation)
        }
        ProvisioningCommand::RetireRuntimeOwnershipBatch(command) => {
            validate_batch_retirement(command, operation)
        }
    }
}

fn validate_synchronize(
    command: &SynchronizeDemandCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_capacity(operation, &command.project_id, command.desired_capacity)?;
    validate_capacity(operation, &command.project_id, command.spawn_needed)?;
    validate_request_seeds(operation, &command.project_id, &command.request_seeds)?;
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_capacity_reservation(
    command: &ApplyCapacityReservationCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_capacity(operation, &command.project_id, command.desired_capacity)?;
    validate_capacity(operation, &command.project_id, command.capacity_deficit)?;
    validate_capacity(operation, &command.project_id, command.spawn_needed)?;
    validate_request_seeds(operation, &command.project_id, &command.request_seeds)?;
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_admission(command: &AdmitNextCommand, operation: &str) -> Result<(), DomainError> {
    validate_bindings(operation, &command.bindings)?;
    validate_optional_request_seed(
        operation,
        "new_request_seed",
        command.new_request_seed.as_ref(),
    )?;
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_failure(command: &RecordFailureCommand, operation: &str) -> Result<(), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    validate_required_text(
        operation,
        &command.request_id,
        &command.reason,
        "reason",
        MAX_PROVISIONING_FAILURE_REASON_BYTES,
    )?;
    validate_collection_length(
        operation,
        &command.request_id,
        "rate_limit_backoff_micros",
        command.rate_limit_backoff_micros.len(),
        MAX_PROVISIONING_BACKOFF_STEPS,
    )?;
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_registration(
    command: &ConfirmRegistrationCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    validate_id(
        operation,
        &command.request_id,
        &command.provider_runtime_id,
        "provider_runtime_id",
    )?;
    validate_id(
        operation,
        &command.request_id,
        &command.wake_target_id,
        "wake_target_id",
    )?;
    validate_optional_provider_binding_observation(
        operation,
        &command.request_id,
        command.provider_binding.as_ref(),
    )
}

fn validate_cancellation(
    command: &CancelRequestCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_registration_cancellation(
    command: &CancelRegistrationFailureCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    validate_required_text(
        operation,
        &command.request_id,
        &command.reason,
        "reason",
        MAX_PROVISIONING_FAILURE_REASON_BYTES,
    )?;
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_retry(
    command: &RetryOperatorBlockedCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    validate_provider_binding_observation(
        operation,
        &command.request_id,
        &command.provider_binding,
    )?;
    if !command.provider_binding.supported {
        return Err(binding_conflict(
            operation,
            &command.provider_binding.project_id,
            "Provider binding observation is explicitly unsupported.",
            Some(command.provider_binding.revision),
        ));
    }
    Ok(())
}

fn validate_retirement(
    command: &RetireRuntimeOwnershipCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_id(
        operation,
        "wake_target_id",
        &command.wake_target_id,
        "wake_target_id",
    )?;
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_batch_retirement(
    command: &RetireRuntimeOwnershipBatchCommand,
    operation: &str,
) -> Result<(), DomainError> {
    validate_id(operation, "project_id", &command.project_id, "project_id")?;
    validate_collection_length(
        operation,
        &command.project_id,
        "wake_target_ids",
        command.wake_target_ids.len(),
        MAX_PROVISIONING_RETIREMENT_BATCH,
    )?;
    for wake_target_id in &command.wake_target_ids {
        validate_id(
            operation,
            &command.project_id,
            wake_target_id,
            "wake_target_id",
        )?;
    }
    validate_terminal_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )
}

fn validate_capacity(operation: &str, project_id: &str, value: u64) -> Result<(), DomainError> {
    if value > MAX_PROVISIONING_REQUESTS as u64 {
        return Err(error(
            operation,
            project_id,
            "Provisioning capacity exceeds the bounded request limit.",
        ));
    }
    Ok(())
}

fn validate_terminal_retention(
    operation: &str,
    resource_id: &str,
    retention: u64,
) -> Result<(), DomainError> {
    validate_retention(operation, resource_id, retention).map(|_| ())
}

fn validate_request_seeds(
    operation: &str,
    resource_id: &str,
    seeds: &[ProvisioningRequestSeed],
) -> Result<(), DomainError> {
    validate_collection_length(
        operation,
        resource_id,
        "request_seeds",
        seeds.len(),
        MAX_PROVISIONING_REQUEST_SEEDS,
    )?;
    for seed in seeds {
        validate_request_seed(operation, resource_id, seed)?;
    }
    Ok(())
}

fn validate_optional_request_seed(
    operation: &str,
    resource_id: &str,
    seed: Option<&ProvisioningRequestSeed>,
) -> Result<(), DomainError> {
    if let Some(seed) = seed {
        validate_request_seed(operation, resource_id, seed)?;
    }
    Ok(())
}

fn validate_request_seed(
    operation: &str,
    resource_id: &str,
    seed: &ProvisioningRequestSeed,
) -> Result<(), DomainError> {
    validate_id(operation, resource_id, &seed.request_id, "request_id")?;
    validate_id(
        operation,
        &seed.request_id,
        &seed.wake_target_id,
        "wake_target_id",
    )
}

fn validate_bindings(
    operation: &str,
    bindings: &[ProviderBindingObservation],
) -> Result<(), DomainError> {
    validate_collection_length(
        operation,
        "bindings",
        "bindings",
        bindings.len(),
        MAX_PROVISIONING_BINDINGS,
    )?;
    for binding in bindings {
        validate_provider_binding_observation(operation, "bindings", binding)?;
    }
    Ok(())
}

fn validate_collection_length(
    operation: &str,
    resource_id: &str,
    label: &str,
    length: usize,
    maximum: usize,
) -> Result<(), DomainError> {
    if length > maximum {
        return Err(error(
            operation,
            resource_id,
            &format!("{label} exceeds the bounded collection limit."),
        ));
    }
    Ok(())
}
