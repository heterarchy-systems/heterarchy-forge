//! Deterministic provisioning state policy.
//!
//! The module owns no persistence, clock, randomness, browser, or runtime I/O.
//! Every identity and timestamp needed for a mutation is supplied in the
//! command payload; the returned decision contains the complete next snapshot
//! and a typed outcome for the external effect plane.

mod admission;
mod callbacks;
mod command_validation;
mod demand_capacity;
mod retirement;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use types::*;

use std::collections::{HashMap, HashSet};

use crate::{DomainError, ErrorCode, Revision, TimestampMicros};

/// Evaluate one explicit provisioning state command.
///
/// # Errors
///
/// Returns a structured domain error when the snapshot is malformed, a
/// command violates an ownership/revision invariant, or supplied capacity and
/// identity values cannot be reconciled safely.
pub fn evaluate_provisioning(
    operation: &str,
    command: ProvisioningCommand,
    mut snapshot: ProvisioningSnapshot,
) -> Result<ProvisioningDecision, DomainError> {
    validation::validate_snapshot(&snapshot, operation)?;
    command_validation::validate_bounds(&command, operation)?;
    let (snapshot, outcome) = match command {
        ProvisioningCommand::SynchronizeDemand(command) => {
            demand_capacity::synchronize_demand(operation, &mut snapshot, command, false)?
        }
        ProvisioningCommand::ApplyCapacityReservation(command) => {
            demand_capacity::apply_capacity_reservation(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::AdmitNext(command) => {
            admission::admit_next(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::ProgressRequest(command) => {
            callbacks::progress_request(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::RecordFailure(command) => {
            callbacks::record_failure(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::ConfirmRegistration(command) => {
            callbacks::confirm_registration(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::CancelRequest(command) => {
            callbacks::cancel_request(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::CancelRegistrationFailure(command) => {
            callbacks::cancel_registration_failure(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::RetryOperatorBlocked(command) => {
            callbacks::retry_operator_blocked(operation, &mut snapshot, command)?
        }
        ProvisioningCommand::RetireRuntimeOwnership(command) => {
            retirement::retire_runtime_ownership(operation, &mut snapshot, &command)?
        }
        ProvisioningCommand::RetireRuntimeOwnershipBatch(command) => {
            retirement::retire_runtime_ownership_batch(operation, &mut snapshot, &command)?
        }
    };
    validation::validate_snapshot(&snapshot, operation)?;
    Ok(ProvisioningDecision { snapshot, outcome })
}

/// Return a provisioning command error with a dedicated machine-readable code.
pub(super) fn error(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::ProvisioningInvalidCommand,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}

/// Return a malformed durable-state error.
pub(super) fn snapshot_error(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::ProvisioningInvalidSnapshot,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}

/// Return an optimistic-concurrency conflict.
pub(super) fn conflict(
    operation: &str,
    resource_id: &str,
    message: &str,
    revision: Option<Revision>,
) -> DomainError {
    DomainError {
        code: ErrorCode::ProvisioningConflict,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: revision,
    }
}

/// Return a stale callback error while preserving the current revision.
pub(super) fn stale_callback(
    operation: &str,
    resource_id: &str,
    message: &str,
    revision: Revision,
) -> DomainError {
    DomainError {
        code: ErrorCode::ProvisioningStaleCallback,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: Some(revision),
    }
}

/// Return a binding identity conflict.
pub(super) fn binding_conflict(
    operation: &str,
    resource_id: &str,
    message: &str,
    revision: Option<Revision>,
) -> DomainError {
    DomainError {
        code: ErrorCode::ProvisioningBindingConflict,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: revision,
    }
}

/// Return an arithmetic failure rather than wrapping or saturating.
pub(super) fn arithmetic_error(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::ProvisioningArithmeticOverflow,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}

pub(super) fn request_not_found(operation: &str, request_id: &str) -> DomainError {
    DomainError {
        code: ErrorCode::ProvisioningRequestNotFound,
        operation: operation.to_owned(),
        resource_id: request_id.to_owned(),
        message: "Provisioning request does not exist.".to_owned(),
        current_revision: None,
    }
}

pub(super) fn request_index(
    state: &ProvisioningSnapshot,
    request_id: &str,
    operation: &str,
) -> Result<usize, DomainError> {
    state
        .requests
        .iter()
        .position(|item| item.request_id == request_id)
        .ok_or_else(|| request_not_found(operation, request_id))
}

pub(super) fn require_admission_owner(
    state: &ProvisioningSnapshot,
    request_index: usize,
    admission_revision: Revision,
    operation: &str,
) -> Result<(), DomainError> {
    let request = &state.requests[request_index];
    if state.admission.in_flight_request_id.as_deref() != Some(request.request_id.as_str())
        || request.admission_revision != Some(admission_revision)
        || state.admission.revision < admission_revision
    {
        return Err(stale_callback(
            operation,
            &request.request_id,
            "Stale provisioning admission callback.",
            state.admission.revision,
        ));
    }
    Ok(())
}

pub(super) fn retry_after(admission: &ProvisioningAdmission, now: u64) -> Option<u64> {
    [
        admission.next_admission_at_micros,
        admission.backoff_until_micros,
    ]
    .into_iter()
    .flatten()
    .map(|value| value.0)
    .filter(|value| *value > now)
    .filter_map(|value| value.checked_sub(now))
    .min()
}

pub(super) fn commit_root(
    state: &mut ProvisioningSnapshot,
    now: TimestampMicros,
    operation: &str,
) -> Result<(), DomainError> {
    // Revision-zero is the repository bootstrap sentinel. Its wall-clock
    // creation timestamp is not domain history, so the first deterministic
    // mutation may use a caller-controlled test/replay clock. Once any durable
    // policy revision exists, timestamps must remain monotonic.
    if state.revision.0 > 0 && now < state.updated_at_micros {
        return Err(arithmetic_error(
            operation,
            "provisioning",
            "Provisioning mutation timestamp precedes the snapshot timestamp.",
        ));
    }
    state.revision = next_revision(state.revision, operation, "provisioning")?;
    state.updated_at_micros = now;
    Ok(())
}

pub(super) fn next_revision(
    current: Revision,
    operation: &str,
    resource_id: &str,
) -> Result<Revision, DomainError> {
    current.0.checked_add(1).map(Revision).ok_or_else(|| {
        arithmetic_error(
            operation,
            resource_id,
            "Provisioning revision cannot advance beyond the u64 limit.",
        )
    })
}

pub(super) fn checked_add(
    lhs: u64,
    rhs: u64,
    operation: &str,
    resource_id: &str,
    description: &str,
) -> Result<u64, DomainError> {
    lhs.checked_add(rhs)
        .ok_or_else(|| arithmetic_error(operation, resource_id, description))
}

pub(super) fn checked_sub(
    lhs: u64,
    rhs: u64,
    operation: &str,
    resource_id: &str,
    description: &str,
) -> Result<u64, DomainError> {
    lhs.checked_sub(rhs)
        .ok_or_else(|| arithmetic_error(operation, resource_id, description))
}

pub(super) fn checked_timestamp_add(
    now: TimestampMicros,
    delta: u64,
    operation: &str,
    resource_id: &str,
    description: &str,
) -> Result<TimestampMicros, DomainError> {
    checked_add(now.0, delta, operation, resource_id, description).map(TimestampMicros)
}

pub(super) fn checked_elapsed(
    now: TimestampMicros,
    then: TimestampMicros,
    operation: &str,
    resource_id: &str,
) -> Result<u64, DomainError> {
    checked_sub(
        now.0,
        then.0,
        operation,
        resource_id,
        "Provisioning timestamps are inverted.",
    )
}

pub(super) fn demand_positive(state: &ProvisioningSnapshot, project_id: &str) -> bool {
    state
        .demands
        .iter()
        .any(|item| item.project_id == project_id && item.spawn_needed > 0)
}

pub(super) fn binding_admissible(
    binding: Option<&&ProviderBindingObservation>,
    required: bool,
) -> bool {
    if !required {
        return binding.is_none_or(|value| value.supported);
    }
    binding.is_some_and(|value| value.supported)
}

pub(super) fn transient_rank(status: ProvisioningRequestStatus) -> u8 {
    match status {
        ProvisioningRequestStatus::OpeningProject => 1,
        ProvisioningRequestStatus::CreatingRuntime => 2,
        ProvisioningRequestStatus::Bootstrapping => 3,
        ProvisioningRequestStatus::WaitingRegistration => 4,
        _ => 0,
    }
}

pub(super) fn failure_status(reason: &str, rate_limited: bool) -> ProvisioningRequestStatus {
    if rate_limited {
        return ProvisioningRequestStatus::RateLimited;
    }
    match reason.trim().to_ascii_lowercase().as_str() {
        "browser_open_cooldown" | "worker_retirement_pending" => {
            ProvisioningRequestStatus::Deferred
        }
        _ => ProvisioningRequestStatus::OperatorBlocked,
    }
}

pub(super) fn is_retirable(status: ProvisioningRequestStatus) -> bool {
    status == ProvisioningRequestStatus::Active || status.transient()
}

pub(super) fn prune_terminal(
    state: &mut ProvisioningSnapshot,
    retention: u64,
    operation: &str,
    protected_request_ids: &HashSet<String>,
) -> Result<bool, DomainError> {
    let retention_usize = validate_retention(operation, "terminal_request_retention", retention)?;
    let mut terminal: Vec<usize> = state
        .requests
        .iter()
        .enumerate()
        .filter(|(_, item)| item.status.prunable())
        .filter(|(_, item)| !protected_request_ids.contains(&item.request_id))
        .map(|(index, _)| index)
        .collect();
    if terminal.len() <= retention_usize {
        return Ok(false);
    }
    terminal.sort_by_key(|index| {
        (
            state.requests[*index].updated_at_micros.0,
            state.requests[*index].request_id.clone(),
        )
    });
    let remove_count = terminal.len() - retention_usize;
    let remove_ids: HashSet<String> = terminal
        .into_iter()
        .take(remove_count)
        .map(|index| state.requests[index].request_id.clone())
        .collect();
    state
        .requests
        .retain(|request| !remove_ids.contains(&request.request_id));
    Ok(true)
}

pub(super) fn validate_id(
    operation: &str,
    resource_id: &str,
    value: &str,
    label: &str,
) -> Result<(), DomainError> {
    if value.trim().is_empty() {
        return Err(error(
            operation,
            resource_id,
            &format!("{label} cannot be empty."),
        ));
    }
    if value.len() > MAX_PROVISIONING_ID_BYTES {
        return Err(error(
            operation,
            resource_id,
            &format!("{label} exceeds the bounded identifier size."),
        ));
    }
    Ok(())
}

pub(super) fn validate_provider_binding_observation(
    operation: &str,
    resource_id: &str,
    binding: &ProviderBindingObservation,
) -> Result<(), DomainError> {
    validate_id(operation, resource_id, &binding.project_id, "project_id")?;
    validate_id(operation, resource_id, &binding.binding_id, "binding_id")?;
    if let Some(fingerprint) = binding.metadata_fingerprint.as_deref() {
        validate_required_text(
            operation,
            resource_id,
            fingerprint,
            "metadata_fingerprint",
            MAX_PROVISIONING_BINDING_FINGERPRINT_BYTES,
        )?;
    }
    Ok(())
}

pub(super) fn validate_optional_provider_binding_observation(
    operation: &str,
    resource_id: &str,
    binding: Option<&ProviderBindingObservation>,
) -> Result<(), DomainError> {
    if let Some(binding) = binding {
        validate_provider_binding_observation(operation, resource_id, binding)?;
    }
    Ok(())
}

pub(super) fn validate_required_text(
    operation: &str,
    resource_id: &str,
    value: &str,
    label: &str,
    maximum_bytes: usize,
) -> Result<(), DomainError> {
    if value.trim().is_empty() {
        return Err(error(
            operation,
            resource_id,
            &format!("{label} cannot be empty."),
        ));
    }
    if value.len() > maximum_bytes {
        return Err(error(
            operation,
            resource_id,
            &format!("{label} exceeds the bounded size."),
        ));
    }
    Ok(())
}

pub(super) fn validate_retention(
    operation: &str,
    resource_id: &str,
    retention: u64,
) -> Result<usize, DomainError> {
    if retention == 0 {
        return Err(error(
            operation,
            resource_id,
            "terminal_request_retention must be positive.",
        ));
    }
    if retention > MAX_PROVISIONING_TERMINAL_RETENTION {
        return Err(error(
            operation,
            resource_id,
            "terminal_request_retention exceeds the bounded retention limit.",
        ));
    }
    usize::try_from(retention).map_err(|_| {
        arithmetic_error(
            operation,
            resource_id,
            "terminal_request_retention does not fit the platform index type.",
        )
    })
}
