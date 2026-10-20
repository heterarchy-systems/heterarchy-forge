#![allow(clippy::wildcard_imports)]

use super::*;

pub(super) fn progress_request(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: ProgressRequestCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    let index = request_index(state, &command.request_id, operation)?;
    require_admission_owner(state, index, command.admission_revision, operation)?;
    let request = &mut state.requests[index];
    if request.status == command.status {
        return Ok((state.clone(), ProvisioningOutcome::Noop));
    }
    if !command.status.transient()
        || !request.status.transient()
        || transient_rank(command.status) < transient_rank(request.status)
    {
        return Err(error(
            operation,
            &command.request_id,
            "Provisioning callback attempted an invalid lifecycle transition.",
        ));
    }
    request.status = command.status;
    request.revision = next_revision(request.revision, operation, &command.request_id)?;
    request.updated_at_micros = command.now_micros;
    commit_root(state, command.now_micros, operation)?;
    Ok((
        state.clone(),
        ProvisioningOutcome::Progressed {
            request_id: command.request_id,
            status: command.status,
        },
    ))
}

#[allow(clippy::too_many_lines)]
pub(super) fn record_failure(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: RecordFailureCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    if command.reason.trim().is_empty() {
        return Err(error(
            operation,
            &command.request_id,
            "reason cannot be empty.",
        ));
    }
    validate_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )?;
    if command.rate_limit_backoff_micros.is_empty()
        || command.rate_limit_backoff_micros.contains(&0)
    {
        return Err(error(
            operation,
            &command.request_id,
            "rate_limit_backoff_micros must contain positive durations.",
        ));
    }
    let index = request_index(state, &command.request_id, operation)?;
    let status = failure_status(&command.reason, command.rate_limited);
    // Exact failure replay is intentionally checked before admission ownership:
    // the original callback clears the lease, so a retry must remain idempotent.
    if state.requests[index].status == status
        && state.requests[index].failure_reason.as_deref() == Some(command.reason.as_str())
        && state.requests[index].admission_revision == Some(command.admission_revision)
    {
        return Ok((
            state.clone(),
            ProvisioningOutcome::FailureRecorded {
                request_id: command.request_id,
                status,
                retry_after_micros: retry_after(&state.admission, command.now_micros.0),
            },
        ));
    }
    require_admission_owner(state, index, command.admission_revision, operation)?;
    if !state.requests[index].status.transient() {
        return Err(conflict(
            operation,
            &command.request_id,
            "Provisioning failure callback is duplicate or terminal.",
            Some(state.requests[index].revision),
        ));
    }
    let attempt = if command.rate_limited {
        let incremented = checked_add(
            state.admission.backoff_attempt,
            1,
            operation,
            "admission",
            "Provisioning rate-limit backoff attempt overflowed.",
        )?;
        let backoff_len = u64::try_from(command.rate_limit_backoff_micros.len()).map_err(|_| {
            arithmetic_error(
                operation,
                &command.request_id,
                "Provisioning rate-limit backoff length does not fit u64.",
            )
        })?;
        incremented.min(backoff_len)
    } else {
        0
    };
    let backoff_until = if attempt > 0 {
        let index = usize::try_from(attempt - 1).map_err(|_| {
            arithmetic_error(
                operation,
                &command.request_id,
                "Provisioning backoff index does not fit the platform index type.",
            )
        })?;
        let delay = *command
            .rate_limit_backoff_micros
            .get(index)
            .ok_or_else(|| {
                error(
                    operation,
                    &command.request_id,
                    "Provisioning rate-limit backoff configuration is incomplete.",
                )
            })?;
        Some(checked_timestamp_add(
            command.now_micros,
            delay,
            operation,
            &command.request_id,
            "Provisioning rate-limit backoff timestamp overflowed.",
        )?)
    } else {
        None
    };
    let next_admission = match backoff_until {
        Some(value) => Some(value),
        None => Some(checked_timestamp_add(
            command.now_micros,
            command.minimum_admission_interval_micros,
            operation,
            "admission",
            "Provisioning admission interval overflowed.",
        )?),
    };
    let request_id = state.requests[index].request_id.clone();
    {
        let request = &mut state.requests[index];
        request.status = status;
        request.failure_reason = Some(command.reason);
        request.revision = next_revision(request.revision, operation, &request_id)?;
        request.updated_at_micros = command.now_micros;
    }
    state.admission.in_flight_request_id = None;
    state.admission.backoff_attempt = attempt;
    state.admission.backoff_until_micros = backoff_until;
    state.admission.next_admission_at_micros = next_admission;
    state.admission.revision = next_revision(state.admission.revision, operation, "admission")?;
    commit_root(state, command.now_micros, operation)?;
    let retry_after_micros = retry_after(&state.admission, command.now_micros.0);
    let protected = HashSet::new();
    prune_terminal(
        state,
        command.terminal_request_retention,
        operation,
        &protected,
    )?;
    Ok((
        state.clone(),
        ProvisioningOutcome::FailureRecorded {
            request_id,
            status,
            retry_after_micros,
        },
    ))
}

pub(super) fn confirm_registration(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: ConfirmRegistrationCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
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
    )?;
    let index = request_index(state, &command.request_id, operation)?;
    validate_registration_binding_fence(operation, &state.requests[index], &command)?;
    if state.requests[index].status == ProvisioningRequestStatus::Active {
        let request = &state.requests[index];
        if request.provider_runtime_id.as_deref() == Some(command.provider_runtime_id.as_str())
            && request.wake_target_id.as_deref() == Some(command.wake_target_id.as_str())
            && request.admission_revision == Some(command.admission_revision)
            && request.provider_binding == command.provider_binding
        {
            return Ok((state.clone(), ProvisioningOutcome::Noop));
        }
        return Err(conflict(
            operation,
            &command.request_id,
            "Duplicate registration uses stale or different identities.",
            request.admission_revision,
        ));
    }
    require_admission_owner(state, index, command.admission_revision, operation)?;
    if state.requests[index].wake_target_id.as_deref() != Some(command.wake_target_id.as_str()) {
        return Err(conflict(
            operation,
            &command.request_id,
            "Callback wake target does not match the server-issued target.",
            state.requests[index].admission_revision,
        ));
    }
    let project_id = state.requests[index].project_id.clone();
    let demand_index = state
        .demands
        .iter()
        .position(|item| item.project_id == project_id)
        .ok_or_else(|| {
            snapshot_error(
                operation,
                &project_id,
                "Provisioning demand does not exist.",
            )
        })?;
    {
        let request = &mut state.requests[index];
        request.status = ProvisioningRequestStatus::Active;
        request.provider_runtime_id = Some(command.provider_runtime_id);
        request.admission_revision = Some(command.admission_revision);
        request.revision = next_revision(request.revision, operation, &request.request_id)?;
        request.updated_at_micros = command.now_micros;
    }
    let demand = &mut state.demands[demand_index];
    // Capacity reconciliation may already have reduced the reservation while
    // this admitted runtime request was in flight. Registration consumes at
    // most one remaining reservation and must not underflow or reject the
    // otherwise valid callback.
    demand.spawn_needed = demand.spawn_needed.saturating_sub(1);
    demand.revision = next_revision(demand.revision, operation, &demand.project_id)?;
    demand.updated_at_micros = command.now_micros;
    state.admission.in_flight_request_id = None;
    state.admission.backoff_attempt = 0;
    state.admission.backoff_until_micros = None;
    state.admission.revision = next_revision(state.admission.revision, operation, "admission")?;
    commit_root(state, command.now_micros, operation)?;
    Ok((
        state.clone(),
        ProvisioningOutcome::Registered {
            request_id: command.request_id,
        },
    ))
}

fn validate_registration_binding_fence(
    operation: &str,
    request: &ProvisioningRequest,
    command: &ConfirmRegistrationCommand,
) -> Result<(), DomainError> {
    if command
        .provider_binding
        .as_ref()
        .is_some_and(|binding| !binding.supported)
    {
        return Err(binding_conflict(
            operation,
            &command.request_id,
            "Provider binding observation is explicitly unsupported.",
            None,
        ));
    }
    if request.provider_binding != command.provider_binding {
        return Err(binding_conflict(
            operation,
            &request.project_id,
            "Registration provider binding fence does not match the admitted request.",
            request
                .provider_binding
                .as_ref()
                .map(|binding| binding.revision),
        ));
    }
    Ok(())
}

pub(super) fn cancel_request(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: CancelRequestCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    validate_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )?;
    let index = request_index(state, &command.request_id, operation)?;
    if state.requests[index].status == ProvisioningRequestStatus::Cancelled {
        return Ok((state.clone(), ProvisioningOutcome::Noop));
    }
    if matches!(
        state.requests[index].status,
        ProvisioningRequestStatus::Active
            | ProvisioningRequestStatus::OperatorBlocked
            | ProvisioningRequestStatus::Failed
    ) {
        return Err(conflict(
            operation,
            &command.request_id,
            "Terminal provisioning request cannot be cancelled.",
            Some(state.requests[index].revision),
        ));
    }
    if state.admission.in_flight_request_id.as_deref() == Some(command.request_id.as_str()) {
        let Some(admission_revision) = command.admission_revision else {
            return Err(stale_callback(
                operation,
                &command.request_id,
                "Stale provisioning admission callback.",
                state.admission.revision,
            ));
        };
        require_admission_owner(state, index, admission_revision, operation)?;
        state.admission.in_flight_request_id = None;
        state.admission.revision = next_revision(state.admission.revision, operation, "admission")?;
    }
    let project_id = state.requests[index].project_id.clone();
    let demand = state
        .demands
        .iter_mut()
        .find(|item| item.project_id == project_id)
        .ok_or_else(|| {
            snapshot_error(
                operation,
                &project_id,
                "Provisioning demand does not exist.",
            )
        })?;
    // Cancellation races with scheduler revalidation in the same way as
    // registration: consume one reservation if it is still present.
    demand.spawn_needed = demand.spawn_needed.saturating_sub(1);
    demand.revision = next_revision(demand.revision, operation, &project_id)?;
    demand.updated_at_micros = command.now_micros;
    let request = &mut state.requests[index];
    request.status = ProvisioningRequestStatus::Cancelled;
    request.failure_reason = Some("cancelled".to_owned());
    request.revision = next_revision(request.revision, operation, &request.request_id)?;
    request.updated_at_micros = command.now_micros;
    commit_root(state, command.now_micros, operation)?;
    let protected = HashSet::from([command.request_id.clone()]);
    prune_terminal(
        state,
        command.terminal_request_retention,
        operation,
        &protected,
    )?;
    Ok((
        state.clone(),
        ProvisioningOutcome::Cancelled {
            request_id: command.request_id,
        },
    ))
}

pub(super) fn cancel_registration_failure(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: CancelRegistrationFailureCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(operation, "request_id", &command.request_id, "request_id")?;
    if command.reason.trim().is_empty() {
        return Err(error(
            operation,
            &command.request_id,
            "reason cannot be empty.",
        ));
    }
    validate_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )?;
    let index = request_index(state, &command.request_id, operation)?;
    require_admission_owner(state, index, command.admission_revision, operation)?;
    let request = &mut state.requests[index];
    request.status = ProvisioningRequestStatus::Cancelled;
    request.failure_reason = Some(command.reason);
    request.revision = next_revision(request.revision, operation, &request.request_id)?;
    request.updated_at_micros = command.now_micros;
    state.admission.in_flight_request_id = None;
    state.admission.revision = next_revision(state.admission.revision, operation, "admission")?;
    commit_root(state, command.now_micros, operation)?;
    let protected = HashSet::from([command.request_id.clone()]);
    prune_terminal(
        state,
        command.terminal_request_retention,
        operation,
        &protected,
    )?;
    Ok((
        state.clone(),
        ProvisioningOutcome::Cancelled {
            request_id: command.request_id,
        },
    ))
}

pub(super) fn retry_operator_blocked(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: RetryOperatorBlockedCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
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
    let index = request_index(state, &command.request_id, operation)?;
    let request = &state.requests[index];
    if request.revision != command.expected_revision {
        return Err(stale_callback(
            operation,
            &command.request_id,
            "Stale provisioning request revision.",
            request.revision,
        ));
    }
    if request.status != ProvisioningRequestStatus::OperatorBlocked {
        return Err(conflict(
            operation,
            &command.request_id,
            "Only an operator-blocked provisioning request can be retried explicitly.",
            Some(request.revision),
        ));
    }
    if command.provider_binding.project_id != request.project_id {
        return Err(binding_conflict(
            operation,
            &command.provider_binding.project_id,
            "Provider binding observation belongs to a different project.",
            Some(request.revision),
        ));
    }
    if request.provider_binding.as_ref() != Some(&command.provider_binding) {
        return Err(binding_conflict(
            operation,
            &request.project_id,
            "Operator retry provider binding fence is stale or changed.",
            request
                .provider_binding
                .as_ref()
                .map(|binding| binding.revision),
        ));
    }
    if state.admission.in_flight_request_id.as_deref() == Some(command.request_id.as_str()) {
        return Err(conflict(
            operation,
            &command.request_id,
            "An operator-blocked request cannot still own global runtime admission.",
            Some(state.admission.revision),
        ));
    }
    let request = &mut state.requests[index];
    // The validated current observation exactly matches the admitted fence; no
    // metadata parsing or support inference occurs in the policy evaluator.
    request.status = ProvisioningRequestStatus::WaitingAdmission;
    request.admission_revision = None;
    request.failure_reason = None;
    request.revision = next_revision(request.revision, operation, &request.request_id)?;
    request.updated_at_micros = command.now_micros;
    commit_root(state, command.now_micros, operation)?;
    Ok((
        state.clone(),
        ProvisioningOutcome::Retried {
            request_id: command.request_id,
        },
    ))
}
