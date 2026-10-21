#![allow(clippy::wildcard_imports)]

use super::*;

const RUNTIME_OWNERSHIP_LOST: &str = "runtime_ownership_lost";

pub(super) fn retire_runtime_ownership(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: &RetireRuntimeOwnershipCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(
        operation,
        "wake_target_id",
        &command.wake_target_id,
        "wake_target_id",
    )?;
    validate_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )?;
    let matching: Vec<usize> = state
        .requests
        .iter()
        .enumerate()
        .filter(|(_, request)| {
            request.wake_target_id.as_deref() == Some(command.wake_target_id.as_str())
        })
        .map(|(index, _)| index)
        .collect();
    let Some(index) = matching
        .iter()
        .copied()
        .find(|index| is_retirable(state.requests[*index].status))
    else {
        let tombstone = matching.iter().copied().find(|index| {
            state.requests[*index].status == ProvisioningRequestStatus::Cancelled
                && state.requests[*index].failure_reason.as_deref() == Some(RUNTIME_OWNERSHIP_LOST)
        });
        return Ok((
            state.clone(),
            ProvisioningOutcome::Retired {
                request_id: tombstone.map(|index| state.requests[index].request_id.clone()),
                changed: false,
            },
        ));
    };
    let request_id = state.requests[index].request_id.clone();
    state.requests[index].status = ProvisioningRequestStatus::Cancelled;
    state.requests[index].failure_reason = Some(RUNTIME_OWNERSHIP_LOST.to_owned());
    state.requests[index].revision =
        next_revision(state.requests[index].revision, operation, &request_id)?;
    state.requests[index].updated_at_micros = command.now_micros;
    if state.admission.in_flight_request_id.as_deref() == Some(request_id.as_str()) {
        state.admission.in_flight_request_id = None;
        state.admission.revision = next_revision(state.admission.revision, operation, "admission")?;
    }
    commit_root(state, command.now_micros, operation)?;
    let protected = HashSet::from([request_id.clone()]);
    prune_terminal(
        state,
        command.terminal_request_retention,
        operation,
        &protected,
    )?;
    Ok((
        state.clone(),
        ProvisioningOutcome::Retired {
            request_id: Some(request_id),
            changed: true,
        },
    ))
}

pub(super) fn retire_runtime_ownership_batch(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: &RetireRuntimeOwnershipBatchCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(operation, "project_id", &command.project_id, "project_id")?;
    validate_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )?;
    if command.wake_target_ids.is_empty() {
        return Err(error(
            operation,
            &command.project_id,
            "wake_target_ids must be non-empty and unique.",
        ));
    }
    let mut wake_ids = HashSet::new();
    for wake_target_id in &command.wake_target_ids {
        validate_id(
            operation,
            &command.project_id,
            wake_target_id,
            "wake_target_id",
        )?;
        if !wake_ids.insert(wake_target_id.as_str()) {
            return Err(error(
                operation,
                &command.project_id,
                "wake_target_ids must be non-empty and unique.",
            ));
        }
    }

    let mut entries = Vec::with_capacity(command.wake_target_ids.len());
    for wake_target_id in &command.wake_target_ids {
        let Some(index) = state.requests.iter().position(|request| {
            request.project_id == command.project_id
                && request.wake_target_id.as_deref() == Some(wake_target_id.as_str())
        }) else {
            return Err(error(
                operation,
                wake_target_id,
                "Batch retirement requires an active or transient provisioning owner, or its tombstone.",
            ));
        };
        let request = &state.requests[index];
        let tombstone = request.status == ProvisioningRequestStatus::Cancelled
            && request.failure_reason.as_deref() == Some(RUNTIME_OWNERSHIP_LOST);
        if !is_retirable(request.status) && !tombstone {
            return Err(error(
                operation,
                wake_target_id,
                "Batch retirement requires an active or transient provisioning owner, or its tombstone.",
            ));
        }
        entries.push((index, request.request_id.clone(), !tombstone));
    }

    let changed = entries.iter().any(|(_, _, should_change)| *should_change);
    let request_ids: Vec<String> = entries.iter().map(|(_, id, _)| id.clone()).collect();
    if !changed {
        return Ok((
            state.clone(),
            ProvisioningOutcome::BatchRetired {
                request_ids,
                changed: false,
            },
        ));
    }
    for (index, request_id, should_change) in &entries {
        if !*should_change {
            continue;
        }
        state.requests[*index].status = ProvisioningRequestStatus::Cancelled;
        state.requests[*index].failure_reason = Some(RUNTIME_OWNERSHIP_LOST.to_owned());
        state.requests[*index].revision =
            next_revision(state.requests[*index].revision, operation, request_id)?;
        state.requests[*index].updated_at_micros = command.now_micros;
        if state.admission.in_flight_request_id.as_deref() == Some(request_id.as_str()) {
            state.admission.in_flight_request_id = None;
            state.admission.revision =
                next_revision(state.admission.revision, operation, "admission")?;
        }
    }
    commit_root(state, command.now_micros, operation)?;
    let protected = request_ids.iter().cloned().collect::<HashSet<_>>();
    prune_terminal(
        state,
        command.terminal_request_retention,
        operation,
        &protected,
    )?;
    Ok((
        state.clone(),
        ProvisioningOutcome::BatchRetired {
            request_ids,
            changed: true,
        },
    ))
}
