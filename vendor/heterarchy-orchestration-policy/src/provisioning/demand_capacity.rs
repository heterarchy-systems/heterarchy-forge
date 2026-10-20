#![allow(clippy::wildcard_imports)]

use super::*;

pub(super) fn synchronize_demand(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: SynchronizeDemandCommand,
    cancel_queued_only: bool,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(operation, "project_id", &command.project_id, "project_id")?;
    if command.spawn_needed > command.desired_capacity {
        return Err(error(
            operation,
            &command.project_id,
            "spawn_needed cannot exceed desired_capacity.",
        ));
    }
    let mut changed = false;
    let mut protected_request_ids = HashSet::new();
    let demand_index = state
        .demands
        .iter()
        .position(|item| item.project_id == command.project_id);
    let demand = if let Some(index) = demand_index {
        let current = &mut state.demands[index];
        if current.desired_capacity != command.desired_capacity
            || current.spawn_needed != command.spawn_needed
        {
            current.desired_capacity = command.desired_capacity;
            current.spawn_needed = command.spawn_needed;
            current.revision = next_revision(current.revision, operation, &command.project_id)?;
            current.updated_at_micros = command.now_micros;
            changed = true;
        }
        current.clone()
    } else {
        if state.demands.len() >= MAX_PROVISIONING_DEMANDS {
            return Err(error(
                operation,
                &command.project_id,
                "Provisioning snapshot cannot add another demand beyond its bounded limit.",
            ));
        }
        changed = true;
        let demand = ProvisioningDemand {
            schema_version: 2,
            project_id: command.project_id.clone(),
            desired_capacity: command.desired_capacity,
            spawn_needed: command.spawn_needed,
            revision: Revision(0),
            created_at_micros: command.now_micros,
            updated_at_micros: command.now_micros,
        };
        state.demands.push(demand.clone());
        demand
    };
    synchronize_requests(
        operation,
        state,
        &demand,
        command.spawn_needed,
        cancel_queued_only,
        &command.request_seeds,
        command.now_micros,
        &mut changed,
        &mut protected_request_ids,
    )?;
    if changed {
        commit_root(state, command.now_micros, operation)?;
    }
    let pruned = prune_terminal(
        state,
        command.terminal_request_retention,
        operation,
        &protected_request_ids,
    )?;
    if pruned && !changed {
        commit_root(state, command.now_micros, operation)?;
    }
    Ok((
        state.clone(),
        ProvisioningOutcome::DemandSynchronized {
            project_id: command.project_id,
            spawn_needed: demand.spawn_needed,
        },
    ))
}

pub(super) fn apply_capacity_reservation(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: ApplyCapacityReservationCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_id(operation, "project_id", &command.project_id, "project_id")?;
    if command.spawn_needed > command.capacity_deficit {
        return Err(error(
            operation,
            &command.project_id,
            "spawn_needed cannot exceed capacity_deficit.",
        ));
    }
    let current_pending = state
        .demands
        .iter()
        .find(|item| item.project_id == command.project_id)
        .map_or(0, |item| item.spawn_needed);
    let current_global_pending = state.demands.iter().try_fold(0_u64, |total, demand| {
        checked_add(
            total,
            demand.spawn_needed,
            operation,
            "capacity",
            "Provisioning global pending capacity overflowed.",
        )
    })?;
    // These four floors intentionally preserve the stale-observation
    // revalidation contract: a scheduler snapshot may be ahead of or behind the
    // locked durable state, and that race reduces reservation instead of failing.
    let project_advance = current_pending.saturating_sub(command.project_pending_snapshot);
    let additional_since_snapshot =
        current_global_pending.saturating_sub(command.global_pending_snapshot);
    let remaining_decision = command.spawn_needed.saturating_sub(project_advance);
    let fresh_global_allowance = command
        .global_headroom
        .saturating_sub(additional_since_snapshot);
    let target_increment = remaining_decision.min(fresh_global_allowance);
    let target_pending = command.capacity_deficit.min(checked_add(
        current_pending,
        target_increment,
        operation,
        &command.project_id,
        "Provisioning project pending capacity overflowed.",
    )?);
    let sync = synchronize_demand(
        operation,
        state,
        SynchronizeDemandCommand {
            project_id: command.project_id.clone(),
            desired_capacity: command.desired_capacity,
            spawn_needed: target_pending,
            request_seeds: command.request_seeds,
            now_micros: command.now_micros,
            terminal_request_retention: command.terminal_request_retention,
        },
        true,
    )?;
    Ok((
        sync.0,
        ProvisioningOutcome::CapacityReserved {
            project_id: command.project_id,
            spawn_needed: target_pending,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(super) fn synchronize_requests(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    demand: &ProvisioningDemand,
    target_spawn_needed: u64,
    cancel_queued_only: bool,
    seeds: &[ProvisioningRequestSeed],
    now: TimestampMicros,
    changed: &mut bool,
    protected_request_ids: &mut HashSet<String>,
) -> Result<(), DomainError> {
    let outstanding_usize = state
        .requests
        .iter()
        .filter(|item| {
            item.project_id == demand.project_id
                && (item.status.pending()
                    || item.status == ProvisioningRequestStatus::OperatorBlocked)
        })
        .count();
    let mut outstanding = u64::try_from(outstanding_usize).map_err(|_| {
        arithmetic_error(
            operation,
            &demand.project_id,
            "Provisioning request count does not fit u64.",
        )
    })?;
    let required_new = target_spawn_needed.saturating_sub(outstanding);
    let required_new_usize = usize::try_from(required_new).map_err(|_| {
        arithmetic_error(
            operation,
            &demand.project_id,
            "Provisioning required request count does not fit the platform index type.",
        )
    })?;
    let available_request_slots = MAX_PROVISIONING_REQUESTS
        .checked_sub(state.requests.len())
        .ok_or_else(|| {
            error(
                operation,
                &demand.project_id,
                "Provisioning snapshot already exceeds its bounded request limit.",
            )
        })?;
    if required_new_usize > available_request_slots {
        return Err(error(
            operation,
            &demand.project_id,
            "Provisioning reservation would exceed the bounded request limit.",
        ));
    }
    let mut seed_index = 0;
    while outstanding < target_spawn_needed {
        let Some(seed) = seeds.get(seed_index) else {
            return Err(error(
                operation,
                &demand.project_id,
                "Provisioning request seeds are required for new reservations.",
            ));
        };
        validate_id(
            operation,
            &demand.project_id,
            &seed.request_id,
            "request_id",
        )?;
        validate_id(
            operation,
            &seed.request_id,
            &seed.wake_target_id,
            "wake_target_id",
        )?;
        seed_index += 1;
        if state.requests.iter().any(|item| {
            item.request_id == seed.request_id
                || item.wake_target_id.as_deref() == Some(seed.wake_target_id.as_str())
        }) {
            return Err(error(
                operation,
                &seed.request_id,
                "Prepared provisioning request or wake target ID collides with durable state.",
            ));
        }
        state.requests.push(ProvisioningRequest {
            schema_version: 2,
            request_id: seed.request_id.clone(),
            project_id: demand.project_id.clone(),
            provider_binding: None,
            status: ProvisioningRequestStatus::WaitingAdmission,
            admission_revision: None,
            revision: Revision(0),
            provider_runtime_id: None,
            wake_target_id: Some(seed.wake_target_id.clone()),
            failure_reason: None,
            created_at_micros: now,
            updated_at_micros: now,
        });
        outstanding = checked_add(
            outstanding,
            1,
            operation,
            &demand.project_id,
            "Provisioning request count overflowed.",
        )?;
        *changed = true;
    }
    if target_spawn_needed == 0 {
        let cancelable = |status: ProvisioningRequestStatus| {
            if cancel_queued_only {
                status.queued()
            } else {
                status.pending()
            }
        };
        let in_flight = state.admission.in_flight_request_id.clone();
        for request in &mut state.requests {
            if request.project_id == demand.project_id && cancelable(request.status) {
                request.status = ProvisioningRequestStatus::Cancelled;
                request.failure_reason = Some("capacity_no_longer_needed".to_owned());
                request.revision = next_revision(request.revision, operation, &request.request_id)?;
                request.updated_at_micros = now;
                protected_request_ids.insert(request.request_id.clone());
                *changed = true;
            }
        }
        if let Some(in_flight_id) = in_flight
            && state.requests.iter().any(|item| {
                item.request_id == in_flight_id
                    && item.status == ProvisioningRequestStatus::Cancelled
            })
        {
            state.admission.in_flight_request_id = None;
            state.admission.revision =
                next_revision(state.admission.revision, operation, "admission")?;
            *changed = true;
        }
    }
    Ok(())
}
