//! Pure deterministic `Reuse -> Wake -> Spawn -> Park -> Retire` planning.

use std::collections::HashSet;

use crate::{DomainError, ErrorCode, Revision};

use super::types::{
    RuntimeActivationAction, RuntimeActivationAvailability, RuntimeActivationDecision,
    RuntimeActivationObservation, RuntimeActivationProviderBinding, RuntimeActivationRuntimeAction,
    RuntimeActivationSnapshot, RuntimeActivationSpawnAction, RuntimeActivationStatus,
};

/// Plan all provider-neutral runtime activation actions from one coherent read.
///
/// The caller applies each returned action with its `ProviderBinding`/runtime
/// CAS fence. A recovery action deliberately consumes this evaluation: the
/// effect boundary persists recovery and takes a fresh observation before new
/// work is delivered, avoiding an action against stale runtime presence.
pub(super) fn plan(
    operation: &str,
    snapshot: &RuntimeActivationSnapshot,
) -> Result<RuntimeActivationDecision, DomainError> {
    let desired_capacity = desired_capacity(snapshot);
    let global_headroom = global_headroom(operation, snapshot)?;
    let global_activation_headroom = global_activation_headroom(snapshot);
    let runtimes = sorted_runtimes(snapshot);
    if let Some(decision) = recovery_decision(
        operation,
        snapshot,
        desired_capacity,
        global_headroom,
        global_activation_headroom,
        &runtimes,
    )? {
        return Ok(decision);
    }

    let retiring_ids = retiring_ids(snapshot, &runtimes);
    let eligible = eligible_runtimes(&runtimes, &retiring_ids);
    let occupied_capacity = occupied_capacity(operation, &eligible)?;
    let mut actions = plan_capacity_actions(
        snapshot,
        desired_capacity,
        global_headroom,
        global_activation_headroom,
        &eligible,
        occupied_capacity,
    );
    append_maintenance_actions(snapshot, &runtimes, &eligible, &mut actions);

    decision_from_actions(
        operation,
        snapshot,
        desired_capacity,
        global_headroom,
        global_activation_headroom,
        occupied_capacity,
        actions,
    )
}

fn desired_capacity(snapshot: &RuntimeActivationSnapshot) -> u64 {
    snapshot
        .engaged_task_count
        .min(snapshot.project_max_runtimes)
        .min(snapshot.global_max_runtimes)
}

fn global_headroom(
    operation: &str,
    snapshot: &RuntimeActivationSnapshot,
) -> Result<u64, DomainError> {
    let globally_reserved = checked_add(
        operation,
        snapshot.global_recoverable_runtime_count,
        snapshot.global_pending_provisioning_count,
    )?;
    Ok(snapshot
        .global_max_runtimes
        .saturating_sub(globally_reserved))
}

fn global_activation_headroom(snapshot: &RuntimeActivationSnapshot) -> u64 {
    snapshot
        .global_max_runtimes
        .saturating_sub(snapshot.global_activated_runtime_count)
}

fn sorted_runtimes(snapshot: &RuntimeActivationSnapshot) -> Vec<&RuntimeActivationObservation> {
    let mut runtimes = snapshot.runtimes.iter().collect::<Vec<_>>();
    runtimes.sort_unstable_by(|left, right| {
        (left.created_at_micros, left.runtime_id.as_str())
            .cmp(&(right.created_at_micros, right.runtime_id.as_str()))
    });
    runtimes
}

fn recovery_decision(
    operation: &str,
    snapshot: &RuntimeActivationSnapshot,
    desired_capacity: u64,
    global_headroom: u64,
    global_activation_headroom: u64,
    runtimes: &[&RuntimeActivationObservation],
) -> Result<Option<RuntimeActivationDecision>, DomainError> {
    let actions = runtimes
        .iter()
        .copied()
        .filter(|runtime| should_recover(runtime))
        .map(|runtime| RuntimeActivationAction::Recover(runtime_action(runtime, false)))
        .collect::<Vec<_>>();
    if actions.is_empty() {
        return Ok(None);
    }
    decision_from_actions(
        operation,
        snapshot,
        desired_capacity,
        global_headroom,
        global_activation_headroom,
        occupied_capacity(operation, runtimes)?,
        actions,
    )
    .map(Some)
}

fn retiring_ids<'a>(
    snapshot: &'a RuntimeActivationSnapshot,
    runtimes: &[&'a RuntimeActivationObservation],
) -> HashSet<&'a str> {
    runtimes
        .iter()
        .copied()
        .filter(|runtime| should_retire(&snapshot.provider_binding, runtime))
        .map(|runtime| runtime.runtime_id.as_str())
        .collect()
}

fn eligible_runtimes<'a>(
    runtimes: &[&'a RuntimeActivationObservation],
    retiring_ids: &HashSet<&str>,
) -> Vec<&'a RuntimeActivationObservation> {
    runtimes
        .iter()
        .copied()
        .filter(|runtime| {
            runtime.provider_compatible && !retiring_ids.contains(runtime.runtime_id.as_str())
        })
        .collect()
}

fn plan_capacity_actions(
    snapshot: &RuntimeActivationSnapshot,
    desired_capacity: u64,
    global_headroom: u64,
    global_activation_headroom: u64,
    eligible: &[&RuntimeActivationObservation],
    occupied_capacity: u64,
) -> Vec<RuntimeActivationAction> {
    let mut remaining = desired_capacity.saturating_sub(occupied_capacity);
    let mut activation_budget = global_activation_headroom;
    let mut actions = Vec::new();
    select_existing(
        eligible,
        &mut remaining,
        &mut activation_budget,
        &mut actions,
        can_reuse,
        |runtime| RuntimeActivationAction::Reuse(runtime_action(runtime, true)),
    );
    select_existing(
        eligible,
        &mut remaining,
        &mut activation_budget,
        &mut actions,
        can_wake,
        |runtime| RuntimeActivationAction::Wake(runtime_action(runtime, true)),
    );
    let count = remaining
        .saturating_sub(snapshot.pending_provisioning_count)
        .min(global_headroom);
    if snapshot.provider_binding.capability.spawn_supported && count > 0 {
        actions.push(RuntimeActivationAction::Spawn(
            RuntimeActivationSpawnAction {
                project_id: snapshot.project_id.clone(),
                binding_id: snapshot.provider_binding.binding_id.clone(),
                binding_revision: snapshot.provider_binding.revision,
                count,
            },
        ));
    }
    actions
}

fn select_existing(
    runtimes: &[&RuntimeActivationObservation],
    remaining: &mut u64,
    activation_budget: &mut u64,
    actions: &mut Vec<RuntimeActivationAction>,
    predicate: fn(&RuntimeActivationObservation) -> bool,
    wrap: impl Fn(&RuntimeActivationObservation) -> RuntimeActivationAction,
) {
    for runtime in runtimes
        .iter()
        .copied()
        .filter(|runtime| predicate(runtime))
    {
        if *remaining == 0 || *activation_budget == 0 {
            break;
        }
        actions.push(wrap(runtime));
        *remaining = remaining.saturating_sub(1);
        *activation_budget = activation_budget.saturating_sub(1);
    }
}

fn append_maintenance_actions(
    snapshot: &RuntimeActivationSnapshot,
    runtimes: &[&RuntimeActivationObservation],
    eligible: &[&RuntimeActivationObservation],
    actions: &mut Vec<RuntimeActivationAction>,
) {
    let selected_ids = selected_runtime_ids(actions);
    if snapshot.provider_binding.capability.park_supported {
        for runtime in eligible.iter().rev().copied().filter(|runtime| {
            runtime.maintenance_eligibility.park_eligible
                && !selected_ids.contains(&runtime.runtime_id)
        }) {
            actions.push(RuntimeActivationAction::Park(runtime_action(
                runtime, false,
            )));
        }
    }
    if snapshot.provider_binding.capability.retire_supported {
        for runtime in runtimes
            .iter()
            .rev()
            .copied()
            .filter(|runtime| should_retire(&snapshot.provider_binding, runtime))
        {
            actions.push(RuntimeActivationAction::Retire(runtime_action(
                runtime, false,
            )));
        }
    }
}

fn selected_runtime_ids(actions: &[RuntimeActivationAction]) -> HashSet<String> {
    actions
        .iter()
        .filter_map(|action| match action {
            RuntimeActivationAction::Reuse(action) | RuntimeActivationAction::Wake(action) => {
                Some(action.runtime_id.clone())
            }
            RuntimeActivationAction::Recover(_)
            | RuntimeActivationAction::Spawn(_)
            | RuntimeActivationAction::Park(_)
            | RuntimeActivationAction::Retire(_) => None,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn decision_from_actions(
    operation: &str,
    snapshot: &RuntimeActivationSnapshot,
    desired_capacity: u64,
    global_headroom: u64,
    global_activation_headroom: u64,
    occupied_capacity: u64,
    actions: Vec<RuntimeActivationAction>,
) -> Result<RuntimeActivationDecision, DomainError> {
    let selected_count = selected_capacity_count(operation, &actions)?;
    let active_capacity = checked_add(operation, occupied_capacity, selected_count)?;
    let capacity_deficit = desired_capacity.saturating_sub(active_capacity);
    let spawned_capacity = spawn_count(operation, &actions)?;
    let committed_capacity = checked_add(
        operation,
        active_capacity,
        snapshot.pending_provisioning_count,
    )?;
    let committed_capacity = checked_add(operation, committed_capacity, spawned_capacity)?;
    Ok(RuntimeActivationDecision {
        project_id: snapshot.project_id.clone(),
        ready_task_count: snapshot.ready_task_count,
        desired_capacity,
        global_activation_headroom,
        global_headroom,
        pending_provisioning_count: snapshot.pending_provisioning_count,
        global_pending_provisioning_count: snapshot.global_pending_provisioning_count,
        capacity_deficit,
        committed_capacity,
        unmet_capacity: desired_capacity.saturating_sub(committed_capacity),
        actions,
    })
}

fn selected_capacity_count(
    operation: &str,
    actions: &[RuntimeActivationAction],
) -> Result<u64, DomainError> {
    let count = actions
        .iter()
        .filter(|action| {
            matches!(
                action,
                RuntimeActivationAction::Reuse(_) | RuntimeActivationAction::Wake(_)
            )
        })
        .count();
    u64::try_from(count).map_err(|_| arithmetic_error(operation))
}

fn spawn_count(operation: &str, actions: &[RuntimeActivationAction]) -> Result<u64, DomainError> {
    actions.iter().try_fold(0, |count, action| match action {
        RuntimeActivationAction::Spawn(spawn) => checked_add(operation, count, spawn.count),
        RuntimeActivationAction::Recover(_)
        | RuntimeActivationAction::Reuse(_)
        | RuntimeActivationAction::Wake(_)
        | RuntimeActivationAction::Park(_)
        | RuntimeActivationAction::Retire(_) => Ok(count),
    })
}

fn occupied_capacity(
    operation: &str,
    runtimes: &[&RuntimeActivationObservation],
) -> Result<u64, DomainError> {
    let occupied = runtimes
        .iter()
        .filter(|runtime| runtime.status.reserves_capacity())
        .count();
    u64::try_from(occupied).map_err(|_| arithmetic_error(operation))
}

fn should_recover(runtime: &RuntimeActivationObservation) -> bool {
    runtime.provider_compatible
        && runtime.delivery_state.delivery_lease_expired
        && runtime.availability != RuntimeActivationAvailability::Offline
}

fn should_retire(
    binding: &RuntimeActivationProviderBinding,
    runtime: &RuntimeActivationObservation,
) -> bool {
    binding.capability.retire_supported
        && runtime.provider_compatible
        && runtime.maintenance_eligibility.retire_eligible
}

fn can_reuse(runtime: &RuntimeActivationObservation) -> bool {
    runtime.status == RuntimeActivationStatus::Idle
        && runtime.availability == RuntimeActivationAvailability::Active
        && runtime.activation_capability.reusable
        && !runtime.delivery_state.cooldown_active
}

fn can_wake(runtime: &RuntimeActivationObservation) -> bool {
    runtime.status == RuntimeActivationStatus::Idle
        && runtime.availability == RuntimeActivationAvailability::Dormant
        && runtime.activation_capability.wake_supported
        && !runtime.delivery_state.cooldown_active
}

fn runtime_action(
    runtime: &RuntimeActivationObservation,
    advances_activation: bool,
) -> RuntimeActivationRuntimeAction {
    RuntimeActivationRuntimeAction {
        runtime_id: runtime.runtime_id.clone(),
        binding_id: runtime.binding_id.clone(),
        binding_revision: runtime.binding_revision,
        observed_revision: runtime.revision,
        observed_activation_revision: runtime.activation_revision,
        next_activation_revision: advances_activation
            .then(|| runtime.activation_revision.0.checked_add(1).map(Revision))
            .flatten(),
    }
}

fn checked_add(operation: &str, left: u64, right: u64) -> Result<u64, DomainError> {
    left.checked_add(right)
        .ok_or_else(|| arithmetic_error(operation))
}

fn arithmetic_error(operation: &str) -> DomainError {
    DomainError {
        code: ErrorCode::RuntimeActivationArithmeticOverflow,
        operation: operation.to_owned(),
        resource_id: "capacity".to_owned(),
        message: "Runtime activation capacity cannot be represented safely.".to_owned(),
        current_revision: None,
    }
}
