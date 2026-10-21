//! Unit and generative regressions for runtime activation planning.

use proptest::prelude::*;

use crate::{ErrorCode, Revision, TimestampMicros};

use super::{evaluate_runtime_activation, *};

fn provider_binding(
    spawn_supported: bool,
    park_supported: bool,
    retire_supported: bool,
) -> RuntimeActivationProviderBinding {
    RuntimeActivationProviderBinding {
        project_id: "project-a".to_owned(),
        binding_id: "binding-a".to_owned(),
        revision: Revision(7),
        capability: ProviderActivationCapability {
            spawn_supported,
            park_supported,
            retire_supported,
        },
    }
}

fn runtime(
    runtime_id: &str,
    status: RuntimeActivationStatus,
    availability: RuntimeActivationAvailability,
    created_at_micros: u64,
) -> RuntimeActivationObservation {
    RuntimeActivationObservation {
        project_id: "project-a".to_owned(),
        runtime_id: runtime_id.to_owned(),
        binding_id: "binding-a".to_owned(),
        binding_revision: Revision(7),
        status,
        availability,
        provider_compatible: true,
        activation_capability: RuntimeActivationRuntimeCapability {
            reusable: availability == RuntimeActivationAvailability::Active,
            wake_supported: availability == RuntimeActivationAvailability::Dormant,
        },
        delivery_state: RuntimeActivationDeliveryState {
            cooldown_active: false,
            delivery_lease_expired: false,
        },
        maintenance_eligibility: RuntimeActivationMaintenanceEligibility {
            park_eligible: false,
            retire_eligible: false,
        },
        revision: Revision(created_at_micros + 10),
        activation_revision: Revision(created_at_micros + 20),
        created_at_micros: TimestampMicros(created_at_micros),
    }
}

fn snapshot(
    engaged_task_count: u64,
    pending_provisioning_count: u64,
    global_max_runtimes: u64,
    global_recoverable_runtime_count: u64,
    runtimes: Vec<RuntimeActivationObservation>,
) -> RuntimeActivationSnapshot {
    RuntimeActivationSnapshot {
        project_id: "project-a".to_owned(),
        ready_task_count: engaged_task_count,
        engaged_task_count,
        project_max_runtimes: engaged_task_count.max(1),
        global_max_runtimes,
        global_recoverable_runtime_count,
        global_activated_runtime_count: 0,
        pending_provisioning_count,
        global_pending_provisioning_count: pending_provisioning_count,
        provider_binding: provider_binding(true, true, true),
        runtimes,
    }
}

fn plan(snapshot: &RuntimeActivationSnapshot) -> RuntimeActivationDecision {
    match evaluate_runtime_activation(
        "runtime_activation_test",
        RuntimeActivationCommand::Plan(RuntimeActivationPlanCommand {}),
        snapshot,
    ) {
        Ok(decision) => decision,
        Err(error) => panic!("expected valid runtime activation decision: {error:?}"),
    }
}

#[test]
fn reuse_wake_spawn_park_retire_actions_follow_stable_policy_order() {
    let mut parked = runtime(
        "parked-runtime",
        RuntimeActivationStatus::Idle,
        RuntimeActivationAvailability::Active,
        30,
    );
    parked.activation_capability.reusable = false;
    parked.maintenance_eligibility.park_eligible = true;
    let mut retired = runtime(
        "retired-runtime",
        RuntimeActivationStatus::Idle,
        RuntimeActivationAvailability::Offline,
        1,
    );
    retired.activation_capability.reusable = false;
    retired.maintenance_eligibility.retire_eligible = true;
    let snapshot = snapshot(
        4,
        0,
        5,
        3,
        vec![
            parked,
            runtime(
                "dormant-runtime",
                RuntimeActivationStatus::Idle,
                RuntimeActivationAvailability::Dormant,
                20,
            ),
            retired,
            runtime(
                "active-runtime",
                RuntimeActivationStatus::Idle,
                RuntimeActivationAvailability::Active,
                10,
            ),
        ],
    );
    let decision = plan(&snapshot);

    assert_eq!(decision.desired_capacity, 4);
    assert_eq!(decision.committed_capacity, 4);
    assert_eq!(decision.unmet_capacity, 0);
    assert_eq!(
        decision.actions,
        vec![
            RuntimeActivationAction::Reuse(RuntimeActivationRuntimeAction {
                runtime_id: "active-runtime".to_owned(),
                binding_id: "binding-a".to_owned(),
                binding_revision: Revision(7),
                observed_revision: Revision(20),
                observed_activation_revision: Revision(30),
                next_activation_revision: Some(Revision(31)),
            }),
            RuntimeActivationAction::Wake(RuntimeActivationRuntimeAction {
                runtime_id: "dormant-runtime".to_owned(),
                binding_id: "binding-a".to_owned(),
                binding_revision: Revision(7),
                observed_revision: Revision(30),
                observed_activation_revision: Revision(40),
                next_activation_revision: Some(Revision(41)),
            }),
            RuntimeActivationAction::Spawn(RuntimeActivationSpawnAction {
                project_id: "project-a".to_owned(),
                binding_id: "binding-a".to_owned(),
                binding_revision: Revision(7),
                count: 2,
            }),
            RuntimeActivationAction::Park(RuntimeActivationRuntimeAction {
                runtime_id: "parked-runtime".to_owned(),
                binding_id: "binding-a".to_owned(),
                binding_revision: Revision(7),
                observed_revision: Revision(40),
                observed_activation_revision: Revision(50),
                next_activation_revision: None,
            }),
            RuntimeActivationAction::Retire(RuntimeActivationRuntimeAction {
                runtime_id: "retired-runtime".to_owned(),
                binding_id: "binding-a".to_owned(),
                binding_revision: Revision(7),
                observed_revision: Revision(11),
                observed_activation_revision: Revision(21),
                next_activation_revision: None,
            }),
        ],
    );
}

#[test]
fn existing_reservations_and_spawn_headroom_bound_committed_capacity() {
    let mut runtime = runtime(
        "cooldown-runtime",
        RuntimeActivationStatus::Idle,
        RuntimeActivationAvailability::Active,
        1,
    );
    runtime.delivery_state.cooldown_active = true;
    let activation_snapshot = snapshot(4, 2, 4, 1, vec![runtime]);
    let decision = plan(&activation_snapshot);

    assert_eq!(decision.committed_capacity, 3);
    assert_eq!(decision.unmet_capacity, 1);
    assert_eq!(
        decision.actions,
        vec![RuntimeActivationAction::Spawn(
            RuntimeActivationSpawnAction {
                project_id: "project-a".to_owned(),
                binding_id: "binding-a".to_owned(),
                binding_revision: Revision(7),
                count: 1,
            }
        )],
    );
}

#[test]
fn expired_delivery_returns_recovery_only_before_fresh_observation() {
    let mut expired = runtime(
        "expired-runtime",
        RuntimeActivationStatus::Waking,
        RuntimeActivationAvailability::Active,
        1,
    );
    expired.delivery_state.delivery_lease_expired = true;
    let activation_snapshot = snapshot(1, 0, 1, 1, vec![expired]);
    let decision = plan(&activation_snapshot);

    assert_eq!(decision.actions.len(), 1);
    assert!(matches!(
        &decision.actions[0],
        RuntimeActivationAction::Recover(action)
            if action.runtime_id == "expired-runtime"
                && action.observed_revision == Revision(11)
                && action.observed_activation_revision == Revision(21)
    ));
}

#[test]
fn invalid_provider_fence_and_duplicate_runtime_fail_closed() {
    let mut stale = runtime(
        "runtime-a",
        RuntimeActivationStatus::Idle,
        RuntimeActivationAvailability::Active,
        1,
    );
    stale.binding_revision = Revision(6);
    let error = match evaluate_runtime_activation(
        "runtime_activation_test",
        RuntimeActivationCommand::Plan(RuntimeActivationPlanCommand {}),
        &snapshot(1, 0, 1, 1, vec![stale]),
    ) {
        Ok(_) => panic!("stale ProviderBinding fence must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::RuntimeActivationInvalidSnapshot);
    assert_eq!(error.resource_id, "runtime-a");

    let duplicate = runtime(
        "runtime-b",
        RuntimeActivationStatus::Idle,
        RuntimeActivationAvailability::Active,
        1,
    );
    let error = match evaluate_runtime_activation(
        "runtime_activation_test",
        RuntimeActivationCommand::Plan(RuntimeActivationPlanCommand {}),
        &snapshot(1, 0, 1, 1, vec![duplicate.clone(), duplicate]),
    ) {
        Ok(_) => panic!("duplicate runtime identity must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::RuntimeActivationInvalidSnapshot);
    assert_eq!(error.resource_id, "runtime-b");
}

proptest! {
    #[test]
    fn planning_is_deterministic_under_input_permutation(reverse in any::<bool>()) {
        let base = vec![
            runtime("runtime-a", RuntimeActivationStatus::Idle, RuntimeActivationAvailability::Active, 10),
            runtime("runtime-b", RuntimeActivationStatus::Idle, RuntimeActivationAvailability::Dormant, 20),
            runtime("runtime-c", RuntimeActivationStatus::Busy, RuntimeActivationAvailability::Active, 30),
            runtime("runtime-d", RuntimeActivationStatus::Idle, RuntimeActivationAvailability::Offline, 40),
        ];
        let mut permuted = base.clone();
        if reverse {
            permuted.reverse();
        }
        let first_snapshot = snapshot(4, 0, 4, 3, base);
        let second_snapshot = snapshot(4, 0, 4, 3, permuted);
        let first = plan(&first_snapshot);
        let second = plan(&second_snapshot);
        prop_assert_eq!(first, second);
    }
}
