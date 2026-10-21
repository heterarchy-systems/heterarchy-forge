#![allow(clippy::expect_used)]

use super::*;
use proptest::prelude::*;

const SCHEMA_VERSION: u32 = 2;

fn empty_snapshot() -> ProvisioningSnapshot {
    ProvisioningSnapshot {
        schema_version: SCHEMA_VERSION,
        revision: Revision(0),
        demands: Vec::new(),
        requests: Vec::new(),
        admission: ProvisioningAdmission {
            schema_version: SCHEMA_VERSION,
            in_flight_request_id: None,
            last_admitted_at_micros: None,
            next_admission_at_micros: None,
            backoff_attempt: 0,
            backoff_until_micros: None,
            revision: Revision(0),
        },
        updated_at_micros: TimestampMicros(0),
    }
}

fn supported_binding(project_id: &str) -> ProviderBindingObservation {
    ProviderBindingObservation {
        project_id: project_id.to_owned(),
        binding_id: format!("binding-{project_id}"),
        revision: Revision(7),
        connector_epoch: 3,
        supported: true,
        metadata_fingerprint: Some("a".repeat(64)),
    }
}

fn evaluate(command: ProvisioningCommand, snapshot: ProvisioningSnapshot) -> ProvisioningDecision {
    super::evaluate_provisioning("provisioning_test", command, snapshot)
        .expect("valid provisioning fixture")
}

fn synchronized(now: u64) -> ProvisioningSnapshot {
    evaluate(
        ProvisioningCommand::SynchronizeDemand(SynchronizeDemandCommand {
            project_id: "project-a".to_owned(),
            desired_capacity: 1,
            spawn_needed: 1,
            request_seeds: vec![ProvisioningRequestSeed {
                request_id: "request-a".to_owned(),
                wake_target_id: "wake-a".to_owned(),
            }],
            now_micros: TimestampMicros(now),
            terminal_request_retention: 128,
        }),
        empty_snapshot(),
    )
    .snapshot
}

fn admitted(snapshot: ProvisioningSnapshot, now: u64) -> ProvisioningSnapshot {
    evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(now),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: false,
            bindings: Vec::new(),
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        snapshot,
    )
    .snapshot
}

fn active(snapshot: ProvisioningSnapshot, now: u64) -> ProvisioningSnapshot {
    evaluate(
        ProvisioningCommand::ConfirmRegistration(ConfirmRegistrationCommand {
            request_id: "request-a".to_owned(),
            provider_runtime_id: "runtime-a".to_owned(),
            wake_target_id: "wake-a".to_owned(),
            admission_revision: Revision(1),
            provider_binding: None,
            now_micros: TimestampMicros(now),
        }),
        snapshot,
    )
    .snapshot
}

#[test]
fn registration_replay_requires_exact_runtime_and_fences() {
    let state = active(admitted(synchronized(10), 20), 30);
    let replay = evaluate(
        ProvisioningCommand::ConfirmRegistration(ConfirmRegistrationCommand {
            request_id: "request-a".to_owned(),
            provider_runtime_id: "runtime-a".to_owned(),
            wake_target_id: "wake-a".to_owned(),
            admission_revision: Revision(1),
            provider_binding: None,
            now_micros: TimestampMicros(31),
        }),
        state.clone(),
    );
    assert_eq!(replay.outcome, ProvisioningOutcome::Noop);
    assert_eq!(replay.snapshot, state);

    let mismatch = super::evaluate_provisioning(
        "provisioning_test",
        ProvisioningCommand::ConfirmRegistration(ConfirmRegistrationCommand {
            request_id: "request-a".to_owned(),
            provider_runtime_id: "runtime-b".to_owned(),
            wake_target_id: "wake-a".to_owned(),
            admission_revision: Revision(1),
            provider_binding: None,
            now_micros: TimestampMicros(31),
        }),
        state,
    )
    .expect_err("runtime mismatch");
    assert_eq!(mismatch.code, ErrorCode::ProvisioningConflict);
}

#[test]
fn admission_requires_explicit_supported_provider_binding_when_configured() {
    let snapshot = synchronized(10);
    let unsupported = ProviderBindingObservation {
        supported: false,
        ..supported_binding("project-a")
    };
    let blocked = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(20),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: true,
            bindings: vec![unsupported],
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        snapshot.clone(),
    );
    assert_eq!(blocked.outcome, ProvisioningOutcome::Noop);

    let admitted = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(20),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: true,
            bindings: vec![supported_binding("project-a")],
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        snapshot,
    );
    assert!(matches!(
        admitted.outcome,
        ProvisioningOutcome::Admitted { .. }
    ));
    assert_eq!(
        admitted.snapshot.requests[0].provider_binding,
        Some(supported_binding("project-a"))
    );
}

#[test]
fn opaque_provider_binding_is_accepted_without_provider_specific_parsing() {
    let opaque = ProviderBindingObservation {
        project_id: "project-a".to_owned(),
        binding_id: "opaque-binding".to_owned(),
        revision: Revision(11),
        connector_epoch: 19,
        supported: true,
        metadata_fingerprint: None,
    };
    let decision = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(20),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: true,
            bindings: vec![opaque.clone()],
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        synchronized(10),
    );
    assert_eq!(decision.snapshot.requests[0].provider_binding, Some(opaque));
}

#[test]
fn retry_rejects_unsupported_observation_without_fingerprint_fallback() {
    let binding = supported_binding("project-a");
    let admitted = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(20),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: true,
            bindings: vec![binding.clone()],
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        synchronized(10),
    )
    .snapshot;
    let blocked = evaluate(
        ProvisioningCommand::RecordFailure(RecordFailureCommand {
            request_id: "request-a".to_owned(),
            admission_revision: Revision(1),
            reason: "runtime_unavailable".to_owned(),
            rate_limited: false,
            now_micros: TimestampMicros(30),
            minimum_admission_interval_micros: 1,
            rate_limit_backoff_micros: vec![30],
            terminal_request_retention: 128,
        }),
        admitted,
    )
    .snapshot;
    let unsupported = ProviderBindingObservation {
        supported: false,
        metadata_fingerprint: Some("f".repeat(64)),
        ..binding.clone()
    };
    let error = super::evaluate_provisioning(
        "provisioning_test",
        ProvisioningCommand::RetryOperatorBlocked(RetryOperatorBlockedCommand {
            request_id: "request-a".to_owned(),
            expected_revision: blocked.requests[0].revision,
            provider_binding: unsupported,
            now_micros: TimestampMicros(40),
        }),
        blocked.clone(),
    )
    .expect_err("explicit unsupported binding must fail closed");
    assert_eq!(error.code, ErrorCode::ProvisioningBindingConflict);

    let stale = ProviderBindingObservation {
        revision: Revision(8),
        ..binding.clone()
    };
    let error = super::evaluate_provisioning(
        "provisioning_test",
        ProvisioningCommand::RetryOperatorBlocked(RetryOperatorBlockedCommand {
            request_id: "request-a".to_owned(),
            expected_revision: blocked.requests[0].revision,
            provider_binding: stale,
            now_micros: TimestampMicros(40),
        }),
        blocked.clone(),
    )
    .expect_err("stale binding fence must fail");
    assert_eq!(error.code, ErrorCode::ProvisioningBindingConflict);

    let retry = evaluate(
        ProvisioningCommand::RetryOperatorBlocked(RetryOperatorBlockedCommand {
            request_id: "request-a".to_owned(),
            expected_revision: blocked.requests[0].revision,
            provider_binding: binding,
            now_micros: TimestampMicros(40),
        }),
        blocked,
    );
    assert!(matches!(retry.outcome, ProvisioningOutcome::Retried { .. }));
    assert_eq!(
        retry.snapshot.requests[0].status,
        ProvisioningRequestStatus::WaitingAdmission
    );
}

#[test]
fn explicit_registration_binding_fence_prevents_stale_binding_confirmation() {
    let binding = supported_binding("project-a");
    let admitted = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(20),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: true,
            bindings: vec![binding.clone()],
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        synchronized(10),
    )
    .snapshot;
    let stale = ProviderBindingObservation {
        revision: Revision(8),
        ..binding.clone()
    };
    let error = super::evaluate_provisioning(
        "provisioning_test",
        ProvisioningCommand::ConfirmRegistration(ConfirmRegistrationCommand {
            request_id: "request-a".to_owned(),
            provider_runtime_id: "runtime-a".to_owned(),
            wake_target_id: "wake-a".to_owned(),
            admission_revision: Revision(1),
            provider_binding: Some(stale),
            now_micros: TimestampMicros(30),
        }),
        admitted,
    )
    .expect_err("binding fence mismatch");
    assert_eq!(error.code, ErrorCode::ProvisioningBindingConflict);
}

#[test]
fn lifecycle_progress_is_ordered_and_stale_leases_return_to_queue() {
    let admitted = admitted(synchronized(10), 20);
    let progressed = evaluate(
        ProvisioningCommand::ProgressRequest(ProgressRequestCommand {
            request_id: "request-a".to_owned(),
            status: ProvisioningRequestStatus::CreatingRuntime,
            admission_revision: Revision(1),
            now_micros: TimestampMicros(21),
        }),
        admitted,
    );
    assert_eq!(
        progressed.snapshot.requests[0].status,
        ProvisioningRequestStatus::CreatingRuntime
    );
    let stale = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(40),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: false,
            bindings: Vec::new(),
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        progressed.snapshot,
    );
    assert_eq!(
        stale.snapshot.requests[0].status,
        ProvisioningRequestStatus::OpeningProject
    );
    assert_eq!(
        stale.snapshot.requests[0].admission_revision,
        Some(Revision(3))
    );
}

#[test]
fn capacity_reconciliation_and_terminal_pruning_remain_bounded() {
    let initial = synchronized(10);
    let reserved = evaluate(
        ProvisioningCommand::ApplyCapacityReservation(ApplyCapacityReservationCommand {
            project_id: "project-a".to_owned(),
            desired_capacity: 2,
            capacity_deficit: 2,
            spawn_needed: 1,
            project_pending_snapshot: 1,
            global_headroom: 1,
            global_pending_snapshot: 1,
            request_seeds: vec![ProvisioningRequestSeed {
                request_id: "request-b".to_owned(),
                wake_target_id: "wake-b".to_owned(),
            }],
            now_micros: TimestampMicros(11),
            terminal_request_retention: 1,
        }),
        initial,
    );
    assert_eq!(reserved.snapshot.requests.len(), 2);
    let admitted = admitted(reserved.snapshot, 20);
    let cancelled = evaluate(
        ProvisioningCommand::CancelRequest(CancelRequestCommand {
            request_id: "request-a".to_owned(),
            admission_revision: Some(Revision(1)),
            now_micros: TimestampMicros(21),
            terminal_request_retention: 1,
        }),
        admitted,
    );
    assert_eq!(
        cancelled.snapshot.requests[0].status,
        ProvisioningRequestStatus::Cancelled
    );
}

#[test]
fn snapshot_and_command_bounds_are_typed_errors() {
    let oversized = ProviderBindingObservation {
        metadata_fingerprint: Some("x".repeat(MAX_PROVISIONING_BINDING_FINGERPRINT_BYTES + 1)),
        ..supported_binding("project-a")
    };
    let error = super::evaluate_provisioning(
        "provisioning_bounds",
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(20),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 1,
            binding_required: true,
            bindings: vec![oversized],
            new_request_seed: None,
            terminal_request_retention: 1,
        }),
        synchronized(10),
    )
    .expect_err("oversized opaque fingerprint");
    assert_eq!(error.code, ErrorCode::ProvisioningInvalidCommand);

    let oversized_requests = ProvisioningSnapshot {
        requests: (0..=MAX_PROVISIONING_REQUESTS)
            .map(|index| ProvisioningRequest {
                schema_version: SCHEMA_VERSION,
                request_id: format!("request-{index}"),
                project_id: "project-a".to_owned(),
                provider_binding: None,
                status: ProvisioningRequestStatus::WaitingAdmission,
                admission_revision: None,
                revision: Revision(0),
                provider_runtime_id: None,
                wake_target_id: Some(format!("wake-{index}")),
                failure_reason: None,
                created_at_micros: TimestampMicros(1),
                updated_at_micros: TimestampMicros(1),
            })
            .collect(),
        ..synchronized(1)
    };
    let error = super::evaluate_provisioning(
        "provisioning_bounds",
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(2),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 1,
            binding_required: false,
            bindings: Vec::new(),
            new_request_seed: None,
            terminal_request_retention: 1,
        }),
        oversized_requests,
    )
    .expect_err("oversized request history");
    assert_eq!(error.code, ErrorCode::ProvisioningInvalidSnapshot);
}

proptest! {
    #[test]
    fn synchronization_never_accepts_spawn_above_capacity(
        desired in 1_u64..32,
        spawn in 0_u64..32,
    ) {
        let result = super::evaluate_provisioning(
            "provisioning_property",
            ProvisioningCommand::SynchronizeDemand(SynchronizeDemandCommand {
                project_id: "project-a".to_owned(),
                desired_capacity: desired,
                spawn_needed: spawn,
                request_seeds: (0..spawn.min(desired).max(1)).map(|index| ProvisioningRequestSeed {
                    request_id: format!("request-{index}"),
                    wake_target_id: format!("wake-{index}"),
                }).collect(),
                now_micros: TimestampMicros(1),
                terminal_request_retention: 128,
            }),
            empty_snapshot(),
        );
        if spawn <= desired {
            prop_assert!(result.is_ok());
        } else {
            prop_assert_eq!(result.expect_err("invalid capacity").code, ErrorCode::ProvisioningInvalidCommand);
        }
    }
}

#[test]
fn duplicate_failure_replay_is_idempotent_after_admission_lease_is_cleared() {
    let command = RecordFailureCommand {
        request_id: "request-a".to_owned(),
        admission_revision: Revision(1),
        reason: "runtime_open_failed".to_owned(),
        rate_limited: false,
        now_micros: TimestampMicros(30),
        minimum_admission_interval_micros: 12,
        rate_limit_backoff_micros: vec![30],
        terminal_request_retention: 128,
    };
    let failed = evaluate(
        ProvisioningCommand::RecordFailure(command.clone()),
        admitted(synchronized(10), 20),
    );
    let replay = evaluate(
        ProvisioningCommand::RecordFailure(command),
        failed.snapshot.clone(),
    );
    assert_eq!(replay.outcome, failed.outcome);
    assert_eq!(replay.snapshot, failed.snapshot);
}

#[test]
fn rate_limit_backoff_is_bounded_and_resets_only_after_registration() {
    let first = evaluate(
        ProvisioningCommand::RecordFailure(RecordFailureCommand {
            request_id: "request-a".to_owned(),
            admission_revision: Revision(1),
            reason: "rate_limit".to_owned(),
            rate_limited: true,
            now_micros: TimestampMicros(30),
            minimum_admission_interval_micros: 1,
            rate_limit_backoff_micros: vec![30, 60, 120],
            terminal_request_retention: 128,
        }),
        admitted(synchronized(10), 20),
    );
    assert_eq!(first.snapshot.admission.backoff_attempt, 1);
    assert_eq!(
        first.snapshot.admission.backoff_until_micros,
        Some(TimestampMicros(60))
    );
    let noop = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(59),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: false,
            bindings: Vec::new(),
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        first.snapshot,
    );
    assert_eq!(noop.outcome, ProvisioningOutcome::Noop);
}

#[test]
fn zero_capacity_cancels_queued_reservations_but_not_inflight_runtime() {
    let admitted_state = admitted(synchronized(10), 20);
    let expanded = evaluate(
        ProvisioningCommand::SynchronizeDemand(SynchronizeDemandCommand {
            project_id: "project-a".to_owned(),
            desired_capacity: 2,
            spawn_needed: 2,
            request_seeds: vec![ProvisioningRequestSeed {
                request_id: "request-b".to_owned(),
                wake_target_id: "wake-b".to_owned(),
            }],
            now_micros: TimestampMicros(21),
            terminal_request_retention: 128,
        }),
        admitted_state,
    )
    .snapshot;
    let reduced = evaluate(
        ProvisioningCommand::ApplyCapacityReservation(ApplyCapacityReservationCommand {
            project_id: "project-a".to_owned(),
            desired_capacity: 0,
            capacity_deficit: 0,
            spawn_needed: 0,
            project_pending_snapshot: 2,
            global_headroom: 0,
            global_pending_snapshot: 2,
            request_seeds: Vec::new(),
            now_micros: TimestampMicros(22),
            terminal_request_retention: 128,
        }),
        expanded,
    );
    assert_eq!(
        reduced.snapshot.requests[0].status,
        ProvisioningRequestStatus::OpeningProject
    );
    assert_eq!(
        reduced.snapshot.requests[1].status,
        ProvisioningRequestStatus::Cancelled
    );
}

#[test]
fn registration_and_cancellation_do_not_underflow_concurrently_consumed_demand() {
    let mut registration_state = admitted(synchronized(10), 20);
    registration_state.demands[0].spawn_needed = 0;
    let registered = active(registration_state, 21);
    assert_eq!(registered.demands[0].spawn_needed, 0);

    let mut cancellation_state = admitted(synchronized(30), 40);
    cancellation_state.demands[0].spawn_needed = 0;
    let cancelled = evaluate(
        ProvisioningCommand::CancelRequest(CancelRequestCommand {
            request_id: "request-a".to_owned(),
            admission_revision: Some(Revision(1)),
            now_micros: TimestampMicros(41),
            terminal_request_retention: 128,
        }),
        cancellation_state,
    );
    assert_eq!(cancelled.snapshot.demands[0].spawn_needed, 0);
}

#[test]
fn bootstrap_replay_time_is_allowed_once_then_monotonic_time_is_enforced() {
    let mut bootstrap = empty_snapshot();
    bootstrap.updated_at_micros = TimestampMicros(1_000);
    let first = evaluate(
        ProvisioningCommand::SynchronizeDemand(SynchronizeDemandCommand {
            project_id: "project-a".to_owned(),
            desired_capacity: 0,
            spawn_needed: 0,
            request_seeds: Vec::new(),
            now_micros: TimestampMicros(10),
            terminal_request_retention: 128,
        }),
        bootstrap,
    );
    let error = super::evaluate_provisioning(
        "provisioning_test",
        ProvisioningCommand::SynchronizeDemand(SynchronizeDemandCommand {
            project_id: "project-a".to_owned(),
            desired_capacity: 1,
            spawn_needed: 0,
            request_seeds: Vec::new(),
            now_micros: TimestampMicros(9),
            terminal_request_retention: 128,
        }),
        first.snapshot,
    )
    .expect_err("monotonic time");
    assert_eq!(error.code, ErrorCode::ProvisioningArithmeticOverflow);
}

#[test]
fn matching_blocked_provider_binding_excludes_automatic_admission() {
    let binding = supported_binding("project-a");
    let admitted_state = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(20),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: true,
            bindings: vec![binding.clone()],
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        synchronized(10),
    )
    .snapshot;
    let blocked = evaluate(
        ProvisioningCommand::RecordFailure(RecordFailureCommand {
            request_id: "request-a".to_owned(),
            admission_revision: Revision(1),
            reason: "runtime_unavailable".to_owned(),
            rate_limited: false,
            now_micros: TimestampMicros(30),
            minimum_admission_interval_micros: 1,
            rate_limit_backoff_micros: vec![1],
            terminal_request_retention: 128,
        }),
        admitted_state,
    )
    .snapshot;
    let next = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(40),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: true,
            bindings: vec![binding],
            new_request_seed: Some(ProvisioningRequestSeed {
                request_id: "request-b".to_owned(),
                wake_target_id: "wake-b".to_owned(),
            }),
            terminal_request_retention: 128,
        }),
        blocked,
    );
    assert_eq!(next.outcome, ProvisioningOutcome::Noop);
}

#[test]
fn retirement_batch_accepts_existing_tombstones_and_replays_without_change() {
    let active_state = active(admitted(synchronized(10), 20), 30);
    let retired = evaluate(
        ProvisioningCommand::RetireRuntimeOwnershipBatch(RetireRuntimeOwnershipBatchCommand {
            project_id: "project-a".to_owned(),
            wake_target_ids: vec!["wake-a".to_owned()],
            now_micros: TimestampMicros(31),
            terminal_request_retention: 128,
        }),
        active_state,
    );
    assert_eq!(
        retired.outcome,
        ProvisioningOutcome::BatchRetired {
            request_ids: vec!["request-a".to_owned()],
            changed: true,
        }
    );
    let replay = evaluate(
        ProvisioningCommand::RetireRuntimeOwnershipBatch(RetireRuntimeOwnershipBatchCommand {
            project_id: "project-a".to_owned(),
            wake_target_ids: vec!["wake-a".to_owned()],
            now_micros: TimestampMicros(32),
            terminal_request_retention: 128,
        }),
        retired.snapshot,
    );
    assert!(matches!(
        replay.outcome,
        ProvisioningOutcome::BatchRetired { changed: false, .. }
    ));
}

#[test]
fn cancellation_result_is_protected_from_terminal_pruning() {
    let mut state = synchronized(10);
    state
        .requests
        .extend((0..2).map(|index| ProvisioningRequest {
            schema_version: SCHEMA_VERSION,
            request_id: format!("old-{index}"),
            project_id: "project-a".to_owned(),
            provider_binding: None,
            status: ProvisioningRequestStatus::Cancelled,
            admission_revision: None,
            revision: Revision(1),
            provider_runtime_id: None,
            wake_target_id: Some(format!("old-wake-{index}")),
            failure_reason: Some("old".to_owned()),
            created_at_micros: TimestampMicros(1),
            updated_at_micros: TimestampMicros(1),
        }));
    let cancelled = evaluate(
        ProvisioningCommand::CancelRequest(CancelRequestCommand {
            request_id: "request-a".to_owned(),
            admission_revision: None,
            now_micros: TimestampMicros(11),
            terminal_request_retention: 1,
        }),
        state,
    );
    assert!(
        cancelled
            .snapshot
            .requests
            .iter()
            .any(|request| request.request_id == "request-a")
    );
}

#[test]
fn snapshot_rejects_orphans_bad_inflight_and_cross_project_binding() {
    let mut orphan = empty_snapshot();
    orphan.updated_at_micros = TimestampMicros(1);
    orphan.requests.push(ProvisioningRequest {
        schema_version: SCHEMA_VERSION,
        request_id: "request-a".to_owned(),
        project_id: "missing-project".to_owned(),
        provider_binding: None,
        status: ProvisioningRequestStatus::WaitingAdmission,
        admission_revision: None,
        revision: Revision(0),
        provider_runtime_id: None,
        wake_target_id: Some("wake-a".to_owned()),
        failure_reason: None,
        created_at_micros: TimestampMicros(1),
        updated_at_micros: TimestampMicros(1),
    });
    let error = super::evaluate_provisioning(
        "provisioning_test",
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(2),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 1,
            binding_required: false,
            bindings: Vec::new(),
            new_request_seed: None,
            terminal_request_retention: 1,
        }),
        orphan,
    )
    .expect_err("orphan");
    assert_eq!(error.code, ErrorCode::ProvisioningInvalidSnapshot);

    let mut cross_binding = admitted(synchronized(10), 20);
    cross_binding.requests[0].provider_binding = Some(ProviderBindingObservation {
        project_id: "project-b".to_owned(),
        ..supported_binding("project-a")
    });
    let error = super::evaluate_provisioning(
        "provisioning_test",
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(21),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 1,
            binding_required: false,
            bindings: Vec::new(),
            new_request_seed: None,
            terminal_request_retention: 1,
        }),
        cross_binding,
    )
    .expect_err("cross project binding");
    assert_eq!(error.code, ErrorCode::ProvisioningInvalidSnapshot);
}

#[test]
fn command_bounds_cover_seed_collections_fingerprints_and_backoff_configuration() {
    let oversized_seeds = (0..=MAX_PROVISIONING_REQUEST_SEEDS)
        .map(|index| ProvisioningRequestSeed {
            request_id: format!("request-{index}"),
            wake_target_id: format!("wake-{index}"),
        })
        .collect();
    let error = super::evaluate_provisioning(
        "provisioning_bounds",
        ProvisioningCommand::SynchronizeDemand(SynchronizeDemandCommand {
            project_id: "project-a".to_owned(),
            desired_capacity: 1,
            spawn_needed: 1,
            request_seeds: oversized_seeds,
            now_micros: TimestampMicros(2),
            terminal_request_retention: 1,
        }),
        empty_snapshot(),
    )
    .expect_err("seed bound");
    assert_eq!(error.code, ErrorCode::ProvisioningInvalidCommand);

    let error = super::evaluate_provisioning(
        "provisioning_bounds",
        ProvisioningCommand::RecordFailure(RecordFailureCommand {
            request_id: "request-a".to_owned(),
            admission_revision: Revision(1),
            reason: "rate_limit".to_owned(),
            rate_limited: true,
            now_micros: TimestampMicros(30),
            minimum_admission_interval_micros: 1,
            rate_limit_backoff_micros: Vec::new(),
            terminal_request_retention: 1,
        }),
        admitted(synchronized(10), 20),
    )
    .expect_err("empty backoff");
    assert_eq!(error.code, ErrorCode::ProvisioningInvalidCommand);
}

#[test]
fn deferred_failure_reenters_admission_with_a_new_fence() {
    let deferred = evaluate(
        ProvisioningCommand::RecordFailure(RecordFailureCommand {
            request_id: "request-a".to_owned(),
            admission_revision: Revision(1),
            reason: "browser_open_cooldown".to_owned(),
            rate_limited: false,
            now_micros: TimestampMicros(30),
            minimum_admission_interval_micros: 1,
            rate_limit_backoff_micros: vec![30],
            terminal_request_retention: 128,
        }),
        admitted(synchronized(10), 20),
    );
    assert_eq!(
        deferred.snapshot.requests[0].status,
        ProvisioningRequestStatus::Deferred
    );
    let reopened = evaluate(
        ProvisioningCommand::AdmitNext(AdmitNextCommand {
            now_micros: TimestampMicros(40),
            minimum_admission_interval_micros: 0,
            admission_lease_micros: 10,
            binding_required: false,
            bindings: Vec::new(),
            new_request_seed: None,
            terminal_request_retention: 128,
        }),
        deferred.snapshot,
    );
    assert_eq!(
        reopened.snapshot.requests[0].status,
        ProvisioningRequestStatus::OpeningProject
    );
    assert_eq!(
        reopened.snapshot.requests[0].admission_revision,
        Some(Revision(3))
    );
}
