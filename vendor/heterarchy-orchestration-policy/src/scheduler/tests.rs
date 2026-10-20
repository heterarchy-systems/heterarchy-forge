//! Scheduler policy regression and generative tests.

use crate::{ErrorCode, Revision, TimestampMicros};

use super::{
    ClaimValidationSnapshot, EvaluateFrontierCommand, ExternalClaimIdentity, FrontierSnapshot,
    PlanClaimAttemptCommand, RequestedParallelism, SchedulerBrokerTask, SchedulerBrokerTaskStatus,
    SchedulerCommand, SchedulerDecision, SchedulerRun, SchedulerRunStatus, SchedulerSnapshot,
    ValidateExternalClaimCommand, evaluate_scheduler,
};

fn run(
    run_id: &str,
    project_id: &str,
    status: SchedulerRunStatus,
    requested_parallelism: u32,
) -> SchedulerRun {
    SchedulerRun {
        run_id: run_id.to_owned(),
        project_id: project_id.to_owned(),
        status,
        requested_parallelism: RequestedParallelism(requested_parallelism),
    }
}

fn task(
    broker_task_id: &str,
    run_id: &str,
    project_id: &str,
    depends_on: &[&str],
    status: SchedulerBrokerTaskStatus,
    external_published: bool,
    created_at_micros: u64,
) -> SchedulerBrokerTask {
    SchedulerBrokerTask {
        broker_task_id: broker_task_id.to_owned(),
        run_id: run_id.to_owned(),
        project_id: project_id.to_owned(),
        objective: format!("objective-{broker_task_id}"),
        role: None,
        depends_on: depends_on
            .iter()
            .map(|dependency| (*dependency).to_owned())
            .collect(),
        status,
        external_published,
        created_at_micros: TimestampMicros(created_at_micros),
        revision: crate::Revision(0),
    }
}

fn evaluate_frontier(snapshot: FrontierSnapshot) -> Result<SchedulerDecision, crate::DomainError> {
    evaluate_scheduler(
        "scheduler_test",
        SchedulerCommand::EvaluateFrontier(EvaluateFrontierCommand {}),
        SchedulerSnapshot::Frontier(snapshot),
    )
}

fn plan_claim(
    project_id: &str,
    run_id: Option<&str>,
    snapshot: FrontierSnapshot,
) -> Result<SchedulerDecision, crate::DomainError> {
    evaluate_scheduler(
        "scheduler_test",
        SchedulerCommand::PlanClaimAttempt(PlanClaimAttemptCommand {
            project_id: project_id.to_owned(),
            run_id: run_id.map(str::to_owned),
        }),
        SchedulerSnapshot::Frontier(snapshot),
    )
}

fn claim_task(
    broker_task_id: &str,
    run_id: &str,
    depends_on: &[&str],
    status: SchedulerBrokerTaskStatus,
    external_published: bool,
    created_at_micros: u64,
) -> SchedulerBrokerTask {
    let mut value = task(
        broker_task_id,
        run_id,
        "project-a",
        depends_on,
        status,
        external_published,
        created_at_micros,
    );
    value.role = Some("executor".to_owned());
    value.revision = Revision(created_at_micros + 20);
    value
}

fn valid_claim() -> ExternalClaimIdentity {
    ExternalClaimIdentity {
        broker_task_id: "task-a".to_owned(),
        run_id: "run-a".to_owned(),
        project_id: "project-a".to_owned(),
        objective: "objective-task-a".to_owned(),
        role: Some("executor".to_owned()),
        expected_task_revision: Revision(21),
        term: 7,
        generation: 3,
        lease_id: "lease-a".to_owned(),
        lease_epoch: 11,
        lease_expires_at_ms: 99_000,
    }
}

fn valid_claim_snapshot() -> ClaimValidationSnapshot {
    ClaimValidationSnapshot {
        project_id: "project-a".to_owned(),
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
        broker_tasks: vec![claim_task(
            "task-a",
            "run-a",
            &[],
            SchedulerBrokerTaskStatus::Queued,
            true,
            1,
        )],
    }
}

fn validate_claim(
    claim: ExternalClaimIdentity,
    snapshot: ClaimValidationSnapshot,
) -> Result<SchedulerDecision, crate::DomainError> {
    evaluate_scheduler(
        "scheduler_test",
        SchedulerCommand::ValidateExternalClaim(ValidateExternalClaimCommand { claim }),
        SchedulerSnapshot::ClaimValidation(snapshot),
    )
}

#[test]
fn frontier_filters_inactive_runs_and_returns_stable_ready_and_aggregate_order() {
    let decision = evaluate_frontier(FrontierSnapshot {
        runs: vec![
            run("run-z", "project-z", SchedulerRunStatus::Active, 4),
            run("run-a", "project-a", SchedulerRunStatus::Active, 2),
            run(
                "run-inactive",
                "project-a",
                SchedulerRunStatus::Cancelled,
                32,
            ),
        ],
        broker_tasks: vec![
            task(
                "a-dependency",
                "run-a",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Completed,
                true,
                1,
            ),
            task(
                "a-published-ready",
                "run-a",
                "project-a",
                &["a-dependency"],
                SchedulerBrokerTaskStatus::Queued,
                true,
                20,
            ),
            task(
                "z-ready",
                "run-z",
                "project-z",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                15,
            ),
            task(
                "a-unpublished-ready",
                "run-a",
                "project-a",
                &["a-dependency"],
                SchedulerBrokerTaskStatus::Queued,
                false,
                10,
            ),
            task(
                "a-claimed",
                "run-a",
                "project-a",
                &["a-dependency"],
                SchedulerBrokerTaskStatus::Claimed,
                true,
                5,
            ),
            task(
                "inactive-ready",
                "run-inactive",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                2,
            ),
        ],
    })
    .expect("valid frontier must evaluate");
    let SchedulerDecision::Frontier(frontier) = decision else {
        panic!("frontier command must return a frontier decision");
    };

    assert_eq!(
        frontier.ready_task_ids,
        vec!["a-unpublished-ready", "z-ready", "a-published-ready"]
    );
    assert_eq!(
        frontier.publishable_task_ids,
        vec!["a-unpublished-ready", "z-ready"]
    );
    assert_eq!(frontier.ready_project_ids, vec!["project-a", "project-z"]);
    assert_eq!(frontier.run_aggregates.len(), 2);
    assert_eq!(frontier.run_aggregates[0].run_id, "run-a");
    assert_eq!(frontier.run_aggregates[0].ready_task_count, 2);
    assert_eq!(frontier.run_aggregates[0].claimed_task_count, 1);
    assert_eq!(frontier.run_aggregates[0].requested_parallelism, 2);
    assert_eq!(frontier.run_aggregates[0].engaged_task_count, 2);
    assert_eq!(frontier.run_aggregates[1].run_id, "run-z");
    assert_eq!(frontier.run_aggregates[1].engaged_task_count, 1);
    assert_eq!(frontier.project_aggregates.len(), 2);
    assert_eq!(frontier.project_aggregates[0].project_id, "project-a");
    assert_eq!(frontier.project_aggregates[0].requested_parallelism, 2);
    assert_eq!(frontier.project_aggregates[0].engaged_task_count, 2);
    assert_eq!(frontier.project_aggregates[1].project_id, "project-z");
}

#[test]
fn frontier_rejects_duplicate_unknown_and_cross_run_observations() {
    let duplicate_run = evaluate_frontier(FrontierSnapshot {
        runs: vec![
            run("run-a", "project-a", SchedulerRunStatus::Active, 1),
            run("run-a", "project-a", SchedulerRunStatus::Active, 1),
        ],
        broker_tasks: Vec::new(),
    })
    .expect_err("duplicate Run ids must be rejected");
    assert_eq!(duplicate_run.code, ErrorCode::SchedulerDuplicateRunId);

    let duplicate_task = evaluate_frontier(FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
        broker_tasks: vec![
            task(
                "task-a",
                "run-a",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                1,
            ),
            task(
                "task-a",
                "run-a",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                2,
            ),
        ],
    })
    .expect_err("duplicate Broker task ids must be rejected");
    assert_eq!(duplicate_task.code, ErrorCode::SchedulerDuplicateTaskId);

    let unknown_dependency = evaluate_frontier(FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
        broker_tasks: vec![task(
            "task-a",
            "run-a",
            "project-a",
            &["missing"],
            SchedulerBrokerTaskStatus::Queued,
            false,
            1,
        )],
    })
    .expect_err("unknown dependency must be rejected");
    assert_eq!(
        unknown_dependency.code,
        ErrorCode::SchedulerUnknownDependency
    );

    let cross_run_dependency = evaluate_frontier(FrontierSnapshot {
        runs: vec![
            run("run-a", "project-a", SchedulerRunStatus::Active, 1),
            run("run-b", "project-a", SchedulerRunStatus::Active, 1),
        ],
        broker_tasks: vec![
            task(
                "task-a",
                "run-a",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Completed,
                true,
                1,
            ),
            task(
                "task-b",
                "run-b",
                "project-a",
                &["task-a"],
                SchedulerBrokerTaskStatus::Queued,
                false,
                2,
            ),
        ],
    })
    .expect_err("cross-Run dependency must be rejected");
    assert_eq!(
        cross_run_dependency.code,
        ErrorCode::SchedulerCrossRunDependency
    );
}

#[test]
fn frontier_rejects_task_project_mismatch() {
    let error = evaluate_frontier(FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
        broker_tasks: vec![task(
            "task-a",
            "run-a",
            "project-b",
            &[],
            SchedulerBrokerTaskStatus::Queued,
            false,
            1,
        )],
    })
    .expect_err("task project must match the owning Run");
    assert_eq!(error.code, ErrorCode::SchedulerInvalidSnapshot);
}

#[test]
fn frontier_matches_claimed_and_inactive_history_projection_semantics() {
    let decision = evaluate_frontier(FrontierSnapshot {
        runs: vec![
            run("run-active", "project-a", SchedulerRunStatus::Active, 2),
            run(
                "run-complete",
                "project-a",
                SchedulerRunStatus::Completed,
                0,
            ),
        ],
        broker_tasks: vec![
            task(
                "dependency",
                "run-active",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                1,
            ),
            task(
                "claimed",
                "run-active",
                "project-a",
                &["dependency"],
                SchedulerBrokerTaskStatus::Claimed,
                false,
                2,
            ),
            task(
                "inactive-history",
                "run-complete",
                "project-a",
                &["missing-history-dependency"],
                SchedulerBrokerTaskStatus::Claimed,
                false,
                3,
            ),
        ],
    })
    .expect("claimed work and inactive history match the durable projection");
    let SchedulerDecision::Frontier(frontier) = decision else {
        panic!("frontier command must return a frontier decision");
    };
    assert_eq!(frontier.run_aggregates.len(), 1);
    assert_eq!(frontier.run_aggregates[0].claimed_task_count, 1);
    assert_eq!(frontier.run_aggregates[0].ready_task_count, 1);
    assert_eq!(frontier.run_aggregates[0].engaged_task_count, 2);
}

#[test]
fn frontier_ties_break_by_task_id_not_input_order() {
    let decision = evaluate_frontier(FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 2)],
        broker_tasks: vec![
            task(
                "task-z",
                "run-a",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                10,
            ),
            task(
                "task-a",
                "run-a",
                "project-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                10,
            ),
        ],
    })
    .expect("tie snapshot must evaluate");
    let SchedulerDecision::Frontier(frontier) = decision else {
        panic!("frontier command must return a frontier decision");
    };
    assert_eq!(frontier.ready_task_ids, vec!["task-a", "task-z"]);
    assert_eq!(frontier.publishable_task_ids, vec!["task-a", "task-z"]);
}

#[test]
fn frontier_rejects_invalid_parallelism_and_preserves_replay_determinism() {
    let invalid_parallelism = evaluate_frontier(FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 0)],
        broker_tasks: Vec::new(),
    })
    .expect_err("zero parallelism must be rejected");
    assert_eq!(
        invalid_parallelism.code,
        ErrorCode::SchedulerInvalidParallelism
    );

    let unbounded_parallelism = evaluate_frontier(FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 33)],
        broker_tasks: Vec::new(),
    })
    .expect_err("parallelism above the public bound must be rejected");
    assert_eq!(
        unbounded_parallelism.code,
        ErrorCode::SchedulerInvalidParallelism
    );

    let snapshot = FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
        broker_tasks: vec![task(
            "task-a",
            "run-a",
            "project-a",
            &[],
            SchedulerBrokerTaskStatus::Queued,
            false,
            1,
        )],
    };
    assert_eq!(
        evaluate_frontier(snapshot.clone()).expect("first evaluation"),
        evaluate_frontier(snapshot).expect("replay evaluation")
    );
}

#[test]
fn claim_plan_returns_none_when_no_task_is_eligible() {
    let SchedulerDecision::ClaimAttempt(decision) = plan_claim(
        "project-a",
        None,
        FrontierSnapshot {
            runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
            broker_tasks: vec![claim_task(
                "task-a",
                "run-a",
                &[],
                SchedulerBrokerTaskStatus::Completed,
                true,
                1,
            )],
        },
    )
    .expect("empty claim plan must be valid") else {
        panic!("claim command must return a claim-attempt decision");
    };
    assert!(decision.candidate.is_none());
}

#[test]
fn claim_plan_selects_oldest_published_ready_task() {
    let SchedulerDecision::ClaimAttempt(decision) = plan_claim(
        "project-a",
        None,
        FrontierSnapshot {
            runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 2)],
            broker_tasks: vec![
                claim_task(
                    "newer",
                    "run-a",
                    &[],
                    SchedulerBrokerTaskStatus::Queued,
                    true,
                    2,
                ),
                claim_task(
                    "oldest",
                    "run-a",
                    &[],
                    SchedulerBrokerTaskStatus::Queued,
                    true,
                    1,
                ),
            ],
        },
    )
    .expect("ready claim candidate must be selected") else {
        panic!("claim command must return a claim-attempt decision");
    };
    assert_eq!(
        decision
            .candidate
            .expect("candidate must exist")
            .broker_task_id,
        "oldest"
    );
}

#[test]
fn claim_plan_honors_exact_run_restriction() {
    let SchedulerDecision::ClaimAttempt(decision) = plan_claim(
        "project-a",
        Some("run-b"),
        FrontierSnapshot {
            runs: vec![
                run("run-a", "project-a", SchedulerRunStatus::Active, 1),
                run("run-b", "project-a", SchedulerRunStatus::Active, 1),
            ],
            broker_tasks: vec![
                claim_task(
                    "older-other-run",
                    "run-a",
                    &[],
                    SchedulerBrokerTaskStatus::Queued,
                    true,
                    1,
                ),
                claim_task(
                    "restricted-run",
                    "run-b",
                    &[],
                    SchedulerBrokerTaskStatus::Queued,
                    true,
                    2,
                ),
            ],
        },
    )
    .expect("run-restricted claim plan must evaluate") else {
        panic!("claim command must return a claim-attempt decision");
    };
    assert_eq!(
        decision
            .candidate
            .expect("candidate must exist")
            .broker_task_id,
        "restricted-run"
    );
}

#[test]
fn claim_plan_excludes_unpublished_tasks() {
    let SchedulerDecision::ClaimAttempt(decision) = plan_claim(
        "project-a",
        None,
        FrontierSnapshot {
            runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
            broker_tasks: vec![claim_task(
                "unpublished",
                "run-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                false,
                1,
            )],
        },
    )
    .expect("unpublished work must be ignored") else {
        panic!("claim command must return a claim-attempt decision");
    };
    assert!(decision.candidate.is_none());
}

#[test]
fn claim_plan_excludes_tasks_with_incomplete_dependencies() {
    let SchedulerDecision::ClaimAttempt(decision) = plan_claim(
        "project-a",
        None,
        FrontierSnapshot {
            runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 1)],
            broker_tasks: vec![
                claim_task(
                    "dependency",
                    "run-a",
                    &[],
                    SchedulerBrokerTaskStatus::Queued,
                    true,
                    2,
                ),
                claim_task(
                    "dependent",
                    "run-a",
                    &["dependency"],
                    SchedulerBrokerTaskStatus::Queued,
                    true,
                    1,
                ),
            ],
        },
    )
    .expect("blocked dependency is a valid claim snapshot") else {
        panic!("claim command must return a claim-attempt decision");
    };
    assert_eq!(
        decision
            .candidate
            .expect("candidate must exist")
            .broker_task_id,
        "dependency"
    );
}

#[test]
fn external_claim_returns_fenced_assignment_intent() {
    let SchedulerDecision::ExternalClaim(decision) =
        validate_claim(valid_claim(), valid_claim_snapshot()).expect("valid claim must pass")
    else {
        panic!("claim validation must return an external-claim decision");
    };
    assert_eq!(decision.assignment.broker_task_id, "task-a");
    assert_eq!(decision.assignment.task_revision, Revision(21));
    assert_eq!(decision.assignment.term, 7);
    assert_eq!(decision.assignment.generation, 3);
    assert_eq!(decision.assignment.lease_id, "lease-a");
    assert_eq!(decision.assignment.lease_epoch, 11);
    assert_eq!(decision.assignment.lease_expires_at_ms, 99_000);
}

#[test]
fn external_claim_rejects_project_mismatch() {
    let mut snapshot = valid_claim_snapshot();
    snapshot.project_id = "project-b".to_owned();
    let error = validate_claim(valid_claim(), snapshot).expect_err("project mismatch must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimMismatch);
}

#[test]
fn external_claim_rejects_run_mismatch() {
    let mut claim = valid_claim();
    claim.run_id = "run-b".to_owned();
    let error = validate_claim(claim, valid_claim_snapshot()).expect_err("unknown Run must fail");
    assert_eq!(error.code, ErrorCode::SchedulerUnknownRun);
}

#[test]
fn external_claim_rejects_inactive_run() {
    let mut snapshot = valid_claim_snapshot();
    snapshot.runs[0].status = SchedulerRunStatus::Completed;
    let error = validate_claim(valid_claim(), snapshot).expect_err("inactive Run must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimMismatch);
}

#[test]
fn external_claim_rejects_unknown_task() {
    let mut claim = valid_claim();
    claim.broker_task_id = "missing-task".to_owned();
    let error = validate_claim(claim, valid_claim_snapshot()).expect_err("unknown task must fail");
    assert_eq!(error.code, ErrorCode::SchedulerUnknownTask);
}

#[test]
fn external_claim_rejects_task_run_mismatch() {
    let mut snapshot = valid_claim_snapshot();
    snapshot
        .runs
        .push(run("run-b", "project-a", SchedulerRunStatus::Active, 1));
    snapshot.broker_tasks[0].run_id = "run-b".to_owned();
    let error = validate_claim(valid_claim(), snapshot).expect_err("task Run mismatch must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimMismatch);
}

#[test]
fn external_claim_rejects_task_scope_mismatch() {
    let mut snapshot = valid_claim_snapshot();
    snapshot.broker_tasks[0].project_id = "project-b".to_owned();
    let error =
        validate_claim(valid_claim(), snapshot).expect_err("task project mismatch must fail");
    assert_eq!(error.code, ErrorCode::SchedulerInvalidSnapshot);
}

#[test]
fn external_claim_rejects_objective_mismatch() {
    let claim = ExternalClaimIdentity {
        objective: "different".to_owned(),
        ..valid_claim()
    };
    let error =
        validate_claim(claim, valid_claim_snapshot()).expect_err("objective mismatch must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimMismatch);
}

#[test]
fn external_claim_rejects_role_mismatch() {
    let claim = ExternalClaimIdentity {
        role: Some("reviewer".to_owned()),
        ..valid_claim()
    };
    let error = validate_claim(claim, valid_claim_snapshot()).expect_err("role mismatch must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimMismatch);
}

#[test]
fn external_claim_rejects_unready_task_status() {
    let mut snapshot = valid_claim_snapshot();
    snapshot.broker_tasks[0].status = SchedulerBrokerTaskStatus::Claimed;
    let error = validate_claim(valid_claim(), snapshot).expect_err("claimed task must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimNotReady);
}

#[test]
fn external_claim_rejects_unpublished_task() {
    let mut snapshot = valid_claim_snapshot();
    snapshot.broker_tasks[0].external_published = false;
    let error = validate_claim(valid_claim(), snapshot).expect_err("unpublished task must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimNotReady);
}

#[test]
fn external_claim_rejects_incomplete_dependencies() {
    let mut snapshot = valid_claim_snapshot();
    snapshot.broker_tasks.insert(
        0,
        claim_task(
            "dependency",
            "run-a",
            &[],
            SchedulerBrokerTaskStatus::Queued,
            true,
            0,
        ),
    );
    snapshot.broker_tasks[1].depends_on = vec!["dependency".to_owned()];
    let error =
        validate_claim(valid_claim(), snapshot).expect_err("incomplete dependency must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimNotReady);
}

#[test]
fn external_claim_rejects_stale_task_revision_fence() {
    let mut claim = valid_claim();
    claim.expected_task_revision = Revision(20);
    let error = validate_claim(claim, valid_claim_snapshot()).expect_err("stale fence must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimFenceMismatch);
    assert_eq!(error.current_revision, Some(Revision(21)));
}

#[test]
fn external_claim_rejects_zero_term_fence() {
    let claim = ExternalClaimIdentity {
        term: 0,
        ..valid_claim()
    };
    let error =
        validate_claim(claim, valid_claim_snapshot()).expect_err("zero term fence must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimFenceMismatch);
}

#[test]
fn external_claim_rejects_zero_generation_fence() {
    let claim = ExternalClaimIdentity {
        generation: 0,
        ..valid_claim()
    };
    let error =
        validate_claim(claim, valid_claim_snapshot()).expect_err("zero generation fence must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimFenceMismatch);
}

#[test]
fn external_claim_rejects_empty_lease_identity_fence() {
    let claim = ExternalClaimIdentity {
        lease_id: String::new(),
        ..valid_claim()
    };
    let error = validate_claim(claim, valid_claim_snapshot())
        .expect_err("empty lease identity fence must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimFenceMismatch);
}

#[test]
fn external_claim_rejects_zero_lease_epoch_fence() {
    let claim = ExternalClaimIdentity {
        lease_epoch: 0,
        ..valid_claim()
    };
    let error = validate_claim(claim, valid_claim_snapshot())
        .expect_err("zero lease epoch fence must fail");
    assert_eq!(error.code, ErrorCode::SchedulerClaimFenceMismatch);
}

#[test]
fn claim_replay_is_deterministic_across_input_order() {
    let snapshot = FrontierSnapshot {
        runs: vec![run("run-a", "project-a", SchedulerRunStatus::Active, 2)],
        broker_tasks: vec![
            claim_task(
                "task-b",
                "run-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                true,
                1,
            ),
            claim_task(
                "task-a",
                "run-a",
                &[],
                SchedulerBrokerTaskStatus::Queued,
                true,
                1,
            ),
        ],
    };
    let mut reordered = snapshot.clone();
    reordered.broker_tasks.reverse();
    assert_eq!(
        plan_claim("project-a", None, snapshot).expect("first plan"),
        plan_claim("project-a", None, reordered).expect("reordered replay plan")
    );
}

#[test]
fn external_claim_validation_replay_is_deterministic() {
    assert_eq!(
        validate_claim(valid_claim(), valid_claim_snapshot()).expect("first validation"),
        validate_claim(valid_claim(), valid_claim_snapshot()).expect("replay validation")
    );
}
