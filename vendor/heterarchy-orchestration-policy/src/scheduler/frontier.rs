//! Pure deterministic runnable-frontier calculation.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{DomainError, ErrorCode};

use super::types::{
    FrontierDecision, FrontierSnapshot, ProjectFrontierAggregate, RunFrontierAggregate,
    SchedulerBrokerTaskStatus,
};
use super::validation::validate_frontier_snapshot;

#[derive(Debug)]
struct MutableRunAggregate {
    project_id: String,
    ready_task_count: u64,
    claimed_task_count: u64,
    requested_parallelism: u64,
}

/// Evaluate local task readiness without claiming, leasing, publishing, or I/O.
pub(super) fn evaluate_frontier(
    operation: &str,
    snapshot: &FrontierSnapshot,
) -> Result<FrontierDecision, DomainError> {
    validate_frontier_snapshot(operation, snapshot)?;

    let runs_by_id = snapshot
        .runs
        .iter()
        .map(|run| (run.run_id.as_str(), run))
        .collect::<HashMap<_, _>>();
    let tasks_by_id = snapshot
        .broker_tasks
        .iter()
        .map(|task| (task.broker_task_id.as_str(), task))
        .collect::<HashMap<_, _>>();
    let mut aggregates = BTreeMap::<(String, String), MutableRunAggregate>::new();
    let mut ready_tasks = Vec::new();
    let mut publishable_tasks = Vec::new();
    let mut ready_project_ids = BTreeSet::new();

    for task in &snapshot.broker_tasks {
        let run = runs_by_id
            .get(task.run_id.as_str())
            .ok_or_else(|| missing_validated_run(operation, &task.run_id))?;
        if !run.status.contributes_capacity() {
            continue;
        }
        match task.status {
            SchedulerBrokerTaskStatus::Claimed => {
                let aggregate = aggregate_for_run(&mut aggregates, run);
                aggregate.claimed_task_count = checked_count_add(
                    operation,
                    &task.broker_task_id,
                    aggregate.claimed_task_count,
                    1,
                )?;
            }
            SchedulerBrokerTaskStatus::Queued if dependencies_completed(task, &tasks_by_id) => {
                let aggregate = aggregate_for_run(&mut aggregates, run);
                aggregate.ready_task_count = checked_count_add(
                    operation,
                    &task.broker_task_id,
                    aggregate.ready_task_count,
                    1,
                )?;
                ready_project_ids.insert(run.project_id.clone());
                ready_tasks.push((task.created_at_micros, task.broker_task_id.clone()));
                if !task.external_published {
                    publishable_tasks.push((task.created_at_micros, task.broker_task_id.clone()));
                }
            }
            SchedulerBrokerTaskStatus::Queued
            | SchedulerBrokerTaskStatus::Completed
            | SchedulerBrokerTaskStatus::Failed => {}
        }
    }

    ready_tasks.sort_unstable();
    publishable_tasks.sort_unstable();
    let run_aggregates = into_run_aggregates(operation, aggregates)?;
    let project_aggregates = aggregate_projects(operation, &run_aggregates)?;

    Ok(FrontierDecision {
        ready_task_ids: ready_tasks
            .into_iter()
            .map(|(_created_at, task_id)| task_id)
            .collect(),
        publishable_task_ids: publishable_tasks
            .into_iter()
            .map(|(_created_at, task_id)| task_id)
            .collect(),
        ready_project_ids: ready_project_ids.into_iter().collect(),
        run_aggregates,
        project_aggregates,
    })
}

fn aggregate_for_run<'a>(
    aggregates: &'a mut BTreeMap<(String, String), MutableRunAggregate>,
    run: &super::types::SchedulerRun,
) -> &'a mut MutableRunAggregate {
    let key = (run.project_id.clone(), run.run_id.clone());
    aggregates
        .entry(key)
        .or_insert_with(|| MutableRunAggregate {
            project_id: run.project_id.clone(),
            ready_task_count: 0,
            claimed_task_count: 0,
            requested_parallelism: u64::from(run.requested_parallelism.0),
        })
}

fn dependencies_completed(
    task: &super::types::SchedulerBrokerTask,
    tasks_by_id: &HashMap<&str, &super::types::SchedulerBrokerTask>,
) -> bool {
    task.depends_on.iter().all(|dependency_id| {
        tasks_by_id
            .get(dependency_id.as_str())
            .is_some_and(|dependency| dependency.status == SchedulerBrokerTaskStatus::Completed)
    })
}

fn into_run_aggregates(
    operation: &str,
    aggregates: BTreeMap<(String, String), MutableRunAggregate>,
) -> Result<Vec<RunFrontierAggregate>, DomainError> {
    aggregates
        .into_iter()
        .map(|((_project_id, run_id), aggregate)| {
            let available_task_count = checked_count_add(
                operation,
                &run_id,
                aggregate.ready_task_count,
                aggregate.claimed_task_count,
            )?;
            Ok(RunFrontierAggregate {
                run_id,
                project_id: aggregate.project_id,
                ready_task_count: aggregate.ready_task_count,
                claimed_task_count: aggregate.claimed_task_count,
                requested_parallelism: aggregate.requested_parallelism,
                engaged_task_count: aggregate.requested_parallelism.min(available_task_count),
            })
        })
        .collect()
}

fn aggregate_projects(
    operation: &str,
    run_aggregates: &[RunFrontierAggregate],
) -> Result<Vec<ProjectFrontierAggregate>, DomainError> {
    let mut aggregates = BTreeMap::<String, ProjectFrontierAggregate>::new();
    for run in run_aggregates {
        let project =
            aggregates
                .entry(run.project_id.clone())
                .or_insert_with(|| ProjectFrontierAggregate {
                    project_id: run.project_id.clone(),
                    ready_task_count: 0,
                    claimed_task_count: 0,
                    requested_parallelism: 0,
                    engaged_task_count: 0,
                });
        project.ready_task_count = checked_count_add(
            operation,
            &project.project_id,
            project.ready_task_count,
            run.ready_task_count,
        )?;
        project.claimed_task_count = checked_count_add(
            operation,
            &project.project_id,
            project.claimed_task_count,
            run.claimed_task_count,
        )?;
        project.requested_parallelism = checked_count_add(
            operation,
            &project.project_id,
            project.requested_parallelism,
            run.requested_parallelism,
        )?;
        project.engaged_task_count = checked_count_add(
            operation,
            &project.project_id,
            project.engaged_task_count,
            run.engaged_task_count,
        )?;
    }
    Ok(aggregates.into_values().collect())
}

fn checked_count_add(
    operation: &str,
    resource_id: &str,
    left: u64,
    right: u64,
) -> Result<u64, DomainError> {
    left.checked_add(right).ok_or_else(|| DomainError {
        code: ErrorCode::SchedulerArithmeticOverflow,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: "Scheduler aggregate total exceeds the u64 limit.".to_owned(),
        current_revision: None,
    })
}

fn missing_validated_run(operation: &str, run_id: &str) -> DomainError {
    DomainError {
        code: ErrorCode::SchedulerInvalidSnapshot,
        operation: operation.to_owned(),
        resource_id: run_id.to_owned(),
        message: "Validated scheduler Run is no longer available.".to_owned(),
        current_revision: None,
    }
}
