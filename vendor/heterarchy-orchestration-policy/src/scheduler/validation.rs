//! Validation for durable scheduler snapshots.

use std::collections::{HashMap, HashSet};

use crate::{DomainError, ErrorCode};

use super::types::{
    FrontierSnapshot, MAX_REQUESTED_PARALLELISM, MAX_SCHEDULER_ID_BYTES,
    MAX_SCHEDULER_OBJECTIVE_BYTES, MAX_SCHEDULER_ROLE_BYTES, MAX_SCHEDULER_RUNS,
    MAX_SCHEDULER_TASKS, MAX_TASK_DEPENDENCIES, RequestedParallelism, SchedulerBrokerTask,
    SchedulerBrokerTaskStatus, SchedulerRun,
};

/// Validate a scheduler frontier snapshot before evaluating policy.
pub(super) fn validate_frontier_snapshot(
    operation: &str,
    snapshot: &FrontierSnapshot,
) -> Result<(), DomainError> {
    validate_scheduler_records(operation, &snapshot.runs, &snapshot.broker_tasks)
}

/// Validate one borrowed scheduler record collection without constructing a
/// second snapshot. Claim validation shares this path so the hot claim path
/// does not clone every Run and Broker task merely to reuse frontier checks.
pub(super) fn validate_scheduler_records(
    operation: &str,
    runs: &[SchedulerRun],
    broker_tasks: &[SchedulerBrokerTask],
) -> Result<(), DomainError> {
    validate_collection_bounds(operation, runs, broker_tasks)?;
    validate_run_ids(operation, runs)?;
    validate_requested_parallelism(operation, runs)?;
    validate_task_ids(operation, broker_tasks)?;

    let runs_by_id = runs
        .iter()
        .map(|run| (run.run_id.as_str(), run))
        .collect::<HashMap<_, _>>();
    let tasks_by_id = broker_tasks
        .iter()
        .map(|task| (task.broker_task_id.as_str(), task))
        .collect::<HashMap<_, _>>();

    for task in broker_tasks {
        validate_task_run(operation, task, &runs_by_id)?;
        validate_task_projection_bounds(operation, task)?;
        let run = runs_by_id
            .get(task.run_id.as_str())
            .ok_or_else(|| invalid_snapshot(operation, &task.run_id, "Unknown scheduler Run."))?;
        if run.status.contributes_capacity() && task.status == SchedulerBrokerTaskStatus::Queued {
            validate_dependencies(operation, task, &tasks_by_id)?;
        }
    }
    Ok(())
}

/// Validate task identity/facts shared by frontier, claim-plan, and
/// external-claim validation paths.
pub(super) fn validate_task_projection_bounds(
    operation: &str,
    task: &SchedulerBrokerTask,
) -> Result<(), DomainError> {
    if task.project_id.is_empty() || task.project_id.len() > MAX_SCHEDULER_ID_BYTES {
        return Err(invalid_snapshot(
            operation,
            &task.broker_task_id,
            "Scheduler task project identity must be non-empty and bounded.",
        ));
    }
    if task.objective.len() > MAX_SCHEDULER_OBJECTIVE_BYTES {
        return Err(invalid_snapshot(
            operation,
            &task.broker_task_id,
            "Scheduler task objective exceeds the bounded size.",
        ));
    }
    if task
        .role
        .as_deref()
        .is_some_and(|role| role.len() > MAX_SCHEDULER_ROLE_BYTES)
    {
        return Err(invalid_snapshot(
            operation,
            &task.broker_task_id,
            "Scheduler task role exceeds the bounded size.",
        ));
    }
    Ok(())
}

fn validate_collection_bounds(
    operation: &str,
    runs: &[SchedulerRun],
    broker_tasks: &[SchedulerBrokerTask],
) -> Result<(), DomainError> {
    if runs.len() > MAX_SCHEDULER_RUNS {
        return Err(invalid_snapshot(
            operation,
            "runs",
            "Scheduler Run snapshot exceeds the bounded Run limit.",
        ));
    }
    if broker_tasks.len() > MAX_SCHEDULER_TASKS {
        return Err(invalid_snapshot(
            operation,
            "broker_tasks",
            "Scheduler task snapshot exceeds the bounded task limit.",
        ));
    }
    if broker_tasks.iter().any(|task| {
        task.depends_on.len() > MAX_TASK_DEPENDENCIES
            || task.broker_task_id.len() > MAX_SCHEDULER_ID_BYTES
            || task.run_id.len() > MAX_SCHEDULER_ID_BYTES
            || task
                .depends_on
                .iter()
                .any(|dependency| dependency.len() > MAX_SCHEDULER_ID_BYTES)
    }) || runs.iter().any(|run| {
        run.run_id.len() > MAX_SCHEDULER_ID_BYTES || run.project_id.len() > MAX_SCHEDULER_ID_BYTES
    }) {
        return Err(invalid_snapshot(
            operation,
            "scheduler_snapshot",
            "Scheduler identifiers or dependency fan-in exceed bounded limits.",
        ));
    }
    Ok(())
}

fn validate_run_ids(operation: &str, runs: &[SchedulerRun]) -> Result<(), DomainError> {
    let mut seen = HashSet::with_capacity(runs.len());
    for run in runs {
        if run.run_id.is_empty() {
            return Err(invalid_snapshot(
                operation,
                "run_id",
                "Scheduler Run identity must not be empty.",
            ));
        }
        if run.project_id.is_empty() {
            return Err(invalid_snapshot(
                operation,
                &run.run_id,
                "Scheduler Run project identity must not be empty.",
            ));
        }
        if !seen.insert(run.run_id.as_str()) {
            return Err(DomainError {
                code: ErrorCode::SchedulerDuplicateRunId,
                operation: operation.to_owned(),
                resource_id: run.run_id.clone(),
                message: format!("Scheduler Run id '{}' is duplicated.", run.run_id),
                current_revision: None,
            });
        }
    }
    Ok(())
}

fn validate_requested_parallelism(
    operation: &str,
    runs: &[SchedulerRun],
) -> Result<(), DomainError> {
    for run in runs {
        if !run.status.contributes_capacity() {
            continue;
        }
        let RequestedParallelism(value) = run.requested_parallelism;
        if !(1..=MAX_REQUESTED_PARALLELISM).contains(&value) {
            return Err(DomainError {
                code: ErrorCode::SchedulerInvalidParallelism,
                operation: operation.to_owned(),
                resource_id: run.run_id.clone(),
                message: format!(
                    "Run requested_parallelism must be between 1 and {MAX_REQUESTED_PARALLELISM}."
                ),
                current_revision: None,
            });
        }
    }
    Ok(())
}

fn validate_task_ids(operation: &str, tasks: &[SchedulerBrokerTask]) -> Result<(), DomainError> {
    let mut seen = HashSet::with_capacity(tasks.len());
    for task in tasks {
        if task.broker_task_id.is_empty() {
            return Err(invalid_snapshot(
                operation,
                "broker_task_id",
                "Scheduler Broker task identity must not be empty.",
            ));
        }
        if !seen.insert(task.broker_task_id.as_str()) {
            return Err(DomainError {
                code: ErrorCode::SchedulerDuplicateTaskId,
                operation: operation.to_owned(),
                resource_id: task.broker_task_id.clone(),
                message: format!(
                    "Scheduler Broker task id '{}' is duplicated.",
                    task.broker_task_id
                ),
                current_revision: None,
            });
        }
    }
    Ok(())
}

fn validate_task_run(
    operation: &str,
    task: &SchedulerBrokerTask,
    runs_by_id: &HashMap<&str, &SchedulerRun>,
) -> Result<(), DomainError> {
    if task.run_id.is_empty() {
        return Err(invalid_snapshot(
            operation,
            &task.broker_task_id,
            "Scheduler Broker task Run identity must not be empty.",
        ));
    }
    let Some(run) = runs_by_id.get(task.run_id.as_str()) else {
        return Err(DomainError {
            code: ErrorCode::SchedulerUnknownRun,
            operation: operation.to_owned(),
            resource_id: task.run_id.clone(),
            message: format!(
                "Scheduler Broker task references unknown Run '{}'.",
                task.run_id
            ),
            current_revision: None,
        });
    };
    if task.project_id != run.project_id {
        return Err(invalid_snapshot(
            operation,
            &task.broker_task_id,
            "Scheduler task project identity must match its owning Run.",
        ));
    }
    Ok(())
}

fn validate_dependencies(
    operation: &str,
    task: &SchedulerBrokerTask,
    tasks_by_id: &HashMap<&str, &SchedulerBrokerTask>,
) -> Result<(), DomainError> {
    for dependency_id in &task.depends_on {
        if dependency_id == &task.broker_task_id {
            return Err(invalid_snapshot(
                operation,
                &task.broker_task_id,
                "Scheduler Broker task cannot depend on itself.",
            ));
        }
        let Some(dependency) = tasks_by_id.get(dependency_id.as_str()) else {
            return Err(DomainError {
                code: ErrorCode::SchedulerUnknownDependency,
                operation: operation.to_owned(),
                resource_id: dependency_id.clone(),
                message: format!(
                    "Scheduler Broker task dependency '{dependency_id}' does not exist."
                ),
                current_revision: None,
            });
        };
        if dependency.run_id != task.run_id {
            return Err(DomainError {
                code: ErrorCode::SchedulerCrossRunDependency,
                operation: operation.to_owned(),
                resource_id: dependency_id.clone(),
                message: format!(
                    "Scheduler Broker task dependency '{dependency_id}' crosses Run boundaries."
                ),
                current_revision: None,
            });
        }
    }
    Ok(())
}

fn invalid_snapshot(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::SchedulerInvalidSnapshot,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}
