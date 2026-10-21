//! Deterministic Broker claim hinting and external-claim validation.
//!
//! The external Broker remains the only owner of claim, lease, generation, and
//! fencing authority. Rust only compares a fresh local projection with the
//! identity returned by a completed Broker call and returns a typed intent for
//! durable orchestration persistence.

use std::collections::HashMap;

use crate::{DomainError, ErrorCode};

use super::types::{
    AssignmentIntent, ClaimAttemptDecision, ClaimReadyHint, ClaimValidationSnapshot,
    ExternalClaimDecision, ExternalClaimIdentity, FrontierSnapshot, MAX_SCHEDULER_ID_BYTES,
    MAX_SCHEDULER_OBJECTIVE_BYTES, MAX_SCHEDULER_ROLE_BYTES, MAX_SCHEDULER_RUNS,
    MAX_SCHEDULER_TASKS, PlanClaimAttemptCommand, SchedulerBrokerTask, SchedulerBrokerTaskStatus,
    SchedulerRunStatus,
};
use super::validation::{
    validate_frontier_snapshot, validate_scheduler_records, validate_task_projection_bounds,
};

/// Plan an optional oldest ready task for a subsequent external claim call.
pub(super) fn plan_claim_attempt(
    operation: &str,
    command: &PlanClaimAttemptCommand,
    snapshot: &FrontierSnapshot,
) -> Result<ClaimAttemptDecision, DomainError> {
    if command.project_id.is_empty() || command.project_id.len() > MAX_SCHEDULER_ID_BYTES {
        return Err(invalid_command(
            operation,
            "project_id",
            "Claim-attempt project identity must be non-empty and bounded.",
        ));
    }
    if command
        .run_id
        .as_deref()
        .is_some_and(|run_id| run_id.is_empty() || run_id.len() > MAX_SCHEDULER_ID_BYTES)
    {
        return Err(invalid_command(
            operation,
            "run_id",
            "Claim-attempt Run identity must be non-empty and bounded when supplied.",
        ));
    }
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
    let mut candidates = snapshot
        .broker_tasks
        .iter()
        .filter(|task| {
            task.status == SchedulerBrokerTaskStatus::Queued
                && task.external_published
                && task.run_id == command.run_id.as_deref().unwrap_or(task.run_id.as_str())
        })
        .filter_map(|task| {
            let run = runs_by_id.get(task.run_id.as_str())?;
            if !run.status.contributes_capacity() || run.project_id != command.project_id {
                return None;
            }
            if !dependencies_completed(task, &tasks_by_id) {
                return None;
            }
            Some(task)
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by(|left, right| {
        (left.created_at_micros, left.broker_task_id.as_str())
            .cmp(&(right.created_at_micros, right.broker_task_id.as_str()))
    });

    Ok(ClaimAttemptDecision {
        candidate: candidates.first().map(|task| {
            let run = runs_by_id
                .get(task.run_id.as_str())
                // The frontier validator and map construction make this
                // branch unreachable.  Avoid panic/unwrap in production by
                // carrying only fields available on the task; project id is
                // checked again in validation and is present in the command.
                .copied();
            ClaimReadyHint {
                broker_task_id: task.broker_task_id.clone(),
                run_id: task.run_id.clone(),
                project_id: run.map_or_else(String::new, |value| value.project_id.clone()),
                objective: task.objective.clone(),
                role: task.role.clone(),
                observed_revision: task.revision,
            }
        }),
    })
}

/// Validate a Broker claim against one fresh local task/run projection.
#[allow(clippy::too_many_lines)]
pub(super) fn validate_external_claim(
    operation: &str,
    claim: &ExternalClaimIdentity,
    snapshot: &ClaimValidationSnapshot,
) -> Result<ExternalClaimDecision, DomainError> {
    validate_claim_identity(operation, claim)?;
    validate_claim_snapshot(operation, snapshot)?;

    if snapshot.project_id != claim.project_id {
        return Err(claim_mismatch(
            operation,
            &claim.broker_task_id,
            "External Broker claim project does not match the fresh local snapshot.",
        ));
    }
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
    let Some(run) = runs_by_id.get(claim.run_id.as_str()) else {
        return Err(DomainError {
            code: ErrorCode::SchedulerUnknownRun,
            operation: operation.to_owned(),
            resource_id: claim.run_id.clone(),
            message: "External Broker claim references an unknown Run.".to_owned(),
            current_revision: None,
        });
    };
    if run.status != SchedulerRunStatus::Active || run.project_id != claim.project_id {
        return Err(claim_mismatch(
            operation,
            &claim.run_id,
            "External Broker claim requires an active Run in the requested project.",
        ));
    }
    let Some(task) = tasks_by_id.get(claim.broker_task_id.as_str()) else {
        return Err(DomainError {
            code: ErrorCode::SchedulerUnknownTask,
            operation: operation.to_owned(),
            resource_id: claim.broker_task_id.clone(),
            message: "External Broker claim references an unknown local task.".to_owned(),
            current_revision: None,
        });
    };
    if task.run_id != claim.run_id || task.project_id != claim.project_id {
        return Err(claim_mismatch(
            operation,
            &claim.broker_task_id,
            "External Broker claim Run/project facts do not match the local task.",
        ));
    }
    if task.status != SchedulerBrokerTaskStatus::Queued || !task.external_published {
        return Err(DomainError {
            code: ErrorCode::SchedulerClaimNotReady,
            operation: operation.to_owned(),
            resource_id: claim.broker_task_id.clone(),
            message: "External Broker claim requires a queued, already-published task.".to_owned(),
            current_revision: Some(task.revision),
        });
    }
    if !dependencies_completed(task, &tasks_by_id) {
        return Err(DomainError {
            code: ErrorCode::SchedulerClaimNotReady,
            operation: operation.to_owned(),
            resource_id: claim.broker_task_id.clone(),
            message: "External Broker claim requires all local task dependencies to be completed."
                .to_owned(),
            current_revision: Some(task.revision),
        });
    }
    if task.objective != claim.objective || task.role != claim.role {
        return Err(claim_mismatch(
            operation,
            &claim.broker_task_id,
            "External Broker claim objective/role does not match the local task.",
        ));
    }
    if task.revision != claim.expected_task_revision {
        return Err(DomainError {
            code: ErrorCode::SchedulerClaimFenceMismatch,
            operation: operation.to_owned(),
            resource_id: claim.broker_task_id.clone(),
            message: "External Broker claim local task revision is stale.".to_owned(),
            current_revision: Some(task.revision),
        });
    }

    Ok(ExternalClaimDecision {
        assignment: AssignmentIntent {
            broker_task_id: claim.broker_task_id.clone(),
            run_id: claim.run_id.clone(),
            project_id: claim.project_id.clone(),
            objective: claim.objective.clone(),
            role: claim.role.clone(),
            task_revision: task.revision,
            term: claim.term,
            generation: claim.generation,
            lease_id: claim.lease_id.clone(),
            lease_epoch: claim.lease_epoch,
            lease_expires_at_ms: claim.lease_expires_at_ms,
        },
    })
}

fn validate_claim_identity(
    operation: &str,
    claim: &ExternalClaimIdentity,
) -> Result<(), DomainError> {
    if claim.broker_task_id.is_empty()
        || claim.broker_task_id.len() > MAX_SCHEDULER_ID_BYTES
        || claim.run_id.is_empty()
        || claim.run_id.len() > MAX_SCHEDULER_ID_BYTES
        || claim.project_id.is_empty()
        || claim.project_id.len() > MAX_SCHEDULER_ID_BYTES
    {
        return Err(invalid_command(
            operation,
            "claim",
            "External claim identities must be non-empty and bounded.",
        ));
    }
    if claim.objective.len() > MAX_SCHEDULER_OBJECTIVE_BYTES {
        return Err(invalid_command(
            operation,
            &claim.broker_task_id,
            "External claim objective exceeds the bounded size.",
        ));
    }
    if claim
        .role
        .as_deref()
        .is_some_and(|role| role.len() > MAX_SCHEDULER_ROLE_BYTES)
    {
        return Err(invalid_command(
            operation,
            &claim.broker_task_id,
            "External claim role exceeds the bounded size.",
        ));
    }
    if claim.term == 0
        || claim.generation == 0
        || claim.lease_id.is_empty()
        || claim.lease_epoch == 0
    {
        return Err(DomainError {
            code: ErrorCode::SchedulerClaimFenceMismatch,
            operation: operation.to_owned(),
            resource_id: claim.broker_task_id.clone(),
            message: "External Broker claim is missing a valid ownership fence.".to_owned(),
            current_revision: Some(claim.expected_task_revision),
        });
    }
    if claim.lease_id.len() > MAX_SCHEDULER_ID_BYTES {
        return Err(invalid_command(
            operation,
            &claim.broker_task_id,
            "External claim lease identity exceeds the bounded size.",
        ));
    }
    Ok(())
}

fn validate_claim_snapshot(
    operation: &str,
    snapshot: &ClaimValidationSnapshot,
) -> Result<(), DomainError> {
    if snapshot.project_id.is_empty() || snapshot.project_id.len() > MAX_SCHEDULER_ID_BYTES {
        return Err(invalid_snapshot(
            operation,
            "project_id",
            "Claim-validation project identity must be non-empty and bounded.",
        ));
    }
    if snapshot.runs.len() > MAX_SCHEDULER_RUNS || snapshot.broker_tasks.len() > MAX_SCHEDULER_TASKS
    {
        return Err(invalid_snapshot(
            operation,
            "claim_validation",
            "Claim-validation snapshot exceeds the bounded collection limits.",
        ));
    }
    // Reuse the frontier validator for duplicate ids, run/project boundaries,
    // dependency fan-in, and active-run parallelism bounds without cloning the
    // full claim-validation snapshot on every external claim.
    validate_scheduler_records(operation, &snapshot.runs, &snapshot.broker_tasks)?;
    for task in &snapshot.broker_tasks {
        validate_task_projection_bounds(operation, task)?;
    }
    Ok(())
}

fn dependencies_completed(
    task: &SchedulerBrokerTask,
    tasks_by_id: &HashMap<&str, &SchedulerBrokerTask>,
) -> bool {
    task.depends_on.iter().all(|dependency_id| {
        tasks_by_id
            .get(dependency_id.as_str())
            .is_some_and(|dependency| dependency.status == SchedulerBrokerTaskStatus::Completed)
    })
}

fn invalid_command(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::SchedulerClaimInvalidCommand,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}

fn invalid_snapshot(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::SchedulerClaimInvalidSnapshot,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}

fn claim_mismatch(operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code: ErrorCode::SchedulerClaimMismatch,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}
