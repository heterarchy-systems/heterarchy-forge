//! Deterministic scheduler frontier and capacity policy.
//!
//! The module accepts durable Run and local Broker-task observations and only
//! returns plans/counts. It never claims work, owns leases, calls a Broker, or
//! performs persistence or runtime I/O.

mod claim;
mod frontier;
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests;
pub mod types;
mod validation;

use crate::{DomainError, ErrorCode};

pub use types::{
    AssignmentIntent, ClaimAttemptDecision, ClaimReadyHint, ClaimValidationSnapshot,
    EvaluateFrontierCommand, ExternalClaimDecision, ExternalClaimIdentity, FrontierDecision,
    FrontierSnapshot, PlanClaimAttemptCommand, ProjectFrontierAggregate, RequestedParallelism,
    RunFrontierAggregate, SchedulerBrokerTask, SchedulerBrokerTaskStatus, SchedulerCommand,
    SchedulerDecision, SchedulerRun, SchedulerRunStatus, SchedulerSnapshot,
    ValidateExternalClaimCommand,
};

/// Evaluate one tagged scheduler command against its matching tagged snapshot.
///
/// # Errors
///
/// Returns a typed domain error when command and snapshot variants do not match
/// or when the selected pure policy rejects its input.
pub fn evaluate_scheduler(
    operation: &str,
    command: SchedulerCommand,
    snapshot: SchedulerSnapshot,
) -> Result<SchedulerDecision, DomainError> {
    match (command, snapshot) {
        (SchedulerCommand::EvaluateFrontier(_command), SchedulerSnapshot::Frontier(snapshot)) => {
            frontier::evaluate_frontier(operation, &snapshot).map(SchedulerDecision::Frontier)
        }
        (SchedulerCommand::PlanClaimAttempt(command), SchedulerSnapshot::Frontier(snapshot)) => {
            claim::plan_claim_attempt(operation, &command, &snapshot)
                .map(SchedulerDecision::ClaimAttempt)
        }
        (
            SchedulerCommand::ValidateExternalClaim(command),
            SchedulerSnapshot::ClaimValidation(snapshot),
        ) => claim::validate_external_claim(operation, &command.claim, &snapshot)
            .map(SchedulerDecision::ExternalClaim),
        (command, snapshot) => Err(DomainError {
            code: ErrorCode::InvalidInput,
            operation: operation.to_owned(),
            resource_id: "scheduler_snapshot".to_owned(),
            message: format!(
                "Scheduler command '{}' does not match scheduler snapshot '{}'.",
                scheduler_command_kind_name(&command),
                scheduler_snapshot_kind_name(&snapshot),
            ),
            current_revision: None,
        }),
    }
}

fn scheduler_command_kind_name(command: &SchedulerCommand) -> &'static str {
    match command {
        SchedulerCommand::EvaluateFrontier(_) => "evaluate_frontier",
        SchedulerCommand::PlanClaimAttempt(_) => "plan_claim_attempt",
        SchedulerCommand::ValidateExternalClaim(_) => "validate_external_claim",
    }
}

fn scheduler_snapshot_kind_name(snapshot: &SchedulerSnapshot) -> &'static str {
    match snapshot {
        SchedulerSnapshot::Frontier(_) => "frontier",
        SchedulerSnapshot::ClaimValidation(_) => "claim_validation",
    }
}
