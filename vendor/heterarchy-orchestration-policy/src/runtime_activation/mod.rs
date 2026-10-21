//! Deterministic provider-neutral runtime activation planning.
//!
//! This module centralizes the policy order `Reuse -> Wake -> Spawn -> Park ->
//! Retire`. External boundaries own runtime observation, `ProviderBinding`
//! validation, persistence, provider effects, and retry loops. Rust returns only
//! ordered revision-fenced intents from bounded explicit input.

mod planner;
mod types;
mod validation;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::manual_let_else, clippy::panic)]
mod tests;

pub use types::*;

use crate::DomainError;

/// Evaluate one typed runtime activation command.
///
/// # Errors
///
/// Returns a structured domain error when the snapshot is malformed or the
/// command/snapshot pair cannot be evaluated safely.
pub fn evaluate_runtime_activation(
    operation: &str,
    command: RuntimeActivationCommand,
    snapshot: &RuntimeActivationSnapshot,
) -> Result<RuntimeActivationDecision, DomainError> {
    validation::validate_snapshot(operation, snapshot)?;
    match command {
        RuntimeActivationCommand::Plan(_command) => planner::plan(operation, snapshot),
    }
}
