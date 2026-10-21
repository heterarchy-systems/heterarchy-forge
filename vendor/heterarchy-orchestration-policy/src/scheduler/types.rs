//! Typed inputs and outputs for deterministic scheduler policy.

use serde::{Deserialize, Serialize};

use crate::TimestampMicros;

/// Upper bound enforced at the public orchestration boundary for Run demand.
pub const MAX_REQUESTED_PARALLELISM: u32 = 32;
pub const MAX_SCHEDULER_RUNS: usize = 1_024;
pub const MAX_SCHEDULER_TASKS: usize = 10_000;
pub const MAX_TASK_DEPENDENCIES: usize = 256;
pub const MAX_SCHEDULER_ID_BYTES: usize = 512;
pub const MAX_SCHEDULER_OBJECTIVE_BYTES: usize = 64 * 1024;
pub const MAX_SCHEDULER_ROLE_BYTES: usize = 512;

/// Scheduler command family nested under the coarse engine command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum SchedulerCommand {
    /// Evaluate ready work and demand from a durable Run/Broker-task snapshot.
    EvaluateFrontier(EvaluateFrontierCommand),
    /// Select the oldest already-published ready task for one Broker claim attempt.
    PlanClaimAttempt(PlanClaimAttemptCommand),
    /// Validate a Broker claim against a fresh local task/run projection.
    ValidateExternalClaim(ValidateExternalClaimCommand),
}

/// Command payload for runnable-frontier calculation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateFrontierCommand {}

/// Command payload for selecting one claim candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanClaimAttemptCommand {
    /// Project namespace in which the external Broker claim will be attempted.
    pub project_id: String,
    /// Optional exact Run restriction. `None` permits the oldest ready Run task.
    #[serde(default)]
    pub run_id: Option<String>,
}

/// Command payload for validating one externally-authorized Broker claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateExternalClaimCommand {
    /// Fenced identity returned by the external Broker claim operation.
    pub claim: ExternalClaimIdentity,
}

/// Scheduler snapshot family nested under the coarse engine snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum SchedulerSnapshot {
    /// Durable Run and local Broker-task projection for frontier calculation.
    Frontier(FrontierSnapshot),
    /// Fresh local task/run facts used to validate one external Broker claim.
    ClaimValidation(ClaimValidationSnapshot),
}

/// Scheduler decision family nested under the coarse engine decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum SchedulerDecision {
    /// Ready/publishable work and stable demand aggregates.
    Frontier(FrontierDecision),
    /// Optional oldest ready hint for the next external Broker claim attempt.
    ClaimAttempt(ClaimAttemptDecision),
    /// Typed assignment intent after local validation of an external claim.
    ExternalClaim(ExternalClaimDecision),
}

/// Snapshot of persisted Runs and their local Broker task projections.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierSnapshot {
    /// Durable Runs, each with its persisted demand configuration.
    pub runs: Vec<SchedulerRun>,
    /// Local Broker-task projections. Broker remains claim/lease authority.
    pub broker_tasks: Vec<SchedulerBrokerTask>,
}

/// Durable Run facts required by scheduler policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRun {
    /// Durable Run identity.
    pub run_id: String,
    /// Canonical project identity for this Run.
    pub project_id: String,
    /// Lifecycle status deciding whether this Run contributes capacity demand.
    pub status: SchedulerRunStatus,
    /// Persisted requested worker parallelism for this Run.
    pub requested_parallelism: RequestedParallelism,
}

/// Run lifecycle states relevant to scheduling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerRunStatus {
    /// The Run can contribute runnable or claimed work.
    Active,
    /// The Run is terminal and cannot contribute capacity demand.
    Completed,
    /// The Run is terminal and cannot contribute capacity demand.
    Cancelled,
}

impl SchedulerRunStatus {
    /// Return whether scheduler demand may be derived from this Run.
    #[must_use]
    pub const fn contributes_capacity(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Bounded caller-persisted parallelism for one Run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RequestedParallelism(pub u32);

/// Local projection of one Broker task; it is not a Broker lease or claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerBrokerTask {
    /// Durable local Broker-task projection identity.
    pub broker_task_id: String,
    /// Durable Run that owns this local task projection.
    pub run_id: String,
    /// Canonical task-local project projection. It must match the owning Run.
    pub project_id: String,
    /// Objective sent to the external Broker and returned with its claim.
    pub objective: String,
    /// Assignment role; physical Worker targets remain role-neutral.
    #[serde(default)]
    pub role: Option<String>,
    /// Local dependency task identities.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Locally observed Broker lifecycle status.
    pub status: SchedulerBrokerTaskStatus,
    /// Whether the task was already successfully published to the Broker.
    pub external_published: bool,
    /// Caller-observed creation timestamp used for deterministic task ordering.
    pub created_at_micros: TimestampMicros,
    /// Local projection revision used as a CAS/fencing observation.
    pub revision: crate::Revision,
}

/// Broker-task statuses that affect local runnable-frontier policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerBrokerTaskStatus {
    /// The task awaits local dependency completion and possible publication.
    Queued,
    /// The Broker has already assigned the task; it consumes engaged capacity.
    Claimed,
    /// The task completed successfully and may satisfy dependencies.
    Completed,
    /// The task failed and cannot satisfy dependencies.
    Failed,
}

impl SchedulerBrokerTaskStatus {
    /// Return whether this local status has passed publication/claim admission.
    #[must_use]
    pub const fn requires_publication(self) -> bool {
        !matches!(self, Self::Queued)
    }
}

/// Stable per-Run frontier counts and bounded demand.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunFrontierAggregate {
    /// Durable Run identity.
    pub run_id: String,
    /// Canonical project identity.
    pub project_id: String,
    /// Number of locally queued tasks with all dependencies completed.
    pub ready_task_count: u64,
    /// Number of locally observed Broker-claimed tasks.
    pub claimed_task_count: u64,
    /// Persisted parallelism for this contributing Run.
    pub requested_parallelism: u64,
    /// Per-Run bounded demand: `min(requested, ready + claimed)`.
    pub engaged_task_count: u64,
}

/// Stable per-project aggregate derived from contributing active Runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectFrontierAggregate {
    /// Canonical project identity.
    pub project_id: String,
    /// Number of locally ready tasks across contributing active Runs.
    pub ready_task_count: u64,
    /// Number of locally claimed tasks across contributing active Runs.
    pub claimed_task_count: u64,
    /// Sum of persisted requested parallelism across contributing active Runs.
    pub requested_parallelism: u64,
    /// Sum of per-Run bounded engaged demand.
    pub engaged_task_count: u64,
}

/// Deterministic runnable-frontier policy result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FrontierDecision {
    /// Active queued tasks with completed dependencies, ordered by `(created_at, id)`.
    pub ready_task_ids: Vec<String>,
    /// Ready tasks not yet published, ordered by `(created_at, id)`.
    pub publishable_task_ids: Vec<String>,
    /// Projects with ready work, in lexical project-id order.
    pub ready_project_ids: Vec<String>,
    /// Contributing active Runs ordered by `(project_id, run_id)`.
    pub run_aggregates: Vec<RunFrontierAggregate>,
    /// Contributing active projects ordered by project id.
    pub project_aggregates: Vec<ProjectFrontierAggregate>,
}

/// Optional project/run restriction for the claim candidate planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClaimReadyHint {
    /// Broker task identity selected by oldest `(created_at, broker_task_id)` order.
    pub broker_task_id: String,
    /// Owning durable Run identity.
    pub run_id: String,
    /// Owning project namespace.
    pub project_id: String,
    /// Objective and role copied from the local projection for caller comparison.
    pub objective: String,
    pub role: Option<String>,
    /// Local task revision observed while selecting the hint.
    pub observed_revision: crate::Revision,
}

/// Result of a claim-attempt plan; no result means no locally eligible hint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClaimAttemptDecision {
    /// Oldest already-published dependency-ready task, if one exists.
    pub candidate: Option<ClaimReadyHint>,
}

/// Local task/run facts used to validate one external Broker claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimValidationSnapshot {
    /// Project namespace supplied to the Broker claim operation.
    pub project_id: String,
    /// Fresh Run projections.
    pub runs: Vec<SchedulerRun>,
    /// Fresh local Broker-task projections.
    pub broker_tasks: Vec<SchedulerBrokerTask>,
}

/// Fenced identity returned by the external Broker. Values are observations only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalClaimIdentity {
    /// Broker task identity returned by the claim operation.
    pub broker_task_id: String,
    /// Run and project scope in which the claim was issued.
    pub run_id: String,
    pub project_id: String,
    /// Broker-returned assignment facts.
    pub objective: String,
    pub role: Option<String>,
    /// Local task revision observed before this external claim was accepted.
    pub expected_task_revision: crate::Revision,
    /// Broker ownership fence. Rust validates presence/shape but never mints it.
    pub term: u64,
    pub generation: u64,
    pub lease_id: String,
    pub lease_epoch: u64,
    #[serde(default)]
    pub lease_expires_at_ms: u64,
}

/// Typed local assignment intent after claim validation succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssignmentIntent {
    pub broker_task_id: String,
    pub run_id: String,
    pub project_id: String,
    pub objective: String,
    pub role: Option<String>,
    pub task_revision: crate::Revision,
    pub term: u64,
    pub generation: u64,
    pub lease_id: String,
    pub lease_epoch: u64,
    pub lease_expires_at_ms: u64,
}

/// Result of external-claim validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExternalClaimDecision {
    /// Validated assignment intent for the durable orchestration boundary, never a Broker claim.
    pub assignment: AssignmentIntent,
}
