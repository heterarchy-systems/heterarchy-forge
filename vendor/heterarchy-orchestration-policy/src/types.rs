use serde::{Deserialize, Serialize};

/// A non-negative optimistic-concurrency revision observed by Orchestration policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(pub u64);

/// A caller-provided UTC timestamp represented as integer microseconds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TimestampMicros(pub u64);

/// Machine-readable policy failure categories owned by Orchestration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidInput,
    EmptyTasks,
    DuplicateTaskKey,
    UnknownDependency,
    SelfDependency,
    Cycle,
    InvalidParallelism,
    RevisionConflict,
    ProvisioningInvalidSnapshot,
    ProvisioningInvalidCommand,
    ProvisioningConflict,
    ProvisioningStaleCallback,
    ProvisioningBindingConflict,
    ProvisioningRequestNotFound,
    ProvisioningArithmeticOverflow,
    SchedulerInvalidSnapshot,
    SchedulerInvalidCommand,
    SchedulerDuplicateRunId,
    SchedulerDuplicateTaskId,
    SchedulerUnknownRun,
    SchedulerUnknownDependency,
    SchedulerCrossRunDependency,
    SchedulerStatusInconsistency,
    SchedulerInvalidParallelism,
    SchedulerArithmeticOverflow,
    SchedulerClaimInvalidSnapshot,
    SchedulerClaimInvalidCommand,
    SchedulerClaimMismatch,
    SchedulerClaimFenceMismatch,
    SchedulerUnknownTask,
    SchedulerClaimNotReady,
    WakeInvalidSnapshot,
    WakeInvalidCommand,
    WakeRevisionOverflow,
    RuntimeActivationInvalidSnapshot,
    RuntimeActivationInvalidCommand,
    RuntimeActivationArithmeticOverflow,
    QueueInvalidSnapshot,
    QueueArithmeticOverflow,
}

/// Structured deterministic policy error. Persistence and transport map this type externally.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DomainError {
    pub code: ErrorCode,
    pub operation: String,
    pub resource_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<Revision>,
}
