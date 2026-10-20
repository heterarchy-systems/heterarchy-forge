//! Deterministic Rust policy for Heterarchy Orchestration.
//!
//! Orchestration decides when and where runnable work may execute, how much
//! capacity it may consume, and which runtime slot may satisfy the request.
//! Forge remains authoritative for Workspace, Goal/DAG, Agent/Team, source
//! mutation, execution evidence, verification, and integration state.

pub mod dependency;
pub mod provisioning;
pub mod queue;
pub mod runtime_activation;
pub mod scheduler;
mod types;
pub mod wake;

pub use dependency::{
    DependencyDecision, DependencyPlan, DependencyTask, MAX_DEPENDENCY_TASKS, validate_dependencies,
};
pub use queue::{
    AGING_THRESHOLD_MICROS, AUTHORITY_CONTROL_RESERVED_SLOTS, DEFAULT_QUEUE_CAPACITY,
    LIVENESS_RESERVED_SLOTS, MAX_PHYSICAL_QUEUE_DEPTH, NONCRITICAL_RESERVED_SLOTS,
    QueueAdmissionDecision, QueueAdmissionInput, QueueAdmissionOutcome, QueueAdmissionRejection,
    QueueCapacity, QueueDepths, QueueDispatchDecision, QueueDispatchInput, QueueDispatchOutcome,
    QueueHeads, ServiceClass, WEIGHTED_ROUND_ROBIN_SCHEDULE, capture_draining_ceiling,
    evaluate_queue_admission, evaluate_queue_dispatch,
};
pub use runtime_activation::{
    MAX_RUNTIME_ACTIVATION_DESIRED_CAPACITY, MAX_RUNTIME_ACTIVATION_ID_BYTES,
    MAX_RUNTIME_ACTIVATION_RUNTIMES, ProviderActivationCapability, RuntimeActivationAction,
    RuntimeActivationActionKind, RuntimeActivationAvailability, RuntimeActivationCommand,
    RuntimeActivationDecision, RuntimeActivationObservation, RuntimeActivationPlanCommand,
    RuntimeActivationProviderBinding, RuntimeActivationRuntimeAction, RuntimeActivationSnapshot,
    RuntimeActivationSpawnAction, RuntimeActivationStatus,
};
pub use types::{DomainError, ErrorCode, Revision, TimestampMicros};
pub use wake::{
    TransitionWakeTargetCommand, WakeCommand, WakeDecision, WakeTargetSnapshot, WakeTargetStatus,
    WakeTargetTransitionDecision, evaluate_wake,
};
