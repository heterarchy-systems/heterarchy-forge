//! Typed inputs and outputs for provider-neutral runtime activation planning.
//!
//! The values in this module are durable or explicitly observed facts. The
//! policy evaluator does not discover providers, read runtime presence, create worker
//! identities, or deliver activation messages.

use serde::{Deserialize, Serialize};

use crate::{Revision, TimestampMicros};

/// Maximum runtime observations considered by one activation plan.
pub const MAX_RUNTIME_ACTIVATION_RUNTIMES: usize = 1_024;
/// Maximum desired runnable capacity accepted by one activation plan.
pub const MAX_RUNTIME_ACTIVATION_DESIRED_CAPACITY: u64 = 1_024;
/// Maximum UTF-8 byte length for opaque provider, project, or runtime ids.
pub const MAX_RUNTIME_ACTIVATION_ID_BYTES: usize = 512;

/// Runtime lifecycle states relevant to activation delivery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeActivationStatus {
    /// The runtime has no assignment or delivery reservation.
    Idle,
    /// Activation delivery has been durably reserved but not yet claimed.
    Waking,
    /// The runtime is attempting to claim Broker work.
    Claiming,
    /// The runtime has an externally-authoritative Broker assignment.
    Busy,
}

impl RuntimeActivationStatus {
    /// Return whether this status already reserves runnable capacity.
    #[must_use]
    pub const fn reserves_capacity(self) -> bool {
        matches!(self, Self::Waking | Self::Claiming | Self::Busy)
    }
}

/// Presence-derived runtime availability reported by the observation adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeActivationAvailability {
    /// The runtime can receive work immediately without provider wakeup.
    Active,
    /// The runtime can be explicitly reactivated by its provider adapter.
    Dormant,
    /// No recoverable runtime presence was observed.
    Offline,
}

/// Provider-level capabilities already validated at the external boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderActivationCapability {
    /// The provider adapter can create a new runtime through a provisioning request.
    pub spawn_supported: bool,
    /// The provider adapter can park a safely idle active runtime.
    pub park_supported: bool,
    /// The provider adapter can retire a safely drained runtime.
    pub retire_supported: bool,
}

/// Current provider binding fence applied to every action in the plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationProviderBinding {
    /// Canonical project namespace for the selected provider binding.
    pub project_id: String,
    /// Opaque `ProviderBinding` identity. Rust never derives provider kind from it.
    pub binding_id: String,
    /// Current durable `ProviderBinding` revision.
    pub revision: Revision,
    /// Capabilities validated for the active provider binding.
    pub capability: ProviderActivationCapability,
}

/// Per-runtime capability observed by the provider boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationRuntimeCapability {
    /// Whether an active idle runtime may receive this plan's work immediately.
    pub reusable: bool,
    /// Whether a dormant idle runtime may receive a provider wake.
    pub wake_supported: bool,
}

/// Delivery state whose booleans are explicitly observed at the external boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationDeliveryState {
    /// Observed active delivery cooldown or backoff state.
    pub cooldown_active: bool,
    /// Observed expired activation delivery lease.
    pub delivery_lease_expired: bool,
}

/// Maintenance eligibility deliberately selected outside the policy evaluator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationMaintenanceEligibility {
    /// Observed safe parking eligibility; policy evaluation never reads a clock.
    pub park_eligible: bool,
    /// Observed safe retirement eligibility; policy evaluation never reads a clock.
    pub retire_eligible: bool,
}

/// One fenced reusable provider runtime observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationObservation {
    /// Canonical project namespace; it must equal the snapshot project.
    pub project_id: String,
    /// Opaque runtime identity, stable across one `ProviderBinding` lifetime.
    pub runtime_id: String,
    /// Provider binding that owns the runtime; it must match the snapshot fence.
    pub binding_id: String,
    /// Provider binding revision observed while reading this runtime.
    pub binding_revision: Revision,
    /// Durable activation lifecycle state.
    pub status: RuntimeActivationStatus,
    /// Runtime availability from the provider observation boundary.
    pub availability: RuntimeActivationAvailability,
    /// Whether the runtime is compatible with the selected `ProviderBinding`.
    pub provider_compatible: bool,
    /// Provider-adapter capability without provider-specific policy semantics.
    #[serde(flatten)]
    pub activation_capability: RuntimeActivationRuntimeCapability,
    /// Explicit delivery cooldown and stale-lease facts.
    #[serde(flatten)]
    pub delivery_state: RuntimeActivationDeliveryState,
    /// Explicit maintenance eligibility from the observation boundary.
    #[serde(flatten)]
    pub maintenance_eligibility: RuntimeActivationMaintenanceEligibility,
    /// Runtime CAS revision required when the effect boundary applies an action.
    pub revision: Revision,
    /// Activation delivery revision required when the effect boundary applies an action.
    pub activation_revision: Revision,
    /// Stable observation ordering key supplied by durable state.
    pub created_at_micros: TimestampMicros,
}

/// Snapshot consumed by one pure runtime activation plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationSnapshot {
    /// Canonical project whose Consumer/runtime pool is being planned.
    pub project_id: String,
    /// Dependency-ready local Broker-task count retained for operator projection.
    pub ready_task_count: u64,
    /// Scheduler-derived active Run demand before capacity policy bounds it.
    pub engaged_task_count: u64,
    /// Maximum runtime capacity permitted for this project.
    pub project_max_runtimes: u64,
    /// Maximum runtime capacity permitted across all projects.
    pub global_max_runtimes: u64,
    /// Compatible recoverable runtimes observed across all projects.
    pub global_recoverable_runtime_count: u64,
    /// Current WAKING, CLAIMING, and BUSY runtime commitments across projects.
    pub global_activated_runtime_count: u64,
    /// Existing durable provisioning reservations for this project.
    pub pending_provisioning_count: u64,
    /// Existing durable provisioning reservations across all projects.
    pub global_pending_provisioning_count: u64,
    /// Current opaque `ProviderBinding` capability and revision fence.
    pub provider_binding: RuntimeActivationProviderBinding,
    /// All reusable runtime observations from one coherent external read.
    pub runtimes: Vec<RuntimeActivationObservation>,
}

/// Command family nested under the coarse engine command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum RuntimeActivationCommand {
    /// Plan reuse, wake, spawn, park, and retirement actions.
    Plan(RuntimeActivationPlanCommand),
}

/// Command payload for a side-effect-free runtime activation plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationPlanCommand {}

/// Action kinds returned by the deterministic activation planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeActivationActionKind {
    /// Clear an expired active/dormant delivery reservation before a fresh read.
    Recover,
    /// Deliver work to an already active, idle runtime.
    Reuse,
    /// Ask a dormant, idle runtime to reactivate and claim work.
    Wake,
    /// Reserve provider-neutral capacity for a new runtime provisioning request.
    Spawn,
    /// Park an idle active runtime already judged safe to park by observation policy.
    Park,
    /// Retire an idle runtime already judged safe to retire by observation policy.
    Retire,
}

/// Fenced action against one existing runtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeActivationRuntimeAction {
    /// Opaque runtime identity; Rust never creates or modifies this id.
    pub runtime_id: String,
    /// Provider binding identity required before applying the effect.
    pub binding_id: String,
    /// Provider binding revision required before applying the effect.
    pub binding_revision: Revision,
    /// Runtime CAS revision required before applying the effect.
    pub observed_revision: Revision,
    /// Activation CAS revision required before applying the effect.
    pub observed_activation_revision: Revision,
    /// Next activation revision for a `Reuse` or `Wake` delivery, otherwise `None`.
    pub next_activation_revision: Option<Revision>,
}

/// Provider-neutral reservation for one or more new runtimes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeActivationSpawnAction {
    /// Canonical project namespace receiving the reservation.
    pub project_id: String,
    /// Provider binding identity selected by the plan.
    pub binding_id: String,
    /// Provider binding revision required before provisioning persistence.
    pub binding_revision: Revision,
    /// Number of provider-neutral provisioning reservations to create.
    pub count: u64,
}

/// Ordered side-effect-free activation action intent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum RuntimeActivationAction {
    /// Recover a stale active/dormant delivery reservation.
    Recover(RuntimeActivationRuntimeAction),
    /// Reuse one active idle runtime.
    Reuse(RuntimeActivationRuntimeAction),
    /// Wake one dormant idle runtime.
    Wake(RuntimeActivationRuntimeAction),
    /// Reserve capacity for new provider-neutral runtime provisioning.
    Spawn(RuntimeActivationSpawnAction),
    /// Park one safe idle active runtime.
    Park(RuntimeActivationRuntimeAction),
    /// Retire one safe idle runtime.
    Retire(RuntimeActivationRuntimeAction),
}

/// Deterministic activation plan and its accounting facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationDecision {
    /// Canonical project receiving this activation plan.
    pub project_id: String,
    /// Dependency-ready task count retained from the scheduler observation.
    pub ready_task_count: u64,
    /// Bounded capacity target calculated by Rust from engaged demand and limits.
    pub desired_capacity: u64,
    /// Additional globally safe runtime delivery actions at this observation.
    pub global_activation_headroom: u64,
    /// Additional globally safe provisioning reservations at this observation.
    pub global_headroom: u64,
    /// Existing project provisioning reservations used by this decision.
    pub pending_provisioning_count: u64,
    /// Existing global provisioning reservations used by this decision.
    pub global_pending_provisioning_count: u64,
    /// Capacity still absent after reuse/wake but before pending reservations.
    pub capacity_deficit: u64,
    /// Existing and newly planned runtime/provisioning commitments.
    pub committed_capacity: u64,
    /// Capacity still not satisfiable after all bounded safe actions.
    pub unmet_capacity: u64,
    /// Ordered actions for CAS-fenced provider-effect execution.
    pub actions: Vec<RuntimeActivationAction>,
}
