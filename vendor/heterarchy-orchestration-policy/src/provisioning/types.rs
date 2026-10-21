//! Deterministic provisioning state policy.
//!
//! The module owns no persistence, clock, randomness, browser, or runtime I/O.
//! Every identity and timestamp needed for a mutation is supplied in the
//! command payload; the returned decision contains the complete next snapshot
//! and a typed outcome for the external effect plane.

use serde::{Deserialize, Serialize};

use crate::{Revision, TimestampMicros};

const DEFAULT_RETENTION: u64 = 128;

/// Maximum independently provisioned projects retained by one durable snapshot.
pub const MAX_PROVISIONING_DEMANDS: usize = 128;
/// Maximum requests, including active and retained terminal tombstones.
pub const MAX_PROVISIONING_REQUESTS: usize = 512;
/// Maximum prepared reservations accepted by one demand command.
pub const MAX_PROVISIONING_REQUEST_SEEDS: usize = 512;
/// Maximum current provider bindings supplied to one admission decision.
pub const MAX_PROVISIONING_BINDINGS: usize = 128;
/// Maximum explicit wake-target owners retired by one atomic batch command.
pub const MAX_PROVISIONING_RETIREMENT_BATCH: usize = 512;
/// Maximum configured backoff steps accepted by one failure callback.
pub const MAX_PROVISIONING_BACKOFF_STEPS: usize = 32;
/// Maximum terminal tombstones retained by the policy.
pub const MAX_PROVISIONING_TERMINAL_RETENTION: u64 = 512;
/// Maximum UTF-8 byte length for opaque provisioning identifiers.
pub const MAX_PROVISIONING_ID_BYTES: usize = 512;
/// Maximum UTF-8 byte length for one opaque provider-binding fingerprint.
pub const MAX_PROVISIONING_BINDING_FINGERPRINT_BYTES: usize = 128;
/// Maximum UTF-8 byte length for a provider failure description.
pub const MAX_PROVISIONING_FAILURE_REASON_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningRequestStatus {
    WaitingAdmission,
    OpeningProject,
    CreatingRuntime,
    Bootstrapping,
    WaitingRegistration,
    Active,
    RateLimited,
    Deferred,
    OperatorBlocked,
    Failed,
    Cancelled,
}

impl ProvisioningRequestStatus {
    pub(super) fn transient(self) -> bool {
        matches!(
            self,
            Self::OpeningProject
                | Self::CreatingRuntime
                | Self::Bootstrapping
                | Self::WaitingRegistration
        )
    }

    pub(super) fn queued(self) -> bool {
        matches!(
            self,
            Self::WaitingAdmission | Self::RateLimited | Self::Deferred
        )
    }

    pub(super) fn pending(self) -> bool {
        self.queued() || self.transient()
    }

    pub(super) fn prunable(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled)
    }
}

/// Provider workspace observation already validated at the external boundary.
///
/// The deterministic policy receives no provider kind, browser path,
/// application label, or provider-specific metadata. The external adapter owns
/// those semantics and reports the resulting support verdict plus opaque identity
/// and revision fences.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBindingObservation {
    pub project_id: String,
    pub binding_id: String,
    pub revision: Revision,
    pub connector_epoch: u64,
    pub supported: bool,
    pub metadata_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningDemand {
    pub schema_version: u32,
    pub project_id: String,
    pub desired_capacity: u64,
    pub spawn_needed: u64,
    pub revision: Revision,
    pub created_at_micros: TimestampMicros,
    pub updated_at_micros: TimestampMicros,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub project_id: String,
    pub provider_binding: Option<ProviderBindingObservation>,
    pub status: ProvisioningRequestStatus,
    pub admission_revision: Option<Revision>,
    pub revision: Revision,
    pub provider_runtime_id: Option<String>,
    pub wake_target_id: Option<String>,
    pub failure_reason: Option<String>,
    pub created_at_micros: TimestampMicros,
    pub updated_at_micros: TimestampMicros,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningAdmission {
    pub schema_version: u32,
    pub in_flight_request_id: Option<String>,
    pub last_admitted_at_micros: Option<TimestampMicros>,
    pub next_admission_at_micros: Option<TimestampMicros>,
    pub backoff_attempt: u64,
    pub backoff_until_micros: Option<TimestampMicros>,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningSnapshot {
    pub schema_version: u32,
    pub revision: Revision,
    pub demands: Vec<ProvisioningDemand>,
    pub requests: Vec<ProvisioningRequest>,
    pub admission: ProvisioningAdmission,
    pub updated_at_micros: TimestampMicros,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningRequestSeed {
    pub request_id: String,
    pub wake_target_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SynchronizeDemandCommand {
    pub project_id: String,
    pub desired_capacity: u64,
    pub spawn_needed: u64,
    pub request_seeds: Vec<ProvisioningRequestSeed>,
    pub now_micros: TimestampMicros,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyCapacityReservationCommand {
    pub project_id: String,
    pub desired_capacity: u64,
    pub capacity_deficit: u64,
    pub spawn_needed: u64,
    pub project_pending_snapshot: u64,
    pub global_headroom: u64,
    pub global_pending_snapshot: u64,
    pub request_seeds: Vec<ProvisioningRequestSeed>,
    pub now_micros: TimestampMicros,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitNextCommand {
    pub now_micros: TimestampMicros,
    pub minimum_admission_interval_micros: u64,
    pub admission_lease_micros: u64,
    pub binding_required: bool,
    pub bindings: Vec<ProviderBindingObservation>,
    pub new_request_seed: Option<ProvisioningRequestSeed>,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressRequestCommand {
    pub request_id: String,
    pub status: ProvisioningRequestStatus,
    pub admission_revision: Revision,
    pub now_micros: TimestampMicros,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordFailureCommand {
    pub request_id: String,
    pub admission_revision: Revision,
    pub reason: String,
    pub rate_limited: bool,
    pub now_micros: TimestampMicros,
    pub minimum_admission_interval_micros: u64,
    pub rate_limit_backoff_micros: Vec<u64>,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRegistrationCommand {
    pub request_id: String,
    pub provider_runtime_id: String,
    pub wake_target_id: String,
    pub admission_revision: Revision,
    pub provider_binding: Option<ProviderBindingObservation>,
    pub now_micros: TimestampMicros,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequestCommand {
    pub request_id: String,
    pub admission_revision: Option<Revision>,
    pub now_micros: TimestampMicros,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRegistrationFailureCommand {
    pub request_id: String,
    pub admission_revision: Revision,
    pub reason: String,
    pub now_micros: TimestampMicros,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryOperatorBlockedCommand {
    pub request_id: String,
    pub expected_revision: Revision,
    /// Current provider workspace binding validated by the observation boundary. Unsupported
    /// observations are rejected; the policy never derives support from opaque
    /// fingerprint contents.
    pub provider_binding: ProviderBindingObservation,
    pub now_micros: TimestampMicros,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetireRuntimeOwnershipCommand {
    pub wake_target_id: String,
    pub now_micros: TimestampMicros,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetireRuntimeOwnershipBatchCommand {
    pub project_id: String,
    pub wake_target_ids: Vec<String>,
    pub now_micros: TimestampMicros,
    #[serde(default = "default_retention")]
    pub terminal_request_retention: u64,
}

fn default_retention() -> u64 {
    DEFAULT_RETENTION
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningCommand {
    SynchronizeDemand(SynchronizeDemandCommand),
    ApplyCapacityReservation(ApplyCapacityReservationCommand),
    AdmitNext(AdmitNextCommand),
    ProgressRequest(ProgressRequestCommand),
    RecordFailure(RecordFailureCommand),
    ConfirmRegistration(ConfirmRegistrationCommand),
    CancelRequest(CancelRequestCommand),
    CancelRegistrationFailure(CancelRegistrationFailureCommand),
    RetryOperatorBlocked(RetryOperatorBlockedCommand),
    RetireRuntimeOwnership(RetireRuntimeOwnershipCommand),
    RetireRuntimeOwnershipBatch(RetireRuntimeOwnershipBatchCommand),
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", content = "payload")]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningOutcome {
    Noop,
    DemandSynchronized {
        project_id: String,
        spawn_needed: u64,
    },
    CapacityReserved {
        project_id: String,
        spawn_needed: u64,
    },
    Admitted {
        request_id: String,
        admission_revision: Revision,
    },
    Progressed {
        request_id: String,
        status: ProvisioningRequestStatus,
    },
    FailureRecorded {
        request_id: String,
        status: ProvisioningRequestStatus,
        retry_after_micros: Option<u64>,
    },
    Registered {
        request_id: String,
    },
    Cancelled {
        request_id: String,
    },
    Retried {
        request_id: String,
    },
    Retired {
        request_id: Option<String>,
        changed: bool,
    },
    BatchRetired {
        request_ids: Vec<String>,
        changed: bool,
    },
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningDecision {
    pub snapshot: ProvisioningSnapshot,
    pub outcome: ProvisioningOutcome,
}
