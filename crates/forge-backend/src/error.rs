//! Typed error envelope mapping.
//!
//! The mapping table is derived from the live forge-control typed error codes
//! (`ControlErrorCode` + `ControlErrorView`) and client-side admission errors
//! (`ControlClientError`). Unknown or unmapped failures collapse to
//! `FORGE_UNAVAILABLE` with the internal category; they never panic and never
//! expose adapter internals.

use std::time::Duration;

use forge_control::{ControlClientError, ControlErrorCode, ControlErrorView};
use serde::Serialize;
use uuid::Uuid;

/// Fixed wire error codes carried by failure envelopes.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    ForgeUnavailable,
    AuthFailed,
    WorkspaceConfinementDenied,
    WorkspaceScopeOverlap,
    WorkspaceRootConflict,
    WorkspaceIdentityConflict,
    WorkspaceRemovalBlocked,
    InvalidPathKind,
    StaleRevision,
    LeaseConflict,
    SourceConflict,
    PlanningConflict,
    ResyncRequired,
    UnknownOutcome,
    InvalidInput,
    CapacityExceeded,
    DependencyUnavailable,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForgeUnavailable => "FORGE_UNAVAILABLE",
            Self::AuthFailed => "AUTH_FAILED",
            Self::WorkspaceConfinementDenied => "WORKSPACE_CONFINEMENT_DENIED",
            Self::WorkspaceScopeOverlap => "WORKSPACE_SCOPE_OVERLAP",
            Self::WorkspaceRootConflict => "WORKSPACE_ROOT_CONFLICT",
            Self::WorkspaceIdentityConflict => "WORKSPACE_IDENTITY_CONFLICT",
            Self::WorkspaceRemovalBlocked => "WORKSPACE_REMOVAL_BLOCKED",
            Self::InvalidPathKind => "INVALID_PATH_KIND",
            Self::StaleRevision => "STALE_REVISION",
            Self::LeaseConflict => "LEASE_CONFLICT",
            Self::SourceConflict => "SOURCE_CONFLICT",
            Self::PlanningConflict => "PLANNING_CONFLICT",
            Self::ResyncRequired => "RESYNC_REQUIRED",
            Self::UnknownOutcome => "UNKNOWN_OUTCOME",
            Self::InvalidInput => "INVALID_INPUT",
            Self::CapacityExceeded => "CAPACITY_EXCEEDED",
            Self::DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Redacted failure body. `message` is always a stable, server-owned summary;
/// adapter, filesystem, SQL, or secret details never cross this boundary.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ForgeError {
    code: ErrorCode,
    message: String,
    category: String,
    retryable: bool,
    recovery_action: String,
    recovery_hint: String,
    readback: Option<Box<ReadbackHint>>,
}

/// Readback guidance pointing at one validated durable identity.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReadbackHint {
    HomeTransferSource {
        workspace_id: Uuid,
        preparation_id: Uuid,
        request_digest: String,
    },
    HomeTransferReservationRetirement {
        scope: crate::ops::ScopeDto,
        issuer: Uuid,
        backend_id: Uuid,
        destination_id: Uuid,
        preparation_id: Uuid,
        reservation_request_id: Uuid,
        request_digest: String,
    },
    EvaluationEvidence {
        workspace_id: Uuid,
        identity: EvaluationEvidenceReadbackIdentity,
    },
    AgentOperationsFreeze {
        workspace_id: Uuid,
        migration_id: Uuid,
        destination_id: Uuid,
        operation: AgentOperationsFreezeReadbackOperation,
        expected_revision: Option<u64>,
        observed_at_ms: i64,
    },
    WorkCut {
        workspace_id: Uuid,
        cut_id: Uuid,
        request_digest: String,
    },
    RecoveryMaintenance {
        workspace_id: Uuid,
        request_id: Uuid,
        request_digest: String,
    },
    LocationState {
        location_id: Uuid,
        expected_revision: i64,
        desired_state: String,
    },
    LocationRemoval {
        location_id: Uuid,
        expected_revision: i64,
        mode: LocationRemovalReadbackMode,
        expected_root_fingerprint: Option<String>,
        expected_state: Option<LocationRemovalReadbackState>,
    },
    RecoveryLease {
        workspace_id: Uuid,
        owner_id: Uuid,
        operation: RecoveryLeaseReadbackOperation,
        expected_epoch: Option<i64>,
        expected_revision: Option<i64>,
        duration_ms: Option<i64>,
    },
    ActivityBootstrap {
        workspace_id: Uuid,
        activity_id: Uuid,
        runtime_instance_id: Uuid,
    },
    ActivityLeaseBatch {
        workspace_id: Uuid,
        operation: ActivityLeaseReadbackOperation,
        leases: Vec<ActivityLeaseReadbackKey>,
    },
    WorkspaceQueueSettings {
        workspace_id: Uuid,
        expected_preference_revision: Option<u64>,
        requested_capacity: u16,
    },
    AgentDelegation {
        workspace_id: Uuid,
        migration_id: Uuid,
        destination_id: Uuid,
        expected_freeze_revision: u64,
        manifest_digest: String,
    },
    AgentBindingReservation {
        workspace_id: Uuid,
        destination_id: Uuid,
        request_id: Uuid,
        session_id: Uuid,
    },
    AgentBindingActivation {
        workspace_id: Uuid,
        destination_id: Uuid,
        request_id: Uuid,
        session_id: Uuid,
    },
    AgentBindingRejection {
        workspace_id: Uuid,
        destination_id: Uuid,
        request_id: Uuid,
        request_digest: String,
        session_id: Uuid,
    },
    AgentSessionReconciliation {
        workspace_id: Uuid,
        destination_id: Uuid,
        request_id: Uuid,
        session_id: Uuid,
    },
    AgentDepartureReconciliation {
        workspace_id: Uuid,
        destination_id: Uuid,
        request_id: Uuid,
        session_id: Uuid,
    },
    ActivityLifecycle {
        workspace_id: Uuid,
        activity_id: Uuid,
        runtime_instance_id: Uuid,
        expected_lease_revision: i64,
    },
    WorkspaceRegistration {
        locator: String,
        proposed_workspace_id: Uuid,
        expected_root_fingerprint: String,
    },
    WorkspaceRootRecovery {
        locator: String,
        request_id: Uuid,
        location_revision: i64,
        expected_workspace_id: Uuid,
        expected_workspace_revision: i64,
        expected_root_path_base64: String,
        expected_root_fingerprint: String,
        expected_created_at_ms: i64,
        expected_updated_at_ms: i64,
        observed_root_path_base64: String,
        observed_root_fingerprint: String,
        observed_witness: String,
        observed_at_ms: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        authority_mode: Option<serde_json::Value>,
    },
    GoalDeletion {
        workspace_id: Uuid,
        activity_id: Uuid,
        goal_id: Uuid,
        target: GoalDeletionReadbackTarget,
        goal_created_at_ms: i64,
        expected_goal_revision: i64,
        expected_dag_head_revision: Option<i64>,
    },
    GoalMutation {
        workspace_id: Uuid,
        activity_id: Uuid,
        goal_id: Uuid,
        mutation_request_id: Uuid,
        request_digest: String,
    },
    DagPlan {
        workspace_id: Uuid,
        activity_id: Uuid,
        goal_id: Uuid,
        plan_request_id: Uuid,
        draft_digest: String,
    },
    Execution {
        execution_id: Uuid,
    },
    Approval {
        workspace_id: Uuid,
        approval_id: Uuid,
        grant_id: Option<Uuid>,
    },
    WorkspaceStop {
        workspace_id: Uuid,
        stop_id: Uuid,
        durable_request_id: Uuid,
        request_digest: String,
        runtime_instance_id: Uuid,
    },
    WriterLease {
        writer_lease_id: Uuid,
    },
    ExpiredActivityRecovery {
        workspace_id: Uuid,
        request_id: Uuid,
        request_digest: String,
        workspace_root_fingerprint: String,
        binding_digest: String,
        delegation_migration_id: Uuid,
        delegation_destination_id: Uuid,
        delegation_freeze_revision: u64,
        delegation_digest: String,
        service_backend_id: Uuid,
        service_issuer_id: Uuid,
        service_runtime_instance_id: Uuid,
        predecessor_activity_id: Uuid,
        successor_activity_id: Uuid,
    },
    UnstartedActivityContinuation {
        workspace_id: Uuid,
        request_id: Uuid,
        request_digest: String,
        activity_id: Uuid,
    },
    StartedActivityLeaseResume {
        scope: crate::ops::ScopeDto,
        request_id: Uuid,
        request_digest: String,
        activity_id: Uuid,
        agent_id: Uuid,
        initiating_session_id: Uuid,
        principal: PrincipalReadback,
    },
    QuiescentActivityLeaseResume {
        scope: crate::ops::ScopeDto,
        request_id: Uuid,
        request_digest: String,
        activity_id: Uuid,
        agent_id: Uuid,
        initiating_session_id: Uuid,
        principal: PrincipalReadback,
    },
}

/// Closed transport identity mirroring the native evaluation mutation cases.
/// It intentionally carries identity only; an absent T1 cut does not certify
/// that a closure attempt had no durable clock-health effect.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvaluationEvidenceReadbackIdentity {
    Manifest {
        manifest_id: Uuid,
        revision: i64,
        digest: String,
    },
    Submission {
        assignment_id: Uuid,
        submitted_revision: i64,
    },
    Review {
        assignment_id: Uuid,
        submitted_revision: i64,
        review_revision: i64,
    },
    T1Closure {
        cut_id: Uuid,
        manifest_id: Uuid,
        manifest_revision: i64,
        manifest_digest: String,
        deadline_ms: i64,
    },
    ReviewCut {
        review_cut_id: Uuid,
        t1_cut_id: Uuid,
    },
}

/// Closed principal identity in immutable recovery readback guidance.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalReadbackKind {
    TrustedStdio,
    DirectToken,
    #[serde(rename = "oauth_grant")]
    OAuthGrant,
}

/// Both nullable identities remain explicit in the Source output contract.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct PrincipalReadback {
    pub kind: PrincipalReadbackKind,
    pub token_id: Option<Uuid>,
    pub grant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentOperationsFreezeReadbackOperation {
    Freeze,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocationRemovalReadbackMode {
    ListOnly,
    DeleteState,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LocationRemovalReadbackState {
    Absent,
    Uninitialized,
    Workspace {
        workspace_id: Uuid,
        workspace_revision: i64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLeaseReadbackOperation {
    Claim,
    Renew,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityLeaseReadbackOperation {
    Renew,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct ActivityLeaseReadbackKey {
    pub activity_id: Uuid,
    pub runtime_instance_id: Uuid,
    pub expected_lease_revision: i64,
}

impl ReadbackHint {
    pub fn home_transfer_reservation_retirement(
        command: &forge_control::HomeTransferSourceCommand,
        request: &forge_domain::HomeTransferReservationRetirementRequest,
    ) -> Option<Self> {
        let scope = &command.scope;
        let locator = scope.locator();
        let relative_root = locator.relative_root().to_str()?.to_owned();
        Some(Self::HomeTransferReservationRetirement {
            scope: crate::ops::ScopeDto {
                workspace_id: scope.workspace_id().into_uuid(),
                workspace_revision: scope.workspace_revision().get(),
                locator: crate::ops::LocatorDto {
                    location_id: locator.location_id().into_uuid(),
                    expected_revision: locator.expected_revision().get(),
                    relative_root,
                },
            },
            issuer: command.service.issuer.into_uuid(),
            backend_id: command.service.backend_id.into_uuid(),
            destination_id: command.service.destination_id,
            preparation_id: request.preparation_id(),
            reservation_request_id: request.reservation_request_id(),
            request_digest: hex_digest(request.request_digest().as_bytes()),
        })
    }

    pub fn evaluation_evidence(
        workspace_id: Uuid,
        identity: &forge_persistence::EvaluationEvidenceMutationIdentity,
    ) -> Self {
        use forge_persistence::EvaluationEvidenceMutationIdentity as Identity;
        let identity = match identity {
            Identity::Manifest {
                manifest_id,
                revision,
                digest,
            } => EvaluationEvidenceReadbackIdentity::Manifest {
                manifest_id: manifest_id.into_uuid(),
                revision: revision.get(),
                digest: hex_digest(digest.as_bytes()),
            },
            Identity::Submission {
                assignment_id,
                submitted_revision,
            } => EvaluationEvidenceReadbackIdentity::Submission {
                assignment_id: assignment_id.into_uuid(),
                submitted_revision: submitted_revision.get(),
            },
            Identity::Review {
                assignment_id,
                submitted_revision,
                review_revision,
            } => EvaluationEvidenceReadbackIdentity::Review {
                assignment_id: assignment_id.into_uuid(),
                submitted_revision: submitted_revision.get(),
                review_revision: review_revision.get(),
            },
            Identity::T1Closure { request } => EvaluationEvidenceReadbackIdentity::T1Closure {
                cut_id: request.cut_id().into_uuid(),
                manifest_id: request.manifest_id().into_uuid(),
                manifest_revision: request.manifest_revision().get(),
                manifest_digest: hex_digest(request.manifest_digest().as_bytes()),
                deadline_ms: request.deadline().get(),
            },
            Identity::ReviewCut {
                review_cut_id,
                t1_cut_id,
            } => EvaluationEvidenceReadbackIdentity::ReviewCut {
                review_cut_id: review_cut_id.into_uuid(),
                t1_cut_id: t1_cut_id.into_uuid(),
            },
        };
        Self::EvaluationEvidence {
            workspace_id,
            identity,
        }
    }

    pub fn goal_deletion(request: forge_domain::GoalDeletionRequest) -> Self {
        Self::GoalDeletion {
            workspace_id: request.workspace_id().into_uuid(),
            activity_id: request.activity_id().into_uuid(),
            goal_id: request.goal_id().into_uuid(),
            target: match request.target() {
                forge_domain::GoalDeletionTarget::Goal => GoalDeletionReadbackTarget::Goal,
                forge_domain::GoalDeletionTarget::Dag => GoalDeletionReadbackTarget::Dag,
            },
            goal_created_at_ms: request.goal_created_at().get(),
            expected_goal_revision: request.expected_goal_revision().get(),
            expected_dag_head_revision: request
                .expected_dag_head_revision()
                .map(forge_domain::DagHeadRevision::get),
        }
    }

    pub const fn execution(execution_id: Uuid) -> Self {
        Self::Execution { execution_id }
    }

    pub const fn approval(workspace_id: Uuid, approval_id: Uuid, grant_id: Option<Uuid>) -> Self {
        Self::Approval {
            workspace_id,
            approval_id,
            grant_id,
        }
    }

    pub const fn writer_lease(writer_lease_id: Uuid) -> Self {
        Self::WriterLease { writer_lease_id }
    }
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ignored = write!(output, "{byte:02x}");
    }
    output
}

/// Closed wire representation of the original deletion target.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoalDeletionReadbackTarget {
    Goal,
    Dag,
}

impl ForgeError {
    fn new(
        code: ErrorCode,
        message: impl Into<String>,
        category: &str,
        retryable: bool,
        recovery_action: &str,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            category: category.to_owned(),
            retryable,
            recovery_action: recovery_action.to_owned(),
            recovery_hint: String::new(),
            readback: None,
        }
    }

    /// Typed invalid-input rejection raised before admission.
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::InvalidInput,
            message,
            "input_validation",
            false,
            "correct_input",
        )
    }

    /// Typed authentication failure (bearer or session proof). Fail-closed.
    pub fn auth_failed() -> Self {
        Self::new(
            ErrorCode::AuthFailed,
            "authentication failed",
            "authentication",
            false,
            "authenticate",
        )
    }

    /// Typed capacity rejection raised before admission; retry with backoff.
    pub fn capacity_exceeded(bound: &str) -> Self {
        let mut error = Self::new(
            ErrorCode::CapacityExceeded,
            "the requested boundary is at capacity",
            "capacity",
            true,
            "wait_for_capacity",
        );
        error.recovery_hint =
            format!("the {bound} bound is saturated; retry after bounded backoff");
        error
    }

    /// Unknown outcome: the command was admitted to the bridge but the caller
    /// deadline (or connection) elapsed before a result was observed. The
    /// durable effect may exist; read back by the supplied durable identity,
    /// never blind retry.
    pub fn unknown_outcome(readback: Option<ReadbackHint>) -> Self {
        let mut error = Self::new(
            ErrorCode::UnknownOutcome,
            "the command outcome is unknown; the admitted effect may have committed",
            "unknown_outcome",
            false,
            "read_back",
        );
        error.readback = readback.map(Box::new);
        error
    }

    /// Typed resync rejection for event cursors behind the retention floor.
    pub fn resync_required(message: impl Into<String>) -> Self {
        let mut error = Self::new(
            ErrorCode::ResyncRequired,
            message,
            "resync_required",
            false,
            "resync",
        );
        "apply a fresh snapshot and replay from its watermark".clone_into(&mut error.recovery_hint);
        error
    }

    /// Unknown or unmapped internal failure; never a panic, never details.
    pub fn internal() -> Self {
        Self::new(
            ErrorCode::ForgeUnavailable,
            "the control service encountered an internal failure",
            "internal",
            false,
            "read_back",
        )
    }

    /// Typed external-dependency unavailability: the affected operation was
    /// not admitted, no durable effect exists, and the same request may be
    /// retried once the dependency recovers. Unrelated reads stay available.
    pub fn dependency_unavailable() -> Self {
        let mut error = Self::new(
            ErrorCode::DependencyUnavailable,
            "the required external session authority is unavailable",
            "dependency_unavailable",
            true,
            "retry_when_available",
        );
        error.recovery_hint = "the configured session authority did not respond; \
                               retry after it recovers; no durable effect was committed"
            .into();
        error
    }

    /// Map one live control error view into the typed envelope table.
    pub fn from_control_view(view: &ControlErrorView) -> Self {
        if matches!(
            view.details(),
            forge_control::ControlErrorDetails::WorkspaceRegistrationUnknown
        ) {
            return Self::unknown_outcome(None);
        }
        // The remote session authority being unreachable is a distinct fault
        // domain: retryable, no-effect, and never collapsed into generic
        // FORGE_UNAVAILABLE.
        if view.code() == forge_control::ControlErrorCode::AgentSessionAuthorityUnavailable {
            return Self::dependency_unavailable();
        }
        let code = match view.code() {
            ControlErrorCode::WorkspaceRemovalBlocked => ErrorCode::WorkspaceRemovalBlocked,
            ControlErrorCode::AuthorizationRequired => ErrorCode::AuthFailed,
            ControlErrorCode::InvalidInput | ControlErrorCode::RequestCancelled => {
                ErrorCode::InvalidInput
            }
            ControlErrorCode::FilePathDenied => ErrorCode::WorkspaceConfinementDenied,
            ControlErrorCode::WorkspaceScopeOverlap => ErrorCode::WorkspaceScopeOverlap,
            ControlErrorCode::WorkspaceRootConflict => ErrorCode::WorkspaceRootConflict,
            ControlErrorCode::WorkspaceIdentityConflict => ErrorCode::WorkspaceIdentityConflict,
            ControlErrorCode::InvalidPathKind => ErrorCode::InvalidPathKind,
            ControlErrorCode::LocationRevisionConflict
            | ControlErrorCode::WorkspaceRevisionConflict
            | ControlErrorCode::WorkspaceQueueSettingsConflict => ErrorCode::StaleRevision,
            ControlErrorCode::ActivityLeaseConflict
            | ControlErrorCode::WriterLeaseNotFound
            | ControlErrorCode::WriterLeaseConflict
            | ControlErrorCode::WriterLeaseRecoveryRequired
            | ControlErrorCode::RecoveryLeaseConflict => ErrorCode::LeaseConflict,
            ControlErrorCode::FileConflict => ErrorCode::SourceConflict,
            ControlErrorCode::GoalConflict
            | ControlErrorCode::GoalNotFound
            | ControlErrorCode::GoalCompletionBlocked
            | ControlErrorCode::GoalEvidenceConflict
            | ControlErrorCode::AgentDagPlanConflict
            | ControlErrorCode::AgentDagReplayConflict
            | ControlErrorCode::HomeTransferFenced
            | ControlErrorCode::CoordinatorNotFound
            | ControlErrorCode::CoordinatorConflict => ErrorCode::PlanningConflict,
            ControlErrorCode::ProjectionResyncRequired => ErrorCode::ResyncRequired,
            ControlErrorCode::CapacityExceeded | ControlErrorCode::FileCapacityExceeded => {
                ErrorCode::CapacityExceeded
            }
            ControlErrorCode::CommittedButUnconfirmed => ErrorCode::UnknownOutcome,
            // Every remaining control family lands on the unavailable bucket
            // with the control category preserved as the coarse reason.
            _ => ErrorCode::ForgeUnavailable,
        };
        Self::new(
            code,
            view.summary(),
            category_str(view),
            view.retryable(),
            recovery_str(view),
        )
    }

    /// Preserve uncertainty from the admitted execution owner so HTTP can
    /// attach the command's exact execution readback identity.
    pub fn from_admitted_execution_view(view: &ControlErrorView) -> Self {
        if view.code() == ControlErrorCode::AgentSessionAuthorityUnavailable {
            return Self::dependency_unavailable();
        }
        match view.outcome() {
            forge_control::ControlOperationOutcome::NotAdmitted => Self::from_control_view(view),
            forge_control::ControlOperationOutcome::Unknown
            | forge_control::ControlOperationOutcome::CommittedButUnconfirmed => {
                Self::unknown_outcome(None)
            }
        }
    }

    /// Map one bridge transport failure (queue/closed/dropped response).
    pub fn from_control_client_error(error: &ControlClientError) -> Self {
        match error {
            ControlClientError::QueueFull => Self::capacity_exceeded("control worker queue"),
            ControlClientError::WorkerShuttingDown => Self::new(
                ErrorCode::ForgeUnavailable,
                ControlErrorCode::WorkerShuttingDown.summary(),
                "runtime_availability",
                false,
                "reconnect",
            ),
            ControlClientError::WorkerClosed => Self::new(
                ErrorCode::ForgeUnavailable,
                ControlErrorCode::WorkerClosed.summary(),
                "runtime_availability",
                false,
                "reconnect",
            ),
            ControlClientError::ResponseDropped => {
                let mut mapped = Self::unknown_outcome(None);
                mapped.message = "the admitted command response was lost before delivery".into();
                mapped
            }
            ControlClientError::Service(service) => Self::from_control_view(&service.view()),
        }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn recovery_action(&self) -> &str {
        &self.recovery_action
    }

    pub fn recovery_hint(&self) -> &str {
        &self.recovery_hint
    }

    pub fn readback(&self) -> Option<&ReadbackHint> {
        self.readback.as_deref()
    }

    /// Attach the command's validated durable identity readback hint.
    pub fn with_readback(mut self, readback: Option<ReadbackHint>) -> Self {
        self.readback = readback.map(Box::new);
        self
    }

    /// Deadline helper shared by the bridge and HTTP timeouts.
    pub const fn deadline_elapsed(deadline: Duration) -> bool {
        !deadline.is_zero()
    }
}

fn category_str(view: &ControlErrorView) -> &'static str {
    use forge_control::ControlErrorCategory as Category;
    match view.category() {
        Category::InputValidation => "input_validation",
        Category::Authentication => "authentication",
        Category::Cancellation => "cancellation",
        Category::WorkspaceState => "workspace_state",
        Category::RevisionConflict => "revision_conflict",
        Category::Lease => "lease",
        Category::Capacity => "capacity",
        Category::RuntimeAvailability => "runtime_availability",
        Category::CapabilitySurface => "capability_surface",
        Category::PathConfinement => "path_confinement",
        Category::SourcePrecondition => "source_precondition",
        Category::Evidence => "evidence",
        Category::Execution => "execution",
        Category::Approval => "approval",
        Category::WorkState => "work_state",
        Category::RecoveryRequired => "recovery_required",
        Category::Authority => "authority",
        Category::Internal => "internal",
    }
}

fn recovery_str(view: &ControlErrorView) -> &'static str {
    use forge_control::ControlRecoveryAction as Action;
    match view.recovery_action() {
        Action::CorrectInput => "correct_input",
        Action::Authenticate => "authenticate",
        Action::DoNotRetry => "do_not_retry",
        Action::WaitForCapacity => "wait_for_capacity",
        Action::ReduceRequest => "reduce_request",
        Action::Reconnect => "reconnect",
        Action::RefreshWorkspace => "refresh_workspace",
        Action::InspectWorkspace => "inspect_workspace",
        Action::RefreshWork => "refresh_work",
        Action::ReadSource => "read_source",
        Action::InspectAdmission => "inspect_admission",
        Action::InspectActivity => "inspect_activity",
        Action::InspectLease => "inspect_lease",
        Action::InspectExecution => "inspect_execution",
        Action::InspectApproval => "inspect_approval",
        Action::InspectEvidence => "inspect_evidence",
        Action::InspectSession => "inspect_session",
        Action::InspectReplay => "inspect_replay",
        Action::RefreshCapabilities => "refresh_capabilities",
        Action::InspectRuntime => "inspect_runtime",
        Action::ReadBack => "read_back",
    }
}

impl std::fmt::Display for ForgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message.as_str())
    }
}

impl std::error::Error for ForgeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_rejections_preserve_identity_through_the_http_code_contract() {
        for (source, expected) in [
            (
                ControlErrorCode::FilePathDenied,
                ErrorCode::WorkspaceConfinementDenied,
            ),
            (
                ControlErrorCode::WorkspaceScopeOverlap,
                ErrorCode::WorkspaceScopeOverlap,
            ),
            (
                ControlErrorCode::InvalidPathKind,
                ErrorCode::InvalidPathKind,
            ),
        ] {
            let view = ControlErrorView::from_service(source, false);
            let mapped = ForgeError::from_control_view(&view);
            assert_eq!(mapped.code(), expected);
            assert_eq!(mapped.message(), view.summary());
            assert_eq!(mapped.category(), "path_confinement");
            assert!(!mapped.retryable());
            assert_eq!(
                crate::client::ForgeHttpServiceCode::from_wire_code(mapped.code().as_str())
                    .as_str(),
                expected.as_str()
            );
        }
    }

    #[test]
    fn session_authority_unavailability_is_a_distinct_retryable_no_effect_code() {
        let view = ControlErrorView::from_service(
            ControlErrorCode::AgentSessionAuthorityUnavailable,
            false,
        );
        let mapped = ForgeError::from_control_view(&view);
        assert_eq!(mapped.code(), ErrorCode::DependencyUnavailable);
        assert_eq!(mapped.category(), "dependency_unavailable");
        assert!(mapped.retryable(), "the operation never started");
        assert_eq!(mapped.recovery_action(), "retry_when_available");
        assert!(mapped.readback().is_none());
        // Session-identity failures keep their distinct non-retryable codes.
        let conflict = ForgeError::from_control_view(&ControlErrorView::from_service(
            ControlErrorCode::AgentSessionConflict,
            false,
        ));
        assert_eq!(conflict.code(), ErrorCode::ForgeUnavailable);
    }

    #[test]
    fn approval_unknown_outcome_keeps_exact_readback_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = Uuid::from_u128(1);
        let approval_id = Uuid::from_u128(2);
        let grant_id = Uuid::from_u128(3);
        let error = ForgeError::unknown_outcome(Some(ReadbackHint::approval(
            workspace_id,
            approval_id,
            Some(grant_id),
        )));
        let wire = serde_json::to_value(&error)?;
        assert_eq!(wire["code"], "UNKNOWN_OUTCOME");
        assert_eq!(wire["readback"]["kind"], "approval");
        assert_eq!(wire["readback"]["workspace_id"], workspace_id.to_string());
        assert_eq!(wire["readback"]["approval_id"], approval_id.to_string());
        assert_eq!(wire["readback"]["grant_id"], grant_id.to_string());
        Ok(())
    }

    #[test]
    fn evaluation_t1_readback_keeps_frozen_manifest_and_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = Uuid::from_u128(0x101);
        let identity = forge_persistence::EvaluationEvidenceMutationIdentity::T1Closure {
            request: forge_domain::EvaluationT1CloseRequest::new(
                forge_domain::EvaluationCutId::new(Uuid::from_u128(0x102))?,
                forge_domain::EvaluationManifestId::new(Uuid::from_u128(0x103))?,
                forge_domain::EvaluationRevision::new(4)?,
                forge_domain::EvaluationDigest::new([0x44; 32])?,
                forge_domain::TimestampMillis::new(900)?,
            ),
        };
        let error = ForgeError::unknown_outcome(Some(ReadbackHint::evaluation_evidence(
            workspace_id,
            &identity,
        )));
        let wire = serde_json::to_value(&error)?;
        assert_eq!(wire["readback"]["kind"], "evaluation_evidence");
        assert_eq!(wire["readback"]["workspace_id"], workspace_id.to_string());
        assert_eq!(wire["readback"]["identity"]["kind"], "t1_closure");
        assert_eq!(
            wire["readback"]["identity"]["cut_id"],
            Uuid::from_u128(0x102).to_string()
        );
        assert_eq!(
            wire["readback"]["identity"]["manifest_id"],
            Uuid::from_u128(0x103).to_string()
        );
        assert_eq!(wire["readback"]["identity"]["manifest_revision"], 4);
        assert_eq!(
            wire["readback"]["identity"]["manifest_digest"],
            "44".repeat(32)
        );
        assert_eq!(wire["readback"]["identity"]["deadline_ms"], 900);
        assert!(wire["readback"]["no_effect"].is_null());
        Ok(())
    }

    #[test]
    fn retirement_unknown_outcome_carries_exact_get_scope_service_and_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = Uuid::from_u128(0x201);
        let location_id = Uuid::from_u128(0x202);
        let preparation_id = Uuid::from_u128(0x203);
        let reservation_request_id = Uuid::from_u128(0x204);
        let backend_id = Uuid::from_u128(0x205);
        let destination_id = Uuid::from_u128(0x206);
        let issuer = Uuid::from_u128(0x207);
        let hint = ReadbackHint::HomeTransferReservationRetirement {
            scope: crate::ops::ScopeDto {
                workspace_id,
                workspace_revision: 9,
                locator: crate::ops::LocatorDto {
                    location_id,
                    expected_revision: 3,
                    relative_root: ".".to_owned(),
                },
            },
            issuer,
            backend_id,
            destination_id,
            preparation_id,
            reservation_request_id,
            request_digest: "a5".repeat(32),
        };
        let wire = serde_json::to_value(ForgeError::unknown_outcome(Some(hint)))?;
        assert_eq!(wire["code"], "UNKNOWN_OUTCOME");
        assert_eq!(
            wire["readback"]["kind"],
            "home_transfer_reservation_retirement"
        );
        assert_eq!(
            wire["readback"]["scope"]["workspace_id"],
            workspace_id.to_string()
        );
        assert_eq!(wire["readback"]["scope"]["workspace_revision"], 9);
        assert_eq!(
            wire["readback"]["scope"]["locator"]["location_id"],
            location_id.to_string()
        );
        assert_eq!(wire["readback"]["scope"]["locator"]["expected_revision"], 3);
        assert_eq!(wire["readback"]["scope"]["locator"]["relative_root"], ".");
        assert_eq!(wire["readback"]["issuer"], issuer.to_string());
        assert_eq!(wire["readback"]["backend_id"], backend_id.to_string());
        assert_eq!(
            wire["readback"]["destination_id"],
            destination_id.to_string()
        );
        assert_eq!(
            wire["readback"]["preparation_id"],
            preparation_id.to_string()
        );
        assert_eq!(
            wire["readback"]["reservation_request_id"],
            reservation_request_id.to_string()
        );
        assert_eq!(wire["readback"]["request_digest"], "a5".repeat(32));
        assert!(wire["readback"].get("bearer").is_none());
        Ok(())
    }
}
