use std::error::Error;
use std::fmt;

use forge_domain::{ActivityId, ApprovalRequestId, ExecutionId, FileEntryKind, WriterLeaseId};

const PROJECTION_RESYNC_REQUIRED_SUMMARY: &str = "the operational projection cannot continue from its durable source cursor and requires resynchronization";

/// Stable machine-readable application-control error category.
///
/// Detailed codes and their derived guidance are remote-safe. Underlying
/// adapter errors are retained as a private source for
/// local diagnostics, but are never included in [`std::fmt::Display`] or the redacted
/// view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ControlErrorCode {
    InvalidInput = 1000,
    AuthorizationRequired = 1004,
    RequestCancelled = 1005,
    ToolUnavailable = 1006,
    LocationNotFound = 1001,
    LocationRevisionConflict = 1002,
    LocationUnavailable = 1003,
    WorkspaceNotFound = 1100,
    WorkspaceNotInitialized = 1101,
    WorkspaceStateUnavailable = 1102,
    WorkspaceIdentityConflict = 1103,
    WorkspaceRevisionConflict = 1104,
    WorkspaceRootConflict = 1105,
    WorkspaceSchemaOutdated = 1106,
    WorkspaceQueueSettingsConflict = 1107,
    WorkspaceRemovalBlocked = 1108,
    ActivityNotFound = 1200,
    ActivityConflict = 1201,
    ActivityLeaseConflict = 1202,
    PersistenceFailure = 1300,
    CommittedButUnconfirmed = 1301,
    ProjectionResyncRequired = 1302,
    CapacityExceeded = 1400,
    WorkerClosed = 1401,
    WorkerShuttingDown = 1402,
    WorkspaceScopeOverlap = 1500,
    FilePathDenied = 1501,
    FileNotFound = 1502,
    FileConflict = 1503,
    FileCapacityExceeded = 1504,
    /// The caller's whole-file CAS digest did not match the observed source.
    FileWholeHashConflict = 1505,
    /// The caller's line range/context digest did not match the observed source.
    FileRangeConflict = 1506,
    /// A source-edit operation targeted non-text bytes.
    FileSourceNotText = 1507,
    /// A read-only source slice ended beyond the observed file bounds.
    FileReadRangeOutOfBounds = 1508,
    /// A source operation expected a different filesystem object kind.
    InvalidPathKind = 1509,
    DiffNotFound = 1600,
    DiffUnavailable = 1601,
    ExecutionNotFound = 1700,
    ExecutionConflict = 1701,
    RustCiToolchainUnavailable = 1702,
    ExecutionProvenanceConflict = 1703,
    /// The server-owned project command catalog changed after discovery.
    CommandCatalogChanged = 1704,
    ApprovalNotFound = 1800,
    ApprovalConflict = 1801,
    ApprovalExpired = 1802,
    GoalNotFound = 1850,
    GoalConflict = 1851,
    GoalCompletionBlocked = 1852,
    GoalEvidenceConflict = 1853,
    DagNotFound = 1860,
    DagConflict = 1861,
    RecoveryLeaseConflict = 1870,
    CheckpointNotFound = 1871,
    CheckpointStateConflict = 1874,
    CheckpointUnavailable = 1875,
    WriterLeaseNotFound = 1880,
    WriterLeaseConflict = 1881,
    WriterLeaseRecoveryRequired = 1882,
    AgentNotFound = 1890,
    AgentConflict = 1891,
    AgentFocusConflict = 1892,
    AgentEvidenceConflict = 1893,
    AgentDagPlanConflict = 1894,
    AgentDagReplayConflict = 1895,
    CoordinatorNotFound = 1896,
    CoordinatorConflict = 1897,
    WorkSelectionAmbiguous = 1898,
    AgentSessionNotFound = 1910,
    AgentSessionClosed = 1911,
    AgentSessionConflict = 1912,
    AgentSessionUnresolved = 1913,
    /// The configured external session authority did not answer. The affected
    /// operation was not admitted and no durable effect exists; unrelated
    /// reads stay available.
    AgentSessionAuthorityUnavailable = 1914,
    Internal = 1900,
}

impl ControlErrorCode {
    /// Stable wire/log label for this category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "CONTROL_INVALID_INPUT",
            Self::AuthorizationRequired => "CONTROL_AUTHORIZATION_REQUIRED",
            Self::RequestCancelled => "CONTROL_REQUEST_CANCELLED",
            Self::ToolUnavailable => "CONTROL_TOOL_UNAVAILABLE",
            Self::LocationNotFound => "CONTROL_LOCATION_NOT_FOUND",
            Self::LocationRevisionConflict => "CONTROL_LOCATION_REVISION_CONFLICT",
            Self::LocationUnavailable => "CONTROL_LOCATION_UNAVAILABLE",
            Self::WorkspaceNotFound => "CONTROL_WORKSPACE_NOT_FOUND",
            Self::WorkspaceNotInitialized => "CONTROL_WORKSPACE_NOT_INITIALIZED",
            Self::WorkspaceStateUnavailable => "CONTROL_WORKSPACE_STATE_UNAVAILABLE",
            Self::WorkspaceIdentityConflict => "CONTROL_WORKSPACE_IDENTITY_CONFLICT",
            Self::WorkspaceRevisionConflict => "CONTROL_WORKSPACE_REVISION_CONFLICT",
            Self::WorkspaceRootConflict => "CONTROL_WORKSPACE_ROOT_CONFLICT",
            Self::WorkspaceSchemaOutdated => "CONTROL_WORKSPACE_SCHEMA_OUTDATED",
            Self::WorkspaceQueueSettingsConflict => "CONTROL_WORKSPACE_QUEUE_SETTINGS_CONFLICT",
            Self::WorkspaceRemovalBlocked => "CONTROL_WORKSPACE_REMOVAL_BLOCKED",
            Self::ActivityNotFound => "CONTROL_ACTIVITY_NOT_FOUND",
            Self::ActivityConflict => "CONTROL_ACTIVITY_CONFLICT",
            Self::ActivityLeaseConflict => "CONTROL_ACTIVITY_LEASE_CONFLICT",
            Self::PersistenceFailure => "CONTROL_PERSISTENCE_FAILURE",
            Self::CommittedButUnconfirmed => "CONTROL_COMMITTED_BUT_UNCONFIRMED",
            Self::ProjectionResyncRequired => "CONTROL_PROJECTION_RESYNC_REQUIRED",
            Self::CapacityExceeded => "CONTROL_CAPACITY_EXCEEDED",
            Self::WorkerClosed => "CONTROL_WORKER_CLOSED",
            Self::WorkerShuttingDown => "CONTROL_WORKER_SHUTTING_DOWN",
            Self::WorkspaceScopeOverlap => "CONTROL_WORKSPACE_SCOPE_OVERLAP",
            Self::FilePathDenied => "CONTROL_FILE_PATH_DENIED",
            Self::FileNotFound => "CONTROL_FILE_NOT_FOUND",
            Self::FileConflict => "CONTROL_FILE_CONFLICT",
            Self::FileCapacityExceeded => "CONTROL_FILE_CAPACITY_EXCEEDED",
            Self::FileWholeHashConflict => "CONTROL_FILE_WHOLE_HASH_CONFLICT",
            Self::FileRangeConflict => "CONTROL_FILE_RANGE_CONFLICT",
            Self::FileSourceNotText => "CONTROL_FILE_SOURCE_NOT_TEXT",
            Self::FileReadRangeOutOfBounds => "CONTROL_FILE_READ_RANGE_OUT_OF_BOUNDS",
            Self::InvalidPathKind => "CONTROL_INVALID_PATH_KIND",
            Self::DiffNotFound => "CONTROL_DIFF_NOT_FOUND",
            Self::DiffUnavailable => "CONTROL_DIFF_UNAVAILABLE",
            Self::ExecutionNotFound => "CONTROL_EXECUTION_NOT_FOUND",
            Self::ExecutionConflict => "CONTROL_EXECUTION_CONFLICT",
            Self::RustCiToolchainUnavailable => "CONTROL_RUST_CI_TOOLCHAIN_UNAVAILABLE",
            Self::ExecutionProvenanceConflict => "CONTROL_EXECUTION_PROVENANCE_CONFLICT",
            Self::CommandCatalogChanged => "CONTROL_COMMAND_CATALOG_CHANGED",
            Self::ApprovalNotFound => "CONTROL_APPROVAL_NOT_FOUND",
            Self::ApprovalConflict => "CONTROL_APPROVAL_CONFLICT",
            Self::ApprovalExpired => "CONTROL_APPROVAL_EXPIRED",
            Self::GoalNotFound => "CONTROL_GOAL_NOT_FOUND",
            Self::GoalConflict => "CONTROL_GOAL_CONFLICT",
            Self::GoalCompletionBlocked => "CONTROL_GOAL_COMPLETION_BLOCKED",
            Self::GoalEvidenceConflict => "CONTROL_GOAL_EVIDENCE_CONFLICT",
            Self::DagNotFound => "CONTROL_DAG_NOT_FOUND",
            Self::DagConflict => "CONTROL_DAG_CONFLICT",
            Self::RecoveryLeaseConflict => "CONTROL_RECOVERY_LEASE_CONFLICT",
            Self::CheckpointNotFound => "CONTROL_CHECKPOINT_NOT_FOUND",
            Self::CheckpointStateConflict => "CONTROL_CHECKPOINT_STATE_CONFLICT",
            Self::CheckpointUnavailable => "CONTROL_CHECKPOINT_UNAVAILABLE",
            Self::WriterLeaseNotFound => "CONTROL_WRITER_LEASE_NOT_FOUND",
            Self::WriterLeaseConflict => "CONTROL_WRITER_LEASE_CONFLICT",
            Self::WriterLeaseRecoveryRequired => "CONTROL_WRITER_LEASE_RECOVERY_REQUIRED",
            Self::AgentNotFound => "CONTROL_AGENT_NOT_FOUND",
            Self::AgentConflict => "CONTROL_AGENT_CONFLICT",
            Self::AgentFocusConflict => "CONTROL_AGENT_FOCUS_CONFLICT",
            Self::AgentEvidenceConflict => "CONTROL_AGENT_EVIDENCE_CONFLICT",
            Self::AgentDagPlanConflict => "CONTROL_AGENT_DAG_PLAN_CONFLICT",
            Self::AgentDagReplayConflict => "CONTROL_AGENT_DAG_REPLAY_CONFLICT",
            Self::CoordinatorNotFound => "CONTROL_COORDINATOR_NOT_FOUND",
            Self::CoordinatorConflict => "CONTROL_COORDINATOR_CONFLICT",
            Self::WorkSelectionAmbiguous => "CONTROL_WORK_SELECTION_AMBIGUOUS",
            Self::AgentSessionNotFound => "CONTROL_AGENT_SESSION_NOT_FOUND",
            Self::AgentSessionClosed => "CONTROL_AGENT_SESSION_CLOSED",
            Self::AgentSessionConflict => "CONTROL_AGENT_SESSION_CONFLICT",
            Self::AgentSessionUnresolved => "CONTROL_AGENT_SESSION_UNRESOLVED",
            Self::AgentSessionAuthorityUnavailable => "CONTROL_AGENT_SESSION_AUTHORITY_UNAVAILABLE",
            Self::Internal => "CONTROL_INTERNAL",
        }
    }

    /// Redacted, stable human-readable summary.  It intentionally contains no
    /// path, SQL, UUID, or adapter-provided text.
    #[allow(
        clippy::too_many_lines,
        reason = "One arm per stable code keeps the redaction table reviewable."
    )]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::InvalidInput => "control input was invalid",
            Self::AuthorizationRequired => "authentication is required for this request",
            Self::RequestCancelled => "the control request was cancelled",
            Self::ToolUnavailable => "the requested tool is unavailable",
            Self::LocationNotFound => "the requested Location was not found",
            Self::LocationRevisionConflict => "the Location revision is stale",
            Self::LocationUnavailable => "the Location is unavailable",
            Self::WorkspaceNotFound => "the requested Workspace was not found",
            Self::WorkspaceNotInitialized => "the Workspace state is not initialized",
            Self::WorkspaceStateUnavailable => "the Workspace state is unavailable",
            Self::WorkspaceIdentityConflict => "the durable Workspace identity conflicts",
            Self::WorkspaceRevisionConflict => "the Workspace revision is stale",
            Self::WorkspaceRootConflict => "the Workspace root no longer matches",
            Self::WorkspaceSchemaOutdated => "the Workspace schema is outdated and unsupported",
            Self::WorkspaceQueueSettingsConflict => {
                "the Workspace queue preference changed; reload before saving again"
            }
            Self::WorkspaceRemovalBlocked => {
                "durable work or a maintenance fence blocks state removal"
            }
            Self::ActivityNotFound => "the requested Activity was not found",
            Self::ActivityConflict => "the Activity conflicts with durable state",
            Self::ActivityLeaseConflict => "the Activity lease is unavailable",
            Self::PersistenceFailure => "durable persistence failed",
            Self::CommittedButUnconfirmed => {
                "durable commit completed but could not be revalidated"
            }
            Self::ProjectionResyncRequired => PROJECTION_RESYNC_REQUIRED_SUMMARY,
            Self::CapacityExceeded => "the control queue is at capacity",
            Self::WorkerClosed => "the control worker is closed",
            Self::WorkerShuttingDown => "the control worker is shutting down",
            Self::WorkspaceScopeOverlap => "the Workspace effect scope overlaps another scope",
            Self::FilePathDenied => "the requested file path is denied",
            Self::FileNotFound => "the requested file was not found",
            Self::FileConflict => "the requested file effect conflicts with current state",
            Self::FileCapacityExceeded => "the requested file effect exceeds bounded capacity",
            Self::FileWholeHashConflict => "the source whole-file hash is stale",
            Self::FileRangeConflict => "the source range or patch context is stale",
            Self::FileSourceNotText => "the requested source is not valid text",
            Self::FileReadRangeOutOfBounds => {
                "the requested source read range exceeds the observed file bounds"
            }
            Self::InvalidPathKind => "the requested source path has an unexpected object kind",
            Self::DiffNotFound => "the requested Diff Evidence was not found",
            Self::DiffUnavailable => "the requested Diff Evidence is unavailable",
            Self::ExecutionNotFound => "the requested execution was not found",
            Self::ExecutionConflict => "the execution conflicts with durable state",
            Self::RustCiToolchainUnavailable => "the required Rust CI toolchain is unavailable",
            Self::ExecutionProvenanceConflict => {
                "the execution authority does not match durable provenance"
            }
            Self::CommandCatalogChanged => {
                "the server-owned project command catalog changed after discovery"
            }
            Self::ApprovalNotFound => "the requested approval was not found",
            Self::ApprovalConflict => "the approval conflicts with durable state",
            Self::ApprovalExpired => "the approval is expired",
            Self::GoalNotFound => "the requested Goal was not found",
            Self::GoalConflict => "the Goal conflicts with durable state",
            Self::GoalCompletionBlocked => "the Goal is blocked by required verification",
            Self::GoalEvidenceConflict => "the Goal evidence association conflicts",
            Self::DagNotFound => "the requested DAG revision or node was not found",
            Self::DagConflict => "the DAG revision, head, node, or lineage conflicts",
            Self::RecoveryLeaseConflict => {
                "the recovery-maintenance lease conflicts with durable state"
            }
            Self::CheckpointNotFound => "the requested checkpoint was not found",
            Self::CheckpointStateConflict => {
                "the current path state differs from the checkpoint POST state"
            }
            Self::CheckpointUnavailable => {
                "the checkpoint object store is unavailable for this workspace"
            }
            Self::WriterLeaseNotFound => "the requested Writer Lease was not found",
            Self::WriterLeaseConflict => "the Writer Lease conflicts with durable source authority",
            Self::WriterLeaseRecoveryRequired => {
                "the Writer Lease is expired or orphaned and requires explicit recovery"
            }
            Self::AgentNotFound => "the requested Agent instance was not found",
            Self::AgentConflict => "the Agent instance conflicts with durable state",
            Self::AgentFocusConflict => "the Agent focus conflicts with the current Goal or DAG",
            Self::AgentEvidenceConflict => {
                "the Agent public evidence reference conflicts with Workspace evidence"
            }
            Self::AgentDagPlanConflict => {
                "the Agent DAG plan conflicts with the current Goal or DAG head"
            }
            Self::AgentDagReplayConflict => {
                "the Agent DAG plan request conflicts with its replay ledger"
            }
            Self::CoordinatorNotFound => "the Activity planning Coordinator was not found",
            Self::CoordinatorConflict => "the Activity planning Coordinator fence conflicts",
            Self::WorkSelectionAmbiguous => {
                "multiple active Goal or DAG candidates are eligible for work reuse"
            }
            Self::Internal => "the control service encountered an internal failure",
            Self::AgentSessionNotFound => "the issued Agent session was not found",
            Self::AgentSessionClosed => "the Agent session is closed",
            Self::AgentSessionConflict => "the Agent session identity or principal conflicts",
            Self::AgentSessionUnresolved => "the historical Agent needs explicit session adoption",
            Self::AgentSessionAuthorityUnavailable => {
                "the external Agent session authority is unavailable"
            }
        }
    }
}

/// Coarse semantic classification; detailed control codes remain stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlErrorCategory {
    InputValidation,
    Authentication,
    Cancellation,
    WorkspaceState,
    RevisionConflict,
    Lease,
    Capacity,
    RuntimeAvailability,
    CapabilitySurface,
    PathConfinement,
    SourcePrecondition,
    Evidence,
    Execution,
    Approval,
    WorkState,
    RecoveryRequired,
    Authority,
    Internal,
}

impl ControlErrorCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputValidation => "input_validation",
            Self::Authentication => "authentication",
            Self::Cancellation => "cancellation",
            Self::WorkspaceState => "workspace_state",
            Self::RevisionConflict => "revision_conflict",
            Self::Lease => "lease",
            Self::Capacity => "capacity",
            Self::RuntimeAvailability => "runtime_availability",
            Self::CapabilitySurface => "capability_surface",
            Self::PathConfinement => "path_confinement",
            Self::SourcePrecondition => "source_precondition",
            Self::Evidence => "evidence",
            Self::Execution => "execution",
            Self::Approval => "approval",
            Self::WorkState => "work_state",
            Self::RecoveryRequired => "recovery_required",
            Self::Authority => "authority",
            Self::Internal => "internal",
        }
    }
}

/// A safe next step, not authorization to perform an effect or retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlRecoveryAction {
    CorrectInput,
    Authenticate,
    DoNotRetry,
    WaitForCapacity,
    ReduceRequest,
    Reconnect,
    RefreshWorkspace,
    InspectWorkspace,
    RefreshWork,
    ReadSource,
    InspectAdmission,
    InspectActivity,
    InspectLease,
    InspectExecution,
    InspectApproval,
    InspectEvidence,
    InspectSession,
    InspectReplay,
    RefreshCapabilities,
    InspectRuntime,
    ReadBack,
}

impl ControlRecoveryAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorrectInput => "correct_input",
            Self::Authenticate => "authenticate",
            Self::DoNotRetry => "do_not_retry",
            Self::WaitForCapacity => "wait_for_capacity",
            Self::ReduceRequest => "reduce_request",
            Self::Reconnect => "reconnect",
            Self::RefreshWorkspace => "refresh_workspace",
            Self::InspectWorkspace => "inspect_workspace",
            Self::RefreshWork => "refresh_work",
            Self::ReadSource => "read_source",
            Self::InspectAdmission => "inspect_admission",
            Self::InspectActivity => "inspect_activity",
            Self::InspectLease => "inspect_lease",
            Self::InspectExecution => "inspect_execution",
            Self::InspectApproval => "inspect_approval",
            Self::InspectEvidence => "inspect_evidence",
            Self::InspectSession => "inspect_session",
            Self::InspectReplay => "inspect_replay",
            Self::RefreshCapabilities => "refresh_capabilities",
            Self::InspectRuntime => "inspect_runtime",
            Self::ReadBack => "read_back",
        }
    }
}

impl ControlRecoveryAction {
    /// Static redacted guidance; never derives text from private adapter errors.
    pub const fn hint(self) -> &'static str {
        match self {
            Self::CorrectInput => {
                "Correct the input within the current authorized scope; do not bypass validation."
            }
            Self::Authenticate => {
                "Authenticate the current connection through its normal supported login flow."
            }
            Self::DoNotRetry => {
                "The request was cancelled. Inspect its current state before deciding on new work."
            }
            Self::WaitForCapacity => {
                "Wait for admission capacity and inspect current state before deciding on a new request."
            }
            Self::ReduceRequest => {
                "Read current state and reduce the requested size or range; do not repeat the oversized request."
            }
            Self::Reconnect => {
                "Reconnect to the control service and refresh the exact workspace and work state."
            }
            Self::RefreshWorkspace => {
                "Refresh the registered Location and resolve the exact Workspace with current revisions."
            }
            Self::InspectWorkspace => {
                "Inspect the registered Workspace and supported migration or recovery path; do not delete or reinitialize state."
            }
            Self::RefreshWork => {
                "Read the current Activity, Agent, Coordinator, Goal and DAG fences before issuing a newly validated request."
            }
            Self::ReadSource => {
                "Read current source hashes and the durable mutation result before preparing a genuinely new edit."
            }
            Self::InspectAdmission => {
                "Inspect the command_run result or pending Approval with approval_get; do not assume an Execution exists."
            }
            Self::InspectActivity => {
                "Read the predecessor Activity and its successor relation with the exact Activity IDs before retrying."
            }
            Self::InspectLease => {
                "Inspect current lease ownership. Renew or recover only through the authorized lifecycle; do not take over live ownership."
            }
            Self::InspectExecution => {
                "Read the existing execution and its result before submitting more work."
            }
            Self::InspectApproval => {
                "Read the current approval and policy state before requesting a new approval."
            }
            Self::InspectEvidence => {
                "Read the referenced evidence and its current work attribution before changing associations."
            }
            Self::InspectSession => {
                "Resolve the issued session and binding. Adopt a legacy record only through an explicit authorized operation."
            }
            Self::InspectReplay => {
                "Read the existing replay record; do not change request identity to disguise a conflicting retry."
            }
            Self::RefreshCapabilities => {
                "Refresh the connector tool catalog and compare the server build and tool-set revision before choosing a supported operation."
            }
            Self::InspectRuntime => {
                "Inspect the configured execution runtime and required toolchain before resubmitting the original command intent."
            }
            Self::ReadBack => {
                "Read back durable state and inspect recovery status before any further write; the previous outcome is not confirmed."
            }
        }
    }
}

/// What this error proves about the requested operation's admission and outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlOperationOutcome {
    NotAdmitted,
    Unknown,
    CommittedButUnconfirmed,
}

/// Small, redacted, machine-readable context for an error. Paths and adapter
/// text remain private; only bounded source counts and durable identities cross
/// the control projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlErrorDetails {
    None,
    /// Registration/upgrade may have changed state before its failing reply.
    WorkspaceRegistrationUnknown,
    SourceReadRange {
        end_line: u64,
        total_lines: u64,
    },
    PathKind {
        expected: FileEntryKind,
        actual: FileEntryKind,
    },
    WriterLeaseConflict {
        lease_id: WriterLeaseId,
    },
    ApprovalTarget {
        approval_id: ApprovalRequestId,
        execution_id: ExecutionId,
    },
    ExecutionTarget {
        execution_id: ExecutionId,
    },
    ActivitySuccessorTarget {
        predecessor_activity_id: ActivityId,
        successor_activity_id: ActivityId,
    },
}

impl ControlOperationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAdmitted => "not_admitted",
            Self::Unknown => "unknown",
            Self::CommittedButUnconfirmed => "committed_but_unconfirmed",
        }
    }
}

impl ControlErrorCode {
    pub const fn category(self) -> ControlErrorCategory {
        match self {
            Self::InvalidInput => ControlErrorCategory::InputValidation,
            Self::AuthorizationRequired => ControlErrorCategory::Authentication,
            Self::RequestCancelled => ControlErrorCategory::Cancellation,
            Self::ToolUnavailable | Self::RustCiToolchainUnavailable => {
                ControlErrorCategory::CapabilitySurface
            }
            Self::LocationNotFound
            | Self::LocationUnavailable
            | Self::WorkspaceNotFound
            | Self::WorkspaceNotInitialized
            | Self::WorkspaceStateUnavailable
            | Self::WorkspaceIdentityConflict
            | Self::WorkspaceRootConflict
            | Self::WorkspaceRemovalBlocked
            | Self::WorkspaceSchemaOutdated => ControlErrorCategory::WorkspaceState,
            Self::LocationRevisionConflict
            | Self::WorkspaceRevisionConflict
            | Self::WorkspaceQueueSettingsConflict
            | Self::ActivityConflict
            | Self::GoalConflict
            | Self::DagConflict
            | Self::AgentConflict
            | Self::AgentFocusConflict
            | Self::AgentDagPlanConflict
            | Self::AgentDagReplayConflict
            | Self::CoordinatorConflict => ControlErrorCategory::RevisionConflict,
            Self::ActivityLeaseConflict
            | Self::RecoveryLeaseConflict
            | Self::WriterLeaseNotFound
            | Self::WriterLeaseConflict => ControlErrorCategory::Lease,
            Self::CapacityExceeded | Self::FileCapacityExceeded => ControlErrorCategory::Capacity,
            Self::WorkerClosed | Self::WorkerShuttingDown => {
                ControlErrorCategory::RuntimeAvailability
            }
            Self::AgentSessionAuthorityUnavailable => ControlErrorCategory::RuntimeAvailability,
            Self::WorkspaceScopeOverlap | Self::FilePathDenied | Self::InvalidPathKind => {
                ControlErrorCategory::PathConfinement
            }
            Self::FileNotFound
            | Self::FileConflict
            | Self::FileWholeHashConflict
            | Self::FileRangeConflict
            | Self::FileSourceNotText
            | Self::FileReadRangeOutOfBounds => ControlErrorCategory::SourcePrecondition,
            Self::DiffNotFound
            | Self::DiffUnavailable
            | Self::GoalEvidenceConflict
            | Self::AgentEvidenceConflict => ControlErrorCategory::Evidence,
            Self::ExecutionNotFound
            | Self::ExecutionConflict
            | Self::ExecutionProvenanceConflict => ControlErrorCategory::Execution,
            Self::CommandCatalogChanged => ControlErrorCategory::CapabilitySurface,
            Self::ApprovalNotFound | Self::ApprovalConflict | Self::ApprovalExpired => {
                ControlErrorCategory::Approval
            }
            Self::ActivityNotFound
            | Self::GoalNotFound
            | Self::GoalCompletionBlocked
            | Self::DagNotFound
            | Self::AgentNotFound
            | Self::CoordinatorNotFound
            | Self::WorkSelectionAmbiguous => ControlErrorCategory::WorkState,
            Self::PersistenceFailure
            | Self::CommittedButUnconfirmed
            | Self::ProjectionResyncRequired
            | Self::CheckpointNotFound
            | Self::CheckpointStateConflict
            | Self::CheckpointUnavailable
            | Self::WriterLeaseRecoveryRequired => ControlErrorCategory::RecoveryRequired,
            Self::AgentSessionNotFound
            | Self::AgentSessionClosed
            | Self::AgentSessionConflict
            | Self::AgentSessionUnresolved => ControlErrorCategory::Authority,
            Self::Internal => ControlErrorCategory::Internal,
        }
    }

    pub const fn recovery_action(self) -> ControlRecoveryAction {
        match self {
            Self::InvalidInput
            | Self::FileSourceNotText
            | Self::FilePathDenied
            | Self::WorkspaceScopeOverlap
            | Self::FileReadRangeOutOfBounds
            | Self::InvalidPathKind => ControlRecoveryAction::CorrectInput,
            Self::AuthorizationRequired => ControlRecoveryAction::Authenticate,
            Self::RequestCancelled => ControlRecoveryAction::DoNotRetry,
            Self::ToolUnavailable | Self::CommandCatalogChanged => {
                ControlRecoveryAction::RefreshCapabilities
            }
            Self::RustCiToolchainUnavailable => ControlRecoveryAction::InspectRuntime,
            Self::CapacityExceeded => ControlRecoveryAction::WaitForCapacity,
            Self::FileCapacityExceeded => ControlRecoveryAction::ReduceRequest,
            Self::WorkerClosed
            | Self::WorkerShuttingDown
            | Self::AgentSessionAuthorityUnavailable => ControlRecoveryAction::Reconnect,
            Self::LocationNotFound
            | Self::LocationRevisionConflict
            | Self::WorkspaceNotFound
            | Self::WorkspaceRevisionConflict
            | Self::WorkspaceQueueSettingsConflict => ControlRecoveryAction::RefreshWorkspace,
            Self::LocationUnavailable
            | Self::WorkspaceNotInitialized
            | Self::WorkspaceStateUnavailable
            | Self::WorkspaceIdentityConflict
            | Self::WorkspaceRootConflict
            | Self::WorkspaceRemovalBlocked
            | Self::WorkspaceSchemaOutdated => ControlRecoveryAction::InspectWorkspace,
            Self::ActivityNotFound
            | Self::ActivityConflict
            | Self::GoalNotFound
            | Self::GoalConflict
            | Self::GoalCompletionBlocked
            | Self::DagNotFound
            | Self::DagConflict
            | Self::AgentNotFound
            | Self::AgentConflict
            | Self::AgentFocusConflict
            | Self::AgentDagPlanConflict
            | Self::CoordinatorNotFound
            | Self::CoordinatorConflict
            | Self::WorkSelectionAmbiguous => ControlRecoveryAction::RefreshWork,
            Self::FileNotFound
            | Self::FileConflict
            | Self::FileWholeHashConflict
            | Self::FileRangeConflict => ControlRecoveryAction::ReadSource,
            Self::ActivityLeaseConflict
            | Self::RecoveryLeaseConflict
            | Self::WriterLeaseNotFound
            | Self::WriterLeaseConflict
            | Self::WriterLeaseRecoveryRequired => ControlRecoveryAction::InspectLease,
            Self::ExecutionNotFound => ControlRecoveryAction::InspectAdmission,
            Self::ExecutionConflict | Self::ExecutionProvenanceConflict => {
                ControlRecoveryAction::InspectAdmission
            }
            Self::ApprovalNotFound | Self::ApprovalConflict | Self::ApprovalExpired => {
                ControlRecoveryAction::InspectApproval
            }
            Self::DiffNotFound
            | Self::DiffUnavailable
            | Self::GoalEvidenceConflict
            | Self::AgentEvidenceConflict => ControlRecoveryAction::InspectEvidence,
            Self::AgentSessionNotFound
            | Self::AgentSessionClosed
            | Self::AgentSessionConflict
            | Self::AgentSessionUnresolved => ControlRecoveryAction::InspectSession,
            Self::AgentDagReplayConflict | Self::ProjectionResyncRequired => {
                ControlRecoveryAction::InspectReplay
            }
            Self::PersistenceFailure
            | Self::CommittedButUnconfirmed
            | Self::CheckpointNotFound
            | Self::CheckpointStateConflict
            | Self::CheckpointUnavailable
            | Self::Internal => ControlRecoveryAction::ReadBack,
        }
    }
}

impl fmt::Display for ControlErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted remote-safe error projection with no owned strings or private context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlErrorView {
    code: ControlErrorCode,
    committed: bool,
    outcome: ControlOperationOutcome,
    retryable: bool,
    details: ControlErrorDetails,
}

impl ControlErrorView {
    /// An ordinary service error does not prove that no effect occurred.
    pub const fn from_service(code: ControlErrorCode, committed: bool) -> Self {
        let committed = committed || matches!(code, ControlErrorCode::CommittedButUnconfirmed);
        Self {
            code,
            committed,
            outcome: if committed {
                ControlOperationOutcome::CommittedButUnconfirmed
            } else {
                ControlOperationOutcome::Unknown
            },
            retryable: false,
            details: ControlErrorDetails::None,
        }
    }

    /// Use only when the caller proves rejection before request admission.
    pub const fn not_admitted(code: ControlErrorCode) -> Self {
        if matches!(code, ControlErrorCode::CommittedButUnconfirmed) {
            return Self::from_service(code, true);
        }
        Self {
            code,
            committed: false,
            outcome: ControlOperationOutcome::NotAdmitted,
            retryable: false,
            details: ControlErrorDetails::None,
        }
    }

    /// A failed queue send proves that this request was not admitted.
    pub const fn retryable_admission() -> Self {
        Self {
            code: ControlErrorCode::CapacityExceeded,
            committed: false,
            outcome: ControlOperationOutcome::NotAdmitted,
            retryable: true,
            details: ControlErrorDetails::None,
        }
    }

    pub const fn unknown(code: ControlErrorCode) -> Self {
        Self::from_service(code, false)
    }

    #[must_use]
    pub const fn with_details(mut self, details: ControlErrorDetails) -> Self {
        self.details = details;
        self
    }

    /// An inner admission failure cannot prove that earlier outer steps had no effect.
    #[must_use]
    pub const fn after_admission(self) -> Self {
        Self::from_service(self.code, self.committed).with_details(self.details)
    }

    pub const fn code(self) -> ControlErrorCode {
        self.code
    }
    pub const fn committed(self) -> bool {
        self.committed
    }
    pub const fn category(self) -> ControlErrorCategory {
        self.code.category()
    }
    pub const fn retryable(self) -> bool {
        self.retryable
    }
    pub const fn outcome(self) -> ControlOperationOutcome {
        self.outcome
    }
    pub const fn details(self) -> ControlErrorDetails {
        self.details
    }
    pub const fn summary(self) -> &'static str {
        self.code.summary()
    }

    pub const fn recovery_action(self) -> ControlRecoveryAction {
        if self.committed
            || (matches!(self.outcome, ControlOperationOutcome::Unknown)
                && matches!(
                    self.code,
                    ControlErrorCode::WorkerClosed
                        | ControlErrorCode::WorkerShuttingDown
                        | ControlErrorCode::CapacityExceeded
                        | ControlErrorCode::RequestCancelled
                ))
        {
            ControlRecoveryAction::ReadBack
        } else {
            match self.details {
                ControlErrorDetails::WorkspaceRegistrationUnknown => {
                    ControlRecoveryAction::ReadBack
                }
                ControlErrorDetails::ApprovalTarget { .. } => {
                    ControlRecoveryAction::InspectApproval
                }
                ControlErrorDetails::ExecutionTarget { .. } => {
                    ControlRecoveryAction::InspectExecution
                }
                ControlErrorDetails::ActivitySuccessorTarget { .. } => {
                    ControlRecoveryAction::InspectActivity
                }
                ControlErrorDetails::None
                | ControlErrorDetails::SourceReadRange { .. }
                | ControlErrorDetails::PathKind { .. }
                | ControlErrorDetails::WriterLeaseConflict { .. } => self.code.recovery_action(),
            }
        }
    }

    pub const fn recovery_hint(self) -> &'static str {
        if self.retryable {
            "The request was not admitted. Retry the same request identity and intent after bounded backoff when capacity is available."
        } else if matches!(self.code, ControlErrorCode::CommandCatalogChanged) {
            "The command catalog fingerprint changed. Refresh command_list, submit a new intent with a new execution ID, or read the existing pending Approval with approval_get before deciding."
        } else {
            self.recovery_action().hint()
        }
    }
}

/// Typed control-plane error with a stable redacted projection.
///
/// `source` is deliberately private and its `Debug` representation is
/// redacted.  Adapters must use [`Self::view`] or [`Self::code`] for remote
/// responses rather than forwarding the source.
#[must_use]
pub struct ControlError {
    code: ControlErrorCode,
    committed: bool,
    details: ControlErrorDetails,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl ControlError {
    pub(crate) fn new(code: ControlErrorCode) -> Self {
        Self {
            code,
            committed: false,
            details: ControlErrorDetails::None,
            source: None,
        }
    }

    pub(crate) fn with_source<E>(code: ControlErrorCode, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            code,
            committed: false,
            details: ControlErrorDetails::None,
            source: Some(Box::new(source)),
        }
    }

    pub(crate) const fn committed() -> Self {
        Self {
            code: ControlErrorCode::CommittedButUnconfirmed,
            committed: true,
            details: ControlErrorDetails::None,
            source: None,
        }
    }

    pub(crate) const fn with_details(mut self, details: ControlErrorDetails) -> Self {
        self.details = details;
        self
    }

    pub const fn code(&self) -> ControlErrorCode {
        self.code
    }

    pub const fn is_committed(&self) -> bool {
        self.committed
    }

    pub const fn view(&self) -> ControlErrorView {
        ControlErrorView::from_service(self.code, self.committed).with_details(self.details)
    }

    pub const fn details(&self) -> ControlErrorDetails {
        self.details
    }

    pub const fn redacted_message(&self) -> &'static str {
        self.code.summary()
    }
}

impl fmt::Debug for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlError")
            .field("code", &self.code)
            .field("committed", &self.committed)
            .field("details", &self.details)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.summary())
    }
}

impl Error for ControlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn ordinary_service_error_stays_unknown_without_admission_proof() {
        let view = ControlErrorView::from_service(ControlErrorCode::FileRangeConflict, false);
        assert_eq!(view.category(), ControlErrorCategory::SourcePrecondition);
        assert_eq!(view.outcome(), ControlOperationOutcome::Unknown);
        assert!(!view.retryable());
        assert_eq!(view.recovery_action(), ControlRecoveryAction::ReadSource);
    }

    #[test]
    fn structured_details_survive_view_and_after_admission() {
        let lease_id = WriterLeaseId::from_uuid(Uuid::from_u128(7));
        let details = ControlErrorDetails::WriterLeaseConflict { lease_id };
        let error = ControlError::new(ControlErrorCode::WriterLeaseConflict).with_details(details);
        assert_eq!(error.details(), details);
        assert_eq!(error.view().details(), details);
        assert_eq!(error.view().after_admission().details(), details);

        let source = ControlErrorView::unknown(ControlErrorCode::FileReadRangeOutOfBounds)
            .with_details(ControlErrorDetails::SourceReadRange {
                end_line: 42,
                total_lines: 7,
            });
        assert_eq!(
            source.details(),
            ControlErrorDetails::SourceReadRange {
                end_line: 42,
                total_lines: 7,
            }
        );
    }

    #[test]
    fn catalog_change_uses_command_list_guidance_without_execution_target() {
        let view = ControlErrorView::unknown(ControlErrorCode::CommandCatalogChanged);
        assert_eq!(view.category(), ControlErrorCategory::CapabilitySurface);
        assert_eq!(
            view.recovery_action(),
            ControlRecoveryAction::RefreshCapabilities
        );
        assert!(view.recovery_hint().contains("command_list"));
        assert!(view.recovery_hint().contains("new execution ID"));
        assert_eq!(view.details(), ControlErrorDetails::None);
        assert_eq!(view.outcome(), ControlOperationOutcome::Unknown);
    }

    #[test]
    fn only_explicit_pre_admission_capacity_rejection_is_retryable() {
        let retryable = ControlErrorView::retryable_admission();
        assert_eq!(retryable.outcome(), ControlOperationOutcome::NotAdmitted);
        assert!(retryable.retryable());

        let unknown = ControlErrorView::unknown(ControlErrorCode::CapacityExceeded);
        assert_eq!(unknown.outcome(), ControlOperationOutcome::Unknown);
        assert!(!unknown.retryable());
    }

    #[test]
    fn committed_failure_preserves_readback_only_guidance() {
        let error = ControlError::committed();
        let view = error.view();
        assert!(view.committed());
        assert_eq!(
            view.outcome(),
            ControlOperationOutcome::CommittedButUnconfirmed
        );
        assert!(!view.retryable());
        assert_eq!(view.recovery_action(), ControlRecoveryAction::ReadBack);
    }

    #[test]
    fn durable_target_details_choose_object_specific_guidance() {
        let approval = ControlErrorView::unknown(ControlErrorCode::ExecutionProvenanceConflict)
            .with_details(ControlErrorDetails::ApprovalTarget {
                approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(10)),
                execution_id: ExecutionId::from_uuid(Uuid::from_u128(11)),
            });
        assert_eq!(
            approval.recovery_action(),
            ControlRecoveryAction::InspectApproval
        );

        let execution = ControlErrorView::unknown(ControlErrorCode::ExecutionConflict)
            .with_details(ControlErrorDetails::ExecutionTarget {
                execution_id: ExecutionId::from_uuid(Uuid::from_u128(12)),
            });
        assert_eq!(
            execution.recovery_action(),
            ControlRecoveryAction::InspectExecution
        );
        assert_eq!(
            ControlErrorView::unknown(ControlErrorCode::ExecutionConflict).recovery_action(),
            ControlRecoveryAction::InspectAdmission
        );
        assert_eq!(
            ControlErrorView::unknown(ControlErrorCode::ExecutionNotFound).recovery_action(),
            ControlRecoveryAction::InspectAdmission
        );
        assert_eq!(
            ControlErrorCode::ExecutionConflict.recovery_action(),
            ControlRecoveryAction::InspectAdmission
        );
        assert_eq!(
            ControlErrorCode::ExecutionProvenanceConflict.recovery_action(),
            ControlRecoveryAction::InspectAdmission
        );
        assert_eq!(
            ControlErrorView::unknown(ControlErrorCode::ExecutionConflict).outcome(),
            ControlOperationOutcome::Unknown
        );
        let successor = ControlErrorView::unknown(ControlErrorCode::ActivityConflict).with_details(
            ControlErrorDetails::ActivitySuccessorTarget {
                predecessor_activity_id: ActivityId::from_uuid(Uuid::from_u128(13)),
                successor_activity_id: ActivityId::from_uuid(Uuid::from_u128(14)),
            },
        );
        assert_eq!(
            successor.recovery_action(),
            ControlRecoveryAction::InspectActivity
        );
    }

    #[test]
    fn request_admission_and_reply_loss_have_different_guidance() {
        use crate::ControlClientError;
        let rejected = ControlClientError::WorkerClosed.view();
        let lost = ControlClientError::ResponseDropped.view();
        assert_eq!(rejected.code(), lost.code());
        assert_eq!(rejected.outcome(), ControlOperationOutcome::NotAdmitted);
        assert_eq!(rejected.recovery_action(), ControlRecoveryAction::Reconnect);
        assert_eq!(lost.outcome(), ControlOperationOutcome::Unknown);
        assert_eq!(lost.recovery_action(), ControlRecoveryAction::ReadBack);
        assert!(!lost.retryable());
        assert!(ControlClientError::QueueFull.view().retryable());
    }

    #[test]
    fn coordinator_projection_preserves_nested_commit_and_unknown_journal() {
        use crate::{
            ControlClientError, ForgeApprovalCoordinatorError, ForgeExecutionCoordinatorError,
        };
        let committed =
            ForgeApprovalCoordinatorError::Execution(ForgeExecutionCoordinatorError::Control(
                ControlClientError::Service(ControlError::committed()),
            ))
            .view();
        assert!(committed.committed());
        assert_eq!(
            committed.outcome(),
            ControlOperationOutcome::CommittedButUnconfirmed
        );
        assert_eq!(committed.recovery_action(), ControlRecoveryAction::ReadBack);
        assert!(!committed.retryable());

        // An inner send can fail after an earlier step durably consumed an
        // authorization or approval. Only the outer queue proves non-admission.
        for view in [
            ForgeExecutionCoordinatorError::Control(ControlClientError::QueueFull).view(),
            ForgeExecutionCoordinatorError::Control(ControlClientError::WorkerClosed).view(),
            ForgeApprovalCoordinatorError::Control(ControlClientError::QueueFull).view(),
            ForgeApprovalCoordinatorError::Execution(ForgeExecutionCoordinatorError::QueueFull)
                .view(),
        ] {
            assert_eq!(view.outcome(), ControlOperationOutcome::Unknown);
            assert_eq!(view.recovery_action(), ControlRecoveryAction::ReadBack);
            assert!(!view.retryable());
        }

        for error in [
            ForgeExecutionCoordinatorError::JournalFailed,
            ForgeExecutionCoordinatorError::JournalTimeout,
            ForgeExecutionCoordinatorError::Closed,
        ] {
            let view = error.view();
            assert_eq!(view.outcome(), ControlOperationOutcome::Unknown);
            assert!(!view.retryable());
        }
        assert!(ForgeExecutionCoordinatorError::QueueFull.view().retryable());
        assert!(
            !ForgeApprovalCoordinatorError::PendingCapacity
                .view()
                .retryable()
        );
        assert!(
            !ForgeApprovalCoordinatorError::AutoScopeCapacity
                .view()
                .retryable()
        );
        assert!(
            !ForgeExecutionCoordinatorError::WaiterIdExhausted
                .view()
                .retryable()
        );
    }
}
