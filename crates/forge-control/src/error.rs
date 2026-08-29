use std::error::Error;
use std::fmt;

/// Stable machine-readable application-control error category.
///
/// The category is the only remote-safe error identity exposed by the control
/// plane.  Underlying adapter errors are retained as a private source for
/// local diagnostics, but are never included in [`std::fmt::Display`] or the redacted
/// view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ControlErrorCode {
    InvalidInput = 1000,
    LocationNotFound = 1001,
    LocationRevisionConflict = 1002,
    LocationUnavailable = 1003,
    WorkspaceNotFound = 1100,
    WorkspaceNotInitialized = 1101,
    WorkspaceStateUnavailable = 1102,
    WorkspaceIdentityConflict = 1103,
    WorkspaceRevisionConflict = 1104,
    WorkspaceRootConflict = 1105,
    WorkspaceMigrationRequired = 1106,
    ActivityNotFound = 1200,
    ActivityConflict = 1201,
    ActivityLeaseConflict = 1202,
    PersistenceFailure = 1300,
    CommittedButUnconfirmed = 1301,
    CapacityExceeded = 1400,
    WorkerClosed = 1401,
    WorkerShuttingDown = 1402,
    WorkspaceScopeOverlap = 1500,
    FilePathDenied = 1501,
    FileNotFound = 1502,
    FileConflict = 1503,
    FileCapacityExceeded = 1504,
    DiffNotFound = 1600,
    DiffUnavailable = 1601,
    DiffLegacyUnavailable = 1602,
    ExecutionNotFound = 1700,
    ExecutionConflict = 1701,
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
    HarnessNotFound = 1880,
    HarnessConflict = 1881,
    AgentNotFound = 1890,
    AgentConflict = 1891,
    AgentFocusConflict = 1892,
    AgentEvidenceConflict = 1893,
    AgentDagGrantNotFound = 1894,
    AgentDagGrantConflict = 1895,
    AgentDagReplanConflict = 1896,
    AgentDagReplayConflict = 1897,
    Internal = 1900,
}

impl ControlErrorCode {
    /// Stable wire/log label for this category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "CONTROL_INVALID_INPUT",
            Self::LocationNotFound => "CONTROL_LOCATION_NOT_FOUND",
            Self::LocationRevisionConflict => "CONTROL_LOCATION_REVISION_CONFLICT",
            Self::LocationUnavailable => "CONTROL_LOCATION_UNAVAILABLE",
            Self::WorkspaceNotFound => "CONTROL_WORKSPACE_NOT_FOUND",
            Self::WorkspaceNotInitialized => "CONTROL_WORKSPACE_NOT_INITIALIZED",
            Self::WorkspaceStateUnavailable => "CONTROL_WORKSPACE_STATE_UNAVAILABLE",
            Self::WorkspaceIdentityConflict => "CONTROL_WORKSPACE_IDENTITY_CONFLICT",
            Self::WorkspaceRevisionConflict => "CONTROL_WORKSPACE_REVISION_CONFLICT",
            Self::WorkspaceRootConflict => "CONTROL_WORKSPACE_ROOT_CONFLICT",
            Self::WorkspaceMigrationRequired => "CONTROL_WORKSPACE_MIGRATION_REQUIRED",
            Self::ActivityNotFound => "CONTROL_ACTIVITY_NOT_FOUND",
            Self::ActivityConflict => "CONTROL_ACTIVITY_CONFLICT",
            Self::ActivityLeaseConflict => "CONTROL_ACTIVITY_LEASE_CONFLICT",
            Self::PersistenceFailure => "CONTROL_PERSISTENCE_FAILURE",
            Self::CommittedButUnconfirmed => "CONTROL_COMMITTED_BUT_UNCONFIRMED",
            Self::CapacityExceeded => "CONTROL_CAPACITY_EXCEEDED",
            Self::WorkerClosed => "CONTROL_WORKER_CLOSED",
            Self::WorkerShuttingDown => "CONTROL_WORKER_SHUTTING_DOWN",
            Self::WorkspaceScopeOverlap => "CONTROL_WORKSPACE_SCOPE_OVERLAP",
            Self::FilePathDenied => "CONTROL_FILE_PATH_DENIED",
            Self::FileNotFound => "CONTROL_FILE_NOT_FOUND",
            Self::FileConflict => "CONTROL_FILE_CONFLICT",
            Self::FileCapacityExceeded => "CONTROL_FILE_CAPACITY_EXCEEDED",
            Self::DiffNotFound => "CONTROL_DIFF_NOT_FOUND",
            Self::DiffUnavailable => "CONTROL_DIFF_UNAVAILABLE",
            Self::DiffLegacyUnavailable => "CONTROL_DIFF_LEGACY_UNAVAILABLE",
            Self::ExecutionNotFound => "CONTROL_EXECUTION_NOT_FOUND",
            Self::ExecutionConflict => "CONTROL_EXECUTION_CONFLICT",
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
            Self::HarnessNotFound => "CONTROL_HARNESS_NOT_FOUND",
            Self::HarnessConflict => "CONTROL_HARNESS_CONFLICT",
            Self::AgentNotFound => "CONTROL_AGENT_NOT_FOUND",
            Self::AgentConflict => "CONTROL_AGENT_CONFLICT",
            Self::AgentFocusConflict => "CONTROL_AGENT_FOCUS_CONFLICT",
            Self::AgentEvidenceConflict => "CONTROL_AGENT_EVIDENCE_CONFLICT",
            Self::AgentDagGrantNotFound => "CONTROL_AGENT_DAG_GRANT_NOT_FOUND",
            Self::AgentDagGrantConflict => "CONTROL_AGENT_DAG_GRANT_CONFLICT",
            Self::AgentDagReplanConflict => "CONTROL_AGENT_DAG_REPLAN_CONFLICT",
            Self::AgentDagReplayConflict => "CONTROL_AGENT_DAG_REPLAY_CONFLICT",
            Self::Internal => "CONTROL_INTERNAL",
        }
    }

    /// Redacted, stable human-readable summary.  It intentionally contains no
    /// path, SQL, UUID, or adapter-provided text.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::InvalidInput => "control input was invalid",
            Self::LocationNotFound => "the requested Location was not found",
            Self::LocationRevisionConflict => "the Location revision is stale",
            Self::LocationUnavailable => "the Location is unavailable",
            Self::WorkspaceNotFound => "the requested Workspace was not found",
            Self::WorkspaceNotInitialized => "the Workspace state is not initialized",
            Self::WorkspaceStateUnavailable => "the Workspace state is unavailable",
            Self::WorkspaceIdentityConflict => "the durable Workspace identity conflicts",
            Self::WorkspaceRevisionConflict => "the Workspace revision is stale",
            Self::WorkspaceRootConflict => "the Workspace root no longer matches",
            Self::WorkspaceMigrationRequired => "the Workspace requires an explicit migration",
            Self::ActivityNotFound => "the requested Activity was not found",
            Self::ActivityConflict => "the Activity conflicts with durable state",
            Self::ActivityLeaseConflict => "the Activity lease is unavailable",
            Self::PersistenceFailure => "durable persistence failed",
            Self::CommittedButUnconfirmed => {
                "durable commit completed but could not be revalidated"
            }
            Self::CapacityExceeded => "the control queue is at capacity",
            Self::WorkerClosed => "the control worker is closed",
            Self::WorkerShuttingDown => "the control worker is shutting down",
            Self::WorkspaceScopeOverlap => "the Workspace effect scope overlaps another scope",
            Self::FilePathDenied => "the requested file path is denied",
            Self::FileNotFound => "the requested file was not found",
            Self::FileConflict => "the requested file effect conflicts with current state",
            Self::FileCapacityExceeded => "the requested file effect exceeds bounded capacity",
            Self::DiffNotFound => "the requested Diff Evidence was not found",
            Self::DiffUnavailable => "the requested Diff Evidence is unavailable",
            Self::DiffLegacyUnavailable => "the ChangeSet predates durable Diff Evidence",
            Self::ExecutionNotFound => "the requested execution was not found",
            Self::ExecutionConflict => "the execution conflicts with durable state",
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
            Self::HarnessNotFound => "no Harness Bundle is applied to the Workspace",
            Self::HarnessConflict => "the Harness state conflicts with durable authority",
            Self::AgentNotFound => "the requested Agent instance was not found",
            Self::AgentConflict => "the Agent instance conflicts with durable state",
            Self::AgentFocusConflict => "the Agent focus conflicts with the current Goal or DAG",
            Self::AgentEvidenceConflict => {
                "the Agent public evidence reference conflicts with Workspace evidence"
            }
            Self::AgentDagGrantNotFound => "the Agent DAG authoring grant was not found",
            Self::AgentDagGrantConflict => {
                "the Agent DAG authoring grant conflicts with durable authority"
            }
            Self::AgentDagReplanConflict => {
                "the Agent DAG replan conflicts with the current Goal or DAG head"
            }
            Self::AgentDagReplayConflict => {
                "the Agent DAG replan request conflicts with its replay ledger"
            }
            Self::Internal => "the control service encountered an internal failure",
        }
    }
}

impl fmt::Display for ControlErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redacted remote-safe error projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlErrorView {
    code: ControlErrorCode,
    committed: bool,
}

impl ControlErrorView {
    pub const fn code(self) -> ControlErrorCode {
        self.code
    }

    pub const fn committed(self) -> bool {
        self.committed
    }

    pub const fn summary(self) -> &'static str {
        self.code.summary()
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
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl ControlError {
    pub(crate) fn new(code: ControlErrorCode) -> Self {
        Self {
            code,
            committed: false,
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
            source: Some(Box::new(source)),
        }
    }

    pub(crate) const fn committed() -> Self {
        Self {
            code: ControlErrorCode::CommittedButUnconfirmed,
            committed: true,
            source: None,
        }
    }

    pub const fn code(&self) -> ControlErrorCode {
        self.code
    }

    pub const fn is_committed(&self) -> bool {
        self.committed
    }

    pub const fn view(&self) -> ControlErrorView {
        ControlErrorView {
            code: self.code,
            committed: self.committed,
        }
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
