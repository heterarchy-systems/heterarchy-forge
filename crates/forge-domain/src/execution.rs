use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{ActivityId, TimestampMillis, WorkspaceId, WorkspaceRelativePath};

const MAX_PROGRAM_BYTES: usize = 4_096;
const MAX_ARGUMENT_BYTES: usize = 4_096;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_TOTAL_BYTES: usize = 16 * 1024;
const MAX_SCRIPT_BYTES: usize = 16 * 1024;
const MIN_TIMEOUT_MILLIS: u64 = 100;
const MAX_TIMEOUT_MILLIS: u64 = 10 * 60 * 1_000;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_EXECUTION_LIST_LIMIT: u16 = 256;
const EXECUTION_REQUEST_DIGEST_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionId(Uuid);

impl ExecutionId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ExecutionId {
    type Err = ExecutionIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(ExecutionIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum ExecutionIdParseError {
    #[error("invalid Execution UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionRevision(i64);

impl ExecutionRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, ExecutionRevisionError> {
        if value < 1 {
            Err(ExecutionRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, ExecutionRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(ExecutionRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionRevisionError {
    #[error("Execution revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Execution revision overflowed at {current}")]
    Overflow { current: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionState {
    Starting,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Interrupted,
}

impl ExecutionState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Starting | Self::Running)
    }

    pub const fn is_terminal(self) -> bool {
        !self.is_active()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionMode {
    Structured,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionFailureCode {
    Admission,
    SandboxUnavailable,
    InvalidWorkingDirectory,
    ProcessSpawn,
    Supervision,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionRequestDigest([u8; EXECUTION_REQUEST_DIGEST_BYTES]);

impl fmt::Debug for ExecutionRequestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionRequestDigest")
            .finish_non_exhaustive()
    }
}

impl ExecutionRequestDigest {
    pub const BYTE_LEN: usize = EXECUTION_REQUEST_DIGEST_BYTES;

    pub const fn from_bytes(value: [u8; EXECUTION_REQUEST_DIGEST_BYTES]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; EXECUTION_REQUEST_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionProgram(PathBuf);

impl ExecutionProgram {
    pub fn new(value: PathBuf) -> Result<Self, ExecutionProgramError> {
        let bytes = value.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_PROGRAM_BYTES || bytes.contains(&0) {
            return Err(ExecutionProgramError::InvalidLength {
                actual: bytes.len(),
                maximum: MAX_PROGRAM_BYTES,
            });
        }
        if !value.is_absolute()
            || value
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(ExecutionProgramError::NotCanonicalAbsolute);
        }
        Ok(Self(value))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionProgramError {
    #[error("Execution program contains {actual} bytes; maximum is {maximum}")]
    InvalidLength { actual: usize, maximum: usize },
    #[error("Execution program must be a canonical absolute path")]
    NotCanonicalAbsolute,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ExecutionArgument(OsString);

impl fmt::Debug for ExecutionArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionArgument")
            .field("bytes", &self.0.as_bytes().len())
            .finish()
    }
}

impl ExecutionArgument {
    pub fn new(value: OsString) -> Result<Self, ExecutionArgumentError> {
        let bytes = value.as_bytes();
        if bytes.len() > MAX_ARGUMENT_BYTES || bytes.contains(&0) {
            Err(ExecutionArgumentError::InvalidLength {
                actual: bytes.len(),
                maximum: MAX_ARGUMENT_BYTES,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionArgumentError {
    #[error("Execution argument contains {actual} bytes; maximum is {maximum}")]
    InvalidLength { actual: usize, maximum: usize },
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ExecutionScript(String);

impl fmt::Debug for ExecutionScript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionScript")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl ExecutionScript {
    pub fn new(value: String) -> Result<Self, ExecutionScriptError> {
        if value.is_empty() || value.len() > MAX_SCRIPT_BYTES || value.contains('\0') {
            Err(ExecutionScriptError::InvalidLength {
                actual: value.len(),
                maximum: MAX_SCRIPT_BYTES,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionScriptError {
    #[error("Execution script contains {actual} bytes; maximum is {maximum}")]
    InvalidLength { actual: usize, maximum: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionTimeoutMillis(u64);

impl ExecutionTimeoutMillis {
    pub const fn new(value: u64) -> Result<Self, ExecutionTimeoutError> {
        if value < MIN_TIMEOUT_MILLIS || value > MAX_TIMEOUT_MILLIS {
            Err(ExecutionTimeoutError::OutOfRange {
                actual: value,
                minimum: MIN_TIMEOUT_MILLIS,
                maximum: MAX_TIMEOUT_MILLIS,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionTimeoutError {
    #[error("Execution timeout {actual}ms is outside {minimum}..={maximum}ms")]
    OutOfRange {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionOutputLimit(u64);

impl ExecutionOutputLimit {
    pub const DEFAULT: Self = Self(64 * 1024);

    pub const fn new(value: u64) -> Result<Self, ExecutionOutputLimitError> {
        if value == 0 || value > MAX_OUTPUT_BYTES {
            Err(ExecutionOutputLimitError::OutOfRange {
                actual: value,
                maximum: MAX_OUTPUT_BYTES,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutputLimitError {
    #[error("Execution output limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u64, maximum: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionPermissions {
    workspace_read: bool,
    workspace_write: bool,
    network: bool,
}

impl ExecutionPermissions {
    pub const fn new(workspace_read: bool, workspace_write: bool, network: bool) -> Self {
        Self {
            workspace_read,
            workspace_write,
            network,
        }
    }

    pub const fn workspace_read(self) -> bool {
        self.workspace_read
    }

    pub const fn workspace_write(self) -> bool {
        self.workspace_write
    }

    pub const fn network(self) -> bool {
        self.network
    }

    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self::new(
            self.workspace_read && other.workspace_read,
            self.workspace_write && other.workspace_write,
            self.network && other.network,
        )
    }

    pub const fn contains(self, requested: Self) -> bool {
        (!requested.workspace_read || self.workspace_read)
            && (!requested.workspace_write || self.workspace_write)
            && (!requested.network || self.network)
    }

    pub const fn is_empty(self) -> bool {
        !self.workspace_read && !self.workspace_write && !self.network
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionKind {
    Structured {
        program: ExecutionProgram,
        arguments: Vec<ExecutionArgument>,
    },
    Shell {
        script: ExecutionScript,
    },
}

impl ExecutionKind {
    pub const fn mode(&self) -> ExecutionMode {
        match self {
            Self::Structured { .. } => ExecutionMode::Structured,
            Self::Shell { .. } => ExecutionMode::Shell,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionAttribution {
    id: ExecutionId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
}

impl ExecutionAttribution {
    pub const fn new(id: ExecutionId, workspace_id: WorkspaceId, activity_id: ActivityId) -> Self {
        Self {
            id,
            workspace_id,
            activity_id,
        }
    }

    pub const fn id(self) -> ExecutionId {
        self.id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionLimits {
    timeout: ExecutionTimeoutMillis,
    output: ExecutionOutputLimit,
}

impl ExecutionLimits {
    pub const fn new(timeout: ExecutionTimeoutMillis, output: ExecutionOutputLimit) -> Self {
        Self { timeout, output }
    }

    pub const fn timeout(self) -> ExecutionTimeoutMillis {
        self.timeout
    }

    pub const fn output(self) -> ExecutionOutputLimit {
        self.output
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRequest {
    attribution: ExecutionAttribution,
    kind: ExecutionKind,
    cwd: Option<WorkspaceRelativePath>,
    limits: ExecutionLimits,
    permissions: ExecutionPermissions,
}

impl ExecutionRequest {
    pub fn new(
        attribution: ExecutionAttribution,
        kind: ExecutionKind,
        cwd: Option<WorkspaceRelativePath>,
        limits: ExecutionLimits,
        permissions: ExecutionPermissions,
    ) -> Result<Self, ExecutionRequestError> {
        if let ExecutionKind::Structured { arguments, .. } = &kind {
            if arguments.len() > MAX_ARGUMENTS {
                return Err(ExecutionRequestError::TooManyArguments {
                    actual: arguments.len(),
                    maximum: MAX_ARGUMENTS,
                });
            }
            let total = arguments.iter().try_fold(0_usize, |total, argument| {
                total.checked_add(argument.as_os_str().as_bytes().len())
            });
            if total.is_none_or(|total| total > MAX_ARGUMENT_TOTAL_BYTES) {
                return Err(ExecutionRequestError::ArgumentsTooLarge {
                    maximum: MAX_ARGUMENT_TOTAL_BYTES,
                });
            }
        }
        Ok(Self {
            attribution,
            kind,
            cwd,
            limits,
            permissions,
        })
    }

    pub const fn id(&self) -> ExecutionId {
        self.attribution.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.attribution.activity_id
    }

    pub const fn kind(&self) -> &ExecutionKind {
        &self.kind
    }

    pub const fn cwd(&self) -> Option<&WorkspaceRelativePath> {
        self.cwd.as_ref()
    }

    pub const fn timeout(&self) -> ExecutionTimeoutMillis {
        self.limits.timeout
    }

    pub const fn output_limit(&self) -> ExecutionOutputLimit {
        self.limits.output
    }

    pub const fn permissions(&self) -> ExecutionPermissions {
        self.permissions
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionRequestError {
    #[error("Execution has {actual} arguments; maximum is {maximum}")]
    TooManyArguments { actual: usize, maximum: usize },
    #[error("Execution argument bytes exceed {maximum}")]
    ArgumentsTooLarge { maximum: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionTimestamps {
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl ExecutionTimestamps {
    pub const fn new(
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Result<Self, ExecutionRecordError> {
        if updated_at.get() < created_at.get() {
            Err(ExecutionRecordError::TimestampOrder)
        } else {
            Ok(Self {
                created_at,
                updated_at,
            })
        }
    }

    pub const fn initial(created_at: TimestampMillis) -> Self {
        Self {
            created_at,
            updated_at: created_at,
        }
    }

    pub const fn created_at(self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionListLimit(u16);

impl ExecutionListLimit {
    pub const DEFAULT: Self = Self(64);

    pub const fn new(value: u16) -> Result<Self, ExecutionListLimitError> {
        if value == 0 || value > MAX_EXECUTION_LIST_LIMIT {
            Err(ExecutionListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_EXECUTION_LIST_LIMIT,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionListLimitError {
    #[error("Execution list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u16, maximum: u16 },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginExecution {
    attribution: ExecutionAttribution,
    mode: ExecutionMode,
    cwd: Option<WorkspaceRelativePath>,
    limits: ExecutionLimits,
    permissions: ExecutionPermissions,
    request_digest: ExecutionRequestDigest,
    observed_at: TimestampMillis,
}

impl BeginExecution {
    pub fn from_request(
        request: &ExecutionRequest,
        request_digest: ExecutionRequestDigest,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            attribution: request.attribution,
            mode: request.kind.mode(),
            cwd: request.cwd.clone(),
            limits: request.limits,
            permissions: request.permissions,
            request_digest,
            observed_at,
        }
    }

    pub const fn attribution(&self) -> ExecutionAttribution {
        self.attribution
    }

    pub const fn id(&self) -> ExecutionId {
        self.attribution.id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.attribution.activity_id()
    }

    pub const fn mode(&self) -> ExecutionMode {
        self.mode
    }

    pub const fn cwd(&self) -> Option<&WorkspaceRelativePath> {
        self.cwd.as_ref()
    }

    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    pub const fn permissions(&self) -> ExecutionPermissions {
        self.permissions
    }

    pub const fn request_digest(&self) -> ExecutionRequestDigest {
        self.request_digest
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub fn with_observed_at(&self, observed_at: TimestampMillis) -> Self {
        Self {
            attribution: self.attribution,
            mode: self.mode,
            cwd: self.cwd.clone(),
            limits: self.limits,
            permissions: self.permissions,
            request_digest: self.request_digest,
            observed_at,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkExecutionRunning {
    id: ExecutionId,
    expected_revision: ExecutionRevision,
    observed_at: TimestampMillis,
}

impl MarkExecutionRunning {
    pub const fn new(
        id: ExecutionId,
        expected_revision: ExecutionRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            expected_revision,
            observed_at,
        }
    }

    pub const fn id(self) -> ExecutionId {
        self.id
    }

    pub const fn expected_revision(self) -> ExecutionRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteExecution {
    expected_revision: ExecutionRevision,
    observed_at: TimestampMillis,
    outcome: ExecutionOutcome,
}

impl CompleteExecution {
    pub const fn new(
        expected_revision: ExecutionRevision,
        observed_at: TimestampMillis,
        outcome: ExecutionOutcome,
    ) -> Self {
        Self {
            expected_revision,
            observed_at,
            outcome,
        }
    }

    pub const fn id(&self) -> ExecutionId {
        self.outcome.id()
    }

    pub const fn expected_revision(&self) -> ExecutionRevision {
        self.expected_revision
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn outcome(&self) -> &ExecutionOutcome {
        &self.outcome
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailExecution {
    id: ExecutionId,
    expected_revision: ExecutionRevision,
    observed_at: TimestampMillis,
    failure_code: ExecutionFailureCode,
}

impl FailExecution {
    pub const fn new(
        id: ExecutionId,
        expected_revision: ExecutionRevision,
        observed_at: TimestampMillis,
        failure_code: ExecutionFailureCode,
    ) -> Self {
        Self {
            id,
            expected_revision,
            observed_at,
            failure_code,
        }
    }

    pub const fn id(self) -> ExecutionId {
        self.id
    }

    pub const fn expected_revision(self) -> ExecutionRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn failure_code(self) -> ExecutionFailureCode {
        self.failure_code
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionCompletionStatus {
    Exited,
    TimedOut,
    Cancelled,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedExecutionOutput {
    retained: Vec<u8>,
    total_bytes: u64,
    truncated: bool,
}

impl BoundedExecutionOutput {
    pub fn new(retained: Vec<u8>, total_bytes: u64, truncated: bool) -> Self {
        Self {
            retained,
            total_bytes,
            truncated,
        }
    }

    pub fn retained(&self) -> &[u8] {
        &self.retained
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionTermination {
    status: ExecutionCompletionStatus,
    exit_code: Option<i32>,
    signal: Option<i32>,
}

impl ExecutionTermination {
    pub const fn new(
        status: ExecutionCompletionStatus,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> Self {
        Self {
            status,
            exit_code,
            signal,
        }
    }

    pub const fn status(self) -> ExecutionCompletionStatus {
        self.status
    }

    pub const fn exit_code(self) -> Option<i32> {
        self.exit_code
    }

    pub const fn signal(self) -> Option<i32> {
        self.signal
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    id: ExecutionId,
    termination: ExecutionTermination,
    duration_millis: u64,
    stdout: BoundedExecutionOutput,
    stderr: BoundedExecutionOutput,
}

impl ExecutionOutcome {
    pub const fn new(
        id: ExecutionId,
        termination: ExecutionTermination,
        duration_millis: u64,
        stdout: BoundedExecutionOutput,
        stderr: BoundedExecutionOutput,
    ) -> Self {
        Self {
            id,
            termination,
            duration_millis,
            stdout,
            stderr,
        }
    }

    pub const fn id(&self) -> ExecutionId {
        self.id
    }

    pub const fn status(&self) -> ExecutionCompletionStatus {
        self.termination.status
    }

    pub const fn exit_code(&self) -> Option<i32> {
        self.termination.exit_code
    }

    pub const fn signal(&self) -> Option<i32> {
        self.termination.signal
    }

    pub const fn duration_millis(&self) -> u64 {
        self.duration_millis
    }

    pub const fn stdout(&self) -> &BoundedExecutionOutput {
        &self.stdout
    }

    pub const fn stderr(&self) -> &BoundedExecutionOutput {
        &self.stderr
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredExecution {
    attribution: ExecutionAttribution,
    mode: ExecutionMode,
    cwd: Option<WorkspaceRelativePath>,
    limits: ExecutionLimits,
    permissions: ExecutionPermissions,
    request_digest: ExecutionRequestDigest,
    state: ExecutionState,
    timestamps: ExecutionTimestamps,
    revision: ExecutionRevision,
    outcome: Option<ExecutionOutcome>,
    failure_code: Option<ExecutionFailureCode>,
}

impl RegisteredExecution {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        attribution: ExecutionAttribution,
        mode: ExecutionMode,
        cwd: Option<WorkspaceRelativePath>,
        limits: ExecutionLimits,
        permissions: ExecutionPermissions,
        request_digest: ExecutionRequestDigest,
        state: ExecutionState,
        timestamps: ExecutionTimestamps,
        revision: ExecutionRevision,
        outcome: Option<ExecutionOutcome>,
        failure_code: Option<ExecutionFailureCode>,
    ) -> Result<Self, ExecutionRecordError> {
        let evidence_is_valid = match state {
            ExecutionState::Starting | ExecutionState::Running | ExecutionState::Interrupted => {
                outcome.is_none() && failure_code.is_none()
            }
            ExecutionState::Completed | ExecutionState::TimedOut | ExecutionState::Cancelled => {
                outcome.as_ref().is_some_and(|value| {
                    value.id() == attribution.id() && state == execution_state_for_outcome(value)
                }) && failure_code.is_none()
            }
            ExecutionState::Failed => {
                (outcome.as_ref().is_some_and(|value| {
                    value.id() == attribution.id()
                        && execution_state_for_outcome(value) == ExecutionState::Failed
                }) && failure_code.is_none())
                    || (outcome.is_none() && failure_code.is_some())
            }
        };
        if !evidence_is_valid {
            return Err(ExecutionRecordError::InvalidEvidence);
        }
        if let Some(outcome) = &outcome {
            validate_bounded_output(outcome.stdout())?;
            validate_bounded_output(outcome.stderr())?;
        }
        Ok(Self {
            attribution,
            mode,
            cwd,
            limits,
            permissions,
            request_digest,
            state,
            timestamps,
            revision,
            outcome,
            failure_code,
        })
    }

    pub const fn id(&self) -> ExecutionId {
        self.attribution.id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.attribution.activity_id()
    }

    pub const fn mode(&self) -> ExecutionMode {
        self.mode
    }

    pub const fn cwd(&self) -> Option<&WorkspaceRelativePath> {
        self.cwd.as_ref()
    }

    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    pub const fn permissions(&self) -> ExecutionPermissions {
        self.permissions
    }

    pub const fn request_digest(&self) -> ExecutionRequestDigest {
        self.request_digest
    }

    pub const fn state(&self) -> ExecutionState {
        self.state
    }

    pub const fn timestamps(&self) -> ExecutionTimestamps {
        self.timestamps
    }

    pub const fn revision(&self) -> ExecutionRevision {
        self.revision
    }

    pub const fn outcome(&self) -> Option<&ExecutionOutcome> {
        self.outcome.as_ref()
    }

    pub const fn failure_code(&self) -> Option<ExecutionFailureCode> {
        self.failure_code
    }
}

pub fn execution_state_for_outcome(outcome: &ExecutionOutcome) -> ExecutionState {
    match outcome.status() {
        ExecutionCompletionStatus::Exited => {
            if outcome.exit_code() == Some(0) {
                ExecutionState::Completed
            } else {
                ExecutionState::Failed
            }
        }
        ExecutionCompletionStatus::TimedOut => ExecutionState::TimedOut,
        ExecutionCompletionStatus::Cancelled => ExecutionState::Cancelled,
    }
}

fn validate_bounded_output(output: &BoundedExecutionOutput) -> Result<(), ExecutionRecordError> {
    let retained =
        u64::try_from(output.retained().len()).map_err(|_| ExecutionRecordError::InvalidOutput)?;
    if retained > output.total_bytes() || output.truncated() != (retained < output.total_bytes()) {
        Err(ExecutionRecordError::InvalidOutput)
    } else {
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionRecordError {
    #[error("Execution timestamps are out of order")]
    TimestampOrder,
    #[error("Execution evidence does not match its state")]
    InvalidEvidence,
    #[error("Execution output evidence is inconsistent")]
    InvalidOutput,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_and_shell_requests_remain_distinct_and_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let attribution = ExecutionAttribution::new(
            ExecutionId::from_uuid(Uuid::from_u128(1)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
        );
        let limits = ExecutionLimits::new(
            ExecutionTimeoutMillis::new(1_000)?,
            ExecutionOutputLimit::DEFAULT,
        );
        let structured = ExecutionRequest::new(
            attribution,
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/usr/bin/printf"))?,
                arguments: vec![ExecutionArgument::new(OsString::from("safe"))?],
            },
            None,
            limits,
            ExecutionPermissions::new(true, false, false),
        )?;
        assert!(matches!(
            structured.kind(),
            ExecutionKind::Structured { .. }
        ));
        let shell = ExecutionRequest::new(
            attribution,
            ExecutionKind::Shell {
                script: ExecutionScript::new("printf shell".to_owned())?,
            },
            None,
            limits,
            ExecutionPermissions::new(true, true, false),
        )?;
        assert!(matches!(shell.kind(), ExecutionKind::Shell { .. }));
        assert!(ExecutionProgram::new(PathBuf::from("relative")).is_err());
        assert!(ExecutionTimeoutMillis::new(99).is_err());
        assert!(ExecutionOutputLimit::new(1024 * 1024 + 1).is_err());
        Ok(())
    }

    #[test]
    fn argument_and_script_debug_are_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let argument = ExecutionArgument::new(OsString::from("token=do-not-log"))?;
        let script = ExecutionScript::new("echo do-not-log".to_owned())?;
        assert!(!format!("{argument:?}").contains("do-not-log"));
        assert!(!format!("{script:?}").contains("do-not-log"));
        Ok(())
    }
}
