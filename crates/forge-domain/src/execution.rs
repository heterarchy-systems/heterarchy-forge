use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, AgentInstanceId, AgentInstanceRevision, AuthenticatedPrincipal,
    GoalNodeAttribution, RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
};

mod native_closure;
mod observation;
pub use native_closure::{
    ExecutionNativeClosureFact, ExecutionNativeClosureFactError, ExecutionNativeClosureFactParts,
    NativeClosureLaunch, NativeClosureProcess, NativeClosureRuntime,
};
pub use observation::{
    ExecutionObservationHeader, ExecutionObservationLifecycle, ExecutionObservationSelection,
    ExecutionOutputSummary, ExecutionTerminalSummary, VerificationEvidenceSnapshot,
};

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
pub const MAX_EXECUTION_COMMAND_ID_BYTES: usize = 128;

/// Maximum size of one retained incremental execution output chunk.
pub const EXECUTION_OUTPUT_CHUNK_BYTES: usize = 4 * 1024;

/// Fixed bounded metadata charge used by durable output reads.
///
/// The charge is intentionally independent of event kind and payload length:
/// a gap marker must consume read budget just like a chunk, so omitted output
/// cannot bypass a caller's byte bound.
pub const EXECUTION_OUTPUT_EVENT_METADATA_BYTES: u64 = 64;

/// Smallest useful durable read budget: one maximum chunk plus its metadata.
pub const MIN_EXECUTION_OUTPUT_READ_BYTES: u64 =
    EXECUTION_OUTPUT_CHUNK_BYTES as u64 + EXECUTION_OUTPUT_EVENT_METADATA_BYTES;

/// Maximum number of events accepted by one durable output read.
pub const MAX_EXECUTION_OUTPUT_READ_EVENTS: usize = 128;

/// Maximum byte budget accepted by one durable output read.
pub const MAX_EXECUTION_OUTPUT_READ_BYTES: u64 = 1024 * 1024;

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

/// The process stream that produced an incremental output event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionOutputStream {
    Stdout,
    Stderr,
}

/// Monotonic sequence assigned by one execution-local output authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionOutputSequence(u64);

impl ExecutionOutputSequence {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: u64) -> Result<Self, ExecutionOutputSequenceError> {
        if value == 0 {
            Err(ExecutionOutputSequenceError::Zero)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, ExecutionOutputSequenceError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(ExecutionOutputSequenceError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutputSequenceError {
    #[error("execution output sequence must be at least 1")]
    Zero,
    #[error("execution output sequence overflowed at {current}")]
    Overflow { current: u64 },
}

/// Cursor position for a single execution's output stream.
///
/// A cursor starts at zero, before the first event. It carries execution
/// identity so a cursor cannot accidentally be applied to another execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionOutputCursor {
    execution_id: ExecutionId,
    after_sequence: u64,
}

impl ExecutionOutputCursor {
    pub const fn initial(execution_id: ExecutionId) -> Self {
        Self {
            execution_id,
            after_sequence: 0,
        }
    }

    pub const fn from_sequence(
        execution_id: ExecutionId,
        sequence: ExecutionOutputSequence,
    ) -> Self {
        Self {
            execution_id,
            after_sequence: sequence.get(),
        }
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn after_sequence(self) -> u64 {
        self.after_sequence
    }
}

/// A bounded chunk of stdout or stderr output.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionOutputChunk {
    execution_id: ExecutionId,
    sequence: ExecutionOutputSequence,
    stream: ExecutionOutputStream,
    bytes: Vec<u8>,
}

impl fmt::Debug for ExecutionOutputChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionOutputChunk")
            .field("execution_id", &self.execution_id)
            .field("sequence", &self.sequence)
            .field("stream", &self.stream)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl ExecutionOutputChunk {
    pub fn new(
        execution_id: ExecutionId,
        sequence: ExecutionOutputSequence,
        stream: ExecutionOutputStream,
        bytes: &[u8],
    ) -> Result<Self, ExecutionOutputChunkError> {
        if bytes.is_empty() || bytes.len() > EXECUTION_OUTPUT_CHUNK_BYTES {
            return Err(ExecutionOutputChunkError::InvalidLength {
                actual: bytes.len(),
                maximum: EXECUTION_OUTPUT_CHUNK_BYTES,
            });
        }
        Ok(Self {
            execution_id,
            sequence,
            stream,
            bytes: bytes.to_vec(),
        })
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn sequence(&self) -> ExecutionOutputSequence {
        self.sequence
    }

    pub const fn stream(&self) -> ExecutionOutputStream {
        self.stream
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn metadata_bytes(&self) -> u64 {
        EXECUTION_OUTPUT_EVENT_METADATA_BYTES
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutputChunkError {
    #[error("execution output chunk contains {actual} bytes; maximum is {maximum}")]
    InvalidLength { actual: usize, maximum: usize },
}

/// Why bytes were omitted from the incremental output event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionOutputGapCause {
    Backpressure,
    OutputLimit,
    BackpressureAndOutputLimit,
}

/// An explicit indication that one or more output chunks were not retained.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutputGap {
    execution_id: ExecutionId,
    sequence: ExecutionOutputSequence,
    first_missing: ExecutionOutputSequence,
    last_missing: ExecutionOutputSequence,
    stream: Option<ExecutionOutputStream>,
    omitted_bytes: u64,
    omitted_chunks: u64,
    cause: ExecutionOutputGapCause,
}

/// Validated payload describing the omitted range represented by a gap.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionOutputGapParts {
    first_missing: ExecutionOutputSequence,
    last_missing: ExecutionOutputSequence,
    stream: Option<ExecutionOutputStream>,
    omitted_bytes: u64,
    omitted_chunks: u64,
    cause: ExecutionOutputGapCause,
}

impl ExecutionOutputGapParts {
    pub const fn new(
        first_missing: ExecutionOutputSequence,
        last_missing: ExecutionOutputSequence,
        stream: Option<ExecutionOutputStream>,
        omitted_bytes: u64,
        omitted_chunks: u64,
        cause: ExecutionOutputGapCause,
    ) -> Self {
        Self {
            first_missing,
            last_missing,
            stream,
            omitted_bytes,
            omitted_chunks,
            cause,
        }
    }

    pub const fn first_missing(self) -> ExecutionOutputSequence {
        self.first_missing
    }

    pub const fn last_missing(self) -> ExecutionOutputSequence {
        self.last_missing
    }

    pub const fn stream(self) -> Option<ExecutionOutputStream> {
        self.stream
    }

    pub const fn omitted_bytes(self) -> u64 {
        self.omitted_bytes
    }

    pub const fn omitted_chunks(self) -> u64 {
        self.omitted_chunks
    }

    pub const fn cause(self) -> ExecutionOutputGapCause {
        self.cause
    }
}

impl ExecutionOutputGap {
    pub fn new(
        execution_id: ExecutionId,
        sequence: ExecutionOutputSequence,
        parts: ExecutionOutputGapParts,
    ) -> Result<Self, ExecutionOutputGapError> {
        if parts.omitted_chunks == 0 || parts.omitted_bytes == 0 {
            return Err(ExecutionOutputGapError::Empty);
        }
        if parts.first_missing > parts.last_missing {
            return Err(ExecutionOutputGapError::InvalidRange);
        }
        let expected_chunks = parts
            .last_missing
            .get()
            .checked_sub(parts.first_missing.get())
            .and_then(|count| count.checked_add(1))
            .ok_or(ExecutionOutputGapError::InvalidRange)?;
        if parts.omitted_chunks != expected_chunks {
            return Err(ExecutionOutputGapError::ChunkCountMismatch);
        }
        let expected_marker = parts
            .last_missing
            .checked_next()
            .map_err(|_| ExecutionOutputGapError::MarkerNotAdjacent)?;
        if sequence != expected_marker {
            return Err(ExecutionOutputGapError::MarkerNotAdjacent);
        }
        Ok(Self {
            execution_id,
            sequence,
            first_missing: parts.first_missing,
            last_missing: parts.last_missing,
            stream: parts.stream,
            omitted_bytes: parts.omitted_bytes,
            omitted_chunks: parts.omitted_chunks,
            cause: parts.cause,
        })
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Sequence of this gap marker. The marker is after the missing range.
    pub const fn sequence(&self) -> ExecutionOutputSequence {
        self.sequence
    }

    pub const fn first_missing(&self) -> ExecutionOutputSequence {
        self.first_missing
    }

    pub const fn last_missing(&self) -> ExecutionOutputSequence {
        self.last_missing
    }

    /// `None` means the omitted range contained both stdout and stderr.
    pub const fn stream(&self) -> Option<ExecutionOutputStream> {
        self.stream
    }

    pub const fn omitted_bytes(&self) -> u64 {
        self.omitted_bytes
    }

    pub const fn omitted_chunks(&self) -> u64 {
        self.omitted_chunks
    }

    pub const fn cause(&self) -> ExecutionOutputGapCause {
        self.cause
    }

    pub const fn metadata_bytes(&self) -> u64 {
        EXECUTION_OUTPUT_EVENT_METADATA_BYTES
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutputGapError {
    #[error("execution output gap must omit at least one non-empty chunk")]
    Empty,
    #[error("execution output gap missing range is invalid")]
    InvalidRange,
    #[error("execution output gap chunk count does not match its missing range")]
    ChunkCountMismatch,
    #[error("execution output gap marker must immediately follow its missing range")]
    MarkerNotAdjacent,
}

/// Incremental output event. Terminal execution events are represented by the
/// separate supervisor event stream.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutputEvent {
    Chunk(ExecutionOutputChunk),
    Gap(ExecutionOutputGap),
}

impl ExecutionOutputEvent {
    pub const fn execution_id(&self) -> ExecutionId {
        match self {
            Self::Chunk(chunk) => chunk.execution_id(),
            Self::Gap(gap) => gap.execution_id(),
        }
    }

    pub const fn sequence(&self) -> ExecutionOutputSequence {
        match self {
            Self::Chunk(chunk) => chunk.sequence(),
            Self::Gap(gap) => gap.sequence(),
        }
    }

    pub const fn key(&self) -> ExecutionOutputEventKey {
        ExecutionOutputEventKey {
            execution_id: self.execution_id(),
            sequence: self.sequence(),
        }
    }

    pub fn read_cost_bytes(&self) -> u64 {
        match self {
            Self::Chunk(chunk) => chunk
                .metadata_bytes()
                .saturating_add(u64::try_from(chunk.bytes().len()).unwrap_or(u64::MAX)),
            Self::Gap(gap) => gap.metadata_bytes(),
        }
    }
}

/// Stable identity for one retained output event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionOutputEventKey {
    execution_id: ExecutionId,
    sequence: ExecutionOutputSequence,
}

impl ExecutionOutputEventKey {
    pub const fn new(execution_id: ExecutionId, sequence: ExecutionOutputSequence) -> Self {
        Self {
            execution_id,
            sequence,
        }
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn sequence(self) -> ExecutionOutputSequence {
        self.sequence
    }
}

/// A bounded, non-destructive output read.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutputRead {
    events: Vec<ExecutionOutputEvent>,
    ack_key: Option<ExecutionOutputEventKey>,
    next_cursor: ExecutionOutputCursor,
    terminal_state: Option<ExecutionState>,
    truncated: bool,
}

impl ExecutionOutputRead {
    pub fn empty() -> Self {
        Self::empty_for(ExecutionId::from_uuid(Uuid::nil()))
    }

    pub fn empty_for(execution_id: ExecutionId) -> Self {
        Self {
            events: Vec::new(),
            ack_key: None,
            next_cursor: ExecutionOutputCursor::initial(execution_id),
            terminal_state: None,
            truncated: false,
        }
    }

    /// Construct a supervisor peek. The cursor and terminal projection are
    /// filled by the durable read path when it has those observations.
    pub fn new(events: Vec<ExecutionOutputEvent>) -> Self {
        let ack_key = events.last().map(ExecutionOutputEvent::key);
        let next_cursor = ack_key.map_or_else(
            || {
                events.first().map_or_else(
                    || ExecutionOutputCursor::initial(ExecutionId::from_uuid(Uuid::nil())),
                    |event| {
                        ExecutionOutputCursor::from_sequence(event.execution_id(), event.sequence())
                    },
                )
            },
            |key| ExecutionOutputCursor::from_sequence(key.execution_id(), key.sequence()),
        );
        Self {
            events,
            ack_key,
            next_cursor,
            terminal_state: None,
            truncated: false,
        }
    }

    pub fn from_parts(
        execution_id: ExecutionId,
        events: Vec<ExecutionOutputEvent>,
        next_cursor: ExecutionOutputCursor,
        terminal_state: Option<ExecutionState>,
        truncated: bool,
    ) -> Self {
        let ack_key = events.last().map(ExecutionOutputEvent::key);
        let next_cursor = events.last().map_or_else(
            || {
                if next_cursor.execution_id() == execution_id {
                    next_cursor
                } else {
                    ExecutionOutputCursor::initial(execution_id)
                }
            },
            |event| ExecutionOutputCursor::from_sequence(event.execution_id(), event.sequence()),
        );
        Self {
            events,
            ack_key,
            next_cursor,
            terminal_state,
            truncated,
        }
    }

    pub fn events(&self) -> &[ExecutionOutputEvent] {
        &self.events
    }

    pub const fn ack_key(&self) -> Option<ExecutionOutputEventKey> {
        self.ack_key
    }

    pub const fn next_cursor(&self) -> ExecutionOutputCursor {
        self.next_cursor
    }

    pub const fn terminal_state(&self) -> Option<ExecutionState> {
        self.terminal_state
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One authorized execution observation from a single durable snapshot.
///
/// The record metadata and bounded output are intentionally carried together
/// so an authority-scoped caller cannot accidentally pair observations from
/// two different `SQLite` snapshots.  Authorization is still performed by the
/// persistence boundary; this type only carries its resulting observation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedExecutionRead {
    record: RegisteredExecution,
    output: ExecutionOutputRead,
}

impl AuthorizedExecutionRead {
    pub const fn new(record: RegisteredExecution, output: ExecutionOutputRead) -> Self {
        Self { record, output }
    }

    pub const fn record(&self) -> &RegisteredExecution {
        &self.record
    }

    pub const fn output(&self) -> &ExecutionOutputRead {
        &self.output
    }

    pub fn into_parts(self) -> (RegisteredExecution, ExecutionOutputRead) {
        (self.record, self.output)
    }
}

/// Bounded, server-discovered identity of a command that may be executed.
///
/// The command identifier is not an executable path or shell expression. It
/// is an opaque identity resolved by the control boundary from trusted
/// Workspace metadata.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionCommandId(String);

impl ExecutionCommandId {
    pub fn new(value: String) -> Result<Self, ExecutionCommandIdError> {
        if value.is_empty() {
            return Err(ExecutionCommandIdError::Empty);
        }
        if value.len() > MAX_EXECUTION_COMMAND_ID_BYTES {
            return Err(ExecutionCommandIdError::TooLong {
                actual: value.len(),
                maximum: MAX_EXECUTION_COMMAND_ID_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ExecutionCommandIdError::ControlCharacter);
        }
        if value.chars().any(char::is_whitespace) {
            return Err(ExecutionCommandIdError::Whitespace);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b':' | b'-')
        }) {
            return Err(ExecutionCommandIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ExecutionCommandId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for ExecutionCommandId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for ExecutionCommandId {
    type Err = ExecutionCommandIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value.to_owned())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionCommandIdError {
    #[error("execution command id must not be empty")]
    Empty,
    #[error("execution command id has {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("execution command id must not contain control characters")]
    ControlCharacter,
    #[error("execution command id must not contain whitespace")]
    Whitespace,
    #[error("execution command id contains a character outside [a-z0-9:-]")]
    InvalidCharacter,
}

/// Immutable Agent/Goal/DAG/Node attribution persisted with an execution.
///
/// This value is only present for an Agent-originated execution. Internal
/// Harness execution deliberately remains representable with no provenance.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionAgentProvenance {
    session_id: Option<crate::AgentSessionId>,
    project_command: Option<crate::ProjectCommandEvidence>,
    execution_id: ExecutionId,
    agent_id: AgentInstanceId,
    agent_revision: AgentInstanceRevision,
    principal: AuthenticatedPrincipal,
    attribution: GoalNodeAttribution,
    command_id: ExecutionCommandId,
}

impl ExecutionAgentProvenance {
    pub fn new(
        execution_id: ExecutionId,
        agent_id: AgentInstanceId,
        agent_revision: AgentInstanceRevision,
        principal: AuthenticatedPrincipal,
        attribution: GoalNodeAttribution,
        command_id: ExecutionCommandId,
        session_id: crate::AgentSessionId,
    ) -> Self {
        Self::from_parts(
            execution_id,
            agent_id,
            agent_revision,
            principal,
            attribution,
            command_id,
            Some(session_id),
        )
    }

    /// Rehydrate immutable evidence, retaining an explicitly unresolved
    /// session for historical records. Such records are never new authority.
    pub fn from_parts(
        execution_id: ExecutionId,
        agent_id: AgentInstanceId,
        agent_revision: AgentInstanceRevision,
        principal: AuthenticatedPrincipal,
        attribution: GoalNodeAttribution,
        command_id: ExecutionCommandId,
        session_id: Option<crate::AgentSessionId>,
    ) -> Self {
        Self {
            session_id,
            project_command: None,
            execution_id,
            agent_id,
            agent_revision,
            principal,
            attribution,
            command_id,
        }
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn session_id(&self) -> Option<crate::AgentSessionId> {
        self.session_id
    }

    /// Attach exact server-side project-command catalog evidence to a new
    /// execution. Legacy evidence remains explicitly absent when rehydrated.
    pub const fn with_project_command(mut self, value: crate::ProjectCommandEvidence) -> Self {
        self.project_command = Some(value);
        self
    }

    pub const fn project_command(&self) -> Option<crate::ProjectCommandEvidence> {
        self.project_command
    }

    /// Compare the durable actor authority fields that govern execution
    /// reads/cancellation. Project-command evidence is immutable execution
    /// metadata and is deliberately not re-supplied by those read endpoints.
    pub fn matches_actor_authority(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.execution_id == other.execution_id
            && self.agent_id == other.agent_id
            && self.agent_revision == other.agent_revision
            && self.principal == other.principal
            && self.attribution == other.attribution
            && self.command_id == other.command_id
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn agent_revision(&self) -> AgentInstanceRevision {
        self.agent_revision
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn attribution(&self) -> GoalNodeAttribution {
        self.attribution
    }

    pub const fn command_id(&self) -> &ExecutionCommandId {
        &self.command_id
    }
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
    runtime_owner: Option<RuntimeInstanceId>,
    provenance: Option<ExecutionAgentProvenance>,
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
            runtime_owner: None,
            provenance: None,
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

    pub const fn runtime_owner(&self) -> Option<RuntimeInstanceId> {
        self.runtime_owner
    }

    pub const fn with_runtime_owner(mut self, runtime_owner: RuntimeInstanceId) -> Self {
        self.runtime_owner = Some(runtime_owner);
        self
    }

    pub const fn provenance(&self) -> Option<&ExecutionAgentProvenance> {
        self.provenance.as_ref()
    }

    pub fn with_provenance(
        mut self,
        provenance: ExecutionAgentProvenance,
    ) -> Result<Self, ExecutionRecordError> {
        if provenance.execution_id() != self.id() {
            return Err(ExecutionRecordError::ProvenanceExecutionMismatch);
        }
        self.provenance = Some(provenance);
        Ok(self)
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
            runtime_owner: self.runtime_owner,
            provenance: self.provenance.clone(),
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
    provenance: Option<ExecutionAgentProvenance>,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecordDefinition {
    mode: ExecutionMode,
    cwd: Option<WorkspaceRelativePath>,
    limits: ExecutionLimits,
    permissions: ExecutionPermissions,
    request_digest: ExecutionRequestDigest,
}

impl ExecutionRecordDefinition {
    pub const fn new(
        mode: ExecutionMode,
        cwd: Option<WorkspaceRelativePath>,
        limits: ExecutionLimits,
        permissions: ExecutionPermissions,
        request_digest: ExecutionRequestDigest,
    ) -> Self {
        Self {
            mode,
            cwd,
            limits,
            permissions,
            request_digest,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecordLifecycle {
    state: ExecutionState,
    timestamps: ExecutionTimestamps,
    revision: ExecutionRevision,
    outcome: Option<ExecutionOutcome>,
    failure_code: Option<ExecutionFailureCode>,
}

impl ExecutionRecordLifecycle {
    pub const fn new(
        state: ExecutionState,
        timestamps: ExecutionTimestamps,
        revision: ExecutionRevision,
        outcome: Option<ExecutionOutcome>,
        failure_code: Option<ExecutionFailureCode>,
    ) -> Self {
        Self {
            state,
            timestamps,
            revision,
            outcome,
            failure_code,
        }
    }
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
        Self::from_parts_with_provenance(
            attribution,
            ExecutionRecordDefinition::new(mode, cwd, limits, permissions, request_digest),
            ExecutionRecordLifecycle::new(state, timestamps, revision, outcome, failure_code),
            None,
        )
    }

    pub fn from_parts_with_provenance(
        attribution: ExecutionAttribution,
        definition: ExecutionRecordDefinition,
        lifecycle: ExecutionRecordLifecycle,
        provenance: Option<ExecutionAgentProvenance>,
    ) -> Result<Self, ExecutionRecordError> {
        if provenance
            .as_ref()
            .is_some_and(|value| value.execution_id() != attribution.id())
        {
            return Err(ExecutionRecordError::ProvenanceExecutionMismatch);
        }
        validate_execution_evidence(
            attribution.id(),
            lifecycle.state,
            lifecycle.outcome.as_ref(),
            lifecycle.failure_code,
        )?;
        Ok(Self {
            attribution,
            mode: definition.mode,
            cwd: definition.cwd,
            limits: definition.limits,
            permissions: definition.permissions,
            request_digest: definition.request_digest,
            state: lifecycle.state,
            timestamps: lifecycle.timestamps,
            revision: lifecycle.revision,
            outcome: lifecycle.outcome,
            failure_code: lifecycle.failure_code,
            provenance,
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

    pub const fn provenance(&self) -> Option<&ExecutionAgentProvenance> {
        self.provenance.as_ref()
    }
}

fn validate_execution_evidence(
    execution_id: ExecutionId,
    state: ExecutionState,
    outcome: Option<&ExecutionOutcome>,
    failure_code: Option<ExecutionFailureCode>,
) -> Result<(), ExecutionRecordError> {
    if outcome.is_some_and(|value| value.id() != execution_id) {
        return Err(ExecutionRecordError::InvalidEvidence);
    }
    validate_execution_termination_evidence(
        state,
        outcome.map(|value| value.termination),
        failure_code,
    )?;
    if let Some(outcome) = outcome {
        validate_bounded_output(outcome.stdout())?;
        validate_bounded_output(outcome.stderr())?;
    }
    Ok(())
}

fn validate_execution_termination_evidence(
    state: ExecutionState,
    termination: Option<ExecutionTermination>,
    failure_code: Option<ExecutionFailureCode>,
) -> Result<(), ExecutionRecordError> {
    let evidence_is_valid = match state {
        ExecutionState::Starting | ExecutionState::Running | ExecutionState::Interrupted => {
            termination.is_none() && failure_code.is_none()
        }
        ExecutionState::Completed | ExecutionState::TimedOut | ExecutionState::Cancelled => {
            termination.is_some_and(|value| state == execution_state_for_termination(value))
                && failure_code.is_none()
        }
        ExecutionState::Failed => {
            (termination.is_some_and(|value| {
                execution_state_for_termination(value) == ExecutionState::Failed
            }) && failure_code.is_none())
                || (termination.is_none() && failure_code.is_some())
        }
    };
    if !evidence_is_valid {
        return Err(ExecutionRecordError::InvalidEvidence);
    }
    Ok(())
}

pub fn execution_state_for_outcome(outcome: &ExecutionOutcome) -> ExecutionState {
    execution_state_for_termination(outcome.termination)
}

fn execution_state_for_termination(termination: ExecutionTermination) -> ExecutionState {
    match termination.status() {
        ExecutionCompletionStatus::Exited => {
            if termination.exit_code() == Some(0) {
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
    #[error("Execution provenance refers to a different execution")]
    ProvenanceExecutionMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_output_values_are_bounded_and_debug_redacts_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(90));
        let sequence = ExecutionOutputSequence::new(1)?;
        assert!(
            ExecutionOutputChunk::new(
                execution_id,
                sequence,
                ExecutionOutputStream::Stdout,
                &vec![b'x'; EXECUTION_OUTPUT_CHUNK_BYTES + 1],
            )
            .is_err()
        );
        let chunk = ExecutionOutputChunk::new(
            execution_id,
            sequence,
            ExecutionOutputStream::Stdout,
            b"secret-output",
        )?;
        let debug = format!("{chunk:?}");
        assert!(!debug.contains("secret-output"));
        assert_eq!(chunk.metadata_bytes() + 13, 64 + 13);
        assert_eq!(
            ExecutionOutputGap::new(
                execution_id,
                ExecutionOutputSequence::new(1)?,
                ExecutionOutputGapParts::new(
                    sequence,
                    sequence,
                    None,
                    1,
                    1,
                    ExecutionOutputGapCause::Backpressure,
                ),
            )
            .err(),
            Some(ExecutionOutputGapError::MarkerNotAdjacent)
        );
        let gap_parts = ExecutionOutputGapParts::new(
            ExecutionOutputSequence::new(2)?,
            ExecutionOutputSequence::new(3)?,
            None,
            8,
            2,
            ExecutionOutputGapCause::Backpressure,
        );
        assert!(
            ExecutionOutputGap::new(execution_id, ExecutionOutputSequence::new(4)?, gap_parts,)
                .is_ok()
        );
        assert_eq!(
            ExecutionOutputGap::new(execution_id, ExecutionOutputSequence::new(5)?, gap_parts,)
                .err(),
            Some(ExecutionOutputGapError::MarkerNotAdjacent)
        );
        assert_eq!(
            ExecutionOutputGap::new(
                execution_id,
                ExecutionOutputSequence::new(4)?,
                ExecutionOutputGapParts::new(
                    ExecutionOutputSequence::new(2)?,
                    ExecutionOutputSequence::new(3)?,
                    None,
                    8,
                    1,
                    ExecutionOutputGapCause::Backpressure,
                ),
            )
            .err(),
            Some(ExecutionOutputGapError::ChunkCountMismatch)
        );
        Ok(())
    }

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

    #[test]
    fn agent_provenance_is_bounded_and_execution_bound() -> Result<(), Box<dyn std::error::Error>> {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(10));
        let agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(11));
        let goal_id = crate::GoalId::from_uuid(Uuid::from_u128(12));
        let node_id = crate::DagNodeId::from_uuid(Uuid::from_u128(13));
        let attribution = GoalNodeAttribution::new(
            goal_id,
            crate::GoalRevision::INITIAL,
            crate::DagRevisionNumber::INITIAL,
            node_id,
            crate::DagNodeRevision::INITIAL,
        );
        let command_id = ExecutionCommandId::new("make:ci".to_owned())?;
        let provenance = ExecutionAgentProvenance::new(
            execution_id,
            agent_id,
            AgentInstanceRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            attribution,
            command_id.clone(),
            crate::AgentSessionId::from_uuid(Uuid::from_u128(16)),
        );
        assert_eq!(provenance.execution_id(), execution_id);
        assert_eq!(provenance.command_id(), &command_id);
        assert!(ExecutionCommandId::new("make: ci".to_owned()).is_err());
        assert!(matches!(
            ExecutionCommandId::new("make:CI".to_owned()),
            Err(ExecutionCommandIdError::InvalidCharacter)
        ));
        assert!(ExecutionCommandId::new("x".repeat(MAX_EXECUTION_COMMAND_ID_BYTES + 1)).is_err());

        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                execution_id,
                WorkspaceId::from_uuid(Uuid::from_u128(14)),
                ActivityId::from_uuid(Uuid::from_u128(15)),
            ),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::DEFAULT,
            ),
            ExecutionPermissions::new(true, false, false),
        )?;
        let begin = BeginExecution::from_request(
            &request,
            ExecutionRequestDigest::from_bytes([1; EXECUTION_REQUEST_DIGEST_BYTES]),
            TimestampMillis::new(20)?,
        );
        let with_provenance = begin.clone().with_provenance(provenance.clone())?;
        assert_eq!(with_provenance.provenance(), Some(&provenance));
        let other = ExecutionAgentProvenance::new(
            ExecutionId::from_uuid(Uuid::from_u128(99)),
            agent_id,
            AgentInstanceRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            attribution,
            command_id,
            crate::AgentSessionId::from_uuid(Uuid::from_u128(17)),
        );
        assert!(begin.with_provenance(other).is_err());
        Ok(())
    }
}
