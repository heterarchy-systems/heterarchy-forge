//! Deterministic evidence for one verification run.
//!
//! A verification run is deliberately keyed by the execution that produced
//! it.  The domain retains only bounded identities, fingerprints, counters,
//! and terminal evidence; output bytes and all effectful observation remain
//! outside this module.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::{
    ExecutionCommandId, ExecutionId, ExecutionOutputEvent, ExecutionOutputSequence,
    ExecutionOutputStream, ExecutionState, FileByteCount, FileContentHash,
    FileContentHashParseError, GoalId, GoalRevision, MAX_GOAL_VERIFICATION_REQUIREMENTS,
    MAX_VERIFICATION_INPUT_BYTES, MAX_VERIFICATION_INPUT_FILES, ProjectCommandCatalogFingerprint,
    RegisteredExecution, TimestampMillis, VerificationInputFingerprint, VerificationInputId,
    VerificationInputManifest, VerificationInputPolicy, WorkspaceId,
};

const OUTPUT_FINGERPRINT_DOMAIN: &[u8] = b"heterarchy-forge-verification-output\0v1";

/// Fixed-width digest of the output evidence associated with one verification
/// run.
///
/// The output itself is owned by an effect boundary.  This type carries only
/// its canonical BLAKE3-256 identity.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VerificationOutputFingerprint([u8; Self::BYTE_LEN]);

impl VerificationOutputFingerprint {
    pub const BYTE_LEN: usize = 32;
    pub const HEX_LEN: usize = Self::BYTE_LEN * 2;
    pub const ALGORITHM: &str = "blake3-256";
    pub const ENCODED_LEN: usize = Self::ALGORITHM.len() + 1 + Self::HEX_LEN;

    pub const fn from_bytes(value: [u8; Self::BYTE_LEN]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LEN] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }

    pub const fn from_hash(value: FileContentHash) -> Self {
        Self::from_bytes(value.into_bytes())
    }

    pub const fn hash(self) -> FileContentHash {
        FileContentHash::from_bytes(self.0)
    }
}

/// Streaming verifier for the complete ordered execution-output ledger.
#[must_use]
pub struct VerificationOutputAccumulator {
    execution_id: ExecutionId,
    next_sequence: ExecutionOutputSequence,
    output: blake3::Hasher,
    stdout: blake3::Hasher,
    stderr: blake3::Hasher,
    stdout_bytes: u64,
    stderr_bytes: u64,
    has_gap: bool,
}

impl fmt::Debug for VerificationOutputAccumulator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationOutputAccumulator")
            .field("execution_id", &self.execution_id)
            .field("next_sequence", &self.next_sequence)
            .field("has_gap", &self.has_gap)
            .finish_non_exhaustive()
    }
}

impl VerificationOutputAccumulator {
    pub fn new(execution_id: ExecutionId) -> Self {
        let mut output = blake3::Hasher::new();
        hash_output_field(&mut output, b"domain", OUTPUT_FINGERPRINT_DOMAIN);
        hash_output_field(
            &mut output,
            b"execution-id",
            execution_id.into_uuid().as_bytes(),
        );
        Self {
            execution_id,
            next_sequence: ExecutionOutputSequence::INITIAL,
            output,
            stdout: blake3::Hasher::new(),
            stderr: blake3::Hasher::new(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            has_gap: false,
        }
    }

    pub fn push(
        &mut self,
        event: &ExecutionOutputEvent,
    ) -> Result<(), VerificationOutputAuditError> {
        if event.execution_id() != self.execution_id {
            return Err(VerificationOutputAuditError::ExecutionMismatch);
        }
        match event {
            ExecutionOutputEvent::Chunk(chunk) => {
                if chunk.sequence() != self.next_sequence {
                    return Err(VerificationOutputAuditError::SequenceCoverage);
                }
                hash_output_field(&mut self.output, b"event-kind", b"chunk");
                hash_output_u64(&mut self.output, b"sequence", chunk.sequence().get());
                let (stream_tag, hasher, count) = match chunk.stream() {
                    ExecutionOutputStream::Stdout => (
                        b"stdout".as_slice(),
                        &mut self.stdout,
                        &mut self.stdout_bytes,
                    ),
                    ExecutionOutputStream::Stderr => (
                        b"stderr".as_slice(),
                        &mut self.stderr,
                        &mut self.stderr_bytes,
                    ),
                };
                hash_output_field(&mut self.output, b"stream", stream_tag);
                hash_output_field(&mut self.output, b"bytes", chunk.bytes());
                hasher.update(chunk.bytes());
                *count = count
                    .checked_add(
                        u64::try_from(chunk.bytes().len())
                            .map_err(|_| VerificationOutputAuditError::IntegerOverflow)?,
                    )
                    .ok_or(VerificationOutputAuditError::IntegerOverflow)?;
                self.next_sequence = chunk
                    .sequence()
                    .checked_next()
                    .map_err(|_| VerificationOutputAuditError::IntegerOverflow)?;
            }
            ExecutionOutputEvent::Gap(gap) => {
                if gap.first_missing() != self.next_sequence {
                    return Err(VerificationOutputAuditError::SequenceCoverage);
                }
                self.has_gap = true;
                hash_output_field(&mut self.output, b"event-kind", b"gap");
                for (label, value) in [
                    (b"sequence".as_slice(), gap.sequence().get()),
                    (b"first-missing".as_slice(), gap.first_missing().get()),
                    (b"last-missing".as_slice(), gap.last_missing().get()),
                    (b"omitted-bytes".as_slice(), gap.omitted_bytes()),
                    (b"omitted-chunks".as_slice(), gap.omitted_chunks()),
                ] {
                    hash_output_u64(&mut self.output, label, value);
                }
                let stream = match gap.stream() {
                    Some(ExecutionOutputStream::Stdout) => b"stdout".as_slice(),
                    Some(ExecutionOutputStream::Stderr) => b"stderr".as_slice(),
                    None => b"mixed".as_slice(),
                };
                hash_output_field(&mut self.output, b"stream", stream);
                hash_output_field(
                    &mut self.output,
                    b"gap-cause",
                    &[match gap.cause() {
                        crate::ExecutionOutputGapCause::Backpressure => 0,
                        crate::ExecutionOutputGapCause::OutputLimit => 1,
                        crate::ExecutionOutputGapCause::BackpressureAndOutputLimit => 2,
                    }],
                );
                self.next_sequence = gap
                    .sequence()
                    .checked_next()
                    .map_err(|_| VerificationOutputAuditError::IntegerOverflow)?;
            }
        }
        Ok(())
    }

    pub fn finish(
        mut self,
        execution: &RegisteredExecution,
    ) -> Result<VerificationRunTerminalStatus, VerificationOutputAuditError> {
        if execution.id() != self.execution_id {
            return Err(VerificationOutputAuditError::ExecutionMismatch);
        }
        if !execution.state().is_terminal() {
            return Err(VerificationOutputAuditError::TerminalRequired);
        }
        hash_output_field(
            &mut self.output,
            b"terminal-state",
            &[execution_state_tag(execution.state())],
        );
        let mut truncated = false;
        if let Some(outcome) = execution.outcome() {
            truncated = outcome.stdout().truncated() || outcome.stderr().truncated();
            for (label, value) in [
                (b"duration-ms".as_slice(), outcome.duration_millis()),
                (b"stdout-total".as_slice(), outcome.stdout().total_bytes()),
                (b"stderr-total".as_slice(), outcome.stderr().total_bytes()),
            ] {
                hash_output_u64(&mut self.output, label, value);
            }
            hash_optional_i32(&mut self.output, b"exit-code", outcome.exit_code());
            hash_optional_i32(&mut self.output, b"signal", outcome.signal());
            hash_output_field(
                &mut self.output,
                b"truncated",
                &[
                    u8::from(outcome.stdout().truncated()),
                    u8::from(outcome.stderr().truncated()),
                ],
            );
            // Retained prefixes cannot prove full-stream byte equality. Their
            // explicit truncation remains Incomplete and can never be Accepted.
            if !self.has_gap
                && !truncated
                && (self.stdout_bytes != outcome.stdout().total_bytes()
                    || self.stderr_bytes != outcome.stderr().total_bytes()
                    || self.stdout.finalize().as_bytes()
                        != blake3::hash(outcome.stdout().retained()).as_bytes()
                    || self.stderr.finalize().as_bytes()
                        != blake3::hash(outcome.stderr().retained()).as_bytes())
            {
                return Err(VerificationOutputAuditError::TerminalOutputMismatch);
            }
        } else {
            hash_output_field(&mut self.output, b"outcome", b"absent");
        }
        let integrity = match (self.has_gap, truncated) {
            (false, false) => VerificationOutputIntegrity::Complete,
            (true, false) => VerificationOutputIntegrity::Gapped,
            (false, true) => VerificationOutputIntegrity::Truncated,
            (true, true) => VerificationOutputIntegrity::GappedAndTruncated,
        };
        let fingerprint =
            VerificationOutputFingerprint::from_bytes(*self.output.finalize().as_bytes());
        Ok(match execution.state() {
            ExecutionState::Completed
                if execution
                    .outcome()
                    .and_then(crate::ExecutionOutcome::exit_code)
                    == Some(0)
                    && integrity.is_complete() =>
            {
                VerificationRunTerminalStatus::accepted(fingerprint)
            }
            ExecutionState::Completed
                if execution
                    .outcome()
                    .and_then(crate::ExecutionOutcome::exit_code)
                    == Some(0) =>
            {
                VerificationRunTerminalStatus::incomplete(fingerprint, integrity)
            }
            ExecutionState::Interrupted => {
                VerificationRunTerminalStatus::recovery_required(Some(fingerprint), Some(integrity))
                    .map_err(|_| VerificationOutputAuditError::InvalidTerminalStatus)?
            }
            ExecutionState::Starting | ExecutionState::Running => {
                return Err(VerificationOutputAuditError::TerminalRequired);
            }
            ExecutionState::Completed
            | ExecutionState::Failed
            | ExecutionState::TimedOut
            | ExecutionState::Cancelled => {
                VerificationRunTerminalStatus::rejected(fingerprint, integrity)
            }
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutputAuditError {
    #[error("verification output belongs to a different execution")]
    ExecutionMismatch,
    #[error("verification output sequence coverage is not exact")]
    SequenceCoverage,
    #[error("verification output counter overflowed")]
    IntegerOverflow,
    #[error("verification output requires a terminal execution")]
    TerminalRequired,
    #[error("verification output does not match terminal retained output")]
    TerminalOutputMismatch,
    #[error("verification terminal status is invalid")]
    InvalidTerminalStatus,
}

fn hash_output_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&u64::try_from(label.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(label);
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}

fn hash_output_u64(hasher: &mut blake3::Hasher, label: &[u8], value: u64) {
    hash_output_field(hasher, label, &value.to_le_bytes());
}

fn hash_optional_i32(hasher: &mut blake3::Hasher, label: &[u8], value: Option<i32>) {
    match value {
        Some(value) => hash_output_field(hasher, label, &value.to_le_bytes()),
        None => hash_output_field(hasher, label, &[]),
    }
}

const fn execution_state_tag(state: ExecutionState) -> u8 {
    match state {
        ExecutionState::Starting => 0,
        ExecutionState::Running => 1,
        ExecutionState::Completed => 2,
        ExecutionState::Failed => 3,
        ExecutionState::TimedOut => 4,
        ExecutionState::Cancelled => 5,
        ExecutionState::Interrupted => 6,
    }
}

impl fmt::Debug for VerificationOutputFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VerificationOutputFingerprint")
            .field(&"<redacted>")
            .finish()
    }
}

impl fmt::Display for VerificationOutputFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        FileContentHash::from_bytes(self.0).fmt(formatter)
    }
}

impl FromStr for VerificationOutputFingerprint {
    type Err = VerificationOutputFingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hash = FileContentHash::from_str(value)
            .map_err(VerificationOutputFingerprintError::InvalidEncoding)?;
        Ok(Self::from_hash(hash))
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutputFingerprintError {
    #[error("verification output fingerprint is invalid")]
    InvalidEncoding(#[source] FileContentHashParseError),
}

impl From<VerificationOutputFingerprint> for FileContentHash {
    fn from(value: VerificationOutputFingerprint) -> Self {
        value.hash()
    }
}

impl From<FileContentHash> for VerificationOutputFingerprint {
    fn from(value: FileContentHash) -> Self {
        Self::from_hash(value)
    }
}

/// Integrity of the retained output evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationOutputIntegrity {
    /// Every output event was observed and no output bound was reached.
    Complete,
    /// One or more output events were missing from the evidence stream.
    Gapped,
    /// The output was cut off by a retained-output bound.
    Truncated,
    /// Output events were missing and the retained output was bounded.
    GappedAndTruncated,
}

impl VerificationOutputIntegrity {
    pub const fn has_gaps(self) -> bool {
        matches!(self, Self::Gapped | Self::GappedAndTruncated)
    }

    pub const fn is_gapped(self) -> bool {
        self.has_gaps()
    }

    pub const fn is_truncated(self) -> bool {
        matches!(self, Self::Truncated | Self::GappedAndTruncated)
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Terminal interpretation of one verification run.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerificationRunTerminalStatus {
    disposition: VerificationRunDisposition,
    output_fingerprint: Option<VerificationOutputFingerprint>,
    output_integrity: Option<VerificationOutputIntegrity>,
}

impl fmt::Debug for VerificationRunTerminalStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationRunTerminalStatus")
            .field("disposition", &self.disposition)
            .field(
                "output_fingerprint_present",
                &self.output_fingerprint.is_some(),
            )
            .field("output_integrity", &self.output_integrity)
            .finish()
    }
}

impl VerificationRunTerminalStatus {
    /// Construct terminal status after validating the disposition/evidence
    /// relationship.
    pub fn new(
        disposition: VerificationRunDisposition,
        output_fingerprint: Option<VerificationOutputFingerprint>,
        output_integrity: Option<VerificationOutputIntegrity>,
    ) -> Result<Self, VerificationRunTerminalStatusError> {
        if disposition != VerificationRunDisposition::RecoveryRequired
            && (output_fingerprint.is_none() || output_integrity.is_none())
        {
            return Err(VerificationRunTerminalStatusError::OutputEvidenceRequired { disposition });
        }

        if output_fingerprint.is_some() != output_integrity.is_some() {
            return Err(VerificationRunTerminalStatusError::PartialOutputEvidence);
        }

        if disposition == VerificationRunDisposition::Accepted
            && output_integrity != Some(VerificationOutputIntegrity::Complete)
        {
            return Err(VerificationRunTerminalStatusError::AcceptedRequiresCompleteOutput);
        }

        Ok(Self {
            disposition,
            output_fingerprint,
            output_integrity,
        })
    }

    /// Construct an accepted terminal result with complete output evidence.
    pub const fn accepted(output_fingerprint: VerificationOutputFingerprint) -> Self {
        Self {
            disposition: VerificationRunDisposition::Accepted,
            output_fingerprint: Some(output_fingerprint),
            output_integrity: Some(VerificationOutputIntegrity::Complete),
        }
    }

    /// Construct a rejected terminal result with its output evidence.
    pub const fn rejected(
        output_fingerprint: VerificationOutputFingerprint,
        output_integrity: VerificationOutputIntegrity,
    ) -> Self {
        Self {
            disposition: VerificationRunDisposition::Rejected,
            output_fingerprint: Some(output_fingerprint),
            output_integrity: Some(output_integrity),
        }
    }

    /// Construct an incomplete terminal result with its output evidence.
    pub const fn incomplete(
        output_fingerprint: VerificationOutputFingerprint,
        output_integrity: VerificationOutputIntegrity,
    ) -> Self {
        Self {
            disposition: VerificationRunDisposition::Incomplete,
            output_fingerprint: Some(output_fingerprint),
            output_integrity: Some(output_integrity),
        }
    }

    /// Construct recovery-required status.  Recovery may have no output
    /// evidence when the producer's terminal outcome is uncertain.
    pub fn recovery_required(
        output_fingerprint: Option<VerificationOutputFingerprint>,
        output_integrity: Option<VerificationOutputIntegrity>,
    ) -> Result<Self, VerificationRunTerminalStatusError> {
        Self::new(
            VerificationRunDisposition::RecoveryRequired,
            output_fingerprint,
            output_integrity,
        )
    }

    pub const fn disposition(self) -> VerificationRunDisposition {
        self.disposition
    }

    pub const fn output_fingerprint(self) -> Option<VerificationOutputFingerprint> {
        self.output_fingerprint
    }

    pub const fn output_integrity(self) -> Option<VerificationOutputIntegrity> {
        self.output_integrity
    }

    pub const fn integrity(self) -> Option<VerificationOutputIntegrity> {
        self.output_integrity()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRunTerminalStatusError {
    #[error("{disposition:?} verification requires output fingerprint and integrity evidence")]
    OutputEvidenceRequired {
        disposition: VerificationRunDisposition,
    },
    #[error("verification output fingerprint and integrity must be present together")]
    PartialOutputEvidence,
    #[error("accepted verification requires complete output integrity")]
    AcceptedRequiresCompleteOutput,
}

/// Disposition of a terminal verification run.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationRunDisposition {
    Accepted,
    Rejected,
    Incomplete,
    RecoveryRequired,
}

/// Lifecycle state for one verification run.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationRunState {
    Starting,
    Terminal(VerificationRunTerminalStatus),
}

impl VerificationRunState {
    pub const fn starting() -> Self {
        Self::Starting
    }

    pub const fn terminal(status: VerificationRunTerminalStatus) -> Self {
        Self::Terminal(status)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal(_))
    }

    pub const fn terminal_status(self) -> Option<VerificationRunTerminalStatus> {
        match self {
            Self::Starting => None,
            Self::Terminal(status) => Some(status),
        }
    }

    pub const fn disposition(self) -> Option<VerificationRunDisposition> {
        match self {
            Self::Starting => None,
            Self::Terminal(status) => Some(status.disposition()),
        }
    }
}

/// Bounded immutable evidence binding one frozen input snapshot to a run.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerificationInputEvidence {
    input_id: VerificationInputId,
    fingerprint: VerificationInputFingerprint,
    policy: VerificationInputPolicy,
    file_count: u32,
    total_bytes: FileByteCount,
}

impl fmt::Debug for VerificationInputEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationInputEvidence")
            .field("input_id", &self.input_id)
            .field("policy", &self.policy)
            .field("file_count", &self.file_count)
            .field("total_bytes", &self.total_bytes)
            .field("fingerprint_present", &true)
            .finish_non_exhaustive()
    }
}

impl VerificationInputEvidence {
    pub fn new(
        input_id: VerificationInputId,
        manifest: &VerificationInputManifest,
    ) -> Result<Self, VerificationInputEvidenceError> {
        Self::from_manifest(input_id, manifest)
    }

    /// Capture only the manifest identity and bounded counters.
    pub fn from_manifest(
        input_id: VerificationInputId,
        manifest: &VerificationInputManifest,
    ) -> Result<Self, VerificationInputEvidenceError> {
        let file_count = u32::try_from(manifest.file_count()).map_err(|_| {
            VerificationInputEvidenceError::FileCountWidth {
                actual: manifest.file_count(),
            }
        })?;
        Self::from_parts(
            input_id,
            manifest.fingerprint(),
            manifest.policy(),
            file_count,
            manifest.total_bytes(),
        )
    }

    /// Rehydrate scalar evidence after an adapter validates persisted integer
    /// widths and policy values.
    pub fn from_parts(
        input_id: VerificationInputId,
        fingerprint: VerificationInputFingerprint,
        policy: VerificationInputPolicy,
        file_count: u32,
        total_bytes: FileByteCount,
    ) -> Result<Self, VerificationInputEvidenceError> {
        let file_count_usize = usize::try_from(file_count)
            .map_err(|_| VerificationInputEvidenceError::FileCountWidth { actual: usize::MAX })?;
        if file_count_usize > MAX_VERIFICATION_INPUT_FILES {
            return Err(VerificationInputEvidenceError::FileCountOutOfRange {
                actual: file_count,
                maximum: MAX_VERIFICATION_INPUT_FILES,
            });
        }
        if total_bytes.get() > MAX_VERIFICATION_INPUT_BYTES {
            return Err(VerificationInputEvidenceError::ByteCountOutOfRange {
                actual: total_bytes.get(),
                maximum: MAX_VERIFICATION_INPUT_BYTES,
            });
        }
        Ok(Self {
            input_id,
            fingerprint,
            policy,
            file_count,
            total_bytes,
        })
    }

    pub const fn input_id(self) -> VerificationInputId {
        self.input_id
    }

    pub const fn id(self) -> VerificationInputId {
        self.input_id()
    }

    pub const fn fingerprint(self) -> VerificationInputFingerprint {
        self.fingerprint
    }

    pub const fn input_fingerprint(self) -> VerificationInputFingerprint {
        self.fingerprint()
    }

    pub const fn policy(self) -> VerificationInputPolicy {
        self.policy
    }

    pub const fn file_count(self) -> u32 {
        self.file_count
    }

    pub const fn total_bytes(self) -> FileByteCount {
        self.total_bytes
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationInputEvidenceError {
    #[error("verification input file count cannot be represented as u32: {actual}")]
    FileCountWidth { actual: usize },
    #[error("verification input file count {actual} exceeds the maximum of {maximum}")]
    FileCountOutOfRange { actual: u32, maximum: usize },
    #[error("verification input byte count {actual} exceeds the maximum of {maximum}")]
    ByteCountOutOfRange { actual: u64, maximum: u64 },
}

/// Immutable evidence record for one execution's verification.
///
/// `execution_id` is the canonical one-to-one run identity.  A separate
/// `VerificationRunId` would create a second identity authority without
/// adding any semantic value.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerificationRun {
    execution_id: ExecutionId,
    workspace_id: WorkspaceId,
    input: VerificationInputEvidence,
    catalog_fingerprint: Option<ProjectCommandCatalogFingerprint>,
    state: VerificationRunState,
}

impl fmt::Debug for VerificationRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationRun")
            .field("execution_id", &self.execution_id)
            .field("workspace_id", &self.workspace_id)
            .field("input", &self.input)
            .field(
                "catalog_fingerprint_present",
                &self.catalog_fingerprint.is_some(),
            )
            .field("state", &self.state)
            .finish()
    }
}

impl VerificationRun {
    pub const fn new(
        execution_id: ExecutionId,
        workspace_id: WorkspaceId,
        input: VerificationInputEvidence,
        catalog_fingerprint: Option<ProjectCommandCatalogFingerprint>,
    ) -> Self {
        Self::starting(execution_id, workspace_id, input, catalog_fingerprint)
    }

    /// Begin a run with no terminal output evidence yet.
    pub const fn starting(
        execution_id: ExecutionId,
        workspace_id: WorkspaceId,
        input: VerificationInputEvidence,
        catalog_fingerprint: Option<ProjectCommandCatalogFingerprint>,
    ) -> Self {
        Self {
            execution_id,
            workspace_id,
            input,
            catalog_fingerprint,
            state: VerificationRunState::Starting,
        }
    }

    /// Construct or rehydrate a run after validating the terminal state.
    pub fn from_parts(
        execution_id: ExecutionId,
        workspace_id: WorkspaceId,
        input: VerificationInputEvidence,
        catalog_fingerprint: Option<ProjectCommandCatalogFingerprint>,
        state: VerificationRunState,
    ) -> Result<Self, VerificationRunError> {
        if let VerificationRunState::Terminal(status) = state {
            // `VerificationRunTerminalStatus` is normally constructed through
            // its validator.  Re-running the invariant here makes the state
            // boundary robust if a status was obtained from a future decoder.
            let _validated = VerificationRunTerminalStatus::new(
                status.disposition(),
                status.output_fingerprint(),
                status.output_integrity(),
            )?;
        }
        Ok(Self {
            execution_id,
            workspace_id,
            input,
            catalog_fingerprint,
            state,
        })
    }

    /// Construct a terminal run from already validated terminal status.
    pub fn terminal(
        execution_id: ExecutionId,
        workspace_id: WorkspaceId,
        input: VerificationInputEvidence,
        catalog_fingerprint: Option<ProjectCommandCatalogFingerprint>,
        status: VerificationRunTerminalStatus,
    ) -> Result<Self, VerificationRunError> {
        Self::from_parts(
            execution_id,
            workspace_id,
            input,
            catalog_fingerprint,
            VerificationRunState::Terminal(status),
        )
    }

    /// Move a starting run to a terminal state while preserving its exact
    /// identity and input/catalog bindings.
    pub fn finish(
        &self,
        status: VerificationRunTerminalStatus,
    ) -> Result<Self, VerificationRunError> {
        if self.state.is_terminal() {
            return Err(VerificationRunError::TerminalMutation);
        }
        Self::terminal(
            self.execution_id,
            self.workspace_id,
            self.input,
            self.catalog_fingerprint,
            status,
        )
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn id(&self) -> ExecutionId {
        self.execution_id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn input(&self) -> VerificationInputEvidence {
        self.input
    }

    pub const fn input_evidence(&self) -> VerificationInputEvidence {
        self.input()
    }

    pub const fn input_id(&self) -> VerificationInputId {
        self.input.input_id()
    }

    pub const fn input_fingerprint(&self) -> VerificationInputFingerprint {
        self.input.fingerprint()
    }

    pub const fn input_policy(&self) -> VerificationInputPolicy {
        self.input.policy()
    }

    pub const fn input_file_count(&self) -> u32 {
        self.input.file_count()
    }

    pub const fn input_total_bytes(&self) -> FileByteCount {
        self.input.total_bytes()
    }

    pub const fn catalog_fingerprint(&self) -> Option<ProjectCommandCatalogFingerprint> {
        self.catalog_fingerprint
    }

    pub const fn state(&self) -> VerificationRunState {
        self.state
    }

    pub const fn terminal_status(&self) -> Option<VerificationRunTerminalStatus> {
        self.state.terminal_status()
    }

    pub const fn disposition(&self) -> Option<VerificationRunDisposition> {
        self.state.disposition()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRunError {
    #[error(transparent)]
    TerminalStatus(#[from] VerificationRunTerminalStatusError),
    #[error("terminal verification run cannot be mutated")]
    TerminalMutation,
}

/// Maximum latest-per-command entries carried by one shared verification projection.
pub const MAX_VERIFICATION_PROJECTION_ENTRIES: usize = 64;

/// Product-wide interpretation of one durable `VerificationRun`.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationProjectionState {
    Running,
    Passed,
    Failed,
}

impl VerificationProjectionState {
    pub fn from_run_state(state: VerificationRunState) -> Self {
        match state {
            VerificationRunState::Starting => Self::Running,
            VerificationRunState::Terminal(status)
                if status.disposition() == VerificationRunDisposition::Accepted =>
            {
                Self::Passed
            }
            VerificationRunState::Terminal(_) => Self::Failed,
        }
    }
}

/// Latest durable verification evidence for one trusted project-command identity.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationProjectionEntry {
    command_id: ExecutionCommandId,
    execution_id: ExecutionId,
    state: VerificationProjectionState,
    disposition: Option<VerificationRunDisposition>,
    updated_at: TimestampMillis,
}

impl VerificationProjectionEntry {
    pub fn from_run(
        command_id: ExecutionCommandId,
        run: &VerificationRun,
        updated_at: TimestampMillis,
    ) -> Self {
        Self {
            command_id,
            execution_id: run.execution_id(),
            state: VerificationProjectionState::from_run_state(run.state()),
            disposition: run.disposition(),
            updated_at,
        }
    }

    pub fn command_id(&self) -> &ExecutionCommandId {
        &self.command_id
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn state(&self) -> VerificationProjectionState {
        self.state
    }

    pub const fn disposition(&self) -> Option<VerificationRunDisposition> {
        self.disposition
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
}

/// Bounded latest-per-command verification snapshot shared by product surfaces.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationProjection {
    entries: Vec<VerificationProjectionEntry>,
}

impl VerificationProjection {
    pub fn new(
        entries: Vec<VerificationProjectionEntry>,
    ) -> Result<Self, VerificationProjectionError> {
        if entries.len() > MAX_VERIFICATION_PROJECTION_ENTRIES {
            return Err(VerificationProjectionError::TooManyEntries {
                actual: entries.len(),
                maximum: MAX_VERIFICATION_PROJECTION_ENTRIES,
            });
        }
        for (index, entry) in entries.iter().enumerate() {
            if entries[..index]
                .iter()
                .any(|existing| existing.command_id() == entry.command_id())
            {
                return Err(VerificationProjectionError::DuplicateCommand {
                    command_id: entry.command_id().clone(),
                });
            }
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[VerificationProjectionEntry] {
        &self.entries
    }

    pub fn entry_for_command(&self, command_id: &str) -> Option<&VerificationProjectionEntry> {
        self.entries
            .iter()
            .find(|entry| entry.command_id().as_str() == command_id)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerificationProjectionError {
    #[error("verification projection has {actual} entries; maximum is {maximum}")]
    TooManyEntries { actual: usize, maximum: usize },
    #[error("verification projection contains duplicate command {command_id}")]
    DuplicateCommand { command_id: ExecutionCommandId },
}

/// Exact association between an execution and one Goal verification
/// requirement.  The Goal revision is retained so a later revision cannot
/// reinterpret the requirement index.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VerificationRequirementAssociation {
    execution_id: ExecutionId,
    goal_id: GoalId,
    goal_revision: GoalRevision,
    requirement_index: u16,
}

impl VerificationRequirementAssociation {
    pub fn new(
        execution_id: ExecutionId,
        goal_id: GoalId,
        goal_revision: GoalRevision,
        requirement_index: u16,
    ) -> Result<Self, VerificationRequirementAssociationError> {
        if usize::from(requirement_index) >= MAX_GOAL_VERIFICATION_REQUIREMENTS {
            return Err(VerificationRequirementAssociationError::IndexOutOfRange {
                actual: requirement_index,
                maximum: MAX_GOAL_VERIFICATION_REQUIREMENTS,
            });
        }
        Ok(Self {
            execution_id,
            goal_id,
            goal_revision,
            requirement_index,
        })
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn goal_revision(self) -> GoalRevision {
        self.goal_revision
    }

    pub const fn requirement_index(self) -> u16 {
        self.requirement_index
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRequirementAssociationError {
    #[error("verification requirement index {actual} exceeds the maximum count of {maximum}")]
    IndexOutOfRange { actual: u16, maximum: usize },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use uuid::Uuid;

    use super::*;
    use crate::{FileContentHash, VerificationInputEntry, WorkspaceRelativePath};

    fn ids() -> (ExecutionId, WorkspaceId, VerificationInputId, GoalId) {
        (
            ExecutionId::from_uuid(Uuid::from_u128(1)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            VerificationInputId::from_uuid(Uuid::from_u128(3)),
            GoalId::from_uuid(Uuid::from_u128(4)),
        )
    }

    fn input_manifest() -> Result<VerificationInputManifest, Box<dyn Error>> {
        let entry = VerificationInputEntry::file(
            WorkspaceRelativePath::new("main.rs".into())?,
            0o644,
            FileByteCount::new(7),
            FileContentHash::from_bytes([5; 32]),
        )?;
        Ok(VerificationInputManifest::new(
            VerificationInputPolicy::V1,
            vec![entry],
        )?)
    }

    fn input_evidence() -> Result<VerificationInputEvidence, Box<dyn Error>> {
        let (_, _, input_id, _) = ids();
        Ok(VerificationInputEvidence::from_manifest(
            input_id,
            &input_manifest()?,
        )?)
    }

    fn output(value: u8) -> VerificationOutputFingerprint {
        VerificationOutputFingerprint::from_bytes([value; VerificationOutputFingerprint::BYTE_LEN])
    }

    fn catalog(value: u8) -> ProjectCommandCatalogFingerprint {
        ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes([value; 32]))
    }

    #[test]
    fn output_fingerprint_is_strict_and_redacted_in_debug() -> Result<(), Box<dyn Error>> {
        let fingerprint = output(0xab);
        let encoded = fingerprint.to_string();
        assert_eq!(encoded.len(), VerificationOutputFingerprint::ENCODED_LEN);
        assert_eq!(
            encoded.parse::<VerificationOutputFingerprint>()?,
            fingerprint
        );
        assert!(
            "blake3-256:AB00000000000000000000000000000000000000000000000000000000000000"
                .parse::<VerificationOutputFingerprint>()
                .is_err()
        );
        assert!("ab".parse::<VerificationOutputFingerprint>().is_err());
        let debug = format!("{fingerprint:?}");
        assert!(!debug.contains("abab"));
        Ok(())
    }

    #[test]
    fn integrity_flags_are_explicit() {
        assert!(VerificationOutputIntegrity::Complete.is_complete());
        assert!(!VerificationOutputIntegrity::Complete.is_gapped());
        assert!(VerificationOutputIntegrity::Gapped.is_gapped());
        assert!(VerificationOutputIntegrity::Truncated.is_truncated());
        assert!(VerificationOutputIntegrity::GappedAndTruncated.is_gapped());
        assert!(VerificationOutputIntegrity::GappedAndTruncated.is_truncated());
    }

    #[test]
    fn output_accumulator_requires_exact_sequence_and_gap_coverage() -> Result<(), Box<dyn Error>> {
        let execution_id = ids().0;
        let out_of_order = ExecutionOutputEvent::Chunk(crate::ExecutionOutputChunk::new(
            execution_id,
            ExecutionOutputSequence::new(2)?,
            ExecutionOutputStream::Stdout,
            b"late",
        )?);
        assert_eq!(
            VerificationOutputAccumulator::new(execution_id)
                .push(&out_of_order)
                .err(),
            Some(VerificationOutputAuditError::SequenceCoverage)
        );
        let mut fingerprints = [None; 3];
        for (index, cause) in [
            crate::ExecutionOutputGapCause::Backpressure,
            crate::ExecutionOutputGapCause::OutputLimit,
            crate::ExecutionOutputGapCause::BackpressureAndOutputLimit,
        ]
        .into_iter()
        .enumerate()
        {
            let gap = ExecutionOutputEvent::Gap(crate::ExecutionOutputGap::new(
                execution_id,
                ExecutionOutputSequence::new(3)?,
                crate::ExecutionOutputGapParts::new(
                    ExecutionOutputSequence::new(1)?,
                    ExecutionOutputSequence::new(2)?,
                    None,
                    8,
                    2,
                    cause,
                ),
            )?);
            let next = ExecutionOutputEvent::Chunk(crate::ExecutionOutputChunk::new(
                execution_id,
                ExecutionOutputSequence::new(4)?,
                ExecutionOutputStream::Stderr,
                b"after-gap",
            )?);
            let mut accumulator = VerificationOutputAccumulator::new(execution_id);
            accumulator.push(&gap)?;
            accumulator.push(&next)?;
            assert!(accumulator.has_gap);
            let fingerprint = accumulator.output.finalize();
            assert!(!fingerprints[..index].contains(&Some(fingerprint)));
            fingerprints[index] = Some(fingerprint);
        }
        Ok(())
    }

    #[test]
    fn input_evidence_captures_manifest_identity_and_validates_bounds() -> Result<(), Box<dyn Error>>
    {
        let evidence = input_evidence()?;
        assert_eq!(evidence.file_count(), 1);
        assert_eq!(evidence.total_bytes().get(), 7);
        assert_eq!(evidence.policy(), VerificationInputPolicy::V1);
        assert_eq!(evidence.input_id(), ids().2);
        assert_eq!(evidence.fingerprint(), input_manifest()?.fingerprint());
        assert!(
            VerificationInputEvidence::from_parts(
                ids().2,
                VerificationInputFingerprint::from_bytes([0; 32]),
                VerificationInputPolicy::V1,
                u32::try_from(MAX_VERIFICATION_INPUT_FILES + 1)?,
                FileByteCount::new(0),
            )
            .is_err()
        );
        assert!(
            VerificationInputEvidence::from_parts(
                ids().2,
                VerificationInputFingerprint::from_bytes([0; 32]),
                VerificationInputPolicy::V1,
                0,
                FileByteCount::new(MAX_VERIFICATION_INPUT_BYTES + 1),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn terminal_status_enforces_output_evidence_contract() -> Result<(), Box<dyn Error>> {
        let accepted = VerificationRunTerminalStatus::accepted(output(1));
        assert_eq!(accepted.disposition(), VerificationRunDisposition::Accepted);
        assert_eq!(
            accepted.output_integrity(),
            Some(VerificationOutputIntegrity::Complete)
        );
        assert!(
            VerificationRunTerminalStatus::new(
                VerificationRunDisposition::Accepted,
                Some(output(1)),
                Some(VerificationOutputIntegrity::Gapped),
            )
            .is_err()
        );
        assert!(
            VerificationRunTerminalStatus::new(VerificationRunDisposition::Rejected, None, None,)
                .is_err()
        );
        let recovery = VerificationRunTerminalStatus::recovery_required(None, None)?;
        assert_eq!(recovery.output_fingerprint(), None);
        assert!(VerificationRunTerminalStatus::recovery_required(Some(output(1)), None).is_err());
        Ok(())
    }

    #[test]
    fn run_is_keyed_by_execution_and_preserves_bindings_across_finish() -> Result<(), Box<dyn Error>>
    {
        let (execution_id, workspace_id, _, _) = ids();
        let starting = VerificationRun::starting(
            execution_id,
            workspace_id,
            input_evidence()?,
            Some(catalog(9)),
        );
        assert_eq!(starting.execution_id(), execution_id);
        assert_eq!(starting.workspace_id(), workspace_id);
        assert_eq!(starting.state(), VerificationRunState::Starting);
        let terminal = starting.finish(VerificationRunTerminalStatus::accepted(output(8)))?;
        assert_eq!(terminal.execution_id(), execution_id);
        assert_eq!(terminal.catalog_fingerprint(), Some(catalog(9)));
        assert_eq!(
            terminal.disposition(),
            Some(VerificationRunDisposition::Accepted)
        );
        assert!(
            terminal
                .finish(VerificationRunTerminalStatus::accepted(output(7)))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn verification_projection_state_follows_durable_run_state() -> Result<(), Box<dyn Error>> {
        let (execution_id, workspace_id, _, _) = ids();
        let command_id = ExecutionCommandId::new("make:check".to_owned())?;
        let starting = VerificationRun::starting(
            execution_id,
            workspace_id,
            input_evidence()?,
            Some(catalog(9)),
        );
        let running = VerificationProjectionEntry::from_run(
            command_id.clone(),
            &starting,
            TimestampMillis::new(10)?,
        );
        assert_eq!(running.state(), VerificationProjectionState::Running);
        assert_eq!(running.disposition(), None);

        let accepted = VerificationRun::starting(
            execution_id,
            workspace_id,
            input_evidence()?,
            Some(catalog(9)),
        )
        .finish(VerificationRunTerminalStatus::accepted(output(8)))?;
        let passed = VerificationProjectionEntry::from_run(
            command_id.clone(),
            &accepted,
            TimestampMillis::new(11)?,
        );
        assert_eq!(passed.state(), VerificationProjectionState::Passed);
        assert_eq!(
            passed.disposition(),
            Some(VerificationRunDisposition::Accepted)
        );

        let incomplete = VerificationRun::starting(
            execution_id,
            workspace_id,
            input_evidence()?,
            Some(catalog(9)),
        )
        .finish(VerificationRunTerminalStatus::recovery_required(
            None, None,
        )?)?;
        let failed = VerificationProjectionEntry::from_run(
            command_id.clone(),
            &incomplete,
            TimestampMillis::new(12)?,
        );
        assert_eq!(failed.state(), VerificationProjectionState::Failed);
        assert_eq!(
            failed.disposition(),
            Some(VerificationRunDisposition::RecoveryRequired)
        );

        let projection = VerificationProjection::new(vec![failed])?;
        assert_eq!(
            projection
                .entry_for_command("make:check")
                .map(VerificationProjectionEntry::state),
            Some(VerificationProjectionState::Failed)
        );
        assert!(projection.entry_for_command("make:test").is_none());
        Ok(())
    }

    #[test]
    fn requirement_association_binds_exact_goal_revision_and_u16_index()
    -> Result<(), Box<dyn Error>> {
        let (execution_id, _, _, goal_id) = ids();
        let revision = GoalRevision::new(7)?;
        let association =
            VerificationRequirementAssociation::new(execution_id, goal_id, revision, 31)?;
        assert_eq!(association.execution_id(), execution_id);
        assert_eq!(association.goal_id(), goal_id);
        assert_eq!(association.goal_revision(), revision);
        assert_eq!(association.requirement_index(), 31);
        assert!(
            VerificationRequirementAssociation::new(execution_id, goal_id, revision, 32).is_err()
        );
        Ok(())
    }
}
