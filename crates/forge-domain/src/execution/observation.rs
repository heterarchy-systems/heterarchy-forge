//! Compact execution evidence. Output bytes belong to the bounded ledger read.

use super::{
    ActivityId, ExecutionAgentProvenance, ExecutionAttribution, ExecutionFailureCode, ExecutionId,
    ExecutionMode, ExecutionRecordDefinition, ExecutionRecordError, ExecutionRequestDigest,
    ExecutionRevision, ExecutionState, ExecutionTermination, ExecutionTimestamps, MAX_OUTPUT_BYTES,
    TimestampMillis, WorkspaceId, validate_execution_termination_evidence,
};
use crate::{VerificationRequirementAssociation, VerificationRun, VerificationRunDisposition};

/// Explicit observation selection, independent of any storage or transport.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionObservationSelection {
    activity_id: ActivityId,
    goal: Option<crate::GoalAttribution>,
}
impl ExecutionObservationSelection {
    pub const fn new(activity_id: ActivityId, goal: Option<crate::GoalAttribution>) -> Self {
        Self { activity_id, goal }
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn goal(self) -> Option<crate::GoalAttribution> {
        self.goal
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionOutputSummary {
    retained_bytes: u64,
    total_bytes: u64,
    truncated: bool,
}

impl ExecutionOutputSummary {
    pub fn new(
        retained_bytes: u64,
        total_bytes: u64,
        truncated: bool,
    ) -> Result<Self, ExecutionRecordError> {
        if retained_bytes > MAX_OUTPUT_BYTES
            || retained_bytes > total_bytes
            || truncated != (retained_bytes < total_bytes)
        {
            return Err(ExecutionRecordError::InvalidOutput);
        }
        Ok(Self {
            retained_bytes,
            total_bytes,
            truncated,
        })
    }
    pub const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }
    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }
    pub const fn truncated(self) -> bool {
        self.truncated
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionTerminalSummary {
    termination: ExecutionTermination,
    duration_millis: u64,
    stdout: ExecutionOutputSummary,
    stderr: ExecutionOutputSummary,
}

impl ExecutionTerminalSummary {
    pub const fn new(
        termination: ExecutionTermination,
        duration_millis: u64,
        stdout: ExecutionOutputSummary,
        stderr: ExecutionOutputSummary,
    ) -> Self {
        Self {
            termination,
            duration_millis,
            stdout,
            stderr,
        }
    }
    pub const fn termination(self) -> ExecutionTermination {
        self.termination
    }
    pub const fn duration_millis(self) -> u64 {
        self.duration_millis
    }
    pub const fn stdout(self) -> ExecutionOutputSummary {
        self.stdout
    }
    pub const fn stderr(self) -> ExecutionOutputSummary {
        self.stderr
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionObservationLifecycle {
    state: ExecutionState,
    timestamps: ExecutionTimestamps,
    revision: ExecutionRevision,
    terminal: Option<ExecutionTerminalSummary>,
    failure_code: Option<ExecutionFailureCode>,
}

impl ExecutionObservationLifecycle {
    pub const fn new(
        state: ExecutionState,
        timestamps: ExecutionTimestamps,
        revision: ExecutionRevision,
        terminal: Option<ExecutionTerminalSummary>,
        failure_code: Option<ExecutionFailureCode>,
    ) -> Self {
        Self {
            state,
            timestamps,
            revision,
            terminal,
            failure_code,
        }
    }
}

/// Immutable metadata from the same execution record, without stdout/stderr blobs.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionObservationHeader {
    attribution: ExecutionAttribution,
    definition: ExecutionRecordDefinition,
    lifecycle: ExecutionObservationLifecycle,
    provenance: Option<ExecutionAgentProvenance>,
}

impl ExecutionObservationHeader {
    pub fn from_parts(
        attribution: ExecutionAttribution,
        definition: ExecutionRecordDefinition,
        lifecycle: ExecutionObservationLifecycle,
        provenance: Option<ExecutionAgentProvenance>,
    ) -> Result<Self, ExecutionRecordError> {
        if provenance
            .as_ref()
            .is_some_and(|value| value.execution_id() != attribution.id())
        {
            return Err(ExecutionRecordError::ProvenanceExecutionMismatch);
        }
        validate_execution_termination_evidence(
            lifecycle.state,
            lifecycle
                .terminal
                .map(ExecutionTerminalSummary::termination),
            lifecycle.failure_code,
        )?;
        Ok(Self {
            attribution,
            definition,
            lifecycle,
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
        self.definition.mode
    }
    pub const fn cwd(&self) -> Option<&crate::WorkspaceRelativePath> {
        self.definition.cwd.as_ref()
    }
    pub const fn limits(&self) -> super::ExecutionLimits {
        self.definition.limits
    }
    pub const fn permissions(&self) -> super::ExecutionPermissions {
        self.definition.permissions
    }
    pub const fn request_digest(&self) -> ExecutionRequestDigest {
        self.definition.request_digest
    }
    pub const fn state(&self) -> ExecutionState {
        self.lifecycle.state
    }
    pub const fn revision(&self) -> ExecutionRevision {
        self.lifecycle.revision
    }
    pub const fn timestamps(&self) -> ExecutionTimestamps {
        self.lifecycle.timestamps
    }
    pub const fn terminal(&self) -> Option<ExecutionTerminalSummary> {
        self.lifecycle.terminal
    }
    pub const fn failure_code(&self) -> Option<ExecutionFailureCode> {
        self.lifecycle.failure_code
    }
    pub const fn provenance(&self) -> Option<&ExecutionAgentProvenance> {
        self.provenance.as_ref()
    }
}

/// Durable run/input/output and requirement links, retaining their actual revision.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEvidenceSnapshot {
    run: VerificationRun,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: u64,
    requirements: Vec<VerificationRequirementAssociation>,
}

impl VerificationEvidenceSnapshot {
    pub fn new(
        header: &ExecutionObservationHeader,
        run: VerificationRun,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: u64,
        requirements: Vec<VerificationRequirementAssociation>,
    ) -> Result<Self, ExecutionRecordError> {
        if revision == 0
            || updated_at.get() < created_at.get()
            || run.execution_id() != header.id()
            || run.workspace_id() != header.workspace_id()
            || run.catalog_fingerprint()
                != header.provenance().and_then(|value| {
                    value
                        .project_command()
                        .map(crate::ProjectCommandEvidence::catalog_fingerprint)
                })
            || requirements.len() > 32
            || requirements
                .iter()
                .any(|link| link.execution_id() != header.id())
            || requirements.iter().any(|link| {
                header.provenance().is_none_or(|provenance| {
                    link.goal_id() != provenance.attribution().goal_id()
                        || link.goal_revision() != provenance.attribution().expected_goal_revision()
                })
            })
            || requirements
                .iter()
                .enumerate()
                .any(|(index, link)| requirements[..index].contains(link))
            || (run.disposition() == Some(VerificationRunDisposition::Accepted)
                && header.state() != ExecutionState::Completed)
        {
            return Err(ExecutionRecordError::InvalidEvidence);
        }
        Ok(Self {
            run,
            created_at,
            updated_at,
            revision,
            requirements,
        })
    }
    pub const fn run(&self) -> &VerificationRun {
        &self.run
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn requirements(&self) -> &[VerificationRequirementAssociation] {
        &self.requirements
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExecutionCompletionStatus;

    #[test]
    fn compact_output_counters_reject_impossible_or_unbounded_shapes() {
        assert!(ExecutionOutputSummary::new(1, 1, false).is_ok());
        assert!(ExecutionOutputSummary::new(1, 2, true).is_ok());
        assert!(ExecutionOutputSummary::new(2, 1, false).is_err());
        assert!(ExecutionOutputSummary::new(1, 2, false).is_err());
        assert!(ExecutionOutputSummary::new(1, 1, true).is_err());
        assert!(
            ExecutionOutputSummary::new(MAX_OUTPUT_BYTES + 1, MAX_OUTPUT_BYTES + 1, false).is_err()
        );
    }

    #[test]
    fn timeout_or_uncertainty_cannot_become_completed_metadata() {
        let timeout = ExecutionTermination::new(ExecutionCompletionStatus::TimedOut, Some(0), None);
        assert!(
            validate_execution_termination_evidence(ExecutionState::Completed, Some(timeout), None)
                .is_err()
        );
        assert!(
            validate_execution_termination_evidence(ExecutionState::TimedOut, Some(timeout), None)
                .is_ok()
        );
        assert!(
            validate_execution_termination_evidence(ExecutionState::Interrupted, None, None)
                .is_ok()
        );
        assert!(
            validate_execution_termination_evidence(ExecutionState::Completed, None, None).is_err()
        );
    }
}
