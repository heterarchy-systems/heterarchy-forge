use thiserror::Error;

use super::{
    ExecutionAttribution, ExecutionOutputCursor, ExecutionRequestDigest, ExecutionRevision,
    TimestampMillis,
};

/// The process-side evidence that closes an admitted native execution.
///
/// An admitted execution may prove that no child was created, or that its
/// process group was reaped.  These observations remain distinct durable
/// facts even though both close the process side of the execution.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeClosureProcess {
    NoChildSpawned,
    ProcessGroupReaped,
}

/// The Rust CI runtime evidence required by a native closure fact.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeClosureRuntime {
    NotApplicable,
    Cleaned,
}

/// The trusted launch family represented by a native closure fact.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeClosureLaunch {
    Baseline,
    RustCi,
    GeneratedPackage,
}

/// Checked input for an immutable native closure fact.
///
/// The parts retain only the evidence needed to bind native closure to one
/// exact execution terminal revision.  Terminal outcome and generated-package
/// manifest remain canonical fields of the execution journal and are not
/// copied into this fact.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionNativeClosureFactParts {
    pub attribution: ExecutionAttribution,
    pub request_digest: ExecutionRequestDigest,
    pub before_revision: ExecutionRevision,
    pub after_revision: ExecutionRevision,
    pub output_cursor: ExecutionOutputCursor,
    pub launch: NativeClosureLaunch,
    pub runtime: NativeClosureRuntime,
    pub process: NativeClosureProcess,
    pub observed_at: TimestampMillis,
}

/// Immutable evidence that one native execution reached a positively closed
/// process/runtime state at one exact terminal revision.
///
/// This is historical evidence, not a permission or a live-runtime handle.
/// Its fields deliberately exclude process identifiers, supervisor keys,
/// runtime pointers, outcomes, manifests, and authorization state.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionNativeClosureFact {
    attribution: ExecutionAttribution,
    request_digest: ExecutionRequestDigest,
    before_revision: ExecutionRevision,
    after_revision: ExecutionRevision,
    output_cursor: ExecutionOutputCursor,
    launch: NativeClosureLaunch,
    runtime: NativeClosureRuntime,
    process: NativeClosureProcess,
    observed_at: TimestampMillis,
}

impl ExecutionNativeClosureFact {
    /// Construct a closure fact after checking its identity, revision step,
    /// output ownership, and launch/runtime pairing.
    pub fn from_parts(
        parts: ExecutionNativeClosureFactParts,
    ) -> Result<Self, ExecutionNativeClosureFactError> {
        if parts.attribution.id().into_uuid().is_nil() {
            return Err(ExecutionNativeClosureFactError::NilExecutionId);
        }
        if parts.attribution.workspace_id().into_uuid().is_nil() {
            return Err(ExecutionNativeClosureFactError::NilWorkspaceId);
        }
        if parts.attribution.activity_id().into_uuid().is_nil() {
            return Err(ExecutionNativeClosureFactError::NilActivityId);
        }

        let expected_after = parts.before_revision.checked_next().map_err(|_| {
            ExecutionNativeClosureFactError::RevisionOverflow {
                before_revision: parts.before_revision,
            }
        })?;
        if parts.after_revision != expected_after {
            return Err(ExecutionNativeClosureFactError::RevisionStep {
                before_revision: parts.before_revision,
                after_revision: parts.after_revision,
            });
        }

        if parts.output_cursor.execution_id() != parts.attribution.id() {
            return Err(
                ExecutionNativeClosureFactError::OutputCursorExecutionMismatch {
                    expected_execution_id: parts.attribution.id(),
                    actual_execution_id: parts.output_cursor.execution_id(),
                },
            );
        }

        if !launch_runtime_pair_is_valid(parts.launch, parts.runtime) {
            return Err(ExecutionNativeClosureFactError::InvalidLaunchRuntimePair {
                launch: parts.launch,
                runtime: parts.runtime,
            });
        }

        Ok(Self {
            attribution: parts.attribution,
            request_digest: parts.request_digest,
            before_revision: parts.before_revision,
            after_revision: parts.after_revision,
            output_cursor: parts.output_cursor,
            launch: parts.launch,
            runtime: parts.runtime,
            process: parts.process,
            observed_at: parts.observed_at,
        })
    }

    pub const fn attribution(&self) -> ExecutionAttribution {
        self.attribution
    }

    pub const fn request_digest(&self) -> ExecutionRequestDigest {
        self.request_digest
    }

    pub const fn before_revision(&self) -> ExecutionRevision {
        self.before_revision
    }

    pub const fn after_revision(&self) -> ExecutionRevision {
        self.after_revision
    }

    pub const fn output_cursor(&self) -> ExecutionOutputCursor {
        self.output_cursor
    }

    pub const fn launch(&self) -> NativeClosureLaunch {
        self.launch
    }

    pub const fn runtime(&self) -> NativeClosureRuntime {
        self.runtime
    }

    pub const fn process(&self) -> NativeClosureProcess {
        self.process
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

const fn launch_runtime_pair_is_valid(
    launch: NativeClosureLaunch,
    runtime: NativeClosureRuntime,
) -> bool {
    matches!(
        (launch, runtime),
        (
            NativeClosureLaunch::Baseline,
            NativeClosureRuntime::NotApplicable
        ) | (
            NativeClosureLaunch::RustCi | NativeClosureLaunch::GeneratedPackage,
            NativeClosureRuntime::Cleaned
        )
    )
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionNativeClosureFactError {
    #[error("native closure fact execution id must not be nil")]
    NilExecutionId,
    #[error("native closure fact workspace id must not be nil")]
    NilWorkspaceId,
    #[error("native closure fact activity id must not be nil")]
    NilActivityId,
    #[error("native closure fact before revision overflowed")]
    RevisionOverflow { before_revision: ExecutionRevision },
    #[error("native closure fact terminal revision must immediately follow before revision")]
    RevisionStep {
        before_revision: ExecutionRevision,
        after_revision: ExecutionRevision,
    },
    #[error("native closure fact output cursor belongs to another execution")]
    OutputCursorExecutionMismatch {
        expected_execution_id: crate::ExecutionId,
        actual_execution_id: crate::ExecutionId,
    },
    #[error("native closure fact launch/runtime pairing is invalid")]
    InvalidLaunchRuntimePair {
        launch: NativeClosureLaunch,
        runtime: NativeClosureRuntime,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn parts() -> Result<ExecutionNativeClosureFactParts, Box<dyn std::error::Error>> {
        let execution_id = crate::ExecutionId::from_uuid(Uuid::from_u128(1));
        Ok(ExecutionNativeClosureFactParts {
            attribution: ExecutionAttribution::new(
                execution_id,
                crate::WorkspaceId::from_uuid(Uuid::from_u128(2)),
                crate::ActivityId::from_uuid(Uuid::from_u128(3)),
            ),
            request_digest: ExecutionRequestDigest::from_bytes([7; 32]),
            before_revision: ExecutionRevision::INITIAL,
            after_revision: ExecutionRevision::INITIAL.checked_next()?,
            output_cursor: ExecutionOutputCursor::initial(execution_id),
            launch: NativeClosureLaunch::Baseline,
            runtime: NativeClosureRuntime::NotApplicable,
            process: NativeClosureProcess::NoChildSpawned,
            observed_at: TimestampMillis::new(10)?,
        })
    }

    #[test]
    fn rejects_nil_attribution_ids() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = parts()?;
        value.attribution = ExecutionAttribution::new(
            crate::ExecutionId::from_uuid(Uuid::nil()),
            value.attribution.workspace_id(),
            value.attribution.activity_id(),
        );
        assert_eq!(
            ExecutionNativeClosureFact::from_parts(value),
            Err(ExecutionNativeClosureFactError::NilExecutionId)
        );

        let mut value = parts()?;
        value.attribution = ExecutionAttribution::new(
            value.attribution.id(),
            crate::WorkspaceId::from_uuid(Uuid::nil()),
            value.attribution.activity_id(),
        );
        assert_eq!(
            ExecutionNativeClosureFact::from_parts(value),
            Err(ExecutionNativeClosureFactError::NilWorkspaceId)
        );

        let mut value = parts()?;
        value.attribution = ExecutionAttribution::new(
            value.attribution.id(),
            value.attribution.workspace_id(),
            crate::ActivityId::from_uuid(Uuid::nil()),
        );
        assert_eq!(
            ExecutionNativeClosureFact::from_parts(value),
            Err(ExecutionNativeClosureFactError::NilActivityId)
        );
        Ok(())
    }

    #[test]
    fn rejects_non_adjacent_terminal_revision() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = parts()?;
        value.after_revision = ExecutionRevision::new(3)?;
        assert!(matches!(
            ExecutionNativeClosureFact::from_parts(value),
            Err(ExecutionNativeClosureFactError::RevisionStep { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_output_cursor_for_another_execution() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = parts()?;
        value.output_cursor =
            ExecutionOutputCursor::initial(crate::ExecutionId::from_uuid(Uuid::from_u128(4)));
        assert!(matches!(
            ExecutionNativeClosureFact::from_parts(value),
            Err(ExecutionNativeClosureFactError::OutputCursorExecutionMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_invalid_launch_runtime_pairings() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = parts()?;
        value.runtime = NativeClosureRuntime::Cleaned;
        assert!(matches!(
            ExecutionNativeClosureFact::from_parts(value),
            Err(ExecutionNativeClosureFactError::InvalidLaunchRuntimePair { .. })
        ));

        let mut value = parts()?;
        value.launch = NativeClosureLaunch::RustCi;
        assert!(matches!(
            ExecutionNativeClosureFact::from_parts(value),
            Err(ExecutionNativeClosureFactError::InvalidLaunchRuntimePair { .. })
        ));
        Ok(())
    }
}
