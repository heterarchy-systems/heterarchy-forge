//! A positive pre-runner rejection is distinct from a generic launch failure.

use std::io::Write as _;

use super::{
    ActiveExecution, CoordinatorRuntime, ForgeExecutionCoordinatorError, control_conflict,
};
use forge_domain::ExecutionId;
use forge_domain::{
    ExecutionNativeClosureFact, ExecutionNativeClosureFactParts, ExecutionOutputCursor,
    ExecutionState, FailExecution, NativeClosureLaunch, NativeClosureProcess, NativeClosureRuntime,
};
use forge_execution::{
    ExecutionError, ExecutionLaunchKind, ExecutionSupervisorError, NativePreSpawnRejection,
    SandboxBackendError,
};
use forge_workspace::VerificationInputError;

/// The coordinator boundary where a native start error was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeStartErrorStage {
    IdentityCapture,
    SupervisorStartResult,
}

impl NativeStartErrorStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityCapture => "identity_capture",
            Self::SupervisorStartResult => "supervisor_start_result",
        }
    }
}

/// Closed, path-free classes that omit the native error payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeStartErrorClass {
    PackageVExecutable,
    VerificationInput,
    VerificationInputMismatch,
    VerificationSource,
    SandboxVerificationSourceScope,
    Other,
}

impl NativeStartErrorClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PackageVExecutable => "package_v_executable",
            Self::VerificationInput => "verification_input",
            Self::VerificationInputMismatch => "verification_input_mismatch",
            Self::VerificationSource => "verification_source",
            Self::SandboxVerificationSourceScope => "sandbox_verification_source_scope",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeStartErrorDiagnostic {
    execution_id: ExecutionId,
    stage: NativeStartErrorStage,
    class: NativeStartErrorClass,
    subclass: &'static str,
}

impl NativeStartErrorDiagnostic {
    fn new(
        execution_id: ExecutionId,
        stage: NativeStartErrorStage,
        error: &ExecutionSupervisorError,
    ) -> Option<Self> {
        let (class, subclass) = match error {
            // A dropped reply has an unknown outcome. Do not log it as a start error.
            ExecutionSupervisorError::ReplyDropped => return None,
            ExecutionSupervisorError::Execution(error) => match error {
                ExecutionError::PackageVExecutable(_) => {
                    (NativeStartErrorClass::PackageVExecutable, "none")
                }
                ExecutionError::VerificationInput(error) => (
                    NativeStartErrorClass::VerificationInput,
                    verification_input_subclass(error),
                ),
                ExecutionError::VerificationInputMismatch => {
                    (NativeStartErrorClass::VerificationInputMismatch, "none")
                }
                ExecutionError::VerificationSource(_) => {
                    (NativeStartErrorClass::VerificationSource, "none")
                }
                ExecutionError::Sandbox(SandboxBackendError::VerificationSourceScope) => (
                    NativeStartErrorClass::SandboxVerificationSourceScope,
                    "none",
                ),
                _ => (NativeStartErrorClass::Other, "none"),
            },
            _ => (NativeStartErrorClass::Other, "none"),
        };
        Some(Self {
            execution_id,
            stage,
            class,
            subclass,
        })
    }

    fn emit(self) {
        let _ = writeln!(std::io::stderr().lock(), "{}", self.as_safe_line());
    }

    fn as_safe_line(self) -> String {
        format!(
            "native execution start error execution_id={} stage={} error_class={} error_subclass={}",
            self.execution_id,
            self.stage.as_str(),
            self.class.as_str(),
            self.subclass
        )
    }
}

fn verification_input_subclass(error: &VerificationInputError) -> &'static str {
    match error {
        VerificationInputError::PublicationUnconfirmed { .. } => "publication_unconfirmed",
        VerificationInputError::Cancelled => "cancelled",
        VerificationInputError::Filesystem(_) => "filesystem",
        VerificationInputError::Manifest(_) => "manifest",
        VerificationInputError::ManifestMalformed => "manifest_malformed",
        VerificationInputError::ManifestTooLarge { .. } => "manifest_too_large",
        VerificationInputError::ScanLimitExceeded { .. } => "scan_limit_exceeded",
        VerificationInputError::SnapshotStale => "snapshot_stale",
        VerificationInputError::SnapshotInvalid => "snapshot_invalid",
        VerificationInputError::FileUnavailable => "file_unavailable",
        VerificationInputError::ReadTooLarge { .. } => "read_too_large",
        VerificationInputError::NotFound => "not_found",
        VerificationInputError::Collision => "collision",
        VerificationInputError::FingerprintMismatch => "fingerprint_mismatch",
        VerificationInputError::InvalidPath => "invalid_path",
        VerificationInputError::AtomicPublishUnsupported => "atomic_publish_unsupported",
        VerificationInputError::CleanupFailed => "cleanup_failed",
        VerificationInputError::StateGate(_) => "state_gate",
    }
}

pub(super) fn diagnose_native_start_error(
    execution_id: ExecutionId,
    stage: NativeStartErrorStage,
    error: &ExecutionSupervisorError,
) {
    if let Some(diagnostic) = NativeStartErrorDiagnostic::new(execution_id, stage, error) {
        diagnostic.emit();
    }
}

impl CoordinatorRuntime {
    pub(super) fn pre_spawn_rejection_fact(
        &self,
        owner: &ActiveExecution,
        failure: &FailExecution,
        proof: &NativePreSpawnRejection,
    ) -> Result<ExecutionNativeClosureFact, ForgeExecutionCoordinatorError> {
        let identity = proof.identity();
        let before = &owner.running;
        if !self.supervisor.client().owns_native_rejection(proof)
            || owner.native_identity != Some(identity)
            || identity.launch_kind() != ExecutionLaunchKind::Baseline
            || before.state() != ExecutionState::Running
            || identity.execution_id() != before.id()
            || identity.workspace_id() != before.workspace_id()
            || identity.activity_id() != before.activity_id()
            || identity.request_digest() != before.request_digest()
            || failure.id() != before.id()
            || failure.expected_revision() != before.revision()
            || failure.failure_code() != proof.failure_code()
        {
            return Err(control_conflict().into());
        }
        ExecutionNativeClosureFact::from_parts(ExecutionNativeClosureFactParts {
            attribution: forge_domain::ExecutionAttribution::new(
                before.id(),
                before.workspace_id(),
                before.activity_id(),
            ),
            request_digest: before.request_digest(),
            before_revision: before.revision(),
            after_revision: before
                .revision()
                .checked_next()
                .map_err(|_| control_conflict())?,
            output_cursor: ExecutionOutputCursor::initial(before.id()),
            launch: NativeClosureLaunch::Baseline,
            process: NativeClosureProcess::NoChildSpawned,
            runtime: NativeClosureRuntime::NotApplicable,
            observed_at: failure.observed_at(),
        })
        .map_err(|_| control_conflict().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::VerificationInputManifestError;
    use forge_execution::{PackageVExecutableError, VerificationExecutionSourceError};
    use forge_workspace::{ConfinedFilesystemError, WorkspaceStateGateError};
    use uuid::Uuid;

    #[test]
    fn native_start_diagnostic_uses_closed_classes_and_safe_fields() {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0x17));
        let cases = [
            (
                ExecutionSupervisorError::Execution(ExecutionError::PackageVExecutable(
                    PackageVExecutableError::ExternalStorageRejected,
                )),
                "package_v_executable",
                "none",
            ),
            (
                ExecutionSupervisorError::Execution(ExecutionError::VerificationInput(
                    VerificationInputError::NotFound,
                )),
                "verification_input",
                "not_found",
            ),
            (
                ExecutionSupervisorError::Execution(ExecutionError::VerificationInputMismatch),
                "verification_input_mismatch",
                "none",
            ),
            (
                ExecutionSupervisorError::Execution(ExecutionError::VerificationSource(
                    VerificationExecutionSourceError::Mismatch,
                )),
                "verification_source",
                "none",
            ),
            (
                ExecutionSupervisorError::Execution(ExecutionError::Sandbox(
                    SandboxBackendError::VerificationSourceScope,
                )),
                "sandbox_verification_source_scope",
                "none",
            ),
            (
                ExecutionSupervisorError::Execution(ExecutionError::InspectCwd(
                    std::io::Error::other("/private/source/path"),
                )),
                "other",
                "none",
            ),
        ];

        for (error, expected_class, expected_subclass) in cases {
            let diagnostic = NativeStartErrorDiagnostic::new(
                execution_id,
                NativeStartErrorStage::IdentityCapture,
                &error,
            );
            let expected_line = format!(
                "native execution start error execution_id={execution_id} stage=identity_capture error_class={expected_class} error_subclass={expected_subclass}"
            );
            assert_eq!(
                diagnostic.map(NativeStartErrorDiagnostic::as_safe_line),
                Some(expected_line)
            );
            assert_eq!(
                diagnostic.map(|value| format!("{value:?}").contains("/private/source/path")),
                Some(false)
            );
        }

        let start_error =
            ExecutionSupervisorError::Execution(ExecutionError::VerificationInputMismatch);
        let diagnostic = NativeStartErrorDiagnostic::new(
            execution_id,
            NativeStartErrorStage::SupervisorStartResult,
            &start_error,
        );
        assert_eq!(
            diagnostic.map(NativeStartErrorDiagnostic::as_safe_line),
            Some(format!(
                "native execution start error execution_id={execution_id} stage=supervisor_start_result error_class=verification_input_mismatch error_subclass=none"
            ))
        );
    }

    #[test]
    fn verification_input_error_subclasses_are_closed_and_path_free() {
        let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0x19));
        let cases = [
            (VerificationInputError::Cancelled, "cancelled"),
            (
                VerificationInputError::Filesystem(ConfinedFilesystemError::NotFound),
                "filesystem",
            ),
            (
                VerificationInputError::Manifest(VerificationInputManifestError::UnsupportedPolicy),
                "manifest",
            ),
            (
                VerificationInputError::ManifestMalformed,
                "manifest_malformed",
            ),
            (
                VerificationInputError::ManifestTooLarge { maximum: 3 },
                "manifest_too_large",
            ),
            (
                VerificationInputError::ScanLimitExceeded { maximum: 4 },
                "scan_limit_exceeded",
            ),
            (VerificationInputError::SnapshotStale, "snapshot_stale"),
            (VerificationInputError::SnapshotInvalid, "snapshot_invalid"),
            (VerificationInputError::FileUnavailable, "file_unavailable"),
            (
                VerificationInputError::ReadTooLarge { maximum: 5 },
                "read_too_large",
            ),
            (VerificationInputError::NotFound, "not_found"),
            (VerificationInputError::Collision, "collision"),
            (
                VerificationInputError::FingerprintMismatch,
                "fingerprint_mismatch",
            ),
            (VerificationInputError::InvalidPath, "invalid_path"),
            (
                VerificationInputError::AtomicPublishUnsupported,
                "atomic_publish_unsupported",
            ),
            (VerificationInputError::CleanupFailed, "cleanup_failed"),
            (
                VerificationInputError::StateGate(WorkspaceStateGateError::Busy),
                "state_gate",
            ),
        ];

        for (input_error, expected_subclass) in cases {
            let error =
                ExecutionSupervisorError::Execution(ExecutionError::VerificationInput(input_error));
            let diagnostic = NativeStartErrorDiagnostic::new(
                execution_id,
                NativeStartErrorStage::SupervisorStartResult,
                &error,
            );
            assert_eq!(
                diagnostic.map(NativeStartErrorDiagnostic::as_safe_line),
                Some(format!(
                    "native execution start error execution_id={execution_id} stage=supervisor_start_result error_class=verification_input error_subclass={expected_subclass}"
                ))
            );
        }
    }

    #[test]
    fn dropped_start_reply_is_not_misreported_as_a_start_error() {
        assert!(
            NativeStartErrorDiagnostic::new(
                ExecutionId::from_uuid(Uuid::from_u128(0x18)),
                NativeStartErrorStage::SupervisorStartResult,
                &ExecutionSupervisorError::ReplyDropped,
            )
            .is_none()
        );
    }
}
