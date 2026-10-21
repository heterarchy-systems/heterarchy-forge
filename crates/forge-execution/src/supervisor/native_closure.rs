use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use forge_domain::{
    ExecutionFailureCode, ExecutionOutcome, ExecutionOutputCursor, GeneratedPackageManifest,
    WorkspaceId,
};

use crate::ExecutionLaunchKind;
use crate::runner::{ProcessFinalization, RustCiRuntimeFinalization};

use super::{ExecutionSupervisorEvent, SupervisorStartIdentity, TerminalEventKey};

/// The process-side disposition that positively closes one native execution.
///
/// `NoChildSpawned` is an admitted execution whose runner established that no
/// child was ever created. It is intentionally distinct from a reaped process
/// group so callers cannot treat the two observations as interchangeable.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessDisposition {
    NoChildSpawned,
    ProcessGroupReaped,
}

/// The Rust CI runtime disposition required by a native closure proof.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeDisposition {
    NotApplicable,
    Cleaned,
}

/// One live owner's quiescence observation, not durable stop or release authority.
/// The caller must preserve its serialized admission fence while consuming it.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWorkspaceQuiescence {
    workspace_id: WorkspaceId,
    owner: SupervisorOwnerToken,
}

impl NativeWorkspaceQuiescence {
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub(super) fn new(workspace_id: WorkspaceId, owner: SupervisorOwnerToken) -> Self {
        Self {
            workspace_id,
            owner,
        }
    }
    pub(super) fn has_owner(&self, owner: &SupervisorOwnerToken) -> bool {
        self.owner.same_owner(owner)
    }
}

/// Opaque proof that one exact native terminal event has closed.
///
/// This type deliberately has no serialization or public constructor. It is
/// produced only by a live execution supervisor after checking its retained
/// event, active runner, finalization evidence, and output handoff state.
/// Output handoff is not durable journal confirmation. A consumer must confirm
/// its own durable output and terminal records before settling a durable stop.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExecutionClosure {
    event: ExecutionSupervisorEvent,
    output_cursor: ExecutionOutputCursor,
    process: ProcessDisposition,
    runtime: RuntimeDisposition,
}

impl NativeExecutionClosure {
    pub const fn event(&self) -> &ExecutionSupervisorEvent {
        &self.event
    }

    pub const fn identity(&self) -> SupervisorStartIdentity {
        self.event.identity()
    }

    pub fn key(&self) -> TerminalEventKey {
        self.event.key()
    }

    pub const fn result(&self) -> &Result<ExecutionOutcome, ExecutionFailureCode> {
        self.event.result()
    }

    pub const fn generated_package(&self) -> Option<GeneratedPackageManifest> {
        self.event.generated_package()
    }

    pub const fn output_cursor(&self) -> ExecutionOutputCursor {
        self.output_cursor
    }

    pub const fn process_disposition(&self) -> ProcessDisposition {
        self.process
    }

    pub const fn runtime_disposition(&self) -> RuntimeDisposition {
        self.runtime
    }

    pub(super) const fn from_parts(
        event: ExecutionSupervisorEvent,
        output_cursor: ExecutionOutputCursor,
        process: ProcessDisposition,
        runtime: RuntimeDisposition,
    ) -> Self {
        Self {
            event,
            output_cursor,
            process,
            runtime,
        }
    }
}

/// Live supervisor ownership capability attached to native terminal events.
///
/// The allocation identity is the owner fence. Atomic contents are not an
/// identity because separate live supervisors can have the same accepting
/// state at the same time.
#[derive(Clone)]
pub(super) struct SupervisorOwnerToken(Arc<AtomicBool>);

impl SupervisorOwnerToken {
    pub(super) fn new(accepting: Arc<AtomicBool>) -> Self {
        Self(accepting)
    }

    pub(super) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for SupervisorOwnerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorOwnerToken")
            .finish_non_exhaustive()
    }
}

impl PartialEq for SupervisorOwnerToken {
    fn eq(&self, other: &Self) -> bool {
        self.same_owner(other)
    }
}

impl Eq for SupervisorOwnerToken {}

pub(super) fn dispositions(
    process: Option<ProcessFinalization>,
    runtime: Option<RustCiRuntimeFinalization>,
    launch_kind: ExecutionLaunchKind,
) -> Option<(ProcessDisposition, RuntimeDisposition)> {
    let process = match process? {
        ProcessFinalization::NoChildSpawned => ProcessDisposition::NoChildSpawned,
        ProcessFinalization::ProcessGroupReaped => ProcessDisposition::ProcessGroupReaped,
        ProcessFinalization::ReapUnconfirmed => return None,
    };
    let runtime = match (launch_kind, runtime?) {
        (ExecutionLaunchKind::Baseline, RustCiRuntimeFinalization::NotApplicable) => {
            RuntimeDisposition::NotApplicable
        }
        (
            ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage,
            RustCiRuntimeFinalization::Cleaned,
        ) => RuntimeDisposition::Cleaned,
        (_, RustCiRuntimeFinalization::Preserved)
        | (ExecutionLaunchKind::Baseline, RustCiRuntimeFinalization::Cleaned)
        | (
            ExecutionLaunchKind::RustCi | ExecutionLaunchKind::RustCiGeneratedPackage,
            RustCiRuntimeFinalization::NotApplicable,
        ) => return None,
    };
    Some((process, runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_and_runtime_finalization_require_positive_pairs() {
        let positive_baseline = dispositions(
            Some(ProcessFinalization::NoChildSpawned),
            Some(RustCiRuntimeFinalization::NotApplicable),
            ExecutionLaunchKind::Baseline,
        );
        assert_eq!(
            positive_baseline,
            Some((
                ProcessDisposition::NoChildSpawned,
                RuntimeDisposition::NotApplicable
            ))
        );
        assert_eq!(
            dispositions(
                Some(ProcessFinalization::ProcessGroupReaped),
                Some(RustCiRuntimeFinalization::Cleaned),
                ExecutionLaunchKind::RustCi,
            ),
            Some((
                ProcessDisposition::ProcessGroupReaped,
                RuntimeDisposition::Cleaned
            ))
        );

        for process in [None, Some(ProcessFinalization::ReapUnconfirmed)] {
            assert_eq!(
                dispositions(
                    process,
                    Some(RustCiRuntimeFinalization::NotApplicable),
                    ExecutionLaunchKind::Baseline,
                ),
                None
            );
        }
        for runtime in [
            None,
            Some(RustCiRuntimeFinalization::Preserved),
            Some(RustCiRuntimeFinalization::Cleaned),
        ] {
            assert_eq!(
                dispositions(
                    Some(ProcessFinalization::ProcessGroupReaped),
                    runtime,
                    ExecutionLaunchKind::Baseline,
                ),
                (runtime == Some(RustCiRuntimeFinalization::NotApplicable)).then_some((
                    ProcessDisposition::ProcessGroupReaped,
                    RuntimeDisposition::NotApplicable,
                )),
            );
        }
        assert_eq!(
            dispositions(
                Some(ProcessFinalization::ProcessGroupReaped),
                Some(RustCiRuntimeFinalization::Preserved),
                ExecutionLaunchKind::RustCi,
            ),
            None
        );
    }

    #[test]
    fn owner_tokens_use_allocation_identity() {
        let first = Arc::new(AtomicBool::new(true));
        let second = Arc::new(AtomicBool::new(true));
        let first_token = SupervisorOwnerToken::new(Arc::clone(&first));
        let first_clone = SupervisorOwnerToken::new(first);
        let second_token = SupervisorOwnerToken::new(second);

        assert_eq!(first_token, first_clone);
        assert_ne!(first_token, second_token);
    }
}
