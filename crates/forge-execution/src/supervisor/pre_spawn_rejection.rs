use std::fmt;

use forge_domain::ExecutionFailureCode;

use super::SupervisorStartIdentity;
use super::native_closure::SupervisorOwnerToken;

/// A rejection phase that is known to run before any runner preparation.
///
/// This is deliberately private to the supervisor. The public start receipt
/// exposes only its existing outcome, while the native proof query requires
/// one of these explicit tags instead of inferring a phase from a failure
/// code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PreSpawnRejectionPhase {
    RootValidation,
    Draining,
    CompletionBacklog,
    TerminalGenerationExhaustion,
}

/// Opaque proof of one exact Baseline Start rejection before runner
/// preparation.
///
/// The proof has no public constructor or serialization surface. Its owner
/// token is checked by the originating live supervisor before a consumer may
/// use it as native evidence.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct NativePreSpawnRejection {
    identity: SupervisorStartIdentity,
    failure_code: ExecutionFailureCode,
    owner: SupervisorOwnerToken,
}

impl fmt::Debug for NativePreSpawnRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePreSpawnRejection")
            .field("identity", &self.identity)
            .field("failure_code", &self.failure_code)
            .finish_non_exhaustive()
    }
}

impl NativePreSpawnRejection {
    pub const fn identity(&self) -> SupervisorStartIdentity {
        self.identity
    }

    pub const fn failure_code(&self) -> ExecutionFailureCode {
        self.failure_code
    }

    pub(super) fn new(
        identity: SupervisorStartIdentity,
        failure_code: ExecutionFailureCode,
        owner: SupervisorOwnerToken,
    ) -> Self {
        Self {
            identity,
            failure_code,
            owner,
        }
    }

    pub(super) fn has_owner(&self, owner: &SupervisorOwnerToken) -> bool {
        self.owner.same_owner(owner)
    }
}
