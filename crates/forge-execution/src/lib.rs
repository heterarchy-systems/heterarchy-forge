//! Bounded macOS sandbox and owned process-group execution boundary.

mod digest;
mod package_v;
mod runner;
mod rust_ci;
mod sandbox;
mod sandbox_linux;
mod supervisor;

pub use digest::execution_request_digest;
pub use forge_domain::{
    EXECUTION_OUTPUT_CHUNK_BYTES, ExecutionOutputChunk, ExecutionOutputChunkError,
    ExecutionOutputCursor, ExecutionOutputEvent, ExecutionOutputEventKey, ExecutionOutputGap,
    ExecutionOutputGapCause, ExecutionOutputGapError, ExecutionOutputGapParts, ExecutionOutputRead,
    ExecutionOutputSequence, ExecutionOutputSequenceError, ExecutionOutputStream,
};
pub use package_v::{
    PACKAGE_V_COMMAND_ID, PACKAGE_V_CONTRACT_VERSION, PACKAGE_V_MANIFEST_NAME,
    PACKAGE_V_SUBCOMMAND, PackageVExecutableCapability, PackageVExecutableError, PackageVResult,
    PackageVValidationError, validate_package_root, validate_published_input,
};
pub use runner::{
    ExecutionCompletionResult, ExecutionError, ExecutionRunner, MAX_OUTPUT_EVENT_BACKLOG,
    RunningExecution,
};
pub use rust_ci::{
    ExecutionLaunchKind, MAX_GENERATED_PACKAGE_BYTES, RUST_CI_DISK_MONITOR_INTERVAL,
    RUST_CI_MAX_ENTRIES, RUST_CI_MAX_LOGICAL_BYTES, RUST_CI_PINNED_VERSION,
    RUST_CI_SANDBOX_MARKER_ENV, RUST_CI_SANDBOX_MARKER_VALUE, RustCiDiscoveryError,
    RustCiDiscoveryInput, RustCiDiscoveryInputError, RustCiDiskError, RustCiDiskUsage,
    RustCiGeneratedPackageOutput, RustCiHostArchitecture, RustCiInputPath, RustCiPreparedStorage,
    RustCiRuntimePaths, RustCiSourceComponent, RustCiStorageError, RustCiStorageSelection,
    RustCiToolchainAvailability, RustCiToolchainCapability, RustCiToolchainView,
    VerificationExecutionSourceError, inspect_rust_ci_disk,
    inspect_rust_ci_disk_with_generated_output,
};
pub use sandbox::{MacOsSandboxProfile, SandboxBackendError, SandboxBackendStatus};
pub use supervisor::{
    ExecutionSupervisor, ExecutionSupervisorClient, ExecutionSupervisorError,
    ExecutionSupervisorEvent, ExecutionSupervisorShutdown, NativeExecutionClosure,
    NativePreSpawnRejection, NativeWorkspaceQuiescence, ProcessDisposition, RuntimeDisposition,
    SupervisorStartIdentity, SupervisorStartOutcome, SupervisorStartReceipt, TerminalEventKey,
};
