//! Bounded macOS sandbox and owned process-group execution boundary.

mod digest;
mod runner;
mod sandbox;
mod supervisor;

pub use digest::execution_request_digest;
pub use runner::{ExecutionError, ExecutionRunner, RunningExecution};
pub use sandbox::{MacOsSandboxProfile, SandboxBackendError, SandboxBackendStatus};
pub use supervisor::{
    ExecutionSupervisor, ExecutionSupervisorClient, ExecutionSupervisorError,
    ExecutionSupervisorEvent, ExecutionSupervisorShutdown,
};
