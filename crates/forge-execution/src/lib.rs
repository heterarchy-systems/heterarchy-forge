//! Bounded macOS sandbox and owned process-group execution boundary.

mod digest;
mod public_tunnel;
mod runner;
mod sandbox;
mod supervisor;

pub use digest::execution_request_digest;
pub use public_tunnel::{CloudflarePublicTunnel, CloudflarePublicTunnelError};
pub use runner::{ExecutionError, ExecutionRunner, RunningExecution};
pub use sandbox::{MacOsSandboxProfile, SandboxBackendError, SandboxBackendStatus};
pub use supervisor::{
    ExecutionSupervisor, ExecutionSupervisorClient, ExecutionSupervisorError,
    ExecutionSupervisorEvent, ExecutionSupervisorShutdown,
};
