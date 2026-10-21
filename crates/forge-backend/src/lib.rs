//! Heterarchy Forge HTTP JSON + resumable SSE transport adapter.
//!
//! `forge-backend` is a thin transport adapter over `forge-control`. It owns
//! HTTP/SSE mechanics only: versioned envelopes, issuer bearer
//! authentication, typed Forge-control authorization, a bounded
//! async-to-blocking command bridge, typed bounds, and the fixed shutdown
//! order. Durable authority remains in forge-control and forge-persistence;
//! this crate never opens a database, never interprets domain policy, and never
//! substitutes an admission envelope for bearer authentication.

#![deny(unsafe_code)]

pub mod auth;
pub mod bridge;
pub mod client;
pub mod config;
pub mod envelope;
pub mod error;
pub mod events;
pub mod http;
pub mod lease_bridge;
pub mod ops;
pub mod recovery;
pub mod remote_authority;
pub mod serve_fence;
pub mod session_protocol;

pub use auth::IssuerAuth;
pub use bridge::{BridgeDrainReport, BridgeOutcome, CommandExecutor, ControlBridge};
pub use client::{
    ForgeHttpClient, ForgeHttpClientConfigError, ForgeHttpClientError, ForgeHttpMutationError,
    ForgeHttpMutationRequest, ForgeHttpServiceCode,
};
pub use config::{
    BackendConfig, ConfigError, DEFAULT_COMMAND_DEADLINE, DEFAULT_SSE_POLL_INTERVAL,
    FORGE_API_VERSION, MAX_BODY_BYTES, MAX_EVENT_PAGE_ROWS,
};
pub use envelope::{
    FailureEnvelope, Reply, RequestEnvelope, SemanticEventDto, StreamResyncHint, SuccessEnvelope,
};
pub use error::{ErrorCode, ForgeError, ReadbackHint};
pub use events::{
    EventPage, EventQuery, EventQueryError, EventRecord, Frame, StreamEnd, Subjects,
    SubscriberGuard,
};
pub use http::{AppState, ServerJoinState, ShutdownPhase, ShutdownReport, router, serve};
pub use ops::workspace_root_recovery::{
    WorkspaceRootRecoveryAuthorityModeWire, WorkspaceRootRecoveryCommitStatus,
    WorkspaceRootRecoveryCommitWire, WorkspaceRootRecoveryDelegationFenceWire,
    WorkspaceRootRecoveryDelegationReceiptWire, WorkspaceRootRecoveryFreezeFenceWire,
    WorkspaceRootRecoveryObservationWire, WorkspaceRootRecoveryProbeStatus,
    WorkspaceRootRecoveryProbeWire, WorkspaceRootRecoveryReadbackStatus,
    WorkspaceRootRecoveryReadbackWire, WorkspaceRootRecoveryReceiptWire,
    WorkspaceRootRecoveryWorkspaceWire,
};
pub use ops::{Command, CommandOp, parse_command};
pub use recovery::{StartupRecoveryReport, run_startup_recovery};
pub use serve_fence::{ServeFence, ServeFenceError};
