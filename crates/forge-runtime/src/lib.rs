//! Owned background runtime and lifecycle coordination for Heterarchy Forge.

mod service;

pub use service::{
    RuntimeClient, RuntimeClientError, RuntimeEventStream, RuntimeService, RuntimeServiceError,
    RuntimeStopParticipant, RuntimeStopParticipantError,
};
