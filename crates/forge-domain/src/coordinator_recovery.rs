//! Explicit native-owner recovery of one Activity's planning Coordinator.
//!
//! This is not an Agent claim, an OAuth identity alias, or a membership change.
//! Only a trusted native operator surface may submit the confirmed command.

use crate::{
    ActivityCoordinatorBinding, AgentAttachmentState, AgentInstanceId, AgentInstanceRevision,
    AgentSessionId, AuthenticatedPrincipal, RegisteredAgentInstance, TimestampMillis,
};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

pub const MAX_COORDINATOR_RECOVERY_REASON_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorRecoveryAgent {
    id: AgentInstanceId,
    session_id: AgentSessionId,
    revision: AgentInstanceRevision,
    principal: AuthenticatedPrincipal,
    updated_at: TimestampMillis,
}
impl CoordinatorRecoveryAgent {
    pub fn new(
        id: AgentInstanceId,
        session_id: AgentSessionId,
        revision: AgentInstanceRevision,
        principal: AuthenticatedPrincipal,
        updated_at: TimestampMillis,
    ) -> Result<Self, CoordinatorRecoveryError> {
        if id.into_uuid().is_nil() || session_id.into_uuid().is_nil() {
            return Err(CoordinatorRecoveryError::InvalidIdentity);
        }
        let invalid_principal = match principal {
            AuthenticatedPrincipal::TrustedStdio => false,
            AuthenticatedPrincipal::DirectToken(id) => id.into_uuid().is_nil(),
            AuthenticatedPrincipal::OAuthGrant(id) => id.into_uuid().is_nil(),
        };
        if invalid_principal {
            return Err(CoordinatorRecoveryError::InvalidIdentity);
        }
        Ok(Self {
            id,
            session_id,
            revision,
            principal,
            updated_at,
        })
    }
    pub fn from_agent(agent: &RegisteredAgentInstance) -> Result<Self, CoordinatorRecoveryError> {
        if agent.attachment_state() != AgentAttachmentState::Attached {
            return Err(CoordinatorRecoveryError::DetachedAgent);
        }
        Self::new(
            agent.id(),
            agent
                .session_id()
                .ok_or(CoordinatorRecoveryError::UnboundAgent)?,
            agent.revision(),
            agent.principal(),
            agent.updated_at(),
        )
    }
    pub const fn id(self) -> AgentInstanceId {
        self.id
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn revision(self) -> AgentInstanceRevision {
        self.revision
    }
    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn updated_at(self) -> TimestampMillis {
        self.updated_at
    }
}

/// Exact before-state shown to the local owner; never refreshed at confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorRecoveryFence {
    binding: ActivityCoordinatorBinding,
    source: CoordinatorRecoveryAgent,
    target: CoordinatorRecoveryAgent,
}
impl CoordinatorRecoveryFence {
    pub fn new(
        binding: ActivityCoordinatorBinding,
        source: CoordinatorRecoveryAgent,
        target: CoordinatorRecoveryAgent,
    ) -> Result<Self, CoordinatorRecoveryError> {
        if binding.workspace_id().into_uuid().is_nil()
            || binding.activity_id().into_uuid().is_nil()
            || binding.agent_id() != source.id()
        {
            return Err(CoordinatorRecoveryError::InvalidIdentity);
        }
        if source.id() == target.id() || source.session_id() == target.session_id() {
            return Err(CoordinatorRecoveryError::SameParticipant);
        }
        if !target.principal().is_trusted_stdio() {
            return Err(CoordinatorRecoveryError::NonLocalTarget);
        }
        Ok(Self {
            binding,
            source,
            target,
        })
    }
    pub fn from_agents(
        binding: ActivityCoordinatorBinding,
        source: &RegisteredAgentInstance,
        target: &RegisteredAgentInstance,
    ) -> Result<Self, CoordinatorRecoveryError> {
        if [source, target].iter().any(|agent| {
            agent.workspace_id() != binding.workspace_id()
                || agent.activity_id() != binding.activity_id()
        }) {
            return Err(CoordinatorRecoveryError::ScopeMismatch);
        }
        Self::new(
            binding,
            CoordinatorRecoveryAgent::from_agent(source)?,
            CoordinatorRecoveryAgent::from_agent(target)?,
        )
    }
    pub const fn binding(self) -> ActivityCoordinatorBinding {
        self.binding
    }
    pub const fn source(self) -> CoordinatorRecoveryAgent {
        self.source
    }
    pub const fn target(self) -> CoordinatorRecoveryAgent {
        self.target
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CoordinatorRecoveryReason(String);
impl CoordinatorRecoveryReason {
    pub fn new(value: String) -> Result<Self, CoordinatorRecoveryError> {
        if value.trim().is_empty()
            || value.len() > MAX_COORDINATOR_RECOVERY_REASON_BYTES
            || value
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}'))
        {
            return Err(CoordinatorRecoveryError::InvalidReason);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for CoordinatorRecoveryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoordinatorRecoveryReason")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Native-owner confirmation. Not serializable as an external HTTP command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedCoordinatorRecovery {
    id: Uuid,
    fence: CoordinatorRecoveryFence,
    reason: CoordinatorRecoveryReason,
    confirmed_at: TimestampMillis,
}
impl ConfirmedCoordinatorRecovery {
    pub fn new(
        id: Uuid,
        fence: CoordinatorRecoveryFence,
        reason: CoordinatorRecoveryReason,
        confirmed_at: TimestampMillis,
    ) -> Result<Self, CoordinatorRecoveryError> {
        if id.is_nil() {
            return Err(CoordinatorRecoveryError::InvalidIdentity);
        }
        if confirmed_at < fence.binding().updated_at()
            || confirmed_at < fence.source().updated_at()
            || confirmed_at < fence.target().updated_at()
        {
            return Err(CoordinatorRecoveryError::TimestampOrder);
        }
        Ok(Self {
            id,
            fence,
            reason,
            confirmed_at,
        })
    }
    pub const fn id(&self) -> Uuid {
        self.id
    }
    pub const fn fence(&self) -> CoordinatorRecoveryFence {
        self.fence
    }
    pub const fn reason(&self) -> &CoordinatorRecoveryReason {
        &self.reason
    }
    pub const fn confirmed_at(&self) -> TimestampMillis {
        self.confirmed_at
    }
}

/// Immutable result of a confirmed local-owner operation, including its before-state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorRecoveryReceipt {
    request: ConfirmedCoordinatorRecovery,
    binding: ActivityCoordinatorBinding,
}
impl CoordinatorRecoveryReceipt {
    pub fn new(request: ConfirmedCoordinatorRecovery) -> Result<Self, CoordinatorRecoveryError> {
        let before = request.fence().binding();
        let binding = ActivityCoordinatorBinding::new(
            before.workspace_id(),
            before.activity_id(),
            request.fence().target().id(),
            before
                .revision()
                .checked_next()
                .map_err(|_| CoordinatorRecoveryError::RevisionOverflow)?,
            request.confirmed_at(),
        );
        Ok(Self { request, binding })
    }
    pub const fn request(&self) -> &ConfirmedCoordinatorRecovery {
        &self.request
    }
    pub const fn binding(&self) -> ActivityCoordinatorBinding {
        self.binding
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorRecoveryError {
    #[error("Coordinator recovery identity is invalid")]
    InvalidIdentity,
    #[error("Coordinator recovery participants must belong to the same Workspace and Activity")]
    ScopeMismatch,
    #[error("Coordinator recovery requires distinct Agents and Sessions")]
    SameParticipant,
    #[error("Coordinator recovery target must use a trusted local Session")]
    NonLocalTarget,
    #[error("Coordinator recovery requires attached Agents")]
    DetachedAgent,
    #[error("Coordinator recovery requires session-bound Agents")]
    UnboundAgent,
    #[error("Coordinator recovery reason must be nonempty, single-line, and at most 1024 bytes")]
    InvalidReason,
    #[error("Coordinator recovery timestamp precedes the reviewed state")]
    TimestampOrder,
    #[error("Coordinator recovery revision overflow")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests;
