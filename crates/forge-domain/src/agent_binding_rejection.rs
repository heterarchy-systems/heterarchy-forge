//! Typed terminal disposition for an invalid reserved Agent binding.
//!
//! A rejection settles one exact reservation after the real activation
//! predicate fails. It never creates an Agent, Ready claim, membership fact,
//! presence row, or activation receipt.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId,
    AgentTransportKind, AuthenticatedPrincipal, TimestampMillis, WorkspaceId,
    WorkspaceRootFingerprint,
};

pub const AGENT_BINDING_REJECTION_DIGEST_BYTES: usize = 32;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentBindingRejectionReason {
    PrincipalTransportMismatch,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingRejectionRequest {
    request_id: Uuid,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    migration_id: Uuid,
    destination_id: Uuid,
    expected_freeze_revision: u64,
    manifest_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
    issuer_id: Uuid,
    workspace_root_fingerprint: WorkspaceRootFingerprint,
    binding_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
    delegation_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
    membership_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
    display_name: AgentDisplayName,
    declared_role: AgentDeclaredRole,
    transport: AgentTransportKind,
    reason: AgentBindingRejectionReason,
    reserved_at: TimestampMillis,
    requested_at: TimestampMillis,
    observed_at: TimestampMillis,
}

impl AgentBindingRejectionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        migration_id: Uuid,
        destination_id: Uuid,
        expected_freeze_revision: u64,
        manifest_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
        issuer_id: Uuid,
        workspace_root_fingerprint: WorkspaceRootFingerprint,
        binding_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
        delegation_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
        membership_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
        display_name: AgentDisplayName,
        declared_role: AgentDeclaredRole,
        transport: AgentTransportKind,
        reason: AgentBindingRejectionReason,
        reserved_at: TimestampMillis,
        requested_at: TimestampMillis,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentBindingRejectionValidationError> {
        if request_id.is_nil()
            || workspace_id.into_uuid().is_nil()
            || activity_id.into_uuid().is_nil()
            || agent_id.into_uuid().is_nil()
            || session_id.into_uuid().is_nil()
            || migration_id.is_nil()
            || destination_id.is_nil()
            || issuer_id.is_nil()
        {
            return Err(AgentBindingRejectionValidationError::NilIdentity);
        }
        if expected_freeze_revision < 1
            || manifest_digest == [0; AGENT_BINDING_REJECTION_DIGEST_BYTES]
            || membership_digest == [0; AGENT_BINDING_REJECTION_DIGEST_BYTES]
            || binding_digest == [0; AGENT_BINDING_REJECTION_DIGEST_BYTES]
            || delegation_digest == [0; AGENT_BINDING_REJECTION_DIGEST_BYTES]
            || *workspace_root_fingerprint.as_bytes() == [0; 16]
        {
            return Err(AgentBindingRejectionValidationError::Fence);
        }
        Ok(Self {
            request_id,
            workspace_id,
            activity_id,
            agent_id,
            session_id,
            principal,
            migration_id,
            destination_id,
            expected_freeze_revision,
            manifest_digest,
            issuer_id,
            workspace_root_fingerprint,
            binding_digest,
            delegation_digest,
            membership_digest,
            display_name,
            declared_role,
            transport,
            reason,
            reserved_at,
            requested_at,
            observed_at,
        })
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }
    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn session_id(&self) -> AgentSessionId {
        self.session_id
    }
    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }
    pub const fn migration_id(&self) -> Uuid {
        self.migration_id
    }
    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }
    pub const fn expected_freeze_revision(&self) -> u64 {
        self.expected_freeze_revision
    }
    pub const fn manifest_digest(&self) -> [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES] {
        self.manifest_digest
    }
    pub const fn issuer_id(&self) -> Uuid {
        self.issuer_id
    }
    pub const fn workspace_root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.workspace_root_fingerprint
    }
    pub const fn binding_digest(&self) -> [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES] {
        self.binding_digest
    }
    pub const fn delegation_digest(&self) -> [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES] {
        self.delegation_digest
    }
    pub const fn membership_digest(&self) -> [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES] {
        self.membership_digest
    }
    pub const fn display_name(&self) -> &AgentDisplayName {
        &self.display_name
    }
    pub const fn declared_role(&self) -> &AgentDeclaredRole {
        &self.declared_role
    }
    pub const fn transport(&self) -> AgentTransportKind {
        self.transport
    }
    pub const fn reason(&self) -> AgentBindingRejectionReason {
        self.reason
    }
    pub const fn reserved_at(&self) -> TimestampMillis {
        self.reserved_at
    }
    pub const fn requested_at(&self) -> TimestampMillis {
        self.requested_at
    }
    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn with_observed_at(mut self, observed_at: TimestampMillis) -> Self {
        self.observed_at = observed_at;
        self
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingRejectionReceipt {
    request: AgentBindingRejectionRequest,
    request_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
    rejected_at: TimestampMillis,
    receipt_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
}

impl AgentBindingRejectionReceipt {
    pub fn from_parts(
        request: AgentBindingRejectionRequest,
        request_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
        rejected_at: TimestampMillis,
        receipt_digest: [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES],
    ) -> Self {
        Self {
            request,
            request_digest,
            rejected_at,
            receipt_digest,
        }
    }
    pub const fn request(&self) -> &AgentBindingRejectionRequest {
        &self.request
    }
    pub const fn request_digest(&self) -> [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES] {
        self.request_digest
    }
    pub const fn rejected_at(&self) -> TimestampMillis {
        self.rejected_at
    }
    pub const fn receipt_digest(&self) -> [u8; AGENT_BINDING_REJECTION_DIGEST_BYTES] {
        self.receipt_digest
    }
    pub const fn request_id(&self) -> Uuid {
        self.request.request_id()
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.request.workspace_id()
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.request.activity_id()
    }
    pub const fn agent_id(&self) -> AgentInstanceId {
        self.request.agent_id()
    }
    pub const fn session_id(&self) -> AgentSessionId {
        self.request.session_id()
    }
    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.request.principal()
    }
    pub const fn reason(&self) -> AgentBindingRejectionReason {
        self.request.reason()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentBindingRejectionValidationError {
    #[error("Agent binding rejection identity is nil")]
    NilIdentity,
    #[error("Agent binding rejection source fence is invalid")]
    Fence,
}
