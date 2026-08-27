use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ExecutionId, ExecutionPermissions, ExecutionRequestDigest, TimestampMillis,
    WorkspaceId,
};

const MAX_AUTO_APPROVAL_USES: u16 = 1_000;

macro_rules! uuid_id {
    ($name:ident, $error:ident, $message:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err($error::InvalidUuid)
            }
        }

        #[derive(Debug, Error)]
        pub enum $error {
            #[error($message)]
            InvalidUuid(#[source] uuid::Error),
        }
    };
}

uuid_id!(
    ApprovalRequestId,
    ApprovalRequestIdParseError,
    "invalid ApprovalRequest UUID"
);
uuid_id!(
    ExecutionGrantId,
    ExecutionGrantIdParseError,
    "invalid ExecutionGrant UUID"
);
uuid_id!(
    AutoApprovalScopeId,
    AutoApprovalScopeIdParseError,
    "invalid AutoApprovalScope UUID"
);

macro_rules! revision {
    ($name:ident, $error:ident, $invalid:literal, $overflow:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(i64);

        impl $name {
            pub const INITIAL: Self = Self(1);

            pub const fn new(value: i64) -> Result<Self, $error> {
                if value < 1 {
                    Err($error::Invalid { actual: value })
                } else {
                    Ok(Self(value))
                }
            }

            pub const fn get(self) -> i64 {
                self.0
            }

            pub const fn checked_next(self) -> Result<Self, $error> {
                match self.0.checked_add(1) {
                    Some(value) => Ok(Self(value)),
                    None => Err($error::Overflow { current: self.0 }),
                }
            }
        }

        #[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
        pub enum $error {
            #[error($invalid)]
            Invalid { actual: i64 },
            #[error($overflow)]
            Overflow { current: i64 },
        }
    };
}

revision!(
    PolicyRevision,
    PolicyRevisionError,
    "Policy revision must be at least 1, got {actual}",
    "Policy revision overflowed at {current}"
);
revision!(
    ApprovalRevision,
    ApprovalRevisionError,
    "Approval revision must be at least 1, got {actual}",
    "Approval revision overflowed at {current}"
);
revision!(
    ExecutionGrantRevision,
    ExecutionGrantRevisionError,
    "Grant revision must be at least 1, got {actual}",
    "Grant revision overflowed at {current}"
);
revision!(
    AutoApprovalScopeRevision,
    AutoApprovalScopeRevisionError,
    "AutoApprovalScope revision must be at least 1, got {actual}",
    "AutoApprovalScope revision overflowed at {current}"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionActionClass {
    DirectStructured,
    DiscoveredProjectCommand,
    ShellEscape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionPolicyRule {
    Deny,
    Ask,
    AutoEligible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionPolicyDisposition {
    Denied,
    ApprovalRequired,
    AutoEligible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestedExecutionPermissions(ExecutionPermissions);

impl RequestedExecutionPermissions {
    pub const fn new(value: ExecutionPermissions) -> Self {
        Self(value)
    }

    pub const fn get(self) -> ExecutionPermissions {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectiveExecutionPermissions(ExecutionPermissions);

impl EffectiveExecutionPermissions {
    pub const fn from_grant(value: ExecutionPermissions) -> Self {
        Self(value)
    }

    pub const fn get(self) -> ExecutionPermissions {
        self.0
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePolicy {
    workspace_id: WorkspaceId,
    revision: PolicyRevision,
    direct_structured: ExecutionPolicyRule,
    discovered_command: ExecutionPolicyRule,
    shell_escape: ExecutionPolicyRule,
    workspace_read: ExecutionPolicyRule,
    workspace_write: ExecutionPolicyRule,
    network: ExecutionPolicyRule,
}

impl WorkspacePolicy {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        workspace_id: WorkspaceId,
        revision: PolicyRevision,
        direct_structured: ExecutionPolicyRule,
        discovered_command: ExecutionPolicyRule,
        shell_escape: ExecutionPolicyRule,
        workspace_read: ExecutionPolicyRule,
        workspace_write: ExecutionPolicyRule,
        network: ExecutionPolicyRule,
    ) -> Self {
        Self {
            workspace_id,
            revision,
            direct_structured,
            discovered_command,
            shell_escape,
            workspace_read,
            workspace_write,
            network,
        }
    }

    pub const fn conservative_default(workspace_id: WorkspaceId) -> Self {
        Self::new(
            workspace_id,
            PolicyRevision::INITIAL,
            ExecutionPolicyRule::Ask,
            ExecutionPolicyRule::AutoEligible,
            ExecutionPolicyRule::Ask,
            ExecutionPolicyRule::AutoEligible,
            ExecutionPolicyRule::Ask,
            ExecutionPolicyRule::Ask,
        )
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn revision(&self) -> PolicyRevision {
        self.revision
    }

    pub const fn rule_for_action(&self, action: ExecutionActionClass) -> ExecutionPolicyRule {
        match action {
            ExecutionActionClass::DirectStructured => self.direct_structured,
            ExecutionActionClass::DiscoveredProjectCommand => self.discovered_command,
            ExecutionActionClass::ShellEscape => self.shell_escape,
        }
    }

    pub const fn direct_structured_rule(&self) -> ExecutionPolicyRule {
        self.direct_structured
    }

    pub const fn discovered_command_rule(&self) -> ExecutionPolicyRule {
        self.discovered_command
    }

    pub const fn shell_escape_rule(&self) -> ExecutionPolicyRule {
        self.shell_escape
    }

    pub const fn workspace_read_rule(&self) -> ExecutionPolicyRule {
        self.workspace_read
    }

    pub const fn workspace_write_rule(&self) -> ExecutionPolicyRule {
        self.workspace_write
    }

    pub const fn network_rule(&self) -> ExecutionPolicyRule {
        self.network
    }

    pub const fn evaluate(
        &self,
        action: ExecutionActionClass,
        permissions: RequestedExecutionPermissions,
    ) -> ExecutionPolicyDisposition {
        let requested = permissions.get();
        let rules = [
            Some(self.rule_for_action(action)),
            if requested.workspace_read() {
                Some(self.workspace_read)
            } else {
                None
            },
            if requested.workspace_write() {
                Some(self.workspace_write)
            } else {
                None
            },
            if requested.network() {
                Some(self.network)
            } else {
                None
            },
        ];
        let mut requires_approval = false;
        let mut index = 0;
        while index < rules.len() {
            if let Some(rule) = rules[index] {
                match rule {
                    ExecutionPolicyRule::Deny => return ExecutionPolicyDisposition::Denied,
                    ExecutionPolicyRule::Ask => requires_approval = true,
                    ExecutionPolicyRule::AutoEligible => {}
                }
            }
            index += 1;
        }
        if requires_approval {
            ExecutionPolicyDisposition::ApprovalRequired
        } else {
            ExecutionPolicyDisposition::AutoEligible
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionAuthorizationRequest {
    execution_id: ExecutionId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    request_digest: ExecutionRequestDigest,
    action: ExecutionActionClass,
    requested: RequestedExecutionPermissions,
}

impl ExecutionAuthorizationRequest {
    pub const fn new(
        execution_id: ExecutionId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        request_digest: ExecutionRequestDigest,
        action: ExecutionActionClass,
        requested: RequestedExecutionPermissions,
    ) -> Self {
        Self {
            execution_id,
            workspace_id,
            activity_id,
            request_digest,
            action,
            requested,
        }
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn request_digest(self) -> ExecutionRequestDigest {
        self.request_digest
    }

    pub const fn action(self) -> ExecutionActionClass {
        self.action
    }

    pub const fn requested(self) -> RequestedExecutionPermissions {
        self.requested
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorizationSource {
    ExplicitGrant,
    AutoApprovalScope,
    LegacyPlan06,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionGrantState {
    Active,
    Consumed,
    Revoked,
    Expired,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionGrant {
    id: ExecutionGrantId,
    approval_id: ApprovalRequestId,
    request: ExecutionAuthorizationRequest,
    effective: EffectiveExecutionPermissions,
    policy_revision: PolicyRevision,
    source: AuthorizationSource,
    expires_at: TimestampMillis,
    state: ExecutionGrantState,
    consumed_at: Option<TimestampMillis>,
    revision: ExecutionGrantRevision,
}

impl ExecutionGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        id: ExecutionGrantId,
        approval_id: ApprovalRequestId,
        request: ExecutionAuthorizationRequest,
        effective: EffectiveExecutionPermissions,
        policy_revision: PolicyRevision,
        source: AuthorizationSource,
        expires_at: TimestampMillis,
        revision: ExecutionGrantRevision,
    ) -> Result<Self, ApprovalDomainError> {
        Self::from_parts(
            id,
            approval_id,
            request,
            effective,
            policy_revision,
            source,
            expires_at,
            ExecutionGrantState::Active,
            None,
            revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: ExecutionGrantId,
        approval_id: ApprovalRequestId,
        request: ExecutionAuthorizationRequest,
        effective: EffectiveExecutionPermissions,
        policy_revision: PolicyRevision,
        source: AuthorizationSource,
        expires_at: TimestampMillis,
        state: ExecutionGrantState,
        consumed_at: Option<TimestampMillis>,
        revision: ExecutionGrantRevision,
    ) -> Result<Self, ApprovalDomainError> {
        if effective.get() != request.requested().get() {
            return Err(ApprovalDomainError::PartialPermissionGrant);
        }
        if (state == ExecutionGrantState::Consumed) != consumed_at.is_some() {
            return Err(ApprovalDomainError::InvalidGrantEvidence);
        }
        Ok(Self {
            id,
            approval_id,
            request,
            effective,
            policy_revision,
            source,
            expires_at,
            state,
            consumed_at,
            revision,
        })
    }

    pub const fn id(&self) -> ExecutionGrantId {
        self.id
    }

    pub const fn approval_id(&self) -> ApprovalRequestId {
        self.approval_id
    }

    pub const fn request(&self) -> ExecutionAuthorizationRequest {
        self.request
    }

    pub const fn effective(&self) -> EffectiveExecutionPermissions {
        self.effective
    }

    pub const fn policy_revision(&self) -> PolicyRevision {
        self.policy_revision
    }

    pub const fn source(&self) -> AuthorizationSource {
        self.source
    }

    pub const fn expires_at(&self) -> TimestampMillis {
        self.expires_at
    }

    pub const fn state(&self) -> ExecutionGrantState {
        self.state
    }

    pub const fn consumed_at(&self) -> Option<TimestampMillis> {
        self.consumed_at
    }

    pub const fn revision(&self) -> ExecutionGrantRevision {
        self.revision
    }

    pub fn consume(
        &self,
        request: ExecutionAuthorizationRequest,
        expected_revision: ExecutionGrantRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, ApprovalDomainError> {
        if self.state != ExecutionGrantState::Active {
            return Err(ApprovalDomainError::GrantUnavailable);
        }
        if self.revision != expected_revision {
            return Err(ApprovalDomainError::RevisionConflict);
        }
        if observed_at.get() >= self.expires_at.get() {
            return Err(ApprovalDomainError::Expired);
        }
        if self.request != request {
            return Err(ApprovalDomainError::GrantMismatch);
        }
        Ok(Self {
            state: ExecutionGrantState::Consumed,
            consumed_at: Some(observed_at),
            revision: self
                .revision
                .checked_next()
                .map_err(|_| ApprovalDomainError::RevisionOverflow)?,
            ..self.clone()
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoApprovalScopeState {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AutoApprovalUseLimit(u16);

impl AutoApprovalUseLimit {
    pub const fn new(value: u16) -> Result<Self, ApprovalDomainError> {
        if value == 0 || value > MAX_AUTO_APPROVAL_USES {
            Err(ApprovalDomainError::InvalidUseLimit {
                actual: value,
                maximum: MAX_AUTO_APPROVAL_USES,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovalScope {
    id: AutoApprovalScopeId,
    workspace_id: WorkspaceId,
    activity_id: Option<ActivityId>,
    action: ExecutionActionClass,
    permission_ceiling: ExecutionPermissions,
    policy_revision: PolicyRevision,
    expires_at: TimestampMillis,
    max_uses: AutoApprovalUseLimit,
    used_count: u16,
    state: AutoApprovalScopeState,
    revision: AutoApprovalScopeRevision,
}

impl AutoApprovalScope {
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        id: AutoApprovalScopeId,
        workspace_id: WorkspaceId,
        activity_id: Option<ActivityId>,
        action: ExecutionActionClass,
        permission_ceiling: ExecutionPermissions,
        policy_revision: PolicyRevision,
        expires_at: TimestampMillis,
        max_uses: AutoApprovalUseLimit,
        revision: AutoApprovalScopeRevision,
    ) -> Result<Self, ApprovalDomainError> {
        Self::from_parts(
            id,
            workspace_id,
            activity_id,
            action,
            permission_ceiling,
            policy_revision,
            expires_at,
            max_uses,
            0,
            AutoApprovalScopeState::Active,
            revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: AutoApprovalScopeId,
        workspace_id: WorkspaceId,
        activity_id: Option<ActivityId>,
        action: ExecutionActionClass,
        permission_ceiling: ExecutionPermissions,
        policy_revision: PolicyRevision,
        expires_at: TimestampMillis,
        max_uses: AutoApprovalUseLimit,
        used_count: u16,
        state: AutoApprovalScopeState,
        revision: AutoApprovalScopeRevision,
    ) -> Result<Self, ApprovalDomainError> {
        if used_count > max_uses.get() {
            return Err(ApprovalDomainError::UseCountOverflow);
        }
        Ok(Self {
            id,
            workspace_id,
            activity_id,
            action,
            permission_ceiling,
            policy_revision,
            expires_at,
            max_uses,
            used_count,
            state,
            revision,
        })
    }

    pub const fn id(&self) -> AutoApprovalScopeId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> Option<ActivityId> {
        self.activity_id
    }

    pub const fn action(&self) -> ExecutionActionClass {
        self.action
    }

    pub const fn permission_ceiling(&self) -> ExecutionPermissions {
        self.permission_ceiling
    }

    pub const fn policy_revision(&self) -> PolicyRevision {
        self.policy_revision
    }

    pub const fn expires_at(&self) -> TimestampMillis {
        self.expires_at
    }

    pub const fn max_uses(&self) -> AutoApprovalUseLimit {
        self.max_uses
    }

    pub const fn used_count(&self) -> u16 {
        self.used_count
    }

    pub const fn state(&self) -> AutoApprovalScopeState {
        self.state
    }

    pub const fn revision(&self) -> AutoApprovalScopeRevision {
        self.revision
    }

    pub fn covers(
        &self,
        request: ExecutionAuthorizationRequest,
        current_policy_revision: PolicyRevision,
        observed_at: TimestampMillis,
    ) -> bool {
        self.state == AutoApprovalScopeState::Active
            && self.workspace_id == request.workspace_id()
            && (self.activity_id.is_none() || self.activity_id == Some(request.activity_id()))
            && self.action == request.action()
            && self.permission_ceiling.contains(request.requested().get())
            && self.policy_revision == current_policy_revision
            && self.used_count < self.max_uses.get()
            && observed_at.get() < self.expires_at.get()
    }

    pub fn consume(
        &self,
        request: ExecutionAuthorizationRequest,
        current_policy_revision: PolicyRevision,
        expected_revision: AutoApprovalScopeRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, ApprovalDomainError> {
        if self.revision != expected_revision {
            return Err(ApprovalDomainError::RevisionConflict);
        }
        if !self.covers(request, current_policy_revision, observed_at) {
            return Err(ApprovalDomainError::AutoScopeMismatch);
        }
        let used_count = self
            .used_count
            .checked_add(1)
            .ok_or(ApprovalDomainError::UseCountOverflow)?;
        Ok(Self {
            used_count,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| ApprovalDomainError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub fn revoke(
        &self,
        expected_revision: AutoApprovalScopeRevision,
    ) -> Result<Self, ApprovalDomainError> {
        if self.state != AutoApprovalScopeState::Active {
            return Err(ApprovalDomainError::AutoScopeMismatch);
        }
        if self.revision != expected_revision {
            return Err(ApprovalDomainError::RevisionConflict);
        }
        Ok(Self {
            state: AutoApprovalScopeState::Revoked,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| ApprovalDomainError::RevisionOverflow)?,
            ..self.clone()
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalRequestState {
    Pending,
    Approved,
    Rejected,
    AutoApproved,
    Denied,
    Cancelled,
    Expired,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalDecision {
    Approve,
    Reject,
    Cancel,
    Expire,
    Supersede,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredApprovalRequest {
    id: ApprovalRequestId,
    request: ExecutionAuthorizationRequest,
    policy_revision: PolicyRevision,
    state: ApprovalRequestState,
    created_at: TimestampMillis,
    expires_at: TimestampMillis,
    decided_at: Option<TimestampMillis>,
    revision: ApprovalRevision,
}

impl RegisteredApprovalRequest {
    pub fn pending(
        id: ApprovalRequestId,
        request: ExecutionAuthorizationRequest,
        policy_revision: PolicyRevision,
        created_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, ApprovalDomainError> {
        Self::from_parts(
            id,
            request,
            policy_revision,
            ApprovalRequestState::Pending,
            created_at,
            expires_at,
            None,
            ApprovalRevision::INITIAL,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: ApprovalRequestId,
        request: ExecutionAuthorizationRequest,
        policy_revision: PolicyRevision,
        state: ApprovalRequestState,
        created_at: TimestampMillis,
        expires_at: TimestampMillis,
        decided_at: Option<TimestampMillis>,
        revision: ApprovalRevision,
    ) -> Result<Self, ApprovalDomainError> {
        if expires_at.get() <= created_at.get() {
            return Err(ApprovalDomainError::InvalidExpiry);
        }
        if (state == ApprovalRequestState::Pending) == decided_at.is_some()
            || decided_at.is_some_and(|value| value.get() < created_at.get())
        {
            return Err(ApprovalDomainError::InvalidApprovalEvidence);
        }
        Ok(Self {
            id,
            request,
            policy_revision,
            state,
            created_at,
            expires_at,
            decided_at,
            revision,
        })
    }

    pub const fn id(&self) -> ApprovalRequestId {
        self.id
    }

    pub const fn request(&self) -> ExecutionAuthorizationRequest {
        self.request
    }

    pub const fn policy_revision(&self) -> PolicyRevision {
        self.policy_revision
    }

    pub const fn state(&self) -> ApprovalRequestState {
        self.state
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn expires_at(&self) -> TimestampMillis {
        self.expires_at
    }

    pub const fn decided_at(&self) -> Option<TimestampMillis> {
        self.decided_at
    }

    pub const fn revision(&self) -> ApprovalRevision {
        self.revision
    }

    pub fn decide(
        &self,
        decision: ApprovalDecision,
        expected_revision: ApprovalRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, ApprovalDomainError> {
        if self.state != ApprovalRequestState::Pending {
            return Err(ApprovalDomainError::ApprovalTerminal);
        }
        if self.revision != expected_revision {
            return Err(ApprovalDomainError::RevisionConflict);
        }
        if observed_at.get() < self.created_at.get() {
            return Err(ApprovalDomainError::TimestampOrder);
        }
        if observed_at.get() >= self.expires_at.get() && decision != ApprovalDecision::Expire {
            return Err(ApprovalDomainError::Expired);
        }
        let state = match decision {
            ApprovalDecision::Approve => ApprovalRequestState::Approved,
            ApprovalDecision::Reject => ApprovalRequestState::Rejected,
            ApprovalDecision::Cancel => ApprovalRequestState::Cancelled,
            ApprovalDecision::Expire => ApprovalRequestState::Expired,
            ApprovalDecision::Supersede => ApprovalRequestState::Superseded,
        };
        Ok(Self {
            state,
            decided_at: Some(observed_at),
            revision: self
                .revision
                .checked_next()
                .map_err(|_| ApprovalDomainError::RevisionOverflow)?,
            ..self.clone()
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionAuthorization {
    source: AuthorizationSource,
    effective: EffectiveExecutionPermissions,
}

impl ExecutionAuthorization {
    pub const fn source(self) -> AuthorizationSource {
        self.source
    }

    pub const fn effective(self) -> EffectiveExecutionPermissions {
        self.effective
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionAuthorizationDecision {
    Denied,
    ApprovalRequired,
    Authorized(ExecutionAuthorization),
}

pub fn evaluate_execution_authorization(
    policy: &WorkspacePolicy,
    request: ExecutionAuthorizationRequest,
    explicit_grant: Option<&ExecutionGrant>,
    auto_scope: Option<&AutoApprovalScope>,
    observed_at: TimestampMillis,
) -> ExecutionAuthorizationDecision {
    if policy.workspace_id() != request.workspace_id() {
        return ExecutionAuthorizationDecision::Denied;
    }
    let disposition = policy.evaluate(request.action(), request.requested());
    if disposition == ExecutionPolicyDisposition::Denied {
        return ExecutionAuthorizationDecision::Denied;
    }
    if let Some(grant) = explicit_grant
        && grant.state() == ExecutionGrantState::Active
        && grant.request() == request
        && grant.policy_revision() == policy.revision()
        && observed_at.get() < grant.expires_at().get()
        && grant.effective().get() == request.requested().get()
    {
        return ExecutionAuthorizationDecision::Authorized(ExecutionAuthorization {
            source: AuthorizationSource::ExplicitGrant,
            effective: grant.effective(),
        });
    }
    if disposition == ExecutionPolicyDisposition::AutoEligible
        && let Some(scope) = auto_scope
        && scope.covers(request, policy.revision(), observed_at)
    {
        return ExecutionAuthorizationDecision::Authorized(ExecutionAuthorization {
            source: AuthorizationSource::AutoApprovalScope,
            effective: EffectiveExecutionPermissions::from_grant(request.requested().get()),
        });
    }
    ExecutionAuthorizationDecision::ApprovalRequired
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDomainError {
    #[error("partial permission grants are not supported")]
    PartialPermissionGrant,
    #[error("approval expiry must follow creation")]
    InvalidExpiry,
    #[error("approval timestamp precedes creation")]
    TimestampOrder,
    #[error("approval or grant revision is stale")]
    RevisionConflict,
    #[error("approval or grant revision overflowed")]
    RevisionOverflow,
    #[error("approval request is terminal")]
    ApprovalTerminal,
    #[error("approval or grant expired")]
    Expired,
    #[error("execution grant is unavailable")]
    GrantUnavailable,
    #[error("execution grant does not match the request")]
    GrantMismatch,
    #[error("execution grant evidence is inconsistent")]
    InvalidGrantEvidence,
    #[error("approval request evidence is inconsistent")]
    InvalidApprovalEvidence,
    #[error("auto approval scope does not cover the request")]
    AutoScopeMismatch,
    #[error("auto approval use count overflowed")]
    UseCountOverflow,
    #[error("auto approval use limit {actual} is outside 1..={maximum}")]
    InvalidUseLimit { actual: u16, maximum: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        workspace: u128,
        activity: u128,
        execution: u128,
        digest: u8,
        action: ExecutionActionClass,
        permissions: ExecutionPermissions,
    ) -> ExecutionAuthorizationRequest {
        ExecutionAuthorizationRequest::new(
            ExecutionId::from_uuid(Uuid::from_u128(execution)),
            WorkspaceId::from_uuid(Uuid::from_u128(workspace)),
            ActivityId::from_uuid(Uuid::from_u128(activity)),
            ExecutionRequestDigest::from_bytes([digest; 32]),
            action,
            RequestedExecutionPermissions::new(permissions),
        )
    }

    #[test]
    fn conservative_policy_never_auto_approves_direct_or_shell_execution() {
        let policy =
            WorkspacePolicy::conservative_default(WorkspaceId::from_uuid(Uuid::from_u128(1)));
        for action in [
            ExecutionActionClass::DirectStructured,
            ExecutionActionClass::ShellEscape,
        ] {
            assert_eq!(
                policy.evaluate(
                    action,
                    RequestedExecutionPermissions::new(ExecutionPermissions::new(
                        true, false, false,
                    )),
                ),
                ExecutionPolicyDisposition::ApprovalRequired
            );
        }
    }

    #[test]
    fn exact_grant_rejects_digest_execution_workspace_and_permission_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy =
            WorkspacePolicy::conservative_default(WorkspaceId::from_uuid(Uuid::from_u128(1)));
        let original = request(
            1,
            2,
            3,
            4,
            ExecutionActionClass::DirectStructured,
            ExecutionPermissions::new(true, true, false),
        );
        let grant = ExecutionGrant::active(
            ExecutionGrantId::from_uuid(Uuid::from_u128(5)),
            ApprovalRequestId::from_uuid(Uuid::from_u128(6)),
            original,
            EffectiveExecutionPermissions::from_grant(original.requested().get()),
            policy.revision(),
            AuthorizationSource::ExplicitGrant,
            TimestampMillis::new(100)?,
            ExecutionGrantRevision::INITIAL,
        )?;
        assert!(matches!(
            evaluate_execution_authorization(
                &policy,
                original,
                Some(&grant),
                None,
                TimestampMillis::new(10)?,
            ),
            ExecutionAuthorizationDecision::Authorized(_)
        ));
        for changed in [
            request(1, 2, 30, 4, original.action(), original.requested().get()),
            request(1, 2, 3, 40, original.action(), original.requested().get()),
            request(
                1,
                2,
                3,
                4,
                original.action(),
                ExecutionPermissions::new(true, false, false),
            ),
        ] {
            assert_eq!(
                evaluate_execution_authorization(
                    &policy,
                    changed,
                    Some(&grant),
                    None,
                    TimestampMillis::new(10)?,
                ),
                ExecutionAuthorizationDecision::ApprovalRequired
            );
        }
        assert_eq!(
            evaluate_execution_authorization(
                &policy,
                request(10, 2, 3, 4, original.action(), original.requested().get()),
                Some(&grant),
                None,
                TimestampMillis::new(10)?,
            ),
            ExecutionAuthorizationDecision::Denied
        );
        assert_eq!(
            evaluate_execution_authorization(
                &policy,
                original,
                Some(&grant),
                None,
                TimestampMillis::new(100)?,
            ),
            ExecutionAuthorizationDecision::ApprovalRequired
        );
        Ok(())
    }

    #[test]
    fn auto_scope_is_workspace_activity_action_permission_time_and_quota_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy =
            WorkspacePolicy::conservative_default(WorkspaceId::from_uuid(Uuid::from_u128(1)));
        let original = request(
            1,
            2,
            3,
            4,
            ExecutionActionClass::DiscoveredProjectCommand,
            ExecutionPermissions::new(true, false, false),
        );
        let scope = AutoApprovalScope::active(
            AutoApprovalScopeId::from_uuid(Uuid::from_u128(7)),
            original.workspace_id(),
            Some(original.activity_id()),
            original.action(),
            ExecutionPermissions::new(true, false, false),
            policy.revision(),
            TimestampMillis::new(100)?,
            AutoApprovalUseLimit::new(1)?,
            AutoApprovalScopeRevision::INITIAL,
        )?;
        assert!(matches!(
            evaluate_execution_authorization(
                &policy,
                original,
                None,
                Some(&scope),
                TimestampMillis::new(10)?,
            ),
            ExecutionAuthorizationDecision::Authorized(_)
        ));
        let consumed = scope.consume(
            original,
            policy.revision(),
            scope.revision(),
            TimestampMillis::new(10)?,
        )?;
        assert!(!consumed.covers(original, policy.revision(), TimestampMillis::new(11)?));
        let network = request(
            1,
            2,
            8,
            9,
            original.action(),
            ExecutionPermissions::new(true, false, true),
        );
        assert_eq!(
            evaluate_execution_authorization(
                &policy,
                network,
                None,
                Some(&scope),
                TimestampMillis::new(10)?,
            ),
            ExecutionAuthorizationDecision::ApprovalRequired
        );
        Ok(())
    }

    #[test]
    fn approvals_and_grants_are_one_shot_cas_and_expiry_guarded()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request(
            1,
            2,
            3,
            4,
            ExecutionActionClass::ShellEscape,
            ExecutionPermissions::new(true, true, false),
        );
        let pending = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(10)),
            request,
            PolicyRevision::INITIAL,
            TimestampMillis::new(1)?,
            TimestampMillis::new(100)?,
        )?;
        let approved = pending.decide(
            ApprovalDecision::Approve,
            pending.revision(),
            TimestampMillis::new(2)?,
        )?;
        assert_eq!(approved.state(), ApprovalRequestState::Approved);
        assert!(
            pending
                .decide(
                    ApprovalDecision::Approve,
                    ApprovalRevision::new(2)?,
                    TimestampMillis::new(2)?,
                )
                .is_err()
        );

        let grant = ExecutionGrant::active(
            ExecutionGrantId::from_uuid(Uuid::from_u128(11)),
            pending.id(),
            request,
            EffectiveExecutionPermissions::from_grant(request.requested().get()),
            PolicyRevision::INITIAL,
            AuthorizationSource::ExplicitGrant,
            TimestampMillis::new(100)?,
            ExecutionGrantRevision::INITIAL,
        )?;
        let consumed = grant.consume(request, grant.revision(), TimestampMillis::new(3)?)?;
        assert_eq!(consumed.state(), ExecutionGrantState::Consumed);
        assert!(
            consumed
                .consume(request, consumed.revision(), TimestampMillis::new(4)?,)
                .is_err()
        );
        Ok(())
    }
}
