//! Effect-free Orchestration-issued execution admission contracts.
//!
//! These values carry an exact request fence from an Orchestration issuer to a
//! later service boundary. They do not authenticate the issuer, revalidate a
//! Forge Workspace/Activity/Agent/Writer Lease state, or consume durable
//! authority. Authentication, scope and lease revalidation, and exactly-once
//! durable consumption remain responsibilities of their respective service
//! and persistence boundaries.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, AgentInstanceId, AgentInstanceRevision, AgentSessionId, ExecutionId,
    ExecutionRequestDigest, GoalNodeAttribution, TimestampMillis, WorkspaceId, WorkspaceRevision,
};

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $parse_error:ident, $error_message:literal) => {
        $(#[$meta])*
        #[must_use]
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
            type Err = $parse_error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err($parse_error::InvalidUuid)
            }
        }

        #[derive(Debug, Error)]
        pub enum $parse_error {
            #[error($error_message)]
            InvalidUuid(#[source] uuid::Error),
        }
    };
}

uuid_identity!(
    /// Opaque identity of the Orchestration issuer for one admission grant.
    ///
    /// This identity is not a credential and does not authenticate a caller.
    OrchestrationIssuerId,
    OrchestrationIssuerIdParseError,
    "invalid Orchestration issuer UUID"
);

uuid_identity!(
    /// Stable identity of the Forge backend authority receiving one grant.
    ///
    /// This identifies backend authority, not a URL, process, or runtime
    /// instance identity.
    ForgeBackendId,
    ForgeBackendIdParseError,
    "invalid Forge backend UUID"
);

/// Exact server-derived backend and Workspace scope fence.
///
/// The backend identity and current Workspace revision must be supplied by a
/// server-owned scope lookup. This value does not perform that lookup.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionAdmissionScope {
    backend_id: ForgeBackendId,
    workspace_id: WorkspaceId,
    expected_workspace_revision: WorkspaceRevision,
}

impl ExecutionAdmissionScope {
    pub const fn new(
        backend_id: ForgeBackendId,
        workspace_id: WorkspaceId,
        expected_workspace_revision: WorkspaceRevision,
    ) -> Self {
        Self {
            backend_id,
            workspace_id,
            expected_workspace_revision,
        }
    }

    pub const fn backend_id(self) -> ForgeBackendId {
        self.backend_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn expected_workspace_revision(self) -> WorkspaceRevision {
        self.expected_workspace_revision
    }
}

/// Exact Agent/session actor fence carried by one admission request.
///
/// The actor is evidence in this domain contract. It is not proof that the
/// session is authenticated or that the Agent revision is current.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionAdmissionActor {
    agent_id: AgentInstanceId,
    expected_agent_revision: AgentInstanceRevision,
    session_id: AgentSessionId,
}

impl ExecutionAdmissionActor {
    pub const fn new(
        agent_id: AgentInstanceId,
        expected_agent_revision: AgentInstanceRevision,
        session_id: AgentSessionId,
    ) -> Self {
        Self {
            agent_id,
            expected_agent_revision,
            session_id,
        }
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn expected_agent_revision(self) -> AgentInstanceRevision {
        self.expected_agent_revision
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
}

/// Exact backend/Workspace/Activity/Goal-node execution request fence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionAdmissionRequest {
    scope: ExecutionAdmissionScope,
    activity_id: ActivityId,
    attribution: GoalNodeAttribution,
    actor: ExecutionAdmissionActor,
    /// Operation/readback idempotency identity for this grant envelope.
    /// Independent revocation and renewal lifecycles are not implemented yet.
    execution_id: ExecutionId,
    digest: ExecutionRequestDigest,
}

impl ExecutionAdmissionRequest {
    pub const fn new(
        scope: ExecutionAdmissionScope,
        activity_id: ActivityId,
        attribution: GoalNodeAttribution,
        actor: ExecutionAdmissionActor,
        execution_id: ExecutionId,
        digest: ExecutionRequestDigest,
    ) -> Self {
        Self {
            scope,
            activity_id,
            attribution,
            actor,
            execution_id,
            digest,
        }
    }

    pub const fn scope(self) -> ExecutionAdmissionScope {
        self.scope
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn attribution(self) -> GoalNodeAttribution {
        self.attribution
    }

    pub const fn actor(self) -> ExecutionAdmissionActor {
        self.actor
    }

    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    pub const fn digest(self) -> ExecutionRequestDigest {
        self.digest
    }
}

/// Typed failure from admission-grant construction or envelope validation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionAdmissionError {
    #[error("execution admission grant issued_at must be before expires_at")]
    InvalidWindow,
    #[error("execution admission grant issuer does not match the authenticated issuer")]
    IssuerMismatch,
    #[error("execution admission request does not match the issued request")]
    RequestMismatch,
    #[error("execution admission grant is not valid before issued_at")]
    NotYetValid,
    #[error("execution admission grant has expired")]
    Expired,
}

/// Bounded Orchestration grant for one exact execution request.
///
/// `issued_at` is the not-before boundary. The grant remains valid for the
/// half-open interval `issued_at <= observed_at < expires_at` after the caller
/// separately authenticates the issuer and revalidates Forge authority.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionAdmissionGrant {
    issuer: OrchestrationIssuerId,
    request: ExecutionAdmissionRequest,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
}

impl ExecutionAdmissionGrant {
    pub fn new(
        issuer: OrchestrationIssuerId,
        request: ExecutionAdmissionRequest,
        issued_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, ExecutionAdmissionError> {
        if issued_at >= expires_at {
            return Err(ExecutionAdmissionError::InvalidWindow);
        }
        Ok(Self {
            issuer,
            request,
            issued_at,
            expires_at,
        })
    }

    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.issuer
    }

    pub const fn request(self) -> ExecutionAdmissionRequest {
        self.request
    }

    pub const fn issued_at(self) -> TimestampMillis {
        self.issued_at
    }

    pub const fn expires_at(self) -> TimestampMillis {
        self.expires_at
    }

    /// Validate only the immutable grant envelope against an already-authenticated issuer.
    ///
    /// `actual_request.scope()` must be a server-derived value carrying the
    /// current backend identity and Workspace revision. This method compares
    /// that value exactly; it does not perform HTTP authentication or scope
    /// lookup, authenticate `authenticated_issuer`, recheck current
    /// Workspace/Activity/Agent/Goal/DAG/Lease state, or consume a grant.
    pub fn validate_for(
        &self,
        authenticated_issuer: OrchestrationIssuerId,
        actual_request: &ExecutionAdmissionRequest,
        observed_at: TimestampMillis,
    ) -> Result<(), ExecutionAdmissionError> {
        if self.issuer != authenticated_issuer {
            return Err(ExecutionAdmissionError::IssuerMismatch);
        }
        if self.request != *actual_request {
            return Err(ExecutionAdmissionError::RequestMismatch);
        }
        if observed_at < self.issued_at {
            return Err(ExecutionAdmissionError::NotYetValid);
        }
        if observed_at >= self.expires_at {
            return Err(ExecutionAdmissionError::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::{DagNodeId, DagNodeRevision, DagRevisionNumber, GoalId, GoalRevision};

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn request() -> ExecutionAdmissionRequest {
        ExecutionAdmissionRequest::new(
            ExecutionAdmissionScope::new(
                ForgeBackendId::from_uuid(Uuid::from_u128(10)),
                WorkspaceId::from_uuid(Uuid::from_u128(1)),
                WorkspaceRevision::INITIAL,
            ),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            GoalNodeAttribution::new(
                GoalId::from_uuid(Uuid::from_u128(3)),
                GoalRevision::INITIAL,
                DagRevisionNumber::INITIAL,
                DagNodeId::from_uuid(Uuid::from_u128(4)),
                DagNodeRevision::INITIAL,
            ),
            ExecutionAdmissionActor::new(
                AgentInstanceId::from_uuid(Uuid::from_u128(5)),
                AgentInstanceRevision::INITIAL,
                AgentSessionId::from_uuid(Uuid::from_u128(6)),
            ),
            ExecutionId::from_uuid(Uuid::from_u128(7)),
            ExecutionRequestDigest::from_bytes([0xA5; ExecutionRequestDigest::BYTE_LEN]),
        )
    }

    #[test]
    fn grant_rejects_non_increasing_window() -> Result<(), Box<dyn Error>> {
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(8));
        let request = request();
        assert_eq!(
            ExecutionAdmissionGrant::new(issuer, request, timestamp(10)?, timestamp(10)?),
            Err(ExecutionAdmissionError::InvalidWindow)
        );
        assert_eq!(
            ExecutionAdmissionGrant::new(issuer, request, timestamp(11)?, timestamp(10)?),
            Err(ExecutionAdmissionError::InvalidWindow)
        );
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table keeps every exact admission fence substitution together"
    )]
    fn validation_uses_exact_issuer_and_request_fences() -> Result<(), Box<dyn Error>> {
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(8));
        let request = request();
        let grant = ExecutionAdmissionGrant::new(issuer, request, timestamp(10)?, timestamp(20)?)?;
        assert_eq!(
            grant.validate_for(
                OrchestrationIssuerId::from_uuid(Uuid::from_u128(9)),
                &request,
                timestamp(15)?,
            ),
            Err(ExecutionAdmissionError::IssuerMismatch)
        );

        let substitutions = [
            (
                "backend scope",
                ExecutionAdmissionRequest {
                    scope: ExecutionAdmissionScope {
                        backend_id: ForgeBackendId::from_uuid(Uuid::from_u128(16)),
                        ..request.scope()
                    },
                    ..request
                },
            ),
            (
                "workspace identity scope",
                ExecutionAdmissionRequest {
                    scope: ExecutionAdmissionScope {
                        workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(17)),
                        ..request.scope()
                    },
                    ..request
                },
            ),
            (
                "workspace revision scope",
                ExecutionAdmissionRequest {
                    scope: ExecutionAdmissionScope {
                        expected_workspace_revision: WorkspaceRevision::new(2)?,
                        ..request.scope()
                    },
                    ..request
                },
            ),
            (
                "activity scope",
                ExecutionAdmissionRequest {
                    activity_id: ActivityId::from_uuid(Uuid::from_u128(11)),
                    ..request
                },
            ),
            (
                "Agent identity",
                ExecutionAdmissionRequest {
                    actor: ExecutionAdmissionActor {
                        agent_id: AgentInstanceId::from_uuid(Uuid::from_u128(12)),
                        ..request.actor()
                    },
                    ..request
                },
            ),
            (
                "Agent revision",
                ExecutionAdmissionRequest {
                    actor: ExecutionAdmissionActor {
                        expected_agent_revision: AgentInstanceRevision::new(2)?,
                        ..request.actor()
                    },
                    ..request
                },
            ),
            (
                "session identity",
                ExecutionAdmissionRequest {
                    actor: ExecutionAdmissionActor {
                        session_id: AgentSessionId::from_uuid(Uuid::from_u128(13)),
                        ..request.actor()
                    },
                    ..request
                },
            ),
            (
                "DAG revision",
                ExecutionAdmissionRequest {
                    attribution: GoalNodeAttribution::new(
                        request.attribution().goal_id(),
                        request.attribution().expected_goal_revision(),
                        DagRevisionNumber::new(2)?,
                        request.attribution().node_id(),
                        request.attribution().expected_node_revision(),
                    ),
                    ..request
                },
            ),
            (
                "node identity",
                ExecutionAdmissionRequest {
                    attribution: GoalNodeAttribution::new(
                        request.attribution().goal_id(),
                        request.attribution().expected_goal_revision(),
                        request.attribution().dag_revision(),
                        DagNodeId::from_uuid(Uuid::from_u128(14)),
                        request.attribution().expected_node_revision(),
                    ),
                    ..request
                },
            ),
            (
                "node revision",
                ExecutionAdmissionRequest {
                    attribution: GoalNodeAttribution::new(
                        request.attribution().goal_id(),
                        request.attribution().expected_goal_revision(),
                        request.attribution().dag_revision(),
                        request.attribution().node_id(),
                        DagNodeRevision::new(2)?,
                    ),
                    ..request
                },
            ),
            (
                "execution identity",
                ExecutionAdmissionRequest {
                    execution_id: ExecutionId::from_uuid(Uuid::from_u128(15)),
                    ..request
                },
            ),
            (
                "request digest",
                ExecutionAdmissionRequest {
                    digest: ExecutionRequestDigest::from_bytes(
                        [0x5A; ExecutionRequestDigest::BYTE_LEN],
                    ),
                    ..request
                },
            ),
        ];
        for (identity, substituted) in substitutions {
            assert_eq!(
                grant.validate_for(issuer, &substituted, timestamp(15)?),
                Err(ExecutionAdmissionError::RequestMismatch),
                "{identity} substitution escaped the exact request fence"
            );
        }
        Ok(())
    }

    #[test]
    fn validation_uses_half_open_time_window() -> Result<(), Box<dyn Error>> {
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(8));
        let request = request();
        let grant = ExecutionAdmissionGrant::new(issuer, request, timestamp(10)?, timestamp(20)?)?;
        assert_eq!(
            grant.validate_for(issuer, &request, timestamp(9)?),
            Err(ExecutionAdmissionError::NotYetValid)
        );
        assert!(grant.validate_for(issuer, &request, timestamp(10)?).is_ok());
        assert!(grant.validate_for(issuer, &request, timestamp(19)?).is_ok());
        assert_eq!(
            grant.validate_for(issuer, &request, timestamp(20)?),
            Err(ExecutionAdmissionError::Expired)
        );
        Ok(())
    }
}
