//! Application session admission, executed by the existing bounded control worker.

use std::path::PathBuf;

use forge_domain::{
    ActivityId, AgentAttachmentState, AgentInstanceId, AgentInstanceRevision, AgentSessionId,
    AgentSessionOpenOutcome, AgentSessionState, AuthenticatedPrincipal, OpenAgentSession,
    RegisteredAgentInstance, RegisteredAgentSession,
};
use forge_persistence::{AgentSessionCatalog, AgentSessionCatalogError};

use crate::agent::map_agent_store_error;
use crate::{ControlError, ControlErrorCode, ForgeControl, ResolvedWorkspaceScope};

#[derive(Debug, Clone, Copy)]
pub struct AgentSessionResolveRequest {
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

/// Redacted failure categories that an external Agent session authority may
/// return without gaining access to control's private error constructors or
/// adapter diagnostics.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSessionAuthorityFailure {
    NotFound,
    Conflict,
    Unavailable,
}

impl AgentSessionAuthorityFailure {
    /// Convert an external provider failure into the stable control error
    /// projection owned by Forge.
    pub fn into_control_error(self) -> ControlError {
        let code = match self {
            Self::NotFound => ControlErrorCode::AgentSessionNotFound,
            Self::Conflict => ControlErrorCode::AgentSessionConflict,
            Self::Unavailable => ControlErrorCode::AgentSessionAuthorityUnavailable,
        };
        ControlError::new(code)
    }
}

/// Application-owned authority for logical Agent session admission and lookup.
///
/// The control worker owns this port and invokes it synchronously.  Only
/// `Send` is required because the worker is the sole caller; the authority is
/// never shared through a process-global lock or a `Sync` object.
pub trait AgentSessionAuthority: Send {
    /// Open or idempotently replay one logical Agent session.
    fn open(&self, request: &OpenAgentSession) -> Result<AgentSessionOpenOutcome, ControlError>;

    /// Resolve one session for the exact authenticated principal.
    fn resolve(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<Option<RegisteredAgentSession>, ControlError>;
}

/// Existing Forge bootstrap adapter for the app-global session catalog.
///
/// The catalog is opened for each operation so the provider remains a thin
/// compatibility owner while the selected runtime authority is injected at
/// the control boundary.
#[derive(Debug)]
struct LocalAgentSessionAuthority {
    path: PathBuf,
}

impl LocalAgentSessionAuthority {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl AgentSessionAuthority for LocalAgentSessionAuthority {
    fn open(&self, request: &OpenAgentSession) -> Result<AgentSessionOpenOutcome, ControlError> {
        let mut catalog = AgentSessionCatalog::open(&self.path).map_err(map_session_error)?;
        catalog.open_session(request).map_err(map_session_error)
    }

    fn resolve(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<Option<RegisteredAgentSession>, ControlError> {
        let Some(catalog) =
            AgentSessionCatalog::open_existing(&self.path).map_err(map_session_error)?
        else {
            return Ok(None);
        };
        catalog
            .resolve(request.session_id, request.principal)
            .map_err(map_session_error)
    }
}

pub(crate) fn local_session_authority(path: PathBuf) -> Box<dyn AgentSessionAuthority> {
    Box::new(LocalAgentSessionAuthority::new(path))
}

#[derive(Debug, Clone)]
pub struct AgentSessionProofRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub agent_id: AgentInstanceId,
    pub expected_agent_revision: AgentInstanceRevision,
    pub session_id: AgentSessionId,
    pub principal: AuthenticatedPrincipal,
}

impl ForgeControl {
    /// Authenticate an owner selector against the durable Session authority
    /// without requiring the Session to remain open. Historical Forge-owned
    /// receipts use this read authority; fresh mutations call
    /// `agent_session_resolve` and therefore still require an open Session.
    pub(crate) fn agent_session_authenticate_historical(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<RegisteredAgentSession, ControlError> {
        let session = self
            .session_authority
            .resolve(request)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentSessionNotFound))?;
        if session.id() != request.session_id || session.principal() != request.principal {
            return Err(ControlError::new(ControlErrorCode::AgentSessionNotFound));
        }
        Ok(session)
    }

    pub fn agent_session_open(
        &self,
        request: &OpenAgentSession,
    ) -> Result<AgentSessionOpenOutcome, ControlError> {
        let outcome = self.session_authority.open(request)?;
        let session = outcome.session();
        if session.principal() != request.principal()
            || session.request_id() != request.request_id()
        {
            return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
        }
        if outcome.created()
            && (session.id() != request.proposed_id() || session.state() != AgentSessionState::Open)
        {
            return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
        }
        Ok(outcome)
    }

    pub fn agent_session_resolve(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<RegisteredAgentSession, ControlError> {
        let session = self
            .session_authority
            .resolve(request)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentSessionNotFound))?;
        if session.id() != request.session_id || session.principal() != request.principal {
            return Err(ControlError::new(ControlErrorCode::AgentSessionNotFound));
        }
        if session.state() != AgentSessionState::Open {
            return Err(ControlError::new(ControlErrorCode::AgentSessionClosed));
        }
        Ok(session)
    }

    /// Validate issued logical identity against the exact current Activity
    /// attachment. Mutating repositories additionally check the same immutable
    /// binding and mutable attachment/CAS state in their own transaction.
    pub fn agent_session_prove(
        &self,
        request: &AgentSessionProofRequest,
    ) -> Result<RegisteredAgentInstance, ControlError> {
        let session = self.agent_session_resolve(AgentSessionResolveRequest {
            session_id: request.session_id,
            principal: request.principal,
        })?;
        let (scope, store) = self.open_agent_workspace(&request.scope)?;
        let agent = store
            .get_agent(request.agent_id)
            .map_err(map_agent_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::AgentNotFound))?;
        if agent.session_id().is_none() {
            return Err(ControlError::new(ControlErrorCode::AgentSessionUnresolved));
        }
        if agent.activity_id() != request.activity_id
            || agent.session_id() != Some(session.id())
            || agent.principal() != request.principal
            || agent.revision() != request.expected_agent_revision
            || agent.attachment_state() != AgentAttachmentState::Attached
        {
            return Err(ControlError::new(ControlErrorCode::AgentSessionConflict));
        }
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(agent)
    }
}

pub(crate) fn map_session_error(error: AgentSessionCatalogError) -> ControlError {
    let code = match &error {
        AgentSessionCatalogError::SessionMissing(_)
        | AgentSessionCatalogError::ForeignPrincipal(_) => ControlErrorCode::AgentSessionNotFound,
        AgentSessionCatalogError::SessionIdConflict(_)
        | AgentSessionCatalogError::RevisionConflict(_)
        | AgentSessionCatalogError::Transition(_) => ControlErrorCode::AgentSessionConflict,
        _ => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{
        AgentSessionOpenRequestId, AgentSessionRevision, AgentSessionState, DirectTokenId,
        TimestampMillis,
    };
    use forge_persistence::GlobalRegistry;
    use forge_workspace::LocationService;
    use uuid::Uuid;

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn command(
        session: u128,
        request: u128,
        principal: AuthenticatedPrincipal,
    ) -> Result<OpenAgentSession, Box<dyn Error>> {
        Ok(OpenAgentSession::new(
            AgentSessionId::from_uuid(id(session)),
            AgentSessionOpenRequestId::from_uuid(id(request)),
            principal,
            timestamp(1)?,
        ))
    }

    fn control(
        authority: Box<dyn AgentSessionAuthority>,
    ) -> Result<(ForgeControl, PathBuf), Box<dyn Error>> {
        let serial = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-session-authority-{}-{}",
            std::process::id(),
            serial
        ));
        fs::create_dir_all(&root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let control =
            ForgeControl::with_session_authority(LocationService::new(registry), authority);
        Ok((control, root))
    }

    fn finish(control: ForgeControl, root: PathBuf) -> Result<(), Box<dyn Error>> {
        drop(control);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[derive(Debug)]
    struct ErrorAuthority;

    impl AgentSessionAuthority for ErrorAuthority {
        fn open(
            &self,
            _request: &OpenAgentSession,
        ) -> Result<AgentSessionOpenOutcome, ControlError> {
            Err(AgentSessionAuthorityFailure::Unavailable.into_control_error())
        }

        fn resolve(
            &self,
            _request: AgentSessionResolveRequest,
        ) -> Result<Option<RegisteredAgentSession>, ControlError> {
            Err(AgentSessionAuthorityFailure::Unavailable.into_control_error())
        }
    }

    #[derive(Debug)]
    struct OpenAuthority {
        outcome: AgentSessionOpenOutcome,
    }

    impl AgentSessionAuthority for OpenAuthority {
        fn open(
            &self,
            _request: &OpenAgentSession,
        ) -> Result<AgentSessionOpenOutcome, ControlError> {
            Ok(self.outcome.clone())
        }

        fn resolve(
            &self,
            _request: AgentSessionResolveRequest,
        ) -> Result<Option<RegisteredAgentSession>, ControlError> {
            Ok(None)
        }
    }

    #[derive(Debug)]
    struct ResolveAuthority {
        session: RegisteredAgentSession,
    }

    impl AgentSessionAuthority for ResolveAuthority {
        fn open(
            &self,
            _request: &OpenAgentSession,
        ) -> Result<AgentSessionOpenOutcome, ControlError> {
            Ok(AgentSessionOpenOutcome::new(self.session.clone(), false))
        }

        fn resolve(
            &self,
            _request: AgentSessionResolveRequest,
        ) -> Result<Option<RegisteredAgentSession>, ControlError> {
            Ok(Some(self.session.clone()))
        }
    }

    #[test]
    fn injected_open_rejects_a_provider_identity_mismatch() -> Result<(), Box<dyn Error>> {
        let principal = AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(1)));
        let request = command(2, 3, principal)?;
        let returned = RegisteredAgentSession::open(
            AgentSessionId::from_uuid(id(4)),
            request.request_id(),
            principal,
            request.observed_at(),
        );
        let (control, root) = control(Box::new(OpenAuthority {
            outcome: AgentSessionOpenOutcome::new(returned, true),
        }))?;
        let error = control
            .agent_session_open(&request)
            .err()
            .ok_or_else(|| std::io::Error::other("mismatched provider output was accepted"))?;
        assert_eq!(error.code(), ControlErrorCode::AgentSessionConflict);
        finish(control, root)
    }

    #[test]
    fn injected_resolve_rejects_a_provider_identity_mismatch() -> Result<(), Box<dyn Error>> {
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let request = AgentSessionResolveRequest {
            session_id: AgentSessionId::from_uuid(id(5)),
            principal,
        };
        let returned = RegisteredAgentSession::open(
            AgentSessionId::from_uuid(id(6)),
            AgentSessionOpenRequestId::from_uuid(id(7)),
            principal,
            timestamp(1)?,
        );
        let (control, root) = control(Box::new(ResolveAuthority { session: returned }))?;
        let error = control
            .agent_session_resolve(request)
            .err()
            .ok_or_else(|| std::io::Error::other("mismatched provider output was accepted"))?;
        assert_eq!(error.code(), ControlErrorCode::AgentSessionNotFound);
        finish(control, root)
    }

    #[test]
    fn injected_closed_replay_stays_closed_and_resolve_reports_closed() -> Result<(), Box<dyn Error>>
    {
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let request = command(8, 9, principal)?;
        let open = RegisteredAgentSession::open(
            request.proposed_id(),
            request.request_id(),
            principal,
            request.observed_at(),
        );
        let closed = open.close(AgentSessionRevision::INITIAL, timestamp(2)?)?;
        let (control, root) = control(Box::new(ResolveAuthority { session: closed }))?;
        let replay = control.agent_session_open(&request)?;
        assert!(!replay.created());
        assert_eq!(replay.session().state(), AgentSessionState::Closed);
        let error = control
            .agent_session_resolve(AgentSessionResolveRequest {
                session_id: request.proposed_id(),
                principal,
            })
            .err()
            .ok_or_else(|| std::io::Error::other("closed session was resolved as open"))?;
        assert_eq!(error.code(), ControlErrorCode::AgentSessionClosed);
        finish(control, root)
    }

    #[test]
    fn historical_owner_read_auth_accepts_a_closed_session_without_opening_it()
    -> Result<(), Box<dyn Error>> {
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let request = command(12, 13, principal)?;
        let open = RegisteredAgentSession::open(
            request.proposed_id(),
            request.request_id(),
            principal,
            request.observed_at(),
        );
        let closed = open.close(AgentSessionRevision::INITIAL, timestamp(2)?)?;
        let (control, root) = control(Box::new(ResolveAuthority {
            session: closed.clone(),
        }))?;
        let resolved =
            control.agent_session_authenticate_historical(AgentSessionResolveRequest {
                session_id: request.proposed_id(),
                principal,
            })?;
        assert_eq!(resolved, closed);
        finish(control, root)
    }

    #[test]
    fn injected_provider_errors_are_not_replaced_by_legacy_catalog_results()
    -> Result<(), Box<dyn Error>> {
        let principal = AuthenticatedPrincipal::TrustedStdio;
        let request = command(10, 11, principal)?;
        let (control, root) = control(Box::new(ErrorAuthority))?;
        let open_error = control
            .agent_session_open(&request)
            .err()
            .ok_or_else(|| std::io::Error::other("provider error was swallowed"))?;
        assert_eq!(
            open_error.code(),
            ControlErrorCode::AgentSessionAuthorityUnavailable
        );
        let resolve_error = control
            .agent_session_resolve(AgentSessionResolveRequest {
                session_id: request.proposed_id(),
                principal,
            })
            .err()
            .ok_or_else(|| std::io::Error::other("provider error was swallowed"))?;
        assert_eq!(
            resolve_error.code(),
            ControlErrorCode::AgentSessionAuthorityUnavailable
        );
        finish(control, root)
    }
}
