//! Transport-neutral identity for a Workspace stop request.
//!
//! A [`WorkspaceStopIntent`] is the value that the authenticated service
//! boundary carries into the existing owner/permit path.  It is an identity
//! fence only: the service identity and propagated session/principal do not
//! grant Workspace administrative permission, and this module never creates
//! or refreshes an Approval, Grant, or cleanup permit.

use std::fmt;

use forge_domain::{
    AgentSessionId, AuthenticatedPrincipal, ForgeBackendId, OrchestrationIssuerId,
    RuntimeInstanceId, TimestampMillis,
};
use forge_persistence::ExecutionStopRequest;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::ResolvedWorkspaceScope;

const STOP_INTENT_DIGEST_NAMESPACE: &[u8] = b"heterarchy-forge.workspace-stop-intent.v1\0";
const STOP_INTENT_DIGEST_VERSION: u8 = 1;

/// Opaque identity of the configured Forge service that accepts Workspace-stop
/// requests.
///
/// These values identify the configured service and its current boot.  They
/// are not credentials, process capabilities, or Workspace permissions.  The
/// HTTP bridge must compare them with its actual configuration before passing
/// an intent to the owner admission path.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkspaceStopServiceIdentity {
    backend_id: ForgeBackendId,
    issuer: OrchestrationIssuerId,
    destination_id: Uuid,
    runtime_instance_id: RuntimeInstanceId,
}

impl WorkspaceStopServiceIdentity {
    /// Build one configured service identity.
    pub fn new(
        backend_id: ForgeBackendId,
        issuer: OrchestrationIssuerId,
        destination_id: Uuid,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<Self, ControlError> {
        if backend_id.into_uuid().is_nil()
            || issuer.into_uuid().is_nil()
            || destination_id.is_nil()
            || runtime_instance_id.into_uuid().is_nil()
        {
            return Err(invalid_input());
        }
        Ok(Self {
            backend_id,
            issuer,
            destination_id,
            runtime_instance_id,
        })
    }

    pub const fn backend_id(&self) -> ForgeBackendId {
        self.backend_id
    }

    pub const fn issuer(&self) -> OrchestrationIssuerId {
        self.issuer
    }

    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }
}

impl fmt::Debug for WorkspaceStopServiceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceStopServiceIdentity")
            .field("backend_id", &"<redacted>")
            .field("issuer", &"<redacted>")
            .field("destination_id", &"<redacted>")
            .field("runtime_instance_id", &"<redacted>")
            .finish()
    }
}

/// One canonical Workspace-stop intent; construction does not authenticate it.
///
/// The digest binds every durable identity needed for replay: configured
/// service identity, exact Workspace/Location scope and revisions, stop and
/// request IDs, and the typed logical session/principal.  Observation time is
/// deliberately supplied only when converting to the persistence request, so
/// an exact retry can use a fresh clock reading without changing identity.
/// The digest is evidence for identity matching; it is never a permission or
/// an Approval/Grant substitute.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceStopIntent {
    scope: ResolvedWorkspaceScope,
    stop_id: Uuid,
    request_id: Uuid,
    service: WorkspaceStopServiceIdentity,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    request_digest: [u8; 32],
}

impl WorkspaceStopIntent {
    /// Construct a stop intent after validating all identity-bearing UUIDs.
    ///
    /// The caller supplies only typed scope and logical identities.  No
    /// authentication, session lookup, permit lookup, or native operation is
    /// performed here; those remain responsibilities of the service and
    /// `ApprovalCoordinator` owner boundaries.
    pub fn new(
        scope: ResolvedWorkspaceScope,
        stop_id: Uuid,
        request_id: Uuid,
        service: WorkspaceStopServiceIdentity,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, ControlError> {
        if stop_id.is_nil() || request_id.is_nil() || session_id.into_uuid().is_nil() {
            return Err(invalid_input());
        }
        validate_scope(&scope)?;
        validate_principal(principal)?;

        let request_digest =
            canonical_request_digest(&scope, stop_id, request_id, service, session_id, principal)?;
        Ok(Self {
            scope,
            stop_id,
            request_id,
            service,
            session_id,
            principal,
            request_digest,
        })
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn stop_id(&self) -> Uuid {
        self.stop_id
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn service(&self) -> &WorkspaceStopServiceIdentity {
        &self.service
    }

    pub const fn session_id(&self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Convert this identity into the existing durable execution-stop request.
    ///
    /// `observed_at` is intentionally absent from the intent digest and is
    /// supplied by the owner immediately before durable capture.  The runtime
    /// instance is the persistence owner identity; it is not Activity
    /// attribution and does not establish native process authority by itself.
    pub const fn execution_request(&self, observed_at: TimestampMillis) -> ExecutionStopRequest {
        ExecutionStopRequest::new(
            self.stop_id,
            self.scope.workspace_id(),
            self.request_id,
            self.service.runtime_instance_id(),
            self.request_digest,
            observed_at,
        )
    }
}

impl fmt::Debug for WorkspaceStopIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceStopIntent")
            .field("scope", &"<redacted>")
            .field("stop_id", &"<redacted>")
            .field("request_id", &"<redacted>")
            .field("service", &self.service)
            .field("session_id", &"<redacted>")
            .field("principal", &"<redacted>")
            .field("request_digest", &"<redacted>")
            .finish()
    }
}

fn invalid_input() -> ControlError {
    ControlError::new(ControlErrorCode::InvalidInput)
}

fn validate_scope(scope: &ResolvedWorkspaceScope) -> Result<(), ControlError> {
    if scope.workspace_id().into_uuid().is_nil()
        || scope.workspace_revision().get() < 1
        || scope.locator().location_id().into_uuid().is_nil()
        || scope.locator().expected_revision().get() < 1
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_principal(principal: AuthenticatedPrincipal) -> Result<(), ControlError> {
    let invalid = match principal {
        AuthenticatedPrincipal::TrustedStdio => false,
        AuthenticatedPrincipal::DirectToken(id) => id.into_uuid().is_nil(),
        AuthenticatedPrincipal::OAuthGrant(id) => id.into_uuid().is_nil(),
    };
    if invalid {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn canonical_request_digest(
    scope: &ResolvedWorkspaceScope,
    stop_id: Uuid,
    request_id: Uuid,
    service: WorkspaceStopServiceIdentity,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> Result<[u8; 32], ControlError> {
    let mut hasher = Sha256::new();
    hasher.update(STOP_INTENT_DIGEST_NAMESPACE);
    hasher.update([STOP_INTENT_DIGEST_VERSION]);

    update_uuid(&mut hasher, 0x10, service.backend_id.into_uuid());
    update_uuid(&mut hasher, 0x11, service.issuer.into_uuid());
    update_uuid(&mut hasher, 0x12, service.destination_id);
    update_uuid(&mut hasher, 0x13, service.runtime_instance_id.into_uuid());

    update_uuid(&mut hasher, 0x20, scope.workspace_id().into_uuid());
    update_i64(&mut hasher, 0x21, scope.workspace_revision().get());
    update_uuid(&mut hasher, 0x22, scope.locator().location_id().into_uuid());
    update_i64(&mut hasher, 0x23, scope.locator().expected_revision().get());
    update_bytes(&mut hasher, 0x24, scope.locator().relative_root_bytes())?;

    update_uuid(&mut hasher, 0x30, stop_id);
    update_uuid(&mut hasher, 0x31, request_id);
    update_uuid(&mut hasher, 0x32, session_id.into_uuid());

    hasher.update([0x33]);
    match principal {
        AuthenticatedPrincipal::TrustedStdio => hasher.update([0x00]),
        AuthenticatedPrincipal::DirectToken(id) => {
            hasher.update([0x01]);
            hasher.update(id.into_uuid().into_bytes());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            hasher.update([0x02]);
            hasher.update(id.into_uuid().into_bytes());
        }
    }

    Ok(hasher.finalize().into())
}

fn update_uuid(hasher: &mut Sha256, tag: u8, value: Uuid) {
    hasher.update([tag]);
    hasher.update(value.into_bytes());
}

fn update_i64(hasher: &mut Sha256, tag: u8, value: i64) {
    hasher.update([tag]);
    hasher.update(value.to_le_bytes());
}

fn update_bytes(hasher: &mut Sha256, tag: u8, value: &[u8]) -> Result<(), ControlError> {
    let length = u64::try_from(value.len()).map_err(|_| invalid_input())?;
    hasher.update([tag]);
    hasher.update(length.to_le_bytes());
    hasher.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use forge_workspace::WorkspaceLocator;
    use std::error::Error;
    use std::path::Path;

    use forge_domain::{
        AgentSessionId, DirectTokenId, LocationId, LocationRevision, OAuthGrantId, WorkspaceId,
        WorkspaceRevision,
    };

    use super::*;

    fn scope(seed: u128) -> Result<ResolvedWorkspaceScope, Box<dyn Error>> {
        Ok(ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(Uuid::from_u128(seed)),
            WorkspaceRevision::new(7)?,
            WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(seed + 1)),
                LocationRevision::new(3)?,
                Path::new("workspace"),
            )?,
        ))
    }

    fn service(seed: u128) -> Result<WorkspaceStopServiceIdentity, ControlError> {
        WorkspaceStopServiceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(seed)),
            OrchestrationIssuerId::from_uuid(Uuid::from_u128(seed + 1)),
            Uuid::from_u128(seed + 2),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 3)),
        )
    }

    fn intent(
        seed: u128,
        service: WorkspaceStopServiceIdentity,
        principal: AuthenticatedPrincipal,
    ) -> Result<WorkspaceStopIntent, Box<dyn Error>> {
        Ok(WorkspaceStopIntent::new(
            scope(seed)?,
            Uuid::from_u128(seed + 4),
            Uuid::from_u128(seed + 5),
            service,
            AgentSessionId::from_uuid(Uuid::from_u128(seed + 6)),
            principal,
        )?)
    }

    #[test]
    fn exact_retry_digest_ignores_only_observation_time() -> Result<(), Box<dyn Error>> {
        let intent = intent(10, service(20)?, AuthenticatedPrincipal::TrustedStdio)?;
        let first = intent.execution_request(TimestampMillis::new(100)?);
        let retry = intent.execution_request(TimestampMillis::new(101)?);

        assert_eq!(first.stop_id(), retry.stop_id());
        assert_eq!(first.request_id(), retry.request_id());
        assert_eq!(first.request_digest(), retry.request_digest());
        assert_ne!(first.observed_at(), retry.observed_at());
        Ok(())
    }

    #[test]
    fn digest_binds_service_scope_session_and_principal_identity() -> Result<(), Box<dyn Error>> {
        let base = intent(30, service(40)?, AuthenticatedPrincipal::TrustedStdio)?;
        let backend = intent(30, service(41)?, AuthenticatedPrincipal::TrustedStdio)?;
        let token = intent(
            30,
            service(40)?,
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(99))),
        )?;
        let oauth = intent(
            30,
            service(40)?,
            AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::from_u128(100))),
        )?;
        let changed_scope = WorkspaceStopIntent::new(
            scope(31)?,
            base.stop_id(),
            base.request_id(),
            *base.service(),
            base.session_id(),
            base.principal(),
        )?;
        let changed_session = WorkspaceStopIntent::new(
            base.scope().clone(),
            base.stop_id(),
            base.request_id(),
            *base.service(),
            AgentSessionId::from_uuid(Uuid::from_u128(101)),
            base.principal(),
        )?;

        assert_ne!(base.request_digest(), backend.request_digest());
        assert_ne!(base.request_digest(), token.request_digest());
        assert_ne!(base.request_digest(), oauth.request_digest());
        assert_ne!(base.request_digest(), changed_scope.request_digest());
        assert_ne!(base.request_digest(), changed_session.request_digest());
        Ok(())
    }

    #[test]
    fn digest_binds_stop_request_revision_and_locator() -> Result<(), Box<dyn Error>> {
        let base = intent(50, service(60)?, AuthenticatedPrincipal::TrustedStdio)?;
        let changed_ids = WorkspaceStopIntent::new(
            base.scope().clone(),
            Uuid::from_u128(500),
            Uuid::from_u128(501),
            *base.service(),
            base.session_id(),
            base.principal(),
        )?;
        let changed_revision = WorkspaceStopIntent::new(
            ResolvedWorkspaceScope::from_observation(
                base.scope().workspace_id(),
                WorkspaceRevision::new(8)?,
                base.scope().locator().clone(),
            ),
            base.stop_id(),
            base.request_id(),
            *base.service(),
            base.session_id(),
            base.principal(),
        )?;
        let changed_locator = WorkspaceStopIntent::new(
            ResolvedWorkspaceScope::from_observation(
                base.scope().workspace_id(),
                base.scope().workspace_revision(),
                WorkspaceLocator::new(
                    base.scope().locator().location_id(),
                    base.scope().locator().expected_revision(),
                    Path::new("other-workspace"),
                )?,
            ),
            base.stop_id(),
            base.request_id(),
            *base.service(),
            base.session_id(),
            base.principal(),
        )?;

        assert_ne!(base.request_digest(), changed_ids.request_digest());
        assert_ne!(base.request_digest(), changed_revision.request_digest());
        assert_ne!(base.request_digest(), changed_locator.request_digest());
        Ok(())
    }

    #[test]
    fn nil_service_scope_and_principal_identities_are_rejected() -> Result<(), Box<dyn Error>> {
        let nil = Uuid::nil();
        let id = Uuid::from_u128(1);
        for (backend, issuer, destination, runtime) in [
            (nil, id, id, id),
            (id, nil, id, id),
            (id, id, nil, id),
            (id, id, id, nil),
        ] {
            assert!(
                WorkspaceStopServiceIdentity::new(
                    ForgeBackendId::from_uuid(backend),
                    OrchestrationIssuerId::from_uuid(issuer),
                    destination,
                    RuntimeInstanceId::from_uuid(runtime),
                )
                .is_err()
            );
        }

        let valid_service = service(70)?;
        let valid_scope = scope(80)?;
        assert!(
            WorkspaceStopIntent::new(
                ResolvedWorkspaceScope::from_observation(
                    WorkspaceId::from_uuid(nil),
                    valid_scope.workspace_revision(),
                    valid_scope.locator().clone(),
                ),
                Uuid::from_u128(81),
                Uuid::from_u128(82),
                valid_service,
                AgentSessionId::from_uuid(Uuid::from_u128(83)),
                AuthenticatedPrincipal::TrustedStdio,
            )
            .is_err()
        );
        assert!(
            WorkspaceStopIntent::new(
                ResolvedWorkspaceScope::from_observation(
                    valid_scope.workspace_id(),
                    valid_scope.workspace_revision(),
                    WorkspaceLocator::new(
                        LocationId::from_uuid(nil),
                        valid_scope.locator().expected_revision(),
                        Path::new("workspace"),
                    )?,
                ),
                Uuid::from_u128(81),
                Uuid::from_u128(82),
                valid_service,
                AgentSessionId::from_uuid(Uuid::from_u128(83)),
                AuthenticatedPrincipal::TrustedStdio,
            )
            .is_err()
        );
        assert!(
            WorkspaceStopIntent::new(
                valid_scope.clone(),
                Uuid::from_u128(81),
                Uuid::from_u128(82),
                valid_service,
                AgentSessionId::from_uuid(nil),
                AuthenticatedPrincipal::TrustedStdio,
            )
            .is_err()
        );
        assert!(
            WorkspaceStopIntent::new(
                valid_scope.clone(),
                Uuid::from_u128(81),
                Uuid::from_u128(82),
                valid_service,
                AgentSessionId::from_uuid(Uuid::from_u128(83)),
                AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(nil)),
            )
            .is_err()
        );
        assert!(
            WorkspaceStopIntent::new(
                valid_scope,
                Uuid::from_u128(81),
                Uuid::from_u128(82),
                valid_service,
                AgentSessionId::from_uuid(Uuid::from_u128(83)),
                AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(nil)),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn debug_output_redacts_identity_values() -> Result<(), Box<dyn Error>> {
        let intent = intent(90, service(100)?, AuthenticatedPrincipal::TrustedStdio)?;
        let debug = format!("{intent:?}");
        assert!(!debug.contains(&intent.stop_id().to_string()));
        assert!(!debug.contains(&intent.service().backend_id().to_string()));
        assert!(!debug.contains("workspace-stop-intent.v1"));
        Ok(())
    }
}
