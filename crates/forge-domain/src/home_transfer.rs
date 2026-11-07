//! Deterministic request envelopes for Home transfer source custody.
//!
//! These values identify an Orchestration preparation and the exact bounded
//! Workspace actor set it attests. They do not authenticate the sender, grant
//! membership, settle work, or authorize a runtime. Forge storage/service
//! owners authenticate the configured issuer and enforce every source effect.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, ForgeBackendId,
    OrchestrationIssuerId, TimestampMillis, WorkspaceId, WorkspaceRevision,
};

/// Workspace Session bound carried by the current Operations identity manifest.
pub const MAX_HOME_TRANSFER_SOURCE_SESSIONS: usize = 128;
/// Current Operations binding bound; excess rows must remain unresolved.
pub const MAX_HOME_TRANSFER_SOURCE_BINDINGS: usize = 256;
const DIGEST_BYTES: usize = 32;
const REQUEST_DOMAIN: &[u8] = b"heterarchy.forge.home-transfer-source-request.v1\0";

mod artifact;
mod assignment_handoff;
mod reservation_retirement;
pub use artifact::{
    HomeArtifactArchive, HomeArtifactArchiveError, HomeArtifactCaptureIntent,
    HomeArtifactCaptureIntentError, HomeArtifactId, HomeArtifactIdError, HomeArtifactIdParseError,
    HomeArtifactIntentDigest, HomeArtifactManifest, HomeArtifactManifestDigest,
    HomeArtifactManifestError, HomeArtifactPathEntry, HomeArtifactPathState,
    MAX_HOME_ARTIFACT_FILE_BYTES, MAX_HOME_ARTIFACT_MANIFEST_BYTES, MAX_HOME_ARTIFACT_PATHS,
    MAX_HOME_ARTIFACT_TOTAL_BYTES,
};
pub use assignment_handoff::{
    HomeHandoffAcceptanceGrant, HomeHandoffAcceptanceReceiptDigest,
    HomeHandoffAffinityAdmissionReferenceDigest, HomeHandoffDomainError,
    HomeHandoffHomeTeamAuthority, HomeHandoffNodeBindingDigest, HomeHandoffProposalRequest,
    HomeHandoffProposalRequestDigest, HomeHandoffRecipientParticipation, HomeHandoffTakeRequest,
    HomeHandoffTakeRequestDigest, HomeHandoffTakeRequestSnapshotError,
    HomeHandoffTemporaryDispatchAuthority, HomeHandoffWorkAuthority,
    MAX_HOME_HANDOFF_REQUEST_SNAPSHOT_BYTES,
};
pub use reservation_retirement::{
    HomeTransferReservationRetirementError, HomeTransferReservationRetirementGrant,
    HomeTransferReservationRetirementRequest, HomeTransferReservationRetirementRequestDigest,
};

/// Checked Workspace/backend owner selected for a source custody request.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeTransferSourceScope {
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    backend_id: ForgeBackendId,
    destination_id: Uuid,
}

impl HomeTransferSourceScope {
    /// # Errors
    /// Rejects nil Workspace, backend, or destination identities.
    pub fn new(
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        backend_id: ForgeBackendId,
        destination_id: Uuid,
    ) -> Result<Self, HomeTransferSourceError> {
        check_id(workspace_id.into_uuid(), "Workspace")?;
        check_id(backend_id.into_uuid(), "Forge backend")?;
        check_id(destination_id, "Orchestration destination")?;
        if workspace_revision.get() < 1 {
            return Err(HomeTransferSourceError::InvalidRevision("Workspace"));
        }
        Ok(Self {
            workspace_id,
            workspace_revision,
            backend_id,
            destination_id,
        })
    }

    #[must_use]
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }
    #[must_use]
    pub const fn workspace_revision(self) -> WorkspaceRevision {
        self.workspace_revision
    }
    pub const fn backend_id(self) -> ForgeBackendId {
        self.backend_id
    }
    #[must_use]
    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }
}

/// Exact Ops-owned transfer subject and approved Home-transfer ancestry.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeTransferSourceSubject {
    transfer_id: Uuid,
    transfer_generation: u64,
    target_profile_id: Uuid,
    target_participation_id: Uuid,
    source_team_id: Uuid,
    destination_team_id: Uuid,
    source_membership_revision: u64,
    participation_revision: u64,
}

impl HomeTransferSourceSubject {
    /// Construct the exact immutable subject from the Operations preparation.
    ///
    /// Team identities are selectors in the Operations record; Forge does not
    /// create a Team or infer election/Team authority from these values.
    ///
    /// # Errors
    /// Rejects nil/equal Team IDs, nil target identity, and invalid revisions.
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor validates the complete immutable Ops subject"
    )]
    pub fn new(
        transfer_id: Uuid,
        transfer_generation: u64,
        target_profile_id: Uuid,
        target_participation_id: Uuid,
        source_team_id: Uuid,
        destination_team_id: Uuid,
        source_membership_revision: u64,
        participation_revision: u64,
    ) -> Result<Self, HomeTransferSourceError> {
        for (value, field) in [
            (transfer_id, "transfer"),
            (target_profile_id, "target Profile"),
            (target_participation_id, "target Participation"),
            (source_team_id, "source Team"),
            (destination_team_id, "destination Team"),
        ] {
            check_id(value, field)?;
        }
        if source_team_id == destination_team_id {
            return Err(HomeTransferSourceError::SameTeam);
        }
        if transfer_generation == 0
            || source_membership_revision == 0
            || participation_revision == 0
            || i64::try_from(transfer_generation).is_err()
            || i64::try_from(source_membership_revision).is_err()
            || i64::try_from(participation_revision).is_err()
        {
            return Err(HomeTransferSourceError::InvalidSubjectRevision);
        }
        Ok(Self {
            transfer_id,
            transfer_generation,
            target_profile_id,
            target_participation_id,
            source_team_id,
            destination_team_id,
            source_membership_revision,
            participation_revision,
        })
    }

    #[must_use]
    pub const fn transfer_id(self) -> Uuid {
        self.transfer_id
    }
    #[must_use]
    pub const fn transfer_generation(self) -> u64 {
        self.transfer_generation
    }
    #[must_use]
    pub const fn target_profile_id(self) -> Uuid {
        self.target_profile_id
    }
    #[must_use]
    pub const fn target_participation_id(self) -> Uuid {
        self.target_participation_id
    }
    #[must_use]
    pub const fn source_team_id(self) -> Uuid {
        self.source_team_id
    }
    #[must_use]
    pub const fn destination_team_id(self) -> Uuid {
        self.destination_team_id
    }
    #[must_use]
    pub const fn source_membership_revision(self) -> u64 {
        self.source_membership_revision
    }
    #[must_use]
    pub const fn participation_revision(self) -> u64 {
        self.participation_revision
    }
}

/// Immutable Ops preparation selector and the two committed identity digests.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeTransferSourceWitness {
    preparation_id: Uuid,
    intent_digest: [u8; DIGEST_BYTES],
    preparation_digest: [u8; DIGEST_BYTES],
}

impl HomeTransferSourceWitness {
    /// # Errors
    /// Rejects nil preparation identity and empty Ops digests.
    pub fn new(
        preparation_id: Uuid,
        intent_digest: [u8; DIGEST_BYTES],
        preparation_digest: [u8; DIGEST_BYTES],
    ) -> Result<Self, HomeTransferSourceError> {
        check_id(preparation_id, "preparation")?;
        if intent_digest == [0; DIGEST_BYTES] || preparation_digest == [0; DIGEST_BYTES] {
            return Err(HomeTransferSourceError::EmptyWitnessDigest);
        }
        Ok(Self {
            preparation_id,
            intent_digest,
            preparation_digest,
        })
    }

    #[must_use]
    pub const fn preparation_id(self) -> Uuid {
        self.preparation_id
    }
    #[must_use]
    pub const fn intent_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.intent_digest
    }
    #[must_use]
    pub const fn preparation_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.preparation_digest
    }
}

/// One exact current Operations Workspace binding tuple.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeTransferSourceBinding {
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}

impl HomeTransferSourceBinding {
    /// Construct one checked source binding. A closed Session can still appear
    /// here as historical fencing identity; this does not make it usable.
    ///
    /// # Errors
    /// Rejects nil identities, including a nil principal identity.
    pub fn new(
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, HomeTransferSourceError> {
        check_id(activity_id.into_uuid(), "Activity")?;
        check_id(agent_id.into_uuid(), "Agent")?;
        check_id(session_id.into_uuid(), "Session")?;
        check_principal(principal)?;
        Ok(Self {
            activity_id,
            agent_id,
            session_id,
            principal,
        })
    }

    #[must_use]
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    #[must_use]
    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }
}

/// Typed and canonical Home-transfer source request. This is a data envelope,
/// never a service credential or participant permission.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTransferSourceRequest {
    witness: HomeTransferSourceWitness,
    scope: HomeTransferSourceScope,
    subject: HomeTransferSourceSubject,
    sessions: Vec<AgentSessionId>,
    bindings: Vec<HomeTransferSourceBinding>,
    digest: HomeTransferSourceRequestDigest,
}

impl HomeTransferSourceRequest {
    /// Canonicalize the complete bounded attestation and calculate its digest.
    ///
    /// # Errors
    /// Rejects missing/duplicate Sessions, excess complete-result bounds,
    /// duplicate bindings or conflicting principals for one Session.
    pub fn new(
        witness: HomeTransferSourceWitness,
        scope: HomeTransferSourceScope,
        subject: HomeTransferSourceSubject,
        mut sessions: Vec<AgentSessionId>,
        mut bindings: Vec<HomeTransferSourceBinding>,
    ) -> Result<Self, HomeTransferSourceError> {
        if subject.transfer_id.is_nil() || scope.workspace_id.into_uuid().is_nil() {
            return Err(HomeTransferSourceError::NilIdentity("request scope"));
        }
        if sessions.is_empty()
            || sessions.len() > MAX_HOME_TRANSFER_SOURCE_SESSIONS
            || bindings.len() > MAX_HOME_TRANSFER_SOURCE_BINDINGS
        {
            return Err(HomeTransferSourceError::Bounds);
        }
        sessions.sort_unstable();
        if sessions.iter().any(|session| session.into_uuid().is_nil())
            || sessions.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(HomeTransferSourceError::DuplicateOrNilSession);
        }
        bindings.sort_unstable_by_key(|binding| binding.agent_id);
        if bindings
            .iter()
            .any(|binding| !sessions.contains(&binding.session_id))
            || bindings
                .windows(2)
                .any(|pair| pair[0].agent_id == pair[1].agent_id)
        {
            return Err(HomeTransferSourceError::BindingIdentity);
        }
        let mut activity_sessions = BTreeSet::new();
        let mut principals_by_session = BTreeMap::new();
        for binding in &bindings {
            if !activity_sessions.insert((binding.activity_id, binding.session_id)) {
                return Err(HomeTransferSourceError::DuplicateActivitySession);
            }
            check_principal(binding.principal)?;
            if principals_by_session
                .insert(binding.session_id, binding.principal)
                .is_some_and(|old| old != binding.principal)
            {
                return Err(HomeTransferSourceError::PrincipalMismatch);
            }
        }
        let mut request = Self {
            witness,
            scope,
            subject,
            sessions,
            bindings,
            digest: HomeTransferSourceRequestDigest([0; DIGEST_BYTES]),
        };
        request.digest = HomeTransferSourceRequestDigest(request.compute_digest()?);
        Ok(request)
    }

    pub const fn witness(&self) -> HomeTransferSourceWitness {
        self.witness
    }
    pub const fn scope(&self) -> HomeTransferSourceScope {
        self.scope
    }
    pub const fn subject(&self) -> HomeTransferSourceSubject {
        self.subject
    }
    pub fn sessions(&self) -> &[AgentSessionId] {
        &self.sessions
    }
    pub fn bindings(&self) -> &[HomeTransferSourceBinding] {
        &self.bindings
    }
    pub const fn request_digest(&self) -> HomeTransferSourceRequestDigest {
        self.digest
    }

    fn compute_digest(&self) -> Result<[u8; DIGEST_BYTES], HomeTransferSourceError> {
        let mut hash = blake3::Hasher::new();
        hash.update(REQUEST_DOMAIN);
        hash.update(&[1]);
        hash.update(self.witness.preparation_id.as_bytes());
        hash.update(&self.witness.intent_digest);
        hash.update(&self.witness.preparation_digest);
        hash.update(self.scope.workspace_id.into_uuid().as_bytes());
        hash.update(&self.scope.workspace_revision.get().to_be_bytes());
        hash.update(self.scope.backend_id.into_uuid().as_bytes());
        hash.update(self.scope.destination_id.as_bytes());
        hash.update(self.subject.transfer_id.as_bytes());
        hash.update(&self.subject.transfer_generation.to_be_bytes());
        hash.update(self.subject.target_profile_id.as_bytes());
        hash.update(self.subject.target_participation_id.as_bytes());
        hash.update(self.subject.source_team_id.as_bytes());
        hash.update(self.subject.destination_team_id.as_bytes());
        hash.update(&self.subject.source_membership_revision.to_be_bytes());
        hash.update(&self.subject.participation_revision.to_be_bytes());
        hash_count(&mut hash, self.sessions.len())?;
        for session in &self.sessions {
            hash.update(session.into_uuid().as_bytes());
        }
        hash_count(&mut hash, self.bindings.len())?;
        for binding in &self.bindings {
            hash.update(binding.activity_id.into_uuid().as_bytes());
            hash.update(binding.agent_id.into_uuid().as_bytes());
            hash.update(binding.session_id.into_uuid().as_bytes());
            match binding.principal {
                AuthenticatedPrincipal::TrustedStdio => {
                    hash.update(&[0]);
                }
                AuthenticatedPrincipal::DirectToken(token) => {
                    hash.update(&[1]);
                    hash.update(token.into_uuid().as_bytes());
                }
                AuthenticatedPrincipal::OAuthGrant(grant) => {
                    hash.update(&[2]);
                    hash.update(grant.into_uuid().as_bytes());
                }
            }
        }
        Ok(*hash.finalize().as_bytes())
    }
}

/// Domain-specific digest of one canonical source request.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeTransferSourceRequestDigest([u8; DIGEST_BYTES]);

impl HomeTransferSourceRequestDigest {
    pub const fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// Action that the Orchestration source grant authorizes.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HomeTransferSourceAction {
    Prepare,
    AbortUnstarted,
}

/// Typed short-lived authorization context for the distinct Prepare/Abort verbs.
/// The Host must authenticate `issuer` and match the request's backend and
/// destination to its configured service identity before trusting this grant.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeTransferSourceGrant {
    issuer: OrchestrationIssuerId,
    action: HomeTransferSourceAction,
    digest: HomeTransferSourceRequestDigest,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
}

impl HomeTransferSourceGrant {
    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.issuer
    }
    pub const fn action(self) -> HomeTransferSourceAction {
        self.action
    }
    pub const fn request_digest(self) -> HomeTransferSourceRequestDigest {
        self.digest
    }
    pub const fn issued_at(self) -> TimestampMillis {
        self.issued_at
    }
    pub const fn expires_at(self) -> TimestampMillis {
        self.expires_at
    }

    /// # Errors
    /// Rejects a nil issuer or a non-increasing time window.
    pub fn new(
        issuer: OrchestrationIssuerId,
        action: HomeTransferSourceAction,
        digest: HomeTransferSourceRequestDigest,
        issued_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, HomeTransferSourceError> {
        check_id(issuer.into_uuid(), "issuer")?;
        if issued_at >= expires_at {
            return Err(HomeTransferSourceError::InvalidWindow);
        }
        Ok(Self {
            issuer,
            action,
            digest,
            issued_at,
            expires_at,
        })
    }

    /// Check the typed grant after authenticating the issuer at the Host.
    /// The validity interval is half-open: issued time is included; expiry is not.
    ///
    /// # Errors
    /// Rejects issuer, action, request digest, or source-time mismatches.
    pub fn validate_for(
        self,
        authenticated_issuer: OrchestrationIssuerId,
        expected_action: HomeTransferSourceAction,
        actual_digest: HomeTransferSourceRequestDigest,
        observed_at: TimestampMillis,
    ) -> Result<(), HomeTransferSourceError> {
        if self.issuer != authenticated_issuer {
            return Err(HomeTransferSourceError::IssuerMismatch);
        }
        if self.action != expected_action {
            return Err(HomeTransferSourceError::ActionMismatch);
        }
        if self.digest != actual_digest {
            return Err(HomeTransferSourceError::RequestMismatch);
        }
        if observed_at < self.issued_at {
            return Err(HomeTransferSourceError::NotYetValid);
        }
        if observed_at >= self.expires_at {
            return Err(HomeTransferSourceError::Expired);
        }
        Ok(())
    }
}

/// Typed validation failures for Home source custody input and grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HomeTransferSourceError {
    #[error("Home transfer source {0} identity is nil")]
    NilIdentity(&'static str),
    #[error("Home transfer source {0} revision is invalid")]
    InvalidRevision(&'static str),
    #[error("Home transfer source transfer generation or subject revision is invalid")]
    InvalidSubjectRevision,
    #[error("Home transfer source Teams must be distinct")]
    SameTeam,
    #[error("Home transfer source Ops digest is empty")]
    EmptyWitnessDigest,
    #[error("Home transfer source manifest exceeds its complete-result bounds")]
    Bounds,
    #[error("Home transfer source Session set is empty, duplicated or nil")]
    DuplicateOrNilSession,
    #[error("Home transfer source binding identity is duplicated or lacks its Session")]
    BindingIdentity,
    #[error("Home transfer source Activity/Session binding is duplicated")]
    DuplicateActivitySession,
    #[error("Home transfer source Session has conflicting principals")]
    PrincipalMismatch,
    #[error("Home transfer source authenticated principal identity is nil")]
    NilPrincipal,
    #[error("Home transfer source grant window is invalid")]
    InvalidWindow,
    #[error("Home transfer source issuer does not match the authenticated Host issuer")]
    IssuerMismatch,
    #[error("Home transfer source grant action does not match the requested operation")]
    ActionMismatch,
    #[error("Home transfer source request digest mismatch")]
    RequestMismatch,
    #[error("Home transfer source grant is not yet valid")]
    NotYetValid,
    #[error("Home transfer source grant expired")]
    Expired,
}

fn check_id(id: Uuid, label: &'static str) -> Result<(), HomeTransferSourceError> {
    if id.is_nil() {
        Err(HomeTransferSourceError::NilIdentity(label))
    } else {
        Ok(())
    }
}

fn check_principal(principal: AuthenticatedPrincipal) -> Result<(), HomeTransferSourceError> {
    let id = match principal {
        AuthenticatedPrincipal::TrustedStdio => return Ok(()),
        AuthenticatedPrincipal::DirectToken(token) => token.into_uuid(),
        AuthenticatedPrincipal::OAuthGrant(grant) => grant.into_uuid(),
    };
    if id.is_nil() {
        Err(HomeTransferSourceError::NilPrincipal)
    } else {
        Ok(())
    }
}

fn hash_count(hash: &mut blake3::Hasher, count: usize) -> Result<(), HomeTransferSourceError> {
    let count = u32::try_from(count).map_err(|_| HomeTransferSourceError::Bounds)?;
    hash.update(&count.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

    fn scope() -> TestResult<HomeTransferSourceScope> {
        Ok(HomeTransferSourceScope::new(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            WorkspaceRevision::INITIAL,
            ForgeBackendId::from_uuid(Uuid::from_u128(2)),
            Uuid::from_u128(3),
        )?)
    }

    fn subject() -> TestResult<HomeTransferSourceSubject> {
        Ok(HomeTransferSourceSubject::new(
            Uuid::from_u128(4),
            2,
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            Uuid::from_u128(7),
            Uuid::from_u128(8),
            3,
            4,
        )?)
    }

    fn witness() -> TestResult<HomeTransferSourceWitness> {
        Ok(HomeTransferSourceWitness::new(
            Uuid::from_u128(9),
            [0xA1; 32],
            [0xB2; 32],
        )?)
    }

    fn binding(
        agent: u128,
        session: u128,
        principal: AuthenticatedPrincipal,
    ) -> TestResult<HomeTransferSourceBinding> {
        binding_in_activity(10, agent, session, principal)
    }

    fn binding_in_activity(
        activity: u128,
        agent: u128,
        session: u128,
        principal: AuthenticatedPrincipal,
    ) -> TestResult<HomeTransferSourceBinding> {
        Ok(HomeTransferSourceBinding::new(
            ActivityId::from_uuid(Uuid::from_u128(activity)),
            AgentInstanceId::from_uuid(Uuid::from_u128(agent)),
            AgentSessionId::from_uuid(Uuid::from_u128(session)),
            principal,
        )?)
    }

    fn sessions() -> Vec<AgentSessionId> {
        [20, 21]
            .map(|id| AgentSessionId::from_uuid(Uuid::from_u128(id)))
            .to_vec()
    }

    fn request(
        sessions: Vec<AgentSessionId>,
        bindings: Vec<HomeTransferSourceBinding>,
    ) -> TestResult<HomeTransferSourceRequest> {
        Ok(HomeTransferSourceRequest::new(
            witness()?,
            scope()?,
            subject()?,
            sessions,
            bindings,
        )?)
    }

    #[test]
    fn session_and_binding_permutations_have_one_canonical_request_digest() -> TestResult<()> {
        let principal = AuthenticatedPrincipal::DirectToken(crate::DirectTokenId::from_uuid(
            Uuid::from_u128(30),
        ));
        let one = request(
            sessions(),
            vec![binding(40, 20, principal)?, binding(41, 21, principal)?],
        )?;
        let two = request(
            sessions().into_iter().rev().collect(),
            vec![binding(41, 21, principal)?, binding(40, 20, principal)?],
        )?;
        assert_eq!(one, two);
        assert_eq!(one.request_digest(), two.request_digest());
        Ok(())
    }

    #[test]
    fn every_owner_scope_and_ops_witness_field_is_digest_bound() -> TestResult<()> {
        let original = request(sessions(), Vec::new())?;
        let other_scope = HomeTransferSourceScope::new(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            WorkspaceRevision::new(2)?,
            ForgeBackendId::from_uuid(Uuid::from_u128(2)),
            Uuid::from_u128(3),
        )?;
        let request_other_scope = HomeTransferSourceRequest::new(
            witness()?,
            other_scope,
            subject()?,
            sessions(),
            Vec::new(),
        )?;
        let subject_other = HomeTransferSourceSubject::new(
            Uuid::from_u128(4),
            3,
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            Uuid::from_u128(7),
            Uuid::from_u128(8),
            3,
            4,
        )?;
        let request_other_generation = HomeTransferSourceRequest::new(
            witness()?,
            scope()?,
            subject_other,
            sessions(),
            Vec::new(),
        )?;
        let witness_other =
            HomeTransferSourceWitness::new(Uuid::from_u128(9), [0xA1; 32], [0xB3; 32])?;
        let request_other_witness = HomeTransferSourceRequest::new(
            witness_other,
            scope()?,
            subject()?,
            sessions(),
            Vec::new(),
        )?;
        assert_ne!(
            original.request_digest(),
            request_other_scope.request_digest()
        );
        assert_ne!(
            original.request_digest(),
            request_other_generation.request_digest()
        );
        assert_ne!(
            original.request_digest(),
            request_other_witness.request_digest()
        );
        Ok(())
    }

    #[test]
    fn request_rejects_invalid_sessions_bindings_and_manifest_bounds() -> TestResult<()> {
        let principal_a = AuthenticatedPrincipal::DirectToken(crate::DirectTokenId::from_uuid(
            Uuid::from_u128(30),
        ));
        let principal_b =
            AuthenticatedPrincipal::OAuthGrant(crate::OAuthGrantId::from_uuid(Uuid::from_u128(31)));
        let session = AgentSessionId::from_uuid(Uuid::from_u128(20));

        assert_eq!(
            HomeTransferSourceRequest::new(
                witness()?,
                scope()?,
                subject()?,
                vec![session, session],
                Vec::new()
            ),
            Err(HomeTransferSourceError::DuplicateOrNilSession)
        );
        assert_eq!(
            HomeTransferSourceRequest::new(
                witness()?,
                scope()?,
                subject()?,
                Vec::new(),
                Vec::new()
            ),
            Err(HomeTransferSourceError::Bounds)
        );
        assert_eq!(
            HomeTransferSourceRequest::new(
                witness()?,
                scope()?,
                subject()?,
                sessions(),
                vec![binding(40, 22, principal_a)?]
            ),
            Err(HomeTransferSourceError::BindingIdentity)
        );
        assert_eq!(
            HomeTransferSourceRequest::new(
                witness()?,
                scope()?,
                subject()?,
                sessions(),
                vec![binding(40, 20, principal_a)?, binding(41, 20, principal_a)?]
            ),
            Err(HomeTransferSourceError::DuplicateActivitySession)
        );
        let different_activity = binding_in_activity(11, 41, 20, principal_b)?;
        assert_eq!(
            HomeTransferSourceRequest::new(
                witness()?,
                scope()?,
                subject()?,
                vec![session],
                vec![binding(40, 20, principal_a)?, different_activity]
            ),
            Err(HomeTransferSourceError::PrincipalMismatch)
        );
        let excess_sessions = vec![session; MAX_HOME_TRANSFER_SOURCE_SESSIONS + 1];
        assert_eq!(
            HomeTransferSourceRequest::new(
                witness()?,
                scope()?,
                subject()?,
                excess_sessions,
                Vec::new()
            ),
            Err(HomeTransferSourceError::Bounds)
        );
        let oversized_bindings = (0..=MAX_HOME_TRANSFER_SOURCE_BINDINGS)
            .map(|index| -> TestResult<_> {
                let ordinal = u128::try_from(index)?;
                binding(1000 + ordinal, 20 + (ordinal % 2), principal_a)
            })
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(
            HomeTransferSourceRequest::new(
                witness()?,
                scope()?,
                subject()?,
                sessions(),
                oversized_bindings
            ),
            Err(HomeTransferSourceError::Bounds)
        );
        Ok(())
    }

    #[test]
    fn subject_and_witness_reject_invalid_team_revision_and_digest() {
        assert_eq!(
            HomeTransferSourceSubject::new(
                Uuid::from_u128(4),
                1,
                Uuid::from_u128(5),
                Uuid::from_u128(6),
                Uuid::from_u128(7),
                Uuid::from_u128(7),
                1,
                1
            ),
            Err(HomeTransferSourceError::SameTeam)
        );
        assert_eq!(
            HomeTransferSourceSubject::new(
                Uuid::from_u128(4),
                0,
                Uuid::from_u128(5),
                Uuid::from_u128(6),
                Uuid::from_u128(7),
                Uuid::from_u128(8),
                1,
                1
            ),
            Err(HomeTransferSourceError::InvalidSubjectRevision),
        );
        assert_eq!(
            HomeTransferSourceWitness::new(Uuid::from_u128(9), [0; 32], [0xB2; 32]),
            Err(HomeTransferSourceError::EmptyWitnessDigest),
        );
        assert!(matches!(
            HomeTransferSourceScope::new(
                WorkspaceId::from_uuid(Uuid::nil()),
                WorkspaceRevision::INITIAL,
                ForgeBackendId::from_uuid(Uuid::from_u128(2)),
                Uuid::from_u128(3)
            ),
            Err(HomeTransferSourceError::NilIdentity("Workspace")),
        ));
    }

    #[test]
    fn grant_binds_issuer_action_digest_and_half_open_source_time() -> TestResult<()> {
        let source = request(sessions(), Vec::new())?;
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(50));
        let grant = HomeTransferSourceGrant::new(
            issuer,
            HomeTransferSourceAction::Prepare,
            source.request_digest(),
            TimestampMillis::new(10)?,
            TimestampMillis::new(20)?,
        )?;
        assert_eq!(
            grant.validate_for(
                issuer,
                HomeTransferSourceAction::Prepare,
                source.request_digest(),
                TimestampMillis::new(10)?
            ),
            Ok(())
        );
        assert_eq!(
            grant.validate_for(
                issuer,
                HomeTransferSourceAction::AbortUnstarted,
                source.request_digest(),
                TimestampMillis::new(15)?
            ),
            Err(HomeTransferSourceError::ActionMismatch)
        );
        assert_eq!(
            grant.validate_for(
                issuer,
                HomeTransferSourceAction::Prepare,
                source.request_digest(),
                TimestampMillis::new(9)?
            ),
            Err(HomeTransferSourceError::NotYetValid)
        );
        assert_eq!(
            grant.validate_for(
                issuer,
                HomeTransferSourceAction::Prepare,
                source.request_digest(),
                TimestampMillis::new(20)?
            ),
            Err(HomeTransferSourceError::Expired)
        );
        assert_eq!(
            grant.validate_for(
                OrchestrationIssuerId::from_uuid(Uuid::from_u128(51)),
                HomeTransferSourceAction::Prepare,
                source.request_digest(),
                TimestampMillis::new(15)?
            ),
            Err(HomeTransferSourceError::IssuerMismatch)
        );
        assert_eq!(
            grant.validate_for(
                issuer,
                HomeTransferSourceAction::Prepare,
                HomeTransferSourceRequestDigest::from_bytes([0xCC; 32]),
                TimestampMillis::new(15)?
            ),
            Err(HomeTransferSourceError::RequestMismatch)
        );
        assert_eq!(
            HomeTransferSourceGrant::new(
                issuer,
                HomeTransferSourceAction::Prepare,
                source.request_digest(),
                TimestampMillis::new(10)?,
                TimestampMillis::new(10)?
            ),
            Err(HomeTransferSourceError::InvalidWindow)
        );
        Ok(())
    }
}
