//! Checked source request and Operations admission values for Home accept-and-take.
//!
//! These values bind immutable request identities and an authenticated owner's
//! admission receipt. They do not authenticate the caller, prove no-prior-work,
//! prove custody or closure, apply an assignment transition, start work, or
//! settle a reservation. Those checks remain with the configured service and
//! Source transaction owners.

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityCoordinatorActor, AgentAssignmentId, AgentAssignmentRevision, AgentAssignmentTarget,
    AuthenticatedPrincipal, OrchestrationIssuerId, TimestampMillis,
};

use super::{HomeArtifactId, HomeTransferSourceScope};

/// Maximum encoded size of either fixed-shape Home handoff request snapshot.
pub const MAX_HOME_HANDOFF_REQUEST_SNAPSHOT_BYTES: usize = 320;

const PROPOSAL_SNAPSHOT_BYTES: usize = 265;
const TAKE_SNAPSHOT_BYTES: usize = 206;
const PROPOSAL_SNAPSHOT_LENGTH: u32 = 265;
const TAKE_SNAPSHOT_LENGTH: u32 = 206;
const PROPOSAL_MAGIC: &[u8; 4] = b"HHPR";
const TAKE_MAGIC: &[u8; 4] = b"HHTR";
const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"heterarchy.forge.home-handoff-proposal-request.digest.v1\0";
const TAKE_DIGEST_DOMAIN: &[u8] = b"heterarchy.forge.home-handoff-take-request.digest.v1\0";
const DIGEST_BYTES: usize = 32;

mod codec;
pub use codec::HomeHandoffTakeRequestSnapshotError;

/// A checked, immutable Home proposal identity and its compare-and-set intent.
///
/// The Source owner derives original root, Goal, DAG, and budget from its
/// records. `artifact_id: None` asks Source to evaluate its no-prior-work path;
/// it is neither permission nor proof that no work or effects exist.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffProposalRequest {
    proposal_id: Uuid,
    handoff_id: Uuid,
    preparation_id: Uuid,
    predecessor_id: AgentAssignmentId,
    predecessor_revision: AgentAssignmentRevision,
    successor_id: AgentAssignmentId,
    coordinator: ActivityCoordinatorActor,
    recipient: AgentAssignmentTarget,
    artifact_id: Option<HomeArtifactId>,
    expected_case_revision: Option<i64>,
    request_digest: HomeHandoffProposalRequestDigest,
}

impl HomeHandoffProposalRequest {
    /// Construct one bounded request and calculate its canonical digest.
    ///
    /// `expected_case_revision: None` requests case creation. A replacement
    /// must supply a positive current case-head revision. No caller-supplied
    /// root assignment or budget is accepted.
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor validates and binds the complete immutable proposal intent"
    )]
    pub fn new(
        proposal_id: Uuid,
        handoff_id: Uuid,
        preparation_id: Uuid,
        predecessor_id: AgentAssignmentId,
        predecessor_revision: AgentAssignmentRevision,
        successor_id: AgentAssignmentId,
        coordinator: ActivityCoordinatorActor,
        recipient: AgentAssignmentTarget,
        artifact_id: Option<HomeArtifactId>,
        expected_case_revision: Option<i64>,
    ) -> Result<Self, HomeHandoffDomainError> {
        check_id(proposal_id, "proposal")?;
        check_id(handoff_id, "handoff")?;
        check_id(preparation_id, "preparation")?;
        check_id(predecessor_id.into_uuid(), "predecessor assignment")?;
        check_id(successor_id.into_uuid(), "successor assignment")?;
        if predecessor_id == successor_id {
            return Err(HomeHandoffDomainError::SuccessorEqualsPredecessor);
        }
        validate_coordinator(coordinator)?;
        validate_recipient(recipient)?;
        if let Some(revision) = expected_case_revision {
            check_revision(revision, "proposal case head")?;
        }

        let mut request = Self {
            proposal_id,
            handoff_id,
            preparation_id,
            predecessor_id,
            predecessor_revision,
            successor_id,
            coordinator,
            recipient,
            artifact_id,
            expected_case_revision,
            request_digest: HomeHandoffProposalRequestDigest([0; DIGEST_BYTES]),
        };
        request.request_digest = HomeHandoffProposalRequestDigest::from_bytes(digest_snapshot::<
            PROPOSAL_SNAPSHOT_LENGTH,
        >(
            PROPOSAL_DIGEST_DOMAIN,
            &request.canonical_snapshot(),
        ))?;
        Ok(request)
    }

    pub const fn proposal_id(self) -> Uuid {
        self.proposal_id
    }

    pub const fn handoff_id(self) -> Uuid {
        self.handoff_id
    }

    pub const fn preparation_id(self) -> Uuid {
        self.preparation_id
    }

    pub const fn predecessor_id(self) -> AgentAssignmentId {
        self.predecessor_id
    }

    pub const fn predecessor_revision(self) -> AgentAssignmentRevision {
        self.predecessor_revision
    }

    pub const fn successor_id(self) -> AgentAssignmentId {
        self.successor_id
    }

    pub const fn coordinator(self) -> ActivityCoordinatorActor {
        self.coordinator
    }

    pub const fn recipient(self) -> AgentAssignmentTarget {
        self.recipient
    }

    pub const fn artifact_id(self) -> Option<HomeArtifactId> {
        self.artifact_id
    }

    pub const fn expected_case_revision(self) -> Option<i64> {
        self.expected_case_revision
    }

    /// Return the versioned fixed-width snapshot used by this request digest.
    /// The snapshot contains no caller-controlled text or unbounded collection.
    pub fn canonical_snapshot(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PROPOSAL_SNAPSHOT_BYTES);
        bytes.extend_from_slice(PROPOSAL_MAGIC);
        bytes.push(1);
        append_uuid(&mut bytes, self.proposal_id);
        append_uuid(&mut bytes, self.handoff_id);
        append_uuid(&mut bytes, self.preparation_id);
        append_uuid(&mut bytes, self.predecessor_id.into_uuid());
        bytes.extend_from_slice(&self.predecessor_revision.get().to_be_bytes());
        append_uuid(&mut bytes, self.successor_id.into_uuid());
        append_uuid(&mut bytes, self.coordinator.workspace_id().into_uuid());
        append_uuid(&mut bytes, self.coordinator.activity_id().into_uuid());
        append_uuid(&mut bytes, self.coordinator.agent_id().into_uuid());
        append_uuid(&mut bytes, self.coordinator.session_id().into_uuid());
        append_principal(&mut bytes, self.coordinator.principal());
        bytes.extend_from_slice(&self.coordinator.expected_revision().get().to_be_bytes());
        append_uuid(&mut bytes, self.recipient.agent_id().into_uuid());
        append_uuid(&mut bytes, self.recipient.session_id().into_uuid());
        append_principal(&mut bytes, self.recipient.principal());
        bytes.extend_from_slice(&self.recipient.agent_revision().get().to_be_bytes());
        append_optional_uuid(&mut bytes, self.artifact_id.map(HomeArtifactId::into_uuid));
        append_optional_i64(&mut bytes, self.expected_case_revision);
        debug_assert_eq!(bytes.len(), PROPOSAL_SNAPSHOT_BYTES);
        debug_assert!(bytes.len() <= MAX_HOME_HANDOFF_REQUEST_SNAPSHOT_BYTES);
        bytes
    }

    pub const fn request_digest(self) -> HomeHandoffProposalRequestDigest {
        self.request_digest
    }
}

/// Checked digest of one canonical proposal request snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeHandoffProposalRequestDigest([u8; DIGEST_BYTES]);

impl HomeHandoffProposalRequestDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Result<Self, HomeHandoffDomainError> {
        check_digest(bytes, "proposal request")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// A checked recipient participation identity from the admission owner.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffRecipientParticipation {
    id: Uuid,
    revision: u64,
}

impl HomeHandoffRecipientParticipation {
    pub fn new(id: Uuid, revision: u64) -> Result<Self, HomeHandoffDomainError> {
        check_id(id, "recipient participation")?;
        check_positive_revision(revision, "recipient participation")?;
        Ok(Self { id, revision })
    }

    pub const fn id(self) -> Uuid {
        self.id
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }
}

/// Nonempty digest for opaque Operations-owned affinity/admission evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeHandoffAffinityAdmissionReferenceDigest([u8; DIGEST_BYTES]);

impl HomeHandoffAffinityAdmissionReferenceDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Result<Self, HomeHandoffDomainError> {
        check_digest(bytes, "affinity/admission reference")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// Nonempty digest for opaque Operations-owned Node binding evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeHandoffNodeBindingDigest([u8; DIGEST_BYTES]);

impl HomeHandoffNodeBindingDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Result<Self, HomeHandoffDomainError> {
        check_digest(bytes, "Node binding")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// Checked Home Team membership and Node binding evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffHomeTeamAuthority {
    affinity_admission_reference_digest: HomeHandoffAffinityAdmissionReferenceDigest,
    team_id: Uuid,
    membership_revision: u64,
    node_binding_revision: u64,
    node_binding_digest: HomeHandoffNodeBindingDigest,
}

impl HomeHandoffHomeTeamAuthority {
    pub fn new(
        affinity_admission_reference_digest: HomeHandoffAffinityAdmissionReferenceDigest,
        team_id: Uuid,
        membership_revision: u64,
        node_binding_revision: u64,
        node_binding_digest: HomeHandoffNodeBindingDigest,
    ) -> Result<Self, HomeHandoffDomainError> {
        check_id(team_id, "Home Team")?;
        check_positive_revision(membership_revision, "Home Team membership")?;
        check_positive_revision(node_binding_revision, "Home Team Node binding")?;
        Ok(Self {
            affinity_admission_reference_digest,
            team_id,
            membership_revision,
            node_binding_revision,
            node_binding_digest,
        })
    }

    pub const fn affinity_admission_reference_digest(
        self,
    ) -> HomeHandoffAffinityAdmissionReferenceDigest {
        self.affinity_admission_reference_digest
    }

    pub const fn team_id(self) -> Uuid {
        self.team_id
    }

    pub const fn membership_revision(self) -> u64 {
        self.membership_revision
    }

    pub const fn node_binding_revision(self) -> u64 {
        self.node_binding_revision
    }

    pub const fn node_binding_digest(self) -> HomeHandoffNodeBindingDigest {
        self.node_binding_digest
    }
}

/// Checked Temporary Dispatch reservation and Node binding evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffTemporaryDispatchAuthority {
    affinity_admission_reference_digest: HomeHandoffAffinityAdmissionReferenceDigest,
    dispatch_id: Uuid,
    destination_team_id: Uuid,
    reservation_authority_revision: u64,
    node_binding_revision: u64,
    node_binding_digest: HomeHandoffNodeBindingDigest,
    end_at: TimestampMillis,
}

impl HomeHandoffTemporaryDispatchAuthority {
    pub fn new(
        affinity_admission_reference_digest: HomeHandoffAffinityAdmissionReferenceDigest,
        dispatch_id: Uuid,
        destination_team_id: Uuid,
        reservation_authority_revision: u64,
        node_binding_revision: u64,
        node_binding_digest: HomeHandoffNodeBindingDigest,
        end_at: TimestampMillis,
    ) -> Result<Self, HomeHandoffDomainError> {
        check_id(dispatch_id, "Temporary Dispatch")?;
        check_id(destination_team_id, "Temporary Dispatch destination Team")?;
        check_positive_revision(
            reservation_authority_revision,
            "Temporary Dispatch reservation/authority",
        )?;
        check_positive_revision(node_binding_revision, "Temporary Dispatch Node binding")?;
        Ok(Self {
            affinity_admission_reference_digest,
            dispatch_id,
            destination_team_id,
            reservation_authority_revision,
            node_binding_revision,
            node_binding_digest,
            end_at,
        })
    }

    pub const fn affinity_admission_reference_digest(
        self,
    ) -> HomeHandoffAffinityAdmissionReferenceDigest {
        self.affinity_admission_reference_digest
    }

    pub const fn dispatch_id(self) -> Uuid {
        self.dispatch_id
    }

    pub const fn destination_team_id(self) -> Uuid {
        self.destination_team_id
    }

    pub const fn reservation_authority_revision(self) -> u64 {
        self.reservation_authority_revision
    }

    pub const fn node_binding_revision(self) -> u64 {
        self.node_binding_revision
    }

    pub const fn node_binding_digest(self) -> HomeHandoffNodeBindingDigest {
        self.node_binding_digest
    }

    pub const fn end_at(self) -> TimestampMillis {
        self.end_at
    }
}

/// Opaque organizational admission evidence for the accepted work authority.
///
/// `WorkspaceWork` represents an Operations-attested unscoped original
/// affinity with an absent Node Team binding. Its public enum constructor does
/// not prove that observation, and it is not a fallback for missing Team or
/// affinity membership. `HomeTeam` and `TemporaryDispatch` carry the same
/// original affinity/admission reference digest alongside their distinct
/// owner evidence. None of these values are Forge-owned Team facts.
///
/// A Temporary Dispatch value does not prove its reservation is active or that
/// custody effects have settled; the configured Source owner must verify the
/// actual Operations receipt and live holds.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HomeHandoffWorkAuthority {
    WorkspaceWork {
        affinity_admission_reference_digest: HomeHandoffAffinityAdmissionReferenceDigest,
    },
    HomeTeam(HomeHandoffHomeTeamAuthority),
    TemporaryDispatch(HomeHandoffTemporaryDispatchAuthority),
}

impl HomeHandoffWorkAuthority {
    pub const fn affinity_admission_reference_digest(
        self,
    ) -> HomeHandoffAffinityAdmissionReferenceDigest {
        match self {
            Self::WorkspaceWork {
                affinity_admission_reference_digest,
            } => affinity_admission_reference_digest,
            Self::HomeTeam(authority) => authority.affinity_admission_reference_digest(),
            Self::TemporaryDispatch(authority) => authority.affinity_admission_reference_digest(),
        }
    }

    pub const fn temporary_dispatch_end_at(self) -> Option<TimestampMillis> {
        match self {
            Self::WorkspaceWork { .. } | Self::HomeTeam(_) => None,
            Self::TemporaryDispatch(dispatch) => Some(dispatch.end_at()),
        }
    }
}

/// Nonempty digest for one immutable Orchestration acceptance receipt.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeHandoffAcceptanceReceiptDigest([u8; DIGEST_BYTES]);

impl HomeHandoffAcceptanceReceiptDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Result<Self, HomeHandoffDomainError> {
        check_digest(bytes, "acceptance receipt")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// Immutable recipient accept-and-take request bound to the current Source scope.
///
/// This request deliberately carries no take timestamp or success assertion.
/// Source samples effective time inside its final transaction.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffTakeRequest {
    acceptance_id: Uuid,
    handoff_id: Uuid,
    proposal_id: Uuid,
    expected_case_revision: i64,
    proposal_digest: HomeHandoffProposalRequestDigest,
    scope: HomeTransferSourceScope,
    recipient: AgentAssignmentTarget,
    request_digest: HomeHandoffTakeRequestDigest,
}

impl HomeHandoffTakeRequest {
    /// Construct one exact accept-and-take intent and calculate its digest.
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor validates and binds the complete immutable take intent"
    )]
    pub fn new(
        acceptance_id: Uuid,
        handoff_id: Uuid,
        proposal_id: Uuid,
        expected_case_revision: i64,
        proposal_digest: HomeHandoffProposalRequestDigest,
        scope: HomeTransferSourceScope,
        recipient: AgentAssignmentTarget,
    ) -> Result<Self, HomeHandoffDomainError> {
        check_id(acceptance_id, "acceptance")?;
        check_id(handoff_id, "handoff")?;
        check_id(proposal_id, "proposal")?;
        check_revision(expected_case_revision, "proposal case head")?;
        validate_recipient(recipient)?;

        let mut request = Self {
            acceptance_id,
            handoff_id,
            proposal_id,
            expected_case_revision,
            proposal_digest,
            scope,
            recipient,
            request_digest: HomeHandoffTakeRequestDigest([0; DIGEST_BYTES]),
        };
        request.request_digest =
            HomeHandoffTakeRequestDigest::from_bytes(digest_snapshot::<TAKE_SNAPSHOT_LENGTH>(
                TAKE_DIGEST_DOMAIN,
                &request.canonical_snapshot(),
            ))?;
        Ok(request)
    }

    pub const fn acceptance_id(self) -> Uuid {
        self.acceptance_id
    }

    pub const fn handoff_id(self) -> Uuid {
        self.handoff_id
    }

    pub const fn proposal_id(self) -> Uuid {
        self.proposal_id
    }

    pub const fn expected_case_revision(self) -> i64 {
        self.expected_case_revision
    }

    pub const fn proposal_digest(self) -> HomeHandoffProposalRequestDigest {
        self.proposal_digest
    }

    pub const fn scope(self) -> HomeTransferSourceScope {
        self.scope
    }

    pub const fn recipient(self) -> AgentAssignmentTarget {
        self.recipient
    }

    /// Return the versioned fixed-width snapshot used by this request digest.
    pub fn canonical_snapshot(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TAKE_SNAPSHOT_BYTES);
        bytes.extend_from_slice(TAKE_MAGIC);
        bytes.push(1);
        append_uuid(&mut bytes, self.acceptance_id);
        append_uuid(&mut bytes, self.handoff_id);
        append_uuid(&mut bytes, self.proposal_id);
        bytes.extend_from_slice(&self.expected_case_revision.to_be_bytes());
        bytes.extend_from_slice(self.proposal_digest.as_bytes());
        append_uuid(&mut bytes, self.scope.workspace_id().into_uuid());
        bytes.extend_from_slice(&self.scope.workspace_revision().get().to_be_bytes());
        append_uuid(&mut bytes, self.scope.backend_id().into_uuid());
        append_uuid(&mut bytes, self.scope.destination_id());
        append_uuid(&mut bytes, self.recipient.agent_id().into_uuid());
        append_uuid(&mut bytes, self.recipient.session_id().into_uuid());
        append_principal(&mut bytes, self.recipient.principal());
        bytes.extend_from_slice(&self.recipient.agent_revision().get().to_be_bytes());
        debug_assert_eq!(bytes.len(), TAKE_SNAPSHOT_BYTES);
        debug_assert!(bytes.len() <= MAX_HOME_HANDOFF_REQUEST_SNAPSHOT_BYTES);
        bytes
    }

    pub const fn request_digest(self) -> HomeHandoffTakeRequestDigest {
        self.request_digest
    }
}

/// Checked digest of one canonical accept-and-take request snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HomeHandoffTakeRequestDigest([u8; DIGEST_BYTES]);

impl HomeHandoffTakeRequestDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Result<Self, HomeHandoffDomainError> {
        check_digest(bytes, "take request")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// Typed admission grant from the authenticated Orchestration owner.
///
/// Construction validates shape and binds a take-request digest; it does not
/// authenticate the issuer or prove that the cited receipt exists. The Source
/// boundary must authenticate the configured private issuer and verify the
/// actual Operations receipt and any live holds before applying work.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeHandoffAcceptanceGrant {
    issuer: OrchestrationIssuerId,
    take_request_digest: HomeHandoffTakeRequestDigest,
    acceptance_receipt_id: Uuid,
    acceptance_receipt_digest: HomeHandoffAcceptanceReceiptDigest,
    moving_profile_id: Uuid,
    recipient_profile_id: Uuid,
    recipient_participation: HomeHandoffRecipientParticipation,
    work_authority: HomeHandoffWorkAuthority,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
}

impl HomeHandoffAcceptanceGrant {
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor checks the complete externally issued admission grant"
    )]
    pub fn new(
        issuer: OrchestrationIssuerId,
        take_request_digest: HomeHandoffTakeRequestDigest,
        acceptance_receipt_id: Uuid,
        acceptance_receipt_digest: HomeHandoffAcceptanceReceiptDigest,
        moving_profile_id: Uuid,
        recipient_profile_id: Uuid,
        recipient_participation: HomeHandoffRecipientParticipation,
        work_authority: HomeHandoffWorkAuthority,
        issued_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, HomeHandoffDomainError> {
        check_id(issuer.into_uuid(), "Orchestration issuer")?;
        check_id(acceptance_receipt_id, "acceptance receipt")?;
        check_id(moving_profile_id, "moving Profile")?;
        check_id(recipient_profile_id, "recipient Profile")?;
        if moving_profile_id == recipient_profile_id {
            return Err(HomeHandoffDomainError::ProfilesMustDiffer);
        }
        if issued_at >= expires_at {
            return Err(HomeHandoffDomainError::InvalidGrantWindow);
        }
        if work_authority
            .temporary_dispatch_end_at()
            .is_some_and(|end_at| expires_at > end_at)
        {
            return Err(HomeHandoffDomainError::GrantExceedsTemporaryDispatchEnd);
        }

        Ok(Self {
            issuer,
            take_request_digest,
            acceptance_receipt_id,
            acceptance_receipt_digest,
            moving_profile_id,
            recipient_profile_id,
            recipient_participation,
            work_authority,
            issued_at,
            expires_at,
        })
    }

    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.issuer
    }

    pub const fn take_request_digest(self) -> HomeHandoffTakeRequestDigest {
        self.take_request_digest
    }

    pub const fn acceptance_receipt_id(self) -> Uuid {
        self.acceptance_receipt_id
    }

    pub const fn acceptance_receipt_digest(self) -> HomeHandoffAcceptanceReceiptDigest {
        self.acceptance_receipt_digest
    }

    pub const fn moving_profile_id(self) -> Uuid {
        self.moving_profile_id
    }

    pub const fn recipient_profile_id(self) -> Uuid {
        self.recipient_profile_id
    }

    pub const fn recipient_participation(self) -> HomeHandoffRecipientParticipation {
        self.recipient_participation
    }

    pub const fn work_authority(self) -> HomeHandoffWorkAuthority {
        self.work_authority
    }

    pub const fn issued_at(self) -> TimestampMillis {
        self.issued_at
    }

    pub const fn expires_at(self) -> TimestampMillis {
        self.expires_at
    }

    /// Validate this grant against authenticated issuer, exact request and
    /// Source-sampled time. The validity interval is half-open.
    pub fn validate_for(
        self,
        authenticated_issuer: OrchestrationIssuerId,
        request: &HomeHandoffTakeRequest,
        source_sampled_at: TimestampMillis,
    ) -> Result<(), HomeHandoffDomainError> {
        if self.issuer != authenticated_issuer {
            return Err(HomeHandoffDomainError::IssuerMismatch);
        }
        if self.take_request_digest != request.request_digest() {
            return Err(HomeHandoffDomainError::RequestDigestMismatch);
        }
        if self
            .work_authority
            .temporary_dispatch_end_at()
            .is_some_and(|end_at| source_sampled_at >= end_at)
        {
            return Err(HomeHandoffDomainError::TemporaryDispatchEnded);
        }
        if source_sampled_at < self.issued_at {
            return Err(HomeHandoffDomainError::NotYetValid);
        }
        if source_sampled_at >= self.expires_at {
            return Err(HomeHandoffDomainError::Expired);
        }
        Ok(())
    }
}

/// Typed validation failures for Home handoff request and admission values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HomeHandoffDomainError {
    #[error("Home handoff {0} identity is nil")]
    NilIdentity(&'static str),
    #[error("Home handoff {0} revision must be positive")]
    InvalidRevision(&'static str),
    #[error("Home handoff {0} digest is empty")]
    EmptyDigest(&'static str),
    #[error("Home handoff successor must differ from predecessor")]
    SuccessorEqualsPredecessor,
    #[error("Home handoff moving and recipient Profiles must differ")]
    ProfilesMustDiffer,
    #[error("Home handoff acceptance grant validity window is invalid")]
    InvalidGrantWindow,
    #[error("Home handoff acceptance grant extends beyond Temporary Dispatch end_at")]
    GrantExceedsTemporaryDispatchEnd,
    #[error("Home handoff grant issuer does not match the authenticated Orchestration issuer")]
    IssuerMismatch,
    #[error("Home handoff grant digest does not match the exact take request")]
    RequestDigestMismatch,
    #[error("Home handoff grant is not yet valid at Source time")]
    NotYetValid,
    #[error("Home handoff grant expired at Source time")]
    Expired,
    #[error("Home handoff Temporary Dispatch has ended at Source time")]
    TemporaryDispatchEnded,
}

fn check_id(id: Uuid, label: &'static str) -> Result<(), HomeHandoffDomainError> {
    if id.is_nil() {
        Err(HomeHandoffDomainError::NilIdentity(label))
    } else {
        Ok(())
    }
}

fn check_revision(revision: i64, label: &'static str) -> Result<(), HomeHandoffDomainError> {
    if revision < 1 {
        Err(HomeHandoffDomainError::InvalidRevision(label))
    } else {
        Ok(())
    }
}

fn check_positive_revision(
    revision: u64,
    label: &'static str,
) -> Result<(), HomeHandoffDomainError> {
    if revision == 0 {
        Err(HomeHandoffDomainError::InvalidRevision(label))
    } else {
        Ok(())
    }
}

fn check_digest(
    bytes: [u8; DIGEST_BYTES],
    label: &'static str,
) -> Result<(), HomeHandoffDomainError> {
    if bytes == [0; DIGEST_BYTES] {
        Err(HomeHandoffDomainError::EmptyDigest(label))
    } else {
        Ok(())
    }
}

fn validate_coordinator(actor: ActivityCoordinatorActor) -> Result<(), HomeHandoffDomainError> {
    check_id(actor.workspace_id().into_uuid(), "Coordinator Workspace")?;
    check_id(actor.activity_id().into_uuid(), "Coordinator Activity")?;
    check_id(actor.agent_id().into_uuid(), "Coordinator Agent")?;
    check_id(actor.session_id().into_uuid(), "Coordinator Session")?;
    validate_principal(actor.principal(), "Coordinator principal")
}

fn validate_recipient(target: AgentAssignmentTarget) -> Result<(), HomeHandoffDomainError> {
    check_id(target.agent_id().into_uuid(), "recipient Agent")?;
    check_id(target.session_id().into_uuid(), "recipient Session")?;
    validate_principal(target.principal(), "recipient principal")
}

fn validate_principal(
    principal: AuthenticatedPrincipal,
    label: &'static str,
) -> Result<(), HomeHandoffDomainError> {
    let stable_id = match principal {
        AuthenticatedPrincipal::TrustedStdio => None,
        AuthenticatedPrincipal::DirectToken(id) => Some(id.into_uuid()),
        AuthenticatedPrincipal::OAuthGrant(id) => Some(id.into_uuid()),
    };
    if stable_id.is_some_and(|id| id.is_nil()) {
        Err(HomeHandoffDomainError::NilIdentity(label))
    } else {
        Ok(())
    }
}

fn append_uuid(bytes: &mut Vec<u8>, value: Uuid) {
    bytes.extend_from_slice(value.as_bytes());
}

fn append_principal(bytes: &mut Vec<u8>, principal: AuthenticatedPrincipal) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => {
            bytes.push(0);
            bytes.extend_from_slice(Uuid::nil().as_bytes());
        }
        AuthenticatedPrincipal::DirectToken(id) => {
            bytes.push(1);
            append_uuid(bytes, id.into_uuid());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            bytes.push(2);
            append_uuid(bytes, id.into_uuid());
        }
    }
}

fn append_optional_uuid(bytes: &mut Vec<u8>, value: Option<Uuid>) {
    if let Some(value) = value {
        bytes.push(1);
        append_uuid(bytes, value);
    } else {
        bytes.push(0);
        bytes.extend_from_slice(Uuid::nil().as_bytes());
    }
}

fn append_optional_i64(bytes: &mut Vec<u8>, value: Option<i64>) {
    if let Some(value) = value {
        bytes.push(1);
        bytes.extend_from_slice(&value.to_be_bytes());
    } else {
        bytes.push(0);
        bytes.extend_from_slice(&0_i64.to_be_bytes());
    }
}

fn digest_snapshot<const SNAPSHOT_LENGTH: u32>(
    domain: &[u8],
    snapshot: &[u8],
) -> [u8; DIGEST_BYTES] {
    debug_assert!(snapshot.len() <= MAX_HOME_HANDOFF_REQUEST_SNAPSHOT_BYTES);
    debug_assert_eq!(usize::try_from(SNAPSHOT_LENGTH).ok(), Some(snapshot.len()));
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    // The two fixed-format callers pass their existing u32 length prefixes;
    // this assertion checks encoder size without narrowing runtime usize.
    hasher.update(&SNAPSHOT_LENGTH.to_be_bytes());
    hasher.update(snapshot);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests;
