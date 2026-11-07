//! Checked values and deterministic evaluation evidence rules.
//!
//! This module contains no clock reads or persistence access. Source-owned
//! records are created and read by `forge-persistence`; these values alone are
//! descriptive data, not authority to mutate an assignment or activate work.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::{
    ActivityId, AgentAssignmentId, AgentAssignmentRevision, AgentInstanceId, AgentSessionId,
    ForgeBackendId, TimestampMillis, WorkspaceId,
};

pub const EVALUATION_DIGEST_BYTES: usize = 32;
/// Maximum number of historical original assignments in one cumulative evaluation cohort.
/// This is independent of the per-Workspace cap on concurrently active assignments.
pub const MAX_EVALUATION_MANIFEST_MEMBERS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvaluationManifestId(Uuid);

impl EvaluationManifestId {
    pub fn new(value: Uuid) -> Result<Self, EvaluationEvidenceError> {
        if value.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("manifest_id"));
        }
        Ok(Self(value))
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvaluationPlanId(Uuid);

impl EvaluationPlanId {
    pub fn new(value: Uuid) -> Result<Self, EvaluationEvidenceError> {
        if value.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("plan_id"));
        }
        Ok(Self(value))
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvaluationWorkUnitId(Uuid);

impl EvaluationWorkUnitId {
    pub fn new(value: Uuid) -> Result<Self, EvaluationEvidenceError> {
        if value.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("work_unit_id"));
        }
        Ok(Self(value))
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvaluationObligationId(Uuid);

impl EvaluationObligationId {
    pub fn new(value: Uuid) -> Result<Self, EvaluationEvidenceError> {
        if value.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("obligation_id"));
        }
        Ok(Self(value))
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvaluationCutId(Uuid);

impl EvaluationCutId {
    pub fn new(value: Uuid) -> Result<Self, EvaluationEvidenceError> {
        if value.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("cut_id"));
        }
        Ok(Self(value))
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvaluationReviewCutId(Uuid);

impl EvaluationReviewCutId {
    pub fn new(value: Uuid) -> Result<Self, EvaluationEvidenceError> {
        if value.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("review_cut_id"));
        }
        Ok(Self(value))
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

/// Exact source identity and frozen T1 value for one closure request.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationT1CloseRequest {
    cut_id: EvaluationCutId,
    manifest_id: EvaluationManifestId,
    manifest_revision: EvaluationRevision,
    manifest_digest: EvaluationDigest,
    deadline: TimestampMillis,
}

impl EvaluationT1CloseRequest {
    pub const fn new(
        cut_id: EvaluationCutId,
        manifest_id: EvaluationManifestId,
        manifest_revision: EvaluationRevision,
        manifest_digest: EvaluationDigest,
        deadline: TimestampMillis,
    ) -> Self {
        Self {
            cut_id,
            manifest_id,
            manifest_revision,
            manifest_digest,
            deadline,
        }
    }

    pub const fn cut_id(self) -> EvaluationCutId {
        self.cut_id
    }

    pub const fn manifest_id(self) -> EvaluationManifestId {
        self.manifest_id
    }

    pub const fn manifest_revision(self) -> EvaluationRevision {
        self.manifest_revision
    }

    pub const fn manifest_digest(self) -> EvaluationDigest {
        self.manifest_digest
    }

    pub const fn deadline(self) -> TimestampMillis {
        self.deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationRevision(i64);

impl EvaluationRevision {
    pub fn new(value: i64) -> Result<Self, EvaluationEvidenceError> {
        if value < 1 {
            return Err(EvaluationEvidenceError::InvalidRevision(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationSourceSequence(i64);

impl EvaluationSourceSequence {
    pub fn new(value: i64) -> Result<Self, EvaluationEvidenceError> {
        if value < 1 {
            return Err(EvaluationEvidenceError::InvalidSequence(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationDigest([u8; EVALUATION_DIGEST_BYTES]);

impl EvaluationDigest {
    pub fn new(value: [u8; EVALUATION_DIGEST_BYTES]) -> Result<Self, EvaluationEvidenceError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(EvaluationEvidenceError::ZeroDigest);
        }
        Ok(Self(value))
    }

    pub const fn into_bytes(self) -> [u8; EVALUATION_DIGEST_BYTES] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; EVALUATION_DIGEST_BYTES] {
        &self.0
    }
}

/// Identity of the actual source owner and the Workspace delegation in force.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationSourceIdentity {
    backend_id: ForgeBackendId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    delegation_migration_id: Uuid,
    delegation_destination_id: Uuid,
    delegation_freeze_revision: EvaluationRevision,
    delegation_manifest_digest: EvaluationDigest,
}

impl EvaluationSourceIdentity {
    pub fn new(
        backend_id: ForgeBackendId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        delegation_migration_id: Uuid,
        delegation_destination_id: Uuid,
        delegation_freeze_revision: EvaluationRevision,
        delegation_manifest_digest: EvaluationDigest,
    ) -> Result<Self, EvaluationEvidenceError> {
        if backend_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("backend_id"));
        }
        if workspace_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("workspace_id"));
        }
        if activity_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("activity_id"));
        }
        if delegation_migration_id.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity(
                "delegation_migration_id",
            ));
        }
        if delegation_destination_id.is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity(
                "delegation_destination_id",
            ));
        }
        Ok(Self {
            backend_id,
            workspace_id,
            activity_id,
            delegation_migration_id,
            delegation_destination_id,
            delegation_freeze_revision,
            delegation_manifest_digest,
        })
    }

    pub const fn backend_id(self) -> ForgeBackendId {
        self.backend_id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn delegation_migration_id(self) -> Uuid {
        self.delegation_migration_id
    }

    pub const fn delegation_destination_id(self) -> Uuid {
        self.delegation_destination_id
    }

    pub const fn delegation_freeze_revision(self) -> EvaluationRevision {
        self.delegation_freeze_revision
    }

    pub const fn delegation_manifest_digest(self) -> EvaluationDigest {
        self.delegation_manifest_digest
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationPlanBinding {
    plan_id: EvaluationPlanId,
    revision: EvaluationRevision,
    digest: EvaluationDigest,
}

impl EvaluationPlanBinding {
    pub const fn new(
        plan_id: EvaluationPlanId,
        revision: EvaluationRevision,
        digest: EvaluationDigest,
    ) -> Self {
        Self {
            plan_id,
            revision,
            digest,
        }
    }

    pub const fn plan_id(self) -> EvaluationPlanId {
        self.plan_id
    }

    pub const fn revision(self) -> EvaluationRevision {
        self.revision
    }

    pub const fn digest(self) -> EvaluationDigest {
        self.digest
    }
}

/// One original assignment reference in a frozen Orchestration cohort.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationManifestMember {
    work_unit_id: EvaluationWorkUnitId,
    obligation_id: EvaluationObligationId,
    assignment_id: AgentAssignmentId,
    assignment_revision: AgentAssignmentRevision,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
    criteria_digest: EvaluationDigest,
}

impl EvaluationManifestMember {
    pub fn new(
        work_unit_id: EvaluationWorkUnitId,
        obligation_id: EvaluationObligationId,
        assignment_id: AgentAssignmentId,
        assignment_revision: AgentAssignmentRevision,
        target_agent_id: AgentInstanceId,
        target_session_id: AgentSessionId,
        criteria_digest: EvaluationDigest,
    ) -> Result<Self, EvaluationEvidenceError> {
        if assignment_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("assignment_id"));
        }
        if target_agent_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("target_agent_id"));
        }
        if target_session_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("target_session_id"));
        }
        Ok(Self {
            work_unit_id,
            obligation_id,
            assignment_id,
            assignment_revision,
            target_agent_id,
            target_session_id,
            criteria_digest,
        })
    }

    pub const fn work_unit_id(self) -> EvaluationWorkUnitId {
        self.work_unit_id
    }

    pub const fn obligation_id(self) -> EvaluationObligationId {
        self.obligation_id
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn assignment_revision(self) -> AgentAssignmentRevision {
        self.assignment_revision
    }

    pub const fn target_agent_id(self) -> AgentInstanceId {
        self.target_agent_id
    }

    pub const fn target_session_id(self) -> AgentSessionId {
        self.target_session_id
    }

    pub const fn criteria_digest(self) -> EvaluationDigest {
        self.criteria_digest
    }
}

/// Caller input for source registration. The digest commits to the whole
/// canonical cohort; only Forge persistence can turn this proposal into a
/// registered source manifest after exact assignment lookups.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationManifestProposal {
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
    source: EvaluationSourceIdentity,
    plan: EvaluationPlanBinding,
    deadline: TimestampMillis,
    members: Vec<EvaluationManifestMember>,
    digest: EvaluationDigest,
}

impl EvaluationManifestProposal {
    pub fn new(
        manifest_id: EvaluationManifestId,
        revision: EvaluationRevision,
        source: EvaluationSourceIdentity,
        plan: EvaluationPlanBinding,
        deadline: TimestampMillis,
        mut members: Vec<EvaluationManifestMember>,
    ) -> Result<Self, EvaluationEvidenceError> {
        validate_manifest_members(&members)?;
        members.sort_unstable_by_key(|member| {
            (
                member.work_unit_id,
                member.obligation_id,
                member.assignment_id,
            )
        });
        let digest = manifest_digest(manifest_id, revision, source, plan, deadline, &members)?;
        Ok(Self {
            manifest_id,
            revision,
            source,
            plan,
            deadline,
            members,
            digest,
        })
    }

    pub const fn manifest_id(&self) -> EvaluationManifestId {
        self.manifest_id
    }

    pub const fn revision(&self) -> EvaluationRevision {
        self.revision
    }

    pub const fn source(&self) -> EvaluationSourceIdentity {
        self.source
    }

    pub const fn plan(&self) -> EvaluationPlanBinding {
        self.plan
    }

    pub const fn deadline(&self) -> TimestampMillis {
        self.deadline
    }

    pub fn members(&self) -> &[EvaluationManifestMember] {
        &self.members
    }

    pub const fn digest(&self) -> EvaluationDigest {
        self.digest
    }

    /// Validate a digest read from durable state against the canonical payload.
    pub fn validates_digest(&self, digest: EvaluationDigest) -> bool {
        self.digest == digest
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationOriginalAssignmentBinding {
    digest: EvaluationDigest,
    assignment_revision: AgentAssignmentRevision,
    source_sequence: EvaluationSourceSequence,
}

impl EvaluationOriginalAssignmentBinding {
    pub const fn new(
        digest: EvaluationDigest,
        assignment_revision: AgentAssignmentRevision,
        source_sequence: EvaluationSourceSequence,
    ) -> Self {
        Self {
            digest,
            assignment_revision,
            source_sequence,
        }
    }

    pub const fn digest(self) -> EvaluationDigest {
        self.digest
    }

    pub const fn assignment_revision(self) -> AgentAssignmentRevision {
        self.assignment_revision
    }

    pub const fn source_sequence(self) -> EvaluationSourceSequence {
        self.source_sequence
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationOriginalBindingStatus {
    Bound(EvaluationOriginalAssignmentBinding),
    UnknownHistorical,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationRegisteredManifestMember {
    declaration: EvaluationManifestMember,
    binding: EvaluationOriginalBindingStatus,
}

impl EvaluationRegisteredManifestMember {
    pub const fn new(
        declaration: EvaluationManifestMember,
        binding: EvaluationOriginalBindingStatus,
    ) -> Self {
        Self {
            declaration,
            binding,
        }
    }

    pub const fn declaration(self) -> EvaluationManifestMember {
        self.declaration
    }

    pub const fn binding(self) -> EvaluationOriginalBindingStatus {
        self.binding
    }
}

/// The source readback, including which original assignment bindings Forge
/// actually established before work became eligible.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationRegisteredManifest {
    proposal: EvaluationManifestProposal,
    members: Vec<EvaluationRegisteredManifestMember>,
    source_sequence: EvaluationSourceSequence,
    seal_timing: EvaluationAdmissionTiming,
}

impl EvaluationRegisteredManifest {
    pub fn from_source_records(
        proposal: EvaluationManifestProposal,
        members: Vec<EvaluationRegisteredManifestMember>,
        source_sequence: EvaluationSourceSequence,
        seal_timing: EvaluationAdmissionTiming,
    ) -> Result<Self, EvaluationEvidenceError> {
        if members.len() != proposal.members().len() {
            return Err(EvaluationEvidenceError::CutMembershipMismatch);
        }
        for (declaration, registered) in proposal.members().iter().zip(&members) {
            if *declaration != registered.declaration() {
                return Err(EvaluationEvidenceError::CutMembershipMismatch);
            }
            if let EvaluationOriginalBindingStatus::Bound(binding) = registered.binding()
                && (binding.assignment_revision() != declaration.assignment_revision()
                    || binding.source_sequence().get() > source_sequence.get())
            {
                return Err(EvaluationEvidenceError::OriginalBindingMismatch);
            }
        }
        Ok(Self {
            proposal,
            members,
            source_sequence,
            seal_timing,
        })
    }

    pub fn proposal(&self) -> &EvaluationManifestProposal {
        &self.proposal
    }

    pub fn members(&self) -> &[EvaluationRegisteredManifestMember] {
        &self.members
    }

    pub const fn source_sequence(&self) -> EvaluationSourceSequence {
        self.source_sequence
    }

    pub const fn seal_timing(&self) -> EvaluationAdmissionTiming {
        self.seal_timing
    }
}

fn validate_manifest_members(
    members: &[EvaluationManifestMember],
) -> Result<(), EvaluationEvidenceError> {
    if members.is_empty() {
        return Err(EvaluationEvidenceError::EmptyManifest);
    }
    if members.len() > MAX_EVALUATION_MANIFEST_MEMBERS {
        return Err(EvaluationEvidenceError::TooManyMembers {
            actual: members.len(),
            maximum: MAX_EVALUATION_MANIFEST_MEMBERS,
        });
    }
    let mut assignments = BTreeSet::new();
    let mut units = BTreeSet::new();
    let mut obligations = BTreeSet::new();
    for member in members {
        if !assignments.insert(member.assignment_id) {
            return Err(EvaluationEvidenceError::DuplicateAssignment(
                member.assignment_id,
            ));
        }
        if !units.insert(member.work_unit_id) {
            return Err(EvaluationEvidenceError::DuplicateWorkUnit(
                member.work_unit_id,
            ));
        }
        if !obligations.insert(member.obligation_id) {
            return Err(EvaluationEvidenceError::DuplicateObligation(
                member.obligation_id,
            ));
        }
    }
    Ok(())
}

fn manifest_digest(
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
    source: EvaluationSourceIdentity,
    plan: EvaluationPlanBinding,
    deadline: TimestampMillis,
    members: &[EvaluationManifestMember],
) -> Result<EvaluationDigest, EvaluationEvidenceError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"forge-source-evaluation-manifest-v1\0");
    hasher.update(manifest_id.into_uuid().as_bytes());
    hasher.update(&revision.get().to_be_bytes());
    hasher.update(source.backend_id().into_uuid().as_bytes());
    hasher.update(source.workspace_id().into_uuid().as_bytes());
    hasher.update(source.activity_id().into_uuid().as_bytes());
    hasher.update(source.delegation_migration_id().as_bytes());
    hasher.update(source.delegation_destination_id().as_bytes());
    hasher.update(&source.delegation_freeze_revision().get().to_be_bytes());
    hasher.update(source.delegation_manifest_digest().as_bytes());
    hasher.update(plan.plan_id().into_uuid().as_bytes());
    hasher.update(&plan.revision().get().to_be_bytes());
    hasher.update(plan.digest().as_bytes());
    hasher.update(&deadline.get().to_be_bytes());
    let member_count =
        u64::try_from(members.len()).map_err(|_| EvaluationEvidenceError::MemberCountOverflow)?;
    hasher.update(&member_count.to_be_bytes());
    for member in members {
        hasher.update(member.work_unit_id().into_uuid().as_bytes());
        hasher.update(member.obligation_id().into_uuid().as_bytes());
        hasher.update(member.assignment_id().into_uuid().as_bytes());
        hasher.update(&member.assignment_revision().get().to_be_bytes());
        hasher.update(member.target_agent_id().into_uuid().as_bytes());
        hasher.update(member.target_session_id().into_uuid().as_bytes());
        hasher.update(member.criteria_digest().as_bytes());
    }
    EvaluationDigest::new(*hasher.finalize().as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationClockReading {
    Trusted(TimestampMillis),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationClockUncertainty {
    Unknown,
    Regressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationAdmissionTiming {
    Trusted(TimestampMillis),
    Unknown(EvaluationClockUncertainty),
}

/// Durable source receipt for the exact immutable submitted assignment version.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationSubmissionReceipt {
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
    author_agent_id: AgentInstanceId,
    author_session_id: AgentSessionId,
    original_binding_digest: Option<EvaluationDigest>,
    criteria_digest: Option<EvaluationDigest>,
    source_sequence: EvaluationSourceSequence,
    timing: EvaluationAdmissionTiming,
    result_digest: EvaluationDigest,
    sources_digest: Option<EvaluationDigest>,
}

impl EvaluationSubmissionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn from_source_record(
        assignment_id: AgentAssignmentId,
        submitted_revision: AgentAssignmentRevision,
        author_agent_id: AgentInstanceId,
        author_session_id: AgentSessionId,
        original_binding_digest: Option<EvaluationDigest>,
        criteria_digest: Option<EvaluationDigest>,
        source_sequence: EvaluationSourceSequence,
        timing: EvaluationAdmissionTiming,
        result_digest: EvaluationDigest,
        sources_digest: Option<EvaluationDigest>,
    ) -> Result<Self, EvaluationEvidenceError> {
        if assignment_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("assignment_id"));
        }
        if author_agent_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("author_agent_id"));
        }
        if author_session_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("author_session_id"));
        }
        if original_binding_digest.is_some() != criteria_digest.is_some() {
            return Err(EvaluationEvidenceError::IncompleteBinding);
        }
        Ok(Self {
            assignment_id,
            submitted_revision,
            author_agent_id,
            author_session_id,
            original_binding_digest,
            criteria_digest,
            source_sequence,
            timing,
            result_digest,
            sources_digest,
        })
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn submitted_revision(self) -> AgentAssignmentRevision {
        self.submitted_revision
    }

    pub const fn author_agent_id(self) -> AgentInstanceId {
        self.author_agent_id
    }

    pub const fn author_session_id(self) -> AgentSessionId {
        self.author_session_id
    }

    pub const fn original_binding_digest(self) -> Option<EvaluationDigest> {
        self.original_binding_digest
    }

    pub const fn criteria_digest(self) -> Option<EvaluationDigest> {
        self.criteria_digest
    }

    pub const fn source_sequence(self) -> EvaluationSourceSequence {
        self.source_sequence
    }

    pub const fn timing(self) -> EvaluationAdmissionTiming {
        self.timing
    }

    pub const fn result_digest(self) -> EvaluationDigest {
        self.result_digest
    }

    pub const fn sources_digest(self) -> Option<EvaluationDigest> {
        self.sources_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationCoverageUnknownReason {
    OriginalBindingMissing,
    LegacySubmissionWithoutReceipt,
    SubmissionTimingUnknown,
    ClockHistoryUncertain,
    ReceiptBindingMismatch,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationT1Coverage {
    Eligible {
        submitted_revision: AgentAssignmentRevision,
        receipt_sequence: EvaluationSourceSequence,
        admitted_at: TimestampMillis,
        result_digest: EvaluationDigest,
        sources_digest: Option<EvaluationDigest>,
    },
    NoEligibleSubmission,
    Unknown {
        reason: EvaluationCoverageUnknownReason,
    },
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationT1CoverageMember {
    member: EvaluationManifestMember,
    coverage: EvaluationT1Coverage,
}

impl EvaluationT1CoverageMember {
    pub const fn new(member: EvaluationManifestMember, coverage: EvaluationT1Coverage) -> Self {
        Self { member, coverage }
    }

    pub const fn member(self) -> EvaluationManifestMember {
        self.member
    }

    pub const fn coverage(self) -> EvaluationT1Coverage {
        self.coverage
    }
}

/// Immutable source-owned view of one closed T1 set.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationT1CoverageCut {
    cut_id: EvaluationCutId,
    manifest_id: EvaluationManifestId,
    manifest_revision: EvaluationRevision,
    manifest_digest: EvaluationDigest,
    deadline: TimestampMillis,
    closed_at: TimestampMillis,
    source_high_water: EvaluationSourceSequence,
    members: Vec<EvaluationT1CoverageMember>,
}

impl EvaluationT1CoverageCut {
    pub fn from_source_records(
        cut_id: EvaluationCutId,
        manifest: &EvaluationManifestProposal,
        deadline: TimestampMillis,
        closed_at: TimestampMillis,
        source_high_water: EvaluationSourceSequence,
        members: Vec<EvaluationT1CoverageMember>,
    ) -> Result<Self, EvaluationEvidenceError> {
        if closed_at <= deadline {
            return Err(EvaluationEvidenceError::CutNotAfterDeadline);
        }
        if manifest.deadline() != deadline {
            return Err(EvaluationEvidenceError::CutDeadlineMismatch);
        }
        validate_cut_members(
            manifest.members(),
            members.iter().map(|member| member.member()),
        )?;
        Ok(Self {
            cut_id,
            manifest_id: manifest.manifest_id(),
            manifest_revision: manifest.revision(),
            manifest_digest: manifest.digest(),
            deadline,
            closed_at,
            source_high_water,
            members,
        })
    }

    pub const fn cut_id(&self) -> EvaluationCutId {
        self.cut_id
    }

    pub const fn manifest_id(&self) -> EvaluationManifestId {
        self.manifest_id
    }

    pub const fn manifest_revision(&self) -> EvaluationRevision {
        self.manifest_revision
    }

    pub const fn manifest_digest(&self) -> EvaluationDigest {
        self.manifest_digest
    }

    pub const fn deadline(&self) -> TimestampMillis {
        self.deadline
    }

    pub const fn closed_at(&self) -> TimestampMillis {
        self.closed_at
    }

    pub const fn source_high_water(&self) -> EvaluationSourceSequence {
        self.source_high_water
    }

    pub fn members(&self) -> &[EvaluationT1CoverageMember] {
        &self.members
    }
}

fn validate_cut_members(
    expected: &[EvaluationManifestMember],
    actual: impl Iterator<Item = EvaluationManifestMember>,
) -> Result<(), EvaluationEvidenceError> {
    let expected_by_id = expected
        .iter()
        .map(|member| (member.assignment_id(), *member))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut actual_by_id = std::collections::BTreeMap::new();
    for member in actual {
        if actual_by_id
            .insert(member.assignment_id(), member)
            .is_some()
        {
            return Err(EvaluationEvidenceError::DuplicateAssignment(
                member.assignment_id(),
            ));
        }
    }
    if expected_by_id != actual_by_id {
        return Err(EvaluationEvidenceError::CutMembershipMismatch);
    }
    Ok(())
}

/// Pure, inclusive T1 classification. Persistence checks assignment rows and
/// receipt identity before calling this function and supplies the durable
/// clock-health history for the member's original binding.
pub fn classify_t1_coverage(
    member: EvaluationManifestMember,
    original_binding_digest: Option<EvaluationDigest>,
    legacy_submission_without_receipt: bool,
    clock_uncertainty_after_binding: bool,
    receipt: Option<EvaluationSubmissionReceipt>,
    deadline: TimestampMillis,
) -> EvaluationT1Coverage {
    let Some(binding_digest) = original_binding_digest else {
        return EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::OriginalBindingMissing,
        };
    };
    if let Some(receipt) = receipt {
        if receipt.assignment_id() != member.assignment_id()
            || receipt.author_agent_id() != member.target_agent_id()
            || receipt.author_session_id() != member.target_session_id()
            || receipt.original_binding_digest() != Some(binding_digest)
            || receipt.criteria_digest() != Some(member.criteria_digest())
            || receipt.submitted_revision().get() <= member.assignment_revision().get()
        {
            return EvaluationT1Coverage::Unknown {
                reason: EvaluationCoverageUnknownReason::ReceiptBindingMismatch,
            };
        }
        return match receipt.timing() {
            EvaluationAdmissionTiming::Trusted(admitted_at) if admitted_at <= deadline => {
                EvaluationT1Coverage::Eligible {
                    submitted_revision: receipt.submitted_revision(),
                    receipt_sequence: receipt.source_sequence(),
                    admitted_at,
                    result_digest: receipt.result_digest(),
                    sources_digest: receipt.sources_digest(),
                }
            }
            EvaluationAdmissionTiming::Trusted(_) => EvaluationT1Coverage::NoEligibleSubmission,
            EvaluationAdmissionTiming::Unknown(_) => EvaluationT1Coverage::Unknown {
                reason: EvaluationCoverageUnknownReason::SubmissionTimingUnknown,
            },
        };
    }
    if legacy_submission_without_receipt {
        return EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::LegacySubmissionWithoutReceipt,
        };
    }
    if clock_uncertainty_after_binding {
        return EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::ClockHistoryUncertain,
        };
    }
    EvaluationT1Coverage::NoEligibleSubmission
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationReviewOutcome {
    Accepted,
    Rejected,
}

/// Review receipt linked to one exact submitted revision and source sequence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvaluationReviewReceipt {
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
    review_revision: AgentAssignmentRevision,
    source_sequence: EvaluationSourceSequence,
    outcome: EvaluationReviewOutcome,
    author_agent_id: AgentInstanceId,
    author_session_id: AgentSessionId,
    reviewer_agent_id: AgentInstanceId,
    reviewer_session_id: AgentSessionId,
    result_digest: EvaluationDigest,
}

impl EvaluationReviewReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn from_source_record(
        assignment_id: AgentAssignmentId,
        submitted_revision: AgentAssignmentRevision,
        review_revision: AgentAssignmentRevision,
        source_sequence: EvaluationSourceSequence,
        outcome: EvaluationReviewOutcome,
        author_agent_id: AgentInstanceId,
        author_session_id: AgentSessionId,
        reviewer_agent_id: AgentInstanceId,
        reviewer_session_id: AgentSessionId,
        result_digest: EvaluationDigest,
    ) -> Result<Self, EvaluationEvidenceError> {
        if assignment_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("assignment_id"));
        }
        if reviewer_agent_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("reviewer_agent_id"));
        }
        if reviewer_session_id.into_uuid().is_nil() {
            return Err(EvaluationEvidenceError::NilIdentity("reviewer_session_id"));
        }
        if review_revision.get() <= submitted_revision.get() {
            return Err(EvaluationEvidenceError::ReviewBeforeSubmission);
        }
        if author_agent_id == reviewer_agent_id {
            return Err(EvaluationEvidenceError::ReviewerIsAuthor);
        }
        Ok(Self {
            assignment_id,
            submitted_revision,
            review_revision,
            source_sequence,
            outcome,
            author_agent_id,
            author_session_id,
            reviewer_agent_id,
            reviewer_session_id,
            result_digest,
        })
    }

    pub const fn assignment_id(self) -> AgentAssignmentId {
        self.assignment_id
    }

    pub const fn submitted_revision(self) -> AgentAssignmentRevision {
        self.submitted_revision
    }

    pub const fn review_revision(self) -> AgentAssignmentRevision {
        self.review_revision
    }

    pub const fn source_sequence(self) -> EvaluationSourceSequence {
        self.source_sequence
    }

    pub const fn outcome(self) -> EvaluationReviewOutcome {
        self.outcome
    }

    pub const fn author_agent_id(self) -> AgentInstanceId {
        self.author_agent_id
    }

    pub const fn author_session_id(self) -> AgentSessionId {
        self.author_session_id
    }

    pub const fn reviewer_agent_id(self) -> AgentInstanceId {
        self.reviewer_agent_id
    }

    pub const fn reviewer_session_id(self) -> AgentSessionId {
        self.reviewer_session_id
    }

    pub const fn result_digest(self) -> EvaluationDigest {
        self.result_digest
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationReviewState {
    NotApplicable,
    Pending {
        submitted_revision: AgentAssignmentRevision,
        receipt_sequence: EvaluationSourceSequence,
    },
    Reviewed(EvaluationReviewReceipt),
    Unknown(EvaluationCoverageUnknownReason),
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationReviewCutMember {
    member: EvaluationManifestMember,
    coverage: EvaluationT1Coverage,
    submission: Option<EvaluationSubmissionReceipt>,
    review: EvaluationReviewState,
}

impl EvaluationReviewCutMember {
    pub const fn new(
        member: EvaluationManifestMember,
        coverage: EvaluationT1Coverage,
        submission: Option<EvaluationSubmissionReceipt>,
        review: EvaluationReviewState,
    ) -> Self {
        Self {
            member,
            coverage,
            submission,
            review,
        }
    }

    pub const fn member(&self) -> EvaluationManifestMember {
        self.member
    }

    pub const fn coverage(&self) -> EvaluationT1Coverage {
        self.coverage
    }

    pub const fn submission(&self) -> Option<EvaluationSubmissionReceipt> {
        self.submission
    }

    pub const fn review(&self) -> EvaluationReviewState {
        self.review
    }
}

/// Immutable source high-water for the review state of every manifest member.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationReviewCut {
    review_cut_id: EvaluationReviewCutId,
    t1_cut_id: EvaluationCutId,
    source_high_water: EvaluationSourceSequence,
    members: Vec<EvaluationReviewCutMember>,
}

impl EvaluationReviewCut {
    pub fn from_source_records(
        review_cut_id: EvaluationReviewCutId,
        t1_cut: &EvaluationT1CoverageCut,
        source_high_water: EvaluationSourceSequence,
        members: Vec<EvaluationReviewCutMember>,
    ) -> Result<Self, EvaluationEvidenceError> {
        if source_high_water.get() <= t1_cut.source_high_water().get() {
            return Err(EvaluationEvidenceError::ReviewCutBeforeT1Cut);
        }
        validate_cut_members(
            &t1_cut
                .members()
                .iter()
                .map(|member| member.member())
                .collect::<Vec<_>>(),
            members.iter().map(EvaluationReviewCutMember::member),
        )?;
        for review_member in &members {
            validate_review_member(review_member, t1_cut.deadline(), source_high_water)?;
        }
        Ok(Self {
            review_cut_id,
            t1_cut_id: t1_cut.cut_id(),
            source_high_water,
            members,
        })
    }

    pub const fn review_cut_id(&self) -> EvaluationReviewCutId {
        self.review_cut_id
    }

    pub const fn t1_cut_id(&self) -> EvaluationCutId {
        self.t1_cut_id
    }

    pub const fn source_high_water(&self) -> EvaluationSourceSequence {
        self.source_high_water
    }

    pub fn members(&self) -> &[EvaluationReviewCutMember] {
        &self.members
    }
}

fn validate_review_member(
    member: &EvaluationReviewCutMember,
    deadline: TimestampMillis,
    source_high_water: EvaluationSourceSequence,
) -> Result<(), EvaluationEvidenceError> {
    let Some(submission) = member.submission() else {
        if matches!(member.coverage(), EvaluationT1Coverage::Eligible { .. }) {
            return Err(EvaluationEvidenceError::ReviewWithoutSubmission);
        }
        return match member.review() {
            EvaluationReviewState::NotApplicable | EvaluationReviewState::Unknown(_) => Ok(()),
            EvaluationReviewState::Pending { .. } | EvaluationReviewState::Reviewed(_) => {
                Err(EvaluationEvidenceError::ReviewWithoutSubmission)
            }
        };
    };
    if submission.assignment_id() != member.member().assignment_id() {
        return Err(EvaluationEvidenceError::ReceiptMemberMismatch);
    }
    if submission.author_agent_id() != member.member().target_agent_id()
        || submission.author_session_id() != member.member().target_session_id()
    {
        return Err(EvaluationEvidenceError::ReceiptMemberMismatch);
    }
    if submission.original_binding_digest().is_some()
        && submission.criteria_digest() != Some(member.member().criteria_digest())
    {
        return Err(EvaluationEvidenceError::ReceiptMemberMismatch);
    }
    if submission.source_sequence().get() > source_high_water.get() {
        return Err(EvaluationEvidenceError::ReceiptBeyondCut);
    }
    match member.coverage() {
        EvaluationT1Coverage::Eligible {
            submitted_revision,
            receipt_sequence,
            admitted_at,
            result_digest,
            sources_digest,
        } if submission.submitted_revision() == submitted_revision
            && submission.source_sequence() == receipt_sequence
            && submission.result_digest() == result_digest
            && submission.sources_digest() == sources_digest
            && matches!(submission.timing(), EvaluationAdmissionTiming::Trusted(value) if value == admitted_at && value <= deadline) =>
        {
            Ok(())
        }
        EvaluationT1Coverage::NoEligibleSubmission if matches!(submission.timing(), EvaluationAdmissionTiming::Trusted(value) if value > deadline) => {
            Ok(())
        }
        EvaluationT1Coverage::Unknown { .. } => Ok(()),
        EvaluationT1Coverage::Eligible { .. } | EvaluationT1Coverage::NoEligibleSubmission => {
            Err(EvaluationEvidenceError::ReceiptMemberMismatch)
        }
    }?;
    match member.review() {
        EvaluationReviewState::NotApplicable => {
            Err(EvaluationEvidenceError::ReviewWithoutSubmission)
        }
        EvaluationReviewState::Pending {
            submitted_revision,
            receipt_sequence,
        } if submitted_revision == submission.submitted_revision()
            && receipt_sequence == submission.source_sequence() =>
        {
            Ok(())
        }
        EvaluationReviewState::Reviewed(review)
            if review.assignment_id() == submission.assignment_id()
                && review.submitted_revision() == submission.submitted_revision()
                && review.author_agent_id() == submission.author_agent_id()
                && review.author_session_id() == submission.author_session_id()
                && review.result_digest() == submission.result_digest()
                && review.source_sequence().get() > submission.source_sequence().get()
                && review.source_sequence().get() <= source_high_water.get() =>
        {
            Ok(())
        }
        EvaluationReviewState::Unknown(_) => Ok(()),
        EvaluationReviewState::Pending { .. } | EvaluationReviewState::Reviewed(_) => {
            Err(EvaluationEvidenceError::ReviewVersionMismatch)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationEvidenceError {
    NilIdentity(&'static str),
    InvalidRevision(i64),
    InvalidSequence(i64),
    ZeroDigest,
    EmptyManifest,
    TooManyMembers { actual: usize, maximum: usize },
    DuplicateAssignment(AgentAssignmentId),
    DuplicateWorkUnit(EvaluationWorkUnitId),
    DuplicateObligation(EvaluationObligationId),
    IncompleteBinding,
    MemberCountOverflow,
    CutNotAfterDeadline,
    CutDeadlineMismatch,
    CutMembershipMismatch,
    ReviewCutBeforeT1Cut,
    ReviewWithoutSubmission,
    ReceiptBeyondCut,
    ReceiptMemberMismatch,
    OriginalBindingMismatch,
    ReviewVersionMismatch,
    ReviewBeforeSubmission,
    ReviewerIsAuthor,
}

impl std::fmt::Display for EvaluationEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NilIdentity(name) => write!(formatter, "evaluation {name} is nil"),
            Self::InvalidRevision(value) => {
                write!(
                    formatter,
                    "evaluation revision must be positive, got {value}"
                )
            }
            Self::InvalidSequence(value) => {
                write!(
                    formatter,
                    "evaluation source sequence must be positive, got {value}"
                )
            }
            Self::ZeroDigest => formatter.write_str("evaluation digest cannot be all zeroes"),
            Self::EmptyManifest => formatter.write_str("evaluation manifest has no members"),
            Self::TooManyMembers { actual, maximum } => write!(
                formatter,
                "evaluation manifest has {actual} members; maximum is {maximum}"
            ),
            Self::DuplicateAssignment(id) => {
                write!(formatter, "evaluation manifest repeats assignment {id}")
            }
            Self::DuplicateWorkUnit(id) => write!(
                formatter,
                "evaluation manifest repeats work unit {}",
                id.into_uuid()
            ),
            Self::DuplicateObligation(id) => write!(
                formatter,
                "evaluation manifest repeats obligation {}",
                id.into_uuid()
            ),
            Self::IncompleteBinding => {
                formatter.write_str("evaluation receipt has an incomplete original binding")
            }
            Self::MemberCountOverflow => {
                formatter.write_str("evaluation manifest member count exceeds its encoding")
            }
            Self::CutNotAfterDeadline => {
                formatter.write_str("evaluation T1 cut observation is not after its deadline")
            }
            Self::CutDeadlineMismatch => {
                formatter.write_str("evaluation T1 deadline differs from the sealed manifest")
            }
            Self::CutMembershipMismatch => {
                formatter.write_str("evaluation cut does not exactly cover its manifest")
            }
            Self::ReviewCutBeforeT1Cut => {
                formatter.write_str("evaluation review cut high-water does not follow T1 cut")
            }
            Self::ReviewWithoutSubmission => {
                formatter.write_str("evaluation review state has no submitted source version")
            }
            Self::ReceiptBeyondCut => formatter
                .write_str("evaluation submission receipt exceeds the review cut high-water"),
            Self::ReceiptMemberMismatch => {
                formatter.write_str("evaluation submission receipt does not match its member")
            }
            Self::OriginalBindingMismatch => formatter
                .write_str("evaluation original binding does not match its manifest member"),
            Self::ReviewVersionMismatch => formatter
                .write_str("evaluation review does not reference the exact submitted version"),
            Self::ReviewBeforeSubmission => {
                formatter.write_str("evaluation review revision does not follow submission")
            }
            Self::ReviewerIsAuthor => {
                formatter.write_str("evaluation reviewer must differ from the assignment author")
            }
        }
    }
}

impl std::error::Error for EvaluationEvidenceError {}

#[cfg(test)]
mod tests;
