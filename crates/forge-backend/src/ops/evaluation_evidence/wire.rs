//! Bounded serialized form of exact evaluation source evidence.

use forge_control::EvaluationEvidenceResponse;
use forge_domain::{
    EvaluationAdmissionTiming, EvaluationClockUncertainty, EvaluationCoverageUnknownReason,
    EvaluationDigest, EvaluationManifestMember, EvaluationManifestProposal,
    EvaluationOriginalBindingStatus, EvaluationRegisteredManifest, EvaluationReviewCut,
    EvaluationReviewCutMember, EvaluationReviewOutcome, EvaluationReviewReceipt,
    EvaluationReviewState, EvaluationSourceIdentity, EvaluationSubmissionReceipt,
    EvaluationT1Coverage, EvaluationT1CoverageCut, EvaluationT1CoverageMember,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ForgeError;

use super::EvaluationEvidenceCommand;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationRecordReadStatus {
    Found,
    Missing,
}

/// Tagged, operation-specific response. `Missing` is an observation only and
/// never asserts that an earlier nonterminal mutation had no durable effect.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationEvidenceResponseWire {
    ManifestSealed {
        source: EvaluationSourceIdentityWire,
        manifest: EvaluationRegisteredManifestWire,
    },
    ManifestRead {
        source: EvaluationSourceIdentityWire,
        status: EvaluationRecordReadStatus,
        manifest: Option<EvaluationRegisteredManifestWire>,
    },
    T1Closed {
        source: EvaluationSourceIdentityWire,
        outcome: EvaluationT1ClosureWire,
    },
    T1Read {
        source: EvaluationSourceIdentityWire,
        status: EvaluationRecordReadStatus,
        cut: Option<EvaluationT1CoverageCutWire>,
    },
    ReviewCutCreated {
        source: EvaluationSourceIdentityWire,
        review_cut: EvaluationReviewCutWire,
    },
    ReviewCutRead {
        source: EvaluationSourceIdentityWire,
        status: EvaluationRecordReadStatus,
        review_cut: Option<EvaluationReviewCutWire>,
    },
    SubmissionReceiptRead {
        source: EvaluationSourceIdentityWire,
        status: EvaluationRecordReadStatus,
        receipt: Option<EvaluationSubmissionReceiptWire>,
    },
    ReviewReceiptRead {
        source: EvaluationSourceIdentityWire,
        status: EvaluationRecordReadStatus,
        receipt: Option<EvaluationReviewReceiptWire>,
    },
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSourceIdentityWire {
    pub backend_id: Uuid,
    pub workspace_id: Uuid,
    pub activity_id: Uuid,
    pub delegation_migration_id: Uuid,
    pub delegation_destination_id: Uuid,
    pub delegation_freeze_revision: i64,
    pub delegation_manifest_digest: String,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationPlanBindingWire {
    pub plan_id: Uuid,
    pub revision: i64,
    pub digest: String,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationManifestMemberWire {
    pub work_unit_id: Uuid,
    pub obligation_id: Uuid,
    pub assignment_id: Uuid,
    pub assignment_revision: i64,
    pub target_agent_id: Uuid,
    pub target_session_id: Uuid,
    pub criteria_digest: String,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationManifestProposalWire {
    pub manifest_id: Uuid,
    pub revision: i64,
    pub source: EvaluationSourceIdentityWire,
    pub plan: EvaluationPlanBindingWire,
    pub deadline_ms: i64,
    pub digest: String,
    pub members: Vec<EvaluationManifestMemberWire>,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationOriginalBindingWire {
    Bound {
        digest: String,
        assignment_revision: i64,
        source_sequence: i64,
    },
    UnknownHistorical,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRegisteredManifestMemberWire {
    pub declaration: EvaluationManifestMemberWire,
    pub binding: EvaluationOriginalBindingWire,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRegisteredManifestWire {
    pub proposal: EvaluationManifestProposalWire,
    pub members: Vec<EvaluationRegisteredManifestMemberWire>,
    pub source_sequence: i64,
    pub seal_timing: EvaluationAdmissionTimingWire,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationAdmissionTimingWire {
    Trusted {
        observed_at_ms: i64,
    },
    Unknown {
        reason: EvaluationClockUncertaintyWire,
    },
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationClockUncertaintyWire {
    Unknown,
    Regressed,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationT1ClosureWire {
    Closed {
        cut: EvaluationT1CoverageCutWire,
    },
    NotClosed {
        timing: EvaluationAdmissionTimingWire,
    },
}

#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationCoverageUnknownReasonWire {
    OriginalBindingMissing,
    LegacySubmissionWithoutReceipt,
    SubmissionTimingUnknown,
    ClockHistoryUncertain,
    ReceiptBindingMismatch,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationT1CoverageWire {
    Eligible {
        submitted_revision: i64,
        receipt_sequence: i64,
        admitted_at_ms: i64,
        result_digest: String,
        sources_digest: Option<String>,
    },
    NoEligibleSubmission,
    Unknown {
        reason: EvaluationCoverageUnknownReasonWire,
    },
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationT1CoverageMemberWire {
    pub member: EvaluationManifestMemberWire,
    pub coverage: EvaluationT1CoverageWire,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationT1CoverageCutWire {
    pub cut_id: Uuid,
    pub manifest_id: Uuid,
    pub manifest_revision: i64,
    pub manifest_digest: String,
    pub deadline_ms: i64,
    pub closed_at_ms: i64,
    pub source_high_water: i64,
    pub members: Vec<EvaluationT1CoverageMemberWire>,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationReviewOutcomeWire {
    Accepted,
    Rejected,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSubmissionReceiptWire {
    pub assignment_id: Uuid,
    pub submitted_revision: i64,
    pub author_agent_id: Uuid,
    pub author_session_id: Uuid,
    pub original_binding_digest: Option<String>,
    pub criteria_digest: Option<String>,
    pub source_sequence: i64,
    pub timing: EvaluationAdmissionTimingWire,
    pub result_digest: String,
    pub sources_digest: Option<String>,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReviewReceiptWire {
    pub assignment_id: Uuid,
    pub submitted_revision: i64,
    pub review_revision: i64,
    pub source_sequence: i64,
    pub outcome: EvaluationReviewOutcomeWire,
    pub author_agent_id: Uuid,
    pub author_session_id: Uuid,
    pub reviewer_agent_id: Uuid,
    pub reviewer_session_id: Uuid,
    pub result_digest: String,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationReviewStateWire {
    NotApplicable,
    Pending {
        submitted_revision: i64,
        receipt_sequence: i64,
    },
    Reviewed {
        receipt: EvaluationReviewReceiptWire,
    },
    Unknown {
        reason: EvaluationCoverageUnknownReasonWire,
    },
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReviewCutMemberWire {
    pub member: EvaluationManifestMemberWire,
    pub coverage: EvaluationT1CoverageWire,
    pub submission: Option<EvaluationSubmissionReceiptWire>,
    pub review: EvaluationReviewStateWire,
}

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReviewCutWire {
    pub review_cut_id: Uuid,
    pub t1_cut_id: Uuid,
    pub source_high_water: i64,
    pub members: Vec<EvaluationReviewCutMemberWire>,
}

pub(super) fn project_response(
    command: &EvaluationEvidenceCommand,
    response: EvaluationEvidenceResponse,
) -> Result<EvaluationEvidenceResponseWire, ForgeError> {
    let source = source_identity_wire(command.request.source);
    match (&command.request.operation, response) {
        (
            forge_control::EvaluationEvidenceOperation::SealManifest { .. },
            EvaluationEvidenceResponse::ManifestSealed(manifest),
        ) => Ok(EvaluationEvidenceResponseWire::ManifestSealed {
            source,
            manifest: registered_manifest_wire(&manifest),
        }),
        (
            forge_control::EvaluationEvidenceOperation::GetManifest { .. },
            EvaluationEvidenceResponse::ManifestRead(manifest),
        ) => Ok(EvaluationEvidenceResponseWire::ManifestRead {
            source,
            status: read_status(manifest.is_some()),
            manifest: manifest.as_ref().map(registered_manifest_wire),
        }),
        (
            forge_control::EvaluationEvidenceOperation::CloseT1 { .. },
            EvaluationEvidenceResponse::T1Closed(outcome),
        ) => {
            let outcome = match outcome {
                forge_persistence::EvaluationT1ClosureOutcome::Closed(cut) => {
                    EvaluationT1ClosureWire::Closed {
                        cut: t1_cut_wire(&cut),
                    }
                }
                forge_persistence::EvaluationT1ClosureOutcome::NotClosed(timing) => {
                    EvaluationT1ClosureWire::NotClosed {
                        timing: timing_wire(timing),
                    }
                }
            };
            Ok(EvaluationEvidenceResponseWire::T1Closed { source, outcome })
        }
        (
            forge_control::EvaluationEvidenceOperation::GetT1Cut { .. },
            EvaluationEvidenceResponse::T1Read(cut),
        ) => Ok(EvaluationEvidenceResponseWire::T1Read {
            source,
            status: read_status(cut.is_some()),
            cut: cut.as_ref().map(t1_cut_wire),
        }),
        (
            forge_control::EvaluationEvidenceOperation::CreateReviewCut { .. },
            EvaluationEvidenceResponse::ReviewCutCreated(review_cut),
        ) => Ok(EvaluationEvidenceResponseWire::ReviewCutCreated {
            source,
            review_cut: review_cut_wire(&review_cut),
        }),
        (
            forge_control::EvaluationEvidenceOperation::GetReviewCut { .. },
            EvaluationEvidenceResponse::ReviewCutRead(review_cut),
        ) => Ok(EvaluationEvidenceResponseWire::ReviewCutRead {
            source,
            status: read_status(review_cut.is_some()),
            review_cut: review_cut.as_ref().map(review_cut_wire),
        }),
        (
            forge_control::EvaluationEvidenceOperation::GetSubmissionReceipt { .. },
            EvaluationEvidenceResponse::SubmissionReceiptRead(receipt),
        ) => Ok(EvaluationEvidenceResponseWire::SubmissionReceiptRead {
            source,
            status: read_status(receipt.is_some()),
            receipt: receipt.as_ref().map(submission_receipt_wire),
        }),
        (
            forge_control::EvaluationEvidenceOperation::GetReviewReceipt { .. },
            EvaluationEvidenceResponse::ReviewReceiptRead(receipt),
        ) => Ok(EvaluationEvidenceResponseWire::ReviewReceiptRead {
            source,
            status: read_status(receipt.is_some()),
            receipt: receipt.as_ref().map(review_receipt_wire),
        }),
        _ => Err(ForgeError::internal()),
    }
}

fn read_status(found: bool) -> EvaluationRecordReadStatus {
    if found {
        EvaluationRecordReadStatus::Found
    } else {
        EvaluationRecordReadStatus::Missing
    }
}

pub(crate) fn source_identity_wire(
    source: EvaluationSourceIdentity,
) -> EvaluationSourceIdentityWire {
    EvaluationSourceIdentityWire {
        backend_id: source.backend_id().into_uuid(),
        workspace_id: source.workspace_id().into_uuid(),
        activity_id: source.activity_id().into_uuid(),
        delegation_migration_id: source.delegation_migration_id(),
        delegation_destination_id: source.delegation_destination_id(),
        delegation_freeze_revision: source.delegation_freeze_revision().get(),
        delegation_manifest_digest: digest_hex(source.delegation_manifest_digest()),
    }
}

pub(crate) fn proposal_wire(
    proposal: &EvaluationManifestProposal,
) -> EvaluationManifestProposalWire {
    EvaluationManifestProposalWire {
        manifest_id: proposal.manifest_id().into_uuid(),
        revision: proposal.revision().get(),
        source: source_identity_wire(proposal.source()),
        plan: EvaluationPlanBindingWire {
            plan_id: proposal.plan().plan_id().into_uuid(),
            revision: proposal.plan().revision().get(),
            digest: digest_hex(proposal.plan().digest()),
        },
        deadline_ms: proposal.deadline().get(),
        digest: digest_hex(proposal.digest()),
        members: proposal.members().iter().map(member_wire).collect(),
    }
}

fn registered_manifest_wire(
    manifest: &EvaluationRegisteredManifest,
) -> EvaluationRegisteredManifestWire {
    EvaluationRegisteredManifestWire {
        proposal: proposal_wire(manifest.proposal()),
        members: manifest
            .members()
            .iter()
            .map(|member| EvaluationRegisteredManifestMemberWire {
                declaration: member_wire(&member.declaration()),
                binding: match member.binding() {
                    EvaluationOriginalBindingStatus::Bound(binding) => {
                        EvaluationOriginalBindingWire::Bound {
                            digest: digest_hex(binding.digest()),
                            assignment_revision: binding.assignment_revision().get(),
                            source_sequence: binding.source_sequence().get(),
                        }
                    }
                    EvaluationOriginalBindingStatus::UnknownHistorical => {
                        EvaluationOriginalBindingWire::UnknownHistorical
                    }
                },
            })
            .collect(),
        source_sequence: manifest.source_sequence().get(),
        seal_timing: timing_wire(manifest.seal_timing()),
    }
}

fn member_wire(member: &EvaluationManifestMember) -> EvaluationManifestMemberWire {
    EvaluationManifestMemberWire {
        work_unit_id: member.work_unit_id().into_uuid(),
        obligation_id: member.obligation_id().into_uuid(),
        assignment_id: member.assignment_id().into_uuid(),
        assignment_revision: member.assignment_revision().get(),
        target_agent_id: member.target_agent_id().into_uuid(),
        target_session_id: member.target_session_id().into_uuid(),
        criteria_digest: digest_hex(member.criteria_digest()),
    }
}

fn timing_wire(timing: EvaluationAdmissionTiming) -> EvaluationAdmissionTimingWire {
    match timing {
        EvaluationAdmissionTiming::Trusted(observed_at) => EvaluationAdmissionTimingWire::Trusted {
            observed_at_ms: observed_at.get(),
        },
        EvaluationAdmissionTiming::Unknown(reason) => EvaluationAdmissionTimingWire::Unknown {
            reason: match reason {
                EvaluationClockUncertainty::Unknown => EvaluationClockUncertaintyWire::Unknown,
                EvaluationClockUncertainty::Regressed => EvaluationClockUncertaintyWire::Regressed,
            },
        },
    }
}

fn t1_cut_wire(cut: &EvaluationT1CoverageCut) -> EvaluationT1CoverageCutWire {
    EvaluationT1CoverageCutWire {
        cut_id: cut.cut_id().into_uuid(),
        manifest_id: cut.manifest_id().into_uuid(),
        manifest_revision: cut.manifest_revision().get(),
        manifest_digest: digest_hex(cut.manifest_digest()),
        deadline_ms: cut.deadline().get(),
        closed_at_ms: cut.closed_at().get(),
        source_high_water: cut.source_high_water().get(),
        members: cut.members().iter().map(t1_member_wire).collect(),
    }
}

fn t1_member_wire(member: &EvaluationT1CoverageMember) -> EvaluationT1CoverageMemberWire {
    EvaluationT1CoverageMemberWire {
        member: member_wire(&member.member()),
        coverage: coverage_wire(member.coverage()),
    }
}

fn coverage_wire(coverage: EvaluationT1Coverage) -> EvaluationT1CoverageWire {
    match coverage {
        EvaluationT1Coverage::Eligible {
            submitted_revision,
            receipt_sequence,
            admitted_at,
            result_digest,
            sources_digest,
        } => EvaluationT1CoverageWire::Eligible {
            submitted_revision: submitted_revision.get(),
            receipt_sequence: receipt_sequence.get(),
            admitted_at_ms: admitted_at.get(),
            result_digest: digest_hex(result_digest),
            sources_digest: sources_digest.map(digest_hex),
        },
        EvaluationT1Coverage::NoEligibleSubmission => {
            EvaluationT1CoverageWire::NoEligibleSubmission
        }
        EvaluationT1Coverage::Unknown { reason } => EvaluationT1CoverageWire::Unknown {
            reason: coverage_unknown_wire(reason),
        },
    }
}

fn coverage_unknown_wire(
    reason: EvaluationCoverageUnknownReason,
) -> EvaluationCoverageUnknownReasonWire {
    match reason {
        EvaluationCoverageUnknownReason::OriginalBindingMissing => {
            EvaluationCoverageUnknownReasonWire::OriginalBindingMissing
        }
        EvaluationCoverageUnknownReason::LegacySubmissionWithoutReceipt => {
            EvaluationCoverageUnknownReasonWire::LegacySubmissionWithoutReceipt
        }
        EvaluationCoverageUnknownReason::SubmissionTimingUnknown => {
            EvaluationCoverageUnknownReasonWire::SubmissionTimingUnknown
        }
        EvaluationCoverageUnknownReason::ClockHistoryUncertain => {
            EvaluationCoverageUnknownReasonWire::ClockHistoryUncertain
        }
        EvaluationCoverageUnknownReason::ReceiptBindingMismatch => {
            EvaluationCoverageUnknownReasonWire::ReceiptBindingMismatch
        }
    }
}

fn submission_receipt_wire(
    receipt: &EvaluationSubmissionReceipt,
) -> EvaluationSubmissionReceiptWire {
    EvaluationSubmissionReceiptWire {
        assignment_id: receipt.assignment_id().into_uuid(),
        submitted_revision: receipt.submitted_revision().get(),
        author_agent_id: receipt.author_agent_id().into_uuid(),
        author_session_id: receipt.author_session_id().into_uuid(),
        original_binding_digest: receipt.original_binding_digest().map(digest_hex),
        criteria_digest: receipt.criteria_digest().map(digest_hex),
        source_sequence: receipt.source_sequence().get(),
        timing: timing_wire(receipt.timing()),
        result_digest: digest_hex(receipt.result_digest()),
        sources_digest: receipt.sources_digest().map(digest_hex),
    }
}

fn review_receipt_wire(receipt: &EvaluationReviewReceipt) -> EvaluationReviewReceiptWire {
    EvaluationReviewReceiptWire {
        assignment_id: receipt.assignment_id().into_uuid(),
        submitted_revision: receipt.submitted_revision().get(),
        review_revision: receipt.review_revision().get(),
        source_sequence: receipt.source_sequence().get(),
        outcome: match receipt.outcome() {
            EvaluationReviewOutcome::Accepted => EvaluationReviewOutcomeWire::Accepted,
            EvaluationReviewOutcome::Rejected => EvaluationReviewOutcomeWire::Rejected,
        },
        author_agent_id: receipt.author_agent_id().into_uuid(),
        author_session_id: receipt.author_session_id().into_uuid(),
        reviewer_agent_id: receipt.reviewer_agent_id().into_uuid(),
        reviewer_session_id: receipt.reviewer_session_id().into_uuid(),
        result_digest: digest_hex(receipt.result_digest()),
    }
}

fn review_cut_wire(cut: &EvaluationReviewCut) -> EvaluationReviewCutWire {
    EvaluationReviewCutWire {
        review_cut_id: cut.review_cut_id().into_uuid(),
        t1_cut_id: cut.t1_cut_id().into_uuid(),
        source_high_water: cut.source_high_water().get(),
        members: cut.members().iter().map(review_member_wire).collect(),
    }
}

fn review_member_wire(member: &EvaluationReviewCutMember) -> EvaluationReviewCutMemberWire {
    EvaluationReviewCutMemberWire {
        member: member_wire(&member.member()),
        coverage: coverage_wire(member.coverage()),
        submission: member.submission().as_ref().map(submission_receipt_wire),
        review: match member.review() {
            EvaluationReviewState::NotApplicable => EvaluationReviewStateWire::NotApplicable,
            EvaluationReviewState::Pending {
                submitted_revision,
                receipt_sequence,
            } => EvaluationReviewStateWire::Pending {
                submitted_revision: submitted_revision.get(),
                receipt_sequence: receipt_sequence.get(),
            },
            EvaluationReviewState::Reviewed(receipt) => EvaluationReviewStateWire::Reviewed {
                receipt: review_receipt_wire(&receipt),
            },
            EvaluationReviewState::Unknown(reason) => EvaluationReviewStateWire::Unknown {
                reason: coverage_unknown_wire(reason),
            },
        },
    }
}

fn digest_hex(digest: EvaluationDigest) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in digest.as_bytes() {
        let _ignored = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{
        ActivityId, AgentAssignmentId, AgentAssignmentRevision, AgentInstanceId, AgentSessionId,
        EvaluationAdmissionTiming, EvaluationCutId, EvaluationDigest, EvaluationManifestId,
        EvaluationManifestMember, EvaluationObligationId, EvaluationOriginalAssignmentBinding,
        EvaluationOriginalBindingStatus, EvaluationPlanBinding, EvaluationPlanId,
        EvaluationRegisteredManifest, EvaluationRegisteredManifestMember, EvaluationReviewCut,
        EvaluationReviewCutId, EvaluationReviewCutMember, EvaluationReviewOutcome,
        EvaluationReviewReceipt, EvaluationReviewState, EvaluationRevision,
        EvaluationSourceIdentity, EvaluationSourceSequence, EvaluationSubmissionReceipt,
        EvaluationT1CloseRequest, EvaluationT1CoverageCut, EvaluationT1CoverageMember,
        EvaluationWorkUnitId, ForgeBackendId, TimestampMillis, WorkspaceId,
    };
    use uuid::Uuid;

    #[test]
    fn maximum_valid_readback_shapes_fit_the_bounded_http_response()
    -> Result<(), Box<dyn std::error::Error>> {
        // This validates the serializer's closed maximum without claiming a
        // persisted 256-assignment source cohort. Domain constructors validate
        // every synthetic source record before production wire projection.
        // UUIDs are fixed at 36 characters, digests at 64, and all i64 values
        // use their maximum 19-digit width. For each collection member, the
        // fixture selects the longest legal enum/optional shape: Bound,
        // Eligible with sources digest, and Reviewed with every receipt digest.
        let (source, proposal) = maximum_proposal()?;
        assert_eq!(proposal.members().len(), 256);
        let source_wire = source_identity_wire(source);
        let registered = maximum_registered_manifest(&proposal)?;
        let registered_wire = registered_manifest_wire(&registered);
        let manifest_sealed = EvaluationEvidenceResponseWire::ManifestSealed {
            source: source_wire.clone(),
            manifest: registered_wire.clone(),
        };
        let manifest_sealed_size = serialized_success_response_size(manifest_sealed)?;
        let manifest_response = EvaluationEvidenceResponseWire::ManifestRead {
            source: source_wire.clone(),
            status: EvaluationRecordReadStatus::Found,
            manifest: Some(registered_wire),
        };
        let manifest_size = serialized_success_response_size(manifest_response)?;

        let t1 = maximum_t1_cut(&proposal)?;
        let t1_closed = EvaluationEvidenceResponseWire::T1Closed {
            source: source_wire.clone(),
            outcome: EvaluationT1ClosureWire::Closed {
                cut: t1_cut_wire(&t1),
            },
        };
        let t1_closed_size = serialized_success_response_size(t1_closed)?;
        let t1_response = EvaluationEvidenceResponseWire::T1Read {
            source: source_wire.clone(),
            status: EvaluationRecordReadStatus::Found,
            cut: Some(t1_cut_wire(&t1)),
        };
        let t1_size = serialized_success_response_size(t1_response)?;

        let review_cut = maximum_review_cut(&proposal, &t1)?;
        let review_cut_wire_value = review_cut_wire(&review_cut);
        let review_created = EvaluationEvidenceResponseWire::ReviewCutCreated {
            source: source_wire.clone(),
            review_cut: review_cut_wire_value.clone(),
        };
        let review_created_size = serialized_success_response_size(review_created)?;
        let review_response = EvaluationEvidenceResponseWire::ReviewCutRead {
            source: source_wire,
            status: EvaluationRecordReadStatus::Found,
            review_cut: Some(review_cut_wire_value),
        };
        let review_size = serialized_success_response_size(review_response)?;
        let unknown_outcome_size = serialized_t1_unknown_outcome_size()?;

        assert_eq!(manifest_sealed_size, 261_876);
        assert_eq!(manifest_size, 261_891);
        assert_eq!(t1_closed_size, 189_099);
        assert_eq!(t1_size, 189_084);
        assert_eq!(review_created_size, 503_264);
        assert_eq!(review_size, 503_278);
        // Error envelopes do not carry member arrays. The full T1 readback
        // identity is their largest evaluation-specific payload.
        assert!(unknown_outcome_size < review_size);
        assert!(review_size <= crate::client::MAX_CLIENT_RESPONSE_BYTES);
        Ok(())
    }

    fn maximum_proposal()
    -> Result<(EvaluationSourceIdentity, EvaluationManifestProposal), Box<dyn std::error::Error>>
    {
        let source = EvaluationSourceIdentity::new(
            ForgeBackendId::from_uuid(Uuid::from_u128(3)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(4)),
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            EvaluationRevision::new(i64::MAX)?,
            EvaluationDigest::new([0x11; 32])?,
        )?;
        let criteria_digest = EvaluationDigest::new([0x33; 32])?;
        let assignment_revision = AgentAssignmentRevision::new(i64::MAX - 2)?;
        let members = (0..forge_domain::MAX_EVALUATION_MANIFEST_MEMBERS)
            .map(|index| -> Result<_, Box<dyn std::error::Error>> {
                let index = u128::try_from(index)?;
                Ok(EvaluationManifestMember::new(
                    EvaluationWorkUnitId::new(Uuid::from_u128(0x1000 + index))?,
                    EvaluationObligationId::new(Uuid::from_u128(0x2000 + index))?,
                    AgentAssignmentId::from_uuid(Uuid::from_u128(0x3000 + index)),
                    assignment_revision,
                    AgentInstanceId::from_uuid(Uuid::from_u128(14)),
                    AgentSessionId::from_uuid(Uuid::from_u128(15)),
                    criteria_digest,
                )?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proposal = EvaluationManifestProposal::new(
            EvaluationManifestId::new(Uuid::from_u128(9))?,
            EvaluationRevision::new(i64::MAX)?,
            source,
            EvaluationPlanBinding::new(
                EvaluationPlanId::new(Uuid::from_u128(10))?,
                EvaluationRevision::new(i64::MAX)?,
                EvaluationDigest::new([0x22; 32])?,
            ),
            TimestampMillis::new(i64::MAX - 1)?,
            members,
        )?;
        Ok((source, proposal))
    }

    fn maximum_registered_manifest(
        proposal: &EvaluationManifestProposal,
    ) -> Result<EvaluationRegisteredManifest, Box<dyn std::error::Error>> {
        let members = proposal
            .members()
            .iter()
            .enumerate()
            .map(
                |(index, declaration)| -> Result<_, Box<dyn std::error::Error>> {
                    let index = i64::try_from(index)?;
                    let binding = EvaluationOriginalAssignmentBinding::new(
                        EvaluationDigest::new([0x55; 32])?,
                        declaration.assignment_revision(),
                        EvaluationSourceSequence::new(i64::MAX - 513 + index)?,
                    );
                    Ok(EvaluationRegisteredManifestMember::new(
                        *declaration,
                        EvaluationOriginalBindingStatus::Bound(binding),
                    ))
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EvaluationRegisteredManifest::from_source_records(
            proposal.clone(),
            members,
            EvaluationSourceSequence::new(i64::MAX - 1)?,
            EvaluationAdmissionTiming::Trusted(TimestampMillis::new(i64::MAX - 1)?),
        )?)
    }

    fn maximum_t1_cut(
        proposal: &EvaluationManifestProposal,
    ) -> Result<EvaluationT1CoverageCut, Box<dyn std::error::Error>> {
        let binding_digest = EvaluationDigest::new([0x55; 32])?;
        let result_digest = EvaluationDigest::new([0x66; 32])?;
        let sources_digest = EvaluationDigest::new([0x77; 32])?;
        let deadline = proposal.deadline();
        let members = proposal
            .members()
            .iter()
            .enumerate()
            .map(|(index, member)| -> Result<_, Box<dyn std::error::Error>> {
                let receipt = maximum_submission_receipt(
                    *member,
                    index,
                    binding_digest,
                    result_digest,
                    sources_digest,
                    deadline,
                )?;
                let coverage = forge_domain::classify_t1_coverage(
                    *member,
                    Some(binding_digest),
                    false,
                    false,
                    Some(receipt),
                    deadline,
                );
                Ok(EvaluationT1CoverageMember::new(*member, coverage))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EvaluationT1CoverageCut::from_source_records(
            EvaluationCutId::new(Uuid::from_u128(11))?,
            proposal,
            deadline,
            TimestampMillis::new(i64::MAX)?,
            EvaluationSourceSequence::new(i64::MAX - 1)?,
            members,
        )?)
    }

    fn maximum_review_cut(
        proposal: &EvaluationManifestProposal,
        t1: &EvaluationT1CoverageCut,
    ) -> Result<EvaluationReviewCut, Box<dyn std::error::Error>> {
        let binding_digest = EvaluationDigest::new([0x55; 32])?;
        let result_digest = EvaluationDigest::new([0x66; 32])?;
        let sources_digest = EvaluationDigest::new([0x77; 32])?;
        let deadline = proposal.deadline();
        let members = t1
            .members()
            .iter()
            .enumerate()
            .map(
                |(index, t1_member)| -> Result<_, Box<dyn std::error::Error>> {
                    let member = t1_member.member();
                    let submission = maximum_submission_receipt(
                        member,
                        index,
                        binding_digest,
                        result_digest,
                        sources_digest,
                        deadline,
                    )?;
                    let index = i64::try_from(index)?;
                    let review = EvaluationReviewReceipt::from_source_record(
                        member.assignment_id(),
                        submission.submitted_revision(),
                        AgentAssignmentRevision::new(i64::MAX)?,
                        EvaluationSourceSequence::new(i64::MAX - 511 + 2 * index)?,
                        EvaluationReviewOutcome::Accepted,
                        member.target_agent_id(),
                        member.target_session_id(),
                        AgentInstanceId::from_uuid(Uuid::from_u128(16)),
                        AgentSessionId::from_uuid(Uuid::from_u128(17)),
                        result_digest,
                    )?;
                    Ok(EvaluationReviewCutMember::new(
                        member,
                        t1_member.coverage(),
                        Some(submission),
                        EvaluationReviewState::Reviewed(review),
                    ))
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EvaluationReviewCut::from_source_records(
            EvaluationReviewCutId::new(Uuid::from_u128(18))?,
            t1,
            EvaluationSourceSequence::new(i64::MAX)?,
            members,
        )?)
    }

    fn maximum_submission_receipt(
        member: EvaluationManifestMember,
        index: usize,
        binding_digest: EvaluationDigest,
        result_digest: EvaluationDigest,
        sources_digest: EvaluationDigest,
        deadline: TimestampMillis,
    ) -> Result<EvaluationSubmissionReceipt, Box<dyn std::error::Error>> {
        let index = i64::try_from(index)?;
        Ok(EvaluationSubmissionReceipt::from_source_record(
            member.assignment_id(),
            AgentAssignmentRevision::new(i64::MAX - 1)?,
            member.target_agent_id(),
            member.target_session_id(),
            Some(binding_digest),
            Some(member.criteria_digest()),
            EvaluationSourceSequence::new(i64::MAX - 512 + 2 * index)?,
            EvaluationAdmissionTiming::Trusted(deadline),
            result_digest,
            Some(sources_digest),
        )?)
    }

    fn serialized_success_response_size(
        response: EvaluationEvidenceResponseWire,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let result = serde_json::to_value(response)?;
        let reply = crate::envelope::Reply::success(Uuid::from_u128(20), result);
        Ok(serde_json::to_vec(&reply)?.len())
    }

    fn serialized_t1_unknown_outcome_size() -> Result<usize, Box<dyn std::error::Error>> {
        let identity = forge_persistence::EvaluationEvidenceMutationIdentity::T1Closure {
            request: EvaluationT1CloseRequest::new(
                EvaluationCutId::new(Uuid::from_u128(21))?,
                EvaluationManifestId::new(Uuid::from_u128(22))?,
                EvaluationRevision::new(i64::MAX)?,
                EvaluationDigest::new([0x55; 32])?,
                TimestampMillis::new(i64::MAX)?,
            ),
        };
        let error = crate::error::ForgeError::unknown_outcome(Some(
            crate::error::ReadbackHint::evaluation_evidence(Uuid::from_u128(2), &identity),
        ));
        let reply = crate::envelope::Reply::failure(Uuid::from_u128(20), &error);
        Ok(serde_json::to_vec(&reply)?.len())
    }
}
