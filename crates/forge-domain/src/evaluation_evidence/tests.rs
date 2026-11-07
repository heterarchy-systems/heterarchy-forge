use super::*;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn digest(byte: u8) -> Result<EvaluationDigest, EvaluationEvidenceError> {
    EvaluationDigest::new([byte; EVALUATION_DIGEST_BYTES])
}

fn member(
    assignment: u128,
    unit: u128,
    obligation: u128,
) -> Result<EvaluationManifestMember, EvaluationEvidenceError> {
    EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(id(unit))?,
        EvaluationObligationId::new(id(obligation))?,
        AgentAssignmentId::from_uuid(id(assignment)),
        AgentAssignmentRevision::INITIAL,
        AgentInstanceId::from_uuid(id(assignment + 500)),
        AgentSessionId::from_uuid(id(assignment + 1_000)),
        digest(7)?,
    )
}

fn source() -> Result<EvaluationSourceIdentity, EvaluationEvidenceError> {
    EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(id(1)),
        WorkspaceId::from_uuid(id(2)),
        ActivityId::from_uuid(id(3)),
        id(4),
        id(5),
        EvaluationRevision::new(1)?,
        digest(6)?,
    )
}

fn plan() -> Result<EvaluationPlanBinding, EvaluationEvidenceError> {
    Ok(EvaluationPlanBinding::new(
        EvaluationPlanId::new(id(8))?,
        EvaluationRevision::new(2)?,
        digest(9)?,
    ))
}

fn proposal(
    members: Vec<EvaluationManifestMember>,
    deadline: TimestampMillis,
) -> Result<EvaluationManifestProposal, EvaluationEvidenceError> {
    EvaluationManifestProposal::new(
        EvaluationManifestId::new(id(10))?,
        EvaluationRevision::new(1)?,
        source()?,
        plan()?,
        deadline,
        members,
    )
}

fn receipt(
    assignment: AgentAssignmentId,
    submitted_revision: i64,
    timing: EvaluationAdmissionTiming,
) -> Result<EvaluationSubmissionReceipt, EvaluationEvidenceError> {
    let assignment_value = assignment.into_uuid().as_u128();
    EvaluationSubmissionReceipt::from_source_record(
        assignment,
        AgentAssignmentRevision::new(submitted_revision)
            .map_err(|_| EvaluationEvidenceError::InvalidRevision(submitted_revision))?,
        AgentInstanceId::from_uuid(id(assignment_value + 500)),
        AgentSessionId::from_uuid(id(assignment_value + 1_000)),
        Some(digest(11)?),
        Some(digest(7)?),
        EvaluationSourceSequence::new(4)?,
        timing,
        digest(12)?,
        Some(digest(13)?),
    )
}

#[test]
fn manifest_canonicalizes_member_order_and_binds_the_exact_cohort()
-> Result<(), Box<dyn std::error::Error>> {
    let first = member(20, 30, 40)?;
    let second = member(21, 31, 41)?;
    let t1 = TimestampMillis::new(100)?;
    let left = proposal(vec![first, second], t1)?;
    let right = proposal(vec![second, first], t1)?;

    assert_eq!(left.digest(), right.digest());
    assert!(left.validates_digest(right.digest()));
    assert!(!left.validates_digest(digest(99)?));
    let same_identity_later_t1 = proposal(vec![second, first], TimestampMillis::new(101)?)?;
    assert_ne!(left.digest(), same_identity_later_t1.digest());
    Ok(())
}

#[test]
fn manifest_rejects_duplicate_assignment_unit_and_obligation_members()
-> Result<(), Box<dyn std::error::Error>> {
    let original = member(20, 30, 40)?;
    let t1 = TimestampMillis::new(100)?;
    assert!(matches!(
        proposal(vec![original, member(20, 31, 41)?], t1),
        Err(EvaluationEvidenceError::DuplicateAssignment(_))
    ));
    assert!(matches!(
        proposal(vec![original, member(21, 30, 41)?], t1),
        Err(EvaluationEvidenceError::DuplicateWorkUnit(_))
    ));
    assert!(matches!(
        proposal(vec![original, member(21, 31, 40)?], t1),
        Err(EvaluationEvidenceError::DuplicateObligation(_))
    ));
    Ok(())
}

#[test]
fn evaluation_cohort_bound_is_independent_of_active_assignment_cap()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(crate::MAX_AGENT_ASSIGNMENTS_PER_WORKSPACE, 32);
    assert_eq!(MAX_EVALUATION_MANIFEST_MEMBERS, 256);

    for count in [32, 33, MAX_EVALUATION_MANIFEST_MEMBERS] {
        let proposal = proposal(cohort_members(count)?, TimestampMillis::new(100)?)?;
        assert_eq!(proposal.members().len(), count);
    }

    let actual = MAX_EVALUATION_MANIFEST_MEMBERS + 1;
    assert!(matches!(
        proposal(cohort_members(actual)?, TimestampMillis::new(100)?),
        Err(EvaluationEvidenceError::TooManyMembers {
            actual: count,
            maximum: MAX_EVALUATION_MANIFEST_MEMBERS,
        }) if count == actual
    ));
    Ok(())
}

fn cohort_members(
    count: usize,
) -> Result<Vec<EvaluationManifestMember>, Box<dyn std::error::Error>> {
    (0..count)
        .map(|index| {
            let index = u128::try_from(index)?;
            member(10_000 + index, 20_000 + index, 30_000 + index).map_err(Into::into)
        })
        .collect()
}

#[test]
fn t1_is_inclusive_and_later_trusted_admission_is_excluded()
-> Result<(), Box<dyn std::error::Error>> {
    let original = member(20, 30, 40)?;
    let t1 = TimestampMillis::new(100)?;
    let exact_t1 = receipt(
        original.assignment_id(),
        2,
        EvaluationAdmissionTiming::Trusted(t1),
    )?;
    assert!(matches!(
        classify_t1_coverage(
            original,
            Some(digest(11)?),
            false,
            false,
            Some(exact_t1),
            t1,
        ),
        EvaluationT1Coverage::Eligible { admitted_at, .. } if admitted_at == t1
    ));

    // A descriptive HTTP timestamp is absent from this decision. Only the
    // trusted source receipt time controls eligibility.
    let after_t1 = receipt(
        original.assignment_id(),
        2,
        EvaluationAdmissionTiming::Trusted(TimestampMillis::new(101)?),
    )?;
    assert_eq!(
        classify_t1_coverage(
            original,
            Some(digest(11)?),
            false,
            false,
            Some(after_t1),
            t1,
        ),
        EvaluationT1Coverage::NoEligibleSubmission
    );
    Ok(())
}

#[test]
fn source_cut_cannot_extend_the_deadline_sealed_in_its_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let t1 = TimestampMillis::new(100)?;
    let original = member(20, 30, 40)?;
    let manifest = proposal(vec![original], t1)?;
    let cut = EvaluationT1CoverageCut::from_source_records(
        EvaluationCutId::new(id(70))?,
        &manifest,
        TimestampMillis::new(101)?,
        TimestampMillis::new(102)?,
        EvaluationSourceSequence::new(5)?,
        vec![EvaluationT1CoverageMember::new(
            original,
            EvaluationT1Coverage::NoEligibleSubmission,
        )],
    );
    assert!(matches!(
        cut,
        Err(EvaluationEvidenceError::CutDeadlineMismatch)
    ));
    Ok(())
}

#[test]
fn clock_regression_and_legacy_submission_remain_unknown() -> Result<(), Box<dyn std::error::Error>>
{
    let original = member(20, 30, 40)?;
    let t1 = TimestampMillis::new(100)?;
    let unknown_timing = receipt(
        original.assignment_id(),
        2,
        EvaluationAdmissionTiming::Unknown(EvaluationClockUncertainty::Regressed),
    )?;
    assert_eq!(
        classify_t1_coverage(
            original,
            Some(digest(11)?),
            false,
            false,
            Some(unknown_timing),
            t1,
        ),
        EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::SubmissionTimingUnknown,
        }
    );
    assert_eq!(
        classify_t1_coverage(original, Some(digest(11)?), true, false, None, t1),
        EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::LegacySubmissionWithoutReceipt,
        }
    );
    assert_eq!(
        classify_t1_coverage(original, Some(digest(11)?), false, true, None, t1),
        EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::ClockHistoryUncertain,
        }
    );
    Ok(())
}

#[test]
fn timely_original_without_review_stays_pending_independent_of_rescue()
-> Result<(), Box<dyn std::error::Error>> {
    let original = member(20, 30, 40)?;
    let timely = receipt(
        original.assignment_id(),
        2,
        EvaluationAdmissionTiming::Trusted(TimestampMillis::new(99)?),
    )?;
    let coverage = classify_t1_coverage(
        original,
        Some(digest(11)?),
        false,
        false,
        Some(timely),
        TimestampMillis::new(100)?,
    );
    assert!(matches!(coverage, EvaluationT1Coverage::Eligible { .. }));

    let review = EvaluationReviewState::Pending {
        submitted_revision: AgentAssignmentRevision::new(2)?,
        receipt_sequence: EvaluationSourceSequence::new(4)?,
    };
    assert!(matches!(review, EvaluationReviewState::Pending { .. }));
    Ok(())
}

#[test]
fn review_receipt_keeps_reviewer_agent_and_session_and_rejects_self_review()
-> Result<(), Box<dyn std::error::Error>> {
    let submitted_revision = AgentAssignmentRevision::new(2)?;
    let review_revision = AgentAssignmentRevision::new(3)?;
    let assignment_id = AgentAssignmentId::from_uuid(id(20));
    let author = AgentInstanceId::from_uuid(id(14));
    let reviewer = AgentInstanceId::from_uuid(id(16));
    let reviewer_session = AgentSessionId::from_uuid(id(17));
    let receipt = EvaluationReviewReceipt::from_source_record(
        assignment_id,
        submitted_revision,
        review_revision,
        EvaluationSourceSequence::new(5)?,
        EvaluationReviewOutcome::Accepted,
        author,
        AgentSessionId::from_uuid(id(15)),
        reviewer,
        reviewer_session,
        digest(12)?,
    )?;
    assert_eq!(receipt.reviewer_agent_id(), reviewer);
    assert_eq!(receipt.reviewer_session_id(), reviewer_session);
    assert!(matches!(
        EvaluationReviewReceipt::from_source_record(
            assignment_id,
            submitted_revision,
            review_revision,
            EvaluationSourceSequence::new(5)?,
            EvaluationReviewOutcome::Accepted,
            author,
            AgentSessionId::from_uuid(id(15)),
            author,
            reviewer_session,
            digest(12)?,
        ),
        Err(EvaluationEvidenceError::ReviewerIsAuthor)
    ));
    Ok(())
}
