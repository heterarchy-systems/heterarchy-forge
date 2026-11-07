use super::super::EvaluationEvidenceStoreError;
use super::super::schema;
use super::{
    ClockState, EvaluatedT1Member, T1CutHeader, clock_state, encode_t1_cut_member, encode_timing,
    ensure_source_state, get_registered_manifest_in_transaction, get_review_cut_in_transaction,
    get_submission_receipt_in_transaction, get_t1_cut_in_transaction, insert_original_binding,
    load_manifest_declarations, load_raw_manifest_members, load_raw_review_cut_members,
    load_raw_t1_cut_members, load_source_assignments, load_submission_receipt,
    next_source_sequence, observe_clock, original_binding_digest,
    persist_manifest_header_and_members, persist_review_cut, persist_t1_cut,
    resolve_original_bindings, seal_manifest_members, validate_assignment_scope,
};

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentAssignmentCoordinator,
    AgentAssignmentId, AgentAssignmentResult, AgentAssignmentRevision, AgentAssignmentState,
    AgentAssignmentTarget, AgentInstanceId, AgentInstanceRevision, AgentSessionId,
    AuthenticatedPrincipal, DagHeadRevision, DagNodeId, DagNodeRevision, DagRevisionNumber,
    EvaluationAdmissionTiming, EvaluationClockReading, EvaluationClockUncertainty,
    EvaluationCoverageUnknownReason, EvaluationCutId, EvaluationDigest, EvaluationManifestId,
    EvaluationManifestMember, EvaluationManifestProposal, EvaluationObligationId,
    EvaluationPlanBinding, EvaluationPlanId, EvaluationReviewCutId, EvaluationReviewCutMember,
    EvaluationReviewState, EvaluationRevision, EvaluationSourceIdentity, EvaluationT1Coverage,
    EvaluationT1CoverageCut, EvaluationT1CoverageMember, EvaluationWorkUnitId, ForgeBackendId,
    GoalId, GoalRevision, MAX_EVALUATION_MANIFEST_MEMBERS, RegisteredAgentAssignment,
    TimestampMillis, WorkCreditBudget, WorkspaceId,
};
use rusqlite::{Connection, Transaction, params};
use std::{error::Error, fs, path::PathBuf};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn source_database() -> Result<(Connection, WorkspaceId), Box<dyn Error>> {
    initialize_source_database(Connection::open_in_memory()?)
}

fn initialize_source_database(
    connection: Connection,
) -> Result<(Connection, WorkspaceId), Box<dyn Error>> {
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.execute_batch(
        "CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY NOT NULL CHECK(length(workspace_id) = 16));",
    )?;
    let workspace_id = WorkspaceId::from_uuid(id(1));
    connection.execute(
        "INSERT INTO workspace(workspace_id) VALUES(?1)",
        params![workspace_id.into_uuid().as_bytes()],
    )?;
    schema::create_schema(&connection)?;
    Ok((connection, workspace_id))
}

struct TemporarySourceDatabase {
    root: PathBuf,
    path: PathBuf,
}

impl TemporarySourceDatabase {
    fn new() -> Result<Self, Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!("forge-evaluation-source-{}", Uuid::now_v7()));
        fs::create_dir(&root)?;
        let path = root.join("workspace.sqlite3");
        Ok(Self { root, path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TemporarySourceDatabase {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn clock_regression_is_sticky_after_a_later_healthy_sample() -> Result<(), Box<dyn Error>> {
    let (connection, workspace_id) = source_database()?;
    ensure_source_state(&connection, workspace_id)?;

    let binding_sequence = next_source_sequence(&connection, workspace_id)?;
    let first = observe_clock(
        &connection,
        workspace_id,
        binding_sequence,
        EvaluationClockReading::Trusted(TimestampMillis::new(100)?),
    )?;
    assert_eq!(
        first,
        EvaluationAdmissionTiming::Trusted(TimestampMillis::new(100)?)
    );

    let regressed_sequence = next_source_sequence(&connection, workspace_id)?;
    let regressed = observe_clock(
        &connection,
        workspace_id,
        regressed_sequence,
        EvaluationClockReading::Trusted(TimestampMillis::new(10)?),
    )?;
    assert_eq!(
        regressed,
        EvaluationAdmissionTiming::Unknown(EvaluationClockUncertainty::Regressed)
    );

    let recovered_sequence = next_source_sequence(&connection, workspace_id)?;
    let recovered = observe_clock(
        &connection,
        workspace_id,
        recovered_sequence,
        EvaluationClockReading::Trusted(TimestampMillis::new(101)?),
    )?;
    assert_eq!(
        recovered,
        EvaluationAdmissionTiming::Trusted(TimestampMillis::new(101)?)
    );
    let state = clock_state(&connection, workspace_id)?;
    assert_eq!(
        state.last_uncertainty_sequence,
        Some(regressed_sequence.get())
    );
    assert!(regressed_sequence.get() > binding_sequence.get());
    Ok(())
}

#[test]
fn source_clock_and_receipt_writes_rollback_together() -> Result<(), Box<dyn Error>> {
    let (mut connection, workspace_id) = source_database()?;
    ensure_source_state(&connection, workspace_id)?;
    let assignment_id = AgentAssignmentId::from_uuid(id(2));
    let author = AgentInstanceId::from_uuid(id(3));
    let author_session = AgentSessionId::from_uuid(id(4));

    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let sequence = next_source_sequence(&transaction, workspace_id)?;
    let timing = observe_clock(
        &transaction,
        workspace_id,
        sequence,
        EvaluationClockReading::Unknown,
    )?;
    let (time_status, admitted_at_ms) = encode_timing(timing);
    transaction.execute(
        "INSERT INTO workspace_evaluation_submission_receipts(workspace_id, assignment_id, submitted_revision, author_agent_id, author_session_id, original_binding_digest, criteria_digest, source_sequence, admission_time_status, admitted_at_ms, result_digest, sources_digest) VALUES(?1, ?2, 2, ?3, ?4, NULL, NULL, ?5, ?6, ?7, ?8, NULL)",
        params![
            workspace_id.into_uuid().as_bytes(),
            assignment_id.into_uuid().as_bytes(),
            author.into_uuid().as_bytes(),
            author_session.into_uuid().as_bytes(),
            sequence.get(),
            time_status,
            admitted_at_ms,
            [5_u8; 32].as_slice(),
        ],
    )?;
    drop(transaction);

    let (source_sequence, clock_health, uncertainty, receipts): (i64, i64, Option<i64>, i64) = connection.query_row(
        "SELECT s.source_sequence, s.clock_health, s.last_uncertainty_sequence, (SELECT COUNT(*) FROM workspace_evaluation_submission_receipts WHERE workspace_id = s.workspace_id) FROM workspace_evaluation_source_state s WHERE s.workspace_id = ?1",
        params![workspace_id.into_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(source_sequence, 0);
    assert_eq!(clock_health, 0);
    assert_eq!(uncertainty, None);
    assert_eq!(receipts, 0);
    Ok(())
}

#[test]
fn source_receipt_readback_uses_the_exact_assignment_revision_key() -> Result<(), Box<dyn Error>> {
    let (connection, workspace_id) = source_database()?;
    let assignment_id = AgentAssignmentId::from_uuid(id(2));
    let author = AgentInstanceId::from_uuid(id(3));
    let author_session = AgentSessionId::from_uuid(id(4));
    connection.execute(
        "INSERT INTO workspace_evaluation_submission_receipts(workspace_id, assignment_id, submitted_revision, author_agent_id, author_session_id, original_binding_digest, criteria_digest, source_sequence, admission_time_status, admitted_at_ms, result_digest, sources_digest) VALUES(?1, ?2, 3, ?3, ?4, NULL, NULL, 7, 0, 100, ?5, NULL)",
        params![
            workspace_id.into_uuid().as_bytes(),
            assignment_id.into_uuid().as_bytes(),
            author.into_uuid().as_bytes(),
            author_session.into_uuid().as_bytes(),
            [5_u8; 32].as_slice(),
        ],
    )?;

    let receipt = load_submission_receipt(
        &connection,
        workspace_id,
        assignment_id,
        AgentAssignmentRevision::new(3)?,
    )?
    .ok_or("source receipt missing from exact key readback")?;
    assert_eq!(receipt.assignment_id(), assignment_id);
    assert_eq!(
        receipt.submitted_revision(),
        AgentAssignmentRevision::new(3)?
    );
    assert_eq!(receipt.source_sequence().get(), 7);
    assert_eq!(
        receipt.timing(),
        EvaluationAdmissionTiming::Trusted(TimestampMillis::new(100)?)
    );
    assert_eq!(receipt.author_agent_id(), AgentInstanceId::from_uuid(id(3)));
    assert!(
        load_submission_receipt(
            &connection,
            workspace_id,
            assignment_id,
            AgentAssignmentRevision::new(4)?,
        )?
        .is_none()
    );
    Ok(())
}

#[test]
fn manifest_target_must_match_the_exact_source_assignment() -> Result<(), Box<dyn Error>> {
    let workspace_id = WorkspaceId::from_uuid(id(100));
    let activity_id = ActivityId::from_uuid(id(101));
    let assignment_id = AgentAssignmentId::from_uuid(id(102));
    let author_id = AgentInstanceId::from_uuid(id(103));
    let author_session = AgentSessionId::from_uuid(id(104));
    let principal = AuthenticatedPrincipal::TrustedStdio;
    let actor = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        AgentInstanceId::from_uuid(id(105)),
        ActivityCoordinatorRevision::INITIAL,
        principal,
        AgentSessionId::from_uuid(id(106)),
    );
    let assignment = RegisteredAgentAssignment::offered(
        assignment_id,
        workspace_id,
        activity_id,
        GoalId::from_uuid(id(107)),
        TimestampMillis::new(1)?,
        GoalRevision::INITIAL,
        DagRevisionNumber::INITIAL,
        DagHeadRevision::INITIAL,
        DagNodeId::from_uuid(id(108)),
        DagNodeRevision::INITIAL,
        AgentAssignmentCoordinator::from_actor(actor),
        AgentAssignmentTarget::new(
            author_id,
            author_session,
            principal,
            AgentInstanceRevision::INITIAL,
        ),
        Some(WorkCreditBudget::Three),
        TimestampMillis::new(2)?,
    )?;
    let source = EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(id(109)),
        workspace_id,
        activity_id,
        id(110),
        id(111),
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([7; 32])?,
    )?;
    let foreign_member = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(id(112))?,
        EvaluationObligationId::new(id(113))?,
        assignment_id,
        assignment.revision(),
        AgentInstanceId::from_uuid(id(114)),
        AgentSessionId::from_uuid(id(115)),
        EvaluationDigest::new([8; 32])?,
    )?;
    assert!(matches!(
        validate_assignment_scope(&assignment, source, &foreign_member),
        Err(EvaluationEvidenceStoreError::SourceScopeMismatch)
    ));
    let exact_member = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(id(112))?,
        EvaluationObligationId::new(id(113))?,
        assignment_id,
        assignment.revision(),
        author_id,
        author_session,
        EvaluationDigest::new([8; 32])?,
    )?;
    assert!(validate_assignment_scope(&assignment, source, &exact_member).is_ok());
    Ok(())
}

#[test]
fn source_readbacks_do_not_advance_clock_or_source_sequence() -> Result<(), Box<dyn Error>> {
    let fixture = readback_fixture()?;
    seed_readback_records(&fixture)?;
    let before = clock_state(&fixture.connection, fixture.workspace_id)?;
    let transaction = fixture.connection.unchecked_transaction()?;
    assert!(
        get_registered_manifest_in_transaction(
            &transaction,
            fixture.backend_id,
            fixture.proposal.manifest_id(),
            EvaluationRevision::new(1)?,
        )?
        .is_some()
    );
    assert!(
        get_submission_receipt_in_transaction(
            &transaction,
            fixture.backend_id,
            fixture.workspace_id,
            fixture.assignment_id,
            AgentAssignmentRevision::new(3)?,
        )?
        .is_some()
    );
    assert!(get_t1_cut_in_transaction(&transaction, fixture.backend_id, fixture.cut_id)?.is_some());
    assert!(
        get_review_cut_in_transaction(&transaction, fixture.backend_id, fixture.review_cut_id)?
            .is_some()
    );
    transaction.commit()?;
    assert_eq!(
        clock_state(&fixture.connection, fixture.workspace_id)?,
        before
    );
    Ok(())
}

#[test]
fn source_readers_reject_257_persisted_manifest_and_cut_members() -> Result<(), Box<dyn Error>> {
    let fixture = readback_fixture()?;
    seed_readback_records(&fixture)?;
    insert_oversized_member_groups(&fixture)?;

    assert!(matches!(
        load_manifest_declarations(
            &fixture.connection,
            fixture.workspace_id,
            fixture.proposal.manifest_id(),
            fixture.proposal.revision(),
        ),
        Err(EvaluationEvidenceStoreError::CorruptRecord(
            "evaluation.member_count"
        ))
    ));
    assert!(matches!(
        load_raw_manifest_members(&fixture.connection, &fixture.proposal),
        Err(EvaluationEvidenceStoreError::CorruptRecord(
            "evaluation.member_count"
        ))
    ));
    assert!(matches!(
        load_raw_t1_cut_members(&fixture.connection, fixture.workspace_id, fixture.cut_id),
        Err(EvaluationEvidenceStoreError::CorruptRecord(
            "evaluation.member_count"
        ))
    ));
    assert!(matches!(
        load_raw_review_cut_members(
            &fixture.connection,
            fixture.workspace_id,
            fixture.review_cut_id,
        ),
        Err(EvaluationEvidenceStoreError::CorruptRecord(
            "evaluation.member_count"
        ))
    ));
    Ok(())
}

fn insert_oversized_member_groups(fixture: &ReadbackFixture) -> Result<(), Box<dyn Error>> {
    for offset in 0..MAX_EVALUATION_MANIFEST_MEMBERS {
        let suffix = u128::try_from(offset)?;
        let assignment_id = id(1_000 + suffix);
        insert_oversized_manifest_member(fixture, assignment_id, suffix)?;
        insert_oversized_t1_member(fixture, assignment_id)?;
        insert_oversized_review_member(fixture, assignment_id)?;
    }
    Ok(())
}

fn insert_oversized_manifest_member(
    fixture: &ReadbackFixture,
    assignment_id: Uuid,
    suffix: u128,
) -> Result<(), Box<dyn Error>> {
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_manifest_members(workspace_id, manifest_id, manifest_revision, assignment_id, work_unit_id, obligation_id, assignment_revision, target_agent_id, target_session_id, criteria_digest, binding_status, binding_assignment_id, binding_digest, binding_sequence) VALUES(?1, ?2, 1, ?3, ?4, ?5, 1, ?6, ?7, ?8, 1, NULL, NULL, NULL)",
        params![
            fixture.workspace_id.into_uuid().as_bytes(),
            fixture.proposal.manifest_id().into_uuid().as_bytes(),
            assignment_id.as_bytes(),
            id(2_000 + suffix).as_bytes(),
            id(3_000 + suffix).as_bytes(),
            id(207).as_bytes(),
            id(208).as_bytes(),
            [8_u8; 32].as_slice(),
        ],
    )?;
    Ok(())
}

fn insert_oversized_t1_member(
    fixture: &ReadbackFixture,
    assignment_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_t1_cut_members(workspace_id, cut_id, assignment_id, coverage_status, submitted_revision, receipt_sequence, unknown_reason) VALUES(?1, ?2, ?3, 2, NULL, NULL, 3)",
        params![
            fixture.workspace_id.into_uuid().as_bytes(),
            fixture.cut_id.into_uuid().as_bytes(),
            assignment_id.as_bytes(),
        ],
    )?;
    Ok(())
}

fn insert_oversized_review_member(
    fixture: &ReadbackFixture,
    assignment_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_review_cut_members(workspace_id, review_cut_id, assignment_id, coverage_status, submitted_revision, review_status, review_revision, review_sequence, reviewer_agent_id, reviewer_session_id, result_digest, review_unknown_reason) VALUES(?1, ?2, ?3, 2, NULL, 4, NULL, NULL, NULL, NULL, NULL, 3)",
        params![
            fixture.workspace_id.into_uuid().as_bytes(),
            fixture.review_cut_id.into_uuid().as_bytes(),
            assignment_id.as_bytes(),
        ],
    )?;
    Ok(())
}

#[test]
fn max_member_historical_manifest_and_unknown_cuts_survive_reopen() -> Result<(), Box<dyn Error>> {
    let temporary = TemporarySourceDatabase::new()?;
    let (mut connection, workspace_id) =
        initialize_source_database(Connection::open(temporary.path())?)?;
    let fixture = historical_cohort_fixture(workspace_id)?;
    persist_historical_cohort(&mut connection, workspace_id, &fixture)?;
    drop(connection);

    let reopened = Connection::open(temporary.path())?;
    reopened.pragma_update(None, "foreign_keys", true)?;
    let transaction = reopened.unchecked_transaction()?;
    let manifest = get_registered_manifest_in_transaction(
        &transaction,
        fixture.backend_id,
        fixture.proposal.manifest_id(),
        fixture.proposal.revision(),
    )?
    .ok_or("256-member historical manifest missing after reopen")?;
    let t1_cut = get_t1_cut_in_transaction(&transaction, fixture.backend_id, fixture.cut_id)?
        .ok_or("256-member T1 cut missing after reopen")?;
    let review_cut =
        get_review_cut_in_transaction(&transaction, fixture.backend_id, fixture.review_cut_id)?
            .ok_or("256-member review cut missing after reopen")?;
    transaction.commit()?;

    assert_eq!(manifest.proposal(), &fixture.proposal);
    assert_eq!(manifest.members().len(), MAX_EVALUATION_MANIFEST_MEMBERS);
    assert!(manifest.members().iter().all(|member| matches!(
        member.binding(),
        forge_domain::EvaluationOriginalBindingStatus::Bound(_)
    )));
    assert_eq!(t1_cut.members().len(), MAX_EVALUATION_MANIFEST_MEMBERS);
    assert!(t1_cut.members().iter().all(|member| matches!(
        member.coverage(),
        EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::ClockHistoryUncertain
        }
    )));
    assert_eq!(review_cut.members().len(), MAX_EVALUATION_MANIFEST_MEMBERS);
    assert!(review_cut.members().iter().all(|member| matches!(
        member.review(),
        EvaluationReviewState::Unknown(EvaluationCoverageUnknownReason::ClockHistoryUncertain)
    )));
    Ok(())
}

struct HistoricalCohortFixture {
    backend_id: ForgeBackendId,
    source: EvaluationSourceIdentity,
    offered: Vec<RegisteredAgentAssignment>,
    proposal: EvaluationManifestProposal,
    cut_id: EvaluationCutId,
    review_cut_id: EvaluationReviewCutId,
}

fn historical_cohort_fixture(
    workspace_id: WorkspaceId,
) -> Result<HistoricalCohortFixture, Box<dyn Error>> {
    let backend_id = ForgeBackendId::from_uuid(id(401));
    let activity_id = ActivityId::from_uuid(id(402));
    let source = EvaluationSourceIdentity::new(
        backend_id,
        workspace_id,
        activity_id,
        id(403),
        id(404),
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([4; 32])?,
    )?;
    let plan = EvaluationPlanBinding::new(
        EvaluationPlanId::new(id(405))?,
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([5; 32])?,
    );
    let (offered, declarations) = historical_offers(workspace_id, activity_id)?;
    let proposal = EvaluationManifestProposal::new(
        EvaluationManifestId::new(id(406))?,
        EvaluationRevision::new(1)?,
        source,
        plan,
        TimestampMillis::new(300)?,
        declarations,
    )?;
    Ok(HistoricalCohortFixture {
        backend_id,
        source,
        offered,
        proposal,
        cut_id: EvaluationCutId::new(id(407))?,
        review_cut_id: EvaluationReviewCutId::new(id(408))?,
    })
}

fn historical_offers(
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<
    (
        Vec<RegisteredAgentAssignment>,
        Vec<EvaluationManifestMember>,
    ),
    Box<dyn Error>,
> {
    let coordinator = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        AgentInstanceId::from_uuid(id(409)),
        ActivityCoordinatorRevision::INITIAL,
        AuthenticatedPrincipal::TrustedStdio,
        AgentSessionId::from_uuid(id(410)),
    );
    let target = AgentAssignmentTarget::new(
        AgentInstanceId::from_uuid(id(411)),
        AgentSessionId::from_uuid(id(412)),
        AuthenticatedPrincipal::TrustedStdio,
        AgentInstanceRevision::INITIAL,
    );
    let mut offers = Vec::with_capacity(MAX_EVALUATION_MANIFEST_MEMBERS);
    let mut declarations = Vec::with_capacity(MAX_EVALUATION_MANIFEST_MEMBERS);
    for offset in 0..MAX_EVALUATION_MANIFEST_MEMBERS {
        let suffix = u128::try_from(offset)?;
        let assignment_id = AgentAssignmentId::from_uuid(id(10_000 + suffix));
        let offered = RegisteredAgentAssignment::offered(
            assignment_id,
            workspace_id,
            activity_id,
            GoalId::from_uuid(id(413)),
            TimestampMillis::new(1)?,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            DagNodeId::from_uuid(id(414)),
            DagNodeRevision::INITIAL,
            AgentAssignmentCoordinator::from_actor(coordinator),
            target,
            Some(WorkCreditBudget::Three),
            TimestampMillis::new(2)?,
        )?;
        declarations.push(EvaluationManifestMember::new(
            EvaluationWorkUnitId::new(id(20_000 + suffix))?,
            EvaluationObligationId::new(id(30_000 + suffix))?,
            assignment_id,
            offered.revision(),
            target.agent_id(),
            target.session_id(),
            EvaluationDigest::new([6; 32])?,
        )?);
        offers.push(offered);
    }
    Ok((offers, declarations))
}

fn persist_historical_cohort(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    fixture: &HistoricalCohortFixture,
) -> Result<(), Box<dyn Error>> {
    ensure_source_state(connection, workspace_id)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let accepted = bind_then_finish_originals(&transaction, workspace_id, fixture)?;
    persist_historical_manifest(&transaction, fixture, &accepted)?;
    persist_unknown_cuts(&transaction, workspace_id, fixture)?;
    transaction.commit()?;
    Ok(())
}

fn bind_then_finish_originals(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    fixture: &HistoricalCohortFixture,
) -> Result<Vec<RegisteredAgentAssignment>, Box<dyn Error>> {
    let mut accepted = Vec::with_capacity(fixture.offered.len());
    let baseline_sequence = next_source_sequence(transaction, workspace_id)?;
    assert_eq!(
        observe_clock(
            transaction,
            workspace_id,
            baseline_sequence,
            EvaluationClockReading::Trusted(TimestampMillis::new(100)?),
        )?,
        EvaluationAdmissionTiming::Trusted(TimestampMillis::new(100)?)
    );
    for (member, offered) in fixture.proposal.members().iter().zip(&fixture.offered) {
        let sequence = next_source_sequence(transaction, workspace_id)?;
        let digest = original_binding_digest(fixture.source, member, offered)?;
        insert_original_binding(
            transaction,
            fixture.source,
            member,
            offered,
            digest,
            sequence,
        )?;
        accepted.push(accepted_assignment(
            offered,
            offered.target(),
            workspace_id,
            fixture.source.activity_id(),
        )?);
    }
    let uncertain_sequence = next_source_sequence(transaction, workspace_id)?;
    observe_clock(
        transaction,
        workspace_id,
        uncertain_sequence,
        EvaluationClockReading::Unknown,
    )?;
    Ok(accepted)
}

fn persist_historical_manifest(
    transaction: &Transaction<'_>,
    fixture: &HistoricalCohortFixture,
    assignments: &[RegisteredAgentAssignment],
) -> Result<(), Box<dyn Error>> {
    let (bindings, needs_new_binding) =
        resolve_original_bindings(transaction, &fixture.proposal, assignments)?;
    assert!(!needs_new_binding);
    let members =
        seal_manifest_members(transaction, &fixture.proposal, assignments, bindings, None)?;
    let _sealed = persist_manifest_header_and_members(
        transaction,
        &fixture.proposal,
        &members,
        EvaluationClockReading::Trusted(TimestampMillis::new(200)?),
    )?;
    assert!(members.iter().all(|member| matches!(
        member.binding(),
        forge_domain::EvaluationOriginalBindingStatus::Bound(_)
    )));
    Ok(())
}

fn persist_unknown_cuts(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    fixture: &HistoricalCohortFixture,
) -> Result<(), Box<dyn Error>> {
    let t1_high_water = next_source_sequence(transaction, workspace_id)?;
    let t1_members = fixture
        .proposal
        .members()
        .iter()
        .map(|member| {
            EvaluationT1CoverageMember::new(
                *member,
                EvaluationT1Coverage::Unknown {
                    reason: EvaluationCoverageUnknownReason::ClockHistoryUncertain,
                },
            )
        })
        .collect::<Vec<_>>();
    let deadline = fixture.proposal.deadline();
    let closed_at = TimestampMillis::new(deadline.get() + 1)?;
    assert_eq!(
        observe_clock(
            transaction,
            workspace_id,
            t1_high_water,
            EvaluationClockReading::Trusted(closed_at),
        )?,
        EvaluationAdmissionTiming::Trusted(closed_at)
    );
    let t1_cut = EvaluationT1CoverageCut::from_source_records(
        fixture.cut_id,
        &fixture.proposal,
        deadline,
        closed_at,
        t1_high_water,
        t1_members.clone(),
    )?;
    persist_historical_t1_cut(transaction, fixture, &t1_cut)?;
    persist_historical_review_cut(transaction, workspace_id, fixture, &t1_cut)?;
    Ok(())
}

fn persist_historical_t1_cut(
    transaction: &Transaction<'_>,
    fixture: &HistoricalCohortFixture,
    cut: &EvaluationT1CoverageCut,
) -> Result<(), Box<dyn Error>> {
    let evaluated = cut
        .members()
        .iter()
        .map(|member| EvaluatedT1Member {
            member: *member,
            insert: encode_t1_cut_member(member.member().assignment_id(), member.coverage()),
        })
        .collect::<Vec<_>>();
    persist_t1_cut(
        transaction,
        &T1CutHeader {
            workspace_id: fixture.proposal.source().workspace_id(),
            cut_id: cut.cut_id(),
            manifest_id: cut.manifest_id(),
            manifest_revision: cut.manifest_revision(),
            manifest_digest: cut.manifest_digest(),
            deadline: cut.deadline(),
            closed_at: cut.closed_at(),
            source_high_water: cut.source_high_water(),
        },
        &evaluated,
    )?;
    Ok(())
}

fn persist_historical_review_cut(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    fixture: &HistoricalCohortFixture,
    t1_cut: &EvaluationT1CoverageCut,
) -> Result<(), Box<dyn Error>> {
    let high_water = next_source_sequence(transaction, workspace_id)?;
    let cut_timing = observe_clock(
        transaction,
        workspace_id,
        high_water,
        EvaluationClockReading::Trusted(TimestampMillis::new(302)?),
    )?;
    let members = t1_cut
        .members()
        .iter()
        .map(|member| {
            EvaluationReviewCutMember::new(
                member.member(),
                member.coverage(),
                None,
                EvaluationReviewState::Unknown(
                    EvaluationCoverageUnknownReason::ClockHistoryUncertain,
                ),
            )
        })
        .collect::<Vec<_>>();
    let cut = forge_domain::EvaluationReviewCut::from_source_records(
        fixture.review_cut_id,
        t1_cut,
        high_water,
        members.clone(),
    )?;
    persist_review_cut(
        transaction,
        workspace_id,
        cut.review_cut_id(),
        cut.t1_cut_id(),
        cut.source_high_water(),
        cut_timing,
        &members,
    )?;
    Ok(())
}

struct ReadbackFixture {
    connection: Connection,
    workspace_id: WorkspaceId,
    backend_id: ForgeBackendId,
    assignment_id: AgentAssignmentId,
    cut_id: EvaluationCutId,
    review_cut_id: EvaluationReviewCutId,
    proposal: EvaluationManifestProposal,
}

fn readback_fixture() -> Result<ReadbackFixture, Box<dyn Error>> {
    let (connection, workspace_id) = source_database()?;
    let backend_id = ForgeBackendId::from_uuid(id(200));
    let activity_id = ActivityId::from_uuid(id(201));
    let assignment_id = AgentAssignmentId::from_uuid(id(206));
    let target_agent = AgentInstanceId::from_uuid(id(207));
    let target_session = AgentSessionId::from_uuid(id(208));
    let source = EvaluationSourceIdentity::new(
        backend_id,
        workspace_id,
        activity_id,
        id(204),
        id(205),
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([5; 32])?,
    )?;
    let member = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(id(209))?,
        EvaluationObligationId::new(id(210))?,
        assignment_id,
        AgentAssignmentRevision::new(1)?,
        target_agent,
        target_session,
        EvaluationDigest::new([6; 32])?,
    )?;
    let plan = EvaluationPlanBinding::new(
        EvaluationPlanId::new(id(203))?,
        EvaluationRevision::new(4)?,
        EvaluationDigest::new([4; 32])?,
    );
    let proposal = EvaluationManifestProposal::new(
        EvaluationManifestId::new(id(202))?,
        EvaluationRevision::new(1)?,
        source,
        plan,
        TimestampMillis::new(100)?,
        vec![member],
    )?;
    Ok(ReadbackFixture {
        connection,
        workspace_id,
        backend_id,
        assignment_id,
        cut_id: EvaluationCutId::new(id(211))?,
        review_cut_id: EvaluationReviewCutId::new(id(212))?,
        proposal,
    })
}

fn seed_readback_records(fixture: &ReadbackFixture) -> Result<(), Box<dyn Error>> {
    let source = fixture.proposal.source();
    let plan = fixture.proposal.plan();
    let member = fixture.proposal.members()[0];
    let workspace_id = fixture.workspace_id;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_source_state(workspace_id, source_sequence, clock_health, last_trusted_at_ms, last_uncertainty_sequence) VALUES(?1, 7, 1, 200, NULL)",
        params![workspace_id.into_uuid().as_bytes()],
    )?;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_manifests(workspace_id, manifest_id, manifest_revision, backend_id, activity_id, delegation_migration_id, delegation_destination_id, delegation_freeze_revision, delegation_manifest_digest, plan_id, plan_revision, plan_digest, deadline_ms, manifest_digest, sealed_sequence, seal_time_status, sealed_at_ms) VALUES(?1, ?2, 1, ?3, ?4, ?5, ?6, 1, ?7, ?8, 4, ?9, 100, ?10, 1, 0, 10)",
        params![
            workspace_id.into_uuid().as_bytes(),
            fixture.proposal.manifest_id().into_uuid().as_bytes(),
            fixture.backend_id.into_uuid().as_bytes(),
            source.activity_id().into_uuid().as_bytes(),
            source.delegation_migration_id().as_bytes(),
            source.delegation_destination_id().as_bytes(),
            source.delegation_manifest_digest().as_bytes(),
            plan.plan_id().into_uuid().as_bytes(),
            plan.digest().as_bytes(),
            fixture.proposal.digest().as_bytes(),
        ],
    )?;
    seed_unknown_member_and_receipt(fixture, member)?;
    seed_readback_cuts(fixture)?;
    Ok(())
}

fn seed_unknown_member_and_receipt(
    fixture: &ReadbackFixture,
    member: EvaluationManifestMember,
) -> Result<(), Box<dyn Error>> {
    let workspace_id = fixture.workspace_id;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_manifest_members(workspace_id, manifest_id, manifest_revision, assignment_id, work_unit_id, obligation_id, assignment_revision, target_agent_id, target_session_id, criteria_digest, binding_status, binding_assignment_id, binding_digest, binding_sequence) VALUES(?1, ?2, 1, ?3, ?4, ?5, 1, ?6, ?7, ?8, 1, NULL, NULL, NULL)",
        params![
            workspace_id.into_uuid().as_bytes(),
            fixture.proposal.manifest_id().into_uuid().as_bytes(),
            fixture.assignment_id.into_uuid().as_bytes(),
            member.work_unit_id().into_uuid().as_bytes(),
            member.obligation_id().into_uuid().as_bytes(),
            member.target_agent_id().into_uuid().as_bytes(),
            member.target_session_id().into_uuid().as_bytes(),
            member.criteria_digest().as_bytes(),
        ],
    )?;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_submission_receipts(workspace_id, assignment_id, submitted_revision, author_agent_id, author_session_id, original_binding_digest, criteria_digest, source_sequence, admission_time_status, admitted_at_ms, result_digest, sources_digest) VALUES(?1, ?2, 3, ?3, ?4, NULL, NULL, 4, 0, 90, ?5, NULL)",
        params![
            workspace_id.into_uuid().as_bytes(),
            fixture.assignment_id.into_uuid().as_bytes(),
            member.target_agent_id().into_uuid().as_bytes(),
            member.target_session_id().into_uuid().as_bytes(),
            [7_u8; 32].as_slice(),
        ],
    )?;
    Ok(())
}

fn seed_readback_cuts(fixture: &ReadbackFixture) -> Result<(), Box<dyn Error>> {
    let workspace_id = fixture.workspace_id;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_t1_cuts(workspace_id, cut_id, manifest_id, manifest_revision, manifest_digest, deadline_ms, closed_at_ms, source_high_water) VALUES(?1, ?2, ?3, 1, ?4, 100, 101, 6)",
        params![
            workspace_id.into_uuid().as_bytes(),
            fixture.cut_id.into_uuid().as_bytes(),
            fixture.proposal.manifest_id().into_uuid().as_bytes(),
            fixture.proposal.digest().as_bytes(),
        ],
    )?;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_t1_cut_members(workspace_id, cut_id, assignment_id, coverage_status, submitted_revision, receipt_sequence, unknown_reason) VALUES(?1, ?2, ?3, 2, NULL, NULL, 3)",
        params![
            workspace_id.into_uuid().as_bytes(),
            fixture.cut_id.into_uuid().as_bytes(),
            fixture.assignment_id.into_uuid().as_bytes(),
        ],
    )?;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_review_cuts(workspace_id, review_cut_id, t1_cut_id, source_high_water, cut_time_status, cut_at_ms) VALUES(?1, ?2, ?3, 7, 0, 102)",
        params![
            workspace_id.into_uuid().as_bytes(),
            fixture.review_cut_id.into_uuid().as_bytes(),
            fixture.cut_id.into_uuid().as_bytes(),
        ],
    )?;
    fixture.connection.execute(
        "INSERT INTO workspace_evaluation_review_cut_members(workspace_id, review_cut_id, assignment_id, coverage_status, submitted_revision, review_status, review_revision, review_sequence, reviewer_agent_id, reviewer_session_id, result_digest, review_unknown_reason) VALUES(?1, ?2, ?3, 2, 3, 1, NULL, NULL, NULL, NULL, NULL, NULL)",
        params![
            workspace_id.into_uuid().as_bytes(),
            fixture.review_cut_id.into_uuid().as_bytes(),
            fixture.assignment_id.into_uuid().as_bytes(),
        ],
    )?;
    Ok(())
}

struct AcceptedOriginalFixture {
    connection: Connection,
    workspace_id: WorkspaceId,
    source: EvaluationSourceIdentity,
    offered: RegisteredAgentAssignment,
    accepted: RegisteredAgentAssignment,
    member: EvaluationManifestMember,
    proposal: EvaluationManifestProposal,
    binding_digest: EvaluationDigest,
}

#[test]
fn accepted_original_binding_requires_same_obligation_and_reuses_cumulative_manifest()
-> Result<(), Box<dyn Error>> {
    let mut fixture = accepted_original_fixture()?;
    seed_original_binding(&mut fixture)?;
    let before = clock_state(&fixture.connection, fixture.workspace_id)?;
    rejects_changed_obligation_without_source_mutation(&mut fixture, before)?;
    reuses_original_obligation_in_cumulative_manifest(&mut fixture, before)?;
    Ok(())
}

fn accepted_original_fixture() -> Result<AcceptedOriginalFixture, Box<dyn Error>> {
    let (connection, workspace_id) = source_database()?;
    let activity_id = ActivityId::from_uuid(id(301));
    let author = AgentInstanceId::from_uuid(id(302));
    let author_session = AgentSessionId::from_uuid(id(303));
    let principal = AuthenticatedPrincipal::TrustedStdio;
    let coordinator = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        AgentInstanceId::from_uuid(id(306)),
        ActivityCoordinatorRevision::INITIAL,
        principal,
        AgentSessionId::from_uuid(id(307)),
    );
    let assignment_id = AgentAssignmentId::from_uuid(id(308));
    let target = AgentAssignmentTarget::new(
        author,
        author_session,
        principal,
        AgentInstanceRevision::INITIAL,
    );
    let offered = RegisteredAgentAssignment::offered(
        assignment_id,
        workspace_id,
        activity_id,
        GoalId::from_uuid(id(309)),
        TimestampMillis::new(1)?,
        GoalRevision::INITIAL,
        DagRevisionNumber::INITIAL,
        DagHeadRevision::INITIAL,
        DagNodeId::from_uuid(id(310)),
        DagNodeRevision::INITIAL,
        AgentAssignmentCoordinator::from_actor(coordinator),
        target,
        Some(WorkCreditBudget::Three),
        TimestampMillis::new(2)?,
    )?;
    let accepted = accepted_assignment(&offered, target, workspace_id, activity_id)?;
    let source = EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(id(311)),
        workspace_id,
        activity_id,
        id(312),
        id(313),
        EvaluationRevision::new(1)?,
        EvaluationDigest::new([7; 32])?,
    )?;
    let member = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(id(314))?,
        EvaluationObligationId::new(id(315))?,
        assignment_id,
        offered.revision(),
        author,
        author_session,
        EvaluationDigest::new([8; 32])?,
    )?;
    let proposal = manifest_proposal(source, member, 316, 317, 2, 9)?;
    let binding_digest = original_binding_digest(source, &member, &offered)?;
    Ok(AcceptedOriginalFixture {
        connection,
        workspace_id,
        source,
        offered,
        accepted,
        member,
        proposal,
        binding_digest,
    })
}

fn accepted_assignment(
    offered: &RegisteredAgentAssignment,
    target: AgentAssignmentTarget,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<RegisteredAgentAssignment, Box<dyn Error>> {
    let running = offered.claim(target, offered.revision(), TimestampMillis::new(3)?)?;
    let submitted = running.submit(
        target,
        running.revision(),
        AgentAssignmentResult::new("original result".to_owned(), Vec::new(), None)?,
        TimestampMillis::new(4)?,
    )?;
    let reviewer = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        AgentInstanceId::from_uuid(id(304)),
        ActivityCoordinatorRevision::INITIAL,
        AuthenticatedPrincipal::TrustedStdio,
        AgentSessionId::from_uuid(id(305)),
    );
    Ok(submitted.accept(reviewer, submitted.revision(), TimestampMillis::new(5)?)?)
}

fn manifest_proposal(
    source: EvaluationSourceIdentity,
    member: EvaluationManifestMember,
    manifest_id: u128,
    plan_id: u128,
    plan_revision: i64,
    digest_byte: u8,
) -> Result<EvaluationManifestProposal, Box<dyn Error>> {
    Ok(EvaluationManifestProposal::new(
        EvaluationManifestId::new(id(manifest_id))?,
        EvaluationRevision::new(1)?,
        source,
        EvaluationPlanBinding::new(
            EvaluationPlanId::new(id(plan_id))?,
            EvaluationRevision::new(plan_revision)?,
            EvaluationDigest::new([digest_byte; 32])?,
        ),
        TimestampMillis::new(100)?,
        vec![member],
    )?)
}

fn seed_original_binding(fixture: &mut AcceptedOriginalFixture) -> Result<(), Box<dyn Error>> {
    let transaction = fixture
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let sequence = next_source_sequence(&transaction, fixture.workspace_id)?;
    insert_original_binding(
        &transaction,
        fixture.source,
        &fixture.member,
        &fixture.offered,
        fixture.binding_digest,
        sequence,
    )?;
    transaction.commit()?;
    Ok(())
}

fn load_cumulative_assignment(
    transaction: &Transaction<'_>,
    proposal: &EvaluationManifestProposal,
    assignment: &RegisteredAgentAssignment,
) -> Result<Vec<RegisteredAgentAssignment>, EvaluationEvidenceStoreError> {
    load_source_assignments(transaction, proposal, &mut |_transaction,
                                                         requested_id|
     -> Result<
        _,
        std::convert::Infallible,
    > {
        if requested_id == assignment.id() {
            Ok(Some(assignment.clone()))
        } else {
            Ok(None)
        }
    })
}

fn rejects_changed_obligation_without_source_mutation(
    fixture: &mut AcceptedOriginalFixture,
    before: ClockState,
) -> Result<(), Box<dyn Error>> {
    let changed_member = EvaluationManifestMember::new(
        fixture.member.work_unit_id(),
        EvaluationObligationId::new(id(318))?,
        fixture.member.assignment_id(),
        fixture.member.assignment_revision(),
        fixture.member.target_agent_id(),
        fixture.member.target_session_id(),
        fixture.member.criteria_digest(),
    )?;
    let changed_proposal = manifest_proposal(fixture.source, changed_member, 319, 320, 3, 10)?;
    let transaction = fixture
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let assignments =
        load_cumulative_assignment(&transaction, &changed_proposal, &fixture.accepted)?;
    assert!(matches!(
        resolve_original_bindings(&transaction, &changed_proposal, &assignments),
        Err(EvaluationEvidenceStoreError::OriginalBindingConflict)
    ));
    assert_eq!(clock_state(&transaction, fixture.workspace_id)?, before);
    transaction.commit()?;
    assert_eq!(
        clock_state(&fixture.connection, fixture.workspace_id)?,
        before
    );
    Ok(())
}

fn reuses_original_obligation_in_cumulative_manifest(
    fixture: &mut AcceptedOriginalFixture,
    before: ClockState,
) -> Result<(), Box<dyn Error>> {
    let transaction = fixture
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let assignments =
        load_cumulative_assignment(&transaction, &fixture.proposal, &fixture.accepted)?;
    assert_eq!(assignments[0].state(), AgentAssignmentState::Accepted);
    assert!(assignments[0].revision().get() > fixture.member.assignment_revision().get());
    let (bindings, needs_new_binding) =
        resolve_original_bindings(&transaction, &fixture.proposal, &assignments)?;
    assert!(!needs_new_binding);
    assert_eq!(
        bindings[0].as_ref().map(|binding| binding.binding_digest),
        Some(fixture.binding_digest)
    );
    assert_eq!(clock_state(&transaction, fixture.workspace_id)?, before);
    transaction.commit()?;
    Ok(())
}
