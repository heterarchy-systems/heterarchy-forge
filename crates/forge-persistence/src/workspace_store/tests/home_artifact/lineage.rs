//! Applied Home successors retain their original assignment root for artifact capture.

use super::*;
use forge_domain::{
    AgentAssignmentHomeHandoffAcceptance, AgentAssignmentHomeHandoffOrigin,
    AgentAssignmentHomeHandoffTransition, AgentAssignmentTarget, HomeArtifactCaptureIntent,
    HomeHandoffAcceptanceGrant, HomeHandoffAcceptanceReceiptDigest,
    HomeHandoffRecipientParticipation, HomeHandoffTakeRequest, HomeHandoffWorkAuthority,
    HomeTransferSourceAction, HomeTransferSourceGrant,
};
use rusqlite::{TransactionBehavior, params};
use uuid::Uuid;

type SuccessorFixture = (Fixture, forge_domain::RegisteredAgentAssignment, Uuid);

fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn proposal_clock(value: i64) -> Result<TimestampMillis, crate::HomeHandoffProposalStoreError> {
    TimestampMillis::new(value).map_err(|_| crate::HomeHandoffProposalStoreError::Clock)
}

/// Seed a valid Applied receipt and exact assignment transition through the
/// persistence owner seams. This is test setup only: it does not exercise or
/// assert a production Home Source Apply operation.
fn home_successor_fixture(label: &str, seed: u128) -> TestResult<SuccessorFixture> {
    let mut fixture = home_artifact_fixture(label, seed, AssignmentSetup::Offered)?;
    let acceptance_id = uuid(seed + 70);
    let handoff_id = uuid(seed + 71);
    let successor_id = AgentAssignmentId::from_uuid(uuid(seed + 72));
    let recipient_session = fixture
        .unaffected_agent
        .session_id()
        .ok_or("Home successor recipient Session is missing")?;
    let recipient = AgentAssignmentTarget::new(
        fixture.unaffected_agent.id(),
        recipient_session,
        fixture.unaffected_agent.principal(),
        fixture.unaffected_agent.revision(),
    );
    let proposal_request = forge_domain::HomeHandoffProposalRequest::new(
        uuid(seed + 73),
        handoff_id,
        fixture.source.request().witness().preparation_id(),
        fixture.assignment.id(),
        fixture.assignment.revision(),
        successor_id,
        fixture.actor,
        recipient,
        None,
        None,
    )?;
    let proposal = fixture
        .store
        .propose_home_assignment_handoff(&proposal_request, || proposal_clock(60))?
        .record();
    let take_request = HomeHandoffTakeRequest::new(
        acceptance_id,
        proposal.request().handoff_id(),
        proposal.request().proposal_id(),
        proposal.case_revision(),
        proposal.request().request_digest(),
        fixture.source.request().scope(),
        recipient,
    )?;
    let source_at = timestamp(70)?;
    let origin = AgentAssignmentHomeHandoffOrigin::new(
        fixture.source.request().witness().preparation_id(),
        handoff_id,
        fixture.assignment.id(),
        fixture.assignment.id(),
    )?;
    let transition = AgentAssignmentHomeHandoffTransition::new(
        &fixture.assignment,
        fixture.assignment.revision(),
        AgentAssignmentHomeHandoffAcceptance::new(
            origin,
            successor_id,
            recipient,
            fixture.actor,
            fixture.assignment.node_revision(),
            source_at,
        ),
    )?;
    let issuer = fixture.source.issuer();
    let grant = HomeHandoffAcceptanceGrant::new(
        issuer,
        take_request.request_digest(),
        acceptance_id,
        HomeHandoffAcceptanceReceiptDigest::from_bytes([0x74; 32])?,
        uuid(seed + 74),
        uuid(seed + 75),
        HomeHandoffRecipientParticipation::new(uuid(seed + 76), 1)?,
        HomeHandoffWorkAuthority::WorkspaceWork {
            affinity_admission_reference_digest:
                forge_domain::HomeHandoffAffinityAdmissionReferenceDigest::from_bytes([0x77; 32])?,
        },
        timestamp(65)?,
        timestamp(80)?,
    )?;
    let outcome = crate::workspace_home_transfers::HomeHandoffAcceptanceOutcomeRecord::from_parts(
        crate::workspace_home_transfers::handoffs::HomeHandoffAcceptanceOutcomeRecordParts {
            request: take_request,
            authenticated_issuer: issuer,
            proposal,
            preparation: fixture.source.clone(),
            source_at,
            terminal:
                crate::workspace_home_transfers::handoffs::HomeHandoffAcceptanceTerminal::Applied {
                    predecessor_before: fixture.assignment.clone(),
                    transition: transition.clone(),
                    grant,
                },
        },
    )?;

    persist_applied_fixture(&mut fixture, &transition, &outcome, acceptance_id)?;

    let successor = fixture
        .store
        .get_agent_assignment(successor_id)?
        .ok_or("Applied Home successor assignment is missing")?;
    let successor_source = prepare_successor_source(&mut fixture, seed)?;
    fixture.source = successor_source;
    Ok((fixture, successor, acceptance_id))
}

fn persist_applied_fixture(
    fixture: &mut Fixture,
    transition: &AgentAssignmentHomeHandoffTransition,
    outcome: &crate::HomeHandoffAcceptanceOutcomeRecord,
    acceptance_id: Uuid,
) -> TestResult {
    // Defer the successor's receipt foreign key only within this fixture
    // transaction. Both records must exist coherently at commit.
    let transaction = fixture
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "defer_foreign_keys", true)?;
    crate::workspace_agent_assignments::persist_home_handoff_transition_in_transaction(
        &transaction,
        &fixture.assignment,
        transition,
        acceptance_id,
    )?;
    let _inserted = crate::workspace_home_transfers::handoffs::insert_outcome_in_transaction(
        &transaction,
        outcome,
    )?;
    transaction.commit()?;
    Ok(())
}

fn prepare_successor_source(
    fixture: &mut Fixture,
    seed: u128,
) -> TestResult<crate::HomeTransferSourceRecord> {
    // The fixture already delegated to this destination. Use that identity
    // without replaying a Workspace freeze through the active Home fence.
    let destination = uuid(seed + 41);
    let coordinator = fixture
        .store
        .get_agent(fixture.actor.agent_id())?
        .ok_or("Coordinator Agent disappeared")?;
    let backend = ForgeBackendId::from_uuid(uuid(seed + 42));
    let request = source_request(
        &fixture.store,
        uuid(seed + 145),
        backend,
        destination,
        &coordinator,
        &fixture.unaffected_agent,
        seed + 146,
    )?;
    // This next transfer moves B only. The original fixture also captured the
    // Coordinator as an alias of A; carrying that alias into B's new request
    // would correctly conflict with A's still-pending Source preparation.
    let successor_session = fixture
        .unaffected_agent
        .session_id()
        .ok_or("Home successor Session is missing")?;
    let request = HomeTransferSourceRequest::new(
        request.witness(),
        request.scope(),
        request.subject(),
        vec![successor_session],
        vec![HomeTransferSourceBinding::new(
            fixture.unaffected_agent.activity_id(),
            fixture.unaffected_agent.id(),
            successor_session,
            fixture.unaffected_agent.principal(),
        )?],
    )?;
    let issuer = fixture.source.issuer();
    let grant = HomeTransferSourceGrant::new(
        issuer,
        HomeTransferSourceAction::Prepare,
        request.request_digest(),
        timestamp(85)?,
        timestamp(140)?,
    )?;
    Ok(fixture
        .store
        .prepare_home_transfer_source(&request, grant, issuer, backend, destination, || {
            source_clock(90)
        })?
        .record()
        .clone())
}

fn successor_intent(
    fixture: &Fixture,
    successor: &forge_domain::RegisteredAgentAssignment,
    seed: u128,
) -> TestResult<HomeArtifactCaptureIntent> {
    Ok(HomeArtifactCaptureIntent::new(
        HomeArtifactId::new(uuid(seed + 200))?,
        fixture.source.request().witness().preparation_id(),
        uuid(seed + 201),
        fixture.workspace_id,
        successor.id(),
        successor.revision(),
        fixture.assignment.id(),
        vec![WorkspaceRelativePath::new(PathBuf::from("handoff.md"))?],
    )?)
}

#[test]
fn applied_home_successor_can_capture_with_the_original_assignment_root() -> TestResult {
    let (mut fixture, successor, _) =
        home_successor_fixture("home-artifact-home-successor", 0xE100)?;
    let root_assignment_id = fixture.assignment.id();
    assert!(matches!(
        successor.origin(),
        forge_domain::AgentAssignmentOrigin::HomeHandoff(origin)
            if origin.root_assignment_id() == root_assignment_id
    ));
    let selected = successor_intent(&fixture, &successor, 0xE100)?;
    fs::write(fixture.root.join("handoff.md"), b"Home successor handback")?;
    let outcome = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, {
            let mut ticks = [timestamp(95)?, timestamp(99)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?;
    let crate::HomeArtifactCaptureOutcome::Sealed(seal) = outcome else {
        return Err("Home successor artifact was not sealed".into());
    };
    assert_eq!(seal.stage().intent(), &selected);
    assert_eq!(
        seal.stage().intent().root_assignment_id(),
        root_assignment_id
    );
    let replay = fixture
        .store
        .capture_home_transfer_artifact(&selected, fixture.actor, {
            let mut ticks = [timestamp(99)?, timestamp(99)?].into_iter();
            move || ticks.next().ok_or(crate::HomeArtifactJournalError::Clock)
        })?;
    let crate::HomeArtifactCaptureOutcome::Sealed(replayed_seal) = replay else {
        return Err("Home successor artifact replay was not sealed".into());
    };
    assert_eq!(replayed_seal, seal);

    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn home_successor_capture_rejects_a_missing_applied_receipt() -> TestResult {
    let (mut fixture, successor, acceptance_id) =
        home_successor_fixture("home-artifact-home-successor-missing-receipt", 0xE200)?;
    let selected = successor_intent(&fixture, &successor, 0xE200)?;
    // Simulate durable-ledger corruption without manufacturing an alternate
    // lineage source. The assignment retains the deleted receipt identity.
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", false)?;
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER home_handoff_acceptance_outcomes_no_delete;")?;
    let deleted = fixture.store.connection.execute(
        "DELETE FROM home_handoff_acceptance_outcomes WHERE acceptance_id=?1",
        [acceptance_id.as_bytes()],
    )?;
    assert_eq!(deleted, 1);
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", true)?;

    let result = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(95),
    );
    assert!(matches!(
        result,
        Err(crate::HomeArtifactJournalError::Assignment(_))
    ));
    assert_stage_absent(&fixture, &selected)?;

    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn home_successor_capture_rejects_a_mismatched_applied_receipt_row() -> TestResult {
    let (mut fixture, successor, acceptance_id) =
        home_successor_fixture("home-artifact-home-successor-mismatched-receipt", 0xE300)?;
    let selected = successor_intent(&fixture, &successor, 0xE300)?;
    // Bypass only this fixture's immutable-row and foreign-key guards to test read-time
    // corruption detection, not the production writer's mutation permissions.
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", false)?;
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER home_handoff_acceptance_outcomes_no_update;")?;
    let changed = fixture.store.connection.execute(
        "UPDATE home_handoff_acceptance_outcomes
         SET successor_assignment_id=?1
         WHERE acceptance_id=?2",
        params![uuid(0xE3FF).as_bytes(), acceptance_id.as_bytes(),],
    )?;
    assert_eq!(changed, 1);
    fixture
        .store
        .connection
        .pragma_update(None, "foreign_keys", true)?;

    let result = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(95),
    );
    assert!(matches!(
        result,
        Err(crate::HomeArtifactJournalError::Assignment(_))
    ));
    assert_stage_absent(&fixture, &selected)?;

    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn home_successor_stage_replay_revalidates_the_applied_receipt() -> TestResult {
    let (mut fixture, successor, acceptance_id) =
        home_successor_fixture("home-artifact-home-successor-replay-corrupt", 0xE400)?;
    let selected = successor_intent(&fixture, &successor, 0xE400)?;
    let _staged = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(95),
    )?;
    // Inject durable-ledger corruption after the stage has already committed.
    fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER home_handoff_acceptance_outcomes_no_update;")?;
    fixture.store.connection.execute(
        "UPDATE home_handoff_acceptance_outcomes SET payload_digest=?1 WHERE acceptance_id=?2",
        params![[0xEF_u8; 32].as_slice(), acceptance_id.as_bytes()],
    )?;
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::get(&fixture.store.connection, &selected),
        Err(crate::HomeArtifactJournalError::Assignment(_))
    ));
    assert!(matches!(
        crate::workspace_home_transfers::artifacts::stage(
            &mut fixture.store.connection,
            &selected,
            fixture.actor,
            || artifact_clock(99),
        ),
        Err(crate::HomeArtifactJournalError::Assignment(_))
    ));
    let retained: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM home_transfer_artifact_stages WHERE handoff_id=?1",
        [selected.handoff_id().as_bytes()],
        |row| row.get(0),
    )?;
    assert_eq!(
        retained, 1,
        "corruption must not erase the immutable capture intent"
    );
    let root = fixture.root.clone();
    drop(fixture.store);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_stage_absent(fixture: &Fixture, intent: &HomeArtifactCaptureIntent) -> TestResult {
    let count: i64 = fixture.store.connection.query_row(
        "SELECT COUNT(*) FROM home_transfer_artifact_stages WHERE handoff_id=?1",
        [intent.handoff_id().as_bytes()],
        |row| row.get(0),
    )?;
    assert_eq!(
        count, 0,
        "a rejected lineage must not leave an artifact stage"
    );
    Ok(())
}
