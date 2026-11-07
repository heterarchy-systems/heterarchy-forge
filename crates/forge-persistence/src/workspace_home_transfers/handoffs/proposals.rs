//! Source proposal transaction, immutable history Get, and exact current-head Get.

mod transport;

use forge_domain::{
    AgentAssignmentHomeHandoffOrigin, AgentAssignmentId, AgentAssignmentOrigin,
    AgentAssignmentState, HomeHandoffProposalRequest, TimestampMillis, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use uuid::Uuid;

use super::HomeHandoffProposalStoreError as Error;
use super::proposal_codec;
use super::proposal_model::{
    HomeHandoffAssignmentLineage, HomeHandoffCaseSnapshot, HomeHandoffProposalEvidence,
    HomeHandoffProposalOutcome, HomeHandoffProposalRecord, HomeHandoffSourceAssignmentPin,
};
use super::proposal_schema;
use crate::workspace_home_transfers::inventory::{
    HomeTransferSourceInventory, SourceAssignment, SourceAssignmentOrigin, SourceAssignmentState,
    SourcePrincipal, SourceWorkCreditBudget,
};
use crate::workspace_home_transfers::{HomeTransferSourceRecord, HomeTransferSourceState};

/// Required same-transaction readback from the actual applied-receipt owner.
/// There is intentionally no default implementation or permissive fallback.
pub(crate) trait HomeHandoffProposalHooks {
    fn handoff_is_applied(&self, connection: &Connection, handoff_id: Uuid) -> Result<bool, Error>;

    fn home_origin_matches_applied_receipt(
        &self,
        connection: &Connection,
        successor_assignment_id: AgentAssignmentId,
        origin: AgentAssignmentHomeHandoffOrigin,
    ) -> Result<bool, Error>;
}

#[derive(Debug, Clone, Copy)]
struct CaseIdentity {
    handoff_id: Uuid,
    preparation_id: Uuid,
    workspace_id: forge_domain::WorkspaceId,
    predecessor_id: AgentAssignmentId,
    root_assignment_id: AgentAssignmentId,
    opened_at: TimestampMillis,
}

#[derive(Debug, Clone, Copy)]
struct HeadPointer {
    case_revision: i64,
    proposal_id: Uuid,
    updated_at: TimestampMillis,
}

#[derive(Debug)]
struct CurrentSourceScope {
    delegation: crate::AgentOperationsDelegation,
    workspace_revision: WorkspaceRevision,
    workspace_updated_at: TimestampMillis,
}

#[derive(Debug)]
struct RawProposal {
    proposal_id: Vec<u8>,
    proposal_id_len: i64,
    handoff_id: Vec<u8>,
    handoff_id_len: i64,
    case_revision: i64,
    preparation_id: Vec<u8>,
    preparation_id_len: i64,
    workspace_id: Vec<u8>,
    workspace_id_len: i64,
    predecessor_id: Vec<u8>,
    predecessor_id_len: i64,
    root_assignment_id: Vec<u8>,
    root_assignment_id_len: i64,
    request_digest: Vec<u8>,
    request_digest_len: i64,
    request_snapshot: Vec<u8>,
    request_snapshot_len: i64,
    source_digest: Vec<u8>,
    source_digest_len: i64,
    source_snapshot: Vec<u8>,
    source_snapshot_len: i64,
    prepared_outcome_digest: Vec<u8>,
    prepared_outcome_digest_len: i64,
    evidence_kind: i64,
    artifact_id: Option<Vec<u8>>,
    artifact_id_len: Option<i64>,
    artifact_digest: Option<Vec<u8>>,
    artifact_digest_len: Option<i64>,
    created_at_ms: i64,
    payload_digest: Vec<u8>,
    payload_digest_len: i64,
}

/// Persist one immutable proposal or return its exact historical replay.
///
/// `sample_clock` is invoked only after the IMMEDIATE writer lock and all
/// admission reads. The proposal path never mutates assignment or effect facts.
#[allow(
    clippy::too_many_lines,
    reason = "one IMMEDIATE transaction owns replay, admission, evidence linkage, and head CAS"
)]
pub(crate) fn propose<C, H>(
    connection: &mut Connection,
    request: &HomeHandoffProposalRequest,
    hooks: &H,
    sample_clock: C,
) -> Result<HomeHandoffProposalOutcome, Error>
where
    C: FnOnce() -> Result<TimestampMillis, Error>,
    H: HomeHandoffProposalHooks,
{
    if request.proposal_id().is_nil()
        || request.handoff_id().is_nil()
        || request.preparation_id().is_nil()
    {
        return Err(Error::Conflict("nil proposal identity"));
    }
    proposal_schema::validate_schema(connection)?;

    // Identity replay precedes current admission. A superseded proposal is
    // returned from history and cannot move the mutable head backwards.
    if let Some(existing) = proposal_history(connection, request)? {
        return Ok(HomeHandoffProposalOutcome::Existing(existing));
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    proposal_schema::validate_schema(&transaction)?;

    // A concurrent creator may have committed after the historical lookup.
    if let Some(existing) = load_proposal_by_id(&transaction, request.proposal_id())? {
        ensure_same_request(request, &existing)?;
        validate_case_parent_in_transaction(&transaction, &existing)?;
        let case = load_case(&transaction, existing.request().handoff_id())?
            .ok_or(Error::Corrupt("proposal case is missing"))?;
        validate_proposal_case(&existing, &case)?;
        transaction.commit()?;
        return replay_or_conflict(request, existing);
    }

    let (prepared, prepared_inventory) =
        read_prepared_parent_and_inventory_in_transaction(&transaction, request.preparation_id())?;
    let current_source = validate_current_source_scope(&transaction, &prepared)?;

    let assignment = crate::workspace_agent_assignments::get_in_transaction(
        &transaction,
        request.predecessor_id(),
    )
    .map_err(|error| Error::AgentAssignment(Box::new(error)))?
    .ok_or(Error::Conflict("current predecessor Assignment is missing"))?;
    validate_predecessor(
        &assignment,
        request,
        prepared.request().scope().workspace_id(),
    )?;
    if crate::workspace_agent_assignments::get_in_transaction(&transaction, request.successor_id())
        .map_err(|error| Error::AgentAssignment(Box::new(error)))?
        .is_some()
    {
        return Err(Error::Conflict(
            "successor Assignment identity already exists",
        ));
    }

    let (lineage, root_assignment_id) = assignment_root(&transaction, hooks, &assignment)?;
    let source =
        HomeHandoffSourceAssignmentPin::from_assignment(&assignment, root_assignment_id, lineage)?;
    validate_prepared_assignment_pin(&prepared, &prepared_inventory, source)?;
    let case = load_case(&transaction, request.handoff_id())?;
    let head = validate_case_for_request(&transaction, request, &source, &case)?;
    if let Some(head) = head {
        if hooks.handoff_is_applied(&transaction, request.handoff_id())? {
            return Err(Error::Conflict(
                "an Applied receipt prevents proposal head replacement",
            ));
        }
        if request.expected_case_revision() != Some(head.case_revision) {
            return Err(Error::Conflict("proposal case-head revision is stale"));
        }
    }

    let goal = crate::workspace_goals::get_goal(&transaction, assignment.goal_id())
        .map_err(|error| Error::Goal(Box::new(error)))?
        .ok_or(Error::Conflict("current predecessor Goal is missing"))?;
    let (node_updated_at, dag_head_updated_at) =
        validate_current_goal_dag(&transaction, &assignment, &goal)?;

    let recipient =
        crate::workspace_agents::get_in_transaction(&transaction, request.recipient().agent_id())
            .map_err(|error| Error::Agent(Box::new(error)))?
            .ok_or(Error::Conflict("current recipient Agent is missing"))?;
    validate_recipient(&recipient, request, &assignment)?;

    let artifact = validate_requested_artifact(
        &transaction,
        request,
        &prepared,
        &source,
        &goal,
        current_source.workspace_revision,
    )?;

    let coordinator_agent =
        crate::workspace_agents::get_in_transaction(&transaction, request.coordinator().agent_id())
            .map_err(|error| Error::Agent(Box::new(error)))?
            .ok_or(Error::Conflict("current Coordinator Agent is missing"))?;
    if coordinator_agent.workspace_id() != assignment.workspace_id()
        || coordinator_agent.activity_id() != assignment.activity_id()
        || coordinator_agent.session_id() != Some(request.coordinator().session_id())
        || coordinator_agent.principal() != request.coordinator().principal()
        || coordinator_agent.attachment_state().is_detached()
    {
        return Err(Error::Conflict(
            "current Coordinator Agent/Session binding is stale",
        ));
    }

    let now = sample_clock()?;
    let coordinator_binding = crate::workspace_coordinators::authorize_live_in_transaction(
        &transaction,
        request.coordinator(),
        now,
    )
    .map_err(|error| Error::Coordinator(Box::new(error)))?;
    let mut high_water = [
        prepared.observed_at(),
        current_source.workspace_updated_at,
        current_source.delegation.delegated_at(),
        current_source.delegation.freeze().updated_at(),
        assignment.created_at(),
        assignment.updated_at(),
        goal.timestamps().created_at(),
        goal.timestamps().updated_at(),
        dag_head_updated_at,
        node_updated_at,
        coordinator_binding.updated_at(),
        coordinator_agent.updated_at(),
        recipient.updated_at(),
    ]
    .into_iter()
    .max()
    .ok_or(Error::Corrupt("proposal high-water set is empty"))?;
    if let Some(head) = head {
        high_water = high_water.max(head.updated_at);
    }
    if let Some(readback) = &artifact {
        high_water = high_water.max(readback.stage().staged_at()).max(
            readback
                .seal()
                .ok_or(Error::Conflict("requested artifact has no verified seal"))?
                .sealed_at(),
        );
    }
    if now < high_water {
        return Err(Error::Conflict(
            "Source proposal time precedes native records",
        ));
    }

    let case_revision = match head {
        None => 1,
        Some(head) => head
            .case_revision
            .checked_add(1)
            .ok_or(Error::Conflict("proposal case revision overflow"))?,
    };
    let evidence = match (request.artifact_id(), artifact.as_ref()) {
        (None, None) => HomeHandoffProposalEvidence::NoArtifactRequested,
        (Some(artifact_id), Some(readback)) => {
            let seal = readback
                .seal()
                .ok_or(Error::Conflict("requested artifact has no verified seal"))?;
            HomeHandoffProposalEvidence::SealedArtifact {
                artifact_id,
                archive_digest: *seal.archive_digest(),
            }
        }
        _ => return Err(Error::Conflict("artifact evidence does not match request")),
    };
    let record = HomeHandoffProposalRecord::new(
        *request,
        case_revision,
        source,
        *prepared.outcome_digest(),
        evidence,
        now,
    )?;
    if let Some(readback) = &artifact {
        validate_artifact_case(readback, request, &prepared, &source, &goal, &record)?;
    }

    if case.is_none() {
        ensure_case_identity_available(&transaction, &source)?;
        insert_case(&transaction, request, &source, now)?;
    }
    insert_proposal(&transaction, &record)?;
    match head {
        None => insert_head(&transaction, &record)?,
        Some(head) => update_head(&transaction, &record, head)?,
    }
    let inserted = load_proposal_by_id(&transaction, request.proposal_id())?
        .ok_or(Error::Corrupt("inserted proposal is missing"))?;
    if inserted != record {
        return Err(Error::Corrupt(
            "inserted proposal differs from exact request",
        ));
    }
    transaction
        .commit()
        .map_err(|source| Error::CommitUnconfirmed {
            handoff_id: request.handoff_id(),
            proposal_id: request.proposal_id(),
            source: Box::new(source),
        })?;

    let readback = match get(connection, request.handoff_id(), request.proposal_id()) {
        Ok(Some(readback)) if readback == record => readback,
        Ok(Some(_)) | Ok(None) | Err(_) => {
            return Err(Error::ReadbackRequired {
                handoff_id: request.handoff_id(),
                proposal_id: request.proposal_id(),
            });
        }
    };
    Ok(HomeHandoffProposalOutcome::Created(readback))
}

/// Read one exact historical proposal and validate its immutable Prepared parent.
/// Current Coordinator and recipient liveness are deliberately not rechecked.
pub(crate) fn get(
    connection: &Connection,
    handoff_id: Uuid,
    proposal_id: Uuid,
) -> Result<Option<HomeHandoffProposalRecord>, Error> {
    let transaction = connection.unchecked_transaction()?;
    let record = get_in_transaction(&transaction, handoff_id, proposal_id)?;
    transaction.commit()?;
    Ok(record)
}

/// Read one exact historical proposal and its immutable Prepared parent from
/// the caller's snapshot. Superseded proposals remain readable without
/// requiring the historical Coordinator or recipient to remain live.
pub(crate) fn get_in_transaction(
    connection: &Connection,
    handoff_id: Uuid,
    proposal_id: Uuid,
) -> Result<Option<HomeHandoffProposalRecord>, Error> {
    if handoff_id.is_nil() || proposal_id.is_nil() {
        return Err(Error::Conflict("nil historical proposal identity"));
    }
    proposal_schema::validate_schema(connection)?;
    let Some(record) = load_proposal_by_id(connection, proposal_id)? else {
        return Ok(None);
    };
    if record.request().handoff_id() != handoff_id {
        return Err(Error::Conflict(
            "proposal identity is bound to a different handoff",
        ));
    }
    let case = load_case(connection, handoff_id)?
        .ok_or(Error::Corrupt("historical proposal case is missing"))?;
    validate_proposal_case(&record, &case)?;
    validate_historical_record_in_transaction(connection, &record, &case)?;
    Ok(Some(record))
}

fn validate_historical_record_in_transaction(
    connection: &Connection,
    record: &HomeHandoffProposalRecord,
    case: &CaseIdentity,
) -> Result<(), Error> {
    let (parent, inventory) =
        read_prepared_parent_and_inventory_in_transaction(connection, case.preparation_id)?;
    validate_record_parent(record, case, &parent)?;
    validate_prepared_assignment_pin(&parent, &inventory, record.source())?;
    let artifact = read_artifact_for_record(connection, record)?;
    validate_record_artifact(record, &parent, artifact.as_ref())
}

/// Read a consistent current-head snapshot. A later head replacement does not
/// invalidate the historical record returned by this read transaction.
pub(crate) fn get_current(
    connection: &Connection,
    handoff_id: Uuid,
) -> Result<Option<HomeHandoffCaseSnapshot>, Error> {
    let transaction = connection.unchecked_transaction()?;
    let snapshot = get_current_in_transaction(&transaction, handoff_id)?;
    transaction.commit()?;
    Ok(snapshot)
}

/// Read one complete current-head snapshot from a caller-owned transaction.
/// This is the Take owner's same-snapshot seam and never starts a nested read.
pub(crate) fn get_current_in_transaction(
    connection: &Connection,
    handoff_id: Uuid,
) -> Result<Option<HomeHandoffCaseSnapshot>, Error> {
    if handoff_id.is_nil() {
        return Err(Error::Conflict("nil handoff identity"));
    }
    proposal_schema::validate_schema(connection)?;
    let Some(case) = load_case(connection, handoff_id)? else {
        return Ok(None);
    };
    let head = load_head(connection, handoff_id)?
        .ok_or(Error::Corrupt("proposal case has no current head"))?;
    let record = load_proposal_by_id(connection, head.proposal_id)?
        .ok_or(Error::Corrupt("proposal head points to a missing record"))?;
    if record.case_revision() != head.case_revision || record.created_at() != head.updated_at {
        return Err(Error::Corrupt(
            "proposal head differs from immutable record",
        ));
    }
    validate_proposal_case(&record, &case)?;
    let (parent, inventory) =
        read_prepared_parent_and_inventory_in_transaction(connection, case.preparation_id)?;
    validate_record_parent(&record, &case, &parent)?;
    validate_prepared_assignment_pin(&parent, &inventory, record.source())?;
    let artifact = read_artifact_for_record(connection, &record)?;
    validate_record_artifact(&record, &parent, artifact.as_ref())?;
    HomeHandoffCaseSnapshot::new(
        case.handoff_id,
        case.preparation_id,
        case.workspace_id,
        case.predecessor_id,
        case.root_assignment_id,
        case.opened_at,
        record,
    )
    .map(Some)
}

fn replay_or_conflict(
    request: &HomeHandoffProposalRequest,
    existing: HomeHandoffProposalRecord,
) -> Result<HomeHandoffProposalOutcome, Error> {
    ensure_same_request(request, &existing)?;
    Ok(HomeHandoffProposalOutcome::Existing(existing))
}

fn ensure_same_request(
    request: &HomeHandoffProposalRequest,
    existing: &HomeHandoffProposalRecord,
) -> Result<(), Error> {
    if existing.request() != *request
        || existing.request().canonical_snapshot() != request.canonical_snapshot()
    {
        return Err(Error::Conflict(
            "proposal identity already contains a different immutable body",
        ));
    }
    Ok(())
}

fn proposal_history(
    connection: &Connection,
    request: &HomeHandoffProposalRequest,
) -> Result<Option<HomeHandoffProposalRecord>, Error> {
    let transaction = connection.unchecked_transaction()?;
    let Some(record) =
        get_in_transaction(&transaction, request.handoff_id(), request.proposal_id())?
    else {
        transaction.commit()?;
        return Ok(None);
    };
    ensure_same_request(request, &record)?;
    transaction.commit()?;
    Ok(Some(record))
}

fn validate_prepared_record(
    parent: &HomeTransferSourceRecord,
    preparation_id: Uuid,
) -> Result<(), Error> {
    if parent.request().witness().preparation_id() != preparation_id
        || parent.state() != HomeTransferSourceState::Prepared
        || parent.outcome_digest() == &[0; 32]
    {
        return Err(Error::Conflict(
            "proposal requires the exact immutable Prepared parent",
        ));
    }
    Ok(())
}

fn read_prepared_parent_and_inventory_in_transaction(
    connection: &Connection,
    preparation_id: Uuid,
) -> Result<(HomeTransferSourceRecord, HomeTransferSourceInventory), Error> {
    let Some((parent, inventory)) =
        super::super::repository::read_record_with_inventory(connection, preparation_id)
            .map_err(|error| Error::HomeTransfer(Box::new(error)))?
    else {
        return Err(Error::Corrupt("Home handoff Prepared parent is missing"));
    };
    validate_prepared_record(&parent, preparation_id)?;
    validate_prepared_parent_row(connection, &parent)?;
    let inventory = inventory.ok_or(Error::Corrupt("Prepared parent inventory is missing"))?;
    Ok((parent, inventory))
}

/// Reuse the exact Prepared assignment check from other handoff owners without
/// opening a nested transaction or rechecking current Coordinator eligibility.
pub(super) fn validate_prepared_assignment_pin(
    parent: &HomeTransferSourceRecord,
    inventory: &HomeTransferSourceInventory,
    source: HomeHandoffSourceAssignmentPin,
) -> Result<(), Error> {
    let request = parent.request();
    let target = source.target();
    let target_agent_id = target.agent_id().into_uuid();
    let target_session_id = target.session_id().into_uuid();
    let target_principal = source_principal(target.principal());
    if request.scope().workspace_id() != source.workspace_id() {
        return Err(Error::Conflict(
            "Prepared source Workspace differs from predecessor scope",
        ));
    }

    let coordinator = source.coordinator();
    let origin = match source.lineage() {
        HomeHandoffAssignmentLineage::CoordinatorOffer => SourceAssignmentOrigin::CoordinatorOffer,
        HomeHandoffAssignmentLineage::HomeHandoff(origin) => SourceAssignmentOrigin::HomeHandoff {
            preparation_id: origin.preparation_id(),
            handoff_id: origin.handoff_id(),
            predecessor_id: origin.predecessor_id().into_uuid(),
            root_assignment_id: origin.root_assignment_id().into_uuid(),
        },
    };
    let expected = SourceAssignment {
        assignment_id: source.assignment_id().into_uuid(),
        origin,
        workspace_id: source.workspace_id().into_uuid(),
        activity_id: source.activity_id().into_uuid(),
        target_agent_id,
        target_session_id,
        target_principal,
        target_agent_revision: target.agent_revision().get(),
        coordinator_agent_id: coordinator.agent_id().into_uuid(),
        coordinator_session_id: coordinator.session_id().into_uuid(),
        coordinator_principal: source_principal(coordinator.principal()),
        coordinator_revision: coordinator.revision().get(),
        state: source_assignment_state(source.state()),
        cancellation_requested: source.cancellation_requested(),
        revision: source.revision().get(),
        created_at_ms: source.created_at().get(),
        updated_at_ms: source.updated_at().get(),
        credit_budget: source.credit_budget().map(source_work_credit_budget),
        result_digest: None,
        goal_id: source.goal_id().into_uuid(),
        goal_created_at_ms: source.goal_created_at().get(),
        goal_revision: source.goal_revision().get(),
        dag_revision: source.dag_revision().get(),
        dag_head_revision: source.dag_head_revision().get(),
        node_id: source.node_id().into_uuid(),
        node_revision: source.node_revision().get(),
    };
    let Some(captured) = inventory
        .assignments
        .iter()
        .find(|assignment| assignment.assignment_id == expected.assignment_id)
    else {
        return Err(Error::Conflict(
            "Prepared inventory does not contain the predecessor Assignment",
        ));
    };
    let state_progresses = matches!(
        (captured.state, expected.state),
        (
            SourceAssignmentState::Offered,
            SourceAssignmentState::Offered | SourceAssignmentState::Running,
        ) | (
            SourceAssignmentState::Running,
            SourceAssignmentState::Running,
        ),
    );
    if captured.origin != expected.origin
        || captured.workspace_id != expected.workspace_id
        || captured.activity_id != expected.activity_id
        || captured.target_agent_id != expected.target_agent_id
        || captured.target_session_id != expected.target_session_id
        || captured.target_principal != expected.target_principal
        || captured.target_agent_revision != expected.target_agent_revision
        || captured.coordinator_agent_id != expected.coordinator_agent_id
        || captured.coordinator_session_id != expected.coordinator_session_id
        || captured.coordinator_principal != expected.coordinator_principal
        || captured.coordinator_revision != expected.coordinator_revision
        || captured.cancellation_requested != expected.cancellation_requested
        || captured.revision > expected.revision
        || captured.created_at_ms != expected.created_at_ms
        || captured.updated_at_ms > expected.updated_at_ms
        || captured.credit_budget != expected.credit_budget
        || captured.result_digest != expected.result_digest
        || captured.goal_id != expected.goal_id
        || captured.goal_created_at_ms != expected.goal_created_at_ms
        || captured.goal_revision != expected.goal_revision
        || captured.dag_revision != expected.dag_revision
        || captured.dag_head_revision != expected.dag_head_revision
        || captured.node_id != expected.node_id
        || captured.node_revision != expected.node_revision
        || !state_progresses
    {
        return Err(Error::Conflict(
            "Prepared inventory predecessor Assignment differs from exact source pins",
        ));
    }
    let captured_agent = inventory
        .agents
        .iter()
        .find(|agent| agent.agent_id == target_agent_id);
    if !request.sessions().contains(&target.session_id())
        || !inventory.session_ids.contains(&target_session_id)
        || captured_agent.is_none_or(|agent| {
            agent.workspace_id != source.workspace_id().into_uuid()
                || agent.activity_id != source.activity_id().into_uuid()
                || agent.session_id != Some(target_session_id)
                || agent.principal != target_principal
        })
    {
        return Err(Error::Conflict(
            "Prepared inventory does not cover the predecessor Agent Session",
        ));
    }
    Ok(())
}

fn source_principal(value: forge_domain::AuthenticatedPrincipal) -> SourcePrincipal {
    match value {
        forge_domain::AuthenticatedPrincipal::TrustedStdio => SourcePrincipal::TrustedStdio,
        forge_domain::AuthenticatedPrincipal::DirectToken(token) => {
            SourcePrincipal::DirectToken(token.into_uuid())
        }
        forge_domain::AuthenticatedPrincipal::OAuthGrant(grant) => {
            SourcePrincipal::OAuthGrant(grant.into_uuid())
        }
    }
}

fn source_assignment_state(value: AgentAssignmentState) -> SourceAssignmentState {
    match value {
        AgentAssignmentState::Offered => SourceAssignmentState::Offered,
        AgentAssignmentState::Running => SourceAssignmentState::Running,
        AgentAssignmentState::Submitted => SourceAssignmentState::Submitted,
        AgentAssignmentState::Accepted => SourceAssignmentState::Accepted,
        AgentAssignmentState::Rejected => SourceAssignmentState::Rejected,
        AgentAssignmentState::Cancelled => SourceAssignmentState::Cancelled,
        AgentAssignmentState::Interrupted => SourceAssignmentState::Interrupted,
    }
}

fn source_work_credit_budget(value: forge_domain::WorkCreditBudget) -> SourceWorkCreditBudget {
    match value {
        forge_domain::WorkCreditBudget::One => SourceWorkCreditBudget::One,
        forge_domain::WorkCreditBudget::Three => SourceWorkCreditBudget::Three,
        forge_domain::WorkCreditBudget::Five => SourceWorkCreditBudget::Five,
    }
}

/// Re-read current Workspace and delegation independently from the original
/// Prepared scope. The Workspace revision may advance while the immutable
/// source assignment pins remain valid.
fn validate_current_source_scope(
    connection: &Connection,
    prepared: &HomeTransferSourceRecord,
) -> Result<CurrentSourceScope, Error> {
    let original_scope = prepared.request().scope();
    let (workspace_bytes, revision, updated_at_ms): (Vec<u8>, i64, i64) = connection.query_row(
        "SELECT substr(workspace_id,1,17),revision,updated_at_ms FROM workspace WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if workspace_bytes.len() != 16
        || Uuid::from_slice(&workspace_bytes)
            .ok()
            .is_none_or(|workspace_id| workspace_id != original_scope.workspace_id().into_uuid())
    {
        return Err(Error::Conflict(
            "current Workspace identity differs from Prepared scope",
        ));
    }
    let workspace_revision = WorkspaceRevision::new(revision)
        .map_err(|_| Error::Corrupt("current Workspace revision"))?;
    if workspace_revision < original_scope.workspace_revision() {
        return Err(Error::Conflict("current Workspace revision regressed"));
    }
    let workspace_updated_at = timestamp(updated_at_ms, "current Workspace updated_at")?;
    let delegation = crate::workspace_agent_migration::delegation(connection)
        .map_err(|error| Error::Migration(Box::new(error)))?
        .ok_or(Error::Conflict("current Source delegation is missing"))?;
    if delegation.workspace_id() != original_scope.workspace_id()
        || delegation.destination_id() != original_scope.destination_id()
        || delegation.migration_id() != prepared.migration_id()
        || delegation.freeze().state() != crate::AgentOperationsFreezeState::Frozen
        || delegation.freeze().revision() != prepared.freeze_revision()
        || delegation.manifest_digest() != *prepared.delegation_digest()
    {
        return Err(Error::Conflict(
            "Prepared parent does not name the current frozen Source delegation",
        ));
    }
    Ok(CurrentSourceScope {
        delegation,
        workspace_revision,
        workspace_updated_at,
    })
}

fn validate_prepared_parent_row(
    connection: &Connection,
    parent: &HomeTransferSourceRecord,
) -> Result<(), Error> {
    let preparation_id = parent.request().witness().preparation_id();
    let raw: Option<PreparedParentRow> = connection
        .query_row(
            "SELECT substr(workspace_id,1,17),length(workspace_id),outcome,substr(request_digest,1,33),length(request_digest),substr(request_payload,1,131073),length(request_payload),substr(outcome_digest,1,33),length(outcome_digest),substr(migration_id,1,17),length(migration_id),freeze_revision,substr(delegation_digest,1,33),length(delegation_digest),observed_at_ms FROM home_transfer_source_operations WHERE preparation_id=?1",
            params![preparation_id.as_bytes()],
            |row| {
                Ok(PreparedParentRow {
                    workspace_id: row.get(0)?,
                    workspace_id_len: row.get(1)?,
                    state: row.get(2)?,
                    request_digest: row.get(3)?,
                    request_digest_len: row.get(4)?,
                    request_payload: row.get(5)?,
                    request_payload_len: row.get(6)?,
                    outcome_digest: row.get(7)?,
                    outcome_digest_len: row.get(8)?,
                    migration_id: row.get(9)?,
                    migration_id_len: row.get(10)?,
                    freeze_revision: row.get(11)?,
                    delegation_digest: row.get(12)?,
                    delegation_digest_len: row.get(13)?,
                    observed_at_ms: row.get(14)?,
                })
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Err(Error::Corrupt("Prepared parent row disappeared"));
    };
    let encoded_request = super::super::encode_home_transfer_source_request(parent.request())
        .map_err(|error| Error::HomeTransfer(Box::new(error)))?;
    if raw.workspace_id_len != 16
        || raw.workspace_id.as_slice()
            != parent
                .request()
                .scope()
                .workspace_id()
                .into_uuid()
                .as_bytes()
        || raw.state != 0
        || raw.request_digest_len != 32
        || raw.request_digest.as_slice() != parent.request().request_digest().as_bytes()
        || raw.request_payload_len < 1
        || raw.request_payload_len > 131_072
        || raw.request_payload != encoded_request
        || raw.outcome_digest_len != 32
        || raw.outcome_digest.as_slice() != parent.outcome_digest()
        || raw.migration_id_len != 16
        || Uuid::from_slice(&raw.migration_id)
            .ok()
            .is_none_or(|value| value != parent.migration_id())
        || raw.freeze_revision < 1
        || u64::try_from(raw.freeze_revision).ok() != Some(parent.freeze_revision())
        || raw.delegation_digest_len != 32
        || raw.delegation_digest.as_slice() != parent.delegation_digest()
        || raw.observed_at_ms != parent.observed_at().get()
    {
        return Err(Error::Corrupt("Prepared parent changed or is inconsistent"));
    }
    Ok(())
}

#[derive(Debug)]
struct PreparedParentRow {
    workspace_id: Vec<u8>,
    workspace_id_len: i64,
    state: i64,
    request_digest: Vec<u8>,
    request_digest_len: i64,
    request_payload: Vec<u8>,
    request_payload_len: i64,
    outcome_digest: Vec<u8>,
    outcome_digest_len: i64,
    migration_id: Vec<u8>,
    migration_id_len: i64,
    freeze_revision: i64,
    delegation_digest: Vec<u8>,
    delegation_digest_len: i64,
    observed_at_ms: i64,
}

fn validate_record_parent(
    record: &HomeHandoffProposalRecord,
    case: &CaseIdentity,
    parent: &HomeTransferSourceRecord,
) -> Result<(), Error> {
    validate_prepared_record(parent, case.preparation_id)?;
    if record.request().preparation_id() != case.preparation_id
        || record.request().handoff_id() != case.handoff_id
        || record.prepared_outcome_digest() != parent.outcome_digest()
        || record.source().workspace_id() != case.workspace_id
        || record.source().assignment_id() != case.predecessor_id
        || record.source().root_assignment_id() != case.root_assignment_id
        || parent.request().scope().workspace_id() != case.workspace_id
        || record.created_at() < parent.observed_at()
    {
        return Err(Error::Corrupt(
            "proposal differs from immutable Prepared parent",
        ));
    }
    Ok(())
}

fn read_artifact_for_record(
    connection: &Connection,
    record: &HomeHandoffProposalRecord,
) -> Result<Option<super::super::artifacts::HomeArtifactReadback>, Error> {
    let HomeHandoffProposalEvidence::SealedArtifact { .. } = record.evidence() else {
        return Ok(None);
    };
    super::super::artifacts::get_by_handoff_id_in_transaction(
        connection,
        record.request().handoff_id(),
    )
    .map_err(|error| Error::Artifact(Box::new(error)))?
    .map(Some)
    .ok_or(Error::Corrupt("proposal sealed artifact stage is missing"))
}

fn validate_record_artifact(
    record: &HomeHandoffProposalRecord,
    parent: &HomeTransferSourceRecord,
    readback: Option<&super::super::artifacts::HomeArtifactReadback>,
) -> Result<(), Error> {
    let (
        HomeHandoffProposalEvidence::SealedArtifact {
            artifact_id,
            archive_digest,
        },
        Some(readback),
    ) = (record.evidence(), readback)
    else {
        return if matches!(
            record.evidence(),
            HomeHandoffProposalEvidence::NoArtifactRequested
        ) && readback.is_none()
        {
            Ok(())
        } else {
            Err(Error::Corrupt(
                "proposal artifact evidence/readback mismatch",
            ))
        };
    };
    let stage = readback.stage();
    let seal = stage_seal(readback)?;
    let request = record.request();
    let source = record.source();
    let inventory_digest = parent.inventory_digest().ok_or(Error::Corrupt(
        "Prepared parent inventory digest is missing",
    ))?;
    let intent = stage.intent();
    if request.artifact_id() != Some(artifact_id)
        || intent.artifact_id() != artifact_id
        || intent.handoff_id() != request.handoff_id()
        || intent.preparation_id() != request.preparation_id()
        || intent.workspace_id() != source.workspace_id()
        || intent.predecessor_assignment_id() != source.assignment_id()
        || intent.predecessor_revision() != request.predecessor_revision()
        || intent.root_assignment_id() != source.root_assignment_id()
        || stage.workspace_id() != source.workspace_id()
        || stage.workspace_revision() < parent.request().scope().workspace_revision()
        || stage.activity_id() != source.activity_id()
        || stage.goal_id() != source.goal_id()
        || stage.source_request_digest() != parent.request().request_digest().as_bytes()
        || stage.source_outcome_digest() != parent.outcome_digest()
        || stage.source_inventory_digest() != inventory_digest
        || stage.source_observed_at() != parent.observed_at()
        || seal.stage() != stage
        || seal.archive().manifest().intent() != intent
        || seal.archive_digest() != &archive_digest
        || seal.sealed_at() < stage.staged_at()
    {
        return Err(Error::Corrupt(
            "historical proposal does not match its native artifact and Prepared parent",
        ));
    }
    Ok(())
}

fn stage_seal(
    readback: &super::super::artifacts::HomeArtifactReadback,
) -> Result<&super::super::artifacts::HomeArtifactSealRecord, Error> {
    readback
        .seal()
        .ok_or(Error::Corrupt("proposal artifact has no native seal"))
}

fn validate_case_parent_in_transaction(
    transaction: &Transaction<'_>,
    record: &HomeHandoffProposalRecord,
) -> Result<(), Error> {
    let case = load_case(transaction, record.request().handoff_id())?
        .ok_or(Error::Corrupt("proposal case is missing"))?;
    validate_proposal_case(record, &case)?;
    let (parent, inventory) =
        read_prepared_parent_and_inventory_in_transaction(transaction, case.preparation_id)?;
    validate_record_parent(record, &case, &parent)?;
    validate_prepared_assignment_pin(&parent, &inventory, record.source())?;
    let artifact = read_artifact_for_record(transaction, record)?;
    validate_record_artifact(record, &parent, artifact.as_ref())
}

fn validate_proposal_case(
    record: &HomeHandoffProposalRecord,
    case: &CaseIdentity,
) -> Result<(), Error> {
    let request = record.request();
    let source = record.source();
    if request.handoff_id() != case.handoff_id
        || request.preparation_id() != case.preparation_id
        || source.workspace_id() != case.workspace_id
        || request.predecessor_id() != case.predecessor_id
        || source.assignment_id() != case.predecessor_id
        || source.root_assignment_id() != case.root_assignment_id
        || record.created_at() < case.opened_at
    {
        return Err(Error::Corrupt("proposal and case identity differ"));
    }
    Ok(())
}

fn validate_case_for_request(
    transaction: &Transaction<'_>,
    request: &HomeHandoffProposalRequest,
    source: &HomeHandoffSourceAssignmentPin,
    case: &Option<CaseIdentity>,
) -> Result<Option<HeadPointer>, Error> {
    match case {
        None => {
            if request.expected_case_revision().is_some() {
                return Err(Error::Conflict(
                    "replacement requires an existing proposal case head",
                ));
            }
            let existing: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT substr(handoff_id,1,17) FROM home_handoff_cases WHERE predecessor_assignment_id=?1",
                    params![source.assignment_id().into_uuid().as_bytes()],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.is_some() {
                return Err(Error::Conflict(
                    "predecessor already has a different stable Home case",
                ));
            }
            Ok(None)
        }
        Some(case) => {
            if case.preparation_id != request.preparation_id()
                || case.workspace_id != source.workspace_id()
                || case.predecessor_id != source.assignment_id()
                || case.root_assignment_id != source.root_assignment_id()
            {
                return Err(Error::Conflict(
                    "handoff ID is already bound to another case identity",
                ));
            }
            if request.expected_case_revision().is_none() {
                return Err(Error::Conflict(
                    "an existing Home case requires an exact expected head revision",
                ));
            }
            let head = load_head(transaction, case.handoff_id)?
                .ok_or(Error::Corrupt("Home case is missing its proposal head"))?;
            if request.expected_case_revision() != Some(head.case_revision) {
                return Err(Error::Conflict("proposal case-head revision is stale"));
            }
            let current = load_proposal_by_id(transaction, head.proposal_id)?
                .ok_or(Error::Corrupt("proposal head record is missing"))?;
            if current.case_revision() != head.case_revision
                || current.created_at() != head.updated_at
            {
                return Err(Error::Corrupt("proposal head differs from history"));
            }
            validate_proposal_case(&current, case)?;
            Ok(Some(head))
        }
    }
}

fn validate_predecessor(
    assignment: &forge_domain::RegisteredAgentAssignment,
    request: &HomeHandoffProposalRequest,
    expected_workspace_id: forge_domain::WorkspaceId,
) -> Result<(), Error> {
    if assignment.id() != request.predecessor_id()
        || assignment.revision() != request.predecessor_revision()
        || assignment.workspace_id() != expected_workspace_id
        || assignment.workspace_id() != request.coordinator().workspace_id()
        || assignment.activity_id() != request.coordinator().activity_id()
        || assignment.cancellation_requested()
        || assignment.result().is_some()
        || !matches!(
            assignment.state(),
            AgentAssignmentState::Offered | AgentAssignmentState::Running
        )
    {
        return Err(Error::Conflict(
            "predecessor Assignment revision, scope, or state is stale",
        ));
    }
    Ok(())
}

fn assignment_root<H: HomeHandoffProposalHooks>(
    connection: &Connection,
    hooks: &H,
    assignment: &forge_domain::RegisteredAgentAssignment,
) -> Result<(HomeHandoffAssignmentLineage, AgentAssignmentId), Error> {
    match assignment.origin() {
        AgentAssignmentOrigin::CoordinatorOffer => Ok((
            HomeHandoffAssignmentLineage::CoordinatorOffer,
            assignment.id(),
        )),
        AgentAssignmentOrigin::HomeHandoff(origin) => {
            if !hooks.home_origin_matches_applied_receipt(connection, assignment.id(), origin)? {
                return Err(Error::Conflict(
                    "Home assignment origin has no exact Applied receipt",
                ));
            }
            Ok((
                HomeHandoffAssignmentLineage::HomeHandoff(origin),
                origin.root_assignment_id(),
            ))
        }
        AgentAssignmentOrigin::CutContinuation(_) => Err(Error::Conflict(
            "Cut continuation lineage is not accepted by Home handoff",
        )),
    }
}

fn validate_current_goal_dag(
    connection: &Connection,
    assignment: &forge_domain::RegisteredAgentAssignment,
    goal: &forge_domain::RegisteredGoal,
) -> Result<(TimestampMillis, TimestampMillis), Error> {
    if goal.id() != assignment.goal_id()
        || goal.workspace_id() != assignment.workspace_id()
        || goal.activity_id() != assignment.activity_id()
        || goal.timestamps().created_at() != assignment.goal_created_at()
        || goal.revision() != assignment.goal_revision()
        || !goal.accepts_new_evidence()
    {
        return Err(Error::Conflict(
            "predecessor Goal is no longer the current active generation",
        ));
    }
    let dag = crate::workspace_dags::get_current_in_transaction(connection, assignment.goal_id())
        .map_err(|error| Error::Dag(Box::new(error)))?
        .ok_or(Error::Conflict("predecessor current DAG is missing"))?;
    let revision = dag.revision();
    if revision.goal_id() != assignment.goal_id()
        || revision.base_goal_revision() != goal.revision()
        || revision.number() != assignment.dag_revision()
        || dag.head().goal_id() != assignment.goal_id()
        || dag.head().dag_revision() != assignment.dag_revision()
        || dag.head().revision() != assignment.dag_head_revision()
    {
        return Err(Error::Conflict(
            "predecessor DAG generation or current head is stale",
        ));
    }
    let node = dag
        .nodes()
        .iter()
        .find(|node| node.id() == assignment.node_id())
        .ok_or(Error::Conflict("predecessor current DAG node is missing"))?;
    if node.goal_id() != assignment.goal_id() || node.dag_revision() != assignment.dag_revision() {
        return Err(Error::Conflict(
            "predecessor current DAG node scope is stale",
        ));
    }
    // Offer pins the Pending node exactly. Claim advances the node separately
    // from the immutable offer snapshot, so Running accepts a non-regressed
    // revision only while the same current node remains Active or Blocked.
    match assignment.state() {
        AgentAssignmentState::Offered
            if node.revision() != assignment.node_revision()
                || node.lifecycle() != &forge_domain::DagNodeLifecycle::Pending =>
        {
            return Err(Error::Conflict(
                "Offered predecessor no longer matches the exact Pending DAG node",
            ));
        }
        AgentAssignmentState::Running
            if node.revision().get() < assignment.node_revision().get()
                || !matches!(
                    node.lifecycle(),
                    forge_domain::DagNodeLifecycle::Active
                        | forge_domain::DagNodeLifecycle::Blocked(_)
                ) =>
        {
            return Err(Error::Conflict(
                "Running predecessor current DAG node is stale or ineligible",
            ));
        }
        AgentAssignmentState::Offered | AgentAssignmentState::Running => {}
        AgentAssignmentState::Submitted
        | AgentAssignmentState::Accepted
        | AgentAssignmentState::Rejected
        | AgentAssignmentState::Cancelled
        | AgentAssignmentState::Interrupted => {
            return Err(Error::Conflict("predecessor state is not handoff eligible"));
        }
    }
    Ok((node.updated_at(), dag.head().updated_at()))
}

fn validate_recipient(
    recipient: &forge_domain::RegisteredAgentInstance,
    request: &HomeHandoffProposalRequest,
    assignment: &forge_domain::RegisteredAgentAssignment,
) -> Result<(), Error> {
    let expected = request.recipient();
    let source = assignment.target();
    if recipient.id() != expected.agent_id()
        || recipient.workspace_id() != assignment.workspace_id()
        || recipient.activity_id() != assignment.activity_id()
        || recipient.session_id() != Some(expected.session_id())
        || recipient.principal() != expected.principal()
        || recipient.revision() != expected.agent_revision()
        || recipient.attachment_state().is_detached()
        || expected.agent_id() == source.agent_id()
        || expected.session_id() == source.session_id()
        || expected.agent_id() == request.coordinator().agent_id()
        || expected.session_id() == request.coordinator().session_id()
    {
        return Err(Error::Conflict(
            "recipient is not the exact attached Agent/Session or is not distinct",
        ));
    }
    Ok(())
}

fn validate_requested_artifact(
    connection: &Connection,
    request: &HomeHandoffProposalRequest,
    parent: &HomeTransferSourceRecord,
    source: &HomeHandoffSourceAssignmentPin,
    goal: &forge_domain::RegisteredGoal,
    current_workspace_revision: WorkspaceRevision,
) -> Result<Option<super::super::artifacts::HomeArtifactReadback>, Error> {
    let Some(artifact_id) = request.artifact_id() else {
        return Ok(None);
    };
    let readback =
        super::super::artifacts::get_by_handoff_id_in_transaction(connection, request.handoff_id())
            .map_err(|error| Error::Artifact(Box::new(error)))?
            .ok_or(Error::Conflict(
                "requested artifact has no native stage and seal",
            ))?;
    let stage = readback.stage();
    let seal = readback
        .seal()
        .ok_or(Error::Conflict("requested artifact has no verified seal"))?;
    let intent = stage.intent();
    let source_inventory_digest = parent.inventory_digest().ok_or(Error::Corrupt(
        "Prepared parent inventory digest is missing",
    ))?;
    if intent.artifact_id() != artifact_id
        || intent.handoff_id() != request.handoff_id()
        || intent.preparation_id() != request.preparation_id()
        || intent.workspace_id() != source.workspace_id()
        || intent.predecessor_assignment_id() != source.assignment_id()
        || intent.predecessor_revision() != request.predecessor_revision()
        || intent.root_assignment_id() != source.root_assignment_id()
        || stage.workspace_id() != source.workspace_id()
        || stage.workspace_revision() < parent.request().scope().workspace_revision()
        || stage.workspace_revision() > current_workspace_revision
        || stage.activity_id() != source.activity_id()
        || stage.goal_id() != goal.id()
        || stage.source_request_digest() != parent.request().request_digest().as_bytes()
        || stage.source_outcome_digest() != parent.outcome_digest()
        || stage.source_inventory_digest() != source_inventory_digest
        || stage.source_observed_at() != parent.observed_at()
        || seal.stage() != stage
        || seal.archive().manifest().intent() != intent
        || seal.archive_digest() == &[0; 32]
        || seal.sealed_at() < stage.staged_at()
    {
        return Err(Error::Conflict(
            "native artifact stage or seal does not match exact proposal pins",
        ));
    }
    Ok(Some(readback))
}

fn validate_artifact_case(
    readback: &super::super::artifacts::HomeArtifactReadback,
    request: &HomeHandoffProposalRequest,
    parent: &HomeTransferSourceRecord,
    source: &HomeHandoffSourceAssignmentPin,
    goal: &forge_domain::RegisteredGoal,
    record: &HomeHandoffProposalRecord,
) -> Result<(), Error> {
    let stage = readback.stage();
    let seal = readback
        .seal()
        .ok_or(Error::Conflict("requested artifact has no verified seal"))?;
    if record.request() != *request
        || record.source() != *source
        || record.prepared_outcome_digest() != parent.outcome_digest()
        || stage.goal_id() != goal.id()
        || !matches!(
            record.evidence(),
            HomeHandoffProposalEvidence::SealedArtifact {
                artifact_id,
                archive_digest,
            } if artifact_id == request.artifact_id().ok_or(Error::Conflict("artifact ID missing"))?
                && archive_digest == *seal.archive_digest()
        )
    {
        return Err(Error::Conflict(
            "proposal artifact evidence changed during admission",
        ));
    }
    Ok(())
}

fn ensure_case_identity_available(
    connection: &Connection,
    source: &HomeHandoffSourceAssignmentPin,
) -> Result<(), Error> {
    let existing: Option<Vec<u8>> = connection
        .query_row(
            "SELECT substr(handoff_id,1,17) FROM home_handoff_cases WHERE predecessor_assignment_id=?1",
            params![source.assignment_id().into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    if existing.is_some() {
        return Err(Error::Conflict(
            "predecessor already has an open Home handoff case",
        ));
    }
    Ok(())
}

fn insert_case(
    transaction: &Transaction<'_>,
    request: &HomeHandoffProposalRequest,
    source: &HomeHandoffSourceAssignmentPin,
    opened_at: TimestampMillis,
) -> Result<(), Error> {
    transaction.execute(
        "INSERT INTO home_handoff_cases(handoff_id,preparation_id,workspace_id,predecessor_assignment_id,root_assignment_id,opened_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            request.handoff_id().as_bytes(),
            request.preparation_id().as_bytes(),
            source.workspace_id().into_uuid().as_bytes(),
            source.assignment_id().into_uuid().as_bytes(),
            source.root_assignment_id().into_uuid().as_bytes(),
            opened_at.get(),
        ],
    )?;
    Ok(())
}

fn insert_proposal(
    transaction: &Transaction<'_>,
    record: &HomeHandoffProposalRecord,
) -> Result<(), Error> {
    let request = record.request();
    let source = record.source();
    let request_snapshot = request.canonical_snapshot();
    let source_snapshot = proposal_codec::encode_source(source)?;
    let source_digest = proposal_codec::source_digest(&source_snapshot)?;
    let (evidence_kind, artifact_id, artifact_digest) = match record.evidence() {
        HomeHandoffProposalEvidence::NoArtifactRequested => (0_i64, None, None),
        HomeHandoffProposalEvidence::SealedArtifact {
            artifact_id,
            archive_digest,
        } => (
            1_i64,
            Some(artifact_id.into_uuid().as_bytes().to_vec()),
            Some(archive_digest.to_vec()),
        ),
    };
    transaction.execute(
        "INSERT INTO home_handoff_proposals(proposal_id,handoff_id,case_revision,preparation_id,workspace_id,predecessor_assignment_id,root_assignment_id,request_digest,request_snapshot,source_digest,source_snapshot,prepared_outcome_digest,evidence_kind,artifact_id,artifact_digest,created_at_ms,payload_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        params![
            request.proposal_id().as_bytes(),
            request.handoff_id().as_bytes(),
            record.case_revision(),
            request.preparation_id().as_bytes(),
            source.workspace_id().into_uuid().as_bytes(),
            source.assignment_id().into_uuid().as_bytes(),
            source.root_assignment_id().into_uuid().as_bytes(),
            request.request_digest().as_bytes(),
            request_snapshot,
            source_digest.as_slice(),
            source_snapshot,
            record.prepared_outcome_digest().as_slice(),
            evidence_kind,
            artifact_id,
            artifact_digest,
            record.created_at().get(),
            record.payload_digest().as_slice(),
        ],
    )?;
    Ok(())
}

fn insert_head(
    transaction: &Transaction<'_>,
    record: &HomeHandoffProposalRecord,
) -> Result<(), Error> {
    transaction.execute(
        "INSERT INTO home_handoff_proposal_heads(handoff_id,case_revision,proposal_id,updated_at_ms) VALUES(?1,?2,?3,?4)",
        params![
            record.request().handoff_id().as_bytes(),
            record.case_revision(),
            record.request().proposal_id().as_bytes(),
            record.created_at().get(),
        ],
    )?;
    Ok(())
}

fn update_head(
    transaction: &Transaction<'_>,
    record: &HomeHandoffProposalRecord,
    expected: HeadPointer,
) -> Result<(), Error> {
    let changed = transaction.execute(
        "UPDATE home_handoff_proposal_heads SET case_revision=?1,proposal_id=?2,updated_at_ms=?3 WHERE handoff_id=?4 AND case_revision=?5 AND proposal_id=?6",
        params![
            record.case_revision(),
            record.request().proposal_id().as_bytes(),
            record.created_at().get(),
            record.request().handoff_id().as_bytes(),
            expected.case_revision,
            expected.proposal_id.as_bytes(),
        ],
    )?;
    if changed != 1 {
        return Err(Error::Conflict("proposal head compare-and-set failed"));
    }
    Ok(())
}

fn load_case(connection: &Connection, handoff_id: Uuid) -> Result<Option<CaseIdentity>, Error> {
    let raw: Option<RawCase> = connection
        .query_row(
            "SELECT substr(handoff_id,1,17),length(handoff_id),substr(preparation_id,1,17),length(preparation_id),substr(workspace_id,1,17),length(workspace_id),substr(predecessor_assignment_id,1,17),length(predecessor_assignment_id),substr(root_assignment_id,1,17),length(root_assignment_id),opened_at_ms FROM home_handoff_cases WHERE handoff_id=?1",
            params![handoff_id.as_bytes()],
            |row| {
                Ok(RawCase {
                    handoff_id: row.get(0)?,
                    handoff_id_len: row.get(1)?,
                    preparation_id: row.get(2)?,
                    preparation_id_len: row.get(3)?,
                    workspace_id: row.get(4)?,
                    workspace_id_len: row.get(5)?,
                    predecessor_id: row.get(6)?,
                    predecessor_id_len: row.get(7)?,
                    root_assignment_id: row.get(8)?,
                    root_assignment_id_len: row.get(9)?,
                    opened_at_ms: row.get(10)?,
                })
            },
        )
        .optional()?;
    raw.map(decode_case).transpose()
}

#[derive(Debug)]
struct RawCase {
    handoff_id: Vec<u8>,
    handoff_id_len: i64,
    preparation_id: Vec<u8>,
    preparation_id_len: i64,
    workspace_id: Vec<u8>,
    workspace_id_len: i64,
    predecessor_id: Vec<u8>,
    predecessor_id_len: i64,
    root_assignment_id: Vec<u8>,
    root_assignment_id_len: i64,
    opened_at_ms: i64,
}

fn decode_case(raw: RawCase) -> Result<CaseIdentity, Error> {
    if raw.handoff_id_len != 16
        || raw.preparation_id_len != 16
        || raw.workspace_id_len != 16
        || raw.predecessor_id_len != 16
        || raw.root_assignment_id_len != 16
    {
        return Err(Error::Corrupt("case identity width"));
    }
    Ok(CaseIdentity {
        handoff_id: decode_uuid(&raw.handoff_id, "case handoff ID")?,
        preparation_id: decode_uuid(&raw.preparation_id, "case preparation ID")?,
        workspace_id: forge_domain::WorkspaceId::from_uuid(decode_uuid(
            &raw.workspace_id,
            "case Workspace ID",
        )?),
        predecessor_id: AgentAssignmentId::from_uuid(decode_uuid(
            &raw.predecessor_id,
            "case predecessor ID",
        )?),
        root_assignment_id: AgentAssignmentId::from_uuid(decode_uuid(
            &raw.root_assignment_id,
            "case root ID",
        )?),
        opened_at: timestamp(raw.opened_at_ms, "case opened_at")?,
    })
}

fn load_head(connection: &Connection, handoff_id: Uuid) -> Result<Option<HeadPointer>, Error> {
    let raw: Option<(i64, Vec<u8>, i64, i64)> = connection
        .query_row(
            "SELECT case_revision,substr(proposal_id,1,17),length(proposal_id),updated_at_ms FROM home_handoff_proposal_heads WHERE handoff_id=?1",
            params![handoff_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    raw.map(
        |(case_revision, proposal_id, proposal_id_len, updated_at_ms)| {
            if case_revision < 1 || proposal_id_len != 16 {
                return Err(Error::Corrupt("proposal head identity"));
            }
            Ok(HeadPointer {
                case_revision,
                proposal_id: decode_uuid(&proposal_id, "head proposal ID")?,
                updated_at: timestamp(updated_at_ms, "head updated_at")?,
            })
        },
    )
    .transpose()
}

fn load_proposal_by_id(
    connection: &Connection,
    proposal_id: Uuid,
) -> Result<Option<HomeHandoffProposalRecord>, Error> {
    let raw = connection
        .query_row(
            "SELECT substr(proposal_id,1,17),length(proposal_id),substr(handoff_id,1,17),length(handoff_id),case_revision,substr(preparation_id,1,17),length(preparation_id),substr(workspace_id,1,17),length(workspace_id),substr(predecessor_assignment_id,1,17),length(predecessor_assignment_id),substr(root_assignment_id,1,17),length(root_assignment_id),substr(request_digest,1,33),length(request_digest),substr(request_snapshot,1,321),length(request_snapshot),substr(source_digest,1,33),length(source_digest),substr(source_snapshot,1,513),length(source_snapshot),substr(prepared_outcome_digest,1,33),length(prepared_outcome_digest),evidence_kind,substr(artifact_id,1,17),length(artifact_id),substr(artifact_digest,1,33),length(artifact_digest),created_at_ms,substr(payload_digest,1,33),length(payload_digest) FROM home_handoff_proposals WHERE proposal_id=?1",
            params![proposal_id.as_bytes()],
            |row| {
                Ok(RawProposal {
                    proposal_id: row.get(0)?,
                    proposal_id_len: row.get(1)?,
                    handoff_id: row.get(2)?,
                    handoff_id_len: row.get(3)?,
                    case_revision: row.get(4)?,
                    preparation_id: row.get(5)?,
                    preparation_id_len: row.get(6)?,
                    workspace_id: row.get(7)?,
                    workspace_id_len: row.get(8)?,
                    predecessor_id: row.get(9)?,
                    predecessor_id_len: row.get(10)?,
                    root_assignment_id: row.get(11)?,
                    root_assignment_id_len: row.get(12)?,
                    request_digest: row.get(13)?,
                    request_digest_len: row.get(14)?,
                    request_snapshot: row.get(15)?,
                    request_snapshot_len: row.get(16)?,
                    source_digest: row.get(17)?,
                    source_digest_len: row.get(18)?,
                    source_snapshot: row.get(19)?,
                    source_snapshot_len: row.get(20)?,
                    prepared_outcome_digest: row.get(21)?,
                    prepared_outcome_digest_len: row.get(22)?,
                    evidence_kind: row.get(23)?,
                    artifact_id: row.get(24)?,
                    artifact_id_len: row.get(25)?,
                    artifact_digest: row.get(26)?,
                    artifact_digest_len: row.get(27)?,
                    created_at_ms: row.get(28)?,
                    payload_digest: row.get(29)?,
                    payload_digest_len: row.get(30)?,
                })
            },
        )
        .optional()?;
    raw.map(decode_proposal).transpose()
}

fn decode_proposal(raw: RawProposal) -> Result<HomeHandoffProposalRecord, Error> {
    if raw.proposal_id_len != 16
        || raw.handoff_id_len != 16
        || raw.preparation_id_len != 16
        || raw.workspace_id_len != 16
        || raw.predecessor_id_len != 16
        || raw.root_assignment_id_len != 16
        || raw.case_revision < 1
        || raw.request_digest_len != 32
        || raw.request_snapshot_len < 1
        || raw.request_snapshot_len > 320
        || raw.source_digest_len != 32
        || raw.source_snapshot_len < 1
        || raw.source_snapshot_len > 512
        || raw.prepared_outcome_digest_len != 32
        || raw.payload_digest_len != 32
        || !matches!(
            (
                raw.evidence_kind,
                raw.artifact_id_len,
                raw.artifact_digest_len
            ),
            (0, None, None) | (1, Some(16), Some(32))
        )
    {
        return Err(Error::Corrupt("proposal row shape or bound"));
    }
    let evidence = proposal_codec::persisted_evidence(
        raw.evidence_kind,
        raw.artifact_id.as_deref(),
        raw.artifact_digest.as_deref(),
    )?;
    let record = proposal_codec::decode_record(
        &raw.request_snapshot,
        &raw.request_digest,
        raw.case_revision,
        &raw.source_snapshot,
        &raw.source_digest,
        &raw.prepared_outcome_digest,
        evidence,
        raw.created_at_ms,
        &raw.payload_digest,
    )?;
    let request = record.request();
    if decode_uuid(&raw.proposal_id, "proposal ID")? != request.proposal_id()
        || decode_uuid(&raw.handoff_id, "proposal handoff ID")? != request.handoff_id()
        || decode_uuid(&raw.preparation_id, "proposal preparation ID")? != request.preparation_id()
        || forge_domain::WorkspaceId::from_uuid(decode_uuid(
            &raw.workspace_id,
            "proposal Workspace ID",
        )?) != record.source().workspace_id()
        || AgentAssignmentId::from_uuid(decode_uuid(
            &raw.predecessor_id,
            "proposal predecessor ID",
        )?) != record.source().assignment_id()
        || AgentAssignmentId::from_uuid(decode_uuid(&raw.root_assignment_id, "proposal root ID")?)
            != record.source().root_assignment_id()
    {
        return Err(Error::Corrupt(
            "proposal indexed identity differs from payload",
        ));
    }
    Ok(record)
}

fn timestamp(value: i64, field: &'static str) -> Result<TimestampMillis, Error> {
    TimestampMillis::new(value).map_err(|_| Error::Corrupt(field))
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, Error> {
    Uuid::from_slice(bytes).map_err(|_| Error::Corrupt(field))
}
