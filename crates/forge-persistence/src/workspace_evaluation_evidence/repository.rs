use std::error::Error;

use forge_domain::{
    ActivityId, AgentAssignmentCoordinator, AgentAssignmentId, AgentAssignmentOrigin,
    AgentAssignmentRevision, AgentAssignmentSourceRef, AgentAssignmentState, AgentInstanceId,
    AgentSessionId, EvaluationAdmissionTiming, EvaluationClockReading, EvaluationClockUncertainty,
    EvaluationCoverageUnknownReason, EvaluationCutId, EvaluationDigest, EvaluationManifestId,
    EvaluationManifestMember, EvaluationManifestProposal, EvaluationObligationId,
    EvaluationOriginalAssignmentBinding, EvaluationOriginalBindingStatus, EvaluationPlanBinding,
    EvaluationPlanId, EvaluationRegisteredManifest, EvaluationRegisteredManifestMember,
    EvaluationReviewCut, EvaluationReviewCutId, EvaluationReviewCutMember, EvaluationReviewOutcome,
    EvaluationReviewReceipt, EvaluationReviewState, EvaluationRevision, EvaluationSourceIdentity,
    EvaluationSourceSequence, EvaluationSubmissionReceipt, EvaluationT1CloseRequest,
    EvaluationT1Coverage, EvaluationT1CoverageCut, EvaluationT1CoverageMember,
    EvaluationWorkUnitId, ForgeBackendId, GoalEvidenceRef, MAX_EVALUATION_MANIFEST_MEMBERS,
    RegisteredAgentAssignment, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::EvaluationEvidenceStoreError;

const SOURCE_DIGEST_DOMAIN: &[u8] = b"heterarchy-forge.assignment-submitted.sources.v1\0";
const BINDING_DIGEST_DOMAIN: &[u8] = b"forge-source-evaluation-original-binding-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EvaluationT1ClosureOutcome {
    NotClosed(EvaluationAdmissionTiming),
    Closed(EvaluationT1CoverageCut),
}

#[derive(Debug)]
struct OriginalBindingRow {
    source: EvaluationSourceIdentity,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
    assignment_revision: AgentAssignmentRevision,
    goal_id: Uuid,
    dag_revision: i64,
    node_id: Uuid,
    node_revision: i64,
    work_unit_id: EvaluationWorkUnitId,
    obligation_id: EvaluationObligationId,
    criteria_digest: EvaluationDigest,
    binding_digest: EvaluationDigest,
    source_sequence: EvaluationSourceSequence,
}

#[derive(Debug)]
struct RawManifestMember {
    assignment_id: Vec<u8>,
    work_unit_id: Vec<u8>,
    obligation_id: Vec<u8>,
    assignment_revision: i64,
    target_agent_id: Vec<u8>,
    target_session_id: Vec<u8>,
    criteria_digest: Vec<u8>,
    binding_status: i64,
    binding_assignment_id: Option<Vec<u8>>,
    binding_digest: Option<Vec<u8>>,
    binding_sequence: Option<i64>,
}

#[derive(Debug)]
struct RawManifestDeclaration {
    assignment_id: Vec<u8>,
    work_unit_id: Vec<u8>,
    obligation_id: Vec<u8>,
    assignment_revision: i64,
    target_agent_id: Vec<u8>,
    target_session_id: Vec<u8>,
    criteria_digest: Vec<u8>,
}

#[derive(Debug)]
struct RawRegisteredManifest {
    backend_id: Vec<u8>,
    activity_id: Vec<u8>,
    delegation_migration_id: Vec<u8>,
    delegation_destination_id: Vec<u8>,
    delegation_freeze_revision: i64,
    delegation_manifest_digest: Vec<u8>,
    plan_id: Vec<u8>,
    plan_revision: i64,
    plan_digest: Vec<u8>,
    deadline_ms: i64,
    manifest_digest: Vec<u8>,
    sealed_sequence: i64,
    seal_time_status: i64,
    sealed_at_ms: Option<i64>,
}

#[derive(Debug)]
struct RawAssignmentMembershipSource {
    backend_id: Vec<u8>,
    activity_id: Vec<u8>,
    delegation_migration_id: Vec<u8>,
    delegation_destination_id: Vec<u8>,
    delegation_freeze_revision: i64,
    delegation_manifest_digest: Vec<u8>,
    target_agent_id: Vec<u8>,
    target_session_id: Vec<u8>,
}

#[derive(Debug)]
struct RawOriginalBinding {
    backend_id: Vec<u8>,
    activity_id: Vec<u8>,
    delegation_migration_id: Vec<u8>,
    delegation_destination_id: Vec<u8>,
    delegation_freeze_revision: i64,
    delegation_manifest_digest: Vec<u8>,
    target_agent_id: Vec<u8>,
    target_session_id: Vec<u8>,
    assignment_revision: i64,
    goal_id: Vec<u8>,
    dag_revision: i64,
    node_id: Vec<u8>,
    node_revision: i64,
    work_unit_id: Vec<u8>,
    obligation_id: Vec<u8>,
    criteria_digest: Vec<u8>,
    binding_digest: Vec<u8>,
    binding_sequence: i64,
}

#[derive(Debug)]
struct RawSubmissionReceipt {
    author_agent_id: Vec<u8>,
    author_session_id: Vec<u8>,
    original_binding_digest: Option<Vec<u8>>,
    criteria_digest: Option<Vec<u8>>,
    source_sequence: i64,
    admission_time_status: i64,
    admitted_at_ms: Option<i64>,
    result_digest: Vec<u8>,
    sources_digest: Option<Vec<u8>>,
}

#[derive(Debug)]
struct RawReviewReceipt {
    source_sequence: i64,
    outcome: i64,
    author_agent_id: Vec<u8>,
    author_session_id: Vec<u8>,
    reviewer_agent_id: Vec<u8>,
    reviewer_session_id: Vec<u8>,
    result_digest: Vec<u8>,
    review_time_status: i64,
    reviewed_at_ms: Option<i64>,
}

#[derive(Debug)]
struct RawT1CutHeader {
    manifest_id: Vec<u8>,
    manifest_revision: i64,
    manifest_digest: Vec<u8>,
    deadline_ms: i64,
    closed_at_ms: i64,
    source_high_water: i64,
}

#[derive(Debug)]
struct RawT1CutMember {
    assignment_id: Vec<u8>,
    coverage_status: i64,
    submitted_revision: Option<i64>,
    receipt_sequence: Option<i64>,
    unknown_reason: Option<i64>,
}

#[derive(Debug)]
struct RawReviewCutHeader {
    t1_cut_id: Vec<u8>,
    source_high_water: i64,
    cut_time_status: i64,
    cut_at_ms: Option<i64>,
}

#[derive(Debug)]
struct RawReviewCutMember {
    assignment_id: Vec<u8>,
    coverage_status: i64,
    submitted_revision: Option<i64>,
    review_status: i64,
    review_revision: Option<i64>,
    review_sequence: Option<i64>,
    reviewer_agent_id: Option<Vec<u8>>,
    reviewer_session_id: Option<Vec<u8>>,
    result_digest: Option<Vec<u8>>,
    unknown_reason: Option<i64>,
}

#[derive(Debug)]
struct T1CutMemberInsert {
    assignment_id: AgentAssignmentId,
    coverage_status: i64,
    submitted_revision: Option<i64>,
    receipt_sequence: Option<i64>,
    unknown_reason: Option<i64>,
}

#[derive(Debug)]
struct EvaluatedT1Member {
    member: EvaluationT1CoverageMember,
    insert: T1CutMemberInsert,
}

#[derive(Debug, Clone, Copy)]
struct T1CutHeader {
    workspace_id: WorkspaceId,
    cut_id: EvaluationCutId,
    manifest_id: EvaluationManifestId,
    manifest_revision: EvaluationRevision,
    manifest_digest: EvaluationDigest,
    deadline: TimestampMillis,
    closed_at: TimestampMillis,
    source_high_water: EvaluationSourceSequence,
}

#[derive(Debug, Clone, Copy)]
struct T1EvaluationContext {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    deadline: TimestampMillis,
    source_high_water: EvaluationSourceSequence,
    clock: ClockState,
}

#[derive(Debug, Clone, Copy)]
struct SubmissionEvidencePayload {
    binding_commitment: Option<EvaluationDigest>,
    criteria_commitment: Option<EvaluationDigest>,
    report_fingerprint: EvaluationDigest,
    source_fingerprint: Option<EvaluationDigest>,
}

#[derive(Debug, Clone, Copy)]
struct ReviewEvidencePayload {
    submission: EvaluationSubmissionReceipt,
    outcome: EvaluationReviewOutcome,
    reviewer: AgentAssignmentCoordinator,
    result_digest: EvaluationDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClockState {
    source_sequence: i64,
    health: i64,
    last_trusted_at_ms: Option<i64>,
    last_uncertainty_sequence: Option<i64>,
}

pub(crate) fn seal_manifest_in_transaction<LookupError, Lookup, Clock>(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    proposal: &EvaluationManifestProposal,
    mut lookup_assignment: Lookup,
    sample_clock: Clock,
) -> Result<EvaluationRegisteredManifest, EvaluationEvidenceStoreError>
where
    LookupError: Error + Send + Sync + 'static,
    Lookup: FnMut(
        &Transaction<'_>,
        AgentAssignmentId,
    ) -> Result<Option<RegisteredAgentAssignment>, LookupError>,
    Clock: FnOnce() -> EvaluationClockReading,
{
    super::schema::validate_schema(transaction)?;
    validate_active_source(transaction, actual_backend, proposal.source())?;
    ensure_source_state(transaction, proposal.source().workspace_id())?;

    if let Some(existing) =
        load_registered_manifest(transaction, proposal.manifest_id(), proposal.revision())?
    {
        if existing.proposal() != proposal {
            return Err(EvaluationEvidenceStoreError::ManifestConflict);
        }
        return Ok(existing);
    }
    let assignments = load_source_assignments(transaction, proposal, &mut lookup_assignment)?;
    let (existing_bindings, needs_new_binding) =
        resolve_original_bindings(transaction, proposal, &assignments)?;
    let binding_sequence = needs_new_binding
        .then(|| next_source_sequence(transaction, proposal.source().workspace_id()))
        .transpose()?;
    let member_records = seal_manifest_members(
        transaction,
        proposal,
        &assignments,
        existing_bindings,
        binding_sequence,
    )?;
    let (seal_sequence, seal_timing) = persist_manifest_header_and_members(
        transaction,
        proposal,
        &member_records,
        sample_clock(),
    )?;
    EvaluationRegisteredManifest::from_source_records(
        proposal.clone(),
        member_records,
        seal_sequence,
        seal_timing,
    )
    .map_err(Into::into)
}

fn load_source_assignments<LookupError, Lookup>(
    transaction: &Transaction<'_>,
    proposal: &EvaluationManifestProposal,
    lookup_assignment: &mut Lookup,
) -> Result<Vec<RegisteredAgentAssignment>, EvaluationEvidenceStoreError>
where
    LookupError: Error + Send + Sync + 'static,
    Lookup: FnMut(
        &Transaction<'_>,
        AgentAssignmentId,
    ) -> Result<Option<RegisteredAgentAssignment>, LookupError>,
{
    let mut assignments = Vec::with_capacity(proposal.members().len());
    for member in proposal.members() {
        let assignment = lookup_assignment(transaction, member.assignment_id())
            .map_err(|error| EvaluationEvidenceStoreError::AssignmentLookup(Box::new(error)))?
            .ok_or(EvaluationEvidenceStoreError::AssignmentNotFound)?;
        validate_assignment_scope(&assignment, proposal.source(), member)?;
        if assignment.origin() != AgentAssignmentOrigin::CoordinatorOffer {
            return Err(EvaluationEvidenceStoreError::InvalidOriginalAssignment);
        }
        assignments.push(assignment);
    }
    Ok(assignments)
}

fn resolve_original_bindings(
    transaction: &Transaction<'_>,
    proposal: &EvaluationManifestProposal,
    assignments: &[RegisteredAgentAssignment],
) -> Result<(Vec<Option<OriginalBindingRow>>, bool), EvaluationEvidenceStoreError> {
    let mut existing_bindings = Vec::with_capacity(proposal.members().len());
    let mut needs_new_binding = false;
    for (member, assignment) in proposal.members().iter().zip(assignments) {
        if let Some(binding) = load_original_binding(
            transaction,
            proposal.source().workspace_id(),
            member.assignment_id(),
        )? {
            validate_binding_reuse(&binding, proposal.source(), member, assignment)?;
            existing_bindings.push(Some(binding));
            continue;
        }
        let existing_unit = load_binding_by_unit(
            transaction,
            proposal.source().workspace_id(),
            member.work_unit_id(),
        )?;
        if let Some(existing_unit) = existing_unit
            && existing_unit.0 != member.assignment_id()
        {
            return Err(EvaluationEvidenceStoreError::OriginalBindingConflict);
        }
        if assignment.revision() != member.assignment_revision() {
            return Err(EvaluationEvidenceStoreError::AssignmentRevisionConflict);
        }
        needs_new_binding |= is_prework_original(assignment);
        existing_bindings.push(None);
    }
    Ok((existing_bindings, needs_new_binding))
}

fn is_prework_original(assignment: &RegisteredAgentAssignment) -> bool {
    assignment.state() == AgentAssignmentState::Offered
        && assignment.result().is_none()
        && assignment.reviewed_by().is_none()
}

fn seal_manifest_members(
    transaction: &Transaction<'_>,
    proposal: &EvaluationManifestProposal,
    assignments: &[RegisteredAgentAssignment],
    existing_bindings: Vec<Option<OriginalBindingRow>>,
    binding_sequence: Option<EvaluationSourceSequence>,
) -> Result<Vec<EvaluationRegisteredManifestMember>, EvaluationEvidenceStoreError> {
    let mut members = Vec::with_capacity(proposal.members().len());
    for ((member, assignment), existing) in proposal
        .members()
        .iter()
        .zip(assignments)
        .zip(existing_bindings)
    {
        let binding = match (existing, is_prework_original(assignment)) {
            (Some(existing), _) => {
                EvaluationOriginalBindingStatus::Bound(EvaluationOriginalAssignmentBinding::new(
                    existing.binding_digest,
                    existing.assignment_revision,
                    existing.source_sequence,
                ))
            }
            (None, true) => {
                let sequence = binding_sequence.ok_or(
                    EvaluationEvidenceStoreError::CorruptRecord("original_binding.sequence"),
                )?;
                let digest = original_binding_digest(proposal.source(), member, assignment)?;
                insert_original_binding(
                    transaction,
                    proposal.source(),
                    member,
                    assignment,
                    digest,
                    sequence,
                )?;
                EvaluationOriginalBindingStatus::Bound(EvaluationOriginalAssignmentBinding::new(
                    digest,
                    member.assignment_revision(),
                    sequence,
                ))
            }
            (None, false) => EvaluationOriginalBindingStatus::UnknownHistorical,
        };
        members.push(EvaluationRegisteredManifestMember::new(*member, binding));
    }
    Ok(members)
}

fn persist_manifest_header_and_members(
    transaction: &Transaction<'_>,
    proposal: &EvaluationManifestProposal,
    members: &[EvaluationRegisteredManifestMember],
    clock_reading: EvaluationClockReading,
) -> Result<(EvaluationSourceSequence, EvaluationAdmissionTiming), EvaluationEvidenceStoreError> {
    let workspace_id = proposal.source().workspace_id();
    let sequence = next_source_sequence(transaction, workspace_id)?;
    let timing = observe_clock(transaction, workspace_id, sequence, clock_reading)?;
    insert_manifest_header(transaction, proposal, sequence, timing)?;
    for member in members {
        insert_manifest_member(transaction, proposal, *member)?;
    }
    Ok((sequence, timing))
}

fn validate_assignment_scope(
    assignment: &RegisteredAgentAssignment,
    source: EvaluationSourceIdentity,
    member: &EvaluationManifestMember,
) -> Result<(), EvaluationEvidenceStoreError> {
    if assignment.id() != member.assignment_id()
        || assignment.workspace_id() != source.workspace_id()
        || assignment.activity_id() != source.activity_id()
        || assignment.target().agent_id() != member.target_agent_id()
        || assignment.target().session_id() != member.target_session_id()
    {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(())
}

fn validate_active_source(
    connection: &Connection,
    actual_backend: ForgeBackendId,
    source: EvaluationSourceIdentity,
) -> Result<(), EvaluationEvidenceStoreError> {
    if actual_backend != source.backend_id() {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    let delegation = crate::workspace_agent_delegation::get(connection, source.workspace_id())
        .map_err(|error| EvaluationEvidenceStoreError::SourceDelegation(Box::new(error)))?
        .ok_or(EvaluationEvidenceStoreError::MissingDelegation)?;
    let freeze_revision = i64::try_from(delegation.freeze().revision());
    if delegation.workspace_id() != source.workspace_id()
        || delegation.migration_id() != source.delegation_migration_id()
        || delegation.destination_id() != source.delegation_destination_id()
        || freeze_revision.ok() != Some(source.delegation_freeze_revision().get())
        || delegation.manifest_digest() != source.delegation_manifest_digest().into_bytes()
    {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(())
}

fn ensure_source_state(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), EvaluationEvidenceStoreError> {
    connection.execute(
        "INSERT OR IGNORE INTO workspace_evaluation_source_state(workspace_id, source_sequence, clock_health, last_trusted_at_ms, last_uncertainty_sequence) VALUES(?1, 0, 0, NULL, NULL)",
        params![workspace_id.into_uuid().as_bytes()],
    )?;
    Ok(())
}

pub(crate) fn assignment_requires_source_clock_in_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
) -> Result<bool, EvaluationEvidenceStoreError> {
    super::schema::validate_schema(transaction)?;
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM workspace_evaluation_original_bindings WHERE workspace_id = ?1 AND assignment_id = ?2) OR EXISTS(SELECT 1 FROM workspace_evaluation_manifest_members WHERE workspace_id = ?1 AND assignment_id = ?2)",
            params![workspace_id.into_uuid().as_bytes(), assignment_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn next_source_sequence(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<EvaluationSourceSequence, EvaluationEvidenceStoreError> {
    ensure_source_state(connection, workspace_id)?;
    let current: i64 = connection.query_row(
        "SELECT source_sequence FROM workspace_evaluation_source_state WHERE workspace_id = ?1",
        params![workspace_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    let next = current
        .checked_add(1)
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "source.sequence_overflow",
        ))?;
    let changed = connection.execute(
        "UPDATE workspace_evaluation_source_state SET source_sequence = ?1 WHERE workspace_id = ?2 AND source_sequence = ?3",
        params![next, workspace_id.into_uuid().as_bytes(), current],
    )?;
    if changed != 1 {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "source.sequence_cas",
        ));
    }
    EvaluationSourceSequence::new(next).map_err(Into::into)
}

fn clock_state(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<ClockState, EvaluationEvidenceStoreError> {
    let state = connection
        .query_row(
            "SELECT source_sequence, clock_health, last_trusted_at_ms, last_uncertainty_sequence FROM workspace_evaluation_source_state WHERE workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| Ok(ClockState {
                source_sequence: row.get(0)?,
                health: row.get(1)?,
                last_trusted_at_ms: row.get(2)?,
                last_uncertainty_sequence: row.get(3)?,
            }),
        )
        .optional()?
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "source.clock_state",
        ))?;
    let valid = match state.health {
        0 => state.last_trusted_at_ms.is_none() && state.last_uncertainty_sequence.is_none(),
        1 => state.last_trusted_at_ms.is_some(),
        2 => state.last_uncertainty_sequence.is_some(),
        _ => false,
    };
    if !valid
        || state
            .last_uncertainty_sequence
            .is_some_and(|sequence| sequence > state.source_sequence)
    {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "source.clock_state_shape",
        ));
    }
    Ok(state)
}

/// The owner calls this only after its IMMEDIATE transaction has acquired the
/// write lock and the mutation command has passed exact scope/CAS validation.
fn observe_clock(
    connection: &Connection,
    workspace_id: WorkspaceId,
    sequence: EvaluationSourceSequence,
    reading: EvaluationClockReading,
) -> Result<EvaluationAdmissionTiming, EvaluationEvidenceStoreError> {
    let state = clock_state(connection, workspace_id)?;
    let timing = match reading {
        EvaluationClockReading::Unknown => {
            EvaluationAdmissionTiming::Unknown(EvaluationClockUncertainty::Unknown)
        }
        EvaluationClockReading::Trusted(observed_at)
            if state
                .last_trusted_at_ms
                .is_some_and(|previous| observed_at.get() < previous) =>
        {
            EvaluationAdmissionTiming::Unknown(EvaluationClockUncertainty::Regressed)
        }
        EvaluationClockReading::Trusted(observed_at) => {
            connection.execute(
                "UPDATE workspace_evaluation_source_state SET clock_health = 1, last_trusted_at_ms = ?1 WHERE workspace_id = ?2",
                params![observed_at.get(), workspace_id.into_uuid().as_bytes()],
            )?;
            EvaluationAdmissionTiming::Trusted(observed_at)
        }
    };
    if let EvaluationAdmissionTiming::Unknown(_) = timing {
        connection.execute(
            "UPDATE workspace_evaluation_source_state SET clock_health = 2, last_uncertainty_sequence = ?1 WHERE workspace_id = ?2",
            params![sequence.get(), workspace_id.into_uuid().as_bytes()],
        )?;
    }
    Ok(timing)
}

fn load_original_binding(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
) -> Result<Option<OriginalBindingRow>, EvaluationEvidenceStoreError> {
    let raw = connection
        .query_row(
            "SELECT backend_id, activity_id, delegation_migration_id, delegation_destination_id, delegation_freeze_revision, delegation_manifest_digest, target_agent_id, target_session_id, assignment_revision, goal_id, dag_revision, node_id, node_revision, work_unit_id, obligation_id, criteria_digest, binding_digest, binding_sequence FROM workspace_evaluation_original_bindings WHERE workspace_id = ?1 AND assignment_id = ?2",
            params![workspace_id.into_uuid().as_bytes(), assignment_id.into_uuid().as_bytes()],
            |row| {
                Ok(RawOriginalBinding {
                    backend_id: row.get(0)?,
                    activity_id: row.get(1)?,
                    delegation_migration_id: row.get(2)?,
                    delegation_destination_id: row.get(3)?,
                    delegation_freeze_revision: row.get(4)?,
                    delegation_manifest_digest: row.get(5)?,
                    target_agent_id: row.get(6)?,
                    target_session_id: row.get(7)?,
                    assignment_revision: row.get(8)?,
                    goal_id: row.get(9)?,
                    dag_revision: row.get(10)?,
                    node_id: row.get(11)?,
                    node_revision: row.get(12)?,
                    work_unit_id: row.get(13)?,
                    obligation_id: row.get(14)?,
                    criteria_digest: row.get(15)?,
                    binding_digest: row.get(16)?,
                    binding_sequence: row.get(17)?,
                })
            },
        )
        .optional()?;
    raw.map(|raw| {
        let source = EvaluationSourceIdentity::new(
            ForgeBackendId::from_uuid(decode_uuid(&raw.backend_id, "binding.backend_id")?),
            workspace_id,
            ActivityId::from_uuid(decode_uuid(&raw.activity_id, "binding.activity_id")?),
            decode_uuid(
                &raw.delegation_migration_id,
                "binding.delegation_migration_id",
            )?,
            decode_uuid(
                &raw.delegation_destination_id,
                "binding.delegation_destination_id",
            )?,
            EvaluationRevision::new(raw.delegation_freeze_revision).map_err(|_| {
                EvaluationEvidenceStoreError::CorruptRecord("binding.delegation_revision")
            })?,
            decode_digest(
                &raw.delegation_manifest_digest,
                "binding.delegation_manifest_digest",
            )?,
        )?;
        Ok(OriginalBindingRow {
            source,
            target_agent_id: AgentInstanceId::from_uuid(decode_uuid(
                &raw.target_agent_id,
                "binding.target_agent_id",
            )?),
            target_session_id: AgentSessionId::from_uuid(decode_uuid(
                &raw.target_session_id,
                "binding.target_session_id",
            )?),
            assignment_revision: AgentAssignmentRevision::new(raw.assignment_revision).map_err(
                |_| EvaluationEvidenceStoreError::CorruptRecord("binding.assignment_revision"),
            )?,
            goal_id: decode_uuid(&raw.goal_id, "binding.goal_id")?,
            dag_revision: positive(raw.dag_revision, "binding.dag_revision")?,
            node_id: decode_uuid(&raw.node_id, "binding.node_id")?,
            node_revision: positive(raw.node_revision, "binding.node_revision")?,
            work_unit_id: EvaluationWorkUnitId::new(decode_uuid(
                &raw.work_unit_id,
                "binding.work_unit_id",
            )?)?,
            obligation_id: EvaluationObligationId::new(decode_uuid(
                &raw.obligation_id,
                "binding.obligation_id",
            )?)?,
            criteria_digest: decode_digest(&raw.criteria_digest, "binding.criteria_digest")?,
            binding_digest: decode_digest(&raw.binding_digest, "binding.binding_digest")?,
            source_sequence: EvaluationSourceSequence::new(raw.binding_sequence)
                .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("binding.sequence"))?,
        })
    })
    .transpose()
}

fn load_binding_by_unit(
    connection: &Connection,
    workspace_id: WorkspaceId,
    work_unit_id: EvaluationWorkUnitId,
) -> Result<Option<(AgentAssignmentId, OriginalBindingRow)>, EvaluationEvidenceStoreError> {
    let assignment_bytes = connection
        .query_row(
            "SELECT assignment_id FROM workspace_evaluation_original_bindings WHERE workspace_id = ?1 AND work_unit_id = ?2",
            params![workspace_id.into_uuid().as_bytes(), work_unit_id.into_uuid().as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(assignment_bytes) = assignment_bytes else {
        return Ok(None);
    };
    let assignment_id =
        AgentAssignmentId::from_uuid(decode_uuid(&assignment_bytes, "binding.assignment_id")?);
    let binding = load_original_binding(connection, workspace_id, assignment_id)?.ok_or(
        EvaluationEvidenceStoreError::CorruptRecord("binding.by_unit"),
    )?;
    Ok(Some((assignment_id, binding)))
}

fn validate_binding_reuse(
    binding: &OriginalBindingRow,
    source: EvaluationSourceIdentity,
    member: &EvaluationManifestMember,
    assignment: &RegisteredAgentAssignment,
) -> Result<(), EvaluationEvidenceStoreError> {
    if binding.source != source
        || binding.assignment_revision != member.assignment_revision()
        || binding.work_unit_id != member.work_unit_id()
        || binding.obligation_id != member.obligation_id()
        || binding.criteria_digest != member.criteria_digest()
        || binding.target_agent_id != member.target_agent_id()
        || binding.target_session_id != member.target_session_id()
        || binding.goal_id != assignment.goal_id().into_uuid()
        || binding.dag_revision != assignment.dag_revision().get()
        || binding.node_id != assignment.node_id().into_uuid()
        || binding.node_revision != assignment.node_revision().get()
        || assignment.revision().get() < binding.assignment_revision.get()
        || assignment.origin() != AgentAssignmentOrigin::CoordinatorOffer
    {
        return Err(EvaluationEvidenceStoreError::OriginalBindingConflict);
    }
    Ok(())
}

fn original_binding_digest(
    source: EvaluationSourceIdentity,
    member: &EvaluationManifestMember,
    assignment: &RegisteredAgentAssignment,
) -> Result<EvaluationDigest, EvaluationEvidenceStoreError> {
    let mut hash = Sha256::new();
    hash.update(BINDING_DIGEST_DOMAIN);
    hash.update(source.backend_id().into_uuid().as_bytes());
    hash.update(source.workspace_id().into_uuid().as_bytes());
    hash.update(source.activity_id().into_uuid().as_bytes());
    hash.update(source.delegation_migration_id().as_bytes());
    hash.update(source.delegation_destination_id().as_bytes());
    hash.update(source.delegation_freeze_revision().get().to_be_bytes());
    hash.update(source.delegation_manifest_digest().as_bytes());
    hash.update(member.assignment_id().into_uuid().as_bytes());
    hash.update(member.assignment_revision().get().to_be_bytes());
    hash.update(member.target_agent_id().into_uuid().as_bytes());
    hash.update(member.target_session_id().into_uuid().as_bytes());
    hash.update(assignment.goal_id().into_uuid().as_bytes());
    hash.update(assignment.dag_revision().get().to_be_bytes());
    hash.update(assignment.node_id().into_uuid().as_bytes());
    hash.update(assignment.node_revision().get().to_be_bytes());
    hash.update(member.work_unit_id().into_uuid().as_bytes());
    hash.update(member.obligation_id().into_uuid().as_bytes());
    hash.update(member.criteria_digest().as_bytes());
    EvaluationDigest::new(hash.finalize().into()).map_err(Into::into)
}

fn insert_original_binding(
    connection: &Connection,
    source: EvaluationSourceIdentity,
    member: &EvaluationManifestMember,
    assignment: &RegisteredAgentAssignment,
    binding_digest: EvaluationDigest,
    source_sequence: EvaluationSourceSequence,
) -> Result<(), EvaluationEvidenceStoreError> {
    connection.execute(
        "INSERT INTO workspace_evaluation_original_bindings(workspace_id, assignment_id, backend_id, activity_id, delegation_migration_id, delegation_destination_id, delegation_freeze_revision, delegation_manifest_digest, target_agent_id, target_session_id, assignment_revision, goal_id, dag_revision, node_id, node_revision, work_unit_id, obligation_id, criteria_digest, binding_digest, binding_sequence) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            source.workspace_id().into_uuid().as_bytes(),
            member.assignment_id().into_uuid().as_bytes(),
            source.backend_id().into_uuid().as_bytes(),
            source.activity_id().into_uuid().as_bytes(),
            source.delegation_migration_id().as_bytes(),
            source.delegation_destination_id().as_bytes(),
            source.delegation_freeze_revision().get(),
            source.delegation_manifest_digest().as_bytes(),
            member.target_agent_id().into_uuid().as_bytes(),
            member.target_session_id().into_uuid().as_bytes(),
            member.assignment_revision().get(),
            assignment.goal_id().into_uuid().as_bytes(),
            assignment.dag_revision().get(),
            assignment.node_id().into_uuid().as_bytes(),
            assignment.node_revision().get(),
            member.work_unit_id().into_uuid().as_bytes(),
            member.obligation_id().into_uuid().as_bytes(),
            member.criteria_digest().as_bytes(),
            binding_digest.as_bytes(),
            source_sequence.get(),
        ],
    )?;
    Ok(())
}

fn insert_manifest_header(
    connection: &Connection,
    proposal: &EvaluationManifestProposal,
    source_sequence: EvaluationSourceSequence,
    seal_timing: EvaluationAdmissionTiming,
) -> Result<(), EvaluationEvidenceStoreError> {
    let (time_status, sealed_at_ms) = encode_timing(seal_timing);
    let source = proposal.source();
    let plan = proposal.plan();
    connection.execute(
        "INSERT INTO workspace_evaluation_manifests(workspace_id, manifest_id, manifest_revision, backend_id, activity_id, delegation_migration_id, delegation_destination_id, delegation_freeze_revision, delegation_manifest_digest, plan_id, plan_revision, plan_digest, deadline_ms, manifest_digest, sealed_sequence, seal_time_status, sealed_at_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            source.workspace_id().into_uuid().as_bytes(),
            proposal.manifest_id().into_uuid().as_bytes(),
            proposal.revision().get(),
            source.backend_id().into_uuid().as_bytes(),
            source.activity_id().into_uuid().as_bytes(),
            source.delegation_migration_id().as_bytes(),
            source.delegation_destination_id().as_bytes(),
            source.delegation_freeze_revision().get(),
            source.delegation_manifest_digest().as_bytes(),
            plan.plan_id().into_uuid().as_bytes(),
            plan.revision().get(),
            plan.digest().as_bytes(),
            proposal.deadline().get(),
            proposal.digest().as_bytes(),
            source_sequence.get(),
            time_status,
            sealed_at_ms,
        ],
    )?;
    Ok(())
}

fn insert_manifest_member(
    connection: &Connection,
    proposal: &EvaluationManifestProposal,
    member: EvaluationRegisteredManifestMember,
) -> Result<(), EvaluationEvidenceStoreError> {
    let declaration = member.declaration();
    let (binding_status, binding_assignment_id, binding_digest, binding_sequence) =
        match member.binding() {
            EvaluationOriginalBindingStatus::Bound(binding) => (
                0_i64,
                Some(
                    declaration
                        .assignment_id()
                        .into_uuid()
                        .into_bytes()
                        .to_vec(),
                ),
                Some(binding.digest().into_bytes().to_vec()),
                Some(binding.source_sequence().get()),
            ),
            EvaluationOriginalBindingStatus::UnknownHistorical => (1_i64, None, None, None),
        };
    connection.execute(
        "INSERT INTO workspace_evaluation_manifest_members(workspace_id, manifest_id, manifest_revision, assignment_id, work_unit_id, obligation_id, assignment_revision, target_agent_id, target_session_id, criteria_digest, binding_status, binding_assignment_id, binding_digest, binding_sequence) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            proposal.source().workspace_id().into_uuid().as_bytes(),
            proposal.manifest_id().into_uuid().as_bytes(),
            proposal.revision().get(),
            declaration.assignment_id().into_uuid().as_bytes(),
            declaration.work_unit_id().into_uuid().as_bytes(),
            declaration.obligation_id().into_uuid().as_bytes(),
            declaration.assignment_revision().get(),
            declaration.target_agent_id().into_uuid().as_bytes(),
            declaration.target_session_id().into_uuid().as_bytes(),
            declaration.criteria_digest().as_bytes(),
            binding_status,
            binding_assignment_id,
            binding_digest,
            binding_sequence,
        ],
    )?;
    Ok(())
}

fn load_registered_manifest(
    connection: &Connection,
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
) -> Result<Option<EvaluationRegisteredManifest>, EvaluationEvidenceStoreError> {
    let workspace_id = workspace_id(connection)?;
    let raw = connection
        .query_row(
            "SELECT backend_id, activity_id, delegation_migration_id, delegation_destination_id, delegation_freeze_revision, delegation_manifest_digest, plan_id, plan_revision, plan_digest, deadline_ms, manifest_digest, sealed_sequence, seal_time_status, sealed_at_ms FROM workspace_evaluation_manifests WHERE workspace_id = ?1 AND manifest_id = ?2 AND manifest_revision = ?3",
            params![workspace_id.into_uuid().as_bytes(), manifest_id.into_uuid().as_bytes(), revision.get()],
            |row| {
                Ok(RawRegisteredManifest {
                    backend_id: row.get(0)?,
                    activity_id: row.get(1)?,
                    delegation_migration_id: row.get(2)?,
                    delegation_destination_id: row.get(3)?,
                    delegation_freeze_revision: row.get(4)?,
                    delegation_manifest_digest: row.get(5)?,
                    plan_id: row.get(6)?,
                    plan_revision: row.get(7)?,
                    plan_digest: row.get(8)?,
                    deadline_ms: row.get(9)?,
                    manifest_digest: row.get(10)?,
                    sealed_sequence: row.get(11)?,
                    seal_time_status: row.get(12)?,
                    sealed_at_ms: row.get(13)?,
                })
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let source = EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(decode_uuid(&raw.backend_id, "manifest.backend_id")?),
        workspace_id,
        ActivityId::from_uuid(decode_uuid(&raw.activity_id, "manifest.activity_id")?),
        decode_uuid(
            &raw.delegation_migration_id,
            "manifest.delegation_migration_id",
        )?,
        decode_uuid(
            &raw.delegation_destination_id,
            "manifest.delegation_destination_id",
        )?,
        EvaluationRevision::new(raw.delegation_freeze_revision).map_err(|_| {
            EvaluationEvidenceStoreError::CorruptRecord("manifest.delegation_revision")
        })?,
        decode_digest(
            &raw.delegation_manifest_digest,
            "manifest.delegation_manifest_digest",
        )?,
    )?;
    let plan = EvaluationPlanBinding::new(
        EvaluationPlanId::new(decode_uuid(&raw.plan_id, "manifest.plan_id")?)?,
        EvaluationRevision::new(raw.plan_revision)
            .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("manifest.plan_revision"))?,
        decode_digest(&raw.plan_digest, "manifest.plan_digest")?,
    );
    let deadline = TimestampMillis::new(raw.deadline_ms)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("manifest.deadline"))?;
    let persisted_digest = decode_digest(&raw.manifest_digest, "manifest.digest")?;
    let source_sequence = EvaluationSourceSequence::new(raw.sealed_sequence)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("manifest.sealed_sequence"))?;
    let seal_timing = decode_timing(raw.seal_time_status, raw.sealed_at_ms, "manifest.seal_time")?;
    let declarations = load_manifest_declarations(connection, workspace_id, manifest_id, revision)?;
    let proposal = EvaluationManifestProposal::new(
        manifest_id,
        revision,
        source,
        plan,
        deadline,
        declarations,
    )?;
    if proposal.digest() != persisted_digest {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "manifest.digest_mismatch",
        ));
    }

    let members = load_registered_members(connection, &proposal)?;
    let registered = EvaluationRegisteredManifest::from_source_records(
        proposal,
        members,
        source_sequence,
        seal_timing,
    )?;
    Ok(Some(registered))
}

fn load_manifest_declarations(
    connection: &Connection,
    workspace_id: WorkspaceId,
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
) -> Result<Vec<EvaluationManifestMember>, EvaluationEvidenceStoreError> {
    let mut statement = connection.prepare(
        "SELECT assignment_id, work_unit_id, obligation_id, assignment_revision, target_agent_id, target_session_id, criteria_digest FROM workspace_evaluation_manifest_members WHERE workspace_id = ?1 AND manifest_id = ?2 AND manifest_revision = ?3 ORDER BY assignment_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            workspace_id.into_uuid().as_bytes(),
            manifest_id.into_uuid().as_bytes(),
            revision.get(),
            evaluation_member_query_limit()?,
        ],
        |row| {
            Ok(RawManifestDeclaration {
                assignment_id: row.get(0)?,
                work_unit_id: row.get(1)?,
                obligation_id: row.get(2)?,
                assignment_revision: row.get(3)?,
                target_agent_id: row.get(4)?,
                target_session_id: row.get(5)?,
                criteria_digest: row.get(6)?,
            })
        },
    )?;
    let mut raw_declarations = rows.collect::<Result<Vec<_>, _>>()?;
    ensure_member_query_bound(raw_declarations.len())?;
    raw_declarations.sort_unstable_by(|left, right| {
        left.work_unit_id
            .cmp(&right.work_unit_id)
            .then_with(|| left.obligation_id.cmp(&right.obligation_id))
            .then_with(|| left.assignment_id.cmp(&right.assignment_id))
    });
    raw_declarations
        .into_iter()
        .map(|raw| {
            Ok(EvaluationManifestMember::new(
                EvaluationWorkUnitId::new(decode_uuid(&raw.work_unit_id, "member.work_unit_id")?)?,
                EvaluationObligationId::new(decode_uuid(
                    &raw.obligation_id,
                    "member.obligation_id",
                )?)?,
                AgentAssignmentId::from_uuid(decode_uuid(
                    &raw.assignment_id,
                    "member.assignment_id",
                )?),
                AgentAssignmentRevision::new(raw.assignment_revision).map_err(|_| {
                    EvaluationEvidenceStoreError::CorruptRecord("member.assignment_revision")
                })?,
                AgentInstanceId::from_uuid(decode_uuid(
                    &raw.target_agent_id,
                    "member.target_agent_id",
                )?),
                AgentSessionId::from_uuid(decode_uuid(
                    &raw.target_session_id,
                    "member.target_session_id",
                )?),
                decode_digest(&raw.criteria_digest, "member.criteria_digest")?,
            )?)
        })
        .collect()
}

fn load_registered_members(
    connection: &Connection,
    proposal: &EvaluationManifestProposal,
) -> Result<Vec<EvaluationRegisteredManifestMember>, EvaluationEvidenceStoreError> {
    load_raw_manifest_members(connection, proposal)?
        .into_iter()
        .map(|raw| decode_registered_manifest_member(connection, proposal, &raw))
        .collect()
}

fn load_raw_manifest_members(
    connection: &Connection,
    proposal: &EvaluationManifestProposal,
) -> Result<Vec<RawManifestMember>, EvaluationEvidenceStoreError> {
    let mut statement = connection.prepare(
        "SELECT assignment_id, work_unit_id, obligation_id, assignment_revision, target_agent_id, target_session_id, criteria_digest, binding_status, binding_assignment_id, binding_digest, binding_sequence FROM workspace_evaluation_manifest_members WHERE workspace_id = ?1 AND manifest_id = ?2 AND manifest_revision = ?3 ORDER BY assignment_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            proposal.source().workspace_id().into_uuid().as_bytes(),
            proposal.manifest_id().into_uuid().as_bytes(),
            proposal.revision().get(),
            evaluation_member_query_limit()?,
        ],
        |row| {
            Ok(RawManifestMember {
                assignment_id: row.get(0)?,
                work_unit_id: row.get(1)?,
                obligation_id: row.get(2)?,
                assignment_revision: row.get(3)?,
                target_agent_id: row.get(4)?,
                target_session_id: row.get(5)?,
                criteria_digest: row.get(6)?,
                binding_status: row.get(7)?,
                binding_assignment_id: row.get(8)?,
                binding_digest: row.get(9)?,
                binding_sequence: row.get(10)?,
            })
        },
    )?;
    let mut members = rows.collect::<Result<Vec<_>, _>>()?;
    ensure_member_query_bound(members.len())?;
    members.sort_unstable_by(|left, right| {
        left.work_unit_id
            .cmp(&right.work_unit_id)
            .then_with(|| left.obligation_id.cmp(&right.obligation_id))
            .then_with(|| left.assignment_id.cmp(&right.assignment_id))
    });
    Ok(members)
}

fn evaluation_member_query_limit() -> Result<i64, EvaluationEvidenceStoreError> {
    let maximum = i64::try_from(MAX_EVALUATION_MANIFEST_MEMBERS)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("manifest.member_limit"))?;
    maximum
        .checked_add(1)
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "manifest.member_limit",
        ))
}

fn ensure_member_query_bound(actual: usize) -> Result<(), EvaluationEvidenceStoreError> {
    if actual > MAX_EVALUATION_MANIFEST_MEMBERS {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "evaluation.member_count",
        ));
    }
    Ok(())
}

fn decode_registered_manifest_member(
    connection: &Connection,
    proposal: &EvaluationManifestProposal,
    raw: &RawManifestMember,
) -> Result<EvaluationRegisteredManifestMember, EvaluationEvidenceStoreError> {
    let declaration = EvaluationManifestMember::new(
        EvaluationWorkUnitId::new(decode_uuid(&raw.work_unit_id, "member.work_unit_id")?)?,
        EvaluationObligationId::new(decode_uuid(&raw.obligation_id, "member.obligation_id")?)?,
        AgentAssignmentId::from_uuid(decode_uuid(&raw.assignment_id, "member.assignment_id")?),
        AgentAssignmentRevision::new(raw.assignment_revision).map_err(|_| {
            EvaluationEvidenceStoreError::CorruptRecord("member.assignment_revision")
        })?,
        AgentInstanceId::from_uuid(decode_uuid(&raw.target_agent_id, "member.target_agent_id")?),
        AgentSessionId::from_uuid(decode_uuid(
            &raw.target_session_id,
            "member.target_session_id",
        )?),
        decode_digest(&raw.criteria_digest, "member.criteria_digest")?,
    )?;
    match raw.binding_status {
        0 => {
            let binding_assignment = raw
                .binding_assignment_id
                .as_deref()
                .map(|bytes| decode_uuid(bytes, "member.binding_assignment_id"))
                .transpose()?
                .map(AgentAssignmentId::from_uuid);
            if binding_assignment != Some(declaration.assignment_id()) {
                return Err(EvaluationEvidenceStoreError::CorruptRecord(
                    "member.binding_assignment_id",
                ));
            }
            let binding = load_original_binding(
                connection,
                proposal.source().workspace_id(),
                declaration.assignment_id(),
            )?
            .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                "member.original_binding",
            ))?;
            let stored_digest = raw
                .binding_digest
                .as_deref()
                .map(|bytes| decode_digest(bytes, "member.binding_digest"))
                .transpose()?
                .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                    "member.binding_digest",
                ))?;
            let stored_sequence = raw
                .binding_sequence
                .map(EvaluationSourceSequence::new)
                .transpose()
                .map_err(|_| {
                    EvaluationEvidenceStoreError::CorruptRecord("member.binding_sequence")
                })?
                .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                    "member.binding_sequence",
                ))?;
            if binding.binding_digest != stored_digest
                || binding.source_sequence != stored_sequence
                || binding.assignment_revision != declaration.assignment_revision()
                || binding.work_unit_id != declaration.work_unit_id()
                || binding.obligation_id != declaration.obligation_id()
                || binding.target_agent_id != declaration.target_agent_id()
                || binding.target_session_id != declaration.target_session_id()
                || binding.criteria_digest != declaration.criteria_digest()
            {
                return Err(EvaluationEvidenceStoreError::CorruptRecord(
                    "member.binding_mismatch",
                ));
            }
            Ok(EvaluationRegisteredManifestMember::new(
                declaration,
                EvaluationOriginalBindingStatus::Bound(EvaluationOriginalAssignmentBinding::new(
                    stored_digest,
                    binding.assignment_revision,
                    stored_sequence,
                )),
            ))
        }
        1 if raw.binding_assignment_id.is_none()
            && raw.binding_digest.is_none()
            && raw.binding_sequence.is_none() =>
        {
            Ok(EvaluationRegisteredManifestMember::new(
                declaration,
                EvaluationOriginalBindingStatus::UnknownHistorical,
            ))
        }
        _ => Err(EvaluationEvidenceStoreError::CorruptRecord(
            "member.binding_status",
        )),
    }
}

pub(crate) fn record_submission_in_transaction<Clock>(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    previous: &RegisteredAgentAssignment,
    submitted: &RegisteredAgentAssignment,
    sample_clock: Clock,
) -> Result<Option<EvaluationSubmissionReceipt>, EvaluationEvidenceStoreError>
where
    Clock: FnOnce() -> EvaluationClockReading,
{
    if previous.origin() != AgentAssignmentOrigin::CoordinatorOffer
        || submitted.origin() != AgentAssignmentOrigin::CoordinatorOffer
    {
        return Ok(None);
    }
    if submitted.state() != AgentAssignmentState::Submitted
        || submitted.id() != previous.id()
        || submitted.workspace_id() != previous.workspace_id()
        || submitted.activity_id() != previous.activity_id()
        || submitted.goal_id() != previous.goal_id()
        || submitted.dag_revision() != previous.dag_revision()
        || submitted.node_id() != previous.node_id()
        || submitted.node_revision() != previous.node_revision()
        || submitted.target() != previous.target()
    {
        return Err(EvaluationEvidenceStoreError::InvalidOriginalAssignment);
    }
    if previous.state() != AgentAssignmentState::Offered
        && previous.state() != AgentAssignmentState::Running
    {
        return Ok(None);
    }
    if previous.revision().get().checked_add(1) != Some(submitted.revision().get())
        || previous.result().is_some()
    {
        return Err(EvaluationEvidenceStoreError::InvalidOriginalAssignment);
    }
    super::schema::validate_schema(transaction)?;
    let Some(payload) = submission_payload(transaction, actual_backend, submitted)? else {
        return Ok(None);
    };
    let submitted_revision = submitted.revision();
    if let Some(existing) = load_submission_receipt(
        transaction,
        submitted.workspace_id(),
        submitted.id(),
        submitted_revision,
    )? {
        return if receipt_matches_submission(
            existing,
            submitted,
            payload.binding_commitment,
            payload.criteria_commitment,
            payload.report_fingerprint,
            payload.source_fingerprint,
        ) {
            Ok(Some(existing))
        } else {
            Err(EvaluationEvidenceStoreError::ReceiptConflict)
        };
    }
    let source_sequence = next_source_sequence(transaction, submitted.workspace_id())?;
    let timing = observe_clock(
        transaction,
        submitted.workspace_id(),
        source_sequence,
        sample_clock(),
    )?;
    let receipt = EvaluationSubmissionReceipt::from_source_record(
        submitted.id(),
        submitted_revision,
        submitted.target().agent_id(),
        submitted.target().session_id(),
        payload.binding_commitment,
        payload.criteria_commitment,
        source_sequence,
        timing,
        payload.report_fingerprint,
        payload.source_fingerprint,
    )?;
    let (time_status, admitted_at_ms) = encode_timing(timing);
    transaction.execute(
        "INSERT INTO workspace_evaluation_submission_receipts(workspace_id, assignment_id, submitted_revision, author_agent_id, author_session_id, original_binding_digest, criteria_digest, source_sequence, admission_time_status, admitted_at_ms, result_digest, sources_digest) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            submitted.workspace_id().into_uuid().as_bytes(),
            submitted.id().into_uuid().as_bytes(),
            submitted_revision.get(),
            submitted.target().agent_id().into_uuid().as_bytes(),
            submitted.target().session_id().into_uuid().as_bytes(),
            payload.binding_commitment.map(|value| value.into_bytes().to_vec()),
            payload.criteria_commitment.map(|value| value.into_bytes().to_vec()),
            source_sequence.get(),
            time_status,
            admitted_at_ms,
            payload.report_fingerprint.as_bytes(),
            payload.source_fingerprint.map(|value| value.into_bytes().to_vec()),
        ],
    )?;
    Ok(Some(receipt))
}

fn submission_payload(
    connection: &Connection,
    actual_backend: ForgeBackendId,
    assignment: &RegisteredAgentAssignment,
) -> Result<Option<SubmissionEvidencePayload>, EvaluationEvidenceStoreError> {
    let binding = load_original_binding(connection, assignment.workspace_id(), assignment.id())?;
    let (binding_digest, criteria_digest) = if let Some(binding) = binding {
        validate_binding_assignment(&binding, assignment)?;
        validate_active_source(connection, actual_backend, binding.source)?;
        (Some(binding.binding_digest), Some(binding.criteria_digest))
    } else {
        let Some(source) = source_for_assignment_membership(
            connection,
            assignment.workspace_id(),
            assignment.id(),
            assignment.activity_id(),
            assignment.target().agent_id(),
            assignment.target().session_id(),
        )?
        else {
            return Ok(None);
        };
        validate_active_source(connection, actual_backend, source)?;
        (None, None)
    };
    let result = assignment
        .result()
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "submission.result",
        ))?;
    Ok(Some(SubmissionEvidencePayload {
        binding_commitment: binding_digest,
        criteria_commitment: criteria_digest,
        report_fingerprint: digest_result(result.report())?,
        source_fingerprint: digest_sources(result.sources())?,
    }))
}

fn validate_binding_assignment(
    binding: &OriginalBindingRow,
    assignment: &RegisteredAgentAssignment,
) -> Result<(), EvaluationEvidenceStoreError> {
    if assignment.origin() != AgentAssignmentOrigin::CoordinatorOffer
        || assignment.workspace_id() != binding.source.workspace_id()
        || assignment.activity_id() != binding.source.activity_id()
        || assignment.target().agent_id() != binding.target_agent_id
        || assignment.target().session_id() != binding.target_session_id
        || assignment.goal_id().into_uuid() != binding.goal_id
        || assignment.dag_revision().get() != binding.dag_revision
        || assignment.node_id().into_uuid() != binding.node_id
        || assignment.node_revision().get() != binding.node_revision
        || assignment.revision().get() < binding.assignment_revision.get()
    {
        return Err(EvaluationEvidenceStoreError::OriginalBindingConflict);
    }
    Ok(())
}

fn source_for_assignment_membership(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    activity_id: ActivityId,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
) -> Result<Option<EvaluationSourceIdentity>, EvaluationEvidenceStoreError> {
    let first = connection
        .query_row(
            "SELECT backend_id, activity_id, delegation_migration_id, delegation_destination_id, delegation_freeze_revision, delegation_manifest_digest, target_agent_id, target_session_id FROM workspace_evaluation_manifests m JOIN workspace_evaluation_manifest_members mm USING(workspace_id, manifest_id, manifest_revision) WHERE m.workspace_id = ?1 AND mm.assignment_id = ?2 LIMIT 1",
            params![workspace_id.into_uuid().as_bytes(), assignment_id.into_uuid().as_bytes()],
            |row| {
                Ok(RawAssignmentMembershipSource {
                    backend_id: row.get(0)?,
                    activity_id: row.get(1)?,
                    delegation_migration_id: row.get(2)?,
                    delegation_destination_id: row.get(3)?,
                    delegation_freeze_revision: row.get(4)?,
                    delegation_manifest_digest: row.get(5)?,
                    target_agent_id: row.get(6)?,
                    target_session_id: row.get(7)?,
                })
            },
        )
        .optional()?;
    let Some(first) = first else {
        return Ok(None);
    };
    let source = EvaluationSourceIdentity::new(
        ForgeBackendId::from_uuid(decode_uuid(&first.backend_id, "manifest.backend_id")?),
        workspace_id,
        activity_id,
        decode_uuid(
            &first.delegation_migration_id,
            "manifest.delegation_migration_id",
        )?,
        decode_uuid(
            &first.delegation_destination_id,
            "manifest.delegation_destination_id",
        )?,
        EvaluationRevision::new(first.delegation_freeze_revision).map_err(|_| {
            EvaluationEvidenceStoreError::CorruptRecord("manifest.delegation_revision")
        })?,
        decode_digest(
            &first.delegation_manifest_digest,
            "manifest.delegation_manifest_digest",
        )?,
    )?;
    if decode_uuid(&first.activity_id, "manifest.activity_id")? != activity_id.into_uuid() {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    if decode_uuid(&first.target_agent_id, "manifest.target_agent_id")?
        != target_agent_id.into_uuid()
        || decode_uuid(&first.target_session_id, "manifest.target_session_id")?
            != target_session_id.into_uuid()
    {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    let conflicting: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_evaluation_manifests m JOIN workspace_evaluation_manifest_members mm USING(workspace_id, manifest_id, manifest_revision) WHERE m.workspace_id = ?1 AND mm.assignment_id = ?2 AND (m.backend_id != ?3 OR m.activity_id != ?4 OR m.delegation_migration_id != ?5 OR m.delegation_destination_id != ?6 OR m.delegation_freeze_revision != ?7 OR m.delegation_manifest_digest != ?8 OR mm.target_agent_id != ?9 OR mm.target_session_id != ?10))",
        params![
            workspace_id.into_uuid().as_bytes(),
            assignment_id.into_uuid().as_bytes(),
            source.backend_id().into_uuid().as_bytes(),
            source.activity_id().into_uuid().as_bytes(),
            source.delegation_migration_id().as_bytes(),
            source.delegation_destination_id().as_bytes(),
            source.delegation_freeze_revision().get(),
            source.delegation_manifest_digest().as_bytes(),
            target_agent_id.into_uuid().as_bytes(),
            target_session_id.into_uuid().as_bytes(),
        ],
        |row| row.get(0),
    )?;
    if conflicting {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(Some(source))
}

fn receipt_matches_submission(
    receipt: EvaluationSubmissionReceipt,
    submitted: &RegisteredAgentAssignment,
    binding_digest: Option<EvaluationDigest>,
    criteria_digest: Option<EvaluationDigest>,
    result_digest: EvaluationDigest,
    sources_digest: Option<EvaluationDigest>,
) -> bool {
    receipt.assignment_id() == submitted.id()
        && receipt.submitted_revision() == submitted.revision()
        && receipt.author_agent_id() == submitted.target().agent_id()
        && receipt.author_session_id() == submitted.target().session_id()
        && receipt.original_binding_digest() == binding_digest
        && receipt.criteria_digest() == criteria_digest
        && receipt.result_digest() == result_digest
        && receipt.sources_digest() == sources_digest
}

fn load_submission_receipt(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
) -> Result<Option<EvaluationSubmissionReceipt>, EvaluationEvidenceStoreError> {
    let raw = connection
        .query_row(
            "SELECT author_agent_id, author_session_id, original_binding_digest, criteria_digest, source_sequence, admission_time_status, admitted_at_ms, result_digest, sources_digest FROM workspace_evaluation_submission_receipts WHERE workspace_id = ?1 AND assignment_id = ?2 AND submitted_revision = ?3",
            params![workspace_id.into_uuid().as_bytes(), assignment_id.into_uuid().as_bytes(), submitted_revision.get()],
            |row| {
                Ok(RawSubmissionReceipt {
                    author_agent_id: row.get(0)?,
                    author_session_id: row.get(1)?,
                    original_binding_digest: row.get(2)?,
                    criteria_digest: row.get(3)?,
                    source_sequence: row.get(4)?,
                    admission_time_status: row.get(5)?,
                    admitted_at_ms: row.get(6)?,
                    result_digest: row.get(7)?,
                    sources_digest: row.get(8)?,
                })
            },
        )
        .optional()?;
    raw.map(|raw| {
        EvaluationSubmissionReceipt::from_source_record(
            assignment_id,
            submitted_revision,
            AgentInstanceId::from_uuid(decode_uuid(
                &raw.author_agent_id,
                "submission.author_agent_id",
            )?),
            AgentSessionId::from_uuid(decode_uuid(
                &raw.author_session_id,
                "submission.author_session_id",
            )?),
            raw.original_binding_digest
                .as_deref()
                .map(|bytes| decode_digest(bytes, "submission.binding_digest"))
                .transpose()?,
            raw.criteria_digest
                .as_deref()
                .map(|bytes| decode_digest(bytes, "submission.criteria_digest"))
                .transpose()?,
            EvaluationSourceSequence::new(raw.source_sequence).map_err(|_| {
                EvaluationEvidenceStoreError::CorruptRecord("submission.source_sequence")
            })?,
            decode_timing(
                raw.admission_time_status,
                raw.admitted_at_ms,
                "submission.admission_time",
            )?,
            decode_digest(&raw.result_digest, "submission.result_digest")?,
            raw.sources_digest
                .as_deref()
                .map(|bytes| decode_digest(bytes, "submission.sources_digest"))
                .transpose()?,
        )
        .map_err(Into::into)
    })
    .transpose()
}

fn digest_result(report: &str) -> Result<EvaluationDigest, EvaluationEvidenceStoreError> {
    EvaluationDigest::new(Sha256::digest(report.as_bytes()).into()).map_err(Into::into)
}

fn digest_sources(
    sources: &[AgentAssignmentSourceRef],
) -> Result<Option<EvaluationDigest>, EvaluationEvidenceStoreError> {
    if sources.is_empty() {
        return Ok(None);
    }
    let count = u8::try_from(sources.len())
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("submission.source_count"))?;
    let mut hash = Sha256::new();
    hash.update(SOURCE_DIGEST_DOMAIN);
    hash.update(u64::from(count).to_be_bytes());
    for source in sources {
        match source {
            AgentAssignmentSourceRef::Url(url) => {
                hash.update([0]);
                let length = u64::try_from(url.as_str().len()).map_err(|_| {
                    EvaluationEvidenceStoreError::CorruptRecord("submission.source_length")
                })?;
                hash.update(length.to_be_bytes());
                hash.update(url.as_str().as_bytes());
            }
            AgentAssignmentSourceRef::Provenance(evidence) => {
                hash.update([1]);
                hash.update(17_u64.to_be_bytes());
                let (tag, id) = match evidence {
                    GoalEvidenceRef::ChangeSet(id) => (0_u8, id.into_uuid()),
                    GoalEvidenceRef::Execution(id) => (1_u8, id.into_uuid()),
                    GoalEvidenceRef::Approval(id) => (2_u8, id.into_uuid()),
                    GoalEvidenceRef::Checkpoint(id) => (3_u8, id.into_uuid()),
                };
                hash.update([tag]);
                hash.update(id.as_bytes());
            }
        }
    }
    EvaluationDigest::new(hash.finalize().into())
        .map(Some)
        .map_err(Into::into)
}

pub(crate) fn record_review_in_transaction<Clock>(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    previous: &RegisteredAgentAssignment,
    reviewed: &RegisteredAgentAssignment,
    sample_clock: Clock,
) -> Result<Option<EvaluationReviewReceipt>, EvaluationEvidenceStoreError>
where
    Clock: FnOnce() -> EvaluationClockReading,
{
    if !matches!(
        reviewed.state(),
        AgentAssignmentState::Accepted | AgentAssignmentState::Rejected
    ) {
        return Ok(None);
    }
    super::schema::validate_schema(transaction)?;
    let Some(payload) = review_payload(transaction, actual_backend, previous, reviewed)? else {
        return Ok(None);
    };
    if let Some(existing) = load_review_receipt(
        transaction,
        reviewed.workspace_id(),
        reviewed.id(),
        payload.submission.submitted_revision(),
        reviewed.revision(),
    )? {
        return if review_receipt_matches(existing, reviewed, &payload) {
            Ok(Some(existing))
        } else {
            Err(EvaluationEvidenceStoreError::ReceiptConflict)
        };
    }
    let source_sequence = next_source_sequence(transaction, reviewed.workspace_id())?;
    let timing = observe_clock(
        transaction,
        reviewed.workspace_id(),
        source_sequence,
        sample_clock(),
    )?;
    let receipt = review_receipt_from_payload(reviewed, &payload, source_sequence)?;
    let (time_status, reviewed_at_ms) = encode_timing(timing);
    persist_review_receipt(
        transaction,
        reviewed,
        &payload,
        source_sequence,
        time_status,
        reviewed_at_ms,
    )?;
    Ok(Some(receipt))
}

fn review_payload(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    previous: &RegisteredAgentAssignment,
    reviewed: &RegisteredAgentAssignment,
) -> Result<Option<ReviewEvidencePayload>, EvaluationEvidenceStoreError> {
    if previous.origin() != AgentAssignmentOrigin::CoordinatorOffer
        || reviewed.origin() != AgentAssignmentOrigin::CoordinatorOffer
        || previous.state() != AgentAssignmentState::Submitted
    {
        return Ok(None);
    }
    if previous.id() != reviewed.id()
        || previous.workspace_id() != reviewed.workspace_id()
        || previous.activity_id() != reviewed.activity_id()
        || previous.goal_id() != reviewed.goal_id()
        || previous.dag_revision() != reviewed.dag_revision()
        || previous.node_id() != reviewed.node_id()
        || previous.node_revision() != reviewed.node_revision()
        || previous.target() != reviewed.target()
        || previous.revision().get().checked_add(1) != Some(reviewed.revision().get())
    {
        return Err(EvaluationEvidenceStoreError::InvalidOriginalAssignment);
    }
    let binding = load_original_binding(transaction, reviewed.workspace_id(), reviewed.id())?;
    if let Some(binding) = binding {
        validate_binding_assignment(&binding, reviewed)?;
        validate_active_source(transaction, actual_backend, binding.source)?;
    } else {
        let Some(source) = source_for_assignment_membership(
            transaction,
            reviewed.workspace_id(),
            reviewed.id(),
            reviewed.activity_id(),
            reviewed.target().agent_id(),
            reviewed.target().session_id(),
        )?
        else {
            return Ok(None);
        };
        validate_active_source(transaction, actual_backend, source)?;
    }
    let Some(submission) = load_submission_receipt(
        transaction,
        previous.workspace_id(),
        previous.id(),
        previous.revision(),
    )?
    else {
        return Ok(None);
    };
    let previous_result = previous
        .result()
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "review.previous_result",
        ))?;
    let reviewed_result = reviewed
        .result()
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord("review.result"))?;
    let review_authority =
        reviewed
            .reviewed_by()
            .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                "review.reviewer",
            ))?;
    let result_digest = digest_result(reviewed_result.report())?;
    if submission.submitted_revision() != previous.revision()
        || submission.author_agent_id() != previous.target().agent_id()
        || submission.author_session_id() != previous.target().session_id()
        || submission.result_digest() != digest_result(previous_result.report())?
        || result_digest != submission.result_digest()
    {
        return Err(EvaluationEvidenceStoreError::ReceiptConflict);
    }
    let outcome = match reviewed.state() {
        AgentAssignmentState::Accepted => EvaluationReviewOutcome::Accepted,
        AgentAssignmentState::Rejected => EvaluationReviewOutcome::Rejected,
        AgentAssignmentState::Offered
        | AgentAssignmentState::Running
        | AgentAssignmentState::Submitted
        | AgentAssignmentState::Cancelled
        | AgentAssignmentState::Interrupted => {
            return Err(EvaluationEvidenceStoreError::InvalidOriginalAssignment);
        }
    };
    Ok(Some(ReviewEvidencePayload {
        submission,
        outcome,
        reviewer: review_authority,
        result_digest,
    }))
}

fn review_receipt_matches(
    receipt: EvaluationReviewReceipt,
    reviewed: &RegisteredAgentAssignment,
    payload: &ReviewEvidencePayload,
) -> bool {
    receipt.assignment_id() == reviewed.id()
        && receipt.submitted_revision() == payload.submission.submitted_revision()
        && receipt.review_revision() == reviewed.revision()
        && receipt.outcome() == payload.outcome
        && receipt.author_agent_id() == payload.submission.author_agent_id()
        && receipt.author_session_id() == payload.submission.author_session_id()
        && receipt.reviewer_agent_id() == payload.reviewer.agent_id()
        && receipt.reviewer_session_id() == payload.reviewer.session_id()
        && receipt.result_digest() == payload.result_digest
}

fn review_receipt_from_payload(
    reviewed: &RegisteredAgentAssignment,
    payload: &ReviewEvidencePayload,
    source_sequence: EvaluationSourceSequence,
) -> Result<EvaluationReviewReceipt, EvaluationEvidenceStoreError> {
    EvaluationReviewReceipt::from_source_record(
        reviewed.id(),
        payload.submission.submitted_revision(),
        reviewed.revision(),
        source_sequence,
        payload.outcome,
        payload.submission.author_agent_id(),
        payload.submission.author_session_id(),
        payload.reviewer.agent_id(),
        payload.reviewer.session_id(),
        payload.result_digest,
    )
    .map_err(Into::into)
}

fn persist_review_receipt(
    transaction: &Transaction<'_>,
    reviewed: &RegisteredAgentAssignment,
    payload: &ReviewEvidencePayload,
    source_sequence: EvaluationSourceSequence,
    time_status: i64,
    reviewed_at_ms: Option<i64>,
) -> Result<(), EvaluationEvidenceStoreError> {
    let outcome_code = match payload.outcome {
        EvaluationReviewOutcome::Accepted => 0_i64,
        EvaluationReviewOutcome::Rejected => 1_i64,
    };
    transaction.execute(
        "INSERT INTO workspace_evaluation_review_receipts(workspace_id, assignment_id, submitted_revision, review_revision, source_sequence, review_time_status, reviewed_at_ms, outcome, author_agent_id, author_session_id, reviewer_agent_id, reviewer_session_id, result_digest) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            reviewed.workspace_id().into_uuid().as_bytes(),
            reviewed.id().into_uuid().as_bytes(),
            payload.submission.submitted_revision().get(),
            reviewed.revision().get(),
            source_sequence.get(),
            time_status,
            reviewed_at_ms,
            outcome_code,
            payload.submission.author_agent_id().into_uuid().as_bytes(),
            payload.submission.author_session_id().into_uuid().as_bytes(),
            payload.reviewer.agent_id().into_uuid().as_bytes(),
            payload.reviewer.session_id().into_uuid().as_bytes(),
            payload.result_digest.as_bytes(),
        ],
    )?;
    Ok(())
}

fn load_review_receipt(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
    review_revision: AgentAssignmentRevision,
) -> Result<Option<EvaluationReviewReceipt>, EvaluationEvidenceStoreError> {
    let raw = connection
        .query_row(
            "SELECT source_sequence, outcome, author_agent_id, author_session_id, reviewer_agent_id, reviewer_session_id, result_digest, review_time_status, reviewed_at_ms FROM workspace_evaluation_review_receipts WHERE workspace_id = ?1 AND assignment_id = ?2 AND submitted_revision = ?3 AND review_revision = ?4",
            params![workspace_id.into_uuid().as_bytes(), assignment_id.into_uuid().as_bytes(), submitted_revision.get(), review_revision.get()],
            |row| {
                Ok(RawReviewReceipt {
                    source_sequence: row.get(0)?,
                    outcome: row.get(1)?,
                    author_agent_id: row.get(2)?,
                    author_session_id: row.get(3)?,
                    reviewer_agent_id: row.get(4)?,
                    reviewer_session_id: row.get(5)?,
                    result_digest: row.get(6)?,
                    review_time_status: row.get(7)?,
                    reviewed_at_ms: row.get(8)?,
                })
            },
        )
        .optional()?;
    raw.map(|raw| {
        let outcome = match raw.outcome {
            0 => EvaluationReviewOutcome::Accepted,
            1 => EvaluationReviewOutcome::Rejected,
            _ => {
                return Err(EvaluationEvidenceStoreError::CorruptRecord(
                    "review.outcome",
                ));
            }
        };
        let _review_timing = decode_timing(
            raw.review_time_status,
            raw.reviewed_at_ms,
            "review.review_time",
        )?;
        EvaluationReviewReceipt::from_source_record(
            assignment_id,
            submitted_revision,
            review_revision,
            EvaluationSourceSequence::new(raw.source_sequence).map_err(|_| {
                EvaluationEvidenceStoreError::CorruptRecord("review.source_sequence")
            })?,
            outcome,
            AgentInstanceId::from_uuid(decode_uuid(
                &raw.author_agent_id,
                "review.author_agent_id",
            )?),
            AgentSessionId::from_uuid(decode_uuid(
                &raw.author_session_id,
                "review.author_session_id",
            )?),
            AgentInstanceId::from_uuid(decode_uuid(
                &raw.reviewer_agent_id,
                "review.reviewer_agent_id",
            )?),
            AgentSessionId::from_uuid(decode_uuid(
                &raw.reviewer_session_id,
                "review.reviewer_session_id",
            )?),
            decode_digest(&raw.result_digest, "review.result_digest")?,
        )
        .map_err(Into::into)
    })
    .transpose()
}

pub(crate) fn close_t1_in_transaction<LookupError, Lookup, Clock>(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    request: &EvaluationT1CloseRequest,
    mut lookup_assignment: Lookup,
    sample_clock: Clock,
) -> Result<EvaluationT1ClosureOutcome, EvaluationEvidenceStoreError>
where
    LookupError: Error + Send + Sync + 'static,
    Lookup: FnMut(
        &Transaction<'_>,
        AgentAssignmentId,
    ) -> Result<Option<RegisteredAgentAssignment>, LookupError>,
    Clock: FnOnce() -> EvaluationClockReading,
{
    let cut_id = request.cut_id();
    let manifest_id = request.manifest_id();
    let manifest_revision = request.manifest_revision();
    let manifest_digest = request.manifest_digest();
    let deadline = request.deadline();
    super::schema::validate_schema(transaction)?;
    let registered = load_registered_manifest(transaction, manifest_id, manifest_revision)?
        .ok_or(EvaluationEvidenceStoreError::RecordNotFound)?;
    if registered.proposal().digest() != manifest_digest {
        return Err(EvaluationEvidenceStoreError::ManifestConflict);
    }
    if registered.proposal().deadline() != deadline {
        return Err(EvaluationEvidenceStoreError::ManifestConflict);
    }
    validate_active_source(transaction, actual_backend, registered.proposal().source())?;
    if let Some(existing) =
        load_t1_cut_by_manifest(transaction, manifest_id, manifest_revision, deadline)?
    {
        if existing.cut_id() != cut_id {
            return Err(EvaluationEvidenceStoreError::CutConflict);
        }
        return Ok(EvaluationT1ClosureOutcome::Closed(existing));
    }
    if get_t1_cut_in_transaction(transaction, actual_backend, cut_id)?.is_some() {
        return Err(EvaluationEvidenceStoreError::CutConflict);
    }

    let workspace_id = registered.proposal().source().workspace_id();
    let source_sequence = next_source_sequence(transaction, workspace_id)?;
    let timing = observe_clock(transaction, workspace_id, source_sequence, sample_clock())?;
    let EvaluationAdmissionTiming::Trusted(closed_at) = timing else {
        return Ok(EvaluationT1ClosureOutcome::NotClosed(timing));
    };
    if closed_at <= deadline {
        return Ok(EvaluationT1ClosureOutcome::NotClosed(timing));
    }
    let clock = clock_state(transaction, workspace_id)?;
    let context = T1EvaluationContext {
        workspace_id,
        activity_id: registered.proposal().source().activity_id(),
        deadline,
        source_high_water: source_sequence,
        clock,
    };
    let evaluated = registered
        .members()
        .iter()
        .map(|member| evaluate_t1_member(transaction, &context, member, &mut lookup_assignment))
        .collect::<Result<Vec<_>, _>>()?;
    let cut_members = evaluated.iter().map(|entry| entry.member).collect();
    let header = T1CutHeader {
        workspace_id,
        cut_id,
        manifest_id,
        manifest_revision,
        manifest_digest,
        deadline,
        closed_at,
        source_high_water: source_sequence,
    };
    persist_t1_cut(transaction, &header, &evaluated)?;
    let cut = EvaluationT1CoverageCut::from_source_records(
        cut_id,
        registered.proposal(),
        deadline,
        closed_at,
        source_sequence,
        cut_members,
    )?;
    Ok(EvaluationT1ClosureOutcome::Closed(cut))
}

fn evaluate_t1_member<LookupError, Lookup>(
    transaction: &Transaction<'_>,
    context: &T1EvaluationContext,
    registered_member: &EvaluationRegisteredManifestMember,
    lookup_assignment: &mut Lookup,
) -> Result<EvaluatedT1Member, EvaluationEvidenceStoreError>
where
    LookupError: Error + Send + Sync + 'static,
    Lookup: FnMut(
        &Transaction<'_>,
        AgentAssignmentId,
    ) -> Result<Option<RegisteredAgentAssignment>, LookupError>,
{
    let member = registered_member.declaration();
    let assignment = lookup_assignment(transaction, member.assignment_id())
        .map_err(|error| EvaluationEvidenceStoreError::AssignmentLookup(Box::new(error)))?;
    let Some(assignment) = assignment else {
        let coverage = EvaluationT1Coverage::Unknown {
            reason: EvaluationCoverageUnknownReason::LegacySubmissionWithoutReceipt,
        };
        return Ok(EvaluatedT1Member {
            member: EvaluationT1CoverageMember::new(member, coverage),
            insert: encode_t1_cut_member(member.assignment_id(), coverage),
        });
    };
    validate_t1_assignment_scope(
        &assignment,
        context.workspace_id,
        context.activity_id,
        registered_member,
    )?;
    if let EvaluationOriginalBindingStatus::Bound(binding) = registered_member.binding() {
        let source_binding =
            load_original_binding(transaction, context.workspace_id, member.assignment_id())?
                .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                    "cut.original_binding",
                ))?;
        validate_binding_assignment(&source_binding, &assignment)?;
        if source_binding.binding_digest != binding.digest()
            || source_binding.source_sequence != binding.source_sequence()
        {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "cut.binding_mismatch",
            ));
        }
    }
    let receipt = load_single_submission_for_assignment(
        transaction,
        context.workspace_id,
        member.assignment_id(),
    )?;
    if receipt
        .is_some_and(|receipt| receipt.source_sequence().get() > context.source_high_water.get())
    {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut.submission_after_high_water",
        ));
    }
    let legacy_submission_without_receipt =
        receipt.is_none() && assignment_has_submission(&assignment);
    let (binding_digest, binding_sequence) = match registered_member.binding() {
        EvaluationOriginalBindingStatus::Bound(binding) => {
            (Some(binding.digest()), Some(binding.source_sequence()))
        }
        EvaluationOriginalBindingStatus::UnknownHistorical => (None, None),
    };
    let clock_uncertainty_after_binding = binding_sequence.is_some_and(|binding_sequence| {
        context
            .clock
            .last_uncertainty_sequence
            .is_some_and(|uncertain| uncertain > binding_sequence.get())
    });
    let coverage = forge_domain::classify_t1_coverage(
        member,
        binding_digest,
        legacy_submission_without_receipt,
        clock_uncertainty_after_binding,
        receipt,
        context.deadline,
    );
    Ok(EvaluatedT1Member {
        member: EvaluationT1CoverageMember::new(member, coverage),
        insert: encode_t1_cut_member(member.assignment_id(), coverage),
    })
}

fn validate_t1_assignment_scope(
    assignment: &RegisteredAgentAssignment,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    member: &EvaluationRegisteredManifestMember,
) -> Result<(), EvaluationEvidenceStoreError> {
    let declaration = member.declaration();
    if assignment.id() != declaration.assignment_id()
        || assignment.workspace_id() != workspace_id
        || assignment.activity_id() != activity_id
        || assignment.target().agent_id() != declaration.target_agent_id()
        || assignment.target().session_id() != declaration.target_session_id()
        || assignment.revision().get() < declaration.assignment_revision().get()
        || assignment.origin() != AgentAssignmentOrigin::CoordinatorOffer
    {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(())
}

fn persist_t1_cut(
    transaction: &Transaction<'_>,
    header: &T1CutHeader,
    members: &[EvaluatedT1Member],
) -> Result<(), EvaluationEvidenceStoreError> {
    transaction.execute(
        "INSERT INTO workspace_evaluation_t1_cuts(workspace_id, cut_id, manifest_id, manifest_revision, manifest_digest, deadline_ms, closed_at_ms, source_high_water) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            header.workspace_id.into_uuid().as_bytes(),
            header.cut_id.into_uuid().as_bytes(),
            header.manifest_id.into_uuid().as_bytes(),
            header.manifest_revision.get(),
            header.manifest_digest.as_bytes(),
            header.deadline.get(),
            header.closed_at.get(),
            header.source_high_water.get(),
        ],
    )?;
    for member in members {
        let row = &member.insert;
        transaction.execute(
            "INSERT INTO workspace_evaluation_t1_cut_members(workspace_id, cut_id, assignment_id, coverage_status, submitted_revision, receipt_sequence, unknown_reason) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                header.workspace_id.into_uuid().as_bytes(),
                header.cut_id.into_uuid().as_bytes(),
                row.assignment_id.into_uuid().as_bytes(),
                row.coverage_status,
                row.submitted_revision,
                row.receipt_sequence,
                row.unknown_reason,
            ],
        )?;
    }
    Ok(())
}

fn encode_t1_cut_member(
    assignment_id: AgentAssignmentId,
    coverage: EvaluationT1Coverage,
) -> T1CutMemberInsert {
    match coverage {
        EvaluationT1Coverage::Eligible {
            submitted_revision,
            receipt_sequence,
            ..
        } => T1CutMemberInsert {
            assignment_id,
            coverage_status: 0,
            submitted_revision: Some(submitted_revision.get()),
            receipt_sequence: Some(receipt_sequence.get()),
            unknown_reason: None,
        },
        EvaluationT1Coverage::NoEligibleSubmission => T1CutMemberInsert {
            assignment_id,
            coverage_status: 1,
            submitted_revision: None,
            receipt_sequence: None,
            unknown_reason: None,
        },
        EvaluationT1Coverage::Unknown { reason } => T1CutMemberInsert {
            assignment_id,
            coverage_status: 2,
            submitted_revision: None,
            receipt_sequence: None,
            unknown_reason: Some(coverage_unknown_code(reason)),
        },
    }
}

fn coverage_unknown_code(reason: EvaluationCoverageUnknownReason) -> i64 {
    match reason {
        EvaluationCoverageUnknownReason::OriginalBindingMissing => 0,
        EvaluationCoverageUnknownReason::LegacySubmissionWithoutReceipt => 1,
        EvaluationCoverageUnknownReason::SubmissionTimingUnknown => 2,
        EvaluationCoverageUnknownReason::ClockHistoryUncertain => 3,
        EvaluationCoverageUnknownReason::ReceiptBindingMismatch => 4,
    }
}

fn decode_coverage_unknown(
    value: i64,
) -> Result<EvaluationCoverageUnknownReason, EvaluationEvidenceStoreError> {
    match value {
        0 => Ok(EvaluationCoverageUnknownReason::OriginalBindingMissing),
        1 => Ok(EvaluationCoverageUnknownReason::LegacySubmissionWithoutReceipt),
        2 => Ok(EvaluationCoverageUnknownReason::SubmissionTimingUnknown),
        3 => Ok(EvaluationCoverageUnknownReason::ClockHistoryUncertain),
        4 => Ok(EvaluationCoverageUnknownReason::ReceiptBindingMismatch),
        _ => Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut.unknown_reason",
        )),
    }
}

fn assignment_has_submission(assignment: &RegisteredAgentAssignment) -> bool {
    assignment.result().is_some()
        || matches!(
            assignment.state(),
            AgentAssignmentState::Submitted
                | AgentAssignmentState::Accepted
                | AgentAssignmentState::Rejected
        )
}

fn load_single_submission_for_assignment(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
) -> Result<Option<EvaluationSubmissionReceipt>, EvaluationEvidenceStoreError> {
    let mut statement = connection.prepare(
        "SELECT submitted_revision FROM workspace_evaluation_submission_receipts WHERE workspace_id = ?1 AND assignment_id = ?2 ORDER BY source_sequence LIMIT 2",
    )?;
    let revisions = statement.query_map(
        params![
            workspace_id.into_uuid().as_bytes(),
            assignment_id.into_uuid().as_bytes()
        ],
        |row| row.get::<_, i64>(0),
    )?;
    let revisions = revisions.collect::<Result<Vec<_>, _>>()?;
    if revisions.len() > 1 {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "submission.multiple_versions",
        ));
    }
    let Some(revision) = revisions.first().copied() else {
        return Ok(None);
    };
    load_submission_receipt(
        connection,
        workspace_id,
        assignment_id,
        AgentAssignmentRevision::new(revision)
            .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("submission.revision"))?,
    )
}

pub(crate) fn get_t1_cut_in_transaction(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    cut_id: EvaluationCutId,
) -> Result<Option<EvaluationT1CoverageCut>, EvaluationEvidenceStoreError> {
    super::schema::validate_schema(transaction)?;
    let Some(cut) = load_t1_cut_by_id(transaction, cut_id)? else {
        return Ok(None);
    };
    if cut.manifest_id().into_uuid().is_nil() {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut.manifest_id",
        ));
    }
    let manifest =
        load_registered_manifest(transaction, cut.manifest_id(), cut.manifest_revision())?
            .ok_or(EvaluationEvidenceStoreError::CorruptRecord("cut.manifest"))?;
    if manifest.proposal().source().backend_id() != actual_backend
        || manifest.proposal().digest() != cut.manifest_digest()
    {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(Some(cut))
}

pub(crate) fn get_registered_manifest_in_transaction(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
) -> Result<Option<EvaluationRegisteredManifest>, EvaluationEvidenceStoreError> {
    super::schema::validate_schema(transaction)?;
    let Some(manifest) = load_registered_manifest(transaction, manifest_id, revision)? else {
        return Ok(None);
    };
    if manifest.proposal().source().backend_id() != actual_backend {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(Some(manifest))
}

pub(crate) fn get_submission_receipt_in_transaction(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
) -> Result<Option<EvaluationSubmissionReceipt>, EvaluationEvidenceStoreError> {
    super::schema::validate_schema(transaction)?;
    let Some(receipt) =
        load_submission_receipt(transaction, workspace_id, assignment_id, submitted_revision)?
    else {
        return Ok(None);
    };
    let source = if let Some(binding) =
        load_original_binding(transaction, workspace_id, assignment_id)?
    {
        if receipt.original_binding_digest() != Some(binding.binding_digest)
            || receipt.criteria_digest() != Some(binding.criteria_digest)
            || receipt.author_agent_id() != binding.target_agent_id
            || receipt.author_session_id() != binding.target_session_id
        {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "submission.binding_mismatch",
            ));
        }
        binding.source
    } else {
        source_for_assignment_membership(
            transaction,
            workspace_id,
            assignment_id,
            assignment_activity_from_submission_scope(transaction, workspace_id, assignment_id)?,
            receipt.author_agent_id(),
            receipt.author_session_id(),
        )?
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "submission.manifest_membership",
        ))?
    };
    if source.backend_id() != actual_backend {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(Some(receipt))
}

pub(crate) fn get_review_receipt_in_transaction(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
    review_revision: AgentAssignmentRevision,
) -> Result<Option<EvaluationReviewReceipt>, EvaluationEvidenceStoreError> {
    super::schema::validate_schema(transaction)?;
    let Some(submission) =
        load_submission_receipt(transaction, workspace_id, assignment_id, submitted_revision)?
    else {
        return Ok(None);
    };
    let source = if let Some(binding) =
        load_original_binding(transaction, workspace_id, assignment_id)?
    {
        if submission.author_agent_id() != binding.target_agent_id
            || submission.author_session_id() != binding.target_session_id
        {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "review.author_binding_mismatch",
            ));
        }
        binding.source
    } else {
        source_for_assignment_membership(
            transaction,
            workspace_id,
            assignment_id,
            assignment_activity_from_submission_scope(transaction, workspace_id, assignment_id)?,
            submission.author_agent_id(),
            submission.author_session_id(),
        )?
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "review.manifest_membership",
        ))?
    };
    if source.backend_id() != actual_backend {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    let review = load_review_receipt(
        transaction,
        workspace_id,
        assignment_id,
        submitted_revision,
        review_revision,
    )?;
    if let Some(review) = review {
        if review.author_agent_id() != submission.author_agent_id()
            || review.author_session_id() != submission.author_session_id()
            || review.result_digest() != submission.result_digest()
        {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "review.submission_mismatch",
            ));
        }
        Ok(Some(review))
    } else {
        Ok(None)
    }
}

fn assignment_activity_from_submission_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
) -> Result<ActivityId, EvaluationEvidenceStoreError> {
    let bytes = connection
        .query_row(
            "SELECT activity_id FROM workspace_evaluation_manifests m JOIN workspace_evaluation_manifest_members mm USING(workspace_id, manifest_id, manifest_revision) WHERE m.workspace_id = ?1 AND mm.assignment_id = ?2 LIMIT 1",
            params![workspace_id.into_uuid().as_bytes(), assignment_id.into_uuid().as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "assignment.manifest_activity",
        ))?;
    Ok(ActivityId::from_uuid(decode_uuid(
        &bytes,
        "manifest.activity_id",
    )?))
}

fn load_t1_cut_by_manifest(
    connection: &Connection,
    manifest_id: EvaluationManifestId,
    revision: EvaluationRevision,
    deadline: TimestampMillis,
) -> Result<Option<EvaluationT1CoverageCut>, EvaluationEvidenceStoreError> {
    let workspace_id = workspace_id(connection)?;
    let cut_id = connection
        .query_row(
            "SELECT cut_id FROM workspace_evaluation_t1_cuts WHERE workspace_id = ?1 AND manifest_id = ?2 AND manifest_revision = ?3 AND deadline_ms = ?4",
            params![workspace_id.into_uuid().as_bytes(), manifest_id.into_uuid().as_bytes(), revision.get(), deadline.get()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    cut_id
        .map(|bytes| {
            let cut_id = EvaluationCutId::new(decode_uuid(&bytes, "cut.cut_id")?)?;
            load_t1_cut_by_id(connection, cut_id)?.ok_or(
                EvaluationEvidenceStoreError::CorruptRecord("cut.by_manifest"),
            )
        })
        .transpose()
}

fn load_t1_cut_by_id(
    connection: &Connection,
    cut_id: EvaluationCutId,
) -> Result<Option<EvaluationT1CoverageCut>, EvaluationEvidenceStoreError> {
    let workspace_id = workspace_id(connection)?;
    let Some(header) = load_raw_t1_cut_header(connection, workspace_id, cut_id)? else {
        return Ok(None);
    };
    let manifest_id =
        EvaluationManifestId::new(decode_uuid(&header.manifest_id, "cut.manifest_id")?)?;
    let manifest_revision = EvaluationRevision::new(header.manifest_revision)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("cut.manifest_revision"))?;
    let manifest = load_registered_manifest(connection, manifest_id, manifest_revision)?
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord("cut.manifest"))?;
    let manifest_digest = decode_digest(&header.manifest_digest, "cut.manifest_digest")?;
    if manifest.proposal().digest() != manifest_digest {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut.manifest_digest_mismatch",
        ));
    }
    let deadline = TimestampMillis::new(header.deadline_ms)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("cut.deadline"))?;
    let closed_at = TimestampMillis::new(header.closed_at_ms)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("cut.closed_at"))?;
    let source_high_water = EvaluationSourceSequence::new(header.source_high_water)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("cut.source_high_water"))?;
    let rows = load_raw_t1_cut_members(connection, workspace_id, cut_id)?;
    let mut persisted = std::collections::BTreeMap::new();
    for raw in rows {
        let assignment_id = AgentAssignmentId::from_uuid(decode_uuid(
            &raw.assignment_id,
            "cut_member.assignment_id",
        )?);
        if persisted.insert(assignment_id, raw).is_some() {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "cut_member.duplicate",
            ));
        }
    }
    if persisted.len() != manifest.members().len() {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut_member.coverage",
        ));
    }
    let mut members = Vec::with_capacity(manifest.members().len());
    for registered_member in manifest.members() {
        let declaration = registered_member.declaration();
        let raw = persisted.remove(&declaration.assignment_id()).ok_or(
            EvaluationEvidenceStoreError::CorruptRecord("cut_member.missing"),
        )?;
        members.push(decode_t1_cut_member(
            connection,
            workspace_id,
            deadline,
            source_high_water,
            declaration,
            &raw,
        )?);
    }
    EvaluationT1CoverageCut::from_source_records(
        cut_id,
        manifest.proposal(),
        deadline,
        closed_at,
        source_high_water,
        members,
    )
    .map(Some)
    .map_err(Into::into)
}

fn load_raw_t1_cut_header(
    connection: &Connection,
    workspace_id: WorkspaceId,
    cut_id: EvaluationCutId,
) -> Result<Option<RawT1CutHeader>, EvaluationEvidenceStoreError> {
    connection
        .query_row(
            "SELECT manifest_id, manifest_revision, manifest_digest, deadline_ms, closed_at_ms, source_high_water FROM workspace_evaluation_t1_cuts WHERE workspace_id = ?1 AND cut_id = ?2",
            params![workspace_id.into_uuid().as_bytes(), cut_id.into_uuid().as_bytes()],
            |row| {
                Ok(RawT1CutHeader {
                    manifest_id: row.get(0)?,
                    manifest_revision: row.get(1)?,
                    manifest_digest: row.get(2)?,
                    deadline_ms: row.get(3)?,
                    closed_at_ms: row.get(4)?,
                    source_high_water: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn load_raw_t1_cut_members(
    connection: &Connection,
    workspace_id: WorkspaceId,
    cut_id: EvaluationCutId,
) -> Result<Vec<RawT1CutMember>, EvaluationEvidenceStoreError> {
    let mut statement = connection.prepare(
        "SELECT assignment_id, coverage_status, submitted_revision, receipt_sequence, unknown_reason FROM workspace_evaluation_t1_cut_members WHERE workspace_id = ?1 AND cut_id = ?2 ORDER BY assignment_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            workspace_id.into_uuid().as_bytes(),
            cut_id.into_uuid().as_bytes(),
            evaluation_member_query_limit()?,
        ],
        |row| {
            Ok(RawT1CutMember {
                assignment_id: row.get(0)?,
                coverage_status: row.get(1)?,
                submitted_revision: row.get(2)?,
                receipt_sequence: row.get(3)?,
                unknown_reason: row.get(4)?,
            })
        },
    )?;
    let members = rows.collect::<Result<Vec<_>, _>>()?;
    ensure_member_query_bound(members.len())?;
    Ok(members)
}

fn decode_t1_cut_member(
    connection: &Connection,
    workspace_id: WorkspaceId,
    deadline: TimestampMillis,
    source_high_water: EvaluationSourceSequence,
    declaration: EvaluationManifestMember,
    raw: &RawT1CutMember,
) -> Result<EvaluationT1CoverageMember, EvaluationEvidenceStoreError> {
    let coverage = match raw.coverage_status {
        0 => decode_eligible_t1_coverage(
            connection,
            workspace_id,
            deadline,
            source_high_water,
            declaration,
            raw,
        )?,
        1 if raw.submitted_revision.is_none()
            && raw.receipt_sequence.is_none()
            && raw.unknown_reason.is_none() =>
        {
            EvaluationT1Coverage::NoEligibleSubmission
        }
        2 if raw.submitted_revision.is_none() && raw.receipt_sequence.is_none() => {
            EvaluationT1Coverage::Unknown {
                reason: decode_coverage_unknown(raw.unknown_reason.ok_or(
                    EvaluationEvidenceStoreError::CorruptRecord("cut_member.unknown_reason"),
                )?)?,
            }
        }
        2 => {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "cut_member.unknown_receipt_fields",
            ));
        }
        _ => {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "cut_member.status",
            ));
        }
    };
    Ok(EvaluationT1CoverageMember::new(declaration, coverage))
}

fn decode_eligible_t1_coverage(
    connection: &Connection,
    workspace_id: WorkspaceId,
    deadline: TimestampMillis,
    source_high_water: EvaluationSourceSequence,
    declaration: EvaluationManifestMember,
    raw: &RawT1CutMember,
) -> Result<EvaluationT1Coverage, EvaluationEvidenceStoreError> {
    let submitted_revision = AgentAssignmentRevision::new(raw.submitted_revision.ok_or(
        EvaluationEvidenceStoreError::CorruptRecord("cut_member.submitted_revision"),
    )?)
    .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("cut_member.submitted_revision"))?;
    let receipt_sequence = EvaluationSourceSequence::new(raw.receipt_sequence.ok_or(
        EvaluationEvidenceStoreError::CorruptRecord("cut_member.receipt_sequence"),
    )?)
    .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("cut_member.receipt_sequence"))?;
    if raw.unknown_reason.is_some() {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut_member.eligible_unknown_reason",
        ));
    }
    let receipt = load_submission_receipt(
        connection,
        workspace_id,
        declaration.assignment_id(),
        submitted_revision,
    )?
    .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
        "cut_member.submission_receipt",
    ))?;
    if receipt.source_sequence() != receipt_sequence
        || receipt_sequence.get() > source_high_water.get()
        || receipt.author_agent_id() != declaration.target_agent_id()
        || receipt.author_session_id() != declaration.target_session_id()
    {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut_member.receipt_mismatch",
        ));
    }
    match receipt.timing() {
        EvaluationAdmissionTiming::Trusted(admitted_at) if admitted_at <= deadline => {
            Ok(EvaluationT1Coverage::Eligible {
                submitted_revision,
                receipt_sequence,
                admitted_at,
                result_digest: receipt.result_digest(),
                sources_digest: receipt.sources_digest(),
            })
        }
        _ => Err(EvaluationEvidenceStoreError::CorruptRecord(
            "cut_member.eligible_timing",
        )),
    }
}

pub(crate) fn create_review_cut_in_transaction<LookupError, Lookup, Clock>(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    review_cut_id: EvaluationReviewCutId,
    t1_cut_id: EvaluationCutId,
    mut lookup_assignment: Lookup,
    sample_clock: Clock,
) -> Result<EvaluationReviewCut, EvaluationEvidenceStoreError>
where
    LookupError: Error + Send + Sync + 'static,
    Lookup: FnMut(
        &Transaction<'_>,
        AgentAssignmentId,
    ) -> Result<Option<RegisteredAgentAssignment>, LookupError>,
    Clock: FnOnce() -> EvaluationClockReading,
{
    super::schema::validate_schema(transaction)?;
    if let Some(existing) = load_review_cut_by_id(transaction, review_cut_id)? {
        if existing.t1_cut_id() != t1_cut_id {
            return Err(EvaluationEvidenceStoreError::CutConflict);
        }
        return Ok(existing);
    }
    if get_review_cut_in_transaction(transaction, actual_backend, review_cut_id)?.is_some() {
        return Err(EvaluationEvidenceStoreError::CutConflict);
    }
    let t1_cut = get_t1_cut_in_transaction(transaction, actual_backend, t1_cut_id)?
        .ok_or(EvaluationEvidenceStoreError::RecordNotFound)?;
    let registered = load_registered_manifest(
        transaction,
        t1_cut.manifest_id(),
        t1_cut.manifest_revision(),
    )?
    .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
        "review_cut.manifest",
    ))?;
    validate_active_source(transaction, actual_backend, registered.proposal().source())?;
    let workspace_id = registered.proposal().source().workspace_id();
    let source_high_water = next_source_sequence(transaction, workspace_id)?;
    let cut_timing = observe_clock(transaction, workspace_id, source_high_water, sample_clock())?;
    let members = build_review_cut_members(
        transaction,
        &t1_cut,
        &registered,
        source_high_water,
        &mut lookup_assignment,
    )?;
    persist_review_cut(
        transaction,
        workspace_id,
        review_cut_id,
        t1_cut_id,
        source_high_water,
        cut_timing,
        &members,
    )?;
    EvaluationReviewCut::from_source_records(review_cut_id, &t1_cut, source_high_water, members)
        .map_err(Into::into)
}

fn build_review_cut_members<LookupError, Lookup>(
    transaction: &Transaction<'_>,
    t1_cut: &EvaluationT1CoverageCut,
    registered: &EvaluationRegisteredManifest,
    source_high_water: EvaluationSourceSequence,
    lookup_assignment: &mut Lookup,
) -> Result<Vec<EvaluationReviewCutMember>, EvaluationEvidenceStoreError>
where
    LookupError: Error + Send + Sync + 'static,
    Lookup: FnMut(
        &Transaction<'_>,
        AgentAssignmentId,
    ) -> Result<Option<RegisteredAgentAssignment>, LookupError>,
{
    let mut members = Vec::with_capacity(t1_cut.members().len());
    for t1_member in t1_cut.members() {
        members.push(build_review_cut_member(
            transaction,
            registered,
            source_high_water,
            t1_member,
            lookup_assignment,
        )?);
    }
    Ok(members)
}

fn build_review_cut_member<LookupError, Lookup>(
    transaction: &Transaction<'_>,
    registered: &EvaluationRegisteredManifest,
    source_high_water: EvaluationSourceSequence,
    t1_member: &EvaluationT1CoverageMember,
    lookup_assignment: &mut Lookup,
) -> Result<EvaluationReviewCutMember, EvaluationEvidenceStoreError>
where
    LookupError: Error + Send + Sync + 'static,
    Lookup: FnMut(
        &Transaction<'_>,
        AgentAssignmentId,
    ) -> Result<Option<RegisteredAgentAssignment>, LookupError>,
{
    let workspace_id = registered.proposal().source().workspace_id();
    let member = t1_member.member();
    let assignment = lookup_assignment(transaction, member.assignment_id())
        .map_err(|error| EvaluationEvidenceStoreError::AssignmentLookup(Box::new(error)))?;
    if let Some(assignment) = assignment.as_ref() {
        validate_review_cut_assignment(transaction, registered, member, assignment)?;
    }
    let submission =
        load_single_submission_for_assignment(transaction, workspace_id, member.assignment_id())?;
    let review = resolve_cut_review_state(
        transaction,
        workspace_id,
        source_high_water,
        t1_member,
        assignment.as_ref(),
        submission,
    )?;
    Ok(EvaluationReviewCutMember::new(
        member,
        t1_member.coverage(),
        submission,
        review,
    ))
}

fn validate_review_cut_assignment(
    transaction: &Transaction<'_>,
    registered: &EvaluationRegisteredManifest,
    member: EvaluationManifestMember,
    assignment: &RegisteredAgentAssignment,
) -> Result<(), EvaluationEvidenceStoreError> {
    let workspace_id = registered.proposal().source().workspace_id();
    if assignment.id() != member.assignment_id()
        || assignment.workspace_id() != workspace_id
        || assignment.activity_id() != registered.proposal().source().activity_id()
        || assignment.target().agent_id() != member.target_agent_id()
        || assignment.target().session_id() != member.target_session_id()
        || assignment.revision().get() < member.assignment_revision().get()
        || assignment.origin() != AgentAssignmentOrigin::CoordinatorOffer
    {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    let registered_member = registered
        .members()
        .iter()
        .find(|registered_member| {
            registered_member.declaration().assignment_id() == member.assignment_id()
        })
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut.manifest_member",
        ))?;
    if let EvaluationOriginalBindingStatus::Bound(binding) = registered_member.binding() {
        let source_binding =
            load_original_binding(transaction, workspace_id, member.assignment_id())?.ok_or(
                EvaluationEvidenceStoreError::CorruptRecord("review_cut.original_binding"),
            )?;
        validate_binding_assignment(&source_binding, assignment)?;
        if source_binding.binding_digest != binding.digest()
            || source_binding.source_sequence != binding.source_sequence()
        {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "review_cut.binding_mismatch",
            ));
        }
    }
    Ok(())
}

fn resolve_cut_review_state(
    connection: &Connection,
    workspace_id: WorkspaceId,
    source_high_water: EvaluationSourceSequence,
    t1_member: &EvaluationT1CoverageMember,
    assignment: Option<&RegisteredAgentAssignment>,
    submission: Option<EvaluationSubmissionReceipt>,
) -> Result<EvaluationReviewState, EvaluationEvidenceStoreError> {
    let member = t1_member.member();
    match submission {
        Some(submission) => {
            if submission.source_sequence().get() > source_high_water.get() {
                return Err(EvaluationEvidenceStoreError::CorruptRecord(
                    "review_cut.submission_after_high_water",
                ));
            }
            if let Some(review) = load_latest_review_receipt(
                connection,
                workspace_id,
                member.assignment_id(),
                submission.submitted_revision(),
                source_high_water,
            )? {
                return Ok(EvaluationReviewState::Reviewed(review));
            }
            if assignment.is_some_and(|value| value.state() == AgentAssignmentState::Submitted) {
                return Ok(EvaluationReviewState::Pending {
                    submitted_revision: submission.submitted_revision(),
                    receipt_sequence: submission.source_sequence(),
                });
            }
            Ok(EvaluationReviewState::Unknown(
                EvaluationCoverageUnknownReason::ReceiptBindingMismatch,
            ))
        }
        None => match (t1_member.coverage(), assignment) {
            (EvaluationT1Coverage::NoEligibleSubmission, Some(value))
                if assignment_has_submission(value) =>
            {
                Ok(EvaluationReviewState::Unknown(
                    EvaluationCoverageUnknownReason::LegacySubmissionWithoutReceipt,
                ))
            }
            (EvaluationT1Coverage::NoEligibleSubmission, _) => {
                Ok(EvaluationReviewState::NotApplicable)
            }
            (EvaluationT1Coverage::Unknown { reason }, _) => {
                Ok(EvaluationReviewState::Unknown(reason))
            }
            (EvaluationT1Coverage::Eligible { .. }, _) => {
                Err(EvaluationEvidenceStoreError::CorruptRecord(
                    "review_cut.eligible_submission_missing",
                ))
            }
        },
    }
}

fn persist_review_cut(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    review_cut_id: EvaluationReviewCutId,
    t1_cut_id: EvaluationCutId,
    source_high_water: EvaluationSourceSequence,
    cut_timing: EvaluationAdmissionTiming,
    members: &[EvaluationReviewCutMember],
) -> Result<(), EvaluationEvidenceStoreError> {
    let (time_status, cut_at_ms) = encode_timing(cut_timing);
    transaction.execute(
        "INSERT INTO workspace_evaluation_review_cuts(workspace_id, review_cut_id, t1_cut_id, source_high_water, cut_time_status, cut_at_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            workspace_id.into_uuid().as_bytes(),
            review_cut_id.into_uuid().as_bytes(),
            t1_cut_id.into_uuid().as_bytes(),
            source_high_water.get(),
            time_status,
            cut_at_ms,
        ],
    )?;
    for member in members {
        insert_review_cut_member(transaction, workspace_id, review_cut_id, member)?;
    }
    Ok(())
}

fn load_latest_review_receipt(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    submitted_revision: AgentAssignmentRevision,
    source_high_water: EvaluationSourceSequence,
) -> Result<Option<EvaluationReviewReceipt>, EvaluationEvidenceStoreError> {
    let review_revision = connection
        .query_row(
            "SELECT review_revision FROM workspace_evaluation_review_receipts WHERE workspace_id = ?1 AND assignment_id = ?2 AND submitted_revision = ?3 AND source_sequence <= ?4 ORDER BY source_sequence DESC LIMIT 1",
            params![workspace_id.into_uuid().as_bytes(), assignment_id.into_uuid().as_bytes(), submitted_revision.get(), source_high_water.get()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    review_revision
        .map(|revision| {
            load_review_receipt(
                connection,
                workspace_id,
                assignment_id,
                submitted_revision,
                AgentAssignmentRevision::new(revision)
                    .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("review.revision"))?,
            )?
            .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                "review.latest_missing",
            ))
        })
        .transpose()
}

fn insert_review_cut_member(
    connection: &Connection,
    workspace_id: WorkspaceId,
    review_cut_id: EvaluationReviewCutId,
    member: &EvaluationReviewCutMember,
) -> Result<(), EvaluationEvidenceStoreError> {
    let assignment_id = member.member().assignment_id();
    let (coverage_status, submitted_revision) = match member.coverage() {
        EvaluationT1Coverage::Eligible {
            submitted_revision, ..
        } => (0_i64, Some(submitted_revision.get())),
        EvaluationT1Coverage::NoEligibleSubmission => {
            let submitted = member
                .submission()
                .map(EvaluationSubmissionReceipt::submitted_revision);
            (1_i64, submitted.map(AgentAssignmentRevision::get))
        }
        EvaluationT1Coverage::Unknown { .. } => {
            let submitted = member
                .submission()
                .map(EvaluationSubmissionReceipt::submitted_revision);
            (2_i64, submitted.map(AgentAssignmentRevision::get))
        }
    };
    let (
        review_status,
        review_revision,
        review_sequence,
        reviewer_agent,
        reviewer_session,
        result_digest,
        unknown_reason,
    ) = match member.review() {
        EvaluationReviewState::NotApplicable => (0_i64, None, None, None, None, None, None),
        EvaluationReviewState::Pending { .. } => (1_i64, None, None, None, None, None, None),
        EvaluationReviewState::Reviewed(receipt) => {
            let status = match receipt.outcome() {
                EvaluationReviewOutcome::Accepted => 2_i64,
                EvaluationReviewOutcome::Rejected => 3_i64,
            };
            (
                status,
                Some(receipt.review_revision().get()),
                Some(receipt.source_sequence().get()),
                Some(
                    receipt
                        .reviewer_agent_id()
                        .into_uuid()
                        .into_bytes()
                        .to_vec(),
                ),
                Some(
                    receipt
                        .reviewer_session_id()
                        .into_uuid()
                        .into_bytes()
                        .to_vec(),
                ),
                Some(receipt.result_digest().into_bytes().to_vec()),
                None,
            )
        }
        EvaluationReviewState::Unknown(reason) => (
            4_i64,
            None,
            None,
            None,
            None,
            None,
            Some(coverage_unknown_code(reason)),
        ),
    };
    connection.execute(
        "INSERT INTO workspace_evaluation_review_cut_members(workspace_id, review_cut_id, assignment_id, coverage_status, submitted_revision, review_status, review_revision, review_sequence, reviewer_agent_id, reviewer_session_id, result_digest, review_unknown_reason) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            workspace_id.into_uuid().as_bytes(),
            review_cut_id.into_uuid().as_bytes(),
            assignment_id.into_uuid().as_bytes(),
            coverage_status,
            submitted_revision,
            review_status,
            review_revision,
            review_sequence,
            reviewer_agent,
            reviewer_session,
            result_digest,
            unknown_reason,
        ],
    )?;
    Ok(())
}

pub(crate) fn get_review_cut_in_transaction(
    transaction: &Transaction<'_>,
    actual_backend: ForgeBackendId,
    review_cut_id: EvaluationReviewCutId,
) -> Result<Option<EvaluationReviewCut>, EvaluationEvidenceStoreError> {
    super::schema::validate_schema(transaction)?;
    let Some(review_cut) = load_review_cut_by_id(transaction, review_cut_id)? else {
        return Ok(None);
    };
    let t1_cut = get_t1_cut_in_transaction(transaction, actual_backend, review_cut.t1_cut_id())?
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut.t1_cut",
        ))?;
    let manifest = load_registered_manifest(
        transaction,
        t1_cut.manifest_id(),
        t1_cut.manifest_revision(),
    )?
    .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
        "review_cut.manifest",
    ))?;
    if manifest.proposal().source().backend_id() != actual_backend {
        return Err(EvaluationEvidenceStoreError::SourceScopeMismatch);
    }
    Ok(Some(review_cut))
}

fn load_review_cut_by_id(
    connection: &Connection,
    review_cut_id: EvaluationReviewCutId,
) -> Result<Option<EvaluationReviewCut>, EvaluationEvidenceStoreError> {
    let workspace_id = workspace_id(connection)?;
    let Some(header) = load_raw_review_cut_header(connection, workspace_id, review_cut_id)? else {
        return Ok(None);
    };
    let t1_cut_id = EvaluationCutId::new(decode_uuid(&header.t1_cut_id, "review_cut.t1_cut_id")?)?;
    let t1_cut = load_t1_cut_by_id(connection, t1_cut_id)?.ok_or(
        EvaluationEvidenceStoreError::CorruptRecord("review_cut.t1_cut"),
    )?;
    let source_high_water = EvaluationSourceSequence::new(header.source_high_water)
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord("review_cut.source_high_water"))?;
    let _cut_timing = decode_timing(
        header.cut_time_status,
        header.cut_at_ms,
        "review_cut.cut_time",
    )?;
    let rows = load_raw_review_cut_members(connection, workspace_id, review_cut_id)?;
    let mut persisted = std::collections::BTreeMap::new();
    for raw in rows {
        let assignment_id = AgentAssignmentId::from_uuid(decode_uuid(
            &raw.assignment_id,
            "review_cut_member.assignment_id",
        )?);
        if persisted.insert(assignment_id, raw).is_some() {
            return Err(EvaluationEvidenceStoreError::CorruptRecord(
                "review_cut_member.duplicate",
            ));
        }
    }
    if persisted.len() != t1_cut.members().len() {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut_member.coverage",
        ));
    }
    let mut members = Vec::with_capacity(t1_cut.members().len());
    for t1_member in t1_cut.members() {
        let assignment_id = t1_member.member().assignment_id();
        let raw =
            persisted
                .remove(&assignment_id)
                .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                    "review_cut_member.missing",
                ))?;
        members.push(decode_review_cut_member(
            connection,
            workspace_id,
            t1_member,
            &raw,
        )?);
    }
    EvaluationReviewCut::from_source_records(review_cut_id, &t1_cut, source_high_water, members)
        .map(Some)
        .map_err(Into::into)
}

fn load_raw_review_cut_header(
    connection: &Connection,
    workspace_id: WorkspaceId,
    review_cut_id: EvaluationReviewCutId,
) -> Result<Option<RawReviewCutHeader>, EvaluationEvidenceStoreError> {
    connection
        .query_row(
            "SELECT t1_cut_id, source_high_water, cut_time_status, cut_at_ms FROM workspace_evaluation_review_cuts WHERE workspace_id = ?1 AND review_cut_id = ?2",
            params![workspace_id.into_uuid().as_bytes(), review_cut_id.into_uuid().as_bytes()],
            |row| {
                Ok(RawReviewCutHeader {
                    t1_cut_id: row.get(0)?,
                    source_high_water: row.get(1)?,
                    cut_time_status: row.get(2)?,
                    cut_at_ms: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn load_raw_review_cut_members(
    connection: &Connection,
    workspace_id: WorkspaceId,
    review_cut_id: EvaluationReviewCutId,
) -> Result<Vec<RawReviewCutMember>, EvaluationEvidenceStoreError> {
    let mut statement = connection.prepare(
        "SELECT assignment_id, coverage_status, submitted_revision, review_status, review_revision, review_sequence, reviewer_agent_id, reviewer_session_id, result_digest, review_unknown_reason FROM workspace_evaluation_review_cut_members WHERE workspace_id = ?1 AND review_cut_id = ?2 ORDER BY assignment_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            workspace_id.into_uuid().as_bytes(),
            review_cut_id.into_uuid().as_bytes(),
            evaluation_member_query_limit()?,
        ],
        |row| {
            Ok(RawReviewCutMember {
                assignment_id: row.get(0)?,
                coverage_status: row.get(1)?,
                submitted_revision: row.get(2)?,
                review_status: row.get(3)?,
                review_revision: row.get(4)?,
                review_sequence: row.get(5)?,
                reviewer_agent_id: row.get(6)?,
                reviewer_session_id: row.get(7)?,
                result_digest: row.get(8)?,
                unknown_reason: row.get(9)?,
            })
        },
    )?;
    let members = rows.collect::<Result<Vec<_>, _>>()?;
    ensure_member_query_bound(members.len())?;
    Ok(members)
}

fn decode_review_cut_member(
    connection: &Connection,
    workspace_id: WorkspaceId,
    t1_member: &EvaluationT1CoverageMember,
    raw: &RawReviewCutMember,
) -> Result<EvaluationReviewCutMember, EvaluationEvidenceStoreError> {
    if raw.assignment_id.as_slice() != t1_member.member().assignment_id().into_uuid().as_bytes() {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut_member.assignment_id",
        ));
    }
    let expected_coverage_status = coverage_code_from_domain(t1_member.coverage());
    if expected_coverage_status != raw.coverage_status {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut_member.coverage_mismatch",
        ));
    }
    let assignment_id = t1_member.member().assignment_id();
    let submission = load_review_cut_submission(
        connection,
        workspace_id,
        assignment_id,
        raw.submitted_revision,
    )?;
    let review = decode_review_cut_state(connection, workspace_id, assignment_id, submission, raw)?;
    Ok(EvaluationReviewCutMember::new(
        t1_member.member(),
        t1_member.coverage(),
        submission,
        review,
    ))
}

fn load_review_cut_submission(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    revision: Option<i64>,
) -> Result<Option<EvaluationSubmissionReceipt>, EvaluationEvidenceStoreError> {
    let Some(revision) = revision else {
        return Ok(None);
    };
    let revision = AgentAssignmentRevision::new(revision).map_err(|_| {
        EvaluationEvidenceStoreError::CorruptRecord("review_cut_member.submission_revision")
    })?;
    load_submission_receipt(connection, workspace_id, assignment_id, revision)?
        .map(Some)
        .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut_member.submission",
        ))
}

fn decode_review_cut_state(
    connection: &Connection,
    workspace_id: WorkspaceId,
    assignment_id: AgentAssignmentId,
    submission: Option<EvaluationSubmissionReceipt>,
    raw: &RawReviewCutMember,
) -> Result<EvaluationReviewState, EvaluationEvidenceStoreError> {
    match raw.review_status {
        0 if raw.unknown_reason.is_none() => Ok(EvaluationReviewState::NotApplicable),
        1 if raw.unknown_reason.is_none() => {
            let receipt = submission.ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                "review_cut_member.pending_submission",
            ))?;
            Ok(EvaluationReviewState::Pending {
                submitted_revision: receipt.submitted_revision(),
                receipt_sequence: receipt.source_sequence(),
            })
        }
        2 | 3 if raw.unknown_reason.is_none() => {
            let receipt = submission.ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                "review_cut_member.review_submission",
            ))?;
            let review_revision = AgentAssignmentRevision::new(raw.review_revision.ok_or(
                EvaluationEvidenceStoreError::CorruptRecord("review_cut_member.review_revision"),
            )?)
            .map_err(|_| {
                EvaluationEvidenceStoreError::CorruptRecord("review_cut_member.review_revision")
            })?;
            let review = load_review_receipt(
                connection,
                workspace_id,
                assignment_id,
                receipt.submitted_revision(),
                review_revision,
            )?
            .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                "review_cut_member.review_receipt",
            ))?;
            validate_review_cut_receipt(&review, raw.review_status, raw)?;
            Ok(EvaluationReviewState::Reviewed(review))
        }
        4 => Ok(EvaluationReviewState::Unknown(decode_coverage_unknown(
            raw.unknown_reason
                .ok_or(EvaluationEvidenceStoreError::CorruptRecord(
                    "review_cut_member.unknown_reason",
                ))?,
        )?)),
        _ => Err(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut_member.review_status",
        )),
    }
}

fn validate_review_cut_receipt(
    review: &EvaluationReviewReceipt,
    review_status: i64,
    raw: &RawReviewCutMember,
) -> Result<(), EvaluationEvidenceStoreError> {
    if Some(review.source_sequence().get()) != raw.review_sequence
        || Some(review.reviewer_agent_id().into_uuid().into_bytes().to_vec())
            != raw.reviewer_agent_id
        || Some(
            review
                .reviewer_session_id()
                .into_uuid()
                .into_bytes()
                .to_vec(),
        ) != raw.reviewer_session_id
        || Some(review.result_digest().into_bytes().to_vec()) != raw.result_digest
        || (review_status == 2 && review.outcome() != EvaluationReviewOutcome::Accepted)
        || (review_status == 3 && review.outcome() != EvaluationReviewOutcome::Rejected)
    {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(
            "review_cut_member.review_mismatch",
        ));
    }
    Ok(())
}

fn coverage_code_from_domain(coverage: EvaluationT1Coverage) -> i64 {
    match coverage {
        EvaluationT1Coverage::Eligible { .. } => 0,
        EvaluationT1Coverage::NoEligibleSubmission => 1,
        EvaluationT1Coverage::Unknown { .. } => 2,
    }
}

fn workspace_id(connection: &Connection) -> Result<WorkspaceId, EvaluationEvidenceStoreError> {
    let bytes = connection.query_row(
        "SELECT substr(workspace_id, 1, 17) FROM workspace LIMIT 1",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    Ok(WorkspaceId::from_uuid(decode_uuid(
        &bytes,
        "workspace.workspace_id",
    )?))
}

fn decode_uuid(bytes: &[u8], label: &'static str) -> Result<Uuid, EvaluationEvidenceStoreError> {
    let id =
        Uuid::from_slice(bytes).map_err(|_| EvaluationEvidenceStoreError::CorruptRecord(label))?;
    if id.is_nil() {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(label));
    }
    Ok(id)
}

fn decode_digest(
    bytes: &[u8],
    label: &'static str,
) -> Result<EvaluationDigest, EvaluationEvidenceStoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord(label))?;
    EvaluationDigest::new(bytes).map_err(|_| EvaluationEvidenceStoreError::CorruptRecord(label))
}

fn positive(value: i64, label: &'static str) -> Result<i64, EvaluationEvidenceStoreError> {
    if value < 1 {
        return Err(EvaluationEvidenceStoreError::CorruptRecord(label));
    }
    Ok(value)
}

fn encode_timing(timing: EvaluationAdmissionTiming) -> (i64, Option<i64>) {
    match timing {
        EvaluationAdmissionTiming::Trusted(observed_at) => (0, Some(observed_at.get())),
        EvaluationAdmissionTiming::Unknown(EvaluationClockUncertainty::Unknown) => (1, None),
        EvaluationAdmissionTiming::Unknown(EvaluationClockUncertainty::Regressed) => (2, None),
    }
}

fn decode_timing(
    status: i64,
    observed_at_ms: Option<i64>,
    label: &'static str,
) -> Result<EvaluationAdmissionTiming, EvaluationEvidenceStoreError> {
    match (status, observed_at_ms) {
        (0, Some(value)) => TimestampMillis::new(value)
            .map(EvaluationAdmissionTiming::Trusted)
            .map_err(|_| EvaluationEvidenceStoreError::CorruptRecord(label)),
        (1, None) => Ok(EvaluationAdmissionTiming::Unknown(
            EvaluationClockUncertainty::Unknown,
        )),
        (2, None) => Ok(EvaluationAdmissionTiming::Unknown(
            EvaluationClockUncertainty::Regressed,
        )),
        _ => Err(EvaluationEvidenceStoreError::CorruptRecord(label)),
    }
}

#[cfg(test)]
mod tests;
