//! Immutable terminal acceptance ledger and transaction-scoped assignment hooks.

mod codec;
mod model;
mod schema;
mod transport;

use forge_domain::{
    AgentAssignmentCoordinator, AgentAssignmentId, AgentAssignmentOrigin, AgentAssignmentState,
    OrchestrationIssuerId, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error as ThisError;
use uuid::Uuid;

use crate::workspace_agent_assignments::home_origin::{self, HomeOriginAssignmentPins};

use super::proposal_model::{
    HomeHandoffAssignmentLineage, HomeHandoffProposalEvidence, HomeHandoffProposalRecord,
    HomeHandoffSourceAssignmentPin,
};

pub use model::{
    HomeHandoffAcceptanceOutcome, HomeHandoffAcceptanceOutcomeKind,
    HomeHandoffAcceptanceOutcomeRecord, HomeHandoffAppliedAcceptance,
    HomeHandoffInitialSuccessorSnapshot,
};
pub(crate) use model::{HomeHandoffAcceptanceOutcomeRecordParts, HomeHandoffAcceptanceTerminal};
pub(crate) use schema::{create_schema, schema_objects, validate_schema};

#[derive(Debug, ThisError)]
pub enum HomeHandoffApplicationStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Domain(#[from] forge_domain::HomeHandoffDomainError),
    #[error("Home acceptance proposal record is invalid")]
    Proposal(#[source] Box<super::HomeHandoffProposalStoreError>),
    #[error("Home acceptance Prepared source record is invalid")]
    HomeTransfer(#[source] Box<crate::HomeTransferStoreError>),
    #[error(transparent)]
    AgentAssignment(Box<crate::AgentAssignmentStoreError>),
    #[error("Home acceptance source conflict: {0}")]
    Conflict(&'static str),
    #[error("Home acceptance record is corrupt: {0}")]
    Corrupt(&'static str),
    #[error(
        "Home acceptance {acceptance_id} commit may have succeeded; exact outcome readback is required"
    )]
    CommitUnconfirmed {
        acceptance_id: Uuid,
        #[source]
        source: Box<rusqlite::Error>,
    },
    #[error(
        "Home acceptance {acceptance_id} commit outcome could not be verified; exact outcome readback is required"
    )]
    ReadbackRequired {
        acceptance_id: Uuid,
        #[source]
        source: Box<HomeHandoffApplicationStoreError>,
    },
}

type Error = HomeHandoffApplicationStoreError;

impl From<super::HomeHandoffProposalStoreError> for HomeHandoffApplicationStoreError {
    fn from(error: super::HomeHandoffProposalStoreError) -> Self {
        match error {
            super::HomeHandoffProposalStoreError::Sqlite(source) => Self::Sqlite(source),
            super::HomeHandoffProposalStoreError::Domain(source) => Self::Domain(source),
            super::HomeHandoffProposalStoreError::HomeTransfer(source) => {
                Self::HomeTransfer(source)
            }
            super::HomeHandoffProposalStoreError::AgentAssignment(source) => {
                Self::AgentAssignment(source)
            }
            other => Self::Proposal(Box::new(other)),
        }
    }
}

impl From<HomeHandoffApplicationStoreError> for super::HomeHandoffProposalStoreError {
    fn from(error: HomeHandoffApplicationStoreError) -> Self {
        match error {
            HomeHandoffApplicationStoreError::Sqlite(source) => Self::Sqlite(source),
            HomeHandoffApplicationStoreError::Domain(source) => Self::Domain(source),
            HomeHandoffApplicationStoreError::Proposal(source) => *source,
            HomeHandoffApplicationStoreError::HomeTransfer(source) => Self::HomeTransfer(source),
            HomeHandoffApplicationStoreError::AgentAssignment(source) => {
                Self::AgentAssignment(source)
            }
            HomeHandoffApplicationStoreError::Conflict(message) => Self::Conflict(message),
            HomeHandoffApplicationStoreError::Corrupt(message) => Self::Corrupt(message),
            error @ (HomeHandoffApplicationStoreError::CommitUnconfirmed { .. }
            | HomeHandoffApplicationStoreError::ReadbackRequired { .. }) => {
                Self::Application(Box::new(error))
            }
        }
    }
}

const DIGEST_BYTES: usize = 32;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HomeHandoffOutcomeWrite {
    Inserted,
    Existing,
}

#[derive(Debug)]
struct RawOutcome {
    request_digest: Vec<u8>,
    request_snapshot: Vec<u8>,
    issuer_id: Vec<u8>,
    handoff_id: Vec<u8>,
    proposal_id: Vec<u8>,
    case_revision: i64,
    preparation_id: Vec<u8>,
    workspace_id: Vec<u8>,
    predecessor_assignment_id: Vec<u8>,
    root_assignment_id: Vec<u8>,
    outcome_kind: i64,
    source_observed_at_ms: i64,
    predecessor_revision_before: Option<i64>,
    predecessor_revision_after: Option<i64>,
    predecessor_terminal_disposition: Option<i64>,
    successor_assignment_id: Option<Vec<u8>>,
    successor_initial_revision: Option<i64>,
    successor_snapshot: Option<Vec<u8>>,
    grant_evidence_snapshot: Option<Vec<u8>>,
    payload_digest: Vec<u8>,
}

pub(crate) fn get_outcome(
    connection: &Connection,
    acceptance_id: Uuid,
) -> Result<Option<HomeHandoffAcceptanceOutcomeRecord>, Error> {
    if acceptance_id.is_nil() {
        return Err(Error::Conflict("acceptance identity"));
    }
    read_raw_outcome(connection, acceptance_id)?
        .as_ref()
        .map(|raw| decode_outcome(connection, acceptance_id, raw))
        .transpose()
}

fn read_raw_outcome(
    connection: &Connection,
    acceptance_id: Uuid,
) -> Result<Option<RawOutcome>, Error> {
    connection
        .query_row(
            "SELECT substr(request_digest,1,33),substr(request_snapshot,1,321),
                    substr(authenticated_issuer_id,1,17),substr(handoff_id,1,17),
                    substr(proposal_id,1,17),case_revision,substr(preparation_id,1,17),
                    substr(workspace_id,1,17),substr(predecessor_assignment_id,1,17),
                    substr(root_assignment_id,1,17),outcome_kind,source_observed_at_ms,
                    predecessor_revision_before,predecessor_revision_after,
                    predecessor_terminal_disposition,
                    substr(successor_assignment_id,1,17),successor_initial_revision,
                    substr(successor_snapshot,1,385),
                    substr(grant_evidence_snapshot,1,321),substr(payload_digest,1,33)
             FROM home_handoff_acceptance_outcomes WHERE acceptance_id=?1",
            params![acceptance_id.as_bytes()],
            |row| {
                Ok(RawOutcome {
                    request_digest: row.get(0)?,
                    request_snapshot: row.get(1)?,
                    issuer_id: row.get(2)?,
                    handoff_id: row.get(3)?,
                    proposal_id: row.get(4)?,
                    case_revision: row.get(5)?,
                    preparation_id: row.get(6)?,
                    workspace_id: row.get(7)?,
                    predecessor_assignment_id: row.get(8)?,
                    root_assignment_id: row.get(9)?,
                    outcome_kind: row.get(10)?,
                    source_observed_at_ms: row.get(11)?,
                    predecessor_revision_before: row.get(12)?,
                    predecessor_revision_after: row.get(13)?,
                    predecessor_terminal_disposition: row.get(14)?,
                    successor_assignment_id: row.get(15)?,
                    successor_initial_revision: row.get(16)?,
                    successor_snapshot: row.get(17)?,
                    grant_evidence_snapshot: row.get(18)?,
                    payload_digest: row.get(19)?,
                })
            },
        )
        .optional()
        .map_err(Error::from)
}

pub(crate) fn insert_outcome_in_transaction(
    transaction: &Transaction<'_>,
    outcome: &HomeHandoffAcceptanceOutcomeRecord,
) -> Result<HomeHandoffOutcomeWrite, Error> {
    if let Some(existing) = get_outcome(transaction, outcome.acceptance_id())? {
        return if existing == *outcome {
            Ok(HomeHandoffOutcomeWrite::Existing)
        } else {
            Err(Error::Conflict(
                "acceptance id was reused with changed intent",
            ))
        };
    }
    validate_record_references(transaction, outcome)?;
    let request_snapshot = outcome.request().canonical_snapshot();
    let request_digest = outcome.request().request_digest();
    let outcome_kind = outcome.outcome_kind().encode();
    let (
        predecessor_revision_before,
        predecessor_revision_after,
        predecessor_terminal_disposition,
        successor_id,
        successor_revision,
        successor_snapshot,
        grant_snapshot,
    ) = match outcome.applied() {
        Some(applied) => (
            Some(applied.predecessor_revision_before().get()),
            Some(applied.predecessor_revision_after().get()),
            Some(encode_assignment_state(
                applied.predecessor_terminal_disposition(),
            )),
            Some(
                applied
                    .successor()
                    .assignment_id()
                    .into_uuid()
                    .into_bytes()
                    .to_vec(),
            ),
            Some(1_i64),
            Some(codec::encode_successor_snapshot(applied.successor())),
            Some(codec::encode_grant_snapshot(applied.grant())?),
        ),
        None => (None, None, None, None, None, None, None),
    };
    let changed = transaction.execute(
        "INSERT INTO home_handoff_acceptance_outcomes (
            acceptance_id,request_digest,request_snapshot,authenticated_issuer_id,
            handoff_id,proposal_id,case_revision,preparation_id,workspace_id,
            predecessor_assignment_id,root_assignment_id,outcome_kind,
            source_observed_at_ms,predecessor_revision_before,
            predecessor_revision_after,predecessor_terminal_disposition,
            successor_assignment_id,successor_initial_revision,successor_snapshot,
            grant_evidence_snapshot,payload_digest
         ) VALUES (
            ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21
         )",
        params![
            outcome.acceptance_id().as_bytes(),
            request_digest.as_bytes().as_slice(),
            request_snapshot.as_slice(),
            outcome.issuer().into_uuid().as_bytes(),
            outcome.handoff_id().as_bytes(),
            outcome.proposal_id().as_bytes(),
            outcome.case_revision(),
            outcome.preparation_id().as_bytes(),
            outcome.workspace_id().into_uuid().as_bytes(),
            outcome.predecessor_id().into_uuid().as_bytes(),
            outcome.root_assignment_id().into_uuid().as_bytes(),
            outcome_kind,
            outcome.source_at().get(),
            predecessor_revision_before,
            predecessor_revision_after,
            predecessor_terminal_disposition,
            successor_id,
            successor_revision,
            successor_snapshot,
            grant_snapshot,
            outcome.payload_digest().as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(Error::Corrupt("acceptance insert count"));
    }
    Ok(HomeHandoffOutcomeWrite::Inserted)
}

/// Checked same-transaction proposal hook. Aborted rows remain readable by
/// exact acceptance ID but do not pin the proposal head.
pub(crate) fn handoff_is_applied(connection: &Connection, handoff_id: Uuid) -> Result<bool, Error> {
    if handoff_id.is_nil() {
        return Err(Error::Conflict("handoff identity"));
    }
    let mut statement = connection.prepare(
        "SELECT substr(acceptance_id,1,17)
         FROM home_handoff_acceptance_outcomes
         WHERE handoff_id=?1 AND outcome_kind=1
         ORDER BY acceptance_id LIMIT 2",
    )?;
    let ids = statement
        .query_map(params![handoff_id.as_bytes()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    match ids.as_slice() {
        [] => Ok(false),
        [acceptance_id] => {
            let acceptance_id = decode_uuid("acceptance_id", acceptance_id)?;
            let outcome = get_outcome(connection, acceptance_id)?
                .ok_or(Error::Corrupt("Applied acceptance disappeared"))?;
            if outcome.handoff_id() != handoff_id
                || outcome.outcome_kind() != HomeHandoffAcceptanceOutcomeKind::Applied
            {
                return Err(Error::Corrupt("Applied handoff index mismatch"));
            }
            Ok(true)
        }
        _ => Err(Error::Corrupt("multiple Applied outcomes for handoff")),
    }
}

/// Checked same-transaction proposal hook for a currently persisted Home
/// assignment. A Home row without its exact Applied receipt is corruption.
pub(crate) fn home_origin_matches_applied_receipt(
    connection: &Connection,
    successor_assignment_id: AgentAssignmentId,
    origin: forge_domain::AgentAssignmentHomeHandoffOrigin,
) -> Result<bool, Error> {
    let pins = home_origin::read(connection, successor_assignment_id)
        .map_err(assignment_error)?
        .ok_or(Error::Corrupt("Home successor assignment is missing"))?;
    if pins.origin_kind != 1 {
        return Err(Error::Corrupt("Home successor origin discriminator"));
    }
    let acceptance_id = pins
        .home_receipt_id
        .ok_or(Error::Corrupt("Home successor receipt is missing"))?;
    let outcome = get_outcome(connection, acceptance_id)?
        .ok_or(Error::Corrupt("Home successor Applied receipt is missing"))?;
    let Some(applied) = outcome.applied() else {
        return Err(Error::Corrupt("Home successor references Aborted receipt"));
    };
    if outcome.acceptance_id() != acceptance_id
        || applied.successor().assignment_id() != successor_assignment_id
        || applied.successor().origin() != origin
        || !applied
            .successor()
            .matches_current_assignment(&pins, acceptance_id)
    {
        return Err(Error::Corrupt("Home successor receipt pins"));
    }
    Ok(true)
}

/// Low-level assignment decoder hook. The Application record was checked via
/// raw assignment pins in `get_outcome`; this path never calls the full decoder.
pub(crate) fn get_applied_origin_for_assignment(
    connection: &Connection,
    successor_assignment_id: AgentAssignmentId,
    acceptance_id: Uuid,
) -> Result<AgentAssignmentOrigin, crate::AgentAssignmentStoreError> {
    let outcome = get_outcome(connection, acceptance_id)
        .map_err(proposal_error_to_assignment)?
        .ok_or(crate::AgentAssignmentStoreError::CorruptRecord(
            "assignment.home_receipt_missing",
        ))?;
    let Some(applied) = outcome.applied() else {
        return Err(crate::AgentAssignmentStoreError::CorruptRecord(
            "assignment.home_receipt_aborted",
        ));
    };
    if outcome.acceptance_id() != acceptance_id
        || applied.successor().assignment_id() != successor_assignment_id
    {
        return Err(crate::AgentAssignmentStoreError::CorruptRecord(
            "assignment.home_receipt_identity",
        ));
    }
    let pins = home_origin::read(connection, successor_assignment_id)?.ok_or(
        crate::AgentAssignmentStoreError::CorruptRecord(
            "assignment.home_receipt_assignment_missing",
        ),
    )?;
    if !applied
        .successor()
        .matches_current_assignment(&pins, acceptance_id)
    {
        return Err(crate::AgentAssignmentStoreError::CorruptRecord(
            "assignment.home_receipt_pins",
        ));
    }
    Ok(AgentAssignmentOrigin::HomeHandoff(
        applied.successor().origin(),
    ))
}

fn decode_outcome(
    connection: &Connection,
    acceptance_id: Uuid,
    raw: &RawOutcome,
) -> Result<HomeHandoffAcceptanceOutcomeRecord, Error> {
    let record = decode_stored_outcome(acceptance_id, raw)?;
    validate_record_references(connection, &record)?;
    Ok(record)
}

fn decode_stored_outcome(
    acceptance_id: Uuid,
    raw: &RawOutcome,
) -> Result<HomeHandoffAcceptanceOutcomeRecord, Error> {
    let record = codec::decode_stored_record(
        &raw.request_snapshot,
        &raw.request_digest,
        OrchestrationIssuerId::from_uuid(decode_uuid("authenticated_issuer_id", &raw.issuer_id)?),
        decode_uuid("preparation_id", &raw.preparation_id)?,
        WorkspaceId::from_uuid(decode_uuid("workspace_id", &raw.workspace_id)?),
        AgentAssignmentId::from_uuid(decode_uuid(
            "predecessor_assignment_id",
            &raw.predecessor_assignment_id,
        )?),
        AgentAssignmentId::from_uuid(decode_uuid("root_assignment_id", &raw.root_assignment_id)?),
        timestamp(raw.source_observed_at_ms, "Source observation time")?,
        raw.outcome_kind,
        raw.predecessor_revision_before,
        raw.predecessor_revision_after,
        raw.predecessor_terminal_disposition,
        raw.successor_snapshot.as_deref(),
        raw.grant_evidence_snapshot.as_deref(),
    )?;
    if record.acceptance_id() != acceptance_id
        || record.handoff_id() != decode_uuid("handoff_id", &raw.handoff_id)?
        || record.proposal_id() != decode_uuid("proposal_id", &raw.proposal_id)?
        || record.case_revision() != raw.case_revision
        || record.preparation_id() != decode_uuid("preparation_id", &raw.preparation_id)?
        || record.workspace_id().into_uuid() != decode_uuid("workspace_id", &raw.workspace_id)?
        || record.predecessor_id().into_uuid()
            != decode_uuid("predecessor_assignment_id", &raw.predecessor_assignment_id)?
        || record.root_assignment_id().into_uuid()
            != decode_uuid("root_assignment_id", &raw.root_assignment_id)?
        || record.payload_digest().as_slice() != digest(&raw.payload_digest)?.as_slice()
    {
        return Err(Error::Corrupt("acceptance row indexes or digest"));
    }
    if let Some(applied) = record.applied()
        && (raw
            .successor_assignment_id
            .as_deref()
            .map(|id| decode_uuid("successor_assignment_id", id))
            .transpose()?
            != Some(applied.successor().assignment_id().into_uuid())
            || raw.successor_initial_revision != Some(1))
    {
        return Err(Error::Corrupt("Applied successor row indexes"));
    }
    if record.applied().is_none()
        && (raw.successor_assignment_id.is_some()
            || raw.successor_initial_revision.is_some()
            || raw.successor_snapshot.is_some()
            || raw.grant_evidence_snapshot.is_some())
    {
        return Err(Error::Corrupt("Aborted outcome contains effect fields"));
    }
    Ok(record)
}

fn validate_record_references(
    connection: &Connection,
    record: &HomeHandoffAcceptanceOutcomeRecord,
) -> Result<(), Error> {
    validate_case_reference(connection, record)?;
    let proposal = read_proposal_record(connection, record)?;
    let source =
        super::super::repository::read_record_with_inventory(connection, record.preparation_id())
            .map_err(|error| Error::HomeTransfer(Box::new(error)))?
            .ok_or(Error::Corrupt("acceptance Prepared source is missing"))?;
    let (source, inventory) = source;
    let inventory = inventory.ok_or(Error::Corrupt("acceptance Source inventory is missing"))?;
    if source.state() != super::super::HomeTransferSourceState::Prepared
        || source.issuer() != record.issuer()
        || source.request().scope() != record.request().scope()
        || source.request().witness().preparation_id() != record.preparation_id()
        || proposal.prepared_outcome_digest() != source.outcome_digest()
        || record.source_at() < source.observed_at()
    {
        return Err(Error::Corrupt("acceptance Prepared source pins"));
    }
    let source_pin = proposal.source();
    super::proposals::validate_prepared_assignment_pin(&source, &inventory, source_pin)
        .map_err(|_| Error::Corrupt("acceptance assignment differs from Prepared inventory"))?;
    if proposal.request().proposal_id() != record.proposal_id()
        || proposal.request().handoff_id() != record.handoff_id()
        || proposal.case_revision() != record.case_revision()
        || proposal.request().request_digest() != record.request().proposal_digest()
        || !proposal
            .request()
            .recipient()
            .has_same_identity(record.request().recipient())
        || proposal.request().preparation_id() != record.preparation_id()
        || proposal.request().predecessor_id() != record.predecessor_id()
        || record.source_at() < proposal.created_at()
        || source_pin.workspace_id() != record.workspace_id()
        || source_pin.assignment_id() != record.predecessor_id()
        || source_pin.root_assignment_id() != record.root_assignment_id()
    {
        return Err(Error::Corrupt("acceptance proposal pins"));
    }
    validate_predecessor_lineage_reference(
        connection,
        record.predecessor_id(),
        source_pin.lineage(),
    )?;
    validate_root_assignment_reference(connection, record.root_assignment_id(), source_pin)?;
    if let Some(applied) = record.applied() {
        validate_applied_assignments(connection, record, &proposal, source_pin, applied)?;
    }
    Ok(())
}

#[allow(
    clippy::type_complexity,
    reason = "four fixed 17-byte substr columns read the case identity row"
)]
fn validate_case_reference(
    connection: &Connection,
    record: &HomeHandoffAcceptanceOutcomeRecord,
) -> Result<(), Error> {
    let raw: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT substr(preparation_id,1,17),substr(workspace_id,1,17),
                    substr(predecessor_assignment_id,1,17),substr(root_assignment_id,1,17)
             FROM home_handoff_cases WHERE handoff_id=?1",
            params![record.handoff_id().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((preparation, workspace, predecessor, root)) = raw else {
        return Err(Error::Corrupt("acceptance Home case is missing"));
    };
    if decode_uuid("case.preparation_id", &preparation)? != record.preparation_id()
        || decode_uuid("case.workspace_id", &workspace)? != record.workspace_id().into_uuid()
        || decode_uuid("case.predecessor_assignment_id", &predecessor)?
            != record.predecessor_id().into_uuid()
        || decode_uuid("case.root_assignment_id", &root)? != record.root_assignment_id().into_uuid()
    {
        return Err(Error::Corrupt("acceptance Home case pins"));
    }
    Ok(())
}

fn read_proposal_record(
    connection: &Connection,
    record: &HomeHandoffAcceptanceOutcomeRecord,
) -> Result<HomeHandoffProposalRecord, Error> {
    let raw = connection
        .query_row(
            "SELECT case_revision,substr(request_digest,1,33),
                    substr(request_snapshot,1,321),substr(source_digest,1,33),
                    substr(source_snapshot,1,513),substr(prepared_outcome_digest,1,33),
                    evidence_kind,substr(artifact_id,1,17),substr(artifact_digest,1,33),
                    created_at_ms,substr(payload_digest,1,33)
             FROM home_handoff_proposals WHERE proposal_id=?1 AND handoff_id=?2 AND case_revision=?3",
            params![
                record.proposal_id().as_bytes(),
                record.handoff_id().as_bytes(),
                record.case_revision(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or(Error::Corrupt("acceptance proposal row is missing"))?;
    let evidence = decode_proposal_evidence(raw.6, raw.7.as_deref(), raw.8.as_deref())?;
    Ok(super::decode_proposal_record(
        &raw.2, &raw.1, raw.0, &raw.4, &raw.3, &raw.5, evidence, raw.9, &raw.10,
    )?)
}

fn decode_proposal_evidence(
    kind: i64,
    artifact_id: Option<&[u8]>,
    digest_bytes: Option<&[u8]>,
) -> Result<HomeHandoffProposalEvidence, Error> {
    match (kind, artifact_id, digest_bytes) {
        (0, None, None) => Ok(HomeHandoffProposalEvidence::NoArtifactRequested),
        (1, Some(id), Some(digest_bytes))
            if id.len() == 16 && digest_bytes.len() == DIGEST_BYTES =>
        {
            let artifact_id = decode_uuid("proposal.artifact_id", id)?;
            let archive_digest = digest(digest_bytes)?;
            if artifact_id.is_nil() || archive_digest == [0; DIGEST_BYTES] {
                return Err(Error::Corrupt("proposal artifact identity"));
            }
            let artifact_id = forge_domain::HomeArtifactId::new(artifact_id)
                .map_err(|_| Error::Corrupt("proposal artifact identity"))?;
            Ok(HomeHandoffProposalEvidence::SealedArtifact {
                artifact_id,
                archive_digest,
            })
        }
        _ => Err(Error::Corrupt("proposal evidence columns")),
    }
}

fn validate_predecessor_lineage_reference(
    connection: &Connection,
    assignment_id: AgentAssignmentId,
    lineage: HomeHandoffAssignmentLineage,
) -> Result<(), Error> {
    let pins = home_origin::read(connection, assignment_id)
        .map_err(assignment_error)?
        .ok_or(Error::Corrupt("acceptance predecessor is missing"))?;
    validate_assignment_lineage_reference(connection, &pins, lineage)
}

fn validate_assignment_lineage_reference(
    connection: &Connection,
    pins: &HomeOriginAssignmentPins,
    lineage: HomeHandoffAssignmentLineage,
) -> Result<(), Error> {
    match lineage {
        HomeHandoffAssignmentLineage::CoordinatorOffer => {
            if pins.origin_kind != 0 || pins.home_receipt_id.is_some() {
                return Err(Error::Corrupt("ordinary assignment origin pins"));
            }
        }
        HomeHandoffAssignmentLineage::HomeHandoff(origin) => {
            if pins.origin_kind != 1 {
                return Err(Error::Corrupt("Home assignment origin kind"));
            }
            let receipt_id = pins
                .home_receipt_id
                .ok_or(Error::Corrupt("Home assignment receipt ID"))?;
            validate_raw_applied_origin_reference(
                connection,
                pins.assignment_id,
                receipt_id,
                origin,
            )?;
        }
    }
    Ok(())
}

/// Validate exactly one ancestor Applied record and its current successor
/// pins. This checks the immediate provenance edge without recursively
/// traversing that ancestor's predecessor history.
fn validate_raw_applied_origin_reference(
    connection: &Connection,
    successor_id: AgentAssignmentId,
    acceptance_id: Uuid,
    origin: forge_domain::AgentAssignmentHomeHandoffOrigin,
) -> Result<(), Error> {
    let raw = read_raw_outcome(connection, acceptance_id)?;
    let Some(raw) = raw else {
        return Err(Error::Corrupt("Home origin Applied receipt is missing"));
    };
    let record = decode_stored_outcome(acceptance_id, &raw)?;
    let successor_pins = home_origin::read(connection, successor_id)
        .map_err(assignment_error)?
        .ok_or(Error::Corrupt("Home origin successor row is missing"))?;
    validate_immediate_ancestor_record(
        acceptance_id,
        successor_id,
        origin,
        &record,
        &successor_pins,
    )
}

fn validate_immediate_ancestor_record(
    acceptance_id: Uuid,
    successor_id: AgentAssignmentId,
    origin: forge_domain::AgentAssignmentHomeHandoffOrigin,
    record: &HomeHandoffAcceptanceOutcomeRecord,
    successor_pins: &HomeOriginAssignmentPins,
) -> Result<(), Error> {
    let Some(applied) = record.applied() else {
        return Err(Error::Corrupt("Home origin references an Aborted outcome"));
    };
    if record.acceptance_id() != acceptance_id
        || record.handoff_id() != origin.handoff_id()
        || record.preparation_id() != origin.preparation_id()
        || record.predecessor_id() != origin.predecessor_id()
        || record.root_assignment_id() != origin.root_assignment_id()
        || applied.successor().assignment_id() != successor_id
        || applied.successor().origin() != origin
        || !applied
            .successor()
            .matches_current_assignment(successor_pins, acceptance_id)
    {
        return Err(Error::Corrupt("Home origin Applied receipt pins"));
    }
    Ok(())
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "HomeHandoffSourceAssignmentPin is a Copy value object"
)]
fn validate_root_assignment_reference(
    connection: &Connection,
    root_id: AgentAssignmentId,
    source_pin: HomeHandoffSourceAssignmentPin,
) -> Result<(), Error> {
    let pins = home_origin::read(connection, root_id)
        .map_err(assignment_error)?
        .ok_or(Error::Corrupt("acceptance root assignment is missing"))?;
    if pins.origin_kind != 0
        || pins.home_receipt_id.is_some()
        || pins.workspace_id != source_pin.workspace_id()
        || pins.activity_id != source_pin.activity_id()
        || pins.goal_id != source_pin.goal_id()
        || pins.goal_created_at != source_pin.goal_created_at()
        || pins.goal_revision != source_pin.goal_revision()
        || pins.dag_revision != source_pin.dag_revision()
        || pins.dag_head_revision != source_pin.dag_head_revision()
        || pins.node_id != source_pin.node_id()
    {
        return Err(Error::Corrupt("acceptance root assignment pins"));
    }
    Ok(())
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "HomeHandoffSourceAssignmentPin is a Copy value object"
)]
fn validate_applied_assignments(
    connection: &Connection,
    record: &HomeHandoffAcceptanceOutcomeRecord,
    proposal: &HomeHandoffProposalRecord,
    source_pin: HomeHandoffSourceAssignmentPin,
    applied: &model::HomeHandoffAppliedAcceptance,
) -> Result<(), Error> {
    let successor = applied.successor();
    let source_disposition = match source_pin.state() {
        AgentAssignmentState::Offered => AgentAssignmentState::Cancelled,
        AgentAssignmentState::Running => AgentAssignmentState::Interrupted,
        _ => return Err(Error::Corrupt("proposal predecessor source state")),
    };
    if applied.predecessor_revision_before() != source_pin.revision()
        || source_pin.revision().get().checked_add(1)
            != Some(applied.predecessor_revision_after().get())
        || applied.predecessor_terminal_disposition() != source_disposition
        || successor.assignment_id() != proposal.request().successor_id()
        || successor.origin().preparation_id() != record.preparation_id()
        || successor.origin().handoff_id() != record.handoff_id()
        || successor.origin().predecessor_id() != record.predecessor_id()
        || successor.origin().root_assignment_id() != record.root_assignment_id()
        || successor.workspace_id() != record.workspace_id()
        || successor.activity_id() != source_pin.activity_id()
        || successor.goal_id() != source_pin.goal_id()
        || successor.goal_created_at() != source_pin.goal_created_at()
        || successor.goal_revision() != source_pin.goal_revision()
        || successor.dag_revision() != source_pin.dag_revision()
        || successor.dag_head_revision() != source_pin.dag_head_revision()
        || successor.node_id() != source_pin.node_id()
        || successor.node_revision().get() < source_pin.node_revision().get()
        || successor.coordinator()
            != AgentAssignmentCoordinator::from_actor(proposal.request().coordinator())
        || successor.target() != record.request().recipient()
        || successor.credit_budget() != source_pin.credit_budget()
        || successor.created_at() != record.source_at()
    {
        return Err(Error::Corrupt(
            "Applied successor does not match proposal pins",
        ));
    }

    let predecessor = home_origin::read(connection, record.predecessor_id())
        .map_err(assignment_error)?
        .ok_or(Error::Corrupt("Applied predecessor is missing"))?;
    if predecessor.assignment_id != source_pin.assignment_id()
        || predecessor.workspace_id != source_pin.workspace_id()
        || predecessor.activity_id != source_pin.activity_id()
        || predecessor.goal_id != source_pin.goal_id()
        || predecessor.goal_created_at != source_pin.goal_created_at()
        || predecessor.goal_revision != source_pin.goal_revision()
        || predecessor.dag_revision != source_pin.dag_revision()
        || predecessor.dag_head_revision != source_pin.dag_head_revision()
        || predecessor.node_id != source_pin.node_id()
        || predecessor.node_revision != source_pin.node_revision()
        || predecessor.coordinator != source_pin.coordinator()
        || predecessor.target != source_pin.target()
        || predecessor.credit_budget != source_pin.credit_budget()
        || predecessor.created_at != source_pin.created_at()
        || predecessor.updated_at != record.source_at()
        || predecessor.revision != applied.predecessor_revision_after()
        || predecessor.state != source_disposition
        || !predecessor.cancellation_requested
    {
        return Err(Error::Corrupt("Applied predecessor state pins"));
    }
    validate_assignment_lineage_reference(connection, &predecessor, source_pin.lineage())?;

    let successor_pins = home_origin::read(connection, successor.assignment_id())
        .map_err(assignment_error)?
        .ok_or(Error::Corrupt("Applied successor row is missing"))?;
    if !successor.matches_current_assignment(&successor_pins, record.acceptance_id()) {
        return Err(Error::Corrupt("Applied successor row pins"));
    }
    Ok(())
}

fn decode_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, Error> {
    if bytes.len() != 16 {
        return Err(Error::Corrupt(field));
    }
    Uuid::from_slice(bytes).map_err(|_| Error::Corrupt(field))
}

fn digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], Error> {
    if bytes.len() != DIGEST_BYTES {
        return Err(Error::Corrupt("digest width"));
    }
    bytes.try_into().map_err(|_| Error::Corrupt("digest width"))
}

fn timestamp(value: i64, field: &'static str) -> Result<TimestampMillis, Error> {
    TimestampMillis::new(value).map_err(|_| Error::Corrupt(field))
}

fn encode_assignment_state(state: AgentAssignmentState) -> i64 {
    match state {
        AgentAssignmentState::Offered => 0,
        AgentAssignmentState::Running => 1,
        AgentAssignmentState::Submitted => 2,
        AgentAssignmentState::Accepted => 3,
        AgentAssignmentState::Rejected => 4,
        AgentAssignmentState::Cancelled => 5,
        AgentAssignmentState::Interrupted => 6,
    }
}

fn assignment_error(error: crate::AgentAssignmentStoreError) -> Error {
    match error {
        crate::AgentAssignmentStoreError::Sqlite(source) => Error::Sqlite(source),
        other => Error::AgentAssignment(Box::new(other)),
    }
}

fn proposal_error_to_assignment(error: Error) -> crate::AgentAssignmentStoreError {
    match error {
        Error::Sqlite(source) => crate::AgentAssignmentStoreError::Sqlite(source),
        Error::AgentAssignment(source) => *source,
        Error::HomeTransfer(source) => crate::AgentAssignmentStoreError::HomeTransfer(source),
        Error::Proposal(source) => match *source {
            super::HomeHandoffProposalStoreError::Sqlite(source) => {
                crate::AgentAssignmentStoreError::Sqlite(source)
            }
            super::HomeHandoffProposalStoreError::AgentAssignment(source) => *source,
            super::HomeHandoffProposalStoreError::HomeTransfer(source) => {
                crate::AgentAssignmentStoreError::HomeTransfer(source)
            }
            _ => crate::AgentAssignmentStoreError::CorruptRecord("assignment.home_receipt_record"),
        },
        _ => crate::AgentAssignmentStoreError::CorruptRecord("assignment.home_receipt"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_agent_assignments::home_origin::HomeOriginAssignmentPins;
    use forge_domain::{
        ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId,
        AgentAssignmentHomeHandoffAcceptance, AgentAssignmentHomeHandoffOrigin,
        AgentAssignmentHomeHandoffTransition, AgentAssignmentRevision, AgentAssignmentTarget,
        AgentInstanceId, AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal,
        DagHeadRevision, DagNodeId, DagNodeRevision, DagRevisionNumber, ForgeBackendId, GoalId,
        GoalRevision, HomeHandoffAcceptanceGrant, HomeHandoffAcceptanceReceiptDigest,
        HomeHandoffAffinityAdmissionReferenceDigest, HomeHandoffProposalRequestDigest,
        HomeHandoffRecipientParticipation, HomeHandoffTakeRequest, HomeHandoffWorkAuthority,
        RegisteredAgentAssignment, TimestampMillis, WorkCreditBudget, WorkspaceId,
        WorkspaceRevision,
    };

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn digest(byte: u8) -> [u8; DIGEST_BYTES] {
        [byte; DIGEST_BYTES]
    }

    #[allow(
        clippy::too_many_lines,
        reason = "test fixture constructs complete valid predecessor, transition, grant, and outcome pins"
    )]
    fn fixture() -> Result<
        (
            HomeHandoffAcceptanceOutcomeRecord,
            HomeOriginAssignmentPins,
            forge_domain::AgentAssignmentHomeHandoffOrigin,
        ),
        Box<dyn std::error::Error>,
    > {
        let workspace_id = WorkspaceId::from_uuid(id(60));
        let activity_id = ActivityId::from_uuid(id(61));
        let coordinator = ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            AgentInstanceId::from_uuid(id(62)),
            ActivityCoordinatorRevision::new(3)?,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(id(63)),
        );
        let predecessor_id = AgentAssignmentId::from_uuid(id(64));
        let predecessor = RegisteredAgentAssignment::offered(
            predecessor_id,
            workspace_id,
            activity_id,
            GoalId::from_uuid(id(65)),
            TimestampMillis::new(1)?,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            DagNodeId::from_uuid(id(66)),
            DagNodeRevision::new(4)?,
            forge_domain::AgentAssignmentCoordinator::from_actor(coordinator),
            AgentAssignmentTarget::new(
                AgentInstanceId::from_uuid(id(67)),
                AgentSessionId::from_uuid(id(68)),
                AuthenticatedPrincipal::TrustedStdio,
                AgentInstanceRevision::INITIAL,
            ),
            Some(WorkCreditBudget::Three),
            TimestampMillis::new(2)?,
        )?;
        let acceptance_id = id(9);
        let handoff_id = id(70);
        let preparation_id = id(69);
        let successor_id = AgentAssignmentId::from_uuid(id(71));
        let origin = AgentAssignmentHomeHandoffOrigin::new(
            preparation_id,
            handoff_id,
            predecessor_id,
            predecessor_id,
        )?;
        let recipient = AgentAssignmentTarget::new(
            AgentInstanceId::from_uuid(id(72)),
            AgentSessionId::from_uuid(id(73)),
            AuthenticatedPrincipal::OAuthGrant(forge_domain::OAuthGrantId::from_uuid(id(74))),
            AgentInstanceRevision::new(2)?,
        );
        let effective_at = TimestampMillis::new(3)?;
        let transition = AgentAssignmentHomeHandoffTransition::new(
            &predecessor,
            predecessor.revision(),
            AgentAssignmentHomeHandoffAcceptance::new(
                origin,
                successor_id,
                recipient,
                coordinator,
                DagNodeRevision::new(5)?,
                effective_at,
            ),
        )?;
        let successor = HomeHandoffInitialSuccessorSnapshot::from_assignment(
            transition.successor(),
            effective_at,
        )?;
        let scope = forge_domain::HomeTransferSourceScope::new(
            workspace_id,
            WorkspaceRevision::new(2)?,
            ForgeBackendId::from_uuid(id(75)),
            id(76),
        )?;
        let request = HomeHandoffTakeRequest::new(
            acceptance_id,
            handoff_id,
            id(77),
            1,
            HomeHandoffProposalRequestDigest::from_bytes(digest(78))?,
            scope,
            recipient,
        )?;
        let issuer = OrchestrationIssuerId::from_uuid(id(79));
        let grant = HomeHandoffAcceptanceGrant::new(
            issuer,
            request.request_digest(),
            id(80),
            HomeHandoffAcceptanceReceiptDigest::from_bytes(digest(81))?,
            id(82),
            id(83),
            HomeHandoffRecipientParticipation::new(id(84), 85)?,
            HomeHandoffWorkAuthority::WorkspaceWork {
                affinity_admission_reference_digest:
                    HomeHandoffAffinityAdmissionReferenceDigest::from_bytes(digest(86))?,
            },
            TimestampMillis::new(3)?,
            TimestampMillis::new(4)?,
        )?;
        let record = model::HomeHandoffAcceptanceOutcomeRecord::from_stored_parts(
            model::HomeHandoffAcceptanceOutcomeRecordStoredParts {
                request,
                issuer,
                preparation_id,
                workspace_id,
                predecessor_id,
                root_assignment_id: predecessor_id,
                source_at: effective_at,
                outcome: model::HomeHandoffAcceptanceOutcome::Applied(
                    model::HomeHandoffAppliedAcceptance {
                        predecessor_revision_before: predecessor.revision(),
                        predecessor_revision_after: transition.predecessor().revision(),
                        predecessor_terminal_disposition: transition.predecessor().state(),
                        successor,
                        grant,
                    },
                ),
            },
        )?;
        let pins = HomeOriginAssignmentPins {
            assignment_id: successor_id,
            origin_kind: 1,
            home_receipt_id: Some(acceptance_id),
            workspace_id,
            activity_id,
            goal_id: predecessor.goal_id(),
            goal_created_at: predecessor.goal_created_at(),
            goal_revision: predecessor.goal_revision(),
            dag_revision: predecessor.dag_revision(),
            dag_head_revision: predecessor.dag_head_revision(),
            node_id: predecessor.node_id(),
            node_revision: DagNodeRevision::new(5)?,
            coordinator: transition.successor().coordinator(),
            target: recipient,
            credit_budget: predecessor.credit_budget(),
            created_at: effective_at,
            updated_at: effective_at,
            revision: AgentAssignmentRevision::INITIAL,
            state: AgentAssignmentState::Running,
            cancellation_requested: false,
        };
        Ok((record, pins, origin))
    }

    fn raw(
        record: &HomeHandoffAcceptanceOutcomeRecord,
    ) -> Result<RawOutcome, Box<dyn std::error::Error>> {
        let applied = record
            .applied()
            .ok_or_else(|| std::io::Error::other("test fixture must be Applied"))?;
        Ok(RawOutcome {
            request_digest: record.request().request_digest().as_bytes().to_vec(),
            request_snapshot: record.request().canonical_snapshot(),
            issuer_id: record.issuer().into_uuid().as_bytes().to_vec(),
            handoff_id: record.handoff_id().as_bytes().to_vec(),
            proposal_id: record.proposal_id().as_bytes().to_vec(),
            case_revision: record.case_revision(),
            preparation_id: record.preparation_id().as_bytes().to_vec(),
            workspace_id: record.workspace_id().into_uuid().as_bytes().to_vec(),
            predecessor_assignment_id: record.predecessor_id().into_uuid().as_bytes().to_vec(),
            root_assignment_id: record.root_assignment_id().into_uuid().as_bytes().to_vec(),
            outcome_kind: 1,
            source_observed_at_ms: record.source_at().get(),
            predecessor_revision_before: Some(applied.predecessor_revision_before().get()),
            predecessor_revision_after: Some(applied.predecessor_revision_after().get()),
            predecessor_terminal_disposition: Some(5),
            successor_assignment_id: Some(
                applied
                    .successor()
                    .assignment_id()
                    .into_uuid()
                    .as_bytes()
                    .to_vec(),
            ),
            successor_initial_revision: Some(1),
            successor_snapshot: Some(codec::encode_successor_snapshot(applied.successor())),
            grant_evidence_snapshot: Some(codec::encode_grant_snapshot(applied.grant())?),
            payload_digest: record.payload_digest().as_slice().to_vec(),
        })
    }

    #[test]
    fn immediate_ancestor_reader_checks_canonical_record_and_current_successor_pins()
    -> Result<(), Box<dyn std::error::Error>> {
        let (record, pins, origin) = fixture()?;
        let acceptance_id = record.acceptance_id();
        let successor_id = pins.assignment_id;
        let original_raw = raw(&record)?;
        let decoded = decode_stored_outcome(acceptance_id, &original_raw)?;
        validate_immediate_ancestor_record(acceptance_id, successor_id, origin, &decoded, &pins)?;

        let mut wrong_payload_digest = raw(&record)?;
        wrong_payload_digest.payload_digest[0] ^= 1;
        assert!(decode_stored_outcome(acceptance_id, &wrong_payload_digest).is_err());

        let mut wrong_request = raw(&record)?;
        wrong_request.request_snapshot[5] ^= 1;
        assert!(decode_stored_outcome(acceptance_id, &wrong_request).is_err());

        let mut wrong_row_selector = raw(&record)?;
        wrong_row_selector.handoff_id[0] ^= 1;
        assert!(decode_stored_outcome(acceptance_id, &wrong_row_selector).is_err());

        let mut wrong_successor_snapshot = raw(&record)?;
        wrong_successor_snapshot
            .successor_snapshot
            .as_mut()
            .ok_or_else(|| std::io::Error::other("test successor snapshot missing"))?[5] ^= 1;
        assert!(decode_stored_outcome(acceptance_id, &wrong_successor_snapshot).is_err());

        let mut wrong_grant = raw(&record)?;
        let grant = wrong_grant
            .grant_evidence_snapshot
            .as_mut()
            .ok_or_else(|| std::io::Error::other("test grant snapshot missing"))?;
        grant[5] = 2;
        assert!(decode_stored_outcome(acceptance_id, &wrong_grant).is_err());

        let wrong_successor = HomeOriginAssignmentPins {
            target: AgentAssignmentTarget::new(
                AgentInstanceId::from_uuid(id(90)),
                pins.target.session_id(),
                pins.target.principal(),
                pins.target.agent_revision(),
            ),
            ..pins
        };
        assert!(
            validate_immediate_ancestor_record(
                acceptance_id,
                successor_id,
                origin,
                &record,
                &wrong_successor,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn immediate_ancestor_allows_running_successor_lifecycle_but_not_offer()
    -> Result<(), Box<dyn std::error::Error>> {
        let (record, pins, origin) = fixture()?;
        let acceptance_id = record.acceptance_id();
        let successor_id = pins.assignment_id;

        for (state, cancellation_requested, revision) in [
            (AgentAssignmentState::Submitted, false, 2_i64),
            (AgentAssignmentState::Accepted, false, 3_i64),
            (AgentAssignmentState::Rejected, false, 3_i64),
            (AgentAssignmentState::Cancelled, true, 3_i64),
            (AgentAssignmentState::Interrupted, true, 2_i64),
        ] {
            let lifecycle_pins = HomeOriginAssignmentPins {
                updated_at: TimestampMillis::new(revision + 3)?,
                revision: AgentAssignmentRevision::new(revision)?,
                state,
                cancellation_requested,
                ..pins
            };
            validate_immediate_ancestor_record(
                acceptance_id,
                successor_id,
                origin,
                &record,
                &lifecycle_pins,
            )?;
        }

        let offered_pins = HomeOriginAssignmentPins {
            state: AgentAssignmentState::Offered,
            ..pins
        };
        assert!(
            validate_immediate_ancestor_record(
                acceptance_id,
                successor_id,
                origin,
                &record,
                &offered_pins,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn applied_history_rejects_a_grant_outside_its_recorded_source_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let (record, _, _) = fixture()?;
        let original = record.applied().ok_or("fixture is not Applied")?;
        let grant = original.grant();
        for (issued_at, expires_at) in [(4, 5), (2, 3)] {
            let mut applied = original.clone();
            applied.grant = HomeHandoffAcceptanceGrant::new(
                grant.issuer(),
                grant.take_request_digest(),
                grant.acceptance_receipt_id(),
                grant.acceptance_receipt_digest(),
                grant.moving_profile_id(),
                grant.recipient_profile_id(),
                grant.recipient_participation(),
                grant.work_authority(),
                TimestampMillis::new(issued_at)?,
                TimestampMillis::new(expires_at)?,
            )?;
            assert!(
                HomeHandoffAcceptanceOutcomeRecord::from_stored_parts(
                    model::HomeHandoffAcceptanceOutcomeRecordStoredParts {
                        request: record.request(),
                        issuer: record.issuer(),
                        preparation_id: record.preparation_id(),
                        workspace_id: record.workspace_id(),
                        predecessor_id: record.predecessor_id(),
                        root_assignment_id: record.root_assignment_id(),
                        source_at: record.source_at(),
                        outcome: HomeHandoffAcceptanceOutcome::Applied(applied),
                    },
                )
                .is_err()
            );
        }
        Ok(())
    }
}
