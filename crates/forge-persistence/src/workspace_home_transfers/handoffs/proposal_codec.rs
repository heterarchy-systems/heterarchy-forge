//! Bounded, canonical snapshots for persisted Home proposal requests and pins.

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentAssignmentCoordinator,
    AgentAssignmentHomeHandoffOrigin, AgentAssignmentId, AgentAssignmentRevision,
    AgentAssignmentState, AgentAssignmentTarget, AgentInstanceId, AgentInstanceRevision,
    AgentSessionId, AuthenticatedPrincipal, DagHeadRevision, DagNodeId, DagNodeRevision,
    DagRevisionNumber, DirectTokenId, GoalId, GoalRevision, HomeArtifactId,
    HomeHandoffProposalRequest, OAuthGrantId, TimestampMillis, WorkCreditBudget, WorkspaceId,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::HomeHandoffProposalStoreError;
use super::proposal_model::{
    HomeHandoffAssignmentLineage, HomeHandoffProposalEvidence, HomeHandoffProposalRecord,
    HomeHandoffSourceAssignmentPin, SourceAssignmentPinParts,
};
use super::proposal_schema::{MAX_REQUEST_SNAPSHOT_BYTES, MAX_SOURCE_SNAPSHOT_BYTES};

const REQUEST_MAGIC: &[u8; 4] = b"HHPR";
const SOURCE_MAGIC: &[u8; 4] = b"HHPS";
const REQUEST_SNAPSHOT_BYTES: usize = 265;
const DIGEST_BYTES: usize = 32;
const SOURCE_DOMAIN: &[u8] = b"heterarchy.forge.home-handoff-proposal.source.v1\0";
const RECORD_DOMAIN: &[u8] = b"heterarchy.forge.home-handoff-proposal.record.v1\0";

pub(super) fn decode_request(
    bytes: &[u8],
    expected_digest: &[u8],
) -> Result<HomeHandoffProposalRequest, HomeHandoffProposalStoreError> {
    if bytes.len() != REQUEST_SNAPSHOT_BYTES
        || bytes.len() > MAX_REQUEST_SNAPSHOT_BYTES
        || expected_digest.len() != DIGEST_BYTES
    {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "request snapshot bound or digest width",
        ));
    }
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != REQUEST_MAGIC || reader.u8()? != 1 {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "request snapshot version",
        ));
    }
    let proposal_id = reader.uuid()?;
    let handoff_id = reader.uuid()?;
    let preparation_id = reader.uuid()?;
    let predecessor_id = AgentAssignmentId::from_uuid(reader.uuid()?);
    let predecessor_revision = AgentAssignmentRevision::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("predecessor revision"))?;
    let successor_id = AgentAssignmentId::from_uuid(reader.uuid()?);
    let coordinator_workspace_id = WorkspaceId::from_uuid(reader.uuid()?);
    let coordinator_activity_id = ActivityId::from_uuid(reader.uuid()?);
    let coordinator_agent_id = AgentInstanceId::from_uuid(reader.uuid()?);
    let coordinator_session_id = AgentSessionId::from_uuid(reader.uuid()?);
    let coordinator_principal = reader.principal()?;
    let coordinator_revision = ActivityCoordinatorRevision::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("Coordinator revision"))?;
    let recipient_agent_id = AgentInstanceId::from_uuid(reader.uuid()?);
    let recipient_session_id = AgentSessionId::from_uuid(reader.uuid()?);
    let recipient_principal = reader.principal()?;
    let recipient_revision = AgentInstanceRevision::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("recipient Agent revision"))?;
    let artifact_id = reader
        .optional_uuid()?
        .map(|artifact_id| {
            HomeArtifactId::new(artifact_id)
                .map_err(|_| HomeHandoffProposalStoreError::Corrupt("artifact ID"))
        })
        .transpose()?;
    let expected_case_revision = reader.optional_i64()?;
    if !reader.is_finished() {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "request snapshot trailing bytes",
        ));
    }

    let coordinator = ActivityCoordinatorActor::new(
        coordinator_workspace_id,
        coordinator_activity_id,
        coordinator_agent_id,
        coordinator_revision,
        coordinator_principal,
        coordinator_session_id,
    );
    let recipient = AgentAssignmentTarget::new(
        recipient_agent_id,
        recipient_session_id,
        recipient_principal,
        recipient_revision,
    );
    let request = HomeHandoffProposalRequest::new(
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
    )?;
    if request.canonical_snapshot().as_slice() != bytes
        || request.request_digest().as_bytes().as_slice() != expected_digest
    {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "request snapshot is not canonical",
        ));
    }
    Ok(request)
}

pub(super) fn encode_source(
    source: HomeHandoffSourceAssignmentPin,
) -> Result<Vec<u8>, HomeHandoffProposalStoreError> {
    let mut bytes = Vec::with_capacity(MAX_SOURCE_SNAPSHOT_BYTES);
    bytes.extend_from_slice(SOURCE_MAGIC);
    bytes.push(1);
    append_uuid(&mut bytes, source.assignment_id().into_uuid());
    append_uuid(&mut bytes, source.root_assignment_id().into_uuid());
    append_uuid(&mut bytes, source.workspace_id().into_uuid());
    append_uuid(&mut bytes, source.activity_id().into_uuid());
    append_uuid(&mut bytes, source.goal_id().into_uuid());
    append_i64(&mut bytes, source.goal_created_at().get());
    append_i64(&mut bytes, source.goal_revision().get());
    append_i64(&mut bytes, source.dag_revision().get());
    append_i64(&mut bytes, source.dag_head_revision().get());
    append_uuid(&mut bytes, source.node_id().into_uuid());
    append_i64(&mut bytes, source.node_revision().get());

    let coordinator = source.coordinator();
    append_uuid(&mut bytes, coordinator.agent_id().into_uuid());
    append_uuid(&mut bytes, coordinator.session_id().into_uuid());
    append_principal(&mut bytes, coordinator.principal());
    append_i64(&mut bytes, coordinator.revision().get());

    let target = source.target();
    append_uuid(&mut bytes, target.agent_id().into_uuid());
    append_uuid(&mut bytes, target.session_id().into_uuid());
    append_principal(&mut bytes, target.principal());
    append_i64(&mut bytes, target.agent_revision().get());

    bytes.push(match source.state() {
        AgentAssignmentState::Offered => 0,
        AgentAssignmentState::Running => 1,
        _ => {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "unsupported source assignment state",
            ));
        }
    });
    bytes.push(u8::from(source.cancellation_requested()));
    bytes.push(match source.credit_budget() {
        None => 0,
        Some(WorkCreditBudget::One) => 1,
        Some(WorkCreditBudget::Three) => 3,
        Some(WorkCreditBudget::Five) => 5,
    });
    append_i64(&mut bytes, source.created_at().get());
    append_i64(&mut bytes, source.updated_at().get());
    append_i64(&mut bytes, source.revision().get());
    match source.lineage() {
        HomeHandoffAssignmentLineage::CoordinatorOffer => bytes.push(0),
        HomeHandoffAssignmentLineage::HomeHandoff(origin) => {
            bytes.push(1);
            append_uuid(&mut bytes, origin.preparation_id());
            append_uuid(&mut bytes, origin.handoff_id());
            append_uuid(&mut bytes, origin.predecessor_id().into_uuid());
            append_uuid(&mut bytes, origin.root_assignment_id().into_uuid());
        }
    }
    if bytes.len() > MAX_SOURCE_SNAPSHOT_BYTES {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "source snapshot exceeds its bound",
        ));
    }
    Ok(bytes)
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded snapshot decoder validates every immutable source pin together"
)]
pub(super) fn decode_source(
    bytes: &[u8],
) -> Result<HomeHandoffSourceAssignmentPin, HomeHandoffProposalStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_SNAPSHOT_BYTES {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "source snapshot bound",
        ));
    }
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != SOURCE_MAGIC || reader.u8()? != 1 {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "source snapshot version",
        ));
    }
    let assignment_id = AgentAssignmentId::from_uuid(reader.uuid()?);
    let root_assignment_id = AgentAssignmentId::from_uuid(reader.uuid()?);
    let workspace_id = WorkspaceId::from_uuid(reader.uuid()?);
    let activity_id = ActivityId::from_uuid(reader.uuid()?);
    let goal_id = GoalId::from_uuid(reader.uuid()?);
    let goal_created_at = timestamp(reader.i64()?, "Goal created_at")?;
    let goal_revision = GoalRevision::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("Goal revision"))?;
    let dag_revision = DagRevisionNumber::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("DAG revision"))?;
    let dag_head_revision = DagHeadRevision::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("DAG head revision"))?;
    let node_id = DagNodeId::from_uuid(reader.uuid()?);
    let node_revision = DagNodeRevision::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("Node revision"))?;

    let coordinator = AgentAssignmentCoordinator::new(
        AgentInstanceId::from_uuid(reader.uuid()?),
        AgentSessionId::from_uuid(reader.uuid()?),
        reader.principal()?,
        ActivityCoordinatorRevision::new(reader.i64()?)
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("Coordinator revision"))?,
    );
    let target = AgentAssignmentTarget::new(
        AgentInstanceId::from_uuid(reader.uuid()?),
        AgentSessionId::from_uuid(reader.uuid()?),
        reader.principal()?,
        AgentInstanceRevision::new(reader.i64()?)
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("target Agent revision"))?,
    );
    let state = match reader.u8()? {
        0 => AgentAssignmentState::Offered,
        1 => AgentAssignmentState::Running,
        _ => {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "source assignment state",
            ));
        }
    };
    let cancellation_requested = reader.boolean()?;
    let credit_budget = match reader.u8()? {
        0 => None,
        value @ (1 | 3 | 5) => Some(
            WorkCreditBudget::try_from_i64(i64::from(value))
                .map_err(|_| HomeHandoffProposalStoreError::Corrupt("credit budget"))?,
        ),
        _ => {
            return Err(HomeHandoffProposalStoreError::Corrupt("credit budget tag"));
        }
    };
    let created_at = timestamp(reader.i64()?, "Assignment created_at")?;
    let updated_at = timestamp(reader.i64()?, "Assignment updated_at")?;
    let revision = AgentAssignmentRevision::new(reader.i64()?)
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("Assignment revision"))?;
    let lineage = match reader.u8()? {
        0 => HomeHandoffAssignmentLineage::CoordinatorOffer,
        1 => {
            let origin = AgentAssignmentHomeHandoffOrigin::new(
                reader.uuid()?,
                reader.uuid()?,
                AgentAssignmentId::from_uuid(reader.uuid()?),
                AgentAssignmentId::from_uuid(reader.uuid()?),
            )
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("Home origin"))?;
            HomeHandoffAssignmentLineage::HomeHandoff(origin)
        }
        _ => {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "source assignment lineage tag",
            ));
        }
    };
    if !reader.is_finished() {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "source snapshot trailing bytes",
        ));
    }
    let source = HomeHandoffSourceAssignmentPin::from_parts(SourceAssignmentPinParts {
        assignment_id,
        root_assignment_id,
        workspace_id,
        activity_id,
        goal_id,
        goal_created_at,
        goal_revision,
        dag_revision,
        dag_head_revision,
        node_id,
        node_revision,
        coordinator,
        target,
        state,
        cancellation_requested,
        credit_budget,
        created_at,
        updated_at,
        revision,
        lineage,
    })?;
    if encode_source(source)?.as_slice() != bytes {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "source snapshot is not canonical",
        ));
    }
    Ok(source)
}

pub(super) fn source_digest(
    bytes: &[u8],
) -> Result<[u8; DIGEST_BYTES], HomeHandoffProposalStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_SNAPSHOT_BYTES {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "source digest input bound",
        ));
    }
    Ok(digest(SOURCE_DOMAIN, bytes))
}

pub(super) fn record_digest(
    request: &HomeHandoffProposalRequest,
    case_revision: i64,
    source: &HomeHandoffSourceAssignmentPin,
    prepared_outcome_digest: &[u8; DIGEST_BYTES],
    evidence: HomeHandoffProposalEvidence,
    created_at: TimestampMillis,
) -> Result<[u8; DIGEST_BYTES], HomeHandoffProposalStoreError> {
    let request_bytes = request.canonical_snapshot();
    let source_bytes = encode_source(*source)?;
    let mut bytes = Vec::with_capacity(request_bytes.len() + source_bytes.len() + 128);
    append_len_prefixed(&mut bytes, &request_bytes)?;
    append_i64(&mut bytes, case_revision);
    append_len_prefixed(&mut bytes, &source_bytes)?;
    bytes.extend_from_slice(prepared_outcome_digest);
    match evidence {
        HomeHandoffProposalEvidence::NoArtifactRequested => bytes.push(0),
        HomeHandoffProposalEvidence::SealedArtifact {
            artifact_id,
            archive_digest,
        } => {
            bytes.push(1);
            append_uuid(&mut bytes, artifact_id.into_uuid());
            bytes.extend_from_slice(&archive_digest);
        }
    }
    append_i64(&mut bytes, created_at.get());
    Ok(digest(RECORD_DOMAIN, &bytes))
}

pub(super) fn persisted_evidence(
    kind: i64,
    artifact_id: Option<&[u8]>,
    artifact_digest: Option<&[u8]>,
) -> Result<HomeHandoffProposalEvidence, HomeHandoffProposalStoreError> {
    match (kind, artifact_id, artifact_digest) {
        (0, None, None) => Ok(HomeHandoffProposalEvidence::NoArtifactRequested),
        (1, Some(id), Some(digest)) if id.len() == 16 && digest.len() == DIGEST_BYTES => {
            let artifact_uuid = Uuid::from_slice(id)
                .map_err(|_| HomeHandoffProposalStoreError::Corrupt("artifact ID"))?;
            let archive_digest: [u8; DIGEST_BYTES] = digest
                .try_into()
                .map_err(|_| HomeHandoffProposalStoreError::Corrupt("archive digest width"))?;
            if artifact_uuid.is_nil() || archive_digest == [0; DIGEST_BYTES] {
                return Err(HomeHandoffProposalStoreError::Corrupt(
                    "empty artifact identity or archive digest",
                ));
            }
            Ok(HomeHandoffProposalEvidence::SealedArtifact {
                artifact_id: HomeArtifactId::new(artifact_uuid)
                    .map_err(|_| HomeHandoffProposalStoreError::Corrupt("artifact ID"))?,
                archive_digest,
            })
        }
        _ => Err(HomeHandoffProposalStoreError::Corrupt(
            "proposal evidence columns",
        )),
    }
}

pub(super) fn decode_record(
    request_snapshot: &[u8],
    request_digest: &[u8],
    case_revision: i64,
    source_snapshot: &[u8],
    stored_source_digest: &[u8],
    prepared_outcome_digest: &[u8],
    evidence: HomeHandoffProposalEvidence,
    created_at_ms: i64,
    payload_digest: &[u8],
) -> Result<HomeHandoffProposalRecord, HomeHandoffProposalStoreError> {
    let request = decode_request(request_snapshot, request_digest)?;
    let source = decode_source(source_snapshot)?;
    let expected_source_digest = source_digest(source_snapshot)?;
    if stored_source_digest.len() != DIGEST_BYTES
        || stored_source_digest != expected_source_digest.as_slice()
        || prepared_outcome_digest.len() != DIGEST_BYTES
        || payload_digest.len() != DIGEST_BYTES
    {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "proposal digest widths or checksum",
        ));
    }
    let prepared_digest: [u8; DIGEST_BYTES] = prepared_outcome_digest
        .try_into()
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("Prepared digest width"))?;
    let created_at = timestamp(created_at_ms, "proposal created_at")?;
    let record = HomeHandoffProposalRecord::new(
        request,
        case_revision,
        source,
        prepared_digest,
        evidence,
        created_at,
    )?;
    if record.payload_digest().as_slice() != payload_digest {
        return Err(HomeHandoffProposalStoreError::Corrupt(
            "proposal payload checksum",
        ));
    }
    Ok(record)
}

fn timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, HomeHandoffProposalStoreError> {
    TimestampMillis::new(value).map_err(|_| HomeHandoffProposalStoreError::Corrupt(field))
}

pub(super) fn append_len_prefixed(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), HomeHandoffProposalStoreError> {
    let length = u32::try_from(value.len())
        .map_err(|_| HomeHandoffProposalStoreError::Corrupt("snapshot length"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub(super) fn append_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_uuid(output: &mut Vec<u8>, value: Uuid) {
    output.extend_from_slice(value.as_bytes());
}

fn append_principal(output: &mut Vec<u8>, principal: AuthenticatedPrincipal) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => {
            output.push(0);
            output.extend_from_slice(Uuid::nil().as_bytes());
        }
        AuthenticatedPrincipal::DirectToken(id) => {
            output.push(1);
            append_uuid(output, id.into_uuid());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            output.push(2);
            append_uuid(output, id.into_uuid());
        }
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], HomeHandoffProposalStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HomeHandoffProposalStoreError::Corrupt(
                "snapshot length overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(HomeHandoffProposalStoreError::Corrupt("truncated snapshot"))?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn u8(&mut self) -> Result<u8, HomeHandoffProposalStoreError> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, HomeHandoffProposalStoreError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HomeHandoffProposalStoreError::Corrupt("snapshot boolean")),
        }
    }

    pub(super) fn i64(&mut self) -> Result<i64, HomeHandoffProposalStoreError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("snapshot integer"))?;
        Ok(i64::from_be_bytes(bytes))
    }

    pub(super) fn uuid(&mut self) -> Result<Uuid, HomeHandoffProposalStoreError> {
        Uuid::from_slice(self.take(16)?)
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("snapshot UUID"))
    }

    fn principal(&mut self) -> Result<AuthenticatedPrincipal, HomeHandoffProposalStoreError> {
        let kind = self.u8()?;
        let id = self.uuid()?;
        match kind {
            0 if id.is_nil() => Ok(AuthenticatedPrincipal::TrustedStdio),
            1 if !id.is_nil() => Ok(AuthenticatedPrincipal::DirectToken(
                DirectTokenId::from_uuid(id),
            )),
            2 if !id.is_nil() => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
                id,
            ))),
            _ => Err(HomeHandoffProposalStoreError::Corrupt("snapshot principal")),
        }
    }

    fn optional_uuid(&mut self) -> Result<Option<Uuid>, HomeHandoffProposalStoreError> {
        let tag = self.u8()?;
        let value = self.uuid()?;
        match (tag, value) {
            (0, value) if value.is_nil() => Ok(None),
            (1, value) if !value.is_nil() => Ok(Some(value)),
            _ => Err(HomeHandoffProposalStoreError::Corrupt(
                "optional UUID tag or padding",
            )),
        }
    }

    fn optional_i64(&mut self) -> Result<Option<i64>, HomeHandoffProposalStoreError> {
        let tag = self.u8()?;
        let value = self.i64()?;
        match (tag, value) {
            (0, 0) => Ok(None),
            (1, value) if value >= 1 => Ok(Some(value)),
            _ => Err(HomeHandoffProposalStoreError::Corrupt(
                "optional integer tag or padding",
            )),
        }
    }

    pub(super) fn array32(&mut self) -> Result<[u8; DIGEST_BYTES], HomeHandoffProposalStoreError> {
        self.take(DIGEST_BYTES)?
            .try_into()
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("snapshot digest width"))
    }

    pub(super) fn length_prefixed(
        &mut self,
        maximum: usize,
    ) -> Result<&'a [u8], HomeHandoffProposalStoreError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("snapshot component length"))?;
        if length == 0 || length > maximum {
            return Err(HomeHandoffProposalStoreError::Corrupt(
                "snapshot component bound",
            ));
        }
        self.take(length)
    }

    fn u32(&mut self) -> Result<u32, HomeHandoffProposalStoreError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| HomeHandoffProposalStoreError::Corrupt("snapshot length width"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub(super) const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
