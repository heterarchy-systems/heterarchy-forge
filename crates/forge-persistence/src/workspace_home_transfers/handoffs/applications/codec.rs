//! Fixed-shape, bounded codecs for terminal Home acceptance rows.

use forge_domain::{
    ActivityCoordinatorRevision, ActivityId, AgentAssignmentCoordinator,
    AgentAssignmentHomeHandoffOrigin, AgentAssignmentId, AgentAssignmentRevision,
    AgentAssignmentState, AgentAssignmentTarget, AgentInstanceId, AgentInstanceRevision,
    AgentSessionId, AuthenticatedPrincipal, DagHeadRevision, DagNodeId, DagNodeRevision,
    DagRevisionNumber, DirectTokenId, GoalId, GoalRevision, HomeHandoffAcceptanceGrant,
    HomeHandoffAcceptanceReceiptDigest, HomeHandoffAffinityAdmissionReferenceDigest,
    HomeHandoffHomeTeamAuthority, HomeHandoffNodeBindingDigest, HomeHandoffRecipientParticipation,
    HomeHandoffTakeRequest, HomeHandoffTakeRequestDigest, HomeHandoffTemporaryDispatchAuthority,
    HomeHandoffWorkAuthority, OAuthGrantId, TimestampMillis, WorkCreditBudget, WorkspaceId,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::model::HomeHandoffAcceptanceOutcomeRecordStoredParts;
use super::schema::{
    MAX_GRANT_SNAPSHOT_BYTES, MAX_REQUEST_SNAPSHOT_BYTES, MAX_SUCCESSOR_SNAPSHOT_BYTES,
};
use super::{
    HomeHandoffAcceptanceOutcome, HomeHandoffAcceptanceOutcomeRecord,
    HomeHandoffApplicationStoreError as Error, HomeHandoffAppliedAcceptance,
    HomeHandoffInitialSuccessorSnapshot,
};

const DIGEST_BYTES: usize = 32;
const GRANT_MAGIC: &[u8; 4] = b"HHAG";
const SUCCESSOR_MAGIC: &[u8; 4] = b"HHAS";
const OUTCOME_DOMAIN: &[u8] = b"heterarchy.forge.home-handoff.acceptance-outcome.v1\0";

pub(super) fn decode_take_request(
    snapshot: &[u8],
    expected_digest: &[u8],
) -> Result<HomeHandoffTakeRequest, Error> {
    if snapshot.len() > MAX_REQUEST_SNAPSHOT_BYTES || expected_digest.len() != DIGEST_BYTES {
        return Err(Error::Corrupt("take request snapshot bound"));
    }
    let request = HomeHandoffTakeRequest::from_canonical_snapshot(snapshot)
        .map_err(|_| Error::Corrupt("take request snapshot"))?;
    if request.request_digest().as_bytes().as_slice() != expected_digest {
        return Err(Error::Corrupt("take request snapshot is not canonical"));
    }
    Ok(request)
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "HomeHandoffAcceptanceGrant is a Copy value object"
)]
pub(super) fn encode_grant_snapshot(grant: HomeHandoffAcceptanceGrant) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::with_capacity(MAX_GRANT_SNAPSHOT_BYTES);
    bytes.extend_from_slice(GRANT_MAGIC);
    bytes.push(1);
    append_uuid(&mut bytes, grant.issuer().into_uuid());
    bytes.extend_from_slice(grant.take_request_digest().as_bytes());
    append_uuid(&mut bytes, grant.acceptance_receipt_id());
    bytes.extend_from_slice(grant.acceptance_receipt_digest().as_bytes());
    append_uuid(&mut bytes, grant.moving_profile_id());
    append_uuid(&mut bytes, grant.recipient_profile_id());
    append_uuid(&mut bytes, grant.recipient_participation().id());
    append_u64(&mut bytes, grant.recipient_participation().revision());
    match grant.work_authority() {
        HomeHandoffWorkAuthority::WorkspaceWork {
            affinity_admission_reference_digest,
        } => {
            bytes.push(0);
            bytes.extend_from_slice(affinity_admission_reference_digest.as_bytes());
        }
        HomeHandoffWorkAuthority::HomeTeam(authority) => {
            bytes.push(1);
            bytes.extend_from_slice(authority.affinity_admission_reference_digest().as_bytes());
            append_uuid(&mut bytes, authority.team_id());
            append_u64(&mut bytes, authority.membership_revision());
            append_u64(&mut bytes, authority.node_binding_revision());
            bytes.extend_from_slice(authority.node_binding_digest().as_bytes());
        }
        HomeHandoffWorkAuthority::TemporaryDispatch(authority) => {
            bytes.push(2);
            bytes.extend_from_slice(authority.affinity_admission_reference_digest().as_bytes());
            append_uuid(&mut bytes, authority.dispatch_id());
            append_uuid(&mut bytes, authority.destination_team_id());
            append_u64(&mut bytes, authority.reservation_authority_revision());
            append_u64(&mut bytes, authority.node_binding_revision());
            bytes.extend_from_slice(authority.node_binding_digest().as_bytes());
            append_i64(&mut bytes, authority.end_at().get());
        }
    }
    append_i64(&mut bytes, grant.issued_at().get());
    append_i64(&mut bytes, grant.expires_at().get());
    if bytes.len() > MAX_GRANT_SNAPSHOT_BYTES {
        return Err(Error::Corrupt("acceptance grant snapshot bound"));
    }
    Ok(bytes)
}

pub(super) fn decode_grant_snapshot(snapshot: &[u8]) -> Result<HomeHandoffAcceptanceGrant, Error> {
    if snapshot.is_empty() || snapshot.len() > MAX_GRANT_SNAPSHOT_BYTES {
        return Err(Error::Corrupt("acceptance grant snapshot bound"));
    }
    let mut reader = Reader::new(snapshot);
    if reader.take(4)? != GRANT_MAGIC || reader.u8()? != 1 {
        return Err(Error::Corrupt("acceptance grant snapshot version"));
    }
    let issuer = forge_domain::OrchestrationIssuerId::from_uuid(reader.uuid()?);
    let request_digest = HomeHandoffTakeRequestDigest::from_bytes(reader.digest()?)?;
    let acceptance_receipt_id = reader.uuid()?;
    let acceptance_receipt_digest =
        HomeHandoffAcceptanceReceiptDigest::from_bytes(reader.digest()?)?;
    let moving_profile_id = reader.uuid()?;
    let recipient_profile_id = reader.uuid()?;
    let participation = HomeHandoffRecipientParticipation::new(reader.uuid()?, reader.u64()?)?;
    let work_authority = match reader.u8()? {
        0 => HomeHandoffWorkAuthority::WorkspaceWork {
            affinity_admission_reference_digest:
                HomeHandoffAffinityAdmissionReferenceDigest::from_bytes(reader.digest()?)?,
        },
        1 => HomeHandoffWorkAuthority::HomeTeam(HomeHandoffHomeTeamAuthority::new(
            HomeHandoffAffinityAdmissionReferenceDigest::from_bytes(reader.digest()?)?,
            reader.uuid()?,
            reader.u64()?,
            reader.u64()?,
            HomeHandoffNodeBindingDigest::from_bytes(reader.digest()?)?,
        )?),
        2 => {
            HomeHandoffWorkAuthority::TemporaryDispatch(HomeHandoffTemporaryDispatchAuthority::new(
                HomeHandoffAffinityAdmissionReferenceDigest::from_bytes(reader.digest()?)?,
                reader.uuid()?,
                reader.uuid()?,
                reader.u64()?,
                reader.u64()?,
                HomeHandoffNodeBindingDigest::from_bytes(reader.digest()?)?,
                timestamp(reader.i64()?, "Temporary Dispatch end_at")?,
            )?)
        }
        _ => return Err(Error::Corrupt("acceptance work authority tag")),
    };
    let issued_at = timestamp(reader.i64()?, "grant issued_at")?;
    let expires_at = timestamp(reader.i64()?, "grant expires_at")?;
    if !reader.is_finished() {
        return Err(Error::Corrupt("acceptance grant trailing bytes"));
    }
    let grant = HomeHandoffAcceptanceGrant::new(
        issuer,
        request_digest,
        acceptance_receipt_id,
        acceptance_receipt_digest,
        moving_profile_id,
        recipient_profile_id,
        participation,
        work_authority,
        issued_at,
        expires_at,
    )?;
    if encode_grant_snapshot(grant)?.as_slice() != snapshot {
        return Err(Error::Corrupt("acceptance grant snapshot is not canonical"));
    }
    Ok(grant)
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "HomeHandoffInitialSuccessorSnapshot is a Copy value object"
)]
pub(super) fn encode_successor_snapshot(successor: HomeHandoffInitialSuccessorSnapshot) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_SUCCESSOR_SNAPSHOT_BYTES);
    bytes.extend_from_slice(SUCCESSOR_MAGIC);
    bytes.push(1);
    append_uuid(&mut bytes, successor.assignment_id().into_uuid());
    let origin = successor.origin();
    append_uuid(&mut bytes, origin.preparation_id());
    append_uuid(&mut bytes, origin.handoff_id());
    append_uuid(&mut bytes, origin.predecessor_id().into_uuid());
    append_uuid(&mut bytes, origin.root_assignment_id().into_uuid());
    append_uuid(&mut bytes, successor.workspace_id().into_uuid());
    append_uuid(&mut bytes, successor.activity_id().into_uuid());
    append_uuid(&mut bytes, successor.goal_id().into_uuid());
    append_i64(&mut bytes, successor.goal_created_at().get());
    append_i64(&mut bytes, successor.goal_revision().get());
    append_i64(&mut bytes, successor.dag_revision().get());
    append_i64(&mut bytes, successor.dag_head_revision().get());
    append_uuid(&mut bytes, successor.node_id().into_uuid());
    append_i64(&mut bytes, successor.node_revision().get());
    let coordinator = successor.coordinator();
    append_uuid(&mut bytes, coordinator.agent_id().into_uuid());
    append_uuid(&mut bytes, coordinator.session_id().into_uuid());
    append_principal(&mut bytes, coordinator.principal());
    append_i64(&mut bytes, coordinator.revision().get());
    let target = successor.target();
    append_uuid(&mut bytes, target.agent_id().into_uuid());
    append_uuid(&mut bytes, target.session_id().into_uuid());
    append_principal(&mut bytes, target.principal());
    append_i64(&mut bytes, target.agent_revision().get());
    bytes.push(budget_tag(successor.credit_budget()));
    append_i64(&mut bytes, successor.created_at().get());
    append_i64(&mut bytes, successor.created_at().get());
    append_i64(&mut bytes, AgentAssignmentRevision::INITIAL.get());
    bytes.push(1); // Running
    bytes.push(0); // cancellation_requested=false
    bytes.push(0); // result/worktree absent
    bytes.push(0); // reviewer absent
    bytes
}

pub(super) fn decode_successor_snapshot(
    snapshot: &[u8],
) -> Result<HomeHandoffInitialSuccessorSnapshot, Error> {
    if snapshot.is_empty() || snapshot.len() > MAX_SUCCESSOR_SNAPSHOT_BYTES {
        return Err(Error::Corrupt("successor snapshot bound"));
    }
    let mut reader = Reader::new(snapshot);
    if reader.take(4)? != SUCCESSOR_MAGIC || reader.u8()? != 1 {
        return Err(Error::Corrupt("successor snapshot version"));
    }
    let assignment_id = AgentAssignmentId::from_uuid(reader.uuid()?);
    let origin = AgentAssignmentHomeHandoffOrigin::new(
        reader.uuid()?,
        reader.uuid()?,
        AgentAssignmentId::from_uuid(reader.uuid()?),
        AgentAssignmentId::from_uuid(reader.uuid()?),
    )
    .map_err(|_| Error::Corrupt("successor Home origin"))?;
    let workspace_id = WorkspaceId::from_uuid(reader.uuid()?);
    let activity_id = ActivityId::from_uuid(reader.uuid()?);
    let goal_id = GoalId::from_uuid(reader.uuid()?);
    let goal_created_at = timestamp(reader.i64()?, "successor Goal created_at")?;
    let goal_revision =
        GoalRevision::new(reader.i64()?).map_err(|_| Error::Corrupt("successor Goal revision"))?;
    let dag_revision = DagRevisionNumber::new(reader.i64()?)
        .map_err(|_| Error::Corrupt("successor DAG revision"))?;
    let dag_head_revision = DagHeadRevision::new(reader.i64()?)
        .map_err(|_| Error::Corrupt("successor DAG head revision"))?;
    let node_id = DagNodeId::from_uuid(reader.uuid()?);
    let node_revision = DagNodeRevision::new(reader.i64()?)
        .map_err(|_| Error::Corrupt("successor Node revision"))?;
    let coordinator = AgentAssignmentCoordinator::new(
        AgentInstanceId::from_uuid(reader.uuid()?),
        AgentSessionId::from_uuid(reader.uuid()?),
        reader.principal()?,
        ActivityCoordinatorRevision::new(reader.i64()?)
            .map_err(|_| Error::Corrupt("successor Coordinator revision"))?,
    );
    let target = AgentAssignmentTarget::new(
        AgentInstanceId::from_uuid(reader.uuid()?),
        AgentSessionId::from_uuid(reader.uuid()?),
        reader.principal()?,
        AgentInstanceRevision::new(reader.i64()?)
            .map_err(|_| Error::Corrupt("successor target revision"))?,
    );
    let credit_budget = decode_budget(reader.u8()?)?;
    let created_at = timestamp(reader.i64()?, "successor created_at")?;
    let updated_at = timestamp(reader.i64()?, "successor updated_at")?;
    let revision = AgentAssignmentRevision::new(reader.i64()?)
        .map_err(|_| Error::Corrupt("successor initial revision"))?;
    let state = match reader.u8()? {
        1 => AgentAssignmentState::Running,
        _ => return Err(Error::Corrupt("successor initial state")),
    };
    let cancellation_requested = reader.boolean()?;
    let result_present = reader.boolean()?;
    let reviewer_present = reader.boolean()?;
    if !reader.is_finished()
        || revision != AgentAssignmentRevision::INITIAL
        || cancellation_requested
        || result_present
        || reviewer_present
        || created_at != updated_at
    {
        return Err(Error::Corrupt("successor initial snapshot shape"));
    }
    let assignment = forge_domain::RegisteredAgentAssignment::from_parts(
        assignment_id,
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
        None,
        None,
        created_at,
        updated_at,
        revision,
        forge_domain::AgentAssignmentOrigin::HomeHandoff(origin),
    )
    .map_err(|_| Error::Corrupt("successor initial domain shape"))?;
    let decoded = HomeHandoffInitialSuccessorSnapshot::from_assignment(&assignment, created_at)?;
    if encode_successor_snapshot(decoded).as_slice() != snapshot {
        return Err(Error::Corrupt("successor snapshot is not canonical"));
    }
    Ok(decoded)
}

pub(super) fn payload_digest(
    record: &HomeHandoffAcceptanceOutcomeRecord,
) -> Result<[u8; DIGEST_BYTES], Error> {
    let mut bytes = Vec::with_capacity(1_152);
    bytes.extend_from_slice(record.request().canonical_snapshot().as_slice());
    append_uuid(&mut bytes, record.issuer().into_uuid());
    append_uuid(&mut bytes, record.handoff_id());
    append_uuid(&mut bytes, record.proposal_id());
    append_i64(&mut bytes, record.case_revision());
    append_uuid(&mut bytes, record.preparation_id());
    append_uuid(&mut bytes, record.workspace_id().into_uuid());
    append_uuid(&mut bytes, record.predecessor_id().into_uuid());
    append_uuid(&mut bytes, record.root_assignment_id().into_uuid());
    append_i64(&mut bytes, record.source_at().get());
    bytes.push(record.outcome_kind().encode_tag());
    if let Some(applied) = record.applied() {
        append_i64(&mut bytes, applied.predecessor_revision_before().get());
        append_i64(&mut bytes, applied.predecessor_revision_after().get());
        bytes.push(encode_state(applied.predecessor_terminal_disposition()));
        let successor = encode_successor_snapshot(applied.successor());
        append_len_prefixed(&mut bytes, &successor)?;
        let grant = encode_grant_snapshot(applied.grant())?;
        append_len_prefixed(&mut bytes, &grant)?;
    }
    let mut digest = Sha256::new();
    digest.update(OUTCOME_DOMAIN);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

#[allow(
    clippy::too_many_arguments,
    reason = "one row decoder validates all persisted acceptance columns together"
)]
pub(super) fn decode_stored_record(
    request_snapshot: &[u8],
    request_digest: &[u8],
    issuer: forge_domain::OrchestrationIssuerId,
    preparation_id: Uuid,
    workspace_id: WorkspaceId,
    predecessor_id: AgentAssignmentId,
    root_assignment_id: AgentAssignmentId,
    source_at: TimestampMillis,
    outcome_kind: i64,
    predecessor_revision_before: Option<i64>,
    predecessor_revision_after: Option<i64>,
    predecessor_terminal_disposition: Option<i64>,
    successor_snapshot: Option<&[u8]>,
    grant_snapshot: Option<&[u8]>,
) -> Result<HomeHandoffAcceptanceOutcomeRecord, Error> {
    let request = decode_take_request(request_snapshot, request_digest)?;
    let outcome = match (
        outcome_kind,
        predecessor_revision_before,
        predecessor_revision_after,
        predecessor_terminal_disposition,
        successor_snapshot,
        grant_snapshot,
    ) {
        (2, None, None, None, None, None) => HomeHandoffAcceptanceOutcome::Aborted,
        (1, Some(before), Some(after), Some(disposition), Some(successor), Some(grant)) => {
            let predecessor_revision_before = AgentAssignmentRevision::new(before)
                .map_err(|_| Error::Corrupt("predecessor before revision"))?;
            let predecessor_revision_after = AgentAssignmentRevision::new(after)
                .map_err(|_| Error::Corrupt("predecessor after revision"))?;
            let predecessor_terminal_disposition = decode_state(disposition)?;
            let successor = decode_successor_snapshot(successor)?;
            let grant = decode_grant_snapshot(grant)?;
            HomeHandoffAcceptanceOutcome::Applied(HomeHandoffAppliedAcceptance {
                predecessor_revision_before,
                predecessor_revision_after,
                predecessor_terminal_disposition,
                successor,
                grant,
            })
        }
        _ => return Err(Error::Corrupt("terminal outcome field shape")),
    };
    HomeHandoffAcceptanceOutcomeRecord::from_stored_parts(
        HomeHandoffAcceptanceOutcomeRecordStoredParts {
            request,
            issuer,
            preparation_id,
            workspace_id,
            predecessor_id,
            root_assignment_id,
            source_at,
            outcome,
        },
    )
}

pub(super) fn append_len_prefixed(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let length = u32::try_from(value.len()).map_err(|_| Error::Corrupt("snapshot length"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

pub(super) fn append_uuid(bytes: &mut Vec<u8>, id: Uuid) {
    bytes.extend_from_slice(id.as_bytes());
}

pub(super) fn append_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn append_principal(bytes: &mut Vec<u8>, principal: AuthenticatedPrincipal) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => bytes.push(0),
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

fn budget_tag(value: Option<WorkCreditBudget>) -> u8 {
    match value {
        None => 0,
        Some(WorkCreditBudget::One) => 1,
        Some(WorkCreditBudget::Three) => 3,
        Some(WorkCreditBudget::Five) => 5,
    }
}

fn decode_budget(value: u8) -> Result<Option<WorkCreditBudget>, Error> {
    match value {
        0 => Ok(None),
        1 | 3 | 5 => WorkCreditBudget::try_from_i64(i64::from(value))
            .map(Some)
            .map_err(|_| Error::Corrupt("successor credit budget")),
        _ => Err(Error::Corrupt("successor credit budget tag")),
    }
}

pub(super) fn encode_state(state: AgentAssignmentState) -> u8 {
    match state {
        AgentAssignmentState::Cancelled => 5,
        AgentAssignmentState::Interrupted => 6,
        AgentAssignmentState::Offered => 0,
        AgentAssignmentState::Running => 1,
        AgentAssignmentState::Submitted => 2,
        AgentAssignmentState::Accepted => 3,
        AgentAssignmentState::Rejected => 4,
    }
}

pub(super) fn decode_state(value: i64) -> Result<AgentAssignmentState, Error> {
    match value {
        5 => Ok(AgentAssignmentState::Cancelled),
        6 => Ok(AgentAssignmentState::Interrupted),
        _ => Err(Error::Corrupt("predecessor terminal disposition")),
    }
}

fn timestamp(value: i64, field: &'static str) -> Result<TimestampMillis, Error> {
    TimestampMillis::new(value).map_err(|_| Error::Corrupt(field))
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error::Corrupt("snapshot truncated"))?;
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    pub(super) fn u8(&mut self) -> Result<u8, Error> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(Error::Corrupt("snapshot truncated"))
    }

    fn boolean(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Corrupt("snapshot boolean")),
        }
    }

    pub(super) fn i64(&mut self) -> Result<i64, Error> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| Error::Corrupt("snapshot i64"))?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| Error::Corrupt("snapshot u64"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(super) fn uuid(&mut self) -> Result<Uuid, Error> {
        Uuid::from_slice(self.take(16)?).map_err(|_| Error::Corrupt("snapshot UUID"))
    }

    pub(super) fn digest(&mut self) -> Result<[u8; DIGEST_BYTES], Error> {
        self.take(DIGEST_BYTES)?
            .try_into()
            .map_err(|_| Error::Corrupt("snapshot digest"))
    }

    fn principal(&mut self) -> Result<AuthenticatedPrincipal, Error> {
        match self.u8()? {
            0 => Ok(AuthenticatedPrincipal::TrustedStdio),
            1 => Ok(AuthenticatedPrincipal::DirectToken(
                DirectTokenId::from_uuid(self.uuid()?),
            )),
            2 => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
                self.uuid()?,
            ))),
            _ => Err(Error::Corrupt("snapshot principal tag")),
        }
    }

    pub(super) fn length_prefixed(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| Error::Corrupt("snapshot component length"))?;
        if length == 0 || length > maximum {
            return Err(Error::Corrupt("snapshot component bound"));
        }
        self.take(length)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| Error::Corrupt("snapshot length width"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub(super) fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{
        ActivityCoordinatorActor, ActivityId, AgentAssignmentCoordinator,
        AgentAssignmentHomeHandoffAcceptance, AgentAssignmentHomeHandoffOrigin,
        AgentAssignmentHomeHandoffTransition, AgentAssignmentId, AgentAssignmentRevision,
        DagHeadRevision, DagNodeId, DagNodeRevision, DagRevisionNumber, ForgeBackendId, GoalId,
        GoalRevision, HomeHandoffProposalRequestDigest, HomeHandoffWorkAuthority,
        RegisteredAgentAssignment, WorkspaceRevision,
    };

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn digest(byte: u8) -> [u8; DIGEST_BYTES] {
        [byte; DIGEST_BYTES]
    }

    fn take_request_with_principal(
        principal: AuthenticatedPrincipal,
    ) -> Result<HomeHandoffTakeRequest, Box<dyn std::error::Error>> {
        let scope = forge_domain::HomeTransferSourceScope::new(
            WorkspaceId::from_uuid(id(1)),
            WorkspaceRevision::new(2)?,
            ForgeBackendId::from_uuid(id(3)),
            id(4),
        )?;
        let recipient = AgentAssignmentTarget::new(
            AgentInstanceId::from_uuid(id(5)),
            AgentSessionId::from_uuid(id(6)),
            principal,
            AgentInstanceRevision::new(8)?,
        );
        Ok(HomeHandoffTakeRequest::new(
            id(9),
            id(10),
            id(11),
            12,
            HomeHandoffProposalRequestDigest::from_bytes(digest(13))?,
            scope,
            recipient,
        )?)
    }

    fn take_request() -> Result<HomeHandoffTakeRequest, Box<dyn std::error::Error>> {
        take_request_with_principal(AuthenticatedPrincipal::DirectToken(
            DirectTokenId::from_uuid(id(7)),
        ))
    }

    fn grant(
        request: HomeHandoffTakeRequest,
        work_authority: HomeHandoffWorkAuthority,
    ) -> Result<HomeHandoffAcceptanceGrant, Box<dyn std::error::Error>> {
        Ok(HomeHandoffAcceptanceGrant::new(
            forge_domain::OrchestrationIssuerId::from_uuid(id(20)),
            request.request_digest(),
            id(21),
            HomeHandoffAcceptanceReceiptDigest::from_bytes(digest(22))?,
            id(23),
            id(24),
            HomeHandoffRecipientParticipation::new(id(25), 26)?,
            work_authority,
            TimestampMillis::new(30)?,
            TimestampMillis::new(40)?,
        )?)
    }

    fn initial_successor() -> Result<RegisteredAgentAssignment, Box<dyn std::error::Error>> {
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
        let source_id = AgentAssignmentId::from_uuid(id(64));
        let source = RegisteredAgentAssignment::offered(
            source_id,
            workspace_id,
            activity_id,
            GoalId::from_uuid(id(65)),
            TimestampMillis::new(1)?,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            DagHeadRevision::INITIAL,
            DagNodeId::from_uuid(id(66)),
            DagNodeRevision::new(4)?,
            AgentAssignmentCoordinator::from_actor(coordinator),
            AgentAssignmentTarget::new(
                AgentInstanceId::from_uuid(id(67)),
                AgentSessionId::from_uuid(id(68)),
                AuthenticatedPrincipal::TrustedStdio,
                AgentInstanceRevision::INITIAL,
            ),
            Some(WorkCreditBudget::Three),
            TimestampMillis::new(2)?,
        )?;
        let origin = AgentAssignmentHomeHandoffOrigin::new(id(69), id(70), source_id, source_id)?;
        let acceptance = AgentAssignmentHomeHandoffAcceptance::new(
            origin,
            AgentAssignmentId::from_uuid(id(71)),
            AgentAssignmentTarget::new(
                AgentInstanceId::from_uuid(id(72)),
                AgentSessionId::from_uuid(id(73)),
                AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id(74))),
                AgentInstanceRevision::new(2)?,
            ),
            coordinator,
            DagNodeRevision::new(5)?,
            TimestampMillis::new(3)?,
        );
        let transition = AgentAssignmentHomeHandoffTransition::new(
            &source,
            AgentAssignmentRevision::INITIAL,
            acceptance,
        )?;
        Ok(transition.successor().clone())
    }

    #[test]
    fn take_request_snapshot_is_canonical_and_binds_every_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = take_request()?;
        let snapshot = request.canonical_snapshot();
        let decoded = decode_take_request(&snapshot, request.request_digest().as_bytes())?;
        assert_eq!(decoded, request);

        let mut changed = snapshot;
        changed[5] ^= 1;
        assert!(decode_take_request(&changed, request.request_digest().as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn trusted_stdio_principal_padding_is_canonical_and_checked()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = take_request_with_principal(AuthenticatedPrincipal::TrustedStdio)?;
        let snapshot = request.canonical_snapshot();
        let decoded = decode_take_request(&snapshot, request.request_digest().as_bytes())?;
        assert_eq!(decoded, request);

        // Fixed take-snapshot fields place the recipient principal tag at 181,
        // followed by the canonical all-zero 16-byte identity slot.
        let mut noncanonical_padding = snapshot;
        noncanonical_padding[182] = 1;
        assert!(
            decode_take_request(&noncanonical_padding, request.request_digest().as_bytes(),)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn grant_evidence_snapshots_round_trip_all_authority_variants()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = take_request()?;
        let affinity = HomeHandoffAffinityAdmissionReferenceDigest::from_bytes(digest(41))?;
        let node_binding = HomeHandoffNodeBindingDigest::from_bytes(digest(42))?;
        let authorities = [
            HomeHandoffWorkAuthority::WorkspaceWork {
                affinity_admission_reference_digest: affinity,
            },
            HomeHandoffWorkAuthority::HomeTeam(HomeHandoffHomeTeamAuthority::new(
                affinity,
                id(43),
                44,
                45,
                node_binding,
            )?),
            HomeHandoffWorkAuthority::TemporaryDispatch(
                HomeHandoffTemporaryDispatchAuthority::new(
                    affinity,
                    id(46),
                    id(47),
                    48,
                    49,
                    node_binding,
                    TimestampMillis::new(80)?,
                )?,
            ),
        ];
        for authority in authorities {
            let value = grant(request, authority)?;
            let snapshot = encode_grant_snapshot(value)?;
            assert_eq!(decode_grant_snapshot(&snapshot)?, value);
        }
        Ok(())
    }

    #[test]
    fn successor_snapshot_preserves_variable_width_trusted_stdio_principal()
    -> Result<(), Box<dyn std::error::Error>> {
        let assignment = initial_successor()?;
        let initial = HomeHandoffInitialSuccessorSnapshot::from_assignment(
            &assignment,
            TimestampMillis::new(3)?,
        )?;
        assert!(initial.coordinator().principal().is_trusted_stdio());
        let snapshot = encode_successor_snapshot(initial);
        assert_eq!(decode_successor_snapshot(&snapshot)?, initial);
        Ok(())
    }
}
