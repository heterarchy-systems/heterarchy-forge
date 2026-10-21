//! Strict HTTP projection for Source-owned quiescent Activity lease recovery.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{PrincipalDto, PrincipalKindDto, ScopeDto};
use crate::error::ForgeError;
use forge_domain::{
    ActivityId, ActivityLeaseProjection, ActivityLeaseRevision, ActivityRevision, ActivityState,
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, AgentSessionRevision,
    AgentSessionState, AuthenticatedPrincipal, ExpiredActivityRecoveryProbeScope, ForgeBackendId,
    LocationId, LocationRevision, OrchestrationIssuerId, QuiescentActivityLeaseResumeAgentCensus,
    QuiescentActivityLeaseResumeBlocker, QuiescentActivityLeaseResumeCoordinationWork,
    QuiescentActivityLeaseResumeExpectation, QuiescentActivityLeaseResumeProbe,
    QuiescentActivityLeaseResumeWorkHistoryCensus, RegisteredActivity, RuntimeInstanceId,
    StartedActivityLeaseResumeAgentSnapshot, StartedActivityLeaseResumeAssignmentCensus,
    StartedActivityLeaseResumeCoordinatorSnapshot, StartedActivityLeaseResumeDagCensus,
    StartedActivityLeaseResumeDelegation, StartedActivityLeaseResumeGoalCensus,
    StartedActivityLeaseResumePhysicalCensus, StartedActivityLeaseResumeServiceIdentity,
    StartedActivityLeaseResumeSessionSnapshot, UnstartedActivityContinuationServiceIdentity,
    WorkspaceId, WorkspaceRevision, WorkspaceRootFingerprint,
};

const REQUEST_DOMAIN: &[u8] = b"forge.quiescent_activity_lease_resume.request.v1\0";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrincipalWire {
    kind: PrincipalKindDto,
    token_id: Option<Uuid>,
    grant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ActivityStateWire {
    Open,
    Closed,
    Interrupted,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SessionStateWire {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BlockerWire {
    ActivityNotOpen,
    ActivityLeaseMissing,
    ActivityLeaseNotExpired,
    InitiatingAgentMissing,
    InitiatingSessionNotOpen,
    InitiatingAgentNotAttached,
    CoordinatorMissing,
    CoordinatorAgentMismatch,
    CoordinatorAgentNotAttached,
    CoordinatorSessionMismatch,
    CoordinatorSessionNotOpen,
    GoalCensusIncomplete,
    DagCensusIncomplete,
    AgentCensusIncomplete,
    CoordinationWorkMissing,
    AssignmentCensusIncomplete,
    AssignmentPresent,
    WorkHistoryIncomplete,
    PhysicalActivityEffectPresent,
    PhysicalCensusIncomplete,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActivityWire {
    activity_id: Uuid,
    workspace_id: Uuid,
    state: ActivityStateWire,
    revision: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
    lease_owner_id: Option<Uuid>,
    lease_until_ms: Option<i64>,
    lease_revision: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AgentWire {
    agent_id: Uuid,
    activity_id: Uuid,
    session_id: Uuid,
    principal: PrincipalWire,
    revision: i64,
    attached: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SessionWire {
    session_id: Uuid,
    principal: PrincipalWire,
    state: SessionStateWire,
    revision: i64,
    updated_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinatorWire {
    agent_id: Uuid,
    session_id: Uuid,
    principal: PrincipalWire,
    agent_revision: i64,
    revision: i64,
    updated_at_ms: i64,
    session_revision: i64,
    session_updated_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ServiceWire {
    backend_id: Uuid,
    issuer: Uuid,
    destination_id: Uuid,
    runtime_instance_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DelegationWire {
    migration_id: Uuid,
    destination_id: Uuid,
    freeze_revision: i64,
    freeze_created_at_ms: i64,
    freeze_updated_at_ms: i64,
    manifest_digest: String,
    delegated_at_ms: i64,
    delegation_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GoalCensusWire {
    row_count: u32,
    digest: String,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DagCensusWire {
    head_count: u32,
    node_count: u32,
    edge_count: u32,
    digest: String,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AgentCensusWire {
    row_count: u32,
    digest: String,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinationWorkWire {
    nonterminal_goal_count: u32,
    nonterminal_goal_with_current_dag_count: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AssignmentCensusWire {
    row_count: u32,
    digest: String,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WorkHistoryCensusWire {
    update_count: u32,
    evidence_ref_count: u32,
    digest: String,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PhysicalCensusWire {
    row_count: u32,
    execution_active_count: u64,
    execution_unknown_count: u64,
    writer_lease_active_count: u64,
    writer_lease_unknown_count: u64,
    pending_effect_count: u64,
    effect_unknown_count: u64,
    unresolved_worktree_count: u64,
    worktree_unknown_count: u64,
    unknown_count: u64,
    digest: String,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProbeWire {
    scope: ScopeDto,
    service: ServiceWire,
    workspace_root_fingerprint: String,
    binding_digest: String,
    delegation: DelegationWire,
    activity: ActivityWire,
    initiating_agent: Option<AgentWire>,
    initiating_session: SessionWire,
    coordinator: Option<CoordinatorWire>,
    coordinator_agent_attached: bool,
    coordinator_session_open: bool,
    goal_census: GoalCensusWire,
    dag_census: DagCensusWire,
    agent_census: AgentCensusWire,
    coordination_work: CoordinationWorkWire,
    assignment_census: AssignmentCensusWire,
    work_history_census: WorkHistoryCensusWire,
    physical_census: PhysicalCensusWire,
    census_version: u16,
    probe_observed_at_ms: i64,
    probe_expires_at_ms: i64,
    probe_digest: String,
    resumable_now: bool,
    blocker: Option<BlockerWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    scope: ScopeDto,
    activity_id: Uuid,
    initiating_session_id: Uuid,
    principal: PrincipalDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunBody {
    scope: ScopeDto,
    request_id: Uuid,
    request_digest: String,
    probe: ProbeWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
    request_id: Uuid,
    request_digest: String,
    activity_id: Uuid,
    agent_id: Uuid,
    initiating_session_id: Uuid,
    principal: PrincipalDto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ResumeCommand {
    Probe {
        scope: forge_control::ResolvedWorkspaceScope,
        activity_id: ActivityId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    },
    Run {
        scope: ScopeDto,
        request_id: Uuid,
        request_digest: [u8; 32],
        probe: Box<QuiescentActivityLeaseResumeProbe>,
    },
    Get {
        scope: forge_control::ResolvedWorkspaceScope,
        request_id: Uuid,
        request_digest: [u8; 32],
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    },
}

impl ResumeCommand {
    pub const fn op(&self) -> super::CommandOp {
        match self {
            Self::Probe { .. } => super::CommandOp::ActivityQuiescentLeaseResumeProbe,
            Self::Run { .. } => super::CommandOp::ActivityQuiescentLeaseResumeRun,
            Self::Get { .. } => super::CommandOp::ActivityQuiescentLeaseResumeGet,
        }
    }

    pub fn readback_hint(&self) -> Option<crate::error::ReadbackHint> {
        let Self::Run {
            scope,
            request_id,
            request_digest,
            probe,
        } = self
        else {
            return None;
        };
        let agent = probe.expectation().initiating_agent()?;
        let session = probe.expectation().initiating_session();
        Some(crate::error::ReadbackHint::QuiescentActivityLeaseResume {
            scope: scope.clone(),
            request_id: *request_id,
            request_digest: hex(request_digest),
            activity_id: probe.expectation().activity().id().into_uuid(),
            agent_id: agent.agent_id().into_uuid(),
            initiating_session_id: session.session_id().into_uuid(),
            principal: principal_readback(session.principal()),
        })
    }
}

fn principal_readback(value: AuthenticatedPrincipal) -> crate::error::PrincipalReadback {
    use crate::error::{PrincipalReadback, PrincipalReadbackKind};
    match value {
        AuthenticatedPrincipal::TrustedStdio => PrincipalReadback {
            kind: PrincipalReadbackKind::TrustedStdio,
            token_id: None,
            grant_id: None,
        },
        AuthenticatedPrincipal::DirectToken(id) => PrincipalReadback {
            kind: PrincipalReadbackKind::DirectToken,
            token_id: Some(id.into_uuid()),
            grant_id: None,
        },
        AuthenticatedPrincipal::OAuthGrant(id) => PrincipalReadback {
            kind: PrincipalReadbackKind::OAuthGrant,
            token_id: None,
            grant_id: Some(id.into_uuid()),
        },
    }
}

pub(super) fn parse(op: super::CommandOp, request_id: Uuid, payload: &Value) -> super::ParseResult {
    non_nil(request_id)?;
    let command = match op {
        super::CommandOp::ActivityQuiescentLeaseResumeProbe => {
            let body: ProbeBody =
                super::parse_body(payload, "Quiescent Activity recovery probe is invalid")?;
            canonical_scope(&body.scope, &payload["scope"])?;
            canonical_uuid(body.activity_id, &payload["activity_id"])?;
            canonical_uuid(
                body.initiating_session_id,
                &payload["initiating_session_id"],
            )?;
            canonical_principal(&body.principal, &payload["principal"])?;
            non_nil(body.scope.workspace_id)?;
            non_nil(body.scope.locator.location_id)?;
            ResumeCommand::Probe {
                scope: super::decode_scope(&body.scope)?,
                activity_id: ActivityId::from_uuid(non_nil(body.activity_id)?),
                session_id: AgentSessionId::from_uuid(non_nil(body.initiating_session_id)?),
                principal: super::decode_principal(&body.principal)?,
            }
        }
        super::CommandOp::ActivityQuiescentLeaseResumeRun => {
            let body: RunBody =
                super::parse_body(payload, "Quiescent Activity recovery run is invalid")?;
            canonical_scope(&body.scope, &payload["scope"])?;
            let _ = super::decode_scope(&body.scope)?;
            canonical_uuid(body.request_id, &payload["request_id"])?;
            if body.request_id != request_id || body.scope != body.probe.scope {
                return Err(invalid_snapshot());
            }
            let exact = parse_exact_probe(payload.get("probe").ok_or_else(invalid_snapshot)?)?;
            let digest = hex_bytes(&body.request_digest)?;
            if request_digest(&body.scope, request_id, &exact)? != digest {
                return Err(invalid_snapshot());
            }
            let probe = exact.domain()?;
            if !probe.resumable_now() {
                return Err(invalid_snapshot());
            }
            ResumeCommand::Run {
                scope: body.scope,
                request_id,
                request_digest: digest,
                probe: Box::new(probe),
            }
        }
        super::CommandOp::ActivityQuiescentLeaseResumeGet => {
            let body: GetBody =
                super::parse_body(payload, "Quiescent Activity recovery get is invalid")?;
            canonical_scope(&body.scope, &payload["scope"])?;
            canonical_uuid(body.request_id, &payload["request_id"])?;
            canonical_uuid(body.activity_id, &payload["activity_id"])?;
            canonical_uuid(body.agent_id, &payload["agent_id"])?;
            canonical_uuid(
                body.initiating_session_id,
                &payload["initiating_session_id"],
            )?;
            canonical_principal(&body.principal, &payload["principal"])?;
            if body.request_id != request_id {
                return Err(invalid_snapshot());
            }
            non_nil(body.scope.workspace_id)?;
            non_nil(body.scope.locator.location_id)?;
            ResumeCommand::Get {
                scope: super::decode_scope(&body.scope)?,
                request_id,
                request_digest: hex_bytes(&body.request_digest)?,
                activity_id: ActivityId::from_uuid(non_nil(body.activity_id)?),
                agent_id: AgentInstanceId::from_uuid(non_nil(body.agent_id)?),
                session_id: AgentSessionId::from_uuid(non_nil(body.initiating_session_id)?),
                principal: super::decode_principal(&body.principal)?,
            }
        }
        _ => {
            return Err(ForgeError::invalid_input(
                "Wrong quiescent recovery operation",
            ));
        }
    };
    Ok(super::Command::ActivityQuiescentLeaseResume {
        request_id,
        request: Box::new(command),
    })
}

fn invalid_snapshot() -> ForgeError {
    ForgeError::invalid_input("Quiescent Activity recovery snapshot fence is invalid")
}

fn non_nil(id: Uuid) -> Result<Uuid, ForgeError> {
    if id.is_nil() {
        Err(invalid_snapshot())
    } else {
        Ok(id)
    }
}

fn canonical_uuid(id: Uuid, raw: &Value) -> Result<(), ForgeError> {
    non_nil(id)?;
    if raw.as_str() != Some(id.to_string().as_str()) {
        return Err(invalid_snapshot());
    }
    Ok(())
}

fn canonical_scope(scope: &ScopeDto, raw: &Value) -> Result<(), ForgeError> {
    canonical_uuid(scope.workspace_id, &raw["workspace_id"])?;
    canonical_uuid(scope.locator.location_id, &raw["locator"]["location_id"])
}

fn canonical_principal(principal: &PrincipalDto, raw: &Value) -> Result<(), ForgeError> {
    if let Some(id) = principal.token_id {
        canonical_uuid(id, &raw["token_id"])?;
    }
    if let Some(id) = principal.grant_id {
        canonical_uuid(id, &raw["grant_id"])?;
    }
    Ok(())
}

fn request_digest(
    scope: &ScopeDto,
    request_id: Uuid,
    probe: &ProbeWire,
) -> Result<[u8; 32], ForgeError> {
    let intent = json!({"scope": scope, "request_id": request_id, "probe": probe});
    let canonical = serde_json::to_vec(&super::activity_lease_resume::sorted_json(&intent)?)
        .map_err(|_| ForgeError::internal())?;
    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    digest.update(canonical);
    Ok(digest.finalize().into())
}

pub(super) fn canonical_request_digest_for_probe(
    scope: &ScopeDto,
    request_id: Uuid,
    probe: &QuiescentActivityLeaseResumeProbe,
) -> Result<[u8; 32], ForgeError> {
    let wire = parse_exact_probe(&probe_json(probe))?;
    request_digest(scope, request_id, &wire)
}

fn parse_exact_probe(value: &Value) -> Result<ProbeWire, ForgeError> {
    let probe: ProbeWire = serde_json::from_value(value.clone())
        .map_err(|_| ForgeError::invalid_input("Quiescent recovery probe is invalid"))?;
    let encoded = serde_json::to_value(&probe).map_err(|_| ForgeError::internal())?;
    if encoded != *value {
        return Err(ForgeError::invalid_input(
            "Quiescent recovery probe must retain every canonical field and explicit null",
        ));
    }
    Ok(probe)
}

fn hex_bytes<const N: usize>(value: &str) -> Result<[u8; N], ForgeError> {
    if value.len() != N * 2 {
        return Err(invalid_snapshot());
    }
    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(invalid_snapshot()),
        };
        bytes[index] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(bytes)
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

impl PrincipalWire {
    fn domain(&self) -> Result<AuthenticatedPrincipal, ForgeError> {
        super::decode_principal(&PrincipalDto {
            kind: self.kind,
            token_id: self.token_id,
            grant_id: self.grant_id,
        })
    }
}

impl ActivityWire {
    fn domain(&self) -> Result<RegisteredActivity, ForgeError> {
        if self.updated_at_ms < self.created_at_ms {
            return Err(invalid_snapshot());
        }
        let lease = ActivityLeaseProjection::from_parts(
            self.lease_owner_id
                .map(non_nil)
                .transpose()?
                .map(RuntimeInstanceId::from_uuid),
            self.lease_until_ms
                .map(super::decode_timestamp)
                .transpose()?,
            ActivityLeaseRevision::new(self.lease_revision).map_err(|_| invalid_snapshot())?,
        )
        .map_err(|_| invalid_snapshot())?;
        Ok(RegisteredActivity::from_parts_with_lease(
            ActivityId::from_uuid(non_nil(self.activity_id)?),
            WorkspaceId::from_uuid(non_nil(self.workspace_id)?),
            match self.state {
                ActivityStateWire::Open => ActivityState::Open,
                ActivityStateWire::Closed => ActivityState::Closed,
                ActivityStateWire::Interrupted => ActivityState::Interrupted,
            },
            super::decode_timestamp(self.created_at_ms)?,
            super::decode_timestamp(self.updated_at_ms)?,
            ActivityRevision::new(self.revision).map_err(|_| invalid_snapshot())?,
            lease,
        ))
    }
}

impl AgentWire {
    fn domain(&self) -> Result<StartedActivityLeaseResumeAgentSnapshot, ForgeError> {
        StartedActivityLeaseResumeAgentSnapshot::new(
            AgentInstanceId::from_uuid(non_nil(self.agent_id)?),
            ActivityId::from_uuid(non_nil(self.activity_id)?),
            AgentSessionId::from_uuid(non_nil(self.session_id)?),
            self.principal.domain()?,
            AgentInstanceRevision::new(self.revision).map_err(|_| invalid_snapshot())?,
            self.attached,
        )
        .map_err(|_| invalid_snapshot())
    }
}

impl SessionWire {
    fn domain(&self) -> Result<StartedActivityLeaseResumeSessionSnapshot, ForgeError> {
        StartedActivityLeaseResumeSessionSnapshot::new(
            AgentSessionId::from_uuid(non_nil(self.session_id)?),
            self.principal.domain()?,
            match self.state {
                SessionStateWire::Open => AgentSessionState::Open,
                SessionStateWire::Closed => AgentSessionState::Closed,
            },
            AgentSessionRevision::new(self.revision).map_err(|_| invalid_snapshot())?,
            super::decode_timestamp(self.updated_at_ms)?,
        )
        .map_err(|_| invalid_snapshot())
    }
}

impl CoordinatorWire {
    fn domain(&self) -> Result<StartedActivityLeaseResumeCoordinatorSnapshot, ForgeError> {
        StartedActivityLeaseResumeCoordinatorSnapshot::new(
            AgentInstanceId::from_uuid(non_nil(self.agent_id)?),
            AgentSessionId::from_uuid(non_nil(self.session_id)?),
            self.principal.domain()?,
            AgentInstanceRevision::new(self.agent_revision).map_err(|_| invalid_snapshot())?,
            forge_domain::ActivityCoordinatorRevision::new(self.revision)
                .map_err(|_| invalid_snapshot())?,
            super::decode_timestamp(self.updated_at_ms)?,
            AgentSessionRevision::new(self.session_revision).map_err(|_| invalid_snapshot())?,
            super::decode_timestamp(self.session_updated_at_ms)?,
        )
        .map_err(|_| invalid_snapshot())
    }
}

impl ServiceWire {
    fn domain(&self) -> Result<StartedActivityLeaseResumeServiceIdentity, ForgeError> {
        let source = UnstartedActivityContinuationServiceIdentity::new(
            ForgeBackendId::from_uuid(non_nil(self.backend_id)?),
            OrchestrationIssuerId::from_uuid(non_nil(self.issuer)?),
            RuntimeInstanceId::from_uuid(non_nil(self.runtime_instance_id)?),
        )
        .map_err(|_| invalid_snapshot())?;
        StartedActivityLeaseResumeServiceIdentity::new(source, non_nil(self.destination_id)?)
            .map_err(|_| invalid_snapshot())
    }
}

impl DelegationWire {
    fn domain(&self) -> Result<StartedActivityLeaseResumeDelegation, ForgeError> {
        StartedActivityLeaseResumeDelegation::new(
            non_nil(self.migration_id)?,
            non_nil(self.destination_id)?,
            u64::try_from(self.freeze_revision).map_err(|_| invalid_snapshot())?,
            super::decode_timestamp(self.freeze_created_at_ms)?,
            super::decode_timestamp(self.freeze_updated_at_ms)?,
            hex_bytes(&self.manifest_digest)?,
            super::decode_timestamp(self.delegated_at_ms)?,
            hex_bytes(&self.delegation_digest)?,
        )
        .map_err(|_| invalid_snapshot())
    }
}

impl BlockerWire {
    const fn domain(self) -> QuiescentActivityLeaseResumeBlocker {
        match self {
            Self::ActivityNotOpen => QuiescentActivityLeaseResumeBlocker::ActivityNotOpen,
            Self::ActivityLeaseMissing => QuiescentActivityLeaseResumeBlocker::ActivityLeaseMissing,
            Self::ActivityLeaseNotExpired => {
                QuiescentActivityLeaseResumeBlocker::ActivityLeaseNotExpired
            }
            Self::InitiatingAgentMissing => {
                QuiescentActivityLeaseResumeBlocker::InitiatingAgentMissing
            }
            Self::InitiatingSessionNotOpen => {
                QuiescentActivityLeaseResumeBlocker::InitiatingSessionNotOpen
            }
            Self::InitiatingAgentNotAttached => {
                QuiescentActivityLeaseResumeBlocker::InitiatingAgentNotAttached
            }
            Self::CoordinatorMissing => QuiescentActivityLeaseResumeBlocker::CoordinatorMissing,
            Self::CoordinatorAgentMismatch => {
                QuiescentActivityLeaseResumeBlocker::CoordinatorAgentMismatch
            }
            Self::CoordinatorAgentNotAttached => {
                QuiescentActivityLeaseResumeBlocker::CoordinatorAgentNotAttached
            }
            Self::CoordinatorSessionMismatch => {
                QuiescentActivityLeaseResumeBlocker::CoordinatorSessionMismatch
            }
            Self::CoordinatorSessionNotOpen => {
                QuiescentActivityLeaseResumeBlocker::CoordinatorSessionNotOpen
            }
            Self::GoalCensusIncomplete => QuiescentActivityLeaseResumeBlocker::GoalCensusIncomplete,
            Self::DagCensusIncomplete => QuiescentActivityLeaseResumeBlocker::DagCensusIncomplete,
            Self::AgentCensusIncomplete => {
                QuiescentActivityLeaseResumeBlocker::AgentCensusIncomplete
            }
            Self::CoordinationWorkMissing => {
                QuiescentActivityLeaseResumeBlocker::CoordinationWorkMissing
            }
            Self::AssignmentCensusIncomplete => {
                QuiescentActivityLeaseResumeBlocker::AssignmentCensusIncomplete
            }
            Self::AssignmentPresent => QuiescentActivityLeaseResumeBlocker::AssignmentPresent,
            Self::WorkHistoryIncomplete => {
                QuiescentActivityLeaseResumeBlocker::WorkHistoryIncomplete
            }
            Self::PhysicalActivityEffectPresent => {
                QuiescentActivityLeaseResumeBlocker::PhysicalActivityEffectPresent
            }
            Self::PhysicalCensusIncomplete => {
                QuiescentActivityLeaseResumeBlocker::PhysicalCensusIncomplete
            }
        }
    }
}

impl ProbeWire {
    fn domain(&self) -> Result<QuiescentActivityLeaseResumeProbe, ForgeError> {
        let scope = decode_probe_scope(self)?;
        let service = self.service.domain()?;
        let delegation = self.delegation.domain()?;
        let initiating_agent = self
            .initiating_agent
            .as_ref()
            .map(AgentWire::domain)
            .transpose()?;
        let initiating_session = self.initiating_session.domain()?;
        let coordinator = self
            .coordinator
            .as_ref()
            .map(CoordinatorWire::domain)
            .transpose()?;
        let expectation = QuiescentActivityLeaseResumeExpectation::new(
            self.activity.domain()?,
            initiating_agent,
            initiating_session,
            coordinator,
            self.coordinator_agent_attached,
            self.coordinator_session_open,
            StartedActivityLeaseResumeGoalCensus::new(
                self.goal_census.row_count,
                hex_bytes(&self.goal_census.digest)?,
                self.goal_census.truncated,
                self.goal_census.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            StartedActivityLeaseResumeDagCensus::new(
                self.dag_census.head_count,
                self.dag_census.node_count,
                self.dag_census.edge_count,
                hex_bytes(&self.dag_census.digest)?,
                self.dag_census.truncated,
                self.dag_census.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            QuiescentActivityLeaseResumeAgentCensus::new(
                self.agent_census.row_count,
                hex_bytes(&self.agent_census.digest)?,
                self.agent_census.truncated,
                self.agent_census.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            QuiescentActivityLeaseResumeCoordinationWork::new(
                self.coordination_work.nonterminal_goal_count,
                self.coordination_work
                    .nonterminal_goal_with_current_dag_count,
            )
            .map_err(|_| invalid_snapshot())?,
            StartedActivityLeaseResumeAssignmentCensus::new(
                self.assignment_census.row_count,
                hex_bytes(&self.assignment_census.digest)?,
                self.assignment_census.truncated,
                self.assignment_census.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            QuiescentActivityLeaseResumeWorkHistoryCensus::new(
                self.work_history_census.update_count,
                self.work_history_census.evidence_ref_count,
                hex_bytes(&self.work_history_census.digest)?,
                self.work_history_census.truncated,
                self.work_history_census.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            StartedActivityLeaseResumePhysicalCensus::new(
                self.physical_census.row_count,
                self.physical_census.execution_active_count,
                self.physical_census.execution_unknown_count,
                self.physical_census.writer_lease_active_count,
                self.physical_census.writer_lease_unknown_count,
                self.physical_census.pending_effect_count,
                self.physical_census.effect_unknown_count,
                self.physical_census.unresolved_worktree_count,
                self.physical_census.worktree_unknown_count,
                self.physical_census.unknown_count,
                hex_bytes(&self.physical_census.digest)?,
                self.physical_census.truncated,
                self.physical_census.complete,
            )
            .map_err(|_| invalid_snapshot())?,
        )
        .map_err(|_| invalid_snapshot())?;
        let probe = QuiescentActivityLeaseResumeProbe::new(
            scope,
            service,
            delegation,
            expectation,
            super::decode_timestamp(self.probe_observed_at_ms)?,
            hex_bytes(&self.probe_digest)?,
            self.resumable_now,
            self.blocker.map(BlockerWire::domain),
        )
        .map_err(|_| invalid_snapshot())?;
        if self.census_version != probe.census_version()
            || self.probe_expires_at_ms != probe.probe_expires_at().get()
        {
            return Err(invalid_snapshot());
        }
        Ok(probe)
    }
}

fn decode_probe_scope(probe: &ProbeWire) -> Result<ExpiredActivityRecoveryProbeScope, ForgeError> {
    let workspace_revision =
        WorkspaceRevision::new(probe.scope.workspace_revision).map_err(|_| invalid_snapshot())?;
    let location_revision = LocationRevision::new(probe.scope.locator.expected_revision)
        .map_err(|_| invalid_snapshot())?;
    ExpiredActivityRecoveryProbeScope::new(
        WorkspaceId::from_uuid(non_nil(probe.scope.workspace_id)?),
        workspace_revision,
        LocationId::from_uuid(non_nil(probe.scope.locator.location_id)?),
        location_revision,
        probe.scope.locator.relative_root.as_bytes().to_vec(),
        WorkspaceRootFingerprint::from_bytes(hex_bytes(&probe.workspace_root_fingerprint)?),
        hex_bytes(&probe.binding_digest)?,
    )
    .map_err(|_| invalid_snapshot())
}

fn current_service(
    clients: &super::BridgeClients,
) -> Result<StartedActivityLeaseResumeServiceIdentity, ForgeError> {
    let source = UnstartedActivityContinuationServiceIdentity::new(
        clients.backend_id,
        clients.issuer,
        clients.runtime_instance_id,
    )
    .map_err(|_| invalid_snapshot())?;
    StartedActivityLeaseResumeServiceIdentity::new(source, clients.destination_id)
        .map_err(|_| invalid_snapshot())
}

pub(super) fn execute(
    clients: &super::BridgeClients,
    command: &ResumeCommand,
) -> Result<Value, ForgeError> {
    match command {
        ResumeCommand::Probe {
            scope,
            activity_id,
            session_id,
            principal,
        } => {
            let request = forge_control::QuiescentActivityLeaseResumeProbeRequest {
                scope: scope.clone(),
                activity_id: *activity_id,
                initiating_session_id: *session_id,
                principal: *principal,
                service: current_service(clients)?,
                observed_at: current_timestamp_millis()?,
            };
            let probe = clients
                .control
                .quiescent_activity_lease_resume_probe(request)
                .map_err(|error| super::forge_error_of_client(&error))?;
            if probe.service().destination_id() != clients.destination_id {
                return Err(invalid_snapshot());
            }
            Ok(probe_json(&probe))
        }
        ResumeCommand::Get {
            scope,
            request_id,
            request_digest,
            activity_id,
            agent_id,
            session_id,
            principal,
        } => {
            let request = forge_control::QuiescentActivityLeaseResumeGetRequest {
                scope: scope.clone(),
                request_id: *request_id,
                request_digest: *request_digest,
                activity_id: *activity_id,
                agent_id: *agent_id,
                initiating_session_id: *session_id,
                principal: *principal,
            };
            let receipt = clients
                .control
                .quiescent_activity_lease_resume_get(request)
                .map_err(|error| super::forge_error_of_client(&error))?;
            Ok(
                json!({"receipt": receipt.as_ref().map(|readback| receipt_json(readback.receipt()))}),
            )
        }
        ResumeCommand::Run {
            scope,
            request_id,
            request_digest,
            probe,
        } => {
            let expectation = probe.expectation();
            let agent = expectation
                .initiating_agent()
                .ok_or_else(invalid_snapshot)?;
            let session = expectation.initiating_session();
            let selector = forge_control::QuiescentActivityLeaseResumeGetRequest {
                scope: super::decode_scope(scope)?,
                request_id: *request_id,
                request_digest: *request_digest,
                activity_id: expectation.activity().id(),
                agent_id: agent.agent_id(),
                initiating_session_id: session.session_id(),
                principal: session.principal(),
            };
            run_after_exact_readback(
                selector,
                |selector| {
                    clients
                        .control
                        .quiescent_activity_lease_resume_get(selector)
                        .map_err(|error| super::forge_error_of_client(&error))
                },
                |readback| receipt_json(readback.receipt()),
                || {
                    Ok(forge_control::QuiescentActivityLeaseResumeRunRequest {
                        scope: super::decode_scope(scope)?,
                        request_id: *request_id,
                        request_digest: *request_digest,
                        probe: (**probe).clone(),
                        current_service: current_service(clients)?,
                    })
                },
                |request| {
                    let operation = clients
                        .control
                        .run_quiescent_activity_lease_resume(request)
                        .map_err(|error| effect_error(&error))?;
                    Ok(json!({"receipt": receipt_json(operation.receipt())}))
                },
            )
        }
    }
}

fn run_after_exact_readback<T, Get, Build, Run>(
    selector: forge_control::QuiescentActivityLeaseResumeGetRequest,
    get: Get,
    receipt_json: impl FnOnce(&T) -> Value,
    build_run_request: Build,
    run: Run,
) -> Result<Value, ForgeError>
where
    Get: FnOnce(
        forge_control::QuiescentActivityLeaseResumeGetRequest,
    ) -> Result<Option<T>, ForgeError>,
    Build: FnOnce() -> Result<forge_control::QuiescentActivityLeaseResumeRunRequest, ForgeError>,
    Run: FnOnce(forge_control::QuiescentActivityLeaseResumeRunRequest) -> Result<Value, ForgeError>,
{
    if let Some(readback) = get(selector)? {
        return Ok(json!({"receipt": receipt_json(&readback)}));
    }
    run(build_run_request()?)
}

fn effect_error(error: &forge_control::ControlClientError) -> ForgeError {
    match error {
        forge_control::ControlClientError::Service(service) => {
            ForgeError::from_admitted_execution_view(&service.view())
        }
        _ => ForgeError::from_control_client_error(error),
    }
}

fn current_timestamp_millis() -> Result<forge_domain::TimestampMillis, ForgeError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ForgeError::invalid_input("Source clock is unavailable"))?;
    let millis = i64::try_from(elapsed.as_millis())
        .map_err(|_| ForgeError::invalid_input("Source clock overflow"))?;
    super::decode_timestamp(millis)
}

fn scope_json(scope: &ExpiredActivityRecoveryProbeScope) -> Value {
    json!({
        "workspace_id": scope.workspace_id().into_uuid(), "workspace_revision": scope.workspace_revision().get(),
        "locator": { "location_id": scope.location_id().into_uuid(), "expected_revision": scope.location_revision().get(), "relative_root": String::from_utf8_lossy(scope.locator()) },
    })
}

fn activity_json(activity: &RegisteredActivity) -> Value {
    json!({
        "activity_id": activity.id().into_uuid(), "workspace_id": activity.workspace_id().into_uuid(),
        "state": match activity.state() { ActivityState::Open => "open", ActivityState::Closed => "closed", ActivityState::Interrupted => "interrupted" },
        "revision": activity.revision().get(), "created_at_ms": activity.created_at().get(), "updated_at_ms": activity.updated_at().get(),
        "lease_owner_id": activity.lease_owner_id().map(RuntimeInstanceId::into_uuid), "lease_until_ms": activity.lease_until().map(forge_domain::TimestampMillis::get), "lease_revision": activity.lease_revision().get(),
    })
}

fn principal_json(value: AuthenticatedPrincipal) -> Value {
    match value {
        AuthenticatedPrincipal::TrustedStdio => {
            json!({"kind":"trusted_stdio","token_id":null,"grant_id":null})
        }
        AuthenticatedPrincipal::DirectToken(id) => {
            json!({"kind":"direct_token","token_id":id.into_uuid(),"grant_id":null})
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            json!({"kind":"oauth_grant","token_id":null,"grant_id":id.into_uuid()})
        }
    }
}

fn agent_json(value: &StartedActivityLeaseResumeAgentSnapshot) -> Value {
    json!({"agent_id":value.agent_id().into_uuid(),"activity_id":value.activity_id().into_uuid(),"session_id":value.session_id().into_uuid(),"principal":principal_json(value.principal()),"revision":value.revision().get(),"attached":value.attached()})
}

fn session_json(value: &StartedActivityLeaseResumeSessionSnapshot) -> Value {
    json!({"session_id":value.session_id().into_uuid(),"principal":principal_json(value.principal()),"state":match value.state(){AgentSessionState::Open=>"open",AgentSessionState::Closed=>"closed"},"revision":value.revision().get(),"updated_at_ms":value.updated_at().get()})
}

fn coordinator_json(value: &StartedActivityLeaseResumeCoordinatorSnapshot) -> Value {
    json!({"agent_id":value.agent_id().into_uuid(),"session_id":value.session_id().into_uuid(),"principal":principal_json(value.principal()),"agent_revision":value.agent_revision().get(),"revision":value.revision().get(),"updated_at_ms":value.updated_at().get(),"session_revision":value.session_revision().get(),"session_updated_at_ms":value.session_updated_at().get()})
}

fn probe_json(probe: &QuiescentActivityLeaseResumeProbe) -> Value {
    let expectation = probe.expectation();
    let service = probe.service();
    let delegation = probe.delegation();
    let goals = expectation.goal_census();
    let dag = expectation.dag_census();
    let agents = expectation.agent_census();
    let coordination = expectation.coordination_work();
    let assignments = expectation.assignment_census();
    let history = expectation.work_history_census();
    let physical = expectation.physical_census();
    json!({
        "scope": scope_json(probe.scope()),
        "service": {"backend_id":service.backend_id().into_uuid(),"issuer":service.issuer().into_uuid(),"destination_id":service.destination_id(),"runtime_instance_id":service.runtime_instance_id().into_uuid()},
        "workspace_root_fingerprint":hex(probe.scope().root_fingerprint().as_bytes()),
        "binding_digest":hex(probe.scope().binding_digest()),
        "delegation":{"migration_id":delegation.migration_id(),"destination_id":delegation.destination_id(),"freeze_revision":delegation.freeze_revision(),"freeze_created_at_ms":delegation.freeze_created_at().get(),"freeze_updated_at_ms":delegation.freeze_updated_at().get(),"manifest_digest":hex(&delegation.manifest_digest()),"delegated_at_ms":delegation.delegated_at().get(),"delegation_digest":hex(&delegation.delegation_digest())},
        "activity":activity_json(expectation.activity()),
        "initiating_agent":expectation.initiating_agent().map(agent_json),
        "initiating_session":session_json(expectation.initiating_session()),
        "coordinator":expectation.coordinator().map(coordinator_json),
        "coordinator_agent_attached":expectation.coordinator_agent_attached(),
        "coordinator_session_open":expectation.coordinator_session_open(),
        "goal_census":{"row_count":goals.row_count(),"digest":hex(&goals.digest()),"truncated":goals.truncated(),"complete":goals.complete()},
        "dag_census":{"head_count":dag.head_count(),"node_count":dag.node_count(),"edge_count":dag.edge_count(),"digest":hex(&dag.digest()),"truncated":dag.truncated(),"complete":dag.complete()},
        "agent_census":{"row_count":agents.row_count(),"digest":hex(&agents.digest()),"truncated":agents.truncated(),"complete":agents.complete()},
        "coordination_work":{"nonterminal_goal_count":coordination.nonterminal_goal_count(),"nonterminal_goal_with_current_dag_count":coordination.nonterminal_goal_with_current_dag_count()},
        "assignment_census":{"row_count":assignments.row_count(),"digest":hex(&assignments.digest()),"truncated":assignments.truncated(),"complete":assignments.complete()},
        "work_history_census":{"update_count":history.update_count(),"evidence_ref_count":history.evidence_ref_count(),"digest":hex(&history.digest()),"truncated":history.truncated(),"complete":history.complete()},
        "physical_census":{"row_count":physical.row_count(),"execution_active_count":physical.execution_active_count(),"execution_unknown_count":physical.execution_unknown_count(),"writer_lease_active_count":physical.writer_lease_active_count(),"writer_lease_unknown_count":physical.writer_lease_unknown_count(),"pending_effect_count":physical.pending_effect_count(),"effect_unknown_count":physical.effect_unknown_count(),"unresolved_worktree_count":physical.unresolved_worktree_count(),"worktree_unknown_count":physical.worktree_unknown_count(),"unknown_count":physical.unknown_count(),"digest":hex(&physical.digest()),"truncated":physical.truncated(),"complete":physical.complete()},
        "census_version":probe.census_version(),"probe_observed_at_ms":probe.probe_observed_at().get(),"probe_expires_at_ms":probe.probe_expires_at().get(),"probe_digest":hex(&probe.probe_digest()),"resumable_now":probe.resumable_now(),"blocker":probe.blocker().map(QuiescentActivityLeaseResumeBlocker::as_wire_str),
    })
}

fn receipt_json(receipt: &forge_domain::QuiescentActivityLeaseResumeReceipt) -> Value {
    json!({
        "schema_version":forge_domain::QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION,
        "request_id":receipt.request_id(),
        "request_digest":hex(&receipt.request_digest()),
        "scope":scope_json(receipt.scope()),
        "activity":activity_json(receipt.activity()),
        "initiating_agent":agent_json(&receipt.initiating_agent()),
        "initiating_session":session_json(&receipt.initiating_session()),
        "coordinator":coordinator_json(&receipt.coordinator()),
        "source_runtime_instance_id":receipt.source_runtime_instance_id().into_uuid(),
        "probe_digest":hex(&receipt.probe_digest()),
        "resumed_at_ms":receipt.resumed_at().get(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiescent_intent() -> Result<(ScopeDto, Uuid, Value), String> {
        let mut body = super::super::activity_lease_resume::tests::intent()?;
        let scope: ScopeDto =
            serde_json::from_value(body["scope"].clone()).map_err(|error| error.to_string())?;
        let request_id = serde_json::from_value(body["request_id"].clone())
            .map_err(|error| error.to_string())?;
        let probe = body["probe"]
            .as_object_mut()
            .ok_or("Started probe object missing")?;
        probe.remove("started_work_proven");
        let probe = &mut body["probe"];
        probe["coordinator_agent_attached"] = json!(true);
        probe["coordinator_session_open"] = json!(true);
        probe["agent_census"] = json!({
            "row_count": 3,
            "digest": "9".repeat(64),
            "truncated": false,
            "complete": true
        });
        probe["coordination_work"] = json!({
            "nonterminal_goal_count": 1,
            "nonterminal_goal_with_current_dag_count": 1
        });
        probe["assignment_census"]["row_count"] = json!(0);
        probe["work_history_census"] = json!({
            "update_count": 3,
            "evidence_ref_count": 3,
            "digest": "a".repeat(64),
            "truncated": false,
            "complete": true
        });
        Ok((scope, request_id, probe.clone()))
    }

    fn run_body() -> Result<(ScopeDto, Uuid, Value, [u8; 32], Value), String> {
        let (scope, request_id, probe_value) = quiescent_intent()?;
        let probe = parse_exact_probe(&probe_value).map_err(|_| "invalid quiescent fixture")?;
        let digest = request_digest(&scope, request_id, &probe).map_err(|_| "digest failed")?;
        let body = json!({
            "scope": scope,
            "request_id": request_id,
            "request_digest": hex(&digest),
            "probe": probe_value
        });
        Ok((scope, request_id, probe_value, digest, body))
    }

    #[test]
    fn canonical_quiescent_digest_and_wire_are_separate_from_started_semantics()
    -> Result<(), String> {
        let (scope, request_id, probe_value, digest, body) = run_body()?;
        let wire = parse_exact_probe(&probe_value).map_err(|_| "invalid quiescent fixture")?;
        let domain = wire.domain().map_err(|_| "invalid Q domain probe")?;
        assert_eq!(probe_json(&domain), probe_value);
        assert_eq!(
            canonical_request_digest_for_probe(&scope, request_id, &domain)
                .map_err(|_| "public digest failed")?,
            digest
        );
        assert!(
            parse(
                super::super::CommandOp::ActivityQuiescentLeaseResumeRun,
                request_id,
                &body
            )
            .is_ok()
        );

        let mut changed_digest = body.clone();
        changed_digest["request_digest"] = json!("0".repeat(64));
        assert!(
            parse(
                super::super::CommandOp::ActivityQuiescentLeaseResumeRun,
                request_id,
                &changed_digest
            )
            .is_err()
        );

        let mut changed_probe = body.clone();
        changed_probe["probe"]["work_history_census"]["digest"] = json!("b".repeat(64));
        assert!(
            parse(
                super::super::CommandOp::ActivityQuiescentLeaseResumeRun,
                request_id,
                &changed_probe
            )
            .is_err()
        );

        let mut started_flag = body;
        started_flag["probe"]["started_work_proven"] = json!(true);
        assert!(
            parse(
                super::super::CommandOp::ActivityQuiescentLeaseResumeRun,
                request_id,
                &started_flag
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn exact_existing_receipt_short_circuits_run_request_construction() -> Result<(), String> {
        let (scope, request_id, probe_value, digest, _) = run_body()?;
        let wire = parse_exact_probe(&probe_value).map_err(|_| "invalid quiescent fixture")?;
        let probe = wire.domain().map_err(|_| "invalid Q domain probe")?;
        let actor = probe
            .expectation()
            .initiating_agent()
            .ok_or("initiating Agent missing")?;
        let session = probe.expectation().initiating_session();
        let selector = forge_control::QuiescentActivityLeaseResumeGetRequest {
            scope: super::super::decode_scope(&scope).map_err(|_| "scope decode failed")?,
            request_id,
            request_digest: digest,
            activity_id: probe.expectation().activity().id(),
            agent_id: actor.agent_id(),
            initiating_session_id: session.session_id(),
            principal: session.principal(),
        };
        let expected_selector = selector.clone();
        let result = run_after_exact_readback(
            selector,
            move |actual| {
                assert_eq!(actual, expected_selector);
                Ok(Some("persisted receipt".to_owned()))
            },
            |receipt| json!(receipt),
            || {
                Err(ForgeError::invalid_input(
                    "run request must not be built after replay",
                ))
            },
            |_| {
                Err(ForgeError::invalid_input(
                    "run must not execute after replay",
                ))
            },
        )
        .map_err(|_| "exact readback should succeed without rebuilding or running")?;
        assert_eq!(result, json!({"receipt": "persisted receipt"}));
        Ok(())
    }
}
