//! Strict HTTP projection for Source-owned started Activity lease recovery.
//!
//! The client retains its immutable intent. This adapter verifies its digest;
//! the Source transaction owns the lease change and durable receipt.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{PrincipalDto, PrincipalKindDto, ScopeDto};
use crate::error::ForgeError;
use forge_domain::{
    ActivityCoordinatorRevision, ActivityId, ActivityLeaseProjection, ActivityLeaseRevision,
    ActivityRevision, ActivityState, AgentInstanceId, AgentInstanceRevision, AgentSessionId,
    AgentSessionRevision, AgentSessionState, AuthenticatedPrincipal,
    ExpiredActivityRecoveryProbeScope, ForgeBackendId, LocationId, LocationRevision,
    OrchestrationIssuerId, RegisteredActivity, RuntimeInstanceId,
    StartedActivityLeaseResumeAgentSnapshot, StartedActivityLeaseResumeAssignmentCensus,
    StartedActivityLeaseResumeBlocker, StartedActivityLeaseResumeCoordinatorSnapshot,
    StartedActivityLeaseResumeDagCensus, StartedActivityLeaseResumeDelegation,
    StartedActivityLeaseResumeExpectation, StartedActivityLeaseResumeGoalCensus,
    StartedActivityLeaseResumePhysicalCensus, StartedActivityLeaseResumeProbe,
    StartedActivityLeaseResumeServiceIdentity, StartedActivityLeaseResumeSessionSnapshot,
    UnstartedActivityContinuationServiceIdentity, WorkspaceId, WorkspaceRevision,
    WorkspaceRootFingerprint,
};

const REQUEST_DOMAIN: &[u8] = b"forge.started_activity_lease_resume.request.v1\0";

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
    ActivityNotStarted,
    ActivityNotOpen,
    ActivityLeaseMissing,
    ActivityLeaseNotExpired,
    InitiatingAgentMissing,
    CoordinatorMissing,
    CoordinatorAgentNotAttached,
    CoordinatorSessionNotOpen,
    GoalCensusIncomplete,
    DagCensusIncomplete,
    AssignmentCensusIncomplete,
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
struct AssignmentCensusWire {
    row_count: u32,
    digest: String,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PhysicalCensusWire {
    row_count: u32,
    execution_active_count: u32,
    execution_unknown_count: u32,
    writer_lease_active_count: u32,
    writer_lease_unknown_count: u32,
    pending_effect_count: u32,
    effect_unknown_count: u32,
    unresolved_worktree_count: u32,
    worktree_unknown_count: u32,
    unknown_count: u32,
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
    started_work_proven: bool,
    goal_census: GoalCensusWire,
    dag_census: DagCensusWire,
    assignment_census: AssignmentCensusWire,
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

/// Canonicalize explicitly, even if another dependency enables `preserve_order`.
pub(super) fn sorted_json(value: &Value) -> Result<Value, ForgeError> {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<_> = fields.keys().collect();
            keys.sort_unstable();
            let mut result = serde_json::Map::new();
            for key in keys {
                result.insert(key.clone(), sorted_json(&fields[key])?);
            }
            Ok(Value::Object(result))
        }
        Value::Array(values) => values
            .iter()
            .map(sorted_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Number(number) if number.as_i64().is_none() => Err(ForgeError::invalid_input(
            "Recovery intent numbers must be signed integers",
        )),
        _ => Ok(value.clone()),
    }
}

fn request_digest(
    scope: &ScopeDto,
    request_id: Uuid,
    probe: &ProbeWire,
) -> Result<[u8; 32], ForgeError> {
    let intent = json!({"scope": scope, "request_id": request_id, "probe": probe});
    let canonical =
        serde_json::to_vec(&sorted_json(&intent)?).map_err(|_| ForgeError::internal())?;
    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    digest.update(canonical);
    Ok(digest.finalize().into())
}

pub(super) fn canonical_request_digest_for_probe(
    scope: &super::ScopeDto,
    request_id: Uuid,
    probe: &StartedActivityLeaseResumeProbe,
) -> Result<[u8; 32], ForgeError> {
    let wire = parse_exact_probe(&probe_json(probe))?;
    request_digest(scope, request_id, &wire)
}

fn parse_exact_probe(value: &Value) -> Result<ProbeWire, ForgeError> {
    let probe: ProbeWire = serde_json::from_value(value.clone())
        .map_err(|_| ForgeError::invalid_input("Started recovery probe is invalid"))?;
    let encoded = serde_json::to_value(&probe).map_err(|_| ForgeError::internal())?;
    if encoded != *value {
        return Err(ForgeError::invalid_input(
            "Started recovery probe must retain every canonical field and explicit null",
        ));
    }
    Ok(probe)
}

fn invalid_snapshot() -> ForgeError {
    ForgeError::invalid_input("Started recovery snapshot fence is invalid")
}

fn non_nil(id: Uuid) -> Result<Uuid, ForgeError> {
    if id.is_nil() {
        Err(invalid_snapshot())
    } else {
        Ok(id)
    }
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
            ActivityCoordinatorRevision::new(self.revision).map_err(|_| invalid_snapshot())?,
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
    const fn domain(self) -> StartedActivityLeaseResumeBlocker {
        match self {
            Self::ActivityNotStarted => StartedActivityLeaseResumeBlocker::ActivityNotStarted,
            Self::ActivityNotOpen => StartedActivityLeaseResumeBlocker::ActivityNotOpen,
            Self::ActivityLeaseMissing => StartedActivityLeaseResumeBlocker::ActivityLeaseMissing,
            Self::ActivityLeaseNotExpired => {
                StartedActivityLeaseResumeBlocker::ActivityLeaseNotExpired
            }
            Self::InitiatingAgentMissing => {
                StartedActivityLeaseResumeBlocker::InitiatingAgentMissing
            }
            Self::CoordinatorMissing => StartedActivityLeaseResumeBlocker::CoordinatorMissing,
            Self::CoordinatorAgentNotAttached => {
                StartedActivityLeaseResumeBlocker::CoordinatorAgentNotAttached
            }
            Self::CoordinatorSessionNotOpen => {
                StartedActivityLeaseResumeBlocker::CoordinatorSessionNotOpen
            }
            Self::GoalCensusIncomplete => StartedActivityLeaseResumeBlocker::GoalCensusIncomplete,
            Self::DagCensusIncomplete => StartedActivityLeaseResumeBlocker::DagCensusIncomplete,
            Self::AssignmentCensusIncomplete => {
                StartedActivityLeaseResumeBlocker::AssignmentCensusIncomplete
            }
            Self::PhysicalActivityEffectPresent => {
                StartedActivityLeaseResumeBlocker::PhysicalActivityEffectPresent
            }
            Self::PhysicalCensusIncomplete => {
                StartedActivityLeaseResumeBlocker::PhysicalCensusIncomplete
            }
        }
    }
}

impl ProbeWire {
    fn domain(&self) -> Result<StartedActivityLeaseResumeProbe, ForgeError> {
        if self.census_version != 1 || self.scope.workspace_id != self.activity.workspace_id {
            return Err(invalid_snapshot());
        }
        let scope = ExpiredActivityRecoveryProbeScope::new(
            WorkspaceId::from_uuid(non_nil(self.scope.workspace_id)?),
            WorkspaceRevision::new(self.scope.workspace_revision)
                .map_err(|_| invalid_snapshot())?,
            LocationId::from_uuid(non_nil(self.scope.locator.location_id)?),
            LocationRevision::new(self.scope.locator.expected_revision)
                .map_err(|_| invalid_snapshot())?,
            self.scope.locator.relative_root.as_bytes().to_vec(),
            WorkspaceRootFingerprint::from_bytes(hex_bytes(&self.workspace_root_fingerprint)?),
            hex_bytes(&self.binding_digest)?,
        )
        .map_err(|_| invalid_snapshot())?;
        let _validated_scope = super::decode_scope(&self.scope)?;
        let goals = &self.goal_census;
        let dag = &self.dag_census;
        let assignments = &self.assignment_census;
        let physical = &self.physical_census;
        let expectation = StartedActivityLeaseResumeExpectation::new(
            self.activity.domain()?,
            self.initiating_agent
                .as_ref()
                .map(AgentWire::domain)
                .transpose()?,
            self.initiating_session.domain()?,
            self.coordinator
                .as_ref()
                .map(CoordinatorWire::domain)
                .transpose()?,
            self.started_work_proven,
            StartedActivityLeaseResumeGoalCensus::new(
                goals.row_count,
                hex_bytes(&goals.digest)?,
                goals.truncated,
                goals.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            StartedActivityLeaseResumeDagCensus::new(
                dag.head_count,
                dag.node_count,
                dag.edge_count,
                hex_bytes(&dag.digest)?,
                dag.truncated,
                dag.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            StartedActivityLeaseResumeAssignmentCensus::new(
                assignments.row_count,
                hex_bytes(&assignments.digest)?,
                assignments.truncated,
                assignments.complete,
            )
            .map_err(|_| invalid_snapshot())?,
            StartedActivityLeaseResumePhysicalCensus::new(
                physical.row_count,
                u64::from(physical.execution_active_count),
                u64::from(physical.execution_unknown_count),
                u64::from(physical.writer_lease_active_count),
                u64::from(physical.writer_lease_unknown_count),
                u64::from(physical.pending_effect_count),
                u64::from(physical.effect_unknown_count),
                u64::from(physical.unresolved_worktree_count),
                u64::from(physical.worktree_unknown_count),
                u64::from(physical.unknown_count),
                hex_bytes(&physical.digest)?,
                physical.truncated,
                physical.complete,
            )
            .map_err(|_| invalid_snapshot())?,
        )
        .map_err(|_| invalid_snapshot())?;
        let probe = StartedActivityLeaseResumeProbe::new(
            scope,
            self.service.domain()?,
            self.delegation.domain()?,
            expectation,
            super::decode_timestamp(self.probe_observed_at_ms)?,
            hex_bytes(&self.probe_digest)?,
            self.resumable_now,
            self.blocker.map(BlockerWire::domain),
        )
        .map_err(|_| invalid_snapshot())?;
        if probe.probe_expires_at().get() != self.probe_expires_at_ms {
            return Err(invalid_snapshot());
        }
        Ok(probe)
    }
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
        probe: Box<StartedActivityLeaseResumeProbe>,
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
            Self::Probe { .. } => super::CommandOp::ActivityStartedLeaseResumeProbe,
            Self::Run { .. } => super::CommandOp::ActivityStartedLeaseResumeRun,
            Self::Get { .. } => super::CommandOp::ActivityStartedLeaseResumeGet,
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
        let actor = probe.expectation().initiating_agent()?;
        let session = probe.expectation().initiating_session();
        Some(crate::error::ReadbackHint::StartedActivityLeaseResume {
            scope: scope.clone(),
            request_id: *request_id,
            request_digest: hex(request_digest),
            activity_id: probe.expectation().activity().id().into_uuid(),
            agent_id: actor.agent_id().into_uuid(),
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
    let request = match op {
        super::CommandOp::ActivityStartedLeaseResumeProbe => {
            let body: ProbeBody =
                super::parse_body(payload, "Started recovery probe request is invalid")?;
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
        super::CommandOp::ActivityStartedLeaseResumeRun => {
            let body: RunBody =
                super::parse_body(payload, "Started recovery run request is invalid")?;
            canonical_scope(&body.scope, &payload["scope"])?;
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
        super::CommandOp::ActivityStartedLeaseResumeGet => {
            let body: GetBody =
                super::parse_body(payload, "Started recovery get request is invalid")?;
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
                "Wrong started recovery operation",
            ));
        }
    };
    Ok(super::Command::ActivityStartedLeaseResume {
        request_id,
        request: Box::new(request),
    })
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

fn current_service(
    clients: &super::BridgeClients,
) -> Result<StartedActivityLeaseResumeServiceIdentity, ForgeError> {
    let identity = UnstartedActivityContinuationServiceIdentity::new(
        clients.backend_id,
        clients.issuer,
        clients.runtime_instance_id,
    )
    .map_err(|_| invalid_snapshot())?;
    StartedActivityLeaseResumeServiceIdentity::new(identity, clients.destination_id)
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
            let request = forge_control::StartedActivityLeaseResumeProbeRequest {
                scope: scope.clone(),
                activity_id: *activity_id,
                initiating_session_id: *session_id,
                principal: *principal,
                service: current_service(clients)?,
                observed_at: current_timestamp_millis()?,
            };
            let probe = clients
                .control
                .started_activity_lease_resume_probe(request)
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
            let request = forge_control::StartedActivityLeaseResumeGetRequest {
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
                .started_activity_lease_resume_get(request)
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
            let actor = expectation
                .initiating_agent()
                .ok_or_else(invalid_snapshot)?;
            let selector = forge_control::StartedActivityLeaseResumeGetRequest {
                scope: super::decode_scope(scope)?,
                request_id: *request_id,
                request_digest: *request_digest,
                activity_id: expectation.activity().id(),
                agent_id: actor.agent_id(),
                initiating_session_id: expectation.initiating_session().session_id(),
                principal: expectation.initiating_session().principal(),
            };
            // Historical exact replay must precede current-boot/TTL admission.
            if let Some(receipt) = clients
                .control
                .started_activity_lease_resume_get(selector)
                .map_err(|error| super::forge_error_of_client(&error))?
            {
                return Ok(json!({"receipt": receipt_json(receipt.receipt())}));
            }
            let request = forge_control::StartedActivityLeaseResumeRunRequest {
                scope: super::decode_scope(scope)?,
                request_id: *request_id,
                request_digest: *request_digest,
                probe: (**probe).clone(),
                current_service: current_service(clients)?,
            };
            let outcome = clients
                .control
                .run_started_activity_lease_resume(request)
                .map_err(|error| effect_error(&error))?;
            Ok(json!({"receipt": receipt_json(outcome.receipt())}))
        }
    }
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

fn agent_json(agent: &StartedActivityLeaseResumeAgentSnapshot) -> Value {
    json!({ "agent_id": agent.agent_id().into_uuid(), "activity_id": agent.activity_id().into_uuid(), "session_id": agent.session_id().into_uuid(),
        "principal": principal_readback(agent.principal()), "revision": agent.revision().get(), "attached": agent.attached() })
}

fn session_json(session: &StartedActivityLeaseResumeSessionSnapshot) -> Value {
    json!({ "session_id": session.session_id().into_uuid(), "principal": principal_readback(session.principal()),
        "state": match session.state() { AgentSessionState::Open => "open", AgentSessionState::Closed => "closed" },
        "revision": session.revision().get(), "updated_at_ms": session.updated_at().get() })
}

fn coordinator_json(coordinator: &StartedActivityLeaseResumeCoordinatorSnapshot) -> Value {
    json!({ "agent_id": coordinator.agent_id().into_uuid(), "session_id": coordinator.session_id().into_uuid(), "principal": principal_readback(coordinator.principal()),
        "agent_revision": coordinator.agent_revision().get(), "revision": coordinator.revision().get(), "updated_at_ms": coordinator.updated_at().get(),
        "session_revision": coordinator.session_revision().get(), "session_updated_at_ms": coordinator.session_updated_at().get() })
}

fn probe_json(probe: &StartedActivityLeaseResumeProbe) -> Value {
    let expected = probe.expectation();
    let service = probe.service();
    let delegation = probe.delegation();
    let goals = expected.goal_census();
    let dag = expected.dag_census();
    let assignments = expected.assignment_census();
    let physical = expected.physical_census();
    json!({
        "scope": scope_json(probe.scope()), "service": { "backend_id": service.backend_id().into_uuid(), "issuer": service.issuer().into_uuid(), "destination_id": service.destination_id(), "runtime_instance_id": service.runtime_instance_id().into_uuid() },
        "workspace_root_fingerprint": hex(&probe.scope().root_fingerprint().into_bytes()), "binding_digest": hex(probe.scope().binding_digest()),
        "delegation": { "migration_id": delegation.migration_id(), "destination_id": delegation.destination_id(), "freeze_revision": delegation.freeze_revision(),
            "freeze_created_at_ms": delegation.freeze_created_at().get(), "freeze_updated_at_ms": delegation.freeze_updated_at().get(), "manifest_digest": hex(&delegation.manifest_digest()), "delegated_at_ms": delegation.delegated_at().get(), "delegation_digest": hex(&delegation.delegation_digest()) },
        "activity": activity_json(expected.activity()), "initiating_agent": expected.initiating_agent().map(agent_json), "initiating_session": session_json(expected.initiating_session()), "coordinator": expected.coordinator().map(coordinator_json), "started_work_proven": expected.started_work_proven(),
        "goal_census": { "row_count": goals.row_count(), "digest": hex(&goals.digest()), "truncated": goals.truncated(), "complete": goals.complete() },
        "dag_census": { "head_count": dag.head_count(), "node_count": dag.node_count(), "edge_count": dag.edge_count(), "digest": hex(&dag.digest()), "truncated": dag.truncated(), "complete": dag.complete() },
        "assignment_census": { "row_count": assignments.row_count(), "digest": hex(&assignments.digest()), "truncated": assignments.truncated(), "complete": assignments.complete() },
        "physical_census": { "row_count": physical.row_count(), "execution_active_count": physical.execution_active_count(), "execution_unknown_count": physical.execution_unknown_count(),
            "writer_lease_active_count": physical.writer_lease_active_count(), "writer_lease_unknown_count": physical.writer_lease_unknown_count(), "pending_effect_count": physical.pending_effect_count(), "effect_unknown_count": physical.effect_unknown_count(),
            "unresolved_worktree_count": physical.unresolved_worktree_count(), "worktree_unknown_count": physical.worktree_unknown_count(), "unknown_count": physical.unknown_count(), "digest": hex(&physical.digest()), "truncated": physical.truncated(), "complete": physical.complete() },
        "census_version": 1, "probe_observed_at_ms": probe.probe_observed_at().get(), "probe_expires_at_ms": probe.probe_expires_at().get(), "probe_digest": hex(&probe.probe_digest()), "resumable_now": probe.resumable_now(), "blocker": probe.blocker().map(StartedActivityLeaseResumeBlocker::as_wire_str),
    })
}

fn receipt_json(receipt: &forge_domain::StartedActivityLeaseResumeReceipt) -> Value {
    json!({
        "schema_version": receipt.schema_version(), "request_id": receipt.request_id(), "request_digest": hex(&receipt.request_digest()), "scope": scope_json(receipt.scope()),
        "activity_id": receipt.activity_id().into_uuid(), "activity": activity_json(receipt.activity()), "initiating_agent": agent_json(receipt.initiating_agent()),
        "initiating_session": session_json(receipt.initiating_session()), "coordinator": coordinator_json(receipt.coordinator()), "source_runtime_instance_id": receipt.source_runtime_instance_id().into_uuid(),
        "probe_digest": hex(&receipt.probe_digest()), "resumed_at_ms": receipt.resumed_at().get(),
    })
}

#[cfg(test)]
pub(in crate::ops) mod tests {
    use super::*;
    const GOLDEN_INTENT: &str = r#"{"probe":{"activity":{"activity_id":"c06a412e-a9aa-42a5-b3b3-cc0ea9f12d35","created_at_ms":1790000000000,"lease_owner_id":"5f079869-c1fd-4652-8191-d731977b7383","lease_revision":11,"lease_until_ms":1790000002000,"revision":7,"state":"open","updated_at_ms":1790000001000,"workspace_id":"6d73e10c-bc23-4805-9581-2986dfbbbec0"},"assignment_census":{"complete":true,"digest":"6666666666666666666666666666666666666666666666666666666666666666","row_count":1,"truncated":false},"binding_digest":"1111111111111111111111111111111111111111111111111111111111111111","blocker":null,"census_version":1,"coordinator":{"agent_id":"39a3ae7c-0d5e-4734-aa31-d3c09cd8ee7a","agent_revision":3,"principal":{"grant_id":null,"kind":"direct_token","token_id":"01a11045-cf31-7db0-9d99-5a54b7c9ac9c"},"revision":4,"session_id":"01a12ab2-5357-75d2-a25e-8932af6f569f","session_revision":2,"session_updated_at_ms":1790000001000,"updated_at_ms":1790000002000},"dag_census":{"complete":true,"digest":"5555555555555555555555555555555555555555555555555555555555555555","edge_count":0,"head_count":1,"node_count":1,"truncated":false},"delegation":{"delegated_at_ms":1789999992000,"delegation_digest":"3333333333333333333333333333333333333333333333333333333333333333","destination_id":"d80145a4-8aa3-45a7-bf3e-4078f1e131ad","freeze_created_at_ms":1789999990000,"freeze_revision":2,"freeze_updated_at_ms":1789999991000,"manifest_digest":"2222222222222222222222222222222222222222222222222222222222222222","migration_id":"6ac4347d-88b9-424c-ae77-76d7fbf65c10"},"goal_census":{"complete":true,"digest":"4444444444444444444444444444444444444444444444444444444444444444","row_count":1,"truncated":false},"initiating_agent":{"activity_id":"c06a412e-a9aa-42a5-b3b3-cc0ea9f12d35","agent_id":"39a3ae7c-0d5e-4734-aa31-d3c09cd8ee7a","attached":true,"principal":{"grant_id":null,"kind":"direct_token","token_id":"01a11045-cf31-7db0-9d99-5a54b7c9ac9c"},"revision":3,"session_id":"01a12ab2-5357-75d2-a25e-8932af6f569f"},"initiating_session":{"principal":{"grant_id":null,"kind":"direct_token","token_id":"01a11045-cf31-7db0-9d99-5a54b7c9ac9c"},"revision":2,"session_id":"01a12ab2-5357-75d2-a25e-8932af6f569f","state":"open","updated_at_ms":1790000001000},"physical_census":{"complete":true,"digest":"7777777777777777777777777777777777777777777777777777777777777777","effect_unknown_count":0,"execution_active_count":0,"execution_unknown_count":0,"pending_effect_count":0,"row_count":0,"truncated":false,"unknown_count":0,"unresolved_worktree_count":0,"worktree_unknown_count":0,"writer_lease_active_count":0,"writer_lease_unknown_count":0},"probe_digest":"8888888888888888888888888888888888888888888888888888888888888888","probe_expires_at_ms":1790000033000,"probe_observed_at_ms":1790000003000,"resumable_now":true,"scope":{"locator":{"expected_revision":1,"location_id":"842edb64-e3eb-4367-a169-5576a32a7a89","relative_root":"naïve"},"workspace_id":"6d73e10c-bc23-4805-9581-2986dfbbbec0","workspace_revision":1},"service":{"backend_id":"234c21c7-5732-4b92-8679-8945f48bdad0","destination_id":"d80145a4-8aa3-45a7-bf3e-4078f1e131ad","issuer":"a65f6ac0-820d-4d1d-9333-9d1b4a2c22b5","runtime_instance_id":"6bc9678b-c360-426a-9cd8-53d1852b9ee7"},"started_work_proven":true,"workspace_root_fingerprint":"00000000000000000000000000000001"},"request_id":"7818e15a-4af6-4f28-bbad-c5d7e335e417","scope":{"locator":{"expected_revision":1,"location_id":"842edb64-e3eb-4367-a169-5576a32a7a89","relative_root":"naïve"},"workspace_id":"6d73e10c-bc23-4805-9581-2986dfbbbec0","workspace_revision":1}}"#;
    const GOLDEN_DIGEST: &str = "1aca60c6c077f228a5518aec9f00dab22c2559250093350b3bd47a6c723b812e";

    pub(in crate::ops) fn intent() -> Result<Value, String> {
        serde_json::from_str(GOLDEN_INTENT).map_err(|e| e.to_string())
    }
    fn run_body() -> Result<(Uuid, Value), String> {
        let mut body = intent()?;
        let request_id =
            serde_json::from_value(body["request_id"].clone()).map_err(|e| e.to_string())?;
        body["request_digest"] = json!(GOLDEN_DIGEST);
        Ok((request_id, body))
    }
    fn exact(value: &Value) -> Result<ProbeWire, String> {
        parse_exact_probe(value).map_err(|_| "expected strict probe".to_owned())
    }

    #[test]
    fn canonical_digest_matches_independent_unicode_and_null_vector() -> Result<(), String> {
        let value = intent()?;
        let scope: ScopeDto =
            serde_json::from_value(value["scope"].clone()).map_err(|e| e.to_string())?;
        let request_id =
            serde_json::from_value(value["request_id"].clone()).map_err(|e| e.to_string())?;
        let probe = exact(&value["probe"])?;
        let digest = request_digest(&scope, request_id, &probe).map_err(|_| "digest failed")?;
        assert_eq!(hex(&digest), GOLDEN_DIGEST);
        let sorted = sorted_json(&value).map_err(|_| "sort failed")?;
        assert_eq!(
            serde_json::to_string(&sorted).map_err(|e| e.to_string())?,
            GOLDEN_INTENT
        );
        let domain = probe.domain().map_err(|_| "invalid domain probe")?;
        assert_eq!(probe_json(&domain), value["probe"]);
        let (request_id, body) = run_body()?;
        assert!(
            parse(
                super::super::CommandOp::ActivityStartedLeaseResumeRun,
                request_id,
                &body
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn missing_nullable_or_noncanonical_uuid_probe_cannot_be_admitted() -> Result<(), String> {
        let mut value = intent()?["probe"].clone();
        value["initiating_session"]["principal"]
            .as_object_mut()
            .ok_or("expected principal object")?
            .remove("grant_id");
        assert!(parse_exact_probe(&value).is_err());
        let mut value = intent()?["probe"].clone();
        let upper = value["scope"]["workspace_id"]
            .as_str()
            .ok_or("expected UUID")?
            .to_uppercase();
        value["scope"]["workspace_id"] = json!(upper);
        assert!(parse_exact_probe(&value).is_err());
        Ok(())
    }

    #[test]
    fn wrong_digest_foreign_scope_extra_owner_and_float_are_rejected_before_io()
    -> Result<(), String> {
        let op = super::super::CommandOp::ActivityStartedLeaseResumeRun;
        let (request_id, body) = run_body()?;
        let mut changed = body.clone();
        changed["request_digest"] = json!("0".repeat(64));
        assert!(parse(op, request_id, &changed).is_err());
        let mut changed = body.clone();
        changed["scope"]["workspace_id"] = json!(Uuid::from_u128(1));
        assert!(parse(op, request_id, &changed).is_err());
        let mut changed = body.clone();
        changed["runtime_instance_id"] = json!(Uuid::from_u128(1));
        assert!(parse(op, request_id, &changed).is_err());
        let mut changed = body.clone();
        changed["probe"]["census_version"] = json!(1.0);
        assert!(parse(op, request_id, &changed).is_err());
        assert!(parse(op, Uuid::nil(), &body).is_err());
        assert!(sorted_json(&json!({"n": 1.0})).is_err());
        Ok(())
    }

    #[test]
    fn closed_principal_and_source_probe_invariants_are_not_coerced() -> Result<(), String> {
        let mut value = intent()?["probe"].clone();
        value["initiating_session"]["principal"]["grant_id"] = json!(Uuid::from_u128(1));
        assert!(exact(&value)?.domain().is_err());
        let mut value = intent()?["probe"].clone();
        value["resumable_now"] = json!(false);
        assert!(exact(&value)?.domain().is_err());
        let mut value = intent()?["probe"].clone();
        value["probe_expires_at_ms"] = json!(1_790_000_090_000_i64);
        assert!(exact(&value)?.domain().is_err());
        Ok(())
    }

    #[test]
    fn uncertain_run_hint_retains_original_actor_and_required_principal_nulls() -> Result<(), String>
    {
        let (request_id, body) = run_body()?;
        let command = parse(
            super::super::CommandOp::ActivityStartedLeaseResumeRun,
            request_id,
            &body,
        )
        .map_err(|_| "expected valid command")?;
        let hint =
            serde_json::to_value(command.readback_hint().ok_or("missing original readback")?)
                .map_err(|e| e.to_string())?;
        assert_eq!(hint["kind"], "started_activity_lease_resume");
        assert_eq!(hint["request_id"], body["request_id"]);
        assert_eq!(hint["scope"], body["scope"]);
        assert_eq!(hint["request_digest"], body["request_digest"]);
        assert_eq!(
            hint["activity_id"],
            body["probe"]["activity"]["activity_id"]
        );
        assert_eq!(
            hint["agent_id"],
            body["probe"]["initiating_agent"]["agent_id"]
        );
        assert_eq!(
            hint["principal"],
            body["probe"]["initiating_session"]["principal"]
        );
        assert!(
            hint["principal"]
                .as_object()
                .ok_or("expected principal")?
                .contains_key("grant_id")
        );
        Ok(())
    }
}
