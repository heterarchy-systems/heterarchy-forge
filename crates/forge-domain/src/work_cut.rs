//! Exact, bounded governance work-cut request envelopes.
//!
//! Validation is not authentication, roster completeness, custody or transfer.
//! The trusted host owns the roster witness; Forge must compare it with current
//! source bindings and establish custody atomically before issuing a cut receipt.

use crate::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, DagNodeId,
    DagRevisionNumber, ForgeBackendId, GoalId, GoalRevision, OrchestrationIssuerId,
    TimestampMillis, WorkspaceId, WorkspaceRevision,
};
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;

pub const MAX_WORK_CUT_SESSIONS: usize = 128;
pub const MAX_WORK_CUT_BINDINGS: usize = 256;
pub const MAX_WORK_CUT_TEAM_NODES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkCutSide {
    Incumbent,
    Elected,
}
impl WorkCutSide {
    const fn tag(self) -> u8 {
        match self {
            Self::Incumbent => 0,
            Self::Elected => 1,
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCutParty {
    participation_id: Uuid,
    profile_id: Uuid,
}
impl WorkCutParty {
    pub fn new(participation_id: Uuid, profile_id: Uuid) -> Result<Self, WorkCutRequestError> {
        nonnil(participation_id)?;
        nonnil(profile_id)?;
        Ok(Self {
            participation_id,
            profile_id,
        })
    }
    pub const fn participation_id(self) -> Uuid {
        self.participation_id
    }
    pub const fn profile_id(self) -> Uuid {
        self.profile_id
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCutSession {
    side: WorkCutSide,
    session_id: AgentSessionId,
}
impl WorkCutSession {
    pub fn new(side: WorkCutSide, session_id: AgentSessionId) -> Result<Self, WorkCutRequestError> {
        nonnil(session_id.into_uuid())?;
        Ok(Self { side, session_id })
    }
    pub const fn side(self) -> WorkCutSide {
        self.side
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCutBinding {
    side: WorkCutSide,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
}
impl WorkCutBinding {
    pub fn new(
        side: WorkCutSide,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> Result<Self, WorkCutRequestError> {
        for id in [
            activity_id.into_uuid(),
            agent_id.into_uuid(),
            session_id.into_uuid(),
        ] {
            nonnil(id)?;
        }
        match principal {
            AuthenticatedPrincipal::TrustedStdio => {}
            AuthenticatedPrincipal::DirectToken(id) => nonnil(id.into_uuid())?,
            AuthenticatedPrincipal::OAuthGrant(id) => nonnil(id.into_uuid())?,
        }
        Ok(Self {
            side,
            activity_id,
            agent_id,
            session_id,
            principal,
        })
    }
    pub const fn side(self) -> WorkCutSide {
        self.side
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkCutNodeScope {
    activity_id: ActivityId,
    goal_id: GoalId,
    goal_created_at: TimestampMillis,
    dag_base_goal_revision: GoalRevision,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
}
impl WorkCutNodeScope {
    pub fn new(
        activity_id: ActivityId,
        goal_id: GoalId,
        goal_created_at: TimestampMillis,
        dag_base_goal_revision: GoalRevision,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    ) -> Result<Self, WorkCutRequestError> {
        nonnil(activity_id.into_uuid())?;
        nonnil(goal_id.into_uuid())?;
        nonnil(node_id.into_uuid())?;
        Ok(Self {
            activity_id,
            goal_id,
            goal_created_at,
            dag_base_goal_revision,
            dag_revision,
            node_id,
        })
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn dag_base_goal_revision(self) -> GoalRevision {
        self.dag_base_goal_revision
    }
    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }
    pub const fn goal_created_at(self) -> TimestampMillis {
        self.goal_created_at
    }
    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }
    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkCutScope {
    Workspace,
    Team {
        team_id: Uuid,
        nodes: Vec<WorkCutNodeScope>,
    },
}
impl WorkCutScope {
    fn canonicalize(&mut self) -> Result<(), WorkCutRequestError> {
        if let Self::Team { team_id, nodes } = self {
            nonnil(*team_id)?;
            if nodes.len() > MAX_WORK_CUT_TEAM_NODES {
                return Err(WorkCutRequestError::Bounds);
            }
            nodes.sort_unstable();
            if nodes.windows(2).any(|p| p[0] == p[1]) {
                return Err(WorkCutRequestError::Duplicate);
            }
        }
        Ok(())
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkCutRequestDigest([u8; 32]);
impl WorkCutRequestDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCutRequest {
    cut_id: Uuid,
    election_id: Uuid,
    destination_id: Uuid,
    backend_id: ForgeBackendId,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    leadership_revision: i64,
    roster_digest: [u8; 32],
    parties: [WorkCutParty; 2],
    sessions: Vec<WorkCutSession>,
    bindings: Vec<WorkCutBinding>,
    scope: WorkCutScope,
    digest: WorkCutRequestDigest,
}
impl WorkCutRequest {
    /// Construct one exact attestation. Party index zero is incumbent, one elected.
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor seals the complete cross-authority attestation"
    )]
    pub fn new(
        cut_id: Uuid,
        election_id: Uuid,
        destination_id: Uuid,
        backend_id: ForgeBackendId,
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        leadership_revision: i64,
        roster_digest: [u8; 32],
        parties: [WorkCutParty; 2],
        mut sessions: Vec<WorkCutSession>,
        mut bindings: Vec<WorkCutBinding>,
        mut scope: WorkCutScope,
    ) -> Result<Self, WorkCutRequestError> {
        for id in [
            cut_id,
            election_id,
            destination_id,
            backend_id.into_uuid(),
            workspace_id.into_uuid(),
        ] {
            nonnil(id)?;
        }
        if leadership_revision < 1 || roster_digest == [0; 32] {
            return Err(WorkCutRequestError::InvalidWitness);
        }
        if parties[0].participation_id == parties[1].participation_id
            || parties[0].profile_id == parties[1].profile_id
        {
            return Err(WorkCutRequestError::SameParty);
        }
        if sessions.len() > MAX_WORK_CUT_SESSIONS || bindings.len() > MAX_WORK_CUT_BINDINGS {
            return Err(WorkCutRequestError::Bounds);
        }
        sessions.sort_unstable_by_key(|v| v.session_id);
        if sessions
            .windows(2)
            .any(|p| p[0].session_id == p[1].session_id)
        {
            return Err(WorkCutRequestError::Duplicate);
        }
        for side in [WorkCutSide::Incumbent, WorkCutSide::Elected] {
            if !sessions.iter().any(|session| session.side == side) {
                return Err(WorkCutRequestError::MissingSession);
            }
        }
        bindings.sort_unstable_by_key(|v| v.agent_id);
        let mut activity_sessions = BTreeSet::new();
        let mut session_principals = std::collections::BTreeMap::new();
        for b in &bindings {
            if !activity_sessions.insert((b.activity_id, b.session_id)) {
                return Err(WorkCutRequestError::Duplicate);
            }
            if session_principals
                .insert(b.session_id, b.principal)
                .is_some_and(|prior| prior != b.principal)
            {
                return Err(WorkCutRequestError::PrincipalMismatch);
            }
            if !sessions
                .iter()
                .any(|s| s.session_id == b.session_id && s.side == b.side)
            {
                return Err(WorkCutRequestError::MissingSession);
            }
        }
        if bindings.windows(2).any(|p| p[0].agent_id == p[1].agent_id) {
            return Err(WorkCutRequestError::Duplicate);
        }
        scope.canonicalize()?;
        let mut value = Self {
            cut_id,
            election_id,
            destination_id,
            backend_id,
            workspace_id,
            workspace_revision,
            leadership_revision,
            roster_digest,
            parties,
            sessions,
            bindings,
            scope,
            digest: WorkCutRequestDigest([0; 32]),
        };
        value.digest = value.compute_digest()?;
        Ok(value)
    }
    pub const fn cut_id(&self) -> Uuid {
        self.cut_id
    }
    pub const fn election_id(&self) -> Uuid {
        self.election_id
    }
    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }
    pub const fn backend_id(&self) -> ForgeBackendId {
        self.backend_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn workspace_revision(&self) -> WorkspaceRevision {
        self.workspace_revision
    }
    pub const fn leadership_revision(&self) -> i64 {
        self.leadership_revision
    }
    pub const fn roster_digest(&self) -> &[u8; 32] {
        &self.roster_digest
    }
    pub const fn parties(&self) -> &[WorkCutParty; 2] {
        &self.parties
    }
    pub fn sessions(&self) -> &[WorkCutSession] {
        &self.sessions
    }
    pub fn bindings(&self) -> &[WorkCutBinding] {
        &self.bindings
    }
    pub const fn scope(&self) -> &WorkCutScope {
        &self.scope
    }
    pub const fn request_digest(&self) -> WorkCutRequestDigest {
        self.digest
    }

    fn compute_digest(&self) -> Result<WorkCutRequestDigest, WorkCutRequestError> {
        let mut hash = blake3::Hasher::new();
        hash.update(b"heterarchy-forge-work-cut-request-v1\0");
        for id in [
            self.cut_id,
            self.election_id,
            self.destination_id,
            self.backend_id.into_uuid(),
            self.workspace_id.into_uuid(),
        ] {
            hash.update(id.as_bytes());
        }
        hash.update(&self.workspace_revision.get().to_be_bytes());
        hash.update(&self.leadership_revision.to_be_bytes());
        hash.update(&self.roster_digest);
        for party in &self.parties {
            hash.update(party.participation_id.as_bytes());
            hash.update(party.profile_id.as_bytes());
        }
        hash_count(&mut hash, self.sessions.len())?;
        for s in &self.sessions {
            hash.update(&[s.side.tag()]);
            hash.update(s.session_id.into_uuid().as_bytes());
        }
        hash_count(&mut hash, self.bindings.len())?;
        for b in &self.bindings {
            hash.update(&[b.side.tag()]);
            for id in [
                b.activity_id.into_uuid(),
                b.agent_id.into_uuid(),
                b.session_id.into_uuid(),
            ] {
                hash.update(id.as_bytes());
            }
            match b.principal {
                AuthenticatedPrincipal::TrustedStdio => {
                    hash.update(&[0]);
                }
                AuthenticatedPrincipal::DirectToken(id) => {
                    hash.update(&[1]);
                    hash.update(id.into_uuid().as_bytes());
                }
                AuthenticatedPrincipal::OAuthGrant(id) => {
                    hash.update(&[2]);
                    hash.update(id.into_uuid().as_bytes());
                }
            }
        }
        match &self.scope {
            WorkCutScope::Workspace => {
                hash.update(&[0]);
            }
            WorkCutScope::Team { team_id, nodes } => {
                hash.update(&[1]);
                hash.update(team_id.as_bytes());
                hash_count(&mut hash, nodes.len())?;
                for n in nodes {
                    hash.update(n.activity_id.into_uuid().as_bytes());
                    hash.update(n.goal_id.into_uuid().as_bytes());
                    hash.update(&n.goal_created_at.get().to_be_bytes());
                    hash.update(&n.dag_base_goal_revision.get().to_be_bytes());
                    hash.update(&n.dag_revision.get().to_be_bytes());
                    hash.update(n.node_id.into_uuid().as_bytes());
                }
            }
        }
        Ok(WorkCutRequestDigest(*hash.finalize().as_bytes()))
    }
}

fn hash_count(hash: &mut blake3::Hasher, count: usize) -> Result<(), WorkCutRequestError> {
    hash.update(
        &u32::try_from(count)
            .map_err(|_| WorkCutRequestError::Bounds)?
            .to_be_bytes(),
    );
    Ok(())
}
fn nonnil(id: Uuid) -> Result<(), WorkCutRequestError> {
    if id.is_nil() {
        Err(WorkCutRequestError::NilIdentity)
    } else {
        Ok(())
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCutGrant {
    issuer: OrchestrationIssuerId,
    digest: WorkCutRequestDigest,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
}
impl WorkCutGrant {
    pub fn new(
        issuer: OrchestrationIssuerId,
        digest: WorkCutRequestDigest,
        issued_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, WorkCutRequestError> {
        nonnil(issuer.into_uuid())?;
        if issued_at >= expires_at {
            return Err(WorkCutRequestError::InvalidWindow);
        }
        Ok(Self {
            issuer,
            digest,
            issued_at,
            expires_at,
        })
    }
    pub const fn issuer(self) -> OrchestrationIssuerId {
        self.issuer
    }
    pub const fn request_digest(self) -> WorkCutRequestDigest {
        self.digest
    }
    pub const fn issued_at(self) -> TimestampMillis {
        self.issued_at
    }
    pub const fn expires_at(self) -> TimestampMillis {
        self.expires_at
    }
    /// The caller must authenticate and authorize this issuer before calling.
    pub fn validate_for(
        self,
        authenticated_issuer: OrchestrationIssuerId,
        actual_request: WorkCutRequestDigest,
        observed_at: TimestampMillis,
    ) -> Result<(), WorkCutRequestError> {
        if self.issuer != authenticated_issuer {
            return Err(WorkCutRequestError::IssuerMismatch);
        }
        if self.digest != actual_request {
            return Err(WorkCutRequestError::RequestMismatch);
        }
        if observed_at < self.issued_at {
            return Err(WorkCutRequestError::NotYetValid);
        }
        if observed_at >= self.expires_at {
            return Err(WorkCutRequestError::Expired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WorkCutRequestError {
    #[error("work-cut identity is nil")]
    NilIdentity,
    #[error("work-cut roster bounds exceeded")]
    Bounds,
    #[error("work-cut identity is duplicated")]
    Duplicate,
    #[error("work-cut logical parties must be distinct")]
    SameParty,
    #[error("work-cut witness is invalid")]
    InvalidWitness,
    #[error("work-cut binding lacks its exact side/session witness")]
    MissingSession,
    #[error("one work-cut Session has conflicting principals")]
    PrincipalMismatch,
    #[error("work-cut grant window is invalid")]
    InvalidWindow,
    #[error("work-cut issuer mismatch")]
    IssuerMismatch,
    #[error("work-cut request digest mismatch")]
    RequestMismatch,
    #[error("work-cut grant is not yet valid")]
    NotYetValid,
    #[error("work-cut grant expired")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn fixture() -> Result<WorkCutRequest> {
        let sessions = vec![
            WorkCutSession::new(
                WorkCutSide::Incumbent,
                AgentSessionId::from_uuid(Uuid::from_u128(21)),
            )?,
            WorkCutSession::new(
                WorkCutSide::Elected,
                AgentSessionId::from_uuid(Uuid::from_u128(22)),
            )?,
        ];
        let bindings = sessions
            .iter()
            .enumerate()
            .map(|(i, s)| {
                WorkCutBinding::new(
                    s.side,
                    ActivityId::from_uuid(Uuid::from_u128(41)),
                    AgentInstanceId::from_uuid(Uuid::from_u128(if i == 0 { 31 } else { 32 })),
                    s.session_id,
                    AuthenticatedPrincipal::TrustedStdio,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let zero_time = TimestampMillis::new(0)?;
        let nodes = [61, 62]
            .map(|id| {
                WorkCutNodeScope::new(
                    ActivityId::from_uuid(Uuid::from_u128(41)),
                    GoalId::from_uuid(Uuid::from_u128(51)),
                    zero_time,
                    GoalRevision::INITIAL,
                    DagRevisionNumber::INITIAL,
                    DagNodeId::from_uuid(Uuid::from_u128(id)),
                )
            })
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(WorkCutRequest::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            ForgeBackendId::from_uuid(Uuid::from_u128(4)),
            WorkspaceId::from_uuid(Uuid::from_u128(5)),
            WorkspaceRevision::INITIAL,
            1,
            [7; 32],
            [
                WorkCutParty::new(Uuid::from_u128(11), Uuid::from_u128(12))?,
                WorkCutParty::new(Uuid::from_u128(13), Uuid::from_u128(14))?,
            ],
            sessions,
            bindings,
            WorkCutScope::Team {
                team_id: Uuid::from_u128(42),
                nodes,
            },
        )?)
    }
    fn rebuild(r: WorkCutRequest) -> std::result::Result<WorkCutRequest, WorkCutRequestError> {
        WorkCutRequest::new(
            r.cut_id,
            r.election_id,
            r.destination_id,
            r.backend_id,
            r.workspace_id,
            r.workspace_revision,
            r.leadership_revision,
            r.roster_digest,
            r.parties,
            r.sessions,
            r.bindings,
            r.scope,
        )
    }

    #[test]
    fn manifest_rejects_ambiguous_missing_and_excessive_identity() -> Result<()> {
        let original = fixture()?;
        let mut r = original.clone();
        r.sessions.push(r.sessions[0]);
        assert_eq!(rebuild(r), Err(WorkCutRequestError::Duplicate));
        let mut r = original.clone();
        let _removed = r.sessions.remove(0);
        assert_eq!(rebuild(r), Err(WorkCutRequestError::MissingSession));
        let mut r = original.clone();
        r.sessions = vec![r.sessions[0]; MAX_WORK_CUT_SESSIONS + 1];
        assert_eq!(rebuild(r), Err(WorkCutRequestError::Bounds));
        let mut r = original.clone();
        r.parties[1] = r.parties[0];
        assert_eq!(rebuild(r), Err(WorkCutRequestError::SameParty));
        let mut r = original.clone();
        r.bindings[1].side = WorkCutSide::Incumbent;
        assert_eq!(rebuild(r), Err(WorkCutRequestError::MissingSession));
        let mut r = original.clone();
        r.bindings[1].agent_id = r.bindings[0].agent_id;
        assert_eq!(rebuild(r), Err(WorkCutRequestError::Duplicate));
        let mut r = original.clone();
        let mut binding = r.bindings[0];
        binding.activity_id = ActivityId::from_uuid(Uuid::from_u128(44));
        binding.agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(34));
        binding.principal = AuthenticatedPrincipal::DirectToken(crate::DirectTokenId::from_uuid(
            Uuid::from_u128(35),
        ));
        r.bindings.push(binding);
        assert_eq!(rebuild(r), Err(WorkCutRequestError::PrincipalMismatch));
        let mut r = original.clone();
        if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
            nodes.push(nodes[0]);
        }
        assert_eq!(rebuild(r), Err(WorkCutRequestError::Duplicate));
        let mut r = original.clone();
        if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
            *nodes = vec![nodes[0]; MAX_WORK_CUT_TEAM_NODES + 1];
        }
        assert_eq!(rebuild(r), Err(WorkCutRequestError::Bounds));
        assert_eq!(
            WorkCutParty::new(Uuid::nil(), Uuid::from_u128(1)),
            Err(WorkCutRequestError::NilIdentity)
        );
        let mut permuted = original.clone();
        permuted.sessions.reverse();
        permuted.bindings.reverse();
        if let WorkCutScope::Team { nodes, .. } = &mut permuted.scope {
            nodes.reverse();
        }
        assert_eq!(rebuild(permuted)?, original);
        let mut cross_activity = original.clone();
        if let WorkCutScope::Team { nodes, .. } = &mut cross_activity.scope {
            nodes[1].activity_id = ActivityId::from_uuid(Uuid::from_u128(99));
        }
        assert_ne!(
            rebuild(cross_activity)?.request_digest(),
            original.request_digest()
        );

        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive substitution regression keeps every digest identity field together"
    )]
    fn request_digest_fences_every_semantic_field() -> Result<()> {
        let original = fixture()?;
        macro_rules! fence {
            ($label:literal, $item:ident, $edit:block) => {{
                let mut $item = original.clone();
                $edit
                assert_ne!($item.compute_digest()?, original.request_digest(), "{} omitted from digest", $label);
            }};
        }
        fence!("cut", r, {
            r.cut_id = Uuid::from_u128(101);
        });
        fence!("election", r, {
            r.election_id = Uuid::from_u128(102);
        });
        fence!("destination", r, {
            r.destination_id = Uuid::from_u128(103);
        });
        fence!("backend", r, {
            r.backend_id = ForgeBackendId::from_uuid(Uuid::from_u128(104));
        });
        fence!("workspace", r, {
            r.workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(105));
        });
        fence!("workspace revision", r, {
            r.workspace_revision = WorkspaceRevision::new(2)?;
        });
        fence!("leadership revision", r, {
            r.leadership_revision = 2;
        });
        fence!("roster digest", r, {
            r.roster_digest = [8; 32];
        });
        fence!("incumbent participation", r, {
            r.parties[0].participation_id = Uuid::from_u128(106);
        });
        fence!("incumbent profile", r, {
            r.parties[0].profile_id = Uuid::from_u128(107);
        });
        fence!("elected participation", r, {
            r.parties[1].participation_id = Uuid::from_u128(108);
        });
        fence!("elected profile", r, {
            r.parties[1].profile_id = Uuid::from_u128(109);
        });
        fence!("session identity", r, {
            r.sessions[0].session_id = AgentSessionId::from_uuid(Uuid::from_u128(110));
        });
        fence!("session side", r, {
            r.sessions[0].side = WorkCutSide::Elected;
        });
        fence!("binding side", r, {
            r.bindings[0].side = WorkCutSide::Elected;
        });
        fence!("binding activity", r, {
            r.bindings[0].activity_id = ActivityId::from_uuid(Uuid::from_u128(111));
        });
        fence!("binding agent", r, {
            r.bindings[0].agent_id = AgentInstanceId::from_uuid(Uuid::from_u128(112));
        });
        fence!("binding session", r, {
            r.bindings[0].session_id = AgentSessionId::from_uuid(Uuid::from_u128(113));
        });
        fence!("principal", r, {
            r.bindings[0].principal = AuthenticatedPrincipal::DirectToken(
                crate::DirectTokenId::from_uuid(Uuid::from_u128(114)),
            );
        });
        fence!("scope kind", r, {
            r.scope = WorkCutScope::Workspace;
        });
        fence!("team", r, {
            if let WorkCutScope::Team { team_id, .. } = &mut r.scope {
                *team_id = Uuid::from_u128(116);
            }
        });
        fence!("node activity", r, {
            if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
                nodes[0].activity_id = ActivityId::from_uuid(Uuid::from_u128(119));
            }
        });
        fence!("node goal", r, {
            if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
                nodes[0].goal_id = GoalId::from_uuid(Uuid::from_u128(117));
            }
        });
        fence!("goal lifetime", r, {
            if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
                nodes[0].goal_created_at = TimestampMillis::new(1)?;
            }
        });
        fence!("DAG base", r, {
            if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
                nodes[0].dag_base_goal_revision = GoalRevision::new(2)?;
            }
        });
        fence!("dag revision", r, {
            if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
                nodes[0].dag_revision = DagRevisionNumber::new(2)?;
            }
        });
        fence!("node identity", r, {
            if let WorkCutScope::Team { nodes, .. } = &mut r.scope {
                nodes[0].node_id = DagNodeId::from_uuid(Uuid::from_u128(118));
            }
        });
        Ok(())
    }

    #[test]
    fn grant_checks_issuer_request_and_half_open_window() -> Result<()> {
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(71));
        let digest = fixture()?.request_digest();
        let grant = WorkCutGrant::new(
            issuer,
            digest,
            TimestampMillis::new(10)?,
            TimestampMillis::new(20)?,
        )?;
        assert!(
            grant
                .validate_for(issuer, digest, TimestampMillis::new(10)?)
                .is_ok()
        );
        assert!(
            grant
                .validate_for(issuer, digest, TimestampMillis::new(19)?)
                .is_ok()
        );
        assert_eq!(
            grant.validate_for(issuer, digest, TimestampMillis::new(9)?),
            Err(WorkCutRequestError::NotYetValid)
        );
        assert_eq!(
            grant.validate_for(issuer, digest, TimestampMillis::new(20)?),
            Err(WorkCutRequestError::Expired)
        );
        assert_eq!(
            grant.validate_for(
                OrchestrationIssuerId::from_uuid(Uuid::from_u128(72)),
                digest,
                TimestampMillis::new(15)?
            ),
            Err(WorkCutRequestError::IssuerMismatch)
        );
        assert_eq!(
            grant.validate_for(
                issuer,
                WorkCutRequestDigest::from_bytes([9; 32]),
                TimestampMillis::new(15)?
            ),
            Err(WorkCutRequestError::RequestMismatch)
        );
        assert_eq!(
            WorkCutGrant::new(
                issuer,
                digest,
                TimestampMillis::new(20)?,
                TimestampMillis::new(20)?
            ),
            Err(WorkCutRequestError::InvalidWindow)
        );
        Ok(())
    }
}
