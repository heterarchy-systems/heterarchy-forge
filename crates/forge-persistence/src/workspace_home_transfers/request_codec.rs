//! Canonical bounded request storage without changing the checked domain type.
use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, DirectTokenId,
    ForgeBackendId, HomeTransferSourceBinding, HomeTransferSourceRequest, HomeTransferSourceScope,
    HomeTransferSourceSubject, HomeTransferSourceWitness, MAX_HOME_TRANSFER_SOURCE_BINDINGS,
    MAX_HOME_TRANSFER_SOURCE_SESSIONS, OAuthGrantId, WorkspaceId, WorkspaceRevision,
};
use uuid::Uuid;

use super::{HomeTransferStoreError as Error, schema};

const MAGIC: &[u8; 5] = b"FHTR\x01";

pub(super) fn encode(request: &HomeTransferSourceRequest) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    let witness = request.witness();
    out.extend_from_slice(witness.preparation_id().as_bytes());
    out.extend_from_slice(witness.intent_digest());
    out.extend_from_slice(witness.preparation_digest());
    let scope = request.scope();
    out.extend_from_slice(scope.workspace_id().into_uuid().as_bytes());
    out.extend_from_slice(&scope.workspace_revision().get().to_be_bytes());
    out.extend_from_slice(scope.backend_id().into_uuid().as_bytes());
    out.extend_from_slice(scope.destination_id().as_bytes());
    let subject = request.subject();
    out.extend_from_slice(subject.transfer_id().as_bytes());
    out.extend_from_slice(&subject.transfer_generation().to_be_bytes());
    for id in [
        subject.target_profile_id(),
        subject.target_participation_id(),
        subject.source_team_id(),
        subject.destination_team_id(),
    ] {
        out.extend_from_slice(id.as_bytes());
    }
    out.extend_from_slice(&subject.source_membership_revision().to_be_bytes());
    out.extend_from_slice(&subject.participation_revision().to_be_bytes());
    count(&mut out, request.sessions().len())?;
    for session in request.sessions() {
        out.extend_from_slice(session.into_uuid().as_bytes());
    }
    count(&mut out, request.bindings().len())?;
    for binding in request.bindings() {
        out.extend_from_slice(binding.activity_id().into_uuid().as_bytes());
        out.extend_from_slice(binding.agent_id().into_uuid().as_bytes());
        out.extend_from_slice(binding.session_id().into_uuid().as_bytes());
        match binding.principal() {
            AuthenticatedPrincipal::TrustedStdio => out.push(0),
            AuthenticatedPrincipal::DirectToken(id) => {
                out.push(1);
                out.extend_from_slice(id.into_uuid().as_bytes());
            }
            AuthenticatedPrincipal::OAuthGrant(id) => {
                out.push(2);
                out.extend_from_slice(id.into_uuid().as_bytes());
            }
        }
    }
    if out.len() > schema::MAX_REQUEST_BYTES {
        return Err(Error::Bounds("Home source request bytes"));
    }
    Ok(out)
}

fn count(out: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    out.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| Error::Bounds("Home source request count"))?
            .to_be_bytes(),
    );
    Ok(())
}

pub(super) fn decode(bytes: &[u8]) -> Result<HomeTransferSourceRequest, Error> {
    if bytes.len() > schema::MAX_REQUEST_BYTES {
        return Err(Error::Bounds("Home source request bytes"));
    }
    let mut r = Reader { bytes, position: 0 };
    if r.fixed::<5>()? != *MAGIC {
        return Err(Error::Corrupt("Home source request version"));
    }
    let witness = HomeTransferSourceWitness::new(r.id()?, r.fixed()?, r.fixed()?)?;
    let workspace = WorkspaceId::from_uuid(r.id()?);
    let revision = WorkspaceRevision::new(i64::from_be_bytes(r.fixed()?))
        .map_err(|_| Error::Corrupt("Home source Workspace revision"))?;
    let scope = HomeTransferSourceScope::new(
        workspace,
        revision,
        ForgeBackendId::from_uuid(r.id()?),
        r.id()?,
    )?;
    let subject = HomeTransferSourceSubject::new(
        r.id()?,
        u64::from_be_bytes(r.fixed()?),
        r.id()?,
        r.id()?,
        r.id()?,
        r.id()?,
        u64::from_be_bytes(r.fixed()?),
        u64::from_be_bytes(r.fixed()?),
    )?;
    let sessions_len = r.count(MAX_HOME_TRANSFER_SOURCE_SESSIONS)?;
    let mut sessions = Vec::with_capacity(sessions_len);
    for _ in 0..sessions_len {
        sessions.push(AgentSessionId::from_uuid(r.id()?));
    }
    let bindings_len = r.count(MAX_HOME_TRANSFER_SOURCE_BINDINGS)?;
    let mut bindings = Vec::with_capacity(bindings_len);
    for _ in 0..bindings_len {
        let activity = ActivityId::from_uuid(r.id()?);
        let agent = AgentInstanceId::from_uuid(r.id()?);
        let session = AgentSessionId::from_uuid(r.id()?);
        let principal = match r.fixed::<1>()?[0] {
            0 => AuthenticatedPrincipal::TrustedStdio,
            1 => AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(r.id()?)),
            2 => AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(r.id()?)),
            _ => return Err(Error::Corrupt("Home source principal tag")),
        };
        bindings.push(HomeTransferSourceBinding::new(
            activity, agent, session, principal,
        )?);
    }
    let request = HomeTransferSourceRequest::new(witness, scope, subject, sessions, bindings)?;
    if r.position != bytes.len() || encode(&request)? != bytes {
        return Err(Error::Corrupt("Home source canonical request"));
    }
    Ok(request)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Reader<'_> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(Error::Corrupt("Home source request size"))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::Corrupt("truncated Home source request"))?;
        self.position = end;
        slice
            .try_into()
            .map_err(|_| Error::Corrupt("Home source request width"))
    }
    fn id(&mut self) -> Result<Uuid, Error> {
        Ok(Uuid::from_bytes(self.fixed()?))
    }
    fn count(&mut self, max: usize) -> Result<usize, Error> {
        let value = usize::from(u16::from_be_bytes(self.fixed()?));
        if value > max {
            return Err(Error::Bounds("Home source request count"));
        }
        Ok(value)
    }
}
