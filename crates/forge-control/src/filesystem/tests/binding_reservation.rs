use super::*;
use crate::{AgentBindingReserveRequest, WriterLeaseAcquireRequest};
use forge_domain::{
    AcquireWriterLease, AgentSessionId, AgentSessionOpenRequestId, AuthenticatedPrincipal,
    OpenAgentSession, WriterLeaseDurationMillis, WriterLeaseId,
};
use forge_persistence::{
    AgentBindingReservationRequest, AgentOperationsFreezeRequest, AgentSessionCatalog,
};

#[test]
fn reserved_binding_cannot_acquire_effect_authority_and_rechecks_closed_session()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("binding-reservation")?;
    let principal = AuthenticatedPrincipal::TrustedStdio;
    let session = fixture.control.agent_session_open(&OpenAgentSession::new(
        AgentSessionId::from_uuid(id(0xBC01)),
        AgentSessionOpenRequestId::from_uuid(id(0xBC02)),
        principal,
        timestamp(15)?,
    ))?;
    let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
        .ok_or("layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(0xBC03),
        id(0xBC04),
        timestamp(20)?,
    )?)?;
    let request = AgentBindingReserveRequest {
        scope: fixture.scope.clone(),
        freeze,
        reservation: AgentBindingReservationRequest::new(
            id(0xBC05),
            fixture.activity.activity_id,
            forge_domain::AgentInstanceId::from_uuid(id(0xBC06)),
            session.session().id(),
            principal,
            timestamp(21)?,
        )?,
        observed_at: timestamp(22)?,
    };
    let reservation = fixture.control.reserve_agent_binding(&request)?;
    assert_eq!(
        fixture.control.reserve_agent_binding(&request)?,
        reservation
    );
    assert!(store.get_agent(request.reservation.agent_id())?.is_none());
    let scope = store
        .get_writer_lease(fixture.write_authority.writer_lease_id())?
        .ok_or("seed lease missing")?
        .scope()
        .clone();
    let lease = WriterLeaseAcquireRequest {
        scope: fixture.scope.clone(),
        activity_id: fixture.activity.activity_id,
        agent_id: request.reservation.agent_id(),
        principal,
        command: AcquireWriterLease::new(
            WriterLeaseId::from_uuid(id(0xBC07)),
            fixture.scope.workspace_id(),
            fixture.activity.activity_id,
            request.reservation.agent_id(),
            scope,
            WriterLeaseDurationMillis::new(1000)?,
            timestamp(22)?,
            session.session().id(),
            principal,
        )?,
    };
    assert_eq!(
        fixture
            .control
            .writer_lease_acquire(&lease)
            .err()
            .map(|e| e.code()),
        Some(ControlErrorCode::AgentNotFound)
    );
    let mut sessions = AgentSessionCatalog::open(fixture.root.join("agent-sessions.sqlite3"))?;
    let _closed = sessions.close(
        session.session().id(),
        principal,
        session.session().revision(),
        timestamp(23)?,
    )?;
    assert_eq!(
        fixture
            .control
            .reserve_agent_binding(&request)
            .err()
            .map(|e| e.code()),
        Some(ControlErrorCode::AgentSessionClosed)
    );
    assert_eq!(
        store.agent_binding_reservation(request.reservation.request_id())?,
        Some(reservation)
    );
    assert!(store.get_agent(request.reservation.agent_id())?.is_none());
    drop(sessions);
    drop(store);
    drop(fixture.control);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
