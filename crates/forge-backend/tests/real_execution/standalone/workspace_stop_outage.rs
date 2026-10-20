//! Real remote-provider outage proof for the administrative stop owner.

use super::*;
use forge_control::{WorkspaceStopIntent, WorkspaceStopServiceIdentity};
use forge_domain::{ForgeBackendId, OrchestrationIssuerId, RuntimeInstanceId};
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;

pub(super) async fn assert_unavailable_stop_owner(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, capability) =
        super::super::registry_ops::get_unauthenticated(address, "/api/v1/capability").await?;
    assert_eq!(status, 200);
    let boot = Uuid::parse_str(
        capability["runtime_instance"]
            .as_str()
            .ok_or("backend boot missing")?,
    )?;
    assert_ne!(boot, fixture.runtime_instance_id.into_uuid());
    let destination = delegated_destination_id(fixture)?;
    let stop_id = Uuid::now_v7();
    let request_id = Uuid::now_v7();
    let pending =
        super::super::approved_owner::raw_pending_shell(fixture, "printf 'outage-pending\\n'")?;
    let unused =
        super::super::approved_owner::raw_approved_shell(fixture, "printf 'outage-unused\\n'")?;
    let auto_scope = super::super::approved_owner::raw_auto_scope(fixture, timestamp_now()?)?;
    let before =
        super::super::approved_owner::authority_snapshot(fixture, &pending, &unused, &auto_scope)?;
    let payload = json!({
        "scope": super::super::lease_readback::scope_json(fixture),
        "stop_id": stop_id, "durable_request_id": request_id,
        "service": {"backend_id":BACKEND_ID,"issuer":ISSUER_ID,"destination_id":destination,"runtime_instance_id":boot},
        "actor": {"session_id":fixture.session_id.into_uuid(),"principal":{"kind":"trusted_stdio"}},
    });
    for operation in ["execution.stop_workspace", "execution.stop_workspace_get"] {
        let (status, reply) = post_command(address, operation, payload.clone()).await?;
        assert_eq!(status, 503, "{operation}: {reply}");
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "DEPENDENCY_UNAVAILABLE");
        assert_eq!(reply["error"]["retryable"], true);
        assert_eq!(reply["error"]["recovery_action"], "retry_when_available");
        assert_eq!(reply["error"]["readback"], Value::Null);
    }
    let service = WorkspaceStopServiceIdentity::new(
        ForgeBackendId::from_uuid(BACKEND_ID),
        OrchestrationIssuerId::from_uuid(ISSUER_ID),
        destination,
        RuntimeInstanceId::from_uuid(boot),
    )?;
    let intent = WorkspaceStopIntent::new(
        fixture.scope.clone(),
        stop_id,
        request_id,
        service,
        fixture.session_id,
        AuthenticatedPrincipal::TrustedStdio,
    )?;
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("original layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    assert!(
        store
            .owned_workspace_stop_for_request(&intent.execution_request(timestamp_now()?))?
            .is_none()
    );
    let after =
        super::super::approved_owner::authority_snapshot(fixture, &pending, &unused, &auto_scope)?;
    assert_eq!(after, before);
    // The parent catalog and native provider still resolve the same live session;
    // the child backend must not use either as a replacement for its remote owner.
    assert_eq!(
        resolve_live_session(fixture).await?.id(),
        fixture.session_id
    );
    Ok(())
}
