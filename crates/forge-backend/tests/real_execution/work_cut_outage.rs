//! Remote-provider outage proof for immutable Work Cut history.

use super::*;
use forge_domain::{
    AgentSessionId, AgentSessionOpenRequestId, AuthenticatedPrincipal, OpenAgentSession,
    WorkCutRequest,
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(super) struct WorkCutOutageContext {
    original_prepare: Value,
    original_get: Value,
    original_request: WorkCutRequest,
    destination: Uuid,
    elected: AgentSessionId,
}

pub(super) async fn prepare_while_live(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<WorkCutOutageContext, Box<dyn std::error::Error>> {
    let destination = delegated_destination_id(fixture)?;
    let elected = AgentSessionId::from_uuid(Uuid::now_v7());
    let _elected_session = fixture.client.agent_session_open(OpenAgentSession::new(
        elected,
        AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp_now()?,
    ))?;
    let request = super::work_cuts::cut_request(fixture, destination, elected, Uuid::now_v7())?;
    let original_prepare = valid_prepare_payload(fixture, destination, &request)?;

    let mut inventory = original_prepare.clone();
    inventory
        .as_object_mut()
        .ok_or("Work Cut prepare payload is not an object")?
        .remove("grant");
    let inventory =
        super::lease_readback::post_ok(address, "work_cut.inventory", inventory).await?;
    assert_eq!(
        inventory["inventory"]["agents"]
            .as_array()
            .ok_or("Work Cut inventory agents missing")?
            .len(),
        1
    );

    let prepared =
        super::lease_readback::post_ok(address, "work_cut.prepare", original_prepare.clone())
            .await?;
    let original_get_payload = get_payload(fixture, destination, &request);
    let original_get =
        super::lease_readback::post_ok(address, "work_cut.get", original_get_payload).await?;
    assert_eq!(original_get["found"], true);
    assert_eq!(
        original_get["record"]["snapshot_digest"],
        prepared["record"]["snapshot_digest"]
    );

    Ok(WorkCutOutageContext {
        original_prepare,
        original_get,
        original_request: request,
        destination,
        elected,
    })
}

pub(super) async fn assert_after_provider_shutdown(
    address: SocketAddr,
    fixture: &Fixture,
    context: &WorkCutOutageContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut inventory = context.original_prepare.clone();
    inventory
        .as_object_mut()
        .ok_or("Work Cut prepare payload is not an object")?
        .remove("grant");
    let (status, failed_inventory) = post_command(address, "work_cut.inventory", inventory).await?;
    assert_dependency_unavailable(status, &failed_inventory, "work_cut.inventory");

    let (status, failed_prepare) = post_command(
        address,
        "work_cut.prepare",
        context.original_prepare.clone(),
    )
    .await?;
    assert_dependency_unavailable(status, &failed_prepare, "work_cut.prepare");

    let original_get = super::lease_readback::post_ok(
        address,
        "work_cut.get",
        get_payload(fixture, context.destination, &context.original_request),
    )
    .await?;
    assert_eq!(original_get, context.original_get);

    let fresh_request = super::work_cuts::cut_request(
        fixture,
        context.destination,
        context.elected,
        Uuid::now_v7(),
    )?;
    let fresh_prepare = valid_prepare_payload(fixture, context.destination, &fresh_request)?;
    let (status, failed_fresh_prepare) =
        post_command(address, "work_cut.prepare", fresh_prepare).await?;
    assert_dependency_unavailable(status, &failed_fresh_prepare, "work_cut.prepare (fresh)");

    let fresh_get = super::lease_readback::post_ok(
        address,
        "work_cut.get",
        get_payload(fixture, context.destination, &fresh_request),
    )
    .await?;
    assert_eq!(fresh_get["found"], false);
    Ok(())
}

fn valid_prepare_payload(
    fixture: &Fixture,
    destination: Uuid,
    request: &WorkCutRequest,
) -> Result<Value, Box<dyn std::error::Error>> {
    let now = timestamp_now()?;
    let mut payload = super::work_cuts::base_payload(fixture, destination);
    payload["request"] = super::work_cuts::request_json(request);
    payload["grant"] = json!({
        "issuer": ISSUER_ID,
        "request_digest": forge_backend::events::hex_encode(request.request_digest().as_bytes()),
        "issued_at_ms": now.get(),
        "expires_at_ms": add_millis(now, 60_000)?.get(),
    });
    Ok(payload)
}

fn get_payload(fixture: &Fixture, destination: Uuid, request: &WorkCutRequest) -> Value {
    let mut payload = super::work_cuts::base_payload(fixture, destination);
    payload["cut_id"] = json!(request.cut_id());
    payload["request_digest"] = json!(forge_backend::events::hex_encode(
        request.request_digest().as_bytes()
    ));
    payload
}

fn assert_dependency_unavailable(status: u16, response: &Value, operation: &str) {
    assert_eq!(status, 503, "{operation}: {response}");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "DEPENDENCY_UNAVAILABLE");
    assert_eq!(response["error"]["retryable"], true);
    assert_eq!(response["error"]["recovery_action"], "retry_when_available");
    assert_eq!(response["error"]["readback"], Value::Null);
}
