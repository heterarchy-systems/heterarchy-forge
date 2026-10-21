//! Actual admitted Work Cut reply-loss and durable readback coverage.

use super::super::binding_lifecycle::{
    HeldResponse, HttpBindingFixture, open_command_without_read,
};
use super::*;
use forge_domain::{AuthenticatedPrincipal, OpenAgentSession};
use serde_json::{Value, json};
use std::time::Duration;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_work_cut_prepare_reply_loss_reads_original_record_before_replay()
-> Result<(), Box<dyn std::error::Error>> {
    for disconnect in [false, true] {
        let (running, held, admitted) =
            HttpBindingFixture::start_holding_first_reply(Some(Duration::from_millis(100))).await?;
        let result = exercise_reply_loss(&running, &held, admitted, disconnect).await;
        let finish = running.finish().await;
        result?;
        finish?;
    }
    Ok(())
}

async fn exercise_reply_loss(
    running: &HttpBindingFixture,
    held: &HeldResponse,
    admitted: tokio::sync::oneshot::Receiver<()>,
    disconnect: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = async {
        let destination = delegated_destination_id(&running.fixture)?;
        let elected = forge_domain::AgentSessionId::from_uuid(Uuid::now_v7());
        let _opened = running
            .fixture
            .client
            .agent_session_open(OpenAgentSession::new(
                elected,
                forge_domain::AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
                AuthenticatedPrincipal::TrustedStdio,
                timestamp_now()?,
            ))?;
        let request = super::cut_request(&running.fixture, destination, elected, Uuid::now_v7())?;
        let now = timestamp_now()?;
        let prepare = valid_prepare(&running.fixture, destination, &request, now)?;
        let mut stream =
            open_command_without_read(running.address, "work_cut.prepare", prepare.clone()).await?;
        tokio::time::timeout(Duration::from_secs(5), admitted).await??;

        if disconnect {
            drop(stream);
        } else {
            let raw = tokio::time::timeout(
                Duration::from_secs(5),
                super::super::read_response_bounded(&mut stream),
            )
            .await??;
            let text = String::from_utf8(raw)?;
            let body: Value =
                serde_json::from_str(text.split_once("\r\n\r\n").ok_or("body missing")?.1)?;
            assert_eq!(body["error"]["code"], "UNKNOWN_OUTCOME", "{body}");
            assert_eq!(body["error"]["readback"]["cut_id"], json!(request.cut_id()));
            assert_eq!(
                body["error"]["readback"]["request_digest"],
                forge_backend::events::hex_encode(request.request_digest().as_bytes())
            );
            drop(stream);
        }

        Ok::<_, Box<dyn std::error::Error>>((request, prepare, destination))
    }
    .await;
    let released = held.release_and_wait().await;
    let (request, prepare, destination) = observed?;
    released?;
    assert_durable_before_replay(running, &request, prepare, destination).await
}

async fn assert_durable_before_replay(
    running: &HttpBindingFixture,
    request: &forge_domain::WorkCutRequest,
    prepare: Value,
    destination: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let control_read =
        running
            .fixture
            .client
            .leadership_work_cut(forge_control::WorkCutCommand {
                scope: running.fixture.scope.clone(),
                service: forge_control::WorkCutService {
                    issuer: forge_domain::OrchestrationIssuerId::from_uuid(ISSUER_ID),
                    backend_id: forge_domain::ForgeBackendId::from_uuid(BACKEND_ID),
                    destination_id: destination,
                },
                operation: forge_control::WorkCutOperation::Get {
                    cut_id: request.cut_id(),
                    request_digest: request.request_digest(),
                },
            })?;
    let forge_control::WorkCutResponse::Record(Some(original)) = control_read else {
        return Err("admitted Work Cut receipt was not readable after reply loss".into());
    };
    assert_eq!(original.request().cut_id(), request.cut_id());
    assert_eq!(
        original.request().request_digest(),
        request.request_digest()
    );

    let mut get = super::base_payload(&running.fixture, destination);
    get["cut_id"] = json!(request.cut_id());
    get["request_digest"] = json!(forge_backend::events::hex_encode(
        request.request_digest().as_bytes()
    ));
    let (get_status, history) = post_command(running.address, "work_cut.get", get).await?;
    if get_status == 200 {
        assert_eq!(history["result"]["found"], true);
        assert_eq!(
            history["result"]["record"]["request"]["request_digest"],
            forge_backend::events::hex_encode(request.request_digest().as_bytes())
        );
    } else {
        assert_eq!(get_status, 202, "{history}");
        assert_eq!(history["error"]["code"], "UNKNOWN_OUTCOME");
    }

    let (replay_status, replay) =
        post_command(running.address, "work_cut.prepare", prepare).await?;
    if replay_status == 200 {
        assert_eq!(replay["result"]["status"], "existing");
        if get_status == 200 {
            assert_eq!(
                replay["result"]["record"]["snapshot_digest"],
                history["result"]["record"]["snapshot_digest"]
            );
        }
    } else {
        assert_eq!(replay_status, 202, "{replay}");
        assert_eq!(replay["error"]["code"], "UNKNOWN_OUTCOME");
        assert_eq!(
            replay["error"]["readback"]["cut_id"],
            json!(request.cut_id())
        );
        assert_eq!(
            replay["error"]["readback"]["request_digest"],
            forge_backend::events::hex_encode(request.request_digest().as_bytes())
        );
    }

    Ok(())
}

fn valid_prepare(
    fixture: &Fixture,
    destination: Uuid,
    request: &forge_domain::WorkCutRequest,
    now: forge_domain::TimestampMillis,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut payload = super::base_payload(fixture, destination);
    payload["request"] = super::request_json(request);
    payload["grant"] = json!({
        "issuer": ISSUER_ID,
        "request_digest": forge_backend::events::hex_encode(request.request_digest().as_bytes()),
        "issued_at_ms": now.get(),
        "expires_at_ms": super::add_millis(now, 60_000)?.get(),
    });
    Ok(payload)
}
