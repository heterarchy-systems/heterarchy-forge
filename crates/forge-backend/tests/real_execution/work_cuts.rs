//! Actual application-owned custody fence, source admission and lease drain.

use super::lease_readback::{path_token, post_ok, scope_json};
use super::*;
use forge_domain::{
    WorkCutBinding, WorkCutParty, WorkCutRequest, WorkCutScope, WorkCutSession, WorkCutSide,
    WorkspaceRevision,
};

mod work_cut_negatives;
mod work_cut_reply_loss;

pub(super) fn cut_request(
    fixture: &Fixture,
    destination: Uuid,
    elected: forge_domain::AgentSessionId,
    cut_id: Uuid,
) -> Result<WorkCutRequest, Box<dyn std::error::Error>> {
    Ok(WorkCutRequest::new(
        cut_id,
        Uuid::now_v7(),
        destination,
        forge_domain::ForgeBackendId::from_uuid(BACKEND_ID),
        fixture.scope.workspace_id(),
        WorkspaceRevision::new(fixture.scope.workspace_revision().get())?,
        1,
        [0xC1; 32],
        [
            WorkCutParty::new(Uuid::now_v7(), Uuid::now_v7())?,
            WorkCutParty::new(Uuid::now_v7(), Uuid::now_v7())?,
        ],
        vec![
            WorkCutSession::new(WorkCutSide::Incumbent, fixture.session_id)?,
            WorkCutSession::new(WorkCutSide::Elected, elected)?,
        ],
        vec![WorkCutBinding::new(
            WorkCutSide::Incumbent,
            fixture.activity_id,
            fixture.agent_id,
            fixture.session_id,
            forge_domain::AuthenticatedPrincipal::TrustedStdio,
        )?],
        WorkCutScope::Workspace,
    )?)
}

pub(super) fn request_json(request: &WorkCutRequest) -> Value {
    json!({"cut_id":request.cut_id(),"election_id":request.election_id(),"destination_id":request.destination_id(),
        "backend_id":request.backend_id().into_uuid(),"workspace_id":request.workspace_id().into_uuid(),
        "workspace_revision":request.workspace_revision().get(),"leadership_revision":request.leadership_revision(),
        "roster_digest":forge_backend::events::hex_encode(request.roster_digest()),
        "parties":{"incumbent":{"participation_id":request.parties()[0].participation_id(),"profile_id":request.parties()[0].profile_id()},
            "elected":{"participation_id":request.parties()[1].participation_id(),"profile_id":request.parties()[1].profile_id()}},
        "sessions":request.sessions().iter().map(|session|json!({"side":side(session.side()),"session_id":session.session_id().into_uuid()})).collect::<Vec<_>>(),
        "bindings":request.bindings().iter().map(|binding|json!({"side":side(binding.side()),"activity_id":binding.activity_id().into_uuid(),
            "agent_id":binding.agent_id().into_uuid(),"session_id":binding.session_id().into_uuid(),"principal":{"kind":"trusted_stdio"}})).collect::<Vec<_>>(),
        "scope":{"kind":"workspace"}})
}

fn side(value: WorkCutSide) -> &'static str {
    match value {
        WorkCutSide::Incumbent => "incumbent",
        WorkCutSide::Elected => "elected",
    }
}

pub(super) fn base_payload(fixture: &Fixture, destination: Uuid) -> Value {
    json!({"scope":scope_json(fixture),"service":{"backend_id":BACKEND_ID,"issuer":ISSUER_ID,"destination_id":destination}})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_cut_blocks_new_source_preserves_old_readback_and_observes_actual_lease_release()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let destination = delegated_destination_id(&fixture)?;
    let elected = forge_domain::AgentSessionId::from_uuid(Uuid::now_v7());
    let _session = fixture
        .client
        .agent_session_open(forge_domain::OpenAgentSession::new(
            elected,
            forge_domain::AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
            forge_domain::AuthenticatedPrincipal::TrustedStdio,
            timestamp_now()?,
        ))?;
    let cache = fixture.root.join("cut-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(backend_config()?, &fixture, &cache, destination)?;
    let address = serve(state.clone()).await?;
    let result = run_cut_flow(&fixture, address, destination, elected).await;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let cleanup = fixture.shutdown();
    result?;
    assert!(shutdown.is_successful());
    cleanup?;
    Ok(())
}

async fn run_cut_flow(
    fixture: &Fixture,
    address: SocketAddr,
    destination: Uuid,
    elected: forge_domain::AgentSessionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let lease_id = Uuid::now_v7();
    let actor = json!({"session_id":fixture.session_id.into_uuid(),"principal":{"kind":"trusted_stdio"},"agent_id":fixture.agent_id.into_uuid()});
    let lease=post_ok(address,"writer_lease.acquire",json!({"scope":scope_json(fixture),"activity_id":fixture.activity_id.into_uuid(),
        "actor":actor,"writer_lease_id":lease_id,"duration_ms":60_000,"scopes":[{"kind":"exact_path","path_base64":path_token("cut-source.rs")},
            {"kind":"exact_path","path_base64":path_token("cut-new.rs")}]})).await?;
    let lease_revision = lease["revision"].as_i64().ok_or("lease revision missing")?;
    let mut source =
        super::source_writes::source_authority_payload(fixture, lease_id, lease_revision)?;
    source["change_set_id"] = json!(Uuid::now_v7());
    source["mutation_id"] = json!(Uuid::now_v7());
    source["operation"] =
        json!({"kind":"add","path_base64":path_token("cut-source.rs"),"content":"before cut\n"});
    let old = post_ok(address, "file.apply_patch", source.clone()).await?;
    let request = cut_request(fixture, destination, elected, Uuid::now_v7())?;
    let mut prepare = base_payload(fixture, destination);
    prepare["request"] = request_json(&request);
    let now = timestamp_now()?;
    prepare["grant"] = json!({"issuer":ISSUER_ID,"request_digest":forge_backend::events::hex_encode(request.request_digest().as_bytes()),
        "issued_at_ms":now.get(),"expires_at_ms":add_millis(now,60_000)?.get()});
    let mut inventory = prepare.clone();
    inventory
        .as_object_mut()
        .ok_or("inventory payload missing")?
        .remove("grant");
    let inventory = post_ok(address, "work_cut.inventory", inventory).await?;
    assert_eq!(
        inventory["inventory"]["agents"]
            .as_array()
            .ok_or("inventory agents missing")?
            .len(),
        1
    );
    let prepared = post_ok(address, "work_cut.prepare", prepare.clone()).await?;
    let mut read = base_payload(fixture, destination);
    read["cut_id"] = json!(request.cut_id());
    read["request_digest"] = json!(forge_backend::events::hex_encode(
        request.request_digest().as_bytes()
    ));
    let history = post_ok(address, "work_cut.get", read.clone()).await?;
    assert_eq!(
        history["record"]["snapshot_digest"],
        prepared["record"]["snapshot_digest"]
    );
    let source_history=post_ok(address,"file.mutation_readback",json!({"scope":scope_json(fixture),
        "activity_id":fixture.activity_id.into_uuid(),"change_set_id":old["change_set_id"],"mutation_id":old["mutation_id"]})).await?;
    assert_eq!(source_history["found"], true);
    assert_eq!(source_history["change_set_state"], "applied");
    source["change_set_id"] = json!(Uuid::now_v7());
    source["mutation_id"] = json!(Uuid::now_v7());
    source["operation"] =
        json!({"kind":"add","path_base64":path_token("cut-new.rs"),"content":"must stay absent\n"});
    let (status, blocked) = post_command(address, "file.apply_patch", source).await?;
    assert_ne!(status, 200, "new source crossed cut: {blocked}");
    assert_eq!(blocked["error"]["code"], "SOURCE_CONFLICT");
    assert!(!fixture.workspace_root.join("cut-new.rs").exists());
    assert_eq!(
        fs::read_to_string(fixture.workspace_root.join("cut-source.rs"))?,
        "before cut\n"
    );
    read["expected_revision"] = json!(1);
    let pending = post_ok(address, "work_cut.drain", read.clone()).await?;
    assert_eq!(pending["effects_drained"], false);
    let released = post_ok(
        address,
        "writer_lease.release",
        json!({"scope":scope_json(fixture),"activity_id":fixture.activity_id.into_uuid(),
        "actor":actor,"writer_lease_id":lease_id,"expected_revision":lease_revision}),
    )
    .await?;
    assert_eq!(released["state"], "released");
    let drained = post_ok(address, "work_cut.drain", read).await?;
    assert_eq!(drained["effects_drained"], true);
    let replay = post_ok(address, "work_cut.prepare", prepare).await?;
    assert_eq!(
        replay["record"]["snapshot_digest"],
        prepared["record"]["snapshot_digest"]
    );
    assert_eq!(old["status"], "applied");
    Ok(())
}
