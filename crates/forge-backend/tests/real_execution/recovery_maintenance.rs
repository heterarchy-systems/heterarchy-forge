//! Real authenticated maintenance run/get and immutable historical replay.

use super::binding_lifecycle::open_command_without_read;
use super::lease_readback::scope_json;
use super::*;
use forge_domain::{
    BeginExecution, BootstrapActivity, ExecutionAttribution, ExecutionKind, ExecutionLimits,
    ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram, ExecutionTimeoutMillis,
};

fn seed_expired(
    fixture: &Fixture,
) -> Result<(forge_domain::ActivityId, forge_domain::ExecutionId), Box<dyn std::error::Error>> {
    let layout =
        WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?.ok_or("layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let activity = forge_domain::ActivityId::from_uuid(Uuid::now_v7());
    let execution = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
    let past = timestamp_now()?;
    let _activity = store.bootstrap_activity(&BootstrapActivity::new(
        activity,
        fixture.scope.workspace_id(),
        fixture.scope.workspace_revision(),
        forge_domain::RuntimeInstanceId::from_uuid(Uuid::now_v7()),
        add_millis(past, 1)?,
        past,
    ))?;
    let request = forge_domain::ExecutionRequest::new(
        ExecutionAttribution::new(execution, fixture.scope.workspace_id(), activity),
        ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
            arguments: Vec::new(),
        },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(1_000)?,
            ExecutionOutputLimit::new(16)?,
        ),
        ExecutionPermissions::new(false, false, false),
    )?;
    let _record = store.begin_execution(&BeginExecution::from_request(
        &request,
        forge_execution::execution_request_digest(&request),
        past,
    ))?;
    Ok((activity, execution))
}

fn payload(fixture: &Fixture, destination: Uuid, request_id: Uuid) -> Value {
    json!({"scope":scope_json(fixture),"request_id":request_id,
        "service":{"backend_id":BACKEND_ID,"issuer":ISSUER_ID,
            "destination_id":destination,"runtime_instance_id":fixture.runtime_instance_id.into_uuid()},
        "duration_ms":30_000,"activity_limit":100,"execution_limit":64})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_maintenance_rejects_caller_clock_owner_service_and_bounds_before_effects()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let destination = delegated_destination_id(&fixture)?;
    let cache = fixture.root.join("maintenance-auth-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(backend_config()?, &fixture, &cache, destination)?;
    let address = serve(state.clone()).await?;
    let request = payload(&fixture, destination, Uuid::now_v7());
    let result = async {
        let native=forge_control::RecoveryMaintenanceRequest::native(fixture.scope.clone(),Uuid::now_v7(),
            fixture.runtime_instance_id,forge_domain::RecoveryLeaseDurationMillis::new(30_000)?,timestamp_now()?,
            (forge_domain::ActivityListLimit::DEFAULT,forge_domain::ExecutionListLimit::DEFAULT))?;
        let native_report=fixture.client.run_recovery_maintenance(native.clone())?;
        let native_digest=forge_backend::events::hex_encode(&native.request_digest);
        let (status,native_history)=post_command(address,"recovery.maintenance.get",json!({
            "scope":scope_json(&fixture),"request_id":native.request_id,"request_digest":native_digest,
        })).await?;
        assert_eq!(status,200,"{native_history}");
        assert_eq!(native_history["result"]["receipt"]["receipt_digest"],
            forge_backend::events::hex_encode(native_report.receipt().ok_or("native receipt missing")?.receipt_digest()));
        for (field, value) in [
            ("claimed_at_ms", json!(i64::MAX)),
            ("owner_id", json!(Uuid::now_v7())),
            ("activity_limit", json!(1001)),
            ("execution_limit", json!(257)),
        ] {
            let mut changed = request.clone();
            changed[field] = value;
            let (status, response) =
                post_command(address, "recovery.maintenance.run", changed).await?;
            assert_ne!(status, 200, "{field}: {response}");
            assert_eq!(response["error"]["code"], "INVALID_INPUT");
        }
        let mut changed = request.clone();
        changed["service"]["backend_id"] = json!(Uuid::now_v7());
        let (status, response) = post_command(address, "recovery.maintenance.run", changed).await?;
        assert_ne!(status, 200, "{response}");
        assert_eq!(response["error"]["code"], "AUTH_FAILED");
        let lease = fixture
            .client
            .recovery_maintenance_lease(fixture.scope.clone())?;
        assert!(lease.is_released());
        assert_eq!(lease.epoch().get(), 1);
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("layout missing")?;
        let connection = rusqlite::Connection::open(layout.database_path())?;
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM recovery_runs", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        drop(connection);
        let mut maximum = request.clone();
        maximum["activity_limit"] = json!(1000);
        maximum["execution_limit"] = json!(256);
        let (status, accepted) = post_command(address, "recovery.maintenance.run", maximum).await?;
        assert_eq!(status, 200, "maximum supported limits rejected: {accepted}");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let cleanup = fixture.shutdown();
    result?;
    assert!(shutdown.is_successful());
    cleanup?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_maintenance_deadline_and_disconnect_preserve_exact_durable_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    use super::binding_lifecycle::HttpBindingFixture;
    for disconnect in [false, true] {
        let (running, held, admitted) =
            HttpBindingFixture::start_holding_first_reply(Some(Duration::from_millis(100))).await?;
        let destination = delegated_destination_id(&running.fixture)?;
        let request = payload(&running.fixture, destination, Uuid::now_v7());
        let result = async {
            let mut stream = open_command_without_read(
                running.address,
                "recovery.maintenance.run",
                request.clone(),
            )
            .await?;
            tokio::time::timeout(Duration::from_secs(5), admitted).await??;
            if disconnect {
                drop(stream);
            } else {
                let raw = tokio::time::timeout(
                    Duration::from_secs(5),
                    super::read_response_bounded(&mut stream),
                )
                .await??;
                let text = String::from_utf8(raw)?;
                let body: Value =
                    serde_json::from_str(text.split_once("\r\n\r\n").ok_or("body missing")?.1)?;
                assert_eq!(body["error"]["code"], "UNKNOWN_OUTCOME", "{body}");
                assert_eq!(
                    body["error"]["readback"]["request_id"],
                    request["request_id"]
                );
                drop(stream);
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let released = held.release_and_wait().await;
        let verify=async {
            let (status,replay)=post_command(running.address,"recovery.maintenance.run",request.clone()).await?;
            let digest=if status==200 {
                assert_eq!(replay["result"]["replayed"],true);
                replay["result"]["request_digest"].clone()
            } else {
                assert_eq!(status,202,"{replay}");assert_eq!(replay["error"]["code"],"UNKNOWN_OUTCOME");
                assert_eq!(replay["error"]["readback"]["request_id"],request["request_id"]);
                replay["error"]["readback"]["request_digest"].clone()
            };
            let get=json!({"scope":scope_json(&running.fixture),"request_id":request["request_id"],"request_digest":digest});
            let hex=digest.as_str().ok_or("readback digest missing")?;
            if hex.len()!=64 {return Err("readback digest length".into());}
            let decoded=(0..64).step_by(2).map(|index|u8::from_str_radix(&hex[index..index+2],16)).collect::<Result<Vec<_>,_>>()?;
            let original_digest:[u8;32]=decoded.try_into().map_err(|_|"digest length mismatch")?;
            let original_id:Uuid=request["request_id"].as_str().ok_or("original id missing")?.parse()?;
            let durable=running.fixture.client.recovery_maintenance_get(running.fixture.scope.clone(),original_id,original_digest)?
                .ok_or("original committed receipt missing after held owner completion")?;
            assert_eq!(durable.request().request_id,original_id);
            assert_eq!(durable.request().request_digest,original_digest);
            let (get_status,history)=post_command(running.address,"recovery.maintenance.get",get).await?;
            if get_status==200 {
                assert_eq!(history["result"]["receipt"]["receipt_digest"],forge_backend::events::hex_encode(durable.receipt_digest()));
                if status==200 {assert_eq!(history["result"]["receipt"],replay["result"]["receipt"]);}
            } else {
                assert_eq!(get_status,202,"{history}");assert_eq!(history["error"]["code"],"UNKNOWN_OUTCOME");
            }
            Ok::<(),Box<dyn std::error::Error>>(())
        }.await;
        let cleanup = running.finish().await;
        result?;
        released?;
        verify?;
        cleanup?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_maintenance_records_exact_history_and_replay_does_not_recapture()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let (activity, execution) = seed_expired(&fixture)?;
    let destination = delegated_destination_id(&fixture)?;
    let cache = fixture.root.join("maintenance-cache");
    fs::create_dir(&cache)?;
    let state = assemble_fixture(backend_config()?, &fixture, &cache, destination)?;
    let address = serve(state.clone()).await?;
    let request = payload(&fixture, destination, Uuid::now_v7());
    let result = async {
        let (status, first) =
            post_command(address, "recovery.maintenance.run", request.clone()).await?;
        assert_eq!(status, 200, "{first}");
        assert_eq!(first["ok"], true);
        let receipt = first["result"]["receipt"].clone();
        assert_eq!(
            receipt["activities"]
                .as_array()
                .ok_or("activity facts missing")?
                .len(),
            1
        );
        assert_eq!(
            receipt["executions"]
                .as_array()
                .ok_or("execution facts missing")?
                .len(),
            1
        );
        assert_eq!(
            receipt["activities"][0]["activity_id"],
            json!(activity.into_uuid())
        );
        assert_eq!(
            receipt["executions"][0]["execution_id"],
            json!(execution.into_uuid())
        );
        assert_eq!(receipt["released_lease"]["owner_id"], Value::Null);
        let get = json!({"scope":scope_json(&fixture),"request_id":request["request_id"],
            "request_digest":receipt["request"]["request_digest"]});
        let (_new_activity, new_execution) = seed_expired(&fixture)?;
        let (status, replay) =
            post_command(address, "recovery.maintenance.run", request.clone()).await?;
        assert_eq!(status, 200, "{replay}");
        assert_eq!(replay["result"]["replayed"], true);
        assert_eq!(replay["result"]["receipt"], receipt);
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert_eq!(
            store
                .get_execution(new_execution)?
                .ok_or("new execution missing")?
                .state(),
            forge_domain::ExecutionState::Starting
        );
        assert!(
            store
                .execution_native_closure_snapshot(execution)?
                .ok_or("classified execution missing")?
                .closure()
                .is_none()
        );
        drop(store);
        let (status, history) = post_command(address, "recovery.maintenance.get", get).await?;
        assert_eq!(status, 200, "{history}");
        assert_eq!(history["result"]["receipt"], receipt);
        let mut changed = request.clone();
        changed["duration_ms"] = json!(60_000);
        let (status, conflict) = post_command(address, "recovery.maintenance.run", changed).await?;
        assert_ne!(status, 200, "{conflict}");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let shutdown = state.shutdown(Duration::from_secs(5)).await;
    let cleanup = fixture.shutdown();
    result?;
    assert!(shutdown.is_successful());
    cleanup?;
    Ok(())
}
