//! Stdio-only MCP adapter for the Heterarchy Forge control plane.
//!
//! This crate is deliberately an adapter.  It owns the MCP transport and the
//! lifetime of the per-process lease tracker, but it does not make a
//! Workspace current, infer an Activity, or treat a JSON-RPC id as authority.
//! Every tool carries the Location revision and the explicit
//! [`forge_workspace::WorkspaceLocator`] needed by the control service.

#![deny(unsafe_code)]

mod frame;
mod http;
mod process;
mod protocol;
mod service;
mod token;

pub use frame::{BoundedMcpFrameReader, MAX_MCP_FRAME_BYTES};
pub use http::{
    MCP_HTTP_AUTH_BLOCKING_CAPACITY, MCP_HTTP_DEFAULT_PORT, MCP_HTTP_MAX_REQUEST_BODY_BYTES,
    MCP_HTTP_STARTUP_TIMEOUT, McpHttpPort, McpHttpServerConfig, McpHttpServerError,
    McpHttpServerHandle, McpHttpServerRuntime, McpHttpServerRuntimeError, McpHttpServerService,
    McpPublicOrigin, McpPublicOriginError,
};
pub use process::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_LEASE_DURATION_MS, MAX_OWNED_ACTIVITIES,
    MAX_OWNED_WORKSPACE_GROUPS, McpConfigError, McpLeasePolicy, McpServerProcess,
    McpServerProcessError, McpShutdownReport,
};
pub use protocol::{
    ActivityBootstrapInput, ActivityBootstrapOutput, ActivityOutput, ActivityStateWire,
    ActivityStatusWire, LocationIdWire, LocationRevisionWire, MAX_ACTIVITY_ID_BYTES,
    MAX_ARGUMENT_BYTES, MAX_ARGUMENT_FIELDS, MAX_ARGUMENT_TREE_NODES, MAX_ID_BYTES,
    MAX_LOCATOR_BYTES, MAX_TOOL_NAME_BYTES, McpToolErrorOutput, OwnershipTrackingWire,
    WireValidationError, WorkspaceCatalogEntryOutput, WorkspaceCatalogStatusWire,
    WorkspaceListInput, WorkspaceListOutput, WorkspaceResolveInput, WorkspaceResolveOutput,
    WorkspaceScopeOutput, WorkspaceSignalWire,
};
pub use service::{MCP_TOOL_NAMES, McpServerService};
pub use token::{McpTokenBootstrapMode, McpTokenRuntime, McpTokenRuntimeError};

#[cfg(test)]
mod integration_tests {
    use std::error::Error;
    use std::fs;
    use std::io;

    use base64::Engine;
    use forge_control::{ForgeControl, ForgeControlClient, ForgeControlWorker};
    use forge_domain::{
        ActivityId, ActivityState, DiffListLimit, EstablishWorkspace, LocationId, LocationRevision,
        RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use serde_json::{Value, json};
    use tokio::io::DuplexStream;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
    use uuid::Uuid;

    use super::{McpLeasePolicy, McpServerProcess};

    type TestError = Box<dyn Error>;
    type TestReader = BufReader<ReadHalf<DuplexStream>>;
    type TestWriter = WriteHalf<DuplexStream>;

    struct Fixture {
        root: std::path::PathBuf,
        workspace_root: std::path::PathBuf,
        location_id: LocationId,
        workspace_id: WorkspaceId,
        client: ForgeControlClient,
        worker: ForgeControlWorker,
    }

    fn fixture() -> Result<Fixture, TestError> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-stdio-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        let location_root = root.join("location");
        let registry_path = root.join("registry.sqlite3");
        fs::create_dir_all(&location_root)?;
        let location_id = LocationId::from_uuid(Uuid::from_u128(101));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        locations.register_selected_path(
            location_id,
            "MCP stdio Location",
            &location_root,
            TimestampMillis::new(1)?,
        )?;
        let layout = WorkspaceStateLayout::initialize(&location_root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(103));
        let workspace_root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            workspace_root,
            layout.root_fingerprint()?,
            TimestampMillis::new(2)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        drop(store);
        drop(locations);
        let (client, worker) =
            ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(&registry_path)?))?;
        Ok(Fixture {
            root,
            workspace_root: location_root,
            location_id,
            workspace_id,
            client,
            worker,
        })
    }

    async fn send_json(writer: &mut TestWriter, value: Value) -> Result<(), TestError> {
        let encoded = serde_json::to_vec(&value)?;
        writer.write_all(&encoded).await?;
        writer.write_all(b"\n").await?;
        Ok(())
    }

    async fn read_json(reader: &mut TestReader) -> Result<Value, TestError> {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            return Err(io::Error::other("server closed before response").into());
        }
        Ok(serde_json::from_str(&line)?)
    }

    async fn initialize(reader: &mut TestReader, writer: &mut TestWriter) -> Result<(), TestError> {
        send_json(
            writer,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "forge-mcp-test", "version": "0.1"}
                }
            }),
        )
        .await?;
        let response = read_json(reader).await?;
        assert_eq!(response["id"], json!(1));
        assert!(response["result"]["capabilities"]["tools"].is_object());
        send_json(
            writer,
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
        )
        .await
    }

    async fn list_tools(reader: &mut TestReader, writer: &mut TestWriter) -> Result<(), TestError> {
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        )
        .await?;
        let response = read_json(reader).await?;
        let names: Vec<&str> = response["result"]["tools"]
            .as_array()
            .ok_or_else(|| io::Error::other("tools list is not an array"))?
            .iter()
            .map(|tool| {
                tool["name"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("tool name is not text"))
            })
            .collect::<Result<_, _>>()?;
        assert_eq!(
            names,
            vec![
                "workspace_list",
                "workspace_resolve",
                "activity_bootstrap",
                "file_read",
                "file_create",
                "file_replace",
                "file_delete",
                "diff_list",
                "diff_read",
                "diff_doctor",
                "diff_retention_plan",
                "diff_artifact_doctor",
                "agent_attach",
                "agent_set_focus",
                "agent_publish_work",
                "agent_get_context",
                "agent_detach",
                "goal_list",
                "goal_get",
                "dag_get_current",
                "dag_authoring_grant_discover",
                "dag_replan_commit",
            ]
        );
        assert!(names.iter().all(|name| {
            !matches!(
                *name,
                "command_run" | "shell_run" | "execution_cancel" | "execution_stop"
            )
        }));
        Ok(())
    }

    async fn workspace_checks(
        reader: &mut TestReader,
        writer: &mut TestWriter,
        location_id: LocationId,
        workspace_id: WorkspaceId,
    ) -> Result<String, TestError> {
        let list_arguments = json!({
            "location_id": location_id.to_string(),
            "expected_revision": LocationRevision::INITIAL.get(),
        });
        for request_id in [3, 4] {
            send_json(
                writer,
                json!({"jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{"name":"workspace_list","arguments":list_arguments.clone()}}),
            )
            .await?;
            let response = read_json(reader).await?;
            assert_eq!(response["id"], json!(request_id));
            assert_ne!(response["result"]["isError"].as_bool(), Some(true));
            assert_eq!(
                response["result"]["structuredContent"]["entries"]
                    .as_array()
                    .map(Vec::len),
                Some(1)
            );
        }
        let entry = read_workspace_entry(reader, writer, location_id).await?;
        assert_eq!(entry["workspaceId"], json!(workspace_id.to_string()));
        assert_eq!(entry["workspaceRevision"], json!(1));
        let locator = entry["locator"]
            .as_str()
            .ok_or_else(|| io::Error::other("Workspace locator is not text"))?
            .to_owned();
        let resolve_arguments = json!({
            "location_id": location_id.to_string(),
            "expected_revision": 1,
            "workspace_id": workspace_id.to_string(),
            "workspace_revision": 1,
            "locator": locator,
        });
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"workspace_resolve","arguments":resolve_arguments.clone()}}),
        )
        .await?;
        let resolved = read_json(reader).await?;
        assert_eq!(
            resolved["result"]["structuredContent"]["scope"]["workspaceId"],
            json!(workspace_id.to_string())
        );
        let mismatch = json!({
            "location_id": location_id.to_string(),
            "expected_revision": 1,
            "workspace_id": Uuid::from_u128(104).to_string(),
            "workspace_revision": 1,
            "locator": resolve_arguments["locator"],
        });
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"workspace_resolve","arguments":mismatch}}),
        )
        .await?;
        let mismatch_response = read_json(reader).await?;
        assert_eq!(mismatch_response["error"]["code"], json!(-32602));
        Ok(locator)
    }

    async fn activity_checks(
        reader: &mut TestReader,
        writer: &mut TestWriter,
        location_id: LocationId,
        workspace_id: WorkspaceId,
        locator: &str,
    ) -> Result<(), TestError> {
        let arguments = json!({
            "location_id": location_id.to_string(),
            "expected_revision": 1,
            "workspace_id": workspace_id.to_string(),
            "workspace_revision": 1,
            "locator": locator,
            "activity_id": Uuid::from_u128(105).to_string(),
        });
        let mut mismatch = arguments.clone();
        mismatch["workspace_id"] = json!(Uuid::from_u128(106).to_string());
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"activity_bootstrap","arguments":mismatch}}),
        )
        .await?;
        let mismatch_response = read_json(reader).await?;
        assert_eq!(mismatch_response["error"]["code"], json!(-32602));
        for request_id in [8, 9] {
            send_json(
                writer,
                json!({"jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{"name":"activity_bootstrap","arguments":arguments.clone()}}),
            )
            .await?;
            let response = read_json(reader).await?;
            assert_eq!(
                response["result"]["structuredContent"]["scope"]["workspaceId"],
                json!(workspace_id.to_string())
            );
            assert!(matches!(
                response["result"]["structuredContent"]["ownershipTracking"].as_str(),
                Some("tracked" | "not_tracked_capacity")
            ));
        }
        Ok(())
    }

    async fn file_checks(
        reader: &mut TestReader,
        writer: &mut TestWriter,
        location_id: LocationId,
        workspace_id: WorkspaceId,
        locator: &str,
    ) -> Result<(), TestError> {
        let path = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"created.txt");
        let common = json!({
            "location_id": location_id.to_string(),
            "expected_revision": 1,
            "workspace_id": workspace_id.to_string(),
            "workspace_revision": 1,
            "locator": locator,
            "activity_id": Uuid::from_u128(105).to_string(),
            "path": path,
        });

        assert_untracked_file_denied(reader, writer, &common).await?;

        let mut create = common.clone();
        create["change_set_id"] = json!(Uuid::from_u128(201).to_string());
        create["mutation_id"] = json!(Uuid::from_u128(202).to_string());
        create["content_base64"] =
            json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"one"));
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"file_create","arguments":create}}),
        )
        .await?;
        let created = read_json(reader).await?;
        assert_eq!(
            created["result"]["structuredContent"]["status"],
            json!("applied")
        );
        let first_hash = created["result"]["structuredContent"]["postState"]["contentHash"]
            .as_str()
            .ok_or_else(|| io::Error::other("create hash missing"))?
            .to_owned();
        assert!(first_hash.starts_with("blake3-256:"));

        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"file_read","arguments":common.clone()}}),
        )
        .await?;
        let read = read_json(reader).await?;
        assert_eq!(
            read["result"]["structuredContent"]["contentBase64"],
            json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"one"))
        );
        assert_eq!(
            read["result"]["structuredContent"]["contentHash"],
            json!(first_hash)
        );

        let mut replace = common.clone();
        replace["change_set_id"] = json!(Uuid::from_u128(203).to_string());
        replace["mutation_id"] = json!(Uuid::from_u128(204).to_string());
        replace["expected_hash"] = json!(first_hash);
        replace["content_base64"] =
            json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"two"));
        let mut second_hash = None;
        for (request_id, expected_status) in [(13, "applied"), (14, "already_applied")] {
            send_json(
                writer,
                json!({"jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{"name":"file_replace","arguments":replace.clone()}}),
            )
            .await?;
            let replaced = read_json(reader).await?;
            assert_eq!(
                replaced["result"]["structuredContent"]["status"],
                json!(expected_status)
            );
            if request_id == 13 {
                second_hash = replaced["result"]["structuredContent"]["postState"]["contentHash"]
                    .as_str()
                    .map(str::to_owned);
            }
        }
        let second_hash = second_hash
            .as_deref()
            .ok_or_else(|| io::Error::other("replace hash missing"))?;
        let mut delete = common.clone();
        delete["change_set_id"] = json!(Uuid::from_u128(205).to_string());
        delete["mutation_id"] = json!(Uuid::from_u128(206).to_string());
        delete["expected_hash"] = json!(second_hash);
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"file_delete","arguments":delete}}),
        )
        .await?;
        let deleted = read_json(reader).await?;
        assert_eq!(
            deleted["result"]["structuredContent"]["status"],
            json!("applied")
        );
        assert_eq!(
            deleted["result"]["structuredContent"]["postState"]["exists"],
            json!(false)
        );
        Ok(())
    }

    async fn diff_checks(
        reader: &mut TestReader,
        writer: &mut TestWriter,
        location_id: LocationId,
        workspace_id: WorkspaceId,
        locator: &str,
    ) -> Result<(), TestError> {
        let scope = json!({
            "location_id": location_id.to_string(),
            "expected_revision": 1,
            "workspace_id": workspace_id.to_string(),
            "workspace_revision": 1,
            "locator": locator,
        });
        let mut list = scope.clone();
        list["activity_id"] = json!(Uuid::from_u128(105).to_string());
        list["limit"] = json!(10);
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"diff_list","arguments":list}}),
        )
        .await?;
        let listed = read_json(reader).await?;
        let diffs = listed["result"]["structuredContent"]["diffs"]
            .as_array()
            .ok_or_else(|| io::Error::other("Diff list is not an array"))?;
        assert_eq!(diffs.len(), 3);
        let mut observed_change_sets = diffs
            .iter()
            .map(|diff| {
                diff["changeSetId"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("Diff change-set id missing"))
                    .map(str::to_owned)
            })
            .collect::<Result<Vec<_>, _>>()?;
        observed_change_sets.sort();
        let mut expected_change_sets = [201_u128, 203, 205]
            .into_iter()
            .map(|value| Uuid::from_u128(value).to_string())
            .collect::<Vec<_>>();
        expected_change_sets.sort();
        assert_eq!(observed_change_sets, expected_change_sets);
        assert!(diffs.iter().all(|diff| {
            diff["activityId"] == json!(Uuid::from_u128(105).to_string())
                && diff["state"] == json!("ready")
        }));

        let create_change_set = Uuid::from_u128(201).to_string();
        let create_diff_id = diffs
            .iter()
            .find(|diff| diff["changeSetId"] == json!(create_change_set))
            .and_then(|diff| diff["diffId"].as_str())
            .ok_or_else(|| io::Error::other("created-file Diff id missing"))?
            .to_owned();
        let mut identity = scope.clone();
        identity["diff_id"] = json!(create_diff_id);
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"diff_read","arguments":identity.clone()}}),
        )
        .await?;
        let read = read_json(reader).await?;
        assert_eq!(
            read["result"]["structuredContent"]["health"],
            json!("available")
        );
        assert_eq!(
            read["result"]["structuredContent"]["diff"]["changeKind"],
            json!("created")
        );
        assert!(
            read["result"]["structuredContent"]["content"]
                .as_str()
                .is_some_and(|content| content.contains("+one"))
        );
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"diff_doctor","arguments":identity}}),
        )
        .await?;
        let doctor = read_json(reader).await?;
        assert_eq!(
            doctor["result"]["structuredContent"]["health"],
            json!("available")
        );

        let mut artifact_doctor = scope;
        artifact_doctor["limit"] = json!(10);
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"diff_artifact_doctor","arguments":artifact_doctor}}),
        )
        .await?;
        let artifacts = read_json(reader).await?;
        let entries = artifacts["result"]["structuredContent"]["entries"]
            .as_array()
            .ok_or_else(|| io::Error::other("Diff artifact inventory is not an array"))?;
        assert_eq!(entries.len(), 3);
        assert!(
            entries
                .iter()
                .all(|entry| entry["ownership"] == json!("owned"))
        );
        Ok(())
    }

    async fn assert_untracked_file_denied(
        reader: &mut TestReader,
        writer: &mut TestWriter,
        common: &Value,
    ) -> Result<(), TestError> {
        let mut untracked = common.clone();
        untracked["activity_id"] = json!(Uuid::from_u128(999).to_string());
        send_json(
            writer,
            json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"file_read","arguments":untracked}}),
        )
        .await?;
        let response = read_json(reader).await?;
        assert_eq!(
            response["error"]["data"]["code"],
            json!("ACTIVITY_NOT_TRACKED")
        );
        Ok(())
    }

    async fn read_workspace_entry(
        reader: &mut TestReader,
        writer: &mut TestWriter,
        location_id: LocationId,
    ) -> Result<Value, TestError> {
        send_json(
            writer,
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "workspace_list",
                    "arguments": {
                        "location_id": location_id.to_string(),
                        "expected_revision": 1
                    }
                }
            }),
        )
        .await?;
        let response = read_json(reader).await?;
        Ok(response["result"]["structuredContent"]["entries"][0].clone())
    }

    #[tokio::test]
    async fn stdio_transport_initialize_list_call_and_eof_shutdown() -> Result<(), TestError> {
        let mut fixture = fixture()?;
        let process = McpServerProcess::with_runtime_id(
            fixture.client,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(102)),
            McpLeasePolicy::new(60_000, std::time::Duration::from_secs(10))?,
        );
        assert!(!process.cancellation_token().is_cancelled());
        let (server_stream, client_stream) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server_stream);
        let (client_read, mut client_write) = tokio::io::split(client_stream);
        let mut reader = BufReader::new(client_read);
        let process_task = tokio::spawn(process.run_with_io(server_read, server_write));
        initialize(&mut reader, &mut client_write).await?;
        list_tools(&mut reader, &mut client_write).await?;
        let locator = workspace_checks(
            &mut reader,
            &mut client_write,
            fixture.location_id,
            fixture.workspace_id,
        )
        .await?;
        activity_checks(
            &mut reader,
            &mut client_write,
            fixture.location_id,
            fixture.workspace_id,
            &locator,
        )
        .await?;
        file_checks(
            &mut reader,
            &mut client_write,
            fixture.location_id,
            fixture.workspace_id,
            &locator,
        )
        .await?;
        diff_checks(
            &mut reader,
            &mut client_write,
            fixture.location_id,
            fixture.workspace_id,
            &locator,
        )
        .await?;
        assert!(!fixture.workspace_root.join("created.txt").exists());
        client_write.shutdown().await?;
        drop(client_write);
        let report = process_task.await??;
        assert!(report.cleanup_attempted() <= report.tracked_activities());
        assert!(report.recovery_required() <= report.tracked_activities());
        fixture.worker.shutdown()?;
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or_else(|| io::Error::other("Workspace state layout missing after shutdown"))?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let activity = store
            .get_activity(ActivityId::from_uuid(Uuid::from_u128(105)))?
            .ok_or_else(|| io::Error::other("bootstrapped Activity missing after shutdown"))?;
        assert_eq!(activity.state(), ActivityState::Closed);
        assert_eq!(activity.lease_owner_id(), None);
        assert_eq!(activity.lease_until(), None);
        let durable_diffs = store.list_diffs(
            ActivityId::from_uuid(Uuid::from_u128(105)),
            DiffListLimit::new(10)?,
        )?;
        assert_eq!(durable_diffs.len(), 3);
        let mut durable_change_sets = durable_diffs
            .iter()
            .map(|diff| diff.change_set_id().to_string())
            .collect::<Vec<_>>();
        durable_change_sets.sort();
        let mut expected_change_sets = [201_u128, 203, 205]
            .into_iter()
            .map(|value| Uuid::from_u128(value).to_string())
            .collect::<Vec<_>>();
        expected_change_sets.sort();
        assert_eq!(durable_change_sets, expected_change_sets);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
