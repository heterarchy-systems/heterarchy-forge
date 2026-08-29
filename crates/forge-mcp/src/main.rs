//! Executable MCP boundary for Heterarchy Forge.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use forge_control::{ForgeControl, ForgeControlClient, McpTokenIssueRequest};
use forge_domain::{
    LocationId, LocationRevision, McpTokenId, McpTokenLabel, McpTokenRevision,
    McpTokenWorkspaceScope, TimestampMillis, WorkspaceId, WorkspaceRevision,
};
use forge_persistence::{GlobalRegistry, RegistryHealth};
use forge_platform::{AppPaths, init_logging};
use forge_workspace::WorkspaceLocator;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::runtime::Builder;
use uuid::Uuid;

use forge_control::ControlWorkerError;
use forge_mcp::{
    MCP_TOOL_NAMES, McpHttpServerHandle, McpServerProcess, McpServerProcessError,
    McpShutdownReport, McpTokenRuntime, McpTokenRuntimeError,
};

const REGISTRY_PATH_ENV: &str = "HETERARCHY_FORGE_REGISTRY_PATH";
const DOCTOR_ARG: &str = "--doctor";
const DOCTOR_DUPLEX_CAPACITY: usize = 32 * 1024;

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let command = parse_command(&arguments);
    if let Err(error) = command.and_then(run) {
        eprintln!("forge-mcp failed: {error}");
        std::process::exit(1);
    }
}

#[derive(Debug)]
enum MainCommand {
    Stdio,
    Doctor,
    HttpServe {
        port: u16,
    },
    TokenIssue {
        label: McpTokenLabel,
        location_id: LocationId,
        location_revision: LocationRevision,
        workspace_id: WorkspaceId,
        workspace_revision: WorkspaceRevision,
        locator: WorkspaceLocator,
    },
    TokenRotate {
        id: McpTokenId,
        revision: McpTokenRevision,
    },
    TokenRevoke {
        id: McpTokenId,
        revision: McpTokenRevision,
    },
    TokenList,
}

fn run(command: MainCommand) -> Result<(), MainError> {
    let paths = AppPaths::discover().map_err(MainError::AppPaths)?;
    let registry_path =
        env::var_os(REGISTRY_PATH_ENV).map_or_else(|| paths.global_registry_path(), PathBuf::from);
    if matches!(command, MainCommand::Doctor) {
        let registry_health = GlobalRegistry::inspect_existing_read_only(&registry_path)
            .map_err(MainError::Registry)?;
        return run_doctor_mode(registry_health);
    }

    paths.ensure_exists().map_err(MainError::AppPaths)?;
    let _logging_guard = init_logging(&paths).map_err(MainError::Logging)?;

    let registry = GlobalRegistry::open(registry_path).map_err(MainError::Registry)?;
    let _registry_health = registry.health().map_err(MainError::Registry)?;

    let control = ForgeControl::new(registry);
    let (client, mut worker) = control.start_worker().map_err(MainError::ControlWorker)?;
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(MainError::Runtime)?;

    let result = execute_command(command, &paths, client, &runtime);

    // The MCP process closes its owned Activities before returning.  The
    // control worker is a separate owner and must be stopped and joined after
    // the transport lifecycle has completed, even when the server failed.
    worker.shutdown().map_err(MainError::ControlWorker)?;
    result?;
    Ok(())
}

fn execute_command(
    command: MainCommand,
    paths: &AppPaths,
    client: ForgeControlClient,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), MainError> {
    match command {
        MainCommand::Stdio => runtime.block_on(run_stdio(client)),
        MainCommand::HttpServe { port } => {
            let token_runtime =
                McpTokenRuntime::start(paths, forge_mcp::McpTokenBootstrapMode::ExistingAuthority)
                    .map_err(MainError::TokenRuntime)?;
            runtime.block_on(run_http(client, token_runtime, port))
        }
        MainCommand::TokenIssue {
            label,
            location_id,
            location_revision,
            workspace_id,
            workspace_revision,
            locator,
        } => {
            let scope = client
                .resolve_workspace(location_id, location_revision, locator)
                .map_err(MainError::ControlClient)?;
            if scope.workspace_id() != workspace_id
                || scope.workspace_revision() != workspace_revision
            {
                return Err(MainError::Arguments(
                    "token scope does not match the current durable Workspace".to_owned(),
                ));
            }
            let mut token_runtime = McpTokenRuntime::start(
                paths,
                forge_mcp::McpTokenBootstrapMode::InitializeAuthority,
            )
            .map_err(MainError::TokenRuntime)?;
            let issued = token_runtime
                .issue(
                    McpTokenIssueRequest::new(
                        label,
                        vec![McpTokenWorkspaceScope::new(location_id, workspace_id)],
                        current_timestamp()?,
                    )
                    .map_err(|error| MainError::Arguments(error.to_string()))?,
                )
                .map_err(MainError::TokenClient)?;
            println!("token_id={}", issued.metadata().id());
            println!("bearer_token={}", issued.reveal().as_str());
            println!("scope={location_id}/{workspace_id}");
            token_runtime.shutdown().map_err(MainError::TokenWorker)?;
            Ok(())
        }
        MainCommand::TokenRotate { id, revision } => {
            let mut token_runtime =
                McpTokenRuntime::start(paths, forge_mcp::McpTokenBootstrapMode::ExistingAuthority)
                    .map_err(MainError::TokenRuntime)?;
            let rotated = token_runtime
                .rotate(id, revision, current_timestamp()?)
                .map_err(MainError::TokenClient)?;
            println!("token_id={}", rotated.replacement().metadata().id());
            println!("bearer_token={}", rotated.replacement().reveal().as_str());
            token_runtime.shutdown().map_err(MainError::TokenWorker)?;
            Ok(())
        }
        MainCommand::TokenRevoke { id, revision } => {
            let mut token_runtime =
                McpTokenRuntime::start(paths, forge_mcp::McpTokenBootstrapMode::ExistingAuthority)
                    .map_err(MainError::TokenRuntime)?;
            let revoked = token_runtime
                .revoke(id, revision, current_timestamp()?)
                .map_err(MainError::TokenClient)?;
            println!("token_id={}", revoked.id());
            println!("state=revoked");
            token_runtime.shutdown().map_err(MainError::TokenWorker)?;
            Ok(())
        }
        MainCommand::TokenList => {
            let mut token_runtime =
                McpTokenRuntime::start(paths, forge_mcp::McpTokenBootstrapMode::ExistingAuthority)
                    .map_err(MainError::TokenRuntime)?;
            for token in token_runtime
                .list(forge_control::MAX_MCP_TOKEN_LIST_RESULTS)
                .map_err(MainError::TokenClient)?
            {
                println!(
                    "token_id={} state={:?} revision={} scopes={} label={}",
                    token.id(),
                    token.state(),
                    token.revision().get(),
                    token.scopes().len(),
                    token.label().as_str()
                );
            }
            token_runtime.shutdown().map_err(MainError::TokenWorker)?;
            Ok(())
        }
        MainCommand::Doctor => Err(MainError::Arguments(
            "doctor command reached normal runtime".to_owned(),
        )),
    }
}

async fn run_http(
    client: ForgeControlClient,
    mut token_runtime: McpTokenRuntime,
    port: u16,
) -> Result<(), MainError> {
    let server = McpHttpServerHandle::start(client, token_runtime.client(), port)
        .await
        .map_err(MainError::Http)?;
    println!("mcp_endpoint={}", server.endpoint());
    tokio::signal::ctrl_c().await.map_err(MainError::Signal)?;
    let _report = server.shutdown().await.map_err(MainError::Http)?;
    token_runtime.shutdown().map_err(MainError::TokenWorker)?;
    Ok(())
}

fn parse_command(arguments: &[String]) -> Result<MainCommand, MainError> {
    if arguments.is_empty() {
        return Ok(MainCommand::Stdio);
    }
    if arguments == [DOCTOR_ARG] {
        return Ok(MainCommand::Doctor);
    }
    match arguments.first().map(String::as_str) {
        Some("http") if arguments.get(1).map(String::as_str) == Some("serve") => {
            if arguments.len() != 3 {
                return Err(argument_usage());
            }
            let port = arguments[2]
                .parse::<u16>()
                .map_err(|_| MainError::Arguments("HTTP port is invalid".to_owned()))?;
            Ok(MainCommand::HttpServe { port })
        }
        Some("token") if arguments.get(1).map(String::as_str) == Some("issue") => {
            if arguments.len() != 8 {
                return Err(argument_usage());
            }
            Ok(MainCommand::TokenIssue {
                label: McpTokenLabel::new(arguments[2].clone())
                    .map_err(|_| MainError::Arguments("token label is invalid".to_owned()))?,
                location_id: arguments[3]
                    .parse()
                    .map_err(|_| MainError::Arguments("Location id is invalid".to_owned()))?,
                location_revision: LocationRevision::new(parse_i64(
                    &arguments[4],
                    "Location revision",
                )?)
                .map_err(|_| MainError::Arguments("Location revision is invalid".to_owned()))?,
                workspace_id: arguments[5]
                    .parse()
                    .map_err(|_| MainError::Arguments("Workspace id is invalid".to_owned()))?,
                workspace_revision: WorkspaceRevision::new(parse_i64(
                    &arguments[6],
                    "Workspace revision",
                )?)
                .map_err(|_| MainError::Arguments("Workspace revision is invalid".to_owned()))?,
                locator: WorkspaceLocator::decode(&arguments[7])
                    .map_err(|_| MainError::Arguments("Workspace locator is invalid".to_owned()))?,
            })
        }
        Some("token") if arguments.get(1).map(String::as_str) == Some("rotate") => {
            parse_token_revision_command(arguments, true)
        }
        Some("token") if arguments.get(1).map(String::as_str) == Some("revoke") => {
            parse_token_revision_command(arguments, false)
        }
        Some("token")
            if arguments.get(1).map(String::as_str) == Some("list") && arguments.len() == 2 =>
        {
            Ok(MainCommand::TokenList)
        }
        Some(_) | None => Err(argument_usage()),
    }
}

fn parse_token_revision_command(
    arguments: &[String],
    rotate: bool,
) -> Result<MainCommand, MainError> {
    if arguments.len() != 4 {
        return Err(argument_usage());
    }
    let id = arguments[2]
        .parse()
        .map_err(|_| MainError::Arguments("token id is invalid".to_owned()))?;
    let revision = McpTokenRevision::new(parse_i64(&arguments[3], "token revision")?)
        .map_err(|_| MainError::Arguments("token revision is invalid".to_owned()))?;
    if rotate {
        Ok(MainCommand::TokenRotate { id, revision })
    } else {
        Ok(MainCommand::TokenRevoke { id, revision })
    }
}

fn parse_i64(value: &str, label: &str) -> Result<i64, MainError> {
    value
        .parse()
        .map_err(|_| MainError::Arguments(format!("{label} is invalid")))
}

fn argument_usage() -> MainError {
    MainError::Arguments(
        "usage: forge-mcp [--doctor|http serve <port>|token issue <label> <location-id> <location-revision> <workspace-id> <workspace-revision> <locator>|token rotate <token-id> <revision>|token revoke <token-id> <revision>|token list]"
            .to_owned(),
    )
}

fn current_timestamp() -> Result<TimestampMillis, MainError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MainError::Clock)?;
    let millis = i64::try_from(duration.as_millis()).map_err(|_| MainError::Clock)?;
    TimestampMillis::new(millis).map_err(|_| MainError::Clock)
}

fn run_doctor_mode(registry_health: Option<RegistryHealth>) -> Result<(), MainError> {
    let temporary_registry = DoctorRegistry::create()?;
    let registry = GlobalRegistry::open(temporary_registry.path()).map_err(MainError::Registry)?;
    let (client, mut worker) = ForgeControl::new(registry)
        .start_worker()
        .map_err(MainError::ControlWorker)?;
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(MainError::Runtime)?;
    let result = runtime.block_on(run_doctor(client, registry_health));
    let shutdown = worker.shutdown().map_err(MainError::ControlWorker);
    result?;
    shutdown?;
    drop(temporary_registry);
    Ok(())
}

async fn run_stdio(client: ForgeControlClient) -> Result<(), MainError> {
    McpServerProcess::new(client)
        .run()
        .await
        .map(|_report| ())
        .map_err(MainError::Mcp)
}

async fn run_doctor(
    client: ForgeControlClient,
    registry_health: Option<RegistryHealth>,
) -> Result<(), MainError> {
    let process = McpServerProcess::new(client);
    let runtime_instance_id = process.runtime_instance_id();
    if runtime_instance_id.into_uuid() == Uuid::nil() {
        return Err(MainError::DoctorInvariant(
            "runtime ownership identity is empty",
        ));
    }
    let smoke = run_doctor_smoke(process).await?;
    if smoke.tool_names != MCP_TOOL_NAMES {
        return Err(MainError::DoctorInvariant(
            "MCP tool order or set is incorrect",
        ));
    }

    // Doctor is the only mode allowed to write PASS markers to stdout.  The
    // stdio mode reserves stdout exclusively for rmcp JSON-RPC frames.
    let initialized = registry_health.is_some();
    if let Some(registry_health) = registry_health
        && (registry_health.schema_version() != 2
            || !registry_health.foreign_keys_enabled()
            || !registry_health.journal_mode().eq_ignore_ascii_case("wal"))
    {
        return Err(MainError::DoctorInvariant(
            "registry health invariants are not verified",
        ));
    }
    println!(
        "mcp_doctor={}",
        if initialized {
            "PASS"
        } else {
            "PASS_WITH_WARNINGS"
        }
    );
    println!(
        "registry_health={}",
        if initialized {
            "PASS"
        } else {
            "NOT_INITIALIZED"
        }
    );
    println!("runtime_ownership=PASS");
    println!("tool_names=PASS");
    println!("shutdown=PASS");
    let _ = smoke.shutdown_report;
    Ok(())
}

struct DoctorRegistry {
    root: PathBuf,
    path: PathBuf,
}

impl DoctorRegistry {
    fn create() -> Result<Self, MainError> {
        let root = env::temp_dir().join(format!(
            "heterarchy-forge-mcp-doctor-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root).map_err(MainError::DoctorIo)?;
        Ok(Self {
            path: root.join("registry.sqlite3"),
            root,
        })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for DoctorRegistry {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
struct DoctorSmokeReport {
    tool_names: [&'static str; 22],
    shutdown_report: McpShutdownReport,
}

async fn run_doctor_smoke(process: McpServerProcess) -> Result<DoctorSmokeReport, MainError> {
    let (server_stream, client_stream) = tokio::io::duplex(DOCTOR_DUPLEX_CAPACITY);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_reader = BufReader::new(client_read);
    let process_task = tokio::spawn(process.run_with_io(server_read, server_write));

    let names_result = async {
        send_json(
            &mut client_write,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "forge-mcp-doctor", "version": env!("CARGO_PKG_VERSION")}
                }
            }),
        )
        .await?;
        let initialize = read_json(&mut client_reader).await?;
        if initialize["id"] != json!(1)
            || !initialize["result"]["capabilities"]["tools"].is_object()
        {
            return Err(MainError::DoctorInvariant(
                "initialize smoke response is invalid",
            ));
        }

        send_json(
            &mut client_write,
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
        )
        .await?;
        send_json(
            &mut client_write,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        )
        .await?;
        let list = read_json(&mut client_reader).await?;
        tool_names(&list)
    }
    .await;
    let names = match names_result {
        Ok(names) => names,
        Err(error) => {
            let _ = client_write.shutdown().await;
            let _ = process_task.await;
            return Err(error);
        }
    };

    client_write.shutdown().await.map_err(MainError::DoctorIo)?;
    let shutdown_report = process_task
        .await
        .map_err(MainError::DoctorTask)?
        .map_err(MainError::Mcp)?;
    Ok(DoctorSmokeReport {
        tool_names: names,
        shutdown_report,
    })
}

async fn send_json<W>(writer: &mut W, value: Value) -> Result<(), MainError>
where
    W: AsyncWrite + Unpin,
{
    let encoded = serde_json::to_vec(&value).map_err(MainError::DoctorJson)?;
    if encoded.len() > DOCTOR_DUPLEX_CAPACITY {
        return Err(MainError::DoctorInvariant(
            "doctor request exceeded bounded input",
        ));
    }
    writer
        .write_all(&encoded)
        .await
        .map_err(MainError::DoctorIo)?;
    writer.write_all(b"\n").await.map_err(MainError::DoctorIo)
}

async fn read_json<R>(reader: &mut BufReader<R>) -> Result<Value, MainError>
where
    R: AsyncRead + Unpin,
{
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(MainError::DoctorIo)?;
    if read == 0 || line.len() > DOCTOR_DUPLEX_CAPACITY {
        return Err(MainError::DoctorInvariant(
            "doctor response was empty or oversized",
        ));
    }
    serde_json::from_str(&line).map_err(MainError::DoctorJson)
}

fn tool_names(response: &Value) -> Result<[&'static str; 22], MainError> {
    let tools = response["result"]["tools"]
        .as_array()
        .ok_or(MainError::DoctorInvariant(
            "tools/list response is not an array",
        ))?;
    if tools.len() != MCP_TOOL_NAMES.len() {
        return Err(MainError::DoctorInvariant("tools/list count is incorrect"));
    }
    for (tool, expected) in tools.iter().zip(MCP_TOOL_NAMES) {
        if tool["name"].as_str() != Some(expected) {
            return Err(MainError::DoctorInvariant("tools/list order is incorrect"));
        }
    }
    Ok(MCP_TOOL_NAMES)
}

#[derive(Debug, Error)]
enum MainError {
    #[error("invalid arguments: {0}")]
    Arguments(String),
    #[error("application paths failed")]
    AppPaths(#[source] forge_platform::AppPathError),
    #[error("logging initialization failed")]
    Logging(#[source] forge_platform::LoggingError),
    #[error("registry startup or health check failed")]
    Registry(#[source] forge_persistence::RegistryError),
    #[error("control worker lifecycle failed")]
    ControlWorker(#[source] ControlWorkerError),
    #[error("control client operation failed")]
    ControlClient(#[source] forge_control::ControlClientError),
    #[error("Tokio runtime startup failed")]
    Runtime(#[source] std::io::Error),
    #[error("MCP server lifecycle failed")]
    Mcp(#[source] McpServerProcessError),
    #[error("MCP HTTP server lifecycle failed")]
    Http(#[source] forge_mcp::McpHttpServerError),
    #[error("MCP token runtime bootstrap failed")]
    TokenRuntime(#[source] McpTokenRuntimeError),
    #[error("MCP token worker lifecycle failed")]
    TokenWorker(#[source] forge_control::McpTokenWorkerError),
    #[error("MCP token operation failed")]
    TokenClient(#[source] forge_control::McpTokenClientError),
    #[error("MCP HTTP shutdown signal failed")]
    Signal(#[source] std::io::Error),
    #[error("system clock is outside the supported range")]
    Clock,
    #[error("doctor check failed: {0}")]
    DoctorInvariant(&'static str),
    #[error("doctor JSON processing failed")]
    DoctorJson(#[source] serde_json::Error),
    #[error("doctor server task failed")]
    DoctorTask(#[source] tokio::task::JoinError),
    #[error("doctor transport I/O failed")]
    DoctorIo(#[source] std::io::Error),
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn command_parser_preserves_stdio_doctor_and_explicit_http_modes() {
        assert!(matches!(parse_command(&[]), Ok(MainCommand::Stdio)));
        assert!(matches!(
            parse_command(&["--doctor".to_owned()]),
            Ok(MainCommand::Doctor)
        ));
        assert!(matches!(
            parse_command(&["http".to_owned(), "serve".to_owned(), "8765".to_owned()]),
            Ok(MainCommand::HttpServe { port: 8765 })
        ));
        assert!(parse_command(&["http".to_owned(), "serve".to_owned()]).is_err());
    }

    #[test]
    fn token_commands_reject_malformed_identity_and_revision() {
        assert!(
            parse_command(&[
                "token".to_owned(),
                "rotate".to_owned(),
                "not-a-token".to_owned(),
                "1".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_command(&[
                "token".to_owned(),
                "revoke".to_owned(),
                Uuid::from_u128(1).to_string(),
                "0".to_owned(),
            ])
            .is_err()
        );
    }
}
