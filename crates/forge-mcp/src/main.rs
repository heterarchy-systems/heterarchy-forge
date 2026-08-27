//! Executable MCP boundary for Heterarchy Forge.

use std::env;
use std::fs;
use std::path::PathBuf;

use forge_control::{ForgeControl, ForgeControlClient};
use forge_persistence::{GlobalRegistry, RegistryHealth};
use forge_platform::{AppPaths, init_logging};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::runtime::Builder;
use uuid::Uuid;

use forge_control::ControlWorkerError;
use forge_mcp::{MCP_TOOL_NAMES, McpServerProcess, McpServerProcessError, McpShutdownReport};

const REGISTRY_PATH_ENV: &str = "HETERARCHY_FORGE_REGISTRY_PATH";
const DOCTOR_ARG: &str = "--doctor";
const DOCTOR_DUPLEX_CAPACITY: usize = 32 * 1024;

fn main() {
    let doctor = env::args().any(|argument| argument == DOCTOR_ARG);
    if let Err(error) = run(doctor) {
        eprintln!("forge-mcp failed: {error}");
        std::process::exit(1);
    }
}

fn run(doctor: bool) -> Result<(), MainError> {
    let paths = AppPaths::discover().map_err(MainError::AppPaths)?;
    let registry_path =
        env::var_os(REGISTRY_PATH_ENV).map_or_else(|| paths.global_registry_path(), PathBuf::from);
    if doctor {
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

    let result = runtime.block_on(run_stdio(client));

    // The MCP process closes its owned Activities before returning.  The
    // control worker is a separate owner and must be stopped and joined after
    // the transport lifecycle has completed, even when the server failed.
    worker.shutdown().map_err(MainError::ControlWorker)?;
    result?;
    Ok(())
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
    tool_names: [&'static str; 12],
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

fn tool_names(response: &Value) -> Result<[&'static str; 12], MainError> {
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
    #[error("application paths failed")]
    AppPaths(#[source] forge_platform::AppPathError),
    #[error("logging initialization failed")]
    Logging(#[source] forge_platform::LoggingError),
    #[error("registry startup or health check failed")]
    Registry(#[source] forge_persistence::RegistryError),
    #[error("control worker lifecycle failed")]
    ControlWorker(#[source] ControlWorkerError),
    #[error("Tokio runtime startup failed")]
    Runtime(#[source] std::io::Error),
    #[error("MCP server lifecycle failed")]
    Mcp(#[source] McpServerProcessError),
    #[error("doctor check failed: {0}")]
    DoctorInvariant(&'static str),
    #[error("doctor JSON processing failed")]
    DoctorJson(#[source] serde_json::Error),
    #[error("doctor server task failed")]
    DoctorTask(#[source] tokio::task::JoinError),
    #[error("doctor transport I/O failed")]
    DoctorIo(#[source] std::io::Error),
}
