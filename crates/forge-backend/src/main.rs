//! Standalone Forge HTTP backend with Orchestration-owned session authority.
//!
//! Contract:
//!   forge-backend serve <config.json>
//!
//! The config is strict JSON:
//! ```json
//! {
//!   "listen": "127.0.0.1:0",
//!   "registry_path": "/absolute/path/registry.sqlite3",
//!   "product_cache_root": "/absolute/product/cache/rust-ci",
//!   "backend_id": "uuid",
//!   "issuer_id": "uuid",
//!   "destination_id": "uuid",
//!   "api_bearer_file": "/absolute/path/api.secret",
//!   "session_authority": "127.0.0.1:9101",
//!   "session_bearer_file": "/absolute/path/session.secret"
//! }
//! ```
//!
//! Root `ForgeControl` with the injected remote authority is the session
//! authority passed into backend composition.  No callback URL or local
//! session-authority fallback is configured by this host.

#![deny(unsafe_code)]

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_backend::config::BackendConfig;
use forge_backend::http::{AppState, serve};
use forge_backend::remote_authority::RemoteAgentSessionAuthority;
use forge_control::{ForgeControl, ForgeControlWorker, ForgeExecutionCoordinator};
use forge_domain::{
    ForgeBackendId, OrchestrationIssuerId, RuntimeInstanceId,
    StartedActivityLeaseResumeServiceIdentity, UnstartedActivityContinuationServiceIdentity,
};
use forge_execution::{
    PACKAGE_V_MANIFEST_NAME, PACKAGE_V_SUBCOMMAND, PackageVExecutableCapability, PackageVResult,
    validate_package_root,
};
use forge_persistence::GlobalRegistry;
use forge_workspace::LocationService;
use serde::Deserialize;
use tokio::runtime::Builder;
use uuid::Uuid;

mod host_activity_leases;
mod host_toolchain;
mod relocation;

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_SECRET_BYTES: usize = 4 * 1024;
const REMOTE_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);
const EXECUTION_CAPACITY: usize = 16;
const SHUTDOWN_OBSERVATION_BUDGET: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostConfig {
    listen: SocketAddr,
    registry_path: PathBuf,
    product_cache_root: PathBuf,
    backend_id: Uuid,
    issuer_id: Uuid,
    destination_id: Uuid,
    api_bearer_file: PathBuf,
    session_authority: SocketAddr,
    session_bearer_file: PathBuf,
    #[serde(default)]
    activity_lease_supervision: Option<host_activity_leases::HostActivityLeaseSupervisionConfig>,
    rust_ci: Option<host_toolchain::HostRustCiConfig>,
}

#[derive(Debug)]
enum HostError {
    Usage,
    ConfigRead,
    ConfigMalformed,
    ConfigPathNotAbsolute(&'static str),
    RegistryInitPathNotAbsolute,
    RegistryUnavailable,
    RegistryInit,
    SecretRead(&'static str),
    SecretEncoding(&'static str),
    SecretEmpty(&'static str),
    SecretMalformed(&'static str),
    CredentialReuse,
    Runtime,
    RemoteAuthority,
    ControlWorkerStart,
    ControlWorkerShutdown,
    LeaseWorkerStart,
    LeaseWorkerShutdown,
    ActivityLeaseSupervisorConfiguration,
    ActivityLeaseSupervisorJournal,
    ActivityLeaseSupervisorShutdown,
    ActivityLeaseSupervisorFailed(host_activity_leases::SupervisorError),
    ExecutionStart,
    ExecutionShutdown,
    ExecutionShutdownTask,
    ApprovalStart,
    ApprovalShutdown,
    BackendConfig,
    BackendAssemble,
    BackendServe,
    ServeFenceBusy,
    ServeFenceUnavailable,
    Signal,
    HttpShutdownIncomplete,
    ControlShutdownIncomplete,
    StartupCleanupIncomplete,
    HostToolchain(host_toolchain::HostToolchainError),
    PackageVRejected,
    Relocation(relocation::RelocationError),
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Usage => {
                "usage: forge-backend serve <config.json> \
                 | forge-backend init-registry <registry.sqlite3> \
                 | forge-backend relocate-workspace <private-plan.json>"
            }
            Self::ConfigRead => "backend configuration could not be read",
            Self::ConfigMalformed => "backend configuration is not valid strict JSON",
            Self::ConfigPathNotAbsolute(field) => {
                return write!(formatter, "{field} must be an absolute path");
            }
            Self::RegistryInitPathNotAbsolute => {
                return formatter.write_str("the registry path must be an absolute path");
            }
            Self::RegistryUnavailable => "the configured Registry is unavailable",
            Self::RegistryInit => "the Registry could not be initialized",
            Self::SecretRead(field) => return write!(formatter, "{field} could not be read"),
            Self::SecretEncoding(field) => return write!(formatter, "{field} is not valid UTF-8"),
            Self::SecretEmpty(field) => return write!(formatter, "{field} is empty"),
            Self::SecretMalformed(field) => {
                return write!(formatter, "{field} contains invalid newline content");
            }
            Self::CredentialReuse => "API and session-service credentials must differ",
            Self::Runtime => "Tokio runtime could not be created",
            Self::RemoteAuthority => "remote session authority configuration failed",
            Self::ControlWorkerStart => "Forge control worker could not be started",
            Self::ControlWorkerShutdown => "Forge control worker did not shut down cleanly",
            Self::LeaseWorkerStart => "Forge Activity lease worker could not be started",
            Self::LeaseWorkerShutdown => "Forge Activity lease worker did not shut down cleanly",
            Self::ActivityLeaseSupervisorConfiguration => {
                "Forge host Activity lease supervision configuration was rejected"
            }
            Self::ActivityLeaseSupervisorJournal => {
                "Forge host Activity lease journal is invalid or conflicts with configuration"
            }
            Self::ActivityLeaseSupervisorShutdown => {
                "Forge host Activity lease supervisor did not stop cleanly"
            }
            Self::ActivityLeaseSupervisorFailed(error) => {
                return fmt::Display::fmt(error, formatter);
            }
            Self::ExecutionStart => "Forge execution coordinator could not be started",
            Self::ExecutionShutdown => "Forge execution coordinator did not shut down cleanly",
            Self::ExecutionShutdownTask => "execution coordinator shutdown task failed",
            Self::ApprovalStart => "the approval coordinator could not be started",
            Self::ApprovalShutdown => "the approval coordinator did not shut down cleanly",
            Self::BackendConfig => "backend configuration was rejected",
            Self::BackendAssemble => "backend composition failed",
            Self::BackendServe => "backend listener could not be started",
            Self::ServeFenceBusy => {
                return write!(
                    formatter,
                    "another forge-backend serve process already owns this Registry"
                );
            }
            Self::ServeFenceUnavailable => "the serve fence could not be taken",
            Self::Signal => "termination signal could not be observed",
            Self::HttpShutdownIncomplete => "backend HTTP shutdown still owns resources",
            Self::ControlShutdownIncomplete => "Forge control shutdown reported unresolved work",
            Self::StartupCleanupIncomplete => "startup failed and owned cleanup was incomplete",
            Self::HostToolchain(error) => return fmt::Display::fmt(error, formatter),
            Self::PackageVRejected => "PackageV structural validation was rejected",
            Self::Relocation(error) => return fmt::Display::fmt(error, formatter),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HostError {}

struct RunningHost {
    state: AppState,
    execution: ForgeExecutionCoordinator,
    approval: forge_control::ForgeApprovalCoordinator,
    control_worker: ForgeControlWorker,
    lease_worker: ForgeControlWorker,
    lease_supervisor: Option<host_activity_leases::HostActivityLeaseSupervisor>,
    // Declared last: the fence releases only after every other owner stopped.
    serve_fence: forge_backend::serve_fence::ServeFence,
}

struct StartedHostWorkers {
    control_client: forge_control::ForgeControlClient,
    control_worker: ForgeControlWorker,
    lease_client: forge_control::ActivityLeaseClient,
    lease_worker: ForgeControlWorker,
    execution: ForgeExecutionCoordinator,
    approval: forge_control::ForgeApprovalCoordinator,
}

enum HostTermination {
    Signal(std::io::Result<()>),
    LeaseSupervisor(host_activity_leases::SupervisorError),
}

impl RunningHost {
    async fn shutdown(self, budget: Duration) -> Result<(), HostError> {
        // Locals drop in reverse declaration order. Retain the exclusive
        // Registry fence until the state and every remaining owner is dropped,
        // including an early error from cleanup.
        let _serve_fence = self.serve_fence;
        let state = self.state;
        let mut execution = self.execution;
        let mut approval = self.approval;
        let mut control_worker = self.control_worker;
        let mut lease_worker = self.lease_worker;
        let mut lease_supervisor = self.lease_supervisor;
        // HTTP admission and its owned event/bridge resources drain first.
        state.stop_admission();
        let supervisor_result = match lease_supervisor.take() {
            Some(supervisor) => match await_shutdown_worker(
                supervisor.stop(),
                "host Activity lease supervisor",
                budget,
            )
            .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(HostError::ActivityLeaseSupervisorFailed(error)),
                Err(_) => Err(HostError::ActivityLeaseSupervisorShutdown),
            },
            None => Ok(()),
        };
        let mut http_report = state.shutdown(budget).await;

        // Approval drains pending decisions and cancels executions through
        // both dependencies. Join it before closing execution or control.
        let approval_result = match await_shutdown_worker(
            tokio::task::spawn_blocking(move || approval.shutdown()),
            "approval coordinator",
            budget,
        )
        .await
        {
            Ok(result) => result.map_err(|_| HostError::ApprovalShutdown),
            Err(_) => Err(HostError::ApprovalShutdown),
        };

        // Execution may synchronously read/write through the control client.
        let execution_result = match await_shutdown_worker(
            tokio::task::spawn_blocking(move || execution.shutdown()),
            "execution coordinator",
            budget,
        )
        .await
        {
            Ok(result) => result.map_err(|_| HostError::ExecutionShutdown),
            Err(_) => Err(HostError::ExecutionShutdownTask),
        };

        let lease_result = match await_shutdown_worker(
            tokio::task::spawn_blocking(move || lease_worker.shutdown_owned(Vec::new())),
            "Activity lease worker",
            budget,
        )
        .await
        {
            Ok(Ok(report))
                if report.failures().is_empty() && report.committed_but_unconfirmed() == 0 =>
            {
                Ok(())
            }
            _ => Err(HostError::LeaseWorkerShutdown),
        };
        let control_result = match await_shutdown_worker(
            tokio::task::spawn_blocking(move || control_worker.shutdown_owned(Vec::new())),
            "control worker",
            budget,
        )
        .await
        {
            Ok(Ok(report))
                if report.failures().is_empty() && report.committed_but_unconfirmed() == 0 =>
            {
                Ok(())
            }
            Ok(Ok(_)) => Err(HostError::ControlShutdownIncomplete),
            Ok(Err(_)) | Err(_) => Err(HostError::ControlWorkerShutdown),
        };

        // A blocking bridge/event/server owner can outlive the first bounded
        // observation.  Retry the root-owned HTTP drain after its dependencies
        // have stopped; never manufacture a Join result from the first report.
        if !http_report.is_successful() {
            http_report = state.shutdown(budget).await;
        }

        if !http_report.is_successful() {
            return Err(HostError::HttpShutdownIncomplete);
        }
        let _approval_report = approval_result?;
        let _execution_report = execution_result?;
        supervisor_result?;
        lease_result?;
        control_result
    }
}

/// Blocking authority work cannot safely be aborted. Report a pending phase
/// after its observation budget, retain its handle, and wait for completion
/// before stopping the next dependency. This is not a hard process-exit timer.
async fn await_shutdown_worker<T>(
    mut task: tokio::task::JoinHandle<T>,
    phase: &'static str,
    budget: Duration,
) -> Result<T, tokio::task::JoinError> {
    if let Ok(result) = tokio::time::timeout(budget, &mut task).await {
        return result;
    }
    let _ = writeln!(
        std::io::stderr(),
        "forge-backend shutdown pending: {phase}; waiting for owned work"
    );
    task.await
}

fn main() {
    if let Err(error) = entrypoint() {
        let _ = writeln!(std::io::stderr(), "forge-backend failed: {error}");
        std::process::exit(1);
    }
}

fn entrypoint() -> Result<(), HostError> {
    match parse_command()? {
        HostCommand::Serve(config_path) => serve_entrypoint(&config_path),
        HostCommand::InitRegistry(path) => init_registry_entrypoint(&path),
        HostCommand::PackageVerify(manifest) => package_verify_entrypoint(&manifest),
        HostCommand::RelocateWorkspace(plan) => {
            relocation::run(&plan).map_err(HostError::Relocation)
        }
    }
}

enum HostCommand {
    Serve(PathBuf),
    InitRegistry(PathBuf),
    PackageVerify(PathBuf),
    RelocateWorkspace(PathBuf),
}

fn parse_command() -> Result<HostCommand, HostError> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let command = arguments
        .next()
        .ok_or(HostError::Usage)?
        .to_string_lossy()
        .into_owned();
    match command.as_str() {
        "serve" => {
            let config = arguments.next().ok_or(HostError::Usage)?;
            if arguments.next().is_some() {
                return Err(HostError::Usage);
            }
            Ok(HostCommand::Serve(PathBuf::from(config)))
        }
        "init-registry" => {
            let path = arguments.next().ok_or(HostError::Usage)?;
            if arguments.next().is_some() {
                return Err(HostError::Usage);
            }
            Ok(HostCommand::InitRegistry(PathBuf::from(path)))
        }
        "relocate-workspace" => {
            let plan = arguments.next().ok_or(HostError::Usage)?;
            if arguments.next().is_some() {
                return Err(HostError::Usage);
            }
            Ok(HostCommand::RelocateWorkspace(PathBuf::from(plan)))
        }
        PACKAGE_V_SUBCOMMAND => {
            let manifest = arguments.next().ok_or(HostError::Usage)?;
            if arguments.next().is_some() || manifest != PACKAGE_V_MANIFEST_NAME {
                return Err(HostError::Usage);
            }
            Ok(HostCommand::PackageVerify(PathBuf::from(manifest)))
        }
        _ => Err(HostError::Usage),
    }
}

fn package_verify_entrypoint(manifest: &Path) -> Result<(), HostError> {
    let capability =
        PackageVExecutableCapability::prepare_current().map_err(|_| HostError::PackageVRejected)?;
    capability
        .revalidate()
        .map_err(|_| HostError::PackageVRejected)?;
    let root = env::current_dir().map_err(|_| HostError::PackageVRejected)?;
    let result = match validate_package_root(&root, manifest) {
        Ok(result) => result,
        Err(_) => PackageVResult::invalid("PackageV structural validation failed"),
    };
    let valid = result.valid();
    let output = result
        .to_json_bytes()
        .map_err(|_| HostError::PackageVRejected)?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|_| HostError::PackageVRejected)?;
    std::io::stdout()
        .write_all(b"\n")
        .map_err(|_| HostError::PackageVRejected)?;
    if valid {
        Ok(())
    } else {
        Err(HostError::PackageVRejected)
    }
}

/// Create-or-open the Global Registry at the exact absolute path, then exit.
/// This is the standalone bootstrap step for an empty state volume; `serve`
/// itself stays fail-closed on a missing registry.
fn init_registry_entrypoint(path: &Path) -> Result<(), HostError> {
    if !path.is_absolute() {
        return Err(HostError::RegistryInitPathNotAbsolute);
    }
    drop(GlobalRegistry::open(path).map_err(|_| HostError::RegistryInit)?);
    println!("{}", path.display());
    Ok(())
}

fn serve_entrypoint(config_path: &Path) -> Result<(), HostError> {
    let config = read_config(config_path)?;
    validate_config_paths(&config)?;
    let api_secret = read_secret(&config.api_bearer_file, "api bearer file")?;
    let session_secret = read_secret(&config.session_bearer_file, "session bearer file")?;
    if api_secret == session_secret {
        return Err(HostError::CredentialReuse);
    }

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| HostError::Runtime)?;
    let host = bootstrap_host(&runtime, &config, api_secret, session_secret)?;
    runtime.block_on(run_host(host))
}

fn read_config(path: &Path) -> Result<HostConfig, HostError> {
    let bytes = read_bounded(path, MAX_CONFIG_BYTES, None)?;
    serde_json::from_slice(&bytes).map_err(|_| HostError::ConfigMalformed)
}

fn read_secret(path: &Path, field: &'static str) -> Result<String, HostError> {
    let bytes = read_bounded(path, MAX_SECRET_BYTES, Some(field))?;
    let secret = String::from_utf8(bytes).map_err(|_| HostError::SecretEncoding(field))?;
    let normalized = match secret.strip_suffix("\r\n") {
        Some(value) => value,
        None => match secret.strip_suffix('\n') {
            Some(value) => value,
            None => secret.as_str(),
        },
    };
    if normalized.is_empty() {
        return Err(HostError::SecretEmpty(field));
    }
    if normalized.contains(['\r', '\n']) {
        return Err(HostError::SecretMalformed(field));
    }
    Ok(normalized.to_owned())
}

fn read_bounded(
    path: &Path,
    limit: usize,
    secret_field: Option<&'static str>,
) -> Result<Vec<u8>, HostError> {
    let file = File::open(path)
        .map_err(|_| secret_field.map_or(HostError::ConfigRead, HostError::SecretRead))?;
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(HostError::ConfigRead)?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| secret_field.map_or(HostError::ConfigRead, HostError::SecretRead))?;
    if bytes.len() > limit {
        return Err(secret_field.map_or(HostError::ConfigRead, HostError::SecretRead));
    }
    Ok(bytes)
}

fn validate_config_paths(config: &HostConfig) -> Result<(), HostError> {
    if config.destination_id.is_nil() {
        return Err(HostError::BackendConfig);
    }
    if !config.product_cache_root.is_absolute() {
        return Err(HostError::ConfigPathNotAbsolute("product_cache_root"));
    }
    if !config.registry_path.is_absolute() {
        return Err(HostError::ConfigPathNotAbsolute("registry_path"));
    }
    if !config.api_bearer_file.is_absolute() {
        return Err(HostError::ConfigPathNotAbsolute("api_bearer_file"));
    }
    if !config.session_bearer_file.is_absolute() {
        return Err(HostError::ConfigPathNotAbsolute("session_bearer_file"));
    }
    Ok(())
}

fn acquire_registry_owner(
    registry_path: &Path,
) -> Result<(forge_backend::ServeFence, GlobalRegistry), HostError> {
    let serve_fence = forge_backend::serve_fence::ServeFence::acquire(registry_path).map_err(
        |error| match error {
            forge_backend::serve_fence::ServeFenceError::Busy { .. } => HostError::ServeFenceBusy,
            _ => HostError::ServeFenceUnavailable,
        },
    )?;
    relocation::ensure_complete(registry_path).map_err(HostError::Relocation)?;
    let registry =
        GlobalRegistry::open_existing(registry_path).map_err(|_| HostError::RegistryUnavailable)?;
    Ok((serve_fence, registry))
}

fn acquire_registry_owner_and_prepare_activity_supervisor(
    registry_path: &Path,
    supervision: Option<&host_activity_leases::HostActivityLeaseSupervisionConfig>,
) -> Result<
    (
        forge_backend::ServeFence,
        GlobalRegistry,
        Option<host_activity_leases::PreparedHostActivityLeaseSupervisor>,
    ),
    HostError,
> {
    // This performs filesystem validation only. No journal directory or file
    // is opened until the exclusive Registry owner is confirmed below.
    host_activity_leases::PreparedHostActivityLeaseSupervisor::validate_config(
        supervision,
        registry_path,
    )
    .map_err(|_| HostError::ActivityLeaseSupervisorConfiguration)?;
    let (serve_fence, registry) = acquire_registry_owner(registry_path)?;
    let prepared = host_activity_leases::PreparedHostActivityLeaseSupervisor::prepare(
        supervision,
        registry_path,
    )
    .map_err(|error| match error {
        host_activity_leases::SupervisorError::Configuration => {
            HostError::ActivityLeaseSupervisorConfiguration
        }
        host_activity_leases::SupervisorError::Journal
        | host_activity_leases::SupervisorError::Clock
        | host_activity_leases::SupervisorError::ControlWorker
        | host_activity_leases::SupervisorError::UnexpectedExit => {
            HostError::ActivityLeaseSupervisorJournal
        }
    })?;
    Ok((serve_fence, registry, prepared))
}

fn bootstrap_host(
    runtime: &tokio::runtime::Runtime,
    config: &HostConfig,
    mut api_secret: String,
    session_secret: String,
) -> Result<RunningHost, HostError> {
    let backend_config = BackendConfig::new(
        config.listen.ip(),
        config.listen.port(),
        api_secret.as_str(),
        ForgeBackendId::from_uuid(config.backend_id),
        OrchestrationIssuerId::from_uuid(config.issuer_id),
    )
    .map_err(|_| HostError::BackendConfig)?;
    // Only the digest survives inside the backend configuration; clear the
    // caller-owned plaintext immediately after composition.
    api_secret.clear();
    drop(api_secret);

    let (serve_fence, registry, prepared_lease_supervisor) =
        acquire_registry_owner_and_prepare_activity_supervisor(
            &config.registry_path,
            config.activity_lease_supervision.as_ref(),
        )?;
    let boot_instance = RuntimeInstanceId::from_uuid(Uuid::now_v7());
    let service = StartedActivityLeaseResumeServiceIdentity::new(
        UnstartedActivityContinuationServiceIdentity::new(
            ForgeBackendId::from_uuid(config.backend_id),
            OrchestrationIssuerId::from_uuid(config.issuer_id),
            boot_instance,
        )
        .map_err(|_| HostError::BackendConfig)?,
        config.destination_id,
    )
    .map_err(|_| HostError::BackendConfig)?;
    let rust_ci_capability = prepare_host_toolchain(config, boot_instance)?;
    let workers = start_host_workers(
        runtime,
        config,
        session_secret,
        registry,
        rust_ci_capability,
    )?;

    // Crash recovery: classify executions and leases left unproven by a
    // previous process before this one admits new work. Per-Workspace
    // failures are reported and never block the other scopes.
    log_startup_recovery(&workers.control_client, boot_instance);

    let execution_client = workers.execution.client();
    let approval_client = workers.approval.client();
    let StartedHostWorkers {
        control_client,
        control_worker,
        lease_client,
        lease_worker,
        execution,
        approval,
    } = workers;
    let Ok(state) = forge_backend::http::assemble(
        backend_config,
        forge_backend::http::BackendClients {
            control: &control_client,
            execution: &execution_client,
            approval: &approval_client,
            activity_leases: &lease_client,
            runtime_instance_id: boot_instance.into_uuid(),
            product_cache_root: &config.product_cache_root,
            destination_id: config.destination_id,
        },
    ) else {
        cleanup_startup(
            Some(approval),
            Some(execution),
            Some(control_worker),
            Some(lease_worker),
        )?;
        return Err(HostError::BackendAssemble);
    };
    state.set_runtime_instance(boot_instance.into_uuid());
    let lease_supervisor = prepared_lease_supervisor.map(|prepared| {
        prepared.start(
            runtime.handle(),
            control_client.clone(),
            lease_client.clone(),
            boot_instance,
            service,
        )
    });
    let host = RunningHost {
        state,
        execution,
        approval,
        control_worker,
        lease_worker,
        lease_supervisor,
        serve_fence,
    };
    Ok(host)
}

fn start_host_workers(
    runtime: &tokio::runtime::Runtime,
    config: &HostConfig,
    mut session_secret: String,
    registry: GlobalRegistry,
    rust_ci_capability: Option<forge_execution::RustCiToolchainCapability>,
) -> Result<StartedHostWorkers, HostError> {
    let (control, lease_control) =
        prepare_control_pair(runtime, config, &session_secret, registry)?;
    session_secret.clear();
    drop(session_secret);
    let (control_client, control_worker) =
        ForgeControlWorker::start(control).map_err(|_| HostError::ControlWorkerStart)?;
    let Ok((lease_client, lease_worker)) = ForgeControlWorker::start_activity_lease(lease_control)
    else {
        cleanup_startup(None, None, Some(control_worker), None)?;
        return Err(HostError::LeaseWorkerStart);
    };
    let Ok(execution) = ForgeExecutionCoordinator::start_with_rust_ci_capability(
        control_client.clone(),
        EXECUTION_CAPACITY,
        rust_ci_capability,
    ) else {
        cleanup_startup(None, None, Some(control_worker), Some(lease_worker))?;
        return Err(HostError::ExecutionStart);
    };
    let execution_client = execution.client();
    let Ok(approval) =
        forge_control::ForgeApprovalCoordinator::start(control_client.clone(), execution_client)
    else {
        cleanup_startup(
            None,
            Some(execution),
            Some(control_worker),
            Some(lease_worker),
        )?;
        return Err(HostError::ApprovalStart);
    };
    Ok(StartedHostWorkers {
        control_client,
        control_worker,
        lease_client,
        lease_worker,
        execution,
        approval,
    })
}

fn log_startup_recovery(
    control: &forge_control::ForgeControlClient,
    boot_instance: RuntimeInstanceId,
) {
    let recovery = forge_backend::recovery::run_startup_recovery(control, boot_instance);
    let _ignored = writeln!(
        std::io::stderr(),
        "forge-backend startup recovery: locations {} workspaces {} classified activities {} executions {} busy {} conflicts {} failures {}",
        recovery.locations_scanned,
        recovery.workspaces_scanned,
        recovery.classified_activities,
        recovery.classified_executions,
        recovery.busy_workspaces,
        recovery.conflicts,
        recovery.failures.len(),
    );
    for failure in &recovery.failures {
        let _ignored = writeln!(
            std::io::stderr(),
            "forge-backend startup recovery failure: {failure}"
        );
    }
}

fn prepare_control_pair(
    runtime: &tokio::runtime::Runtime,
    config: &HostConfig,
    session_secret: &str,
    registry: GlobalRegistry,
) -> Result<(ForgeControl, ForgeControl), HostError> {
    let remote_authority = RemoteAgentSessionAuthority::new(
        runtime.handle().clone(),
        config.session_authority,
        session_secret,
        REMOTE_AUTHORITY_TIMEOUT,
    )
    .map_err(|_| HostError::RemoteAuthority)?;
    let lease_registry = GlobalRegistry::open_existing(&config.registry_path)
        .map_err(|_| HostError::RegistryUnavailable)?;
    let lease_authority = RemoteAgentSessionAuthority::new(
        runtime.handle().clone(),
        config.session_authority,
        session_secret,
        REMOTE_AUTHORITY_TIMEOUT,
    )
    .map_err(|_| HostError::RemoteAuthority)?;
    Ok((
        ForgeControl::with_session_authority(
            LocationService::new(registry),
            Box::new(remote_authority),
        ),
        ForgeControl::with_session_authority(
            LocationService::new(lease_registry),
            Box::new(lease_authority),
        ),
    ))
}

fn prepare_host_toolchain(
    config: &HostConfig,
    boot_instance: RuntimeInstanceId,
) -> Result<Option<forge_execution::RustCiToolchainCapability>, HostError> {
    let Some(configuration) = config.rust_ci.as_ref() else {
        return Ok(None);
    };
    let prepared =
        host_toolchain::prepare(configuration, &config.product_cache_root, boot_instance)
            .map_err(HostError::HostToolchain)?;
    let _ignored = writeln!(
        std::io::stderr(),
        "forge-backend Rust CI storage: {:?}; failed SSD attempts {}",
        prepared.selection,
        prepared.ssd_failures
    );
    Ok(Some(prepared.capability))
}

async fn run_host(mut host: RunningHost) -> Result<(), HostError> {
    let Ok(address) = serve(host.state.clone()).await else {
        host.shutdown(SHUTDOWN_OBSERVATION_BUDGET)
            .await
            .map_err(|_| HostError::StartupCleanupIncomplete)?;
        return Err(HostError::BackendServe);
    };
    println!("{address}");

    // SIGINT (Ctrl-C) and SIGTERM both observe the same fixed shutdown order;
    // SIGTERM is what container runtimes send on stop.
    let termination = if let Some(supervisor) = host.lease_supervisor.as_mut() {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => HostTermination::Signal(signal),
            signal = terminate_signal() => HostTermination::Signal(signal),
            error = supervisor.wait_for_failure() => HostTermination::LeaseSupervisor(error),
        }
    } else {
        let signal = tokio::select! {
            signal = tokio::signal::ctrl_c() => signal,
            signal = terminate_signal() => signal,
        };
        HostTermination::Signal(signal)
    };
    let cleanup = host.shutdown(SHUTDOWN_OBSERVATION_BUDGET).await;
    cleanup?;
    match termination {
        HostTermination::Signal(signal) => signal.map_err(|_| HostError::Signal),
        HostTermination::LeaseSupervisor(error) => {
            Err(HostError::ActivityLeaseSupervisorFailed(error))
        }
    }
}

async fn terminate_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    terminate.recv().await;
    Ok(())
}

fn cleanup_startup(
    approval: Option<forge_control::ForgeApprovalCoordinator>,
    execution: Option<ForgeExecutionCoordinator>,
    control_worker: Option<ForgeControlWorker>,
    lease_worker: Option<ForgeControlWorker>,
) -> Result<(), HostError> {
    let approval_result = match approval {
        Some(mut approval) => approval
            .shutdown()
            .map(|_| ())
            .map_err(|_| HostError::ApprovalShutdown),
        None => Ok(()),
    };
    let execution_result = match execution {
        Some(mut execution) => execution
            .shutdown()
            .map(|_| ())
            .map_err(|_| HostError::ExecutionShutdown),
        None => Ok(()),
    };
    let control_result = match control_worker {
        Some(mut worker) => match worker.shutdown_owned(Vec::new()) {
            Ok(report)
                if report.failures().is_empty() && report.committed_but_unconfirmed() == 0 =>
            {
                Ok(())
            }
            Ok(_) => Err(HostError::ControlShutdownIncomplete),
            Err(_) => Err(HostError::ControlWorkerShutdown),
        },
        None => Ok(()),
    };
    let lease_result = match lease_worker {
        Some(mut worker) => match worker.shutdown_owned(Vec::new()) {
            Ok(report)
                if report.failures().is_empty() && report.committed_but_unconfirmed() == 0 =>
            {
                Ok(())
            }
            _ => Err(HostError::LeaseWorkerShutdown),
        },
        None => Ok(()),
    };
    if approval_result.is_err()
        || execution_result.is_err()
        || control_result.is_err()
        || lease_result.is_err()
    {
        return Err(HostError::StartupCleanupIncomplete);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{HostConfig, await_shutdown_worker};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    #[test]
    fn legacy_host_config_defaults_activity_supervision_off() -> Result<(), Box<dyn Error>> {
        let config: HostConfig = serde_json::from_str(
            r#"{
                "listen":"127.0.0.1:0",
                "registry_path":"/tmp/registry.sqlite3",
                "product_cache_root":"/tmp/product-cache",
                "backend_id":"00000000-0000-7000-8000-000000000001",
                "issuer_id":"00000000-0000-7000-8000-000000000002",
                "destination_id":"00000000-0000-7000-8000-000000000003",
                "api_bearer_file":"/tmp/api-token",
                "session_authority":"127.0.0.1:9101",
                "session_bearer_file":"/tmp/session-token"
            }"#,
        )?;
        assert!(config.activity_lease_supervision.is_none());
        Ok(())
    }

    #[derive(Debug)]
    struct FenceDropProbe {
        registry: std::path::PathBuf,
        held: Arc<AtomicBool>,
        report: forge_backend::BridgeDrainReport,
    }

    impl Drop for FenceDropProbe {
        fn drop(&mut self) {
            self.held.store(
                matches!(
                    forge_backend::ServeFence::acquire(&self.registry),
                    Err(forge_backend::ServeFenceError::Busy { .. })
                ),
                Ordering::Release,
            );
        }
    }

    impl forge_backend::CommandExecutor for FenceDropProbe {
        fn submit(
            &self,
            _: forge_backend::Command,
        ) -> Result<
            tokio::sync::oneshot::Receiver<forge_backend::BridgeOutcome>,
            forge_backend::ForgeError,
        > {
            Err(forge_backend::ForgeError::invalid_input(
                "drop probe admits no commands",
            ))
        }
        fn inflight(&self) -> usize {
            0
        }
        fn drain_and_join(&self, _: Duration) -> forge_backend::BridgeDrainReport {
            self.report
        }
    }

    async fn check_host_fence_drop(failed_bridge: bool) -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("forge-host-fence-drop-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let registry = root.join("registry.sqlite3");
        let (control, worker) = forge_control::ForgeControlWorker::start(
            forge_control::ForgeControl::new(forge_persistence::GlobalRegistry::open(&registry)?),
        )?;
        let (_lease_client, lease_worker) =
            forge_control::ForgeControlWorker::start_activity_lease(
                forge_control::ForgeControl::new(forge_persistence::GlobalRegistry::open_existing(
                    &registry,
                )?),
            )?;
        let execution = forge_control::ForgeExecutionCoordinator::start(control.clone(), 2)?;
        let approval =
            forge_control::ForgeApprovalCoordinator::start(control.clone(), execution.client())?;
        let held = Arc::new(AtomicBool::new(false));
        let executor = FenceDropProbe {
            registry: registry.clone(),
            held: Arc::clone(&held),
            report: forge_backend::BridgeDrainReport {
                worker_panics: usize::from(failed_bridge),
                ..forge_backend::BridgeDrainReport::default()
            },
        };
        let config = forge_backend::BackendConfig::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            0,
            "host-fence-drop-test",
            forge_domain::ForgeBackendId::from_uuid(uuid::Uuid::now_v7()),
            forge_domain::OrchestrationIssuerId::from_uuid(uuid::Uuid::now_v7()),
        )?;
        let state = forge_backend::AppState::new(
            config,
            Arc::new(executor),
            Arc::new(forge_backend::events::ControlEventQuery::new(control)),
        );
        let host = super::RunningHost {
            state,
            execution,
            approval,
            control_worker: worker,
            lease_worker,
            lease_supervisor: None,
            serve_fence: forge_backend::ServeFence::acquire(&registry)?,
        };
        let result = host.shutdown(Duration::from_secs(1)).await;
        assert_eq!(result.is_err(), failed_bridge);
        assert!(
            held.load(Ordering::Acquire),
            "state must drop while Registry remains exclusively fenced"
        );
        drop(forge_backend::ServeFence::acquire(&registry)?);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn host_shutdown_retains_fence_through_state_drop_on_success_and_error()
    -> Result<(), Box<dyn std::error::Error>> {
        check_host_fence_drop(false).await?;
        check_host_fence_drop(true).await
    }

    #[tokio::test]
    async fn shutdown_observation_timeout_retains_worker_until_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let (release, blocked) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::spawn(blocked);
        let mut shutdown = Box::pin(await_shutdown_worker(
            worker,
            "controlled worker",
            Duration::ZERO,
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut shutdown)
                .await
                .is_err()
        );
        release
            .send(())
            .map_err(|()| "shutdown dropped the owned worker")?;
        shutdown.await??;
        Ok(())
    }
}
