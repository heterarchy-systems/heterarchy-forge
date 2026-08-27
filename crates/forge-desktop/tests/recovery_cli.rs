use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::{
    ActivityId, ActivityState, BeginExecution, BootstrapActivity, EstablishWorkspace,
    ExecutionAttribution, ExecutionId, ExecutionKind, ExecutionLimits, ExecutionOutputLimit,
    ExecutionPermissions, ExecutionProgram, ExecutionRequest, ExecutionRequestDigest,
    ExecutionState, ExecutionTimeoutMillis, LocationId, RuntimeInstanceId, TimestampMillis,
    WorkspaceId, WorkspaceRevision, WorkspaceRoot,
};
use forge_persistence::{GlobalRegistry, WorkspaceStore};
use forge_workspace::{LocationService, WorkspaceStateLayout};
use uuid::Uuid;

struct RecoveryCliFixture {
    root: PathBuf,
    home: PathBuf,
    registry_path: PathBuf,
    workspace_root: PathBuf,
    activity_id: ActivityId,
    execution_id: ExecutionId,
}

fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(TimestampMillis::new(i64::try_from(elapsed.as_millis())?)?)
}

fn fixture() -> Result<RecoveryCliFixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-desktop-recovery-cli-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let home = root.join("home");
    let location_root = root.join("location");
    let workspace_root = location_root.join("workspace");
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&workspace_root)?;
    let registry_path = root.join("registry.sqlite3");
    let now = timestamp_now()?;
    let location_id = LocationId::from_uuid(Uuid::now_v7());
    let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
    locations.register_selected_path(location_id, "Recovery CLI", &location_root, now)?;
    drop(locations);

    let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
    let activity_id = ActivityId::from_uuid(Uuid::now_v7());
    let execution_id = ExecutionId::from_uuid(Uuid::now_v7());
    let mut store = WorkspaceStore::open(
        &layout,
        EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            now,
        ),
    )?;
    let expired_until = TimestampMillis::new(now.get().saturating_sub(1_000))?;
    let started_at = TimestampMillis::new(now.get().saturating_sub(2_000))?;
    store.bootstrap_activity(&BootstrapActivity::new(
        activity_id,
        workspace_id,
        WorkspaceRevision::INITIAL,
        RuntimeInstanceId::from_uuid(Uuid::now_v7()),
        expired_until,
        started_at,
    ))?;
    let request = ExecutionRequest::new(
        ExecutionAttribution::new(execution_id, workspace_id, activity_id),
        ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
            arguments: Vec::new(),
        },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(1_000)?,
            ExecutionOutputLimit::new(16)?,
        ),
        ExecutionPermissions::new(true, false, false),
    )?;
    let started = store.begin_execution(&BeginExecution::from_request(
        &request,
        ExecutionRequestDigest::from_bytes([0x40; 32]),
        now,
    ))?;
    assert_eq!(started.record().id(), execution_id);
    drop(store);

    Ok(RecoveryCliFixture {
        root,
        home,
        registry_path,
        workspace_root: std::fs::canonicalize(workspace_root)?,
        activity_id,
        execution_id,
    })
}

fn desktop_command(fixture: &RecoveryCliFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_forge-desktop"));
    command
        .env("HOME", &fixture.home)
        .env("HETERARCHY_FORGE_REGISTRY_PATH", &fixture.registry_path)
        .env("RUST_LOG", "off")
        .stdin(Stdio::null());
    command
}

fn output_text(output: &Output) -> Result<&str, std::str::Utf8Error> {
    std::str::from_utf8(&output.stdout)
}

fn assert_stale_state(fixture: &RecoveryCliFixture) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let activity = store
        .get_activity(fixture.activity_id)?
        .ok_or("seeded Activity missing")?;
    let execution = store
        .get_execution(fixture.execution_id)?
        .ok_or("seeded Execution missing")?;
    assert_eq!(activity.state(), ActivityState::Open);
    assert_eq!(execution.state(), ExecutionState::Starting);
    Ok(())
}

fn assert_recovered_state(fixture: &RecoveryCliFixture) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("Workspace layout missing after recovery")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let activity = store
        .get_activity(fixture.activity_id)?
        .ok_or("recovered Activity missing")?;
    let execution = store
        .get_execution(fixture.execution_id)?
        .ok_or("recovered Execution missing")?;
    assert_eq!(activity.state(), ActivityState::Interrupted);
    assert_eq!(execution.state(), ExecutionState::Interrupted);
    assert!(store.get_recovery_maintenance_lease()?.is_released());
    Ok(())
}

#[test]
fn desktop_doctor_is_observational_and_explicit_recovery_cli_is_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    assert_stale_state(&fixture)?;

    let doctor = desktop_command(&fixture).arg("--doctor").output()?;
    assert!(doctor.status.success());
    let doctor_stdout = output_text(&doctor)?;
    assert!(
        doctor_stdout
            .lines()
            .any(|line| line == "Heterarchy Forge doctor: PASS")
    );
    assert!(
        doctor_stdout
            .lines()
            .any(|line| line == "registry_health=PASS")
    );
    assert_stale_state(&fixture)?;

    let recovery = desktop_command(&fixture)
        .arg("--recover-workspace")
        .arg(&fixture.workspace_root)
        .output()?;
    assert!(recovery.status.success());
    let recovery_stdout = output_text(&recovery)?;
    for expected in [
        "recovery_outcome=COMPLETED",
        "activities_classified=1",
        "executions_classified=1",
        "binding_confirmed=true",
        "release_uncertain=false",
    ] {
        assert!(recovery_stdout.lines().any(|line| line == expected));
    }
    assert_recovered_state(&fixture)?;

    let retry = desktop_command(&fixture)
        .arg("--recover-workspace")
        .arg(&fixture.workspace_root)
        .output()?;
    assert!(retry.status.success());
    let retry_stdout = output_text(&retry)?;
    assert!(
        retry_stdout
            .lines()
            .any(|line| line == "recovery_outcome=COMPLETED")
    );
    assert!(
        retry_stdout
            .lines()
            .any(|line| line == "activities_classified=0")
    );
    assert!(
        retry_stdout
            .lines()
            .any(|line| line == "executions_classified=0")
    );
    assert_recovered_state(&fixture)?;

    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}
