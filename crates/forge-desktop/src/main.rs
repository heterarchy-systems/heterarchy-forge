use std::cell::Cell;
use std::env;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak as RcWeak};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_control::{
    ActivityLiveness, ActivityProjection, ControlClientError, DiffListRequest, DiffListResult,
    DiffReadRequest, DiffReadResult, ForgeApprovalCoordinator, ForgeApprovalCoordinatorClient,
    ForgeApprovalCoordinatorError, ForgeControl, ForgeControlClient, ForgeControlWorker,
    ForgeExecutionCoordinator, ForgeExecutionCoordinatorError, HarnessLibrary, PendingApproval,
    PendingApprovalProjection, PendingControl, ResolvedWorkspaceScope, WorkspaceActivityProjection,
    WorkspaceActivityProjectionRequest, WorkspaceLocator,
};
use forge_domain::{
    ActivityId, ActivityListLimit, ActivityState, ApprovalRequestId, DiffArtifactHealth,
    DiffChangeKind, DiffEvidenceState, DiffId, DiffListLimit, DiffRenderKind, LocationId,
    LocationIdParseError, LocationName, LocationRevision, LocationState, RegisteredDiffEvidence,
    RegisteredWorkspace, RuntimeCommand, RuntimePhase, RuntimeProjection, TimestampMillis,
    TimestampMillisError, WorkspaceId, WorkspaceRevision,
};
use forge_persistence::{
    GlobalRegistry, HarnessCatalog, HarnessCatalogError, RegistryError, RegistryHealth,
    WorkspaceStore, WorkspaceStoreError,
};
use forge_platform::{
    AppPathError, AppPaths, FolderPickerError, FolderSelection, LoggingError, init_logging,
    pick_folder,
};
use forge_runtime::{
    RuntimeClient, RuntimeEventStream, RuntimeService, RuntimeServiceError, RuntimeStopParticipant,
    RuntimeStopParticipantError,
};
use forge_ui::{
    AboutWindow, ActivityRow, AppWindow, ApprovalRow, DiffRow, ForgeTray, LocationRow, WorkspaceRow,
};
use forge_workspace::{
    LocationRepositoryError, LocationService, LocationServiceError, StateLayoutError,
    WorkspaceCandidateKey, WorkspaceCandidateKind, WorkspaceDiscoveryError,
    WorkspaceKeyResolveError, WorkspaceLocatorError, WorkspaceStateLayout, diff_path_label,
};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};
use thiserror::Error;
use tracing::{error, info};
use uuid::Uuid;

mod dag_ui;
mod doctor_ui;
mod goal_ui;
mod harness_ui;
mod harness_worker;
pub mod location_worker;

use dag_ui::{UiDagIntent, bind_dag_actions, start_dag_pump};
use doctor_ui::{UiDoctorIntent, bind_doctor_actions, reset_doctor_projection, start_doctor_pump};
use goal_ui::{UiGoalIntent, bind_goal_actions, start_goal_pump};
use harness_ui::{UiHarnessIntent, bind_harness_actions, start_harness_pump};
use harness_worker::{HarnessLibraryClient, HarnessLibraryWorker, HarnessWorkerError};
use location_worker::{
    LocationAction, LocationOutcome, LocationServiceClient, LocationServiceWorker,
    LocationWorkerError, PendingRequest,
};

const DOCTOR_TIMEOUT: Duration = Duration::from_secs(5);
const REGISTRY_PATH_ENV: &str = "HETERARCHY_FORGE_REGISTRY_PATH";

#[derive(Debug)]
struct DesktopApprovalStop(ForgeApprovalCoordinatorClient);

impl RuntimeStopParticipant for DesktopApprovalStop {
    fn stop_and_drain(&self) -> Result<(), RuntimeStopParticipantError> {
        self.0
            .emergency_stop()
            .map(|_| ())
            .map_err(|_| RuntimeStopParticipantError::DrainFailed)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Heterarchy Forge failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    let paths = AppPaths::discover()?;
    let registry_path = registry_path(&paths);
    let arguments: Vec<std::ffi::OsString> = env::args_os().collect();
    if arguments.iter().any(|argument| argument == "--doctor") {
        let registry_health = GlobalRegistry::inspect_existing_read_only(&registry_path)?;
        return run_doctor(&paths, registry_health);
    }
    if let Some(target) = recover_workspace_argument(&arguments)? {
        let summary = run_recovery_entry(&registry_path, &target)?;
        print_recovery_summary(&summary);
        return Ok(());
    }

    paths.ensure_exists()?;
    let _logging_guard = init_logging(&paths)?;
    let services = bootstrap_services(&paths)?;

    run_application(&paths, services)
}

const RECOVERY_WORKSPACE_FLAG: &str = "--recover-workspace";
const RECOVERY_LEASE_DURATION_MILLIS: i64 = 30_000;

/// Extract an explicit operator-requested recovery target.
///
/// The flag never appears implicitly: exactly one occurrence followed by
/// exactly one path value is accepted, and normal boot ignores it entirely.
fn recover_workspace_argument(
    arguments: &[std::ffi::OsString],
) -> Result<Option<PathBuf>, AppError> {
    let mut found: Option<PathBuf> = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == std::ffi::OsStr::new(RECOVERY_WORKSPACE_FLAG) {
            if found.is_some() {
                return Err(AppError::RecoveryArguments);
            }
            let value = arguments
                .get(index + 1)
                .ok_or(AppError::RecoveryArguments)?;
            if value == std::ffi::OsStr::new("--doctor")
                || value == std::ffi::OsStr::new(RECOVERY_WORKSPACE_FLAG)
            {
                return Err(AppError::RecoveryArguments);
            }
            found = Some(PathBuf::from(value));
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(found)
}

/// Bounded redacted summary of one explicit recovery-maintenance entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryRunSummary {
    outcome: forge_control::RecoveryMaintenanceOutcome,
    classified_activities: usize,
    classified_executions: usize,
    binding_confirmed: bool,
    release_uncertain: bool,
}

/// Explicit trusted-local recovery surface.
///
/// This is only reachable through `--recover-workspace <PATH>`; boot, Doctor,
/// and every read path never invoke it.  The target must resolve to exactly
/// one registered ready Workspace by exact canonical root equality; identity
/// is never created or inferred here.
fn run_recovery_entry(
    registry_path: &Path,
    workspace_path: &Path,
) -> Result<RecoveryRunSummary, AppError> {
    use forge_control::{RecoveryLeaseDurationMillis, RecoveryMaintenanceRequest};
    use forge_domain::{ExecutionListLimit, RuntimeInstanceId};

    let canonical_target =
        std::fs::canonicalize(workspace_path).map_err(|_| AppError::RecoveryTargetNotFound)?;
    let locations_service = LocationService::new(GlobalRegistry::open(registry_path)?);
    let listed = locations_service.list_locations(forge_domain::LocationListLimit::DEFAULT)?;

    let mut matches: Vec<(LocationId, LocationRevision, WorkspaceLocator)> = Vec::new();
    for location in listed {
        let discovery = locations_service.discover_current(location.id(), location.revision())?;
        for candidate in discovery.candidates() {
            if candidate.absolute_root() != canonical_target {
                continue;
            }
            let Some(layout) = WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
                .map_err(AppError::StateLayout)?
            else {
                continue;
            };
            let workspace = WorkspaceStore::inspect_existing_read_only(&layout)?;
            if workspace.root().as_path() != canonical_target {
                continue;
            }
            matches.push((
                location.id(),
                location.revision(),
                candidate.key().locator(location.revision())?,
            ));
        }
    }
    let [resolved] = matches.as_slice() else {
        return Err(AppError::RecoveryTargetNotFound);
    };
    let (location_id, location_revision, locator) = (resolved.0, resolved.1, &resolved.2);

    let control = ForgeControl::with_location_service(locations_service);
    let scope = control.resolve_workspace(location_id, location_revision, locator)?;
    let observed_at = observed_timestamp_now().map_err(AppError::RecoveryClock)?;
    let request = RecoveryMaintenanceRequest {
        scope,
        owner_id: RuntimeInstanceId::from_uuid(Uuid::now_v7()),
        duration: RecoveryLeaseDurationMillis::new(RECOVERY_LEASE_DURATION_MILLIS)
            .map_err(|_| AppError::RecoveryArguments)?,
        claimed_at: observed_at,
        classify_at: observed_at,
        activity_limit: ActivityListLimit::DEFAULT,
        execution_limit: ExecutionListLimit::DEFAULT,
    };
    let report = control.run_recovery_maintenance(&request)?;
    Ok(RecoveryRunSummary {
        outcome: report.outcome(),
        classified_activities: report.reconciled_activities().len(),
        classified_executions: report.reconciled_executions().len(),
        binding_confirmed: report.binding_confirmed(),
        release_uncertain: report.release_uncertain(),
    })
}

fn print_recovery_summary(summary: &RecoveryRunSummary) {
    let outcome = match summary.outcome {
        forge_control::RecoveryMaintenanceOutcome::Completed => "COMPLETED",
        forge_control::RecoveryMaintenanceOutcome::Busy => "BUSY",
        forge_control::RecoveryMaintenanceOutcome::ClaimConflict => "CLAIM_CONFLICT",
    };
    println!("recovery_outcome={outcome}");
    println!("activities_classified={}", summary.classified_activities);
    println!("executions_classified={}", summary.classified_executions);
    println!("binding_confirmed={}", summary.binding_confirmed);
    println!("release_uncertain={}", summary.release_uncertain);
}

fn bootstrap_services(paths: &AppPaths) -> Result<ApplicationServices, AppError> {
    bootstrap_registry(registry_path(paths))
}

fn registry_path(paths: &AppPaths) -> PathBuf {
    env::var_os(REGISTRY_PATH_ENV).map_or_else(|| paths.global_registry_path(), PathBuf::from)
}

#[derive(Debug)]
struct ApplicationServices {
    location_service: LocationService<GlobalRegistry>,
    registry_health: RegistryHealth,
}

struct DesktopPumpServices {
    location: LocationServiceClient,
    activity: ForgeControlClient,
    approval: ForgeApprovalCoordinatorClient,
    harness: HarnessLibraryClient,
    diagnostics_dir: PathBuf,
}

struct UiChannelBundle {
    location_intents: Receiver<UiLocationIntent>,
    location_sinks: LocationUiSinks,
    activity_intents: Receiver<UiActivityIntent>,
    approval_intents: Receiver<UiApprovalIntent>,
    goal_intents: Receiver<UiGoalIntent>,
    dag_intents: Receiver<UiDagIntent>,
    doctor_intents: Receiver<UiDoctorIntent>,
    harness_intents: Receiver<UiHarnessIntent>,
    location_busy: Rc<Cell<bool>>,
    activity_busy: Rc<Cell<bool>>,
    approval_busy: Rc<Cell<bool>>,
    goal_busy: Rc<Cell<bool>>,
    dag_busy: Rc<Cell<bool>>,
    harness_busy: Rc<Cell<bool>>,
}

struct DesktopPumps {
    projection: Rc<Timer>,
    location: Rc<Timer>,
    activity: Rc<Timer>,
    goal: Rc<Timer>,
    dag: Rc<Timer>,
    doctor: Rc<Timer>,
    approval: Rc<Timer>,
    harness: Rc<Timer>,
}

impl DesktopPumps {
    fn stop(self) {
        let Self {
            projection,
            location,
            activity,
            goal,
            dag,
            doctor,
            approval,
            harness,
        } = self;
        drop((
            projection, location, activity, goal, dag, doctor, approval, harness,
        ));
    }
}

#[derive(Debug)]
enum UiLocationIntent {
    Register(LocationAction),
    Refresh,
    Discover {
        id: LocationId,
        expected_revision: LocationRevision,
    },
    SelectWorkspace(i32),
}

#[derive(Debug, Clone, Copy)]
enum PendingLocationAction {
    StartupList,
    RefreshList,
    Register,
    PostRegisterList,
    Discover {
        id: LocationId,
        expected_revision: LocationRevision,
    },
    SelectWorkspace {
        index: i32,
    },
}

/// Exact durable scope captured only after a Workspace selection commit.
///
/// The locator is reconstructed from the controller-owned candidate key and
/// the Location revision observed by discovery.  The returned Workspace
/// identity and revision are carried separately so an Activity refresh can
/// never silently fall back to another Workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActivityWorkspaceScope {
    location_id: LocationId,
    location_revision: LocationRevision,
    locator: WorkspaceLocator,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
}

#[derive(Debug)]
enum UiActivityIntent {
    WorkspaceSelected(Option<ActivityWorkspaceScope>),
    Refresh,
    SelectActivity(ActivityId),
    ViewDiff(DiffId),
    CloseDiff,
}

#[derive(Debug)]
enum UiApprovalIntent {
    WorkspaceSelected(Option<ActivityWorkspaceScope>),
    Refresh,
    Approve(ApprovalRequestId),
    Reject(ApprovalRequestId),
    SetAutoApproval(bool),
    StopWorkspace,
    EmergencyStop,
}

#[derive(Clone)]
struct LocationUiSinks {
    activity: SyncSender<UiActivityIntent>,
    approval: SyncSender<UiApprovalIntent>,
    goal: SyncSender<UiGoalIntent>,
    dag: SyncSender<UiDagIntent>,
    doctor: SyncSender<UiDoctorIntent>,
    harness: SyncSender<UiHarnessIntent>,
}

/// Immutable candidate identity captured from one Location discovery.
///
/// The Slint model contains only display rows. These native-path keys and the
/// Location revision stay owned by the controller until a worker reply commits
/// a selection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceCandidateSnapshot {
    key: WorkspaceCandidateKey,
    location_id: LocationId,
    location_revision: LocationRevision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceSelectionProjection {
    id: String,
    revision: String,
    root: String,
}

impl From<&RegisteredWorkspace> for WorkspaceSelectionProjection {
    fn from(workspace: &RegisteredWorkspace) -> Self {
        Self {
            id: workspace.id().to_string(),
            revision: workspace.revision().get().to_string(),
            root: workspace.root().as_path().to_string_lossy().into_owned(),
        }
    }
}

#[derive(Debug, Error)]
enum UiLocationPreparationError {
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampMillisError),
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
    #[error("system timestamp does not fit in signed milliseconds")]
    TimestampOverflow,
}

#[derive(Debug, Error, PartialEq, Eq)]
enum UiLocationAdmissionError {
    #[error("another Location action is already pending")]
    Busy,
    #[error("Location action queue is full")]
    QueueFull,
}

#[derive(Debug, Error)]
enum UiDiscoverTargetError {
    #[error("invalid Location id")]
    Id(#[source] LocationIdParseError),
    #[error("invalid Location revision")]
    RevisionParse(#[source] std::num::ParseIntError),
    #[error(transparent)]
    RevisionValue(#[from] forge_domain::LocationRevisionError),
}

#[derive(Debug, Error)]
enum ActivityWorkspaceScopeError {
    #[error("durable Workspace belongs to a different Location")]
    LocationMismatch,
    #[error(transparent)]
    Locator(#[from] WorkspaceLocatorError),
}

struct LocationUiController {
    app: AppWindow,
    client: LocationServiceClient,
    intents: Receiver<UiLocationIntent>,
    activity_intents: SyncSender<UiActivityIntent>,
    approval_intents: SyncSender<UiApprovalIntent>,
    goal_intents: SyncSender<UiGoalIntent>,
    dag_intents: SyncSender<UiDagIntent>,
    doctor_intents: SyncSender<UiDoctorIntent>,
    harness_intents: SyncSender<UiHarnessIntent>,
    busy: Rc<Cell<bool>>,
    pending: Option<PendingRequest>,
    pending_action: Option<PendingLocationAction>,
    workspace_candidates: Vec<WorkspaceCandidateSnapshot>,
}

impl LocationUiController {
    fn new(
        app: AppWindow,
        client: LocationServiceClient,
        intents: Receiver<UiLocationIntent>,
        sinks: LocationUiSinks,
        busy: Rc<Cell<bool>>,
    ) -> Self {
        let LocationUiSinks {
            activity: activity_intents,
            approval: approval_intents,
            goal: goal_intents,
            dag: dag_intents,
            doctor: doctor_intents,
            harness: harness_intents,
        } = sinks;
        Self {
            app,
            client,
            intents,
            activity_intents,
            approval_intents,
            goal_intents,
            dag_intents,
            doctor_intents,
            harness_intents,
            busy,
            pending: None,
            pending_action: None,
            workspace_candidates: Vec::new(),
        }
    }

    fn start(&mut self) {
        self.busy.set(true);
        self.app.set_location_action_busy(true);
        self.app.set_location_status("Loading locations…".into());
        self.begin(
            PendingLocationAction::StartupList,
            LocationAction::list_default(),
        );
    }

    fn tick(&mut self) {
        self.poll_pending();
        if self.pending.is_none() {
            match self.intents.try_recv() {
                Ok(intent) => self.handle_intent(intent),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
            }
        }
    }

    fn poll_pending(&mut self) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let result = match pending.try_recv() {
            Ok(Some(result)) => result,
            Ok(None) => return,
            Err(error) => Err(error),
        };
        self.pending.take();
        let action = self.pending_action.take();
        self.handle_reply(action, result);
    }

    fn handle_intent(&mut self, intent: UiLocationIntent) {
        match intent {
            UiLocationIntent::Register(action) => {
                self.begin(PendingLocationAction::Register, action);
            }
            UiLocationIntent::Refresh => {
                self.app.set_location_status("Refreshing locations…".into());
                self.begin(
                    PendingLocationAction::RefreshList,
                    LocationAction::list_default(),
                );
            }
            UiLocationIntent::Discover {
                id,
                expected_revision,
            } => {
                self.clear_workspace("Discovering Workspace candidates…");
                self.begin(
                    PendingLocationAction::Discover {
                        id,
                        expected_revision,
                    },
                    LocationAction::discover(id, expected_revision),
                );
            }
            UiLocationIntent::SelectWorkspace(index) => self.select_workspace(index),
        }
    }

    fn begin(&mut self, action: PendingLocationAction, request: LocationAction) {
        if self.pending.is_some() {
            self.set_location_error(
                "LOCATION_ACTION_BUSY",
                "Another Location action is pending.",
            );
            return;
        }
        match self.client.submit(request) {
            Ok(pending) => {
                self.pending = Some(pending);
                self.pending_action = Some(action);
            }
            Err(error) => {
                self.finish_busy();
                if matches!(action, PendingLocationAction::SelectWorkspace { .. }) {
                    self.set_workspace_error_for_worker(&error);
                } else {
                    self.set_location_error_for_worker(&error);
                }
            }
        }
    }

    fn handle_reply(
        &mut self,
        action: Option<PendingLocationAction>,
        result: Result<LocationOutcome, LocationWorkerError>,
    ) {
        let Some(action) = action else {
            self.finish_busy();
            self.set_location_error(
                "LOCATION_PROTOCOL",
                "Location worker returned an untracked reply.",
            );
            return;
        };
        match (action, result) {
            (
                PendingLocationAction::StartupList
                | PendingLocationAction::RefreshList
                | PendingLocationAction::PostRegisterList,
                Ok(LocationOutcome::Locations(locations)),
            ) => {
                self.apply_locations(&locations);
                self.clear_workspace("Select a Location to discover Workspaces.");
                self.finish_busy();
                if matches!(action, PendingLocationAction::PostRegisterList) {
                    self.app.set_location_status(
                        format!(
                            "Location registered · {} Location{}",
                            locations.len(),
                            if locations.len() == 1 { "" } else { "s" }
                        )
                        .into(),
                    );
                }
            }
            (PendingLocationAction::Register, Ok(LocationOutcome::Registered(_))) => {
                self.app
                    .set_location_status("Location registered; refreshing…".into());
                self.begin(
                    PendingLocationAction::PostRegisterList,
                    LocationAction::list_default(),
                );
            }
            (
                PendingLocationAction::Discover {
                    id,
                    expected_revision,
                },
                Ok(LocationOutcome::Discovered(discovery)),
            ) => {
                self.apply_workspace_candidates(&discovery, id, expected_revision);
                self.finish_busy();
                self.app.set_workspace_status(
                    format!(
                        "{} Workspace candidate{}",
                        discovery.candidates().len(),
                        if discovery.candidates().len() == 1 {
                            ""
                        } else {
                            "s"
                        }
                    )
                    .into(),
                );
            }
            (
                PendingLocationAction::SelectWorkspace { index },
                Ok(LocationOutcome::WorkspaceRegistered(workspace)),
            ) => {
                self.apply_workspace_selection(index, &workspace);
                self.finish_busy();
            }
            (PendingLocationAction::SelectWorkspace { .. }, Ok(other)) => {
                self.finish_busy();
                self.set_workspace_error(
                    "WORKSPACE_PROTOCOL",
                    format!("Unexpected Workspace worker outcome: {other:?}"),
                );
            }
            (PendingLocationAction::SelectWorkspace { .. }, Err(error)) => {
                self.finish_busy();
                self.set_workspace_error_for_worker(&error);
            }
            (_, Ok(other)) => {
                self.finish_busy();
                self.set_location_error(
                    "LOCATION_PROTOCOL",
                    format!("Unexpected Location worker outcome: {other:?}"),
                );
            }
            (_, Err(error)) => {
                if matches!(action, PendingLocationAction::Discover { .. })
                    && is_revision_conflict(&error)
                {
                    self.set_location_error_for_worker(&error);
                    self.begin(
                        PendingLocationAction::RefreshList,
                        LocationAction::list_default(),
                    );
                } else {
                    self.finish_busy();
                    self.set_location_error_for_worker(&error);
                }
            }
        }
    }

    fn apply_locations(&mut self, locations: &[forge_domain::RegisteredLocation]) {
        let rows = location_rows(locations);
        self.app
            .set_location_rows(ModelRc::new(VecModel::from(rows)));
        if locations.is_empty() {
            self.app
                .set_location_status("No Locations registered yet.".into());
        } else {
            self.app.set_location_status(
                format!(
                    "{} Location{} ready",
                    locations.len(),
                    if locations.len() == 1 { "" } else { "s" }
                )
                .into(),
            );
        }
    }

    fn clear_workspace(&mut self, status: &str) {
        self.app
            .set_workspace_rows(ModelRc::new(VecModel::from(Vec::<WorkspaceRow>::new())));
        self.app.set_selected_workspace_index(-1);
        self.app.set_selected_workspace_id("".into());
        self.app.set_selected_workspace_revision("".into());
        self.app.set_selected_workspace_root("".into());
        self.workspace_candidates.clear();
        reset_doctor_projection(&self.app, "Select a committed Workspace to run Doctor.");
        self.notify_workspace_scope(None);
        self.app.set_workspace_status(status.into());
    }

    fn notify_workspace_scope(&self, scope: Option<ActivityWorkspaceScope>) {
        let harness_scope = scope.as_ref().map(|scope| {
            ResolvedWorkspaceScope::from_observation(
                scope.workspace_id,
                scope.workspace_revision,
                scope.locator.clone(),
            )
        });
        let approval_scope = scope.clone();
        let goal_scope = scope.clone();
        let dag_scope = scope.clone();
        let doctor_scope = scope.clone();
        if self
            .activity_intents
            .try_send(UiActivityIntent::WorkspaceSelected(scope))
            .is_err()
        {
            error!("Activity projection scope queue is full or closed");
            self.app
                .set_activity_live_rows(ModelRc::new(VecModel::from(Vec::<ActivityRow>::new())));
            self.app
                .set_activity_history_rows(ModelRc::new(VecModel::from(Vec::<ActivityRow>::new())));
            self.app.set_activity_status(
                "ERROR [ACTIVITY_SCOPE_QUEUE] Activity scope update was not admitted.".into(),
            );
        }
        if self
            .approval_intents
            .try_send(UiApprovalIntent::WorkspaceSelected(approval_scope))
            .is_err()
        {
            error!("Approval projection scope queue is full or closed");
            self.app
                .set_approval_rows(ModelRc::new(VecModel::from(Vec::<ApprovalRow>::new())));
            self.app.set_approval_status(
                "ERROR [APPROVAL_SCOPE_QUEUE] Approval scope update was not admitted.".into(),
            );
        }
        if self
            .goal_intents
            .try_send(UiGoalIntent::WorkspaceSelected(goal_scope))
            .is_err()
        {
            error!("Goal projection scope queue is full or closed");
            self.app.set_goal_rows(ModelRc::new(
                VecModel::from(Vec::<forge_ui::GoalRow>::new()),
            ));
            self.app.set_goal_status(
                "ERROR [GOAL_SCOPE_QUEUE] Goal scope update was not admitted.".into(),
            );
        }
        if self
            .dag_intents
            .try_send(UiDagIntent::WorkspaceSelected(dag_scope))
            .is_err()
        {
            error!("DAG projection scope queue is full or closed");
            self.app.set_dag_node_rows(ModelRc::new(VecModel::from(
                Vec::<forge_ui::DagNodeRow>::new(),
            )));
            self.app.set_dag_edge_rows(ModelRc::new(VecModel::from(
                Vec::<forge_ui::DagEdgeRow>::new(),
            )));
            self.app.set_dag_column_count(0);
            self.app.set_dag_lane_count(0);
            self.app.set_dag_revision("".into());
            self.app.set_dag_status(
                "ERROR [DAG_SCOPE_QUEUE] DAG scope update was not admitted.".into(),
            );
        }
        if self
            .doctor_intents
            .try_send(UiDoctorIntent::WorkspaceSelected(doctor_scope))
            .is_err()
        {
            error!("Doctor projection scope queue is full or closed");
            reset_doctor_projection(
                &self.app,
                "ERROR [DOCTOR_SCOPE_QUEUE] Doctor scope update was not admitted.",
            );
        }
        if self
            .harness_intents
            .try_send(UiHarnessIntent::WorkspaceSelected(harness_scope))
            .is_err()
        {
            error!("Harness projection scope queue is full or closed");
            self.app.set_harness_status(
                "ERROR [HARNESS_SCOPE_QUEUE] Harness scope update was not admitted.".into(),
            );
        }
    }

    fn apply_workspace_candidates(
        &mut self,
        discovery: &forge_workspace::WorkspaceDiscovery,
        location_id: LocationId,
        location_revision: LocationRevision,
    ) {
        let rows = workspace_rows(discovery.candidates());
        self.workspace_candidates = discovery
            .candidates()
            .iter()
            .take(256)
            .map(|candidate| WorkspaceCandidateSnapshot {
                key: candidate.key(),
                location_id,
                location_revision,
            })
            .collect();
        self.app
            .set_workspace_rows(ModelRc::new(VecModel::from(rows)));
        self.app.set_selected_workspace_index(-1);
        self.app.set_selected_workspace_id("".into());
        self.app.set_selected_workspace_revision("".into());
        self.app.set_selected_workspace_root("".into());
    }

    fn select_workspace(&mut self, index: i32) {
        let Ok(index_usize) = usize::try_from(index) else {
            return;
        };
        let Some(snapshot) = self.workspace_candidates.get(index_usize).cloned() else {
            return;
        };
        let observed_at = match observed_timestamp_now() {
            Ok(observed_at) => observed_at,
            Err(error) => {
                self.set_workspace_error("WORKSPACE_TIMESTAMP", error.to_string());
                return;
            }
        };
        let action = LocationAction::select_workspace(
            snapshot.key,
            snapshot.location_id,
            snapshot.location_revision,
            WorkspaceId::from_uuid(Uuid::now_v7()),
            observed_at,
        );
        self.app
            .set_workspace_status("Establishing Workspace…".into());
        self.busy.set(true);
        self.app.set_location_action_busy(true);
        self.begin(PendingLocationAction::SelectWorkspace { index }, action);
    }

    fn apply_workspace_selection(&mut self, index: i32, workspace: &RegisteredWorkspace) {
        let Some((committed_index, projection)) =
            committed_workspace_projection_from_result(index, Ok(workspace))
        else {
            return;
        };
        let status = format!(
            "Workspace ready · id {} · revision {} · root {}",
            projection.id, projection.revision, projection.root
        );
        self.app.set_selected_workspace_id(projection.id.into());
        self.app
            .set_selected_workspace_revision(projection.revision.into());
        self.app.set_selected_workspace_root(projection.root.into());
        self.app.set_selected_workspace_index(committed_index);
        self.app.set_workspace_status(status.into());
        reset_doctor_projection(
            &self.app,
            "Loading bounded read-only Workspace diagnostics…",
        );

        let Some(snapshot) = usize::try_from(index)
            .ok()
            .and_then(|index| self.workspace_candidates.get(index))
        else {
            self.notify_workspace_scope(None);
            self.set_workspace_error(
                "WORKSPACE_SELECTION_SCOPE_MISSING",
                "Committed Workspace is not present in the discovery snapshot.",
            );
            return;
        };
        match activity_workspace_scope(snapshot, workspace) {
            Ok(scope) => self.notify_workspace_scope(Some(scope)),
            Err(error) => {
                self.notify_workspace_scope(None);
                self.set_workspace_error(
                    "WORKSPACE_LOCATOR_INVALID",
                    format!("Committed Workspace scope could not be reconstructed: {error}"),
                );
            }
        }
    }

    fn set_workspace_error(&self, code: &str, message: impl Into<SharedString>) {
        self.app
            .set_workspace_status(format!("ERROR [{code}] {}", message.into()).into());
    }

    fn finish_busy(&self) {
        self.busy.set(false);
        self.app.set_location_action_busy(false);
    }

    fn set_location_error_for_worker(&self, error: &LocationWorkerError) {
        let (code, message) = location_error_code_message(error);
        self.set_location_error(code, message);
    }

    fn set_workspace_error_for_worker(&self, error: &LocationWorkerError) {
        let (code, message) = location_error_code_message(error);
        self.set_workspace_error(code, message);
    }

    fn set_location_error(&self, code: &str, message: impl Into<SharedString>) {
        let message: SharedString = message.into();
        self.app
            .set_location_status(format!("ERROR [{code}] {message}").into());
    }
}

struct ActivityUiController {
    app: AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiActivityIntent>,
    busy: Rc<Cell<bool>>,
    scope: Option<ActivityWorkspaceScope>,
    selected_activity_id: Option<ActivityId>,
    selected_diff_id: Option<DiffId>,
    pending_activities: Option<PendingControl<WorkspaceActivityProjection>>,
    pending_diff_list: Option<PendingControl<DiffListResult>>,
    pending_diff_read: Option<PendingControl<DiffReadResult>>,
}

impl ActivityUiController {
    fn new(
        app: AppWindow,
        client: ForgeControlClient,
        intents: Receiver<UiActivityIntent>,
        busy: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            app,
            client,
            intents,
            busy,
            scope: None,
            selected_activity_id: None,
            selected_diff_id: None,
            pending_activities: None,
            pending_diff_list: None,
            pending_diff_read: None,
        }
    }

    fn start(&mut self) {
        self.clear_rows("Select a committed Workspace to view Activities.");
    }

    fn tick(&mut self) {
        self.poll_intents();
        self.poll_pending_activities();
        self.poll_pending_diff_list();
        self.poll_pending_diff_read();
    }

    fn poll_intents(&mut self) {
        while let Ok(intent) = self.intents.try_recv() {
            match intent {
                UiActivityIntent::WorkspaceSelected(scope) => {
                    // A scope change invalidates any response admitted for the
                    // previous Workspace. Dropping the pending receiver keeps
                    // the UI from applying a stale projection when that work
                    // eventually completes in the control worker.
                    self.pending_activities.take();
                    self.pending_diff_list.take();
                    self.pending_diff_read.take();
                    self.selected_activity_id = None;
                    self.selected_diff_id = None;
                    self.scope = scope;
                    self.busy.set(false);
                    self.clear_diff_projection("Select an Activity to inspect changes.");
                    if self.scope.is_some() {
                        self.begin_refresh();
                    } else {
                        self.clear_rows("Select a committed Workspace to view Activities.");
                    }
                }
                UiActivityIntent::Refresh => {
                    if self.has_pending() {
                        self.app
                            .set_activity_status("An Activity request is already pending.".into());
                    } else {
                        self.begin_refresh();
                    }
                }
                UiActivityIntent::SelectActivity(activity_id) => {
                    if self.has_pending() {
                        self.app
                            .set_diff_status("A request is already pending.".into());
                    } else {
                        self.begin_diff_list(activity_id);
                    }
                }
                UiActivityIntent::ViewDiff(diff_id) => {
                    if self.has_pending() {
                        self.app
                            .set_diff_status("A request is already pending.".into());
                    } else {
                        self.begin_diff_read(diff_id);
                    }
                }
                UiActivityIntent::CloseDiff => self.close_diff_view(),
            }
        }
    }

    fn begin_refresh(&mut self) {
        let Some(scope) = self.scope.clone() else {
            self.clear_rows("Select a committed Workspace to view Activities.");
            return;
        };
        let now = match observed_timestamp_now() {
            Ok(now) => now,
            Err(error) => {
                self.busy.set(false);
                self.set_error("ACTIVITY_TIMESTAMP", error.to_string());
                return;
            }
        };
        let pending = self.client.submit_list_workspace_activity_projections(
            WorkspaceActivityProjectionRequest {
                location_id: scope.location_id,
                expected_location_revision: scope.location_revision,
                locator: scope.locator,
                expected_workspace_id: scope.workspace_id,
                expected_workspace_revision: scope.workspace_revision,
                now,
                limit: ActivityListLimit::DEFAULT,
            },
        );
        match pending {
            Ok(pending) => {
                self.busy.set(true);
                self.app.set_activity_action_busy(true);
                self.app
                    .set_activity_status("Refreshing Activities…".into());
                self.pending_activities = Some(pending);
            }
            Err(error) => {
                self.busy.set(false);
                self.app.set_activity_action_busy(false);
                self.set_control_error(&error);
            }
        }
    }

    fn begin_diff_list(&mut self, activity_id: ActivityId) {
        let Some(scope) = self.scope.as_ref().map(resolved_activity_scope) else {
            self.reset_busy();
            self.clear_diff_projection("Select a committed Workspace first.");
            return;
        };
        let limit = match DiffListLimit::new(50) {
            Ok(limit) => limit,
            Err(error) => {
                self.reset_busy();
                self.set_diff_error("DIFF_LIMIT", error.to_string());
                return;
            }
        };
        match self.client.submit_diff_list(DiffListRequest {
            scope,
            activity_id,
            limit,
        }) {
            Ok(pending) => {
                self.selected_activity_id = Some(activity_id);
                self.selected_diff_id = None;
                self.busy.set(true);
                self.app.set_activity_action_busy(true);
                self.app
                    .set_selected_activity_id(activity_id.to_string().into());
                self.app.set_diff_view_open(false);
                self.app.set_diff_view_title("".into());
                self.app.set_diff_view_content("".into());
                self.app
                    .set_diff_rows(ModelRc::new(VecModel::from(Vec::<DiffRow>::new())));
                self.app.set_diff_status("Loading changes…".into());
                self.pending_diff_list = Some(pending);
            }
            Err(error) => {
                self.reset_busy();
                self.set_diff_control_error(&error);
            }
        }
    }

    fn begin_diff_read(&mut self, diff_id: DiffId) {
        let Some(scope) = self.scope.as_ref().map(resolved_activity_scope) else {
            self.reset_busy();
            self.clear_diff_projection("Select a committed Workspace first.");
            return;
        };
        match self
            .client
            .submit_diff_read(DiffReadRequest { scope, diff_id })
        {
            Ok(pending) => {
                self.selected_diff_id = Some(diff_id);
                self.busy.set(true);
                self.app.set_activity_action_busy(true);
                self.app.set_diff_status("Loading verified Diff…".into());
                self.pending_diff_read = Some(pending);
            }
            Err(error) => {
                self.reset_busy();
                self.set_diff_control_error(&error);
            }
        }
    }

    fn has_pending(&self) -> bool {
        self.pending_activities.is_some()
            || self.pending_diff_list.is_some()
            || self.pending_diff_read.is_some()
    }

    fn reset_busy(&self) {
        self.busy.set(false);
        self.app.set_activity_action_busy(false);
    }

    fn poll_pending_activities(&mut self) {
        let Some(pending) = self.pending_activities.as_ref() else {
            return;
        };
        let result = match pending.try_recv() {
            Ok(Some(result)) => result.map_err(ControlClientError::Service),
            Ok(None) => return,
            Err(error) => Err(error),
        };
        self.pending_activities.take();
        self.busy.set(false);
        self.app.set_activity_action_busy(false);
        match result {
            Ok(projection) => self.apply_projection(&projection),
            Err(error) => self.set_control_error(&error),
        }
    }

    fn poll_pending_diff_list(&mut self) {
        let Some(pending) = self.pending_diff_list.as_ref() else {
            return;
        };
        let result = match pending.try_recv() {
            Ok(Some(result)) => result.map_err(ControlClientError::Service),
            Ok(None) => return,
            Err(error) => Err(error),
        };
        self.pending_diff_list.take();
        self.busy.set(false);
        self.app.set_activity_action_busy(false);
        match result {
            Ok(projection) => self.apply_diff_list(&projection),
            Err(error) => self.set_diff_control_error(&error),
        }
    }

    fn poll_pending_diff_read(&mut self) {
        let Some(pending) = self.pending_diff_read.as_ref() else {
            return;
        };
        let result = match pending.try_recv() {
            Ok(Some(result)) => result.map_err(ControlClientError::Service),
            Ok(None) => return,
            Err(error) => Err(error),
        };
        self.pending_diff_read.take();
        self.busy.set(false);
        self.app.set_activity_action_busy(false);
        match result {
            Ok(projection) => self.apply_diff_read(&projection),
            Err(error) => self.set_diff_control_error(&error),
        }
    }

    fn apply_projection(&self, projection: &WorkspaceActivityProjection) {
        let Some(scope) = self.scope.as_ref() else {
            self.clear_rows("Select a committed Workspace to view Activities.");
            return;
        };
        let returned_scope = projection.scope();
        if returned_scope.workspace_id() != scope.workspace_id
            || returned_scope.workspace_revision() != scope.workspace_revision
            || returned_scope.locator() != &scope.locator
        {
            self.clear_rows("Activity projection scope changed; refresh required.");
            self.set_error(
                "ACTIVITY_SCOPE_STALE",
                "Activity projection belongs to a different Workspace revision.",
            );
            return;
        }
        let now = match observed_timestamp_now() {
            Ok(now) => now,
            Err(error) => {
                self.set_error("ACTIVITY_TIMESTAMP", error.to_string());
                return;
            }
        };
        let (live, history) = activity_rows(projection.activities(), now);
        let live_count = live.len();
        let history_count = history.len();
        self.app
            .set_activity_live_rows(ModelRc::new(VecModel::from(live)));
        self.app
            .set_activity_history_rows(ModelRc::new(VecModel::from(history)));
        let total = projection.activities().len();
        self.app.set_activity_status(
            format!(
                "{} Activity{} · Live {} · History {}",
                total,
                if total == 1 { "" } else { "ies" },
                live_count,
                history_count,
            )
            .into(),
        );
    }

    fn apply_diff_list(&self, projection: &DiffListResult) {
        let Some(activity_id) = self.selected_activity_id else {
            self.clear_diff_projection("Select an Activity to inspect changes.");
            return;
        };
        if !self.scope_matches(projection.scope())
            || projection
                .diffs()
                .iter()
                .any(|diff| diff.activity_id() != activity_id)
        {
            self.clear_diff_projection("Diff projection scope changed; refresh required.");
            self.set_diff_error(
                "DIFF_SCOPE_STALE",
                "Diff metadata belongs to a different Workspace or Activity.",
            );
            return;
        }
        let rows: Vec<_> = projection.diffs().iter().take(50).map(diff_row).collect();
        let count = rows.len();
        self.app.set_diff_rows(ModelRc::new(VecModel::from(rows)));
        self.app.set_diff_status(if count == 0 {
            "No durable changes for this Activity.".into()
        } else {
            format!(
                "{} change{} · select one to view",
                count,
                if count == 1 { "" } else { "s" }
            )
            .into()
        });
    }

    fn apply_diff_read(&self, projection: &DiffReadResult) {
        let Some(selected_diff_id) = self.selected_diff_id else {
            self.close_diff_view();
            return;
        };
        if !self.scope_matches(projection.scope())
            || projection.evidence().id() != selected_diff_id
            || self
                .selected_activity_id
                .is_some_and(|activity_id| projection.evidence().activity_id() != activity_id)
        {
            self.close_diff_view();
            self.set_diff_error(
                "DIFF_SCOPE_STALE",
                "Diff payload belongs to a stale selection.",
            );
            return;
        }
        let evidence = projection.evidence();
        let title = format!(
            "{} · {}",
            diff_path_label(evidence.file().path()),
            diff_change_kind_label(evidence.file().kind())
        );
        let content = projection.content().map_or_else(
            || diff_unavailable_message(evidence, projection.health()),
            str::to_owned,
        );
        self.app.set_diff_view_title(title.into());
        self.app.set_diff_view_content(content.into());
        self.app.set_diff_view_open(true);
        self.app.set_diff_status(
            format!(
                "{} · {}",
                diff_health_label(projection.health()),
                diff_state_label(evidence.state())
            )
            .into(),
        );
    }

    fn scope_matches(&self, returned: &ResolvedWorkspaceScope) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|scope| diff_scope_matches(scope, returned))
    }

    fn close_diff_view(&self) {
        self.app.set_diff_view_open(false);
        self.app.set_diff_view_title("".into());
        self.app.set_diff_view_content("".into());
        let count = self.app.get_diff_rows().row_count();
        self.app.set_diff_status(if count == 0 {
            "No durable changes for this Activity.".into()
        } else {
            format!(
                "{} change{} · select one to view",
                count,
                if count == 1 { "" } else { "s" }
            )
            .into()
        });
    }

    fn clear_rows(&self, status: &str) {
        self.busy.set(false);
        self.app
            .set_activity_live_rows(ModelRc::new(VecModel::from(Vec::<ActivityRow>::new())));
        self.app
            .set_activity_history_rows(ModelRc::new(VecModel::from(Vec::<ActivityRow>::new())));
        self.app.set_activity_action_busy(false);
        self.app.set_activity_status(status.into());
        self.clear_diff_projection("Select an Activity to inspect changes.");
    }

    fn clear_diff_projection(&self, status: &str) {
        self.app.set_selected_activity_id("".into());
        self.app
            .set_diff_rows(ModelRc::new(VecModel::from(Vec::<DiffRow>::new())));
        self.app.set_diff_view_open(false);
        self.app.set_diff_view_title("".into());
        self.app.set_diff_view_content("".into());
        self.app.set_diff_status(status.into());
    }

    fn set_control_error(&self, error: &ControlClientError) {
        self.set_error(error.code().as_str(), error.code().summary());
    }

    fn set_diff_control_error(&self, error: &ControlClientError) {
        self.set_diff_error(error.code().as_str(), error.code().summary());
    }

    fn set_diff_error(&self, code: &str, message: impl Into<SharedString>) {
        self.app
            .set_diff_status(format!("ERROR [{code}] {}", message.into()).into());
    }

    fn set_error(&self, code: &str, message: impl Into<SharedString>) {
        self.app
            .set_activity_status(format!("ERROR [{code}] {}", message.into()).into());
    }
}

enum PendingApprovalUi {
    List(PendingApproval<Vec<PendingApprovalProjection>>),
    Approve(PendingApproval<forge_domain::ExecutionId>),
    Reject(PendingApproval<forge_domain::RegisteredApprovalRequest>),
    SetAuto(PendingApproval<bool>),
    StopWorkspace(PendingApproval<usize>),
    Emergency(PendingApproval<usize>),
}

struct ApprovalUiController {
    app: AppWindow,
    tray: ForgeTray,
    client: ForgeApprovalCoordinatorClient,
    intents: Receiver<UiApprovalIntent>,
    busy: Rc<Cell<bool>>,
    scope: Option<ActivityWorkspaceScope>,
    pending: Option<PendingApprovalUi>,
}

impl ApprovalUiController {
    fn new(
        app: AppWindow,
        tray: ForgeTray,
        client: ForgeApprovalCoordinatorClient,
        intents: Receiver<UiApprovalIntent>,
        busy: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            app,
            tray,
            client,
            intents,
            busy,
            scope: None,
            pending: None,
        }
    }

    fn start(&self) {
        self.clear("Select a committed Workspace to inspect approvals.");
    }

    fn tick(&mut self) {
        self.poll_pending();
        if self.pending.is_some() {
            return;
        }
        while let Ok(intent) = self.intents.try_recv() {
            match intent {
                UiApprovalIntent::WorkspaceSelected(scope) => {
                    self.scope = scope;
                    self.tray.set_workspace_selected(self.scope.is_some());
                    self.app.set_auto_approval_enabled(false);
                    self.tray.set_auto_approval_enabled(false);
                    if self.scope.is_some() {
                        self.begin_list();
                    } else {
                        self.clear("Select a committed Workspace to inspect approvals.");
                    }
                }
                UiApprovalIntent::Refresh => self.begin_list(),
                UiApprovalIntent::Approve(id) => self.begin_approve(id),
                UiApprovalIntent::Reject(id) => self.begin_reject(id),
                UiApprovalIntent::SetAutoApproval(enabled) => self.begin_set_auto(enabled),
                UiApprovalIntent::StopWorkspace => self.begin_stop_workspace(),
                UiApprovalIntent::EmergencyStop => self.begin_emergency_stop(),
            }
            if self.pending.is_some() {
                break;
            }
        }
    }

    fn begin_list(&mut self) {
        let Some(scope) = self.scope.as_ref().map(resolved_activity_scope) else {
            self.clear("Select a committed Workspace to inspect approvals.");
            return;
        };
        match self.client.submit_list_pending(scope) {
            Ok(pending) => {
                self.set_busy(true);
                self.app
                    .set_approval_status("Loading pending approvals…".into());
                self.pending = Some(PendingApprovalUi::List(pending));
            }
            Err(error) => self.fail(&error),
        }
    }

    fn begin_approve(&mut self, id: ApprovalRequestId) {
        match self.client.submit_approve_once(id) {
            Ok(pending) => {
                self.set_busy(true);
                self.app
                    .set_approval_status("Applying one-shot approval…".into());
                self.pending = Some(PendingApprovalUi::Approve(pending));
            }
            Err(error) => self.fail(&error),
        }
    }

    fn begin_reject(&mut self, id: ApprovalRequestId) {
        match self.client.submit_reject(id) {
            Ok(pending) => {
                self.set_busy(true);
                self.app.set_approval_status("Rejecting request…".into());
                self.pending = Some(PendingApprovalUi::Reject(pending));
            }
            Err(error) => self.fail(&error),
        }
    }

    fn begin_set_auto(&mut self, enabled: bool) {
        let Some(scope) = self.scope.as_ref().map(resolved_activity_scope) else {
            self.clear("Select a committed Workspace before changing Auto Approval.");
            return;
        };
        match self.client.submit_set_auto_approval(scope, enabled) {
            Ok(pending) => {
                self.set_busy(true);
                self.app.set_approval_status(
                    if enabled {
                        "Enabling bounded Auto Approval…"
                    } else {
                        "Disabling Auto Approval…"
                    }
                    .into(),
                );
                self.pending = Some(PendingApprovalUi::SetAuto(pending));
            }
            Err(error) => self.fail(&error),
        }
    }

    fn begin_emergency_stop(&mut self) {
        match self.client.submit_emergency_stop() {
            Ok(pending) => {
                self.set_busy(true);
                self.app
                    .set_approval_status("Emergency stop: revoking local authority…".into());
                self.pending = Some(PendingApprovalUi::Emergency(pending));
            }
            Err(error) => self.fail(&error),
        }
    }

    fn begin_stop_workspace(&mut self) {
        let Some(workspace_id) = self.scope.as_ref().map(|scope| scope.workspace_id) else {
            self.clear("Select a committed Workspace before stopping Workspace work.");
            return;
        };
        match self.client.submit_stop_workspace(workspace_id) {
            Ok(pending) => {
                self.set_busy(true);
                self.app.set_approval_status(
                    "Stopping Workspace executions and revoking local authority…".into(),
                );
                self.pending = Some(PendingApprovalUi::StopWorkspace(pending));
            }
            Err(error) => self.fail(&error),
        }
    }

    fn poll_pending(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let still_pending = match pending {
            PendingApprovalUi::List(pending) => match pending.try_recv() {
                Ok(None) => Some(PendingApprovalUi::List(pending)),
                Ok(Some(Ok(rows))) => {
                    self.apply_rows(&rows);
                    None
                }
                Ok(Some(Err(error))) | Err(error) => {
                    self.fail(&error);
                    None
                }
            },
            PendingApprovalUi::Approve(pending) => match pending.try_recv() {
                Ok(None) => Some(PendingApprovalUi::Approve(pending)),
                Ok(Some(Ok(_))) => {
                    self.app
                        .set_approval_status("Approval consumed; execution started.".into());
                    self.begin_list();
                    None
                }
                Ok(Some(Err(error))) | Err(error) => {
                    self.fail(&error);
                    None
                }
            },
            PendingApprovalUi::Reject(pending) => match pending.try_recv() {
                Ok(None) => Some(PendingApprovalUi::Reject(pending)),
                Ok(Some(Ok(_))) => {
                    self.app.set_approval_status("Request rejected.".into());
                    self.begin_list();
                    None
                }
                Ok(Some(Err(error))) | Err(error) => {
                    self.fail(&error);
                    None
                }
            },
            PendingApprovalUi::SetAuto(pending) => match pending.try_recv() {
                Ok(None) => Some(PendingApprovalUi::SetAuto(pending)),
                Ok(Some(Ok(enabled))) => {
                    self.app.set_auto_approval_enabled(enabled);
                    self.tray.set_auto_approval_enabled(enabled);
                    self.app.set_approval_status(
                        if enabled {
                            "Auto Approval is bounded to discovered read-only Workspace commands."
                        } else {
                            "Auto Approval is off."
                        }
                        .into(),
                    );
                    None
                }
                Ok(Some(Err(error))) | Err(error) => {
                    self.fail(&error);
                    None
                }
            },
            PendingApprovalUi::StopWorkspace(pending) => match pending.try_recv() {
                Ok(None) => Some(PendingApprovalUi::StopWorkspace(pending)),
                Ok(Some(Ok(count))) => {
                    self.clear(&format!(
                        "Workspace stop completed; {count} item(s) cancelled."
                    ));
                    self.app.set_auto_approval_enabled(false);
                    self.tray.set_auto_approval_enabled(false);
                    None
                }
                Ok(Some(Err(error))) | Err(error) => {
                    self.fail(&error);
                    None
                }
            },
            PendingApprovalUi::Emergency(pending) => match pending.try_recv() {
                Ok(None) => Some(PendingApprovalUi::Emergency(pending)),
                Ok(Some(Ok(count))) => {
                    self.clear(&format!(
                        "Emergency stop completed; {count} item(s) cancelled."
                    ));
                    self.app.set_auto_approval_enabled(false);
                    self.tray.set_auto_approval_enabled(false);
                    None
                }
                Ok(Some(Err(error))) | Err(error) => {
                    self.fail(&error);
                    None
                }
            },
        };
        if let Some(pending) = still_pending {
            self.pending = Some(pending);
        } else if self.pending.is_none() {
            self.set_busy(false);
        }
    }

    fn apply_rows(&self, rows: &[PendingApprovalProjection]) {
        let projected: Vec<_> = rows
            .iter()
            .copied()
            .map(|row| ApprovalRow {
                id: row.approval_id().to_string().into(),
                action: approval_action_label(row.action()).into(),
                scope: "Workspace-scoped request".into(),
                expires_at: row.expires_at().get().to_string().into(),
            })
            .collect();
        let count = i32::try_from(projected.len()).unwrap_or(i32::MAX);
        self.app
            .set_approval_rows(ModelRc::new(VecModel::from(projected)));
        self.app.set_approval_status(if count == 0 {
            "No pending approvals.".into()
        } else {
            format!("{count} pending approval(s)").into()
        });
        self.tray.set_pending_approval_count(count);
    }

    fn clear(&self, status: &str) {
        self.app
            .set_approval_rows(ModelRc::new(VecModel::from(Vec::<ApprovalRow>::new())));
        self.app.set_approval_status(status.into());
        self.tray.set_pending_approval_count(0);
        self.set_busy(false);
    }

    fn fail(&self, error: &ForgeApprovalCoordinatorError) {
        self.app
            .set_approval_status(format!("ERROR [APPROVAL_CONTROL] {error}").into());
        self.set_busy(false);
    }

    fn set_busy(&self, value: bool) {
        self.busy.set(value);
        self.app.set_approval_action_busy(value);
    }
}

const fn approval_action_label(action: forge_domain::ExecutionActionClass) -> &'static str {
    match action {
        forge_domain::ExecutionActionClass::DirectStructured => "Direct command",
        forge_domain::ExecutionActionClass::DiscoveredProjectCommand => {
            "Discovered project command"
        }
        forge_domain::ExecutionActionClass::ShellEscape => "Shell command",
    }
}

fn resolved_activity_scope(scope: &ActivityWorkspaceScope) -> ResolvedWorkspaceScope {
    ResolvedWorkspaceScope::from_observation(
        scope.workspace_id,
        scope.workspace_revision,
        scope.locator.clone(),
    )
}

fn diff_scope_matches(scope: &ActivityWorkspaceScope, returned: &ResolvedWorkspaceScope) -> bool {
    returned.workspace_id() == scope.workspace_id
        && returned.workspace_revision() == scope.workspace_revision
        && returned.locator() == &scope.locator
}

fn diff_row(evidence: &RegisteredDiffEvidence) -> DiffRow {
    DiffRow {
        id: evidence.id().to_string().into(),
        path: diff_path_label(evidence.file().path()).into(),
        kind: diff_change_kind_label(evidence.file().kind()).into(),
        state: format!(
            "{} / {}",
            diff_state_label(evidence.state()),
            diff_render_kind_label(evidence.payload().render_kind())
        )
        .into(),
        summary: format!(
            "+{} -{}",
            evidence.file().additions().get(),
            evidence.file().deletions().get()
        )
        .into(),
    }
}

const fn diff_change_kind_label(kind: DiffChangeKind) -> &'static str {
    match kind {
        DiffChangeKind::Created => "Created",
        DiffChangeKind::Modified => "Modified",
        DiffChangeKind::Deleted => "Deleted",
    }
}

const fn diff_state_label(state: DiffEvidenceState) -> &'static str {
    match state {
        DiffEvidenceState::Intent => "Intent",
        DiffEvidenceState::Ready => "Ready",
        DiffEvidenceState::SummaryOnly => "Summary only",
        DiffEvidenceState::Abandoned => "Abandoned",
        DiffEvidenceState::PurgePending => "Purge pending",
        DiffEvidenceState::Tombstoned => "Archived",
    }
}

const fn diff_render_kind_label(kind: DiffRenderKind) -> &'static str {
    match kind {
        DiffRenderKind::Text => "Text",
        DiffRenderKind::Binary => "Binary",
        DiffRenderKind::Oversized => "Oversized",
    }
}

const fn diff_health_label(health: DiffArtifactHealth) -> &'static str {
    match health {
        DiffArtifactHealth::Available => "Available",
        DiffArtifactHealth::NotApplicable => "No text artifact",
        DiffArtifactHealth::Archived => "Archived",
        DiffArtifactHealth::Missing => "Missing artifact",
        DiffArtifactHealth::Corrupt => "Corrupt artifact",
    }
}

fn diff_unavailable_message(
    evidence: &RegisteredDiffEvidence,
    health: DiffArtifactHealth,
) -> String {
    format!(
        "Diff text is unavailable.\n\nState: {}\nKind: {}\nHealth: {}\n\nThis record remains durable metadata and is not recovery data.",
        diff_state_label(evidence.state()),
        diff_render_kind_label(evidence.payload().render_kind()),
        diff_health_label(health)
    )
}

fn activity_row_with_liveness(
    projection: &ActivityProjection,
    liveness: ActivityLiveness,
    display_label: &str,
) -> ActivityRow {
    let activity = projection.activity();
    ActivityRow {
        id: activity.id().to_string().into(),
        display_label: display_label.into(),
        state: activity_state_label(activity.state()).into(),
        liveness: activity_liveness_label(liveness).into(),
        revision: activity.revision().get().to_string().into(),
        created_at: activity_timestamp_label(activity.created_at()).into(),
        updated_at: activity_timestamp_label(activity.updated_at()).into(),
    }
}

fn activity_rows(
    projections: &[ActivityProjection],
    now: TimestampMillis,
) -> (Vec<ActivityRow>, Vec<ActivityRow>) {
    let mut live = Vec::new();
    let mut history = Vec::new();
    for (index, projection) in projections.iter().take(256).enumerate() {
        let display_label = format!("Chat {:02}", index + 1);
        let effective_liveness = if projection.state() == ActivityState::Open
            && projection.activity().lease().is_expired_at(now)
        {
            ActivityLiveness::Expired
        } else {
            projection.liveness()
        };
        let row = activity_row_with_liveness(projection, effective_liveness, &display_label);
        if activity_is_live(projection, now) {
            live.push(row);
        } else {
            history.push(row);
        }
    }
    (live, history)
}

fn activity_is_live(projection: &ActivityProjection, now: TimestampMillis) -> bool {
    projection.state() == ActivityState::Open
        && projection.liveness() == ActivityLiveness::Live
        && projection.activity().lease().is_live_at(now)
}

fn activity_state_label(state: ActivityState) -> &'static str {
    match state {
        ActivityState::Open => "Open",
        ActivityState::Closed => "Closed",
        ActivityState::Interrupted => "Interrupted",
    }
}

fn activity_liveness_label(liveness: ActivityLiveness) -> &'static str {
    match liveness {
        ActivityLiveness::Available => "Available",
        ActivityLiveness::Live => "Live",
        ActivityLiveness::Expired => "Expired",
        ActivityLiveness::Closed => "Closed",
        ActivityLiveness::Interrupted => "Interrupted",
    }
}

fn activity_timestamp_label(timestamp: TimestampMillis) -> String {
    format!("{} ms UTC", timestamp.get())
}

/// Pure commit mapping used only after the worker has returned a durable
/// `RegisteredWorkspace`. Pending/error replies never call this function, so
/// an optimistic candidate click cannot mutate the committed index.
fn committed_workspace_projection(
    index: i32,
    workspace: &RegisteredWorkspace,
) -> (i32, WorkspaceSelectionProjection) {
    (index, WorkspaceSelectionProjection::from(workspace))
}

fn committed_workspace_projection_from_result(
    index: i32,
    result: Result<&RegisteredWorkspace, &LocationWorkerError>,
) -> Option<(i32, WorkspaceSelectionProjection)> {
    result
        .ok()
        .map(|workspace| committed_workspace_projection(index, workspace))
}

/// Reconstruct the exact relative locator from the immutable discovery
/// snapshot after the worker has returned the durable Workspace identity.
/// A mismatched Location identity is rejected rather than falling back to a
/// default or process-global Workspace.
fn activity_workspace_scope(
    snapshot: &WorkspaceCandidateSnapshot,
    workspace: &RegisteredWorkspace,
) -> Result<ActivityWorkspaceScope, ActivityWorkspaceScopeError> {
    if workspace.location_id() != snapshot.location_id {
        return Err(ActivityWorkspaceScopeError::LocationMismatch);
    }
    let locator = snapshot.key.locator(snapshot.location_revision)?;
    Ok(ActivityWorkspaceScope {
        location_id: snapshot.location_id,
        location_revision: snapshot.location_revision,
        locator,
        workspace_id: workspace.id(),
        workspace_revision: workspace.revision(),
    })
}

fn location_row(location: &forge_domain::RegisteredLocation) -> LocationRow {
    LocationRow {
        machine_id: location.id().to_string().into(),
        revision: location.revision().get().to_string().into(),
        display_name: location.name().as_str().into(),
        root: location
            .root()
            .as_path()
            .to_string_lossy()
            .into_owned()
            .into(),
        state: location_state_label(location.state()).into(),
    }
}

fn location_rows(locations: &[forge_domain::RegisteredLocation]) -> Vec<LocationRow> {
    locations.iter().take(100).map(location_row).collect()
}

fn workspace_row(candidate: &forge_workspace::WorkspaceCandidate) -> WorkspaceRow {
    let signals = candidate.signals();
    WorkspaceRow {
        label: candidate.display_label().into_owned().into(),
        kind: workspace_kind_label(candidate.kind()).into(),
        relative_display: candidate
            .relative_root()
            .to_string_lossy()
            .into_owned()
            .into(),
        signals: format!(
            "cargo={} git={} agents={} forge={}",
            signal_label(signals.cargo_workspace()),
            signal_label(signals.git_repository()),
            signal_label(signals.agent_instructions()),
            signal_label(signals.forge_state()),
        )
        .into(),
    }
}

fn workspace_rows(candidates: &[forge_workspace::WorkspaceCandidate]) -> Vec<WorkspaceRow> {
    candidates.iter().take(256).map(workspace_row).collect()
}

fn parse_discover_target(
    id: &str,
    revision: &str,
) -> Result<(LocationId, LocationRevision), UiDiscoverTargetError> {
    let id = LocationId::from_str(id).map_err(UiDiscoverTargetError::Id)?;
    let revision = revision
        .parse::<i64>()
        .map_err(UiDiscoverTargetError::RevisionParse)
        .and_then(|value| {
            LocationRevision::new(value).map_err(UiDiscoverTargetError::RevisionValue)
        })?;
    Ok((id, revision))
}

fn location_state_label(state: LocationState) -> &'static str {
    match state {
        LocationState::Enabled => "Enabled",
        LocationState::Disabled => "Disabled",
    }
}

fn workspace_kind_label(kind: WorkspaceCandidateKind) -> &'static str {
    match kind {
        WorkspaceCandidateKind::LocationRoot => "Location root",
        WorkspaceCandidateKind::DirectChild => "Direct child",
    }
}

fn signal_label(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn location_error_code_message(error: &LocationWorkerError) -> (&'static str, String) {
    match error {
        LocationWorkerError::Service(service) => match service {
            LocationServiceError::Repository(repository) => match repository {
                LocationRepositoryError::AlreadyRegistered { .. } => {
                    ("LOCATION_ALREADY_REGISTERED", repository.to_string())
                }
                LocationRepositoryError::IdentityConflict(_) => {
                    ("LOCATION_ID_CONFLICT", repository.to_string())
                }
                LocationRepositoryError::NotFound(_) => {
                    ("LOCATION_NOT_FOUND", repository.to_string())
                }
                LocationRepositoryError::RevisionConflict { .. } => {
                    ("LOCATION_REVISION_CONFLICT", repository.to_string())
                }
                LocationRepositoryError::RevisionOverflow { .. } => {
                    ("LOCATION_REVISION_OVERFLOW", repository.to_string())
                }
                LocationRepositoryError::Backend { .. } => {
                    ("LOCATION_REPOSITORY_ERROR", repository.to_string())
                }
            },
            LocationServiceError::Discovery(discovery) => match discovery {
                WorkspaceDiscoveryError::LocationDisabled(_) => {
                    ("LOCATION_DISABLED", discovery.to_string())
                }
                WorkspaceDiscoveryError::LocationUnavailable { .. } => {
                    ("LOCATION_UNAVAILABLE", discovery.to_string())
                }
                WorkspaceDiscoveryError::LocationIsNotDirectory(_) => {
                    ("LOCATION_NOT_DIRECTORY", discovery.to_string())
                }
                WorkspaceDiscoveryError::CanonicalizeLocation { .. } => {
                    ("LOCATION_CANONICALIZE_ERROR", discovery.to_string())
                }
                WorkspaceDiscoveryError::LocationIdentityMoved { .. } => {
                    ("LOCATION_IDENTITY_MOVED", discovery.to_string())
                }
                WorkspaceDiscoveryError::ReadLocation { .. } => {
                    ("LOCATION_READ_ERROR", discovery.to_string())
                }
                WorkspaceDiscoveryError::ReadEntry { .. }
                | WorkspaceDiscoveryError::InspectEntry { .. }
                | WorkspaceDiscoveryError::CanonicalizeChild { .. }
                | WorkspaceDiscoveryError::ChildEscapesLocation { .. }
                | WorkspaceDiscoveryError::TooManyCandidates { .. } => {
                    ("WORKSPACE_DISCOVERY_ERROR", discovery.to_string())
                }
            },
            LocationServiceError::WorkspaceKey(key) => match key {
                WorkspaceKeyResolveError::LocationMismatch { .. } => {
                    ("WORKSPACE_LOCATION_MISMATCH", key.to_string())
                }
                WorkspaceKeyResolveError::NotFound { .. } => {
                    ("WORKSPACE_CANDIDATE_STALE", key.to_string())
                }
            },
            LocationServiceError::WorkspaceResolve(_) => {
                ("WORKSPACE_RESOLVE_ERROR", service.to_string())
            }
            LocationServiceError::WorkspaceLocator(_) => {
                ("WORKSPACE_LOCATOR_INVALID", service.to_string())
            }
            LocationServiceError::InspectSelectedPath { .. } => {
                ("LOCATION_PATH_ERROR", service.to_string())
            }
            LocationServiceError::SelectedPathIsNotDirectory(_) => {
                ("LOCATION_NOT_DIRECTORY", service.to_string())
            }
            LocationServiceError::CanonicalizeSelectedPath { .. } => {
                ("LOCATION_CANONICALIZE_ERROR", service.to_string())
            }
            LocationServiceError::InvalidName(_) => ("LOCATION_NAME_INVALID", service.to_string()),
            LocationServiceError::InvalidRoot(_) => ("LOCATION_ROOT_INVALID", service.to_string()),
        },
        LocationWorkerError::ShuttingDown => ("LOCATION_WORKER_SHUTTING_DOWN", error.to_string()),
        LocationWorkerError::Unavailable => ("LOCATION_WORKER_UNAVAILABLE", error.to_string()),
        LocationWorkerError::QueueFull => ("LOCATION_QUEUE_FULL", error.to_string()),
        LocationWorkerError::RequestIdExhausted => {
            ("LOCATION_REQUEST_ID_EXHAUSTED", error.to_string())
        }
        LocationWorkerError::ThreadSpawn(_) => ("LOCATION_WORKER_START_ERROR", error.to_string()),
        LocationWorkerError::ThreadPanicked => ("LOCATION_WORKER_PANIC", error.to_string()),
        LocationWorkerError::StateLayout(layout) => {
            (workspace_layout_error_code(layout), error.to_string())
        }
        LocationWorkerError::WorkspaceStore(store) => {
            (workspace_store_error_code(store), error.to_string())
        }
        LocationWorkerError::WorkspaceRoot(_) => ("WORKSPACE_ROOT_INVALID", error.to_string()),
        LocationWorkerError::WorkspaceIdentityCommittedSelectionUnconfirmed { .. } => (
            "WORKSPACE_COMMITTED_REVALIDATION_REQUIRED",
            error.to_string(),
        ),
    }
}

fn workspace_layout_error_code(error: &StateLayoutError) -> &'static str {
    match error {
        StateLayoutError::WorkspaceFingerprintRootIsSymlink(_) => "WORKSPACE_ROOT_SYMLINK",
        StateLayoutError::WorkspaceFingerprintRootMoved { .. } => "WORKSPACE_ROOT_MOVED",
        StateLayoutError::WorkspaceIsNotDirectory(_)
        | StateLayoutError::WorkspaceFingerprintRootNotDirectory(_) => {
            "WORKSPACE_ROOT_NOT_DIRECTORY"
        }
        _ => "WORKSPACE_LAYOUT_ERROR",
    }
}

fn workspace_store_error_code(error: &WorkspaceStoreError) -> &'static str {
    match error {
        WorkspaceStoreError::WorkspaceRootBindingConflict { .. } => "WORKSPACE_BINDING_CONFLICT",
        WorkspaceStoreError::LocationBindingConflict { .. } => "WORKSPACE_IDENTITY_CONFLICT",
        _ => "WORKSPACE_STORE_ERROR",
    }
}

fn is_revision_conflict(error: &LocationWorkerError) -> bool {
    matches!(
        error,
        LocationWorkerError::Service(LocationServiceError::Repository(
            LocationRepositoryError::RevisionConflict { .. }
        ))
    )
}

fn folder_picker_error_status(error: &FolderPickerError) -> String {
    let code = match error {
        FolderPickerError::MainThreadRequired => "FOLDER_PICKER_MAIN_THREAD",
        FolderPickerError::NativeDialogAborted => "FOLDER_PICKER_ABORTED",
        FolderPickerError::AcceptedWithoutUrl => "FOLDER_PICKER_MISSING_URL",
        FolderPickerError::AcceptedWithoutFilePath => "FOLDER_PICKER_MISSING_PATH",
        FolderPickerError::UnexpectedModalResponse { .. } => "FOLDER_PICKER_UNEXPECTED_RESPONSE",
        FolderPickerError::UnsupportedPlatform => "FOLDER_PICKER_UNSUPPORTED",
    };
    format!("ERROR [{code}] {error}")
}

fn observed_timestamp_now() -> Result<TimestampMillis, UiLocationPreparationError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UiLocationPreparationError::ClockBeforeEpoch)?;
    let millis = i64::try_from(elapsed.as_millis())
        .map_err(|_| UiLocationPreparationError::TimestampOverflow)?;
    TimestampMillis::new(millis).map_err(UiLocationPreparationError::InvalidTimestamp)
}

fn prepare_register_action<Now, Id>(
    name: LocationName,
    selection: FolderSelection,
    now: Now,
    id_factory: Id,
) -> Result<Option<LocationAction>, UiLocationPreparationError>
where
    Now: FnOnce() -> Result<TimestampMillis, UiLocationPreparationError>,
    Id: FnOnce() -> LocationId,
{
    let FolderSelection::Selected(root) = selection else {
        return Ok(None);
    };
    let id = id_factory();
    let observed_at = now()?;
    Ok(Some(LocationAction::register(id, name, root, observed_at)))
}

fn bootstrap_registry(path: impl Into<PathBuf>) -> Result<ApplicationServices, AppError> {
    let registry = GlobalRegistry::open(path)?;
    let registry_health = registry.health()?;
    Ok(ApplicationServices {
        location_service: LocationService::new(registry),
        registry_health,
    })
}

fn run_application(paths: &AppPaths, services: ApplicationServices) -> Result<(), AppError> {
    let ApplicationServices {
        location_service,
        registry_health: _registry_health,
    } = services;
    let mut location_worker = LocationServiceWorker::start(location_service)?;
    let harness_catalog = HarnessCatalog::open(paths.harness_catalog_path())?;
    let mut harness_worker = HarnessLibraryWorker::start(HarnessLibrary::new(harness_catalog))?;
    // Keep the control plane on its own GlobalRegistry connection and worker.
    // The Location worker remains the sole owner of its application service;
    // Activity projections use the control worker's bounded pending boundary.
    let control_registry = GlobalRegistry::open(registry_path(paths))?;
    let (activity_client, mut activity_worker) =
        ForgeControl::new(control_registry).start_worker()?;
    info!("starting Heterarchy Forge desktop application");

    let mut execution_coordinator = ForgeExecutionCoordinator::start(activity_client.clone(), 16)?;
    let mut approval_coordinator =
        ForgeApprovalCoordinator::start(activity_client.clone(), execution_coordinator.client())?;
    let mut runtime = RuntimeService::start_with_stop_participant(Arc::new(DesktopApprovalStop(
        approval_coordinator.client(),
    )))?;
    let runtime_client = runtime.client();
    let events = runtime.take_event_stream()?;
    let app = AppWindow::new()?;
    let tray = ForgeTray::new()?;
    let about = AboutWindow::new()?;
    app.set_application_support_path(path_string(paths.application_support()));

    bind_runtime_actions(&app, &tray, &runtime_client);
    bind_window_actions(&app, &tray);
    bind_about_action(&tray, &about);
    bind_quit_actions(&app, &tray);
    let ui_channels = setup_ui_channels(&app, &tray, &runtime_client);

    app.show()?;
    tray.show()?;
    let pumps = start_desktop_pumps(
        &app,
        &tray,
        events,
        DesktopPumpServices {
            location: location_worker.client(),
            activity: activity_client,
            approval: approval_coordinator.client(),
            harness: harness_worker.client(),
            diagnostics_dir: paths.diagnostics_dir(),
        },
        ui_channels,
    );
    let run_result = slint::run_event_loop().map_err(AppError::Ui);

    pumps.stop();
    shutdown_application(
        &mut runtime,
        &mut approval_coordinator,
        &mut execution_coordinator,
        &mut activity_worker,
        &mut harness_worker,
        &mut location_worker,
    )?;
    run_result
}

fn setup_ui_channels(
    app: &AppWindow,
    tray: &ForgeTray,
    runtime_client: &RuntimeClient,
) -> UiChannelBundle {
    let (location_intent_tx, location_intents) = mpsc::sync_channel(1);
    let (activity_intent_tx, activity_intents) = mpsc::sync_channel(4);
    let (approval_intent_tx, approval_intents) = mpsc::sync_channel(4);
    let (goal_intent_tx, goal_intents) = mpsc::sync_channel(8);
    let (dag_intent_tx, dag_intents) = mpsc::sync_channel(8);
    let (doctor_intent_tx, doctor_intents) = mpsc::sync_channel(4);
    let (harness_intent_tx, harness_intents) = mpsc::sync_channel(4);
    let folder_picker_open = Rc::new(Cell::new(false));
    let location_busy = Rc::new(Cell::new(false));
    let activity_busy = Rc::new(Cell::new(false));
    let approval_busy = Rc::new(Cell::new(false));
    let goal_busy = Rc::new(Cell::new(false));
    let dag_busy = Rc::new(Cell::new(false));
    let harness_busy = Rc::new(Cell::new(false));

    bind_location_actions(
        app,
        &location_intent_tx,
        &folder_picker_open,
        &location_busy,
    );
    bind_activity_actions(app, &activity_intent_tx, &activity_busy);
    bind_goal_actions(app, &goal_intent_tx, &goal_busy);
    bind_dag_actions(app, &dag_intent_tx);
    bind_doctor_actions(app, &doctor_intent_tx);
    bind_harness_actions(app, &harness_intent_tx, &harness_busy);
    bind_approval_actions(
        app,
        tray,
        runtime_client,
        &approval_intent_tx,
        &approval_busy,
    );

    UiChannelBundle {
        location_intents,
        location_sinks: LocationUiSinks {
            activity: activity_intent_tx,
            approval: approval_intent_tx,
            goal: goal_intent_tx,
            dag: dag_intent_tx,
            doctor: doctor_intent_tx,
            harness: harness_intent_tx,
        },
        activity_intents,
        approval_intents,
        goal_intents,
        dag_intents,
        doctor_intents,
        harness_intents,
        location_busy,
        activity_busy,
        approval_busy,
        goal_busy,
        dag_busy,
        harness_busy,
    }
}

fn start_desktop_pumps(
    app: &AppWindow,
    tray: &ForgeTray,
    events: RuntimeEventStream,
    services: DesktopPumpServices,
    channels: UiChannelBundle,
) -> DesktopPumps {
    let DesktopPumpServices {
        location: location_client,
        activity: activity_client,
        approval: approval_client,
        harness: harness_client,
        diagnostics_dir,
    } = services;
    let UiChannelBundle {
        location_intents,
        location_sinks,
        activity_intents,
        approval_intents,
        goal_intents,
        dag_intents,
        doctor_intents,
        harness_intents,
        location_busy,
        activity_busy,
        approval_busy,
        goal_busy,
        dag_busy,
        harness_busy,
    } = channels;
    let dag_intents_for_goal = location_sinks.dag.clone();
    DesktopPumps {
        projection: start_projection_pump(app, tray, events),
        location: start_location_pump(
            app,
            location_client,
            location_intents,
            location_sinks,
            location_busy,
        ),
        activity: start_activity_pump(
            app,
            activity_client.clone(),
            activity_intents,
            activity_busy,
        ),
        goal: start_goal_pump(
            app,
            activity_client.clone(),
            goal_intents,
            dag_intents_for_goal,
            goal_busy,
        ),
        dag: start_dag_pump(app, activity_client.clone(), dag_intents, dag_busy),
        doctor: start_doctor_pump(
            app,
            activity_client.clone(),
            doctor_intents,
            diagnostics_dir,
        ),
        approval: start_approval_pump(app, tray, approval_client, approval_intents, approval_busy),
        harness: start_harness_pump(
            app,
            harness_client,
            activity_client,
            harness_intents,
            harness_busy,
        ),
    }
}

fn shutdown_application(
    runtime: &mut RuntimeService,
    approval_coordinator: &mut ForgeApprovalCoordinator,
    execution_coordinator: &mut ForgeExecutionCoordinator,
    activity_worker: &mut ForgeControlWorker,
    harness_worker: &mut HarnessLibraryWorker,
    location_worker: &mut LocationServiceWorker<GlobalRegistry>,
) -> Result<(), AppError> {
    // Runtime stop drains every owned process group first. The execution owner
    // then joins before the control worker, keeping terminal journaling viable.
    runtime.shutdown()?;
    let _approval_report = approval_coordinator.shutdown()?;
    let _execution_report = execution_coordinator.shutdown()?;
    activity_worker.shutdown()?;
    harness_worker.shutdown()?;
    location_worker.shutdown()?;
    Ok(())
}

fn bind_location_actions(
    app: &AppWindow,
    intents: &SyncSender<UiLocationIntent>,
    folder_picker_open: &Rc<Cell<bool>>,
    location_action_busy: &Rc<Cell<bool>>,
) {
    bind_add_location(app, intents, folder_picker_open, location_action_busy);
    bind_refresh_locations(app, intents, folder_picker_open, location_action_busy);
    bind_discover_location(app, intents, folder_picker_open, location_action_busy);
    bind_select_workspace(app, intents);
}

fn bind_add_location(
    app: &AppWindow,
    intents: &SyncSender<UiLocationIntent>,
    folder_picker_open: &Rc<Cell<bool>>,
    location_action_busy: &Rc<Cell<bool>>,
) {
    let intents_for_add = intents.clone();
    let app_for_add = app.clone_strong();
    let picker_for_add = Rc::clone(folder_picker_open);
    let busy_for_add = Rc::clone(location_action_busy);
    app.on_add_location(move |name| {
        if picker_for_add.get() || busy_for_add.get() {
            return;
        }
        let name = match LocationName::new(name.to_string()) {
            Ok(name) => name,
            Err(error) => {
                app_for_add
                    .set_location_status(format!("ERROR [LOCATION_NAME_INVALID] {error}").into());
                return;
            }
        };
        picker_for_add.set(true);
        app_for_add.set_folder_picker_open(true);
        let selection = pick_folder();
        picker_for_add.set(false);
        app_for_add.set_folder_picker_open(false);
        match selection {
            Ok(selection) => {
                match prepare_register_action(name, selection, observed_timestamp_now, || {
                    LocationId::from_uuid(Uuid::now_v7())
                }) {
                    Ok(Some(action)) => {
                        enqueue_location_intent(
                            &intents_for_add,
                            &app_for_add,
                            &busy_for_add,
                            UiLocationIntent::Register(action),
                        );
                    }
                    Ok(None) => {}
                    Err(error) => app_for_add
                        .set_location_status(format!("ERROR [LOCATION_TIMESTAMP] {error}").into()),
                }
            }
            Err(error) => {
                app_for_add.set_location_status(folder_picker_error_status(&error).into());
            }
        }
    });
}

fn bind_refresh_locations(
    app: &AppWindow,
    intents: &SyncSender<UiLocationIntent>,
    folder_picker_open: &Rc<Cell<bool>>,
    location_action_busy: &Rc<Cell<bool>>,
) {
    let intents_for_refresh = intents.clone();
    let app_for_refresh = app.clone_strong();
    let picker_for_refresh = Rc::clone(folder_picker_open);
    let busy_for_refresh = Rc::clone(location_action_busy);
    app.on_refresh_locations(move || {
        if picker_for_refresh.get() || busy_for_refresh.get() {
            return;
        }
        enqueue_location_intent(
            &intents_for_refresh,
            &app_for_refresh,
            &busy_for_refresh,
            UiLocationIntent::Refresh,
        );
    });
}

fn bind_discover_location(
    app: &AppWindow,
    intents: &SyncSender<UiLocationIntent>,
    folder_picker_open: &Rc<Cell<bool>>,
    location_action_busy: &Rc<Cell<bool>>,
) {
    let intents_for_discover = intents.clone();
    let app_for_discover = app.clone_strong();
    let picker_for_discover = Rc::clone(folder_picker_open);
    let busy_for_discover = Rc::clone(location_action_busy);
    app.on_discover_location(move |id, revision| {
        if picker_for_discover.get() || busy_for_discover.get() {
            return;
        }
        let (id, revision) = match parse_discover_target(&id, &revision) {
            Ok(target) => target,
            Err(error @ UiDiscoverTargetError::Id(_)) => {
                app_for_discover
                    .set_location_status(format!("ERROR [LOCATION_ID_INVALID] {error}").into());
                return;
            }
            Err(error) => {
                app_for_discover.set_location_status(
                    format!("ERROR [LOCATION_REVISION_INVALID] {error}").into(),
                );
                return;
            }
        };
        enqueue_location_intent(
            &intents_for_discover,
            &app_for_discover,
            &busy_for_discover,
            UiLocationIntent::Discover {
                id,
                expected_revision: revision,
            },
        );
    });
}

fn bind_select_workspace(app: &AppWindow, intents: &SyncSender<UiLocationIntent>) {
    let intents_for_select = intents.clone();
    let app_for_select = app.clone_strong();
    app.on_select_workspace(move |index| {
        if intents_for_select
            .try_send(UiLocationIntent::SelectWorkspace(index))
            .is_err()
        {
            app_for_select.set_workspace_status("Workspace selection is busy; try again.".into());
        }
    });
}

fn bind_activity_actions(
    app: &AppWindow,
    intents: &SyncSender<UiActivityIntent>,
    activity_action_busy: &Rc<Cell<bool>>,
) {
    let intents_for_refresh = intents.clone();
    let app_for_refresh = app.clone_strong();
    let busy_for_refresh = Rc::clone(activity_action_busy);
    app.on_refresh_activities(move || {
        if busy_for_refresh.get() {
            return;
        }
        match intents_for_refresh.try_send(UiActivityIntent::Refresh) {
            Ok(()) => busy_for_refresh.set(true),
            Err(mpsc::TrySendError::Full(_)) => app_for_refresh.set_activity_status(
                "ERROR [ACTIVITY_QUEUE_FULL] Activity refresh queue is full.".into(),
            ),
            Err(mpsc::TrySendError::Disconnected(_)) => app_for_refresh.set_activity_status(
                "ERROR [ACTIVITY_WORKER_UNAVAILABLE] Activity worker is unavailable.".into(),
            ),
        }
    });

    let intents_for_activity = intents.clone();
    let app_for_activity = app.clone_strong();
    let busy_for_activity = Rc::clone(activity_action_busy);
    app.on_select_activity(move |value| {
        if busy_for_activity.get() {
            return;
        }
        let Ok(activity_id) = ActivityId::from_str(value.as_str()) else {
            app_for_activity.set_diff_status(
                "ERROR [ACTIVITY_ID_INVALID] Activity identity is invalid.".into(),
            );
            return;
        };
        match intents_for_activity.try_send(UiActivityIntent::SelectActivity(activity_id)) {
            Ok(()) => busy_for_activity.set(true),
            Err(mpsc::TrySendError::Full(_)) => app_for_activity
                .set_diff_status("ERROR [ACTIVITY_QUEUE_FULL] Request queue is full.".into()),
            Err(mpsc::TrySendError::Disconnected(_)) => app_for_activity.set_diff_status(
                "ERROR [ACTIVITY_WORKER_UNAVAILABLE] Activity worker is unavailable.".into(),
            ),
        }
    });

    let intents_for_diff = intents.clone();
    let app_for_diff = app.clone_strong();
    let busy_for_diff = Rc::clone(activity_action_busy);
    app.on_view_diff(move |value| {
        if busy_for_diff.get() {
            return;
        }
        let Ok(diff_id) = DiffId::from_str(value.as_str()) else {
            app_for_diff
                .set_diff_status("ERROR [DIFF_ID_INVALID] Diff identity is invalid.".into());
            return;
        };
        match intents_for_diff.try_send(UiActivityIntent::ViewDiff(diff_id)) {
            Ok(()) => busy_for_diff.set(true),
            Err(mpsc::TrySendError::Full(_)) => app_for_diff
                .set_diff_status("ERROR [ACTIVITY_QUEUE_FULL] Request queue is full.".into()),
            Err(mpsc::TrySendError::Disconnected(_)) => app_for_diff.set_diff_status(
                "ERROR [ACTIVITY_WORKER_UNAVAILABLE] Activity worker is unavailable.".into(),
            ),
        }
    });

    let intents_for_close = intents.clone();
    let app_for_close = app.clone_strong();
    app.on_close_diff_view(move || {
        if intents_for_close
            .try_send(UiActivityIntent::CloseDiff)
            .is_err()
        {
            app_for_close
                .set_diff_status("ERROR [ACTIVITY_QUEUE_FULL] Request queue is full.".into());
        }
    });
}

fn bind_approval_actions(
    app: &AppWindow,
    tray: &ForgeTray,
    runtime_client: &RuntimeClient,
    intents: &SyncSender<UiApprovalIntent>,
    busy: &Rc<Cell<bool>>,
) {
    bind_open_approvals(app, tray);

    let intents_for_refresh = intents.clone();
    let app_for_refresh = app.clone_strong();
    let busy_for_refresh = Rc::clone(busy);
    app.on_refresh_approvals(move || {
        enqueue_approval_intent(
            &intents_for_refresh,
            &app_for_refresh,
            &busy_for_refresh,
            UiApprovalIntent::Refresh,
        );
    });

    let intents_for_approve = intents.clone();
    let app_for_approve = app.clone_strong();
    let busy_for_approve = Rc::clone(busy);
    app.on_approve_request(move |value| {
        let Ok(id) = ApprovalRequestId::from_str(value.as_str()) else {
            app_for_approve.set_approval_status(
                "ERROR [APPROVAL_ID_INVALID] Invalid approval identity.".into(),
            );
            return;
        };
        enqueue_approval_intent(
            &intents_for_approve,
            &app_for_approve,
            &busy_for_approve,
            UiApprovalIntent::Approve(id),
        );
    });

    let intents_for_reject = intents.clone();
    let app_for_reject = app.clone_strong();
    let busy_for_reject = Rc::clone(busy);
    app.on_reject_request(move |value| {
        let Ok(id) = ApprovalRequestId::from_str(value.as_str()) else {
            app_for_reject.set_approval_status(
                "ERROR [APPROVAL_ID_INVALID] Invalid approval identity.".into(),
            );
            return;
        };
        enqueue_approval_intent(
            &intents_for_reject,
            &app_for_reject,
            &busy_for_reject,
            UiApprovalIntent::Reject(id),
        );
    });

    let intents_for_auto = intents.clone();
    let app_for_auto = app.clone_strong();
    let busy_for_auto = Rc::clone(busy);
    app.on_set_auto_approval(move |enabled| {
        enqueue_approval_intent(
            &intents_for_auto,
            &app_for_auto,
            &busy_for_auto,
            UiApprovalIntent::SetAutoApproval(enabled),
        );
    });
    let intents_for_tray_auto = intents.clone();
    let app_for_tray_auto = app.clone_strong();
    let busy_for_tray_auto = Rc::clone(busy);
    tray.on_set_auto_approval(move |enabled| {
        enqueue_approval_intent(
            &intents_for_tray_auto,
            &app_for_tray_auto,
            &busy_for_tray_auto,
            UiApprovalIntent::SetAutoApproval(enabled),
        );
    });

    bind_workspace_stop_actions(app, tray, intents, busy);
    bind_emergency_stop_actions(app, tray, runtime_client, intents, busy);
}

fn bind_workspace_stop_actions(
    app: &AppWindow,
    tray: &ForgeTray,
    intents: &SyncSender<UiApprovalIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let intents_for_workspace_stop = intents.clone();
    let app_for_workspace_stop = app.clone_strong();
    let busy_for_workspace_stop = Rc::clone(busy);
    app.on_stop_workspace_work(move || {
        enqueue_approval_intent(
            &intents_for_workspace_stop,
            &app_for_workspace_stop,
            &busy_for_workspace_stop,
            UiApprovalIntent::StopWorkspace,
        );
    });
    let intents_for_tray_workspace_stop = intents.clone();
    let app_for_tray_workspace_stop = app.clone_strong();
    let busy_for_tray_workspace_stop = Rc::clone(busy);
    tray.on_stop_workspace_work(move || {
        enqueue_approval_intent(
            &intents_for_tray_workspace_stop,
            &app_for_tray_workspace_stop,
            &busy_for_tray_workspace_stop,
            UiApprovalIntent::StopWorkspace,
        );
    });
}

fn bind_emergency_stop_actions(
    app: &AppWindow,
    tray: &ForgeTray,
    runtime_client: &RuntimeClient,
    intents: &SyncSender<UiApprovalIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let intents_for_stop = intents.clone();
    let app_for_stop = app.clone_strong();
    let busy_for_stop = Rc::clone(busy);
    let runtime_for_stop = runtime_client.clone();
    app.on_emergency_stop(move || {
        send_runtime_command(&runtime_for_stop, RuntimeCommand::EmergencyStop);
        enqueue_approval_intent(
            &intents_for_stop,
            &app_for_stop,
            &busy_for_stop,
            UiApprovalIntent::EmergencyStop,
        );
    });
    let intents_for_tray_stop = intents.clone();
    let app_for_tray_stop = app.clone_strong();
    let busy_for_tray_stop = Rc::clone(busy);
    let runtime_for_tray_stop = runtime_client.clone();
    tray.on_emergency_stop(move || {
        send_runtime_command(&runtime_for_tray_stop, RuntimeCommand::EmergencyStop);
        enqueue_approval_intent(
            &intents_for_tray_stop,
            &app_for_tray_stop,
            &busy_for_tray_stop,
            UiApprovalIntent::EmergencyStop,
        );
    });
}

fn bind_open_approvals(app: &AppWindow, tray: &ForgeTray) {
    let app_for_open = app.as_weak();
    tray.on_open_approvals(move || {
        let Some(app_for_open) = app_for_open.upgrade() else {
            return;
        };
        if let Err(error) = app_for_open.show() {
            error!(%error, "failed to show approval queue");
        }
    });
}

fn enqueue_approval_intent(
    intents: &SyncSender<UiApprovalIntent>,
    app: &AppWindow,
    busy: &Rc<Cell<bool>>,
    intent: UiApprovalIntent,
) {
    if busy.get() {
        return;
    }
    match intents.try_send(intent) {
        Ok(()) => {
            busy.set(true);
            app.set_approval_action_busy(true);
        }
        Err(mpsc::TrySendError::Full(_)) => {
            app.set_approval_status("ERROR [APPROVAL_QUEUE_FULL] Approval queue is full.".into());
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            app.set_approval_status(
                "ERROR [APPROVAL_WORKER_UNAVAILABLE] Approval worker is unavailable.".into(),
            );
        }
    }
}

fn enqueue_location_intent(
    intents: &SyncSender<UiLocationIntent>,
    app: &AppWindow,
    busy: &Rc<Cell<bool>>,
    intent: UiLocationIntent,
) {
    match try_admit_location_intent(intents, busy, intent) {
        Ok(()) => app.set_location_action_busy(true),
        Err(UiLocationAdmissionError::Busy) => {}
        Err(UiLocationAdmissionError::QueueFull) => {
            app.set_location_action_busy(false);
            app.set_location_status(
                "ERROR [LOCATION_QUEUE_FULL] Location action queue is full.".into(),
            );
        }
    }
}

fn try_admit_location_intent(
    intents: &SyncSender<UiLocationIntent>,
    busy: &Rc<Cell<bool>>,
    intent: UiLocationIntent,
) -> Result<(), UiLocationAdmissionError> {
    if busy.replace(true) {
        return Err(UiLocationAdmissionError::Busy);
    }
    if intents.try_send(intent).is_err() {
        busy.set(false);
        return Err(UiLocationAdmissionError::QueueFull);
    }
    Ok(())
}

fn start_location_pump(
    app: &AppWindow,
    client: LocationServiceClient,
    intents: Receiver<UiLocationIntent>,
    sinks: LocationUiSinks,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller =
        LocationUiController::new(app.clone_strong(), client, intents, sinks, busy);
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
}

fn start_activity_pump(
    app: &AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiActivityIntent>,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller = ActivityUiController::new(app.clone_strong(), client, intents, busy);
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
}

fn start_approval_pump(
    app: &AppWindow,
    tray: &ForgeTray,
    client: ForgeApprovalCoordinatorClient,
    intents: Receiver<UiApprovalIntent>,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller = ApprovalUiController::new(
        app.clone_strong(),
        tray.clone_strong(),
        client,
        intents,
        busy,
    );
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
}

fn bind_runtime_actions(app: &AppWindow, tray: &ForgeTray, runtime_client: &RuntimeClient) {
    let client = runtime_client.clone();
    app.on_start_runtime(move || send_runtime_command(&client, RuntimeCommand::Start));

    let client = runtime_client.clone();
    app.on_stop_runtime(move || send_runtime_command(&client, RuntimeCommand::Stop));

    let client = runtime_client.clone();
    app.on_restart_runtime(move || send_runtime_command(&client, RuntimeCommand::Restart));

    let client = runtime_client.clone();
    tray.on_start_runtime(move || send_runtime_command(&client, RuntimeCommand::Start));

    let client = runtime_client.clone();
    tray.on_stop_runtime(move || send_runtime_command(&client, RuntimeCommand::Stop));

    let client = runtime_client.clone();
    tray.on_restart_runtime(move || send_runtime_command(&client, RuntimeCommand::Restart));
}

fn bind_window_actions(app: &AppWindow, tray: &ForgeTray) {
    let app_weak = app.as_weak();
    tray.on_open_window(move || {
        let Some(window) = app_weak.upgrade() else {
            return;
        };
        if let Err(source) = window.show() {
            error!(%source, "failed to show Heterarchy Forge window");
        }
    });
}

/// Keep the About window owned by the application stack while the tray
/// callback retains only a weak handle. This makes repeated menu activation
/// idempotent without creating a tray/window retain cycle.
fn bind_about_action(tray: &ForgeTray, about: &AboutWindow) {
    let about_weak = about.as_weak();
    tray.on_open_about(move || {
        let Some(window) = about_weak.upgrade() else {
            return;
        };
        if let Err(source) = window.show() {
            error!(%source, "failed to show Heterarchy Forge About window");
        }
    });
}

fn bind_quit_actions(app: &AppWindow, tray: &ForgeTray) {
    app.on_quit_application(request_event_loop_shutdown);
    tray.on_quit_application(request_event_loop_shutdown);
}

fn request_event_loop_shutdown() {
    if let Err(source) = slint::quit_event_loop() {
        error!(%source, "failed to request Slint event-loop shutdown");
    }
}

fn send_runtime_command(client: &RuntimeClient, command: RuntimeCommand) {
    if let Err(source) = client.send(command) {
        error!(?command, %source, "failed to enqueue runtime command");
    }
}

fn start_projection_pump(
    app: &AppWindow,
    tray: &ForgeTray,
    mut events: RuntimeEventStream,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let timer_weak = Rc::downgrade(&timer);
    let app = app.clone_strong();
    let tray = tray.clone_strong();

    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        match poll_latest_projection(&mut events) {
            Ok(Some(projection)) => {
                apply_window_projection(&app, &projection);
                tray.set_runtime_status(projection.status.into());
            }
            Ok(None) => {}
            Err(RuntimeServiceError::EventStreamClosed) => stop_projection_pump(&timer_weak),
            Err(source) => {
                error!(%source, "runtime projection stream failed");
                stop_projection_pump(&timer_weak);
            }
        }
    });

    timer
}

fn stop_projection_pump(timer: &RcWeak<Timer>) {
    if let Some(timer) = timer.upgrade() {
        timer.stop();
    }
}

fn poll_latest_projection(
    events: &mut RuntimeEventStream,
) -> Result<Option<UiRuntimeProjection>, RuntimeServiceError> {
    events
        .take_latest()
        .map(|projection| projection.map(|projection| UiRuntimeProjection::from(&projection)))
}

fn apply_window_projection(window: &AppWindow, projection: &UiRuntimeProjection) {
    window.set_runtime_status(projection.status.clone().into());
    window.set_runtime_detail(projection.detail.clone().into());
    window.set_runtime_generation(projection.generation);
    window.set_uptime_seconds(projection.uptime_seconds);
}

fn run_doctor(paths: &AppPaths, registry_health: Option<RegistryHealth>) -> Result<(), AppError> {
    let mut runtime = RuntimeService::start()?;
    let mut events = runtime.take_event_stream()?;
    let projection = wait_for_phase(&mut events, RuntimePhase::Running, DOCTOR_TIMEOUT)?;

    if let Some(registry_health) = registry_health {
        println!("Heterarchy Forge doctor: PASS");
        println!("{}", format_registry_health(&registry_health));
    } else {
        println!("Heterarchy Forge doctor: PASS_WITH_WARNINGS");
        println!("registry_health=NOT_INITIALIZED");
    }
    println!(
        "application_support={}",
        paths.application_support().display()
    );
    println!("cache={}", paths.cache().display());
    println!("logs={}", paths.logs().display());
    println!("runtime_phase={}", projection.phase().label());
    println!("runtime_generation={}", projection.generation().get());

    runtime.shutdown()?;
    Ok(())
}

fn format_registry_health(health: &RegistryHealth) -> String {
    format!(
        "registry_health=PASS\nregistry_schema_version={}\nregistry_journal_mode={}\nregistry_foreign_keys_enabled={}",
        health.schema_version(),
        health.journal_mode(),
        health.foreign_keys_enabled(),
    )
}

fn wait_for_phase(
    events: &mut RuntimeEventStream,
    phase: RuntimePhase,
    timeout: Duration,
) -> Result<RuntimeProjection, AppError> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(AppError::DoctorTimeout(phase));
        }
        let projection = events.recv_timeout(deadline.saturating_duration_since(now))?;
        if projection.phase() == phase {
            return Ok(projection);
        }
    }
}

fn path_string(path: &Path) -> SharedString {
    path.to_string_lossy().into_owned().into()
}

#[derive(Debug, Clone)]
struct UiRuntimeProjection {
    status: String,
    detail: String,
    generation: i32,
    uptime_seconds: i32,
}

impl From<&RuntimeProjection> for UiRuntimeProjection {
    fn from(projection: &RuntimeProjection) -> Self {
        let status = projection.phase().label().to_owned();
        let detail = match projection {
            RuntimeProjection::Starting { .. } => "Booting background Tokio runtime".to_owned(),
            RuntimeProjection::Running { .. } => {
                "Runtime is ready for workspace services".to_owned()
            }
            RuntimeProjection::Restarting { .. } => "Restarting owned runtime services".to_owned(),
            RuntimeProjection::Stopping { .. } => "Stopping owned runtime services".to_owned(),
            RuntimeProjection::Stopped { .. } => "Runtime is stopped".to_owned(),
            RuntimeProjection::Failed { code, .. } => {
                format!("Runtime failed with code {}", code.label())
            }
        };

        Self {
            status,
            detail,
            generation: saturating_i32(projection.generation().get()),
            uptime_seconds: saturating_i32(projection.uptime_seconds()),
        }
    }
}

fn saturating_i32(value: u64) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

#[derive(Debug, Error)]
enum AppError {
    #[error(transparent)]
    AppPath(#[from] AppPathError),
    #[error(transparent)]
    Logging(#[from] LoggingError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    LocationWorker(#[from] LocationWorkerError),
    #[error(transparent)]
    HarnessCatalog(#[from] HarnessCatalogError),
    #[error(transparent)]
    HarnessWorker(#[from] HarnessWorkerError),
    #[error(transparent)]
    ControlWorker(#[from] forge_control::ControlWorkerError),
    #[error(transparent)]
    Runtime(#[from] RuntimeServiceError),
    #[error(transparent)]
    ExecutionCoordinator(#[from] ForgeExecutionCoordinatorError),
    #[error(transparent)]
    ApprovalCoordinator(#[from] ForgeApprovalCoordinatorError),
    #[error(transparent)]
    Ui(#[from] slint::PlatformError),
    #[error(transparent)]
    Control(#[from] forge_control::ControlError),
    #[error(transparent)]
    Locator(#[from] WorkspaceLocatorError),
    #[error(transparent)]
    WorkspaceStore(#[from] WorkspaceStoreError),
    #[error(transparent)]
    StateLayout(#[from] StateLayoutError),
    #[error(transparent)]
    LocationService(#[from] LocationServiceError),
    #[error("--recover-workspace arguments were invalid")]
    RecoveryArguments,
    #[error("recovery target did not resolve to exactly one registered ready workspace")]
    RecoveryTargetNotFound,
    #[error("recovery clock observation failed: {0}")]
    RecoveryClock(#[source] UiLocationPreparationError),
    #[error("timed out waiting for runtime phase {0:?}")]
    DoctorTimeout(RuntimePhase),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_control::ForgeControl;
    use forge_domain::{
        ActivityId, ActivityLeaseProjection, ActivityLeaseRevision, ActivityListLimit,
        ActivityLiveness, ActivityProjection, ActivityRevision, ActivityState, ChangeSetId,
        DiffArtifactHealth, DiffAttribution, DiffChangeKind, DiffContractVersions,
        DiffEvidenceTimestamps, DiffFileSummary, DiffId, DiffLineCount, DiffPayloadProjection,
        DiffRenderKind, DiffRevision, FileMutationId, LocationId, LocationName, LocationRevision,
        LocationRoot, LocationState, RegisteredActivity, RegisteredDiffEvidence,
        RegisteredLocation, RegisteredWorkspace, RuntimeFailureCode, RuntimeGeneration,
        RuntimeInstanceId, RuntimeProjection, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
        WorkspaceRevision, WorkspaceRoot, WorkspaceRootFingerprint,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_runtime::RuntimeService;
    use forge_workspace::{
        LocationService, WorkspaceDiscovery, WorkspaceLocator, WorkspaceStateLayout,
    };
    use uuid::Uuid;

    use super::{
        AppError, FolderSelection, LocationAction, LocationWorkerError, UiLocationAdmissionError,
        UiLocationIntent, UiLocationPreparationError, WorkspaceActivityProjectionRequest,
        WorkspaceCandidateSnapshot, activity_rows, activity_workspace_scope, bootstrap_registry,
        diff_row, diff_scope_matches, diff_unavailable_message, format_registry_health,
        location_rows, parse_discover_target, prepare_register_action, recover_workspace_argument,
        resolved_activity_scope, run_recovery_entry, try_admit_location_intent, workspace_rows,
    };

    #[test]
    fn slint_about_attribution_is_reachable_from_top_level_tray_menu() {
        let ui_source = include_str!("../../forge-ui/ui/app-window.slint");
        let desktop_source = include_str!("main.rs");

        assert!(ui_source.contains("export component AboutWindow inherits Window"));
        assert!(ui_source.contains("AboutSlint"));
        assert!(ui_source.contains("title: \"About Heterarchy Forge\""));
        assert!(ui_source.contains("callback open-about();"));
        assert!(ui_source.contains("title: \"About Heterarchy Forge\";"));
        assert!(ui_source.contains("root.open-about();"));
        assert!(desktop_source.contains("fn bind_about_action"));
        assert!(desktop_source.contains("tray.on_open_about"));
        assert!(desktop_source.contains("about.as_weak()"));
    }

    #[test]
    fn slint_diff_inspector_is_read_only_and_activity_scoped() {
        let ui_source = include_str!("../../forge-ui/ui/app-window.slint");
        let model_source = include_str!("../../forge-ui/ui/models.slint");
        let component_source = include_str!("../../forge-ui/ui/components.slint");
        let desktop_source = include_str!("main.rs");

        assert!(model_source.contains("export struct DiffRow"));
        assert!(ui_source.contains("callback select-activity(string);"));
        assert!(ui_source.contains("callback view-diff(string);"));
        assert!(ui_source.contains("read-only: true;"));
        assert!(ui_source.contains("EVIDENCE / DIFF"));
        assert!(component_source.contains("accessible-role: list-item;"));
        assert!(component_source.contains("accessible-action-default"));
        assert!(component_source.contains("FocusScope"));
        assert!(ui_source.contains("accessible-label: \"Location name\";"));
        assert!(ui_source.contains("min-width: 1120px;"));
        assert!(ui_source.contains("min-height: 720px;"));
        assert!(desktop_source.contains("submit_diff_list"));
        assert!(desktop_source.contains("submit_diff_read"));
        assert!(desktop_source.contains("DIFF_SCOPE_STALE"));
    }

    #[test]
    fn slint_workspace_doctor_is_bounded_nonblocking_and_explicitly_exported() {
        let ui_source = include_str!("../../forge-ui/ui/app-window.slint");
        let model_source = include_str!("../../forge-ui/ui/models.slint");
        let doctor_source = include_str!("doctor_ui.rs");

        assert!(model_source.contains("export struct DoctorFindingRow"));
        assert!(ui_source.contains("callback refresh-doctor();"));
        assert!(ui_source.contains("callback export-doctor-diagnostics();"));
        assert!(ui_source.contains("WORKSPACE DOCTOR"));
        assert!(ui_source.contains("doctor-export-content"));
        assert!(ui_source.contains("read-only: true;"));
        assert!(ui_source.contains("Explicit bounded text export"));
        assert!(doctor_source.contains("submit_workspace_doctor"));
        assert!(doctor_source.contains("PendingControl<WorkspaceDoctorResult>"));
        assert!(doctor_source.contains("MAX_DOCTOR_UI_FINDINGS: usize = 64"));
        assert!(doctor_source.contains("MAX_DOCTOR_EXPORT_BYTES: usize = 16 * 1024"));
        assert!(doctor_source.contains("thread::Builder::new()"));
        assert!(!doctor_source.contains("client.workspace_doctor("));
    }

    #[test]
    fn slint_approval_queue_is_owner_controlled_nonblocking_and_tray_reachable() {
        let ui_source = include_str!("../../forge-ui/ui/app-window.slint");
        let model_source = include_str!("../../forge-ui/ui/models.slint");
        let desktop_source = include_str!("main.rs");

        assert!(model_source.contains("export struct ApprovalRow"));
        assert!(ui_source.contains("callback approve-request(string);"));
        assert!(ui_source.contains("callback reject-request(string);"));
        assert!(ui_source.contains("callback set-auto-approval(bool);"));
        assert!(ui_source.contains("callback stop-workspace-work();"));
        assert!(ui_source.contains("callback emergency-stop();"));
        assert!(ui_source.contains("title: \"Pending Approvals · \""));
        assert!(ui_source.contains("title: \"Emergency Stop\";"));
        assert!(!ui_source.contains("text: approval.id"));
        assert!(desktop_source.contains("struct ApprovalUiController"));
        assert!(desktop_source.contains("submit_list_pending"));
        assert!(desktop_source.contains("submit_stop_workspace"));
        assert!(desktop_source.contains("PendingApprovalUi"));
        assert!(desktop_source.contains("try_recv()"));
        assert!(desktop_source.contains("approval_coordinator.client()"));
    }

    fn assert_slint_workbench_models(ui_source: &str, model_source: &str, component_source: &str) {
        assert!(model_source.contains("export struct GoalRow"));
        assert!(model_source.contains("export struct DagNodeRow"));
        assert!(model_source.contains("export struct DagEdgeRow"));
        assert!(model_source.contains("column: int"));
        assert!(model_source.contains("from-column: int"));
        assert!(model_source.contains("current-path: bool"));
        assert!(model_source.contains("export struct WorkNarrativeRow"));
        assert!(ui_source.contains("DEPENDENCY GRAPH"));
        assert!(ui_source.contains("No published work step"));
        assert!(ui_source.contains("Private model reasoning is never displayed."));
        assert!(ui_source.contains("No durable Goal"));
        assert!(ui_source.contains("callback create-goal(string, string);"));
        assert!(ui_source.contains("callback complete-goal(string, string);"));
        assert!(ui_source.contains("No Chat-authored DAG"));
        assert!(ui_source.contains("callback select-dag-node(string);"));
        assert!(ui_source.contains("Read-only dependency graph revision"));
        assert!(ui_source.contains("goal-rows: [];"));
        assert!(ui_source.contains("dag-node-rows: [];"));
        assert!(ui_source.contains("work-narrative-rows: [];"));
        assert!(component_source.contains("component PaneSplitter inherits TouchArea"));
        assert!(component_source.contains("mouse-cursor: ew-resize;"));
        assert!(component_source.contains("drag-start-width"));
        assert!(component_source.contains("component DagEdgeConnector"));
        assert!(component_source.contains("component PaneChevron"));
        assert!(component_source.contains("Key.LeftArrow"));
        assert!(ui_source.contains("label: \"UPTIME\""));
        assert!(ui_source.contains("CONTEXT INSPECTOR"));
        assert!(ui_source.contains("label: \"SETTINGS\""));
        assert!(ui_source.contains("Locations / Workspaces"));
        assert!(ui_source.contains("session-local"));
        assert!(ui_source.contains("root.width >= 1600px"));
        assert!(ui_source.contains("No Workspace selected"));
    }

    fn assert_slint_responsive_accessibility_contract(ui_source: &str, theme_source: &str) {
        for direction_block in [
            "// THESIS:",
            "// OWN-WORLD:",
            "// STORY:",
            "// FIRST VIEWPORT:",
            "// FORM:",
            "// FINISH:",
        ] {
            assert!(ui_source.contains(direction_block));
        }
        assert!(ui_source.contains(
            "center-minimum: root.wide-layout ? 720px : root.minimum-layout ? 570px : 620px"
        ));
        assert!(ui_source.contains(
            "left-minimum: root.wide-layout ? 300px : root.minimum-layout ? 236px : 260px"
        ));
        assert!(ui_source.contains(
            "right-minimum: root.wide-layout ? 380px : root.minimum-layout ? 300px : 320px"
        ));
        assert!(ui_source.contains("root.left-rail-collapsed ? 48px"));
        assert!(ui_source.contains("root.right-rail-collapsed ? 48px"));
        assert!(ui_source.contains("if root.settings-open : HorizontalBox"));
        assert!(ui_source.contains("if !root.settings-open : HorizontalBox"));
        assert!(ui_source.contains("if root.wide-layout : HorizontalBox"));
        assert!(ui_source.contains("if !root.wide-layout : VerticalBox"));
        assert!(!ui_source.contains("safety-open"));
        assert!(!ui_source.contains("auto-collapse"));
        assert!(ui_source.contains("accessible-role: navigation"));
        assert!(ui_source.contains("accessible-role: main"));
        assert!(ui_source.contains("accessible-role: complementary"));
        assert!(ui_source.contains("accessible-role: content-info"));
        assert!(ui_source.contains("current-width: root.effective-left-width"));
        assert!(ui_source.contains("current-width: root.effective-right-width"));
        assert!(ui_source.contains("dag-edge-rows: []"));
        assert!(ui_source.contains("dag-column-count: 0"));
        assert!(ui_source.contains("root.dag-column-count * root.dag-node-width"));
        assert!(theme_source.contains("unavailable-text: #a47c5f"));
        assert!(theme_source.contains("exceeds 4.5:1"));
        assert!(ui_source.contains("Private model reasoning is never displayed."));
        assert!(!ui_source.to_ascii_lowercase().contains("chain-of-thought"));
    }

    fn assert_slint_harness_apply_contract(ui_source: &str, harness_ui_source: &str) {
        assert!(ui_source.contains("harness-preview-applyable: false"));
        assert!(ui_source.contains("callback preview-harness(string, string);"));
        assert!(ui_source.contains("callback apply-harness-preview();"));
        assert!(
            ui_source
                .contains("label: root.harness-action-busy ? \"Applying…\" : \"Apply Preview\"")
        );
        assert!(ui_source.contains("!root.harness-action-busy && root.harness-preview-applyable"));
        assert!(harness_ui_source.contains("HarnessApplyRequest"));
        assert!(harness_ui_source.contains("expected_preview: preview"));
        assert!(harness_ui_source.contains("preview.can_apply_with_agents_merge()"));
        assert!(harness_ui_source.contains("current.preview = None;"));
        assert!(harness_ui_source.contains("HarnessPreviewDisposition::Merge => \"MERGE\""));
        assert!(harness_ui_source.contains("HarnessPreviewKind::ManagedManifest"));
    }

    fn assert_slint_dag_remains_read_only(ui_source: &str, dag_ui_source: &str) {
        let goal_ui_source = include_str!("goal_ui.rs");
        assert!(goal_ui_source.contains("struct GoalUiController"));
        assert!(goal_ui_source.contains("submit_goal_list"));
        assert!(goal_ui_source.contains("submit_goal_review"));
        assert!(goal_ui_source.contains("submit_goal_complete"));
        assert!(goal_ui_source.contains("notify_dag_selection"));
        assert!(dag_ui_source.contains("submit_dag_get_current"));
        assert!(dag_ui_source.contains("DAG_SCOPE_MISMATCH"));
        assert!(dag_ui_source.contains("project_stored_dag"));
        for forbidden in [
            "DagRevisionCreateRequest",
            "DagNodeStartRequest",
            "DagNodeUpdateRequest",
            "submit_dag_revision_create",
            "submit_dag_node_start",
            "submit_dag_node_update",
        ] {
            assert!(!dag_ui_source.contains(forbidden));
        }
        for forbidden in [
            "callback create-dag",
            "callback update-dag",
            "callback delete-dag",
            "callback start-dag-node",
            "callback complete-dag-node",
        ] {
            assert!(!ui_source.contains(forbidden));
        }
    }

    #[test]
    fn slint_workbench_reserves_truthful_goal_dag_and_work_narrative_projections() {
        let ui_source = include_str!("../../forge-ui/ui/app-window.slint");
        let model_source = include_str!("../../forge-ui/ui/models.slint");
        let component_source = include_str!("../../forge-ui/ui/components.slint");
        let theme_source = include_str!("../../forge-ui/ui/theme.slint");
        let dag_ui_source = include_str!("dag_ui.rs");
        let harness_ui_source = include_str!("harness_ui.rs");

        assert_slint_workbench_models(ui_source, model_source, component_source);
        assert_slint_responsive_accessibility_contract(ui_source, theme_source);
        assert_slint_dag_remains_read_only(ui_source, dag_ui_source);
        assert_slint_harness_apply_contract(ui_source, harness_ui_source);
    }

    #[test]
    fn bootstrap_opens_owned_registry_before_application_services_are_used()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("bootstrap")?;
        let path = root.join("registry.sqlite3");
        let services = bootstrap_registry(&path)?;

        assert!(path.is_file());
        assert_eq!(services.registry_health.schema_version(), 2);
        assert_eq!(
            services.registry_health.journal_mode().to_ascii_lowercase(),
            "wal"
        );
        assert!(services.registry_health.foreign_keys_enabled());

        drop(services);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn bootstrap_rejects_corrupt_registry_without_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("corrupt")?;
        fs::create_dir_all(&root)?;
        let path = root.join("registry.sqlite3");
        let corrupt_bytes = b"not a SQLite database";
        fs::write(&path, corrupt_bytes)?;

        let result = bootstrap_registry(&path);

        assert!(matches!(result, Err(AppError::Registry(_))));
        assert_eq!(fs::read(&path)?, corrupt_bytes);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_health_format_contains_only_verified_registry_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("doctor-format")?;
        let services = bootstrap_registry(root.join("registry.sqlite3"))?;

        assert_eq!(
            format_registry_health(&services.registry_health),
            "registry_health=PASS\nregistry_schema_version=2\nregistry_journal_mode=wal\nregistry_foreign_keys_enabled=true"
        );

        drop(services);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ui_projection_maps_each_phase_and_saturates_display_values() {
        let cases = [
            (
                RuntimeProjection::Starting {
                    generation: RuntimeGeneration::INITIAL,
                },
                "Starting",
                "Booting background Tokio runtime",
                0,
            ),
            (
                RuntimeProjection::Running {
                    generation: RuntimeGeneration::INITIAL,
                    uptime_seconds: 7,
                },
                "Running",
                "Runtime is ready for workspace services",
                7,
            ),
            (
                RuntimeProjection::Restarting {
                    generation: RuntimeGeneration::INITIAL,
                },
                "Restarting",
                "Restarting owned runtime services",
                0,
            ),
            (
                RuntimeProjection::Stopping {
                    generation: RuntimeGeneration::INITIAL,
                },
                "Stopping",
                "Stopping owned runtime services",
                0,
            ),
            (
                RuntimeProjection::Stopped {
                    generation: RuntimeGeneration::INITIAL,
                },
                "Stopped",
                "Runtime is stopped",
                0,
            ),
            (
                RuntimeProjection::Failed {
                    generation: RuntimeGeneration::INITIAL,
                    code: RuntimeFailureCode::Internal,
                },
                "Failed",
                "Runtime failed with code internal",
                0,
            ),
        ];

        for (projection, status, detail, uptime_seconds) in cases {
            let mapped = super::UiRuntimeProjection::from(&projection);
            assert_eq!(mapped.status, status);
            assert_eq!(mapped.detail, detail);
            assert_eq!(mapped.generation, 1);
            assert_eq!(mapped.uptime_seconds, uptime_seconds);
        }

        assert_eq!(super::saturating_i32(u64::MAX), i32::MAX);
        assert_eq!(
            super::UiRuntimeProjection::from(&RuntimeProjection::Running {
                generation: RuntimeGeneration::INITIAL,
                uptime_seconds: u64::MAX,
            })
            .uptime_seconds,
            i32::MAX
        );
    }

    #[test]
    fn activity_projection_mapping_keeps_only_fresh_open_leases_live()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = TimestampMillis::new(20)?;
        let projections = vec![
            activity_projection(1, ActivityState::Open, None, now)?,
            activity_projection(2, ActivityState::Open, Some(100), now)?,
            activity_projection(3, ActivityState::Open, Some(10), now)?,
            activity_projection(4, ActivityState::Closed, None, now)?,
            activity_projection(5, ActivityState::Interrupted, None, now)?,
        ];

        let (live, history) = activity_rows(&projections, now);
        assert_eq!(live.len(), 1);
        assert_eq!(history.len(), 4);
        assert_eq!(live[0].display_label.as_str(), "Chat 02");
        assert_eq!(live[0].state.as_str(), "Open");
        assert_eq!(live[0].liveness.as_str(), "Live");
        assert_eq!(live[0].revision.as_str(), "1");
        assert!(live[0].created_at.contains("ms UTC"));
        assert!(live[0].updated_at.contains("ms UTC"));
        assert!(history.iter().all(|row| row.liveness.as_str() != "Live"));
        assert!(history.iter().any(|row| row.liveness.as_str() == "Expired"));
        assert!(history.iter().any(|row| row.state.as_str() == "Closed"));
        assert!(
            history
                .iter()
                .any(|row| row.state.as_str() == "Interrupted")
        );
        Ok(())
    }

    #[test]
    fn diff_projection_preserves_attribution_summary_and_safe_path_label()
    -> Result<(), Box<dyn std::error::Error>> {
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0xD401));
        let evidence = RegisteredDiffEvidence::from_parts(
            DiffAttribution::new(
                DiffId::for_change_set(change_set_id),
                WorkspaceId::from_uuid(Uuid::from_u128(0xD402)),
                ActivityId::from_uuid(Uuid::from_u128(0xD403)),
                change_set_id,
                FileMutationId::from_uuid(Uuid::from_u128(0xD404)),
            ),
            DiffFileSummary::new(
                WorkspaceRelativePath::new(PathBuf::from("src/runtime.rs"))?,
                DiffChangeKind::Modified,
                DiffLineCount::new(12),
                DiffLineCount::new(4),
            ),
            DiffPayloadProjection::SummaryOnly {
                render_kind: DiffRenderKind::Binary,
            },
            DiffEvidenceTimestamps::new(TimestampMillis::new(10)?, TimestampMillis::new(11)?),
            DiffContractVersions::V1,
            DiffRevision::INITIAL,
        );
        let row = diff_row(&evidence);
        assert_eq!(row.id.as_str(), evidence.id().to_string());
        assert_eq!(row.path.as_str(), "src/runtime.rs");
        assert_eq!(row.kind.as_str(), "Modified");
        assert_eq!(row.summary.as_str(), "+12 -4");
        assert!(row.state.as_str().contains("Summary only / Binary"));
        let message = diff_unavailable_message(&evidence, DiffArtifactHealth::NotApplicable);
        assert!(message.contains("No text artifact"));
        assert!(message.contains("not recovery data"));
        Ok(())
    }

    #[test]
    fn reconstructed_diff_scope_is_correlation_only_and_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xD410));
        let scope = super::ActivityWorkspaceScope {
            location_id,
            location_revision: LocationRevision::INITIAL,
            locator: WorkspaceLocator::new(location_id, LocationRevision::INITIAL, ".")?,
            workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(0xD411)),
            workspace_revision: WorkspaceRevision::new(3)?,
        };
        let rebuilt = resolved_activity_scope(&scope);
        assert_eq!(rebuilt.workspace_id(), scope.workspace_id);
        assert_eq!(rebuilt.workspace_revision(), scope.workspace_revision);
        assert_eq!(rebuilt.locator(), &scope.locator);
        assert!(diff_scope_matches(&scope, &rebuilt));
        let stale = forge_control::ResolvedWorkspaceScope::from_observation(
            scope.workspace_id,
            WorkspaceRevision::new(4)?,
            scope.locator.clone(),
        );
        assert!(!diff_scope_matches(&scope, &stale));
        Ok(())
    }

    #[test]
    fn activity_scope_rebuilds_exact_locator_from_committed_workspace()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("activity-scope")?;
        fs::create_dir_all(root.join("child"))?;
        let location_id = LocationId::from_uuid(Uuid::from_u128(700));
        let location = RegisteredLocation::from_parts_with_revision(
            location_id,
            LocationName::new("Activity scope")?,
            LocationRoot::from_canonical(fs::canonicalize(&root)?)?,
            LocationState::Enabled,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            LocationRevision::INITIAL,
        );
        let discovery = WorkspaceDiscovery::scan(&location)?;
        let candidate = discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.relative_root() == std::path::Path::new("child"))
            .ok_or("child candidate missing")?;
        let snapshot = WorkspaceCandidateSnapshot {
            key: candidate.key(),
            location_id,
            location_revision: LocationRevision::INITIAL,
        };
        let workspace = RegisteredWorkspace::from_parts_with_revision(
            WorkspaceId::from_uuid(Uuid::from_u128(701)),
            location_id,
            WorkspaceRoot::from_canonical(root.join("child"))?,
            WorkspaceRootFingerprint::from_bytes([3; 16]),
            TimestampMillis::new(2)?,
            TimestampMillis::new(3)?,
            WorkspaceRevision::new(4)?,
        );
        let scope = activity_workspace_scope(&snapshot, &workspace)?;
        assert_eq!(scope.location_id, location_id);
        assert_eq!(scope.location_revision, LocationRevision::INITIAL);
        assert_eq!(scope.locator.location_id(), location_id);
        assert_eq!(scope.locator.expected_revision(), LocationRevision::INITIAL);
        assert_eq!(scope.locator.relative_root(), std::path::Path::new("child"));
        assert_eq!(scope.workspace_id, workspace.id());
        assert_eq!(scope.workspace_revision, workspace.revision());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn restarted_control_projection_is_durable_isolated_and_projects_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("activity-restart")?;
        fs::create_dir_all(root.join("alpha"))?;
        fs::create_dir_all(root.join("beta"))?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::from_u128(800));
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Activity restart",
            &root,
            TimestampMillis::new(1)?,
        )?;
        drop(locations);

        let workspace_alpha = WorkspaceId::from_uuid(Uuid::from_u128(801));
        let workspace_beta = WorkspaceId::from_uuid(Uuid::from_u128(802));
        initialize_test_workspace(&root.join("alpha"), workspace_alpha, location_id, 2)?;
        initialize_test_workspace(&root.join("beta"), workspace_beta, location_id, 2)?;
        let alpha_locator = WorkspaceLocator::new(
            location_id,
            location.revision(),
            std::path::Path::new("alpha"),
        )?;
        let beta_locator = WorkspaceLocator::new(
            location_id,
            location.revision(),
            std::path::Path::new("beta"),
        )?;

        let (client, mut worker) =
            ForgeControl::new(GlobalRegistry::open(&registry_path)?).start_worker()?;
        let alpha_scope =
            client.resolve_workspace(location_id, location.revision(), alpha_locator.clone())?;
        let beta_scope =
            client.resolve_workspace(location_id, location.revision(), beta_locator.clone())?;
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(803));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(804));
        let bootstrap = client.bootstrap_activity(
            alpha_scope.clone(),
            activity_id,
            runtime_id,
            TimestampMillis::new(10)?,
            TimestampMillis::new(20)?,
        )?;
        assert!(bootstrap.is_committed());
        let expired_at = TimestampMillis::new(
            bootstrap
                .activity()
                .and_then(forge_domain::RegisteredActivity::lease_until)
                .ok_or("bootstrapped lease expiry missing")?
                .get()
                + 1,
        )?;
        worker.shutdown()?;

        // Reopen both the control service and its owned worker. This proves
        // the desktop's refresh path reads the Workspace-local SQLite row
        // rather than relying on the previous controller's memory or silently
        // reconciling semantic state during a projection read.
        let (client, mut worker) =
            ForgeControl::new(GlobalRegistry::open(&registry_path)?).start_worker()?;
        let alpha_projection = client
            .submit_list_workspace_activity_projections(WorkspaceActivityProjectionRequest {
                location_id: alpha_scope.locator().location_id(),
                expected_location_revision: alpha_scope.locator().expected_revision(),
                locator: alpha_scope.locator().clone(),
                expected_workspace_id: alpha_scope.workspace_id(),
                expected_workspace_revision: alpha_scope.workspace_revision(),
                now: expired_at,
                limit: ActivityListLimit::DEFAULT,
            })?
            .recv()?;
        assert_eq!(alpha_projection.activities().len(), 1);
        assert_eq!(alpha_projection.activities()[0].id(), activity_id);
        assert_eq!(
            alpha_projection.activities()[0].liveness(),
            ActivityLiveness::Expired
        );
        let (live, history) = activity_rows(alpha_projection.activities(), expired_at);
        assert!(live.is_empty());
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].state.as_str(), "Open");
        assert_eq!(history[0].liveness.as_str(), "Expired");
        let alpha_layout = WorkspaceStateLayout::inspect_existing(root.join("alpha"))?
            .ok_or("alpha Workspace layout missing after projection")?;
        let persisted = WorkspaceStore::open_existing(&alpha_layout)?
            .get_activity(activity_id)?
            .ok_or("persisted Activity missing after projection")?;
        assert_eq!(persisted.state(), ActivityState::Open);

        let beta_projection = client
            .submit_list_workspace_activity_projections(WorkspaceActivityProjectionRequest {
                location_id: beta_scope.locator().location_id(),
                expected_location_revision: beta_scope.locator().expected_revision(),
                locator: beta_scope.locator().clone(),
                expected_workspace_id: beta_scope.workspace_id(),
                expected_workspace_revision: beta_scope.workspace_revision(),
                now: TimestampMillis::new(30)?,
                limit: ActivityListLimit::DEFAULT,
            })?
            .recv()?;
        assert!(beta_projection.activities().is_empty());
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn initialize_test_workspace(
        root: &std::path::Path,
        workspace_id: WorkspaceId,
        location_id: LocationId,
        observed_at: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = WorkspaceStateLayout::initialize(root)?;
        let command = forge_domain::EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(observed_at)?,
        );
        let _store = WorkspaceStore::open(&layout, &command)?;
        Ok(())
    }

    fn activity_projection(
        seed: u128,
        state: ActivityState,
        lease_until: Option<i64>,
        now: TimestampMillis,
    ) -> Result<ActivityProjection, Box<dyn std::error::Error>> {
        let lease = match lease_until {
            Some(until) => ActivityLeaseProjection::from_parts(
                Some(RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 1000))),
                Some(TimestampMillis::new(until)?),
                ActivityLeaseRevision::INITIAL,
            )?,
            None => ActivityLeaseProjection::unleased(),
        };
        let activity = RegisteredActivity::from_parts_with_lease(
            ActivityId::from_uuid(Uuid::from_u128(seed)),
            WorkspaceId::from_uuid(Uuid::from_u128(9000)),
            state,
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
            ActivityRevision::INITIAL,
            lease,
        );
        Ok(ActivityProjection::from_activity(activity, now))
    }

    #[test]
    fn workspace_commit_projection_contains_only_durable_identity_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = RegisteredWorkspace::from_parts_with_revision(
            WorkspaceId::from_uuid(Uuid::from_u128(100)),
            LocationId::from_uuid(Uuid::from_u128(101)),
            WorkspaceRoot::from_canonical(PathBuf::from("/tmp/forge-committed-workspace"))?,
            WorkspaceRootFingerprint::from_bytes([7; 16]),
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
            WorkspaceRevision::new(3)?,
        );
        let (index, projection) = super::committed_workspace_projection(4, &workspace);
        assert_eq!(index, 4);
        assert_eq!(projection.id, workspace.id().to_string());
        assert_eq!(projection.revision, "3");
        assert_eq!(projection.root, "/tmp/forge-committed-workspace");
        Ok(())
    }

    #[test]
    fn committed_revalidation_error_cannot_produce_ui_workspace_projection() {
        for reason in [
            crate::location_worker::WorkspaceRevalidationReason::LocationRevisionChanged,
            crate::location_worker::WorkspaceRevalidationReason::CandidateFingerprintChanged,
            crate::location_worker::WorkspaceRevalidationReason::CandidateStale,
        ] {
            let error = LocationWorkerError::WorkspaceIdentityCommittedSelectionUnconfirmed {
                workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(102)),
                reason,
            };
            assert_eq!(
                super::location_error_code_message(&error).0,
                "WORKSPACE_COMMITTED_REVALIDATION_REQUIRED"
            );
            let result: Result<&RegisteredWorkspace, &LocationWorkerError> = Err(&error);
            assert!(super::committed_workspace_projection_from_result(4, result).is_none());
        }
    }

    #[test]
    fn latest_projection_poll_is_nonblocking_when_idle() -> Result<(), Box<dyn std::error::Error>> {
        let mut service = RuntimeService::start()?;
        let mut events = service.take_event_stream()?;
        let _ = events.recv_timeout(std::time::Duration::from_secs(1))?;

        assert!(super::poll_latest_projection(&mut events)?.is_none());

        service.shutdown()?;
        Ok(())
    }

    #[test]
    fn cancelled_selection_does_not_invoke_id_or_clock_preparation()
    -> Result<(), Box<dyn std::error::Error>> {
        let id_calls = Cell::new(0);
        let clock_calls = Cell::new(0);
        let prepared = prepare_register_action(
            LocationName::new("Cancelled")?,
            FolderSelection::Cancelled,
            || {
                clock_calls.set(clock_calls.get() + 1);
                TimestampMillis::new(1).map_err(UiLocationPreparationError::InvalidTimestamp)
            },
            || {
                id_calls.set(id_calls.get() + 1);
                LocationId::from_uuid(Uuid::now_v7())
            },
        )?;
        assert!(prepared.is_none());
        assert_eq!(id_calls.get(), 0);
        assert_eq!(clock_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn selected_folder_prepares_v7_id_timestamp_and_native_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected_path = PathBuf::from("/tmp/native-location");
        let prepared = prepare_register_action(
            LocationName::new("Selected")?,
            FolderSelection::Selected(selected_path.clone()),
            || TimestampMillis::new(42).map_err(UiLocationPreparationError::InvalidTimestamp),
            || LocationId::from_uuid(Uuid::now_v7()),
        )?;
        let Some(LocationAction::Register {
            id,
            name,
            root,
            observed_at,
        }) = prepared
        else {
            return Err("selected folder did not prepare a register action".into());
        };
        assert_eq!(name.as_str(), "Selected");
        assert_eq!(root, selected_path);
        assert_eq!(observed_at.get(), 42);
        assert_eq!(id.into_uuid().get_version_num(), 7);
        Ok(())
    }

    #[test]
    fn ui_admission_rejects_reentry_and_full_handoff_without_blocking()
    -> Result<(), Box<dyn std::error::Error>> {
        let (intents, receiver) = std::sync::mpsc::sync_channel(1);
        let busy = std::rc::Rc::new(Cell::new(false));
        try_admit_location_intent(&intents, &busy, UiLocationIntent::Refresh)?;
        assert!(matches!(
            try_admit_location_intent(&intents, &busy, UiLocationIntent::Refresh),
            Err(UiLocationAdmissionError::Busy)
        ));
        drop(receiver);
        busy.set(false);
        let (full_intents, _full_receiver) = std::sync::mpsc::sync_channel(1);
        full_intents.try_send(UiLocationIntent::Refresh)?;
        let started = std::time::Instant::now();
        assert!(matches!(
            try_admit_location_intent(&full_intents, &busy, UiLocationIntent::Refresh),
            Err(UiLocationAdmissionError::QueueFull)
        ));
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        Ok(())
    }

    #[test]
    fn location_and_workspace_models_are_bounded_and_revision_round_trips()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("model-bounds")?;
        let location = RegisteredLocation::from_parts_with_revision(
            LocationId::from_uuid(Uuid::now_v7()),
            LocationName::new("Bounded")?,
            LocationRoot::from_canonical(root.clone())?,
            LocationState::Enabled,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            LocationRevision::new(17)?,
        );
        let locations = vec![location; 101];
        assert_eq!(location_rows(&locations).len(), 100);
        let (parsed_id, parsed_revision) =
            parse_discover_target(locations[0].id().to_string().as_str(), "17")
                .map_err(|error| error.to_string())?;
        assert_eq!(parsed_id, locations[0].id());
        assert_eq!(parsed_revision, LocationRevision::new(17)?);

        fs::create_dir_all(root.join("child"))?;
        let registered = RegisteredLocation::from_parts_with_revision(
            locations[0].id(),
            locations[0].name().clone(),
            LocationRoot::from_canonical(fs::canonicalize(&root)?)?,
            LocationState::Enabled,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            LocationRevision::new(17)?,
        );
        let discovery = WorkspaceDiscovery::scan(&registered)?;
        let mut many = Vec::new();
        for _ in 0..200 {
            many.extend(discovery.candidates().iter().cloned());
        }
        assert_eq!(workspace_rows(&many).len(), 256);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn unique_test_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("heterarchy-forge-desktop-{label}-{unique}")))
    }

    fn recovery_millis() -> Result<i64, Box<dyn std::error::Error>> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(i64::try_from(elapsed.as_millis())?)
    }

    struct RecoveryFixture {
        registry_path: PathBuf,
        workspace_root: PathBuf,
        location_id: LocationId,
        location_revision: LocationRevision,
    }

    fn recovery_fixture(label: &str) -> Result<RecoveryFixture, Box<dyn std::error::Error>> {
        use forge_domain::EstablishWorkspace;

        let root = unique_test_root(&format!("recovery-{label}"))?;
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace-0");
        fs::create_dir_all(&workspace_root)?;
        let registry_path = root.join("registry.sqlite3");
        let location_id = LocationId::from_uuid(Uuid::now_v7());
        let observed_at = TimestampMillis::new(recovery_millis()?)?;
        let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
        let location = locations.register_selected_path(
            location_id,
            "Recovery Fixture",
            &location_root,
            observed_at,
        )?;
        let revision = location.revision();
        drop(locations);

        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let durable_root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
        let command = EstablishWorkspace::new(
            WorkspaceId::from_uuid(Uuid::now_v7()),
            location_id,
            durable_root,
            layout.root_fingerprint()?,
            observed_at,
        );
        drop(WorkspaceStore::open(&layout, &command)?);

        Ok(RecoveryFixture {
            registry_path,
            workspace_root: std::fs::canonicalize(&workspace_root)?,
            location_id,
            location_revision: revision,
        })
    }

    fn recovery_scope(
        fixture: &RecoveryFixture,
    ) -> Result<
        (
            forge_control::ForgeControl,
            forge_control::ResolvedWorkspaceScope,
        ),
        Box<dyn std::error::Error>,
    > {
        let control = ForgeControl::new(GlobalRegistry::open(&fixture.registry_path)?);
        // Catalog readiness is observational; poll briefly for quiescence
        // under parallel test load instead of failing on a transient
        // `Unavailable` observation.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let scope = loop {
            let entries = control.workspace_list(fixture.location_id, fixture.location_revision)?;
            if let Some(entry) = entries.iter().find(|entry| entry.status().is_ready()) {
                break control.resolve_workspace(
                    fixture.location_id,
                    fixture.location_revision,
                    entry.locator(),
                )?;
            }
            if std::time::Instant::now() >= deadline {
                return Err("ready workspace catalog entry missing".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        };
        Ok((control, scope))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn recover_workspace_argument_parsing_is_explicit() {
        let flag = std::ffi::OsString::from("--recover-workspace");
        let target = std::ffi::OsString::from("/tmp/some-workspace");

        assert_eq!(
            recover_workspace_argument(&[
                std::ffi::OsString::from("binary"),
                flag.clone(),
                target.clone(),
            ])
            .expect("valid arguments must parse"),
            Some(PathBuf::from("/tmp/some-workspace"))
        );
        assert!(
            recover_workspace_argument(&[std::ffi::OsString::from("binary")])
                .expect("no flag must parse")
                .is_none()
        );
        assert!(matches!(
            recover_workspace_argument(&[std::ffi::OsString::from("binary"), flag.clone()]),
            Err(AppError::RecoveryArguments)
        ));
        assert!(matches!(
            recover_workspace_argument(&[
                std::ffi::OsString::from("binary"),
                flag.clone(),
                target.clone(),
                flag.clone(),
                target,
            ]),
            Err(AppError::RecoveryArguments)
        ));
        assert!(matches!(
            recover_workspace_argument(&[
                std::ffi::OsString::from("binary"),
                flag,
                std::ffi::OsString::from("--doctor"),
            ]),
            Err(AppError::RecoveryArguments)
        ));
    }

    #[test]
    fn recovery_entry_classifies_and_releases_on_registered_target()
    -> Result<(), Box<dyn std::error::Error>> {
        use forge_control::RecoveryMaintenanceOutcome;
        use forge_domain::ExecutionId;

        let fixture = recovery_fixture("entry")?;
        seed_expired_running_execution(&fixture, 0xD51)?;

        let summary = run_recovery_entry(&fixture.registry_path, &fixture.workspace_root)?;
        assert_eq!(summary.outcome, RecoveryMaintenanceOutcome::Completed);
        assert_eq!(summary.classified_activities, 1);
        assert_eq!(summary.classified_executions, 1);
        assert!(summary.binding_confirmed);
        assert!(!summary.release_uncertain);

        // Durable effects: execution classified, fence released.
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let execution = store
            .get_execution(ExecutionId::from_uuid(Uuid::from_u128(0xD51)))?
            .ok_or("seeded execution missing")?;
        assert_eq!(execution.state(), forge_domain::ExecutionState::Interrupted);
        let lease = store.get_recovery_maintenance_lease()?;
        assert!(lease.is_released());
        assert_eq!(lease.epoch().get(), 1);
        drop(store);

        // A second entry run is idempotent.
        let second = run_recovery_entry(&fixture.registry_path, &fixture.workspace_root)?;
        assert_eq!(second.outcome, RecoveryMaintenanceOutcome::Completed);
        assert_eq!(second.classified_activities, 0);
        assert_eq!(second.classified_executions, 0);

        fs::remove_dir_all(
            fixture
                .registry_path
                .parent()
                .ok_or("fixture root missing")?,
        )?;
        Ok(())
    }

    #[test]
    fn recovery_entry_reports_busy_without_mutation_while_fence_held()
    -> Result<(), Box<dyn std::error::Error>> {
        use forge_control::RecoveryMaintenanceOutcome;
        use forge_domain::{ClaimRecoveryLease, RecoveryLeaseDurationMillis};

        let fixture = recovery_fixture("busy")?;
        seed_expired_running_execution(&fixture, 0xD52)?;

        // A foreign live owner claims the fence before the entry runs.
        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("workspace layout missing")?;
        let mut store = WorkspaceStore::open_existing(&layout)?;
        let workspace_id = store.workspace()?.id();
        let foreign_claim = ClaimRecoveryLease::new(
            workspace_id,
            RuntimeInstanceId::from_uuid(Uuid::now_v7()),
            RecoveryLeaseDurationMillis::new(30_000)?,
            TimestampMillis::new(recovery_millis()?)?,
        )?;
        let claimed = store.claim_recovery_maintenance_lease(foreign_claim)?;
        assert!(claimed.is_acquired());
        drop(store);

        let summary = run_recovery_entry(&fixture.registry_path, &fixture.workspace_root)?;
        assert_eq!(summary.outcome, RecoveryMaintenanceOutcome::Busy);
        assert_eq!(summary.classified_activities, 0);
        assert_eq!(summary.classified_executions, 0);

        // Nothing was classified while the fence was held.
        let store = WorkspaceStore::open_existing(&layout)?;
        let execution = store
            .get_execution(forge_domain::ExecutionId::from_uuid(Uuid::from_u128(0xD52)))?
            .ok_or("seeded execution missing")?;
        assert_eq!(execution.state(), forge_domain::ExecutionState::Starting);

        fs::remove_dir_all(
            fixture
                .registry_path
                .parent()
                .ok_or("fixture root missing")?,
        )?;
        Ok(())
    }

    #[test]
    fn recovery_entry_fails_closed_on_unregistered_target() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = recovery_fixture("unknown")?;
        let unregistered = fixture.workspace_root.parent().ok_or("parent missing")?;
        let result = run_recovery_entry(&fixture.registry_path, unregistered);
        assert!(matches!(result, Err(AppError::RecoveryTargetNotFound)));

        let missing = fixture.workspace_root.join("does-not-exist");
        let result = run_recovery_entry(&fixture.registry_path, &missing);
        assert!(matches!(result, Err(AppError::RecoveryTargetNotFound)));

        fs::remove_dir_all(
            fixture
                .registry_path
                .parent()
                .ok_or("fixture root missing")?,
        )?;
        Ok(())
    }
    fn seed_expired_running_execution(
        fixture: &RecoveryFixture,
        raw_execution_id: u128,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use forge_domain::{
            BeginExecution, ExecutionAttribution, ExecutionId, ExecutionKind, ExecutionLimits,
            ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram, ExecutionRequest,
            ExecutionRequestDigest, ExecutionTimeoutMillis,
        };

        let now = TimestampMillis::new(recovery_millis()?)?;
        let expired_until = TimestampMillis::new(now.get().saturating_sub(1_000))?;
        let started_at = TimestampMillis::new(now.get().saturating_sub(2_000))?;
        let activity_id = ActivityId::from_uuid(Uuid::now_v7());
        let (control, scope) = recovery_scope(fixture)?;
        let _bootstrapped = control.bootstrap_activity(
            &scope,
            activity_id,
            RuntimeInstanceId::from_uuid(Uuid::now_v7()),
            started_at,
            expired_until,
        )?;

        let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
            .ok_or("workspace layout missing")?;
        let mut store = WorkspaceStore::open_existing(&layout)?;
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(raw_execution_id)),
                scope.workspace_id(),
                activity_id,
            ),
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
        let _started = store.begin_execution(&BeginExecution::from_request(
            &request,
            ExecutionRequestDigest::from_bytes(
                [u8::try_from(raw_execution_id).unwrap_or(u8::MAX); 32],
            ),
            now,
        ))?;
        Ok(())
    }
}
