//! Bounded operator-safe projection of the existing read-only Workspace Doctor.
//!
//! This module owns no health policy. `forge-control` remains the authority for
//! aggregate outcome and typed findings; desktop code only reduces that result
//! to bounded display rows and a copyable text export.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use forge_control::{
    ControlClientError, ForgeControlClient, PendingControl, WorkspaceCheckpointStoreStatus,
    WorkspaceDiffArtifactStatus, WorkspaceDoctorAggregateOutcome,
    WorkspaceDoctorObservationConsistency, WorkspaceDoctorRequest, WorkspaceDoctorResult,
};
use forge_domain::WorkspaceId;
use forge_persistence::{DagDoctorIssue, DagDoctorState};
use forge_ui::{AppWindow, DoctorFindingRow};
use forge_workspace::{CheckpointSide, GitLocalStateDoctor};
use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};
use thiserror::Error;
use uuid::Uuid;

use super::{ActivityWorkspaceScope, resolved_activity_scope};

const MAX_DOCTOR_UI_FINDINGS: usize = 64;
const MAX_DOCTOR_EXPORT_BYTES: usize = 16 * 1024;
const MAX_DOCTOR_UI_INTENTS_PER_TICK: usize = 4;
const EXPORT_TRUNCATED_TRUE: &str = "ui_projection_truncated=true\n";
const EXPORT_TRUNCATED_FALSE: &str = "ui_projection_truncated=false\n";
const MAX_EXPORT_MARKER_BYTES: usize = EXPORT_TRUNCATED_FALSE.len();

#[derive(Debug)]
pub(super) enum UiDoctorIntent {
    WorkspaceSelected(Option<ActivityWorkspaceScope>),
    Refresh,
    Export,
}

#[derive(Debug, Clone)]
struct DoctorExportSnapshot {
    workspace_id: WorkspaceId,
    content: String,
}

#[derive(Debug)]
struct DoctorExportTask {
    workspace_id: WorkspaceId,
    result: Receiver<Result<String, DoctorExportError>>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug, Error)]
enum DoctorExportError {
    #[error("diagnostics directory is not a regular directory")]
    InvalidDirectory,
    #[error("failed to inspect diagnostics directory")]
    InspectDirectory(#[source] io::Error),
    #[error("failed to create diagnostics directory")]
    CreateDirectory(#[source] io::Error),
    #[error("Doctor diagnostics exceeded the configured export bound")]
    TooLarge,
    #[error("failed to create diagnostics temporary file")]
    CreateTemporary(#[source] io::Error),
    #[error("failed to write diagnostics temporary file")]
    WriteTemporary(#[source] io::Error),
    #[error("failed to sync diagnostics temporary file")]
    SyncTemporary(#[source] io::Error),
    #[error("failed to publish diagnostics export")]
    Publish(#[source] io::Error),
    #[error("diagnostics export worker could not start")]
    Spawn(#[source] io::Error),
    #[error("diagnostics export worker panicked")]
    WorkerPanicked,
    #[error("diagnostics export worker disconnected")]
    WorkerDisconnected,
}

impl DoctorExportTask {
    fn try_finish(&mut self) -> Option<Result<String, DoctorExportError>> {
        match self.result.try_recv() {
            Ok(result) => {
                if self.join().is_err() {
                    Some(Err(DoctorExportError::WorkerPanicked))
                } else {
                    Some(result)
                }
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                if self.join().is_err() {
                    Some(Err(DoctorExportError::WorkerPanicked))
                } else {
                    Some(Err(DoctorExportError::WorkerDisconnected))
                }
            }
        }
    }

    fn join(&mut self) -> thread::Result<()> {
        self.worker.take().map_or(Ok(()), JoinHandle::join)
    }
}

impl Drop for DoctorExportTask {
    fn drop(&mut self) {
        let _ignored = self.join();
    }
}

#[derive(Debug)]
struct DoctorUiProjection {
    outcome: &'static str,
    summary: String,
    rows: Vec<DoctorFindingRow>,
    export: String,
    truncated: bool,
}

struct DoctorProjectionBuilder {
    rows: Vec<DoctorFindingRow>,
    export: String,
    observed_findings: usize,
    truncated: bool,
}

impl DoctorProjectionBuilder {
    fn new(result: &WorkspaceDoctorResult) -> Self {
        let report = result.report();
        let mut this = Self {
            rows: Vec::with_capacity(MAX_DOCTOR_UI_FINDINGS),
            export: String::with_capacity(4 * 1024),
            observed_findings: 0,
            truncated: false,
        };
        this.push_export_line("HETERARCHY FORGE WORKSPACE DOCTOR");
        this.push_export_line(&format!(
            "outcome={}",
            doctor_outcome_label(result.outcome())
        ));
        this.push_export_line(&format!(
            "observation_consistency={}",
            observation_consistency_label(result.observation_consistency())
        ));
        this.push_export_line(&format!("workspace_id={}", result.scope().workspace_id()));
        this.push_export_line(&format!("location_id={}", report.location_id()));
        this.push_export_line(&format!(
            "workspace_revision={}",
            result.scope().workspace_revision().get()
        ));
        this.push_export_line(&format!("application_id={}", report.application_id()));
        this.push_export_line(&format!("schema_version={}", report.schema_version()));
        this.push_export_line(&format!(
            "sqlite_quick_check={}",
            pass_fail(report.quick_check().passed())
        ));
        this.push_export_line(&format!(
            "sqlite_foreign_keys={}",
            pass_fail(report.foreign_key_check().passed())
        ));
        this.push_export_line(&format!(
            "git_local_state={}",
            git_local_state_label(result.git_local_state())
        ));
        this.push_export_line(&format!(
            "stale_executions={}{}",
            report.stale_executions().count(),
            truncation_suffix(report.stale_executions().truncated())
        ));
        this.push_export_line(&format!(
            "stale_checkpoint_restores={}{}",
            report.stale_checkpoint_restores().count(),
            truncation_suffix(report.stale_checkpoint_restores().truncated())
        ));
        this
    }

    fn push(&mut self, area: &'static str, status: &'static str, detail: &str) {
        self.observed_findings = self.observed_findings.saturating_add(1);
        self.push_export_line(&format!("{area}|{status}|{detail}"));
        if self.rows.len() < MAX_DOCTOR_UI_FINDINGS {
            self.rows.push(DoctorFindingRow {
                area: area.into(),
                status: status.into(),
                detail: detail.into(),
            });
        } else {
            self.truncated = true;
        }
    }

    fn push_export_line(&mut self, line: &str) {
        let required = line.len().saturating_add(1);
        let body_limit = MAX_DOCTOR_EXPORT_BYTES.saturating_sub(MAX_EXPORT_MARKER_BYTES);
        if self.export.len().saturating_add(required) > body_limit {
            self.truncated = true;
            return;
        }
        self.export.push_str(line);
        self.export.push('\n');
    }

    fn finish(mut self, outcome: WorkspaceDoctorAggregateOutcome) -> DoctorUiProjection {
        let display_count = self.rows.len();
        let marker = if self.truncated {
            EXPORT_TRUNCATED_TRUE
        } else {
            EXPORT_TRUNCATED_FALSE
        };
        self.export.push_str(marker);
        debug_assert!(self.export.len() <= MAX_DOCTOR_EXPORT_BYTES);
        let summary = if self.observed_findings == 0 {
            "No actionable findings in the bounded Doctor observation.".to_owned()
        } else {
            format!(
                "{} finding{} observed · {} displayed{}",
                self.observed_findings,
                if self.observed_findings == 1 { "" } else { "s" },
                display_count,
                if self.truncated {
                    " · UI export truncated"
                } else {
                    ""
                }
            )
        };
        DoctorUiProjection {
            outcome: doctor_outcome_label(outcome),
            summary,
            rows: self.rows,
            export: self.export,
            truncated: self.truncated,
        }
    }
}

fn doctor_ui_projection(result: &WorkspaceDoctorResult) -> DoctorUiProjection {
    let mut builder = DoctorProjectionBuilder::new(result);
    project_observation_consistency(result, &mut builder);
    project_persistence_findings(result, &mut builder);
    project_git_finding(result, &mut builder);
    project_checkpoint_findings(result, &mut builder);
    project_diff_findings(result, &mut builder);
    project_dag_findings(result, &mut builder);
    builder.finish(result.outcome())
}

fn project_observation_consistency(
    result: &WorkspaceDoctorResult,
    builder: &mut DoctorProjectionBuilder,
) {
    match result.observation_consistency() {
        WorkspaceDoctorObservationConsistency::Stable => builder.push(
            "OBSERVATION",
            "STABLE",
            "SQLite, Git local-state, checkpoint-store, and Diff inventory sources remained unchanged across this Doctor pass.",
        ),
        WorkspaceDoctorObservationConsistency::Changed => builder.push(
            "OBSERVATION",
            "INCOMPLETE",
            "One or more bounded observation sources changed during Doctor; refresh after activity settles before treating cross-authority findings as final.",
        ),
    }
}

fn project_persistence_findings(
    result: &WorkspaceDoctorResult,
    builder: &mut DoctorProjectionBuilder,
) {
    let report = result.report();
    if !report.quick_check().passed() {
        builder.push("PERSISTENCE", "DAMAGED", "SQLite quick_check failed.");
    }
    if !report.foreign_key_check().passed() {
        builder.push(
            "PERSISTENCE",
            "DAMAGED",
            "SQLite foreign-key validation failed.",
        );
    }
    if !report.stale_executions().is_empty() {
        let detail = format!(
            "{} stale execution row{}{}.",
            report.stale_executions().count(),
            plural(report.stale_executions().count()),
            truncation_detail(report.stale_executions().truncated())
        );
        builder.push("EXECUTION", "RECOVERY", &detail);
    }
    if !report.stale_checkpoint_restores().is_empty() {
        let detail = format!(
            "{} stale restore row{}{}.",
            report.stale_checkpoint_restores().count(),
            plural(report.stale_checkpoint_restores().count()),
            truncation_detail(report.stale_checkpoint_restores().truncated())
        );
        builder.push("CHECKPOINT", "RECOVERY", &detail);
    }
}

fn project_git_finding(result: &WorkspaceDoctorResult, builder: &mut DoctorProjectionBuilder) {
    match result.git_local_state() {
        GitLocalStateDoctor::Verified | GitLocalStateDoctor::NotGitRepository => {}
        GitLocalStateDoctor::MissingLocalExclude => {
            builder.push("GIT", "DAMAGED", "Forge state exclusion is missing.");
        }
        GitLocalStateDoctor::TrackedStateConflict => builder.push(
            "GIT",
            "DAMAGED",
            "Forge state conflicts with tracked Git state.",
        ),
        GitLocalStateDoctor::StateVisibleToGit => builder.push(
            "GIT",
            "DAMAGED",
            "Forge state is visible to the user Git repository.",
        ),
        GitLocalStateDoctor::Unavailable => builder.push(
            "GIT",
            "INCOMPLETE",
            "Git local-state observation was unavailable.",
        ),
    }
}

fn project_checkpoint_findings(
    result: &WorkspaceDoctorResult,
    builder: &mut DoctorProjectionBuilder,
) {
    for finding in result.checkpoint_store().findings() {
        let status = finding.status();
        if status == WorkspaceCheckpointStoreStatus::OwnedAvailable {
            continue;
        }
        let checkpoint = finding
            .checkpoint_id()
            .map_or_else(|| "store".to_owned(), |id| format!("checkpoint {id}"));
        let side = finding.side().map_or("journal", checkpoint_side_label);
        let detail = format!(
            "{checkpoint} · {side} · {}",
            checkpoint_status_label(status)
        );
        builder.push("CHECKPOINT", checkpoint_severity(status), &detail);
    }
    if !result.checkpoint_store().is_complete() {
        builder.push(
            "CHECKPOINT",
            "INCOMPLETE",
            "Checkpoint Doctor observation reached a configured bound.",
        );
    }
}

fn project_diff_findings(result: &WorkspaceDoctorResult, builder: &mut DoctorProjectionBuilder) {
    for finding in result.diff_artifacts().findings() {
        let status = finding.status();
        if matches!(
            status,
            WorkspaceDiffArtifactStatus::OwnedAvailable
                | WorkspaceDiffArtifactStatus::NotApplicable
        ) {
            continue;
        }
        let identity = finding.diff_id().map_or_else(
            || "unidentified artifact".to_owned(),
            |id| format!("diff {id}"),
        );
        let detail = format!("{identity} · {}", diff_status_label(status));
        builder.push("DIFF", diff_severity(status), &detail);
    }
    if !result.diff_artifacts().is_complete() {
        builder.push(
            "DIFF",
            "INCOMPLETE",
            "Diff Doctor observation reached a configured bound.",
        );
    }
}

fn project_dag_findings(result: &WorkspaceDoctorResult, builder: &mut DoctorProjectionBuilder) {
    let report = result.report();
    for finding in report.dag_semantics().findings() {
        if let DagDoctorState::Damaged(issue) = finding.state() {
            let revision = finding.dag_revision().map_or_else(
                || "unknown revision".to_owned(),
                |value| format!("revision {}", value.get()),
            );
            let detail = format!(
                "goal {} · {revision} · {}",
                finding.goal_id(),
                dag_issue_label(issue)
            );
            builder.push("DAG", "DAMAGED", &detail);
        }
    }
    if !report.dag_semantics().is_complete() {
        builder.push(
            "DAG",
            "INCOMPLETE",
            "Current DAG Doctor observation reached the 32-head bound.",
        );
    }
}

fn diagnostics_file_name(workspace_id: WorkspaceId) -> String {
    format!("workspace-doctor-{workspace_id}.txt")
}

fn ensure_diagnostics_directory(path: &Path) -> Result<(), DoctorExportError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(DoctorExportError::InvalidDirectory)
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(DoctorExportError::CreateDirectory)?;
            let metadata =
                fs::symlink_metadata(path).map_err(DoctorExportError::InspectDirectory)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                Err(DoctorExportError::InvalidDirectory)
            } else {
                Ok(())
            }
        }
        Err(source) => Err(DoctorExportError::InspectDirectory(source)),
    }
}

fn write_doctor_export(
    diagnostics_dir: &Path,
    snapshot: &DoctorExportSnapshot,
) -> Result<String, DoctorExportError> {
    if snapshot.content.len() > MAX_DOCTOR_EXPORT_BYTES {
        return Err(DoctorExportError::TooLarge);
    }
    ensure_diagnostics_directory(diagnostics_dir)?;
    let file_name = diagnostics_file_name(snapshot.workspace_id);
    let destination = diagnostics_dir.join(&file_name);
    let temporary = diagnostics_dir.join(format!(".{file_name}.{}.tmp", Uuid::now_v7()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(DoctorExportError::CreateTemporary)?;
    if let Err(source) = file.write_all(snapshot.content.as_bytes()) {
        drop(file);
        let _ignored = fs::remove_file(&temporary);
        return Err(DoctorExportError::WriteTemporary(source));
    }
    if let Err(source) = file.sync_all() {
        drop(file);
        let _ignored = fs::remove_file(&temporary);
        return Err(DoctorExportError::SyncTemporary(source));
    }
    drop(file);
    if let Err(source) = fs::rename(&temporary, &destination) {
        let _ignored = fs::remove_file(&temporary);
        return Err(DoctorExportError::Publish(source));
    }
    Ok(file_name)
}

fn start_doctor_export(
    diagnostics_dir: PathBuf,
    snapshot: DoctorExportSnapshot,
) -> Result<DoctorExportTask, DoctorExportError> {
    let workspace_id = snapshot.workspace_id;
    let (sender, result) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("forge-doctor-export".to_owned())
        .spawn(move || {
            let export = write_doctor_export(&diagnostics_dir, &snapshot);
            let _ignored = sender.send(export);
        })
        .map_err(DoctorExportError::Spawn)?;
    Ok(DoctorExportTask {
        workspace_id,
        result,
        worker: Some(worker),
    })
}

struct DoctorUiController {
    app: AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiDoctorIntent>,
    diagnostics_dir: PathBuf,
    scope: Option<ActivityWorkspaceScope>,
    pending: Option<PendingControl<WorkspaceDoctorResult>>,
    latest_export: Option<DoctorExportSnapshot>,
    export_task: Option<DoctorExportTask>,
}

impl DoctorUiController {
    fn new(
        app: AppWindow,
        client: ForgeControlClient,
        intents: Receiver<UiDoctorIntent>,
        diagnostics_dir: PathBuf,
    ) -> Self {
        Self {
            app,
            client,
            intents,
            diagnostics_dir,
            scope: None,
            pending: None,
            latest_export: None,
            export_task: None,
        }
    }

    fn start(&mut self) {
        self.clear("Select a committed Workspace to run Doctor.");
    }

    fn tick(&mut self) {
        self.drain_intents();
        self.poll_pending();
        self.poll_export();
    }

    fn drain_intents(&mut self) {
        for _ in 0..MAX_DOCTOR_UI_INTENTS_PER_TICK {
            match self.intents.try_recv() {
                Ok(UiDoctorIntent::WorkspaceSelected(scope)) => self.select_scope(scope),
                Ok(UiDoctorIntent::Refresh) => self.begin_if_idle(),
                Ok(UiDoctorIntent::Export) => self.begin_export(),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
    }

    fn select_scope(&mut self, scope: Option<ActivityWorkspaceScope>) {
        self.pending.take();
        self.latest_export = None;
        self.scope = scope;
        self.app
            .set_doctor_diagnostics_status("No diagnostics exported for this Workspace.".into());
        if self.scope.is_some() {
            self.clear("Loading bounded read-only Workspace diagnostics…");
            self.begin_if_idle();
        } else {
            self.clear("Select a committed Workspace to run Doctor.");
        }
    }

    fn begin_if_idle(&mut self) {
        if self.pending.is_some() {
            return;
        }
        let Some(scope) = self.scope.as_ref() else {
            self.clear("Select a committed Workspace to run Doctor.");
            return;
        };
        self.app.set_doctor_action_busy(true);
        self.app.set_doctor_status("OBSERVING · READ ONLY".into());
        let request = WorkspaceDoctorRequest {
            scope: resolved_activity_scope(scope),
        };
        match self.client.submit_workspace_doctor(request) {
            Ok(pending) => self.pending = Some(pending),
            Err(error) => self.set_client_error(&error),
        }
    }

    fn poll_pending(&mut self) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let result = match pending.try_recv() {
            Ok(Some(result)) => result,
            Ok(None) => return,
            Err(error) => {
                self.pending.take();
                self.set_client_error(&error);
                return;
            }
        };
        self.pending.take();
        self.app.set_doctor_action_busy(false);
        match result {
            Ok(result) => self.apply(&result),
            Err(error) => {
                self.latest_export = None;
                self.clear_projection();
                self.app.set_doctor_status(
                    format!(
                        "ERROR [{}] {}",
                        error.code().as_str(),
                        error.code().summary()
                    )
                    .into(),
                );
            }
        }
    }

    fn apply(&mut self, result: &WorkspaceDoctorResult) {
        let Some(scope) = self.scope.as_ref() else {
            self.clear("Select a committed Workspace to run Doctor.");
            return;
        };
        if result.scope().workspace_id() != scope.workspace_id
            || result.scope().workspace_revision() != scope.workspace_revision
            || result.scope().locator() != &scope.locator
        {
            self.clear("Doctor reply belongs to a stale Workspace selection.");
            return;
        }
        let projection = doctor_ui_projection(result);
        self.latest_export = Some(DoctorExportSnapshot {
            workspace_id: result.scope().workspace_id(),
            content: projection.export,
        });
        self.app
            .set_doctor_finding_rows(ModelRc::new(VecModel::from(projection.rows)));
        self.app.set_doctor_status(projection.outcome.into());
        self.app.set_doctor_summary(projection.summary.into());
        if let Some(snapshot) = self.latest_export.as_ref() {
            self.app
                .set_doctor_export_content(snapshot.content.as_str().into());
        }
        self.app.set_doctor_truncated(projection.truncated);
        self.app.set_doctor_action_busy(false);
    }

    fn begin_export(&mut self) {
        if self.export_task.is_some() {
            return;
        }
        let Some(scope) = self.scope.as_ref() else {
            self.app.set_doctor_diagnostics_status(
                "Select a committed Workspace before exporting diagnostics.".into(),
            );
            return;
        };
        let Some(snapshot) = self.latest_export.clone() else {
            self.app.set_doctor_diagnostics_status(
                "Run Workspace Doctor before exporting diagnostics.".into(),
            );
            return;
        };
        if snapshot.workspace_id != scope.workspace_id {
            self.latest_export = None;
            self.app.set_doctor_diagnostics_status(
                "Doctor diagnostics belong to a stale Workspace selection.".into(),
            );
            return;
        }
        self.app.set_doctor_export_busy(true);
        self.app
            .set_doctor_diagnostics_status("Exporting bounded diagnostics…".into());
        if let Ok(task) = start_doctor_export(self.diagnostics_dir.clone(), snapshot) {
            self.export_task = Some(task);
        } else {
            self.app.set_doctor_export_busy(false);
            self.app.set_doctor_diagnostics_status(
                "ERROR [DOCTOR_EXPORT_START] Diagnostics export was not started.".into(),
            );
        }
    }

    fn poll_export(&mut self) {
        let Some(task) = self.export_task.as_mut() else {
            return;
        };
        let Some(result) = task.try_finish() else {
            return;
        };
        let workspace_id = task.workspace_id;
        self.export_task.take();
        self.app.set_doctor_export_busy(false);
        if self.scope.as_ref().map(|scope| scope.workspace_id) != Some(workspace_id) {
            return;
        }
        match result {
            Ok(file_name) => self.app.set_doctor_diagnostics_status(
                format!("Exported {file_name} to Application Support diagnostics.").into(),
            ),
            Err(_) => self.app.set_doctor_diagnostics_status(
                "ERROR [DOCTOR_EXPORT_WRITE] Diagnostics export failed.".into(),
            ),
        }
    }

    fn set_client_error(&mut self, error: &ControlClientError) {
        self.latest_export = None;
        self.clear_projection();
        self.app.set_doctor_status(
            format!(
                "ERROR [{}] {}",
                error.code().as_str(),
                error.code().summary()
            )
            .into(),
        );
        self.app.set_doctor_action_busy(false);
    }

    fn clear(&mut self, status: &str) {
        self.latest_export = None;
        self.clear_projection();
        self.app.set_doctor_status(status.into());
        self.app.set_doctor_action_busy(false);
    }

    fn clear_projection(&self) {
        self.app
            .set_doctor_finding_rows(ModelRc::new(VecModel::from(Vec::<DoctorFindingRow>::new())));
        self.app.set_doctor_summary("".into());
        self.app.set_doctor_export_content("".into());
        self.app.set_doctor_truncated(false);
    }
}

pub(super) fn reset_doctor_projection(app: &AppWindow, status: &str) {
    app.set_doctor_finding_rows(ModelRc::new(VecModel::from(Vec::<DoctorFindingRow>::new())));
    app.set_doctor_status(status.into());
    app.set_doctor_summary("".into());
    app.set_doctor_export_content("".into());
    app.set_doctor_diagnostics_status("No diagnostics exported for this Workspace.".into());
    app.set_doctor_truncated(false);
    app.set_doctor_action_busy(false);
    app.set_doctor_export_busy(false);
}

pub(super) fn bind_doctor_actions(app: &AppWindow, intents: &SyncSender<UiDoctorIntent>) {
    let refresh_intents = intents.clone();
    let refresh_app = app.clone_strong();
    app.clone_strong().on_refresh_doctor(move || {
        if refresh_intents.try_send(UiDoctorIntent::Refresh).is_err() {
            refresh_app.set_doctor_status(
                "ERROR [DOCTOR_UI_QUEUE] Doctor refresh was not admitted.".into(),
            );
        }
    });

    let export_intents = intents.clone();
    let export_app = app.clone_strong();
    app.clone_strong().on_export_doctor_diagnostics(move || {
        if export_intents.try_send(UiDoctorIntent::Export).is_err() {
            export_app.set_doctor_diagnostics_status(
                "ERROR [DOCTOR_EXPORT_QUEUE] Diagnostics export was not admitted.".into(),
            );
        }
    });
}

pub(super) fn start_doctor_pump(
    app: &AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiDoctorIntent>,
    diagnostics_dir: PathBuf,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller =
        DoctorUiController::new(app.clone_strong(), client, intents, diagnostics_dir);
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
}

const fn doctor_outcome_label(outcome: WorkspaceDoctorAggregateOutcome) -> &'static str {
    match outcome {
        WorkspaceDoctorAggregateOutcome::Healthy => "HEALTHY",
        WorkspaceDoctorAggregateOutcome::RecoveryRequired => "RECOVERY REQUIRED",
        WorkspaceDoctorAggregateOutcome::Damaged => "DAMAGED",
        WorkspaceDoctorAggregateOutcome::Incomplete => "INCOMPLETE",
    }
}

const fn observation_consistency_label(
    consistency: WorkspaceDoctorObservationConsistency,
) -> &'static str {
    match consistency {
        WorkspaceDoctorObservationConsistency::Stable => "stable",
        WorkspaceDoctorObservationConsistency::Changed => "changed",
    }
}

const fn git_local_state_label(state: GitLocalStateDoctor) -> &'static str {
    match state {
        GitLocalStateDoctor::NotGitRepository => "NOT_GIT_REPOSITORY",
        GitLocalStateDoctor::Verified => "VERIFIED",
        GitLocalStateDoctor::MissingLocalExclude => "MISSING_LOCAL_EXCLUDE",
        GitLocalStateDoctor::TrackedStateConflict => "TRACKED_STATE_CONFLICT",
        GitLocalStateDoctor::StateVisibleToGit => "STATE_VISIBLE_TO_GIT",
        GitLocalStateDoctor::Unavailable => "UNAVAILABLE",
    }
}

const fn checkpoint_side_label(side: CheckpointSide) -> &'static str {
    match side {
        CheckpointSide::Pre => "PRE",
        CheckpointSide::Post => "POST",
    }
}

const fn checkpoint_severity(status: WorkspaceCheckpointStoreStatus) -> &'static str {
    match status {
        WorkspaceCheckpointStoreStatus::OwnedAvailable => "OK",
        WorkspaceCheckpointStoreStatus::Starting | WorkspaceCheckpointStoreStatus::OrphanRef => {
            "RECOVERY"
        }
        WorkspaceCheckpointStoreStatus::Unverified => "INCOMPLETE",
        WorkspaceCheckpointStoreStatus::RefMissing
        | WorkspaceCheckpointStoreStatus::RefMismatch
        | WorkspaceCheckpointStoreStatus::ObjectMissing
        | WorkspaceCheckpointStoreStatus::ObjectTypeMismatch
        | WorkspaceCheckpointStoreStatus::Conflicting
        | WorkspaceCheckpointStoreStatus::Corrupt
        | WorkspaceCheckpointStoreStatus::StoreMissing => "DAMAGED",
    }
}

const fn checkpoint_status_label(status: WorkspaceCheckpointStoreStatus) -> &'static str {
    match status {
        WorkspaceCheckpointStoreStatus::OwnedAvailable => "owned object/ref available",
        WorkspaceCheckpointStoreStatus::Starting => "capture is still Starting",
        WorkspaceCheckpointStoreStatus::RefMissing => "expected retained ref is missing",
        WorkspaceCheckpointStoreStatus::RefMismatch => "retained ref differs from SQLite evidence",
        WorkspaceCheckpointStoreStatus::ObjectMissing => "referenced Git object is missing",
        WorkspaceCheckpointStoreStatus::ObjectTypeMismatch => "Git object type is invalid",
        WorkspaceCheckpointStoreStatus::OrphanRef => "retained ref has no durable row",
        WorkspaceCheckpointStoreStatus::Conflicting => "checkpoint evidence conflicts",
        WorkspaceCheckpointStoreStatus::Corrupt => "checkpoint store evidence is corrupt",
        WorkspaceCheckpointStoreStatus::StoreMissing => "owned checkpoint store is missing",
        WorkspaceCheckpointStoreStatus::Unverified => {
            "bounded observation could not verify evidence"
        }
    }
}

const fn diff_severity(status: WorkspaceDiffArtifactStatus) -> &'static str {
    match status {
        WorkspaceDiffArtifactStatus::OwnedAvailable
        | WorkspaceDiffArtifactStatus::NotApplicable => "OK",
        WorkspaceDiffArtifactStatus::Orphan | WorkspaceDiffArtifactStatus::Pending => "RECOVERY",
        WorkspaceDiffArtifactStatus::Unverified => "INCOMPLETE",
        WorkspaceDiffArtifactStatus::DatabaseMissing
        | WorkspaceDiffArtifactStatus::Corrupt
        | WorkspaceDiffArtifactStatus::InvalidSymlink
        | WorkspaceDiffArtifactStatus::InvalidNonRegular
        | WorkspaceDiffArtifactStatus::InvalidHardlink
        | WorkspaceDiffArtifactStatus::Conflicting => "DAMAGED",
    }
}

const fn diff_status_label(status: WorkspaceDiffArtifactStatus) -> &'static str {
    match status {
        WorkspaceDiffArtifactStatus::OwnedAvailable => "owned artifact available",
        WorkspaceDiffArtifactStatus::DatabaseMissing => "database expects unavailable artifact",
        WorkspaceDiffArtifactStatus::Corrupt => "artifact payload is corrupt",
        WorkspaceDiffArtifactStatus::InvalidSymlink => "invalid symlink in Diff store",
        WorkspaceDiffArtifactStatus::InvalidNonRegular => "invalid non-regular node in Diff store",
        WorkspaceDiffArtifactStatus::InvalidHardlink => "invalid hardlink in Diff store",
        WorkspaceDiffArtifactStatus::Orphan => "artifact has no durable Diff row",
        WorkspaceDiffArtifactStatus::Conflicting => "artifact evidence conflicts",
        WorkspaceDiffArtifactStatus::Pending => "pending Diff artifact requires recovery",
        WorkspaceDiffArtifactStatus::NotApplicable => "no artifact is required",
        WorkspaceDiffArtifactStatus::Unverified => "bounded observation could not verify artifact",
    }
}

const fn dag_issue_label(issue: DagDoctorIssue) -> &'static str {
    match issue {
        DagDoctorIssue::MissingHead => "current DAG head is missing",
        DagDoctorIssue::MissingRevision => "current DAG revision is missing",
        DagDoctorIssue::HeadRevisionMismatch => "DAG head revision metadata conflicts",
        DagDoctorIssue::HeadTimestampMismatch => "DAG head timestamp metadata conflicts",
        DagDoctorIssue::CountMismatch => "declared DAG node/edge count conflicts",
        DagDoctorIssue::AcceptanceInvalid => "DAG acceptance criteria are invalid",
        DagDoctorIssue::LifecycleInvalid => "DAG node lifecycle/revision is invalid",
        DagDoctorIssue::StructureInvalid => "DAG structure is invalid",
        DagDoctorIssue::Cycle => "DAG contains a cycle",
        DagDoctorIssue::ReadinessInvalid => "DAG readiness conflicts with dependencies",
    }
}

const fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

const fn truncation_suffix(truncated: bool) -> &'static str {
    if truncated { "+" } else { "" }
}

const fn truncation_detail(truncated: bool) -> &'static str {
    if truncated {
        " (bounded count truncated)"
    } else {
        ""
    }
}

const fn plural(count: u16) -> &'static str {
    if count == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_EXPORT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn export_root(label: &str) -> PathBuf {
        let serial = NEXT_EXPORT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "forge-doctor-export-{label}-{}-{serial}",
            std::process::id()
        ))
    }

    #[test]
    fn doctor_ui_projection_builder_caps_rows_and_export_bytes() {
        let mut builder = DoctorProjectionBuilder {
            rows: Vec::with_capacity(MAX_DOCTOR_UI_FINDINGS),
            export: String::with_capacity(128),
            observed_findings: 0,
            truncated: false,
        };
        for index in 0..100 {
            let detail = format!("finding-{index}-{}", "x".repeat(300));
            builder.push("TEST", "DAMAGED", &detail);
        }
        let projection = builder.finish(WorkspaceDoctorAggregateOutcome::Damaged);
        assert_eq!(projection.rows.len(), MAX_DOCTOR_UI_FINDINGS);
        assert!(projection.export.len() <= MAX_DOCTOR_EXPORT_BYTES);
        assert!(projection.export.ends_with(EXPORT_TRUNCATED_TRUE));
        assert!(projection.truncated);
        assert!(projection.summary.contains("100 findings observed"));
    }

    #[test]
    fn status_labels_are_operator_safe_and_stable() {
        assert_eq!(
            doctor_outcome_label(WorkspaceDoctorAggregateOutcome::RecoveryRequired),
            "RECOVERY REQUIRED"
        );
        assert_eq!(
            observation_consistency_label(WorkspaceDoctorObservationConsistency::Stable),
            "stable"
        );
        assert_eq!(
            observation_consistency_label(WorkspaceDoctorObservationConsistency::Changed),
            "changed"
        );
        assert_eq!(
            diff_status_label(WorkspaceDiffArtifactStatus::InvalidSymlink),
            "invalid symlink in Diff store"
        );
        assert_eq!(
            checkpoint_status_label(WorkspaceCheckpointStoreStatus::ObjectMissing),
            "referenced Git object is missing"
        );
        assert_eq!(
            dag_issue_label(DagDoctorIssue::Cycle),
            "DAG contains a cycle"
        );
    }

    #[test]
    fn bounded_doctor_export_is_private_atomic_and_workspace_named()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = export_root("write");
        fs::create_dir_all(&root)?;
        let diagnostics = root.join("diagnostics");
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xD0C7));
        let snapshot = DoctorExportSnapshot {
            workspace_id,
            content: "outcome=HEALTHY\nui_projection_truncated=false\n".to_owned(),
        };

        let file_name = write_doctor_export(&diagnostics, &snapshot)?;
        assert_eq!(file_name, diagnostics_file_name(workspace_id));
        let destination = diagnostics.join(&file_name);
        assert_eq!(fs::read_to_string(&destination)?, snapshot.content);
        assert_eq!(
            fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&diagnostics)?.count(), 1);

        let updated = DoctorExportSnapshot {
            workspace_id,
            content: "outcome=DAMAGED\nui_projection_truncated=false\n".to_owned(),
        };
        assert_eq!(write_doctor_export(&diagnostics, &updated)?, file_name);
        assert_eq!(fs::read_to_string(&destination)?, updated.content);
        assert_eq!(fs::read_dir(&diagnostics)?.count(), 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_export_rejects_oversize_and_symlinked_diagnostics_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = export_root("reject");
        fs::create_dir_all(&root)?;
        let diagnostics = root.join("diagnostics");
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xD0C8));
        let oversized = DoctorExportSnapshot {
            workspace_id,
            content: "x".repeat(MAX_DOCTOR_EXPORT_BYTES + 1),
        };
        assert!(matches!(
            write_doctor_export(&diagnostics, &oversized),
            Err(DoctorExportError::TooLarge)
        ));
        assert!(!diagnostics.exists());

        let target = root.join("redirect-target");
        fs::create_dir(&target)?;
        symlink(&target, &diagnostics)?;
        let safe = DoctorExportSnapshot {
            workspace_id,
            content: "outcome=HEALTHY\n".to_owned(),
        };
        assert!(matches!(
            write_doctor_export(&diagnostics, &safe),
            Err(DoctorExportError::InvalidDirectory)
        ));
        assert_eq!(fs::read_dir(&target)?.count(), 0);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn doctor_export_worker_is_owned_and_reaped() -> Result<(), Box<dyn std::error::Error>> {
        let root = export_root("worker");
        fs::create_dir_all(&root)?;
        let diagnostics = root.join("diagnostics");
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xD0C9));
        let snapshot = DoctorExportSnapshot {
            workspace_id,
            content: "outcome=HEALTHY\nui_projection_truncated=false\n".to_owned(),
        };
        let mut task = start_doctor_export(diagnostics.clone(), snapshot)?;

        let result = (0..1_000)
            .find_map(|_| {
                let result = task.try_finish();
                if result.is_none() {
                    thread::sleep(Duration::from_millis(1));
                }
                result
            })
            .ok_or("diagnostics export worker did not finish within the bounded test window")??;
        assert_eq!(result, diagnostics_file_name(workspace_id));
        assert!(task.worker.is_none());
        assert!(diagnostics.join(result).is_file());

        fs::remove_dir_all(root)?;
        Ok(())
    }
}
