//! Native Harness Library projection and registration controls.
//!
//! The Slint thread owns only the native folder picker and bounded intent
//! admission. Bundle inspection and Harness Catalog persistence remain on the
//! single-owner [`HarnessLibraryWorker`](crate::harness_worker::HarnessLibraryWorker).

use std::cell::Cell;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use forge_control::{
    ControlClientError, ControlError, ForgeControlClient, ForgeHarnessVerifierCoordinatorClient,
    ForgeHarnessVerifierCoordinatorError, HarnessApplyRequest, HarnessPreviewRequest,
    HarnessVerifierRunRequest, HarnessVerifyRequest, PendingControl, PendingHarnessVerifierRun,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    AppliedHarness, HarnessBundleId, HarnessRevision, HarnessVerificationState, HarnessVerifierRun,
    HarnessVerifierItemState, HarnessVerifierRunState, TimestampMillis,
};
use forge_persistence::HarnessCatalogEntry;
use forge_platform::{FolderSelection, pick_folder};
use forge_ui::{AppWindow, HarnessRow};
use forge_workspace::{HarnessInstallPreview, HarnessPreviewDisposition, HarnessPreviewKind};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use tracing::error;

use crate::harness_worker::{
    HarnessLibraryClient, HarnessWorkerAction, HarnessWorkerOutcome, PendingHarnessRequest,
};

const PUMP_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub(crate) enum UiHarnessIntent {
    WorkspaceSelected(Option<ResolvedWorkspaceScope>),
    Refresh,
    Register(std::path::PathBuf),
    RefreshBundle {
        id: HarnessBundleId,
        expected_revision: HarnessRevision,
    },
    Preview {
        id: HarnessBundleId,
        expected_revision: HarnessRevision,
    },
    ApplyPreview,
    RunVerifiers,
    RefreshVerifiers,
    VerifyApplied,
}

#[derive(Debug)]
enum PendingVerifierKind {
    Latest(PendingHarnessVerifierRun<Option<HarnessVerifierRun>>),
    Start(PendingHarnessVerifierRun<HarnessVerifierRun>),
    Refresh(PendingHarnessVerifierRun<Option<HarnessVerifierRun>>),
}

#[derive(Debug)]
struct PendingVerifierAction {
    scope: ResolvedWorkspaceScope,
    kind: PendingVerifierKind,
}

#[derive(Debug)]
enum VerifierOutcome {
    Latest(Option<HarnessVerifierRun>),
    Started(HarnessVerifierRun),
    Refreshed(Option<HarnessVerifierRun>),
}

impl PendingVerifierAction {
    fn try_recv(
        &self,
    ) -> Result<
        Option<Result<VerifierOutcome, ForgeHarnessVerifierCoordinatorError>>,
        TryRecvError,
    > {
        match &self.kind {
            PendingVerifierKind::Latest(pending) => pending.try_recv().map(|result| {
                result.map(|reply| reply.map(VerifierOutcome::Latest))
            }),
            PendingVerifierKind::Start(pending) => pending.try_recv().map(|result| {
                result.map(|reply| reply.map(VerifierOutcome::Started))
            }),
            PendingVerifierKind::Refresh(pending) => pending.try_recv().map(|result| {
                result.map(|reply| reply.map(VerifierOutcome::Refreshed))
            }),
        }
    }
}

#[derive(Debug)]
enum PendingWorkspaceHarness {
    Read(PendingControl<Option<AppliedHarness>>),
    Preview(PendingControl<HarnessInstallPreview>),
    Apply(PendingControl<AppliedHarness>),
    Verify(PendingControl<AppliedHarness>),
}

impl PendingWorkspaceHarness {
    const fn is_preview(&self) -> bool {
        matches!(self, Self::Preview(_))
    }

    fn try_recv(
        &self,
    ) -> Result<Option<Result<WorkspaceHarnessOutcome, ControlError>>, ControlClientError> {
        match self {
            Self::Read(pending) => pending
                .try_recv()
                .map(|result| result.map(|reply| reply.map(WorkspaceHarnessOutcome::Read))),
            Self::Preview(pending) => pending
                .try_recv()
                .map(|result| result.map(|reply| reply.map(WorkspaceHarnessOutcome::Preview))),
            Self::Apply(pending) => pending
                .try_recv()
                .map(|result| result.map(|reply| reply.map(WorkspaceHarnessOutcome::Applied))),
            Self::Verify(pending) => pending
                .try_recv()
                .map(|result| result.map(|reply| reply.map(WorkspaceHarnessOutcome::Verified))),
        }
    }
}

#[derive(Debug)]
enum WorkspaceHarnessOutcome {
    Read(Option<AppliedHarness>),
    Preview(HarnessInstallPreview),
    Applied(AppliedHarness),
    Verified(AppliedHarness),
}

#[derive(Debug, Default)]
struct HarnessUiState {
    scope: Option<ResolvedWorkspaceScope>,
    entries: Vec<HarnessCatalogEntry>,
    applied: Option<AppliedHarness>,
    preview: Option<HarnessInstallPreview>,
    verifier_run: Option<HarnessVerifierRun>,
    pending_library: Option<PendingHarnessRequest>,
    pending_control: Option<PendingWorkspaceHarness>,
    pending_verifier: Option<PendingVerifierAction>,
}

impl HarnessUiState {
    const fn is_busy(&self) -> bool {
        self.pending_library.is_some()
            || self.pending_control.is_some()
            || self.pending_verifier.is_some()
    }
}

pub(crate) fn bind_harness_actions(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    bind_register_harness(app, intents, busy);
    bind_refresh_harnesses(app, intents, busy);
    bind_refresh_harness(app, intents, busy);
    bind_preview_harness(app, intents, busy);
    bind_apply_preview(app, intents, busy);
    bind_run_verifiers(app, intents, busy);
    bind_refresh_verifiers(app, intents, busy);
    bind_verify_harness(app, intents, busy);
}

fn bind_register_harness(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let register_intents = intents.clone();
    let register_app = app.clone_strong();
    let register_busy = Rc::clone(busy);
    app.on_register_harness(move || {
        if register_busy.get() {
            return;
        }
        match pick_folder() {
            Ok(FolderSelection::Selected(source_root)) => {
                if register_intents
                    .try_send(UiHarnessIntent::Register(source_root))
                    .is_err()
                {
                    register_app.set_harness_library_status(
                        "ERROR [HARNESS_QUEUE] Harness registration was not admitted.".into(),
                    );
                }
            }
            Ok(FolderSelection::Cancelled) => {}
            Err(error) => register_app
                .set_harness_library_status(format!("ERROR [HARNESS_PICKER] {error}").into()),
        }
    });
}

fn bind_refresh_harnesses(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let refresh_intents = intents.clone();
    let refresh_app = app.clone_strong();
    let refresh_busy = Rc::clone(busy);
    app.on_refresh_harnesses(move || {
        if refresh_busy.get() {
            return;
        }
        if refresh_intents.try_send(UiHarnessIntent::Refresh).is_err() {
            refresh_app.set_harness_library_status(
                "ERROR [HARNESS_QUEUE] Harness refresh was not admitted.".into(),
            );
        }
    });
}

fn bind_refresh_harness(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let bundle_intents = intents.clone();
    let bundle_app = app.clone_strong();
    let bundle_busy = Rc::clone(busy);
    app.on_refresh_harness(move |id, revision| {
        if bundle_busy.get() {
            return;
        }
        let Some((id, expected_revision)) = parse_harness_target(id.as_str(), revision.as_str())
        else {
            bundle_app.set_harness_library_status(
                "ERROR [HARNESS_IDENTITY] Harness row identity is invalid.".into(),
            );
            return;
        };
        if bundle_intents
            .try_send(UiHarnessIntent::RefreshBundle {
                id,
                expected_revision,
            })
            .is_err()
        {
            bundle_app.set_harness_library_status(
                "ERROR [HARNESS_QUEUE] Harness Bundle refresh was not admitted.".into(),
            );
        }
    });
}

fn bind_preview_harness(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let preview_intents = intents.clone();
    let preview_app = app.clone_strong();
    let preview_busy = Rc::clone(busy);
    app.on_preview_harness(move |id, revision| {
        if preview_busy.get() {
            return;
        }
        let Some((id, expected_revision)) = parse_harness_target(id.as_str(), revision.as_str())
        else {
            preview_app.set_harness_preview_status(
                "ERROR [HARNESS_IDENTITY] Harness row identity is invalid.".into(),
            );
            return;
        };
        if preview_intents
            .try_send(UiHarnessIntent::Preview {
                id,
                expected_revision,
            })
            .is_err()
        {
            preview_app.set_harness_preview_status(
                "ERROR [HARNESS_QUEUE] Harness Preview was not admitted.".into(),
            );
        }
    });
}

fn bind_apply_preview(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let apply_intents = intents.clone();
    let apply_app = app.clone_strong();
    let apply_busy = Rc::clone(busy);
    app.on_apply_harness_preview(move || {
        if apply_busy.get() {
            return;
        }
        if apply_intents
            .try_send(UiHarnessIntent::ApplyPreview)
            .is_err()
        {
            apply_app.set_harness_preview_status(
                "ERROR [HARNESS_QUEUE] Harness Apply was not admitted.".into(),
            );
        }
    });
}

fn bind_run_verifiers(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let verifier_intents = intents.clone();
    let verifier_app = app.clone_strong();
    let verifier_busy = Rc::clone(busy);
    app.on_run_harness_verifiers(move || {
        if verifier_busy.get() {
            return;
        }
        if verifier_intents
            .try_send(UiHarnessIntent::RunVerifiers)
            .is_err()
        {
            verifier_app.set_harness_verifier_status(
                "ERROR [HARNESS_QUEUE] Declared verifier run was not admitted.".into(),
            );
        }
    });
}

fn bind_refresh_verifiers(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let verifier_intents = intents.clone();
    let verifier_app = app.clone_strong();
    let verifier_busy = Rc::clone(busy);
    app.on_refresh_harness_verifiers(move || {
        if verifier_busy.get() {
            return;
        }
        if verifier_intents
            .try_send(UiHarnessIntent::RefreshVerifiers)
            .is_err()
        {
            verifier_app.set_harness_verifier_status(
                "ERROR [HARNESS_QUEUE] Declared verifier refresh was not admitted.".into(),
            );
        }
    });
}

fn bind_verify_harness(
    app: &AppWindow,
    intents: &SyncSender<UiHarnessIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let verify_intents = intents.clone();
    let verify_app = app.clone_strong();
    let verify_busy = Rc::clone(busy);
    app.on_verify_applied_harness(move || {
        if verify_busy.get() {
            return;
        }
        if verify_intents
            .try_send(UiHarnessIntent::VerifyApplied)
            .is_err()
        {
            verify_app.set_harness_status(
                "ERROR [HARNESS_QUEUE] Harness verification was not admitted.".into(),
            );
        }
    });
}

fn parse_harness_target(id: &str, revision: &str) -> Option<(HarnessBundleId, HarnessRevision)> {
    let id = HarnessBundleId::from_str(id).ok()?;
    let revision = revision.parse::<i64>().ok()?;
    HarnessRevision::new(revision)
        .ok()
        .map(|revision| (id, revision))
}

pub(crate) fn start_harness_pump(
    app: &AppWindow,
    library: HarnessLibraryClient,
    control: ForgeControlClient,
    verifier: ForgeHarnessVerifierCoordinatorClient,
    intents: Receiver<UiHarnessIntent>,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let timer_for_callback = Rc::clone(&timer);
    let app = app.clone_strong();
    let state = Rc::new(std::cell::RefCell::new(HarnessUiState::default()));
    let state_for_callback = Rc::clone(&state);

    submit_library_action(
        &app,
        &library,
        &state,
        &busy,
        HarnessWorkerAction::List,
        "Loading registered Harness Bundles…",
    );

    timer.start(TimerMode::Repeated, PUMP_INTERVAL, move || {
        poll_library_pending(&app, &library, &state_for_callback, &busy);
        poll_control_pending(&app, &state_for_callback, &busy);
        poll_verifier_pending(&app, &state_for_callback, &busy);
        if state_for_callback.borrow().is_busy() {
            return;
        }
        match intents.try_recv() {
            Ok(UiHarnessIntent::WorkspaceSelected(scope)) => {
                select_workspace_scope(
                    &app,
                    &control,
                    &verifier,
                    &state_for_callback,
                    &busy,
                    scope,
                );
            }
            Ok(UiHarnessIntent::Refresh) => submit_library_action(
                &app,
                &library,
                &state_for_callback,
                &busy,
                HarnessWorkerAction::List,
                "Refreshing Harness Library…",
            ),
            Ok(UiHarnessIntent::Register(source_root)) => {
                register_selected_harness(&app, &library, &state_for_callback, &busy, source_root);
            }
            Ok(UiHarnessIntent::RefreshBundle {
                id,
                expected_revision,
            }) => refresh_bundle(
                &app,
                &library,
                &state_for_callback,
                &busy,
                id,
                expected_revision,
            ),
            Ok(UiHarnessIntent::Preview {
                id,
                expected_revision,
            }) => preview_registered_harness(
                &app,
                &control,
                &state_for_callback,
                &busy,
                id,
                expected_revision,
            ),
            Ok(UiHarnessIntent::ApplyPreview) => {
                apply_previewed_harness(&app, &control, &state_for_callback, &busy);
            }
            Ok(UiHarnessIntent::RunVerifiers) => {
                run_declared_verifiers(&app, &verifier, &state_for_callback, &busy);
            }
            Ok(UiHarnessIntent::RefreshVerifiers) => {
                refresh_declared_verifiers(&app, &verifier, &state_for_callback, &busy);
            }
            Ok(UiHarnessIntent::VerifyApplied) => {
                verify_applied_harness(&app, &control, &state_for_callback, &busy);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                timer_for_callback.stop();
            }
        }
    });
    timer
}

fn refresh_bundle(
    app: &AppWindow,
    client: &HarnessLibraryClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
    id: HarnessBundleId,
    expected_revision: HarnessRevision,
) {
    let Ok(observed_at) = observed_timestamp_now() else {
        app.set_harness_library_status(
            "ERROR [HARNESS_CLOCK] System time is outside the supported range.".into(),
        );
        return;
    };
    submit_library_action(
        app,
        client,
        state,
        busy,
        HarnessWorkerAction::Refresh {
            id,
            expected_revision,
            observed_at,
        },
        "Re-inspecting Harness Bundle…",
    );
}

fn register_selected_harness(
    app: &AppWindow,
    client: &HarnessLibraryClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
    source_root: std::path::PathBuf,
) {
    let Ok(observed_at) = observed_timestamp_now() else {
        app.set_harness_library_status(
            "ERROR [HARNESS_CLOCK] System time is outside the supported range.".into(),
        );
        return;
    };
    submit_library_action(
        app,
        client,
        state,
        busy,
        HarnessWorkerAction::Register {
            source_root,
            observed_at,
        },
        "Inspecting and registering Harness Bundle…",
    );
}

fn submit_library_action(
    app: &AppWindow,
    client: &HarnessLibraryClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
    action: HarnessWorkerAction,
    status: &str,
) {
    match client.submit(action) {
        Ok(request) => {
            state.borrow_mut().pending_library = Some(request);
            busy.set(true);
            app.set_harness_action_busy(true);
            app.set_harness_library_status(status.into());
        }
        Err(error) => {
            app.set_harness_library_status(format!("ERROR [HARNESS_WORKER] {error}").into());
        }
    }
}

fn poll_library_pending(
    app: &AppWindow,
    client: &HarnessLibraryClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let result = state
        .borrow()
        .pending_library
        .as_ref()
        .map(PendingHarnessRequest::try_recv);
    let Some(result) = result else {
        return;
    };
    let reply = match result {
        Ok(Some(reply)) => reply,
        Ok(None) => return,
        Err(error) => {
            finish_library_pending(app, state, busy);
            app.set_harness_library_status(format!("ERROR [HARNESS_WORKER] {error}").into());
            return;
        }
    };
    finish_library_pending(app, state, busy);
    match reply {
        Ok(HarnessWorkerOutcome::Listed(entries)) => {
            let mut current = state.borrow_mut();
            current.entries = entries;
            current.preview = None;
            drop(current);
            render_harness_projection(app, state);
        }
        Ok(HarnessWorkerOutcome::Registered(_) | HarnessWorkerOutcome::Refreshed(_)) => {
            submit_library_action(
                app,
                client,
                state,
                busy,
                HarnessWorkerAction::List,
                "Harness Bundle registered. Refreshing Library…",
            );
        }
        Err(error) => {
            error!(error = %error, "Harness Library action failed");
            app.set_harness_library_status(format!("ERROR [HARNESS_LIBRARY] {error}").into());
        }
    }
}

fn finish_library_pending(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    state.borrow_mut().pending_library.take();
    sync_busy(app, state, busy);
}

fn select_workspace_scope(
    app: &AppWindow,
    control: &ForgeControlClient,
    verifier: &ForgeHarnessVerifierCoordinatorClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
    scope: Option<ResolvedWorkspaceScope>,
) {
    {
        let mut current = state.borrow_mut();
        current.scope.clone_from(&scope);
        current.applied = None;
        current.preview = None;
        current.verifier_run = None;
    }
    render_harness_projection(app, state);
    let Some(scope) = scope else {
        app.set_harness_status("Select a committed Workspace to inspect Harness state.".into());
        return;
    };
    match control.submit_harness_get_applied(scope.clone()) {
        Ok(pending) => submit_control_pending(
            app,
            state,
            busy,
            PendingWorkspaceHarness::Read(pending),
            "Loading durable Workspace Harness…",
        ),
        Err(error) => app.set_harness_status(format!("ERROR [HARNESS_CONTROL] {error}").into()),
    }
    match verifier.submit_latest(scope.clone()) {
        Ok(pending) => submit_verifier_pending(
            app,
            state,
            busy,
            PendingVerifierAction {
                scope,
                kind: PendingVerifierKind::Latest(pending),
            },
            "Loading durable declared-verifier result…",
        ),
        Err(error) => {
            app.set_harness_verifier_status(format!("ERROR [HARNESS_VERIFIER] {error}").into());
        }
    }
}

fn run_declared_verifiers(
    app: &AppWindow,
    verifier: &ForgeHarnessVerifierCoordinatorClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let Some(request) = verifier_request(app, state, true) else {
        return;
    };
    let scope = request.scope().clone();
    match verifier.submit_start(request) {
        Ok(pending) => submit_verifier_pending(
            app,
            state,
            busy,
            PendingVerifierAction {
                scope,
                kind: PendingVerifierKind::Start(pending),
            },
            "Submitting declared verifiers to Approval…",
        ),
        Err(error) => {
            app.set_harness_verifier_status(format!("ERROR [HARNESS_VERIFIER] {error}").into());
        }
    }
}

fn refresh_declared_verifiers(
    app: &AppWindow,
    verifier: &ForgeHarnessVerifierCoordinatorClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let Some(request) = verifier_request(app, state, false) else {
        return;
    };
    let scope = request.scope().clone();
    match verifier.submit_refresh(request) {
        Ok(pending) => submit_verifier_pending(
            app,
            state,
            busy,
            PendingVerifierAction {
                scope,
                kind: PendingVerifierKind::Refresh(pending),
            },
            "Refreshing declared-verifier result…",
        ),
        Err(error) => {
            app.set_harness_verifier_status(format!("ERROR [HARNESS_VERIFIER] {error}").into());
        }
    }
}

fn verifier_request(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    require_source_ready: bool,
) -> Option<HarnessVerifierRunRequest> {
    let current = state.borrow();
    let Some(scope) = current.scope.clone() else {
        app.set_harness_verifier_status(
            "Select a committed Workspace before running declared verifiers.".into(),
        );
        return None;
    };
    let Some(applied) = current.applied.as_ref() else {
        app.set_harness_verifier_status("No Harness Bundle is applied to this Workspace.".into());
        return None;
    };
    if require_source_ready && applied.state() != HarnessVerificationState::Ready {
        app.set_harness_verifier_status(
            "Check Source Integrity successfully before running declared verifiers.".into(),
        );
        return None;
    }
    let Some(entry) = current
        .entries
        .iter()
        .find(|entry| entry.bundle().descriptor().id() == applied.bundle().id())
    else {
        app.set_harness_verifier_status(
            "ERROR [HARNESS_SOURCE] Applied Harness source is not registered in the Library."
                .into(),
        );
        return None;
    };
    Some(HarnessVerifierRunRequest::new(
        scope,
        entry.source_root().to_path_buf(),
    ))
}

fn preview_registered_harness(
    app: &AppWindow,
    control: &ForgeControlClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
    id: HarnessBundleId,
    expected_revision: HarnessRevision,
) {
    let request = {
        let current = state.borrow();
        let Some(scope) = current.scope.clone() else {
            app.set_harness_preview_status("Select a committed Workspace before Preview.".into());
            return;
        };
        let Some(entry) = current.entries.iter().find(|entry| {
            entry.bundle().descriptor().id() == id && entry.bundle().revision() == expected_revision
        }) else {
            app.set_harness_preview_status(
                "ERROR [HARNESS_STALE] Harness Library row is stale.".into(),
            );
            return;
        };
        HarnessPreviewRequest {
            scope,
            source_root: entry.source_root().to_path_buf(),
            expected_bundle: entry.bundle().descriptor().clone(),
        }
    };
    match control.submit_harness_preview(request) {
        Ok(pending) => submit_control_pending(
            app,
            state,
            busy,
            PendingWorkspaceHarness::Preview(pending),
            "Inspecting Workspace Harness changes…",
        ),
        Err(error) => {
            app.set_harness_preview_status(format!("ERROR [HARNESS_CONTROL] {error}").into());
        }
    }
}

fn apply_previewed_harness(
    app: &AppWindow,
    control: &ForgeControlClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let request = {
        let current = state.borrow();
        let Some(scope) = current.scope.clone() else {
            app.set_harness_preview_status(
                "Select a committed Workspace before Harness Apply.".into(),
            );
            return;
        };
        let Some(preview) = current.preview.clone() else {
            app.set_harness_preview_status("Run Preview before Harness Apply.".into());
            return;
        };
        if !preview.can_apply_with_agents_merge() {
            app.set_harness_preview_status(
                "Harness Preview contains unresolved conflicts; Apply is blocked.".into(),
            );
            return;
        }
        if current
            .applied
            .as_ref()
            .is_some_and(|applied| applied.bundle() != preview.descriptor())
        {
            app.set_harness_preview_status(
                "A different Harness is already applied; use the dedicated Update / Switch flow."
                    .into(),
            );
            return;
        }
        let Some(entry) = current
            .entries
            .iter()
            .find(|entry| entry.bundle().descriptor() == preview.descriptor())
        else {
            app.set_harness_preview_status(
                "ERROR [HARNESS_STALE] Previewed Harness is no longer registered.".into(),
            );
            return;
        };
        let Ok(observed_at) = observed_timestamp_now() else {
            app.set_harness_preview_status(
                "ERROR [HARNESS_CLOCK] System time is outside the supported range.".into(),
            );
            return;
        };
        HarnessApplyRequest {
            scope,
            source_root: entry.source_root().to_path_buf(),
            expected_preview: preview,
            observed_at,
        }
    };
    match control.submit_harness_apply(request) {
        Ok(pending) => submit_control_pending(
            app,
            state,
            busy,
            PendingWorkspaceHarness::Apply(pending),
            "Materializing Harness Preview…",
        ),
        Err(error) => {
            app.set_harness_preview_status(format!("ERROR [HARNESS_CONTROL] {error}").into());
        }
    }
}

fn verify_applied_harness(
    app: &AppWindow,
    control: &ForgeControlClient,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let target = {
        let current = state.borrow();
        let Some(scope) = current.scope.clone() else {
            app.set_harness_status("Select a committed Workspace before verification.".into());
            return;
        };
        let Some(applied) = current.applied.as_ref() else {
            app.set_harness_status("No Harness Bundle is applied to this Workspace.".into());
            return;
        };
        let Some(entry) = current
            .entries
            .iter()
            .find(|entry| entry.bundle().descriptor().id() == applied.bundle().id())
        else {
            app.set_harness_status(
                "ERROR [HARNESS_SOURCE] Applied Harness source is not registered in the Library."
                    .into(),
            );
            return;
        };
        (scope, entry.source_root().to_path_buf())
    };
    let Ok(observed_at) = observed_timestamp_now() else {
        app.set_harness_status(
            "ERROR [HARNESS_CLOCK] System time is outside the supported range.".into(),
        );
        return;
    };
    let request = HarnessVerifyRequest {
        scope: target.0,
        source_root: target.1,
        observed_at,
    };
    match control.submit_harness_verify_source(request) {
        Ok(pending) => submit_control_pending(
            app,
            state,
            busy,
            PendingWorkspaceHarness::Verify(pending),
            "Verifying applied Harness source…",
        ),
        Err(error) => app.set_harness_status(format!("ERROR [HARNESS_CONTROL] {error}").into()),
    }
}

fn submit_control_pending(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
    pending: PendingWorkspaceHarness,
    status: &str,
) {
    let is_preview = pending.is_preview();
    state.borrow_mut().pending_control = Some(pending);
    busy.set(true);
    app.set_harness_action_busy(true);
    if is_preview {
        app.set_harness_preview_status(status.into());
    } else {
        app.set_harness_status(status.into());
    }
}

fn submit_verifier_pending(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
    pending: PendingVerifierAction,
    status: &str,
) {
    state.borrow_mut().pending_verifier = Some(pending);
    busy.set(true);
    app.set_harness_action_busy(true);
    app.set_harness_verifier_status(status.into());
}

fn poll_verifier_pending(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let pending = state.borrow().pending_verifier.as_ref().map(|pending| {
        (
            pending.scope.clone(),
            pending.try_recv(),
        )
    });
    let Some((scope, result)) = pending else {
        return;
    };
    let reply = match result {
        Ok(Some(reply)) => reply,
        Ok(None) => return,
        Err(error) => {
            finish_verifier_pending(app, state, busy);
            app.set_harness_verifier_status(
                format!("ERROR [HARNESS_VERIFIER_CHANNEL] {error}").into(),
            );
            return;
        }
    };
    finish_verifier_pending(app, state, busy);
    if state.borrow().scope.as_ref() != Some(&scope) {
        return;
    }
    match reply {
        Ok(VerifierOutcome::Latest(run) | VerifierOutcome::Refreshed(run)) => {
            state.borrow_mut().verifier_run = run;
            render_harness_projection(app, state);
        }
        Ok(VerifierOutcome::Started(run)) => {
            state.borrow_mut().verifier_run = Some(run);
            render_harness_projection(app, state);
        }
        Err(error) => {
            error!(error = %error, "Harness declared verifier action failed");
            app.set_harness_verifier_status(
                format!("ERROR [HARNESS_VERIFIER] {error}").into(),
            );
        }
    }
}

fn finish_verifier_pending(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    state.borrow_mut().pending_verifier.take();
    sync_busy(app, state, busy);
}

fn poll_control_pending(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let is_preview = state
        .borrow()
        .pending_control
        .as_ref()
        .is_some_and(PendingWorkspaceHarness::is_preview);
    let result = state
        .borrow()
        .pending_control
        .as_ref()
        .map(PendingWorkspaceHarness::try_recv);
    let Some(result) = result else {
        return;
    };
    let reply = match result {
        Ok(Some(reply)) => reply,
        Ok(None) => return,
        Err(error) => {
            finish_control_pending(app, state, busy);
            if is_preview {
                app.set_harness_preview_status(format!("ERROR [HARNESS_CONTROL] {error}").into());
            } else {
                app.set_harness_status(format!("ERROR [HARNESS_CONTROL] {error}").into());
            }
            return;
        }
    };
    finish_control_pending(app, state, busy);
    match reply {
        Ok(WorkspaceHarnessOutcome::Read(applied)) => {
            state.borrow_mut().applied = applied;
            render_harness_projection(app, state);
        }
        Ok(WorkspaceHarnessOutcome::Preview(preview)) => {
            state.borrow_mut().preview = Some(preview);
            render_harness_projection(app, state);
        }
        Ok(WorkspaceHarnessOutcome::Applied(applied)) => {
            {
                let mut current = state.borrow_mut();
                current.applied = Some(applied);
                current.preview = None;
            }
            render_harness_projection(app, state);
            app.set_harness_preview_status(
                "Harness materialized and durable state committed. Run Preview again to inspect the current Workspace."
                    .into(),
            );
            app.set_harness_preview_applyable(false);
        }
        Ok(WorkspaceHarnessOutcome::Verified(applied)) => {
            state.borrow_mut().applied = Some(applied);
            render_harness_projection(app, state);
        }
        Err(error) => {
            error!(error = %error, "Workspace Harness control action failed");
            if is_preview {
                app.set_harness_preview_status(
                    format!("ERROR [{}] {}", error.code().as_str(), error).into(),
                );
            } else {
                app.set_harness_status(
                    format!("ERROR [{}] {}", error.code().as_str(), error).into(),
                );
            }
        }
    }
}

fn finish_control_pending(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    state.borrow_mut().pending_control.take();
    sync_busy(app, state, busy);
}

fn sync_busy(
    app: &AppWindow,
    state: &Rc<std::cell::RefCell<HarnessUiState>>,
    busy: &Rc<Cell<bool>>,
) {
    let is_busy = state.borrow().is_busy();
    busy.set(is_busy);
    app.set_harness_action_busy(is_busy);
}

fn render_harness_projection(app: &AppWindow, state: &Rc<std::cell::RefCell<HarnessUiState>>) {
    let current = state.borrow();
    apply_entries(app, &current.entries, current.applied.as_ref());
    apply_applied_harness(app, current.applied.as_ref(), &current.entries);
    apply_harness_preview(app, current.preview.as_ref(), current.applied.as_ref());
    apply_harness_verifier(app, current.verifier_run.as_ref());
}

fn apply_harness_verifier(app: &AppWindow, run: Option<&HarnessVerifierRun>) {
    let Some(run) = run else {
        app.set_harness_verifier_rows(ModelRc::new(VecModel::from(Vec::<HarnessRow>::new())));
        app.set_harness_verifier_status("No declared Harness verifier run recorded.".into());
        return;
    };
    let rows = run
        .items()
        .iter()
        .enumerate()
        .map(|(index, item)| HarnessRow {
            machine_id: SharedString::from(index.to_string()),
            revision: SharedString::from(""),
            label: SharedString::from(item.name().as_str()),
            value: SharedString::from(verifier_item_detail(item)),
            state: SharedString::from(verifier_item_state_label(item.state())),
        })
        .collect::<Vec<_>>();
    app.set_harness_verifier_rows(ModelRc::new(VecModel::from(rows)));
    let status = match run.state() {
        HarnessVerifierRunState::PendingApproval => {
            "VERIFIERS · PENDING APPROVAL · approve requests in the Approval panel".to_owned()
        }
        HarnessVerifierRunState::Running => "VERIFIERS · RUNNING".to_owned(),
        HarnessVerifierRunState::Passed => format!(
            "VERIFIERS · PASSED · {}/{} passed",
            run.passed_count(),
            run.items().len()
        ),
        HarnessVerifierRunState::Failed => format!(
            "VERIFIERS · FAILED · {} passed · {} failed",
            run.passed_count(),
            run.failed_count()
        ),
    };
    app.set_harness_verifier_status(status.into());
}

fn verifier_item_state_label(state: HarnessVerifierItemState) -> &'static str {
    match state {
        HarnessVerifierItemState::PendingApproval => "PENDING APPROVAL",
        HarnessVerifierItemState::Running => "RUNNING",
        HarnessVerifierItemState::Passed => "PASSED",
        HarnessVerifierItemState::Failed => "FAILED",
        HarnessVerifierItemState::Rejected => "REJECTED",
    }
}

fn verifier_item_detail(item: &forge_domain::HarnessVerifierItem) -> String {
    match item.state() {
        HarnessVerifierItemState::PendingApproval => "Approval required".to_owned(),
        HarnessVerifierItemState::Running => "Execution running".to_owned(),
        HarnessVerifierItemState::Rejected => "Approval was not granted".to_owned(),
        HarnessVerifierItemState::Passed | HarnessVerifierItemState::Failed => {
            let duration = item.duration_millis().map_or_else(
                || "duration unavailable".to_owned(),
                |value| format!("{value} ms"),
            );
            item.exit_code().map_or_else(
                || duration.clone(),
                |exit_code| format!("exit {exit_code} · {duration}"),
            )
        }
    }
}

fn apply_entries(
    app: &AppWindow,
    entries: &[HarnessCatalogEntry],
    applied: Option<&AppliedHarness>,
) {
    let applied_id = applied.map(|value| value.bundle().id());
    let rows = entries
        .iter()
        .map(|entry| harness_row(entry, applied_id))
        .collect::<Vec<_>>();
    app.set_harness_rows(ModelRc::new(VecModel::from(rows)));
    app.set_harness_library_status(
        format!(
            "{} Harness Bundle{} registered",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        )
        .into(),
    );
}

fn harness_row(entry: &HarnessCatalogEntry, applied_id: Option<HarnessBundleId>) -> HarnessRow {
    let descriptor = entry.bundle().descriptor();
    HarnessRow {
        machine_id: SharedString::from(descriptor.id().to_string()),
        revision: SharedString::from(entry.bundle().revision().get().to_string()),
        label: SharedString::from(descriptor.name().as_str()),
        value: SharedString::from(format!(
            "v{} · {} · {}",
            descriptor.version().as_str(),
            descriptor.content_hash(),
            entry.source_root().display()
        )),
        state: SharedString::from(if applied_id == Some(descriptor.id()) {
            "APPLIED"
        } else {
            "REGISTERED"
        }),
    }
}

fn apply_harness_preview(
    app: &AppWindow,
    preview: Option<&HarnessInstallPreview>,
    applied: Option<&AppliedHarness>,
) {
    let Some(preview) = preview else {
        app.set_harness_preview_rows(ModelRc::new(VecModel::from(Vec::<HarnessRow>::new())));
        app.set_harness_preview_applyable(false);
        app.set_harness_preview_status(
            "Select a registered Harness Bundle to preview Workspace changes.".into(),
        );
        return;
    };
    let rows = preview
        .items()
        .iter()
        .enumerate()
        .map(|(index, item)| HarnessRow {
            machine_id: SharedString::from(index.to_string()),
            revision: SharedString::from(""),
            label: SharedString::from(item.path().as_path().display().to_string()),
            value: SharedString::from(format!(
                "{} · {} bytes",
                match item.kind() {
                    HarnessPreviewKind::ManagedFile => "managed file",
                    HarnessPreviewKind::AgentsFile => "AGENTS.md",
                    HarnessPreviewKind::ManagedManifest => "managed manifest",
                },
                item.source_size().get()
            )),
            state: SharedString::from(match item.disposition() {
                HarnessPreviewDisposition::Create => "CREATE",
                HarnessPreviewDisposition::Merge => "MERGE",
                HarnessPreviewDisposition::Unchanged => "UNCHANGED",
                HarnessPreviewDisposition::Conflict => "CONFLICT",
            }),
        })
        .collect::<Vec<_>>();
    app.set_harness_preview_rows(ModelRc::new(VecModel::from(rows)));
    let switch_required = applied.is_some_and(|value| value.bundle() != preview.descriptor());
    app.set_harness_preview_applyable(preview.can_apply_with_agents_merge() && !switch_required);
    app.set_harness_preview_status(
        if switch_required {
            "Preview is valid, but a different Harness is already applied; Update / Switch is required."
                .to_owned()
        } else {
            format!(
                "Preview · create {} · merge {} · unchanged {} · conflict {}",
                preview.creates(),
                preview.merges(),
                preview.unchanged(),
                preview.conflicts()
            )
        }
        .into(),
    );
}

fn apply_applied_harness(
    app: &AppWindow,
    applied: Option<&AppliedHarness>,
    entries: &[HarnessCatalogEntry],
) {
    let Some(applied) = applied else {
        app.set_applied_harness_name("Not connected".into());
        app.set_applied_harness_version("".into());
        app.set_applied_harness_source("".into());
        app.set_applied_harness_hash("".into());
        app.set_applied_harness_verification("UNVERIFIED".into());
        app.set_applied_harness_verified_at("".into());
        app.set_harness_status("No Harness Bundle is applied to this Workspace.".into());
        return;
    };
    let descriptor = applied.bundle();
    let source = entries
        .iter()
        .find(|entry| entry.bundle().descriptor().id() == descriptor.id())
        .map(|entry| entry.source_root().display().to_string())
        .unwrap_or_default();
    let verification = match applied.state() {
        HarnessVerificationState::Applied => "UNVERIFIED",
        HarnessVerificationState::Ready => "SOURCE VERIFIED",
        HarnessVerificationState::Failed => "SOURCE DRIFT",
    };
    app.set_applied_harness_name(descriptor.name().as_str().into());
    app.set_applied_harness_version(descriptor.version().as_str().into());
    app.set_applied_harness_source(source.into());
    app.set_applied_harness_hash(descriptor.content_hash().to_string().into());
    app.set_applied_harness_verification(verification.into());
    app.set_applied_harness_verified_at(
        applied
            .verified_at()
            .map(|value| value.get().to_string())
            .unwrap_or_default()
            .into(),
    );
    app.set_harness_status(
        format!(
            "Workspace Harness revision {} · {verification}",
            applied.revision().get()
        )
        .into(),
    );
}

fn observed_timestamp_now() -> Result<TimestampMillis, ()> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?;
    let millis = i64::try_from(duration.as_millis()).map_err(|_| ())?;
    TimestampMillis::new(millis).map_err(|_| ())
}
