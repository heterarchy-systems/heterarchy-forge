use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

use forge_control::{
    ControlClientError, ForgeControlClient, GoalCompletionRequest, GoalLifecycleAction,
    GoalLifecycleRequest, PendingControl, ResolvedWorkspaceScope,
};
use forge_domain::{
    GoalCompletionBlocker, GoalContract, GoalId, GoalListLimit, GoalObjective, GoalReview,
    GoalRevision, GoalStatement, GoalStatus, GoalStatusKind, RegisteredGoal,
};
use forge_ui::{AppWindow, GoalRow};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use uuid::Uuid;

use crate::dag_ui::UiDagIntent;
use crate::{ActivityWorkspaceScope, observed_timestamp_now, resolved_activity_scope};

pub(crate) enum UiGoalIntent {
    WorkspaceSelected(Option<ActivityWorkspaceScope>),
    Refresh,
    Create {
        objective: String,
        success_criterion: String,
    },
    Select(GoalId),
    Transition {
        goal_id: GoalId,
        expected_revision: GoalRevision,
        action: GoalLifecycleAction,
    },
    Complete {
        goal_id: GoalId,
        expected_revision: GoalRevision,
    },
}

enum PendingGoalUi {
    List(PendingControl<Vec<RegisteredGoal>>),
    Create(PendingControl<RegisteredGoal>),
    Review {
        goal_id: GoalId,
        pending: PendingControl<GoalReview>,
    },
    Transition(PendingControl<RegisteredGoal>),
    Complete(PendingControl<RegisteredGoal>),
}

struct GoalUiController {
    app: AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiGoalIntent>,
    dag_intents: SyncSender<UiDagIntent>,
    busy: Rc<Cell<bool>>,
    scope: Option<ActivityWorkspaceScope>,
    goals: Vec<RegisteredGoal>,
    reviews: HashMap<GoalId, GoalReview>,
    selected_goal_id: Option<GoalId>,
    published_dag_goal_id: Cell<Option<GoalId>>,
    pending: Option<PendingGoalUi>,
}

impl GoalUiController {
    fn new(
        app: AppWindow,
        client: ForgeControlClient,
        intents: Receiver<UiGoalIntent>,
        dag_intents: SyncSender<UiDagIntent>,
        busy: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            app,
            client,
            intents,
            dag_intents,
            busy,
            scope: None,
            goals: Vec::new(),
            reviews: HashMap::new(),
            selected_goal_id: None,
            published_dag_goal_id: Cell::new(None),
            pending: None,
        }
    }

    fn start(&self) {
        self.clear("Select a committed Workspace to view Goals.");
    }

    fn tick(&mut self) {
        self.poll_pending();
        if self.pending.is_none() {
            while let Ok(intent) = self.intents.try_recv() {
                self.handle_intent(intent);
                if self.pending.is_some() {
                    break;
                }
            }
        }
    }

    fn handle_intent(&mut self, intent: UiGoalIntent) {
        match intent {
            UiGoalIntent::WorkspaceSelected(scope) => {
                self.pending.take();
                self.scope = scope;
                self.goals.clear();
                self.reviews.clear();
                self.selected_goal_id = None;
                self.published_dag_goal_id.set(None);
                self.set_busy(false);
                if self.scope.is_some() {
                    self.begin_list();
                } else {
                    self.clear("Select a committed Workspace to view Goals.");
                }
            }
            UiGoalIntent::Refresh => self.begin_list(),
            UiGoalIntent::Create {
                objective,
                success_criterion,
            } => self.begin_create(objective, success_criterion),
            UiGoalIntent::Select(goal_id) => {
                self.selected_goal_id = Some(goal_id);
                self.notify_dag_selection(Some(goal_id));
                self.begin_review(goal_id);
            }
            UiGoalIntent::Transition {
                goal_id,
                expected_revision,
                action,
            } => self.begin_transition(goal_id, expected_revision, action),
            UiGoalIntent::Complete {
                goal_id,
                expected_revision,
            } => self.begin_complete(goal_id, expected_revision),
        }
    }

    fn begin_list(&mut self) {
        let Some(scope) = self.resolved_scope() else {
            self.clear("Select a committed Workspace to view Goals.");
            return;
        };
        match self.client.submit_goal_list(scope, GoalListLimit::DEFAULT) {
            Ok(pending) => {
                self.set_busy(true);
                self.app.set_goal_status("Refreshing durable Goals…".into());
                self.pending = Some(PendingGoalUi::List(pending));
            }
            Err(error) => self.fail_control(&error),
        }
    }

    fn begin_create(&mut self, objective: String, success_criterion: String) {
        let Some(scope) = self.resolved_scope() else {
            self.clear("Select a committed Workspace before creating a Goal.");
            return;
        };
        let objective = match GoalObjective::new(objective) {
            Ok(value) => value,
            Err(error) => {
                self.fail("GOAL_CONTRACT_INVALID", error.to_string());
                return;
            }
        };
        let success = match GoalStatement::new(success_criterion) {
            Ok(value) => value,
            Err(error) => {
                self.fail("GOAL_CONTRACT_INVALID", error.to_string());
                return;
            }
        };
        let contract = match GoalContract::new(
            objective,
            vec![success],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ) {
            Ok(value) => value,
            Err(error) => {
                self.fail("GOAL_CONTRACT_INVALID", error.to_string());
                return;
            }
        };
        let observed_at = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail("GOAL_TIMESTAMP", error.to_string());
                return;
            }
        };
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::now_v7()),
            scope.workspace_id(),
            contract,
            observed_at,
        );
        match self.client.submit_goal_create(scope, goal) {
            Ok(pending) => {
                self.set_busy(true);
                self.app.set_goal_status("Creating durable Goal…".into());
                self.pending = Some(PendingGoalUi::Create(pending));
            }
            Err(error) => self.fail_control(&error),
        }
    }

    fn begin_review(&mut self, goal_id: GoalId) {
        let Some(scope) = self.resolved_scope() else {
            self.clear("Select a committed Workspace to review a Goal.");
            return;
        };
        match self.client.submit_goal_review(scope, goal_id) {
            Ok(pending) => {
                self.set_busy(true);
                self.app
                    .set_goal_status("Reviewing hard completion checks…".into());
                self.pending = Some(PendingGoalUi::Review { goal_id, pending });
            }
            Err(error) => self.fail_control(&error),
        }
    }

    fn begin_transition(
        &mut self,
        goal_id: GoalId,
        expected_revision: GoalRevision,
        action: GoalLifecycleAction,
    ) {
        let Some(scope) = self.resolved_scope() else {
            self.clear("Select a committed Workspace to update a Goal.");
            return;
        };
        if !self.goal_revision_matches(goal_id, expected_revision) {
            self.fail(
                "GOAL_REVISION_STALE",
                "The selected Goal revision is stale.",
            );
            return;
        }
        let observed_at = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail("GOAL_TIMESTAMP", error.to_string());
                return;
            }
        };
        match self.client.submit_goal_transition(GoalLifecycleRequest {
            scope,
            goal_id,
            expected_revision,
            observed_at,
            action,
        }) {
            Ok(pending) => {
                self.set_busy(true);
                self.app.set_goal_status("Updating Goal lifecycle…".into());
                self.pending = Some(PendingGoalUi::Transition(pending));
            }
            Err(error) => self.fail_control(&error),
        }
    }

    fn begin_complete(&mut self, goal_id: GoalId, expected_revision: GoalRevision) {
        let Some(scope) = self.resolved_scope() else {
            self.clear("Select a committed Workspace to complete a Goal.");
            return;
        };
        if !self.goal_revision_matches(goal_id, expected_revision) {
            self.fail(
                "GOAL_REVISION_STALE",
                "The selected Goal revision is stale.",
            );
            return;
        }
        let observed_at = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail("GOAL_TIMESTAMP", error.to_string());
                return;
            }
        };
        match self.client.submit_goal_complete(GoalCompletionRequest {
            scope,
            goal_id,
            expected_revision,
            review_id: Uuid::now_v7(),
            observed_at,
        }) {
            Ok(pending) => {
                self.set_busy(true);
                self.app
                    .set_goal_status("Revalidating evidence and completing Goal…".into());
                self.pending = Some(PendingGoalUi::Complete(pending));
            }
            Err(error) => self.fail_control(&error),
        }
    }

    fn poll_pending(&mut self) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let ready = match pending {
            PendingGoalUi::List(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(GoalReply::List))),
            PendingGoalUi::Create(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(GoalReply::Created))),
            PendingGoalUi::Review { goal_id, pending } => pending.try_recv().map(|value| {
                value.map(|result| result.map(|review| GoalReply::Reviewed(*goal_id, review)))
            }),
            PendingGoalUi::Transition(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(GoalReply::Transitioned))),
            PendingGoalUi::Complete(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(GoalReply::Completed))),
        };
        let result = match ready {
            Ok(Some(result)) => result,
            Ok(None) => return,
            Err(error) => {
                self.pending.take();
                self.fail_control(&error);
                return;
            }
        };
        self.pending.take();
        match result {
            Ok(GoalReply::List(goals)) => self.apply_list(goals),
            Ok(GoalReply::Created(goal)) => {
                self.selected_goal_id = Some(goal.id());
                self.notify_dag_selection(Some(goal.id()));
                self.app.set_goal_compose_open(false);
                self.app.set_goal_objective_input("".into());
                self.app.set_goal_success_criterion_input("".into());
                self.begin_list();
            }
            Ok(GoalReply::Reviewed(goal_id, review)) => {
                if self.selected_goal_id == Some(goal_id) {
                    self.reviews.insert(goal_id, review);
                    self.apply_rows();
                    self.apply_selected_goal(goal_id);
                    self.set_ready_status();
                } else {
                    self.set_busy(false);
                }
            }
            Ok(GoalReply::Transitioned(goal) | GoalReply::Completed(goal)) => {
                self.selected_goal_id = Some(goal.id());
                self.reviews.remove(&goal.id());
                self.begin_list();
            }
            Err(error) => self.fail_control_error(&error),
        }
    }

    fn apply_list(&mut self, goals: Vec<RegisteredGoal>) {
        let workspace_id = self.scope.as_ref().map(|scope| scope.workspace_id);
        if goals
            .iter()
            .any(|goal| Some(goal.workspace_id()) != workspace_id)
        {
            self.fail(
                "GOAL_SCOPE_MISMATCH",
                "Goal response crossed Workspace scope.",
            );
            return;
        }
        self.reviews
            .retain(|goal_id, _| goals.iter().any(|goal| goal.id() == *goal_id));
        self.goals = goals;
        self.apply_rows();
        if let Some(selected) = self
            .selected_goal_id
            .filter(|id| self.goals.iter().any(|goal| goal.id() == *id))
        {
            self.apply_selected_goal(selected);
            self.begin_review(selected);
        } else {
            self.selected_goal_id = None;
            self.clear_selected_goal();
            self.set_ready_status();
        }
    }

    fn apply_rows(&self) {
        let rows = self
            .goals
            .iter()
            .map(|goal| goal_row(goal, self.reviews.get(&goal.id())))
            .collect::<Vec<_>>();
        self.app.set_goal_rows(ModelRc::new(VecModel::from(rows)));
    }

    fn apply_selected_goal(&self, goal_id: GoalId) {
        let Some(goal) = self.goals.iter().find(|goal| goal.id() == goal_id) else {
            self.clear_selected_goal();
            return;
        };
        let row = goal_row(goal, self.reviews.get(&goal_id));
        self.app.set_selected_goal_id(row.id.clone());
        self.app.set_selected_goal_revision(row.revision.clone());
        self.app.set_selected_goal_state(row.state.clone());
        self.app.set_selected_goal_objective(row.objective.clone());
        self.app
            .set_selected_goal_success_criterion(row.success_criterion.clone());
        self.app
            .set_selected_goal_check_summary(row.check_summary.clone());
        self.app
            .set_selected_goal_evidence_summary(row.evidence_summary.clone());
        self.app.set_selected_goal_blocker(row.blocker.clone());
        self.app.set_selected_goal_can_pause(row.can_pause);
        self.app.set_selected_goal_can_resume(row.can_resume);
        self.app.set_selected_goal_can_cancel(row.can_cancel);
        self.app.set_selected_goal_can_complete(row.can_complete);
        self.notify_dag_selection(Some(goal_id));
    }

    fn notify_dag_selection(&self, goal_id: Option<GoalId>) {
        if self.published_dag_goal_id.get() == goal_id {
            return;
        }
        if self
            .dag_intents
            .try_send(UiDagIntent::GoalSelected(goal_id))
            .is_ok()
        {
            self.published_dag_goal_id.set(goal_id);
            return;
        }
        // The DAG is a read-only adjunct. A full/closed queue must not change
        // Goal authority or block the UI thread. Keep the previous cursor so
        // the next Goal/list projection retries the latest selection.
        self.app.set_goal_status(
            "ERROR [DAG_SCOPE_QUEUE] DAG selection update was not admitted.".into(),
        );
    }

    fn clear_selected_goal(&self) {
        self.notify_dag_selection(None);
        self.app.set_selected_goal_id("".into());
        self.app.set_selected_goal_revision("".into());
        self.app.set_selected_goal_state("".into());
        self.app.set_selected_goal_objective("".into());
        self.app.set_selected_goal_success_criterion("".into());
        self.app.set_selected_goal_check_summary("".into());
        self.app.set_selected_goal_evidence_summary("".into());
        self.app.set_selected_goal_blocker("".into());
        self.app.set_selected_goal_can_pause(false);
        self.app.set_selected_goal_can_resume(false);
        self.app.set_selected_goal_can_cancel(false);
        self.app.set_selected_goal_can_complete(false);
    }

    fn clear(&self, status: &str) {
        self.app
            .set_goal_rows(ModelRc::new(VecModel::from(Vec::<GoalRow>::new())));
        self.clear_selected_goal();
        self.app.set_goal_status(status.into());
        self.set_busy(false);
    }

    fn set_ready_status(&self) {
        self.app.set_goal_status(if self.goals.is_empty() {
            "No durable Goal · Activity remains valid without one".into()
        } else {
            format!(
                "{} durable Goal{} · select one for fresh hard review",
                self.goals.len(),
                if self.goals.len() == 1 { "" } else { "s" }
            )
            .into()
        });
        self.set_busy(false);
    }

    fn resolved_scope(&self) -> Option<ResolvedWorkspaceScope> {
        self.scope.as_ref().map(resolved_activity_scope)
    }

    fn goal_revision_matches(&self, goal_id: GoalId, revision: GoalRevision) -> bool {
        self.goals
            .iter()
            .find(|goal| goal.id() == goal_id)
            .is_some_and(|goal| goal.revision() == revision)
    }

    fn set_busy(&self, value: bool) {
        self.busy.set(value);
        self.app.set_goal_action_busy(value);
    }

    fn fail_control(&self, error: &ControlClientError) {
        self.fail(error.code().as_str(), error.code().summary());
    }

    fn fail_control_error(&self, error: &forge_control::ControlError) {
        self.fail(error.code().as_str(), error.code().summary());
    }

    fn fail(&self, code: &str, message: impl Into<SharedString>) {
        self.app
            .set_goal_status(format!("ERROR [{code}] {}", message.into()).into());
        self.set_busy(false);
    }
}

enum GoalReply {
    List(Vec<RegisteredGoal>),
    Created(RegisteredGoal),
    Reviewed(GoalId, GoalReview),
    Transitioned(RegisteredGoal),
    Completed(RegisteredGoal),
}

fn goal_row(goal: &RegisteredGoal, review: Option<&GoalReview>) -> GoalRow {
    let passed = review.map_or(0, |review| {
        review
            .hard_checks()
            .iter()
            .filter(|check| check.is_passed())
            .count()
    });
    let total = review.map_or(
        goal.contract().verification_requirements().len(),
        |review| review.hard_checks().len(),
    );
    let blocker = review
        .and_then(|review| review.blockers().first().copied())
        .map_or_else(
            || match goal.status() {
                GoalStatus::Blocked(blocker) => blocker.reason().as_str().to_owned(),
                GoalStatus::Failed(failure) => failure.reason().as_str().to_owned(),
                GoalStatus::Active
                | GoalStatus::Paused
                | GoalStatus::Completed
                | GoalStatus::Cancelled => String::new(),
            },
            blocker_label,
        );
    let state = status_label(goal.status());
    let review_ready = review.is_some_and(GoalReview::can_complete);
    GoalRow {
        id: goal.id().to_string().into(),
        title: goal.contract().objective().as_str().into(),
        objective: goal.contract().objective().as_str().into(),
        state: state.into(),
        revision: goal.revision().get().to_string().into(),
        success_criterion: goal
            .contract()
            .success_criteria()
            .first()
            .map_or("No criterion", GoalStatement::as_str)
            .into(),
        check_summary: if review.is_some() {
            format!("{passed}/{total} hard checks").into()
        } else {
            "Review on selection".into()
        },
        evidence_summary: review.map_or_else(
            || "Fresh evidence review not loaded".into(),
            |review| {
                format!(
                    "{} hard checks · {} completion blockers · manual acceptance required",
                    review.hard_checks().len(),
                    review.blockers().len()
                )
                .into()
            },
        ),
        blocker: blocker.into(),
        can_pause: matches!(goal.status(), GoalStatus::Active | GoalStatus::Blocked(_)),
        can_resume: matches!(goal.status(), GoalStatus::Paused | GoalStatus::Blocked(_)),
        can_cancel: !goal.status().is_terminal(),
        can_complete: matches!(goal.status(), GoalStatus::Active) && review_ready,
        terminal: goal.status().is_terminal(),
    }
}

const fn status_label(status: &GoalStatus) -> &'static str {
    match status.kind() {
        GoalStatusKind::Active => "ACTIVE",
        GoalStatusKind::Paused => "PAUSED",
        GoalStatusKind::Blocked => "BLOCKED",
        GoalStatusKind::Completed => "COMPLETED",
        GoalStatusKind::Failed => "FAILED",
        GoalStatusKind::Cancelled => "CANCELLED",
    }
}

fn blocker_label(blocker: GoalCompletionBlocker) -> String {
    match blocker {
        GoalCompletionBlocker::RequiredVerification { requirement_index } => {
            format!(
                "Required verification {} is incomplete",
                requirement_index + 1
            )
        }
        GoalCompletionBlocker::PendingApproval(_) => "A linked approval is pending".to_owned(),
        GoalCompletionBlocker::ActiveExecution(_) => "A linked execution is active".to_owned(),
        GoalCompletionBlocker::UnsealedEvidence(_) => "Linked evidence is not sealed".to_owned(),
    }
}

pub(crate) fn bind_goal_actions(
    app: &AppWindow,
    intents: &SyncSender<UiGoalIntent>,
    busy: &Rc<Cell<bool>>,
) {
    let intents_create = intents.clone();
    let app_create = app.clone_strong();
    let busy_create = Rc::clone(busy);
    app.on_create_goal(move |objective, success| {
        enqueue(
            &intents_create,
            &app_create,
            &busy_create,
            UiGoalIntent::Create {
                objective: objective.to_string(),
                success_criterion: success.to_string(),
            },
        );
    });

    let intents_refresh = intents.clone();
    let app_refresh = app.clone_strong();
    let busy_refresh = Rc::clone(busy);
    app.on_refresh_goals(move || {
        enqueue(
            &intents_refresh,
            &app_refresh,
            &busy_refresh,
            UiGoalIntent::Refresh,
        );
    });

    let intents_select = intents.clone();
    let app_select = app.clone_strong();
    let busy_select = Rc::clone(busy);
    app.on_select_goal(move |id| {
        let Ok(goal_id) = GoalId::from_str(id.as_str()) else {
            app_select.set_goal_status("ERROR [GOAL_ID_INVALID] Invalid Goal identity.".into());
            return;
        };
        enqueue(
            &intents_select,
            &app_select,
            &busy_select,
            UiGoalIntent::Select(goal_id),
        );
    });

    bind_transition(
        app,
        intents,
        busy,
        &GoalLifecycleAction::Pause,
        GoalAction::Pause,
    );
    bind_transition(
        app,
        intents,
        busy,
        &GoalLifecycleAction::Resume,
        GoalAction::Resume,
    );
    bind_transition(
        app,
        intents,
        busy,
        &GoalLifecycleAction::Cancel,
        GoalAction::Cancel,
    );
    bind_complete(app, intents, busy);
}

#[derive(Clone, Copy)]
enum GoalAction {
    Pause,
    Resume,
    Cancel,
}

fn bind_transition(
    app: &AppWindow,
    intents: &SyncSender<UiGoalIntent>,
    busy: &Rc<Cell<bool>>,
    action: &GoalLifecycleAction,
    callback: GoalAction,
) {
    match callback {
        GoalAction::Pause => {
            let intents = intents.clone();
            let app_for_callback = app.clone_strong();
            let busy = Rc::clone(busy);
            let action = action.clone();
            app.on_pause_goal(move |id, revision| {
                enqueue_transition(
                    &id,
                    &revision,
                    &intents,
                    &app_for_callback,
                    &busy,
                    action.clone(),
                );
            });
        }
        GoalAction::Resume => {
            let intents = intents.clone();
            let app_for_callback = app.clone_strong();
            let busy = Rc::clone(busy);
            let action = action.clone();
            app.on_resume_goal(move |id, revision| {
                enqueue_transition(
                    &id,
                    &revision,
                    &intents,
                    &app_for_callback,
                    &busy,
                    action.clone(),
                );
            });
        }
        GoalAction::Cancel => {
            let intents = intents.clone();
            let app_for_callback = app.clone_strong();
            let busy = Rc::clone(busy);
            let action = action.clone();
            app.on_cancel_goal(move |id, revision| {
                enqueue_transition(
                    &id,
                    &revision,
                    &intents,
                    &app_for_callback,
                    &busy,
                    action.clone(),
                );
            });
        }
    }
}

fn enqueue_transition(
    id: &SharedString,
    revision: &SharedString,
    intents: &SyncSender<UiGoalIntent>,
    app: &AppWindow,
    busy: &Rc<Cell<bool>>,
    action: GoalLifecycleAction,
) {
    let Some((goal_id, expected_revision)) = parse_target(id, revision, app) else {
        return;
    };
    enqueue(
        intents,
        app,
        busy,
        UiGoalIntent::Transition {
            goal_id,
            expected_revision,
            action,
        },
    );
}

fn bind_complete(app: &AppWindow, intents: &SyncSender<UiGoalIntent>, busy: &Rc<Cell<bool>>) {
    let intents = intents.clone();
    let app_for_callback = app.clone_strong();
    let busy = Rc::clone(busy);
    app.on_complete_goal(move |id, revision| {
        let Some((goal_id, expected_revision)) = parse_target(&id, &revision, &app_for_callback)
        else {
            return;
        };
        enqueue(
            &intents,
            &app_for_callback,
            &busy,
            UiGoalIntent::Complete {
                goal_id,
                expected_revision,
            },
        );
    });
}

fn parse_target(
    id: &SharedString,
    revision: &SharedString,
    app: &AppWindow,
) -> Option<(GoalId, GoalRevision)> {
    let goal_id = GoalId::from_str(id.as_str()).ok();
    let goal_revision = revision
        .as_str()
        .parse::<i64>()
        .ok()
        .and_then(|value| GoalRevision::new(value).ok());
    if let (Some(goal_id), Some(goal_revision)) = (goal_id, goal_revision) {
        Some((goal_id, goal_revision))
    } else {
        app.set_goal_status("ERROR [GOAL_TARGET_INVALID] Invalid Goal target.".into());
        None
    }
}

fn enqueue(
    intents: &SyncSender<UiGoalIntent>,
    app: &AppWindow,
    busy: &Rc<Cell<bool>>,
    intent: UiGoalIntent,
) {
    if busy.replace(true) {
        return;
    }
    match intents.try_send(intent) {
        Ok(()) => app.set_goal_action_busy(true),
        Err(mpsc::TrySendError::Full(_)) => {
            busy.set(false);
            app.set_goal_action_busy(false);
            app.set_goal_status("ERROR [GOAL_QUEUE_FULL] Goal queue is full.".into());
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            busy.set(false);
            app.set_goal_action_busy(false);
            app.set_goal_status(
                "ERROR [GOAL_WORKER_UNAVAILABLE] Goal worker is unavailable.".into(),
            );
        }
    }
}

pub(crate) fn start_goal_pump(
    app: &AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiGoalIntent>,
    dag_intents: SyncSender<UiDagIntent>,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller =
        GoalUiController::new(app.clone_strong(), client, intents, dag_intents, busy);
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
}

#[cfg(test)]
mod tests {
    use forge_domain::{TimestampMillis, WorkspaceId};

    use super::*;

    fn goal() -> Result<RegisteredGoal, Box<dyn std::error::Error>> {
        Ok(RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(1)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            GoalContract::new(
                GoalObjective::new("Ship the durable Goal projection".to_owned())?,
                vec![GoalStatement::new("All hard checks pass".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            TimestampMillis::new(10)?,
        ))
    }

    #[test]
    fn populated_goal_row_exposes_only_operator_safe_lifecycle_and_review_facts()
    -> Result<(), Box<dyn std::error::Error>> {
        let goal = goal()?;
        let review = GoalReview::new(goal.id(), goal.revision(), Vec::new(), Vec::new(), true)?;
        let row = goal_row(&goal, Some(&review));
        assert_eq!(row.state.as_str(), "ACTIVE");
        assert_eq!(row.revision.as_str(), "1");
        assert_eq!(row.success_criterion.as_str(), "All hard checks pass");
        assert!(row.can_pause);
        assert!(row.can_cancel);
        assert!(row.can_complete);
        assert!(!row.terminal);
        assert!(!row.evidence_summary.contains("reasoning"));
        Ok(())
    }

    #[test]
    fn terminal_goal_row_disables_every_mutating_action() -> Result<(), Box<dyn std::error::Error>>
    {
        let goal = goal()?;
        let cancelled = goal.cancel(goal.revision(), TimestampMillis::new(11)?)?;
        let row = goal_row(&cancelled, None);
        assert_eq!(row.state.as_str(), "CANCELLED");
        assert!(row.terminal);
        assert!(!row.can_pause);
        assert!(!row.can_resume);
        assert!(!row.can_cancel);
        assert!(!row.can_complete);
        Ok(())
    }
}
