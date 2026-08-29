//! Desktop projection for durable Agent attachments and public work, plus
//! explicit operator issue/revoke of one-shot exact-head DAG authoring grants.

use std::cell::Cell;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

use forge_control::{
    AgentContextRequest, AgentDagGrantDiscoverRequest, AgentDagGrantGetRequest,
    AgentDagGrantIssueRequest, AgentDagGrantRevokeRequest, AgentListRequest, ControlClientError,
    ForgeControlClient, PendingControl,
};
use forge_domain::{
    ActivityLiveness, AgentAttachmentProjection, AgentAttachmentState, AgentAuthoringCredential,
    AgentContextProjection, AgentDagAuthoringActor, AgentDagAuthoringGrant,
    AgentDagAuthoringGrantAvailability, AgentDagAuthoringGrantId, AgentDagAuthoringGrantTtl,
    AgentInstanceId, AgentListLimit, AgentTransportKind, AgentWorkPhase, DagHeadRevision,
    DagNodeId, DagRevisionNumber, GoalAttribution, GoalId, GoalRevision, TimestampMillis,
};
use forge_ui::{AgentRow, AppWindow};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};
use uuid::Uuid;

use crate::{ActivityWorkspaceScope, observed_timestamp_now, resolved_activity_scope};

const AGENT_OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) enum UiAgentIntent {
    WorkspaceSelected(Option<ActivityWorkspaceScope>),
    SelectAgent(AgentInstanceId),
    SelectNode(DagNodeId),
    IssueDagGrant {
        agent_id: AgentInstanceId,
        goal: GoalAttribution,
        dag_revision: DagRevisionNumber,
        head_revision: DagHeadRevision,
    },
    RevokeDagGrant,
}

enum PendingAgentUi {
    List(PendingControl<Vec<AgentAttachmentProjection>>),
    AgentContext {
        agent_id: AgentInstanceId,
        pending: PendingControl<Option<AgentContextProjection>>,
    },
    NodeContext {
        node_id: DagNodeId,
        agent_id: AgentInstanceId,
        pending: PendingControl<Option<AgentContextProjection>>,
    },
    GrantIssue(PendingControl<AgentDagAuthoringGrant>),
    GrantRevoke(PendingControl<AgentDagAuthoringGrant>),
    GrantGet(PendingControl<Option<AgentDagAuthoringGrant>>),
    GrantDiscover(PendingControl<Option<AgentDagAuthoringGrant>>),
}

pub(crate) fn bind_agent_actions(app: &AppWindow, intents: &SyncSender<UiAgentIntent>) {
    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_select_agent(move |value| {
        let Ok(agent_id) = AgentInstanceId::from_str(value.as_str()) else {
            app_for_action.set_inspector_detail("선택한 Agent ID가 올바르지 않습니다.".into());
            return;
        };
        if sender
            .try_send(UiAgentIntent::SelectAgent(agent_id))
            .is_err()
        {
            app_for_action.set_inspector_detail("Agent 선택 요청이 가득 찼습니다.".into());
        }
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_select_agent_work_for_node(move |value| {
        let Ok(node_id) = DagNodeId::from_str(value.as_str()) else {
            app_for_action.set_inspector_detail("선택한 DAG 단계 ID가 올바르지 않습니다.".into());
            return;
        };
        if sender.try_send(UiAgentIntent::SelectNode(node_id)).is_err() {
            app_for_action.set_inspector_detail("단계 작업 조회 요청이 가득 찼습니다.".into());
        }
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_issue_agent_dag_grant(
        move |agent_id, goal_id, goal_revision, dag_revision, head_revision| {
            let parsed = (|| {
                Ok::<_, ()>(UiAgentIntent::IssueDagGrant {
                    agent_id: AgentInstanceId::from_str(agent_id.as_str()).map_err(|_| ())?,
                    goal: GoalAttribution::new(
                        GoalId::from_str(goal_id.as_str()).map_err(|_| ())?,
                        parse_revision(goal_revision.as_str(), GoalRevision::new)?,
                    ),
                    dag_revision: parse_revision(dag_revision.as_str(), DagRevisionNumber::new)?,
                    head_revision: parse_revision(head_revision.as_str(), DagHeadRevision::new)?,
                })
            })();
            let Ok(intent) = parsed else {
                app_for_action.set_agent_dag_grant_status(
                    "선택한 Agent·Goal·DAG revision 정보가 올바르지 않습니다.".into(),
                );
                return;
            };
            if sender.try_send(intent).is_err() {
                app_for_action
                    .set_agent_dag_grant_status("재계획 권한 요청이 가득 찼습니다.".into());
            }
        },
    );

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_revoke_agent_dag_grant(move || {
        if sender.try_send(UiAgentIntent::RevokeDagGrant).is_err() {
            app_for_action
                .set_agent_dag_grant_status("재계획 권한 회수 요청이 가득 찼습니다.".into());
        }
    });
}

pub(crate) fn start_agent_pump(
    app: &AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiAgentIntent>,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller = AgentUiController::new(app.clone_strong(), client, intents, busy);
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
}

struct AgentUiController {
    app: AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiAgentIntent>,
    busy: Rc<Cell<bool>>,
    scope: Option<ActivityWorkspaceScope>,
    agents: Vec<AgentAttachmentProjection>,
    active_grant: Option<AgentDagAuthoringGrant>,
    pending: Option<PendingAgentUi>,
    next_observation: Instant,
    next_grant_observation: Instant,
}

impl AgentUiController {
    fn new(
        app: AppWindow,
        client: ForgeControlClient,
        intents: Receiver<UiAgentIntent>,
        busy: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            app,
            client,
            intents,
            busy,
            scope: None,
            agents: Vec::new(),
            active_grant: None,
            pending: None,
            next_observation: Instant::now(),
            next_grant_observation: Instant::now(),
        }
    }

    fn start(&self) {
        self.clear();
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
        if self.pending.is_none()
            && self.active_grant.is_some()
            && self.app.get_agent_dag_grant_active()
            && Instant::now() >= self.next_grant_observation
        {
            self.begin_grant_get();
        } else if self.pending.is_none()
            && self.scope.is_some()
            && Instant::now() >= self.next_observation
        {
            self.begin_list();
        }
    }

    fn handle_intent(&mut self, intent: UiAgentIntent) {
        match intent {
            UiAgentIntent::WorkspaceSelected(scope) => {
                self.pending.take();
                self.scope = scope;
                self.agents.clear();
                self.active_grant.take();
                self.clear();
                self.set_busy(false);
                if self.scope.is_some() {
                    self.begin_list();
                }
            }
            UiAgentIntent::SelectAgent(agent_id) => {
                self.active_grant.take();
                self.clear_grant();
                self.begin_agent_context(agent_id);
            }
            UiAgentIntent::SelectNode(node_id) => self.begin_node_context(node_id),
            UiAgentIntent::IssueDagGrant {
                agent_id,
                goal,
                dag_revision,
                head_revision,
            } => self.begin_grant_issue(agent_id, goal, dag_revision, head_revision),
            UiAgentIntent::RevokeDagGrant => self.begin_grant_revoke(),
        }
    }

    fn begin_list(&mut self) {
        let Some(scope) = self.scope.as_ref().map(resolved_activity_scope) else {
            self.clear();
            return;
        };
        let now = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail("AGENT_TIMESTAMP", error.to_string());
                return;
            }
        };
        match self.client.submit_agent_list(AgentListRequest {
            scope,
            activity_id: None,
            now,
            limit: AgentListLimit::DEFAULT,
        }) {
            Ok(pending) => {
                self.pending = Some(PendingAgentUi::List(pending));
                self.next_observation = Instant::now() + AGENT_OBSERVATION_INTERVAL;
                self.set_busy(true);
            }
            Err(error) => self.fail_control(&error),
        }
    }

    fn begin_agent_context(&mut self, agent_id: AgentInstanceId) {
        let Some((scope, activity_id)) = self.context_scope(agent_id) else {
            self.fail(
                "AGENT_NOT_FOUND",
                "선택한 Agent를 현재 Workspace에서 찾을 수 없습니다.",
            );
            return;
        };
        let now = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail("AGENT_TIMESTAMP", error.to_string());
                return;
            }
        };
        match self.client.submit_agent_get_context(AgentContextRequest {
            scope,
            activity_id,
            agent_id,
            now,
            focus_event_limit: AgentListLimit::DEFAULT,
            work_update_limit: AgentListLimit::DEFAULT,
        }) {
            Ok(pending) => {
                self.pending = Some(PendingAgentUi::AgentContext { agent_id, pending });
                self.set_busy(true);
            }
            Err(error) => self.fail_control(&error),
        }
    }

    fn begin_node_context(&mut self, node_id: DagNodeId) {
        let matching = self
            .agents
            .iter()
            .filter(|projection| {
                projection
                    .agent()
                    .focus()
                    .node()
                    .is_some_and(|node| node.id() == node_id)
            })
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [] => self.clear_node_work(),
            [projection] => {
                let agent_id = projection.agent().id();
                let Some((scope, activity_id)) = self.context_scope(agent_id) else {
                    self.clear_node_work();
                    return;
                };
                let now = match observed_timestamp_now() {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail("AGENT_TIMESTAMP", error.to_string());
                        return;
                    }
                };
                match self.client.submit_agent_get_context(AgentContextRequest {
                    scope,
                    activity_id,
                    agent_id,
                    now,
                    focus_event_limit: AgentListLimit::DEFAULT,
                    work_update_limit: AgentListLimit::DEFAULT,
                }) {
                    Ok(pending) => {
                        self.pending = Some(PendingAgentUi::NodeContext {
                            node_id,
                            agent_id,
                            pending,
                        });
                        self.set_busy(true);
                    }
                    Err(error) => self.fail_control(&error),
                }
            }
            projections => {
                self.app.set_selected_dag_agent_name(
                    format!("연결된 에이전트 {}개", projections.len()).into(),
                );
                self.app.set_selected_dag_work_summary(
                    "여러 Agent가 이 단계에 연결되어 있습니다. Agent를 선택해 작업을 확인하세요."
                        .into(),
                );
                self.app.set_selected_dag_public_summary("".into());
                self.app.set_selected_dag_last_observed("".into());
            }
        }
    }

    fn begin_grant_issue(
        &mut self,
        agent_id: AgentInstanceId,
        goal: GoalAttribution,
        dag_revision: DagRevisionNumber,
        head_revision: DagHeadRevision,
    ) {
        let Some((scope, actor)) = self.agent_authoring_actor(agent_id) else {
            return;
        };
        let issued_at = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail_grant("AGENT_GRANT_TIMESTAMP", error.to_string());
                return;
            }
        };
        let request = AgentDagGrantIssueRequest {
            scope,
            grant_id: AgentDagAuthoringGrantId::from_uuid(Uuid::now_v7()),
            actor,
            goal,
            expected_dag_revision: dag_revision,
            expected_head_revision: head_revision,
            issued_at,
            ttl: AgentDagAuthoringGrantTtl::DEFAULT,
        };
        match self.client.submit_agent_dag_grant_issue(request) {
            Ok(pending) => {
                self.pending = Some(PendingAgentUi::GrantIssue(pending));
                self.app.set_agent_dag_grant_status(
                    "선택한 Agent와 현재 DAG head를 확인해 5분·1회 권한을 발급하는 중…".into(),
                );
                self.set_busy(true);
            }
            Err(error) => self.fail_grant(error.code().as_str(), error.code().summary()),
        }
    }

    fn begin_grant_revoke(&mut self) {
        let Some(grant) = self.active_grant.as_ref() else {
            self.fail_grant("AGENT_GRANT_MISSING", "회수할 활성 권한이 없습니다.");
            return;
        };
        let Some(scope) = self.scope.as_ref().map(resolved_activity_scope) else {
            self.fail_grant("AGENT_GRANT_SCOPE", "선택한 Workspace가 없습니다.");
            return;
        };
        match self
            .client
            .submit_agent_dag_grant_revoke(AgentDagGrantRevokeRequest {
                scope,
                grant_id: grant.id(),
                expected_revision: grant.revision(),
            }) {
            Ok(pending) => {
                self.pending = Some(PendingAgentUi::GrantRevoke(pending));
                self.app
                    .set_agent_dag_grant_status("재계획 권한을 회수하는 중…".into());
                self.set_busy(true);
            }
            Err(error) => self.fail_grant(error.code().as_str(), error.code().summary()),
        }
    }

    fn begin_grant_get(&mut self) {
        let Some(grant) = self.active_grant.as_ref() else {
            return;
        };
        let Some(scope) = self.scope.as_ref().map(resolved_activity_scope) else {
            self.active_grant.take();
            self.clear_grant();
            return;
        };
        match self
            .client
            .submit_agent_dag_grant_get(AgentDagGrantGetRequest {
                scope,
                grant_id: grant.id(),
            }) {
            Ok(pending) => {
                self.pending = Some(PendingAgentUi::GrantGet(pending));
                self.next_grant_observation = Instant::now() + AGENT_OBSERVATION_INTERVAL;
            }
            Err(error) => self.fail_grant(error.code().as_str(), error.code().summary()),
        }
    }

    fn begin_grant_discover(&mut self, agent_id: AgentInstanceId) {
        let Some((scope, actor)) = self.agent_authoring_actor(agent_id) else {
            return;
        };
        let Some((goal, expected_dag_revision, expected_head_revision)) =
            self.selected_grant_target()
        else {
            self.clear_grant();
            return;
        };
        let now = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail_grant("AGENT_GRANT_TIMESTAMP", error.to_string());
                return;
            }
        };
        match self
            .client
            .submit_agent_dag_grant_discover(AgentDagGrantDiscoverRequest {
                scope,
                actor,
                goal,
                expected_dag_revision,
                expected_head_revision,
                now,
            }) {
            Ok(pending) => {
                self.pending = Some(PendingAgentUi::GrantDiscover(pending));
                self.set_busy(true);
            }
            Err(error) => self.fail_grant(error.code().as_str(), error.code().summary()),
        }
    }

    fn agent_authoring_actor(
        &self,
        agent_id: AgentInstanceId,
    ) -> Option<(
        forge_control::ResolvedWorkspaceScope,
        AgentDagAuthoringActor,
    )> {
        let projection = self
            .agents
            .iter()
            .find(|projection| projection.agent().id() == agent_id)?;
        let agent = projection.agent();
        if projection.activity().liveness() != ActivityLiveness::Live
            || agent.attachment_state().is_detached()
        {
            self.fail_grant(
                "AGENT_GRANT_NOT_LIVE",
                "실시간 Activity에 연결된 Agent만 재계획 권한을 받을 수 있습니다.",
            );
            return None;
        }
        let credential = match (agent.transport_principal(), agent.transport_kind()) {
            (Some(token_id), _) => AgentAuthoringCredential::Token(token_id),
            (None, AgentTransportKind::Stdio) => AgentAuthoringCredential::TrustedStdio,
            (None, _) => {
                self.fail_grant(
                    "AGENT_GRANT_PRINCIPAL",
                    "이 Agent의 인증 principal을 확인할 수 없습니다.",
                );
                return None;
            }
        };
        let scope = self.scope.as_ref().map(resolved_activity_scope)?;
        Some((
            scope,
            AgentDagAuthoringActor::new(
                agent.workspace_id(),
                agent.id(),
                agent.activity_id(),
                credential,
            ),
        ))
    }

    fn selected_grant_target(
        &self,
    ) -> Option<(GoalAttribution, DagRevisionNumber, DagHeadRevision)> {
        let goal_id = GoalId::from_str(self.app.get_selected_goal_id().as_str()).ok()?;
        let goal_revision = parse_revision(
            self.app.get_selected_goal_revision().as_str(),
            GoalRevision::new,
        )
        .ok()?;
        let dag_revision =
            parse_revision(self.app.get_dag_revision().as_str(), DagRevisionNumber::new).ok()?;
        let head_revision = parse_revision(
            self.app.get_dag_head_revision().as_str(),
            DagHeadRevision::new,
        )
        .ok()?;
        Some((
            GoalAttribution::new(goal_id, goal_revision),
            dag_revision,
            head_revision,
        ))
    }

    fn context_scope(
        &self,
        agent_id: AgentInstanceId,
    ) -> Option<(
        forge_control::ResolvedWorkspaceScope,
        forge_domain::ActivityId,
    )> {
        let activity_id = self
            .agents
            .iter()
            .find(|projection| projection.agent().id() == agent_id)?
            .agent()
            .activity_id();
        self.scope
            .as_ref()
            .map(|scope| (resolved_activity_scope(scope), activity_id))
    }

    // Keep the pending variant and its typed reply reducer together so every
    // queue response has one exhaustive correlation check.
    #[allow(clippy::too_many_lines)]
    fn poll_pending(&mut self) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let grant_operation = matches!(
            pending,
            PendingAgentUi::GrantIssue(_)
                | PendingAgentUi::GrantRevoke(_)
                | PendingAgentUi::GrantGet(_)
                | PendingAgentUi::GrantDiscover(_)
        );
        let result = match pending {
            PendingAgentUi::List(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(AgentReply::List))),
            PendingAgentUi::AgentContext { agent_id, pending } => pending.try_recv().map(|value| {
                value.map(|result| {
                    result.map(|context| AgentReply::AgentContext {
                        agent_id: *agent_id,
                        context,
                    })
                })
            }),
            PendingAgentUi::NodeContext {
                node_id,
                agent_id,
                pending,
            } => pending.try_recv().map(|value| {
                value.map(|result| {
                    result.map(|context| AgentReply::NodeContext {
                        node_id: *node_id,
                        agent_id: *agent_id,
                        context,
                    })
                })
            }),
            PendingAgentUi::GrantIssue(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(AgentReply::GrantIssued))),
            PendingAgentUi::GrantRevoke(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(AgentReply::GrantRevoked))),
            PendingAgentUi::GrantGet(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(AgentReply::GrantObserved))),
            PendingAgentUi::GrantDiscover(pending) => pending
                .try_recv()
                .map(|value| value.map(|result| result.map(AgentReply::GrantDiscovered))),
        };
        let result = match result {
            Ok(Some(result)) => result,
            Ok(None) => return,
            Err(error) => {
                self.pending.take();
                if grant_operation {
                    self.fail_grant(error.code().as_str(), error.code().summary());
                } else {
                    self.fail_control(&error);
                }
                return;
            }
        };
        self.pending.take();
        match result {
            Ok(AgentReply::List(agents)) => {
                self.agents = agents;
                self.publish_agents();
                self.next_observation = Instant::now() + AGENT_OBSERVATION_INTERVAL;
                self.set_busy(false);
            }
            Ok(AgentReply::AgentContext { agent_id, context }) => {
                if self.app.get_selected_agent_id().as_str() == agent_id.to_string()
                    && let Some(context) = context
                {
                    self.publish_selected_agent(&context);
                    self.set_busy(false);
                    self.begin_grant_discover(agent_id);
                    return;
                }
                self.set_busy(false);
            }
            Ok(AgentReply::NodeContext {
                node_id,
                agent_id,
                context,
            }) => {
                if context.is_some()
                    && self.app.get_selected_dag_id().as_str() == node_id.to_string()
                    && let Some(context) = context
                {
                    debug_assert_eq!(context.attachment().agent().id(), agent_id);
                    self.publish_selected_node_work(&context);
                }
                self.set_busy(false);
            }
            Ok(AgentReply::GrantIssued(grant)) => {
                self.active_grant = Some(grant);
                self.publish_grant();
                self.next_grant_observation = Instant::now() + AGENT_OBSERVATION_INTERVAL;
                self.set_busy(false);
            }
            Ok(AgentReply::GrantRevoked(grant)) => {
                self.active_grant = Some(grant);
                self.publish_grant();
                self.set_busy(false);
            }
            Ok(AgentReply::GrantObserved(grant) | AgentReply::GrantDiscovered(grant)) => {
                self.active_grant = grant;
                self.publish_grant();
                self.next_grant_observation = Instant::now() + AGENT_OBSERVATION_INTERVAL;
                self.set_busy(false);
            }
            Err(error) if grant_operation => {
                self.fail_grant(error.code().as_str(), error.code().summary());
            }
            Err(error) => self.fail_control_error(&error),
        }
    }

    fn publish_agents(&self) {
        let now = observed_timestamp_now().ok();
        let rows = self
            .agents
            .iter()
            .map(|projection| {
                let agent = projection.agent();
                let focus = agent.focus();
                AgentRow {
                    id: agent.id().to_string().into(),
                    display_name: agent.display_name().as_str().into(),
                    role: agent.declared_role().as_str().into(),
                    state: attachment_state_label(agent.attachment_state()).into(),
                    liveness: liveness_label(projection.activity().liveness()).into(),
                    current_goal: focus
                        .goal()
                        .map(|goal| self.goal_label(goal.goal_id()))
                        .unwrap_or_default()
                        .into(),
                    current_node: focus
                        .node()
                        .map(|node| self.node_label(node.id()))
                        .unwrap_or_default()
                        .into(),
                    public_summary: "".into(),
                    evidence: "".into(),
                    last_observed: now
                        .map_or_else(
                            || "시간 확인 불가".to_owned(),
                            |now| relative_time(now, agent.updated_at()),
                        )
                        .into(),
                }
            })
            .collect::<Vec<_>>();
        self.app.set_agent_rows(ModelRc::new(VecModel::from(rows)));
    }

    fn publish_selected_agent(&self, context: &AgentContextProjection) {
        let agent = context.attachment().agent();
        let latest = latest_work_update(context);
        let now = observed_timestamp_now().ok();
        self.app
            .set_selected_agent_name(agent.display_name().as_str().into());
        self.app
            .set_selected_agent_role(agent.declared_role().as_str().into());
        self.app.set_selected_agent_state(
            latest
                .map_or_else(
                    || attachment_state_label(agent.attachment_state()),
                    |update| work_phase_label(update.phase()),
                )
                .into(),
        );
        self.app.set_selected_agent_liveness(
            liveness_label(context.attachment().activity().liveness()).into(),
        );
        self.app.set_selected_agent_current_goal(
            agent
                .focus()
                .goal()
                .map(|goal| self.goal_label(goal.goal_id()))
                .unwrap_or_default()
                .into(),
        );
        self.app.set_selected_agent_current_node(
            agent
                .focus()
                .node()
                .map(|node| self.node_label(node.id()))
                .unwrap_or_default()
                .into(),
        );
        self.app.set_selected_agent_public_summary(
            latest
                .map(|update| update.summary().as_str())
                .unwrap_or_default()
                .into(),
        );
        self.app.set_selected_agent_evidence(
            latest
                .map(|update| evidence_label(update.evidence_refs().len()))
                .unwrap_or_default()
                .into(),
        );
        self.app.set_selected_agent_last_observed(
            now.map_or_else(
                || "시간 확인 불가".to_owned(),
                |now| {
                    relative_time(
                        now,
                        latest.map_or(
                            agent.updated_at(),
                            forge_domain::AgentWorkUpdate::observed_at,
                        ),
                    )
                },
            )
            .into(),
        );
    }

    fn publish_selected_node_work(&self, context: &AgentContextProjection) {
        let agent = context.attachment().agent();
        let latest = latest_work_update(context);
        let now = observed_timestamp_now().ok();
        self.app
            .set_selected_dag_agent_name(agent.display_name().as_str().into());
        self.app.set_selected_dag_work_summary(
            latest
                .map_or("관측된 작업 없음", |update| {
                    work_phase_label(update.phase())
                })
                .into(),
        );
        self.app.set_selected_dag_public_summary(
            latest
                .map(|update| update.summary().as_str())
                .unwrap_or_default()
                .into(),
        );
        self.app.set_selected_dag_last_observed(
            now.map_or_else(
                || "시간 확인 불가".to_owned(),
                |now| {
                    relative_time(
                        now,
                        latest.map_or(
                            agent.updated_at(),
                            forge_domain::AgentWorkUpdate::observed_at,
                        ),
                    )
                },
            )
            .into(),
        );
    }

    fn goal_label(&self, id: forge_domain::GoalId) -> String {
        let model = self.app.get_goal_rows();
        model
            .iter()
            .find(|row| row.id.as_str() == id.to_string())
            .map_or_else(|| "선택한 Goal".to_owned(), |row| row.title.to_string())
    }

    fn node_label(&self, id: DagNodeId) -> String {
        let model = self.app.get_dag_node_rows();
        model
            .iter()
            .find(|row| row.id.as_str() == id.to_string())
            .map_or_else(|| "선택한 단계".to_owned(), |row| row.label.to_string())
    }

    fn clear(&self) {
        self.app
            .set_agent_rows(ModelRc::new(VecModel::from(Vec::<AgentRow>::new())));
        self.app.set_selected_agent_id("".into());
        self.clear_grant();
        self.clear_node_work();
    }

    fn publish_grant(&self) {
        let Some(grant) = self.active_grant.as_ref() else {
            self.clear_grant();
            return;
        };
        let now = observed_timestamp_now().unwrap_or_else(|_| grant.issued_at());
        let availability = grant.availability(now);
        let (label, status) = match availability {
            AgentDagAuthoringGrantAvailability::Available => {
                let remaining = grant.expires_at().get().saturating_sub(now.get()) / 1_000;
                (
                    "활성",
                    format!(
                        "현재 DAG head에만 유효한 1회 권한 · {remaining}초 남음 · Agent가 MCP에서 자동으로 찾을 수 있습니다."
                    ),
                )
            }
            AgentDagAuthoringGrantAvailability::Expired => (
                "만료",
                "5분 권한이 만료되었습니다. 현재 head가 그대로라면 새 권한을 발급할 수 있습니다."
                    .to_owned(),
            ),
            AgentDagAuthoringGrantAvailability::Consumed => (
                "사용됨",
                "Agent가 이 권한으로 한 번의 새 DAG revision을 게시했습니다.".to_owned(),
            ),
            AgentDagAuthoringGrantAvailability::Revoked => {
                ("회수됨", "재계획 권한이 회수되었습니다.".to_owned())
            }
        };
        self.app
            .set_agent_dag_grant_id(grant.id().to_string().into());
        self.app
            .set_agent_dag_grant_goal_id(grant.goal().goal_id().to_string().into());
        self.app.set_agent_dag_grant_availability(label.into());
        self.app.set_agent_dag_grant_status(status.into());
        self.app
            .set_agent_dag_grant_active(availability.is_available());
    }

    fn clear_grant(&self) {
        self.app.set_agent_dag_grant_id("".into());
        self.app.set_agent_dag_grant_goal_id("".into());
        self.app.set_agent_dag_grant_availability("없음".into());
        self.app.set_agent_dag_grant_active(false);
        self.app.set_agent_dag_grant_status(
            "Goal과 DAG를 선택하면 이 Agent에게 5분간 한 번의 재계획 권한을 줄 수 있습니다.".into(),
        );
    }

    fn clear_node_work(&self) {
        self.app.set_selected_dag_agent_name("".into());
        self.app.set_selected_dag_work_summary("".into());
        self.app.set_selected_dag_public_summary("".into());
        self.app.set_selected_dag_last_observed("".into());
    }

    fn set_busy(&self, value: bool) {
        self.busy.set(value);
        self.app.set_agent_action_busy(value);
    }

    fn fail_control(&self, error: &ControlClientError) {
        self.fail(error.code().as_str(), error.code().summary());
    }

    fn fail_control_error(&self, error: &forge_control::ControlError) {
        self.fail(error.code().as_str(), error.code().summary());
    }

    fn fail(&self, code: &str, message: impl Into<SharedString>) {
        self.app
            .set_inspector_detail(format!("오류 [{code}] {}", message.into()).into());
        self.set_busy(false);
    }

    fn fail_grant(&self, code: &str, message: impl Into<SharedString>) {
        self.app
            .set_agent_dag_grant_status(format!("오류 [{code}] {}", message.into()).into());
        self.set_busy(false);
    }
}

enum AgentReply {
    List(Vec<AgentAttachmentProjection>),
    AgentContext {
        agent_id: AgentInstanceId,
        context: Option<AgentContextProjection>,
    },
    NodeContext {
        node_id: DagNodeId,
        agent_id: AgentInstanceId,
        context: Option<AgentContextProjection>,
    },
    GrantIssued(AgentDagAuthoringGrant),
    GrantRevoked(AgentDagAuthoringGrant),
    GrantObserved(Option<AgentDagAuthoringGrant>),
    GrantDiscovered(Option<AgentDagAuthoringGrant>),
}

fn latest_work_update(context: &AgentContextProjection) -> Option<&forge_domain::AgentWorkUpdate> {
    context
        .work_updates()
        .iter()
        .max_by_key(|update| update.sequence())
}

const fn attachment_state_label(state: AgentAttachmentState) -> &'static str {
    match state {
        AgentAttachmentState::Attached => "연결됨",
        AgentAttachmentState::Detached => "종료됨",
    }
}

const fn liveness_label(liveness: ActivityLiveness) -> &'static str {
    match liveness {
        ActivityLiveness::Available => "Lease 없음",
        ActivityLiveness::Live => "실시간",
        ActivityLiveness::Expired => "연결 끊김",
        ActivityLiveness::Closed => "닫힘",
        ActivityLiveness::Interrupted => "중단됨",
    }
}

const fn work_phase_label(phase: AgentWorkPhase) -> &'static str {
    match phase {
        AgentWorkPhase::Planning => "계획 중",
        AgentWorkPhase::Executing => "작업 중",
        AgentWorkPhase::Waiting => "대기",
        AgentWorkPhase::Verifying => "검증 중",
        AgentWorkPhase::Completed => "완료",
        AgentWorkPhase::Blocked => "차단됨",
        AgentWorkPhase::Failed => "실패",
    }
}

fn evidence_label(count: usize) -> String {
    if count == 0 {
        "연결된 근거 없음".to_owned()
    } else {
        format!("근거 {count}개")
    }
}

fn relative_time(now: TimestampMillis, observed: TimestampMillis) -> String {
    let seconds = now.get().saturating_sub(observed.get()).max(0) / 1_000;
    match seconds {
        0..=4 => "방금".to_owned(),
        5..=59 => format!("{seconds}초 전"),
        60..=3_599 => format!("{}분 전", seconds / 60),
        _ => format!("{}시간 전", seconds / 3_600),
    }
}

fn parse_revision<T, E>(
    value: &str,
    constructor: impl FnOnce(i64) -> Result<T, E>,
) -> Result<T, ()> {
    let raw = value.parse::<i64>().map_err(|_| ())?;
    constructor(raw).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(value: i64) -> TimestampMillis {
        TimestampMillis::new(value).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn agent_labels_are_korean_operator_safe_and_do_not_imply_authority() {
        assert_eq!(
            attachment_state_label(AgentAttachmentState::Attached),
            "연결됨"
        );
        assert_eq!(liveness_label(ActivityLiveness::Expired), "연결 끊김");
        assert_eq!(work_phase_label(AgentWorkPhase::Executing), "작업 중");
        assert_eq!(work_phase_label(AgentWorkPhase::Waiting), "대기");
    }

    #[test]
    fn relative_time_is_bounded_and_saturates_clock_regression() {
        assert_eq!(relative_time(timestamp(10_000), timestamp(9_000)), "방금");
        assert_eq!(
            relative_time(timestamp(70_000), timestamp(10_000)),
            "1분 전"
        );
        assert_eq!(relative_time(timestamp(10_000), timestamp(11_000)), "방금");
    }

    #[test]
    fn evidence_label_never_fabricates_content() {
        assert_eq!(evidence_label(0), "연결된 근거 없음");
        assert_eq!(evidence_label(3), "근거 3개");
    }
}
