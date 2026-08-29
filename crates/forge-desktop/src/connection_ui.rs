//! Slint projection/controller for explicit MCP Connection settings.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::Duration;

use forge_control::{McpTokenIssueRequest, McpTokenMetadata};
use forge_domain::{
    DEFAULT_MCP_LOCAL_PORT, McpConnectionSettings, McpTokenLabel, McpTokenState,
    McpTokenWorkspaceScope, RegisteredMcpConnectionSettings,
};
use forge_mcp::McpTokenRuntimeError;
use forge_ui::{AppWindow, McpTokenRow};
use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};

use crate::connection_worker::{
    ConnectionServerProjection, ConnectionWorkerAction, ConnectionWorkerError,
    ConnectionWorkerOutcome, McpConnectionClient, PendingConnectionRequest,
};
use crate::{ActivityWorkspaceScope, observed_timestamp_now};

pub(crate) enum UiConnectionIntent {
    WorkspaceSelected(Option<ActivityWorkspaceScope>),
    Refresh,
    Save { public_base: String, port: String },
    Issue { label: String },
    Rotate { index: i32 },
    Revoke { index: i32 },
    Start,
    Stop,
    DismissReveal,
}

pub(crate) fn bind_connection_actions(app: &AppWindow, intents: &SyncSender<UiConnectionIntent>) {
    let send =
        |intent: UiConnectionIntent, sender: &SyncSender<UiConnectionIntent>, app: &AppWindow| {
            if sender.try_send(intent).is_err() {
                app.set_mcp_connection_status(
                    "오류 [MCP_CONNECTION_QUEUE] 연결 요청이 가득 찼습니다.".into(),
                );
            }
        };

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_save_mcp_connection(move |public_base, port| {
        send(
            UiConnectionIntent::Save {
                public_base: public_base.to_string(),
                port: port.to_string(),
            },
            &sender,
            &app_for_action,
        );
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_refresh_mcp_connection(move || {
        send(UiConnectionIntent::Refresh, &sender, &app_for_action);
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_issue_mcp_token(move |label| {
        send(
            UiConnectionIntent::Issue {
                label: label.to_string(),
            },
            &sender,
            &app_for_action,
        );
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_rotate_mcp_token(move |index| {
        send(
            UiConnectionIntent::Rotate { index },
            &sender,
            &app_for_action,
        );
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_revoke_mcp_token(move |index| {
        send(
            UiConnectionIntent::Revoke { index },
            &sender,
            &app_for_action,
        );
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_start_mcp_server(move || {
        send(UiConnectionIntent::Start, &sender, &app_for_action);
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_stop_mcp_server(move || {
        send(UiConnectionIntent::Stop, &sender, &app_for_action);
    });

    let sender = intents.clone();
    let app_for_action = app.clone_strong();
    app.on_dismiss_mcp_token_reveal(move || {
        send(UiConnectionIntent::DismissReveal, &sender, &app_for_action);
    });
}

pub(crate) fn start_connection_pump(
    app: &AppWindow,
    client: McpConnectionClient,
    intents: Receiver<UiConnectionIntent>,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller = ConnectionUiController::new(app.clone_strong(), client, intents, busy);
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
}

struct ConnectionUiController {
    app: AppWindow,
    client: McpConnectionClient,
    intents: Receiver<UiConnectionIntent>,
    busy: Rc<Cell<bool>>,
    scope: Option<ActivityWorkspaceScope>,
    settings: Option<RegisteredMcpConnectionSettings>,
    tokens: Vec<McpTokenMetadata>,
    pending: Option<PendingConnectionRequest>,
}

impl ConnectionUiController {
    fn new(
        app: AppWindow,
        client: McpConnectionClient,
        intents: Receiver<UiConnectionIntent>,
        busy: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            app,
            client,
            intents,
            busy,
            scope: None,
            settings: None,
            tokens: Vec::new(),
            pending: None,
        }
    }

    fn start(&mut self) {
        self.app
            .set_mcp_connection_status("연결 설정을 불러오는 중…".into());
        self.begin(ConnectionWorkerAction::Load);
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

    fn handle_intent(&mut self, intent: UiConnectionIntent) {
        match intent {
            UiConnectionIntent::WorkspaceSelected(scope) => {
                self.scope = scope;
                self.clear_reveal();
                self.publish_tokens();
                self.begin(ConnectionWorkerAction::Load);
            }
            UiConnectionIntent::Refresh => self.begin(ConnectionWorkerAction::Load),
            UiConnectionIntent::Save { public_base, port } => {
                self.begin_save(public_base, &port);
            }
            UiConnectionIntent::Issue { label } => {
                let Some(scope) = self.scope.as_ref() else {
                    self.fail("MCP_WORKSPACE_REQUIRED", "먼저 Workspace를 선택하세요.");
                    return;
                };
                let label = match McpTokenLabel::new(label) {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail("MCP_TOKEN_LABEL_INVALID", error.to_string());
                        return;
                    }
                };
                let observed_at = match observed_timestamp_now() {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail("MCP_TIMESTAMP", error.to_string());
                        return;
                    }
                };
                let request = match McpTokenIssueRequest::new(
                    label,
                    vec![McpTokenWorkspaceScope::new(
                        scope.location_id,
                        scope.workspace_id,
                    )],
                    observed_at,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail("MCP_TOKEN_REQUEST_INVALID", error.to_string());
                        return;
                    }
                };
                self.begin(ConnectionWorkerAction::Issue { request });
            }
            UiConnectionIntent::Rotate { index } => {
                let Some(token) = self.token_at(index).cloned() else {
                    self.fail(
                        "MCP_TOKEN_SELECTION",
                        "선택한 자격 증명을 찾을 수 없습니다.",
                    );
                    return;
                };
                let observed_at = match observed_timestamp_now() {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail("MCP_TIMESTAMP", error.to_string());
                        return;
                    }
                };
                self.begin(ConnectionWorkerAction::Rotate {
                    id: token.id(),
                    expected_revision: token.revision(),
                    observed_at,
                });
            }
            UiConnectionIntent::Revoke { index } => {
                let Some(token) = self.token_at(index).cloned() else {
                    self.fail(
                        "MCP_TOKEN_SELECTION",
                        "선택한 자격 증명을 찾을 수 없습니다.",
                    );
                    return;
                };
                let observed_at = match observed_timestamp_now() {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail("MCP_TIMESTAMP", error.to_string());
                        return;
                    }
                };
                self.begin(ConnectionWorkerAction::Revoke {
                    id: token.id(),
                    expected_revision: token.revision(),
                    observed_at,
                });
            }
            UiConnectionIntent::Start => self.begin(ConnectionWorkerAction::Start),
            UiConnectionIntent::Stop => self.begin(ConnectionWorkerAction::Stop),
            UiConnectionIntent::DismissReveal => self.clear_reveal(),
        }
    }

    fn begin_save(&mut self, public_base: String, port: &str) {
        let Ok(port) = port.trim().parse::<u16>() else {
            self.fail(
                "MCP_PORT_INVALID",
                "로컬 포트는 1부터 65535 사이의 숫자여야 합니다.",
            );
            return;
        };
        let settings = match McpConnectionSettings::from_input(public_base, Some(port)) {
            Ok(settings) => settings,
            Err(error) => {
                self.fail("MCP_ENDPOINT_INVALID", error.to_string());
                return;
            }
        };
        let observed_at = match observed_timestamp_now() {
            Ok(value) => value,
            Err(error) => {
                self.fail("MCP_TIMESTAMP", error.to_string());
                return;
            }
        };
        self.begin(ConnectionWorkerAction::Save {
            settings,
            expected_revision: self
                .settings
                .as_ref()
                .map(RegisteredMcpConnectionSettings::revision),
            observed_at,
        });
    }

    fn begin(&mut self, action: ConnectionWorkerAction) {
        if self.pending.is_some() {
            return;
        }
        match self.client.submit(action) {
            Ok(pending) => {
                self.pending = Some(pending);
                self.set_busy(true);
            }
            Err(error) => self.fail_worker(&error),
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
        match result {
            Ok(ConnectionWorkerOutcome::Loaded {
                settings,
                tokens,
                server,
            }) => {
                self.settings = settings;
                self.tokens = tokens;
                self.publish_settings();
                self.publish_tokens();
                self.publish_server(server);
                self.set_busy(false);
            }
            Ok(ConnectionWorkerOutcome::Saved(settings)) => {
                self.settings = Some(settings);
                self.publish_settings();
                self.publish_server(ConnectionServerProjection::Stopped);
                self.app
                    .set_mcp_connection_status("공개 MCP 주소를 저장했습니다.".into());
                self.set_busy(false);
            }
            Ok(ConnectionWorkerOutcome::Issued(issued)) => {
                self.app
                    .set_mcp_token_reveal(issued.reveal().as_str().into());
                self.app.set_mcp_token_reveal_status(
                    "한 번만 표시됩니다. 지금 MCP 클라이언트에 복사하세요.".into(),
                );
                self.set_busy(false);
                self.begin(ConnectionWorkerAction::Load);
            }
            Ok(ConnectionWorkerOutcome::Rotated(rotation)) => {
                self.app
                    .set_mcp_token_reveal(rotation.replacement().reveal().as_str().into());
                self.app.set_mcp_token_reveal_status(
                    "기존 토큰은 즉시 중지됐습니다. 새 토큰을 복사하세요.".into(),
                );
                self.set_busy(false);
                self.begin(ConnectionWorkerAction::Load);
            }
            Ok(ConnectionWorkerOutcome::Revoked) => {
                self.clear_reveal();
                self.set_busy(false);
                self.begin(ConnectionWorkerAction::Load);
            }
            Ok(ConnectionWorkerOutcome::Started(server)) => {
                self.publish_server(server);
                self.set_busy(false);
            }
            Ok(ConnectionWorkerOutcome::Stopped) => {
                self.publish_server(ConnectionServerProjection::Stopped);
                self.set_busy(false);
            }
            Err(error) => self.fail_worker(&error),
        }
    }

    fn publish_settings(&self) {
        if let Some(settings) = self.settings.as_ref() {
            self.app
                .set_mcp_public_origin_input(settings.public_origin().unwrap_or_default().into());
            self.app
                .set_mcp_local_port_input(settings.local_port().get().to_string().into());
            self.app
                .set_mcp_public_endpoint(settings.mcp_endpoint().unwrap_or_default().into());
            self.app.set_mcp_local_endpoint(
                format!("http://127.0.0.1:{}/mcp", settings.local_port().get()).into(),
            );
            self.app.set_mcp_profile_configured(true);
            if settings.public_origin().is_some() {
                self.app
                    .set_mcp_connection_status("Custom MCP 도메인을 저장했습니다.".into());
                self.app.set_mcp_public_route_status(
                    "Custom domain 우선 · bridge 시작 시 Cloudflare tunnel 사용".into(),
                );
            } else {
                self.app.set_mcp_connection_status(
                    "도메인이 비어 있어 Cloudflare Quick Tunnel을 사용합니다.".into(),
                );
                self.app.set_mcp_public_route_status(
                    "Quick Tunnel · bridge 시작 시 trycloudflare.com 주소 자동 생성".into(),
                );
            }
        } else {
            self.app.set_mcp_profile_configured(false);
            self.app.set_mcp_public_origin_input("".into());
            self.app
                .set_mcp_local_port_input(DEFAULT_MCP_LOCAL_PORT.to_string().into());
            self.app.set_mcp_public_endpoint("".into());
            self.app.set_mcp_connection_status(
                "저장된 도메인이 없으면 Cloudflare Quick Tunnel을 사용합니다.".into(),
            );
            self.app.set_mcp_public_route_status(
                "기본값 · bridge 시작 시 trycloudflare.com 주소 자동 생성".into(),
            );
        }
    }

    fn publish_tokens(&mut self) {
        let scoped = self
            .scope
            .as_ref()
            .map(|scope| {
                self.tokens
                    .iter()
                    .filter(|token| {
                        token.scopes().iter().any(|token_scope| {
                            token_scope.location_id() == scope.location_id
                                && token_scope.workspace_id() == scope.workspace_id
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.tokens = scoped;
        let active = self
            .tokens
            .iter()
            .filter(|token| token.state() == McpTokenState::Active)
            .count();
        let rows = self
            .tokens
            .iter()
            .map(|token| McpTokenRow {
                label: token.label().as_str().into(),
                detail: "선택한 Workspace에서만 사용할 수 있습니다.".into(),
                state: token_state_label(token.state()).into(),
            })
            .collect::<Vec<_>>();
        self.app
            .set_mcp_token_rows(ModelRc::new(VecModel::from(rows)));
        self.app
            .set_mcp_active_token_count(i32::try_from(active).unwrap_or(i32::MAX));
        self.app.set_selected_mcp_token_index(-1);
    }

    fn publish_server(&self, server: ConnectionServerProjection) {
        match server {
            ConnectionServerProjection::Stopped => {
                self.app.set_mcp_server_running(false);
                self.app.set_mcp_server_status("중지됨".into());
                self.app.set_mcp_server_detail(
                    if self.settings.is_some() {
                        "주소 저장됨 · 접근 토큰 없이도 안전하게 시작할 수 있습니다."
                    } else {
                        "외부 MCP 주소를 저장하면 로컬 서버를 시작할 수 있습니다."
                    }
                    .into(),
                );
            }
            ConnectionServerProjection::Running {
                local_endpoint,
                public_endpoint,
            } => {
                self.app.set_mcp_server_running(true);
                self.app.set_mcp_server_status("실행 중".into());
                self.app
                    .set_mcp_server_detail(format!("로컬 수신 중 · {local_endpoint}").into());
                if let Some(endpoint) = public_endpoint {
                    self.app.set_mcp_public_endpoint(endpoint.into());
                }
            }
        }
    }

    fn token_at(&self, index: i32) -> Option<&McpTokenMetadata> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.tokens.get(index))
    }

    fn clear_reveal(&self) {
        self.app.set_mcp_token_reveal("".into());
        self.app.set_mcp_token_reveal_status("".into());
    }

    fn set_busy(&self, value: bool) {
        self.busy.set(value);
        self.app.set_mcp_action_busy(value);
    }

    fn fail_worker(&self, error: &ConnectionWorkerError) {
        let code = match error {
            ConnectionWorkerError::QueueFull => "MCP_CONNECTION_QUEUE",
            ConnectionWorkerError::Unavailable | ConnectionWorkerError::ShuttingDown => {
                "MCP_CONNECTION_UNAVAILABLE"
            }
            ConnectionWorkerError::RevisionConflict => "MCP_CONNECTION_STALE",
            ConnectionWorkerError::AlreadyRunning => "MCP_SERVER_RUNNING",
            ConnectionWorkerError::AlreadyStopped => "MCP_SERVER_STOPPED",
            ConnectionWorkerError::RunningSettingsLocked => "MCP_SETTINGS_RUNNING",
            ConnectionWorkerError::TokenRuntime(McpTokenRuntimeError::PepperRecoveryRequired) => {
                "MCP_KEY_RECOVERY"
            }
            ConnectionWorkerError::Http(_) => "MCP_SERVER",
            ConnectionWorkerError::Tunnel(_) => "MCP_TUNNEL",
            ConnectionWorkerError::TokenRuntime(_) | ConnectionWorkerError::Token(_) => "MCP_TOKEN",
            ConnectionWorkerError::Settings(_) => "MCP_SETTINGS",
            ConnectionWorkerError::ThreadSpawn(_) | ConnectionWorkerError::ThreadPanicked => {
                "MCP_CONNECTION_WORKER"
            }
        };
        self.fail(code, error.to_string());
    }

    fn fail(&self, code: &str, message: impl AsRef<str>) {
        self.app
            .set_mcp_connection_status(format!("오류 [{code}] {}", message.as_ref()).into());
        self.set_busy(false);
    }
}

const fn token_state_label(state: McpTokenState) -> &'static str {
    match state {
        McpTokenState::Active => "활성",
        McpTokenState::Revoked => "폐기됨",
        McpTokenState::Rotated => "회전됨",
    }
}
