//! Reproducible populated-workbench snapshot for visual review.

use std::cell::Cell;
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc;

use forge_ui::{
    ActivityRow, AgentRow, AppWindow, DagEdgeRow, DagNodeRow, GoalRow, HarnessRow,
    WorkNarrativeRow, WorkspaceRow,
};
use slint::{ComponentHandle, ModelRc, PhysicalSize, RenderingState, Timer, VecModel};

fn main() -> Result<(), Box<dyn Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "snapshot output is required")
        })?;
    let page = std::env::args()
        .nth(2)
        .map(|value| value.parse::<i32>())
        .transpose()?
        .unwrap_or(0)
        .clamp(0, 4);
    let app = AppWindow::new()?;
    seed_workbench(&app);
    app.set_active_page(page);
    app.set_workspace_view_open(page != 0);
    app.window().set_size(PhysicalSize::new(1_480, 920));
    let (sender, receiver) = mpsc::sync_channel(1);
    let weak = app.as_weak();
    let rendered_frames = Rc::new(Cell::new(0_u8));
    let frame_counter = Rc::clone(&rendered_frames);
    app.window()
        .set_rendering_notifier(move |state, _graphics| {
            if !matches!(state, RenderingState::AfterRendering) {
                return;
            }
            match frame_counter.replace(frame_counter.get().saturating_add(1)) {
                0 | 1 => {
                    if let Some(app) = weak.upgrade() {
                        // The first rendered Workspace change intentionally clears
                        // descendant selections. Re-seed after that safety turn,
                        // then request the populated review frame.
                        seed_workbench(&app);
                        app.window().request_redraw();
                    }
                }
                2 => {
                    let selected = weak.clone();
                    let sender = sender.clone();
                    let output = output.clone();
                    Timer::single_shot(std::time::Duration::ZERO, move || {
                        let result = selected
                            .upgrade()
                            .ok_or_else(|| io::Error::other("selected snapshot window was dropped"))
                            .and_then(|app| {
                                app.window()
                                    .take_snapshot()
                                    .map_err(|error| io::Error::other(error.to_string()))
                            })
                            .and_then(|snapshot| write_ppm(&output, &snapshot));
                        let _ignored = sender.send(result);
                        let _ignored = slint::quit_event_loop();
                    });
                }
                _ => {}
            }
        })?;
    app.show()?;
    slint::run_event_loop()?;
    receiver.recv()??;
    Ok(())
}

fn seed_workbench(app: &AppWindow) {
    seed_workspace(app);
    seed_goals_and_dag(app);
    seed_agents(app);
    seed_harness(app);
}

fn seed_workspace(app: &AppWindow) {
    app.set_workspace_rows(ModelRc::new(VecModel::from(vec![
        WorkspaceRow {
            label: "heterarchy-forge".into(),
            kind: "Rust Workspace".into(),
            relative_display: "~/Projects/heterarchy-forge".into(),
            signals: "연결 준비됨 · Harness 적용됨".into(),
            readiness_status: "연결 준비됨".into(),
            harness_status: "rust_dev_harness 감지".into(),
        },
        WorkspaceRow {
            label: "collab-protocol".into(),
            kind: "Rust Workspace".into(),
            relative_display: "~/Projects/collab-protocol".into(),
            signals: "연결 준비됨".into(),
            readiness_status: "연결 준비됨".into(),
            harness_status: "Harness 미감지".into(),
        },
        WorkspaceRow {
            label: "infra-core".into(),
            kind: "Python Workspace".into(),
            relative_display: "~/Projects/infra-core".into(),
            signals: "대기".into(),
            readiness_status: "연결 준비됨".into(),
            harness_status: "python_dev_harness 감지".into(),
        },
    ])));
    app.set_selected_workspace_index(0);
    app.set_selected_workspace_id("0198-workspace".into());
    app.set_selected_workspace_revision("16".into());
    app.set_selected_workspace_root("~/Projects/heterarchy-forge".into());
    app.set_runtime_status("RUNNING".into());
    app.set_runtime_detail("백그라운드 런타임 정상".into());
    app.set_runtime_generation(12);
    app.set_applied_harness_name("Rust + Python Harness".into());
    app.set_applied_harness_version("1.5.3".into());
    app.set_applied_harness_source("registered bundle · local".into());
    app.set_applied_harness_hash("sha256:7f3a…91cd".into());
    app.set_applied_harness_verification("SOURCE VERIFIED".into());
    app.set_applied_harness_verified_at("5분 전".into());
    app.set_uptime_seconds(742);

    app.set_activity_live_rows(ModelRc::new(VecModel::from(vec![
        ActivityRow {
            id: "activity-1".into(),
            display_label: "연결 도메인".into(),
            state: "RUNNING".into(),
            liveness: "LIVE".into(),
            revision: "7".into(),
            created_at: "14:30".into(),
            updated_at: "14:44".into(),
        },
        ActivityRow {
            id: "activity-2".into(),
            display_label: "한글 UI".into(),
            state: "VERIFYING".into(),
            liveness: "LIVE".into(),
            revision: "4".into(),
            created_at: "14:35".into(),
            updated_at: "14:43".into(),
        },
    ])));
}

fn seed_goals_and_dag(app: &AppWindow) {
    app.set_goal_rows(ModelRc::new(VecModel::from(vec![
        GoalRow {
            id: "0198-goal".into(),
            title: "MCP 연결과 안전한 재계획".into(),
            objective: "Chat Agent가 현재 Goal과 DAG를 보고 안전하게 이어서 작업한다".into(),
            state: "ACTIVE".into(),
            revision: "3".into(),
            success_criterion: "정확한 head에서 한 번의 successor revision만 게시".into(),
            check_summary: "필수 검증 3개 중 2개 통과".into(),
            evidence_summary: "연결된 근거 5개".into(),
            blocker: "".into(),
            terminal: false,
            can_pause: true,
            can_resume: false,
            can_cancel: true,
            can_complete: false,
        },
        GoalRow {
            id: "goal-harness".into(),
            title: "Harness 시스템 고도화".into(),
            objective: "검증 가능한 Harness lifecycle을 완성한다".into(),
            state: "COMPLETED".into(),
            revision: "8".into(),
            success_criterion: "모든 verifier가 통과한다".into(),
            check_summary: "검증 완료".into(),
            evidence_summary: "근거 8개".into(),
            blocker: "".into(),
            terminal: true,
            can_pause: false,
            can_resume: false,
            can_cancel: false,
            can_complete: false,
        },
        GoalRow {
            id: "goal-ui".into(),
            title: "프로젝트 템플릿 개선".into(),
            objective: "Workspace 템플릿 경험을 정리한다".into(),
            state: "DRAFT".into(),
            revision: "1".into(),
            success_criterion: "템플릿 계약 검증".into(),
            check_summary: "대기".into(),
            evidence_summary: "".into(),
            blocker: "".into(),
            terminal: false,
            can_pause: false,
            can_resume: false,
            can_cancel: true,
            can_complete: false,
        },
    ])));
    app.set_selected_goal_id("0198-goal".into());
    app.set_selected_goal_revision("3".into());
    app.set_selected_goal_state("ACTIVE".into());
    app.set_selected_goal_objective(
        "Chat Agent가 현재 Goal과 DAG를 보고 안전하게 이어서 작업한다".into(),
    );
    app.set_selected_goal_success_criterion(
        "정확한 head에서 한 번의 successor revision만 게시".into(),
    );
    app.set_selected_goal_check_summary("필수 검증 3개 중 2개 통과".into());
    app.set_selected_goal_evidence_summary("연결된 근거 5개".into());
    app.set_selected_goal_can_pause(true);
    app.set_selected_goal_can_cancel(true);
    app.set_dag_revision("7".into());
    app.set_dag_head_revision("4".into());
    app.set_dag_status("정확한 DAG v7 · 노드 3 · 연결 2 · 읽기 전용".into());
    app.set_dag_column_count(3);
    app.set_dag_lane_count(1);
    app.set_dag_node_rows(ModelRc::new(VecModel::from(vec![
        node("node-a", "연결 계약 확인", "COMPLETED", "완료", 0, true),
        node("node-b", "재계획 권한 통합", "ACTIVE", "진행 중", 1, false),
        node("node-c", "전체 검증과 기록", "PENDING", "대기", 2, false),
    ])));
    app.set_dag_edge_rows(ModelRc::new(VecModel::from(vec![
        edge(
            "node-a",
            "node-b",
            "연결 계약 확인",
            "재계획 권한 통합",
            0,
            1,
            true,
        ),
        edge(
            "node-b",
            "node-c",
            "재계획 권한 통합",
            "전체 검증과 기록",
            1,
            2,
            false,
        ),
    ])));
}

fn seed_agents(app: &AppWindow) {
    app.set_agent_rows(ModelRc::new(VecModel::from(vec![
        AgentRow {
            id: "0198-agent".into(),
            display_name: "Orca Architect".into(),
            role: "아키텍트".into(),
            state: "ATTACHED".into(),
            liveness: "ACTIVE".into(),
            current_goal: "MCP 연결과 안전한 재계획".into(),
            current_node: "재계획 권한 통합".into(),
            public_summary: "도메인 모델과 연결 규약을 검토 중".into(),
            evidence: "근거 2개".into(),
            last_observed: "방금".into(),
        },
        AgentRow {
            id: "agent-luna".into(),
            display_name: "Luna Coder".into(),
            role: "구현".into(),
            state: "ATTACHED".into(),
            liveness: "ACTIVE".into(),
            current_goal: "MCP 연결과 안전한 재계획".into(),
            current_node: "재계획 권한 통합".into(),
            public_summary: "UI 구성 요소를 구현 중".into(),
            evidence: "근거 1개".into(),
            last_observed: "1분 전".into(),
        },
        AgentRow {
            id: "agent-terra".into(),
            display_name: "Terra Reviewer".into(),
            role: "검증".into(),
            state: "ATTACHED".into(),
            liveness: "WAITING".into(),
            current_goal: "MCP 연결과 안전한 재계획".into(),
            current_node: "전체 검증과 기록".into(),
            public_summary: "선행 작업 완료를 기다리는 중".into(),
            evidence: "".into(),
            last_observed: "2분 전".into(),
        },
    ])));
    app.set_selected_agent_id("0198-agent".into());
    app.set_selected_agent_name("Orca Architect".into());
    app.set_selected_agent_role("아키텍트".into());
    app.set_selected_agent_state("ATTACHED".into());
    app.set_selected_agent_liveness("ACTIVE".into());
    app.set_selected_agent_current_goal("MCP 연결과 안전한 재계획".into());
    app.set_selected_agent_current_node("재계획 권한 통합".into());
    app.set_selected_agent_public_summary("도메인 모델과 연결 규약을 검토 중".into());
    app.set_selected_agent_evidence("근거 2개".into());
    app.set_selected_agent_last_observed("방금".into());
    app.set_agent_dag_grant_availability("활성".into());
    app.set_agent_dag_grant_status(
        "현재 DAG head에만 유효한 1회 권한 · 248초 남음 · MCP에서 자동 발견".into(),
    );
    app.set_agent_dag_grant_active(true);

    app.set_work_narrative_rows(ModelRc::new(VecModel::from(vec![
        WorkNarrativeRow {
            phase: "계획".into(),
            action: "아키텍처 검토 시작".into(),
            rationale: "MCP 연결 흐름 정리".into(),
            evidence: "설계 노트 1건".into(),
            state: "COMPLETED".into(),
        },
        WorkNarrativeRow {
            phase: "실행".into(),
            action: "도메인 타입 초안 작성".into(),
            rationale: "연결/해제 상태 분리".into(),
            evidence: "증거 2건".into(),
            state: "EXECUTING".into(),
        },
        WorkNarrativeRow {
            phase: "검증".into(),
            action: "DAG 조건 점검".into(),
            rationale: "통합 전 의존성 확인".into(),
            evidence: "체크 1건".into(),
            state: "WAITING".into(),
        },
    ])));
}

fn seed_harness(app: &AppWindow) {
    app.set_harness_rows(ModelRc::new(VecModel::from(vec![
        harness("rust", "14", "Rust Harness", "Systems · v1.4.2", "READY"),
        harness(
            "python",
            "13",
            "Python Harness",
            "Backend · v1.3.0",
            "READY",
        ),
        harness(
            "typescript",
            "12",
            "TS Harness",
            "Frontend · v1.2.1",
            "READY",
        ),
        harness(
            "hybrid",
            "15",
            "Rust + Python Harness",
            "Fullstack · v1.5.3",
            "CURRENT",
        ),
        harness(
            "custom",
            "9",
            "Custom Composition",
            "Custom · v0.9.2",
            "DRAFT",
        ),
    ])));
    app.set_harness_skill_rows(ModelRc::new(VecModel::from(vec![
        harness(
            "skill-fastapi",
            "4",
            "FastAPI",
            "Python backend",
            "SELECTED",
        ),
        harness(
            "skill-pydantic",
            "5",
            "Pydantic",
            "Strict schema",
            "SELECTED",
        ),
        harness(
            "skill-di",
            "3",
            "Dependency Injection",
            "Composition",
            "READY",
        ),
        harness("skill-mcp", "6", "MCP", "Transport", "SELECTED"),
    ])));
    app.set_harness_verifier_rows(ModelRc::new(VecModel::from(vec![
        harness("rules", "1", "rules", "정책 및 규칙 검증", "READY"),
        harness("format", "1", "format", "포맷 및 스타일 검증", "READY"),
        harness("check", "1", "check", "정적 검사", "READY"),
        harness("tests", "1", "tests", "자동화 테스트", "READY"),
        harness(
            "custom-verifier",
            "1",
            "custom verifier",
            "사용자 정의 검증",
            "READY",
        ),
    ])));
    app.set_harness_composition_base_name("Rust Harness".into());
    app.set_harness_composition_base_index(0);
    app.set_harness_composition_selected_skill_count(3);
    app.set_harness_composition_status("Base + 선택 Skill로 새 Bundle 구성 가능".into());
    app.set_harness_library_status("5개 등록".into());
    app.set_harness_skill_status("4개 등록".into());
    app.set_harness_verifier_status("5 / 5 READY".into());
}

fn harness(id: &str, revision: &str, label: &str, value: &str, state: &str) -> HarnessRow {
    HarnessRow {
        machine_id: id.into(),
        revision: revision.into(),
        label: label.into(),
        value: value.into(),
        state: state.into(),
    }
}

fn node(
    id: &str,
    label: &str,
    state: &str,
    state_label: &str,
    column: i32,
    terminal: bool,
) -> DagNodeRow {
    DagNodeRow {
        id: id.into(),
        label: label.into(),
        state: state.into(),
        state_label: state_label.into(),
        objective: format!("{label}의 관측 가능한 결과를 만든다").into(),
        acceptance: "근거와 검증 결과가 연결됨".into(),
        depends_on: if column == 0 { "" } else { "이전 단계" }.into(),
        waiting_on: "".into(),
        evidence: if terminal {
            "근거 2개"
        } else {
            "근거 없음"
        }
        .into(),
        revision: "1".into(),
        current: state == "ACTIVE",
        terminal,
        column,
        lane: 0,
        old_column: i16::try_from(column).map_or(0.0, f32::from),
        old_lane: 0.0,
        transition_kind: "STABLE".into(),
        transition_epoch: 1,
        transition_progress: 1.0,
        transition_delay_ms: 0,
        transition_entering: false,
        transition_exiting: false,
    }
}

fn edge(
    upstream_id: &str,
    downstream_id: &str,
    upstream_label: &str,
    downstream_label: &str,
    from_column: i32,
    to_column: i32,
    current_path: bool,
) -> DagEdgeRow {
    DagEdgeRow {
        upstream_id: upstream_id.into(),
        downstream_id: downstream_id.into(),
        upstream_label: upstream_label.into(),
        downstream_label: downstream_label.into(),
        from_column,
        from_lane: 0,
        to_column,
        to_lane: 0,
        blocked: false,
        current_path,
        transition_kind: "STABLE".into(),
        transition_epoch: 1,
        transition_progress: 1.0,
        transition_entering: false,
        transition_exiting: false,
    }
}

fn write_ppm(
    path: &Path,
    snapshot: &slint::SharedPixelBuffer<slint::Rgba8Pixel>,
) -> io::Result<()> {
    let mut file = File::create(path)?;
    write!(
        file,
        "P6\n{} {}\n255\n",
        snapshot.width(),
        snapshot.height()
    )?;
    let rgba = snapshot.as_bytes();
    let mut rgb = Vec::with_capacity(rgba.len() / 4 * 3);
    for pixel in rgba.chunks_exact(4) {
        rgb.extend_from_slice(&pixel[..3]);
    }
    file.write_all(&rgb)
}
