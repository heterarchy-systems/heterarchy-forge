//! Read-only desktop projection for the durable Goal DAG.
//!
//! The DAG is written by the trusted local control plane (or a future
//! authenticated producer), never by this module or by Slint.  This module
//! only requests the current revision for the selected Goal and reduces the
//! validated domain snapshots into bounded operator-facing rows.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

use crate::{ActivityWorkspaceScope, resolved_activity_scope};
use forge_control::{ControlClientError, ForgeControlClient, PendingControl};
use forge_domain::{
    DagAcceptanceCriterion, DagLineageKind, DagNodeId, DagNodeLineage, DagNodeProjection,
    DagNodeStatus, DagReadinessError, DagRevision, GoalId, RegisteredDagNode,
};
use forge_persistence::StoredDagRevision;
use forge_ui::{AppWindow, DagEdgeRow, DagNodeRow};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use thiserror::Error;

const DAG_OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);
const DAG_CONTROL_PUMP_INTERVAL: Duration = Duration::from_millis(100);
const DAG_MOTION_PUMP_INTERVAL: Duration = Duration::from_millis(16);
const DAG_FADE_DURATION: Duration = Duration::from_millis(180);
const DAG_UPDATE_DURATION: Duration = Duration::from_millis(160);
const DAG_MOVE_DURATION: Duration = Duration::from_millis(220);
const DAG_SPLIT_DURATION: Duration = Duration::from_millis(240);
const DAG_REDUCED_MOTION_DURATION: Duration = Duration::from_millis(80);
const DAG_LARGE_GRAPH_DURATION: Duration = Duration::from_millis(140);
const DAG_SPLIT_STAGGER_STEP_MS: u64 = 20;
const DAG_SPLIT_STAGGER_MAX_MS: u64 = 60;
const DAG_LARGE_NODE_CHANGE_COUNT: usize = 24;
const DAG_LARGE_EDGE_CHANGE_COUNT: usize = 64;
const DAG_MAX_NODE_ROWS: usize = 128;
const DAG_MAX_EDGE_ROWS: usize = 512;

fn layout_coordinate(value: i32) -> f32 {
    i16::try_from(value).map_or(0.0, f32::from)
}

fn transition_duration_millis(duration: Duration) -> f32 {
    u16::try_from(duration.as_millis().max(1)).map_or(f32::from(u16::MAX), f32::from)
}

fn transition_delay_millis(value: i32) -> f32 {
    u16::try_from(value.max(0)).map_or(0.0, f32::from)
}

#[allow(clippy::cast_possible_truncation)]
fn rounded_layout_coordinate(value: f32) -> i32 {
    debug_assert!(value.is_finite());
    value.round() as i32
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DagTransitionKind {
    Stable,
    Enter,
    Exit,
    Update,
    Move,
    Replace,
    Split,
    Merge,
    Crossfade,
}

impl DagTransitionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "STABLE",
            Self::Enter => "ENTER",
            Self::Exit => "EXIT",
            Self::Update => "UPDATE",
            Self::Move => "MOVE",
            Self::Replace => "REPLACE",
            Self::Split => "SPLIT",
            Self::Merge => "MERGE",
            Self::Crossfade => "CROSSFADE",
        }
    }
}

#[derive(Clone)]
struct DagTransitionPlan {
    initial: DagUiProjection,
    target: DagUiProjection,
    started_at: Instant,
    duration: Duration,
    epoch: i32,
    reduced_motion: bool,
}

/// Intents accepted by the desktop DAG controller.
///
/// Workspace and Goal selection are correlation data only.  They never grant
/// a capability to mutate durable state.  The only control request emitted by
/// this controller is the read-only current-DAG lookup.
pub(crate) enum UiDagIntent {
    WorkspaceSelected(Option<ActivityWorkspaceScope>),
    GoalSelected(Option<GoalId>),
    SelectNode(DagNodeId),
}

struct PendingDagUi {
    scope: ActivityWorkspaceScope,
    goal_id: GoalId,
    pending: PendingControl<Option<StoredDagRevision>>,
}

#[derive(Clone)]
struct DagUiProjection {
    nodes: Vec<DagNodeRow>,
    edges: Vec<DagEdgeRow>,
    column_count: i32,
    lane_count: i32,
}

impl DagUiProjection {
    fn normalized(mut self) -> Self {
        for node in &mut self.nodes {
            node.old_column = layout_coordinate(node.column);
            node.old_lane = layout_coordinate(node.lane);
            node.transition_kind = DagTransitionKind::Stable.as_str().into();
            node.transition_epoch = 0;
            node.transition_progress = 1.0;
            node.transition_delay_ms = 0;
            node.transition_entering = false;
            node.transition_exiting = false;
        }
        for edge in &mut self.edges {
            edge.transition_kind = DagTransitionKind::Stable.as_str().into();
            edge.transition_epoch = 0;
            edge.transition_progress = 1.0;
            edge.transition_entering = false;
            edge.transition_exiting = false;
        }
        self
    }
}

fn materialize_transition(transition: &DagTransitionPlan, now: Instant) -> DagUiProjection {
    let mut frame = transition.initial.clone();
    let progress = transition_progress(transition, now);
    set_projection_progress(&mut frame, transition, progress);
    frame
}

fn transition_progress(transition: &DagTransitionPlan, now: Instant) -> f32 {
    if transition.duration.is_zero() {
        return 1.0;
    }
    let elapsed = now.saturating_duration_since(transition.started_at);
    (elapsed.as_secs_f32() / transition.duration.as_secs_f32()).clamp(0.0, 1.0)
}

fn set_projection_progress(
    projection: &mut DagUiProjection,
    transition: &DagTransitionPlan,
    progress: f32,
) {
    let duration_ms = transition_duration_millis(transition.duration);
    for node in &mut projection.nodes {
        let delay_fraction = if transition.reduced_motion {
            0.0
        } else {
            transition_delay_millis(node.transition_delay_ms) / duration_ms
        };
        node.transition_progress = if progress <= delay_fraction {
            0.0
        } else {
            ((progress - delay_fraction) / (1.0 - delay_fraction).max(f32::EPSILON)).clamp(0.0, 1.0)
        };
        node.transition_epoch = transition.epoch;
    }
    for edge in &mut projection.edges {
        edge.transition_progress = progress;
        edge.transition_epoch = transition.epoch;
    }
}

#[allow(clippy::too_many_arguments)]
fn build_transition_plan(
    previous: &StoredDagRevision,
    next: &StoredDagRevision,
    source: &DagUiProjection,
    target: DagUiProjection,
    epoch: i32,
    reduced_motion: bool,
) -> Option<DagTransitionPlan> {
    let target = target.normalized();
    if projection_semantically_equal(source, &target) {
        return None;
    }

    let direct_successor = next.revision().parent() == Some(previous.revision().number());
    let source_by_id = source
        .nodes
        .iter()
        .map(|node| (node.id.to_string(), node))
        .collect::<BTreeMap<_, _>>();
    let target_ids = target
        .nodes
        .iter()
        .map(|node| node.id.to_string())
        .collect::<BTreeSet<_>>();
    let changed_nodes = target
        .nodes
        .iter()
        .filter(|node| {
            source_by_id
                .get(node.id.as_str())
                .is_none_or(|source| !node_semantically_equal(source, node))
        })
        .count()
        + source
            .nodes
            .iter()
            .filter(|node| !target_ids.contains(node.id.as_str()))
            .count();
    let changed_edges = changed_edge_count(source, &target);
    let large = changed_nodes > DAG_LARGE_NODE_CHANGE_COUNT
        || changed_edges > DAG_LARGE_EDGE_CHANGE_COUNT
        || !direct_successor;

    let mut initial = target.clone();
    let duration = if reduced_motion {
        DAG_REDUCED_MOTION_DURATION
    } else if large {
        DAG_LARGE_GRAPH_DURATION
    } else if next
        .lineage()
        .iter()
        .any(|lineage| lineage.kind() == DagLineageKind::Split)
    {
        DAG_SPLIT_DURATION
    } else if target.nodes.iter().any(|node| {
        source_by_id
            .get(node.id.as_str())
            .is_some_and(|source| source.column != node.column || source.lane != node.lane)
    }) {
        DAG_MOVE_DURATION
    } else if changed_nodes > 0 {
        DAG_FADE_DURATION
    } else {
        DAG_UPDATE_DURATION
    };

    if reduced_motion || large {
        for node in &mut initial.nodes {
            node.transition_kind = DagTransitionKind::Crossfade.as_str().into();
            node.transition_epoch = epoch;
            node.transition_progress = 0.0;
            node.transition_entering = true;
            node.transition_exiting = false;
            node.old_column = layout_coordinate(node.column);
            node.old_lane = layout_coordinate(node.lane);
        }
        for edge in &mut initial.edges {
            edge.transition_kind = DagTransitionKind::Crossfade.as_str().into();
            edge.transition_epoch = epoch;
            edge.transition_progress = 0.0;
            edge.transition_entering = true;
            edge.transition_exiting = false;
        }
    } else {
        apply_node_transition_rows(&mut initial, source, next.lineage(), epoch);
        apply_edge_transition_rows(&mut initial, source, epoch);
    }

    Some(DagTransitionPlan {
        initial,
        target,
        started_at: Instant::now(),
        duration,
        epoch,
        reduced_motion,
    })
}

fn apply_node_transition_rows(
    initial: &mut DagUiProjection,
    source: &DagUiProjection,
    lineage: &[DagNodeLineage],
    epoch: i32,
) {
    let source_by_id = source
        .nodes
        .iter()
        .map(|node| (node.id.to_string(), node))
        .collect::<BTreeMap<_, _>>();
    let target_ids = initial
        .nodes
        .iter()
        .map(|node| node.id.to_string())
        .collect::<BTreeSet<_>>();
    let lineage_by_successor = lineage_by_successor(lineage);
    let split_ordinals = split_successor_ordinals(lineage);

    for node in &mut initial.nodes {
        node.transition_epoch = epoch;
        node.transition_progress = 0.0;
        if let Some(source_node) = source_by_id.get(node.id.as_str()) {
            let (old_column, old_lane) = visual_node_position(source_node);
            node.old_column = old_column;
            node.old_lane = old_lane;
            node.transition_kind =
                if source_node.column != node.column || source_node.lane != node.lane {
                    DagTransitionKind::Move.as_str().into()
                } else if !node_semantically_equal(source_node, node) {
                    DagTransitionKind::Update.as_str().into()
                } else {
                    DagTransitionKind::Stable.as_str().into()
                };
            continue;
        }

        node.transition_entering = true;
        node.transition_kind = DagTransitionKind::Enter.as_str().into();
        node.old_column = layout_coordinate(node.column);
        node.old_lane = layout_coordinate(node.lane);
        if let Some((prior_id, kind)) = lineage_by_successor.get(node.id.as_str()) {
            if let Some(prior) = source_by_id.get(prior_id) {
                let (old_column, old_lane) = visual_node_position(prior);
                node.old_column = old_column;
                node.old_lane = old_lane;
            }
            node.transition_kind = lineage_transition_kind(*kind).as_str().into();
            if *kind == DagLineageKind::Split {
                let ordinal = split_ordinals.get(node.id.as_str()).copied().unwrap_or(0);
                node.transition_delay_ms = i32::try_from(
                    (ordinal as u64 * DAG_SPLIT_STAGGER_STEP_MS).min(DAG_SPLIT_STAGGER_MAX_MS),
                )
                .unwrap_or(i32::MAX);
            }
        }
    }

    if initial.nodes.len() >= DAG_MAX_NODE_ROWS {
        return;
    }
    for source_node in &source.nodes {
        if target_ids.contains(source_node.id.as_str()) {
            continue;
        }
        if initial.nodes.len() >= DAG_MAX_NODE_ROWS {
            break;
        }
        let mut exiting = source_node.clone();
        let (column, lane) = visual_node_position(source_node);
        exiting.old_column = column;
        exiting.old_lane = lane;
        exiting.column = rounded_layout_coordinate(column);
        exiting.lane = rounded_layout_coordinate(lane);
        exiting.transition_epoch = epoch;
        exiting.transition_progress = 0.0;
        exiting.transition_entering = false;
        exiting.transition_exiting = true;
        exiting.transition_kind = prior_lineage_kind(lineage, source_node.id.as_str())
            .map_or(DagTransitionKind::Exit, lineage_transition_kind)
            .as_str()
            .into();
        initial.nodes.push(exiting);
    }
}

fn apply_edge_transition_rows(initial: &mut DagUiProjection, source: &DagUiProjection, epoch: i32) {
    let source_keys = source.edges.iter().map(edge_key).collect::<BTreeSet<_>>();
    let target_keys = initial.edges.iter().map(edge_key).collect::<BTreeSet<_>>();
    for edge in &mut initial.edges {
        edge.transition_epoch = epoch;
        edge.transition_progress = 0.0;
        if source_keys.contains(&edge_key(edge)) {
            edge.transition_kind = DagTransitionKind::Stable.as_str().into();
        } else {
            edge.transition_kind = DagTransitionKind::Enter.as_str().into();
            edge.transition_entering = true;
        }
    }
    for source_edge in &source.edges {
        if target_keys.contains(&edge_key(source_edge)) || initial.edges.len() >= DAG_MAX_EDGE_ROWS
        {
            continue;
        }
        let mut exiting = source_edge.clone();
        exiting.transition_kind = DagTransitionKind::Exit.as_str().into();
        exiting.transition_epoch = epoch;
        exiting.transition_progress = 0.0;
        exiting.transition_entering = false;
        exiting.transition_exiting = true;
        initial.edges.push(exiting);
    }
}

fn projection_semantically_equal(left: &DagUiProjection, right: &DagUiProjection) -> bool {
    left.nodes.len() == right.nodes.len()
        && left.edges.len() == right.edges.len()
        && left
            .nodes
            .iter()
            .zip(&right.nodes)
            .all(|(left, right)| node_semantically_equal(left, right))
        && left.edges.iter().zip(&right.edges).all(|(left, right)| {
            edge_key(left) == edge_key(right)
                && left.blocked == right.blocked
                && left.current_path == right.current_path
                && left.from_column == right.from_column
                && left.from_lane == right.from_lane
                && left.to_column == right.to_column
                && left.to_lane == right.to_lane
        })
}

fn node_semantically_equal(left: &DagNodeRow, right: &DagNodeRow) -> bool {
    left.id == right.id
        && left.label == right.label
        && left.state == right.state
        && left.objective == right.objective
        && left.acceptance == right.acceptance
        && left.depends_on == right.depends_on
        && left.waiting_on == right.waiting_on
        && left.evidence == right.evidence
        && left.revision == right.revision
        && left.current == right.current
        && left.terminal == right.terminal
        && left.column == right.column
        && left.lane == right.lane
}

fn changed_edge_count(source: &DagUiProjection, target: &DagUiProjection) -> usize {
    let source_keys = source.edges.iter().map(edge_key).collect::<BTreeSet<_>>();
    let target_keys = target.edges.iter().map(edge_key).collect::<BTreeSet<_>>();
    source_keys.symmetric_difference(&target_keys).count()
}

fn edge_key(edge: &DagEdgeRow) -> (String, String) {
    (edge.upstream_id.to_string(), edge.downstream_id.to_string())
}

fn visual_node_position(node: &DagNodeRow) -> (f32, f32) {
    let progress = node.transition_progress.clamp(0.0, 1.0);
    (
        node.old_column + (layout_coordinate(node.column) - node.old_column) * progress,
        node.old_lane + (layout_coordinate(node.lane) - node.old_lane) * progress,
    )
}

fn lineage_by_successor(lineage: &[DagNodeLineage]) -> BTreeMap<String, (String, DagLineageKind)> {
    lineage
        .iter()
        .map(|item| {
            (
                item.successor_node_id().to_string(),
                (item.prior_node_id().to_string(), item.kind()),
            )
        })
        .collect()
}

fn split_successor_ordinals(lineage: &[DagNodeLineage]) -> BTreeMap<String, usize> {
    let mut by_prior = BTreeMap::<String, Vec<String>>::new();
    for item in lineage
        .iter()
        .filter(|item| item.kind() == DagLineageKind::Split)
    {
        by_prior
            .entry(item.prior_node_id().to_string())
            .or_default()
            .push(item.successor_node_id().to_string());
    }
    let mut result = BTreeMap::new();
    for successors in by_prior.values_mut() {
        successors.sort();
        for (ordinal, successor) in successors.iter().enumerate() {
            result.insert(successor.clone(), ordinal);
        }
    }
    result
}

fn prior_lineage_kind(lineage: &[DagNodeLineage], prior_id: &str) -> Option<DagLineageKind> {
    lineage
        .iter()
        .find(|item| item.prior_node_id().to_string() == prior_id)
        .map(|item| item.kind())
}

const fn lineage_transition_kind(kind: DagLineageKind) -> DagTransitionKind {
    match kind {
        DagLineageKind::Split => DagTransitionKind::Split,
        DagLineageKind::Replace => DagTransitionKind::Replace,
        DagLineageKind::Merge => DagTransitionKind::Merge,
    }
}

#[derive(Debug, Error)]
enum DagUiProjectionError {
    #[error(transparent)]
    Readiness(#[from] DagReadinessError),
    #[error("validated DAG edge references a node without a projected coordinate")]
    MissingCoordinate,
}

pub(crate) struct DagUiController {
    app: AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiDagIntent>,
    busy: Rc<Cell<bool>>,
    scope: Option<ActivityWorkspaceScope>,
    selected_goal_id: Option<GoalId>,
    current: Option<StoredDagRevision>,
    current_projection: Option<DagUiProjection>,
    transition: Option<DagTransitionPlan>,
    transition_epoch: i32,
    pending: Option<PendingDagUi>,
    next_observation: Instant,
}

impl DagUiController {
    pub(crate) fn new(
        app: AppWindow,
        client: ForgeControlClient,
        intents: Receiver<UiDagIntent>,
        busy: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            app,
            client,
            intents,
            busy,
            scope: None,
            selected_goal_id: None,
            current: None,
            current_projection: None,
            transition: None,
            transition_epoch: 0,
            pending: None,
            next_observation: Instant::now(),
        }
    }

    pub(crate) fn start(&self) {
        self.clear("Select a committed Workspace and Goal to view the DAG.");
    }

    pub(crate) fn tick(&mut self) {
        self.poll_pending();
        self.poll_intents();
        self.poll_observation();
    }

    fn transition_active(&self) -> bool {
        self.transition.is_some()
    }

    fn poll_intents(&mut self) {
        // Selection changes are cheap and read-only.  Drain all available
        // intents so a rapid Goal click cannot leave stale refresh requests in
        // the bounded queue behind the latest selection.
        while let Ok(intent) = self.intents.try_recv() {
            self.handle_intent(intent);
        }
    }

    fn handle_intent(&mut self, intent: UiDagIntent) {
        match intent {
            UiDagIntent::WorkspaceSelected(scope) => {
                self.pending.take();
                self.current.take();
                self.current_projection.take();
                self.transition.take();
                self.scope = scope;
                self.selected_goal_id = None;
                self.set_busy(false);
                self.clear(if self.scope.is_some() {
                    "Select a Goal to view its Chat-authored DAG."
                } else {
                    "Select a committed Workspace and Goal to view the DAG."
                });
            }
            UiDagIntent::GoalSelected(goal_id) => {
                self.pending.take();
                self.current.take();
                self.current_projection.take();
                self.transition.take();
                self.selected_goal_id = goal_id;
                self.set_busy(false);
                self.begin_current();
            }
            UiDagIntent::SelectNode(node_id) => self.select_node(node_id),
        }
    }

    fn begin_current(&mut self) {
        self.begin_current_observation(true);
    }

    fn poll_observation(&mut self) {
        if self.pending.is_none()
            && self.scope.is_some()
            && self.selected_goal_id.is_some()
            && Instant::now() >= self.next_observation
        {
            self.begin_current_observation(false);
        }
    }

    fn begin_current_observation(&mut self, clear_projection: bool) {
        let (Some(scope), Some(goal_id)) = (self.scope.clone(), self.selected_goal_id) else {
            self.current.take();
            self.current_projection.take();
            self.transition.take();
            self.clear(if self.scope.is_some() {
                "Select a Goal to view its Chat-authored DAG."
            } else {
                "Select a committed Workspace and Goal to view the DAG."
            });
            return;
        };
        let resolved = resolved_activity_scope(&scope);
        if clear_projection {
            self.clear_dag_projection();
            self.app.set_dag_revision("".into());
            self.app.set_dag_head_revision("".into());
        }
        self.next_observation = Instant::now() + DAG_OBSERVATION_INTERVAL;
        match self.client.submit_dag_get_current(resolved, goal_id) {
            Ok(pending) => {
                self.set_busy(true);
                if clear_projection {
                    self.app
                        .set_dag_status("현재 Goal 계획을 불러오는 중…".into());
                }
                self.pending = Some(PendingDagUi {
                    scope,
                    goal_id,
                    pending,
                });
            }
            Err(error) => self.fail_control(&error),
        }
    }

    // The exact-scope reply reducer stays exhaustive in one place so stale
    // Goal/head responses cannot bypass a sibling branch's correlation guard.
    #[allow(clippy::too_many_lines)]
    fn poll_pending(&mut self) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let ready = pending.pending.try_recv();
        let result = match ready {
            Ok(Some(result)) => result,
            Ok(None) => return,
            Err(error) => {
                self.pending.take();
                self.fail_control(&error);
                return;
            }
        };
        let pending = self.pending.take();
        let Some(pending) = pending else {
            self.fail("DAG_PROTOCOL", "DAG worker returned an untracked reply.");
            return;
        };

        // A response is applied only to the exact scope and Goal that
        // admitted it.  Scope changes drop the receiver above; these checks
        // protect against a response that races with a same-tick selection.
        if self.scope.as_ref() != Some(&pending.scope)
            || self.selected_goal_id != Some(pending.goal_id)
        {
            self.set_busy(false);
            return;
        }

        match result {
            Ok(Some(stored)) => {
                if stored.revision().goal_id() != pending.goal_id
                    || stored.head().goal_id() != pending.goal_id
                    || stored.revision().number() != stored.head().dag_revision()
                {
                    self.current.take();
                    self.fail(
                        "DAG_SCOPE_MISMATCH",
                        "DAG response crossed the selected Goal or current head.",
                    );
                    return;
                }
                if self.current.as_ref() == Some(&stored) {
                    self.set_busy(false);
                    self.next_observation = Instant::now() + DAG_OBSERVATION_INTERVAL;
                    return;
                }
                match project_stored_dag(&stored) {
                    Ok(projection) => {
                        let node_count = projection.nodes.len();
                        let edge_count = projection.edges.len();
                        let next_revision = stored.revision().number().get();
                        let reduced_motion = self.app.get_dag_reduced_motion();
                        let transition_epoch = self.next_transition_epoch();
                        let source_projection = self
                            .transition
                            .as_ref()
                            .map(|transition| materialize_transition(transition, Instant::now()))
                            .or_else(|| self.current_projection.clone());
                        let transition = self
                            .current
                            .as_ref()
                            .zip(source_projection.as_ref())
                            .and_then(|(previous, source)| {
                                build_transition_plan(
                                    previous,
                                    &stored,
                                    source,
                                    projection.clone(),
                                    transition_epoch,
                                    reduced_motion,
                                )
                            });
                        self.current = Some(stored);
                        if let Some(transition) = transition {
                            self.current_projection = Some(transition.target.clone());
                            self.set_dag_projection(transition.initial.clone());
                            self.transition = Some(transition);
                        } else {
                            self.transition = None;
                            let projection = projection.normalized();
                            self.current_projection = Some(projection.clone());
                            self.set_dag_projection(projection);
                        }
                        self.app.set_dag_revision(self.current.as_ref().map_or_else(
                            || "".into(),
                            |dag| dag.revision().number().get().to_string().into(),
                        ));
                        self.app
                            .set_dag_head_revision(self.current.as_ref().map_or_else(
                                || "".into(),
                                |dag| dag.head().revision().get().to_string().into(),
                            ));
                        self.app.set_dag_status(
                            format!(
                                "정확한 DAG v{} · 노드 {} · 연결 {} · 읽기 전용",
                                self.current
                                    .as_ref()
                                    .map_or(next_revision, |dag| dag.revision().number().get()),
                                node_count,
                                edge_count,
                            )
                            .into(),
                        );
                        self.next_observation = Instant::now() + DAG_OBSERVATION_INTERVAL;
                        self.set_busy(false);
                    }
                    Err(error) => {
                        self.current.take();
                        self.fail("DAG_PROJECTION_INVALID", error.to_string());
                    }
                }
            }
            Ok(None) => {
                self.current.take();
                self.current_projection.take();
                self.transition.take();
                self.clear_dag_projection();
                self.app.set_dag_revision("".into());
                self.app.set_dag_head_revision("".into());
                self.app.set_selected_dag_id("".into());
                self.app
                    .set_dag_status("이 Goal에 게시된 DAG가 없습니다.".into());
                self.next_observation = Instant::now() + DAG_OBSERVATION_INTERVAL;
                self.set_busy(false);
            }
            Err(error) => self.fail_control_error(&error),
        }
    }

    fn select_node(&self, node_id: DagNodeId) {
        let known = self
            .current
            .as_ref()
            .is_some_and(|dag| dag.nodes().iter().any(|node| node.id() == node_id));
        if !known {
            self.app.set_dag_status(
                "ERROR [DAG_NODE_UNKNOWN] Selected node is not in the current DAG.".into(),
            );
        }
    }

    fn next_transition_epoch(&mut self) -> i32 {
        self.transition_epoch = self.transition_epoch.wrapping_add(1);
        if self.transition_epoch <= 0 {
            self.transition_epoch = 1;
        }
        self.transition_epoch
    }

    fn advance_transition(&mut self) {
        let Some(transition) = self.transition.as_ref() else {
            return;
        };
        let progress = transition_progress(transition, Instant::now());
        if progress >= 1.0 {
            let target = transition.target.clone();
            self.set_dag_projection(target.clone());
            self.current_projection = Some(target.clone());
            self.transition = None;
            self.clear_removed_selection(&target);
            return;
        }

        let mut frame = transition.initial.clone();
        set_projection_progress(&mut frame, transition, progress);
        self.set_dag_projection(frame);
    }

    fn clear_removed_selection(&self, target: &DagUiProjection) {
        let selected = self.app.get_selected_dag_id();
        if selected.is_empty() {
            return;
        }
        let remains = target
            .nodes
            .iter()
            .any(|node| node.id.as_str() == selected.as_str());
        if !remains {
            self.app.set_selected_dag_id("".into());
        }
    }

    fn clear(&self, status: &str) {
        self.clear_dag_projection();
        self.app.set_dag_revision("".into());
        self.app.set_dag_head_revision("".into());
        self.app.set_dag_head_revision("".into());
        self.app.set_selected_dag_id("".into());
        self.app.set_dag_status(status.into());
        self.set_busy(false);
    }

    fn clear_dag_projection(&self) {
        self.app
            .set_dag_node_rows(ModelRc::new(VecModel::from(Vec::<DagNodeRow>::new())));
        self.app
            .set_dag_edge_rows(ModelRc::new(VecModel::from(Vec::<DagEdgeRow>::new())));
        self.app.set_dag_column_count(0);
        self.app.set_dag_lane_count(0);
    }

    fn set_dag_projection(&self, projection: DagUiProjection) {
        self.app
            .set_dag_node_rows(ModelRc::new(VecModel::from(projection.nodes)));
        self.app
            .set_dag_edge_rows(ModelRc::new(VecModel::from(projection.edges)));
        self.app.set_dag_column_count(projection.column_count);
        self.app.set_dag_lane_count(projection.lane_count);
    }

    fn set_busy(&self, value: bool) {
        self.busy.set(value);
    }

    fn fail_control(&self, error: &ControlClientError) {
        self.fail(error.code().as_str(), error.code().summary());
    }

    fn fail_control_error(&self, error: &forge_control::ControlError) {
        self.fail(error.code().as_str(), error.code().summary());
    }

    fn fail(&self, code: &str, message: impl Into<SharedString>) {
        self.clear_dag_projection();
        self.app.set_dag_revision("".into());
        self.app
            .set_dag_status(format!("ERROR [{code}] {}", message.into()).into());
        self.set_busy(false);
    }
}

/// Reduce a validated durable DAG into the exact operator-safe Slint model.
///
/// The domain owns topological ordering and readiness.  This function only
/// formats those results; it never infers lifecycle or dependency authority
/// from UI state.  The input bounds are set by `forge-domain` (128 nodes and
/// 512 edges), so the projection remains bounded even for malformed external
/// payloads rejected at the control/persistence boundary.
fn project_stored_dag(stored: &StoredDagRevision) -> Result<DagUiProjection, DagUiProjectionError> {
    let revision = stored.revision();
    let evidence_counts = stored
        .evidence()
        .iter()
        .map(|summary| (summary.node_id(), summary.count()))
        .collect::<BTreeMap<_, _>>();
    project_dag(revision, stored.nodes(), &evidence_counts)
}

fn project_dag(
    revision: &DagRevision,
    snapshots: &[RegisteredDagNode],
    evidence_counts: &BTreeMap<DagNodeId, u16>,
) -> Result<DagUiProjection, DagUiProjectionError> {
    let projections = revision.project(snapshots)?;
    let labels = projections
        .iter()
        .map(|projection| {
            (
                projection.node().id(),
                projection.node().definition().title().as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let (positions, column_count, lane_count) = project_dag_layout(revision, &projections);
    let nodes = project_dag_nodes(revision, &projections, &labels, &positions, evidence_counts)?;
    let edges = project_dag_edges(revision, &projections, &labels, &positions)?;

    Ok(DagUiProjection {
        nodes,
        edges,
        column_count,
        lane_count,
    })
}

fn project_dag_layout(
    revision: &DagRevision,
    projections: &[DagNodeProjection],
) -> (BTreeMap<DagNodeId, (i32, i32)>, i32, i32) {
    // Domain topological order is deterministic (ordinal, then identity).
    // Columns are longest upstream depth; lanes are stable encounter order
    // within a column. These are presentation coordinates, not DAG authority.
    let mut positions = BTreeMap::<DagNodeId, (i32, i32)>::new();
    let mut next_lane = BTreeMap::<i32, i32>::new();
    for projection in projections {
        let node_id = projection.node().id();
        let column = revision
            .edges()
            .iter()
            .filter(|edge| edge.downstream() == node_id)
            .filter_map(|edge| {
                positions
                    .get(&edge.upstream())
                    .map(|(column, _)| column + 1)
            })
            .max()
            .unwrap_or(0);
        let lane = *next_lane.get(&column).unwrap_or(&0);
        next_lane.insert(column, lane + 1);
        positions.insert(node_id, (column, lane));
    }
    let column_count = positions
        .values()
        .map(|(column, _)| column + 1)
        .max()
        .unwrap_or(0);
    let lane_count = next_lane.values().copied().max().unwrap_or(0);
    (positions, column_count, lane_count)
}

fn project_dag_nodes(
    revision: &DagRevision,
    projections: &[DagNodeProjection],
    labels: &BTreeMap<DagNodeId, &str>,
    positions: &BTreeMap<DagNodeId, (i32, i32)>,
    evidence_counts: &BTreeMap<DagNodeId, u16>,
) -> Result<Vec<DagNodeRow>, DagUiProjectionError> {
    projections
        .iter()
        .map(|projection| {
            let node = projection.node();
            let node_id = node.id();
            let depends_on = revision
                .edges()
                .iter()
                .filter(|edge| edge.downstream() == node_id)
                .filter_map(|edge| labels.get(&edge.upstream()).copied())
                .collect::<Vec<_>>()
                .join(", ");
            let waiting_on = projection
                .waiting_on()
                .iter()
                .filter_map(|id| labels.get(id).copied())
                .collect::<Vec<_>>()
                .join(", ");
            let acceptance = node
                .definition()
                .acceptance()
                .iter()
                .map(DagAcceptanceCriterion::as_str)
                .collect::<Vec<_>>()
                .join(" · ");
            let evidence = evidence_counts.get(&node_id).copied().unwrap_or(0);
            let (column, lane) = positions
                .get(&node_id)
                .copied()
                .ok_or(DagUiProjectionError::MissingCoordinate)?;
            Ok(DagNodeRow {
                id: node_id.to_string().into(),
                label: node.definition().title().as_str().into(),
                state: dag_status_label(projection.status()).into(),
                state_label: dag_status_korean_label(projection.status()).into(),
                objective: node.definition().objective().as_str().into(),
                acceptance: acceptance.into(),
                depends_on: depends_on.into(),
                waiting_on: waiting_on.into(),
                evidence: evidence_label(evidence).into(),
                revision: node.revision().get().to_string().into(),
                current: projection.status() == DagNodeStatus::Active,
                terminal: node.lifecycle().is_terminal(),
                column,
                lane,
                old_column: layout_coordinate(column),
                old_lane: layout_coordinate(lane),
                transition_kind: DagTransitionKind::Stable.as_str().into(),
                transition_epoch: 0,
                transition_progress: 1.0,
                transition_delay_ms: 0,
                transition_entering: false,
                transition_exiting: false,
            })
        })
        .collect()
}

fn project_dag_edges(
    revision: &DagRevision,
    projections: &[DagNodeProjection],
    labels: &BTreeMap<DagNodeId, &str>,
    positions: &BTreeMap<DagNodeId, (i32, i32)>,
) -> Result<Vec<DagEdgeRow>, DagUiProjectionError> {
    revision
        .edges()
        .iter()
        .map(|edge| {
            let (from_column, from_lane) = positions
                .get(&edge.upstream())
                .copied()
                .ok_or(DagUiProjectionError::MissingCoordinate)?;
            let (to_column, to_lane) = positions
                .get(&edge.downstream())
                .copied()
                .ok_or(DagUiProjectionError::MissingCoordinate)?;
            let downstream = projections
                .iter()
                .find(|projection| projection.node().id() == edge.downstream())
                .ok_or(DagUiProjectionError::MissingCoordinate)?;
            let upstream_label = labels
                .get(&edge.upstream())
                .copied()
                .ok_or(DagUiProjectionError::MissingCoordinate)?;
            let downstream_label = labels
                .get(&edge.downstream())
                .copied()
                .ok_or(DagUiProjectionError::MissingCoordinate)?;
            let blocked = downstream.waiting_on().contains(&edge.upstream());
            let current_path = downstream.status() == DagNodeStatus::Active;
            Ok(DagEdgeRow {
                upstream_id: edge.upstream().to_string().into(),
                downstream_id: edge.downstream().to_string().into(),
                upstream_label: upstream_label.into(),
                downstream_label: downstream_label.into(),
                from_column,
                from_lane,
                to_column,
                to_lane,
                blocked,
                current_path,
                transition_kind: DagTransitionKind::Stable.as_str().into(),
                transition_epoch: 0,
                transition_progress: 1.0,
                transition_entering: false,
                transition_exiting: false,
            })
        })
        .collect()
}

fn dag_status_label(status: DagNodeStatus) -> &'static str {
    match status {
        DagNodeStatus::Pending => "PENDING",
        DagNodeStatus::Ready => "READY",
        DagNodeStatus::Active => "ACTIVE",
        DagNodeStatus::Blocked => "BLOCKED",
        DagNodeStatus::Completed => "COMPLETED",
        DagNodeStatus::Failed => "FAILED",
        DagNodeStatus::Skipped => "SKIPPED",
        DagNodeStatus::Cancelled => "CANCELLED",
    }
}

fn dag_status_korean_label(status: DagNodeStatus) -> &'static str {
    match status {
        DagNodeStatus::Pending => "대기",
        DagNodeStatus::Ready => "준비됨",
        DagNodeStatus::Active => "진행 중",
        DagNodeStatus::Blocked => "차단됨",
        DagNodeStatus::Completed => "완료",
        DagNodeStatus::Failed => "실패",
        DagNodeStatus::Skipped => "건너뜀",
        DagNodeStatus::Cancelled => "취소됨",
    }
}

fn evidence_label(count: u16) -> String {
    if count == 0 {
        "No linked durable evidence".to_owned()
    } else {
        format!(
            "{count} linked evidence item{}",
            if count == 1 { "" } else { "s" }
        )
    }
}

/// Bind the only DAG callback.  It validates and queues a read-only node
/// selection; there are deliberately no create/edit/delete/transition
/// callbacks in this surface.
pub(crate) fn bind_dag_actions(app: &AppWindow, intents: &SyncSender<UiDagIntent>) {
    let intents = intents.clone();
    let app_for_callback = app.clone_strong();
    app.on_select_dag_node(move |id| {
        let Ok(node_id) = DagNodeId::from_str(id.as_str()) else {
            app_for_callback
                .set_dag_status("ERROR [DAG_NODE_ID_INVALID] Invalid DAG node identity.".into());
            return;
        };
        match intents.try_send(UiDagIntent::SelectNode(node_id)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => app_for_callback
                .set_dag_status("ERROR [DAG_QUEUE_FULL] DAG selection queue is full.".into()),
            Err(mpsc::TrySendError::Disconnected(_)) => app_for_callback
                .set_dag_status("ERROR [DAG_WORKER_UNAVAILABLE] DAG worker is unavailable.".into()),
        }
    });
}

pub(crate) struct DagPumpTimers {
    _control: Rc<Timer>,
    _motion: Rc<Timer>,
}

fn start_motion_timer(timer: &Rc<Timer>, controller: &Rc<RefCell<DagUiController>>) {
    if timer.running() {
        return;
    }
    let timer_weak = Rc::downgrade(timer);
    let controller = Rc::clone(controller);
    timer.start(TimerMode::Repeated, DAG_MOTION_PUMP_INTERVAL, move || {
        let active = {
            let mut controller = controller.borrow_mut();
            controller.advance_transition();
            controller.transition_active()
        };
        if !active && let Some(timer) = timer_weak.upgrade() {
            timer.stop();
        }
    });
}

pub(crate) fn start_dag_pump(
    app: &AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiDagIntent>,
    busy: Rc<Cell<bool>>,
) -> DagPumpTimers {
    let control = Rc::new(Timer::default());
    let motion = Rc::new(Timer::default());
    let controller = Rc::new(RefCell::new(DagUiController::new(
        app.clone_strong(),
        client,
        intents,
        busy,
    )));
    controller.borrow().start();
    let control_controller = Rc::clone(&controller);
    let control_motion = Rc::clone(&motion);
    control.start(TimerMode::Repeated, DAG_CONTROL_PUMP_INTERVAL, move || {
        control_controller.borrow_mut().tick();
        if control_controller.borrow().transition_active() {
            start_motion_timer(&control_motion, &control_controller);
        }
    });
    DagPumpTimers {
        _control: control,
        _motion: motion,
    }
}

#[cfg(test)]
mod tests {
    use forge_domain::{
        DagAcceptanceCriterion, DagEdge, DagNodeDefinition, DagNodeObjective, DagNodeOrdinal,
        DagNodeTitle, DagRevisionId, DagRevisionNumber, GoalRevision, TimestampMillis,
    };
    use uuid::Uuid;

    use super::*;

    fn timestamp(value: i64) -> TimestampMillis {
        TimestampMillis::new(value).unwrap_or_else(|_| unreachable!())
    }

    type DagFixture = (DagRevision, Vec<RegisteredDagNode>, DagNodeId, DagNodeId);

    fn fixture() -> Result<DagFixture, Box<dyn std::error::Error>> {
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0x100));
        let first_id = DagNodeId::from_uuid(Uuid::from_u128(0x101));
        let second_id = DagNodeId::from_uuid(Uuid::from_u128(0x102));
        let first = DagNodeDefinition::new(
            first_id,
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Prepare".to_owned())?,
            DagNodeObjective::new("Prepare the workspace".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "Workspace is prepared".to_owned(),
            )?],
        )?;
        let second = DagNodeDefinition::new(
            second_id,
            DagNodeOrdinal::new(1)?,
            DagNodeTitle::new("Verify".to_owned())?,
            DagNodeObjective::new("Verify the result".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "Result is verified".to_owned(),
            )?],
        )?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0x103)),
            goal_id,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![first, second],
            vec![DagEdge::new(first_id, second_id)],
            timestamp(10),
        )?;
        let snapshots = revision
            .nodes()
            .iter()
            .cloned()
            .map(|definition| {
                RegisteredDagNode::create(goal_id, revision.number(), definition, timestamp(10))
            })
            .collect();
        Ok((revision, snapshots, first_id, second_id))
    }

    fn definition(
        id: DagNodeId,
        ordinal: u16,
        title: &str,
    ) -> Result<DagNodeDefinition, Box<dyn std::error::Error>> {
        Ok(DagNodeDefinition::new(
            id,
            DagNodeOrdinal::new(ordinal)?,
            DagNodeTitle::new(title.to_owned())?,
            DagNodeObjective::new(format!("Observe {title}"))?,
            vec![DagAcceptanceCriterion::new(format!("{title} is observed"))?],
        )?)
    }

    #[test]
    fn projection_places_single_root_without_edges() -> Result<(), Box<dyn std::error::Error>> {
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0x200));
        let node_id = DagNodeId::from_uuid(Uuid::from_u128(0x201));
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0x202)),
            goal_id,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![definition(node_id, 0, "Root")?],
            Vec::new(),
            timestamp(20),
        )?;
        let snapshots = revision
            .nodes()
            .iter()
            .cloned()
            .map(|node| RegisteredDagNode::create(goal_id, revision.number(), node, timestamp(20)))
            .collect::<Vec<_>>();
        let projection = project_dag(&revision, &snapshots, &BTreeMap::new())?;

        assert_eq!(projection.nodes.len(), 1);
        assert!(projection.edges.is_empty());
        assert_eq!(projection.column_count, 1);
        assert_eq!(projection.lane_count, 1);
        assert_eq!(projection.nodes[0].column, 0);
        assert_eq!(projection.nodes[0].lane, 0);
        Ok(())
    }

    #[test]
    fn projection_is_deterministic_for_branch_and_merge_exact_edges()
    -> Result<(), Box<dyn std::error::Error>> {
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0x300));
        let root_id = DagNodeId::from_uuid(Uuid::from_u128(0x301));
        let inspect_id = DagNodeId::from_uuid(Uuid::from_u128(0x302));
        let verify_id = DagNodeId::from_uuid(Uuid::from_u128(0x303));
        let merge_id = DagNodeId::from_uuid(Uuid::from_u128(0x304));
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0x305)),
            goal_id,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![
                definition(root_id, 0, "Root")?,
                definition(inspect_id, 1, "Inspect")?,
                definition(verify_id, 2, "Verify")?,
                definition(merge_id, 3, "Merge")?,
            ],
            vec![
                DagEdge::new(root_id, inspect_id),
                DagEdge::new(root_id, verify_id),
                DagEdge::new(inspect_id, merge_id),
                DagEdge::new(verify_id, merge_id),
            ],
            timestamp(30),
        )?;
        let snapshots = revision
            .nodes()
            .iter()
            .cloned()
            .map(|node| RegisteredDagNode::create(goal_id, revision.number(), node, timestamp(30)))
            .collect::<Vec<_>>();
        let first = project_dag(&revision, &snapshots, &BTreeMap::new())?;
        let second = project_dag(&revision, &snapshots, &BTreeMap::new())?;

        assert_eq!(first.column_count, 3);
        assert_eq!(first.lane_count, 2);
        assert_eq!(first.edges.len(), 4);
        assert!(
            first
                .edges
                .iter()
                .all(|edge| edge.to_column > edge.from_column)
        );
        assert_eq!(first.nodes[0].column, 0);
        assert_eq!((first.nodes[1].column, first.nodes[1].lane), (1, 0));
        assert_eq!((first.nodes[2].column, first.nodes[2].lane), (1, 1));
        assert_eq!((first.nodes[3].column, first.nodes[3].lane), (2, 0));
        assert!(first.edges.iter().all(|edge| edge.blocked));
        assert!(first.edges.iter().all(|edge| !edge.current_path));
        let first_edges = first
            .edges
            .iter()
            .map(|edge| {
                (
                    edge.upstream_id.clone(),
                    edge.downstream_id.clone(),
                    edge.from_column,
                    edge.from_lane,
                    edge.to_column,
                    edge.to_lane,
                )
            })
            .collect::<Vec<_>>();
        let second_edges = second
            .edges
            .iter()
            .map(|edge| {
                (
                    edge.upstream_id.clone(),
                    edge.downstream_id.clone(),
                    edge.from_column,
                    edge.from_lane,
                    edge.to_column,
                    edge.to_lane,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(first_edges, second_edges);
        Ok(())
    }

    #[test]
    fn current_path_marks_only_exact_edges_into_active_downstream()
    -> Result<(), Box<dyn std::error::Error>> {
        let (revision, mut snapshots, first_id, second_id) = fixture()?;
        snapshots[0] =
            revision.start_node(&snapshots, first_id, snapshots[0].revision(), timestamp(11))?;
        snapshots[0] = snapshots[0]
            .clone()
            .complete(snapshots[0].revision(), timestamp(12))?;
        snapshots[1] = revision.start_node(
            &snapshots,
            second_id,
            snapshots[1].revision(),
            timestamp(13),
        )?;
        let projection = project_dag(&revision, &snapshots, &BTreeMap::new())?;

        assert_eq!(projection.edges.len(), 1);
        assert!(!projection.edges[0].blocked);
        assert!(projection.edges[0].current_path);
        assert_eq!(
            projection.edges[0].downstream_id.as_str(),
            second_id.to_string()
        );
        Ok(())
    }

    #[test]
    fn projection_preserves_topological_dependencies_waiting_and_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let (revision, snapshots, first_id, second_id) = fixture()?;
        let evidence = BTreeMap::from([(second_id, 2)]);
        let projection = project_dag(&revision, &snapshots, &evidence)?;
        let rows = &projection.nodes;

        assert_eq!(rows.len(), 2);
        assert_eq!(projection.column_count, 2);
        assert_eq!(projection.lane_count, 1);
        assert_eq!(projection.edges.len(), 1);
        assert_eq!(projection.edges[0].from_column, 0);
        assert_eq!(projection.edges[0].to_column, 1);
        assert!(projection.edges[0].blocked);
        assert!(!projection.edges[0].current_path);
        assert_eq!(rows[0].id.as_str(), first_id.to_string());
        assert_eq!(rows[0].state.as_str(), "READY");
        assert_eq!(rows[0].depends_on.as_str(), "");
        assert!(!rows[0].current);
        assert_eq!(rows[1].id.as_str(), second_id.to_string());
        assert_eq!(rows[1].state.as_str(), "PENDING");
        assert_eq!(rows[1].depends_on.as_str(), "Prepare");
        assert_eq!(rows[1].waiting_on.as_str(), "Prepare");
        assert_eq!(rows[1].evidence.as_str(), "2 linked evidence items");
        assert!(!rows[1].terminal);
        Ok(())
    }

    #[test]
    fn projection_marks_completed_nodes_terminal_without_inventing_readiness()
    -> Result<(), Box<dyn std::error::Error>> {
        let (revision, mut snapshots, first_id, second_id) = fixture()?;
        let first =
            revision.start_node(&snapshots, first_id, snapshots[0].revision(), timestamp(11))?;
        snapshots[0] = first.clone();
        let active = project_dag(&revision, &snapshots, &BTreeMap::new())?;
        assert_eq!(active.nodes[0].state.as_str(), "ACTIVE");
        assert!(active.nodes[0].current);
        let first = first.complete(first.revision(), timestamp(12))?;
        snapshots[0] = first;
        let evidence = BTreeMap::new();
        let projection = project_dag(&revision, &snapshots, &evidence)?;
        let rows = &projection.nodes;

        assert_eq!(rows[0].state.as_str(), "COMPLETED");
        assert!(rows[0].terminal);
        assert_eq!(rows[1].id.as_str(), second_id.to_string());
        assert_eq!(rows[1].state.as_str(), "READY");
        assert!(!rows[1].terminal);
        assert!(!projection.edges[0].blocked);
        assert!(!projection.edges[0].current_path);
        Ok(())
    }

    #[test]
    fn split_transition_starts_successors_at_the_prior_node_and_staggers_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let (revision, snapshots, prior_id, retained_id) = fixture()?;
        let source = project_dag(&revision, &snapshots, &BTreeMap::new())?.normalized();
        let first_successor = DagNodeId::from_uuid(Uuid::from_u128(0x104));
        let second_successor = DagNodeId::from_uuid(Uuid::from_u128(0x105));
        let prior = source
            .nodes
            .iter()
            .find(|node| node.id.as_str() == prior_id.to_string())
            .ok_or("prior node missing")?;
        let retained = source
            .nodes
            .iter()
            .find(|node| node.id.as_str() == retained_id.to_string())
            .ok_or("retained node missing")?
            .clone();
        let mut first = prior.clone();
        first.id = first_successor.to_string().into();
        first.label = "Inspect".into();
        first.column = 1;
        first.lane = 0;
        let mut second = prior.clone();
        second.id = second_successor.to_string().into();
        second.label = "Verify".into();
        second.column = 1;
        second.lane = 1;
        let mut initial = DagUiProjection {
            nodes: vec![first, second, retained],
            edges: Vec::new(),
            column_count: 2,
            lane_count: 2,
        }
        .normalized();
        let lineage = [
            DagNodeLineage::new(prior_id, first_successor, DagLineageKind::Split),
            DagNodeLineage::new(prior_id, second_successor, DagLineageKind::Split),
        ];

        apply_node_transition_rows(&mut initial, &source, &lineage, 7);

        let first = initial
            .nodes
            .iter()
            .find(|node| node.id.as_str() == first_successor.to_string())
            .ok_or("first successor missing")?;
        let second = initial
            .nodes
            .iter()
            .find(|node| node.id.as_str() == second_successor.to_string())
            .ok_or("second successor missing")?;
        assert_eq!(first.transition_kind.as_str(), "SPLIT");
        assert_eq!(second.transition_kind.as_str(), "SPLIT");
        assert!(first.transition_entering && second.transition_entering);
        assert_eq!((first.old_column, first.old_lane), (0.0, 0.0));
        assert_eq!((second.old_column, second.old_lane), (0.0, 0.0));
        assert_eq!(first.transition_delay_ms, 0);
        assert_eq!(second.transition_delay_ms, 20);
        let exiting_prior = initial
            .nodes
            .iter()
            .find(|node| node.id.as_str() == prior_id.to_string())
            .ok_or("exiting prior missing")?;
        assert!(exiting_prior.transition_exiting);
        assert_eq!(exiting_prior.transition_kind.as_str(), "SPLIT");
        Ok(())
    }

    #[test]
    fn reduced_motion_ignores_spatial_stagger_and_stays_within_eighty_ms()
    -> Result<(), Box<dyn std::error::Error>> {
        let (revision, snapshots, _, _) = fixture()?;
        let target = project_dag(&revision, &snapshots, &BTreeMap::new())?.normalized();
        let mut initial = target.clone();
        initial.nodes[0].transition_delay_ms = 60;
        initial.nodes[0].transition_entering = true;
        let transition = DagTransitionPlan {
            initial: initial.clone(),
            target,
            started_at: Instant::now(),
            duration: DAG_REDUCED_MOTION_DURATION,
            epoch: 11,
            reduced_motion: true,
        };
        set_projection_progress(&mut initial, &transition, 0.5);

        assert!(transition.duration <= Duration::from_millis(80));
        assert!((initial.nodes[0].transition_progress - 0.5).abs() < f32::EPSILON);
        assert_eq!(initial.nodes[0].transition_epoch, 11);
        Ok(())
    }

    #[test]
    fn edge_transition_keeps_new_and_removed_edges_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let (revision, snapshots, _, second_id) = fixture()?;
        let source = project_dag(&revision, &snapshots, &BTreeMap::new())?.normalized();
        let successor_id = DagNodeId::from_uuid(Uuid::from_u128(0x106));
        let mut entering = source.edges[0].clone();
        entering.upstream_id = second_id.to_string().into();
        entering.downstream_id = successor_id.to_string().into();
        entering.upstream_label = "Verify".into();
        entering.downstream_label = "Publish".into();
        entering.from_column = 1;
        entering.to_column = 2;
        let mut initial = DagUiProjection {
            nodes: source.nodes.clone(),
            edges: vec![entering],
            column_count: 3,
            lane_count: 1,
        }
        .normalized();

        apply_edge_transition_rows(&mut initial, &source, 13);

        assert_eq!(initial.edges.len(), 2);
        assert!(initial.edges.iter().any(|edge| {
            edge.downstream_id.as_str() == successor_id.to_string()
                && edge.transition_entering
                && edge.transition_kind.as_str() == "ENTER"
        }));
        assert!(initial.edges.iter().any(|edge| {
            edge.downstream_id == source.edges[0].downstream_id
                && edge.transition_exiting
                && edge.transition_kind.as_str() == "EXIT"
        }));
        Ok(())
    }

    #[test]
    fn evidence_label_is_bounded_and_truthful() {
        assert_eq!(evidence_label(0), "No linked durable evidence");
        assert_eq!(evidence_label(1), "1 linked evidence item");
        assert_eq!(evidence_label(32), "32 linked evidence items");
    }
}
