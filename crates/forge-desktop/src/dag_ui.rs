//! Read-only desktop projection for the durable Goal DAG.
//!
//! The DAG is written by the trusted local control plane (or a future
//! authenticated producer), never by this module or by Slint.  This module
//! only requests the current revision for the selected Goal and reduces the
//! validated domain snapshots into bounded operator-facing rows.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

use crate::{ActivityWorkspaceScope, resolved_activity_scope};
use forge_control::{ControlClientError, ForgeControlClient, PendingControl};
use forge_domain::{
    DagAcceptanceCriterion, DagNodeId, DagNodeProjection, DagNodeStatus, DagReadinessError,
    DagRevision, GoalId, RegisteredDagNode,
};
use forge_persistence::StoredDagRevision;
use forge_ui::{AppWindow, DagEdgeRow, DagNodeRow};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use thiserror::Error;

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

struct DagUiProjection {
    nodes: Vec<DagNodeRow>,
    edges: Vec<DagEdgeRow>,
    column_count: i32,
    lane_count: i32,
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
    pending: Option<PendingDagUi>,
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
            pending: None,
        }
    }

    pub(crate) fn start(&self) {
        self.clear("Select a committed Workspace and Goal to view the DAG.");
    }

    pub(crate) fn tick(&mut self) {
        self.poll_pending();
        self.poll_intents();
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
                self.selected_goal_id = goal_id;
                self.set_busy(false);
                self.begin_current();
            }
            UiDagIntent::SelectNode(node_id) => self.select_node(node_id),
        }
    }

    fn begin_current(&mut self) {
        let (Some(scope), Some(goal_id)) = (self.scope.clone(), self.selected_goal_id) else {
            self.current.take();
            self.clear(if self.scope.is_some() {
                "Select a Goal to view its Chat-authored DAG."
            } else {
                "Select a committed Workspace and Goal to view the DAG."
            });
            return;
        };
        let resolved = resolved_activity_scope(&scope);
        self.clear_dag_projection();
        self.app.set_dag_revision("".into());
        match self.client.submit_dag_get_current(resolved, goal_id) {
            Ok(pending) => {
                self.set_busy(true);
                self.app.set_dag_status("Loading current Goal DAG…".into());
                self.pending = Some(PendingDagUi {
                    scope,
                    goal_id,
                    pending,
                });
            }
            Err(error) => self.fail_control(&error),
        }
    }

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
                match project_stored_dag(&stored) {
                    Ok(projection) => {
                        let node_count = projection.nodes.len();
                        let edge_count = projection.edges.len();
                        self.current = Some(stored);
                        self.set_dag_projection(projection);
                        self.app.set_dag_revision(self.current.as_ref().map_or_else(
                            || "".into(),
                            |dag| dag.revision().number().get().to_string().into(),
                        ));
                        self.app.set_dag_status(
                            format!(
                                "Current DAG revision {} · {} node{} · {} exact edge{} · read-only projection",
                                self.current
                                    .as_ref()
                                    .map_or(0, |dag| dag.revision().number().get()),
                                node_count,
                                if node_count == 1 { "" } else { "s" },
                                edge_count,
                                if edge_count == 1 { "" } else { "s" }
                            )
                            .into(),
                        );
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
                self.clear_dag_projection();
                self.app.set_dag_revision("".into());
                self.app
                    .set_dag_status("No Chat-authored DAG for this Goal.".into());
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

    fn clear(&self, status: &str) {
        self.clear_dag_projection();
        self.app.set_dag_revision("".into());
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

pub(crate) fn start_dag_pump(
    app: &AppWindow,
    client: ForgeControlClient,
    intents: Receiver<UiDagIntent>,
    busy: Rc<Cell<bool>>,
) -> Rc<Timer> {
    let timer = Rc::new(Timer::default());
    let mut controller = DagUiController::new(app.clone_strong(), client, intents, busy);
    controller.start();
    timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
        controller.tick();
    });
    timer
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
    fn evidence_label_is_bounded_and_truthful() {
        assert_eq!(evidence_label(0), "No linked durable evidence");
        assert_eq!(evidence_label(1), "1 linked evidence item");
        assert_eq!(evidence_label(32), "32 linked evidence items");
    }
}
