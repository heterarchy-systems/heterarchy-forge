//! Goal inventory and deletion adapters over the Forge control boundary.
//!
//! Goal deletion is a Coordinator-authorized, exact-fence operation.  The
//! request carries no filesystem path or cache root; the trusted host supplies
//! the product-cache root to execution after parsing.

use std::path::Path;

use forge_control::{
    ForgeControlClient, GoalDeleteIssue, GoalDeleteOutcome, GoalDeletePhase, GoalDeleteRequest,
    GoalDeletionAuthority, ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityCoordinatorActor, ActivityId, DagHeadRevision,
    GoalDeletionRequest as DomainGoalDeletionRequest, GoalDeletionTarget, GoalId, GoalListLimit,
    GoalRevision, TimestampMillis,
};
use forge_persistence::GoalDeletionPendingInventory;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::planning::{PlanningAuthorityDto, decode_authority};
use super::{ScopeDto, decode_goal_revision, decode_scope, decode_timestamp, parse_body};
use crate::error::ForgeError;

const MAX_PENDING_DELETION_RESULTS: u32 = 32;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalListCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) activity_id: ActivityId,
    pub(super) limit: GoalListLimit,
}

/// Parsed deletion command. It carries the exact Coordinator actor, Goal/DAG
/// fences, and observed timestamp; no cache path or other filesystem authority
/// is transported here.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalDeleteCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) request: DomainGoalDeletionRequest,
    pub(super) actor: ActivityCoordinatorActor,
    pub(super) observed_at: TimestampMillis,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalDeletionPendingCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListBody {
    scope: ScopeDto,
    activity_id: Uuid,
    limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteBody {
    authority: PlanningAuthorityDto,
    target: GoalDeletionTargetDto,
    goal_id: Uuid,
    goal_created_at_ms: i64,
    expected_goal_revision: i64,
    #[serde(default)]
    expected_dag_head_revision: Option<i64>,
    observed_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GoalDeletionTargetDto {
    Goal,
    Dag,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingBody {
    scope: ScopeDto,
    limit: u32,
}

/// Parse a bounded read-only Goal inventory request.
pub(super) fn parse_list(value: &Value) -> Result<GoalListCommand, ForgeError> {
    let body: ListBody = parse_body(value, "goal.list payload is invalid")?;
    require_id(body.scope.workspace_id, "scope workspace id")?;
    require_id(body.scope.locator.location_id, "scope location id")?;
    let scope = decode_scope(&body.scope)?;
    let activity_id = ActivityId::from_uuid(require_id(body.activity_id, "activity id")?);
    let limit = GoalListLimit::new(body.limit)
        .map_err(|_| ForgeError::invalid_input("Goal list limit is invalid"))?;
    Ok(GoalListCommand {
        scope,
        activity_id,
        limit,
    })
}

/// Parse one Coordinator-authorized Goal or DAG deletion request.
pub(super) fn parse_delete(value: &Value) -> Result<GoalDeleteCommand, ForgeError> {
    let body: DeleteBody = parse_body(value, "goal.delete payload is invalid")?;
    let (scope, actor) = decode_authority(&body.authority)?;
    let target = DomainGoalDeletionRequest::new(
        body.target.into_domain(),
        scope.workspace_id(),
        actor.activity_id(),
        GoalId::from_uuid(require_id(body.goal_id, "goal id")?),
        decode_timestamp(body.goal_created_at_ms)?,
        decode_goal_revision(body.expected_goal_revision)?,
        body.expected_dag_head_revision
            .map(DagHeadRevision::new)
            .transpose()
            .map_err(|_| ForgeError::invalid_input("DAG head revision is invalid"))?,
    );
    Ok(GoalDeleteCommand {
        scope,
        request: target,
        actor,
        observed_at: decode_timestamp(body.observed_at_ms)?,
    })
}

/// Parse bounded pending-cleanup discovery. This path is observational and
/// does not require a live Coordinator actor or session.
pub(super) fn parse_pending(value: &Value) -> Result<GoalDeletionPendingCommand, ForgeError> {
    let body: PendingBody = parse_body(value, "goal.delete_pending payload is invalid")?;
    require_id(body.scope.workspace_id, "scope workspace id")?;
    require_id(body.scope.locator.location_id, "scope location id")?;
    if body.limit == 0 || body.limit > MAX_PENDING_DELETION_RESULTS {
        return Err(ForgeError::invalid_input(
            "pending Goal deletion limit is invalid",
        ));
    }
    Ok(GoalDeletionPendingCommand {
        scope: super::decode_scope(&body.scope)?,
        limit: body.limit,
    })
}

/// Execute a bounded Goal inventory read and reuse the canonical Goal
/// projection shared with `goal.read`.
pub(super) fn execute_list(
    client: &ForgeControlClient,
    command: &GoalListCommand,
) -> Result<Value, ForgeError> {
    let goals = client
        .goal_list(command.scope.clone(), command.activity_id, command.limit)
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(json!({
        "scope": super::source::scope_json(&command.scope)?,
        "activity_id": command.activity_id.into_uuid(),
        "goals": goals.iter().map(super::plan::goal_json).collect::<Vec<_>>(),
    }))
}

/// Execute one destructive deletion step using the host-owned trusted cache
/// root. The response is the native bounded phase/progress projection.
pub(super) fn execute_delete(
    client: &ForgeControlClient,
    trusted_cache_root: &Path,
    command: &GoalDeleteCommand,
) -> Result<Value, ForgeError> {
    let outcome = client
        .goal_delete(
            GoalDeleteRequest::new(
                command.scope.clone(),
                command.request,
                GoalDeletionAuthority::Coordinator(command.actor),
                command.observed_at,
            ),
            Some(trusted_cache_root.to_path_buf()),
        )
        .map_err(|error| super::forge_error_of_client(&error))?;
    delete_json(&command.scope, outcome)
}

/// Execute pending-cleanup discovery without reauthorizing or retrying any
/// deletion. The original fences remain observations for a later fresh actor.
pub(super) fn execute_pending(
    client: &ForgeControlClient,
    command: &GoalDeletionPendingCommand,
) -> Result<Value, ForgeError> {
    let inventory = client
        .goal_delete_pending(command.scope.clone(), command.limit)
        .map_err(|error| super::forge_error_of_client(&error))?;
    pending_json(&command.scope, &inventory)
}

fn delete_json(
    scope: &ResolvedWorkspaceScope,
    outcome: GoalDeleteOutcome,
) -> Result<Value, ForgeError> {
    Ok(json!({
        "scope": super::source::scope_json(scope)?,
        "target": target_json(outcome.target()),
        "goal_id": outcome.goal_id().into_uuid(),
        "phase": phase_json(outcome.phase()),
        "cleanup_id": outcome.cleanup_id(),
        "remaining_count": outcome.remaining_count(),
        "next_goal_revision": outcome.next_goal_revision().map(GoalRevision::get),
        "issue": outcome.issue().map(issue_json),
        "retry_authorized": false,
    }))
}

fn pending_json(
    scope: &ResolvedWorkspaceScope,
    inventory: &GoalDeletionPendingInventory,
) -> Result<Value, ForgeError> {
    Ok(json!({
        "scope": super::source::scope_json(scope)?,
        "summaries": inventory.summaries().iter().map(|summary| {
            let request = summary.request();
            json!({
                "cleanup_id": summary.cleanup_id(),
                "target": target_json(request.target()),
                "activity_id": request.activity_id().into_uuid(),
                "goal_id": request.goal_id().into_uuid(),
                "goal_created_at_ms": request.goal_created_at().get(),
                "expected_goal_revision": request.expected_goal_revision().get(),
                "expected_dag_head_revision": request.expected_dag_head_revision().map(DagHeadRevision::get),
                "remaining": summary.remaining(),
            })
        }).collect::<Vec<_>>(),
        "has_more": inventory.has_more(),
        "retry_authorized": false,
    }))
}

impl GoalDeletionTargetDto {
    const fn into_domain(self) -> GoalDeletionTarget {
        match self {
            Self::Goal => GoalDeletionTarget::Goal,
            Self::Dag => GoalDeletionTarget::Dag,
        }
    }
}

const fn target_json(value: GoalDeletionTarget) -> &'static str {
    match value {
        GoalDeletionTarget::Goal => "goal",
        GoalDeletionTarget::Dag => "dag",
    }
}

const fn phase_json(value: GoalDeletePhase) -> &'static str {
    match value {
        GoalDeletePhase::Complete => "complete",
        GoalDeletePhase::Pending => "pending",
        GoalDeletePhase::Blocked => "blocked",
    }
}

const fn issue_json(value: GoalDeleteIssue) -> &'static str {
    match value {
        GoalDeleteIssue::Filesystem => "filesystem",
        GoalDeleteIssue::RootBinding => "root_binding",
        GoalDeleteIssue::ArtifactConflict => "artifact_conflict",
        GoalDeleteIssue::ProductCacheUnavailable => "product_cache_unavailable",
    }
}

fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}
