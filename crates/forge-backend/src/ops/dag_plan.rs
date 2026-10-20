//! Coordinator DAG planning commands and historical receipt readback.
//!
//! This module owns only bounded JSON conversion.  DAG authority, replay
//! identity, Goal attribution, and durable receipt observation remain in
//! forge-control and forge-persistence.

use std::collections::BTreeMap;

use forge_control::{AgentDagPlanCommitRequest, DagPlanReadbackRequest, ForgeControlClient};
use forge_domain::{
    ActivityCoordinatorActor, AgentDagDraft, AgentDagDraftDigest, AgentDagPlanRequest,
    AgentDagPlanRequestId, AgentWorkUpdateId, AgentWorkUpdateSequence, AuthenticatedPrincipal,
    DagAcceptanceCriterion, DagEdge, DagHeadRevision, DagLineageKind, DagNodeDefinition, DagNodeId,
    DagNodeLifecycle, DagNodeLineage, DagNodeObjective, DagNodeOrdinal, DagNodeRevision,
    DagNodeTitle, DagRevision, DagRevisionId, DagRevisionNumber, GoalAttribution, GoalId,
    GoalRevision, RegisteredDagNode, TimestampMillis,
};
use forge_persistence::AgentDagPlanRecord;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::planning::{PlanningAuthorityDto, decode_authority};
use super::{ScopeDto, decode_dag_revision, decode_goal_revision, decode_timestamp, parse_body};
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitBody {
    authority: PlanningAuthorityDto,
    plan_request_id: Uuid,
    goal_id: Uuid,
    expected_goal_revision: i64,
    #[serde(default)]
    expected_parent_revision: Option<i64>,
    #[serde(default)]
    expected_head_revision: Option<i64>,
    draft: DraftDto,
    history_update_id: Uuid,
    history_update_sequence: i64,
    observed_at_ms: i64,
}

/// The command-level Goal and parent fields are kept outside this full draft
/// shape so the control request has one explicit authority/CAS tuple.  The
/// draft still carries every immutable revision, node, predicate, edge, and
/// lineage field required to construct the native domain projection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftDto {
    revision_id: Uuid,
    dag_revision: i64,
    nodes: Vec<NodeDto>,
    edges: Vec<EdgeDto>,
    lineage: Vec<LineageDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeDto {
    node_id: Uuid,
    ordinal: u16,
    title: String,
    objective: String,
    acceptance: Vec<String>,
    lifecycle: NodeLifecycleDto,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum NodeLifecycleDto {
    Pending,
    Completed {
        created_at_ms: i64,
        updated_at_ms: i64,
        node_revision: i64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeDto {
    upstream: Uuid,
    downstream: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageDto {
    prior_node_id: Uuid,
    successor_node_id: Uuid,
    kind: LineageKindDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LineageKindDto {
    Split,
    Replace,
    Merge,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackBody {
    scope: ScopeDto,
    activity_id: Uuid,
    goal_id: Uuid,
    plan_request_id: Uuid,
    #[serde(default)]
    expected_draft_digest: Option<String>,
}

/// Parse one Coordinator-authorized initial or successor DAG plan.
pub(super) fn parse_commit(value: &Value) -> Result<AgentDagPlanCommitRequest, ForgeError> {
    let body: CommitBody = parse_body(value, "dag.plan_commit payload is invalid")?;
    let (scope, actor) = decode_authority(&body.authority)?;
    let goal_id = GoalId::from_uuid(require_id(body.goal_id, "goal id")?);
    let expected_goal_revision = decode_goal_revision(body.expected_goal_revision)?;
    let expected_parent_revision = body
        .expected_parent_revision
        .map(decode_dag_revision)
        .transpose()?;
    let expected_head_revision = body
        .expected_head_revision
        .map(DagHeadRevision::new)
        .transpose()
        .map_err(|_| ForgeError::invalid_input("DAG head revision is invalid"))?;
    if expected_parent_revision.is_some() != expected_head_revision.is_some() {
        return Err(ForgeError::invalid_input(
            "DAG parent and head revisions must be supplied together",
        ));
    }
    let observed_at = decode_timestamp(body.observed_at_ms)?;
    let draft = parse_draft(
        body.draft,
        goal_id,
        expected_goal_revision,
        expected_parent_revision,
        observed_at,
    )?;
    let request = AgentDagPlanRequest::new(
        AgentDagPlanRequestId::from_uuid(require_id(body.plan_request_id, "plan request id")?),
        actor,
        GoalAttribution::new(goal_id, expected_goal_revision),
        expected_parent_revision,
        expected_head_revision,
        draft,
        AgentWorkUpdateId::from_uuid(require_id(body.history_update_id, "history update id")?),
        AgentWorkUpdateSequence::new(body.history_update_sequence)
            .map_err(|_| ForgeError::invalid_input("history update sequence is invalid"))?,
        observed_at,
    );
    Ok(AgentDagPlanCommitRequest { scope, request })
}

struct ParsedNodes {
    definitions: Vec<DagNodeDefinition>,
    lifecycles: BTreeMap<DagNodeId, NodeLifecycleDto>,
}

fn parse_nodes(nodes: Vec<NodeDto>) -> Result<ParsedNodes, ForgeError> {
    let mut definitions = Vec::with_capacity(nodes.len());
    let mut lifecycles = BTreeMap::new();
    for node in nodes {
        let node_id = DagNodeId::from_uuid(require_id(node.node_id, "DAG node id")?);
        let acceptance = node
            .acceptance
            .into_iter()
            .map(|criterion| {
                DagAcceptanceCriterion::new(criterion)
                    .map_err(|_| ForgeError::invalid_input("DAG acceptance predicate is invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let definition = DagNodeDefinition::new(
            node_id,
            DagNodeOrdinal::new(node.ordinal)
                .map_err(|_| ForgeError::invalid_input("DAG node ordinal is invalid"))?,
            DagNodeTitle::new(node.title)
                .map_err(|_| ForgeError::invalid_input("DAG node title is invalid"))?,
            DagNodeObjective::new(node.objective)
                .map_err(|_| ForgeError::invalid_input("DAG node objective is invalid"))?,
            acceptance,
        )
        .map_err(|_| ForgeError::invalid_input("DAG node definition is invalid"))?;
        if lifecycles.insert(node_id, node.lifecycle).is_some() {
            return Err(ForgeError::invalid_input("DAG node ids must be unique"));
        }
        definitions.push(definition);
    }

    Ok(ParsedNodes {
        definitions,
        lifecycles,
    })
}

fn parse_draft(
    value: DraftDto,
    goal_id: GoalId,
    goal_revision: GoalRevision,
    parent_revision: Option<DagRevisionNumber>,
    observed_at: TimestampMillis,
) -> Result<AgentDagDraft, ForgeError> {
    if value.nodes.is_empty() || value.nodes.len() > forge_domain::MAX_DAG_NODES {
        return Err(ForgeError::invalid_input(
            "DAG node count is outside the supported bound",
        ));
    }
    if value.edges.len() > forge_domain::MAX_DAG_EDGES
        || value.lineage.len() > forge_domain::MAX_DAG_EDGES
    {
        return Err(ForgeError::invalid_input(
            "DAG edge or lineage count is outside the supported bound",
        ));
    }

    let ParsedNodes {
        definitions,
        mut lifecycles,
    } = parse_nodes(value.nodes)?;

    let edges = value
        .edges
        .into_iter()
        .map(|edge| {
            Ok(DagEdge::new(
                DagNodeId::from_uuid(require_id(edge.upstream, "DAG upstream node id")?),
                DagNodeId::from_uuid(require_id(edge.downstream, "DAG downstream node id")?),
            ))
        })
        .collect::<Result<Vec<_>, ForgeError>>()?;
    let lineage = value
        .lineage
        .into_iter()
        .map(|item| {
            Ok(DagNodeLineage::new(
                DagNodeId::from_uuid(require_id(item.prior_node_id, "DAG lineage prior node id")?),
                DagNodeId::from_uuid(require_id(
                    item.successor_node_id,
                    "DAG lineage successor node id",
                )?),
                match item.kind {
                    LineageKindDto::Split => DagLineageKind::Split,
                    LineageKindDto::Replace => DagLineageKind::Replace,
                    LineageKindDto::Merge => DagLineageKind::Merge,
                },
            ))
        })
        .collect::<Result<Vec<_>, ForgeError>>()?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(require_id(value.revision_id, "DAG revision id")?),
        goal_id,
        goal_revision,
        DagRevisionNumber::new(value.dag_revision)
            .map_err(|_| ForgeError::invalid_input("DAG revision number is invalid"))?,
        parent_revision,
        definitions,
        edges,
        observed_at,
    )
    .map_err(|_| ForgeError::invalid_input("DAG revision is invalid"))?;

    let nodes = revision
        .nodes()
        .iter()
        .cloned()
        .map(|definition| {
            let lifecycle = lifecycles
                .remove(&definition.id())
                .ok_or_else(|| ForgeError::invalid_input("DAG node lifecycle is missing"))?;
            match lifecycle {
                NodeLifecycleDto::Pending => Ok(RegisteredDagNode::create(
                    goal_id,
                    revision.number(),
                    definition,
                    observed_at,
                )),
                NodeLifecycleDto::Completed {
                    created_at_ms,
                    updated_at_ms,
                    node_revision,
                } => RegisteredDagNode::from_parts(
                    goal_id,
                    revision.number(),
                    definition,
                    DagNodeLifecycle::Completed,
                    decode_timestamp(created_at_ms)?,
                    decode_timestamp(updated_at_ms)?,
                    DagNodeRevision::new(node_revision)
                        .map_err(|_| ForgeError::invalid_input("DAG node revision is invalid"))?,
                )
                .map_err(|_| ForgeError::invalid_input("completed DAG node is invalid")),
            }
        })
        .collect::<Result<Vec<_>, ForgeError>>()?;
    if !lifecycles.is_empty() {
        return Err(ForgeError::invalid_input(
            "DAG node lifecycle shape is invalid",
        ));
    }
    AgentDagDraft::new(revision, nodes, lineage)
        .map_err(|_| ForgeError::invalid_input("DAG draft is invalid"))
}

/// Parse one historical DAG plan identity without granting replay authority.
pub(super) fn parse_readback(value: &Value) -> Result<DagPlanReadbackRequest, ForgeError> {
    let body: ReadbackBody = parse_body(value, "dag.plan_readback payload is invalid")?;
    require_id(body.scope.workspace_id, "scope workspace id")?;
    require_id(body.scope.locator.location_id, "scope location id")?;
    let activity_id =
        forge_domain::ActivityId::from_uuid(require_id(body.activity_id, "activity id")?);
    let goal_id = GoalId::from_uuid(require_id(body.goal_id, "goal id")?);
    let plan_request_id =
        AgentDagPlanRequestId::from_uuid(require_id(body.plan_request_id, "plan request id")?);
    let expected_draft_digest = body
        .expected_draft_digest
        .as_deref()
        .map(parse_draft_digest)
        .transpose()?;
    Ok(DagPlanReadbackRequest {
        scope: super::decode_scope(&body.scope)?,
        activity_id,
        goal_id,
        plan_request_id,
        expected_draft_digest,
    })
}

fn parse_draft_digest(value: &str) -> Result<AgentDagDraftDigest, ForgeError> {
    if value.len() != AgentDagDraftDigest::BYTE_LEN * 2 {
        return Err(ForgeError::invalid_input(
            "DAG draft digest must be 64 lowercase hex characters",
        ));
    }
    let bytes = super::decode_hex(value)?;
    let bytes: [u8; AgentDagDraftDigest::BYTE_LEN] = bytes.try_into().map_err(|_| {
        ForgeError::invalid_input("DAG draft digest must be 64 lowercase hex characters")
    })?;
    if super::encode_hex(&bytes) != value {
        return Err(ForgeError::invalid_input(
            "DAG draft digest must be lowercase hex",
        ));
    }
    Ok(AgentDagDraftDigest::from_bytes(bytes))
}

/// Execute one Coordinator DAG plan commit and project the committed revision
/// returned by the same control operation.
pub(super) fn execute_commit(
    client: &ForgeControlClient,
    request: &AgentDagPlanCommitRequest,
) -> Result<Value, ForgeError> {
    let scope = super::source::scope_json(&request.scope)?;
    let result = client
        .agent_dag_plan_commit(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    let receipt = result.receipt();
    let digest = request.request.digest();
    Ok(json!({
        "scope": scope,
        "plan_request_id": request.request.id().into_uuid(),
        "request_id": receipt.request_id().into_uuid(),
        "draft_digest": super::encode_hex(digest.as_bytes()),
        "committed_dag_revision_id": receipt.dag_revision_id().into_uuid(),
        "committed_dag_revision": receipt.dag_revision().get(),
        "committed_at_ms": receipt.committed_at().get(),
        "replayed": receipt.replayed(),
        "dag": super::plan::dag_json(result.revision())?,
        "retry_authorized": false,
    }))
}

/// Execute one historical DAG plan readback.  A missing row is an observation
/// only and does not prove that an admitted commit could never have completed.
pub(super) fn execute_readback(
    client: &ForgeControlClient,
    request: &DagPlanReadbackRequest,
) -> Result<Value, ForgeError> {
    let record = client
        .dag_plan_readback(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    readback_json(request, record.as_ref())
}

fn readback_json(
    request: &DagPlanReadbackRequest,
    record: Option<&AgentDagPlanRecord>,
) -> Result<Value, ForgeError> {
    let scope = super::source::scope_json(&request.scope)?;
    let common = json!({
        "scope": scope,
        "activity_id": request.activity_id.into_uuid(),
        "goal_id": request.goal_id.into_uuid(),
        "plan_request_id": request.plan_request_id.into_uuid(),
        "retry_authorized": false,
        "request_equivalence_proven": false,
    });
    let Value::Object(mut response) = common else {
        return Err(ForgeError::internal());
    };
    let Some(record) = record else {
        response.insert("found".to_owned(), Value::Bool(false));
        return Ok(Value::Object(response));
    };

    let actor = record.actor();
    let goal = record.goal();
    response.insert("found".to_owned(), Value::Bool(true));
    response.insert(
        "request_id".to_owned(),
        json!(record.request_id().into_uuid()),
    );
    response.insert("actor".to_owned(), actor_json(actor));
    response.insert("goal_id".to_owned(), json!(goal.goal_id().into_uuid()));
    response.insert(
        "goal_revision".to_owned(),
        json!(goal.expected_revision().get()),
    );
    response.insert(
        "expected_parent_revision".to_owned(),
        json!(
            record
                .expected_parent_revision()
                .map(DagRevisionNumber::get)
        ),
    );
    response.insert(
        "expected_head_revision".to_owned(),
        json!(record.expected_head_revision().map(DagHeadRevision::get)),
    );
    response.insert(
        "draft_digest".to_owned(),
        json!(super::encode_hex(record.digest().as_bytes())),
    );
    response.insert(
        "committed_dag_revision_id".to_owned(),
        json!(record.committed_dag_revision_id().into_uuid()),
    );
    response.insert(
        "committed_dag_revision".to_owned(),
        json!(record.committed_dag_revision().get()),
    );
    response.insert(
        "history_update_id".to_owned(),
        json!(record.history_update_id().into_uuid()),
    );
    response.insert(
        "history_update_sequence".to_owned(),
        json!(record.history_update_sequence().get()),
    );
    response.insert(
        "committed_at_ms".to_owned(),
        json!(record.committed_at().get()),
    );
    Ok(Value::Object(response))
}

fn actor_json(value: ActivityCoordinatorActor) -> Value {
    json!({
        "workspace_id": value.workspace_id().into_uuid(),
        "activity_id": value.activity_id().into_uuid(),
        "agent_id": value.agent_id().into_uuid(),
        "expected_coordinator_revision": value.expected_revision().get(),
        "principal": principal_json(value.principal()),
        "session_id": value.session_id().into_uuid(),
    })
}

fn principal_json(value: AuthenticatedPrincipal) -> Value {
    match value {
        AuthenticatedPrincipal::TrustedStdio => json!({ "kind": "trusted_stdio" }),
        AuthenticatedPrincipal::DirectToken(id) => {
            json!({ "kind": "direct_token", "token_id": id.into_uuid() })
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            json!({ "kind": "oauth_grant", "grant_id": id.into_uuid() })
        }
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
