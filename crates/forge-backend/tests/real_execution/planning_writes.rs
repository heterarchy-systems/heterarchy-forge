use super::lease_readback::{path_token, post_ok, scope_json};
use super::*;
use serde_json::{Value, json};

const PROOF_PATH: &str = "planning-completion-proof.txt";

struct PlanningState {
    goal_id: Uuid,
    goal_revision: i64,
    coordinator_revision: i64,
    old_creation_request_id: Uuid,
    old_creation_receipt: Value,
    plan_request_id: Uuid,
    node_id: Uuid,
    plan_payload: Value,
}

fn planning_authority(fixture: &Fixture, coordinator_revision: i64) -> Value {
    json!({
        "scope": scope_json(fixture),
        "activity_id": fixture.activity_id.into_uuid(),
        "actor": {
            "session_id": fixture.session_id.into_uuid(),
            "principal": { "kind": "trusted_stdio" },
            "agent_id": fixture.agent_id.into_uuid(),
            "expected_coordinator_revision": coordinator_revision,
        },
    })
}

fn contract(objective: &str) -> Value {
    json!({
        "objective": objective,
        "success_criteria": ["The planning proof completes"],
        "constraints": [],
        "out_of_scope": [],
        "verification_requirements": [{
            "kind": "file_present",
            "path_base64": path_token(PROOF_PATH),
            "description": "The completion proof file exists",
        }],
        "stop_conditions": [],
    })
}

fn create_payload(
    authority: &Value,
    goal_id: Uuid,
    mutation_request_id: Uuid,
    observed_at_ms: i64,
) -> Value {
    json!({
        "authority": authority,
        "mutation_request_id": mutation_request_id,
        "goal_id": goal_id,
        "observed_at_ms": observed_at_ms,
        "contract": contract("Exercise HTTP Goal planning"),
    })
}

fn revise_payload(
    authority: &Value,
    goal_id: Uuid,
    mutation_request_id: Uuid,
    expected_goal_revision: i64,
    observed_at_ms: i64,
) -> Value {
    json!({
        "authority": authority,
        "mutation_request_id": mutation_request_id,
        "goal_id": goal_id,
        "expected_goal_revision": expected_goal_revision,
        "observed_at_ms": observed_at_ms,
        "contract": contract("Exercise revised HTTP Goal planning"),
    })
}

fn transition_payload(
    authority: &Value,
    goal_id: Uuid,
    mutation_request_id: Uuid,
    expected_goal_revision: i64,
    observed_at_ms: i64,
    action: &str,
) -> Value {
    json!({
        "authority": authority,
        "mutation_request_id": mutation_request_id,
        "goal_id": goal_id,
        "expected_goal_revision": expected_goal_revision,
        "observed_at_ms": observed_at_ms,
        "action": {"kind": action},
    })
}

fn complete_payload(
    authority: &Value,
    goal_id: Uuid,
    mutation_request_id: Uuid,
    expected_goal_revision: i64,
    review_id: Uuid,
    observed_at_ms: i64,
) -> Value {
    json!({
        "authority": authority,
        "mutation_request_id": mutation_request_id,
        "goal_id": goal_id,
        "expected_goal_revision": expected_goal_revision,
        "observed_at_ms": observed_at_ms,
        "review_id": review_id,
    })
}

fn mutation_readback_payload(
    fixture: &Fixture,
    goal_id: Uuid,
    mutation_request_id: Uuid,
    expected_request_digest: Option<&Value>,
) -> Value {
    let mut payload = json!({
        "scope": scope_json(fixture),
        "activity_id": fixture.activity_id.into_uuid(),
        "goal_id": goal_id,
        "mutation_request_id": mutation_request_id,
    });
    if let Some(digest) = expected_request_digest {
        payload["expected_request_digest"] = digest.clone();
    }
    payload
}

fn revision(result: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    result["receipt"]["result_goal_revision"]
        .as_i64()
        .ok_or_else(|| "Goal mutation result revision is missing".into())
}

async fn assert_conflict(
    address: SocketAddr,
    operation: &str,
    payload: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, response) = post_command(address, operation, payload).await?;
    assert_eq!(
        status, 409,
        "expected a conflict from {operation}: {response}"
    );
    assert_eq!(response["ok"], false);
    Ok(())
}

fn current_plan_fences(fixture: &Fixture) -> Result<(i64, i64), Box<dyn std::error::Error>> {
    let binding = fixture
        .client
        .activity_coordinator_get(forge_control::CoordinatorGetRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
        })
        .map_err(|error| format!("planning Coordinator read: {error:?}"))?
        .ok_or("fixture Coordinator binding is missing")?;
    let context = fixture
        .client
        .agent_get_context(forge_control::AgentContextRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            agent_id: fixture.agent_id,
            now: timestamp_now()?,
            focus_event_limit: AgentListLimit::DEFAULT,
            work_update_limit: AgentListLimit::DEFAULT,
        })
        .map_err(|error| format!("planning Agent context read: {error:?}"))?
        .ok_or("fixture Agent context is missing")?;
    let current_sequence = context
        .work_updates()
        .iter()
        .map(|update| update.sequence().get())
        .max()
        .unwrap_or(0);
    let next_sequence = current_sequence
        .checked_add(1)
        .ok_or("Agent work update sequence overflow")?;
    Ok((binding.revision().get(), next_sequence))
}

async fn assert_goal_history(
    address: SocketAddr,
    fixture: &Fixture,
    goal_id: Uuid,
    create_request_id: Uuid,
    create_receipt: &Value,
    current_revision: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let readback = post_ok(
        address,
        "goal.mutation_readback",
        mutation_readback_payload(fixture, goal_id, create_request_id, None),
    )
    .await?;
    assert_eq!(readback["found"], true);
    assert_eq!(&readback["receipt"], create_receipt);
    assert_eq!(readback["receipt"]["result_goal_revision"], 1);
    let current = post_ok(
        address,
        "goal.read",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "goal_id": goal_id,
        }),
    )
    .await?;
    assert_eq!(current["found"], true);
    assert_eq!(current["revision"], current_revision);
    Ok(())
}

async fn assert_goal_lifecycle(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(Uuid, i64, i64, Uuid, Value), Box<dyn std::error::Error>> {
    let (coordinator_revision, _) = current_plan_fences(fixture)?;
    let authority = planning_authority(fixture, coordinator_revision);
    let goal_id = Uuid::now_v7();
    let create_request_id = Uuid::now_v7();
    let create = create_payload(
        &authority,
        goal_id,
        create_request_id,
        timestamp_now()?.get(),
    );
    let created = post_ok(address, "goal.create", create.clone()).await?;
    assert_eq!(created["receipt"]["kind"], "create");
    assert_eq!(created["receipt"]["result_goal_revision"], 1);
    assert_eq!(created["replayed"], false);
    let create_receipt = created["receipt"].clone();

    let revised = post_ok(
        address,
        "goal.revise",
        revise_payload(
            &authority,
            goal_id,
            Uuid::now_v7(),
            1,
            timestamp_now()?.get(),
        ),
    )
    .await?;
    assert_eq!(revision(&revised)?, 2);
    let paused = post_ok(
        address,
        "goal.transition",
        transition_payload(
            &authority,
            goal_id,
            Uuid::now_v7(),
            2,
            timestamp_now()?.get(),
            "pause",
        ),
    )
    .await?;
    assert_eq!(paused["receipt"]["result_status"], "paused");
    assert_eq!(revision(&paused)?, 3);
    let resumed = post_ok(
        address,
        "goal.transition",
        transition_payload(
            &authority,
            goal_id,
            Uuid::now_v7(),
            3,
            timestamp_now()?.get(),
            "resume",
        ),
    )
    .await?;
    assert_eq!(resumed["receipt"]["result_status"], "active");
    assert_eq!(revision(&resumed)?, 4);
    assert_goal_history(
        address,
        fixture,
        goal_id,
        create_request_id,
        &create_receipt,
        4,
    )
    .await?;

    assert_goal_replay_and_stale(
        address,
        goal_id,
        coordinator_revision,
        authority,
        create,
        create_receipt.clone(),
    )
    .await?;
    Ok((
        goal_id,
        4,
        coordinator_revision,
        create_request_id,
        create_receipt,
    ))
}

async fn assert_goal_replay_and_stale(
    address: SocketAddr,
    goal_id: Uuid,
    coordinator_revision: i64,
    authority: Value,
    create: Value,
    create_receipt: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let replay = post_ok(address, "goal.create", create.clone()).await?;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["receipt"], create_receipt);
    assert_eq!(replay["current_goal"]["revision"], 4);
    let mut changed = create;
    changed["contract"]["objective"] = json!("Changed body with the same mutation identity");
    assert_conflict(address, "goal.create", changed).await?;

    let mut stale_coordinator = authority.clone();
    stale_coordinator["actor"]["expected_coordinator_revision"] = json!(coordinator_revision + 1);
    assert_conflict(
        address,
        "goal.revise",
        revise_payload(
            &stale_coordinator,
            goal_id,
            Uuid::now_v7(),
            4,
            timestamp_now()?.get(),
        ),
    )
    .await?;
    assert_conflict(
        address,
        "goal.revise",
        revise_payload(
            &authority,
            goal_id,
            Uuid::now_v7(),
            1,
            timestamp_now()?.get(),
        ),
    )
    .await?;
    Ok(())
}

fn plan_payload(
    authority: &Value,
    goal_id: Uuid,
    goal_revision: i64,
    plan_request_id: Uuid,
    node_id: Uuid,
    history: (Uuid, i64),
    observed_at_ms: i64,
) -> Value {
    let (history_update_id, history_update_sequence) = history;
    json!({
        "authority": authority,
        "plan_request_id": plan_request_id,
        "goal_id": goal_id,
        "expected_goal_revision": goal_revision,
        "draft": {
            "revision_id": Uuid::now_v7(),
            "dag_revision": 1,
            "nodes": [{
                "node_id": node_id,
                "ordinal": 0,
                "title": "Complete planning proof",
                "objective": "Exercise the HTTP DAG lifecycle",
                "acceptance": ["The planning node completes"],
                "lifecycle": {"state": "pending"},
            }],
            "edges": [],
            "lineage": [],
        },
        "history_update_id": history_update_id,
        "history_update_sequence": history_update_sequence,
        "observed_at_ms": observed_at_ms,
    })
}

async fn assert_plan_readback(
    address: SocketAddr,
    fixture: &Fixture,
    goal_id: Uuid,
    plan_request_id: Uuid,
    draft_digest: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = json!({
        "scope": scope_json(fixture),
        "activity_id": fixture.activity_id.into_uuid(),
        "goal_id": goal_id,
        "plan_request_id": plan_request_id,
    });
    let without_digest = post_ok(address, "dag.plan_readback", identity.clone()).await?;
    assert_eq!(without_digest["found"], true);
    assert_eq!(&without_digest["draft_digest"], draft_digest);
    let mut with_digest = identity.clone();
    with_digest["expected_draft_digest"] = draft_digest.clone();
    assert_eq!(
        post_ok(address, "dag.plan_readback", with_digest).await?,
        without_digest
    );
    let mut wrong_digest = identity;
    wrong_digest["expected_draft_digest"] = json!("00".repeat(32));
    assert_conflict(address, "dag.plan_readback", wrong_digest).await
}

fn node_payload(
    fixture: &Fixture,
    goal_id: Uuid,
    goal_revision: i64,
    dag_revision: i64,
    node_id: Uuid,
    expected_node_revision: i64,
    observed_at_ms: i64,
) -> Value {
    json!({
        "scope": scope_json(fixture),
        "activity_id": fixture.activity_id.into_uuid(),
        "actor": {
            "session_id": fixture.session_id.into_uuid(),
            "principal": { "kind": "trusted_stdio" },
            "workspace_id": fixture.scope.workspace_id().into_uuid(),
        },
        "goal_id": goal_id,
        "expected_goal_revision": goal_revision,
        "expected_dag_revision": dag_revision,
        "node_id": node_id,
        "expected_node_revision": expected_node_revision,
        "observed_at_ms": observed_at_ms,
    })
}

async fn assert_plan_nodes(
    address: SocketAddr,
    fixture: &Fixture,
    state: &PlanningState,
) -> Result<i64, Box<dyn std::error::Error>> {
    let committed = post_ok(address, "dag.plan_commit", state.plan_payload.clone()).await?;
    assert_eq!(committed["replayed"], false);
    assert_eq!(committed["committed_dag_revision"], 1);
    let replay = post_ok(address, "dag.plan_commit", state.plan_payload.clone()).await?;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["draft_digest"], committed["draft_digest"]);
    assert_plan_readback(
        address,
        fixture,
        state.goal_id,
        state.plan_request_id,
        &committed["draft_digest"],
    )
    .await?;

    let started = post_ok(
        address,
        "node.start",
        node_payload(
            fixture,
            state.goal_id,
            state.goal_revision,
            1,
            state.node_id,
            1,
            timestamp_now()?.get(),
        ),
    )
    .await?;
    assert_eq!(started["node_id"], state.node_id.to_string());
    assert_eq!(started["goal_id"], json!(state.goal_id));
    assert_eq!(started["dag_revision"], 1);
    assert_eq!(started["lifecycle"], "active");
    assert_eq!(started["state"], "Active");
    assert!(started["node_revision"].as_i64().is_some());
    assert!(started["updated_at_ms"].as_i64().is_some());
    assert!(started["lifecycle_reason"].is_null());
    let dag = post_ok(
        address,
        "dag.read_current",
        json!({"scope": scope_json(fixture), "goal_id": state.goal_id}),
    )
    .await?;
    let node = dag["nodes"]
        .as_array()
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| node["node_id"] == state.node_id.to_string())
        })
        .ok_or("started planning node disappeared")?;
    assert_eq!(node["status"], "active");
    let node_revision = node["revision"].as_i64().ok_or("node revision missing")?;
    let completed = post_ok(
        address,
        "node.complete",
        node_payload(
            fixture,
            state.goal_id,
            state.goal_revision,
            1,
            state.node_id,
            node_revision,
            timestamp_now()?.get(),
        ),
    )
    .await?;
    assert_eq!(completed["node_id"], state.node_id.to_string());
    assert_eq!(completed["state"], "Completed");
    assert_eq!(completed["lifecycle"], "completed");
    assert_eq!(completed["goal_id"], json!(state.goal_id));
    assert_eq!(completed["dag_revision"], 1);
    // Completing is a transition: the readback carries the post-transition
    // node revision, one past the revision the command was admitted against.
    assert_eq!(completed["node_revision"], node_revision + 1);
    let current = post_ok(
        address,
        "dag.read_current",
        json!({"scope": scope_json(fixture), "goal_id": state.goal_id}),
    )
    .await?;
    let node = current["nodes"]
        .as_array()
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| node["node_id"] == state.node_id.to_string())
        })
        .ok_or("completed planning node disappeared")?;
    assert_eq!(node["status"], "completed");
    current["head_revision"]
        .as_i64()
        .ok_or_else(|| "DAG head revision is missing".into())
}

async fn assert_goal_completion(
    address: SocketAddr,
    fixture: &Fixture,
    state: &PlanningState,
    dag_head_revision: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let blocked = complete_payload(
        &planning_authority(fixture, state.coordinator_revision),
        state.goal_id,
        Uuid::now_v7(),
        state.goal_revision,
        Uuid::now_v7(),
        timestamp_now()?.get(),
    );
    let (status, response) = post_command(address, "goal.complete", blocked).await?;
    assert_eq!(
        status, 409,
        "missing FilePresent proof was accepted: {response}"
    );
    assert_eq!(response["ok"], false);
    fs::write(fixture.workspace_root.join(PROOF_PATH), b"planning proof\n")?;

    let completion_request_id = Uuid::now_v7();
    let completion = complete_payload(
        &planning_authority(fixture, state.coordinator_revision),
        state.goal_id,
        completion_request_id,
        state.goal_revision,
        Uuid::now_v7(),
        timestamp_now()?.get(),
    );
    let completed = post_ok(address, "goal.complete", completion.clone()).await?;
    assert_eq!(completed["receipt"]["kind"], "complete");
    assert_eq!(
        completed["receipt"]["result_goal_revision"],
        state.goal_revision + 1
    );
    assert_eq!(completed["receipt"]["result_status"], "completed");
    let receipt = completed["receipt"].clone();
    let replay = post_ok(address, "goal.complete", completion).await?;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["receipt"], receipt);
    assert_eq!(replay["current_goal"]["revision"], state.goal_revision + 1);
    let readback = post_ok(
        address,
        "goal.mutation_readback",
        mutation_readback_payload(
            fixture,
            state.goal_id,
            completion_request_id,
            Some(&receipt["request_digest"]),
        ),
    )
    .await?;
    assert_eq!(readback["receipt"], receipt);
    assert_delete_recreate(address, fixture, state, dag_head_revision).await
}

async fn assert_delete_recreate(
    address: SocketAddr,
    fixture: &Fixture,
    state: &PlanningState,
    dag_head_revision: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let existing = fixture
        .client
        .goal_get(
            fixture.scope.clone(),
            fixture.activity_id,
            GoalId::from_uuid(state.goal_id),
        )?
        .ok_or("completed Goal disappeared before HTTP deletion")?;
    assert_http_goal_delete(address, fixture, state, &existing, dag_head_revision).await?;
    assert_same_uuid_recreation(address, fixture, state).await
}

async fn assert_http_goal_delete(
    address: SocketAddr,
    fixture: &Fixture,
    state: &PlanningState,
    existing: &forge_domain::RegisteredGoal,
    dag_head_revision: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let delete_payload = json!({
        "authority": planning_authority(fixture, state.coordinator_revision),
        "target": "goal",
        "goal_id": state.goal_id,
        "goal_created_at_ms": existing.timestamps().created_at().get(),
        "expected_goal_revision": existing.revision().get(),
        "expected_dag_head_revision": dag_head_revision,
        "observed_at_ms": timestamp_now()?.get(),
    });
    let listed = post_ok(
        address,
        "goal.list",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "limit": 32,
        }),
    )
    .await?;
    assert!(
        listed["goals"]
            .as_array()
            .is_some_and(|goals| goals.iter().any(|goal| {
                goal["goal_id"] == state.goal_id.to_string()
                    && goal["revision"] == existing.revision().get()
            }))
    );

    let mut stale_created_at = delete_payload.clone();
    stale_created_at["goal_created_at_ms"] = json!(
        existing
            .timestamps()
            .created_at()
            .get()
            .checked_add(1)
            .ok_or("Goal creation timestamp overflow")?
    );
    assert_conflict(address, "goal.delete", stale_created_at).await?;

    let mut stale_dag_head = delete_payload.clone();
    stale_dag_head["expected_dag_head_revision"] = json!(
        dag_head_revision
            .checked_add(1)
            .ok_or("DAG head revision overflow")?
    );
    assert_conflict(address, "goal.delete", stale_dag_head).await?;

    // SQL-only deletion has no durable mutation receipt. Submit the exact
    // current fences once and observe the HTTP outcome directly; the absence
    // of a Goal is not a retry signal.
    let deleted = post_ok(address, "goal.delete", delete_payload).await?;
    assert_eq!(deleted["target"], "goal");
    assert_eq!(deleted["goal_id"], state.goal_id.to_string());
    assert_eq!(deleted["phase"], "complete");
    assert_eq!(deleted["cleanup_id"], Value::Null);
    assert_eq!(deleted["remaining_count"], 0);
    assert_eq!(deleted["retry_authorized"], false);

    let after_delete = post_ok(
        address,
        "goal.list",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "limit": 32,
        }),
    )
    .await?;
    assert!(!after_delete["goals"].as_array().is_some_and(|goals| {
        goals
            .iter()
            .any(|goal| goal["goal_id"] == state.goal_id.to_string())
    }));
    let pending = post_ok(
        address,
        "goal.delete_pending",
        json!({"scope": scope_json(fixture), "limit": 32}),
    )
    .await?;
    assert_eq!(pending["summaries"], json!([]));
    assert_eq!(pending["has_more"], false);
    assert_eq!(pending["retry_authorized"], false);
    Ok(())
}

async fn assert_same_uuid_recreation(
    address: SocketAddr,
    fixture: &Fixture,
    state: &PlanningState,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_request_id = Uuid::now_v7();
    let recreated = post_ok(
        address,
        "goal.create",
        create_payload(
            &planning_authority(fixture, state.coordinator_revision),
            state.goal_id,
            new_request_id,
            timestamp_now()?.get(),
        ),
    )
    .await?;
    assert_eq!(recreated["replayed"], false);
    assert_eq!(recreated["receipt"]["result_goal_revision"], 1);
    assert_ne!(state.old_creation_request_id, new_request_id);
    let after_recreate = post_ok(
        address,
        "goal.list",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "limit": 32,
        }),
    )
    .await?;
    assert!(after_recreate["goals"].as_array().is_some_and(|goals| {
        goals
            .iter()
            .any(|goal| goal["goal_id"] == state.goal_id.to_string() && goal["revision"] == 1)
    }));
    let old = post_ok(
        address,
        "goal.mutation_readback",
        mutation_readback_payload(fixture, state.goal_id, state.old_creation_request_id, None),
    )
    .await?;
    assert_eq!(old["found"], true);
    assert_eq!(old["receipt"], state.old_creation_receipt);
    assert_eq!(old["receipt"]["result_goal_revision"], 1);
    let new = post_ok(
        address,
        "goal.mutation_readback",
        mutation_readback_payload(fixture, state.goal_id, new_request_id, None),
    )
    .await?;
    assert_eq!(new["found"], true);
    assert_eq!(new["receipt"], recreated["receipt"]);
    assert_eq!(new["receipt"]["result_goal_revision"], 1);
    Ok(())
}

pub(super) async fn assert_http_planning(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let (
        goal_id,
        goal_revision,
        coordinator_revision,
        old_creation_request_id,
        old_creation_receipt,
    ) = assert_goal_lifecycle(address, fixture).await?;
    let (_, history_update_sequence) = current_plan_fences(fixture)?;
    let plan_request_id = Uuid::now_v7();
    let node_id = Uuid::now_v7();
    let authority = planning_authority(fixture, coordinator_revision);
    let plan_payload = plan_payload(
        &authority,
        goal_id,
        goal_revision,
        plan_request_id,
        node_id,
        (Uuid::now_v7(), history_update_sequence),
        timestamp_now()?.get(),
    );
    let state = PlanningState {
        goal_id,
        goal_revision,
        coordinator_revision,
        old_creation_request_id,
        old_creation_receipt,
        plan_request_id,
        node_id,
        plan_payload,
    };
    let dag_head_revision = assert_plan_nodes(address, fixture, &state).await?;
    assert_goal_completion(address, fixture, &state, dag_head_revision).await
}
