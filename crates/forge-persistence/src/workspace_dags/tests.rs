use forge_domain::{
    ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId,
    AgentTransportKind, AuthenticatedPrincipal, DagAcceptanceCriterion, DagNodeObjective,
    DagNodeOrdinal, DagNodeTitle, DirectTokenId, ExecutionId, GoalContract, GoalEvidenceRef,
    GoalNodeAttribution, GoalObjective, GoalRevision, GoalStatement, RegisteredAgentInstance,
    RegisteredGoal, WorkspaceId,
};
use uuid::Uuid;

use super::*;

fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    Ok(TimestampMillis::new(value)?)
}

fn node_transition(
    goal: &RegisteredGoal,
    dag_revision: DagRevisionNumber,
    node: &RegisteredDagNode,
    observed_at: TimestampMillis,
) -> DagNodeTransition {
    DagNodeTransition::new(
        DagTransitionScope::new(
            goal.workspace_id(),
            goal.activity_id(),
            goal.id(),
            goal.revision(),
            dag_revision,
        ),
        node.id(),
        node.revision(),
        observed_at,
    )
}

fn repository() -> Result<(Connection, RegisteredGoal), Box<dyn std::error::Error>> {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities(
                activity_id BLOB PRIMARY KEY NOT NULL,
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                state INTEGER NOT NULL,
                lease_owner_id BLOB,
                lease_until_ms INTEGER
             );",
    )?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
    connection.execute(
        "INSERT INTO workspace(workspace_id) VALUES (?1)",
        params![workspace_id.into_uuid().as_bytes()],
    )?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(3));
    connection.execute(
        "INSERT INTO activities(activity_id, workspace_id, state, lease_owner_id, lease_until_ms) VALUES (?1, ?2, 1, ?3, 100)",
        params![
            activity_id.into_uuid().as_bytes(),
            workspace_id.into_uuid().as_bytes(),
            Uuid::from_u128(0x7003).as_bytes(),
        ],
    )?;
    workspace_goals::create_schema(&connection)?;
    create_schema(&connection)?;
    crate::workspace_semantic_events::create_schema(&connection)?;
    crate::workspace_goal_creation_watermarks::create_schema(&connection)?;
    crate::workspace_goal_deletion::create_schema(&connection)?;
    crate::workspace_work_cuts::create_schema(&connection)?;
    let goal = RegisteredGoal::create(
        GoalId::from_uuid(Uuid::from_u128(2)),
        workspace_id,
        activity_id,
        GoalContract::new(
            GoalObjective::new("Implement versioned DAG persistence".to_owned())?,
            vec![GoalStatement::new("DAG round-trips".to_owned())?],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        timestamp(10)?,
    );
    let _ = workspace_goals::insert_goal(&mut connection, &goal)?;
    Ok((connection, goal))
}

fn authorized_repository()
-> Result<(Connection, RegisteredGoal, RegisteredAgentInstance), Box<dyn std::error::Error>> {
    let (connection, goal) = repository()?;
    crate::workspace_agents::create_schema(&connection)?;
    crate::workspace_agent_events::create_schema(&connection)?;
    crate::workspace_coordinators::create_schema(&connection)?;
    let agent = RegisteredAgentInstance::create_bound(
        AgentInstanceId::from_uuid(Uuid::from_u128(0x7001)),
        goal.workspace_id(),
        goal.activity_id(),
        AgentSessionId::from_uuid(Uuid::from_u128(0x7002)),
        AgentDisplayName::new("DAG Agent".to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp(1)?,
    );
    crate::legacy_agent_seed::seed_agent(
        &connection,
        &agent,
        Some(crate::workspace_agent_events::derived_event_id(
            agent.id(),
            agent.revision(),
            forge_domain::AgentEventKind::Joined,
        )),
    )?;
    Ok((connection, goal, agent))
}

fn definition(id: u128, ordinal: u16) -> Result<DagNodeDefinition, Box<dyn std::error::Error>> {
    Ok(DagNodeDefinition::new(
        DagNodeId::from_uuid(Uuid::from_u128(id)),
        DagNodeOrdinal::new(ordinal)?,
        DagNodeTitle::new(format!("Node {id}"))?,
        DagNodeObjective::new(format!("Complete node {id}"))?,
        vec![DagAcceptanceCriterion::new(format!("Node {id} accepted"))?],
    )?)
}

fn revision(
    goal: &RegisteredGoal,
    number: i64,
    definitions: Vec<DagNodeDefinition>,
    edges: Vec<DagEdge>,
) -> Result<(DagRevision, Vec<RegisteredDagNode>), Box<dyn std::error::Error>> {
    let number = DagRevisionNumber::new(number)?;
    let revision = DagRevision::new(
        DagRevisionId::from_uuid(Uuid::from_u128(100 + u128::try_from(number.get())?)),
        goal.id(),
        GoalRevision::INITIAL,
        number,
        if number == DagRevisionNumber::INITIAL {
            None
        } else {
            Some(DagRevisionNumber::new(number.get() - 1)?)
        },
        definitions.clone(),
        edges,
        timestamp(10 + number.get())?,
    )?;
    let nodes = definitions
        .into_iter()
        .map(|definition| {
            RegisteredDagNode::create(goal.id(), number, definition, revision.created_at())
        })
        .collect();
    Ok((revision, nodes))
}

#[test]
fn schema_sql_matches_created_objects() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
             CREATE TABLE goals(goal_id BLOB PRIMARY KEY);",
    )?;
    create_schema(&connection)?;
    validate_schema(&connection)?;
    assert_eq!(schema_objects().len(), 8);
    Ok(())
}

#[test]
fn initial_revision_round_trips_and_exact_retry_is_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(10, 0)?;
    let b = definition(11, 1)?;
    let (revision, nodes) = revision(
        &goal,
        1,
        vec![b.clone(), a.clone()],
        vec![DagEdge::new(a.id(), b.id())],
    )?;
    let stored = insert_revision(&mut connection, &revision, &nodes, &[], None)?;
    assert_eq!(stored.revision(), &revision);
    assert_eq!(stored.head().revision(), DagHeadRevision::INITIAL);
    assert_eq!(get_current(&connection, goal.id())?, Some(stored.clone()));
    let mut reordered = nodes.clone();
    reordered.reverse();
    assert_eq!(
        insert_revision(&mut connection, &revision, &reordered, &[], None)?,
        stored
    );
    Ok(())
}

#[test]
fn exact_retry_survives_goal_revision_change_and_lineage_reordering()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(12, 0)?;
    let b = definition(13, 1)?;
    let (first, first_nodes) = revision(&goal, 1, vec![a.clone(), b.clone()], Vec::new())?;
    let _ = insert_revision(&mut connection, &first, &first_nodes, &[], None)?;

    let c = definition(14, 0)?;
    let d = definition(15, 2)?;
    let (second, second_nodes) = revision(&goal, 2, vec![c.clone(), b, d.clone()], Vec::new())?;
    let lineage = vec![
        DagNodeLineage::new(a.id(), c.id(), DagLineageKind::Split),
        DagNodeLineage::new(a.id(), d.id(), DagLineageKind::Split),
    ];
    let stored = insert_revision(
        &mut connection,
        &second,
        &second_nodes,
        &lineage,
        Some(DagHeadRevision::INITIAL),
    )?;

    // The Goal revision is mutable state unrelated to the already
    // committed DAG identity.  Retrying the exact request must converge
    // even after that state advances.
    let paused = goal.pause(goal.revision(), timestamp(30)?)?;
    let _ = workspace_goals::update_goal(&mut connection, &paused, goal.revision())?;

    let mut reordered = lineage;
    reordered.reverse();
    assert_eq!(
        insert_revision(
            &mut connection,
            &second,
            &second_nodes,
            &reordered,
            Some(stored.head().revision()),
        )?,
        stored
    );
    Ok(())
}

#[test]
fn head_compare_and_set_rejects_stale_replan_without_partial_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(20, 0)?;
    let (first, first_nodes) = revision(&goal, 1, vec![a.clone()], Vec::new())?;
    let _ = insert_revision(&mut connection, &first, &first_nodes, &[], None)?;
    let b = definition(21, 1)?;
    let (second, second_nodes) = revision(&goal, 2, vec![a, b], Vec::new())?;
    assert!(matches!(
        insert_revision(
            &mut connection,
            &second,
            &second_nodes,
            &[],
            Some(DagHeadRevision::new(2)?)
        ),
        Err(DagStoreError::HeadConflict)
    ));
    assert!(get_revision(&connection, goal.id(), DagRevisionNumber::new(2)?)?.is_none());
    let stored = insert_revision(
        &mut connection,
        &second,
        &second_nodes,
        &[],
        Some(DagHeadRevision::INITIAL),
    )?;
    assert_eq!(stored.head().dag_revision(), DagRevisionNumber::new(2)?);
    Ok(())
}

#[test]
fn current_head_node_transitions_recompute_readiness_and_are_cas_guarded()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(30, 0)?;
    let b = definition(31, 1)?;
    let (revision, nodes) = revision(
        &goal,
        1,
        vec![a.clone(), b.clone()],
        vec![DagEdge::new(a.id(), b.id())],
    )?;
    let _ = insert_revision(&mut connection, &revision, &nodes, &[], None)?;
    assert!(matches!(
        start_node(
            &mut connection,
            node_transition(&goal, revision.number(), &nodes[1], timestamp(20)?),
        ),
        Err(DagStoreError::Transition(
            forge_domain::DagNodeTransitionError::NotReady
        ))
    ));
    let active_a = start_node(
        &mut connection,
        node_transition(&goal, revision.number(), &nodes[0], timestamp(20)?),
    )?;
    let completed_a = active_a.complete(active_a.revision(), timestamp(21)?)?;
    assert_eq!(
        update_node(&mut connection, &completed_a, active_a.revision())?,
        completed_a
    );
    let active_b = start_node(
        &mut connection,
        node_transition(&goal, revision.number(), &nodes[1], timestamp(22)?),
    )?;
    assert_eq!(active_b.lifecycle(), &DagNodeLifecycle::Active);
    assert!(matches!(
        update_node(&mut connection, &active_b, active_b.revision()),
        Err(DagStoreError::NodeConflict)
    ));
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "One regression covers session fences and atomic DAG-node transition rollback."
)]
#[test]
fn authorized_node_transitions_require_current_attached_session_and_roll_back()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal, agent) = authorized_repository()?;
    let first = definition(60, 0)?;
    let second = definition(61, 1)?;
    let (revision, nodes) = revision(&goal, 1, vec![first, second], Vec::new())?;
    let _ = insert_revision(&mut connection, &revision, &nodes, &[], None)?;

    let unresolved_session = AgentSessionId::from_uuid(Uuid::from_u128(0x7003));
    assert!(matches!(
        start_node_authorized(
            &mut connection,
            node_transition(&goal, revision.number(), &nodes[0], timestamp(20)?),
            unresolved_session,
            agent.principal(),
            timestamp(99)?,
        ),
        Err(DagStoreError::AgentAuthorizationConflict)
    ));

    let foreign_principal =
        AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(0x7004)));
    assert!(matches!(
        start_node_authorized(
            &mut connection,
            node_transition(&goal, revision.number(), &nodes[0], timestamp(21)?),
            agent.session_id().ok_or("agent session missing")?,
            foreign_principal,
            timestamp(99)?,
        ),
        Err(DagStoreError::AgentAuthorizationConflict)
    ));

    let stale = DagNodeTransition::new(
        DagTransitionScope::new(
            goal.workspace_id(),
            goal.activity_id(),
            goal.id(),
            goal.revision(),
            revision.number(),
        ),
        nodes[0].id(),
        DagNodeRevision::new(2)?,
        timestamp(22)?,
    );
    assert!(matches!(
        start_node_authorized(
            &mut connection,
            stale,
            agent.session_id().ok_or("agent session missing")?,
            agent.principal(),
            timestamp(99)?,
        ),
        Err(DagStoreError::Transition(
            forge_domain::DagNodeTransitionError::RevisionConflict
        ))
    ));

    let active = start_node_authorized(
        &mut connection,
        node_transition(&goal, revision.number(), &nodes[0], timestamp(23)?),
        agent.session_id().ok_or("agent session missing")?,
        agent.principal(),
        timestamp(99)?,
    )?;
    assert_eq!(active.lifecycle(), &DagNodeLifecycle::Active);
    let completed = complete_node_authorized(
        &mut connection,
        DagNodeTransition::new(
            DagTransitionScope::new(
                goal.workspace_id(),
                goal.activity_id(),
                goal.id(),
                goal.revision(),
                revision.number(),
            ),
            active.id(),
            active.revision(),
            timestamp(24)?,
        ),
        agent.session_id().ok_or("agent session missing")?,
        agent.principal(),
        timestamp(99)?,
    )?;
    assert_eq!(completed.lifecycle(), &DagNodeLifecycle::Completed);

    connection.execute(
        "UPDATE agent_instances SET attachment_state = 1, revision = 2 WHERE agent_id = ?1",
        params![agent.id().into_uuid().as_bytes()],
    )?;
    assert!(matches!(
        start_node_authorized(
            &mut connection,
            node_transition(&goal, revision.number(), &nodes[1], timestamp(25)?),
            agent.session_id().ok_or("agent session missing")?,
            agent.principal(),
            timestamp(99)?,
        ),
        Err(DagStoreError::AgentAuthorizationConflict)
    ));

    let current = get_current(&connection, goal.id())?.ok_or("current DAG missing")?;
    let second = current
        .nodes()
        .iter()
        .find(|node| node.id() == nodes[1].id())
        .ok_or("second node missing")?;
    assert_eq!(second.lifecycle(), &DagNodeLifecycle::Pending);
    assert_eq!(second.revision(), DagNodeRevision::INITIAL);
    Ok(())
}

#[test]
fn completed_node_evidence_is_carried_into_the_new_revision()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(40, 0)?;
    let (first, first_nodes) = revision(&goal, 1, vec![a.clone()], Vec::new())?;
    let _ = insert_revision(&mut connection, &first, &first_nodes, &[], None)?;
    let active = start_node(
        &mut connection,
        node_transition(&goal, first.number(), &first_nodes[0], timestamp(20)?),
    )?;
    let completed = active.complete(active.revision(), timestamp(21)?)?;
    let completed = update_node(&mut connection, &completed, active.revision())?;
    let evidence_id = Uuid::from_u128(41);
    connection.execute(
        "INSERT INTO goal_evidence_refs (
                goal_id, evidence_kind, evidence_id, associated_at_ms
             ) VALUES (?1, 1, ?2, 22)",
        params![goal.id().into_uuid().as_bytes(), evidence_id.as_bytes()],
    )?;
    connection.execute(
        "INSERT INTO goal_dag_node_evidence_refs (
                goal_id, dag_revision, node_id, evidence_kind, evidence_id, associated_at_ms
             ) VALUES (?1, 1, ?2, 1, ?3, 22)",
        params![
            goal.id().into_uuid().as_bytes(),
            a.id().into_uuid().as_bytes(),
            evidence_id.as_bytes()
        ],
    )?;
    let b = definition(42, 1)?;
    let (second, mut second_nodes) = revision(&goal, 2, vec![a.clone(), b], Vec::new())?;
    let carried = completed.carry_to_revision(second.number());
    let index = second_nodes
        .iter()
        .position(|node| node.id() == a.id())
        .ok_or("carried node missing")?;
    second_nodes[index] = carried;
    let _ = insert_revision(
        &mut connection,
        &second,
        &second_nodes,
        &[],
        Some(DagHeadRevision::INITIAL),
    )?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM goal_dag_node_evidence_refs
             WHERE goal_id = ?1 AND dag_revision = 2 AND node_id = ?2",
        params![
            goal.id().into_uuid().as_bytes(),
            a.id().into_uuid().as_bytes()
        ],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn node_evidence_association_allows_goal_bound_refs_beyond_old_node_cap_and_exact_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let node_definition = definition(0x4600, 0)?;
    let (dag, nodes) = revision(&goal, 1, vec![node_definition], Vec::new())?;
    let _ = insert_revision(&mut connection, &dag, &nodes, &[], None)?;
    let active = start_node(
        &mut connection,
        node_transition(&goal, dag.number(), &nodes[0], timestamp(20)?),
    )?;
    let attribution = GoalNodeAttribution::new(
        goal.id(),
        goal.revision(),
        dag.number(),
        active.id(),
        active.revision(),
    );
    let evidence: Vec<_> = (0..33_u128)
        .map(|index| {
            GoalEvidenceRef::Execution(ExecutionId::from_uuid(Uuid::from_u128(0x4700 + index)))
        })
        .collect();
    for (index, evidence) in evidence.iter().copied().enumerate() {
        let (kind, id) = workspace_goals::encode_evidence(evidence);
        connection.execute(
            "INSERT INTO goal_evidence_refs (
                    goal_id, evidence_kind, evidence_id, associated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
            params![
                goal.id().into_uuid().as_bytes(),
                kind,
                id.as_slice(),
                30 + i64::try_from(index)?
            ],
        )?;
        let transaction = connection.transaction()?;
        associate_node_evidence_in_transaction(
            &transaction,
            Some(attribution),
            evidence,
            timestamp(30 + i64::try_from(index)?)?,
        )?;
        transaction.commit()?;
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM goal_dag_node_evidence_refs
         WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3",
        params![
            goal.id().into_uuid().as_bytes(),
            dag.number().get(),
            active.id().into_uuid().as_bytes()
        ],
        |row| row.get(0),
    )?;
    assert_eq!(count, 33);

    let transaction = connection.transaction()?;
    associate_node_evidence_in_transaction(
        &transaction,
        Some(attribution),
        evidence[0],
        timestamp(100)?,
    )?;
    transaction.commit()?;
    let retry_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM goal_dag_node_evidence_refs
         WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3",
        params![
            goal.id().into_uuid().as_bytes(),
            dag.number().get(),
            active.id().into_uuid().as_bytes()
        ],
        |row| row.get(0),
    )?;
    assert_eq!(retry_count, 33);
    Ok(())
}

#[test]
fn new_or_open_nodes_cannot_be_marked_completed_during_replanning()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(43, 0)?;
    let (first, first_nodes) = revision(&goal, 1, vec![a.clone()], Vec::new())?;

    let mut initially_completed = first_nodes.clone();
    initially_completed[0] = RegisteredDagNode::from_parts(
        goal.id(),
        first.number(),
        a.clone(),
        DagNodeLifecycle::Completed,
        timestamp(10)?,
        timestamp(11)?,
        DagNodeRevision::new(2)?,
    )?;
    assert!(matches!(
        insert_revision(&mut connection, &first, &initially_completed, &[], None),
        Err(DagStoreError::ProjectionMismatch)
    ));
    let _ = insert_revision(&mut connection, &first, &first_nodes, &[], None)?;

    let b = definition(44, 1)?;
    let (second, pending_nodes) = revision(&goal, 2, vec![a.clone(), b.clone()], Vec::new())?;
    let mut new_node_completed = pending_nodes.clone();
    new_node_completed[1] = RegisteredDagNode::from_parts(
        goal.id(),
        second.number(),
        b,
        DagNodeLifecycle::Completed,
        timestamp(20)?,
        timestamp(21)?,
        DagNodeRevision::new(2)?,
    )?;
    assert!(matches!(
        insert_revision(
            &mut connection,
            &second,
            &new_node_completed,
            &[],
            Some(DagHeadRevision::INITIAL),
        ),
        Err(DagStoreError::CompletedNodeNotCarried(id)) if id == new_node_completed[1].id()
    ));

    let mut open_node_completed = pending_nodes;
    open_node_completed[0] = RegisteredDagNode::from_parts(
        goal.id(),
        second.number(),
        a.clone(),
        DagNodeLifecycle::Completed,
        timestamp(20)?,
        timestamp(21)?,
        DagNodeRevision::new(2)?,
    )?;
    assert!(matches!(
        insert_revision(
            &mut connection,
            &second,
            &open_node_completed,
            &[],
            Some(DagHeadRevision::INITIAL),
        ),
        Err(DagStoreError::CompletedNodeChanged(id)) if id == a.id()
    ));
    assert!(get_revision(&connection, goal.id(), second.number())?.is_none());
    Ok(())
}

#[test]
fn completed_carry_requires_durable_parent_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(45, 0)?;
    let (first, first_nodes) = revision(&goal, 1, vec![a.clone()], Vec::new())?;
    let _ = insert_revision(&mut connection, &first, &first_nodes, &[], None)?;
    let active = start_node(
        &mut connection,
        node_transition(&goal, first.number(), &first_nodes[0], timestamp(20)?),
    )?;
    let completed = active.complete(active.revision(), timestamp(21)?)?;
    let _ = update_node(&mut connection, &completed, active.revision())?;

    let (second, mut second_nodes) = revision(&goal, 2, vec![a.clone()], Vec::new())?;
    second_nodes[0] = completed.carry_to_revision(second.number());
    assert!(matches!(
        insert_revision(
            &mut connection,
            &second,
            &second_nodes,
            &[],
            Some(DagHeadRevision::INITIAL),
        ),
        Err(DagStoreError::CompletedNodeEvidenceMissing(id)) if id == a.id()
    ));
    assert!(get_revision(&connection, goal.id(), second.number())?.is_none());
    Ok(())
}

#[test]
fn omitted_open_nodes_require_typed_versioned_lineage() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let a = definition(50, 0)?;
    let b = definition(51, 1)?;
    let (first, first_nodes) = revision(&goal, 1, vec![a.clone(), b.clone()], Vec::new())?;
    let _ = insert_revision(&mut connection, &first, &first_nodes, &[], None)?;
    let c = definition(52, 0)?;
    let d = definition(53, 2)?;
    let (second, second_nodes) = revision(&goal, 2, vec![c.clone(), b, d.clone()], Vec::new())?;
    assert!(matches!(
        insert_revision(
            &mut connection, &second, &second_nodes, &[], Some(DagHeadRevision::INITIAL),
        ),
        Err(DagStoreError::LineageMissing(id)) if id == a.id()
    ));
    let lineage = vec![
        DagNodeLineage::new(a.id(), c.id(), DagLineageKind::Split),
        DagNodeLineage::new(a.id(), d.id(), DagLineageKind::Split),
    ];
    let stored = insert_revision(
        &mut connection,
        &second,
        &second_nodes,
        &lineage,
        Some(DagHeadRevision::INITIAL),
    )?;
    assert_eq!(stored.lineage(), canonical_lineage(&lineage));
    assert_eq!(
        get_dag_lineage_count(&connection, goal.id(), second.number())?,
        2
    );
    Ok(())
}

#[test]
fn current_dag_doctor_projects_ready_and_pending_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let upstream = definition(0xD001, 0)?;
    let downstream = definition(0xD002, 1)?;
    let (revision, nodes) = revision(
        &goal,
        1,
        vec![upstream.clone(), downstream.clone()],
        vec![DagEdge::new(upstream.id(), downstream.id())],
    )?;
    let _ = insert_revision(&mut connection, &revision, &nodes, &[], None)?;

    let report = doctor_current(&connection, goal.workspace_id())?;
    assert!(!report.truncated());
    assert_eq!(report.findings().len(), 1);
    assert_eq!(report.findings()[0].goal_id(), goal.id());
    assert_eq!(
        report.findings()[0].dag_revision(),
        Some(DagRevisionNumber::INITIAL)
    );
    let DagDoctorState::Healthy(summary) = report.findings()[0].state() else {
        return Err("healthy DAG Doctor projection expected".into());
    };
    assert_eq!(summary.ready(), 1);
    assert_eq!(summary.pending(), 1);
    assert_eq!(summary.active(), 0);
    assert!(!report.is_damaged());
    Ok(())
}

#[test]
fn current_dag_doctor_accepts_healthy_replanned_head() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let first_node = definition(0xD009, 0)?;
    let (first, first_nodes) = revision(&goal, 1, vec![first_node.clone()], Vec::new())?;
    let _ = insert_revision(&mut connection, &first, &first_nodes, &[], None)?;

    let second_node = definition(0xD00A, 1)?;
    let (second, second_nodes) = revision(&goal, 2, vec![first_node, second_node], Vec::new())?;
    let stored = insert_revision(
        &mut connection,
        &second,
        &second_nodes,
        &[],
        Some(DagHeadRevision::INITIAL),
    )?;
    assert_eq!(stored.head().dag_revision(), DagRevisionNumber::new(2)?);
    assert_eq!(stored.head().revision(), DagHeadRevision::new(2)?);

    let report = doctor_current(&connection, goal.workspace_id())?;
    assert!(!report.truncated());
    assert_eq!(report.findings().len(), 1);
    assert_eq!(
        report.findings()[0].dag_revision(),
        Some(DagRevisionNumber::new(2)?)
    );
    let DagDoctorState::Healthy(summary) = report.findings()[0].state() else {
        return Err("healthy replanned DAG Doctor projection expected".into());
    };
    assert_eq!(summary.ready(), 2);
    assert_eq!(summary.pending(), 0);
    Ok(())
}

#[test]
fn current_dag_doctor_detects_missing_head_authority() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let node = definition(0xD00B, 0)?;
    let (revision, nodes) = revision(&goal, 1, vec![node], Vec::new())?;
    let _ = insert_revision(&mut connection, &revision, &nodes, &[], None)?;
    connection.execute(
        "DELETE FROM goal_dag_heads WHERE goal_id = ?1",
        params![goal.id().into_uuid().as_bytes()],
    )?;

    let report = doctor_current(&connection, goal.workspace_id())?;
    assert!(!report.truncated());
    assert_eq!(report.findings().len(), 1);
    assert_eq!(report.findings()[0].goal_id(), goal.id());
    assert_eq!(report.findings()[0].dag_revision(), None);
    assert_eq!(
        report.findings()[0].state(),
        DagDoctorState::Damaged(DagDoctorIssue::MissingHead)
    );
    assert!(report.is_damaged());
    Ok(())
}

#[test]
fn current_dag_doctor_detects_cycle_after_durable_edge_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let upstream = definition(0xD011, 0)?;
    let downstream = definition(0xD012, 1)?;
    let (revision, nodes) = revision(
        &goal,
        1,
        vec![upstream.clone(), downstream.clone()],
        vec![DagEdge::new(upstream.id(), downstream.id())],
    )?;
    let _ = insert_revision(&mut connection, &revision, &nodes, &[], None)?;
    connection.execute(
        "INSERT INTO goal_dag_edges (
                goal_id, dag_revision, upstream_node_id, downstream_node_id
             ) VALUES (?1, 1, ?2, ?3)",
        params![
            goal.id().into_uuid().as_bytes(),
            downstream.id().into_uuid().as_bytes(),
            upstream.id().into_uuid().as_bytes(),
        ],
    )?;
    connection.execute(
        "UPDATE goal_dag_revisions SET edge_count = 2
             WHERE goal_id = ?1 AND dag_revision = 1",
        params![goal.id().into_uuid().as_bytes()],
    )?;

    let report = doctor_current(&connection, goal.workspace_id())?;
    assert_eq!(
        report.findings()[0].state(),
        DagDoctorState::Damaged(DagDoctorIssue::Cycle)
    );
    assert!(report.is_damaged());
    Ok(())
}

#[test]
fn current_dag_doctor_detects_active_node_waiting_on_unfinished_dependency()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let upstream = definition(0xD021, 0)?;
    let downstream = definition(0xD022, 1)?;
    let (revision, nodes) = revision(
        &goal,
        1,
        vec![upstream.clone(), downstream.clone()],
        vec![DagEdge::new(upstream.id(), downstream.id())],
    )?;
    let _ = insert_revision(&mut connection, &revision, &nodes, &[], None)?;
    connection.execute(
        "UPDATE goal_dag_nodes
             SET lifecycle_state = 1, updated_at_ms = 20, node_revision = 2
             WHERE goal_id = ?1 AND dag_revision = 1 AND node_id = ?2",
        params![
            goal.id().into_uuid().as_bytes(),
            downstream.id().into_uuid().as_bytes(),
        ],
    )?;

    let report = doctor_current(&connection, goal.workspace_id())?;
    assert_eq!(
        report.findings()[0].state(),
        DagDoctorState::Damaged(DagDoctorIssue::ReadinessInvalid)
    );
    Ok(())
}

#[test]
fn current_dag_doctor_detects_impossible_lifecycle_revision_and_acceptance_gap()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, goal) = repository()?;
    let node = definition(0xD031, 0)?;
    let (revision, nodes) = revision(&goal, 1, vec![node.clone()], Vec::new())?;
    let _ = insert_revision(&mut connection, &revision, &nodes, &[], None)?;
    connection.execute(
        "UPDATE goal_dag_nodes SET node_revision = 2
             WHERE goal_id = ?1 AND dag_revision = 1 AND node_id = ?2",
        params![
            goal.id().into_uuid().as_bytes(),
            node.id().into_uuid().as_bytes(),
        ],
    )?;
    let lifecycle = doctor_current(&connection, goal.workspace_id())?;
    assert_eq!(
        lifecycle.findings()[0].state(),
        DagDoctorState::Damaged(DagDoctorIssue::LifecycleInvalid)
    );

    connection.execute(
        "UPDATE goal_dag_nodes
             SET node_revision = 1, updated_at_ms = created_at_ms
             WHERE goal_id = ?1 AND dag_revision = 1 AND node_id = ?2",
        params![
            goal.id().into_uuid().as_bytes(),
            node.id().into_uuid().as_bytes(),
        ],
    )?;
    connection.execute(
        "DELETE FROM goal_dag_node_acceptance
             WHERE goal_id = ?1 AND dag_revision = 1 AND node_id = ?2",
        params![
            goal.id().into_uuid().as_bytes(),
            node.id().into_uuid().as_bytes(),
        ],
    )?;
    let acceptance = doctor_current(&connection, goal.workspace_id())?;
    assert_eq!(
        acceptance.findings()[0].state(),
        DagDoctorState::Damaged(DagDoctorIssue::AcceptanceInvalid)
    );
    Ok(())
}

#[test]
fn current_dag_doctor_is_bounded_and_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let (mut connection, first_goal) = repository()?;
    let first_node = definition(0xD100, 0)?;
    let (first_revision, first_nodes) = revision(&first_goal, 1, vec![first_node], Vec::new())?;
    let _ = insert_revision(&mut connection, &first_revision, &first_nodes, &[], None)?;

    for offset in 1..=DAG_DOCTOR_MAX_CURRENT_DAGS {
        let seed = u128::try_from(offset)?;
        let goal = RegisteredGoal::create(
            GoalId::from_uuid(Uuid::from_u128(0xE000 + seed)),
            first_goal.workspace_id(),
            first_goal.activity_id(),
            GoalContract::new(
                GoalObjective::new(format!("Doctor bounded Goal {offset}"))?,
                vec![GoalStatement::new("DAG remains valid".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(100 + i64::try_from(offset)?)?,
        );
        let _ = workspace_goals::insert_goal(&mut connection, &goal)?;
        let definition = definition(0xF000 + seed, 0)?;
        let dag = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xF100 + seed)),
            goal.id(),
            goal.revision(),
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(200 + i64::try_from(offset)?)?,
        )?;
        let nodes = vec![RegisteredDagNode::create(
            goal.id(),
            dag.number(),
            definition,
            dag.created_at(),
        )];
        let _ = insert_revision(&mut connection, &dag, &nodes, &[], None)?;
    }

    let report = doctor_current(&connection, first_goal.workspace_id())?;
    assert_eq!(report.findings().len(), DAG_DOCTOR_MAX_CURRENT_DAGS);
    assert!(report.truncated());
    assert!(
        report
            .findings()
            .windows(2)
            .all(|window| { window[0].goal_id() < window[1].goal_id() })
    );
    Ok(())
}

fn get_dag_lineage_count(
    connection: &Connection,
    goal_id: GoalId,
    number: DagRevisionNumber,
) -> Result<i64, rusqlite::Error> {
    connection.query_row(
        "SELECT COUNT(*) FROM goal_dag_node_lineage WHERE goal_id = ?1 AND new_dag_revision = ?2",
        params![goal_id.into_uuid().as_bytes(), number.get()],
        |row| row.get(0),
    )
}
