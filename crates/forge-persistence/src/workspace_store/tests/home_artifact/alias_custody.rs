//! Native stage-quiescence coverage for old-custody Session aliases.

use super::*;

fn fixture_with_same_session_alias_writer_lease(
    label: &str,
    seed: u128,
    lease_path: &str,
) -> TestResult<Fixture> {
    let mut workspace = prepare_home_artifact_workspace(label, seed)?;
    let scope = prepare_home_artifact_goal_dag(&mut workspace, seed)?;
    let offered = offer_home_predecessor(&mut workspace, &scope, seed)?;
    let assignment = advance_home_predecessor(&mut workspace, offered, AssignmentSetup::Offered)?;

    let alias_activity_id = activity_id(seed + 900);
    workspace
        .store
        .bootstrap_activity(&forge_domain::BootstrapActivity::new(
            alias_activity_id,
            workspace.workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 901)),
            timestamp(200)?,
            timestamp(34)?,
        ))?;

    // Activate a real second-Activity Agent against the same logical Session
    // before Home Prepare captures its source inventory.
    let freeze_request = crate::AgentOperationsFreezeRequest::new(
        Uuid::from_u128(seed + 40),
        Uuid::from_u128(seed + 41),
        timestamp(35)?,
    )?;
    let freeze = workspace.store.freeze_agent_operations(&freeze_request)?;
    let delegation =
        workspace
            .store
            .delegate_agent_operations(&freeze, [0x5C; 32], timestamp(36)?)?;
    let alias_agent_id = forge_domain::AgentInstanceId::from_uuid(Uuid::from_u128(seed + 902));
    let alias_session_id = workspace
        .target_agent
        .session_id()
        .ok_or("predecessor Agent Session is missing")?;
    let reservation = crate::AgentBindingReservationRequest::new(
        Uuid::from_u128(seed + 903),
        alias_activity_id,
        alias_agent_id,
        alias_session_id,
        workspace.target_agent.principal(),
        timestamp(38)?,
    )?;
    let reserved = workspace
        .store
        .reserve_agent_binding(&freeze, &reservation, timestamp(39)?)?;
    assert_eq!(reserved.request(), &reservation);
    let activation = crate::AgentBindingActivationRequest::new(
        reservation.request_id(),
        [0x61; 32],
        forge_domain::AgentDisplayName::new("same-session alias".to_owned())?,
        forge_domain::AgentDeclaredRole::new("worker".to_owned())?,
        forge_domain::AgentTransportKind::Stdio,
    )?;
    let activated =
        workspace
            .store
            .activate_agent_binding(&delegation, &activation, timestamp(40)?)?;
    let alias_agent = workspace
        .store
        .get_agent(activated.agent_id())?
        .ok_or("activated alias Agent is missing")?;
    assert_eq!(alias_agent.activity_id(), alias_activity_id);
    assert_eq!(alias_agent.session_id(), Some(alias_session_id));
    assert_ne!(
        alias_agent.activity_id(),
        workspace.target_agent.activity_id()
    );

    let lease = acquire_writer_lease_for_path(
        &mut workspace.store,
        workspace.workspace_id,
        alias_activity_id,
        &alias_agent,
        Uuid::from_u128(seed + 904),
        WorkspaceRelativePath::new(PathBuf::from(lease_path))?,
        42,
    )?;
    assert_eq!(
        workspace.store.get_writer_lease(lease.id())?,
        Some(lease),
        "the second-Activity alias Writer Lease must be admitted before Home Prepare"
    );

    let source = prepare_home_source(&mut workspace, seed)?;
    Ok(Fixture {
        root: workspace.root,
        layout: workspace.layout,
        store: workspace.store,
        workspace_id: workspace.workspace_id,
        activity_id: workspace.activity_id,
        target_agent: workspace.target_agent,
        unaffected_agent: workspace.unaffected_agent,
        actor: workspace.actor,
        assignment,
        source,
    })
}

#[test]
fn stage_rejects_overlapping_writer_lease_from_same_session_alias_in_second_activity() -> TestResult
{
    let mut fixture = fixture_with_same_session_alias_writer_lease(
        "home-artifact-alias-overlapping-lease",
        0xAC10,
        "handoff.md",
    )?;
    let selected = intent(
        &fixture,
        0xAC20,
        0xAC30,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;

    let stage = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    );
    fs::remove_dir_all(fixture.root)?;
    assert!(
        matches!(&stage, Err(crate::HomeArtifactJournalError::Quiescence(_))),
        "overlapping old-custody alias was not rejected: {stage:?}"
    );
    Ok(())
}

#[test]
fn stage_allows_disjoint_writer_lease_from_same_session_alias_in_second_activity() -> TestResult {
    let mut fixture = fixture_with_same_session_alias_writer_lease(
        "home-artifact-alias-disjoint-lease",
        0xAC40,
        "other.md",
    )?;
    let selected = intent(
        &fixture,
        0xAC50,
        0xAC60,
        fixture.assignment.id(),
        fixture.assignment.id(),
        "handoff.md",
    )?;

    let stage = crate::workspace_home_transfers::artifacts::stage(
        &mut fixture.store.connection,
        &selected,
        fixture.actor,
        || artifact_clock(50),
    );
    fs::remove_dir_all(fixture.root)?;
    assert!(matches!(
        stage,
        Ok(crate::workspace_home_transfers::artifacts::HomeArtifactStageOutcome::Created(_))
    ));
    Ok(())
}
