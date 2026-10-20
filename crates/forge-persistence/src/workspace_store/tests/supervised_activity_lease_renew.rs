//! Same-transaction Goal and Coordinator fences for host-supervised renewals.

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct SupervisedRenewFixture {
    fixture: FileFactFixture,
    actor: forge_domain::ActivityCoordinatorActor,
    assignment: forge_domain::RegisteredAgentAssignment,
    goal_id: GoalId,
    goal_created_at: TimestampMillis,
    command: RenewActivityLease,
}

fn supervised_renew_fixture(label: &str, seed: u128) -> TestResult<SupervisedRenewFixture> {
    let mut fixture = file_fact_fixture(label, seed)?;
    let workspace_id = fixture.store.workspace()?.id();
    let activity_id = fixture.activity.id();
    let assignment =
        seed_assignment_for_offer_seal_migration(&mut fixture.store, workspace_id, activity_id)?;
    let coordinator = fixture
        .store
        .get_activity_coordinator(activity_id)?
        .ok_or("Coordinator missing")?;
    let agent = fixture
        .store
        .get_agent(coordinator.agent_id())?
        .ok_or("Coordinator Agent missing")?;
    let session_id = agent.session_id().ok_or("Coordinator Session missing")?;
    let actor = forge_domain::ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        agent.id(),
        coordinator.revision(),
        agent.principal(),
        session_id,
    );
    let goal_id = assignment.goal_id();
    let goal = fixture.store.get_goal(goal_id)?.ok_or("Goal missing")?;
    assert_eq!(goal.status().kind(), forge_domain::GoalStatusKind::Active);
    fixture.store.connection.execute(
        "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
        params![5_000_i64, activity_id.into_uuid().as_bytes().as_slice()],
    )?;
    let command = RenewActivityLease::new(
        activity_id,
        fixture.owner,
        fixture.activity.lease_revision(),
        timestamp(6_000)?,
        timestamp(2_000)?,
    );
    Ok(SupervisedRenewFixture {
        fixture,
        actor,
        assignment,
        goal_id,
        goal_created_at: goal.timestamps().created_at(),
        command,
    })
}

#[test]
fn supervised_renew_reuses_lease_cas_when_goal_and_coordinator_match() -> TestResult {
    let mut scenario = supervised_renew_fixture("supervised-renew-valid", 0xDA_1000)?;
    let before = scenario
        .fixture
        .store
        .get_activity(scenario.command.id())?
        .ok_or("Activity missing")?;
    let renewed = scenario
        .fixture
        .store
        .renew_activity_lease_with_supervision_guard(
            &scenario.command,
            scenario.actor,
            scenario.goal_id,
            scenario.goal_created_at,
        )?;
    assert_eq!(renewed.id(), before.id());
    assert_eq!(renewed.state(), before.state());
    assert_eq!(renewed.revision(), before.revision());
    assert_eq!(renewed.created_at(), before.created_at());
    assert_eq!(renewed.updated_at(), before.updated_at());
    assert_eq!(renewed.lease_owner_id(), Some(scenario.fixture.owner));
    assert_eq!(renewed.lease_until(), Some(timestamp(6_000)?));
    assert_eq!(
        renewed.lease_revision().get(),
        before.lease_revision().get() + 1
    );
    fs::remove_dir_all(&scenario.fixture.root)?;
    Ok(())
}

#[test]
fn supervised_renew_rejects_goal_terminalized_after_host_precheck() -> TestResult {
    let mut scenario = supervised_renew_fixture("supervised-renew-goal-terminal", 0xDA_2000)?;
    let goal = scenario
        .fixture
        .store
        .get_goal(scenario.goal_id)?
        .ok_or("Goal missing")?;
    let cancelled = goal.cancel(goal.revision(), timestamp(3_000)?)?;
    let _updated_goal = scenario.fixture.store.update_goal(
        scenario.actor,
        &cancelled,
        goal.revision(),
        timestamp(3_000)?,
    )?;
    let before = scenario
        .fixture
        .store
        .get_activity(scenario.command.id())?
        .ok_or("Activity missing")?;
    assert!(matches!(
        scenario.fixture.store.renew_activity_lease_with_supervision_guard(
            &scenario.command,
            scenario.actor,
            scenario.goal_id,
            scenario.goal_created_at,
        ),
        Err(WorkspaceStoreError::ActivityLeaseUnavailable(activity_id))
            if activity_id == scenario.command.id()
    ));
    assert_eq!(
        scenario.fixture.store.get_activity(scenario.command.id())?,
        Some(before)
    );
    fs::remove_dir_all(&scenario.fixture.root)?;
    Ok(())
}

#[test]
fn supervised_renew_rejects_coordinator_transfer_after_host_precheck() -> TestResult {
    let mut scenario =
        supervised_renew_fixture("supervised-renew-coordinator-transfer", 0xDA_3000)?;
    let activity_id = scenario.command.id();
    let _transfer = scenario.fixture.store.transfer_activity_coordinator(
        forge_domain::TransferActivityCoordinator::new(
            scenario.actor,
            scenario.assignment.target().agent_id(),
            timestamp(3_000)?,
        ),
        timestamp(3_000)?,
    )?;
    let before = scenario
        .fixture
        .store
        .get_activity(activity_id)?
        .ok_or("Activity missing")?;
    assert!(matches!(
        scenario.fixture.store.renew_activity_lease_with_supervision_guard(
            &scenario.command,
            scenario.actor,
            scenario.goal_id,
            scenario.goal_created_at,
        ),
        Err(WorkspaceStoreError::ActivityLeaseUnavailable(id)) if id == activity_id
    ));
    assert_eq!(
        scenario.fixture.store.get_activity(activity_id)?,
        Some(before)
    );
    fs::remove_dir_all(&scenario.fixture.root)?;
    Ok(())
}
