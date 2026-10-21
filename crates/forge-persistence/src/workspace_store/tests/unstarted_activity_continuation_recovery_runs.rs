//! Real Source boots record recovery classification runs. Zero-effect runs are
//! admissible history; effectful or inconsistent runs fail closed.

use super::unstarted_activity_continuation::{probe, recovered_predecessor_fixture};
use super::*;

use forge_domain::{
    ExecutionListLimit, RecoveryLeaseDurationMillis, RuntimeInstanceId,
    UnstartedActivityContinuationBlocker,
};
use rusqlite::params;
use uuid::Uuid;

fn record_boot_recovery_run(
    fixture: &mut FileFactFixture,
    seed: u128,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let binding = fixture.store.journal_binding()?;
    let request = crate::RecoveryRunRequest::new(
        (
            Uuid::from_u128(seed),
            binding.workspace_id(),
            RuntimeInstanceId::from_uuid(Uuid::from_u128(seed + 1)),
        ),
        [0x61; 32],
        binding.recovery_history_digest(),
        RecoveryLeaseDurationMillis::new(5_000)?,
        (timestamp(1_200)?, timestamp(1_200)?),
        (ActivityListLimit::DEFAULT, ExecutionListLimit::DEFAULT),
    )?;
    let crate::RecoveryRunOperation::Recorded {
        activities,
        executions,
        ..
    } = fixture.store.run_recovery_request(&binding, &request)?
    else {
        return Err("boot recovery run was not recorded".into());
    };
    assert!(
        activities.is_empty() && executions.is_empty(),
        "attached unstarted team must not be interrupted by boot recovery"
    );
    Ok(request.request_id)
}

fn cleanup(fixture: FileFactFixture) -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_v66_zero_effect_boot_recovery_run_remains_continuable()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, _delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-boot-run", 0xF600)?;
    let before = probe(&fixture, &assignment)?;
    assert!(before.continuable_now(), "{:?}", before.blocker());
    let _run = record_boot_recovery_run(&mut fixture, 0xF6A0)?;
    let after = probe(&fixture, &assignment)?;
    assert!(after.continuable_now(), "{:?}", after.blocker());
    assert_eq!(
        after.expectation().expected_plan_digest(),
        before.expectation().expected_plan_digest(),
        "transient boot classification history is not plan content"
    );
    assert_eq!(
        fixture.store.get_activity(fixture.activity.id())?,
        Some(fixture.activity.clone()),
        "probe and zero-effect run leave the expired Activity untouched"
    );
    cleanup(fixture)
}

#[test]
fn canonical_v66_effectful_or_inconsistent_recovery_run_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, _delegation, assignment) =
        recovered_predecessor_fixture("unstarted-continuation-run-mismatch", 0xF700)?;
    let run = record_boot_recovery_run(&mut fixture, 0xF7A0)?;
    let predecessor: Vec<u8> = fixture.store.connection.query_row(
        "SELECT activity_id FROM activities WHERE activity_id != ?1",
        params![fixture.activity.id().into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    fixture.store.connection.execute(
        "INSERT INTO recovery_run_activities(
            request_id, ordinal, activity_id, workspace_id, before_state, before_revision,
            before_created_at_ms, before_updated_at_ms, before_lease_owner_id,
            before_lease_until_ms, before_lease_revision, after_revision,
            after_updated_at_ms, after_lease_revision
         ) VALUES (?1, 0, ?2, ?3, 1, 1, 10, 10, ?4, 50, 1, 2, 60, 2)",
        params![
            run.as_bytes(),
            predecessor,
            fixture.store.workspace()?.id().into_uuid().as_bytes(),
            Uuid::from_u128(0xF7B0).as_bytes(),
        ],
    )?;
    assert_eq!(
        probe(&fixture, &assignment)?.blocker(),
        Some(UnstartedActivityContinuationBlocker::OrphanRecord),
        "child rows hidden behind a zero declared count are corrupt provenance"
    );
    fixture.store.connection.execute(
        "UPDATE recovery_runs SET activity_count=1 WHERE request_id=?1",
        params![run.as_bytes()],
    )?;
    assert_eq!(
        probe(&fixture, &assignment)?.blocker(),
        Some(UnstartedActivityContinuationBlocker::PhysicalEffectPresent),
        "a recovery run that interrupted any Activity is not unstarted history"
    );
    cleanup(fixture)
}
