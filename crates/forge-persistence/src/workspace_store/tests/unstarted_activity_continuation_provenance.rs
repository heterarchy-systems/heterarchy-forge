//! Focused p28 provenance regressions for unstarted continuation.

use super::*;

use rusqlite::params;
use uuid::Uuid;

fn provenance_digest(fixture: &FileFactFixture) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let workspace_id = fixture.store.workspace()?.id();
    Ok(
        crate::workspace_store::unstarted_activity_continuation::provenance::validate_and_digest_p28_provenance_for_test(
            &fixture.store.connection,
            workspace_id,
            fixture.activity.id(),
        )?,
    )
}

#[test]
fn real_p28_recovery_provenance_validates_and_hashes_every_canonical_row()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, _assignment) =
        super::unstarted_activity_continuation::recovered_predecessor_fixture(
            "unstarted-provenance-positive",
            0xB100,
        )?;
    let first = provenance_digest(&fixture)?;
    let repeated = provenance_digest(&fixture)?;
    assert_ne!(first, [0; 32]);
    assert_eq!(first, repeated);

    let (other, _delegation, _assignment) =
        super::unstarted_activity_continuation::recovered_predecessor_fixture(
            "unstarted-provenance-full-row-sensitivity",
            0xB200,
        )?;
    let other_digest = provenance_digest(&other)?;
    assert_ne!(first, other_digest);

    let root = fixture.root.clone();
    let other_root = other.root.clone();
    drop(fixture);
    drop(other);
    std::fs::remove_dir_all(root)?;
    std::fs::remove_dir_all(other_root)?;
    Ok(())
}

#[test]
fn mismatched_successor_provenance_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, _assignment) =
        super::unstarted_activity_continuation::recovered_predecessor_fixture(
            "unstarted-provenance-mismatch",
            0xB300,
        )?;
    fixture.store.connection.execute(
        "UPDATE activity_successors SET runtime_instance_id=?1 WHERE successor_activity_id=?2",
        params![
            Uuid::from_u128(0xB3FF).as_bytes(),
            fixture.activity.id().into_uuid().as_bytes(),
        ],
    )?;
    assert!(provenance_digest(&fixture).is_err());

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn missing_recovery_agent_counterpart_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, _assignment) =
        super::unstarted_activity_continuation::recovered_predecessor_fixture(
            "unstarted-provenance-missing-agent",
            0xB400,
        )?;
    fixture.store.connection.execute(
        "DELETE FROM expired_activity_recovery_agents
         WHERE request_id=(SELECT request_id FROM expired_activity_recovery_receipts WHERE successor_activity_id=?1)
           AND ordinal=(SELECT MAX(ordinal) FROM expired_activity_recovery_agents
                        WHERE request_id=(SELECT request_id FROM expired_activity_recovery_receipts WHERE successor_activity_id=?1))",
        params![fixture.activity.id().into_uuid().as_bytes()],
    )?;
    assert!(provenance_digest(&fixture).is_err());

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn corrupt_redundant_receipt_state_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _delegation, _assignment) =
        super::unstarted_activity_continuation::recovered_predecessor_fixture(
            "unstarted-provenance-corrupt-receipt",
            0xB500,
        )?;
    fixture
        .store
        .connection
        .execute_batch("PRAGMA ignore_check_constraints=ON")?;
    fixture.store.connection.execute(
        "UPDATE expired_activity_recovery_receipts
         SET predecessor_before_state=0
         WHERE successor_activity_id=?1",
        params![fixture.activity.id().into_uuid().as_bytes()],
    )?;
    assert!(provenance_digest(&fixture).is_err());

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
