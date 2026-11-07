use super::*;

#[test]
fn self_consistent_retirement_cannot_predate_its_source_ancestry() -> TestResult<()> {
    let mut fixture = fixture("retirement-ancestry-time", 0xA500)?;
    let reservation =
        pending_reservation(&mut fixture, 0xA510, AuthenticatedPrincipal::TrustedStdio)?;
    let parent = prepare_parent(&mut fixture, 0xA520, &reservation, &[])?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    let record = retirement(&mut fixture, &request, grant, 400)?
        .record()
        .clone();
    for observed_at in [299, 202] {
        let mut parts = crate::HomeTransferReservationRetirementRecordParts {
            request,
            issuer: record.issuer(),
            observed_at: timestamp(observed_at)?,
            grant_issued_at: timestamp(100)?,
            grant_expires_at: record.grant_expires_at(),
            source_inventory_digest: *record.source_inventory_digest(),
            reservation_digest: *record.reservation_digest(),
            receipt_digest: [0; 32],
        };
        parts.receipt_digest =
            crate::workspace_home_transfers::retirements::receipt_parts_digest_for_fixture(&parts);
        // Pure consistency cannot consult the reservation or parent clock.
        let _consistent = crate::HomeTransferReservationRetirementRecord::from_parts(&parts)?;
        replace_fixture_retirement_time(&mut fixture.store.connection, &parts)?;
        assert_terminal_reads_reject(&fixture, &request, &reservation);
    }
    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn replace_fixture_retirement_time(
    connection: &mut Connection,
    parts: &crate::HomeTransferReservationRetirementRecordParts,
) -> TestResult<()> {
    let transaction = connection.transaction()?;
    let original_trigger: String = transaction.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='home_transfer_reservation_retirements_no_update'",
        [],
        |row| row.get(0),
    )?;
    transaction.execute_batch("DROP TRIGGER home_transfer_reservation_retirements_no_update")?;
    assert_eq!(transaction.execute(
        "UPDATE home_transfer_reservation_retirements SET observed_at_ms=?1,grant_issued_at_ms=?2,receipt_digest=?3 WHERE preparation_id=?4 AND reservation_request_id=?5",
        params![parts.observed_at.get(),parts.grant_issued_at.get(),parts.receipt_digest.as_slice(),parts.request.preparation_id().as_bytes(),parts.request.reservation_request_id().as_bytes()],
    )?, 1);
    transaction.execute_batch(&original_trigger)?;
    transaction.commit()?;
    Ok(())
}

fn assert_terminal_reads_reject(
    fixture: &Fixture,
    request: &HomeTransferReservationRetirementRequest,
    reservation: &crate::AgentBindingReservation,
) {
    use crate::workspace_home_transfers::retirements;
    for result in [
        retirements::get(
            &fixture.store.connection,
            request.preparation_id(),
            request.reservation_request_id(),
        ),
        retirements::get_for_reservation(
            &fixture.store.connection,
            request.reservation_request_id(),
        ),
    ] {
        assert!(matches!(
            result,
            Err(crate::HomeTransferStoreError::Corrupt(_))
        ));
    }
    assert!(matches!(
        retirements::is_valid_settlement(&fixture.store.connection, reservation),
        Err(crate::HomeTransferStoreError::Corrupt(_))
    ));
}

#[test]
fn retired_agent_and_session_tuple_stay_closed_after_home_fence_disposition() -> TestResult<()> {
    let mut fixture = fixture("retirement-identity-update-guard", 0xA700)?;
    let reservation =
        pending_reservation(&mut fixture, 0xA710, AuthenticatedPrincipal::TrustedStdio)?;
    let parent = prepare_parent(&mut fixture, 0xA720, &reservation, &[])?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    let outcome = retirement(&mut fixture, &request, grant, 400)?;
    assert!(matches!(
        outcome,
        crate::HomeTransferReservationRetirementOutcome::Created(_)
    ));

    remove_home_fence_rows(&mut fixture.store.connection, request.preparation_id())?;
    // Isolate the retirement identity fence from the existing delegated-write
    // authorization triggers; this is not an authorized metadata-write flow.
    let freeze_guards = suspend_fixture_agent_freeze_guards(&fixture.store.connection)?;

    assert_retired_identity_updates_blocked(&fixture.store.connection, &reservation)?;

    restore_fixture_guards(&fixture.store.connection, &freeze_guards)?;
    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn assert_retired_identity_updates_blocked(
    connection: &Connection,
    reservation: &crate::AgentBindingReservation,
) -> TestResult<()> {
    let legacy_agent_id = id(0xA730);
    let unrelated_session_id = id(0xA731);
    connection.execute(
        "INSERT INTO agent_instances (
            agent_id, workspace_id, activity_id, display_name, declared_role,
            transport_kind, principal_kind, principal_id, attachment_state,
            created_at_ms, updated_at_ms, revision, session_id
         ) VALUES (?1, ?2, ?3, 'legacy agent', 'worker', 1, 0, NULL, 0, 204, 204, 1, NULL)",
        params![
            legacy_agent_id.as_bytes(),
            reservation.workspace_id().into_uuid().as_bytes(),
            reservation.request().activity_id().into_uuid().as_bytes(),
        ],
    )?;

    assert_eq!(
        connection.execute(
            "UPDATE agent_instances SET display_name='unrelated metadata update' WHERE agent_id=?1",
            params![legacy_agent_id.as_bytes()],
        )?,
        1,
        "metadata updates do not consult the terminal identity guard",
    );
    assert_eq!(
        connection.execute(
            "UPDATE agent_instances SET session_id=?1 WHERE agent_id=?2",
            params![unrelated_session_id.as_bytes(), legacy_agent_id.as_bytes()],
        )?,
        1,
        "an unrelated Activity/Session identity remains available",
    );
    assert_eq!(
        connection.execute(
            "UPDATE agent_instances SET session_id=?1 WHERE agent_id=?2",
            params![unrelated_session_id.as_bytes(), legacy_agent_id.as_bytes()],
        )?,
        1,
        "a no-op identity assignment remains legal",
    );

    for (sql, target, context) in [
        (
            "UPDATE agent_instances SET session_id=?1 WHERE agent_id=?2",
            reservation.request().session_id().into_uuid(),
            "retired Activity/Session tuple update was admitted",
        ),
        (
            "UPDATE agent_instances SET agent_id=?1 WHERE agent_id=?2",
            reservation.request().agent_id().into_uuid(),
            "retired Agent ID update was admitted",
        ),
    ] {
        let error = connection
            .execute(sql, params![target.as_bytes(), legacy_agent_id.as_bytes()])
            .err()
            .ok_or(context)?;
        assert!(
            error
                .to_string()
                .contains("Home reservation Agent or Activity/Session tuple was retired"),
            "unexpected identity update error: {error}",
        );
    }

    let (stored_agent_id, stored_session_id): (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT agent_id, session_id FROM agent_instances WHERE agent_id=?1",
        params![legacy_agent_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(stored_agent_id.as_slice(), legacy_agent_id.as_bytes());
    assert_eq!(
        stored_session_id.as_slice(),
        unrelated_session_id.as_bytes(),
        "rejected identity changes preserve the current binding",
    );
    Ok(())
}

fn suspend_fixture_agent_freeze_guards(connection: &Connection) -> TestResult<Vec<String>> {
    let mut guards = Vec::new();
    for name in [
        "agent_operations_freeze_agent_instances_insert_guard",
        "agent_operations_freeze_agent_instances_update_guard",
    ] {
        let sql = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get::<_, String>(0),
        )?;
        connection.execute_batch(&format!("DROP TRIGGER {name}"))?;
        guards.push(sql);
    }
    Ok(guards)
}

fn restore_fixture_guards(connection: &Connection, guards: &[String]) -> TestResult<()> {
    for sql in guards {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

fn remove_home_fence_rows(connection: &mut Connection, preparation_id: Uuid) -> TestResult<()> {
    let fence_delete_guards = [
        "home_transfer_source_subjects_no_delete",
        "home_transfer_source_sessions_no_delete",
        "home_transfer_source_agents_no_delete",
        "home_transfer_source_activities_no_delete",
    ];
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut canonical_guards = Vec::with_capacity(fence_delete_guards.len());
    for name in fence_delete_guards {
        let sql: String = transaction.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
            params![name],
            |row| row.get(0),
        )?;
        transaction.execute_batch(&format!("DROP TRIGGER {name}"))?;
        canonical_guards.push(sql);
    }
    for table in [
        "home_transfer_source_sessions",
        "home_transfer_source_agents",
        "home_transfer_source_activities",
        "home_transfer_source_subjects",
    ] {
        transaction.execute(
            &format!("DELETE FROM {table} WHERE preparation_id=?1"),
            params![preparation_id.as_bytes()],
        )?;
    }
    for sql in canonical_guards {
        transaction.execute_batch(&sql)?;
    }
    transaction.commit()?;
    Ok(())
}

#[test]
fn terminal_reads_reject_corrupt_retirement_with_materialized_reserved_agent() -> TestResult<()> {
    let mut fixture = fixture("retirement-materialized-agent-corruption", 0xA800)?;
    let reservation =
        pending_reservation(&mut fixture, 0xA810, AuthenticatedPrincipal::TrustedStdio)?;
    let parent = prepare_parent(&mut fixture, 0xA820, &reservation, &[])?;
    let request = retirement_request(&fixture, &parent, &reservation)?;
    let grant = retirement_grant(&request, fixture.issuer)?;
    let outcome = retirement(&mut fixture, &request, grant, 400)?;
    assert!(matches!(
        outcome,
        crate::HomeTransferReservationRetirementOutcome::Created(_)
    ));

    let connection = &mut fixture.store.connection;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let freeze_guards = suspend_fixture_agent_freeze_guards(&transaction)?;
    let materialization_guard: String = transaction.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type='trigger' AND name='agent_instances_block_home_reservation_retirement'",
        [],
        |row| row.get(0),
    )?;
    transaction.execute_batch("DROP TRIGGER agent_instances_block_home_reservation_retirement")?;
    transaction.execute(
        "INSERT INTO agent_instances (
            agent_id, workspace_id, activity_id, display_name, declared_role,
            transport_kind, principal_kind, principal_id, attachment_state,
            created_at_ms, updated_at_ms, revision, session_id
         ) VALUES (?1, ?2, ?3, 'corrupt retired agent', 'worker', 1, 0, NULL, 0, 204, 204, 1, ?4)",
        params![
            reservation.request().agent_id().into_uuid().as_bytes(),
            reservation.workspace_id().into_uuid().as_bytes(),
            reservation.request().activity_id().into_uuid().as_bytes(),
            reservation.request().session_id().into_uuid().as_bytes(),
        ],
    )?;
    transaction.execute_batch(&materialization_guard)?;
    restore_fixture_guards(&transaction, &freeze_guards)?;
    transaction.commit()?;
    crate::workspace_home_transfers::retirements::schema::validate_schema(
        &fixture.store.connection,
    )?;

    assert_terminal_reads_reject(&fixture, &request, &reservation);

    drop(fixture.store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}
