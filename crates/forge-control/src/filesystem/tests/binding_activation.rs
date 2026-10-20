use super::*;
use crate::EffectFactOutboxReadRequest;
use crate::{
    AgentBindingActivateRequest, AgentBindingActivationReadRequest, AgentBindingReserveRequest,
    AgentEffectOutboxReadRequest, AgentOperationsDelegationRequest, ControlErrorCode,
};
use forge_domain::{
    AgentDeclaredRole, AgentDisplayName, AgentSessionId, AgentSessionOpenRequestId,
    AgentTransportKind, AuthenticatedPrincipal, DirectTokenId, OpenAgentSession,
};
use forge_persistence::{
    AgentBindingActivationRequest, AgentBindingReservationRequest, AgentEffectFact,
    AgentOperationsFreezeRequest,
};
use forge_workspace::WorkspaceStateLayout;

#[test]
fn native_activation_rechecks_session_identity_and_work_destination()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("binding-activation")?;
    let principal = AuthenticatedPrincipal::TrustedStdio;
    let session = fixture.control.agent_session_open(&OpenAgentSession::new(
        AgentSessionId::from_uuid(id(0xBA01)),
        AgentSessionOpenRequestId::from_uuid(id(0xBA02)),
        principal,
        timestamp(15)?,
    ))?;
    let foreign_principal =
        AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(0xBA03)));
    let foreign_session = fixture.control.agent_session_open(&OpenAgentSession::new(
        AgentSessionId::from_uuid(id(0xBA04)),
        AgentSessionOpenRequestId::from_uuid(id(0xBA05)),
        foreign_principal,
        timestamp(16)?,
    ))?;

    let activate = prepare_activation(&fixture, session.session().id(), principal)?;
    let request_id = activate.activation.request_id();
    let receipt = fixture.control.activate_agent_binding(&activate)?;
    assert_eq!(receipt.request_id(), request_id);
    assert_eq!(
        fixture
            .control
            .activate_agent_binding(&AgentBindingActivateRequest {
                observed_at: timestamp(99)?,
                ..activate.clone()
            })?,
        receipt
    );

    let foreign_activation = AgentBindingActivateRequest {
        session_id: foreign_session.session().id(),
        principal: foreign_principal,
        ..activate.clone()
    };
    assert_eq!(
        fixture
            .control
            .activate_agent_binding(&foreign_activation)
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::AgentSessionConflict)
    );
    assert_eq!(
        fixture
            .control
            .agent_binding_activation(&AgentBindingActivationReadRequest {
                scope: fixture.scope.clone(),
                request_id,
                session_id: foreign_session.session().id(),
                principal: foreign_principal,
            })?,
        None
    );

    assert_agent_effect_outbox_boundaries(&fixture, &activate)?;
    assert_effect_fact_outbox_boundaries(&fixture, &activate)?;

    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn assert_agent_effect_outbox_boundaries(
    fixture: &Fixture,
    activate: &AgentBindingActivateRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrong_destination = AgentEffectOutboxReadRequest {
        scope: fixture.scope.clone(),
        destination_id: id(0xBAFF),
        after: 0,
        limit: 64,
    };
    assert_eq!(
        fixture
            .control
            .agent_effect_outbox(&wrong_destination)
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::AgentConflict)
    );
    let facts = fixture
        .control
        .agent_effect_outbox(&AgentEffectOutboxReadRequest {
            scope: fixture.scope.clone(),
            destination_id: activate.delegation.destination_id(),
            after: 0,
            limit: 64,
        })?;
    assert_eq!(facts.len(), 1);
    assert!(matches!(facts[0].fact(), AgentEffectFact::Focus(_)));

    Ok(())
}

fn assert_effect_fact_outbox_boundaries(
    fixture: &Fixture,
    activate: &AgentBindingActivateRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrong_effect_destination = EffectFactOutboxReadRequest {
        scope: fixture.scope.clone(),
        migration_id: activate.delegation.migration_id(),
        destination_id: id(0xBAFE),
        after: 0,
        limit: 64,
    };
    assert_eq!(
        fixture
            .control
            .effect_fact_outbox(&wrong_effect_destination)
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::AgentConflict)
    );
    let wrong_effect_migration = EffectFactOutboxReadRequest {
        scope: fixture.scope.clone(),
        migration_id: id(0xBAFD),
        destination_id: activate.delegation.destination_id(),
        after: 0,
        limit: 64,
    };
    assert_eq!(
        fixture
            .control
            .effect_fact_outbox(&wrong_effect_migration)
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::AgentConflict)
    );
    assert_eq!(
        fixture
            .control
            .effect_fact_outbox(&EffectFactOutboxReadRequest {
                scope: fixture.scope.clone(),
                migration_id: activate.delegation.migration_id(),
                destination_id: activate.delegation.destination_id(),
                after: 0,
                limit: 0,
            })
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::InvalidInput)
    );
    assert_eq!(
        fixture
            .control
            .effect_fact_outbox(&EffectFactOutboxReadRequest {
                scope: fixture.scope.clone(),
                migration_id: activate.delegation.migration_id(),
                destination_id: activate.delegation.destination_id(),
                after: 0,
                limit: 65,
            })
            .err()
            .map(|error| error.code()),
        Some(ControlErrorCode::CapacityExceeded)
    );
    assert!(
        fixture
            .control
            .effect_fact_outbox(&EffectFactOutboxReadRequest {
                scope: fixture.scope.clone(),
                migration_id: activate.delegation.migration_id(),
                destination_id: activate.delegation.destination_id(),
                after: 0,
                limit: 64,
            })?
            .is_empty(),
        "activation alone must not fabricate Forge-owned effect facts"
    );

    Ok(())
}

fn prepare_activation(
    fixture: &Fixture,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> Result<AgentBindingActivateRequest, Box<dyn std::error::Error>> {
    let layout =
        WorkspaceStateLayout::inspect_existing(workspace_root(fixture))?.ok_or("layout missing")?;
    let mut store = forge_persistence::WorkspaceStore::open_existing(&layout)?;
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        id(0xBA10),
        id(0xBA11),
        timestamp(20)?,
    )?)?;
    drop(store);

    let request_id = id(0xBA12);
    let reservation = AgentBindingReservationRequest::new(
        request_id,
        fixture.activity.activity_id,
        forge_domain::AgentInstanceId::from_uuid(id(0xBA13)),
        session_id,
        principal,
        timestamp(21)?,
    )?;
    let reserve = AgentBindingReserveRequest {
        scope: fixture.scope.clone(),
        freeze: freeze.clone(),
        reservation,
        observed_at: timestamp(22)?,
    };
    let _reserved = fixture.control.reserve_agent_binding(&reserve)?;

    let delegated =
        fixture
            .control
            .delegate_agent_operations(&AgentOperationsDelegationRequest {
                scope: fixture.scope.clone(),
                freeze,
                manifest_digest: [0xBA; 32],
                observed_at: timestamp(23)?,
            })?;
    let activation = AgentBindingActivationRequest::new(
        request_id,
        [0xBB; 32],
        AgentDisplayName::new("native-worker".to_owned())?,
        AgentDeclaredRole::new("worker".to_owned())?,
        AgentTransportKind::Stdio,
    )?;
    Ok(AgentBindingActivateRequest {
        scope: fixture.scope.clone(),
        delegation: delegated,
        activation,
        session_id,
        principal,
        observed_at: timestamp(24)?,
    })
}

#[test]
fn delegated_departure_reconciles_through_the_control_worker()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{AgentDepartureReconcileReadRequest, AgentDepartureReconcileRequest};
    use forge_domain::{AgentInstanceRevision, DetachAgent};
    use forge_persistence::{AgentDepartureCommand, AgentDepartureReconciliationRequest};

    let fixture = fixture("agent-departure")?;
    let principal = AuthenticatedPrincipal::TrustedStdio;
    let source_session = fixture.control.agent_session_open(&OpenAgentSession::new(
        AgentSessionId::from_uuid(id(0xBD01)),
        AgentSessionOpenRequestId::from_uuid(id(0xBD02)),
        principal,
        timestamp(15)?,
    ))?;
    let foreign_session = fixture.control.agent_session_open(&OpenAgentSession::new(
        AgentSessionId::from_uuid(id(0xBD03)),
        AgentSessionOpenRequestId::from_uuid(id(0xBD04)),
        principal,
        timestamp(16)?,
    ))?;
    let foreign_session_id = foreign_session.session().id();

    let activate = prepare_activation(&fixture, source_session.session().id(), principal)?;
    let activated = fixture.control.activate_agent_binding(&activate)?;
    let agent_id = activated.reservation().request().agent_id();
    let request_id = id(0xBD10);
    let reconciliation = AgentDepartureReconciliationRequest::new(
        request_id,
        AgentDepartureCommand::Detach(DetachAgent::new(
            agent_id,
            fixture.activity.activity_id,
            AgentInstanceRevision::INITIAL,
            timestamp(30)?,
        )),
        source_session.session().id(),
        principal,
        [0x77; 32],
    )?;
    let scope = fixture.scope.clone();
    let migration_id = activate.delegation.migration_id();
    let destination_id = activate.delegation.destination_id();
    let (client, mut worker) = crate::worker::ForgeControlWorker::start(fixture.control)?;
    assert!(
        client
            .effect_fact_outbox(EffectFactOutboxReadRequest {
                scope: scope.clone(),
                migration_id,
                destination_id,
                after: 0,
                limit: 64,
            })?
            .is_empty(),
        "the worker must round-trip an empty generic effect-fact page"
    );
    let receipt = client.reconcile_agent_departure(AgentDepartureReconcileRequest {
        scope: scope.clone(),
        reconciliation,
    })?;
    assert_eq!(receipt.request_id(), request_id);
    assert_eq!(receipt.agent_id(), agent_id);
    assert_eq!(receipt.session_id(), source_session.session().id());
    assert_eq!(
        receipt.result_agent_revision().get(),
        AgentInstanceRevision::INITIAL.get() + 1
    );
    assert_eq!(
        client.agent_departure_reconciliation(AgentDepartureReconcileReadRequest {
            scope: scope.clone(),
            request_id,
            session_id: source_session.session().id(),
            principal,
        })?,
        Some(receipt)
    );
    assert_eq!(
        client.agent_departure_reconciliation(AgentDepartureReconcileReadRequest {
            scope,
            request_id,
            session_id: foreign_session_id,
            principal,
        })?,
        None,
        "a departure receipt must be hidden from foreign sessions"
    );

    worker.shutdown()?;
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
