use super::*;
use forge_backend::{ForgeHttpClient, ForgeHttpClientError, ForgeHttpServiceCode};
use forge_control::{
    AgentBindingReserveRequest, HomeTransferSourceCommand, HomeTransferSourceOperation,
    HomeTransferSourceResponse, HomeTransferSourceService,
};
use forge_domain::{
    HomeTransferReservationRetirementGrant, HomeTransferReservationRetirementRequest,
    HomeTransferSourceAction, HomeTransferSourceGrant,
};
use forge_persistence::{AgentBindingReservationRequest, HomeTransferSourceRecord};

struct RetirementCase {
    service: HomeTransferSourceService,
    parent: HomeTransferSourceRecord,
    request: HomeTransferReservationRetirementRequest,
    grant: HomeTransferReservationRetirementGrant,
}

fn prepare_unused_case(fixture: &Fixture) -> TestResult<RetirementCase> {
    let destination = delegated_destination_id(fixture)?;
    let activity = bootstrap_extra_activity(fixture)?;
    let delegation = fixture
        .client
        .agent_operations_delegation(forge_control::AgentOperationsDelegationReadRequest {
            scope: fixture.scope.clone(),
        })?
        .ok_or("delegation missing")?;
    let reservation_request = AgentBindingReservationRequest::new(
        Uuid::now_v7(),
        activity,
        AgentInstanceId::from_uuid(Uuid::now_v7()),
        fixture.session_id,
        AuthenticatedPrincipal::TrustedStdio,
        timestamp_now()?,
    )?;
    let reservation = fixture
        .client
        .reserve_agent_binding(AgentBindingReserveRequest {
            scope: fixture.scope.clone(),
            freeze: delegation.freeze().clone(),
            reservation: reservation_request,
            observed_at: timestamp_now()?,
        })?;
    close_target_session(fixture)?;
    let service = HomeTransferSourceService {
        issuer: forge_domain::OrchestrationIssuerId::from_uuid(ISSUER_ID),
        backend_id: ForgeBackendId::from_uuid(BACKEND_ID),
        destination_id: destination,
    };
    let request = source_request(fixture, destination, Uuid::now_v7(), 0xD100)?;
    let now = timestamp_now()?;
    let parent = fixture
        .client
        .home_transfer_source(HomeTransferSourceCommand {
            scope: fixture.scope.clone(),
            service,
            operation: HomeTransferSourceOperation::Prepare {
                grant: HomeTransferSourceGrant::new(
                    service.issuer,
                    HomeTransferSourceAction::Prepare,
                    request.request_digest(),
                    now,
                    add_millis(now, 30_000)?,
                )?,
                request: request.clone(),
            },
        })?;
    let HomeTransferSourceResponse::Outcome(parent) = parent else {
        return Err("native preparation did not return its original".into());
    };
    assert!(
        parent
            .captured_pending_binding_reservation_ids()?
            .contains(&reservation.request().request_id())
    );
    let request = HomeTransferReservationRetirementRequest::new(
        request.scope(),
        request.witness().preparation_id(),
        request.request_digest(),
        *parent.outcome_digest(),
        reservation.request().request_id(),
    )?;
    let now = timestamp_now()?;
    let grant = HomeTransferReservationRetirementGrant::new(
        service.issuer,
        request.request_digest(),
        now,
        add_millis(now, 30_000)?,
    )?;
    Ok(RetirementCase {
        service,
        parent,
        request,
        grant,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_reservation_retirement_unknown_reply_recovers_exactly_with_closed_session()
-> TestResult<()> {
    let (running, held, _admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let observed = async {
        // Native setup bypasses the HTTP reply holder; retirement is the first
        // actual HTTP command. The synthetic Ops witness is not Ops integration.
        let case = prepare_unused_case(&running.fixture)?;
        let client = ForgeHttpClient::new(
            running.address,
            SECRET,
            case.service.backend_id,
            case.service.destination_id,
            Duration::from_secs(5),
        )?;
        let command = HomeTransferSourceCommand {
            scope: running.fixture.scope.clone(),
            service: case.service,
            operation: HomeTransferSourceOperation::RetireUnusedReservation {
                request: case.request,
                grant: case.grant,
            },
        };
        let prepared = client.prepare_home_transfer_source_command(&command, Uuid::now_v7())?;
        let Err(error) = client.send_prepared_home_transfer_source(&prepared).await else {
            return Err("withheld retirement response was not uncertain".into());
        };
        assert!(error.is_unknown_outcome());
        assert!(matches!(
            error.cause(),
            ForgeHttpClientError::Service {
                status: 202,
                code: ForgeHttpServiceCode::UnknownOutcome,
            }
        ));
        assert_eq!(error.prepared(), Some(&prepared));
        let lookup = prepared
            .reservation_retirement_readback_command(&running.fixture.scope)
            .ok_or("uncertain mutation lost exact retirement lookup")?;
        let record = get_retirement_until_present(&client, &lookup).await?;
        assert_eq!(record.request(), &case.request);
        Ok::<_, Box<dyn std::error::Error>>((client, case, prepared, record))
    }
    .await;
    let released = held.release_and_wait().await;
    let result = async {
        let (client, case, prepared, original) = observed?;
        released?;
        let replay = client.send_prepared_home_transfer_source(&prepared).await?;
        assert_eq!(
            replay,
            HomeTransferSourceResponse::ReservationRetirementOutcome(original.clone())
        );
        assert_parent_unchanged(&client, &running.fixture, &case).await?;
        assert_changed_retirement_conflicts(&client, &running.fixture, &case, &original).await
    }
    .await;
    let finished = running.finish().await;
    result?;
    finished
}

async fn get_retirement_until_present(
    client: &ForgeHttpClient,
    lookup: &HomeTransferSourceCommand,
) -> TestResult<forge_persistence::HomeTransferReservationRetirementRecord> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..100 {
            let prepared = client.prepare_home_transfer_source_command(lookup, Uuid::now_v7())?;
            match client.send_prepared_home_transfer_source(&prepared).await? {
                HomeTransferSourceResponse::ReservationRetirementRecord(Some(record)) => {
                    return Ok(record);
                }
                HomeTransferSourceResponse::ReservationRetirementRecord(None) => {
                    tokio::task::yield_now().await;
                }
                _ => return Err("retirement Get returned a mutation outcome".into()),
            }
        }
        Err("retirement was not observed within the bounded readback loop".into())
    })
    .await?
}

async fn assert_parent_unchanged(
    client: &ForgeHttpClient,
    fixture: &Fixture,
    case: &RetirementCase,
) -> TestResult<()> {
    let command = HomeTransferSourceCommand {
        scope: fixture.scope.clone(),
        service: case.service,
        operation: HomeTransferSourceOperation::Get {
            preparation_id: case.request.preparation_id(),
            request_digest: case.request.source_request_digest(),
        },
    };
    let prepared = client.prepare_home_transfer_source_command(&command, Uuid::now_v7())?;
    assert_eq!(
        client.send_prepared_home_transfer_source(&prepared).await?,
        HomeTransferSourceResponse::Record(Some(case.parent.clone()))
    );
    Ok(())
}

async fn assert_changed_retirement_conflicts(
    client: &ForgeHttpClient,
    fixture: &Fixture,
    case: &RetirementCase,
    original: &forge_persistence::HomeTransferReservationRetirementRecord,
) -> TestResult<()> {
    let mut wrong_parent = case.request.source_outcome_digest();
    wrong_parent[0] ^= 1;
    let changed = HomeTransferReservationRetirementRequest::new(
        case.request.scope(),
        case.request.preparation_id(),
        case.request.source_request_digest(),
        wrong_parent,
        case.request.reservation_request_id(),
    )?;
    let command = HomeTransferSourceCommand {
        scope: fixture.scope.clone(),
        service: case.service,
        operation: HomeTransferSourceOperation::RetireUnusedReservation {
            request: changed,
            grant: HomeTransferReservationRetirementGrant::new(
                case.service.issuer,
                changed.request_digest(),
                case.grant.issued_at(),
                case.grant.expires_at(),
            )?,
        },
    };
    let prepared = client.prepare_home_transfer_source_command(&command, Uuid::now_v7())?;
    let Err(error) = client.send_prepared_home_transfer_source(&prepared).await else {
        return Err("changed retirement replaced the original".into());
    };
    assert!(!error.is_unknown_outcome());
    assert!(matches!(
        error.cause(),
        ForgeHttpClientError::Service { status: 409, .. }
    ));
    let lookup = HomeTransferSourceCommand {
        scope: fixture.scope.clone(),
        service: case.service,
        operation: HomeTransferSourceOperation::GetReservationRetirement {
            preparation_id: case.request.preparation_id(),
            reservation_request_id: case.request.reservation_request_id(),
            request_digest: case.request.request_digest(),
        },
    };
    assert_eq!(
        &get_retirement_until_present(client, &lookup).await?,
        original
    );
    assert_parent_unchanged(client, fixture, case).await
}
