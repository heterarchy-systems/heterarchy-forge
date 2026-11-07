use std::{
    error::Error,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header::HeaderValue},
    response::Response,
    routing::post,
};
use base64::Engine as _;
use forge_control::{
    HomeTransferSourceCommand, HomeTransferSourceOperation, HomeTransferSourceResponse,
    HomeTransferSourceService, ResolvedWorkspaceScope, WorkspaceLocator,
};
use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, DirectTokenId,
    EstablishWorkspace, ForgeBackendId, HomeTransferReservationRetirementGrant,
    HomeTransferReservationRetirementRequest, HomeTransferSourceAction, HomeTransferSourceBinding,
    HomeTransferSourceGrant, HomeTransferSourceRequest, HomeTransferSourceScope,
    HomeTransferSourceSubject, HomeTransferSourceWitness, LocationId, LocationRevision,
    OrchestrationIssuerId, TimestampMillis, WorkspaceId, WorkspaceRoot,
};
use forge_persistence::{
    AgentOperationsFreezeRequest, HomeTransferReservationRetirementRecord,
    HomeTransferReservationRetirementRecordParts, HomeTransferSourceRecord,
    HomeTransferSourceState, WorkspaceStore,
};
use forge_workspace::WorkspaceStateLayout;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, net::TcpListener, sync::oneshot, task::JoinHandle};
use uuid::Uuid;

use super::{ForgeHttpClient, ForgeHttpClientError, ForgeHttpHomeTransferSourceError};

type TestResult<T> = Result<T, Box<dyn Error>>;

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn create() -> TestResult<Self> {
        let configured = std::env::var_os("TMPDIR").ok_or("TMPDIR must be configured")?;
        let configured = PathBuf::from(configured);
        if !configured.is_absolute() {
            return Err("TMPDIR must be absolute".into());
        }
        let canonical = fs::canonicalize(&configured)?;
        if canonical != configured || !canonical.is_dir() {
            return Err("TMPDIR must be an existing canonical directory".into());
        }
        let root = canonical.join(format!("forge-home-source-client-{}", Uuid::now_v7()));
        fs::create_dir(&root)?;
        Ok(Self(root))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

struct SourceRecordFixture {
    _root: TemporaryRoot,
    record: HomeTransferSourceRecord,
    current_scope: ResolvedWorkspaceScope,
    backend_id: ForgeBackendId,
    destination_id: Uuid,
    issuer: OrchestrationIssuerId,
}

fn source_record_fixture() -> TestResult<SourceRecordFixture> {
    let root = TemporaryRoot::create()?;
    let layout = WorkspaceStateLayout::initialize(root.path())?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA001));
    let location_id = LocationId::from_uuid(Uuid::from_u128(0xA002));
    let workspace_command = EstablishWorkspace::new(
        workspace_id,
        location_id,
        WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
        layout.root_fingerprint()?,
        timestamp(1)?,
    );
    let mut store = WorkspaceStore::open(&layout, &workspace_command)?;
    let backend_id = ForgeBackendId::from_uuid(Uuid::from_u128(0xA003));
    let destination_id = Uuid::from_u128(0xA004);
    let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xA005));
    let migration_id = Uuid::from_u128(0xA006);
    let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
        migration_id,
        destination_id,
        timestamp(2)?,
    )?)?;
    let _delegation = store.delegate_agent_operations(&freeze, [0xA6; 32], timestamp(3)?)?;

    let workspace = store.workspace()?;
    let request = HomeTransferSourceRequest::new(
        HomeTransferSourceWitness::new(Uuid::from_u128(0xA007), [0xA7; 32], [0xA8; 32])?,
        HomeTransferSourceScope::new(
            workspace.id(),
            workspace.revision(),
            backend_id,
            destination_id,
        )?,
        HomeTransferSourceSubject::new(
            Uuid::from_u128(0xA009),
            1,
            Uuid::from_u128(0xA00A),
            Uuid::from_u128(0xA00B),
            Uuid::from_u128(0xA00C),
            Uuid::from_u128(0xA00D),
            1,
            1,
        )?,
        vec![AgentSessionId::from_uuid(Uuid::from_u128(0xA00E))],
        Vec::new(),
    )?;
    let grant = HomeTransferSourceGrant::new(
        issuer,
        HomeTransferSourceAction::Prepare,
        request.request_digest(),
        timestamp(20)?,
        timestamp(100)?,
    )?;
    let sample_time = timestamp(30)?;
    let outcome = store.prepare_home_transfer_source(
        &request,
        grant,
        issuer,
        backend_id,
        destination_id,
        || Ok(sample_time),
    )?;
    let record = outcome.record().clone();
    let current_revision = workspace.revision().checked_next()?;
    let locator = WorkspaceLocator::new(location_id, LocationRevision::INITIAL, Path::new("."))?;
    let current_scope =
        ResolvedWorkspaceScope::from_observation(workspace.id(), current_revision, locator);
    drop(store);
    Ok(SourceRecordFixture {
        _root: root,
        record,
        current_scope,
        backend_id,
        destination_id,
        issuer,
    })
}

fn timestamp(value: i64) -> TestResult<TimestampMillis> {
    Ok(TimestampMillis::new(value)?)
}

fn make_client(
    authority: SocketAddr,
    backend_id: ForgeBackendId,
    destination_id: Uuid,
) -> TestResult<ForgeHttpClient> {
    Ok(ForgeHttpClient::new(
        authority,
        "home-source-test-secret",
        backend_id,
        destination_id,
        Duration::from_secs(1),
    )?)
}

fn abort_command(
    fixture: &SourceRecordFixture,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
) -> TestResult<HomeTransferSourceCommand> {
    let request = fixture.record.request().clone();
    let grant = HomeTransferSourceGrant::new(
        fixture.issuer,
        HomeTransferSourceAction::AbortUnstarted,
        request.request_digest(),
        issued_at,
        expires_at,
    )?;
    Ok(HomeTransferSourceCommand {
        scope: fixture.current_scope.clone(),
        service: HomeTransferSourceService {
            issuer: fixture.issuer,
            backend_id: fixture.backend_id,
            destination_id: fixture.destination_id,
        },
        operation: HomeTransferSourceOperation::AbortUnstarted { request, grant },
    })
}

fn retirement_request(
    fixture: &SourceRecordFixture,
    reservation_request_id: Uuid,
) -> TestResult<HomeTransferReservationRetirementRequest> {
    Ok(HomeTransferReservationRetirementRequest::new(
        HomeTransferSourceScope::new(
            fixture.current_scope.workspace_id(),
            fixture.current_scope.workspace_revision(),
            fixture.backend_id,
            fixture.destination_id,
        )?,
        fixture.record.request().witness().preparation_id(),
        fixture.record.request().request_digest(),
        *fixture.record.outcome_digest(),
        reservation_request_id,
    )?)
}

fn retirement_command(
    fixture: &SourceRecordFixture,
    request: HomeTransferReservationRetirementRequest,
    issued_at: i64,
    expires_at: i64,
) -> TestResult<HomeTransferSourceCommand> {
    let grant = HomeTransferReservationRetirementGrant::new(
        fixture.issuer,
        request.request_digest(),
        timestamp(issued_at)?,
        timestamp(expires_at)?,
    )?;
    Ok(HomeTransferSourceCommand {
        scope: fixture.current_scope.clone(),
        service: HomeTransferSourceService {
            issuer: fixture.issuer,
            backend_id: fixture.backend_id,
            destination_id: fixture.destination_id,
        },
        operation: HomeTransferSourceOperation::RetireUnusedReservation { request, grant },
    })
}

fn retirement_record(
    request: HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
) -> TestResult<HomeTransferReservationRetirementRecord> {
    let observed_at = timestamp(40)?;
    let grant_issued_at = timestamp(20)?;
    let grant_expires_at = timestamp(100)?;
    let source_inventory_digest = [0xD1; 32];
    let reservation_digest = [0xD2; 32];
    let receipt_digest = retirement_receipt_digest(
        &request,
        issuer,
        observed_at,
        grant_issued_at,
        grant_expires_at,
        &source_inventory_digest,
        &reservation_digest,
    );
    Ok(HomeTransferReservationRetirementRecord::from_parts(
        &HomeTransferReservationRetirementRecordParts {
            request,
            issuer,
            observed_at,
            grant_issued_at,
            grant_expires_at,
            source_inventory_digest,
            reservation_digest,
            receipt_digest,
        },
    )?)
}

fn retirement_receipt_digest(
    request: &HomeTransferReservationRetirementRequest,
    issuer: OrchestrationIssuerId,
    observed_at: TimestampMillis,
    grant_issued_at: TimestampMillis,
    grant_expires_at: TimestampMillis,
    source_inventory_digest: &[u8; 32],
    reservation_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"forge.home-transfer.reservation-retirement.receipt.v1\0");
    hash.update([1]);
    let request_digest = request.request_digest();
    let issuer_uuid = issuer.into_uuid();
    let observed_at_bytes = observed_at.get().to_be_bytes();
    let grant_issued_at_bytes = grant_issued_at.get().to_be_bytes();
    let grant_expires_at_bytes = grant_expires_at.get().to_be_bytes();
    let fields: [(u8, u8, &[u8]); 7] = [
        (1, 32, request_digest.as_bytes()),
        (2, 16, issuer_uuid.as_bytes()),
        (3, 8, &observed_at_bytes),
        (4, 8, &grant_issued_at_bytes),
        (5, 8, &grant_expires_at_bytes),
        (6, 32, source_inventory_digest),
        (7, 32, reservation_digest),
    ];
    for (tag, length, value) in fields {
        hash.update([tag, length]);
        hash.update(value);
    }
    hash.finalize().into()
}

fn get_command(fixture: &SourceRecordFixture) -> HomeTransferSourceCommand {
    HomeTransferSourceCommand {
        scope: fixture.current_scope.clone(),
        service: HomeTransferSourceService {
            issuer: fixture.issuer,
            backend_id: fixture.backend_id,
            destination_id: fixture.destination_id,
        },
        operation: HomeTransferSourceOperation::Get {
            preparation_id: fixture.record.request().witness().preparation_id(),
            request_digest: fixture.record.request().request_digest(),
        },
    }
}

#[test]
fn persistence_owned_snapshot_round_trips_and_rejects_tampering() -> TestResult<()> {
    let fixture = source_record_fixture()?;
    let snapshot = fixture.record.to_snapshot_bytes()?;
    assert!(snapshot.starts_with(b"FHTS\x01"));
    assert_eq!(
        HomeTransferSourceRecord::from_snapshot_bytes(&snapshot)?,
        fixture.record
    );

    let mut tampered = snapshot;
    let final_byte = tampered.last_mut().ok_or("snapshot bytes were empty")?;
    *final_byte ^= 1;
    assert!(HomeTransferSourceRecord::from_snapshot_bytes(&tampered).is_err());
    Ok(())
}

#[tokio::test]
async fn send_preserves_state_and_accepts_historical_request_and_grant_window() -> TestResult<()> {
    let fixture = source_record_fixture()?;
    let result = json!({
        "record": crate::ops::home_transfers::record_json(&fixture.record),
    });
    let host = MockHost::start_success(result).await?;
    let client = make_client(host.address, fixture.backend_id, fixture.destination_id)?;
    let command = abort_command(&fixture, timestamp(200)?, timestamp(300)?)?;
    let request_id = Uuid::from_u128(0xA100);
    let prepared = client.prepare_home_transfer_source_command(&command, request_id)?;

    assert_eq!(prepared.request_id(), request_id);
    assert_eq!(prepared.authority(), host.address);
    assert_eq!(prepared.backend_id(), fixture.backend_id);
    assert_eq!(prepared.destination_id(), fixture.destination_id);
    assert!(prepared.body_bytes().len() <= 64 * 1024);
    assert!(!format!("{prepared:?}").contains("home-source-test-secret"));
    let envelope: Value = serde_json::from_slice(prepared.body_bytes())?;
    assert_eq!(envelope["request_id"], json!(request_id));
    assert_eq!(envelope["op"], "home_transfer.source_abort_unstarted");
    assert_eq!(envelope["payload"]["scope"]["workspace_revision"], 2);
    assert_eq!(
        envelope["payload"]["request"]["scope"]["workspace_revision"],
        1
    );
    assert_eq!(envelope["payload"]["grant"]["issued_at_ms"], 200);

    let reserved = client.reserve_home_transfer_source_send(prepared.clone())?;
    assert_eq!(reserved.prepared(), &prepared);
    let response = reserved.send().await?;
    let HomeTransferSourceResponse::Outcome(receipt) = response else {
        return Err("mutation returned a read response variant".into());
    };
    assert_eq!(receipt, fixture.record);
    assert_eq!(receipt.state(), HomeTransferSourceState::Prepared);
    assert_eq!(receipt.grant_issued_at(), timestamp(20)?);
    assert_eq!(receipt.grant_expires_at(), timestamp(100)?);

    let get = client
        .prepare_home_transfer_source_command(&get_command(&fixture), Uuid::from_u128(0xA101))?;
    let response = client.send_prepared_home_transfer_source(&get).await?;
    let HomeTransferSourceResponse::Record(Some(readback)) = response else {
        return Err("exact Get did not return the historical source record".into());
    };
    assert_eq!(readback, fixture.record);
    assert_eq!(host.calls(), 2);
    let bodies = host.request_bodies()?;
    assert_eq!(bodies[0].as_slice(), prepared.body_bytes());
    host.finish().await?;
    Ok(())
}

#[tokio::test]
async fn oversized_body_and_client_pins_reject_without_network_exchange() -> TestResult<()> {
    let fixture = source_record_fixture()?;
    let host = MockHost::start_success(json!({"record": null})).await?;
    let trusted = make_client(host.address, fixture.backend_id, fixture.destination_id)?;

    let oversized = oversized_command(&fixture)?;
    assert!(matches!(
        trusted.prepare_home_transfer_source_command(&oversized, Uuid::from_u128(0xA200)),
        Err(ForgeHttpHomeTransferSourceError::Rejected {
            cause: ForgeHttpClientError::RequestTooLarge,
            ..
        })
    ));

    let prepared = trusted
        .prepare_home_transfer_source_command(&get_command(&fixture), Uuid::from_u128(0xA201))?;
    let wrong_backend = make_client(
        host.address,
        ForgeBackendId::from_uuid(Uuid::from_u128(0xA2FF)),
        fixture.destination_id,
    )?;
    assert!(matches!(
        wrong_backend
            .send_prepared_home_transfer_source(&prepared)
            .await,
        Err(ForgeHttpHomeTransferSourceError::Rejected {
            cause: ForgeHttpClientError::DestinationMismatch,
            ..
        })
    ));
    let wrong_destination = make_client(host.address, fixture.backend_id, Uuid::from_u128(0xA2FE))?;
    assert!(matches!(
        wrong_destination
            .send_prepared_home_transfer_source(&prepared)
            .await,
        Err(ForgeHttpHomeTransferSourceError::Rejected {
            cause: ForgeHttpClientError::DestinationMismatch,
            ..
        })
    ));

    let mut reservations = Vec::new();
    for _ in 0..4 {
        reservations.push(trusted.reserve_home_transfer_source_send(prepared.clone())?);
    }
    assert_eq!(reservations[0].prepared(), &prepared);
    assert_eq!(
        reservations[0].prepared().body_bytes(),
        prepared.body_bytes()
    );
    let Err(
        saturated @ ForgeHttpHomeTransferSourceError::Rejected {
            cause: ForgeHttpClientError::Capacity,
            ..
        },
    ) = trusted.reserve_home_transfer_source_send(prepared.clone())
    else {
        return Err("fifth Home source reservation bypassed the four-slot bound".into());
    };
    assert!(saturated.prepared().is_some());
    assert_eq!(saturated.request_id(), prepared.request_id());
    drop(reservations.pop());
    let released_slot = trusted.reserve_home_transfer_source_send(prepared.clone())?;
    drop(released_slot);
    drop(reservations);
    assert_eq!(host.calls(), 0);
    host.finish().await?;

    let second = MockHost::start_success(json!({"record": null})).await?;
    let wrong_authority = make_client(second.address, fixture.backend_id, fixture.destination_id)?;
    assert!(matches!(
        wrong_authority
            .send_prepared_home_transfer_source(&prepared)
            .await,
        Err(ForgeHttpHomeTransferSourceError::Rejected {
            cause: ForgeHttpClientError::DestinationMismatch,
            ..
        })
    ));
    assert_eq!(second.calls(), 0);
    second.finish().await?;
    Ok(())
}

#[tokio::test]
async fn server_confirmed_mutation_rejection_is_rejected_not_unknown() -> TestResult<()> {
    let fixture = source_record_fixture()?;
    let error = crate::ForgeError::resync_required("source scope changed");
    let host = MockHost::start_failure(StatusCode::CONFLICT, error).await?;
    let client = make_client(host.address, fixture.backend_id, fixture.destination_id)?;
    let command = abort_command(&fixture, timestamp(200)?, timestamp(300)?)?;
    let prepared =
        client.prepare_home_transfer_source_command(&command, Uuid::from_u128(0xA300))?;

    let result = client.send_prepared_home_transfer_source(&prepared).await;
    assert!(matches!(
        result,
        Err(ForgeHttpHomeTransferSourceError::Rejected {
            cause: ForgeHttpClientError::Service {
                status: 409,
                code: super::ForgeHttpServiceCode::ResyncRequired,
            },
            ..
        })
    ));
    assert_eq!(host.calls(), 1);
    host.finish().await?;
    Ok(())
}

#[tokio::test]
async fn dispatched_transport_loss_retains_exact_prepared_attempt_without_retry() -> TestResult<()>
{
    let fixture = source_record_fixture()?;
    let mut host = DropHost::start().await?;
    let client = make_client(host.address, fixture.backend_id, fixture.destination_id)?;
    let command = abort_command(&fixture, timestamp(200)?, timestamp(300)?)?;
    let prepared =
        client.prepare_home_transfer_source_command(&command, Uuid::from_u128(0xA400))?;

    let result = client.send_prepared_home_transfer_source(&prepared).await;
    let received = host.receive_request().await?;
    assert_eq!(received, prepared.body_bytes());
    match result {
        Err(ForgeHttpHomeTransferSourceError::UnknownOutcome {
            prepared: retained,
            cause,
        }) => {
            assert_eq!(retained.as_ref(), &prepared);
            assert!(matches!(
                cause,
                ForgeHttpClientError::Transport | ForgeHttpClientError::Protocol
            ));
        }
        Ok(_) => return Err("transport loss was reported as a successful mutation".into()),
        Err(error) => return Err(format!("transport loss was not unknown: {error}").into()),
    }
    assert_eq!(host.accepted.load(Ordering::Acquire), 1);
    host.finish().await?;
    Ok(())
}

#[tokio::test]
async fn retirement_unknown_outcome_keeps_exact_prepared_command_and_builds_only_its_get()
-> TestResult<()> {
    let fixture = source_record_fixture()?;
    let request = retirement_request(&fixture, Uuid::from_u128(0xA410))?;
    let command = retirement_command(&fixture, request, 200, 300)?;
    let mut host = DropHost::start().await?;
    let client = make_client(host.address, fixture.backend_id, fixture.destination_id)?;
    let prepared =
        client.prepare_home_transfer_source_command(&command, Uuid::from_u128(0xA411))?;

    let result = client.send_prepared_home_transfer_source(&prepared).await;
    let received = host.receive_request().await?;
    assert_eq!(received, prepared.body_bytes());
    match result {
        Err(ForgeHttpHomeTransferSourceError::UnknownOutcome {
            prepared: retained,
            cause,
        }) => {
            assert_eq!(retained.as_ref(), &prepared);
            assert!(matches!(
                cause,
                ForgeHttpClientError::Transport | ForgeHttpClientError::Protocol
            ));
            let readback = retained
                .reservation_retirement_readback_command(&fixture.current_scope)
                .ok_or("unknown retirement did not retain its exact readback identity")?;
            assert_eq!(
                readback.operation,
                HomeTransferSourceOperation::GetReservationRetirement {
                    preparation_id: request.preparation_id(),
                    reservation_request_id: request.reservation_request_id(),
                    request_digest: request.request_digest(),
                }
            );
            assert_eq!(readback.scope, command.scope);
            assert_eq!(readback.service, command.service);
        }
        Ok(_) => return Err("transport loss was reported as a successful retirement".into()),
        Err(error) => return Err(format!("retirement loss was not unknown: {error}").into()),
    }
    assert_eq!(host.accepted.load(Ordering::Acquire), 1);
    host.finish().await?;

    let get_host = MockHost::start_success(json!({"record": null})).await?;
    let get_client = make_client(get_host.address, fixture.backend_id, fixture.destination_id)?;
    let get = prepared
        .reservation_retirement_readback_command(&fixture.current_scope)
        .ok_or("prepared retirement did not yield an exact readback")?;
    let get_prepared =
        get_client.prepare_home_transfer_source_command(&get, Uuid::from_u128(0xA412))?;
    let envelope: Value = serde_json::from_slice(get_prepared.body_bytes())?;
    assert_eq!(envelope["op"], "home_transfer.reservation_retirement_get");
    assert_eq!(
        envelope["payload"]["preparation_id"],
        json!(request.preparation_id())
    );
    assert_eq!(
        envelope["payload"]["reservation_request_id"],
        json!(request.reservation_request_id())
    );
    assert_eq!(
        envelope["payload"]["request_digest"],
        json!(crate::ops::home_transfers::wire::encode_digest(
            request.request_digest().as_bytes()
        ))
    );
    assert!(matches!(
        get_client
            .send_prepared_home_transfer_source(&get_prepared)
            .await?,
        HomeTransferSourceResponse::ReservationRetirementRecord(None)
    ));
    assert_eq!(get_host.calls(), 1);
    get_host.finish().await?;
    Ok(())
}

#[tokio::test]
async fn retirement_response_checks_receipt_and_exact_reservation_key() -> TestResult<()> {
    let fixture = source_record_fixture()?;
    let request = retirement_request(&fixture, Uuid::from_u128(0xA420))?;
    let record = retirement_record(request, fixture.issuer)?;
    let record_json = crate::ops::home_transfers::wire::retirement_record_json(&record);
    let host = MockHost::start_success(json!({"record": record_json.clone()})).await?;
    let client = make_client(host.address, fixture.backend_id, fixture.destination_id)?;
    let command = retirement_command(&fixture, request, 200, 300)?;
    let prepared =
        client.prepare_home_transfer_source_command(&command, Uuid::from_u128(0xA421))?;
    let envelope: Value = serde_json::from_slice(prepared.body_bytes())?;
    assert_eq!(envelope["op"], "home_transfer.reservation_retire_unused");
    assert_eq!(envelope["payload"]["grant"]["issued_at_ms"], 200);
    assert_eq!(envelope["payload"]["grant"]["expires_at_ms"], 300);
    assert_eq!(
        envelope["payload"]["request"]["request_digest"],
        json!(crate::ops::home_transfers::wire::encode_digest(
            request.request_digest().as_bytes()
        ))
    );
    let response = client.send_prepared_home_transfer_source(&prepared).await?;
    let HomeTransferSourceResponse::ReservationRetirementOutcome(receipt) = response else {
        return Err("retirement mutation returned the wrong response variant".into());
    };
    assert_eq!(receipt, record);
    assert_eq!(receipt.grant_issued_at(), timestamp(20)?);
    assert_eq!(receipt.grant_expires_at(), timestamp(100)?);
    assert_ne!(receipt.grant_issued_at(), timestamp(200)?);
    host.finish().await?;

    let readback_host = MockHost::start_success(json!({"record": record_json.clone()})).await?;
    let readback_client = make_client(
        readback_host.address,
        fixture.backend_id,
        fixture.destination_id,
    )?;
    let readback_command = prepared
        .reservation_retirement_readback_command(&fixture.current_scope)
        .ok_or("successful retirement did not yield its exact readback")?;
    let readback = readback_client
        .prepare_home_transfer_source_command(&readback_command, Uuid::from_u128(0xA425))?;
    let HomeTransferSourceResponse::ReservationRetirementRecord(Some(readback_record)) =
        readback_client
            .send_prepared_home_transfer_source(&readback)
            .await?
    else {
        return Err("exact retirement Get did not return its immutable record".into());
    };
    assert_eq!(readback_record, record);
    readback_host.finish().await?;
    Ok(())
}

#[tokio::test]
async fn retirement_rejects_hostile_record_fields_and_other_reservation_key() -> TestResult<()> {
    let fixture = source_record_fixture()?;
    let request = retirement_request(&fixture, Uuid::from_u128(0xA420))?;
    let record = retirement_record(request, fixture.issuer)?;
    let record_json = crate::ops::home_transfers::wire::retirement_record_json(&record);
    let command = retirement_command(&fixture, request, 200, 300)?;

    let mut unknown_fields = record_json.clone();
    unknown_fields["unexpected"] = json!(true);
    let hostile_host = MockHost::start_success(json!({"record": unknown_fields})).await?;
    let hostile_client = make_client(
        hostile_host.address,
        fixture.backend_id,
        fixture.destination_id,
    )?;
    let prepared =
        hostile_client.prepare_home_transfer_source_command(&command, Uuid::from_u128(0xA422))?;
    assert!(matches!(
        hostile_client
            .send_prepared_home_transfer_source(&prepared)
            .await,
        Err(ForgeHttpHomeTransferSourceError::UnknownOutcome {
            cause: ForgeHttpClientError::Protocol,
            ..
        })
    ));
    hostile_host.finish().await?;

    let other_request = retirement_request(&fixture, Uuid::from_u128(0xA423))?;
    let other_record = retirement_record(other_request, fixture.issuer)?;
    let wrong_key_host = MockHost::start_success(json!({
        "record": crate::ops::home_transfers::wire::retirement_record_json(&other_record),
    }))
    .await?;
    let wrong_key_client = make_client(
        wrong_key_host.address,
        fixture.backend_id,
        fixture.destination_id,
    )?;
    let get_command = HomeTransferSourceCommand {
        scope: fixture.current_scope.clone(),
        service: HomeTransferSourceService {
            issuer: fixture.issuer,
            backend_id: fixture.backend_id,
            destination_id: fixture.destination_id,
        },
        operation: HomeTransferSourceOperation::GetReservationRetirement {
            preparation_id: request.preparation_id(),
            reservation_request_id: request.reservation_request_id(),
            request_digest: request.request_digest(),
        },
    };
    let get = wrong_key_client
        .prepare_home_transfer_source_command(&get_command, Uuid::from_u128(0xA424))?;
    assert!(matches!(
        wrong_key_client
            .send_prepared_home_transfer_source(&get)
            .await,
        Err(ForgeHttpHomeTransferSourceError::ReadFailed {
            cause: ForgeHttpClientError::Protocol,
            ..
        })
    ));
    wrong_key_host.finish().await?;
    Ok(())
}

#[tokio::test]
async fn strict_record_decoder_rejects_unknown_fields_and_noncanonical_capsule() -> TestResult<()> {
    let fixture = source_record_fixture()?;
    let mut unknown_record = crate::ops::home_transfers::record_json(&fixture.record);
    unknown_record["unexpected"] = json!(true);
    let unknown_host = MockHost::start_success(json!({"record": unknown_record})).await?;
    let client = make_client(
        unknown_host.address,
        fixture.backend_id,
        fixture.destination_id,
    )?;
    let prepared = client
        .prepare_home_transfer_source_command(&get_command(&fixture), Uuid::from_u128(0xA500))?;
    assert!(matches!(
        client.send_prepared_home_transfer_source(&prepared).await,
        Err(ForgeHttpHomeTransferSourceError::ReadFailed {
            cause: ForgeHttpClientError::Protocol,
            ..
        })
    ));
    unknown_host.finish().await?;

    let mut noncanonical = crate::ops::home_transfers::record_json(&fixture.record);
    let payload = noncanonical["inventory_payload_base64"]
        .as_str()
        .ok_or("prepared fixture did not contain an inventory capsule")?
        .to_owned();
    noncanonical["inventory_payload_base64"] = json!(format!("{payload}="));
    let bad_capsule_host = MockHost::start_success(json!({"record": noncanonical})).await?;
    let client = make_client(
        bad_capsule_host.address,
        fixture.backend_id,
        fixture.destination_id,
    )?;
    let command = abort_command(&fixture, timestamp(200)?, timestamp(300)?)?;
    let prepared =
        client.prepare_home_transfer_source_command(&command, Uuid::from_u128(0xA501))?;
    assert!(matches!(
        client.send_prepared_home_transfer_source(&prepared).await,
        Err(ForgeHttpHomeTransferSourceError::UnknownOutcome {
            cause: ForgeHttpClientError::Protocol,
            ..
        })
    ));
    bad_capsule_host.finish().await?;

    let oversized = vec![0xCC; 512 * 1024 + 1];
    let mut oversized_record = crate::ops::home_transfers::record_json(&fixture.record);
    oversized_record["inventory_payload_base64"] =
        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&oversized));
    let oversized_host = MockHost::start_success(json!({"record": oversized_record})).await?;
    let client = make_client(
        oversized_host.address,
        fixture.backend_id,
        fixture.destination_id,
    )?;
    let prepared = client
        .prepare_home_transfer_source_command(&get_command(&fixture), Uuid::from_u128(0xA502))?;
    assert!(matches!(
        client.send_prepared_home_transfer_source(&prepared).await,
        Err(ForgeHttpHomeTransferSourceError::ReadFailed {
            cause: ForgeHttpClientError::Protocol,
            ..
        })
    ));
    oversized_host.finish().await?;
    Ok(())
}

fn oversized_command(fixture: &SourceRecordFixture) -> TestResult<HomeTransferSourceCommand> {
    let session_count = forge_domain::MAX_HOME_TRANSFER_SOURCE_SESSIONS;
    let binding_count = forge_domain::MAX_HOME_TRANSFER_SOURCE_BINDINGS;
    let sessions: Vec<_> = (0..session_count)
        .map(|index| {
            u128::try_from(index)
                .map(|index| AgentSessionId::from_uuid(Uuid::from_u128(0xB000 + index)))
        })
        .collect::<Result<_, _>>()?;
    let token = DirectTokenId::from_uuid(Uuid::from_u128(0xC000));
    let bindings: Vec<_> = (0..binding_count)
        .map(|index| -> TestResult<_> {
            let index = u128::try_from(index)?;
            Ok(HomeTransferSourceBinding::new(
                ActivityId::from_uuid(Uuid::from_u128(0xD000 + index)),
                AgentInstanceId::from_uuid(Uuid::from_u128(0xE000 + index)),
                sessions[usize::try_from(index)? % sessions.len()],
                AuthenticatedPrincipal::DirectToken(token),
            )?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let request = HomeTransferSourceRequest::new(
        HomeTransferSourceWitness::new(Uuid::from_u128(0xF000), [0xD1; 32], [0xD2; 32])?,
        HomeTransferSourceScope::new(
            fixture.record.request().scope().workspace_id(),
            fixture.record.request().scope().workspace_revision(),
            fixture.backend_id,
            fixture.destination_id,
        )?,
        HomeTransferSourceSubject::new(
            Uuid::from_u128(0xF001),
            1,
            Uuid::from_u128(0xF002),
            Uuid::from_u128(0xF003),
            Uuid::from_u128(0xF004),
            Uuid::from_u128(0xF005),
            1,
            1,
        )?,
        sessions,
        bindings,
    )?;
    let service = HomeTransferSourceService {
        issuer: fixture.issuer,
        backend_id: fixture.backend_id,
        destination_id: fixture.destination_id,
    };
    let grant = HomeTransferSourceGrant::new(
        fixture.issuer,
        HomeTransferSourceAction::Prepare,
        request.request_digest(),
        timestamp(200)?,
        timestamp(300)?,
    )?;
    let relative_root = "\"".repeat(1_024);
    let locator = WorkspaceLocator::new(
        fixture.current_scope.locator().location_id(),
        fixture.current_scope.locator().expected_revision(),
        Path::new(&relative_root),
    )?;
    Ok(HomeTransferSourceCommand {
        scope: ResolvedWorkspaceScope::from_observation(
            fixture.current_scope.workspace_id(),
            fixture.current_scope.workspace_revision(),
            locator,
        ),
        service,
        operation: HomeTransferSourceOperation::Prepare { request, grant },
    })
}

#[derive(Clone)]
enum MockReply {
    Success(Value),
    Failure { status: StatusCode, error: Value },
}

struct MockState {
    reply: MockReply,
    calls: AtomicUsize,
    request_bodies: Mutex<Vec<Vec<u8>>>,
}

struct MockHost {
    address: SocketAddr,
    state: Arc<MockState>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), std::io::Error>>,
}

impl MockHost {
    async fn start(reply: MockReply) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let state = Arc::new(MockState {
            reply,
            calls: AtomicUsize::new(0),
            request_bodies: Mutex::new(Vec::new()),
        });
        let router = Router::new()
            .route(
                "/api/v1/commands/home_transfer.source_prepare",
                post(mock_home_source_response),
            )
            .route(
                "/api/v1/commands/home_transfer.source_abort_unstarted",
                post(mock_home_source_response),
            )
            .route(
                "/api/v1/commands/home_transfer.source_get",
                post(mock_home_source_response),
            )
            .route(
                "/api/v1/commands/home_transfer.reservation_retire_unused",
                post(mock_home_source_response),
            )
            .route(
                "/api/v1/commands/home_transfer.reservation_retirement_get",
                post(mock_home_source_response),
            )
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            address,
            state,
            stop,
            task,
        })
    }

    async fn start_success(result: Value) -> TestResult<Self> {
        Self::start(MockReply::Success(result)).await
    }

    async fn start_failure(status: StatusCode, error: crate::ForgeError) -> TestResult<Self> {
        Self::start(MockReply::Failure {
            status,
            error: serde_json::to_value(error)?,
        })
        .await
    }

    async fn finish(self) -> TestResult<()> {
        self.stop
            .send(())
            .map_err(|()| "mock Home source host did not accept shutdown")?;
        self.task.await??;
        Ok(())
    }

    fn calls(&self) -> usize {
        self.state.calls.load(Ordering::Acquire)
    }

    fn request_bodies(&self) -> TestResult<Vec<Vec<u8>>> {
        Ok(self
            .state
            .request_bodies
            .lock()
            .map_err(|_| "mock request body lock poisoned")?
            .clone())
    }
}

async fn mock_home_source_response(
    State(state): State<Arc<MockState>>,
    request: Request<Body>,
) -> Response<Body> {
    state.calls.fetch_add(1, Ordering::AcqRel);
    let body = to_bytes(request.into_body(), 128 * 1024)
        .await
        .unwrap_or_default();
    if let Ok(mut bodies) = state.request_bodies.lock() {
        bodies.push(body.to_vec());
    }
    let request_id = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|envelope| envelope.get("request_id").cloned())
        .unwrap_or(Value::Null);
    let (status, value) = match &state.reply {
        MockReply::Success(result) => (
            StatusCode::OK,
            json!({
                "forge_api": crate::config::FORGE_API_VERSION,
                "request_id": request_id,
                "ok": true,
                "result": result,
            }),
        ),
        MockReply::Failure { status, error } => (
            *status,
            json!({
                "forge_api": crate::config::FORGE_API_VERSION,
                "request_id": request_id,
                "ok": false,
                "error": error,
            }),
        ),
    };
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

struct DropHost {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    received: oneshot::Receiver<Vec<u8>>,
    task: JoinHandle<Result<(), std::io::Error>>,
}

impl DropHost {
    async fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let task_accepted = Arc::clone(&accepted);
        let (received_sender, received) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            task_accepted.fetch_add(1, Ordering::AcqRel);
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 4096];
            loop {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..read]);
                if let Some(body) = http_request_body(&bytes) {
                    let _sent = received_sender.send(body.to_vec());
                    drop(stream);
                    return Ok(());
                }
                if bytes.len() > 128 * 1024 {
                    break;
                }
            }
            let _sent = received_sender.send(bytes);
            drop(stream);
            Ok(())
        });
        Ok(Self {
            address,
            accepted,
            received,
            task,
        })
    }

    async fn receive_request(&mut self) -> TestResult<Vec<u8>> {
        Ok(
            tokio::time::timeout(Duration::from_secs(2), &mut self.received)
                .await
                .map_err(|_| "drop host did not receive the prepared command")??,
        )
    }

    async fn finish(self) -> TestResult<()> {
        self.task.await??;
        Ok(())
    }
}

fn http_request_body(bytes: &[u8]) -> Option<&[u8]> {
    let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })?;
    let body_start = header_end.checked_add(4)?;
    let request_end = body_start.checked_add(content_length)?;
    bytes.get(body_start..request_end)
}
