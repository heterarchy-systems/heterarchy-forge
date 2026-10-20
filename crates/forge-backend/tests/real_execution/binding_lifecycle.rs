//! Real loopback HTTP proof for the delegated Agent binding lifecycle.
//!
//! The fixture's source freeze, delegation seal, and initial Agent are created
//! by the existing native owner.  HTTP then carries only scalar references and
//! attestations; every mutation is read back through the same durable identity.

use super::lease_readback::{path_token, post_ok, scope_json};
use super::*;

use forge_backend::lease_bridge::{ActivityLeaseBridge, RoutingExecutor};
use forge_backend::{BridgeDrainReport, BridgeOutcome, CommandExecutor, ControlBridge};
use forge_control::{AgentListRequest, AgentSessionResolveRequest};
use forge_domain::{AgentListLimit, AgentSessionOpenRequestId, DirectTokenId, OpenAgentSession};
use forge_persistence::AgentSessionCatalog;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;

const MEMBERSHIP_DIGEST: [u8; 32] = [0xB1; 32];
const DEPARTURE_DIGEST: [u8; 32] = [0xC1; 32];

#[derive(Clone)]
struct DelegationFacts {
    migration_id: Uuid,
    destination_id: Uuid,
    freeze_revision: i64,
    manifest_digest: String,
}

pub(super) struct HttpBindingFixture {
    pub(super) fixture: Fixture,
    pub(super) state: forge_backend::AppState,
    pub(super) address: SocketAddr,
}

#[derive(Debug, Default)]
pub(super) struct HeldResponse {
    release: Notify,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl HeldResponse {
    pub(super) async fn release_and_wait(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.release.notify_one();
        let task = self
            .task
            .lock()
            .map_err(|_| "held reply task lock poisoned")?
            .take();
        if let Some(mut task) = task {
            if let Ok(result) = timeout(Duration::from_secs(5), &mut task).await {
                result.map_err(|_| "held bridge reply task panicked")?;
            } else {
                task.abort();
                let _cancelled = task.await;
                return Err("held bridge reply task did not join within its bound".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct HoldingExecutor {
    inner: Arc<dyn CommandExecutor>,
    held: Arc<HeldResponse>,
    admitted: Mutex<Option<oneshot::Sender<()>>>,
}

impl HoldingExecutor {
    fn new(
        inner: Arc<dyn CommandExecutor>,
        held: Arc<HeldResponse>,
        admitted: oneshot::Sender<()>,
    ) -> Self {
        Self {
            inner,
            held,
            admitted: Mutex::new(Some(admitted)),
        }
    }
}

impl CommandExecutor for HoldingExecutor {
    fn submit(
        &self,
        command: forge_backend::Command,
    ) -> Result<oneshot::Receiver<BridgeOutcome>, forge_backend::error::ForgeError> {
        let receiver = self.inner.submit(command)?;
        let signal = self
            .admitted
            .lock()
            .map_err(|_| forge_backend::error::ForgeError::internal())?
            .take();
        let Some(signal) = signal else {
            return Ok(receiver);
        };
        let (reply_sender, reply_receiver) = oneshot::channel();
        let mut slot = self
            .held
            .task
            .lock()
            .map_err(|_| forge_backend::error::ForgeError::internal())?;
        let held = Arc::clone(&self.held);
        let task = tokio::spawn(async move {
            let outcome = receiver.await.unwrap_or(BridgeOutcome::UnknownOutcome);
            held.release.notified().await;
            let _ = reply_sender.send(outcome);
        });
        *slot = Some(task);
        let _ = signal.send(());
        Ok(reply_receiver)
    }

    fn begin_wait(
        &self,
        request: forge_control::ExecutionWaitParameters,
    ) -> Result<forge_control::ExecutionWaitHandle, forge_backend::error::ForgeError> {
        self.inner.begin_wait(request)
    }

    fn stop_admission(&self) {
        self.inner.stop_admission();
    }

    fn inflight(&self) -> usize {
        self.inner.inflight()
    }

    fn drain_and_join(&self, drain_timeout: Duration) -> BridgeDrainReport {
        self.inner.drain_and_join(drain_timeout)
    }
}

impl HttpBindingFixture {
    pub(super) async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = prepare_fixture().map_err(|error| format!("native HTTP fixture: {error}"))?;
        let product_cache_root = fixture.root.join("product-cache");
        fs::create_dir_all(&product_cache_root)?;
        let destination_id = delegated_destination_id(&fixture)?;
        let state = super::assemble_fixture(
            backend_config()?,
            &fixture,
            &product_cache_root,
            destination_id,
        )?;
        let address = serve(state.clone())
            .await
            .map_err(|error| format!("HTTP listener: {error}"))?;
        Ok(Self {
            fixture,
            state,
            address,
        })
    }

    pub(super) async fn start_holding_first_reply(
        command_deadline: Option<Duration>,
    ) -> Result<(Self, Arc<HeldResponse>, oneshot::Receiver<()>), Box<dyn std::error::Error>> {
        let fixture = prepare_fixture()
            .map_err(|error| format!("held-reply native HTTP fixture: {error}"))?;
        let product_cache_root = fixture.root.join("product-cache");
        fs::create_dir_all(&product_cache_root)?;
        let destination_id = delegated_destination_id(&fixture)?;
        let config = match command_deadline {
            Some(deadline) => backend_config()?.with_command_deadline(deadline),
            None => backend_config()?,
        };
        let general = Arc::new(ControlBridge::start(
            &fixture.client,
            &fixture.execution.client(),
            &fixture.approval.client(),
            fixture.runtime_instance_id,
            &config,
            &product_cache_root,
            destination_id,
        )?);
        let lease = Arc::new(ActivityLeaseBridge::start(&fixture.activity_leases)?);
        let bridge = Arc::new(RoutingExecutor::new(general, lease));
        let held = Arc::new(HeldResponse::default());
        let (admitted_sender, admitted_receiver) = oneshot::channel();
        let executor = Arc::new(HoldingExecutor::new(
            bridge,
            Arc::clone(&held),
            admitted_sender,
        ));
        let state = forge_backend::AppState::new(
            config,
            executor,
            Arc::new(forge_backend::events::ControlEventQuery::new(
                fixture.client.clone(),
            )),
        );
        state.set_probe(Arc::new(fixture.client.clone()));
        state.set_execution_fast_lane(Arc::new(fixture.execution.client()));
        let address = serve(state.clone()).await?;
        Ok((
            Self {
                fixture,
                state,
                address,
            },
            held,
            admitted_receiver,
        ))
    }

    pub(super) async fn finish(self) -> Result<(), Box<dyn std::error::Error>> {
        let Self {
            fixture,
            state,
            address: _,
        } = self;
        let shutdown = state.shutdown(Duration::from_secs(5)).await;
        let fixture_result = fixture.shutdown();
        if !shutdown.is_successful() {
            return Err(
                format!("binding HTTP server shutdown was incomplete: {shutdown:?}").into(),
            );
        }
        fixture_result
    }
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    forge_backend::events::hex_encode(bytes)
}

fn principal() -> Value {
    json!({"kind": "trusted_stdio"})
}

fn freeze_ref(facts: &DelegationFacts) -> Value {
    json!({
        "migration_id": facts.migration_id,
        "expected_freeze_revision": facts.freeze_revision,
    })
}

fn delegation_ref(facts: &DelegationFacts) -> Value {
    json!({
        "migration_id": facts.migration_id,
        "expected_freeze_revision": facts.freeze_revision,
        "manifest_digest": facts.manifest_digest,
    })
}

fn common(fixture: &Fixture, destination_id: Uuid) -> Value {
    json!({
        "scope": scope_json(fixture),
        "issuer_id": ISSUER_ID,
        "destination_id": destination_id,
    })
}

fn merge(mut left: Value, right: Value) -> Value {
    if let (Some(left), Value::Object(right)) = (left.as_object_mut(), right) {
        left.extend(right);
    }
    left
}

fn delegation_facts(fixture: &Fixture) -> Result<DelegationFacts, Box<dyn std::error::Error>> {
    let delegation = fixture
        .client
        .agent_operations_delegation(forge_control::AgentOperationsDelegationReadRequest {
            scope: fixture.scope.clone(),
        })?
        .ok_or("fixture delegation seal is missing")?;
    Ok(DelegationFacts {
        migration_id: delegation.migration_id(),
        destination_id: delegation.destination_id(),
        freeze_revision: i64::try_from(delegation.freeze().revision())?,
        manifest_digest: hex_digest(&delegation.manifest_digest()),
    })
}

/// Audit only the isolated fixture's retired participation tables. This is a
/// read-only assertion, never a product query or a source of work authority.
fn participation_rows(fixture: &Fixture) -> Result<(i64, i64, i64), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("fixture Workspace layout missing")?;
    let connection = rusqlite::Connection::open_with_flags(
        layout.database_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(connection.query_row(
        "SELECT (SELECT COUNT(*) FROM agent_presence), (SELECT COUNT(*) FROM agent_events), (SELECT COUNT(*) FROM agent_inbox)",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

fn current_handoff_snapshot(
    fixture: &Fixture,
) -> Result<forge_domain::CoordinationSnapshot, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("fixture Workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let agent = store
        .get_agent(fixture.agent_id)?
        .ok_or("source Agent missing")?;
    let focus = agent.focus();
    let goal = store
        .get_goal(focus.goal().ok_or("source Goal focus missing")?.goal_id())?
        .ok_or("source Goal missing")?;
    let dag = store
        .get_current_dag(goal.id())?
        .ok_or("source DAG missing")?;
    Ok(forge_domain::CoordinationSnapshot::new(
        Some(GoalAttribution::new(goal.id(), goal.revision())),
        Some(dag.head().dag_revision()),
        Some(dag.head().revision()),
        focus.node(),
    )?)
}

fn session_id_for_fixture(
    fixture: &Fixture,
    session_id: AgentSessionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = fixture
        .client
        .agent_session_resolve(AgentSessionResolveRequest {
            session_id,
            principal: AuthenticatedPrincipal::TrustedStdio,
        })?;
    let registry = GlobalRegistry::open_existing(fixture.root.join("registry.sqlite3"))?;
    let catalog_path = registry
        .database_path()
        .with_file_name("agent-sessions.sqlite3");
    let mut catalog = AgentSessionCatalog::open_existing(&catalog_path)?
        .ok_or("Agent session catalog disappeared during lifecycle proof")?;
    let closed = catalog.close(
        session.id(),
        AuthenticatedPrincipal::TrustedStdio,
        session.revision(),
        timestamp_now()?,
    )?;
    if closed.state() != forge_domain::AgentSessionState::Closed {
        return Err("session close did not produce the closed state".into());
    }
    Ok(())
}

fn open_secondary_session(fixture: &Fixture) -> Result<AgentSessionId, Box<dyn std::error::Error>> {
    let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
    let _opened = fixture.client.agent_session_open(OpenAgentSession::new(
        session_id,
        AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
        AuthenticatedPrincipal::TrustedStdio,
        timestamp_now()?,
    ))?;
    Ok(session_id)
}

fn current_agent_revision(
    fixture: &Fixture,
    agent_id: AgentInstanceId,
) -> Result<i64, Box<dyn std::error::Error>> {
    fixture
        .client
        .agent_list(AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: Some(fixture.activity_id),
            now: timestamp_now()?,
            limit: AgentListLimit::DEFAULT,
        })?
        .into_iter()
        .find(|entry| entry.agent().id() == agent_id)
        .map(|entry| entry.agent().revision().get())
        .ok_or_else(|| "current Agent projection missing".into())
}

fn coordination_snapshot_json(snapshot: forge_domain::CoordinationSnapshot) -> Value {
    json!({
        "goal": snapshot.goal().map(|goal| json!({
            "goal_id": goal.goal_id().into_uuid(),
            "expected_revision": goal.expected_revision().get(),
        })),
        "dag_revision": snapshot.dag_revision().map(forge_domain::DagRevisionNumber::get),
        "dag_head_revision": snapshot
            .dag_head_revision()
            .map(forge_domain::DagHeadRevision::get),
        "node": snapshot.node().map(|node| json!({
            "node_id": node.node_id().into_uuid(),
            "expected_revision": node.expected_revision().get(),
        })),
    })
}

fn reservation_payload(
    fixture: &Fixture,
    facts: &DelegationFacts,
    request_id: Uuid,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
) -> Result<Value, Box<dyn std::error::Error>> {
    let requested_at_ms = timestamp_now()?.get();
    let observed_at_ms = timestamp_now()?.get();
    Ok(merge(
        common(fixture, facts.destination_id),
        json!({
            "reference": freeze_ref(facts),
            "reservation": {
                "request_id": request_id,
                "activity_id": fixture.activity_id.into_uuid(),
                "agent_id": agent_id.into_uuid(),
                "session_id": session_id.into_uuid(),
                "principal": principal(),
                "requested_at_ms": requested_at_ms,
            },
            "observed_at_ms": observed_at_ms,
        }),
    ))
}

fn activation_payload(
    fixture: &Fixture,
    facts: &DelegationFacts,
    request_id: Uuid,
    session_id: AgentSessionId,
    display_name: &str,
    declared_role: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let observed_at_ms = timestamp_now()?.get();
    Ok(merge(
        common(fixture, facts.destination_id),
        json!({
            "reference": delegation_ref(facts),
            "activation": {
                "request_id": request_id,
                "membership_digest": hex_digest(&MEMBERSHIP_DIGEST),
                "display_name": display_name,
                "declared_role": declared_role,
                "transport": "stdio",
            },
            "session_id": session_id.into_uuid(),
            "principal": principal(),
            "observed_at_ms": observed_at_ms,
        }),
    ))
}

async fn assert_delegation_reads(
    address: SocketAddr,
    fixture: &Fixture,
    facts: &DelegationFacts,
) -> Result<(), Box<dyn std::error::Error>> {
    let delegated = post_ok(
        address,
        "agent.operations.delegate",
        merge(
            common(fixture, facts.destination_id),
            json!({
            "reference": freeze_ref(facts),
                "manifest_digest": facts.manifest_digest,
                "observed_at_ms": timestamp_now()?.get(),
            }),
        ),
    )
    .await?;
    assert_eq!(delegated["migration_id"], json!(facts.migration_id));
    assert_eq!(delegated["destination_id"], json!(facts.destination_id));
    assert_eq!(delegated["freeze_revision"], facts.freeze_revision);
    assert_eq!(delegated["manifest_digest"], facts.manifest_digest);

    let seal = post_ok(
        address,
        "agent.operations.delegation_get",
        merge(
            common(fixture, facts.destination_id),
            json!({"reference": delegation_ref(facts)}),
        ),
    )
    .await?;
    assert_eq!(seal, delegated);
    Ok(())
}

async fn assert_delegate_and_reservation_reads(
    address: SocketAddr,
    fixture: &Fixture,
    facts: &DelegationFacts,
) -> Result<(Uuid, AgentInstanceId, AgentSessionId, Value), Box<dyn std::error::Error>> {
    assert_delegation_reads(address, fixture, facts).await?;
    let session_id = open_secondary_session(fixture)?;
    let request_id = Uuid::now_v7();
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    let reservation = reservation_payload(fixture, facts, request_id, agent_id, session_id)?;
    let reserved = post_ok(address, "agent.binding.reserve", reservation.clone()).await?;
    let replay = post_ok(address, "agent.binding.reserve", reservation.clone()).await?;
    assert_eq!(replay, reserved);

    let mut collision = reservation.clone();
    collision["reservation"]["agent_id"] = json!(Uuid::now_v7());
    let collision_response =
        assert_rejected(address, "agent.binding.reserve", collision, 409).await?;
    assert_eq!(collision_response["error"]["code"], "FORGE_UNAVAILABLE");
    assert_eq!(collision_response["error"]["category"], "revision_conflict");

    let mut stale = reservation.clone();
    stale["reference"]["expected_freeze_revision"] = json!(facts.freeze_revision.saturating_add(1));
    let stale_response = assert_rejected(address, "agent.binding.reserve", stale, 409).await?;
    assert_eq!(stale_response["error"]["code"], "FORGE_UNAVAILABLE");
    assert_eq!(stale_response["error"]["category"], "revision_conflict");

    let mut foreign_destination = reservation.clone();
    foreign_destination["destination_id"] = json!(Uuid::now_v7());
    let foreign =
        assert_rejected(address, "agent.binding.reserve", foreign_destination, 400).await?;
    assert_eq!(foreign["error"]["code"], "AUTH_FAILED");
    assert_eq!(foreign["error"]["category"], "authentication");

    let read = post_ok(
        address,
        "agent.binding.reservation_get",
        merge(
            common(fixture, facts.destination_id),
            json!({
                "request_id": request_id,
                "session_id": session_id.into_uuid(),
                "principal": principal(),
            }),
        ),
    )
    .await?;
    assert_eq!(read["found"], true);
    assert_eq!(read["request_id"], json!(request_id));
    assert_eq!(read["agent_id"], json!(agent_id.into_uuid()));

    let foreign = post_ok(
        address,
        "agent.binding.reservation_get",
        merge(
            common(fixture, facts.destination_id),
            json!({
                "request_id": request_id,
                "session_id": fixture.session_id.into_uuid(),
                "principal": principal(),
            }),
        ),
    )
    .await?;
    assert_eq!(foreign["found"], false);

    let before = participation_rows(fixture)?;
    assert_eq!(before, (0, 0, 0));
    assert!(
        fixture
            .client
            .agent_get_context(forge_control::AgentContextRequest {
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                agent_id,
                now: timestamp_now()?,
                focus_event_limit: AgentListLimit::DEFAULT,
                work_update_limit: AgentListLimit::DEFAULT,
            })?
            .is_none()
    );
    let (status, lease) = post_command(
        address,
        "writer_lease.acquire",
        json!({
            "scope": scope_json(fixture),
                "activity_id": fixture.activity_id.into_uuid(),
            "actor": {
                "session_id": session_id.into_uuid(),
                "principal": principal(),
                "agent_id": agent_id.into_uuid(),
            },
            "writer_lease_id": Uuid::now_v7(),
            "duration_ms": 2_000,
            "scopes": [{"kind": "exact_path", "path_base64": path_token("reserved-only.txt")}],
        }),
    )
    .await?;
    assert_ne!(
        status, 200,
        "a reservation must not grant Writer Lease authority: {lease}"
    );
    assert_eq!(lease["ok"], false);
    assert_eq!(lease["error"]["code"], "FORGE_UNAVAILABLE");
    assert_eq!(lease["error"]["category"], "work_state");
    assert_eq!(before, participation_rows(fixture)?);

    Ok((request_id, agent_id, session_id, reservation))
}

async fn assert_rejected(
    address: SocketAddr,
    operation: &str,
    payload: Value,
    expected_status: u16,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_command(address, operation, payload).await?;
    assert_eq!(status, expected_status, "{operation} response: {response}");
    assert_eq!(response["ok"], false);
    Ok(response)
}

async fn post_exact_ok(
    address: SocketAddr,
    operation: &str,
    request_id: Uuid,
    payload: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let body = json!({
        "forge_api": 1,
        "request_id": request_id,
        "op": operation,
        "payload": payload,
    })
    .to_string();
    let request = format!(
        "POST /api/v1/commands/{operation} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, response) = exchange_json(address, &request).await?;
    if status != 200 || response["ok"] != true {
        return Err(format!("{operation} failed ({status}): {response}").into());
    }
    Ok(response["result"].clone())
}

pub(super) async fn open_command_without_read(
    address: SocketAddr,
    operation: &str,
    payload: Value,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
    let body = envelope(operation, &payload);
    let request = format!(
        "POST /api/v1/commands/{operation} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream.write_all(request.as_bytes()).await?;
    Ok(stream)
}

async fn assert_activation_and_departure(
    address: SocketAddr,
    fixture: &Fixture,
    facts: &DelegationFacts,
    request_id: Uuid,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    activation: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let activation_read = post_ok(
        address,
        "agent.binding.activation_get",
        merge(
            common(fixture, facts.destination_id),
            json!({
                "request_id": request_id,
                "session_id": session_id.into_uuid(),
                "principal": principal(),
            }),
        ),
    )
    .await?;
    assert_eq!(activation_read["found"], true);
    assert_eq!(
        activation_read["membership_digest"],
        hex_digest(&MEMBERSHIP_DIGEST)
    );
    assert_eq!(activation_read["request_id"], json!(request_id));

    let foreign_activation_read = post_ok(
        address,
        "agent.binding.activation_get",
        merge(
            common(fixture, facts.destination_id),
            json!({
                "request_id": request_id,
                "session_id": fixture.session_id.into_uuid(),
                "principal": principal(),
            }),
        ),
    )
    .await?;
    assert_eq!(foreign_activation_read["found"], false);

    let context = post_ok(
        address,
        "agent.get_context",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "agent_id": agent_id.into_uuid(),
        }),
    )
    .await?;
    assert_eq!(context["found"], true);
    assert_eq!(context["focus_event_count"], 1);
    assert_eq!(context["work_update_count"], 0);

    let replay = post_ok(address, "agent.binding.activate", activation.clone()).await?;
    assert_eq!(replay["request_id"], json!(request_id));
    let mut stale_delegation = activation.clone();
    stale_delegation["reference"]["manifest_digest"] = json!("b2".repeat(32));
    let stale_delegation_response =
        assert_rejected(address, "agent.binding.activate", stale_delegation, 409).await?;
    assert_eq!(
        stale_delegation_response["error"]["code"],
        "FORGE_UNAVAILABLE"
    );
    assert_eq!(
        stale_delegation_response["error"]["category"],
        "revision_conflict"
    );
    let mut foreign_activation = activation.clone();
    foreign_activation["session_id"] = json!(fixture.session_id.into_uuid());
    let foreign_activation_response =
        assert_rejected(address, "agent.binding.activate", foreign_activation, 409).await?;
    assert_eq!(
        foreign_activation_response["error"]["code"],
        "FORGE_UNAVAILABLE"
    );
    assert_eq!(
        foreign_activation_response["error"]["category"],
        "authority"
    );
    let mut collision = activation.clone();
    collision["activation"]["display_name"] = json!("different-name");
    let collision_response =
        assert_rejected(address, "agent.binding.activate", collision, 409).await?;
    assert_eq!(collision_response["error"]["code"], "FORGE_UNAVAILABLE");
    assert_eq!(collision_response["error"]["category"], "revision_conflict");

    assert_detach_readback(address, fixture, facts, agent_id, session_id).await?;
    let resurrect = assert_rejected(address, "agent.binding.activate", activation, 409).await?;
    assert_eq!(resurrect["error"]["code"], "FORGE_UNAVAILABLE");
    assert_eq!(resurrect["error"]["category"], "revision_conflict");
    Ok(())
}

async fn assert_detach_readback(
    address: SocketAddr,
    fixture: &Fixture,
    facts: &DelegationFacts,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_revision = current_agent_revision(fixture, agent_id)?;
    let departure_request_id = Uuid::now_v7();
    let departure = merge(
        common(fixture, facts.destination_id),
        json!({
            "reconciliation": {
                "request_id": departure_request_id,
                    "session_id": session_id.into_uuid(),
                "principal": principal(),
                "identity_digest": hex_digest(&DEPARTURE_DIGEST),
                "command": {
                    "kind": "detach",
                    "agent_id": agent_id.into_uuid(),
                    "activity_id": fixture.activity_id.into_uuid(),
                    "expected_agent_revision": expected_revision,
                    "observed_at_ms": timestamp_now()?.get(),
                },
            },
        }),
    );
    let receipt = post_ok(address, "agent.departure.reconcile", departure.clone()).await?;
    assert_eq!(receipt["request_id"], json!(departure_request_id));
    assert_eq!(receipt["agent_id"], json!(agent_id.into_uuid()));
    assert_eq!(receipt["session_id"], json!(session_id.into_uuid()));
    assert_eq!(receipt["kind"], "detach");
    assert_eq!(receipt["expected_agent_revision"], expected_revision);
    assert_eq!(receipt["result_agent_revision"], expected_revision + 1);

    let departure_read = post_ok(
        address,
        "agent.departure.reconciliation_get",
        merge(
            common(fixture, facts.destination_id),
            json!({
                "request_id": departure_request_id,
                "session_id": session_id.into_uuid(),
                "principal": principal(),
            }),
        ),
    )
    .await?;
    assert_eq!(departure_read["found"], true);
    assert_eq!(departure_read, receipt);

    let foreign_read = post_ok(
        address,
        "agent.departure.reconciliation_get",
        merge(
            common(fixture, facts.destination_id),
            json!({
                "request_id": departure_request_id,
                "session_id": fixture.session_id.into_uuid(),
                "principal": principal(),
            }),
        ),
    )
    .await?;
    assert_eq!(foreign_read["found"], false);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "The ordered HTTP proof keeps native readback and each lifecycle fence visible."
)]
async fn binding_lifecycle_http_proves_delegate_reserve_activate_and_detach()
-> Result<(), Box<dyn std::error::Error>> {
    let running = HttpBindingFixture::start().await?;
    let facts = delegation_facts(&running.fixture)?;
    let result = async {
        let (request_id, agent_id, session_id, _) =
            assert_delegate_and_reservation_reads(running.address, &running.fixture, &facts)
                .await?;
        let activation = activation_payload(
            &running.fixture,
            &facts,
            request_id,
            session_id,
            "http-binding-agent",
            "worker",
        )?;
        let activated = post_ok(
            running.address,
            "agent.binding.activate",
            activation.clone(),
        )
        .await?;
        assert_eq!(activated["agent_id"], json!(agent_id.into_uuid()));
        assert_activation_and_departure(
            running.address,
            &running.fixture,
            &facts,
            request_id,
            agent_id,
            session_id,
            activation,
        )
        .await
    }
    .await;
    let finish = running.finish().await;
    result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "The real HTTP proof keeps reservation, rejection, Get, and both parsed scope assertions together."
)]
async fn binding_rejection_http_projects_plain_scope_for_reject_and_get()
-> Result<(), Box<dyn std::error::Error>> {
    let running = HttpBindingFixture::start().await?;
    let facts = delegation_facts(&running.fixture)?;
    let result = async {
        assert_delegation_reads(running.address, &running.fixture, &facts).await?;
        let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
        let token_id = DirectTokenId::from_uuid(Uuid::now_v7());
        let principal = AuthenticatedPrincipal::DirectToken(token_id);
        let _opened = running
            .fixture
            .client
            .agent_session_open(OpenAgentSession::new(
                session_id,
                AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
                principal,
                timestamp_now()?,
            ))?;
        let principal_wire = json!({
            "kind": "direct_token",
            "token_id": token_id.into_uuid(),
            "grant_id": null,
        });
        let request_id = Uuid::now_v7();
        let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
        let reservation = json!({
            "request_id": request_id,
            "activity_id": running.fixture.activity_id.into_uuid(),
            "agent_id": agent_id.into_uuid(),
            "session_id": session_id.into_uuid(),
            "principal": principal_wire,
            "requested_at_ms": timestamp_now()?.get(),
        });
        post_ok(
            running.address,
            "agent.binding.reserve",
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "reference": freeze_ref(&facts),
                    "reservation": reservation,
                    "observed_at_ms": timestamp_now()?.get(),
                }),
            ),
        )
        .await?;
        let rejected = post_exact_ok(
            running.address,
            "agent.binding.reject",
            request_id,
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "reference": delegation_ref(&facts),
                    "reservation": reservation,
                    "activation": {
                        "request_id": request_id,
                        "membership_digest": hex_digest(&MEMBERSHIP_DIGEST),
                        "display_name": "rejected-token-agent",
                        "declared_role": "worker",
                        "transport": "other",
                    },
                    "reason": "principal_transport_mismatch",
                    "observed_at_ms": timestamp_now()?.get(),
                }),
            ),
        )
        .await?;
        let rejected_scope: forge_backend::ops::ScopeDto =
            serde_json::from_value(rejected["scope"].clone())?;
        assert_eq!(
            rejected_scope.workspace_id,
            running.fixture.scope.workspace_id().into_uuid()
        );
        assert_eq!(rejected["status"], "recorded");
        let request_digest = rejected["receipt"]["request_digest"]
            .as_str()
            .ok_or("rejection request digest missing")?;
        let read = post_exact_ok(
            running.address,
            "agent.binding.rejection_get",
            request_id,
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "request_id": request_id,
                    "request_digest": request_digest,
                    "session_id": session_id.into_uuid(),
                    "principal": principal_wire,
                }),
            ),
        )
        .await?;
        let read_scope: forge_backend::ops::ScopeDto =
            serde_json::from_value(read["scope"].clone())?;
        assert_eq!(read_scope, rejected_scope);
        assert_eq!(read["found"], true);
        assert_eq!(read["receipt"], rejected["receipt"]);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let finish = running.finish().await;
    result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binding_lifecycle_http_disconnect_after_admission_reads_reservation_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) = HttpBindingFixture::start_holding_first_reply(None).await?;
    let facts = delegation_facts(&running.fixture)?;
    let session_id = open_secondary_session(&running.fixture)?;
    let request_id = Uuid::now_v7();
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    let reservation =
        reservation_payload(&running.fixture, &facts, request_id, agent_id, session_id)?;
    let before = participation_rows(&running.fixture)?;
    assert_eq!(before, (0, 0, 0));

    let result = async {
        let mut stream =
            open_command_without_read(running.address, "agent.binding.reserve", reservation)
                .await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let close_result = stream.shutdown().await;
        drop(stream);
        held.release_and_wait().await?;
        close_result?;

        let read = post_ok(
            running.address,
            "agent.binding.reservation_get",
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "request_id": request_id,
                    "session_id": session_id.into_uuid(),
                    "principal": principal(),
                }),
            ),
        )
        .await?;
        assert_eq!(read["found"], true);
        assert_eq!(read["request_id"], json!(request_id));
        assert_eq!(read["agent_id"], json!(agent_id.into_uuid()));
        assert_eq!(read["session_id"], json!(session_id.into_uuid()));

        assert!(
            running
                .fixture
                .client
                .agent_get_context(forge_control::AgentContextRequest {
                    scope: running.fixture.scope.clone(),
                    activity_id: running.fixture.activity_id,
                    agent_id,
                    now: timestamp_now()?,
                    focus_event_limit: AgentListLimit::DEFAULT,
                    work_update_limit: AgentListLimit::DEFAULT,
                })?
                .is_none()
        );
        assert_eq!(before, participation_rows(&running.fixture)?);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let finish = running.finish().await;
    result?;
    release_result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binding_lifecycle_http_deadline_returns_typed_reservation_readback_hint()
-> Result<(), Box<dyn std::error::Error>> {
    let (running, held, admitted) =
        HttpBindingFixture::start_holding_first_reply(Some(Duration::from_secs(1))).await?;
    let facts = delegation_facts(&running.fixture)?;
    let session_id = open_secondary_session(&running.fixture)?;
    let request_id = Uuid::now_v7();
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    let reservation =
        reservation_payload(&running.fixture, &facts, request_id, agent_id, session_id)?;
    let result = async {
        let mut stream =
            open_command_without_read(running.address, "agent.binding.reserve", reservation)
                .await?;
        timeout(Duration::from_secs(5), admitted).await??;
        let response_result = async {
            let raw = timeout(Duration::from_secs(5), read_response_bounded(&mut stream)).await??;
            let text = String::from_utf8(raw)?;
            let status = text
                .split_whitespace()
                .nth(1)
                .ok_or("HTTP status missing")?
                .parse::<u16>()?;
            let body = text.split_once("\r\n\r\n").ok_or("HTTP body missing")?.1;
            let response: Value = serde_json::from_str(body)?;
            assert_eq!(status, 202, "deadline response: {response}");
            assert_eq!(response["error"]["code"], "UNKNOWN_OUTCOME");
            assert_eq!(response["error"]["recovery_action"], "read_back");
            assert_eq!(
                response["error"]["readback"]["kind"],
                "agent_binding_reservation"
            );
            assert_eq!(
                response["error"]["readback"]["request_id"],
                json!(request_id)
            );
            assert_eq!(
                response["error"]["readback"]["session_id"],
                json!(session_id.into_uuid())
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        drop(stream);
        held.release_and_wait().await?;
        response_result?;

        let read = post_ok(
            running.address,
            "agent.binding.reservation_get",
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "request_id": request_id,
                    "session_id": session_id.into_uuid(),
                    "principal": principal(),
                }),
            ),
        )
        .await?;
        assert_eq!(read["found"], true);
        assert_eq!(read["agent_id"], json!(agent_id.into_uuid()));
        assert!(
            running
                .fixture
                .client
                .agent_get_context(forge_control::AgentContextRequest {
                    scope: running.fixture.scope.clone(),
                    activity_id: running.fixture.activity_id,
                    agent_id,
                    now: timestamp_now()?,
                    focus_event_limit: AgentListLimit::DEFAULT,
                    work_update_limit: AgentListLimit::DEFAULT,
                })?
                .is_none()
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let release_result = held.release_and_wait().await;
    let finish = running.finish().await;
    result?;
    release_result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "The handoff proof keeps actor, target, coordination, and receipt fences together."
)]
async fn binding_lifecycle_http_proves_native_handoff_actor_and_target_fences()
-> Result<(), Box<dyn std::error::Error>> {
    let running = HttpBindingFixture::start().await?;
    let facts = delegation_facts(&running.fixture)?;
    let result = async {
        let (request_id, target_agent_id, target_session_id, _) =
            assert_delegate_and_reservation_reads(running.address, &running.fixture, &facts)
                .await?;
        let activation = activation_payload(
            &running.fixture,
            &facts,
            request_id,
            target_session_id,
            "handoff-target",
            "coordinator",
        )?;
        post_ok(running.address, "agent.binding.activate", activation).await?;

        let coordination = current_handoff_snapshot(&running.fixture)?;
        let coordinator = running
            .fixture
            .client
            .activity_coordinator_get(forge_control::CoordinatorGetRequest {
                scope: running.fixture.scope.clone(),
                activity_id: running.fixture.activity_id,
            })?
            .ok_or("native Coordinator binding missing for handoff")?;
        let source_revision = current_agent_revision(&running.fixture, running.fixture.agent_id)?;
        let target_revision = current_agent_revision(&running.fixture, target_agent_id)?;
        let request_id = Uuid::now_v7();
        let handoff = merge(
            common(&running.fixture, facts.destination_id),
            json!({
                "reconciliation": {
                    "request_id": request_id,
                    "session_id": running.fixture.session_id.into_uuid(),
                    "principal": principal(),
                    "identity_digest": hex_digest(&DEPARTURE_DIGEST),
                    "command": {
                        "kind": "handoff",
                        "activity_id": running.fixture.activity_id.into_uuid(),
                        "agent_id": running.fixture.agent_id.into_uuid(),
                        "expected_coordinator_revision": coordinator.revision().get(),
                        "expected_source_agent_revision": source_revision,
                        "target_agent_id": target_agent_id.into_uuid(),
                        "target_session_id": target_session_id.into_uuid(),
                        "target_principal": principal(),
                        "expected_target_revision": target_revision,
                        "expected_coordination": coordination_snapshot_json(coordination),
                        "event_id": Uuid::now_v7(),
                        "observed_at_ms": timestamp_now()?.get(),
                    },
                },
            }),
        );
        let before = participation_rows(&running.fixture)?;
        assert_eq!(before, (0, 0, 0));
        let receipt = post_ok(
            running.address,
            "agent.departure.reconcile",
            handoff.clone(),
        )
        .await?;
        assert_eq!(receipt["request_id"], json!(request_id));
        assert_eq!(receipt["kind"], "handoff");
        assert_eq!(
            receipt["agent_id"],
            json!(running.fixture.agent_id.into_uuid())
        );
        assert_eq!(
            receipt["target_agent_id"],
            json!(target_agent_id.into_uuid())
        );
        assert_eq!(
            receipt["target_session_id"],
            json!(target_session_id.into_uuid())
        );
        assert_eq!(
            receipt["result_coordinator_revision"],
            coordinator.revision().get() + 1
        );
        let replay = post_ok(running.address, "agent.departure.reconcile", handoff).await?;
        assert_eq!(replay, receipt);

        let read = post_ok(
            running.address,
            "agent.departure.reconciliation_get",
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "request_id": request_id,
                    "session_id": running.fixture.session_id.into_uuid(),
                    "principal": principal(),
                }),
            ),
        )
        .await?;
        assert_eq!(read, receipt);
        let foreign_read = post_ok(
            running.address,
            "agent.departure.reconciliation_get",
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "request_id": request_id,
                    "session_id": target_session_id.into_uuid(),
                    "principal": principal(),
                }),
            ),
        )
        .await?;
        assert_eq!(foreign_read["found"], false);

        assert_eq!(before, participation_rows(&running.fixture)?);
        let current_coordinator = running
            .fixture
            .client
            .activity_coordinator_get(forge_control::CoordinatorGetRequest {
                scope: running.fixture.scope.clone(),
                activity_id: running.fixture.activity_id,
            })?
            .ok_or("Coordinator missing after handoff")?;
        assert_eq!(current_coordinator.agent_id(), target_agent_id);
        assert_eq!(
            current_coordinator.revision().get(),
            coordinator.revision().get() + 1
        );
        let agents = post_ok(
            running.address,
            "agent.list",
            json!({
                "scope": scope_json(&running.fixture),
                "activity_id": running.fixture.activity_id.into_uuid(),
            }),
        )
        .await?;
        let entries = agents["agents"].as_array().ok_or("Agent list missing")?;
        let source = entries
            .iter()
            .find(|entry| entry["agent_id"] == json!(running.fixture.agent_id.into_uuid()))
            .ok_or("handoff source projection missing")?;
        let target = entries
            .iter()
            .find(|entry| entry["agent_id"] == json!(target_agent_id.into_uuid()))
            .ok_or("handoff target projection missing")?;
        assert_eq!(source["attachment_state"], "detached");
        assert_eq!(target["attachment_state"], "attached");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let finish = running.finish().await;
    result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binding_lifecycle_http_rejects_closed_session_and_foreign_issuer()
-> Result<(), Box<dyn std::error::Error>> {
    let running = HttpBindingFixture::start().await?;
    let facts = delegation_facts(&running.fixture)?;
    let session_id = open_secondary_session(&running.fixture)?;
    let request_id = Uuid::now_v7();
    let agent_id = AgentInstanceId::from_uuid(Uuid::now_v7());
    let reservation =
        reservation_payload(&running.fixture, &facts, request_id, agent_id, session_id)?;
    session_id_for_fixture(&running.fixture, session_id)?;
    let result = async {
        let closed =
            assert_rejected(running.address, "agent.binding.reserve", reservation, 409).await?;
        assert_eq!(closed["error"]["code"], "FORGE_UNAVAILABLE");
        assert_eq!(closed["error"]["category"], "authority");
        let mut wrong_issuer = common(&running.fixture, facts.destination_id);
        wrong_issuer["issuer_id"] = json!(Uuid::now_v7());
        wrong_issuer["reference"] = freeze_ref(&facts);
        wrong_issuer["manifest_digest"] = json!(facts.manifest_digest);
        wrong_issuer["observed_at_ms"] = json!(timestamp_now()?.get());
        let unauthorized = assert_rejected(
            running.address,
            "agent.operations.delegate",
            wrong_issuer,
            400,
        )
        .await?;
        assert_eq!(unauthorized["error"]["code"], "AUTH_FAILED");
        assert_eq!(unauthorized["error"]["category"], "authentication");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let finish = running.finish().await;
    result?;
    finish
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binding_lifecycle_http_does_not_fabricate_legacy_session_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let running = HttpBindingFixture::start().await?;
    let facts = delegation_facts(&running.fixture)?;
    let request_id = Uuid::now_v7();
    let expected_revision = current_agent_revision(&running.fixture, running.fixture.agent_id)?;
    let payload = merge(
        common(&running.fixture, facts.destination_id),
        json!({
            "reconciliation": {
                "request_id": request_id,
                "activity_id": running.fixture.activity_id.into_uuid(),
                "agent_id": running.fixture.agent_id.into_uuid(),
                "session_id": running.fixture.session_id.into_uuid(),
                "principal": principal(),
                "expected_agent_revision": expected_revision,
                "observed_at_ms": timestamp_now()?.get(),
            },
        }),
    );
    let result = async {
        let response =
            assert_rejected(running.address, "agent.session.reconcile", payload, 409).await?;
        assert_eq!(response["error"]["code"], "FORGE_UNAVAILABLE");
        assert_eq!(response["error"]["category"], "revision_conflict");
        let read = post_ok(
            running.address,
            "agent.session.reconciliation_get",
            merge(
                common(&running.fixture, facts.destination_id),
                json!({
                    "request_id": request_id,
                    "session_id": running.fixture.session_id.into_uuid(),
                    "principal": principal(),
                }),
            ),
        )
        .await?;
        assert_eq!(read["found"], false);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let finish = running.finish().await;
    result?;
    finish
}
