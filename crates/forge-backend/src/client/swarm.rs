//! Checked client-side HTTP projections for Forge Swarm workspace isolation,
//! capture, convergence, materialization, settlement, and purge operations.

use forge_control::{
    MAX_SWARM_CONVERGENCE_CANDIDATES, ResolvedWorkspaceScope, SwarmConvergeRequest,
    SwarmMaterializeHybridRequest, SwarmMemberCaptureRequest, SwarmPurgeRequest,
    SwarmSettleRequest, SwarmSettlementGetRequest, SwarmWorkspaceGetRequest,
    SwarmWorkspaceProvisionRequest,
};
use forge_domain::{AgentSessionId, AuthenticatedPrincipal, SwarmSettlementTarget};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    ForgeHttpClient, ForgeHttpClientError, decode_command_response, migration_request_body,
    migration_scope_payload,
};
use crate::ops::swarm::{
    SwarmConvergenceCandidateDto, SwarmConvergenceOutcomeWire, SwarmMemberOutputWire,
    SwarmPurgeWire, SwarmSettleWire, SwarmSettlementGetWire, SwarmSettlementReceiptWire,
    SwarmTargetWire, SwarmWorkspaceGetWire, SwarmWorkspaceModeWire, SwarmWorkspaceReceiptWire,
};
use crate::ops::{CommandOp, PrincipalDto, SessionActorDto, encode_hex};

impl ForgeHttpClient {
    /// Provision an isolated Swarm member workspace (`Inherit`, `Share`, or `Branch`) over HTTP.
    pub async fn swarm_workspace_provision(
        &self,
        request: &SwarmWorkspaceProvisionRequest,
    ) -> Result<SwarmWorkspaceReceiptWire, ForgeHttpClientError> {
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        validate_non_nil(request.member_id.into_uuid())?;
        validate_non_nil(request.session_id.into_uuid())?;
        if let SwarmSettlementTarget::DagNodeHybrid {
            goal_id, node_id, ..
        } = request.target
        {
            validate_non_nil(goal_id.into_uuid())?;
            validate_non_nil(node_id.into_uuid())?;
        }
        if let Some(ref oid) = request.candidate_commit_oid {
            validate_commit_oid(oid)?;
        }
        let target_wire = SwarmTargetWire::from_domain(request.target);
        let mode_wire = SwarmWorkspaceModeWire::from_domain(request.mode);
        let fields = json!({
            "actor": actor_dto(&request.scope, request.session_id, request.principal),
            "swarm_run_id": request.swarm_run_id.into_uuid(),
            "member_id": request.member_id.into_uuid(),
            "mode": mode_wire,
            "target": target_wire,
            "candidate_commit_oid": request.candidate_commit_oid,
            "observed_at_ms": request.observed_at.get(),
        });
        let receipt: SwarmWorkspaceReceiptWire = self
            .execute_swarm_command(CommandOp::SwarmWorkspaceProvision, &request.scope, fields)
            .await?;
        if receipt.swarm_run_id != request.swarm_run_id.into_uuid()
            || receipt.member_id != request.member_id.into_uuid()
            || receipt.mode != mode_wire
            || receipt.target != target_wire
            || receipt.worktree_path.is_empty()
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        Ok(receipt)
    }

    /// Inspect one provisioned Swarm member workspace over HTTP.
    pub async fn swarm_workspace_get(
        &self,
        request: &SwarmWorkspaceGetRequest,
    ) -> Result<SwarmWorkspaceGetWire, ForgeHttpClientError> {
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        validate_non_nil(request.member_id.into_uuid())?;
        let fields = json!({
            "swarm_run_id": request.swarm_run_id.into_uuid(),
            "member_id": request.member_id.into_uuid(),
        });
        let view: SwarmWorkspaceGetWire = self
            .execute_swarm_command(CommandOp::SwarmWorkspaceGet, &request.scope, fields)
            .await?;
        if view.workspace_id != request.scope.workspace_id().into_uuid()
            || view.swarm_run_id != request.swarm_run_id.into_uuid()
            || view.member_id != request.member_id.into_uuid()
            || view.found != view.receipt.is_some()
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        if let Some(ref receipt) = view.receipt
            && (receipt.swarm_run_id != view.swarm_run_id || receipt.member_id != view.member_id)
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        Ok(view)
    }

    /// Capture one completed Swarm member workspace snapshot over HTTP.
    pub async fn swarm_member_capture(
        &self,
        request: &SwarmMemberCaptureRequest,
    ) -> Result<SwarmMemberOutputWire, ForgeHttpClientError> {
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        validate_non_nil(request.member_id.into_uuid())?;
        validate_non_nil(request.session_id.into_uuid())?;
        let fields = json!({
            "actor": actor_dto(&request.scope, request.session_id, request.principal),
            "swarm_run_id": request.swarm_run_id.into_uuid(),
            "member_id": request.member_id.into_uuid(),
            "captured_at_ms": request.captured_at.get(),
        });
        let output: SwarmMemberOutputWire = self
            .execute_swarm_command(CommandOp::SwarmMemberCapture, &request.scope, fields)
            .await?;
        if output.swarm_run_id != request.swarm_run_id.into_uuid()
            || output.member_id != request.member_id.into_uuid()
            || validate_commit_oid(&output.output_commit_oid).is_err()
            || !is_hex_64(&output.final_tree_blake3)
            || !is_hex_64(&output.diff_digest)
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        Ok(output)
    }

    /// Converge ordered captured Swarm candidates via deterministic 3-way merge over HTTP.
    pub async fn swarm_converge(
        &self,
        request: &SwarmConvergeRequest,
    ) -> Result<SwarmConvergenceOutcomeWire, ForgeHttpClientError> {
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        validate_non_nil(request.session_id.into_uuid())?;
        if request.candidates.is_empty()
            || request.candidates.len() > MAX_SWARM_CONVERGENCE_CANDIDATES
        {
            return Err(ForgeHttpClientError::InvalidRequest);
        }
        let mut candidates = Vec::with_capacity(request.candidates.len());
        for candidate in &request.candidates {
            validate_non_nil(candidate.member_id.into_uuid())?;
            if let Some(ref oid) = candidate.expected_output_commit_oid {
                validate_commit_oid(oid)?;
            }
            candidates.push(SwarmConvergenceCandidateDto {
                member_id: candidate.member_id.into_uuid(),
                expected_output_commit_oid: candidate.expected_output_commit_oid.clone(),
                expected_diff_digest: candidate
                    .expected_diff_digest
                    .as_ref()
                    .map(|bytes| encode_hex(bytes)),
            });
        }
        let fields = json!({
            "actor": actor_dto(&request.scope, request.session_id, request.principal),
            "swarm_run_id": request.swarm_run_id.into_uuid(),
            "candidates": candidates,
            "observed_at_ms": request.observed_at.get(),
        });
        let outcome: SwarmConvergenceOutcomeWire = self
            .execute_swarm_command(CommandOp::SwarmConverge, &request.scope, fields)
            .await?;
        let expected_run = request.swarm_run_id.into_uuid();
        match &outcome {
            SwarmConvergenceOutcomeWire::Converged {
                swarm_run_id,
                converged_commit_oid,
                converged_tree_blake3,
                converged_diff_digest,
                ..
            } if *swarm_run_id != expected_run
                || validate_commit_oid(converged_commit_oid).is_err()
                || !is_hex_64(converged_tree_blake3)
                || !is_hex_64(converged_diff_digest) =>
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            SwarmConvergenceOutcomeWire::Conflict { swarm_run_id, .. }
                if *swarm_run_id != expected_run =>
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            _ => {}
        }
        Ok(outcome)
    }

    /// Atomically settle a converged `StandaloneSwarm` candidate into `<workspace_root>`
    /// and enqueue `SWARM_SETTLED_KIND = 6` when delegated.
    pub async fn swarm_settle(
        &self,
        request: &SwarmSettleRequest,
    ) -> Result<SwarmSettleWire, ForgeHttpClientError> {
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        validate_non_nil(request.settlement_id)?;
        validate_non_nil(request.coordinator_agent_id.into_uuid())?;
        validate_non_nil(request.session_id.into_uuid())?;
        if let Some(activity_id) = request.activity_id {
            validate_non_nil(activity_id.into_uuid())?;
        }
        validate_commit_oid(&request.converged_commit_oid)?;
        let fields = json!({
            "activity_id": request.activity_id.map(forge_domain::ActivityId::into_uuid),
            "actor": actor_dto(&request.scope, request.session_id, request.principal),
            "coordinator_agent_id": request.coordinator_agent_id.into_uuid(),
            "swarm_run_id": request.swarm_run_id.into_uuid(),
            "settlement_id": request.settlement_id,
            "converged_commit_oid": request.converged_commit_oid,
            "expected_diff_digest": request.expected_diff_digest.as_ref().map(|bytes| encode_hex(bytes)),
            "settled_at_ms": request.settled_at.get(),
        });
        let wire: SwarmSettleWire = self
            .execute_swarm_command(CommandOp::SwarmSettle, &request.scope, fields)
            .await?;
        validate_settlement_receipt_wire(
            &wire.receipt,
            request.settlement_id,
            request.swarm_run_id.into_uuid(),
            &request.converged_commit_oid,
            SwarmTargetWire::StandaloneSwarm,
        )?;
        Ok(wire)
    }

    /// Materialize a converged `DagNodeHybrid` candidate into an active target DAG node worktree.
    pub async fn swarm_materialize_hybrid(
        &self,
        request: &SwarmMaterializeHybridRequest,
    ) -> Result<SwarmSettlementReceiptWire, ForgeHttpClientError> {
        validate_non_nil(request.activity_id.into_uuid())?;
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        validate_non_nil(request.settlement_id)?;
        validate_non_nil(request.goal_id.into_uuid())?;
        validate_non_nil(request.node_id.into_uuid())?;
        validate_non_nil(request.session_id.into_uuid())?;
        validate_commit_oid(&request.converged_commit_oid)?;
        let fields = json!({
            "activity_id": request.activity_id.into_uuid(),
            "actor": actor_dto(&request.scope, request.session_id, request.principal),
            "swarm_run_id": request.swarm_run_id.into_uuid(),
            "settlement_id": request.settlement_id,
            "goal_id": request.goal_id.into_uuid(),
            "expected_goal_revision": request.expected_goal_revision.get(),
            "expected_dag_revision": request.expected_dag_revision.get(),
            "node_id": request.node_id.into_uuid(),
            "converged_commit_oid": request.converged_commit_oid,
            "expected_diff_digest": request.expected_diff_digest.as_ref().map(|bytes| encode_hex(bytes)),
            "settled_at_ms": request.settled_at.get(),
        });
        let receipt: SwarmSettlementReceiptWire = self
            .execute_swarm_command(CommandOp::SwarmMaterializeHybrid, &request.scope, fields)
            .await?;
        validate_settlement_receipt_wire(
            &receipt,
            request.settlement_id,
            request.swarm_run_id.into_uuid(),
            &request.converged_commit_oid,
            SwarmTargetWire::DagNodeHybrid {
                goal_id: request.goal_id.into_uuid(),
                dag_revision: request.expected_dag_revision.get(),
                node_id: request.node_id.into_uuid(),
            },
        )?;
        Ok(receipt)
    }

    /// Read one Swarm settlement journal and matching durable `SwarmSettled` outbox record.
    pub async fn swarm_settlement_get(
        &self,
        request: &SwarmSettlementGetRequest,
    ) -> Result<SwarmSettlementGetWire, ForgeHttpClientError> {
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        let fields = json!({
            "swarm_run_id": request.swarm_run_id.into_uuid(),
        });
        let view: SwarmSettlementGetWire = self
            .execute_swarm_command(CommandOp::SwarmSettlementGet, &request.scope, fields)
            .await?;
        let expected_workspace = request.scope.workspace_id().into_uuid();
        let expected_run = request.swarm_run_id.into_uuid();
        if view.workspace_id != expected_workspace || view.swarm_run_id != expected_run {
            return Err(ForgeHttpClientError::Protocol);
        }
        if let Some(ref receipt) = view.receipt
            && (receipt.swarm_run_id != expected_run || !is_hex_64(&receipt.converged_diff_digest))
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        if let Some(ref entry) = view.outbox_entry {
            let crate::ops::effect_facts::wire::EffectFactWire::SwarmSettled {
                settlement_id,
                workspace_id,
                swarm_run_id,
                settled_tree_digest,
                converged_diff_digest,
                coordinator_agent_id,
                settled_at_ms,
                ..
            } = &entry.fact
            else {
                return Err(ForgeHttpClientError::Protocol);
            };
            if entry.sequence == 0
                || entry.workspace_id != expected_workspace
                || *workspace_id != expected_workspace
                || *swarm_run_id != expected_run
                || settlement_id.is_nil()
                || coordinator_agent_id.is_nil()
                || !is_hex_64(settled_tree_digest)
                || !is_hex_64(converged_diff_digest)
                || *settled_at_ms < 0
                || view
                    .receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.settlement_id != settlement_id.to_string())
            {
                return Err(ForgeHttpClientError::Protocol);
            }
        }
        Ok(view)
    }

    /// Purge ephemeral Swarm member worktrees, baseline/member manifests, and settlement journals.
    pub async fn swarm_purge(
        &self,
        request: &SwarmPurgeRequest,
    ) -> Result<SwarmPurgeWire, ForgeHttpClientError> {
        validate_non_nil(request.swarm_run_id.into_uuid())?;
        validate_non_nil(request.session_id.into_uuid())?;
        let fields = json!({
            "actor": actor_dto(&request.scope, request.session_id, request.principal),
            "swarm_run_id": request.swarm_run_id.into_uuid(),
        });
        let purged: SwarmPurgeWire = self
            .execute_swarm_command(CommandOp::SwarmPurge, &request.scope, fields)
            .await?;
        if purged.workspace_id != request.scope.workspace_id().into_uuid()
            || purged.swarm_run_id != request.swarm_run_id.into_uuid()
            || !purged.purged
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        Ok(purged)
    }

    async fn execute_swarm_command<R: DeserializeOwned>(
        &self,
        op: CommandOp,
        scope: &ResolvedWorkspaceScope,
        fields: Value,
    ) -> Result<R, ForgeHttpClientError> {
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForgeHttpClientError::Capacity)?;
        let request_id = Uuid::now_v7();
        let body = migration_request_body(op, migration_scope_payload(scope)?, fields, request_id)?;
        let result = tokio::time::timeout(self.timeout, self.exchange_command(op, body))
            .await
            .map_err(|_| ForgeHttpClientError::Timeout)??;
        let value = decode_command_response(result, request_id)?;
        serde_json::from_value(value).map_err(|_| ForgeHttpClientError::Protocol)
    }
}

fn actor_dto(
    scope: &ResolvedWorkspaceScope,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
) -> SessionActorDto {
    SessionActorDto {
        session_id: session_id.into_uuid(),
        principal: PrincipalDto::from_domain(principal),
        workspace_id: scope.workspace_id().into_uuid(),
    }
}

fn validate_non_nil(id: Uuid) -> Result<(), ForgeHttpClientError> {
    if id.is_nil() {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    Ok(())
}

fn validate_commit_oid(oid: &str) -> Result<(), ForgeHttpClientError> {
    if !(40..=64).contains(&oid.len()) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ForgeHttpClientError::InvalidRequest);
    }
    Ok(())
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_settlement_receipt_wire(
    receipt: &SwarmSettlementReceiptWire,
    expected_settlement_id: Uuid,
    expected_swarm_run_id: Uuid,
    expected_converged_commit_oid: &str,
    expected_target: SwarmTargetWire,
) -> Result<(), ForgeHttpClientError> {
    if receipt.settlement_id != expected_settlement_id.to_string()
        || receipt.swarm_run_id != expected_swarm_run_id
        || receipt.converged_commit_oid != expected_converged_commit_oid
        || receipt.target != expected_target
        || !is_hex_64(&receipt.converged_diff_digest)
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use forge_control::{
        AgentBindingActivateRequest, AgentBindingReserveRequest, AgentOperationsDelegationRequest,
        CoordinatorClaimRequest, EffectFactOutboxReadRequest, ForgeApprovalCoordinator,
        ForgeControl, ForgeControlWorker, ForgeExecutionCoordinator, SwarmConvergeRequest,
        SwarmConvergenceCandidate, SwarmMemberCaptureRequest, SwarmPurgeRequest,
        SwarmSettleRequest, SwarmSettlementGetRequest, SwarmWorkspaceGetRequest,
        SwarmWorkspaceProvisionRequest,
    };
    use forge_domain::{
        ActivityId, AgentDeclaredRole, AgentDisplayName, AgentInstanceId, AgentSessionId,
        AgentSessionOpenRequestId, AgentTransportKind, AuthenticatedPrincipal, EstablishWorkspace,
        ForgeBackendId, LocationId, LocationRevision, OpenAgentSession, OrchestrationIssuerId,
        RuntimeInstanceId, SwarmMemberId, SwarmRunId, SwarmSettlementTarget, SwarmWorkspaceMode,
        TimestampMillis, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{
        AgentBindingActivationRequest, AgentBindingReservationRequest,
        AgentOperationsFreezeRequest, GlobalRegistry, WorkspaceStore,
    };
    use forge_workspace::{LocationService, WorkspaceStateLayout};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use uuid::Uuid;

    use crate::bridge::{CommandExecutor, ControlBridge};
    use crate::client::{ForgeHttpClient, ForgeHttpClientError, ForgeHttpServiceCode};
    use crate::config::BackendConfig;
    use crate::events::ControlEventQuery;
    use crate::http::{AppState, router};
    use crate::ops::effect_facts::wire::EffectFactWire;
    use crate::ops::swarm::{SettlementJournalStateWire, SwarmConvergenceOutcomeWire};

    static NEXT_HTTP_SWARM_SEQ: AtomicU64 = AtomicU64::new(1);

    struct HttpSwarmTestEnv {
        root: PathBuf,
        workspace_root: PathBuf,
        registry_path: PathBuf,
        location_id: LocationId,
    }

    impl HttpSwarmTestEnv {
        fn new(label: &str) -> Result<Self, Box<dyn Error>> {
            let seq = NEXT_HTTP_SWARM_SEQ.fetch_add(1, Ordering::Relaxed);
            // Must remain outside /Volumes/256.SSD/RustBuild so Forge path_policy allows worktrees.
            let root = PathBuf::from(format!(
                "/var/tmp/heterarchy-forge-backend-swarm-{label}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            let location_root = root.join("location");
            let workspace_root = location_root.join("workspace-0");
            fs::create_dir_all(&workspace_root)?;
            let registry_path = root.join("registry.sqlite3");
            let location_id = LocationId::from_uuid(Uuid::now_v7());
            let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
            let location = locations.register_selected_path(
                location_id,
                "Backend Swarm Test Location",
                &location_root,
                TimestampMillis::new(1)?,
            )?;
            drop(locations);
            let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
            let canonical_ws_root =
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
            let _store = WorkspaceStore::open(
                &layout,
                EstablishWorkspace::new(
                    WorkspaceId::from_uuid(Uuid::now_v7()),
                    location.id(),
                    canonical_ws_root,
                    layout.root_fingerprint()?,
                    TimestampMillis::new(2)?,
                ),
            )?;
            Ok(Self {
                root,
                workspace_root,
                registry_path,
                location_id,
            })
        }
    }

    impl Drop for HttpSwarmTestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn now_ts() -> Result<TimestampMillis, Box<dyn Error>> {
        let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        Ok(TimestampMillis::new(i64::try_from(millis)?)?)
    }

    struct LiveHttpSwarmHarness {
        env: HttpSwarmTestEnv,
        http_client: ForgeHttpClient,
        scope: forge_control::ResolvedWorkspaceScope,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        migration_id: Uuid,
        destination_id: Uuid,
        live_now: TimestampMillis,
        stop_tx: oneshot::Sender<()>,
        server_join: tokio::task::JoinHandle<Result<(), std::io::Error>>,
        bridge: Arc<ControlBridge>,
        approval: ForgeApprovalCoordinator,
        execution: ForgeExecutionCoordinator,
        control_worker: ForgeControlWorker,
    }

    struct CoordinatorIdentity {
        runtime_instance_id: RuntimeInstanceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        live_now: TimestampMillis,
    }

    struct DelegationIds {
        migration_id: Uuid,
        destination_id: Uuid,
    }

    impl LiveHttpSwarmHarness {
        async fn start() -> Result<Self, Box<dyn Error>> {
            let env = HttpSwarmTestEnv::new("e2e")?;
            fs::write(
                env.workspace_root.join("shared.txt"),
                "line1\nline2\nline3\nline4\nline5\n",
            )?;
            let control = ForgeControl::new(GlobalRegistry::open(&env.registry_path)?);
            let (control_client, control_worker) = ForgeControlWorker::start(control)?;
            let locator = control_client
                .workspace_discover(env.location_id, LocationRevision::INITIAL)?
                .into_iter()
                .find(|entry| entry.display_name() == "workspace-0")
                .ok_or("workspace-0 missing")?
                .locator()
                .clone();
            let scope = control_client.resolve_workspace(
                env.location_id,
                LocationRevision::INITIAL,
                locator,
            )?;
            let live_now = now_ts()?;
            let coords = CoordinatorIdentity {
                runtime_instance_id: RuntimeInstanceId::from_uuid(Uuid::now_v7()),
                activity_id: ActivityId::from_uuid(Uuid::now_v7()),
                agent_id: AgentInstanceId::from_uuid(Uuid::now_v7()),
                session_id: AgentSessionId::from_uuid(Uuid::now_v7()),
                principal: AuthenticatedPrincipal::TrustedStdio,
                live_now,
            };
            let _activity = control_client.bootstrap_activity(
                scope.clone(),
                coords.activity_id,
                coords.runtime_instance_id,
                live_now,
                TimestampMillis::new(live_now.get() + 600_000)?,
            )?;
            let _session = control_client.agent_session_open(OpenAgentSession::new(
                coords.session_id,
                AgentSessionOpenRequestId::from_uuid(Uuid::now_v7()),
                coords.principal,
                live_now,
            ))?;
            let (migration_id, destination_id) =
                activate_delegated_coordinator(&env, &control_client, &scope, &coords)?;
            Self::spawn_http_server(
                env,
                control_client,
                control_worker,
                scope,
                coords,
                DelegationIds {
                    migration_id,
                    destination_id,
                },
            )
            .await
        }

        async fn spawn_http_server(
            env: HttpSwarmTestEnv,
            control_client: forge_control::ForgeControlClient,
            control_worker: ForgeControlWorker,
            scope: forge_control::ResolvedWorkspaceScope,
            coords: CoordinatorIdentity,
            delegation: DelegationIds,
        ) -> Result<Self, Box<dyn Error>> {
            let execution = ForgeExecutionCoordinator::start(control_client.clone(), 1)?;
            let approval =
                ForgeApprovalCoordinator::start(control_client.clone(), execution.client())?;
            let product_cache_root = env.root.join("product-cache");
            fs::create_dir_all(&product_cache_root)?;
            let backend_id = ForgeBackendId::from_uuid(Uuid::now_v7());
            let issuer_id = OrchestrationIssuerId::from_uuid(Uuid::now_v7());
            let secret = "swarm-http-integration-secret";
            let config =
                BackendConfig::new("127.0.0.1".parse()?, 0, secret, backend_id, issuer_id)?;
            let bridge = Arc::new(ControlBridge::start(
                &control_client,
                &execution.client(),
                &approval.client(),
                coords.runtime_instance_id,
                &config,
                &product_cache_root,
                delegation.destination_id,
            )?);
            let state = AppState::new(
                config,
                bridge.clone(),
                Arc::new(ControlEventQuery::new(control_client.clone())),
            );
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let authority = listener.local_addr()?;
            let (stop_tx, stop_rx) = oneshot::channel::<()>();
            let server_join = tokio::spawn(async move {
                let app = router(state);
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = stop_rx.await;
                    })
                    .await
            });
            let http_client = ForgeHttpClient::new(
                authority,
                secret,
                backend_id,
                delegation.destination_id,
                Duration::from_secs(5),
            )?;
            Ok(Self {
                env,
                http_client,
                scope,
                activity_id: coords.activity_id,
                agent_id: coords.agent_id,
                session_id: coords.session_id,
                principal: coords.principal,
                migration_id: delegation.migration_id,
                destination_id: delegation.destination_id,
                live_now: coords.live_now,
                stop_tx,
                server_join,
                bridge,
                approval,
                execution,
                control_worker,
            })
        }

        async fn shutdown(mut self) -> Result<(), Box<dyn Error>> {
            let _ = self.stop_tx.send(());
            self.server_join.await??;
            let _ = self.bridge.drain_and_join(Duration::from_secs(2));
            let _ = self.approval.shutdown();
            let _ = self.execution.shutdown();
            self.control_worker.shutdown()?;
            Ok(())
        }
    }

    fn activate_delegated_coordinator(
        env: &HttpSwarmTestEnv,
        control_client: &forge_control::ForgeControlClient,
        scope: &forge_control::ResolvedWorkspaceScope,
        coords: &CoordinatorIdentity,
    ) -> Result<(Uuid, Uuid), Box<dyn Error>> {
        let layout = WorkspaceStateLayout::inspect_existing(&env.workspace_root)?
            .ok_or("workspace layout missing")?;
        let mut store = WorkspaceStore::open_existing(&layout)?;
        let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            coords.live_now,
        )?)?;
        drop(store);
        let migration_id = freeze.migration_id();
        let destination_id = freeze.destination_id();

        let binding_req_id = Uuid::now_v7();
        let reservation = AgentBindingReservationRequest::new(
            binding_req_id,
            coords.activity_id,
            coords.agent_id,
            coords.session_id,
            coords.principal,
            coords.live_now,
        )?;
        let _reserved = control_client.reserve_agent_binding(AgentBindingReserveRequest {
            scope: scope.clone(),
            freeze: freeze.clone(),
            reservation,
            observed_at: coords.live_now,
        })?;
        let delegation =
            control_client.delegate_agent_operations(AgentOperationsDelegationRequest {
                scope: scope.clone(),
                freeze,
                manifest_digest: [0xC1; 32],
                observed_at: coords.live_now,
            })?;
        let activation = AgentBindingActivationRequest::new(
            binding_req_id,
            [0xC2; 32],
            AgentDisplayName::new("Swarm HTTP Coordinator".to_owned())?,
            AgentDeclaredRole::new("coordinator".to_owned())?,
            AgentTransportKind::Stdio,
        )?;
        let _activated = control_client.activate_agent_binding(AgentBindingActivateRequest {
            scope: scope.clone(),
            delegation,
            activation,
            session_id: coords.session_id,
            principal: coords.principal,
            observed_at: coords.live_now,
        })?;
        let _coordinator = control_client.activity_coordinator_claim(CoordinatorClaimRequest {
            session_id: coords.session_id,
            scope: scope.clone(),
            activity_id: coords.activity_id,
            agent_id: coords.agent_id,
            principal: coords.principal,
            observed_at: coords.live_now,
        })?;
        Ok((migration_id, destination_id))
    }

    async fn converge_share_and_branch(
        h: &LiveHttpSwarmHarness,
        swarm_run_id: SwarmRunId,
        share_id: SwarmMemberId,
        branch_id: SwarmMemberId,
    ) -> Result<(String, [u8; 32]), Box<dyn Error>> {
        let share_ws = h
            .http_client
            .swarm_workspace_provision(&SwarmWorkspaceProvisionRequest {
                scope: h.scope.clone(),
                session_id: h.session_id,
                principal: h.principal,
                swarm_run_id,
                member_id: share_id,
                mode: SwarmWorkspaceMode::Share,
                target: SwarmSettlementTarget::StandaloneSwarm,
                candidate_commit_oid: None,
                observed_at: h.live_now,
            })
            .await?;
        let branch_ws = h
            .http_client
            .swarm_workspace_provision(&SwarmWorkspaceProvisionRequest {
                scope: h.scope.clone(),
                session_id: h.session_id,
                principal: h.principal,
                swarm_run_id,
                member_id: branch_id,
                mode: SwarmWorkspaceMode::Branch,
                target: SwarmSettlementTarget::StandaloneSwarm,
                candidate_commit_oid: None,
                observed_at: h.live_now,
            })
            .await?;

        let inspected = h
            .http_client
            .swarm_workspace_get(&SwarmWorkspaceGetRequest {
                scope: h.scope.clone(),
                swarm_run_id,
                member_id: share_id,
            })
            .await?;
        assert!(inspected.found);
        assert_eq!(inspected.receipt.as_ref(), Some(&share_ws));

        fs::write(
            PathBuf::from(&share_ws.worktree_path).join("shared.txt"),
            "line1-http-share\nline2\nline3\nline4\nline5\n",
        )?;
        fs::write(
            PathBuf::from(&branch_ws.worktree_path).join("shared.txt"),
            "line1\nline2\nline3\nline4\nline5-http-branch\n",
        )?;

        let share_out = h
            .http_client
            .swarm_member_capture(&SwarmMemberCaptureRequest {
                scope: h.scope.clone(),
                session_id: h.session_id,
                principal: h.principal,
                swarm_run_id,
                member_id: share_id,
                captured_at: h.live_now,
            })
            .await?;
        let branch_out = h
            .http_client
            .swarm_member_capture(&SwarmMemberCaptureRequest {
                scope: h.scope.clone(),
                session_id: h.session_id,
                principal: h.principal,
                swarm_run_id,
                member_id: branch_id,
                captured_at: h.live_now,
            })
            .await?;

        let SwarmConvergenceOutcomeWire::Converged {
            converged_commit_oid,
            converged_diff_digest,
            ..
        } = h
            .http_client
            .swarm_converge(&SwarmConvergeRequest {
                scope: h.scope.clone(),
                session_id: h.session_id,
                principal: h.principal,
                swarm_run_id,
                candidates: vec![
                    SwarmConvergenceCandidate {
                        member_id: share_id,
                        expected_output_commit_oid: Some(share_out.output_commit_oid),
                        expected_diff_digest: None,
                    },
                    SwarmConvergenceCandidate {
                        member_id: branch_id,
                        expected_output_commit_oid: Some(branch_out.output_commit_oid),
                        expected_diff_digest: None,
                    },
                ],
                observed_at: h.live_now,
            })
            .await?
        else {
            return Err("expected converged outcome over HTTP".into());
        };
        Ok((converged_commit_oid, decode_hex_32(&converged_diff_digest)?))
    }

    async fn verify_settle_and_outbox(
        h: &LiveHttpSwarmHarness,
        swarm_run_id: SwarmRunId,
        converged_commit_oid: String,
        expected_digest: [u8; 32],
    ) -> Result<(), Box<dyn Error>> {
        let settlement_id = Uuid::now_v7();
        let settled = h
            .http_client
            .swarm_settle(&SwarmSettleRequest {
                scope: h.scope.clone(),
                activity_id: Some(h.activity_id),
                session_id: h.session_id,
                principal: h.principal,
                coordinator_agent_id: h.agent_id,
                swarm_run_id,
                settlement_id,
                converged_commit_oid: converged_commit_oid.clone(),
                expected_diff_digest: Some(expected_digest),
                settled_at: h.live_now,
            })
            .await?;
        assert_eq!(settled.receipt.state, SettlementJournalStateWire::Applied);
        assert_eq!(settled.outbox_sequence, Some(1));
        assert_eq!(
            fs::read_to_string(h.env.workspace_root.join("shared.txt"))?,
            "line1-http-share\nline2\nline3\nline4\nline5-http-branch\n"
        );

        let outbox = h
            .http_client
            .effect_fact_outbox(&EffectFactOutboxReadRequest {
                scope: h.scope.clone(),
                migration_id: h.migration_id,
                destination_id: h.destination_id,
                after: 0,
                limit: 16,
            })
            .await?;
        assert_eq!(outbox.entries.len(), 1);
        assert!(matches!(
            &outbox.entries[0].fact,
            EffectFactWire::SwarmSettled {
                settlement_id: wire_sid,
                swarm_run_id: wire_run,
                ..
            } if *wire_sid == settlement_id && *wire_run == swarm_run_id.into_uuid()
        ));

        let conflict_err = h
            .http_client
            .swarm_settle(&SwarmSettleRequest {
                scope: h.scope.clone(),
                activity_id: Some(h.activity_id),
                session_id: h.session_id,
                principal: h.principal,
                coordinator_agent_id: h.agent_id,
                swarm_run_id,
                settlement_id: Uuid::now_v7(),
                converged_commit_oid,
                expected_diff_digest: Some(expected_digest),
                settled_at: h.live_now,
            })
            .await
            .err()
            .ok_or("conflicting settlement_id must fail over HTTP")?;
        assert!(matches!(
            conflict_err,
            ForgeHttpClientError::Service {
                code: ForgeHttpServiceCode::PlanningConflict,
                ..
            }
        ));
        Ok(())
    }

    async fn verify_purge_and_post_state(
        h: &LiveHttpSwarmHarness,
        swarm_run_id: SwarmRunId,
        share_id: SwarmMemberId,
    ) -> Result<(), Box<dyn Error>> {
        let pre_purge = h
            .http_client
            .swarm_settlement_get(&SwarmSettlementGetRequest {
                scope: h.scope.clone(),
                swarm_run_id,
            })
            .await?;
        assert!(pre_purge.receipt.is_some());
        assert!(
            h.http_client
                .swarm_purge(&SwarmPurgeRequest {
                    scope: h.scope.clone(),
                    session_id: h.session_id,
                    principal: h.principal,
                    swarm_run_id,
                })
                .await?
                .purged
        );
        assert!(
            !h.http_client
                .swarm_workspace_get(&SwarmWorkspaceGetRequest {
                    scope: h.scope.clone(),
                    swarm_run_id,
                    member_id: share_id,
                })
                .await?
                .found
        );
        let post_purge = h
            .http_client
            .swarm_settlement_get(&SwarmSettlementGetRequest {
                scope: h.scope.clone(),
                swarm_run_id,
            })
            .await?;
        assert!(post_purge.receipt.is_none());
        assert_eq!(post_purge.outbox_entry.map(|e| e.sequence), Some(1));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_client_swarm_lifecycle_settles_emits_kind_6_and_purges()
    -> Result<(), Box<dyn Error>> {
        let h = LiveHttpSwarmHarness::start().await?;
        let swarm_run_id = SwarmRunId::from_uuid(Uuid::now_v7());
        let share_id = SwarmMemberId::from_uuid(Uuid::now_v7());
        let branch_id = SwarmMemberId::from_uuid(Uuid::now_v7());
        let bad_oid_err = h
            .http_client
            .swarm_workspace_provision(&SwarmWorkspaceProvisionRequest {
                scope: h.scope.clone(),
                session_id: h.session_id,
                principal: h.principal,
                swarm_run_id,
                member_id: share_id,
                mode: SwarmWorkspaceMode::Share,
                target: SwarmSettlementTarget::StandaloneSwarm,
                candidate_commit_oid: Some("../bad".to_owned()),
                observed_at: h.live_now,
            })
            .await
            .err()
            .ok_or("client preflight must reject invalid OID")?;
        assert_eq!(bad_oid_err, ForgeHttpClientError::InvalidRequest);

        let (converged_commit_oid, expected_digest) =
            converge_share_and_branch(&h, swarm_run_id, share_id, branch_id).await?;
        verify_settle_and_outbox(&h, swarm_run_id, converged_commit_oid, expected_digest).await?;
        verify_purge_and_post_state(&h, swarm_run_id, share_id).await?;
        h.shutdown().await
    }

    fn decode_hex_32(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let bytes = crate::ops::decode_hex(value).map_err(|_| "invalid hex digest")?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "expected 32-byte digest".into())
    }
}
