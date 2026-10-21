//! Same-Activity recovery for an expired lease when durable work actually started.

use std::error::Error;

use forge_domain::{
    ActivityCoordinatorRevision, ActivityId, ActivityLeaseProjection, ActivityLeaseRevision,
    ActivityRevision, ActivityState, AgentInstanceId, AgentInstanceRevision, AgentSessionId,
    AgentSessionRevision, AgentSessionState, AuthenticatedPrincipal, DirectTokenId,
    ExpiredActivityRecoveryProbeScope, LocationId, LocationRevision, OAuthGrantId,
    RegisteredActivity, RuntimeInstanceId, StartedActivityLeaseResumeAgentSnapshot,
    StartedActivityLeaseResumeAssignmentCensus, StartedActivityLeaseResumeBlocker,
    StartedActivityLeaseResumeCoordinatorSnapshot, StartedActivityLeaseResumeDagCensus,
    StartedActivityLeaseResumeExpectation, StartedActivityLeaseResumeGetRequest,
    StartedActivityLeaseResumeGoalCensus, StartedActivityLeaseResumePhysicalCensus,
    StartedActivityLeaseResumeProbe, StartedActivityLeaseResumeProbeRequest,
    StartedActivityLeaseResumeReceipt, StartedActivityLeaseResumeRunRequest,
    StartedActivityLeaseResumeServiceIdentity, StartedActivityLeaseResumeSessionSnapshot,
    StartedActivityLeaseResumeValidationError, TimestampMillis, WorkspaceId, WorkspaceRevision,
    WorkspaceRootFingerprint,
};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, Params, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{WorkspaceJournalBinding, WorkspaceStore, WorkspaceStoreError};

const RECEIPT_PAYLOAD_VERSION: &[u8; 4] = b"G04\x01";
const RECEIPT_PAYLOAD_DOMAIN: &[u8] = b"forge.started_activity_lease_resume.receipt.v1";
const MAX_RECEIPT_PAYLOAD_BYTES: usize = 65_536;

pub use forge_domain::StartedActivityLeaseResumeOperation;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedActivityLeaseResumeReadback {
    receipt: StartedActivityLeaseResumeReceipt,
}

impl StartedActivityLeaseResumeReadback {
    pub const fn receipt(&self) -> &StartedActivityLeaseResumeReceipt {
        &self.receipt
    }
}

#[derive(Debug, Error)]
pub enum StartedActivityLeaseResumeStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("started Activity lease resume input is invalid: {0}")]
    Invalid(&'static str),
    #[error("started Activity lease resume conflicts with durable state: {0}")]
    Conflict(&'static str),
    #[error("started Activity lease resume receipt is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("started Activity lease resume clock observation failed")]
    Clock(#[source] Box<dyn Error + Send + Sync>),
    #[error(transparent)]
    Domain(#[from] StartedActivityLeaseResumeValidationError),
    #[error(transparent)]
    Scope(#[from] forge_domain::ExpiredActivityRecoveryValidationError),
    #[error("started Activity lease resume Workspace persistence failure")]
    Workspace(#[source] Box<WorkspaceStoreError>),
}

impl From<WorkspaceStoreError> for StartedActivityLeaseResumeStoreError {
    fn from(value: WorkspaceStoreError) -> Self {
        Self::Workspace(Box::new(value))
    }
}

impl WorkspaceStore {
    /// Capture one Source-selected, read-only started-work recovery probe.
    #[allow(clippy::too_many_arguments)]
    pub fn probe_started_activity_lease_resume(
        &self,
        binding: &WorkspaceJournalBinding,
        request: &StartedActivityLeaseResumeProbeRequest,
        service: StartedActivityLeaseResumeServiceIdentity,
        initiating_session: StartedActivityLeaseResumeSessionSnapshot,
        coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
        observed_at: TimestampMillis,
    ) -> Result<StartedActivityLeaseResumeProbe, WorkspaceStoreError> {
        if self.journal_binding()? != *binding
            || binding.recovery_history_digest() != *request.scope().binding_digest()
        {
            return Err(StartedActivityLeaseResumeStoreError::Conflict("binding").into());
        }
        if initiating_session.session_id() != request.initiating_session_id()
            || initiating_session.principal() != request.principal()
        {
            return Err(
                StartedActivityLeaseResumeStoreError::Conflict("initiating Session").into(),
            );
        }
        super::validate_schema_shape(&self.connection)?;
        let transaction = self.connection.unchecked_transaction()?;
        let result = probe_in_transaction(
            &transaction,
            binding,
            request.scope(),
            request.activity_id(),
            request.initiating_session_id(),
            request.principal(),
            service,
            initiating_session,
            coordinator_session,
            observed_at,
        );
        match result {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error.into())
            }
        }
    }

    /// Atomically compare the exact probe, advance only the Activity lease
    /// tuple, and record the immutable receipt in the same SQLite transaction.
    pub fn run_started_activity_lease_resume_with_clock<F>(
        &mut self,
        binding: &WorkspaceJournalBinding,
        request: &StartedActivityLeaseResumeRunRequest,
        initiating_session: StartedActivityLeaseResumeSessionSnapshot,
        coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
        clock: F,
    ) -> Result<StartedActivityLeaseResumeOperation, WorkspaceStoreError>
    where
        F: FnOnce() -> Result<TimestampMillis, WorkspaceStoreError>,
    {
        let expected_agent = validate_run_request(self, binding, request, initiating_session)?;
        super::validate_schema_shape(&self.connection)?;
        let live_paths = super::WorkspaceLiveBinding {
            state_root: &self.state_root,
            state_root_identity: self.state_root_identity,
            workspace_root: &self.workspace_root,
            root_fingerprint: self.root_fingerprint,
            database_path: &self.path,
            database_identity: self.database_identity,
            wal_identity: self.wal_identity,
            shm_identity: self.shm_identity,
        };
        super::ensure_live_paths(live_paths)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::ensure_live_paths(live_paths)?;
        if let Some(receipt) =
            replay_if_present(&transaction, request, expected_agent, initiating_session)?
        {
            transaction.commit()?;
            return Ok(StartedActivityLeaseResumeOperation::Replay(receipt));
        }
        let source_now = clock()
            .map_err(|error| StartedActivityLeaseResumeStoreError::Clock(Box::new(error)))?;
        super::ensure_live_paths(live_paths)?;
        let receipt = record_resume_in_transaction(
            &transaction,
            binding,
            request,
            initiating_session,
            coordinator_session,
            source_now,
        )?;
        super::ensure_live_paths(live_paths)?;
        transaction.commit().map_err(|error| {
            WorkspaceStoreError::StartedActivityLeaseResumeCommittedUnconfirmed {
                request_id: request.request_id(),
                source: Box::new(WorkspaceStoreError::StartedActivityLeaseResume(
                    StartedActivityLeaseResumeStoreError::Sqlite(error),
                )),
            }
        })?;

        let get_request = StartedActivityLeaseResumeGetRequest::new(
            request.scope().clone(),
            request.request_id(),
            request.request_digest(),
            receipt.activity_id(),
            expected_agent.agent_id(),
            initiating_session.session_id(),
            initiating_session.principal(),
        )
        .map_err(StartedActivityLeaseResumeStoreError::Domain)?;
        match self.started_activity_lease_resume_readback_for_request(binding, &get_request) {
            Ok(Some(readback)) if readback.receipt == receipt => {
                Ok(StartedActivityLeaseResumeOperation::Recorded(receipt))
            }
            Ok(_) => Err(
                WorkspaceStoreError::StartedActivityLeaseResumeCommittedUnconfirmed {
                    request_id: request.request_id(),
                    source: Box::new(WorkspaceStoreError::StartedActivityLeaseResume(
                        StartedActivityLeaseResumeStoreError::Corrupt("committed receipt readback"),
                    )),
                },
            ),
            Err(error) => Err(
                WorkspaceStoreError::StartedActivityLeaseResumeCommittedUnconfirmed {
                    request_id: request.request_id(),
                    source: Box::new(error),
                },
            ),
        }
    }

    /// Read one immutable receipt using every identity field supplied by Get.
    pub fn started_activity_lease_resume_readback_for_request(
        &self,
        binding: &WorkspaceJournalBinding,
        request: &StartedActivityLeaseResumeGetRequest,
    ) -> Result<Option<StartedActivityLeaseResumeReadback>, WorkspaceStoreError> {
        if self.journal_binding()? != *binding {
            return Err(StartedActivityLeaseResumeStoreError::Conflict("binding").into());
        }
        super::validate_schema_shape(&self.connection)?;
        let row = self
            .connection
            .query_row(
                "SELECT request_digest, workspace_id, activity_id, location_id,
                    location_revision, workspace_revision, locator, root_fingerprint,
                    binding_digest, agent_id, initiating_session_id, principal_kind,
                    principal_id, source_runtime_instance_id, resumed_at_ms,
                    receipt_payload, receipt_checksum
             FROM started_activity_lease_resume_receipts WHERE request_id=?1",
                params![request.request_id().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, Option<Vec<u8>>>(12)?,
                        row.get::<_, Vec<u8>>(13)?,
                        row.get::<_, i64>(14)?,
                        row.get::<_, Vec<u8>>(15)?,
                        row.get::<_, Vec<u8>>(16)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            request_digest,
            workspace_id,
            activity_id,
            location_id,
            location_revision,
            workspace_revision,
            locator,
            root_fingerprint,
            binding_digest,
            agent_id,
            initiating_session_id,
            principal_kind,
            principal_id,
            source_runtime_id,
            resumed_at,
            payload,
            checksum,
        )) = row
        else {
            return Ok(None);
        };
        if decode_digest(&request_digest, "request_digest")? != request.request_digest()
            || decode_uuid(&workspace_id, "workspace_id")?
                != request.scope().workspace_id().into_uuid()
            || decode_uuid(&activity_id, "activity_id")? != request.activity_id().into_uuid()
            || decode_uuid(&location_id, "location_id")?
                != request.scope().location_id().into_uuid()
            || location_revision != request.scope().location_revision().get()
            || workspace_revision != request.scope().workspace_revision().get()
            || locator.as_slice() != request.scope().locator()
            || decode_fixed::<16>(&root_fingerprint, "root_fingerprint")?
                != request.scope().root_fingerprint().into_bytes()
            || decode_digest(&binding_digest, "binding_digest")?
                != *request.scope().binding_digest()
            || decode_uuid(&agent_id, "agent_id")? != request.agent_id().into_uuid()
            || decode_uuid(&initiating_session_id, "initiating_session_id")?
                != request.initiating_session_id().into_uuid()
            || decode_principal(principal_kind, principal_id.as_deref())? != request.principal()
        {
            return Err(StartedActivityLeaseResumeStoreError::Conflict("receipt identity").into());
        }
        let source_runtime = decode_uuid(&source_runtime_id, "source_runtime_instance_id")?;
        let resumed_at = decode_timestamp(resumed_at, "resumed_at_ms")?;
        if payload.len() > MAX_RECEIPT_PAYLOAD_BYTES
            || decode_digest(&checksum, "receipt_checksum")? != digest_receipt_payload(&payload)
        {
            return Err(StartedActivityLeaseResumeStoreError::Corrupt("payload checksum").into());
        }
        let receipt = decode_receipt(&payload)?;
        if receipt.request_id() != request.request_id()
            || receipt.request_digest() != request.request_digest()
            || receipt.activity_id() != request.activity_id()
            || receipt.initiating_agent().agent_id() != request.agent_id()
            || receipt.initiating_session().session_id() != request.initiating_session_id()
            || receipt.initiating_session().principal() != request.principal()
            || receipt.source_runtime_instance_id().into_uuid() != source_runtime
            || receipt.resumed_at() != resumed_at
            || receipt.scope() != request.scope()
        {
            return Err(StartedActivityLeaseResumeStoreError::Corrupt("payload identity").into());
        }
        Ok(Some(StartedActivityLeaseResumeReadback { receipt }))
    }
}

fn validate_run_request(
    store: &WorkspaceStore,
    binding: &WorkspaceJournalBinding,
    request: &StartedActivityLeaseResumeRunRequest,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
) -> Result<StartedActivityLeaseResumeAgentSnapshot, WorkspaceStoreError> {
    if store.journal_binding()? != *binding
        || binding.recovery_history_digest() != *request.scope().binding_digest()
    {
        return Err(StartedActivityLeaseResumeStoreError::Conflict("binding").into());
    }
    let expected_probe = request.probe();
    let agent = expected_probe
        .expectation()
        .initiating_agent()
        .copied()
        .ok_or(StartedActivityLeaseResumeStoreError::Conflict(
            "initiating Agent missing",
        ))?;
    if initiating_session.session_id()
        != expected_probe
            .expectation()
            .initiating_session()
            .session_id()
        || initiating_session.principal()
            != expected_probe
                .expectation()
                .initiating_session()
                .principal()
    {
        return Err(
            StartedActivityLeaseResumeStoreError::Conflict("initiating Session changed").into(),
        );
    }
    Ok(agent)
}

fn replay_if_present(
    connection: &Connection,
    request: &StartedActivityLeaseResumeRunRequest,
    expected_agent: StartedActivityLeaseResumeAgentSnapshot,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
) -> Result<Option<StartedActivityLeaseResumeReceipt>, StartedActivityLeaseResumeStoreError> {
    let Some(receipt) = load_receipt(connection, request.request_id())? else {
        return Ok(None);
    };
    if receipt.request_digest() != request.request_digest()
        || receipt.scope() != request.scope()
        || receipt.probe_digest() != request.probe().probe_digest()
        || receipt.activity_id() != expected_agent.activity_id()
        || receipt.initiating_agent().agent_id() != expected_agent.agent_id()
        || receipt.initiating_session().session_id() != initiating_session.session_id()
        || receipt.initiating_session().principal() != initiating_session.principal()
    {
        return Err(StartedActivityLeaseResumeStoreError::Conflict(
            "request identity/digest",
        ));
    }
    Ok(Some(receipt))
}

#[allow(clippy::too_many_arguments)]
fn record_resume_in_transaction(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    request: &StartedActivityLeaseResumeRunRequest,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
    resumed_at: TimestampMillis,
) -> Result<StartedActivityLeaseResumeReceipt, StartedActivityLeaseResumeStoreError> {
    let probe = request.probe();
    if !probe.is_live_at(resumed_at) {
        return Err(StartedActivityLeaseResumeStoreError::Conflict(
            "probe expired or clock regressed",
        ));
    }
    if request.current_service().runtime_instance_id() != probe.service().runtime_instance_id() {
        return Err(StartedActivityLeaseResumeStoreError::Conflict(
            "Source boot changed",
        ));
    }
    let current = recompute_probe(
        transaction,
        binding,
        request,
        initiating_session,
        coordinator_session,
    )?;
    if current != *probe || !current.resumable_now() {
        return Err(StartedActivityLeaseResumeStoreError::Conflict(
            "Source probe fence changed",
        ));
    }
    let activity_after = advance_activity_lease(transaction, request, probe, resumed_at)?;
    let receipt = StartedActivityLeaseResumeReceipt::from_successful_probe(
        probe,
        request.request_id(),
        request.request_digest(),
        activity_after,
        resumed_at,
    )?;
    insert_receipt(transaction, request, &receipt)?;
    Ok(receipt)
}

fn recompute_probe(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    request: &StartedActivityLeaseResumeRunRequest,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
) -> Result<StartedActivityLeaseResumeProbe, StartedActivityLeaseResumeStoreError> {
    let probe = request.probe();
    let probe_request = StartedActivityLeaseResumeProbeRequest::new(
        request.scope().clone(),
        probe.expectation().activity().id(),
        initiating_session.session_id(),
        initiating_session.principal(),
    )?;
    probe_in_transaction(
        transaction,
        binding,
        request.scope(),
        probe_request.activity_id(),
        probe_request.initiating_session_id(),
        probe_request.principal(),
        request.current_service(),
        initiating_session,
        coordinator_session,
        probe.probe_observed_at(),
    )
}

fn advance_activity_lease(
    transaction: &Transaction<'_>,
    request: &StartedActivityLeaseResumeRunRequest,
    probe: &StartedActivityLeaseResumeProbe,
    resumed_at: TimestampMillis,
) -> Result<RegisteredActivity, StartedActivityLeaseResumeStoreError> {
    let before = probe.expectation().activity();
    let owner = request.current_service().runtime_instance_id();
    let lease_until = TimestampMillis::new(
        resumed_at
            .get()
            .checked_add(forge_domain::STARTED_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS)
            .ok_or(StartedActivityLeaseResumeStoreError::Invalid(
                "lease deadline overflow",
            ))?,
    )
    .map_err(|_| StartedActivityLeaseResumeStoreError::Invalid("lease deadline"))?;
    let lease_revision = before
        .lease_revision()
        .checked_next()
        .map_err(|_| StartedActivityLeaseResumeStoreError::Conflict("lease revision overflow"))?;
    let original_owner =
        before
            .lease_owner_id()
            .ok_or(StartedActivityLeaseResumeStoreError::Conflict(
                "original lease missing",
            ))?;
    let original_until =
        before
            .lease_until()
            .ok_or(StartedActivityLeaseResumeStoreError::Conflict(
                "original lease missing",
            ))?;
    update_activity_lease(
        transaction,
        before,
        owner,
        lease_until,
        lease_revision,
        original_owner,
        original_until,
    )?;
    let lease = ActivityLeaseProjection::from_parts(Some(owner), Some(lease_until), lease_revision)
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("resumed lease"))?;
    Ok(RegisteredActivity::from_parts_with_lease(
        before.id(),
        before.workspace_id(),
        before.state(),
        before.created_at(),
        before.updated_at(),
        before.revision(),
        lease,
    ))
}

pub(super) fn update_activity_lease(
    transaction: &Transaction<'_>,
    before: &RegisteredActivity,
    owner: RuntimeInstanceId,
    lease_until: TimestampMillis,
    lease_revision: forge_domain::ActivityLeaseRevision,
    original_owner: RuntimeInstanceId,
    original_until: TimestampMillis,
) -> Result<(), StartedActivityLeaseResumeStoreError> {
    let updated = transaction.execute(
        "UPDATE activities SET lease_owner_id=?1, lease_until_ms=?2, lease_revision=?3
         WHERE activity_id=?4 AND workspace_id=?5 AND state=1 AND revision=?6
           AND created_at_ms=?7 AND updated_at_ms=?8 AND lease_owner_id=?9
           AND lease_until_ms=?10 AND lease_revision=?11",
        params![
            owner.into_uuid().as_bytes().as_slice(),
            lease_until.get(),
            lease_revision.get(),
            before.id().into_uuid().as_bytes().as_slice(),
            before.workspace_id().into_uuid().as_bytes().as_slice(),
            before.revision().get(),
            before.created_at().get(),
            before.updated_at().get(),
            original_owner.into_uuid().as_bytes().as_slice(),
            original_until.get(),
            before.lease_revision().get(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(StartedActivityLeaseResumeStoreError::Conflict(
            "Activity lease compare-and-swap",
        ))
    }
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    request: &StartedActivityLeaseResumeRunRequest,
    receipt: &StartedActivityLeaseResumeReceipt,
) -> Result<(), StartedActivityLeaseResumeStoreError> {
    let payload = encode_receipt(receipt);
    if payload.is_empty() || payload.len() > MAX_RECEIPT_PAYLOAD_BYTES {
        return Err(StartedActivityLeaseResumeStoreError::Invalid(
            "receipt payload bounds",
        ));
    }
    let checksum = digest_receipt_payload(&payload);
    let (principal_kind, principal_id) = encode_principal(receipt.initiating_session().principal());
    let agent = receipt.initiating_agent();
    transaction.execute(
        "INSERT INTO started_activity_lease_resume_receipts (
            request_id, request_digest, workspace_id, activity_id, location_id,
            location_revision, workspace_revision, locator, root_fingerprint,
            binding_digest, agent_id, initiating_session_id, principal_kind,
            principal_id, source_runtime_instance_id, resumed_at_ms, receipt_payload,
            receipt_checksum
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        params![
            request.request_id().as_bytes().as_slice(),
            request.request_digest().as_slice(),
            request
                .scope()
                .workspace_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            receipt.activity_id().into_uuid().as_bytes().as_slice(),
            request
                .scope()
                .location_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            request.scope().location_revision().get(),
            request.scope().workspace_revision().get(),
            request.scope().locator(),
            request.scope().root_fingerprint().as_bytes().as_slice(),
            request.scope().binding_digest().as_slice(),
            agent.agent_id().into_uuid().as_bytes().as_slice(),
            receipt
                .initiating_session()
                .session_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            principal_kind,
            principal_id.as_deref(),
            receipt
                .source_runtime_instance_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
            receipt.resumed_at().get(),
            payload,
            checksum.as_slice(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn probe_in_transaction(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    scope: &ExpiredActivityRecoveryProbeScope,
    activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    service: StartedActivityLeaseResumeServiceIdentity,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
    observed_at: TimestampMillis,
) -> Result<StartedActivityLeaseResumeProbe, StartedActivityLeaseResumeStoreError> {
    let delegation = load_scope_delegation(transaction, binding, scope)?;
    let actor = load_activity_actors(
        transaction,
        scope.workspace_id(),
        activity_id,
        initiating_session_id,
        principal,
        initiating_session,
        coordinator_session,
    )?;
    let (goal_census, dag_census, assignment_census, physical_census, started_work_proven) =
        census_activity(transaction, scope.workspace_id(), activity_id)?;
    let expectation = StartedActivityLeaseResumeExpectation::new(
        actor.activity,
        actor.initiating_agent,
        actor.initiating_session,
        actor.coordinator,
        started_work_proven,
        goal_census,
        dag_census,
        assignment_census,
        physical_census,
    )?;
    let blocker = first_probe_blocker(
        &expectation,
        observed_at,
        actor.coordinator_agent_attached,
        actor.coordinator_session_open,
    );
    let resumable_now = blocker.is_none();
    let probe_digest = digest_probe(
        scope,
        service,
        delegation,
        &expectation,
        observed_at,
        resumable_now,
        blocker,
    );
    Ok(StartedActivityLeaseResumeProbe::new(
        scope.clone(),
        service,
        delegation,
        expectation,
        observed_at,
        probe_digest,
        resumable_now,
        blocker,
    )?)
}

pub(super) fn load_scope_delegation(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    scope: &ExpiredActivityRecoveryProbeScope,
) -> Result<forge_domain::StartedActivityLeaseResumeDelegation, StartedActivityLeaseResumeStoreError>
{
    let workspace = super::decode_workspace(super::query_workspace_row(transaction)?.ok_or(
        StartedActivityLeaseResumeStoreError::Conflict("Workspace missing"),
    )?)?;
    if workspace.id() != scope.workspace_id()
        || workspace.revision() != scope.workspace_revision()
        || workspace.location_id() != scope.location_id()
        || workspace.root_fingerprint() != scope.root_fingerprint()
        || binding.recovery_history_digest() != *scope.binding_digest()
    {
        return Err(StartedActivityLeaseResumeStoreError::Conflict(
            "scope fence",
        ));
    }
    let (fence, digest) =
        super::expired_activity_recovery::load_delegation_fence(transaction, scope.workspace_id())
            .map_err(WorkspaceStoreError::ExpiredActivityRecovery)?;
    let delegation = forge_domain::StartedActivityLeaseResumeDelegation::new(
        fence.migration_id(),
        fence.destination_id(),
        fence.revision(),
        fence.created_at(),
        fence.updated_at(),
        fence.manifest_digest(),
        fence.delegated_at(),
        digest,
    )?;
    Ok(delegation)
}

pub(super) struct ActivityActors {
    pub(super) activity: RegisteredActivity,
    pub(super) initiating_agent: Option<StartedActivityLeaseResumeAgentSnapshot>,
    pub(super) initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    pub(super) coordinator: Option<StartedActivityLeaseResumeCoordinatorSnapshot>,
    pub(super) coordinator_agent_attached: bool,
    pub(super) coordinator_session_open: bool,
}

pub(super) fn load_activity_actors(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
) -> Result<ActivityActors, StartedActivityLeaseResumeStoreError> {
    if initiating_session.session_id() != initiating_session_id
        || initiating_session.principal() != principal
    {
        return Err(StartedActivityLeaseResumeStoreError::Conflict(
            "initiating Session fence",
        ));
    }
    let raw = super::query_activity_row(transaction, activity_id)?.ok_or(
        StartedActivityLeaseResumeStoreError::Conflict("Activity missing"),
    )?;
    let activity = super::decode_activity(&raw)?;
    if activity.workspace_id() != workspace_id {
        return Err(StartedActivityLeaseResumeStoreError::Conflict(
            "Activity Workspace",
        ));
    }
    let initiating_agent = find_agent_for_session(
        transaction,
        workspace_id,
        activity_id,
        initiating_session_id,
    )?
    .as_ref()
    .filter(|agent| agent.principal() == principal)
    .and_then(project_agent);
    let binding = crate::workspace_coordinators::get_in_transaction(transaction, activity_id)
        .map_err(WorkspaceStoreError::Coordinator)?;
    let (coordinator, attached, session_open) = match binding {
        Some(binding) => {
            let agent =
                crate::workspace_agents::get_in_transaction(transaction, binding.agent_id())
                    .map_err(WorkspaceStoreError::Agent)?
                    .ok_or(StartedActivityLeaseResumeStoreError::Corrupt(
                        "Coordinator Agent missing",
                    ))?;
            let session_id =
                agent
                    .session_id()
                    .ok_or(StartedActivityLeaseResumeStoreError::Corrupt(
                        "Coordinator Session missing",
                    ))?;
            let snapshot = coordinator_session
                .filter(|session| {
                    session.session_id() == session_id && session.principal() == agent.principal()
                })
                .map(|session| {
                    StartedActivityLeaseResumeCoordinatorSnapshot::new(
                        agent.id(),
                        session_id,
                        agent.principal(),
                        agent.revision(),
                        binding.revision(),
                        binding.updated_at(),
                        session.revision(),
                        session.updated_at(),
                    )
                })
                .transpose()?;
            let session_open = coordinator_session.is_some_and(|session| {
                session.session_id() == session_id
                    && session.principal() == agent.principal()
                    && session.state() == AgentSessionState::Open
            });
            (
                snapshot,
                agent.attachment_state().is_attached(),
                session_open,
            )
        }
        None => (None, false, false),
    };
    Ok(ActivityActors {
        activity,
        initiating_agent,
        initiating_session,
        coordinator,
        coordinator_agent_attached: attached,
        coordinator_session_open: session_open,
    })
}

fn find_agent_for_session(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    session_id: AgentSessionId,
) -> Result<Option<forge_domain::RegisteredAgentInstance>, StartedActivityLeaseResumeStoreError> {
    let agent_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT agent_id FROM agent_instances
             WHERE workspace_id=?1 AND activity_id=?2 AND session_id=?3 LIMIT 1",
            params![
                workspace_id.into_uuid().as_bytes().as_slice(),
                activity_id.into_uuid().as_bytes().as_slice(),
                session_id.into_uuid().as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(agent_id) = agent_id else {
        return Ok(None);
    };
    let agent_id = AgentInstanceId::from_uuid(decode_uuid(&agent_id, "initiating_agent.agent_id")?);
    crate::workspace_agents::get_in_transaction(connection, agent_id)
        .map_err(WorkspaceStoreError::Agent)
        .map_err(StartedActivityLeaseResumeStoreError::from)
}

fn digest_probe(
    scope: &ExpiredActivityRecoveryProbeScope,
    service: StartedActivityLeaseResumeServiceIdentity,
    delegation: forge_domain::StartedActivityLeaseResumeDelegation,
    expectation: &StartedActivityLeaseResumeExpectation,
    observed_at: TimestampMillis,
    resumable_now: bool,
    blocker: Option<StartedActivityLeaseResumeBlocker>,
) -> [u8; 32] {
    let mut writer = PayloadWriter::default();
    encode_scope(&mut writer, scope);
    writer.uuid(service.backend_id().into_uuid());
    writer.uuid(service.issuer().into_uuid());
    writer.uuid(service.destination_id());
    writer.uuid(service.runtime_instance_id().into_uuid());
    writer.uuid(delegation.migration_id());
    writer.uuid(delegation.destination_id());
    writer.i64(i64::try_from(delegation.freeze_revision()).unwrap_or(i64::MAX));
    writer.i64(delegation.freeze_created_at().get());
    writer.i64(delegation.freeze_updated_at().get());
    writer.bytes(&delegation.manifest_digest());
    writer.i64(delegation.delegated_at().get());
    writer.bytes(&delegation.delegation_digest());
    encode_activity(&mut writer, expectation.activity());
    match expectation.initiating_agent() {
        Some(agent) => {
            writer.u8(1);
            encode_agent(&mut writer, *agent);
        }
        None => writer.u8(0),
    }
    encode_session(&mut writer, *expectation.initiating_session());
    match expectation.coordinator() {
        Some(coordinator) => {
            writer.u8(1);
            encode_coordinator(&mut writer, *coordinator);
        }
        None => writer.u8(0),
    }
    writer.u8(u8::from(expectation.started_work_proven()));
    let goals = expectation.goal_census();
    writer.u32(goals.row_count());
    writer.bytes(&goals.digest());
    writer.u8(u8::from(goals.truncated()));
    writer.u8(u8::from(goals.complete()));
    let dag = expectation.dag_census();
    writer.u32(dag.head_count());
    writer.u32(dag.node_count());
    writer.u32(dag.edge_count());
    writer.bytes(&dag.digest());
    writer.u8(u8::from(dag.truncated()));
    writer.u8(u8::from(dag.complete()));
    let assignments = expectation.assignment_census();
    writer.u32(assignments.row_count());
    writer.bytes(&assignments.digest());
    writer.u8(u8::from(assignments.truncated()));
    writer.u8(u8::from(assignments.complete()));
    let physical = expectation.physical_census();
    writer.u32(physical.row_count());
    for value in [
        physical.execution_active_count(),
        physical.execution_unknown_count(),
        physical.writer_lease_active_count(),
        physical.writer_lease_unknown_count(),
        physical.pending_effect_count(),
        physical.effect_unknown_count(),
        physical.unresolved_worktree_count(),
        physical.worktree_unknown_count(),
        physical.unknown_count(),
    ] {
        writer.u64(value);
    }
    writer.bytes(&physical.digest());
    writer.u8(u8::from(physical.truncated()));
    writer.u8(u8::from(physical.complete()));
    writer.i64(observed_at.get());
    writer.u8(u8::from(resumable_now));
    writer.u8(blocker.map_or(u8::MAX, blocker_code));
    let mut hasher = Sha256::new();
    hasher.update(b"forge.started_activity_lease_resume.probe.v1\0");
    hasher.update(writer.finish());
    hasher.finalize().into()
}

fn blocker_code(value: StartedActivityLeaseResumeBlocker) -> u8 {
    match value {
        StartedActivityLeaseResumeBlocker::ActivityNotStarted => 0,
        StartedActivityLeaseResumeBlocker::ActivityNotOpen => 1,
        StartedActivityLeaseResumeBlocker::ActivityLeaseMissing => 2,
        StartedActivityLeaseResumeBlocker::ActivityLeaseNotExpired => 3,
        StartedActivityLeaseResumeBlocker::InitiatingAgentMissing => 4,
        StartedActivityLeaseResumeBlocker::CoordinatorMissing => 5,
        StartedActivityLeaseResumeBlocker::CoordinatorAgentNotAttached => 6,
        StartedActivityLeaseResumeBlocker::CoordinatorSessionNotOpen => 7,
        StartedActivityLeaseResumeBlocker::GoalCensusIncomplete => 8,
        StartedActivityLeaseResumeBlocker::DagCensusIncomplete => 9,
        StartedActivityLeaseResumeBlocker::AssignmentCensusIncomplete => 10,
        StartedActivityLeaseResumeBlocker::PhysicalActivityEffectPresent => 11,
        StartedActivityLeaseResumeBlocker::PhysicalCensusIncomplete => 12,
    }
}

fn project_agent(
    agent: &forge_domain::RegisteredAgentInstance,
) -> Option<StartedActivityLeaseResumeAgentSnapshot> {
    StartedActivityLeaseResumeAgentSnapshot::new(
        agent.id(),
        agent.activity_id(),
        agent.session_id()?,
        agent.principal(),
        agent.revision(),
        agent.attachment_state().is_attached(),
    )
    .ok()
}

fn first_probe_blocker(
    expectation: &StartedActivityLeaseResumeExpectation,
    observed_at: TimestampMillis,
    coordinator_agent_attached: bool,
    coordinator_session_open: bool,
) -> Option<StartedActivityLeaseResumeBlocker> {
    let activity = expectation.activity();
    if !expectation.started_work_proven() {
        return Some(StartedActivityLeaseResumeBlocker::ActivityNotStarted);
    }
    if activity.state() != ActivityState::Open {
        return Some(StartedActivityLeaseResumeBlocker::ActivityNotOpen);
    }
    if activity.lease_owner_id().is_none() || activity.lease_until().is_none() {
        return Some(StartedActivityLeaseResumeBlocker::ActivityLeaseMissing);
    }
    if !activity.lease().is_expired_at(observed_at) {
        return Some(StartedActivityLeaseResumeBlocker::ActivityLeaseNotExpired);
    }
    let Some(agent) = expectation.initiating_agent() else {
        return Some(StartedActivityLeaseResumeBlocker::InitiatingAgentMissing);
    };
    if !agent.attached() {
        return Some(StartedActivityLeaseResumeBlocker::InitiatingAgentMissing);
    }
    let Some(coordinator) = expectation.coordinator() else {
        return Some(StartedActivityLeaseResumeBlocker::CoordinatorMissing);
    };
    if !coordinator_agent_attached {
        return Some(StartedActivityLeaseResumeBlocker::CoordinatorAgentNotAttached);
    }
    if !coordinator_session_open {
        return Some(StartedActivityLeaseResumeBlocker::CoordinatorSessionNotOpen);
    }
    if !expectation.goal_census().complete() || expectation.goal_census().truncated() {
        return Some(StartedActivityLeaseResumeBlocker::GoalCensusIncomplete);
    }
    if !expectation.dag_census().complete() || expectation.dag_census().truncated() {
        return Some(StartedActivityLeaseResumeBlocker::DagCensusIncomplete);
    }
    if !expectation.assignment_census().complete() || expectation.assignment_census().truncated() {
        return Some(StartedActivityLeaseResumeBlocker::AssignmentCensusIncomplete);
    }
    let physical = expectation.physical_census();
    if !physical.complete() || physical.truncated() {
        return Some(StartedActivityLeaseResumeBlocker::PhysicalCensusIncomplete);
    }
    if physical.execution_active_count() != 0
        || physical.execution_unknown_count() != 0
        || physical.writer_lease_active_count() != 0
        || physical.writer_lease_unknown_count() != 0
        || physical.pending_effect_count() != 0
        || physical.effect_unknown_count() != 0
        || physical.unresolved_worktree_count() != 0
        || physical.worktree_unknown_count() != 0
        || physical.unknown_count() != 0
    {
        return Some(StartedActivityLeaseResumeBlocker::PhysicalActivityEffectPresent);
    }
    let _ = coordinator;
    None
}

type ActivityCensus = (
    StartedActivityLeaseResumeGoalCensus,
    StartedActivityLeaseResumeDagCensus,
    StartedActivityLeaseResumeAssignmentCensus,
    StartedActivityLeaseResumePhysicalCensus,
    bool,
);

fn census_activity(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<ActivityCensus, StartedActivityLeaseResumeStoreError> {
    let goal = goal_census(connection, workspace_id, activity_id)?;
    let dag = dag_census(connection, workspace_id, activity_id)?;
    let (assignments, started_work_proven) =
        assignment_census(connection, workspace_id, activity_id)?;
    let physical = physical_census(connection, workspace_id, activity_id)?;
    Ok((goal, dag, assignments, physical, started_work_proven))
}

pub(super) fn goal_census(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<StartedActivityLeaseResumeGoalCensus, StartedActivityLeaseResumeStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"forge.started_activity_lease_resume.goal_census.v1");
    let (count, truncated) = hash_query(
        connection,
        "SELECT * FROM goals WHERE workspace_id=?1 AND activity_id=?2 ORDER BY goal_id LIMIT ?3",
        params![
            workspace.as_slice(),
            activity.as_slice(),
            i64::from(forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_GOAL_ROWS) + 1
        ],
        &mut hasher,
        forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_GOAL_ROWS as usize,
    )?;
    Ok(StartedActivityLeaseResumeGoalCensus::new(
        count,
        hasher.finalize().into(),
        truncated,
        !truncated,
    )?)
}

pub(super) fn dag_census(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<StartedActivityLeaseResumeDagCensus, StartedActivityLeaseResumeStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let tables: [(&str, &str, usize); 8] = [
        (
            "heads",
            "SELECT h.* FROM goal_dag_heads h JOIN goals g ON g.goal_id=h.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY h.goal_id LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_HEADS as usize,
        ),
        (
            "revisions",
            "SELECT r.* FROM goal_dag_revisions r JOIN goals g ON g.goal_id=r.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY r.goal_id,r.dag_revision LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES as usize,
        ),
        (
            "nodes",
            "SELECT n.* FROM goal_dag_nodes n JOIN goals g ON g.goal_id=n.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY n.goal_id,n.dag_revision,n.node_id LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_NODES as usize,
        ),
        (
            "edges",
            "SELECT e.* FROM goal_dag_edges e JOIN goals g ON g.goal_id=e.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY e.goal_id,e.dag_revision,e.upstream_node_id,e.downstream_node_id LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES as usize,
        ),
        (
            "lineage",
            "SELECT l.* FROM goal_dag_node_lineage l JOIN goals g ON g.goal_id=l.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY l.goal_id,l.new_dag_revision,l.prior_node_id,l.successor_node_id LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES as usize,
        ),
        (
            "node_evidence",
            "SELECT e.* FROM goal_dag_node_evidence_refs e JOIN goals g ON g.goal_id=e.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY e.goal_id,e.dag_revision,e.node_id,e.evidence_kind,e.evidence_id LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES as usize,
        ),
        (
            "acceptance",
            "SELECT a.* FROM goal_dag_node_acceptance a JOIN goals g ON g.goal_id=a.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY a.goal_id,a.dag_revision,a.node_id,a.ordinal LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES as usize,
        ),
        (
            "goal_evidence",
            "SELECT e.* FROM goal_evidence_refs e JOIN goals g ON g.goal_id=e.goal_id WHERE g.workspace_id=?1 AND g.activity_id=?2 ORDER BY e.goal_id,e.evidence_kind,e.evidence_id LIMIT ?3",
            forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_DAG_EDGES as usize,
        ),
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"forge.started_activity_lease_resume.dag_census.v1");
    let (mut heads, mut nodes, mut edges) = (0_u32, 0_u32, 0_u32);
    let mut truncated = false;
    for (name, sql, maximum) in tables {
        hasher.update(name.as_bytes());
        let (count, table_truncated) = hash_query(
            connection,
            sql,
            params![
                workspace.as_slice(),
                activity.as_slice(),
                i64::try_from(maximum + 1).unwrap_or(i64::MAX)
            ],
            &mut hasher,
            maximum,
        )?;
        match name {
            "heads" => heads = count,
            "nodes" => nodes = count,
            "edges" => edges = count,
            _ => {}
        }
        truncated |= table_truncated;
    }
    Ok(StartedActivityLeaseResumeDagCensus::new(
        heads,
        nodes,
        edges,
        hasher.finalize().into(),
        truncated,
        !truncated,
    )?)
}

pub(super) fn assignment_census(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(StartedActivityLeaseResumeAssignmentCensus, bool), StartedActivityLeaseResumeStoreError>
{
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"forge.started_activity_lease_resume.assignment_census.v1");
    let maximum = forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_ASSIGNMENT_ROWS as usize;
    let queries = [
        (
            "assignments",
            "SELECT * FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2 ORDER BY assignment_id LIMIT ?3",
            maximum,
        ),
        (
            "sources",
            "SELECT s.* FROM agent_assignment_sources s JOIN agent_assignments a ON a.assignment_id=s.assignment_id WHERE a.workspace_id=?1 AND a.activity_id=?2 ORDER BY s.assignment_id,s.ordinal LIMIT ?3",
            maximum * 32,
        ),
        (
            "seals",
            "SELECT s.* FROM agent_assignment_offer_seals s WHERE s.workspace_id=?1 AND s.activity_id=?2 ORDER BY s.assignment_id LIMIT ?3",
            maximum,
        ),
    ];
    let mut count = 0;
    let mut truncated = false;
    for (name, sql, table_maximum) in queries {
        hasher.update(name.as_bytes());
        let (table_count, table_truncated) = hash_query(
            connection,
            sql,
            params![
                workspace.as_slice(),
                activity.as_slice(),
                i64::try_from(table_maximum + 1).unwrap_or(i64::MAX)
            ],
            &mut hasher,
            table_maximum,
        )?;
        if name == "assignments" {
            count = table_count;
        }
        truncated |= table_truncated;
    }
    let started_work_proven = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2 AND state IN (1,2,3,4))",
        params![workspace.as_slice(), activity.as_slice()],
        |row| row.get(0),
    )?;
    let census = StartedActivityLeaseResumeAssignmentCensus::new(
        count,
        hasher.finalize().into(),
        truncated,
        !truncated,
    )?;
    Ok((census, started_work_proven))
}

pub(super) fn hash_query<P: Params>(
    connection: &Connection,
    sql: &str,
    params: P,
    hasher: &mut Sha256,
    maximum: usize,
) -> Result<(u32, bool), StartedActivityLeaseResumeStoreError> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(params)?;
    let mut count = 0_usize;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > maximum + 1 {
            return Err(StartedActivityLeaseResumeStoreError::Corrupt(
                "census query exceeded limit",
            ));
        }
        let columns = row.as_ref().column_count();
        hasher.update(u64::try_from(columns).unwrap_or(u64::MAX).to_le_bytes());
        for index in 0..columns {
            match row.get_ref(index)? {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hasher.update(value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) => {
                    hasher.update([3]);
                    hasher.update((value.len() as u64).to_le_bytes());
                    hasher.update(value);
                }
                ValueRef::Blob(value) => {
                    hasher.update([4]);
                    hasher.update((value.len() as u64).to_le_bytes());
                    hasher.update(value);
                }
            }
        }
    }
    let truncated = count > maximum;
    Ok((
        u32::try_from(count.min(maximum)).unwrap_or(u32::MAX),
        truncated,
    ))
}

pub(super) fn query_count<P: Params>(
    connection: &Connection,
    sql: &str,
    params: P,
) -> Result<u64, StartedActivityLeaseResumeStoreError> {
    let value: i64 = connection.query_row(sql, params, |row| row.get(0))?;
    u64::try_from(value)
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("negative count"))
}

pub(super) fn physical_census(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<StartedActivityLeaseResumePhysicalCensus, StartedActivityLeaseResumeStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"forge.started_activity_lease_resume.physical_census.v1");
    let maximum = forge_domain::STARTED_ACTIVITY_LEASE_RESUME_MAX_PHYSICAL_ROWS as usize;
    let counts = physical_activity_counts(connection, workspace, activity)?;
    let (mut row_count, mut truncated) =
        hash_basic_physical_rows(connection, workspace, activity, maximum, &mut hasher)?;
    let additional =
        crate::workspace_store::expired_activity_recovery::started_activity_physical_blockers(
            connection,
            workspace_id,
            activity_id,
            u32::try_from(maximum).unwrap_or(u32::MAX),
        )
        .map_err(WorkspaceStoreError::ExpiredActivityRecovery)
        .map_err(StartedActivityLeaseResumeStoreError::from)?;
    hasher.update(b"expired_activity_physical_blockers");
    hasher.update(additional.digest);
    row_count = row_count.saturating_add(additional.row_count as usize);
    truncated |= additional.truncated;
    let (unresolved_worktrees, worktree_unknown, worktree_count, worktree_truncated) =
        assignment_worktree_counts(connection, workspace, activity, maximum)?;
    truncated |= worktree_truncated;
    row_count = row_count.saturating_add(worktree_count);
    truncated |= row_count > maximum;
    let pending_effects = counts
        .pending_effects
        .saturating_add(additional.pending_count);
    let unknown = counts
        .execution_unknown
        .saturating_add(counts.writer_unknown)
        .saturating_add(counts.effect_unknown)
        .saturating_add(worktree_unknown)
        .saturating_add(additional.unknown_count);
    hasher.update(b"workspace_foreign_key_check");
    let (foreign_key_violations, foreign_key_truncated) = hash_query(
        connection,
        "PRAGMA foreign_key_check",
        [],
        &mut hasher,
        maximum,
    )?;
    truncated |= foreign_key_truncated;
    row_count = row_count.saturating_add(foreign_key_violations as usize);
    let row_count = u32::try_from(row_count.min(maximum)).unwrap_or(u32::MAX);
    let unknown = unknown.saturating_add(u64::from(foreign_key_violations));
    Ok(StartedActivityLeaseResumePhysicalCensus::new(
        row_count,
        counts.execution_active,
        counts.execution_unknown,
        counts.writer_active,
        counts.writer_unknown,
        pending_effects,
        counts.effect_unknown,
        unresolved_worktrees,
        worktree_unknown,
        unknown,
        hasher.finalize().into(),
        truncated,
        !truncated,
    )?)
}

struct PhysicalActivityCounts {
    execution_active: u64,
    execution_unknown: u64,
    writer_active: u64,
    writer_unknown: u64,
    pending_effects: u64,
    effect_unknown: u64,
}

fn physical_activity_counts(
    connection: &Connection,
    workspace: [u8; 16],
    activity: [u8; 16],
) -> Result<PhysicalActivityCounts, StartedActivityLeaseResumeStoreError> {
    Ok(PhysicalActivityCounts {
        execution_active: query_count(
            connection,
            "SELECT COUNT(*) FROM executions WHERE workspace_id=?1 AND activity_id=?2 AND state IN (0,1)",
            params![workspace, activity],
        )?,
        execution_unknown: query_count(
            connection,
            "SELECT COUNT(*) FROM executions WHERE workspace_id=?1 AND activity_id=?2 AND state NOT IN (0,1,2,3,4,5,6)",
            params![workspace, activity],
        )?,
        writer_active: query_count(
            connection,
            "SELECT COUNT(*) FROM writer_leases WHERE workspace_id=?1 AND activity_id=?2 AND state=0",
            params![workspace, activity],
        )?,
        writer_unknown: query_count(
            connection,
            "SELECT COUNT(*) FROM writer_leases WHERE workspace_id=?1 AND activity_id=?2 AND state NOT IN (0,1)",
            params![workspace, activity],
        )?,
        pending_effects: query_count(
            connection,
            "SELECT COUNT(*) FROM change_sets WHERE workspace_id=?1 AND activity_id=?2 AND state=0",
            params![workspace, activity],
        )?,
        effect_unknown: query_count(
            connection,
            "SELECT COUNT(*) FROM change_sets WHERE workspace_id=?1 AND activity_id=?2 AND state NOT IN (0,1,2)",
            params![workspace, activity],
        )?,
    })
}

fn hash_basic_physical_rows(
    connection: &Connection,
    workspace: [u8; 16],
    activity: [u8; 16],
    maximum: usize,
    hasher: &mut Sha256,
) -> Result<(usize, bool), StartedActivityLeaseResumeStoreError> {
    let mut row_count = 0_usize;
    let mut truncated = false;
    for (name, sql) in [
        (
            "executions",
            "SELECT * FROM executions WHERE workspace_id=?1 AND activity_id=?2 ORDER BY execution_id LIMIT ?3",
        ),
        (
            "writer_leases",
            "SELECT * FROM writer_leases WHERE workspace_id=?1 AND activity_id=?2 ORDER BY lease_id LIMIT ?3",
        ),
        (
            "change_sets",
            "SELECT * FROM change_sets WHERE workspace_id=?1 AND activity_id=?2 ORDER BY changeset_id LIMIT ?3",
        ),
        (
            "file_mutations",
            "SELECT m.* FROM file_mutations m JOIN change_sets c ON c.changeset_id=m.changeset_id WHERE c.workspace_id=?1 AND c.activity_id=?2 ORDER BY m.changeset_id,m.ordinal LIMIT ?3",
        ),
        (
            "tree_mutations",
            "SELECT m.* FROM tree_mutations m JOIN change_sets c ON c.changeset_id=m.changeset_id WHERE c.workspace_id=?1 AND c.activity_id=?2 ORDER BY m.changeset_id,m.ordinal LIMIT ?3",
        ),
    ] {
        hasher.update(name.as_bytes());
        let (count, was_truncated) = hash_query(
            connection,
            sql,
            params![
                workspace,
                activity,
                i64::try_from(maximum + 1).unwrap_or(i64::MAX)
            ],
            hasher,
            maximum,
        )?;
        row_count = row_count.saturating_add(count as usize);
        truncated |= was_truncated;
    }
    Ok((row_count, truncated))
}

fn assignment_worktree_counts(
    connection: &Connection,
    workspace: [u8; 16],
    activity: [u8; 16],
    maximum: usize,
) -> Result<(u64, u64, usize, bool), StartedActivityLeaseResumeStoreError> {
    let mut statement = connection.prepare(
        "SELECT state, worktree_root_fingerprint, worktree_repository_fingerprint, worktree_baseline
         FROM agent_assignments WHERE workspace_id=?1 AND activity_id=?2
         AND (worktree_root_fingerprint IS NOT NULL OR worktree_repository_fingerprint IS NOT NULL OR worktree_baseline IS NOT NULL)
         ORDER BY assignment_id LIMIT ?3",
    )?;
    let mut rows = statement.query(params![
        workspace,
        activity,
        i64::try_from(maximum + 1).unwrap_or(i64::MAX),
    ])?;
    let mut count = 0_usize;
    let mut unresolved = 0_u64;
    let mut unknown = 0_u64;
    while let Some(row) = rows.next()? {
        count += 1;
        let state: i64 = row.get(0)?;
        let root: Option<Vec<u8>> = row.get(1)?;
        let repository: Option<Vec<u8>> = row.get(2)?;
        let baseline: Option<Vec<u8>> = row.get(3)?;
        let complete = root.as_ref().is_some_and(|value| value.len() == 16)
            && repository.as_ref().is_some_and(|value| value.len() == 16)
            && baseline.as_ref().is_some_and(|value| value.len() == 20);
        let absent = root.is_none() && repository.is_none() && baseline.is_none();
        if !complete && !absent {
            unknown += 1;
        } else if complete && matches!(state, 0..=2) {
            unresolved += 1;
        } else if !matches!(state, 0..=6) {
            unknown += 1;
        }
    }
    Ok((unresolved, unknown, count, count > maximum))
}

fn encode_receipt(receipt: &StartedActivityLeaseResumeReceipt) -> Vec<u8> {
    let mut writer = PayloadWriter::default();
    writer.bytes(RECEIPT_PAYLOAD_VERSION);
    encode_scope(&mut writer, receipt.scope());
    writer.uuid(receipt.request_id());
    writer.bytes(&receipt.request_digest());
    encode_activity(&mut writer, receipt.activity());
    encode_agent(&mut writer, *receipt.initiating_agent());
    encode_session(&mut writer, *receipt.initiating_session());
    encode_coordinator(&mut writer, *receipt.coordinator());
    writer.uuid(receipt.source_runtime_instance_id().into_uuid());
    writer.bytes(&receipt.probe_digest());
    writer.i64(receipt.resumed_at().get());
    writer.finish()
}

fn decode_receipt(
    payload: &[u8],
) -> Result<StartedActivityLeaseResumeReceipt, StartedActivityLeaseResumeStoreError> {
    if payload.len() > MAX_RECEIPT_PAYLOAD_BYTES {
        return Err(StartedActivityLeaseResumeStoreError::Corrupt(
            "payload bounds",
        ));
    }
    let mut reader = PayloadReader::new(payload);
    if reader.bytes(4)? != RECEIPT_PAYLOAD_VERSION {
        return Err(StartedActivityLeaseResumeStoreError::Corrupt(
            "payload version",
        ));
    }
    let scope = decode_scope(&mut reader)?;
    let request_id = reader.uuid()?;
    let request_digest = reader.fixed::<32>()?;
    let activity = decode_activity(&mut reader)?;
    let initiating_agent = decode_agent(&mut reader)?;
    let initiating_session = decode_session(&mut reader)?;
    let coordinator = decode_coordinator(&mut reader)?;
    let runtime = RuntimeInstanceId::from_uuid(reader.uuid()?);
    let probe_digest = reader.fixed::<32>()?;
    let resumed_at = decode_timestamp(reader.i64()?, "resumed_at_ms")?;
    reader.finish()?;
    Ok(StartedActivityLeaseResumeReceipt::from_parts(
        scope,
        request_id,
        request_digest,
        activity,
        initiating_agent,
        initiating_session,
        coordinator,
        runtime,
        probe_digest,
        resumed_at,
    )?)
}

pub(super) fn encode_scope(writer: &mut PayloadWriter, scope: &ExpiredActivityRecoveryProbeScope) {
    writer.uuid(scope.workspace_id().into_uuid());
    writer.i64(scope.workspace_revision().get());
    writer.uuid(scope.location_id().into_uuid());
    writer.i64(scope.location_revision().get());
    writer.blob(scope.locator());
    writer.bytes(scope.root_fingerprint().as_bytes());
    writer.bytes(scope.binding_digest());
}

pub(super) fn decode_scope(
    reader: &mut PayloadReader<'_>,
) -> Result<ExpiredActivityRecoveryProbeScope, StartedActivityLeaseResumeStoreError> {
    let workspace = WorkspaceId::from_uuid(reader.uuid()?);
    let workspace_revision = WorkspaceRevision::new(reader.i64()?)
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("workspace_revision"))?;
    let location = LocationId::from_uuid(reader.uuid()?);
    let location_revision = LocationRevision::new(reader.i64()?)
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("location_revision"))?;
    let locator = reader.blob(4096)?;
    let root = WorkspaceRootFingerprint::from_bytes(reader.fixed::<16>()?);
    let binding = reader.fixed::<32>()?;
    Ok(ExpiredActivityRecoveryProbeScope::new(
        workspace,
        workspace_revision,
        location,
        location_revision,
        locator,
        root,
        binding,
    )?)
}

pub(super) fn encode_activity(writer: &mut PayloadWriter, activity: &RegisteredActivity) {
    writer.uuid(activity.id().into_uuid());
    writer.uuid(activity.workspace_id().into_uuid());
    writer.u8(encode_activity_state(activity.state()));
    writer.i64(activity.revision().get());
    writer.i64(activity.created_at().get());
    writer.i64(activity.updated_at().get());
    writer.optional_uuid(activity.lease_owner_id().map(RuntimeInstanceId::into_uuid));
    writer.optional_i64(activity.lease_until().map(TimestampMillis::get));
    writer.i64(activity.lease_revision().get());
}

pub(super) fn decode_activity(
    reader: &mut PayloadReader<'_>,
) -> Result<RegisteredActivity, StartedActivityLeaseResumeStoreError> {
    let id = ActivityId::from_uuid(reader.uuid()?);
    let workspace = WorkspaceId::from_uuid(reader.uuid()?);
    let state = decode_activity_state(reader.u8()?)?;
    let revision = ActivityRevision::new(reader.i64()?)
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("activity.revision"))?;
    let created_at = decode_timestamp(reader.i64()?, "activity.created_at")?;
    let updated_at = decode_timestamp(reader.i64()?, "activity.updated_at")?;
    let owner = reader.optional_uuid()?.map(RuntimeInstanceId::from_uuid);
    let until = reader
        .optional_i64()?
        .map(|value| decode_timestamp(value, "activity.lease_until"))
        .transpose()?;
    let lease_revision = ActivityLeaseRevision::new(reader.i64()?)
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("activity.lease_revision"))?;
    let lease = ActivityLeaseProjection::from_parts(owner, until, lease_revision)
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("activity.lease"))?;
    Ok(RegisteredActivity::from_parts_with_lease(
        id, workspace, state, created_at, updated_at, revision, lease,
    ))
}

pub(super) fn encode_agent(
    writer: &mut PayloadWriter,
    agent: StartedActivityLeaseResumeAgentSnapshot,
) {
    writer.uuid(agent.agent_id().into_uuid());
    writer.uuid(agent.activity_id().into_uuid());
    writer.uuid(agent.session_id().into_uuid());
    writer.principal(agent.principal());
    writer.i64(agent.revision().get());
    writer.u8(u8::from(agent.attached()));
}

pub(super) fn decode_agent(
    reader: &mut PayloadReader<'_>,
) -> Result<StartedActivityLeaseResumeAgentSnapshot, StartedActivityLeaseResumeStoreError> {
    Ok(StartedActivityLeaseResumeAgentSnapshot::new(
        AgentInstanceId::from_uuid(reader.uuid()?),
        ActivityId::from_uuid(reader.uuid()?),
        AgentSessionId::from_uuid(reader.uuid()?),
        reader.principal()?,
        AgentInstanceRevision::new(reader.i64()?)
            .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("agent.revision"))?,
        reader.bool()?,
    )?)
}

pub(super) fn encode_session(
    writer: &mut PayloadWriter,
    session: StartedActivityLeaseResumeSessionSnapshot,
) {
    writer.uuid(session.session_id().into_uuid());
    writer.principal(session.principal());
    writer.u8(encode_session_state(session.state()));
    writer.i64(session.revision().get());
    writer.i64(session.updated_at().get());
}

pub(super) fn decode_session(
    reader: &mut PayloadReader<'_>,
) -> Result<StartedActivityLeaseResumeSessionSnapshot, StartedActivityLeaseResumeStoreError> {
    Ok(StartedActivityLeaseResumeSessionSnapshot::new(
        AgentSessionId::from_uuid(reader.uuid()?),
        reader.principal()?,
        decode_session_state(reader.u8()?)?,
        AgentSessionRevision::new(reader.i64()?)
            .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("session.revision"))?,
        decode_timestamp(reader.i64()?, "session.updated_at")?,
    )?)
}

pub(super) fn encode_coordinator(
    writer: &mut PayloadWriter,
    value: StartedActivityLeaseResumeCoordinatorSnapshot,
) {
    writer.uuid(value.agent_id().into_uuid());
    writer.uuid(value.session_id().into_uuid());
    writer.principal(value.principal());
    writer.i64(value.agent_revision().get());
    writer.i64(value.revision().get());
    writer.i64(value.updated_at().get());
    writer.i64(value.session_revision().get());
    writer.i64(value.session_updated_at().get());
}

pub(super) fn decode_coordinator(
    reader: &mut PayloadReader<'_>,
) -> Result<StartedActivityLeaseResumeCoordinatorSnapshot, StartedActivityLeaseResumeStoreError> {
    Ok(StartedActivityLeaseResumeCoordinatorSnapshot::new(
        AgentInstanceId::from_uuid(reader.uuid()?),
        AgentSessionId::from_uuid(reader.uuid()?),
        reader.principal()?,
        AgentInstanceRevision::new(reader.i64()?).map_err(|_| {
            StartedActivityLeaseResumeStoreError::Corrupt("coordinator.agent_revision")
        })?,
        ActivityCoordinatorRevision::new(reader.i64()?)
            .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("coordinator.revision"))?,
        decode_timestamp(reader.i64()?, "coordinator.updated_at")?,
        AgentSessionRevision::new(reader.i64()?).map_err(|_| {
            StartedActivityLeaseResumeStoreError::Corrupt("coordinator.session_revision")
        })?,
        decode_timestamp(reader.i64()?, "coordinator.session_updated_at")?,
    )?)
}

#[derive(Default)]
pub(super) struct PayloadWriter(Vec<u8>);

impl PayloadWriter {
    pub(super) fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    pub(super) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    pub(super) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    pub(super) fn i64(&mut self, value: i64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    pub(super) fn uuid(&mut self, value: Uuid) {
        self.0.extend_from_slice(value.as_bytes());
    }
    pub(super) fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    pub(super) fn blob(&mut self, value: &[u8]) {
        let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&length.to_le_bytes());
        self.0.extend_from_slice(value);
    }
    pub(super) fn optional_uuid(&mut self, value: Option<Uuid>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.uuid(value);
            }
            None => self.u8(0),
        }
    }
    pub(super) fn optional_i64(&mut self, value: Option<i64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.i64(value);
            }
            None => self.u8(0),
        }
    }
    pub(super) fn principal(&mut self, value: AuthenticatedPrincipal) {
        match value {
            AuthenticatedPrincipal::TrustedStdio => self.u8(0),
            AuthenticatedPrincipal::DirectToken(id) => {
                self.u8(1);
                self.uuid(id.into_uuid());
            }
            AuthenticatedPrincipal::OAuthGrant(id) => {
                self.u8(2);
                self.uuid(id.into_uuid());
            }
        }
    }
    pub(super) fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub(super) struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], StartedActivityLeaseResumeStoreError> {
        let end = self.offset.checked_add(length).ok_or(
            StartedActivityLeaseResumeStoreError::Corrupt("payload offset"),
        )?;
        let result = self.bytes.get(self.offset..end).ok_or(
            StartedActivityLeaseResumeStoreError::Corrupt("payload truncated"),
        )?;
        self.offset = end;
        Ok(result)
    }
    pub(super) fn u8(&mut self) -> Result<u8, StartedActivityLeaseResumeStoreError> {
        Ok(self.take(1)?[0])
    }
    pub(super) fn bool(&mut self) -> Result<bool, StartedActivityLeaseResumeStoreError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StartedActivityLeaseResumeStoreError::Corrupt("boolean")),
        }
    }
    pub(super) fn i64(&mut self) -> Result<i64, StartedActivityLeaseResumeStoreError> {
        Ok(i64::from_le_bytes(self.fixed::<8>()?))
    }
    pub(super) fn bytes(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], StartedActivityLeaseResumeStoreError> {
        self.take(length)
    }
    pub(super) fn fixed<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], StartedActivityLeaseResumeStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("fixed bytes"))
    }
    pub(super) fn uuid(&mut self) -> Result<Uuid, StartedActivityLeaseResumeStoreError> {
        Uuid::from_slice(self.take(16)?)
            .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt("uuid"))
    }
    pub(super) fn blob(
        &mut self,
        maximum: usize,
    ) -> Result<Vec<u8>, StartedActivityLeaseResumeStoreError> {
        let length = u32::from_le_bytes(self.fixed::<4>()?) as usize;
        if length == 0 || length > maximum {
            return Err(StartedActivityLeaseResumeStoreError::Corrupt("blob bounds"));
        }
        Ok(self.take(length)?.to_vec())
    }
    pub(super) fn optional_uuid(
        &mut self,
    ) -> Result<Option<Uuid>, StartedActivityLeaseResumeStoreError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.uuid()?)),
            _ => Err(StartedActivityLeaseResumeStoreError::Corrupt(
                "optional uuid",
            )),
        }
    }
    pub(super) fn optional_i64(
        &mut self,
    ) -> Result<Option<i64>, StartedActivityLeaseResumeStoreError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.i64()?)),
            _ => Err(StartedActivityLeaseResumeStoreError::Corrupt(
                "optional integer",
            )),
        }
    }
    pub(super) fn principal(
        &mut self,
    ) -> Result<AuthenticatedPrincipal, StartedActivityLeaseResumeStoreError> {
        match self.u8()? {
            0 => Ok(AuthenticatedPrincipal::TrustedStdio),
            1 => Ok(AuthenticatedPrincipal::DirectToken(
                DirectTokenId::from_uuid(self.uuid()?),
            )),
            2 => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
                self.uuid()?,
            ))),
            _ => Err(StartedActivityLeaseResumeStoreError::Corrupt(
                "principal kind",
            )),
        }
    }
    pub(super) fn finish(&self) -> Result<(), StartedActivityLeaseResumeStoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StartedActivityLeaseResumeStoreError::Corrupt(
                "trailing payload",
            ))
        }
    }
}

fn encode_activity_state(value: ActivityState) -> u8 {
    match value {
        ActivityState::Open => 0,
        ActivityState::Closed => 1,
        ActivityState::Interrupted => 2,
    }
}
fn decode_activity_state(value: u8) -> Result<ActivityState, StartedActivityLeaseResumeStoreError> {
    match value {
        0 => Ok(ActivityState::Open),
        1 => Ok(ActivityState::Closed),
        2 => Ok(ActivityState::Interrupted),
        _ => Err(StartedActivityLeaseResumeStoreError::Corrupt(
            "activity.state",
        )),
    }
}
fn encode_session_state(value: AgentSessionState) -> u8 {
    match value {
        AgentSessionState::Open => 0,
        AgentSessionState::Closed => 1,
    }
}
fn decode_session_state(
    value: u8,
) -> Result<AgentSessionState, StartedActivityLeaseResumeStoreError> {
    match value {
        0 => Ok(AgentSessionState::Open),
        1 => Ok(AgentSessionState::Closed),
        _ => Err(StartedActivityLeaseResumeStoreError::Corrupt(
            "session.state",
        )),
    }
}
fn digest_receipt_payload(value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_PAYLOAD_DOMAIN);
    hasher.update(value);
    hasher.finalize().into()
}
fn load_receipt(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<StartedActivityLeaseResumeReceipt>, StartedActivityLeaseResumeStoreError> {
    let row = connection
        .query_row(
            "SELECT receipt_payload, receipt_checksum FROM started_activity_lease_resume_receipts WHERE request_id=?1",
            params![request_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((payload, checksum)) = row else {
        return Ok(None);
    };
    if payload.is_empty()
        || payload.len() > MAX_RECEIPT_PAYLOAD_BYTES
        || decode_digest(&checksum, "receipt_checksum")? != digest_receipt_payload(&payload)
    {
        return Err(StartedActivityLeaseResumeStoreError::Corrupt(
            "receipt checksum",
        ));
    }
    let receipt = decode_receipt(&payload)?;
    if receipt.request_id() != request_id {
        return Err(StartedActivityLeaseResumeStoreError::Corrupt(
            "request identity",
        ));
    }
    Ok(Some(receipt))
}
fn decode_uuid(
    value: &[u8],
    field: &'static str,
) -> Result<Uuid, StartedActivityLeaseResumeStoreError> {
    Uuid::from_slice(value).map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt(field))
}
fn decode_fixed<const N: usize>(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; N], StartedActivityLeaseResumeStoreError> {
    value
        .try_into()
        .map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt(field))
}
fn decode_digest(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; 32], StartedActivityLeaseResumeStoreError> {
    decode_fixed(value, field)
}
fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, StartedActivityLeaseResumeStoreError> {
    TimestampMillis::new(value).map_err(|_| StartedActivityLeaseResumeStoreError::Corrupt(field))
}
fn decode_principal(
    kind: i64,
    id: Option<&[u8]>,
) -> Result<AuthenticatedPrincipal, StartedActivityLeaseResumeStoreError> {
    match (kind, id) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(id)) => Ok(AuthenticatedPrincipal::DirectToken(
            DirectTokenId::from_uuid(decode_uuid(id, "principal_id")?),
        )),
        (2, Some(id)) => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
            decode_uuid(id, "principal_id")?,
        ))),
        _ => Err(StartedActivityLeaseResumeStoreError::Corrupt("principal")),
    }
}
fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes().to_vec())),
    }
}
