//! Durable quiescent same-Activity lease resume with exact Source readback.

use forge_domain::{
    ActivityId, ActivityLeaseProjection, ActivityState, AgentSessionId, AuthenticatedPrincipal,
    ExpiredActivityRecoveryProbeScope, LocationRevision,
    QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES, QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_AGENT_ROWS,
    QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_EVIDENCE_REFS,
    QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_UPDATE_ROWS, QuiescentActivityLeaseResumeAgentCensus,
    QuiescentActivityLeaseResumeBlocker, QuiescentActivityLeaseResumeCoordinationWork,
    QuiescentActivityLeaseResumeExpectation, QuiescentActivityLeaseResumeGetRequest,
    QuiescentActivityLeaseResumeOperation, QuiescentActivityLeaseResumeProbe,
    QuiescentActivityLeaseResumeProbeRequest, QuiescentActivityLeaseResumeReceipt,
    QuiescentActivityLeaseResumeReceiptParts, QuiescentActivityLeaseResumeRunRequest,
    QuiescentActivityLeaseResumeValidationError, QuiescentActivityLeaseResumeWorkHistoryCensus,
    RegisteredActivity, RuntimeInstanceId, StartedActivityLeaseResumeAssignmentCensus,
    StartedActivityLeaseResumeDagCensus, StartedActivityLeaseResumeDelegation,
    StartedActivityLeaseResumeGoalCensus, StartedActivityLeaseResumePhysicalCensus,
    StartedActivityLeaseResumeServiceIdentity, StartedActivityLeaseResumeSessionSnapshot,
    TimestampMillis, WorkspaceId, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::started_activity_lease_resume as started;
use super::started_activity_lease_resume::StartedActivityLeaseResumeStoreError;
use super::{WorkspaceJournalBinding, WorkspaceLiveBinding, WorkspaceStore, WorkspaceStoreError};

const RECEIPT_PAYLOAD_VERSION: &[u8; 4] = b"QAR\x01";
const RECEIPT_PAYLOAD_DOMAIN: &[u8] = b"forge.quiescent_activity_lease_resume.receipt.v1\0";
const PROBE_DIGEST_DOMAIN: &[u8] = b"forge.quiescent_activity_lease_resume.probe.v1\0";
const MAX_RECEIPT_PAYLOAD_BYTES: usize = 65_536;

#[derive(Debug, Error)]
pub enum QuiescentActivityLeaseResumeStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("quiescent Activity lease resume input is invalid: {0}")]
    Invalid(&'static str),
    #[error("quiescent Activity lease resume conflicts with durable state: {0}")]
    Conflict(&'static str),
    #[error("quiescent Activity lease resume receipt is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("quiescent Activity lease resume clock observation failed")]
    Clock(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Domain(#[from] QuiescentActivityLeaseResumeValidationError),
    #[error(transparent)]
    Started(#[from] StartedActivityLeaseResumeStoreError),
    #[error(transparent)]
    Scope(#[from] forge_domain::ExpiredActivityRecoveryValidationError),
    #[error("quiescent Activity lease resume Workspace persistence failure")]
    Workspace(#[source] Box<WorkspaceStoreError>),
}

impl From<WorkspaceStoreError> for QuiescentActivityLeaseResumeStoreError {
    fn from(value: WorkspaceStoreError) -> Self {
        Self::Workspace(Box::new(value))
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescentActivityLeaseResumeReadback {
    receipt: QuiescentActivityLeaseResumeReceipt,
}

struct QuiescentActivityLeaseResumeReceiptRow {
    request_digest: Vec<u8>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    location_id: Vec<u8>,
    location_revision: i64,
    workspace_revision: i64,
    locator: Vec<u8>,
    root_fingerprint: Vec<u8>,
    binding_digest: Vec<u8>,
    agent_id: Vec<u8>,
    initiating_session_id: Vec<u8>,
    principal_kind: i64,
    principal_id: Option<Vec<u8>>,
    source_runtime_instance_id: Vec<u8>,
    resumed_at_ms: i64,
    receipt_payload: Vec<u8>,
    receipt_checksum: Vec<u8>,
}

impl QuiescentActivityLeaseResumeReadback {
    pub const fn receipt(&self) -> &QuiescentActivityLeaseResumeReceipt {
        &self.receipt
    }
}

impl WorkspaceStore {
    /// Capture a side-effect-free Source probe over one SQLite snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn probe_quiescent_activity_lease_resume(
        &self,
        binding: &WorkspaceJournalBinding,
        request: &QuiescentActivityLeaseResumeProbeRequest,
        service: StartedActivityLeaseResumeServiceIdentity,
        initiating_session: StartedActivityLeaseResumeSessionSnapshot,
        coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
        observed_at: TimestampMillis,
    ) -> Result<QuiescentActivityLeaseResumeProbe, WorkspaceStoreError> {
        let result = (|| {
            if self.journal_binding()? != *binding
                || binding.recovery_history_digest() != *request.scope().binding_digest()
            {
                return Err(QuiescentActivityLeaseResumeStoreError::Conflict("binding"));
            }
            if initiating_session.session_id() != request.initiating_session_id()
                || initiating_session.principal() != request.principal()
            {
                return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
                    "initiating Session",
                ));
            }
            super::validate_schema_shape(&self.connection)?;
            let transaction = self.connection.unchecked_transaction()?;
            match probe_in_transaction(
                &transaction,
                QuiescentActivityLeaseResumeProbeInput {
                    binding,
                    scope: request.scope(),
                    activity_id: request.activity_id(),
                    initiating_session_id: request.initiating_session_id(),
                    principal: request.principal(),
                    service,
                    initiating_session,
                    coordinator_session,
                    observed_at,
                },
            ) {
                Ok(value) => {
                    transaction.commit()?;
                    Ok(value)
                }
                Err(error) => {
                    let _ = transaction.rollback();
                    Err(error)
                }
            }
        })();
        result.map_err(WorkspaceStoreError::from)
    }

    /// Re-observe every fence under BEGIN IMMEDIATE, CAS only the lease tuple,
    /// and insert the immutable receipt in that same transaction.
    pub fn run_quiescent_activity_lease_resume_with_clock<F>(
        &mut self,
        binding: &WorkspaceJournalBinding,
        request: &QuiescentActivityLeaseResumeRunRequest,
        initiating_session: StartedActivityLeaseResumeSessionSnapshot,
        coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
        clock: F,
    ) -> Result<QuiescentActivityLeaseResumeOperation, WorkspaceStoreError>
    where
        F: FnOnce() -> Result<TimestampMillis, WorkspaceStoreError>,
    {
        (|| {
            validate_run_request(self, binding, request, initiating_session)?;
            super::validate_schema_shape(&self.connection)?;
            let live_paths = WorkspaceLiveBinding {
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
            if let Some(receipt) = replay_if_present(&transaction, request)? {
                transaction.commit()?;
                return Ok(QuiescentActivityLeaseResumeOperation::Replay(receipt));
            }
            let source_now = clock()
                .map_err(|error| QuiescentActivityLeaseResumeStoreError::Clock(Box::new(error)))?;
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
                WorkspaceStoreError::QuiescentActivityLeaseResumeCommittedUnconfirmed {
                    request_id: request.request_id(),
                    source: Box::new(WorkspaceStoreError::QuiescentActivityLeaseResume(
                        QuiescentActivityLeaseResumeStoreError::Sqlite(error),
                    )),
                }
            })?;

            let get_request = QuiescentActivityLeaseResumeGetRequest::new(
                request.scope().clone(),
                request.request_id(),
                request.request_digest(),
                receipt.activity_id(),
                receipt.initiating_agent().agent_id(),
                receipt.initiating_session().session_id(),
                receipt.initiating_session().principal(),
            )
            .map_err(QuiescentActivityLeaseResumeStoreError::from)?;
            match self.quiescent_activity_lease_resume_readback_for_request(binding, &get_request) {
                Ok(Some(readback)) if readback.receipt == receipt => {
                    Ok(QuiescentActivityLeaseResumeOperation::Recorded(receipt))
                }
                Ok(_) => Err(
                    WorkspaceStoreError::QuiescentActivityLeaseResumeCommittedUnconfirmed {
                        request_id: request.request_id(),
                        source: Box::new(WorkspaceStoreError::QuiescentActivityLeaseResume(
                            QuiescentActivityLeaseResumeStoreError::Corrupt(
                                "committed receipt readback",
                            ),
                        )),
                    },
                ),
                Err(error) => Err(
                    WorkspaceStoreError::QuiescentActivityLeaseResumeCommittedUnconfirmed {
                        request_id: request.request_id(),
                        source: Box::new(error),
                    },
                ),
            }
        })()
    }

    /// Read one immutable receipt by request ID and every exact caller fence.
    pub fn quiescent_activity_lease_resume_readback_for_request(
        &self,
        binding: &WorkspaceJournalBinding,
        request: &QuiescentActivityLeaseResumeGetRequest,
    ) -> Result<Option<QuiescentActivityLeaseResumeReadback>, WorkspaceStoreError> {
        let result = (|| {
            if self.journal_binding()? != *binding
                || binding.recovery_history_digest() != *request.scope().binding_digest()
            {
                return Err(QuiescentActivityLeaseResumeStoreError::Conflict("binding"));
            }
            super::validate_schema_shape(&self.connection)?;
            let Some(row) = load_receipt_row(&self.connection, request.request_id())? else {
                return Ok(None);
            };
            decode_exact_receipt_row(request, &row).map(Some)
        })();
        result.map_err(WorkspaceStoreError::from)
    }
}

fn load_receipt_row(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<QuiescentActivityLeaseResumeReceiptRow>, QuiescentActivityLeaseResumeStoreError>
{
    connection
        .query_row(
            "SELECT request_digest, workspace_id, activity_id, location_id,
                location_revision, workspace_revision, locator, root_fingerprint,
                binding_digest, agent_id, initiating_session_id, principal_kind,
                principal_id, source_runtime_instance_id, resumed_at_ms,
                receipt_payload, receipt_checksum
             FROM quiescent_activity_lease_resume_receipts WHERE request_id=?1",
            params![request_id.as_bytes().as_slice()],
            |row| {
                Ok(QuiescentActivityLeaseResumeReceiptRow {
                    request_digest: row.get(0)?,
                    workspace_id: row.get(1)?,
                    activity_id: row.get(2)?,
                    location_id: row.get(3)?,
                    location_revision: row.get(4)?,
                    workspace_revision: row.get(5)?,
                    locator: row.get(6)?,
                    root_fingerprint: row.get(7)?,
                    binding_digest: row.get(8)?,
                    agent_id: row.get(9)?,
                    initiating_session_id: row.get(10)?,
                    principal_kind: row.get(11)?,
                    principal_id: row.get(12)?,
                    source_runtime_instance_id: row.get(13)?,
                    resumed_at_ms: row.get(14)?,
                    receipt_payload: row.get(15)?,
                    receipt_checksum: row.get(16)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn decode_exact_receipt_row(
    request: &QuiescentActivityLeaseResumeGetRequest,
    row: &QuiescentActivityLeaseResumeReceiptRow,
) -> Result<QuiescentActivityLeaseResumeReadback, QuiescentActivityLeaseResumeStoreError> {
    let request_digest = decode_fixed::<32>(&row.request_digest, "request_digest")?;
    let checksum = decode_fixed::<32>(&row.receipt_checksum, "receipt_checksum")?;
    if row.receipt_payload.is_empty()
        || row.receipt_payload.len() > MAX_RECEIPT_PAYLOAD_BYTES
        || checksum != digest_receipt_payload(&row.receipt_payload)
    {
        return Err(QuiescentActivityLeaseResumeStoreError::Corrupt(
            "receipt checksum",
        ));
    }
    if request_digest != request.request_digest() {
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
            "request digest",
        ));
    }
    let receipt = decode_receipt(&row.receipt_payload)?;
    if receipt.request_id() != request.request_id()
        || receipt.request_digest() != request.request_digest()
        || receipt.scope() != request.scope()
        || receipt.activity_id() != request.activity_id()
        || receipt.initiating_agent().agent_id() != request.agent_id()
        || receipt.initiating_session().session_id() != request.initiating_session_id()
        || receipt.initiating_session().principal() != request.principal()
    {
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
            "receipt identity",
        ));
    }
    validate_receipt_columns(row, &receipt)?;
    Ok(QuiescentActivityLeaseResumeReadback { receipt })
}

fn validate_receipt_columns(
    row: &QuiescentActivityLeaseResumeReceiptRow,
    receipt: &QuiescentActivityLeaseResumeReceipt,
) -> Result<(), QuiescentActivityLeaseResumeStoreError> {
    let scope = receipt.scope();
    if decode_fixed::<16>(&row.workspace_id, "workspace_id")?
        != scope.workspace_id().into_uuid().into_bytes()
        || decode_fixed::<16>(&row.activity_id, "activity_id")?
            != receipt.activity_id().into_uuid().into_bytes()
        || decode_fixed::<16>(&row.location_id, "location_id")?
            != scope.location_id().into_uuid().into_bytes()
        || LocationRevision::new(row.location_revision)
            .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt("location_revision"))?
            != scope.location_revision()
        || WorkspaceRevision::new(row.workspace_revision)
            .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt("workspace_revision"))?
            != scope.workspace_revision()
        || row.locator.as_slice() != scope.locator()
        || decode_fixed::<16>(&row.root_fingerprint, "root_fingerprint")?
            != *scope.root_fingerprint().as_bytes()
        || decode_fixed::<32>(&row.binding_digest, "binding_digest")? != *scope.binding_digest()
        || decode_fixed::<16>(&row.agent_id, "agent_id")?
            != receipt
                .initiating_agent()
                .agent_id()
                .into_uuid()
                .into_bytes()
        || decode_fixed::<16>(&row.initiating_session_id, "initiating_session_id")?
            != receipt
                .initiating_session()
                .session_id()
                .into_uuid()
                .into_bytes()
        || decode_principal(row.principal_kind, row.principal_id.as_deref())?
            != receipt.initiating_session().principal()
        || decode_fixed::<16>(
            &row.source_runtime_instance_id,
            "source_runtime_instance_id",
        )? != receipt
            .source_runtime_instance_id()
            .into_uuid()
            .into_bytes()
        || decode_timestamp(row.resumed_at_ms, "resumed_at_ms")? != receipt.resumed_at()
    {
        return Err(QuiescentActivityLeaseResumeStoreError::Corrupt(
            "receipt columns",
        ));
    }
    Ok(())
}

fn validate_run_request(
    store: &WorkspaceStore,
    binding: &WorkspaceJournalBinding,
    request: &QuiescentActivityLeaseResumeRunRequest,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
) -> Result<(), QuiescentActivityLeaseResumeStoreError> {
    if store.journal_binding()? != *binding
        || binding.recovery_history_digest() != *request.scope().binding_digest()
    {
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict("binding"));
    }
    let probe = request.probe();
    let expected = probe.expectation().initiating_agent().copied().ok_or(
        QuiescentActivityLeaseResumeStoreError::Conflict("initiating Agent missing"),
    )?;
    if request.scope() != probe.scope()
        || initiating_session.session_id() != probe.expectation().initiating_session().session_id()
        || initiating_session.principal() != probe.expectation().initiating_session().principal()
        || expected.session_id() != initiating_session.session_id()
        || expected.principal() != initiating_session.principal()
    {
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
            "initiating Session changed",
        ));
    }
    Ok(())
}

fn replay_if_present(
    connection: &Connection,
    request: &QuiescentActivityLeaseResumeRunRequest,
) -> Result<Option<QuiescentActivityLeaseResumeReceipt>, QuiescentActivityLeaseResumeStoreError> {
    let Some(receipt) = load_receipt(connection, request.request_id())? else {
        return Ok(None);
    };
    let probe = request.probe();
    let expected_agent = probe.expectation().initiating_agent().ok_or(
        QuiescentActivityLeaseResumeStoreError::Conflict("initiating Agent missing"),
    )?;
    if receipt.request_digest() != request.request_digest()
        || receipt.scope() != request.scope()
        || receipt.probe_digest() != probe.probe_digest()
        || receipt.activity_id() != probe.expectation().activity().id()
        || receipt.initiating_agent().agent_id() != expected_agent.agent_id()
        || receipt.initiating_session().session_id()
            != probe.expectation().initiating_session().session_id()
        || receipt.initiating_session().principal()
            != probe.expectation().initiating_session().principal()
    {
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
            "request identity/digest",
        ));
    }
    Ok(Some(receipt))
}

fn record_resume_in_transaction(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    request: &QuiescentActivityLeaseResumeRunRequest,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
    source_now: TimestampMillis,
) -> Result<QuiescentActivityLeaseResumeReceipt, QuiescentActivityLeaseResumeStoreError> {
    let probe = request.probe();
    if !probe.is_live_at(source_now) {
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
            "probe expired or clock regressed",
        ));
    }
    if request.current_service() != probe.service() {
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
            "Source boot/delegation changed",
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
        return Err(QuiescentActivityLeaseResumeStoreError::Conflict(
            "Source probe fence changed",
        ));
    }
    let activity_after = advance_activity_lease(transaction, request, probe, source_now)?;
    let receipt = QuiescentActivityLeaseResumeReceipt::from_successful_probe(
        probe,
        request.request_id(),
        request.request_digest(),
        activity_after,
        source_now,
    )?;
    insert_receipt(transaction, request, &receipt)?;
    Ok(receipt)
}

fn recompute_probe(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    request: &QuiescentActivityLeaseResumeRunRequest,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
) -> Result<QuiescentActivityLeaseResumeProbe, QuiescentActivityLeaseResumeStoreError> {
    let probe = request.probe();
    let expectation = probe.expectation();
    probe_in_transaction(
        transaction,
        QuiescentActivityLeaseResumeProbeInput {
            binding,
            scope: request.scope(),
            activity_id: expectation.activity().id(),
            initiating_session_id: initiating_session.session_id(),
            principal: initiating_session.principal(),
            service: request.current_service(),
            initiating_session,
            coordinator_session,
            observed_at: probe.probe_observed_at(),
        },
    )
}

fn advance_activity_lease(
    transaction: &Transaction<'_>,
    request: &QuiescentActivityLeaseResumeRunRequest,
    probe: &QuiescentActivityLeaseResumeProbe,
    source_now: TimestampMillis,
) -> Result<RegisteredActivity, QuiescentActivityLeaseResumeStoreError> {
    let before = probe.expectation().activity();
    let owner = request.current_service().runtime_instance_id();
    let lease_until = TimestampMillis::new(
        source_now
            .get()
            .checked_add(forge_domain::QUIESCENT_ACTIVITY_LEASE_RESUME_LEASE_DURATION_MS)
            .ok_or(QuiescentActivityLeaseResumeStoreError::Invalid(
                "lease deadline overflow",
            ))?,
    )
    .map_err(|_| QuiescentActivityLeaseResumeStoreError::Invalid("lease deadline"))?;
    let lease_revision = before
        .lease_revision()
        .checked_next()
        .map_err(|_| QuiescentActivityLeaseResumeStoreError::Conflict("lease revision overflow"))?;
    let original_owner =
        before
            .lease_owner_id()
            .ok_or(QuiescentActivityLeaseResumeStoreError::Conflict(
                "original lease missing",
            ))?;
    let original_until =
        before
            .lease_until()
            .ok_or(QuiescentActivityLeaseResumeStoreError::Conflict(
                "original lease missing",
            ))?;
    started::update_activity_lease(
        transaction,
        before,
        owner,
        lease_until,
        lease_revision,
        original_owner,
        original_until,
    )?;
    let lease = ActivityLeaseProjection::from_parts(Some(owner), Some(lease_until), lease_revision)
        .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt("resumed lease"))?;
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

#[derive(Clone, Copy)]
struct QuiescentActivityLeaseResumeProbeInput<'a> {
    binding: &'a WorkspaceJournalBinding,
    scope: &'a ExpiredActivityRecoveryProbeScope,
    activity_id: ActivityId,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    service: StartedActivityLeaseResumeServiceIdentity,
    initiating_session: StartedActivityLeaseResumeSessionSnapshot,
    coordinator_session: Option<StartedActivityLeaseResumeSessionSnapshot>,
    observed_at: TimestampMillis,
}

fn probe_in_transaction(
    transaction: &Transaction<'_>,
    input: QuiescentActivityLeaseResumeProbeInput<'_>,
) -> Result<QuiescentActivityLeaseResumeProbe, QuiescentActivityLeaseResumeStoreError> {
    let QuiescentActivityLeaseResumeProbeInput {
        binding,
        scope,
        activity_id,
        initiating_session_id,
        principal,
        service,
        initiating_session,
        coordinator_session,
        observed_at,
    } = input;
    let delegation = started::load_scope_delegation(transaction, binding, scope)?;
    let actors = started::load_activity_actors(
        transaction,
        scope.workspace_id(),
        activity_id,
        initiating_session_id,
        principal,
        initiating_session,
        coordinator_session,
    )?;
    let goal_census = started::goal_census(transaction, scope.workspace_id(), activity_id)?;
    let dag_census = started::dag_census(transaction, scope.workspace_id(), activity_id)?;
    let agent_census = agent_census(transaction, scope.workspace_id(), activity_id)?;
    let coordination_work = coordination_work(transaction, scope.workspace_id(), activity_id)?;
    let (assignment_census, _) =
        started::assignment_census(transaction, scope.workspace_id(), activity_id)?;
    let work_history_census = work_history_census(transaction, scope.workspace_id(), activity_id)?;
    let physical_census = started::physical_census(transaction, scope.workspace_id(), activity_id)?;
    let expectation = QuiescentActivityLeaseResumeExpectation::new(
        actors.activity,
        actors.initiating_agent,
        actors.initiating_session,
        actors.coordinator,
        actors.coordinator_agent_attached,
        actors.coordinator_session_open,
        goal_census,
        dag_census,
        agent_census,
        coordination_work,
        assignment_census,
        work_history_census,
        physical_census,
    )?;
    let blocker = first_probe_blocker(&expectation, observed_at);
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
    Ok(QuiescentActivityLeaseResumeProbe::new(
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

pub(super) fn agent_census(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<QuiescentActivityLeaseResumeAgentCensus, QuiescentActivityLeaseResumeStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let maximum = QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_AGENT_ROWS as usize;
    let mut hasher = Sha256::new();
    hasher.update(b"forge.quiescent_activity_lease_resume.agent_census.v1\0");
    let (row_count, truncated) = started::hash_query(
        connection,
        "SELECT * FROM agent_instances WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id LIMIT ?3",
        params![
            workspace.as_slice(),
            activity.as_slice(),
            i64::try_from(maximum + 1).unwrap_or(i64::MAX)
        ],
        &mut hasher,
        maximum,
    )?;
    Ok(QuiescentActivityLeaseResumeAgentCensus::new(
        row_count,
        hasher.finalize().into(),
        truncated,
        !truncated,
    )?)
}

pub(super) fn coordination_work(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<QuiescentActivityLeaseResumeCoordinationWork, QuiescentActivityLeaseResumeStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let nonterminal_goal_count = started::query_count(
        connection,
        "SELECT COUNT(*) FROM goals WHERE workspace_id=?1 AND activity_id=?2 AND state IN (0,1,2)",
        params![workspace.as_slice(), activity.as_slice()],
    )?;
    let work_goal_count = started::query_count(
        connection,
        "SELECT COUNT(*) FROM goals g WHERE g.workspace_id=?1 AND g.activity_id=?2 AND g.state IN (0,1,2)
         AND EXISTS (SELECT 1 FROM goal_dag_heads h JOIN goal_dag_nodes n
           ON n.goal_id=h.goal_id AND n.dag_revision=h.dag_revision
           WHERE h.goal_id=g.goal_id)",
        params![workspace.as_slice(), activity.as_slice()],
    )?;
    let nonterminal_goal_count = u32::try_from(nonterminal_goal_count)
        .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt("nonterminal_goal_count"))?;
    let work_goal_count = u32::try_from(work_goal_count)
        .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt("coordination_work_count"))?;
    Ok(QuiescentActivityLeaseResumeCoordinationWork::new(
        nonterminal_goal_count,
        work_goal_count,
    )?)
}

pub(super) fn work_history_census(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<QuiescentActivityLeaseResumeWorkHistoryCensus, QuiescentActivityLeaseResumeStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"forge.quiescent_activity_lease_resume.work_history_census.v1\0");
    hasher.update(b"agent_work_updates\0");
    let (update_count, updates_truncated) = started::hash_query(
        connection,
        "SELECT * FROM agent_work_updates WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id,update_sequence,update_id LIMIT ?3",
        params![
            workspace.as_slice(),
            activity.as_slice(),
            i64::from(QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_UPDATE_ROWS) + 1
        ],
        &mut hasher,
        QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_UPDATE_ROWS as usize,
    )?;
    hasher.update(b"agent_work_update_evidence_refs\0");
    let (evidence_ref_count, evidence_truncated) = started::hash_query(
        connection,
        "SELECT r.* FROM agent_work_update_evidence_refs r JOIN agent_work_updates u
           ON u.update_id=r.update_id AND u.agent_id=r.agent_id AND u.workspace_id=r.workspace_id
         WHERE u.workspace_id=?1 AND u.activity_id=?2 ORDER BY r.update_id,r.evidence_kind,r.evidence_id LIMIT ?3",
        params![workspace.as_slice(), activity.as_slice(), i64::from(QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_EVIDENCE_REFS) + 1],
        &mut hasher,
        QUIESCENT_ACTIVITY_LEASE_RESUME_MAX_WORK_EVIDENCE_REFS as usize,
    )?;
    let evidence_counts_match: bool = connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM agent_work_updates u
          WHERE u.workspace_id=?1 AND u.activity_id=?2 AND u.evidence_count !=
            (SELECT COUNT(*) FROM agent_work_update_evidence_refs r
              WHERE r.update_id=u.update_id AND r.agent_id=u.agent_id AND r.workspace_id=u.workspace_id))",
        params![workspace.as_slice(), activity.as_slice()],
        |row| row.get(0),
    )?;
    let truncated = updates_truncated || evidence_truncated;
    Ok(QuiescentActivityLeaseResumeWorkHistoryCensus::new(
        update_count,
        evidence_ref_count,
        hasher.finalize().into(),
        truncated,
        !truncated && evidence_counts_match,
    )?)
}

fn first_probe_blocker(
    expectation: &QuiescentActivityLeaseResumeExpectation,
    observed_at: TimestampMillis,
) -> Option<QuiescentActivityLeaseResumeBlocker> {
    let activity = expectation.activity();
    if activity.state() != ActivityState::Open {
        return Some(QuiescentActivityLeaseResumeBlocker::ActivityNotOpen);
    }
    let (Some(owner), Some(until)) = (activity.lease_owner_id(), activity.lease_until()) else {
        return Some(QuiescentActivityLeaseResumeBlocker::ActivityLeaseMissing);
    };
    if owner.into_uuid().is_nil() || until.get() > observed_at.get() {
        return Some(QuiescentActivityLeaseResumeBlocker::ActivityLeaseNotExpired);
    }
    let Some(agent) = expectation.initiating_agent() else {
        return Some(QuiescentActivityLeaseResumeBlocker::InitiatingAgentMissing);
    };
    if expectation.initiating_session().state() != forge_domain::AgentSessionState::Open {
        return Some(QuiescentActivityLeaseResumeBlocker::InitiatingSessionNotOpen);
    }
    if !agent.attached() {
        return Some(QuiescentActivityLeaseResumeBlocker::InitiatingAgentNotAttached);
    }
    let Some(coordinator) = expectation.coordinator() else {
        return Some(QuiescentActivityLeaseResumeBlocker::CoordinatorMissing);
    };
    if coordinator.agent_id() != agent.agent_id()
        || coordinator.agent_revision() != agent.revision()
        || coordinator.principal() != agent.principal()
    {
        return Some(QuiescentActivityLeaseResumeBlocker::CoordinatorAgentMismatch);
    }
    if !expectation.coordinator_agent_attached() {
        return Some(QuiescentActivityLeaseResumeBlocker::CoordinatorAgentNotAttached);
    }
    if coordinator.session_id() != expectation.initiating_session().session_id()
        || coordinator.session_revision() != expectation.initiating_session().revision()
        || coordinator.session_updated_at() != expectation.initiating_session().updated_at()
        || coordinator.principal() != expectation.initiating_session().principal()
    {
        return Some(QuiescentActivityLeaseResumeBlocker::CoordinatorSessionMismatch);
    }
    if !expectation.coordinator_session_open() {
        return Some(QuiescentActivityLeaseResumeBlocker::CoordinatorSessionNotOpen);
    }
    if !expectation.goal_census().complete() || expectation.goal_census().truncated() {
        return Some(QuiescentActivityLeaseResumeBlocker::GoalCensusIncomplete);
    }
    if !expectation.dag_census().complete() || expectation.dag_census().truncated() {
        return Some(QuiescentActivityLeaseResumeBlocker::DagCensusIncomplete);
    }
    if !expectation.agent_census().complete() || expectation.agent_census().truncated() {
        return Some(QuiescentActivityLeaseResumeBlocker::AgentCensusIncomplete);
    }
    if expectation
        .coordination_work()
        .nonterminal_goal_with_current_dag_count()
        == 0
    {
        return Some(QuiescentActivityLeaseResumeBlocker::CoordinationWorkMissing);
    }
    let assignments = expectation.assignment_census();
    if !assignments.complete() || assignments.truncated() {
        return Some(QuiescentActivityLeaseResumeBlocker::AssignmentCensusIncomplete);
    }
    if assignments.row_count() != 0 {
        return Some(QuiescentActivityLeaseResumeBlocker::AssignmentPresent);
    }
    if !expectation.work_history_census().complete()
        || expectation.work_history_census().truncated()
    {
        return Some(QuiescentActivityLeaseResumeBlocker::WorkHistoryIncomplete);
    }
    let physical = expectation.physical_census();
    if physical.execution_active_count() != 0
        || physical.writer_lease_active_count() != 0
        || physical.pending_effect_count() != 0
        || physical.unresolved_worktree_count() != 0
    {
        return Some(QuiescentActivityLeaseResumeBlocker::PhysicalActivityEffectPresent);
    }
    if !physical.complete()
        || physical.truncated()
        || physical.execution_unknown_count() != 0
        || physical.writer_lease_unknown_count() != 0
        || physical.effect_unknown_count() != 0
        || physical.worktree_unknown_count() != 0
        || physical.unknown_count() != 0
    {
        return Some(QuiescentActivityLeaseResumeBlocker::PhysicalCensusIncomplete);
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn digest_probe(
    scope: &ExpiredActivityRecoveryProbeScope,
    service: StartedActivityLeaseResumeServiceIdentity,
    delegation: StartedActivityLeaseResumeDelegation,
    expectation: &QuiescentActivityLeaseResumeExpectation,
    observed_at: TimestampMillis,
    resumable_now: bool,
    blocker: Option<QuiescentActivityLeaseResumeBlocker>,
) -> [u8; QUIESCENT_ACTIVITY_LEASE_RESUME_DIGEST_BYTES] {
    let mut writer = started::PayloadWriter::default();
    writer.bytes(PROBE_DIGEST_DOMAIN);
    started::encode_scope(&mut writer, scope);
    writer.uuid(service.backend_id().into_uuid());
    writer.uuid(service.issuer().into_uuid());
    writer.uuid(service.destination_id());
    writer.uuid(service.runtime_instance_id().into_uuid());
    writer.uuid(delegation.migration_id());
    writer.uuid(delegation.destination_id());
    writer.u64(delegation.freeze_revision());
    writer.i64(delegation.freeze_created_at().get());
    writer.i64(delegation.freeze_updated_at().get());
    writer.bytes(&delegation.manifest_digest());
    writer.i64(delegation.delegated_at().get());
    writer.bytes(&delegation.delegation_digest());
    started::encode_activity(&mut writer, expectation.activity());
    if let Some(agent) = expectation.initiating_agent() {
        writer.u8(1);
        started::encode_agent(&mut writer, *agent);
    } else {
        writer.u8(0);
    }
    started::encode_session(&mut writer, *expectation.initiating_session());
    if let Some(coordinator) = expectation.coordinator() {
        writer.u8(1);
        started::encode_coordinator(&mut writer, *coordinator);
    } else {
        writer.u8(0);
    }
    writer.u8(u8::from(expectation.coordinator_agent_attached()));
    writer.u8(u8::from(expectation.coordinator_session_open()));
    encode_goal_census(&mut writer, expectation.goal_census());
    encode_dag_census(&mut writer, expectation.dag_census());
    encode_agent_census(&mut writer, expectation.agent_census());
    writer.u32(expectation.coordination_work().nonterminal_goal_count());
    writer.u32(
        expectation
            .coordination_work()
            .nonterminal_goal_with_current_dag_count(),
    );
    encode_assignment_census(&mut writer, expectation.assignment_census());
    encode_work_history_census(&mut writer, expectation.work_history_census());
    encode_physical_census(&mut writer, expectation.physical_census());
    writer.i64(observed_at.get());
    writer.u8(u8::from(resumable_now));
    writer.u8(blocker.map_or(0, blocker_code));
    let mut hasher = Sha256::new();
    hasher.update(writer.finish());
    hasher.finalize().into()
}

fn blocker_code(value: QuiescentActivityLeaseResumeBlocker) -> u8 {
    match value {
        QuiescentActivityLeaseResumeBlocker::ActivityNotOpen => 1,
        QuiescentActivityLeaseResumeBlocker::ActivityLeaseMissing => 2,
        QuiescentActivityLeaseResumeBlocker::ActivityLeaseNotExpired => 3,
        QuiescentActivityLeaseResumeBlocker::InitiatingAgentMissing => 4,
        QuiescentActivityLeaseResumeBlocker::InitiatingSessionNotOpen => 5,
        QuiescentActivityLeaseResumeBlocker::InitiatingAgentNotAttached => 6,
        QuiescentActivityLeaseResumeBlocker::CoordinatorMissing => 7,
        QuiescentActivityLeaseResumeBlocker::CoordinatorAgentMismatch => 8,
        QuiescentActivityLeaseResumeBlocker::CoordinatorAgentNotAttached => 9,
        QuiescentActivityLeaseResumeBlocker::CoordinatorSessionMismatch => 10,
        QuiescentActivityLeaseResumeBlocker::CoordinatorSessionNotOpen => 11,
        QuiescentActivityLeaseResumeBlocker::GoalCensusIncomplete => 12,
        QuiescentActivityLeaseResumeBlocker::DagCensusIncomplete => 13,
        QuiescentActivityLeaseResumeBlocker::AgentCensusIncomplete => 14,
        QuiescentActivityLeaseResumeBlocker::CoordinationWorkMissing => 15,
        QuiescentActivityLeaseResumeBlocker::AssignmentCensusIncomplete => 16,
        QuiescentActivityLeaseResumeBlocker::AssignmentPresent => 17,
        QuiescentActivityLeaseResumeBlocker::WorkHistoryIncomplete => 18,
        QuiescentActivityLeaseResumeBlocker::PhysicalActivityEffectPresent => 19,
        QuiescentActivityLeaseResumeBlocker::PhysicalCensusIncomplete => 20,
    }
}

fn encode_goal_census(
    writer: &mut started::PayloadWriter,
    value: StartedActivityLeaseResumeGoalCensus,
) {
    writer.u32(value.row_count());
    writer.bytes(&value.digest());
    writer.u8(u8::from(value.truncated()));
    writer.u8(u8::from(value.complete()));
}

fn encode_dag_census(
    writer: &mut started::PayloadWriter,
    value: StartedActivityLeaseResumeDagCensus,
) {
    writer.u32(value.head_count());
    writer.u32(value.node_count());
    writer.u32(value.edge_count());
    writer.bytes(&value.digest());
    writer.u8(u8::from(value.truncated()));
    writer.u8(u8::from(value.complete()));
}

fn encode_agent_census(
    writer: &mut started::PayloadWriter,
    value: QuiescentActivityLeaseResumeAgentCensus,
) {
    writer.u32(value.row_count());
    writer.bytes(&value.digest());
    writer.u8(u8::from(value.truncated()));
    writer.u8(u8::from(value.complete()));
}

fn encode_assignment_census(
    writer: &mut started::PayloadWriter,
    value: StartedActivityLeaseResumeAssignmentCensus,
) {
    writer.u32(value.row_count());
    writer.bytes(&value.digest());
    writer.u8(u8::from(value.truncated()));
    writer.u8(u8::from(value.complete()));
}

fn encode_work_history_census(
    writer: &mut started::PayloadWriter,
    value: QuiescentActivityLeaseResumeWorkHistoryCensus,
) {
    writer.u32(value.update_count());
    writer.u32(value.evidence_ref_count());
    writer.bytes(&value.digest());
    writer.u8(u8::from(value.truncated()));
    writer.u8(u8::from(value.complete()));
}

fn encode_physical_census(
    writer: &mut started::PayloadWriter,
    value: StartedActivityLeaseResumePhysicalCensus,
) {
    writer.u32(value.row_count());
    writer.u64(value.execution_active_count());
    writer.u64(value.execution_unknown_count());
    writer.u64(value.writer_lease_active_count());
    writer.u64(value.writer_lease_unknown_count());
    writer.u64(value.pending_effect_count());
    writer.u64(value.effect_unknown_count());
    writer.u64(value.unresolved_worktree_count());
    writer.u64(value.worktree_unknown_count());
    writer.u64(value.unknown_count());
    writer.bytes(&value.digest());
    writer.u8(u8::from(value.truncated()));
    writer.u8(u8::from(value.complete()));
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    request: &QuiescentActivityLeaseResumeRunRequest,
    receipt: &QuiescentActivityLeaseResumeReceipt,
) -> Result<(), QuiescentActivityLeaseResumeStoreError> {
    let payload = encode_receipt(receipt);
    if payload.is_empty() || payload.len() > MAX_RECEIPT_PAYLOAD_BYTES {
        return Err(QuiescentActivityLeaseResumeStoreError::Invalid(
            "receipt payload bounds",
        ));
    }
    let checksum = digest_receipt_payload(&payload);
    let (principal_kind, principal_id) = encode_principal(receipt.initiating_session().principal());
    transaction.execute(
        "INSERT INTO quiescent_activity_lease_resume_receipts (
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
            receipt
                .initiating_agent()
                .agent_id()
                .into_uuid()
                .as_bytes()
                .as_slice(),
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

fn encode_receipt(receipt: &QuiescentActivityLeaseResumeReceipt) -> Vec<u8> {
    let mut writer = started::PayloadWriter::default();
    writer.bytes(RECEIPT_PAYLOAD_VERSION);
    started::encode_scope(&mut writer, receipt.scope());
    writer.uuid(receipt.request_id());
    writer.bytes(&receipt.request_digest());
    started::encode_activity(&mut writer, receipt.activity());
    started::encode_agent(&mut writer, receipt.initiating_agent());
    started::encode_session(&mut writer, receipt.initiating_session());
    started::encode_coordinator(&mut writer, receipt.coordinator());
    writer.uuid(receipt.source_runtime_instance_id().into_uuid());
    writer.bytes(&receipt.probe_digest());
    writer.i64(receipt.resumed_at().get());
    writer.finish()
}

fn decode_receipt(
    payload: &[u8],
) -> Result<QuiescentActivityLeaseResumeReceipt, QuiescentActivityLeaseResumeStoreError> {
    if payload.len() > MAX_RECEIPT_PAYLOAD_BYTES {
        return Err(QuiescentActivityLeaseResumeStoreError::Corrupt(
            "payload bounds",
        ));
    }
    let mut reader = started::PayloadReader::new(payload);
    if reader.bytes(4)? != RECEIPT_PAYLOAD_VERSION {
        return Err(QuiescentActivityLeaseResumeStoreError::Corrupt(
            "payload version",
        ));
    }
    let scope = started::decode_scope(&mut reader)?;
    let request_id = reader.uuid()?;
    let request_digest = reader.fixed::<32>()?;
    let activity = started::decode_activity(&mut reader)?;
    let agent = started::decode_agent(&mut reader)?;
    let session = started::decode_session(&mut reader)?;
    let coordinator = started::decode_coordinator(&mut reader)?;
    let runtime = RuntimeInstanceId::from_uuid(reader.uuid()?);
    let probe_digest = reader.fixed::<32>()?;
    let resumed_at = decode_timestamp(reader.i64()?, "resumed_at_ms")?;
    reader.finish()?;
    Ok(QuiescentActivityLeaseResumeReceipt::from_parts(
        QuiescentActivityLeaseResumeReceiptParts {
            scope,
            request_id,
            request_digest,
            activity_after: activity,
            initiating_agent: agent,
            initiating_session: session,
            coordinator,
            source_runtime_instance_id: runtime,
            probe_digest,
            resumed_at,
        },
    )?)
}

fn load_receipt(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<QuiescentActivityLeaseResumeReceipt>, QuiescentActivityLeaseResumeStoreError> {
    let row = connection
        .query_row(
            "SELECT receipt_payload, receipt_checksum FROM quiescent_activity_lease_resume_receipts WHERE request_id=?1",
            params![request_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((payload, checksum)) = row else {
        return Ok(None);
    };
    if payload.is_empty()
        || payload.len() > MAX_RECEIPT_PAYLOAD_BYTES
        || decode_fixed::<32>(&checksum, "receipt_checksum")? != digest_receipt_payload(&payload)
    {
        return Err(QuiescentActivityLeaseResumeStoreError::Corrupt(
            "receipt checksum",
        ));
    }
    let receipt = decode_receipt(&payload)?;
    if receipt.request_id() != request_id {
        return Err(QuiescentActivityLeaseResumeStoreError::Corrupt(
            "request identity",
        ));
    }
    Ok(Some(receipt))
}

fn decode_fixed<const N: usize>(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; N], QuiescentActivityLeaseResumeStoreError> {
    value
        .try_into()
        .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt(field))
}

fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, QuiescentActivityLeaseResumeStoreError> {
    TimestampMillis::new(value).map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt(field))
}

fn encode_principal(value: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match value {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes().to_vec())),
    }
}

fn decode_principal(
    kind: i64,
    id: Option<&[u8]>,
) -> Result<AuthenticatedPrincipal, QuiescentActivityLeaseResumeStoreError> {
    match (kind, id) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(value)) => Ok(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(
                Uuid::from_slice(value)
                    .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt("principal_id"))?,
            ),
        )),
        (2, Some(value)) => Ok(AuthenticatedPrincipal::OAuthGrant(
            forge_domain::OAuthGrantId::from_uuid(
                Uuid::from_slice(value)
                    .map_err(|_| QuiescentActivityLeaseResumeStoreError::Corrupt("principal_id"))?,
            ),
        )),
        _ => Err(QuiescentActivityLeaseResumeStoreError::Corrupt("principal")),
    }
}

fn digest_receipt_payload(value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_PAYLOAD_DOMAIN);
    hasher.update(value);
    hasher.finalize().into()
}
