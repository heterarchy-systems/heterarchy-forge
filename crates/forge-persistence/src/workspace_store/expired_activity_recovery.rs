//! Atomic expired Activity successor recovery.
//!
//! The operation is deliberately native to the Workspace owner.  It claims
//! the existing recovery-maintenance lease after the SQLite IMMEDIATE writer
//! lock is held, rechecks every probe fence, terminalizes the exact expired
//! predecessor, creates a leased successor and immutable receipt, then
//! releases the same recovery epoch before committing once.

#![allow(
    clippy::cast_possible_wrap,
    clippy::cmp_owned,
    clippy::collapsible_if,
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::error::Error;

use forge_domain::{
    ActivityId, ActivityLeaseRevision, ActivityRevision, ActivityState, ActivitySuccessor,
    AgentAttachmentState, AgentInstanceId, AuthenticatedPrincipal, ClaimRecoveryLease,
    ExpectedActivityCoordinator, ExpectedExpiredActivity, ExpiredActivityRecoveryAgentSnapshot,
    ExpiredActivityRecoveryBlocker, ExpiredActivityRecoveryDelegationFence,
    ExpiredActivityRecoveryExpectation, ExpiredActivityRecoveryFreezeState,
    ExpiredActivityRecoveryProbe, ExpiredActivityRecoveryProbeScope,
    ExpiredActivityRecoverySessionEvidence, ExpiredActivityRecoveryValidationError, ForgeBackendId,
    OrchestrationIssuerId, RecoveryLeaseDurationMillis, RecoveryMaintenanceLease,
    RegisteredActivity, ReleaseRecoveryLease, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Params, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_store::{WorkspaceJournalBinding, WorkspaceStore, WorkspaceStoreError};

const DIGEST_BYTES: usize = 32;
const MAX_AGENT_ROWS: u32 = 257;
const PROBE_DOMAIN: &[u8] = b"forge.activity.expired-successor-recovery.probe.v1\0";
const AGENTS_DOMAIN: &[u8] = b"forge.activity.expired-successor-recovery.agents.v1\0";
const COORDINATOR_DOMAIN: &[u8] = b"forge.activity.expired-successor-recovery.coordinator.v1\0";
const RELATION_DOMAIN: &[u8] = b"forge.activity.expired-successor-recovery.relation.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"forge.activity.expired-successor-recovery.receipt.v1\0";

/// Request accepted only after the control boundary has resolved the exact
/// initiating Session and checked the current `BridgeClients` identity.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryStoreRequest {
    pub request_id: Uuid,
    pub request_digest: [u8; DIGEST_BYTES],
    pub probe_scope: ExpiredActivityRecoveryProbeScope,
    pub probe_observed_at: TimestampMillis,
    pub probe_digest: [u8; DIGEST_BYTES],
    pub delegation: ExpiredActivityRecoveryDelegationFence,
    pub delegation_digest: [u8; DIGEST_BYTES],
    pub service_backend_id: ForgeBackendId,
    pub service_issuer: OrchestrationIssuerId,
    pub service_destination_id: Uuid,
    pub owner_id: RuntimeInstanceId,
    pub duration: RecoveryLeaseDurationMillis,
    pub expectation: ExpiredActivityRecoveryExpectation,
    pub session: ExpiredActivityRecoverySessionEvidence,
}

impl ExpiredActivityRecoveryStoreRequest {
    pub fn validate(&self) -> Result<(), ExpiredActivityRecoveryStoreError> {
        if self.request_id.is_nil()
            || self.request_digest == [0; DIGEST_BYTES]
            || self.probe_digest == [0; DIGEST_BYTES]
            || self.delegation_digest == [0; DIGEST_BYTES]
            || self.service_destination_id.is_nil()
            || self.owner_id.into_uuid().is_nil()
            || self.service_backend_id.into_uuid().is_nil()
            || self.service_issuer.into_uuid().is_nil()
        {
            return Err(ExpiredActivityRecoveryStoreError::Invalid(
                "request identity",
            ));
        }
        if self.expectation.predecessor().activity_id() == self.expectation.successor_activity_id()
        {
            return Err(ExpiredActivityRecoveryStoreError::Invalid("self link"));
        }
        if self.delegation.workspace_id() != self.probe_scope.workspace_id()
            || self.delegation.destination_id() != self.service_destination_id
        {
            return Err(ExpiredActivityRecoveryStoreError::Conflict(
                "delegation/service scope mismatch",
            ));
        }
        if self.session.session_id() != self.expectation.initiating_session_id()
            || self.session.principal() != self.expectation.principal()
        {
            return Err(ExpiredActivityRecoveryStoreError::Conflict(
                "Session evidence does not match the expectation",
            ));
        }
        Ok(())
    }
}

/// Atomic result classification. Busy and claim-conflict carry the unchanged
/// lease and never contain a semantic receipt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiredActivityRecoveryOperation {
    Recorded(ExpiredActivityRecoveryReceipt),
    Replay(ExpiredActivityRecoveryReceipt),
    Busy(RecoveryMaintenanceLease),
    ClaimConflict(RecoveryMaintenanceLease),
}

/// Immutable recovery result plus the exact snapshots required for restart
/// readback. Current Activity projections are intentionally read separately.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryReceipt {
    request_id: Uuid,
    request_digest: [u8; DIGEST_BYTES],
    probe_scope: ExpiredActivityRecoveryProbeScope,
    probe_observed_at: TimestampMillis,
    probe_digest: [u8; DIGEST_BYTES],
    delegation: ExpiredActivityRecoveryDelegationFence,
    delegation_digest: [u8; DIGEST_BYTES],
    service_backend_id: ForgeBackendId,
    service_issuer: OrchestrationIssuerId,
    service_destination_id: Uuid,
    owner_id: RuntimeInstanceId,
    duration: RecoveryLeaseDurationMillis,
    recovered_at: TimestampMillis,
    claimed_lease_until: TimestampMillis,
    claimed_epoch: i64,
    claimed_revision: i64,
    released_epoch: i64,
    released_revision: i64,
    released_updated_at: TimestampMillis,
    session: ExpiredActivityRecoverySessionEvidence,
    expectation: ExpiredActivityRecoveryExpectation,
    predecessor_after: RegisteredActivity,
    successor: RegisteredActivity,
    relation: ActivitySuccessor,
    agents: Vec<ExpiredActivityRecoveryAgentSnapshot>,
    coordinator_digest: [u8; DIGEST_BYTES],
    relation_digest: [u8; DIGEST_BYTES],
    receipt_digest: [u8; DIGEST_BYTES],
}

/// One coherent historical receipt plus the current lineage projections read
/// from the same Workspace SQLite snapshot. The historical receipt remains
/// immutable while current successor lease/coordinator state may advance.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredActivityRecoveryReadback {
    receipt: ExpiredActivityRecoveryReceipt,
    current_predecessor: RegisteredActivity,
    current_successor: RegisteredActivity,
    relation: ActivitySuccessor,
}

impl ExpiredActivityRecoveryReadback {
    pub const fn receipt(&self) -> &ExpiredActivityRecoveryReceipt {
        &self.receipt
    }
    pub const fn current_predecessor(&self) -> &RegisteredActivity {
        &self.current_predecessor
    }
    pub const fn current_successor(&self) -> &RegisteredActivity {
        &self.current_successor
    }
    pub const fn relation(&self) -> ActivitySuccessor {
        self.relation
    }
}

impl ExpiredActivityRecoveryReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &ExpiredActivityRecoveryStoreRequest,
        recovered_at: TimestampMillis,
        claimed: &RecoveryMaintenanceLease,
        released: &RecoveryMaintenanceLease,
        predecessor_after: RegisteredActivity,
        successor: RegisteredActivity,
        relation: ActivitySuccessor,
        agents: Vec<ExpiredActivityRecoveryAgentSnapshot>,
        coordinator_digest: [u8; DIGEST_BYTES],
    ) -> Result<Self, ExpiredActivityRecoveryStoreError> {
        let relation_digest = relation_digest(&relation);
        let mut receipt = Self {
            request_id: request.request_id,
            request_digest: request.request_digest,
            probe_scope: request.probe_scope.clone(),
            probe_observed_at: request.probe_observed_at,
            probe_digest: request.probe_digest,
            delegation: request.delegation,
            delegation_digest: request.delegation_digest,
            service_backend_id: request.service_backend_id,
            service_issuer: request.service_issuer,
            service_destination_id: request.service_destination_id,
            owner_id: request.owner_id,
            duration: request.duration,
            recovered_at,
            claimed_lease_until: claimed.lease_until().ok_or(
                ExpiredActivityRecoveryStoreError::Invalid("claimed recovery lease expiry"),
            )?,
            claimed_epoch: claimed.epoch().get(),
            claimed_revision: claimed.revision().get(),
            released_epoch: released.epoch().get(),
            released_revision: released.revision().get(),
            released_updated_at: released.updated_at(),
            session: request.session,
            expectation: request.expectation.clone(),
            predecessor_after,
            successor,
            relation,
            agents,
            coordinator_digest,
            relation_digest,
            receipt_digest: [0; DIGEST_BYTES],
        };
        receipt.receipt_digest = receipt_digest(&receipt);
        Ok(receipt)
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub const fn request_digest(&self) -> [u8; DIGEST_BYTES] {
        self.request_digest
    }
    pub const fn probe_observed_at(&self) -> TimestampMillis {
        self.probe_observed_at
    }
    pub const fn probe_digest(&self) -> [u8; DIGEST_BYTES] {
        self.probe_digest
    }
    pub const fn delegation(&self) -> ExpiredActivityRecoveryDelegationFence {
        self.delegation
    }
    pub const fn delegation_digest(&self) -> [u8; DIGEST_BYTES] {
        self.delegation_digest
    }
    pub const fn service_backend_id(&self) -> ForgeBackendId {
        self.service_backend_id
    }
    pub const fn service_issuer(&self) -> OrchestrationIssuerId {
        self.service_issuer
    }
    pub const fn service_destination_id(&self) -> Uuid {
        self.service_destination_id
    }
    pub const fn owner_id(&self) -> RuntimeInstanceId {
        self.owner_id
    }
    pub const fn duration(&self) -> RecoveryLeaseDurationMillis {
        self.duration
    }
    pub const fn recovered_at(&self) -> TimestampMillis {
        self.recovered_at
    }
    pub const fn claimed_lease_until(&self) -> TimestampMillis {
        self.claimed_lease_until
    }
    pub const fn claimed_epoch(&self) -> i64 {
        self.claimed_epoch
    }
    pub const fn claimed_revision(&self) -> i64 {
        self.claimed_revision
    }
    pub const fn released_epoch(&self) -> i64 {
        self.released_epoch
    }
    pub const fn released_revision(&self) -> i64 {
        self.released_revision
    }
    pub const fn released_updated_at(&self) -> TimestampMillis {
        self.released_updated_at
    }
    pub const fn session(&self) -> ExpiredActivityRecoverySessionEvidence {
        self.session
    }
    pub const fn expectation(&self) -> &ExpiredActivityRecoveryExpectation {
        &self.expectation
    }
    pub const fn predecessor_after(&self) -> &RegisteredActivity {
        &self.predecessor_after
    }
    pub const fn successor(&self) -> &RegisteredActivity {
        &self.successor
    }
    pub const fn relation(&self) -> ActivitySuccessor {
        self.relation
    }
    pub fn agents(&self) -> &[ExpiredActivityRecoveryAgentSnapshot] {
        &self.agents
    }
    pub const fn coordinator_digest(&self) -> [u8; DIGEST_BYTES] {
        self.coordinator_digest
    }
    pub const fn relation_digest(&self) -> [u8; DIGEST_BYTES] {
        self.relation_digest
    }
    pub const fn receipt_digest(&self) -> [u8; DIGEST_BYTES] {
        self.receipt_digest
    }
    pub const fn probe_scope(&self) -> &ExpiredActivityRecoveryProbeScope {
        &self.probe_scope
    }
}

#[derive(Debug, Error)]
pub enum ExpiredActivityRecoveryStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("expired Activity recovery request is invalid: {0}")]
    Invalid(&'static str),
    #[error("expired Activity recovery request conflicts with durable state: {0}")]
    Conflict(&'static str),
    #[error("expired Activity recovery receipt is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("expired Activity recovery schema is damaged: {0}")]
    Schema(String),
    #[error("expired Activity recovery clock observation failed")]
    Clock(#[source] Box<dyn Error + Send + Sync>),
    #[error("expired Activity recovery commit requires exact readback")]
    CommitUnconfirmed(#[source] rusqlite::Error),
    #[error("expired Activity recovery rollback requires exact readback")]
    RollbackUnconfirmed {
        source: Box<ExpiredActivityRecoveryStoreError>,
        rollback: rusqlite::Error,
    },
    #[error(transparent)]
    Validation(#[from] ExpiredActivityRecoveryValidationError),
    #[error(transparent)]
    Recovery(#[from] crate::RecoveryStoreError),
    #[error(transparent)]
    Agent(#[from] crate::AgentStoreError),
    #[error(transparent)]
    Coordinator(#[from] crate::CoordinatorStoreError),
    #[error(transparent)]
    Delegation(#[from] crate::AgentOperationsDelegationError),
    #[error(transparent)]
    Successor(#[from] crate::ActivitySuccessorStoreError),
    #[error("expired Activity recovery binding disposition validation failed")]
    BindingDisposition(
        #[source] Box<crate::workspace_agent_binding_rejections::AgentBindingRejectionStoreError>,
    ),
    #[error("expired Activity recovery activation validation failed")]
    BindingActivation(#[source] Box<crate::AgentBindingActivationError>),
    #[error("expired Activity recovery delegated Workspace persistence failure")]
    Workspace(#[source] Box<WorkspaceStoreError>),
}

impl From<WorkspaceStoreError> for ExpiredActivityRecoveryStoreError {
    fn from(error: WorkspaceStoreError) -> Self {
        Self::Workspace(Box::new(error))
    }
}

impl WorkspaceStore {
    /// Read-only exact probe. It never claims, releases, or otherwise writes
    /// the Workspace recovery-maintenance lease.
    pub fn probe_expired_activity_recovery(
        &self,
        binding: &WorkspaceJournalBinding,
        probe_scope: &ExpiredActivityRecoveryProbeScope,
        predecessor_activity_id: ActivityId,
        observed_at: TimestampMillis,
    ) -> Result<ExpiredActivityRecoveryProbe, WorkspaceStoreError> {
        if self.journal_binding()? != *binding
            || probe_scope.workspace_id() != binding.workspace_id()
            || probe_scope.workspace_revision() != binding.workspace_revision()
            || probe_scope.location_id() != binding.location_id()
        {
            return Err(ExpiredActivityRecoveryStoreError::Conflict("binding scope").into());
        }
        if binding.recovery_history_digest() != *probe_scope.binding_digest() {
            return Err(ExpiredActivityRecoveryStoreError::Conflict("root/binding fence").into());
        }
        let transaction = self.connection.unchecked_transaction()?;
        let result = probe_in_transaction(
            &transaction,
            binding,
            probe_scope,
            predecessor_activity_id,
            observed_at,
        );
        match result {
            Ok(probe) => {
                transaction.commit()?;
                Ok(probe)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error.into())
            }
        }
    }

    pub fn expired_activity_recovery_for_request(
        &self,
        binding: &WorkspaceJournalBinding,
        request_id: Uuid,
        request_digest: [u8; DIGEST_BYTES],
    ) -> Result<Option<ExpiredActivityRecoveryReceipt>, WorkspaceStoreError> {
        Ok(self
            .expired_activity_recovery_readback_for_request(binding, request_id, request_digest)?
            .map(|readback| readback.receipt().clone()))
    }

    pub fn expired_activity_recovery_readback_for_request(
        &self,
        binding: &WorkspaceJournalBinding,
        request_id: Uuid,
        request_digest: [u8; DIGEST_BYTES],
    ) -> Result<Option<ExpiredActivityRecoveryReadback>, WorkspaceStoreError> {
        if self.journal_binding()? != *binding {
            return Err(ExpiredActivityRecoveryStoreError::Conflict("binding").into());
        }
        if request_id.is_nil() || request_digest == [0; DIGEST_BYTES] {
            return Err(ExpiredActivityRecoveryStoreError::Invalid("readback selector").into());
        }
        let transaction = self.connection.unchecked_transaction()?;
        let Some(receipt) = load_receipt(&transaction, request_id)? else {
            let child_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM expired_activity_recovery_agents WHERE request_id = ?1",
                params![request_id.as_bytes()],
                |row| row.get(0),
            )?;
            if child_count != 0 {
                return Err(
                    ExpiredActivityRecoveryStoreError::Corrupt("orphan child snapshots").into(),
                );
            }
            transaction.commit()?;
            return Ok(None);
        };
        if receipt.request_digest() != request_digest {
            return Err(ExpiredActivityRecoveryStoreError::Conflict("request digest").into());
        }
        validate_receipt(&transaction, &receipt)?;
        let predecessor_raw = super::query_activity_row(
            &transaction,
            receipt.expectation().predecessor().activity_id(),
        )?
        .ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
            "current predecessor missing",
        ))?;
        let successor_raw =
            super::query_activity_row(&transaction, receipt.expectation().successor_activity_id())?
                .ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
                    "current successor missing",
                ))?;
        let current_predecessor = super::decode_activity(&predecessor_raw)?;
        let current_successor = super::decode_activity(&successor_raw)?;
        let relation = crate::workspace_activity_successors::get_by_predecessor(
            &transaction,
            receipt.expectation().predecessor().activity_id(),
        )?
        .ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
            "current relation missing",
        ))?;
        if relation != receipt.relation {
            return Err(
                ExpiredActivityRecoveryStoreError::Corrupt("current relation changed").into(),
            );
        }
        transaction.commit()?;
        Ok(Some(ExpiredActivityRecoveryReadback {
            receipt,
            current_predecessor,
            current_successor,
            relation,
        }))
    }

    pub fn run_expired_activity_recovery_with_clock<F>(
        &mut self,
        binding: &WorkspaceJournalBinding,
        request: &ExpiredActivityRecoveryStoreRequest,
        clock: F,
    ) -> Result<ExpiredActivityRecoveryOperation, WorkspaceStoreError>
    where
        F: FnOnce() -> Result<TimestampMillis, WorkspaceStoreError>,
    {
        request.validate()?;
        if self.journal_binding()? != *binding {
            return Err(ExpiredActivityRecoveryStoreError::Conflict("binding").into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = run_in_transaction(&transaction, binding, request, clock);
        match result {
            Ok(outcome) => {
                transaction.commit().map_err(|source| {
                    WorkspaceStoreError::ExpiredActivityRecovery(
                        ExpiredActivityRecoveryStoreError::CommitUnconfirmed(source),
                    )
                })?;
                Ok(outcome)
            }
            Err(error) => match transaction.rollback() {
                Ok(()) => Err(error.into()),
                Err(rollback) => Err(WorkspaceStoreError::ExpiredActivityRecovery(
                    ExpiredActivityRecoveryStoreError::RollbackUnconfirmed {
                        source: Box::new(error),
                        rollback,
                    },
                )),
            },
        }
    }
}

fn probe_in_transaction(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    scope: &ExpiredActivityRecoveryProbeScope,
    predecessor_activity_id: ActivityId,
    observed_at: TimestampMillis,
) -> Result<ExpiredActivityRecoveryProbe, ExpiredActivityRecoveryStoreError> {
    let workspace_raw = super::query_workspace_row(transaction)?.ok_or(
        ExpiredActivityRecoveryStoreError::Conflict("Workspace missing"),
    )?;
    let workspace = super::decode_workspace(workspace_raw)?;
    if workspace.id() != scope.workspace_id()
        || workspace.revision() != scope.workspace_revision()
        || workspace.location_id() != scope.location_id()
        || workspace.root_fingerprint() != scope.root_fingerprint()
        || binding.recovery_history_digest() != *scope.binding_digest()
    {
        return Err(ExpiredActivityRecoveryStoreError::Conflict("scope fence"));
    }
    let delegation = load_delegation_fence(transaction, scope.workspace_id())?;
    let raw = super::query_activity_row(transaction, predecessor_activity_id)?.ok_or(
        ExpiredActivityRecoveryStoreError::Conflict("predecessor missing"),
    )?;
    let predecessor = super::decode_activity(&raw)?;
    if predecessor.workspace_id() != scope.workspace_id() {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "predecessor Workspace",
        ));
    }
    let Some(owner) = predecessor.lease_owner_id() else {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "predecessor unleased",
        ));
    };
    let Some(until) = predecessor.lease_until() else {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "predecessor unleased",
        ));
    };
    if predecessor.state() != ActivityState::Open {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "predecessor terminal",
        ));
    }
    let expected = ExpectedExpiredActivity::new(
        predecessor.id(),
        predecessor.revision(),
        predecessor.created_at(),
        predecessor.updated_at(),
        owner,
        until,
        predecessor.lease_revision(),
    )?;
    let agents = crate::workspace_agents::list_for_activity_in_transaction(
        transaction,
        scope.workspace_id(),
        predecessor_activity_id,
        MAX_AGENT_ROWS,
    )?;
    if agents.is_empty() || agents.len() > forge_domain::MAX_AGENT_LIST_RESULTS as usize {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "Agent census bounds",
        ));
    }
    let snapshots = agents
        .iter()
        .map(ExpiredActivityRecoveryAgentSnapshot::from_agent)
        .collect::<Vec<_>>();
    let agent_digest = agents_digest(&snapshots);
    let coordinator =
        crate::workspace_coordinators::get_in_transaction(transaction, predecessor_activity_id)?
            .map(|binding| {
                ExpectedActivityCoordinator::new(
                    binding.agent_id(),
                    binding.revision().get(),
                    binding.updated_at(),
                )
            })
            .transpose()?;
    let blocker = first_blocker(transaction, scope.workspace_id(), predecessor_activity_id)?;
    let delegation_digest = delegation.1;
    let probe_digest = probe_digest(
        scope,
        delegation.0,
        delegation_digest,
        expected,
        snapshots.as_slice(),
        coordinator,
        observed_at,
        blocker,
    );
    Ok(ExpiredActivityRecoveryProbe::from_parts(
        scope.clone(),
        delegation.0,
        delegation_digest,
        expected,
        u16::try_from(snapshots.len())
            .map_err(|_| ExpiredActivityRecoveryStoreError::Conflict("Agent census overflow"))?,
        agent_digest,
        coordinator,
        observed_at,
        probe_digest,
        until.get() <= observed_at.get(),
        blocker,
    )?)
}

fn run_in_transaction<F>(
    transaction: &Transaction<'_>,
    binding: &WorkspaceJournalBinding,
    request: &ExpiredActivityRecoveryStoreRequest,
    clock: F,
) -> Result<ExpiredActivityRecoveryOperation, ExpiredActivityRecoveryStoreError>
where
    F: FnOnce() -> Result<TimestampMillis, WorkspaceStoreError>,
{
    if let Some(existing) = load_receipt(transaction, request.request_id)? {
        if existing.request_digest() != request.request_digest {
            return Err(ExpiredActivityRecoveryStoreError::Conflict(
                "request digest",
            ));
        }
        validate_receipt(transaction, &existing)?;
        return Ok(ExpiredActivityRecoveryOperation::Replay(existing));
    }
    let recovered_at =
        clock().map_err(|error| ExpiredActivityRecoveryStoreError::Clock(Box::new(error)))?;
    let claim = ClaimRecoveryLease::new(
        request.probe_scope.workspace_id(),
        request.owner_id,
        request.duration,
        recovered_at,
    )
    .map_err(|_| ExpiredActivityRecoveryStoreError::Invalid("recovery duration"))?;
    let claimed = crate::workspace_recovery::claim(transaction, &claim)?;
    if matches!(
        claimed.status(),
        crate::RecoveryLeaseClaimStatus::AlreadyOwned
    ) {
        return Ok(ExpiredActivityRecoveryOperation::ClaimConflict(
            claimed.lease().clone(),
        ));
    }
    if matches!(
        claimed.status(),
        crate::RecoveryLeaseClaimStatus::Busy | crate::RecoveryLeaseClaimStatus::ClaimConflict
    ) {
        return Ok(match claimed.status() {
            crate::RecoveryLeaseClaimStatus::Busy => {
                ExpiredActivityRecoveryOperation::Busy(claimed.lease().clone())
            }
            crate::RecoveryLeaseClaimStatus::ClaimConflict
            | crate::RecoveryLeaseClaimStatus::AlreadyOwned => {
                ExpiredActivityRecoveryOperation::ClaimConflict(claimed.lease().clone())
            }
            crate::RecoveryLeaseClaimStatus::Acquired => unreachable!(),
        });
    }
    let claimed_lease = claimed.lease().clone();
    super::recovery_maintenance::validate_binding_and_lease(
        transaction,
        binding,
        &claimed_lease,
        recovered_at,
    )?;
    let (delegation, delegation_digest) =
        load_delegation_fence(transaction, request.probe_scope.workspace_id())?;
    if delegation != request.delegation
        || delegation_digest != request.delegation_digest
        || delegation.destination_id() != request.service_destination_id
    {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "delegation fence",
        ));
    }
    let predecessor_raw =
        super::query_activity_row(transaction, request.expectation.predecessor().activity_id())?
            .ok_or(ExpiredActivityRecoveryStoreError::Conflict(
                "predecessor missing",
            ))?;
    let predecessor = super::decode_activity(&predecessor_raw)?;
    let expected = request.expectation.predecessor();
    if predecessor.workspace_id() != request.probe_scope.workspace_id()
        || predecessor.state() != ActivityState::Open
        || predecessor.id() != expected.activity_id()
        || predecessor.revision() != expected.revision()
        || predecessor.created_at() != expected.created_at()
        || predecessor.updated_at() != expected.updated_at()
        || predecessor.lease_owner_id() != Some(expected.lease_owner_id())
        || predecessor.lease_until() != Some(expected.lease_until())
        || predecessor.lease_revision() != expected.lease_revision()
        || expected.lease_until().get() > recovered_at.get()
    {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "predecessor fence",
        ));
    }
    if super::query_activity_row(transaction, request.expectation.successor_activity_id())?
        .is_some()
    {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "successor collision",
        ));
    }
    if crate::workspace_activity_successors::get_by_predecessor(
        transaction,
        expected.activity_id(),
    )?
    .is_some()
    {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "predecessor relation",
        ));
    }
    let agents = crate::workspace_agents::list_for_activity_in_transaction(
        transaction,
        request.probe_scope.workspace_id(),
        expected.activity_id(),
        MAX_AGENT_ROWS,
    )?;
    let snapshots = agents
        .iter()
        .map(ExpiredActivityRecoveryAgentSnapshot::from_agent)
        .collect::<Vec<_>>();
    if snapshots.len() != usize::from(request.expectation.expected_agent_count())
        || agents_digest(&snapshots) != *request.expectation.expected_agent_digest()
    {
        return Err(ExpiredActivityRecoveryStoreError::Conflict("Agent census"));
    }
    let initiating_attached = snapshots.iter().any(|agent| {
        agent.attachment_state() == AgentAttachmentState::Attached
            && agent.session_id() == Some(request.expectation.initiating_session_id())
            && agent.principal() == request.expectation.principal()
    });
    if !initiating_attached {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "initiating Session binding",
        ));
    }
    if snapshots.iter().any(|agent| {
        agent.attachment_state() == AgentAttachmentState::Attached && agent.session_id().is_none()
    }) {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "unbound attached Agent",
        ));
    }
    let coordinator_binding =
        crate::workspace_coordinators::get_in_transaction(transaction, expected.activity_id())?;
    let expected_coordinator = request.expectation.expected_coordinator();
    let observed_coordinator = coordinator_binding
        .map(|binding| {
            ExpectedActivityCoordinator::new(
                binding.agent_id(),
                binding.revision().get(),
                binding.updated_at(),
            )
        })
        .transpose()?;
    if observed_coordinator != expected_coordinator {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "Coordinator fence",
        ));
    }
    if let Some(coordinator) = observed_coordinator {
        if !snapshots
            .iter()
            .any(|agent| agent.agent_id() == coordinator.agent_id())
        {
            return Err(ExpiredActivityRecoveryStoreError::Conflict(
                "Coordinator Agent",
            ));
        }
    }
    let blocker = first_blocker(
        transaction,
        request.probe_scope.workspace_id(),
        expected.activity_id(),
    )?;
    if blocker.is_some() {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "recovery blocker",
        ));
    }
    if probe_digest(
        &request.probe_scope,
        request.delegation,
        request.delegation_digest,
        expected,
        snapshots.as_slice(),
        observed_coordinator,
        request.probe_observed_at,
        None,
    ) != request.probe_digest
    {
        return Err(ExpiredActivityRecoveryStoreError::Conflict("probe digest"));
    }
    let next_revision = expected
        .revision()
        .checked_next()
        .map_err(|_| ExpiredActivityRecoveryStoreError::Invalid("predecessor revision overflow"))?;
    let next_lease_revision = expected.lease_revision().checked_next().map_err(|_| {
        ExpiredActivityRecoveryStoreError::Invalid("predecessor lease revision overflow")
    })?;
    let changed = transaction.execute(
        "UPDATE activities SET state = ?1, updated_at_ms = ?2, revision = ?3,
                lease_owner_id = NULL, lease_until_ms = NULL, lease_revision = ?4
         WHERE activity_id = ?5 AND workspace_id = ?6 AND state = ?7
           AND revision = ?8 AND created_at_ms = ?9 AND updated_at_ms = ?10
           AND lease_owner_id = ?11 AND lease_until_ms = ?12 AND lease_revision = ?13",
        params![
            super::encode_activity_state(ActivityState::Interrupted),
            recovered_at.get(),
            next_revision.get(),
            next_lease_revision.get(),
            expected.activity_id().into_uuid().as_bytes(),
            request.probe_scope.workspace_id().into_uuid().as_bytes(),
            super::encode_activity_state(ActivityState::Open),
            expected.revision().get(),
            expected.created_at().get(),
            expected.updated_at().get(),
            expected.lease_owner_id().into_uuid().as_bytes(),
            expected.lease_until().get(),
            expected.lease_revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "predecessor CAS",
        ));
    }
    let predecessor_after = super::decode_activity(
        &super::query_activity_row(transaction, expected.activity_id())?.ok_or(
            ExpiredActivityRecoveryStoreError::Corrupt("predecessor after missing"),
        )?,
    )?;
    let successor_lease_until = request
        .duration
        .checked_lease_until(recovered_at)
        .map_err(|_| ExpiredActivityRecoveryStoreError::Invalid("successor lease overflow"))?;
    transaction.execute(
        "INSERT INTO activities (activity_id, workspace_id, state, created_at_ms,
             updated_at_ms, revision, lease_owner_id, lease_until_ms, lease_revision)
         VALUES (?1, ?2, ?3, ?4, ?4, 1, ?5, ?6, 1)",
        params![
            request
                .expectation
                .successor_activity_id()
                .into_uuid()
                .as_bytes(),
            request.probe_scope.workspace_id().into_uuid().as_bytes(),
            super::encode_activity_state(ActivityState::Open),
            recovered_at.get(),
            request.owner_id.into_uuid().as_bytes(),
            successor_lease_until.get(),
        ],
    )?;
    let successor = super::decode_activity(
        &super::query_activity_row(transaction, request.expectation.successor_activity_id())?
            .ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
                "successor missing",
            ))?,
    )?;
    let relation = ActivitySuccessor::from_parts(
        request.probe_scope.workspace_id(),
        expected.activity_id(),
        predecessor_after.revision(),
        successor.id(),
        request.expectation.initiating_session_id(),
        request.owner_id,
        recovered_at,
    )
    .map_err(|_| ExpiredActivityRecoveryStoreError::Invalid("successor relation"))?;
    crate::workspace_activity_successors::insert_in_transaction(transaction, relation)?;
    let release = ReleaseRecoveryLease::new(
        request.probe_scope.workspace_id(),
        request.owner_id,
        claimed_lease.epoch(),
        claimed_lease.revision(),
        recovered_at,
    );
    let released = crate::workspace_recovery::release(transaction, &release)?;
    let coordinator_digest = coordinator_digest(observed_coordinator);
    let receipt = ExpiredActivityRecoveryReceipt::new(
        request,
        recovered_at,
        &claimed_lease,
        &released,
        predecessor_after,
        successor,
        relation,
        snapshots,
        coordinator_digest,
    )?;
    insert_receipt(transaction, &receipt)?;
    let persisted = load_receipt(transaction, request.request_id)?.ok_or(
        ExpiredActivityRecoveryStoreError::Corrupt("receipt insert readback"),
    )?;
    if persisted != receipt {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "receipt insert projection",
        ));
    }
    let released_check =
        crate::workspace_recovery::get(transaction, request.probe_scope.workspace_id())?;
    if released_check != released
        || released_check.owner_id().is_some()
        || released_check.epoch() != claimed_lease.epoch()
        || released_check.revision()
            != claimed_lease.revision().checked_next().map_err(|_| {
                ExpiredActivityRecoveryStoreError::Invalid("recovery lease revision overflow")
            })?
    {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "released recovery lease projection",
        ));
    }
    let (delegation_check, delegation_digest_check) =
        load_delegation_fence(transaction, request.probe_scope.workspace_id())?;
    if delegation_check != request.delegation
        || delegation_digest_check != request.delegation_digest
    {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "delegation proof projection",
        ));
    }
    validate_receipt(transaction, &persisted)?;
    Ok(ExpiredActivityRecoveryOperation::Recorded(receipt))
}

pub(crate) fn load_delegation_fence(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<
    (ExpiredActivityRecoveryDelegationFence, [u8; DIGEST_BYTES]),
    ExpiredActivityRecoveryStoreError,
> {
    let delegation = crate::workspace_agent_delegation::get(connection, workspace_id)?.ok_or(
        ExpiredActivityRecoveryStoreError::Conflict("delegation missing"),
    )?;
    let freeze = delegation.freeze();
    if freeze.state() != crate::AgentOperationsFreezeState::Frozen {
        return Err(ExpiredActivityRecoveryStoreError::Conflict(
            "delegation released",
        ));
    }
    let fence = ExpiredActivityRecoveryDelegationFence::new(
        delegation.migration_id(),
        delegation.workspace_id(),
        delegation.destination_id(),
        ExpiredActivityRecoveryFreezeState::Frozen,
        freeze.revision(),
        freeze.created_at(),
        freeze.updated_at(),
        delegation.manifest_digest(),
        delegation.delegated_at(),
    )?;
    let authority = forge_domain::WorkspaceRootRecoveryDelegatedAuthority::new(
        forge_domain::WorkspaceRootRecoveryFreezeFence {
            migration_id: freeze.migration_id(),
            workspace_id: freeze.workspace_id(),
            destination_id: freeze.destination_id(),
            state: forge_domain::WorkspaceRootRecoveryFreezeState::Frozen,
            revision: freeze.revision(),
            created_at: freeze.created_at(),
            updated_at: freeze.updated_at(),
        },
        forge_domain::WorkspaceRootRecoveryDelegationFence {
            migration_id: delegation.migration_id(),
            workspace_id: delegation.workspace_id(),
            destination_id: delegation.destination_id(),
            freeze_revision: freeze.revision(),
            manifest_digest: delegation.manifest_digest(),
            delegated_at: delegation.delegated_at(),
        },
    )
    .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("delegation authority"))?;
    Ok((
        fence,
        crate::workspace_store::delegated_authority_digest(authority),
    ))
}

pub(crate) fn agents_digest(agents: &[ExpiredActivityRecoveryAgentSnapshot]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(AGENTS_DOMAIN);
    hash_u64(&mut hasher, agents.len() as u64);
    for agent in agents {
        hash_uuid(&mut hasher, agent.agent_id().into_uuid());
        hash_uuid(&mut hasher, agent.workspace_id().into_uuid());
        hash_uuid(&mut hasher, agent.activity_id().into_uuid());
        hash_optional_uuid(&mut hasher, agent.session_id().map(|id| id.into_uuid()));
        hash_text(&mut hasher, agent.display_name().as_str());
        hash_text(&mut hasher, agent.declared_role().as_str());
        hash_u8(&mut hasher, encode_transport(agent.transport_kind()));
        hash_principal(&mut hasher, agent.principal());
        hash_u8(&mut hasher, encode_attachment(agent.attachment_state()));
        hash_optional_uuid(&mut hasher, agent.focus_goal_id().map(|id| id.into_uuid()));
        hash_optional_i64(
            &mut hasher,
            agent.focus_goal_revision().map(|revision| revision.get()),
        );
        hash_optional_i64(
            &mut hasher,
            agent.focus_dag_revision().map(|revision| revision.get()),
        );
        hash_optional_uuid(&mut hasher, agent.focus_node_id().map(|id| id.into_uuid()));
        hash_optional_i64(
            &mut hasher,
            agent.focus_node_revision().map(|revision| revision.get()),
        );
        hash_i64(&mut hasher, agent.created_at().get());
        hash_i64(&mut hasher, agent.updated_at().get());
        hash_i64(&mut hasher, agent.revision().get());
    }
    hasher.finalize().into()
}

pub(crate) fn coordinator_digest(value: Option<ExpectedActivityCoordinator>) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(COORDINATOR_DOMAIN);
    match value {
        Some(value) => {
            hash_u8(&mut hasher, 1);
            hash_uuid(&mut hasher, value.agent_id().into_uuid());
            hash_i64(&mut hasher, value.revision());
            hash_i64(&mut hasher, value.updated_at().get());
        }
        None => hash_u8(&mut hasher, 0),
    }
    hasher.finalize().into()
}

fn probe_digest(
    scope: &ExpiredActivityRecoveryProbeScope,
    delegation: ExpiredActivityRecoveryDelegationFence,
    delegation_digest: [u8; DIGEST_BYTES],
    predecessor: ExpectedExpiredActivity,
    agents: &[ExpiredActivityRecoveryAgentSnapshot],
    coordinator: Option<ExpectedActivityCoordinator>,
    observed_at: TimestampMillis,
    blocker: Option<ExpiredActivityRecoveryBlocker>,
) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(PROBE_DOMAIN);
    hash_uuid(&mut hasher, scope.workspace_id().into_uuid());
    hash_i64(&mut hasher, scope.workspace_revision().get());
    hash_uuid(&mut hasher, scope.location_id().into_uuid());
    hash_i64(&mut hasher, scope.location_revision().get());
    hash_bytes(&mut hasher, scope.locator());
    hasher.update(scope.root_fingerprint().as_bytes());
    hasher.update(scope.binding_digest());
    hash_delegation(&mut hasher, delegation);
    hasher.update(delegation_digest);
    hash_expected_activity(&mut hasher, predecessor);
    hasher.update(agents_digest(agents));
    hash_optional_coordinator(&mut hasher, coordinator);
    hash_u8(&mut hasher, encode_blocker(blocker));
    hash_i64(&mut hasher, observed_at.get());
    hasher.finalize().into()
}

fn relation_digest(relation: &ActivitySuccessor) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(RELATION_DOMAIN);
    hash_uuid(&mut hasher, relation.workspace_id().into_uuid());
    hash_uuid(&mut hasher, relation.predecessor_activity_id().into_uuid());
    hash_i64(&mut hasher, relation.predecessor_activity_revision().get());
    hash_uuid(&mut hasher, relation.successor_activity_id().into_uuid());
    hash_uuid(&mut hasher, relation.initiating_session_id().into_uuid());
    hash_uuid(&mut hasher, relation.runtime_instance_id().into_uuid());
    hash_i64(&mut hasher, relation.created_at().get());
    hasher.finalize().into()
}

fn receipt_digest(receipt: &ExpiredActivityRecoveryReceipt) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_DOMAIN);
    hash_uuid(&mut hasher, receipt.request_id);
    hasher.update(receipt.request_digest);
    hash_uuid(&mut hasher, receipt.probe_scope.workspace_id().into_uuid());
    hash_i64(&mut hasher, receipt.probe_scope.workspace_revision().get());
    hash_uuid(&mut hasher, receipt.probe_scope.location_id().into_uuid());
    hash_i64(&mut hasher, receipt.probe_scope.location_revision().get());
    hash_bytes(&mut hasher, receipt.probe_scope.locator());
    hasher.update(receipt.probe_scope.root_fingerprint().as_bytes());
    hasher.update(receipt.probe_scope.binding_digest());
    hash_i64(&mut hasher, receipt.probe_observed_at.get());
    hasher.update(receipt.probe_digest);
    hash_delegation(&mut hasher, receipt.delegation);
    hasher.update(receipt.delegation_digest);
    hash_uuid(&mut hasher, receipt.service_backend_id.into_uuid());
    hash_uuid(&mut hasher, receipt.service_issuer.into_uuid());
    hash_uuid(&mut hasher, receipt.service_destination_id);
    hash_uuid(&mut hasher, receipt.owner_id.into_uuid());
    hash_i64(&mut hasher, receipt.duration.get());
    hash_i64(&mut hasher, receipt.recovered_at.get());
    hash_i64(&mut hasher, receipt.claimed_lease_until.get());
    hash_i64(&mut hasher, receipt.claimed_epoch);
    hash_i64(&mut hasher, receipt.claimed_revision);
    hash_i64(&mut hasher, receipt.released_epoch);
    hash_i64(&mut hasher, receipt.released_revision);
    hash_i64(&mut hasher, receipt.released_updated_at.get());
    hash_uuid(&mut hasher, receipt.session.session_id().into_uuid());
    hash_principal(&mut hasher, receipt.session.principal());
    hash_i64(&mut hasher, receipt.session.session_revision());
    hash_i64(&mut hasher, receipt.session.session_updated_at().get());
    hash_expected_activity(&mut hasher, receipt.expectation.predecessor());
    hash_uuid(
        &mut hasher,
        receipt.expectation.successor_activity_id().into_uuid(),
    );
    hash_uuid(
        &mut hasher,
        receipt.expectation.initiating_session_id().into_uuid(),
    );
    hash_principal(&mut hasher, receipt.expectation.principal());
    hash_u64(
        &mut hasher,
        u64::from(receipt.expectation.expected_agent_count()),
    );
    hasher.update(receipt.expectation.expected_agent_digest());
    hash_optional_coordinator(&mut hasher, receipt.expectation.expected_coordinator());
    hash_activity(&mut hasher, &receipt.predecessor_after);
    hash_activity(&mut hasher, &receipt.successor);
    hasher.update(receipt.coordinator_digest);
    hasher.update(receipt.relation_digest);
    hasher.update(receipt.agents_digest());
    hasher.finalize().into()
}

impl ExpiredActivityRecoveryReceipt {
    fn agents_digest(&self) -> [u8; DIGEST_BYTES] {
        agents_digest(&self.agents)
    }
}

fn hash_activity(hasher: &mut Sha256, activity: &RegisteredActivity) {
    hash_uuid(hasher, activity.id().into_uuid());
    hash_uuid(hasher, activity.workspace_id().into_uuid());
    hash_u8(
        hasher,
        match activity.state() {
            ActivityState::Open => 1,
            ActivityState::Closed => 0,
            ActivityState::Interrupted => 2,
        },
    );
    hash_i64(hasher, activity.created_at().get());
    hash_i64(hasher, activity.updated_at().get());
    hash_i64(hasher, activity.revision().get());
    hash_optional_uuid(hasher, activity.lease_owner_id().map(|id| id.into_uuid()));
    hash_optional_i64(hasher, activity.lease_until().map(|value| value.get()));
    hash_i64(hasher, activity.lease_revision().get());
}

fn hash_expected_activity(hasher: &mut Sha256, activity: ExpectedExpiredActivity) {
    hash_uuid(hasher, activity.activity_id().into_uuid());
    hash_i64(hasher, activity.revision().get());
    hash_i64(hasher, activity.created_at().get());
    hash_i64(hasher, activity.updated_at().get());
    hash_uuid(hasher, activity.lease_owner_id().into_uuid());
    hash_i64(hasher, activity.lease_until().get());
    hash_i64(hasher, activity.lease_revision().get());
}

fn hash_delegation(hasher: &mut Sha256, delegation: ExpiredActivityRecoveryDelegationFence) {
    hash_uuid(hasher, delegation.migration_id());
    hash_uuid(hasher, delegation.workspace_id().into_uuid());
    hash_uuid(hasher, delegation.destination_id());
    hash_u8(hasher, 0);
    hash_u64(hasher, delegation.revision());
    hash_i64(hasher, delegation.created_at().get());
    hash_i64(hasher, delegation.updated_at().get());
    hasher.update(delegation.manifest_digest());
    hash_i64(hasher, delegation.delegated_at().get());
}

fn hash_optional_coordinator(
    hasher: &mut Sha256,
    coordinator: Option<ExpectedActivityCoordinator>,
) {
    match coordinator {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_uuid(hasher, value.agent_id().into_uuid());
            hash_i64(hasher, value.revision());
            hash_i64(hasher, value.updated_at().get());
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_principal(hasher: &mut Sha256, principal: AuthenticatedPrincipal) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => hash_u8(hasher, 0),
        AuthenticatedPrincipal::DirectToken(id) => {
            hash_u8(hasher, 1);
            hash_uuid(hasher, id.into_uuid());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            hash_u8(hasher, 2);
            hash_uuid(hasher, id.into_uuid());
        }
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}
fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value);
}
fn hash_uuid(hasher: &mut Sha256, value: Uuid) {
    hasher.update(value.as_bytes());
}
fn hash_optional_uuid(hasher: &mut Sha256, value: Option<Uuid>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_uuid(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}
fn hash_optional_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_i64(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}
fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_le_bytes());
}
fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
fn hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn encode_transport(value: forge_domain::AgentTransportKind) -> u8 {
    match value {
        forge_domain::AgentTransportKind::Retired => 0,
        forge_domain::AgentTransportKind::Stdio => 1,
        forge_domain::AgentTransportKind::StreamableHttp => 2,
        forge_domain::AgentTransportKind::Other => 3,
    }
}
fn encode_attachment(value: AgentAttachmentState) -> u8 {
    match value {
        AgentAttachmentState::Attached => 0,
        AgentAttachmentState::Detached => 1,
    }
}
fn encode_blocker(value: Option<ExpiredActivityRecoveryBlocker>) -> u8 {
    value.map_or(255, |value| match value {
        ExpiredActivityRecoveryBlocker::PendingWorkspaceStop => 0,
        ExpiredActivityRecoveryBlocker::ActiveWorkCut => 1,
        ExpiredActivityRecoveryBlocker::PendingBindingActivation => 2,
        ExpiredActivityRecoveryBlocker::PendingGoalDeletion => 3,
        ExpiredActivityRecoveryBlocker::NonterminalGoal => 4,
        ExpiredActivityRecoveryBlocker::NonterminalCurrentDagNode => 5,
        ExpiredActivityRecoveryBlocker::ActiveExecution => 6,
        ExpiredActivityRecoveryBlocker::ActiveWriterLease => 7,
        ExpiredActivityRecoveryBlocker::StartingCheckpoint => 8,
        ExpiredActivityRecoveryBlocker::UnsettledCheckpointRestore => 9,
        ExpiredActivityRecoveryBlocker::StartingChangeSet => 10,
        ExpiredActivityRecoveryBlocker::PendingDiffEvidence => 11,
        ExpiredActivityRecoveryBlocker::StartingVerification => 12,
        ExpiredActivityRecoveryBlocker::PendingApproval => 13,
        ExpiredActivityRecoveryBlocker::ActiveExecutionGrant => 14,
        ExpiredActivityRecoveryBlocker::ActiveAutoApprovalScope => 15,
        ExpiredActivityRecoveryBlocker::NonterminalAssignment => 16,
    })
}

pub(crate) fn first_blocker(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<Option<ExpiredActivityRecoveryBlocker>, ExpiredActivityRecoveryStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut dispositions = connection.prepare(
        "SELECT r.request_id, a.request_id, j.request_id
         FROM agent_binding_reservations r
         LEFT JOIN agent_binding_activations a ON a.request_id = r.request_id
         LEFT JOIN agent_binding_rejections j ON j.request_id = r.request_id
         WHERE r.workspace_id = ?1 AND r.activity_id = ?2
         ORDER BY r.request_id",
    )?;
    let mut rows = dispositions.query(params![workspace.as_slice(), activity.as_slice()])?;
    while let Some(row) = rows.next()? {
        let request_id = Uuid::from_slice(row.get::<_, Vec<u8>>(0)?.as_slice())
            .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("binding request id"))?;
        let activation_present = row.get::<_, Option<Vec<u8>>>(1)?.is_some();
        let rejection_present = row.get::<_, Option<Vec<u8>>>(2)?.is_some();
        if activation_present && rejection_present {
            return Err(ExpiredActivityRecoveryStoreError::Corrupt(
                "activation and rejection both exist",
            ));
        }
        if activation_present {
            if crate::workspace_agent_binding_activation::get(connection, request_id)
                .map_err(|error| {
                    ExpiredActivityRecoveryStoreError::BindingActivation(Box::new(error))
                })?
                .is_none()
            {
                return Err(ExpiredActivityRecoveryStoreError::Corrupt(
                    "activation readback",
                ));
            }
            continue;
        }
        if rejection_present
            && crate::workspace_agent_binding_rejections::is_valid_settlement(
                connection, request_id,
            )
            .map_err(|error| {
                ExpiredActivityRecoveryStoreError::BindingDisposition(Box::new(error))
            })?
        {
            continue;
        }
        return Ok(Some(
            ExpiredActivityRecoveryBlocker::PendingBindingActivation,
        ));
    }
    let checks: [(&str, ExpiredActivityRecoveryBlocker); 16] = [
        (
            "SELECT EXISTS(SELECT 1 FROM workspace_execution_stop_fences WHERE workspace_id = ?1 AND length(?2) = 16)",
            ExpiredActivityRecoveryBlocker::PendingWorkspaceStop,
        ),
        (
            "SELECT EXISTS(
                 SELECT 1 FROM leadership_work_cuts c
                 JOIN leadership_work_cut_agents a ON a.cut_id = c.cut_id
                 WHERE c.workspace_id = ?1 AND c.state = 0 AND a.activity_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM leadership_work_cuts c
                 JOIN leadership_work_cut_nodes n ON n.cut_id = c.cut_id
                 WHERE c.workspace_id = ?1 AND c.state = 0 AND n.activity_id = ?2
             ) OR EXISTS(
                 SELECT 1 FROM leadership_work_cuts c
                 JOIN leadership_work_cut_team_nodes t ON t.cut_id = c.cut_id
                 WHERE c.workspace_id = ?1 AND c.state = 0 AND t.activity_id = ?2
             )",
            ExpiredActivityRecoveryBlocker::ActiveWorkCut,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM goal_deletion_cleanup_journal WHERE workspace_id = ?1 AND activity_id = ?2)",
            ExpiredActivityRecoveryBlocker::PendingGoalDeletion,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM goals WHERE workspace_id = ?1 AND activity_id = ?2 AND state IN (0, 1, 2))",
            ExpiredActivityRecoveryBlocker::NonterminalGoal,
        ),
        (
            "SELECT EXISTS(
                 SELECT 1 FROM goals g
                 JOIN goal_dag_heads h ON h.goal_id = g.goal_id
                 JOIN goal_dag_nodes n ON n.goal_id = h.goal_id AND n.dag_revision = h.dag_revision
                 WHERE g.workspace_id = ?1 AND g.activity_id = ?2 AND n.lifecycle_state IN (0, 1, 2)
             )",
            ExpiredActivityRecoveryBlocker::NonterminalCurrentDagNode,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM executions WHERE workspace_id = ?1 AND activity_id = ?2 AND state IN (0, 1))",
            ExpiredActivityRecoveryBlocker::ActiveExecution,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM writer_leases WHERE workspace_id = ?1 AND activity_id = ?2 AND state = 0)",
            ExpiredActivityRecoveryBlocker::ActiveWriterLease,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE workspace_id = ?1 AND activity_id = ?2 AND state = 0)",
            ExpiredActivityRecoveryBlocker::StartingCheckpoint,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM checkpoint_restores WHERE workspace_id = ?1 AND activity_id = ?2 AND state IN (0, 3))",
            ExpiredActivityRecoveryBlocker::UnsettledCheckpointRestore,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM change_sets WHERE workspace_id = ?1 AND activity_id = ?2 AND state = 0)",
            ExpiredActivityRecoveryBlocker::StartingChangeSet,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM diff_evidence WHERE workspace_id = ?1 AND activity_id = ?2 AND state IN (0, 4))",
            ExpiredActivityRecoveryBlocker::PendingDiffEvidence,
        ),
        (
            "SELECT EXISTS(
                 SELECT 1 FROM verification_runs vr
                 JOIN executions e ON e.execution_id = vr.execution_id
                 WHERE e.workspace_id = ?1 AND e.activity_id = ?2 AND vr.state = 0
             )",
            ExpiredActivityRecoveryBlocker::StartingVerification,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM approval_requests WHERE workspace_id = ?1 AND activity_id = ?2 AND state = 0)",
            ExpiredActivityRecoveryBlocker::PendingApproval,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM execution_grants WHERE workspace_id = ?1 AND activity_id = ?2 AND state = 0)",
            ExpiredActivityRecoveryBlocker::ActiveExecutionGrant,
        ),
        (
            "SELECT EXISTS(
                 SELECT 1 FROM auto_approval_scopes
                 WHERE workspace_id = ?1 AND state = 0 AND (activity_id IS NULL OR activity_id = ?2)
             )",
            ExpiredActivityRecoveryBlocker::ActiveAutoApprovalScope,
        ),
        (
            "SELECT EXISTS(SELECT 1 FROM agent_assignments WHERE workspace_id = ?1 AND activity_id = ?2 AND state IN (0, 1, 2))",
            ExpiredActivityRecoveryBlocker::NonterminalAssignment,
        ),
    ];
    for (sql, blocker) in checks {
        let active: bool = connection.query_row(
            sql,
            params![workspace.as_slice(), activity.as_slice()],
            |row| row.get(0),
        )?;
        if active {
            return Ok(Some(blocker));
        }
    }
    Ok(None)
}

/// Bounded physical fences shared by expired-Activity recovery and started
/// lease resume. Logical Goal, DAG, and Assignment blockers are intentionally
/// excluded here; callers capture those histories in their own census.
pub(crate) struct StartedActivityPhysicalBlockers {
    pub pending_count: u64,
    pub unknown_count: u64,
    pub row_count: u32,
    pub digest: [u8; 32],
    pub truncated: bool,
}

const STARTED_PHYSICAL_PREDICATES: [(&str, &str); 13] = [
    (
        "workspace_stop",
        "SELECT * FROM workspace_execution_stop_fences WHERE workspace_id=?1 AND length(?2)=16 LIMIT ?3",
    ),
    (
        "active_work_cuts",
        "SELECT c.* FROM leadership_work_cuts c JOIN leadership_work_cut_agents a ON a.cut_id=c.cut_id WHERE c.workspace_id=?1 AND c.state=0 AND a.activity_id=?2 UNION ALL SELECT c.* FROM leadership_work_cuts c JOIN leadership_work_cut_nodes n ON n.cut_id=c.cut_id WHERE c.workspace_id=?1 AND c.state=0 AND n.activity_id=?2 UNION ALL SELECT c.* FROM leadership_work_cuts c JOIN leadership_work_cut_team_nodes t ON t.cut_id=c.cut_id WHERE c.workspace_id=?1 AND c.state=0 AND t.activity_id=?2 LIMIT ?3",
    ),
    (
        "goal_deletion",
        "SELECT * FROM goal_deletion_cleanup_journal WHERE workspace_id=?1 AND activity_id=?2 LIMIT ?3",
    ),
    (
        "executions",
        "SELECT * FROM executions WHERE workspace_id=?1 AND activity_id=?2 AND state IN (0,1) LIMIT ?3",
    ),
    (
        "writer_leases",
        "SELECT * FROM writer_leases WHERE workspace_id=?1 AND activity_id=?2 AND state=0 LIMIT ?3",
    ),
    (
        "checkpoints",
        "SELECT * FROM checkpoints WHERE workspace_id=?1 AND activity_id=?2 AND state=0 LIMIT ?3",
    ),
    (
        "checkpoint_restores",
        "SELECT * FROM checkpoint_restores WHERE workspace_id=?1 AND activity_id=?2 AND state IN (0,3) LIMIT ?3",
    ),
    (
        "change_sets",
        "SELECT * FROM change_sets WHERE workspace_id=?1 AND activity_id=?2 AND state=0 LIMIT ?3",
    ),
    (
        "diff_evidence",
        "SELECT * FROM diff_evidence WHERE workspace_id=?1 AND activity_id=?2 AND state IN (0,4) LIMIT ?3",
    ),
    (
        "verification_runs",
        "SELECT vr.* FROM verification_runs vr JOIN executions e ON e.execution_id=vr.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2 AND vr.state=0 LIMIT ?3",
    ),
    (
        "approval_requests",
        "SELECT * FROM approval_requests WHERE workspace_id=?1 AND activity_id=?2 AND state=0 LIMIT ?3",
    ),
    (
        "execution_grants",
        "SELECT * FROM execution_grants WHERE workspace_id=?1 AND activity_id=?2 AND state=0 LIMIT ?3",
    ),
    (
        "auto_approval_scopes",
        "SELECT * FROM auto_approval_scopes WHERE workspace_id=?1 AND state=0 AND (activity_id IS NULL OR activity_id=?2) LIMIT ?3",
    ),
];

const STARTED_UNKNOWN_STATUS_QUERIES: [(&str, &str); 2] = [
    (
        "execution_unknown",
        "SELECT * FROM executions WHERE workspace_id=?1 AND activity_id=?2 AND state NOT IN (0,1,2,3,4,5,6) LIMIT ?3",
    ),
    (
        "writer_lease_unknown",
        "SELECT * FROM writer_leases WHERE workspace_id=?1 AND activity_id=?2 AND state NOT IN (0,1) LIMIT ?3",
    ),
];

const STARTED_PHYSICAL_HISTORY_QUERIES: [(&str, &str); 18] = [
    (
        "workspace_stop_history",
        "SELECT * FROM workspace_execution_stop_fences WHERE workspace_id=?1 ORDER BY rowid LIMIT ?3",
    ),
    (
        "work_cut_history",
        "SELECT DISTINCT c.* FROM leadership_work_cuts c WHERE c.workspace_id=?1 AND (EXISTS(SELECT 1 FROM leadership_work_cut_agents a WHERE a.cut_id=c.cut_id AND a.activity_id=?2) OR EXISTS(SELECT 1 FROM leadership_work_cut_nodes n WHERE n.cut_id=c.cut_id AND n.activity_id=?2) OR EXISTS(SELECT 1 FROM leadership_work_cut_team_nodes t WHERE t.cut_id=c.cut_id AND t.activity_id=?2)) ORDER BY c.cut_id LIMIT ?3",
    ),
    (
        "work_cut_agents",
        "SELECT a.* FROM leadership_work_cut_agents a JOIN leadership_work_cuts c ON c.cut_id=a.cut_id WHERE c.workspace_id=?1 AND a.activity_id=?2 ORDER BY c.cut_id,a.agent_id LIMIT ?3",
    ),
    (
        "work_cut_nodes",
        "SELECT n.* FROM leadership_work_cut_nodes n JOIN leadership_work_cuts c ON c.cut_id=n.cut_id WHERE c.workspace_id=?1 AND n.activity_id=?2 ORDER BY c.cut_id,n.goal_id,n.node_id LIMIT ?3",
    ),
    (
        "work_cut_team_nodes",
        "SELECT t.* FROM leadership_work_cut_team_nodes t JOIN leadership_work_cuts c ON c.cut_id=t.cut_id WHERE c.workspace_id=?1 AND t.activity_id=?2 ORDER BY c.cut_id,t.goal_id,t.node_id LIMIT ?3",
    ),
    (
        "goal_deletion_history",
        "SELECT * FROM goal_deletion_cleanup_journal WHERE workspace_id=?1 AND activity_id=?2 ORDER BY rowid LIMIT ?3",
    ),
    (
        "binding_reservations",
        "SELECT * FROM agent_binding_reservations WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id LIMIT ?3",
    ),
    (
        "binding_activations",
        "SELECT a.* FROM agent_binding_activations a JOIN agent_binding_reservations r ON r.request_id=a.request_id WHERE r.workspace_id=?1 AND r.activity_id=?2 ORDER BY a.request_id LIMIT ?3",
    ),
    (
        "binding_rejections",
        "SELECT * FROM agent_binding_rejections WHERE workspace_id=?1 AND activity_id=?2 ORDER BY request_id LIMIT ?3",
    ),
    (
        "checkpoint_history",
        "SELECT * FROM checkpoints WHERE workspace_id=?1 AND activity_id=?2 ORDER BY checkpoint_id LIMIT ?3",
    ),
    (
        "checkpoint_restore_history",
        "SELECT * FROM checkpoint_restores WHERE workspace_id=?1 AND activity_id=?2 ORDER BY restore_id LIMIT ?3",
    ),
    (
        "diff_history",
        "SELECT * FROM diff_evidence WHERE workspace_id=?1 AND activity_id=?2 ORDER BY diff_id LIMIT ?3",
    ),
    (
        "verification_history",
        "SELECT vr.* FROM verification_runs vr JOIN executions e ON e.execution_id=vr.execution_id WHERE e.workspace_id=?1 AND e.activity_id=?2 ORDER BY vr.execution_id LIMIT ?3",
    ),
    (
        "approval_history",
        "SELECT * FROM approval_requests WHERE workspace_id=?1 AND activity_id=?2 ORDER BY approval_id LIMIT ?3",
    ),
    (
        "execution_grant_history",
        "SELECT * FROM execution_grants WHERE workspace_id=?1 AND activity_id=?2 ORDER BY grant_id LIMIT ?3",
    ),
    (
        "auto_approval_history",
        "SELECT * FROM auto_approval_scopes WHERE workspace_id=?1 AND (activity_id IS NULL OR activity_id=?2) ORDER BY scope_id LIMIT ?3",
    ),
    (
        "execution_history",
        "SELECT * FROM executions WHERE workspace_id=?1 AND activity_id=?2 ORDER BY execution_id LIMIT ?3",
    ),
    (
        "writer_lease_history",
        "SELECT * FROM writer_leases WHERE workspace_id=?1 AND activity_id=?2 ORDER BY lease_id LIMIT ?3",
    ),
];

const STARTED_AGENT_OUTBOX_QUERIES: [(&str, &str); 4] = [
    (
        "agent_outbox_entries",
        "SELECT o.* FROM agent_effect_outbox_entries o WHERE o.workspace_id=?1 AND (EXISTS(SELECT 1 FROM agent_effect_outbox_focus f WHERE f.outbox_sequence=o.sequence AND f.activity_id=?2) OR EXISTS(SELECT 1 FROM agent_effect_outbox_transitions t WHERE t.outbox_sequence=o.sequence AND t.activity_id=?2)) ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "agent_outbox_focus",
        "SELECT f.* FROM agent_effect_outbox_focus f JOIN agent_effect_outbox_entries o ON o.sequence=f.outbox_sequence WHERE o.workspace_id=?1 AND f.activity_id=?2 ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "agent_outbox_transitions",
        "SELECT t.* FROM agent_effect_outbox_transitions t JOIN agent_effect_outbox_entries o ON o.sequence=t.outbox_sequence WHERE o.workspace_id=?1 AND t.activity_id=?2 ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "agent_outbox_recipients",
        "SELECT r.* FROM agent_effect_outbox_recipients r JOIN agent_effect_outbox_entries o ON o.sequence=r.outbox_sequence WHERE o.workspace_id=?1 AND (EXISTS(SELECT 1 FROM agent_effect_outbox_focus f WHERE f.outbox_sequence=o.sequence AND f.activity_id=?2) OR EXISTS(SELECT 1 FROM agent_effect_outbox_transitions t WHERE t.outbox_sequence=o.sequence AND t.activity_id=?2)) ORDER BY r.outbox_sequence,r.hint_index LIMIT ?3",
    ),
];

const STARTED_EFFECT_OUTBOX_QUERIES: [(&str, &str); 7] = [
    (
        "effect_outbox_entries",
        "SELECT o.* FROM effect_fact_outbox_entries o WHERE o.workspace_id=?1 AND (EXISTS(SELECT 1 FROM effect_fact_outbox_execution_terminal f WHERE f.outbox_sequence=o.sequence AND f.activity_id=?2) OR EXISTS(SELECT 1 FROM effect_fact_outbox_change_set f WHERE f.outbox_sequence=o.sequence AND f.activity_id=?2) OR EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_review f WHERE f.outbox_sequence=o.sequence AND f.activity_id=?2) OR EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_offered f WHERE f.outbox_sequence=o.sequence AND f.activity_id=?2) OR EXISTS(SELECT 1 FROM effect_fact_outbox_assignment_submitted f WHERE f.outbox_sequence=o.sequence AND f.activity_id=?2)) ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "effect_outbox_execution",
        "SELECT f.* FROM effect_fact_outbox_execution_terminal f JOIN effect_fact_outbox_entries o ON o.sequence=f.outbox_sequence WHERE o.workspace_id=?1 AND f.activity_id=?2 ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "effect_outbox_changeset",
        "SELECT f.* FROM effect_fact_outbox_change_set f JOIN effect_fact_outbox_entries o ON o.sequence=f.outbox_sequence WHERE o.workspace_id=?1 AND f.activity_id=?2 ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "effect_outbox_review",
        "SELECT f.* FROM effect_fact_outbox_assignment_review f JOIN effect_fact_outbox_entries o ON o.sequence=f.outbox_sequence WHERE o.workspace_id=?1 AND f.activity_id=?2 ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "effect_outbox_offer",
        "SELECT f.* FROM effect_fact_outbox_assignment_offered f JOIN effect_fact_outbox_entries o ON o.sequence=f.outbox_sequence WHERE o.workspace_id=?1 AND f.activity_id=?2 ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "effect_outbox_submitted",
        "SELECT f.* FROM effect_fact_outbox_assignment_submitted f JOIN effect_fact_outbox_entries o ON o.sequence=f.outbox_sequence WHERE o.workspace_id=?1 AND f.activity_id=?2 ORDER BY o.sequence LIMIT ?3",
    ),
    (
        "effect_outbox_submitted_sources",
        "SELECT r.* FROM effect_fact_outbox_assignment_submitted_source_ref r JOIN effect_fact_outbox_assignment_submitted f ON f.outbox_sequence=r.outbox_sequence JOIN effect_fact_outbox_entries o ON o.sequence=f.outbox_sequence WHERE o.workspace_id=?1 AND f.activity_id=?2 ORDER BY r.outbox_sequence,r.ordinal LIMIT ?3",
    ),
];

const STARTED_UNKNOWN_OUTBOX_QUERIES: [(&str, &str); 2] = [
    (
        "agent_outbox_unknown",
        "SELECT o.* FROM agent_effect_outbox_entries o LEFT JOIN agent_effect_outbox_focus f ON f.outbox_sequence=o.sequence LEFT JOIN agent_effect_outbox_transitions t ON t.outbox_sequence=o.sequence WHERE o.workspace_id=?1 AND (o.fact_kind NOT IN (0,1) OR (o.fact_kind=0 AND (f.outbox_sequence IS NULL OR t.outbox_sequence IS NOT NULL)) OR (o.fact_kind=1 AND (t.outbox_sequence IS NULL OR f.outbox_sequence IS NOT NULL))) LIMIT ?3",
    ),
    (
        "effect_outbox_unknown",
        "SELECT o.* FROM effect_fact_outbox_entries o LEFT JOIN effect_fact_outbox_execution_terminal x ON x.outbox_sequence=o.sequence LEFT JOIN effect_fact_outbox_change_set c ON c.outbox_sequence=o.sequence LEFT JOIN effect_fact_outbox_assignment_review r ON r.outbox_sequence=o.sequence LEFT JOIN effect_fact_outbox_assignment_offered f ON f.outbox_sequence=o.sequence LEFT JOIN effect_fact_outbox_assignment_submitted s ON s.outbox_sequence=o.sequence WHERE o.workspace_id=?1 AND ((o.fact_kind=0 AND (x.outbox_sequence IS NULL OR c.outbox_sequence IS NOT NULL OR r.outbox_sequence IS NOT NULL OR f.outbox_sequence IS NOT NULL OR s.outbox_sequence IS NOT NULL)) OR (o.fact_kind=1 AND (c.outbox_sequence IS NULL OR x.outbox_sequence IS NOT NULL OR r.outbox_sequence IS NOT NULL OR f.outbox_sequence IS NOT NULL OR s.outbox_sequence IS NOT NULL)) OR (o.fact_kind=2 AND (r.outbox_sequence IS NULL OR x.outbox_sequence IS NOT NULL OR c.outbox_sequence IS NOT NULL OR f.outbox_sequence IS NOT NULL OR s.outbox_sequence IS NOT NULL)) OR (o.fact_kind=3 AND (f.outbox_sequence IS NULL OR x.outbox_sequence IS NOT NULL OR c.outbox_sequence IS NOT NULL OR r.outbox_sequence IS NOT NULL OR s.outbox_sequence IS NOT NULL)) OR (o.fact_kind=4 AND (s.outbox_sequence IS NULL OR x.outbox_sequence IS NOT NULL OR c.outbox_sequence IS NOT NULL OR r.outbox_sequence IS NOT NULL OR f.outbox_sequence IS NOT NULL)) OR o.fact_kind NOT IN (0,1,2,3,4)) LIMIT ?3",
    ),
];

pub(crate) fn started_activity_physical_blockers(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    maximum: u32,
) -> Result<StartedActivityPhysicalBlockers, ExpiredActivityRecoveryStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let limit = i64::from(maximum).saturating_add(1);
    let mut pending_count = 0_u64;
    let mut unknown_count = 0_u64;
    let mut truncated = false;
    let mut row_count = 0_u64;
    let mut hasher = Sha256::new();
    hasher.update(b"forge.started_activity_lease_resume.physical_blockers.v1");
    for (name, sql) in STARTED_PHYSICAL_PREDICATES {
        hasher.update(name.as_bytes());
        let (count, was_truncated) = hash_bounded_rows(
            connection,
            sql,
            params![workspace.as_slice(), activity.as_slice(), limit],
            maximum as usize,
            &mut hasher,
        )?;
        row_count = row_count.saturating_add(u64::from(count));
        truncated |= was_truncated;
        pending_count = pending_count.saturating_add(u64::from(count));
    }

    for (name, sql) in STARTED_PHYSICAL_HISTORY_QUERIES {
        hasher.update(name.as_bytes());
        let (count, was_truncated) = hash_bounded_rows(
            connection,
            sql,
            params![workspace.as_slice(), activity.as_slice(), limit],
            maximum as usize,
            &mut hasher,
        )?;
        row_count = row_count.saturating_add(u64::from(count));
        truncated |= was_truncated;
    }

    for (name, sql) in STARTED_UNKNOWN_STATUS_QUERIES {
        hasher.update(name.as_bytes());
        let (count, was_truncated) = hash_bounded_rows(
            connection,
            sql,
            params![workspace.as_slice(), activity.as_slice(), limit],
            maximum as usize,
            &mut hasher,
        )?;
        unknown_count = unknown_count.saturating_add(u64::from(count));
        row_count = row_count.saturating_add(u64::from(count));
        truncated |= was_truncated;
    }

    let disposition_sql = "SELECT r.request_id, a.request_id, j.request_id
         FROM agent_binding_reservations r
         LEFT JOIN agent_binding_activations a ON a.request_id=r.request_id
         LEFT JOIN agent_binding_rejections j ON j.request_id=r.request_id
         WHERE r.workspace_id=?1 AND r.activity_id=?2
         ORDER BY r.request_id LIMIT ?3";
    hasher.update(b"binding_dispositions");
    let (reservation_count, reservation_truncated) = hash_bounded_rows(
        connection,
        disposition_sql,
        params![workspace.as_slice(), activity.as_slice(), limit],
        maximum as usize,
        &mut hasher,
    )?;
    truncated |= reservation_truncated;
    row_count = row_count.saturating_add(u64::from(reservation_count));
    let mut dispositions = connection.prepare(disposition_sql)?;
    let mut rows = dispositions.query(params![workspace.as_slice(), activity.as_slice(), limit])?;
    let mut reservation_pending_count = 0_u64;
    while let Some(row) = rows.next()? {
        let request_id = Uuid::from_slice(row.get::<_, Vec<u8>>(0)?.as_slice())
            .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("binding request id"))?;
        let activated = row.get::<_, Option<Vec<u8>>>(1)?.is_some();
        let rejected = row.get::<_, Option<Vec<u8>>>(2)?.is_some();
        if activated && rejected {
            return Err(ExpiredActivityRecoveryStoreError::Corrupt(
                "activation and rejection both exist",
            ));
        }
        let settled_rejection = rejected
            && crate::workspace_agent_binding_rejections::is_valid_settlement(
                connection, request_id,
            )
            .map_err(|error| {
                ExpiredActivityRecoveryStoreError::BindingDisposition(Box::new(error))
            })?;
        if activated {
            if crate::workspace_agent_binding_activation::get(connection, request_id)
                .map_err(|error| {
                    ExpiredActivityRecoveryStoreError::BindingActivation(Box::new(error))
                })?
                .is_none()
            {
                unknown_count = unknown_count.saturating_add(1);
            }
        } else if !settled_rejection {
            reservation_pending_count = reservation_pending_count.saturating_add(1);
        }
    }
    pending_count = pending_count.saturating_add(reservation_pending_count);

    for (name, sql) in STARTED_AGENT_OUTBOX_QUERIES
        .into_iter()
        .chain(STARTED_EFFECT_OUTBOX_QUERIES)
    {
        hasher.update(name.as_bytes());
        let (count, was_truncated) = hash_bounded_rows(
            connection,
            sql,
            params![workspace.as_slice(), activity.as_slice(), limit],
            maximum as usize,
            &mut hasher,
        )?;
        row_count = row_count.saturating_add(u64::from(count));
        truncated |= was_truncated;
    }
    for (name, sql) in STARTED_UNKNOWN_OUTBOX_QUERIES {
        hasher.update(name.as_bytes());
        let (count, was_truncated) = hash_bounded_rows(
            connection,
            sql,
            params![workspace.as_slice(), activity.as_slice(), limit],
            maximum as usize,
            &mut hasher,
        )?;
        unknown_count = unknown_count.saturating_add(u64::from(count));
        row_count = row_count.saturating_add(u64::from(count));
        truncated |= was_truncated;
    }
    let row_count = u32::try_from(row_count.min(u64::from(maximum)))
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("physical row count"))?;
    Ok(StartedActivityPhysicalBlockers {
        pending_count,
        unknown_count,
        row_count,
        digest: hasher.finalize().into(),
        truncated,
    })
}

fn hash_bounded_rows<P: Params>(
    connection: &Connection,
    sql: &str,
    params: P,
    maximum: usize,
    hasher: &mut Sha256,
) -> Result<(u32, bool), ExpiredActivityRecoveryStoreError> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(params)?;
    let mut count = 0_usize;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > maximum + 1 {
            return Err(ExpiredActivityRecoveryStoreError::Corrupt(
                "physical census query exceeded its bound",
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
    Ok((
        u32::try_from(count.min(maximum)).unwrap_or(u32::MAX),
        count > maximum,
    ))
}

fn principal_parts(principal: AuthenticatedPrincipal) -> (i64, Option<[u8; 16]>) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().into_bytes())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().into_bytes())),
    }
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    receipt: &ExpiredActivityRecoveryReceipt,
) -> Result<(), ExpiredActivityRecoveryStoreError> {
    let predecessor = receipt.expectation.predecessor();
    let (principal_kind, principal_id) = principal_parts(receipt.session.principal());
    let (delegation_state, delegation_revision) = (0_i64, receipt.delegation.revision() as i64);
    let coordinator = receipt.expectation.expected_coordinator();
    transaction.execute(
        "INSERT INTO expired_activity_recovery_receipts (
            request_id, workspace_id, location_id, location_revision, locator_relative_root,
            workspace_revision, request_digest, binding_digest, workspace_root_fingerprint,
            probe_observed_at_ms, probe_digest, delegation_migration_id, delegation_workspace_id,
            delegation_destination_id, delegation_freeze_state, delegation_freeze_revision,
            delegation_freeze_created_at_ms, delegation_freeze_updated_at_ms,
            delegation_manifest_digest, delegation_delegated_at_ms, delegation_digest,
            service_backend_id, service_issuer_id, service_destination_id, owner_runtime_instance_id,
            duration_ms, recovered_at_ms, claimed_lease_until_ms, claimed_epoch, claimed_revision,
            released_epoch, released_revision, released_updated_at_ms, initiating_session_id,
            initiating_principal_kind, initiating_principal_id, session_revision, session_updated_at_ms,
            predecessor_activity_id, predecessor_before_state, predecessor_before_revision,
            predecessor_before_created_at_ms, predecessor_before_updated_at_ms,
            predecessor_before_lease_owner_id, predecessor_before_lease_until_ms,
            predecessor_before_lease_revision, predecessor_after_state, predecessor_after_revision,
            predecessor_after_updated_at_ms, predecessor_after_lease_revision, successor_activity_id,
            successor_state, successor_owner_id, successor_lease_until_ms, successor_revision,
            successor_lease_revision, successor_created_at_ms, successor_updated_at_ms, agent_count,
            agent_digest, coordinator_present, coordinator_agent_id, coordinator_revision,
            coordinator_updated_at_ms, coordinator_digest, relation_digest, receipt_digest
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
            ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33,
            ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48, ?49,
            ?50, ?51, ?52, ?53, ?54, ?55, ?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63, ?64, ?65,
            ?66, ?67)",
        params![
            receipt.request_id.as_bytes(),
            receipt.probe_scope.workspace_id().into_uuid().as_bytes(),
            receipt.probe_scope.location_id().into_uuid().as_bytes(),
            receipt.probe_scope.location_revision().get(),
            receipt.probe_scope.locator(),
            receipt.probe_scope.workspace_revision().get(),
            receipt.request_digest,
            receipt.probe_scope.binding_digest(),
            receipt.probe_scope.root_fingerprint().as_bytes(),
            receipt.probe_observed_at.get(),
            receipt.probe_digest,
            receipt.delegation.migration_id().as_bytes(),
            receipt.delegation.workspace_id().into_uuid().as_bytes(),
            receipt.delegation.destination_id().as_bytes(),
            delegation_state,
            delegation_revision,
            receipt.delegation.created_at().get(),
            receipt.delegation.updated_at().get(),
            receipt.delegation.manifest_digest(),
            receipt.delegation.delegated_at().get(),
            receipt.delegation_digest,
            receipt.service_backend_id.into_uuid().as_bytes(),
            receipt.service_issuer.into_uuid().as_bytes(),
            receipt.service_destination_id.as_bytes(),
            receipt.owner_id.into_uuid().as_bytes(),
            receipt.duration.get(),
            receipt.recovered_at.get(),
            receipt.claimed_lease_until.get(),
            receipt.claimed_epoch,
            receipt.claimed_revision,
            receipt.released_epoch,
            receipt.released_revision,
            receipt.released_updated_at.get(),
            receipt.session.session_id().into_uuid().as_bytes(),
            principal_kind,
            principal_id.as_ref().map(|id| id.as_slice()),
            receipt.session.session_revision(),
            receipt.session.session_updated_at().get(),
            predecessor.activity_id().into_uuid().as_bytes(),
            1_i64,
            predecessor.revision().get(),
            predecessor.created_at().get(),
            predecessor.updated_at().get(),
            predecessor.lease_owner_id().into_uuid().as_bytes(),
            predecessor.lease_until().get(),
            predecessor.lease_revision().get(),
            2_i64,
            receipt.predecessor_after.revision().get(),
            receipt.predecessor_after.updated_at().get(),
            receipt.predecessor_after.lease_revision().get(),
            receipt.successor.id().into_uuid().as_bytes(),
            1_i64,
            receipt.owner_id.into_uuid().as_bytes(),
            receipt.successor.lease_until().unwrap_or(receipt.claimed_lease_until).get(),
            receipt.successor.revision().get(),
            receipt.successor.lease_revision().get(),
            receipt.successor.created_at().get(),
            receipt.successor.updated_at().get(),
            receipt.agents.len() as i64,
            receipt.agents_digest(),
            i64::from(coordinator.is_some()),
            coordinator.map(|value| value.agent_id().into_uuid().into_bytes()),
            coordinator.map(|value| value.revision()),
            coordinator.map(|value| value.updated_at().get()),
            receipt.coordinator_digest,
            receipt.relation_digest,
            receipt.receipt_digest,
        ],
    )?;
    for (ordinal, agent) in receipt.agents.iter().enumerate() {
        let (principal_kind, principal_id) = principal_parts(agent.principal());
        let focus_goal_id = agent.focus_goal_id().map(|id| id.into_uuid().into_bytes());
        let focus_node_id = agent.focus_node_id().map(|id| id.into_uuid().into_bytes());
        transaction.execute(
            "INSERT INTO expired_activity_recovery_agents (
                request_id, ordinal, agent_id, workspace_id, activity_id, session_id,
                display_name, declared_role, transport_kind, principal_kind, principal_id,
                attachment_state, focus_goal_id, focus_goal_revision, focus_dag_revision,
                focus_node_id, focus_node_revision, created_at_ms, updated_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                receipt.request_id.as_bytes(),
                ordinal as i64,
                agent.agent_id().into_uuid().as_bytes(),
                agent.workspace_id().into_uuid().as_bytes(),
                agent.activity_id().into_uuid().as_bytes(),
                agent.session_id().map(|id| id.into_uuid().into_bytes()),
                agent.display_name().as_str(),
                agent.declared_role().as_str(),
                encode_transport(agent.transport_kind()),
                principal_kind,
                principal_id.as_ref().map(|id| id.as_slice()),
                encode_attachment(agent.attachment_state()),
                focus_goal_id.as_ref().map(|id| id.as_slice()),
                agent.focus_goal_revision().map(|value| value.get()),
                agent.focus_dag_revision().map(|value| value.get()),
                focus_node_id.as_ref().map(|id| id.as_slice()),
                agent.focus_node_revision().map(|value| value.get()),
                agent.created_at().get(),
                agent.updated_at().get(),
                agent.revision().get(),
            ],
        )?;
    }
    Ok(())
}

pub(super) fn load_receipt(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<ExpiredActivityRecoveryReceipt>, ExpiredActivityRecoveryStoreError> {
    let mut statement = connection
        .prepare("SELECT * FROM expired_activity_recovery_receipts WHERE request_id = ?1")?;
    let mut rows = statement.query(params![request_id.as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };

    let request_id = decode_uuid(row.get::<_, Vec<u8>>(0)?, "receipt.request_id")?;
    let workspace_id =
        forge_domain::WorkspaceId::from_uuid(decode_uuid(row.get(1)?, "receipt.workspace_id")?);
    let location_id =
        forge_domain::LocationId::from_uuid(decode_uuid(row.get(2)?, "receipt.location_id")?);
    let location_revision = forge_domain::LocationRevision::new(row.get(3)?)
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("receipt.location_revision"))?;
    let locator: Vec<u8> = row.get(4)?;
    let workspace_revision = forge_domain::WorkspaceRevision::new(row.get(5)?)
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("receipt.workspace_revision"))?;
    let request_digest = decode_digest(row.get(6)?, "receipt.request_digest")?;
    let binding_digest = decode_digest(row.get(7)?, "receipt.binding_digest")?;
    let root_bytes: Vec<u8> = row.get(8)?;
    let root_fingerprint = forge_domain::WorkspaceRootFingerprint::from_bytes(
        root_bytes
            .try_into()
            .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("receipt.root_fingerprint"))?,
    );
    let probe_observed_at = timestamp(row.get(9)?, "receipt.probe_observed_at_ms")?;
    let probe_digest = decode_digest(row.get(10)?, "receipt.probe_digest")?;
    let delegation_migration_id = decode_uuid(row.get(11)?, "receipt.delegation_migration_id")?;
    let delegation_workspace_id = forge_domain::WorkspaceId::from_uuid(decode_uuid(
        row.get(12)?,
        "receipt.delegation_workspace_id",
    )?);
    let delegation_destination_id = decode_uuid(row.get(13)?, "receipt.delegation_destination_id")?;
    let delegation_state = row.get::<_, i64>(14)?;
    let delegation_revision = u64::try_from(row.get::<_, i64>(15)?)
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("receipt.delegation_revision"))?;
    let delegation_created_at = timestamp(row.get(16)?, "receipt.delegation_created_at_ms")?;
    let delegation_updated_at = timestamp(row.get(17)?, "receipt.delegation_updated_at_ms")?;
    let delegation_manifest_digest =
        decode_digest(row.get(18)?, "receipt.delegation_manifest_digest")?;
    let delegation_delegated_at = timestamp(row.get(19)?, "receipt.delegation_delegated_at_ms")?;
    let delegation_digest = decode_digest(row.get(20)?, "receipt.delegation_digest")?;
    let service_backend_id = forge_domain::ForgeBackendId::from_uuid(decode_uuid(
        row.get(21)?,
        "receipt.service_backend_id",
    )?);
    let service_issuer = forge_domain::OrchestrationIssuerId::from_uuid(decode_uuid(
        row.get(22)?,
        "receipt.service_issuer_id",
    )?);
    let service_destination_id = decode_uuid(row.get(23)?, "receipt.service_destination_id")?;
    let owner_id = RuntimeInstanceId::from_uuid(decode_uuid(
        row.get(24)?,
        "receipt.owner_runtime_instance_id",
    )?);
    let duration = RecoveryLeaseDurationMillis::new(row.get(25)?)
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("receipt.duration"))?;
    let recovered_at = timestamp(row.get(26)?, "receipt.recovered_at_ms")?;
    let claimed_lease_until = timestamp(row.get(27)?, "receipt.claimed_lease_until_ms")?;
    let claimed_epoch = row.get(28)?;
    let claimed_revision = row.get(29)?;
    let released_epoch = row.get(30)?;
    let released_revision = row.get(31)?;
    let released_updated_at = timestamp(row.get(32)?, "receipt.released_updated_at_ms")?;
    let initiating_session_id =
        forge_domain::AgentSessionId::from_uuid(decode_uuid(row.get(33)?, "receipt.session_id")?);
    let session_principal = decode_principal(row.get(34)?, row.get(35)?)?;
    let session_revision = row.get(36)?;
    let session_updated_at = timestamp(row.get(37)?, "receipt.session_updated_at_ms")?;
    let predecessor_activity_id = ActivityId::from_uuid(decode_uuid(
        row.get(38)?,
        "receipt.predecessor_activity_id",
    )?);
    let predecessor_before_revision = ActivityRevision::new(row.get(40)?).map_err(|_| {
        ExpiredActivityRecoveryStoreError::Corrupt("receipt.predecessor_before_revision")
    })?;
    let predecessor_before_created_at =
        timestamp(row.get(41)?, "receipt.predecessor_before_created_at_ms")?;
    let predecessor_before_updated_at =
        timestamp(row.get(42)?, "receipt.predecessor_before_updated_at_ms")?;
    let predecessor_before_lease_owner = RuntimeInstanceId::from_uuid(decode_uuid(
        row.get(43)?,
        "receipt.predecessor_before_lease_owner_id",
    )?);
    let predecessor_before_lease_until =
        timestamp(row.get(44)?, "receipt.predecessor_before_lease_until_ms")?;
    let predecessor_before_lease_revision =
        ActivityLeaseRevision::new(row.get(45)?).map_err(|_| {
            ExpiredActivityRecoveryStoreError::Corrupt("receipt.predecessor_before_lease_revision")
        })?;
    let predecessor_after_revision = ActivityRevision::new(row.get(47)?).map_err(|_| {
        ExpiredActivityRecoveryStoreError::Corrupt("receipt.predecessor_after_revision")
    })?;
    let predecessor_after_updated_at =
        timestamp(row.get(48)?, "receipt.predecessor_after_updated_at_ms")?;
    let predecessor_after_lease_revision =
        ActivityLeaseRevision::new(row.get(49)?).map_err(|_| {
            ExpiredActivityRecoveryStoreError::Corrupt("receipt.predecessor_after_lease_revision")
        })?;
    let successor_activity_id =
        ActivityId::from_uuid(decode_uuid(row.get(50)?, "receipt.successor_activity_id")?);
    let successor_owner_id =
        RuntimeInstanceId::from_uuid(decode_uuid(row.get(52)?, "receipt.successor_owner_id")?);
    let successor_lease_until = timestamp(row.get(53)?, "receipt.successor_lease_until_ms")?;
    let successor_revision = ActivityRevision::new(row.get(54)?)
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("receipt.successor_revision"))?;
    let successor_lease_revision = ActivityLeaseRevision::new(row.get(55)?).map_err(|_| {
        ExpiredActivityRecoveryStoreError::Corrupt("receipt.successor_lease_revision")
    })?;
    let successor_created_at = timestamp(row.get(56)?, "receipt.successor_created_at_ms")?;
    let successor_updated_at = timestamp(row.get(57)?, "receipt.successor_updated_at_ms")?;
    let agent_count = u16::try_from(row.get::<_, i64>(58)?)
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("receipt.agent_count"))?;
    let agent_digest = decode_digest(row.get(59)?, "receipt.agent_digest")?;
    let coordinator_present = row.get::<_, i64>(60)? != 0;
    let coordinator_agent_id = row
        .get::<_, Option<Vec<u8>>>(61)?
        .map(|bytes| {
            decode_uuid(bytes, "receipt.coordinator_agent_id").map(AgentInstanceId::from_uuid)
        })
        .transpose()?;
    let coordinator_revision = row.get::<_, Option<i64>>(62)?;
    let coordinator_updated_at = row
        .get::<_, Option<i64>>(63)?
        .map(|value| timestamp(value, "receipt.coordinator_updated_at_ms"))
        .transpose()?;
    let coordinator_digest = decode_digest(row.get(64)?, "receipt.coordinator_digest")?;
    let relation_digest = decode_digest(row.get(65)?, "receipt.relation_digest")?;
    let stored_receipt_digest = decode_digest(row.get(66)?, "receipt.receipt_digest")?;
    if claimed_epoch < 1
        || claimed_revision < 2
        || released_epoch != claimed_epoch
        || released_revision != claimed_revision + 1
    {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "receipt recovery lease fence",
        ));
    }
    if delegation_state != 0
        || !coordinator_present
            && (coordinator_agent_id.is_some()
                || coordinator_revision.is_some()
                || coordinator_updated_at.is_some())
    {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt("receipt shape"));
    }
    let scope = ExpiredActivityRecoveryProbeScope::new(
        workspace_id,
        workspace_revision,
        location_id,
        location_revision,
        locator,
        root_fingerprint,
        binding_digest,
    )?;
    let delegation = ExpiredActivityRecoveryDelegationFence::new(
        delegation_migration_id,
        delegation_workspace_id,
        delegation_destination_id,
        ExpiredActivityRecoveryFreezeState::Frozen,
        delegation_revision,
        delegation_created_at,
        delegation_updated_at,
        delegation_manifest_digest,
        delegation_delegated_at,
    )?;
    let expected = ExpectedExpiredActivity::new(
        predecessor_activity_id,
        predecessor_before_revision,
        predecessor_before_created_at,
        predecessor_before_updated_at,
        predecessor_before_lease_owner,
        predecessor_before_lease_until,
        predecessor_before_lease_revision,
    )?;
    let expected_coordinator = if coordinator_present {
        Some(ExpectedActivityCoordinator::new(
            coordinator_agent_id.ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
                "coordinator agent",
            ))?,
            coordinator_revision.ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
                "coordinator revision",
            ))?,
            coordinator_updated_at.ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
                "coordinator updated",
            ))?,
        )?)
    } else {
        None
    };
    let expectation = ExpiredActivityRecoveryExpectation::new(
        expected,
        successor_activity_id,
        initiating_session_id,
        session_principal,
        agent_count,
        agent_digest,
        expected_coordinator,
    )?;
    let session = ExpiredActivityRecoverySessionEvidence::new(
        initiating_session_id,
        session_principal,
        session_revision,
        session_updated_at,
    )?;
    let predecessor_after = RegisteredActivity::from_parts_with_lease(
        predecessor_activity_id,
        workspace_id,
        ActivityState::Interrupted,
        predecessor_before_created_at,
        predecessor_after_updated_at,
        predecessor_after_revision,
        forge_domain::ActivityLeaseProjection::from_parts(
            None,
            None,
            predecessor_after_lease_revision,
        )
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("predecessor after lease"))?,
    );
    let successor = RegisteredActivity::from_parts_with_lease(
        successor_activity_id,
        workspace_id,
        ActivityState::Open,
        successor_created_at,
        successor_updated_at,
        successor_revision,
        forge_domain::ActivityLeaseProjection::from_parts(
            Some(successor_owner_id),
            Some(successor_lease_until),
            successor_lease_revision,
        )
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("successor lease"))?,
    );
    let relation = crate::workspace_activity_successors::get_by_predecessor(
        connection,
        predecessor_activity_id,
    )?
    .ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
        "successor relation missing",
    ))?;
    let agents = load_agent_snapshots(connection, request_id)?;
    if agents.len() != usize::from(agent_count) {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "Agent snapshot count",
        ));
    }
    let receipt = ExpiredActivityRecoveryReceipt {
        request_id,
        request_digest,
        probe_scope: scope,
        probe_observed_at,
        probe_digest,
        delegation,
        delegation_digest,
        service_backend_id,
        service_issuer,
        service_destination_id,
        owner_id,
        duration,
        recovered_at,
        claimed_lease_until,
        claimed_epoch,
        claimed_revision,
        released_epoch,
        released_revision,
        released_updated_at,
        session,
        expectation,
        predecessor_after,
        successor,
        relation,
        agents,
        coordinator_digest,
        relation_digest,
        receipt_digest: stored_receipt_digest,
    };
    Ok(Some(receipt))
}

fn load_agent_snapshots(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Vec<ExpiredActivityRecoveryAgentSnapshot>, ExpiredActivityRecoveryStoreError> {
    let mut statement = connection.prepare(
        "SELECT request_id, ordinal, agent_id, workspace_id, activity_id, session_id,
                display_name, declared_role, transport_kind, principal_kind, principal_id,
                attachment_state, focus_goal_id, focus_goal_revision, focus_dag_revision,
                focus_node_id, focus_node_revision, created_at_ms, updated_at_ms, revision
         FROM expired_activity_recovery_agents
         WHERE request_id = ?1 ORDER BY ordinal ASC",
    )?;
    let mut rows = statement.query(params![request_id.as_bytes()])?;
    let mut snapshots = Vec::new();
    while let Some(row) = rows.next()? {
        let stored_request = decode_uuid(row.get::<_, Vec<u8>>(0)?, "Agent snapshot request")?;
        if stored_request != request_id {
            return Err(ExpiredActivityRecoveryStoreError::Corrupt(
                "Agent snapshot request",
            ));
        }
        let ordinal = row.get::<_, i64>(1)?;
        if ordinal != snapshots.len() as i64 || ordinal >= 256 {
            return Err(ExpiredActivityRecoveryStoreError::Corrupt(
                "Agent snapshot ordinal",
            ));
        }
        let agent_id = AgentInstanceId::from_uuid(decode_uuid(row.get(2)?, "Agent snapshot id")?);
        let workspace_id =
            WorkspaceId::from_uuid(decode_uuid(row.get(3)?, "Agent snapshot Workspace")?);
        let activity_id =
            ActivityId::from_uuid(decode_uuid(row.get(4)?, "Agent snapshot Activity")?);
        let session_id = row
            .get::<_, Option<Vec<u8>>>(5)?
            .map(|bytes| {
                decode_uuid(bytes, "Agent snapshot Session")
                    .map(forge_domain::AgentSessionId::from_uuid)
            })
            .transpose()?;
        let display_name = forge_domain::AgentDisplayName::new(row.get(6)?).map_err(|_| {
            ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot display name")
        })?;
        let declared_role = forge_domain::AgentDeclaredRole::new(row.get(7)?)
            .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot role"))?;
        let transport_kind = decode_transport(row.get(8)?)?;
        let principal = decode_principal(row.get(9)?, row.get(10)?)?;
        let attachment_state = decode_attachment(row.get(11)?)?;
        let focus_goal_id = row
            .get::<_, Option<Vec<u8>>>(12)?
            .map(|bytes| {
                decode_uuid(bytes, "Agent snapshot goal").map(forge_domain::GoalId::from_uuid)
            })
            .transpose()?;
        let focus_goal_revision = row
            .get::<_, Option<i64>>(13)?
            .map(|value| forge_domain::GoalRevision::new(value))
            .transpose()
            .map_err(|_| {
                ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot goal revision")
            })?;
        let focus_dag_revision = row
            .get::<_, Option<i64>>(14)?
            .map(|value| forge_domain::DagRevisionNumber::new(value))
            .transpose()
            .map_err(|_| {
                ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot DAG revision")
            })?;
        let focus_node_id = row
            .get::<_, Option<Vec<u8>>>(15)?
            .map(|bytes| {
                decode_uuid(bytes, "Agent snapshot node").map(forge_domain::DagNodeId::from_uuid)
            })
            .transpose()?;
        let focus_node_revision = row
            .get::<_, Option<i64>>(16)?
            .map(|value| forge_domain::DagNodeRevision::new(value))
            .transpose()
            .map_err(|_| {
                ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot node revision")
            })?;
        let created_at = timestamp(row.get(17)?, "Agent snapshot created")?;
        let updated_at = timestamp(row.get(18)?, "Agent snapshot updated")?;
        let revision = forge_domain::AgentInstanceRevision::new(row.get(19)?)
            .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot revision"))?;
        let focus_goal = focus_goal_id
            .zip(focus_goal_revision)
            .map(|(id, revision)| forge_domain::GoalAttribution::new(id, revision));
        let focus_node = focus_node_id
            .zip(focus_node_revision)
            .map(|(id, revision)| forge_domain::AgentFocusNode::new(id, revision));
        let focus = forge_domain::AgentFocus::new(focus_goal, focus_dag_revision, focus_node)
            .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot focus"))?;
        let agent =
            forge_domain::RegisteredAgentInstance::from_parts(forge_domain::AgentRecordParts {
                id: agent_id,
                workspace_id,
                activity_id,
                session_id,
                display_name,
                declared_role,
                transport_kind,
                principal,
                attachment_state,
                focus,
                created_at,
                updated_at,
                revision,
            })
            .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt("Agent snapshot projection"))?;
        snapshots.push(ExpiredActivityRecoveryAgentSnapshot::from_agent(&agent));
    }
    Ok(snapshots)
}

pub(super) fn validate_receipt(
    connection: &Connection,
    receipt: &ExpiredActivityRecoveryReceipt,
) -> Result<(), ExpiredActivityRecoveryStoreError> {
    let expected = receipt.expectation.predecessor();
    if receipt.session.session_id() != receipt.expectation.initiating_session_id()
        || receipt.session.principal() != receipt.expectation.principal()
        || receipt.predecessor_after.state() != ActivityState::Interrupted
        || receipt.predecessor_after.lease_owner_id().is_some()
        || receipt.predecessor_after.lease_until().is_some()
        || receipt.predecessor_after.revision()
            != expected.revision().checked_next().map_err(|_| {
                ExpiredActivityRecoveryStoreError::Corrupt("predecessor revision proof")
            })?
        || receipt.predecessor_after.lease_revision()
            != expected.lease_revision().checked_next().map_err(|_| {
                ExpiredActivityRecoveryStoreError::Corrupt("predecessor lease revision proof")
            })?
        || receipt.claimed_revision < 2
    {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "immutable predecessor/session proof",
        ));
    }
    if receipt.receipt_digest != receipt_digest(receipt)
        || receipt.relation_digest != relation_digest(&receipt.relation)
        || receipt.agents_digest() != receipt.expectation.expected_agent_digest().to_owned()
    {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt("receipt digest"));
    }
    let relation = crate::workspace_activity_successors::get_by_predecessor(
        connection,
        receipt.expectation.predecessor().activity_id(),
    )?
    .ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
        "relation missing",
    ))?;
    if relation != receipt.relation {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "relation changed",
        ));
    }
    let predecessor_raw =
        super::query_activity_row(connection, receipt.expectation.predecessor().activity_id())?
            .ok_or(ExpiredActivityRecoveryStoreError::Corrupt(
                "predecessor missing",
            ))?;
    let predecessor = super::decode_activity(&predecessor_raw)?;
    let successor_raw =
        super::query_activity_row(connection, receipt.expectation.successor_activity_id())?.ok_or(
            ExpiredActivityRecoveryStoreError::Corrupt("successor missing"),
        )?;
    let successor = super::decode_activity(&successor_raw)?;
    if predecessor.id() != receipt.predecessor_after.id()
        || predecessor.state() == ActivityState::Open
        || successor.id() != receipt.successor.id()
        || successor.workspace_id() != receipt.successor.workspace_id()
    {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "current lineage",
        ));
    }
    let children = load_agent_snapshots(connection, receipt.request_id)?;
    if children != receipt.agents {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "Agent snapshots changed",
        ));
    }
    if !children.iter().any(|agent| {
        agent.attachment_state() == AgentAttachmentState::Attached
            && agent.session_id() == Some(receipt.expectation.initiating_session_id())
            && agent.principal() == receipt.expectation.principal()
    }) {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "initiating Session is not retained in Agent snapshots",
        ));
    }
    Ok(())
}

fn decode_uuid(
    value: Vec<u8>,
    field: &'static str,
) -> Result<Uuid, ExpiredActivityRecoveryStoreError> {
    Uuid::from_slice(&value).map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt(field))
}
fn decode_digest(
    value: Vec<u8>,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], ExpiredActivityRecoveryStoreError> {
    let bytes: [u8; DIGEST_BYTES] = value
        .try_into()
        .map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt(field))?;
    if bytes == [0; DIGEST_BYTES] {
        return Err(ExpiredActivityRecoveryStoreError::Corrupt(field));
    }
    Ok(bytes)
}
fn timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, ExpiredActivityRecoveryStoreError> {
    TimestampMillis::new(value).map_err(|_| ExpiredActivityRecoveryStoreError::Corrupt(field))
}
fn decode_principal(
    kind: i64,
    value: Option<Vec<u8>>,
) -> Result<AuthenticatedPrincipal, ExpiredActivityRecoveryStoreError> {
    match (kind, value) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(value)) => Ok(AuthenticatedPrincipal::DirectToken(
            forge_domain::DirectTokenId::from_uuid(decode_uuid(value, "principal")?),
        )),
        (2, Some(value)) => Ok(AuthenticatedPrincipal::OAuthGrant(
            forge_domain::OAuthGrantId::from_uuid(decode_uuid(value, "principal")?),
        )),
        _ => Err(ExpiredActivityRecoveryStoreError::Corrupt(
            "principal shape",
        )),
    }
}
fn decode_transport(
    value: i64,
) -> Result<forge_domain::AgentTransportKind, ExpiredActivityRecoveryStoreError> {
    match value {
        0 => Ok(forge_domain::AgentTransportKind::Retired),
        1 => Ok(forge_domain::AgentTransportKind::Stdio),
        2 => Ok(forge_domain::AgentTransportKind::StreamableHttp),
        3 => Ok(forge_domain::AgentTransportKind::Other),
        _ => Err(ExpiredActivityRecoveryStoreError::Corrupt("transport")),
    }
}
fn decode_attachment(
    value: i64,
) -> Result<AgentAttachmentState, ExpiredActivityRecoveryStoreError> {
    match value {
        0 => Ok(AgentAttachmentState::Attached),
        1 => Ok(AgentAttachmentState::Detached),
        _ => Err(ExpiredActivityRecoveryStoreError::Corrupt("attachment")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_uuid_hash_is_fixed_width_without_a_length_prefix() {
        let value = Uuid::from_u128(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10);
        let mut actual = Sha256::new();
        hash_uuid(&mut actual, value);
        let expected: [u8; DIGEST_BYTES] = Sha256::digest(value.as_bytes()).into();
        assert_eq!(actual.finalize().as_slice(), expected.as_slice());
    }

    #[test]
    fn probe_and_agent_digests_change_for_observation_blocker_scope_and_agent_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = WorkspaceId::from_uuid(Uuid::from_u128(1));
        let activity = ActivityId::from_uuid(Uuid::from_u128(2));
        let successor = ActivityId::from_uuid(Uuid::from_u128(3));
        let owner = RuntimeInstanceId::from_uuid(Uuid::from_u128(4));
        let session = forge_domain::AgentSessionId::from_uuid(Uuid::from_u128(5));
        let scope = ExpiredActivityRecoveryProbeScope::new(
            workspace,
            forge_domain::WorkspaceRevision::INITIAL,
            forge_domain::LocationId::from_uuid(Uuid::from_u128(6)),
            forge_domain::LocationRevision::INITIAL,
            b".".to_vec(),
            forge_domain::WorkspaceRootFingerprint::from_bytes([8; 16]),
            [9; 32],
        )?;
        let delegation = ExpiredActivityRecoveryDelegationFence::new(
            Uuid::from_u128(10),
            workspace,
            Uuid::from_u128(11),
            ExpiredActivityRecoveryFreezeState::Frozen,
            1,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            [12; 32],
            TimestampMillis::new(2)?,
        )?;
        let predecessor = ExpectedExpiredActivity::new(
            activity,
            ActivityRevision::INITIAL,
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
            owner,
            TimestampMillis::new(0)?,
            ActivityLeaseRevision::INITIAL,
        )?;
        let agent = forge_domain::RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(Uuid::from_u128(13)),
            workspace,
            activity,
            session,
            forge_domain::AgentDisplayName::new("agent".to_owned())?,
            forge_domain::AgentDeclaredRole::new("role".to_owned())?,
            forge_domain::AgentTransportKind::Stdio,
            AuthenticatedPrincipal::TrustedStdio,
            TimestampMillis::new(2)?,
        );
        let snapshot = ExpiredActivityRecoveryAgentSnapshot::from_agent(&agent);
        let base = probe_digest(
            &scope,
            delegation,
            [14; 32],
            predecessor,
            std::slice::from_ref(&snapshot),
            None,
            TimestampMillis::new(10)?,
            None,
        );
        assert_ne!(
            base,
            probe_digest(
                &scope,
                delegation,
                [14; 32],
                predecessor,
                std::slice::from_ref(&snapshot),
                None,
                TimestampMillis::new(11)?,
                None
            )
        );
        assert_ne!(
            base,
            probe_digest(
                &scope,
                delegation,
                [14; 32],
                predecessor,
                std::slice::from_ref(&snapshot),
                None,
                TimestampMillis::new(10)?,
                Some(ExpiredActivityRecoveryBlocker::ActiveWriterLease)
            )
        );
        assert_ne!(
            base,
            probe_digest(
                &scope,
                delegation,
                [15; 32],
                predecessor,
                std::slice::from_ref(&snapshot),
                None,
                TimestampMillis::new(10)?,
                None
            )
        );
        let changed_predecessor = ExpectedExpiredActivity::new(
            activity,
            ActivityRevision::new(2)?,
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
            owner,
            TimestampMillis::new(0)?,
            ActivityLeaseRevision::INITIAL,
        )?;
        assert_ne!(
            base,
            probe_digest(
                &scope,
                delegation,
                [14; 32],
                changed_predecessor,
                std::slice::from_ref(&snapshot),
                None,
                TimestampMillis::new(10)?,
                None
            )
        );
        let coordinator = ExpectedActivityCoordinator::new(
            AgentInstanceId::from_uuid(Uuid::from_u128(13)),
            1,
            TimestampMillis::new(2)?,
        )?;
        assert_ne!(
            base,
            probe_digest(
                &scope,
                delegation,
                [14; 32],
                predecessor,
                std::slice::from_ref(&snapshot),
                Some(coordinator),
                TimestampMillis::new(10)?,
                None
            )
        );
        let changed_scope = ExpiredActivityRecoveryProbeScope::new(
            workspace,
            forge_domain::WorkspaceRevision::INITIAL,
            forge_domain::LocationId::from_uuid(Uuid::from_u128(6)),
            forge_domain::LocationRevision::INITIAL,
            b"subdir".to_vec(),
            forge_domain::WorkspaceRootFingerprint::from_bytes([8; 16]),
            [9; 32],
        )?;
        assert_ne!(
            base,
            probe_digest(
                &changed_scope,
                delegation,
                [14; 32],
                predecessor,
                std::slice::from_ref(&snapshot),
                None,
                TimestampMillis::new(10)?,
                None
            )
        );
        let changed_agent = forge_domain::RegisteredAgentInstance::create_bound(
            AgentInstanceId::from_uuid(Uuid::from_u128(13)),
            workspace,
            activity,
            session,
            forge_domain::AgentDisplayName::new("changed".to_owned())?,
            forge_domain::AgentDeclaredRole::new("role".to_owned())?,
            forge_domain::AgentTransportKind::Stdio,
            AuthenticatedPrincipal::TrustedStdio,
            TimestampMillis::new(2)?,
        );
        assert_ne!(
            agents_digest(std::slice::from_ref(&snapshot)),
            agents_digest(&[ExpiredActivityRecoveryAgentSnapshot::from_agent(
                &changed_agent
            ),])
        );
        let _ = successor;
        Ok(())
    }
}
