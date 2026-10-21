//! Atomic, source-owned work cuts and bounded custody records.
//!
//! A held cut fences fresh work; it is not a completed reciprocal transfer.
//! The host must authenticate its private governance issuer before invoking
//! preparation. Domain envelopes alone do not establish that authority.

use forge_domain::{
    ActivityId, AgentInstanceId, ForgeBackendId, OrchestrationIssuerId, TimestampMillis,
    WorkCutGrant, WorkCutNodeScope, WorkCutRequest,
};
use rusqlite::Connection;
use thiserror::Error;
use uuid::Uuid;

mod continuations;
mod drain;
mod effects;
pub(crate) mod guards;
mod repository;
mod schema;

pub(crate) use continuations::schema::{
    create as create_continuation_schema, objects as continuation_schema_objects,
    validate as validate_continuation_schema,
};
pub use continuations::{
    AssignmentContinuationAcknowledgeOutcome, AssignmentContinuationAcknowledgment,
    AssignmentContinuationIntent, AssignmentContinuationIntentError,
    AssignmentContinuationPrepareOutcome, AssignmentContinuationProposal,
};
pub(crate) use continuations::{
    acknowledge as acknowledge_continuation, get as get_continuation,
    get_ack as get_continuation_acknowledgment, prepare as prepare_continuation,
    prepare_intent as prepare_continuation_intent,
    successor_reserved as continuation_successor_reserved,
};
pub use drain::{WorkCutDrainObservation, WorkCutEffectProgress, WorkCutEffectSettlement};

const MAX_WORK_CUT_EFFECTS: usize = 1024;

#[derive(Debug, Error)]
pub enum WorkCutError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Inventory(#[from] Box<crate::WorkInventoryError>),
    #[error(transparent)]
    Domain(#[from] forge_domain::WorkCutRequestError),
    #[error(transparent)]
    ContinuationDomain(#[from] forge_domain::AgentAssignmentContinuationError),
    #[error(transparent)]
    Assignment(Box<crate::AgentAssignmentStoreError>),
    #[error(transparent)]
    Agent(Box<crate::AgentStoreError>),
    #[error(transparent)]
    Dag(Box<crate::DagStoreError>),
    #[error(transparent)]
    Goal(Box<crate::GoalStoreError>),
    #[error("work cut exceeds its complete-result bound")]
    Bounds,
    #[error("work cut source conflict: {0}")]
    Conflict(&'static str),
    #[error("work cut persisted data is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("work cut {cut_id} commit is unconfirmed; read that exact identity")]
    CommitUnconfirmed {
        cut_id: Uuid,
        #[source]
        source: Box<rusqlite::Error>,
    },
    #[error(
        "continuation {successor_id} request {request_id:?} commit is unconfirmed; read that exact identity"
    )]
    ContinuationCommitUnconfirmed {
        successor_id: forge_domain::AgentAssignmentId,
        request_id: Option<Uuid>,
        #[source]
        source: Box<rusqlite::Error>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkCutEffectKind {
    WriterLease,
    Execution,
    ChangeSet,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCutEffect {
    kind: WorkCutEffectKind,
    id: Uuid,
    revision: i64,
    state: i64,
    activity_id: ActivityId,
    agent_id: Option<AgentInstanceId>,
    node_scope: Option<WorkCutNodeScope>,
}
impl WorkCutEffect {
    pub(super) fn new(
        kind: WorkCutEffectKind,
        id: Uuid,
        revision: i64,
        state: i64,
        activity_id: ActivityId,
        agent_id: Option<AgentInstanceId>,
        node_scope: Option<WorkCutNodeScope>,
    ) -> Result<Self, WorkCutError> {
        if id.is_nil()
            || activity_id.into_uuid().is_nil()
            || revision < 1
            || state < 0
            || agent_id.is_some_and(|id| id.into_uuid().is_nil())
        {
            return Err(WorkCutError::Corrupt("effect identity"));
        }
        Ok(Self {
            kind,
            id,
            revision,
            state,
            activity_id,
            agent_id,
            node_scope,
        })
    }
    pub const fn kind(self) -> WorkCutEffectKind {
        self.kind
    }
    pub const fn id(self) -> Uuid {
        self.id
    }
    #[must_use]
    pub const fn revision(self) -> i64 {
        self.revision
    }
    #[must_use]
    pub const fn state(self) -> i64 {
        self.state
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    #[must_use]
    pub const fn agent_id(self) -> Option<AgentInstanceId> {
        self.agent_id
    }
    #[must_use]
    pub const fn node_scope(self) -> Option<WorkCutNodeScope> {
        self.node_scope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkCutState {
    Held,
    Released,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCutRecord {
    request: WorkCutRequest,
    inventory: crate::WorkCutInventory,
    effects: Vec<WorkCutEffect>,
    issuer: OrchestrationIssuerId,
    prepared_at: TimestampMillis,
    snapshot_digest: [u8; 32],
    authorization_issued_at: TimestampMillis,
    authorization_expires_at: TimestampMillis,
    state: WorkCutState,
    revision: i64,
    updated_at: TimestampMillis,
}
impl WorkCutRecord {
    pub const fn request(&self) -> &WorkCutRequest {
        &self.request
    }
    pub const fn inventory(&self) -> &crate::WorkCutInventory {
        &self.inventory
    }
    pub fn effects(&self) -> &[WorkCutEffect] {
        &self.effects
    }
    pub const fn issuer(&self) -> OrchestrationIssuerId {
        self.issuer
    }
    pub const fn prepared_at(&self) -> TimestampMillis {
        self.prepared_at
    }
    pub const fn authorization_issued_at(&self) -> TimestampMillis {
        self.authorization_issued_at
    }
    pub const fn authorization_expires_at(&self) -> TimestampMillis {
        self.authorization_expires_at
    }
    pub const fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
    pub const fn state(&self) -> WorkCutState {
        self.state
    }
    #[must_use]
    pub const fn revision(&self) -> i64 {
        self.revision
    }
    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkCutPrepareOutcome {
    Prepared(WorkCutRecord),
    Existing(WorkCutRecord),
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), WorkCutError> {
    schema::create_schema(connection)
}
pub(crate) fn validate_schema(connection: &Connection) -> Result<(), WorkCutError> {
    schema::validate_schema(connection)
}
pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    schema::schema_objects()
}

pub(crate) fn prepare(
    connection: &mut Connection,
    request: &WorkCutRequest,
    grant: WorkCutGrant,
    authenticated_issuer: OrchestrationIssuerId,
    actual_backend: ForgeBackendId,
    now: TimestampMillis,
) -> Result<WorkCutPrepareOutcome, WorkCutError> {
    repository::prepare(
        connection,
        request,
        grant,
        authenticated_issuer,
        actual_backend,
        now,
    )
}
pub(crate) fn get(
    connection: &Connection,
    cut_id: Uuid,
) -> Result<Option<WorkCutRecord>, WorkCutError> {
    repository::get(connection, cut_id)
}

pub(crate) fn observe_drain(
    connection: &Connection,
    cut_id: Uuid,
    expected_revision: i64,
    observed_at: TimestampMillis,
) -> Result<WorkCutDrainObservation, WorkCutError> {
    drain::observe(connection, cut_id, expected_revision, observed_at)
}

fn decode_id(bytes: &[u8]) -> Result<Uuid, WorkCutError> {
    let id = Uuid::from_slice(bytes).map_err(|_| WorkCutError::Corrupt("UUID"))?;
    if id.is_nil() {
        return Err(WorkCutError::Corrupt("nil UUID"));
    }
    Ok(id)
}
