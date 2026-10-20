//! Delegated reconciliation of one Agent departure (detach or Coordinator
//! handoff).
//!
//! This transition is valid only after Agent operations were delegated to
//! Orchestration. It mutates only the minimal Forge effect/planning-plane state
//! (the Agent row, its focus fact, and — for handoff — the Coordinator binding)
//! and records an immutable receipt in the same `SQLite` transaction. Left
//! membership events, HandoffStarted/HandoffCompleted events, presence, inbox
//! receipts, and effect-outbox writes are deliberately outside this module:
//! the participation plane is Orchestration-owned.

use forge_domain::{
    ActivityCoordinatorRevision, ActivityId, AgentHandoff, AgentInstanceId, AgentInstanceRevision,
    AgentInstanceRevisionError, AgentSessionId, AuthenticatedPrincipal, DetachAgent,
    TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    workspace_agent_delegation::{self, AgentOperationsDelegation, AgentOperationsDelegationError},
    workspace_agents::{self, AgentStoreError},
    workspace_coordinators::{self, CoordinatorStoreError},
};

const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const MAX_SCHEMA_SQL_BYTES: i64 = 16 * 1024;
const MAX_SCHEMA_METADATA_ROWS: usize = 64;
const TABLE: &str = "agent_departure_reconciliations";
const TABLE_SQL: &str = "CREATE TABLE agent_departure_reconciliations (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16 AND request_id != zeroblob(16)), migration_id BLOB NOT NULL REFERENCES agent_operations_delegations(migration_id) CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), agent_id BLOB NOT NULL CHECK(length(agent_id) = 16 AND agent_id != zeroblob(16)), session_id BLOB NOT NULL CHECK(length(session_id) = 16 AND session_id != zeroblob(16)), kind INTEGER NOT NULL CHECK(kind IN (0, 1)), expected_agent_revision INTEGER NOT NULL CHECK(expected_agent_revision >= 1), result_agent_revision INTEGER NOT NULL CHECK(result_agent_revision = expected_agent_revision + 1), target_agent_id BLOB CHECK(target_agent_id IS NULL OR (length(target_agent_id) = 16 AND target_agent_id != zeroblob(16))), target_session_id BLOB CHECK(target_session_id IS NULL OR (length(target_session_id) = 16 AND target_session_id != zeroblob(16))), result_coordinator_revision INTEGER CHECK(result_coordinator_revision IS NULL OR result_coordinator_revision >= 1), identity_digest BLOB NOT NULL CHECK(length(identity_digest) = 32), reconciled_at_ms INTEGER NOT NULL CHECK(reconciled_at_ms >= 0), CHECK((kind = 0 AND target_agent_id IS NULL AND target_session_id IS NULL AND result_coordinator_revision IS NULL) OR (kind = 1 AND target_agent_id IS NOT NULL AND target_session_id IS NOT NULL AND result_coordinator_revision IS NOT NULL)), UNIQUE(workspace_id, agent_id), FOREIGN KEY(agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id), FOREIGN KEY(target_agent_id, workspace_id, activity_id) REFERENCES agent_instances(agent_id, workspace_id, activity_id))";

/// Which departure a journal row records. `Detach` is a plain session-bound
/// detach; `Handoff` is the atomic Coordinator handoff detach.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentDepartureKind {
    Detach,
    Handoff,
}

impl AgentDepartureKind {
    const fn encode(self) -> i64 {
        match self {
            Self::Detach => 0,
            Self::Handoff => 1,
        }
    }

    fn decode(value: i64) -> Result<Self, AgentDepartureReconciliationError> {
        match value {
            0 => Ok(Self::Detach),
            1 => Ok(Self::Handoff),
            _ => Err(AgentDepartureReconciliationError::CorruptRecord(
                "departure kind",
            )),
        }
    }
}

/// The exact departure command carried by one reconciliation request. Both
/// variants reuse the existing Forge domain commands; the authenticated caller
/// identity and the immutable identity digest travel with the request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDepartureCommand {
    Detach(DetachAgent),
    Handoff(Box<AgentHandoff>),
}

impl AgentDepartureCommand {
    pub const fn kind(&self) -> AgentDepartureKind {
        match self {
            Self::Detach(_) => AgentDepartureKind::Detach,
            Self::Handoff(_) => AgentDepartureKind::Handoff,
        }
    }

    pub const fn detach(&self) -> Option<&DetachAgent> {
        match self {
            Self::Detach(command) => Some(command),
            Self::Handoff(_) => None,
        }
    }

    pub fn handoff(&self) -> Option<&AgentHandoff> {
        match self {
            Self::Detach(_) => None,
            Self::Handoff(command) => Some(command),
        }
    }

    fn activity_id(&self) -> ActivityId {
        match self {
            Self::Detach(command) => command.activity_id(),
            Self::Handoff(command) => command.actor().activity_id(),
        }
    }

    fn agent_id(&self) -> AgentInstanceId {
        match self {
            Self::Detach(command) => command.agent_id(),
            Self::Handoff(command) => command.actor().agent_id(),
        }
    }

    fn expected_agent_revision(&self) -> AgentInstanceRevision {
        match self {
            Self::Detach(command) => command.expected_revision(),
            Self::Handoff(command) => command.expected_source_agent_revision(),
        }
    }

    fn observed_at(&self) -> TimestampMillis {
        match self {
            Self::Detach(command) => command.observed_at(),
            Self::Handoff(command) => command.observed_at(),
        }
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDepartureReconciliationRequest {
    request_id: Uuid,
    command: AgentDepartureCommand,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    identity_digest: [u8; DIGEST_BYTES],
}

impl AgentDepartureReconciliationRequest {
    /// Build a checked departure reconciliation request. The session and
    /// principal are the authenticated caller identity: for a detach this is
    /// the departing Agent's own session; for a handoff it must exactly match
    /// the handoff source Coordinator session. The identity digest is recorded
    /// immutably and must be reproduced exactly on replay.
    pub fn new(
        request_id: Uuid,
        command: AgentDepartureCommand,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        identity_digest: [u8; DIGEST_BYTES],
    ) -> Result<Self, AgentDepartureReconciliationError> {
        if request_id.is_nil() {
            return Err(AgentDepartureReconciliationError::InvalidRequestId);
        }
        if identity_digest == [0_u8; DIGEST_BYTES] {
            return Err(AgentDepartureReconciliationError::ZeroIdentityDigest);
        }
        if let AgentDepartureCommand::Handoff(handoff) = &command
            && (handoff.actor().session_id() != session_id
                || handoff.actor().principal() != principal)
        {
            return Err(AgentDepartureReconciliationError::CallerMismatch);
        }
        Ok(Self {
            request_id,
            command,
            session_id,
            principal,
            identity_digest,
        })
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn command(&self) -> &AgentDepartureCommand {
        &self.command
    }

    pub const fn session_id(&self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn identity_digest(&self) -> [u8; DIGEST_BYTES] {
        self.identity_digest
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentDepartureReconciliation {
    request_id: Uuid,
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    kind: AgentDepartureKind,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    expected_agent_revision: AgentInstanceRevision,
    result_agent_revision: AgentInstanceRevision,
    target_agent_id: Option<AgentInstanceId>,
    target_session_id: Option<AgentSessionId>,
    result_coordinator_revision: Option<ActivityCoordinatorRevision>,
    identity_digest: [u8; DIGEST_BYTES],
    reconciled_at: TimestampMillis,
}

impl AgentDepartureReconciliation {
    pub const fn request_id(self) -> Uuid {
        self.request_id
    }
    pub const fn migration_id(self) -> Uuid {
        self.migration_id
    }
    pub const fn destination_id(self) -> Uuid {
        self.destination_id
    }
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }
    pub const fn kind(self) -> AgentDepartureKind {
        self.kind
    }
    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }
    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }
    pub const fn expected_agent_revision(self) -> AgentInstanceRevision {
        self.expected_agent_revision
    }
    pub const fn result_agent_revision(self) -> AgentInstanceRevision {
        self.result_agent_revision
    }
    pub const fn target_agent_id(self) -> Option<AgentInstanceId> {
        self.target_agent_id
    }
    pub const fn target_session_id(self) -> Option<AgentSessionId> {
        self.target_session_id
    }
    pub const fn result_coordinator_revision(self) -> Option<ActivityCoordinatorRevision> {
        self.result_coordinator_revision
    }
    pub const fn identity_digest(self) -> [u8; DIGEST_BYTES] {
        self.identity_digest
    }
    pub const fn reconciled_at(self) -> TimestampMillis {
        self.reconciled_at
    }
}

#[derive(Debug, Error)]
pub enum AgentDepartureReconciliationError {
    #[error("Agent departure reconciliation request identity is nil")]
    InvalidRequestId,
    #[error("Agent departure reconciliation identity digest must be non-zero")]
    ZeroIdentityDigest,
    #[error("Agent departure reconciliation caller does not match the handoff source session")]
    CallerMismatch,
    #[error("Agent departure reconciliation request does not match the requested departure kind")]
    KindMismatch,
    #[error("Agent operations delegation for Workspace {0} is missing")]
    DelegationMissing(WorkspaceId),
    #[error("Agent operations delegation for Workspace {0} is stale")]
    StaleDelegation(WorkspaceId),
    #[error("Agent departure reconciliation command targets a different Workspace")]
    WorkspaceMismatch,
    #[error("Agent departure reconciliation timestamp predates source delegation")]
    TimestampOrder,
    #[error("Agent departure reconciliation request conflicts with durable state")]
    RequestConflict,
    #[error("Agent departure reconciliation receipt is corrupt: {0}")]
    CorruptRecord(&'static str),
    #[error("Agent departure reconciliation schema is damaged")]
    DamagedSchema,
    #[error("Agent departure reconciliation schema metadata exceeds {0} rows")]
    SchemaMetadataTooLarge(usize),
    #[error("Agent departure reconciliation schema SQL is {actual} bytes; maximum is {maximum}")]
    SchemaSqlTooLarge { actual: i64, maximum: i64 },
    #[error(
        "Agent departure reconciliation {request_id} commit is unconfirmed; read the same request identity"
    )]
    CommitUnconfirmed {
        request_id: Uuid,
        #[source]
        source: rusqlite::Error,
    },
    #[error(transparent)]
    Delegation(#[from] AgentOperationsDelegationError),
    #[error(transparent)]
    Agent(#[from] AgentStoreError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorStoreError),
    #[error(transparent)]
    AgentRevision(#[from] AgentInstanceRevisionError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub(crate) fn create_schema(
    connection: &Connection,
) -> Result<(), AgentDepartureReconciliationError> {
    connection.execute_batch(TABLE_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> Vec<(&'static str, &'static str)> {
    vec![("table", TABLE)]
}

pub(crate) fn validate_schema(
    connection: &Connection,
) -> Result<(), AgentDepartureReconciliationError> {
    let length = connection
        .query_row(
            "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type='table' AND name=?1",
            params![TABLE],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(AgentDepartureReconciliationError::DamagedSchema)?;
    if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&length) {
        return Err(AgentDepartureReconciliationError::SchemaSqlTooLarge {
            actual: length,
            maximum: MAX_SCHEMA_SQL_BYTES,
        });
    }
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
        params![TABLE],
        |row| row.get(0),
    )?;
    if i64::try_from(actual.len()).ok() != Some(length)
        || normalize_sql(&actual) != normalize_sql(TABLE_SQL)
    {
        return Err(AgentDepartureReconciliationError::DamagedSchema);
    }
    validate_columns(connection)?;
    validate_foreign_keys(connection)
}

/// Reconcile one plain detach departure. The command must be a
/// [`AgentDepartureCommand::Detach`]; the caller must have already resolved
/// migration/delegation authority and the authenticated session.
pub(crate) fn reconcile_detach(
    connection: &mut Connection,
    delegation: &AgentOperationsDelegation,
    request: &AgentDepartureReconciliationRequest,
) -> Result<AgentDepartureReconciliation, AgentDepartureReconciliationError> {
    if request.command().kind() != AgentDepartureKind::Detach {
        return Err(AgentDepartureReconciliationError::KindMismatch);
    }
    reconcile(connection, delegation, request, None)
}

/// Reconcile one Coordinator handoff departure. The command must be a
/// [`AgentDepartureCommand::Handoff`]. Validation mirrors the historical
/// Coordinator handoff admission; only the effect/planning-plane writes and the
/// journal receipt remain.
pub(crate) fn reconcile_handoff(
    connection: &mut Connection,
    delegation: &AgentOperationsDelegation,
    request: &AgentDepartureReconciliationRequest,
    admitted_at: TimestampMillis,
) -> Result<AgentDepartureReconciliation, AgentDepartureReconciliationError> {
    if request.command().kind() != AgentDepartureKind::Handoff {
        return Err(AgentDepartureReconciliationError::KindMismatch);
    }
    reconcile(connection, delegation, request, Some(admitted_at))
}

pub(crate) fn reconcile(
    connection: &mut Connection,
    delegation: &AgentOperationsDelegation,
    request: &AgentDepartureReconciliationRequest,
    admitted_at: Option<TimestampMillis>,
) -> Result<AgentDepartureReconciliation, AgentDepartureReconciliationError> {
    let command = request.command();
    if command.kind() == AgentDepartureKind::Handoff {
        let handoff = command
            .handoff()
            .ok_or(AgentDepartureReconciliationError::KindMismatch)?;
        if handoff.actor().workspace_id() != delegation.workspace_id() {
            return Err(AgentDepartureReconciliationError::WorkspaceMismatch);
        }
    }
    if command.observed_at().get() < delegation.delegated_at().get() {
        return Err(AgentDepartureReconciliationError::TimestampOrder);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction)?;
    let current_delegation =
        workspace_agent_delegation::get(&transaction, delegation.workspace_id())?.ok_or(
            AgentDepartureReconciliationError::DelegationMissing(delegation.workspace_id()),
        )?;
    if !same_delegation(&current_delegation, delegation) {
        return Err(AgentDepartureReconciliationError::StaleDelegation(
            delegation.workspace_id(),
        ));
    }

    if let (AgentDepartureCommand::Handoff(handoff), Some(admitted_at)) = (command, admitted_at) {
        workspace_coordinators::ensure_live_activity_in_transaction(
            &transaction,
            handoff.actor().activity_id(),
            handoff.actor().workspace_id(),
            admitted_at,
        )?;
    }

    if let Some(existing) = load(&transaction, request.request_id())? {
        let receipt = decode(&existing)?;
        if !matches_request(receipt, delegation, request) {
            return Err(AgentDepartureReconciliationError::RequestConflict);
        }
        verify_departed_state(&transaction, receipt)?;
        transaction.commit().map_err(|source| {
            AgentDepartureReconciliationError::CommitUnconfirmed {
                request_id: request.request_id(),
                source,
            }
        })?;
        return Ok(receipt);
    }

    let receipt = match command {
        AgentDepartureCommand::Detach(detach) => {
            apply_detach(&transaction, delegation, request, detach)?
        }
        AgentDepartureCommand::Handoff(handoff) => {
            apply_handoff(&transaction, delegation, request, handoff.as_ref())?
        }
    };
    let stored_raw = load(&transaction, request.request_id())?.ok_or(
        AgentDepartureReconciliationError::CorruptRecord("insert readback"),
    )?;
    let stored = decode(&stored_raw)?;
    if stored != receipt {
        return Err(AgentDepartureReconciliationError::CorruptRecord(
            "insert identity",
        ));
    }
    transaction.commit().map_err(|source| {
        AgentDepartureReconciliationError::CommitUnconfirmed {
            request_id: request.request_id(),
            source,
        }
    })?;
    Ok(receipt)
}

/// Apply one detach departure inside the caller's transaction: exact bound
/// attached Agent with revision CAS, current-Coordinator refusal, active
/// Writer Lease and execution guards, then the Agent row update plus its
/// `Detached` focus fact, and finally the immutable journal receipt. No Left
/// membership event, presence, inbox, or effect-outbox write is performed.
fn apply_detach(
    transaction: &rusqlite::Transaction<'_>,
    delegation: &AgentOperationsDelegation,
    request: &AgentDepartureReconciliationRequest,
    detach: &DetachAgent,
) -> Result<AgentDepartureReconciliation, AgentDepartureReconciliationError> {
    let workspace_id = delegation.workspace_id();
    let current = workspace_agents::ensure_bound_attached_agent(
        transaction,
        workspace_id,
        detach.activity_id(),
        detach.agent_id(),
        request.session_id(),
        request.principal(),
        Some(detach.expected_revision()),
    )?;
    let is_current_coordinator: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM activity_coordinators WHERE activity_id = ?1 AND agent_id = ?2)",
        params![
            detach.activity_id().into_uuid().as_bytes(),
            current.id().into_uuid().as_bytes(),
        ],
        |row| row.get(0),
    )?;
    if is_current_coordinator {
        return Err(AgentStoreError::CurrentCoordinatorCannotDetach(current.id()).into());
    }
    workspace_coordinators::ensure_no_active_writer_lease(
        transaction,
        current.id(),
        detach.activity_id(),
    )?;
    workspace_coordinators::ensure_no_active_execution(
        transaction,
        current.id(),
        detach.activity_id(),
    )?;

    let updated =
        workspace_agents::detach_in_transaction(transaction, &current, detach.observed_at())?;
    let result_agent_revision = detach.expected_revision().checked_next()?;
    if updated.revision() != result_agent_revision {
        return Err(AgentDepartureReconciliationError::CorruptRecord(
            "Agent revision readback",
        ));
    }
    let receipt = AgentDepartureReconciliation {
        request_id: request.request_id(),
        migration_id: delegation.migration_id(),
        destination_id: delegation.destination_id(),
        workspace_id,
        activity_id: detach.activity_id(),
        kind: AgentDepartureKind::Detach,
        agent_id: detach.agent_id(),
        session_id: request.session_id(),
        expected_agent_revision: detach.expected_revision(),
        result_agent_revision,
        target_agent_id: None,
        target_session_id: None,
        result_coordinator_revision: None,
        identity_digest: request.identity_digest(),
        reconciled_at: detach.observed_at(),
    };
    insert(transaction, receipt)?;
    Ok(receipt)
}

/// Apply one Coordinator handoff departure inside the caller's transaction.
/// Admission mirrors the historical Coordinator handoff: Coordinator CAS
/// authorization, source and target bound attached with exact revisions, no
/// same-session handoff, target not already Coordinator, timestamp ordering,
/// the coordination snapshot fence, and no active Writer Lease or execution
/// for both Agents. Writes are limited to the target focus transfer, the
/// source detach (without a Left participation event), the Coordinator row
/// CAS, and the journal receipt.
#[allow(clippy::too_many_lines)]
fn apply_handoff(
    transaction: &rusqlite::Transaction<'_>,
    delegation: &AgentOperationsDelegation,
    request: &AgentDepartureReconciliationRequest,
    handoff: &AgentHandoff,
) -> Result<AgentDepartureReconciliation, AgentDepartureReconciliationError> {
    let actor = handoff.actor();
    let current = workspace_coordinators::authorize_in_transaction(transaction, actor)?;
    let source = workspace_agents::ensure_bound_attached_agent(
        transaction,
        actor.workspace_id(),
        actor.activity_id(),
        actor.agent_id(),
        actor.session_id(),
        actor.principal(),
        Some(handoff.expected_source_agent_revision()),
    )?;
    if source.id() == handoff.target_agent_id() {
        return Err(CoordinatorStoreError::TargetAlreadyCoordinator.into());
    }
    if actor.session_id() == handoff.target_session_id() {
        return Err(CoordinatorStoreError::SameSessionHandoff.into());
    }
    let target = workspace_agents::ensure_bound_attached_agent(
        transaction,
        actor.workspace_id(),
        actor.activity_id(),
        handoff.target_agent_id(),
        handoff.target_session_id(),
        handoff.target_principal(),
        Some(handoff.expected_target_revision()),
    )?;
    if handoff.observed_at().get() < current.updated_at().get()
        || handoff.observed_at().get() < source.updated_at().get()
        || handoff.observed_at().get() < target.updated_at().get()
    {
        return Err(CoordinatorStoreError::TimestampOrder.into());
    }
    let source_coordination =
        crate::workspace_agent_events::coordination_snapshot_for_agent(transaction, &source)
            .map_err(CoordinatorStoreError::from)?;
    let current_coordination = crate::workspace_agent_events::current_coordination_snapshot(
        transaction,
        actor.workspace_id(),
        actor.activity_id(),
        &source,
    )
    .map_err(CoordinatorStoreError::from)?;
    if source_coordination != current_coordination
        || current_coordination != handoff.expected_coordination()
    {
        return Err(CoordinatorStoreError::CoordinationRevisionConflict.into());
    }
    workspace_coordinators::ensure_no_active_writer_lease(
        transaction,
        source.id(),
        actor.activity_id(),
    )?;
    workspace_coordinators::ensure_no_active_writer_lease(
        transaction,
        target.id(),
        actor.activity_id(),
    )?;
    workspace_coordinators::ensure_no_active_execution(
        transaction,
        source.id(),
        actor.activity_id(),
    )?;
    workspace_coordinators::ensure_no_active_execution(
        transaction,
        target.id(),
        actor.activity_id(),
    )?;

    let transferred_focus = match source_coordination.goal() {
        Some(goal) => {
            forge_domain::AgentFocus::new(Some(goal), source_coordination.dag_revision(), None)
                .map_err(|_| CoordinatorStoreError::CoordinationRevisionConflict)?
        }
        None => forge_domain::AgentFocus::unfocused(),
    };
    let focus_command = forge_domain::SetAgentFocus::new(
        target.id(),
        actor.activity_id(),
        handoff.expected_target_revision(),
        transferred_focus,
        handoff.observed_at(),
    );
    let transferred = workspace_agents::set_focus_in_transaction(transaction, &focus_command)?;
    let detached =
        workspace_agents::detach_in_transaction(transaction, &source, handoff.observed_at())?;
    let next_revision = current
        .revision()
        .checked_next()
        .map_err(|_| CoordinatorStoreError::RevisionOverflow)?;
    let changed = transaction.execute(
        "UPDATE activity_coordinators SET agent_id = ?1, revision = ?2, updated_at_ms = ?3 WHERE activity_id = ?4 AND agent_id = ?5 AND revision = ?6",
        params![
            transferred.id().into_uuid().as_bytes(),
            next_revision.get(),
            handoff.observed_at().get(),
            current.activity_id().into_uuid().as_bytes(),
            current.agent_id().into_uuid().as_bytes(),
            current.revision().get(),
        ],
    )?;
    if changed != 1 {
        return Err(CoordinatorStoreError::RevisionConflict.into());
    }
    let result_agent_revision = handoff.expected_source_agent_revision().checked_next()?;
    if detached.revision() != result_agent_revision {
        return Err(AgentDepartureReconciliationError::CorruptRecord(
            "Agent revision readback",
        ));
    }
    let receipt = AgentDepartureReconciliation {
        request_id: request.request_id(),
        migration_id: delegation.migration_id(),
        destination_id: delegation.destination_id(),
        workspace_id: delegation.workspace_id(),
        activity_id: actor.activity_id(),
        kind: AgentDepartureKind::Handoff,
        agent_id: actor.agent_id(),
        session_id: actor.session_id(),
        expected_agent_revision: handoff.expected_source_agent_revision(),
        result_agent_revision,
        target_agent_id: Some(handoff.target_agent_id()),
        target_session_id: Some(handoff.target_session_id()),
        result_coordinator_revision: Some(next_revision),
        identity_digest: request.identity_digest(),
        reconciled_at: handoff.observed_at(),
    };
    insert(transaction, receipt)?;
    Ok(receipt)
}

/// Verify the durable post-departure state for a replayed request. A receipt
/// whose effect did not durably happen is a conflict, never a replay.
fn verify_departed_state(
    connection: &Connection,
    receipt: AgentDepartureReconciliation,
) -> Result<(), AgentDepartureReconciliationError> {
    let agent = workspace_agents::get_in_transaction(connection, receipt.agent_id)?
        .ok_or(AgentStoreError::AgentNotFound(receipt.agent_id))?;
    if agent.workspace_id() != receipt.workspace_id
        || agent.activity_id() != receipt.activity_id
        || agent.session_id() != Some(receipt.session_id)
        || agent.revision() != receipt.result_agent_revision
        || agent.attachment_state() != forge_domain::AgentAttachmentState::Detached
    {
        return Err(AgentDepartureReconciliationError::RequestConflict);
    }
    if receipt.kind == AgentDepartureKind::Handoff {
        let binding = workspace_coordinators::get_in_transaction(connection, receipt.activity_id)?
            .ok_or(CoordinatorStoreError::CoordinatorMissing(
                receipt.activity_id,
            ))?;
        let target_agent_id =
            receipt
                .target_agent_id
                .ok_or(AgentDepartureReconciliationError::CorruptRecord(
                    "handoff target",
                ))?;
        let result_coordinator_revision = receipt.result_coordinator_revision.ok_or(
            AgentDepartureReconciliationError::CorruptRecord("coordinator revision"),
        )?;
        if binding.agent_id() != target_agent_id
            || binding.revision() != result_coordinator_revision
        {
            return Err(AgentDepartureReconciliationError::RequestConflict);
        }
    }
    Ok(())
}

pub(crate) fn get(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<AgentDepartureReconciliation>, AgentDepartureReconciliationError> {
    if request_id.is_nil() {
        return Err(AgentDepartureReconciliationError::InvalidRequestId);
    }
    validate_schema(connection)?;
    let raw = load(connection, request_id)?;
    raw.as_ref().map(decode).transpose()
}

fn same_delegation(left: &AgentOperationsDelegation, right: &AgentOperationsDelegation) -> bool {
    left.migration_id() == right.migration_id()
        && left.workspace_id() == right.workspace_id()
        && left.destination_id() == right.destination_id()
        && left.freeze().revision() == right.freeze().revision()
        && left.manifest_digest() == right.manifest_digest()
        && left.delegated_at() == right.delegated_at()
}

fn matches_request(
    receipt: AgentDepartureReconciliation,
    delegation: &AgentOperationsDelegation,
    request: &AgentDepartureReconciliationRequest,
) -> bool {
    let command = request.command();
    receipt.request_id == request.request_id()
        && receipt.migration_id == delegation.migration_id()
        && receipt.destination_id == delegation.destination_id()
        && receipt.workspace_id == delegation.workspace_id()
        && receipt.activity_id == command.activity_id()
        && receipt.kind == command.kind()
        && receipt.agent_id == command.agent_id()
        && receipt.session_id == request.session_id()
        && receipt.expected_agent_revision == command.expected_agent_revision()
        && receipt.identity_digest == request.identity_digest()
        && receipt.reconciled_at == command.observed_at()
}

fn insert(
    connection: &Connection,
    receipt: AgentDepartureReconciliation,
) -> Result<(), AgentDepartureReconciliationError> {
    connection.execute(
        "INSERT INTO agent_departure_reconciliations(request_id,migration_id,workspace_id,destination_id,activity_id,agent_id,session_id,kind,expected_agent_revision,result_agent_revision,target_agent_id,target_session_id,result_coordinator_revision,identity_digest,reconciled_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![
            receipt.request_id.as_bytes(),
            receipt.migration_id.as_bytes(),
            receipt.workspace_id.into_uuid().as_bytes(),
            receipt.destination_id.as_bytes(),
            receipt.activity_id.into_uuid().as_bytes(),
            receipt.agent_id.into_uuid().as_bytes(),
            receipt.session_id.into_uuid().as_bytes(),
            receipt.kind.encode(),
            receipt.expected_agent_revision.get(),
            receipt.result_agent_revision.get(),
            receipt.target_agent_id.map(|id| id.into_uuid().as_bytes().to_vec()),
            receipt.target_session_id.map(|id| id.into_uuid().as_bytes().to_vec()),
            receipt.result_coordinator_revision.map(ActivityCoordinatorRevision::get),
            receipt.identity_digest.as_slice(),
            receipt.reconciled_at.get(),
        ],
    )?;
    Ok(())
}

#[derive(Debug)]
struct RawReceipt {
    request_id: Vec<u8>,
    migration_id: Vec<u8>,
    workspace_id: Vec<u8>,
    destination_id: Vec<u8>,
    activity_id: Vec<u8>,
    agent_id: Vec<u8>,
    session_id: Vec<u8>,
    kind: i64,
    expected_agent_revision: i64,
    result_agent_revision: i64,
    target_agent_id: Option<Vec<u8>>,
    target_session_id: Option<Vec<u8>>,
    result_coordinator_revision: Option<i64>,
    identity_digest: Vec<u8>,
    reconciled_at: i64,
}

fn load(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<RawReceipt>, AgentDepartureReconciliationError> {
    connection
        .query_row(
            "SELECT substr(request_id,1,17),substr(migration_id,1,17),substr(workspace_id,1,17),substr(destination_id,1,17),substr(activity_id,1,17),substr(agent_id,1,17),substr(session_id,1,17),kind,expected_agent_revision,result_agent_revision,substr(target_agent_id,1,17),substr(target_session_id,1,17),result_coordinator_revision,identity_digest,reconciled_at_ms FROM agent_departure_reconciliations WHERE request_id=?1 LIMIT 1",
            params![request_id.as_bytes()],
            |row| {
                Ok(RawReceipt {
                    request_id: row.get(0)?,
                    migration_id: row.get(1)?,
                    workspace_id: row.get(2)?,
                    destination_id: row.get(3)?,
                    activity_id: row.get(4)?,
                    agent_id: row.get(5)?,
                    session_id: row.get(6)?,
                    kind: row.get(7)?,
                    expected_agent_revision: row.get(8)?,
                    result_agent_revision: row.get(9)?,
                    target_agent_id: row.get(10)?,
                    target_session_id: row.get(11)?,
                    result_coordinator_revision: row.get(12)?,
                    identity_digest: row.get(13)?,
                    reconciled_at: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn decode(
    raw: &RawReceipt,
) -> Result<AgentDepartureReconciliation, AgentDepartureReconciliationError> {
    let kind = AgentDepartureKind::decode(raw.kind)?;
    let expected_agent_revision = AgentInstanceRevision::new(raw.expected_agent_revision)
        .map_err(|_| AgentDepartureReconciliationError::CorruptRecord("expected revision"))?;
    let result_agent_revision = AgentInstanceRevision::new(raw.result_agent_revision)
        .map_err(|_| AgentDepartureReconciliationError::CorruptRecord("result revision"))?;
    if expected_agent_revision.checked_next().ok() != Some(result_agent_revision) {
        return Err(AgentDepartureReconciliationError::CorruptRecord(
            "revision transition",
        ));
    }
    let target_agent_id = raw
        .target_agent_id
        .as_ref()
        .map(|bytes| decode_uuid(bytes, "target_agent_id"))
        .transpose()?
        .map(AgentInstanceId::from_uuid);
    let target_session_id = raw
        .target_session_id
        .as_ref()
        .map(|bytes| decode_uuid(bytes, "target_session_id"))
        .transpose()?
        .map(AgentSessionId::from_uuid);
    let result_coordinator_revision = raw
        .result_coordinator_revision
        .map(ActivityCoordinatorRevision::new)
        .transpose()
        .map_err(|_| AgentDepartureReconciliationError::CorruptRecord("coordinator revision"))?;
    match kind {
        AgentDepartureKind::Detach => {
            if target_agent_id.is_some()
                || target_session_id.is_some()
                || result_coordinator_revision.is_some()
            {
                return Err(AgentDepartureReconciliationError::CorruptRecord(
                    "detach target",
                ));
            }
        }
        AgentDepartureKind::Handoff => {
            if target_agent_id.is_none()
                || target_session_id.is_none()
                || result_coordinator_revision.is_none()
            {
                return Err(AgentDepartureReconciliationError::CorruptRecord(
                    "handoff target",
                ));
            }
        }
    }
    let identity_digest = decode_digest(&raw.identity_digest)?;
    Ok(AgentDepartureReconciliation {
        request_id: decode_uuid(&raw.request_id, "request_id")?,
        migration_id: decode_uuid(&raw.migration_id, "migration_id")?,
        destination_id: decode_uuid(&raw.destination_id, "destination_id")?,
        workspace_id: WorkspaceId::from_uuid(decode_uuid(&raw.workspace_id, "workspace_id")?),
        activity_id: ActivityId::from_uuid(decode_uuid(&raw.activity_id, "activity_id")?),
        kind,
        agent_id: AgentInstanceId::from_uuid(decode_uuid(&raw.agent_id, "agent_id")?),
        session_id: AgentSessionId::from_uuid(decode_uuid(&raw.session_id, "session_id")?),
        expected_agent_revision,
        result_agent_revision,
        target_agent_id,
        target_session_id,
        result_coordinator_revision,
        identity_digest,
        reconciled_at: TimestampMillis::new(raw.reconciled_at)
            .map_err(|_| AgentDepartureReconciliationError::CorruptRecord("timestamp"))?,
    })
}

fn decode_uuid(
    bytes: &[u8],
    field: &'static str,
) -> Result<Uuid, AgentDepartureReconciliationError> {
    if bytes.len() != ID_BYTES {
        return Err(AgentDepartureReconciliationError::CorruptRecord(field));
    }
    Uuid::from_slice(bytes).map_err(|_| AgentDepartureReconciliationError::CorruptRecord(field))
}

fn decode_digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], AgentDepartureReconciliationError> {
    if bytes.len() != DIGEST_BYTES {
        return Err(AgentDepartureReconciliationError::CorruptRecord(
            "identity_digest",
        ));
    }
    let mut digest = [0_u8; DIGEST_BYTES];
    digest.copy_from_slice(bytes);
    Ok(digest)
}

fn validate_columns(connection: &Connection) -> Result<(), AgentDepartureReconciliationError> {
    let mut statement = connection.prepare("PRAGMA table_info(agent_departure_reconciliations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentDepartureReconciliationError::SchemaMetadataTooLarge(
                MAX_SCHEMA_METADATA_ROWS,
            ));
        }
        actual.push((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ));
    }
    let expected = [
        ("request_id", "BLOB", 1, 1),
        ("migration_id", "BLOB", 1, 0),
        ("workspace_id", "BLOB", 1, 0),
        ("destination_id", "BLOB", 1, 0),
        ("activity_id", "BLOB", 1, 0),
        ("agent_id", "BLOB", 1, 0),
        ("session_id", "BLOB", 1, 0),
        ("kind", "INTEGER", 1, 0),
        ("expected_agent_revision", "INTEGER", 1, 0),
        ("result_agent_revision", "INTEGER", 1, 0),
        ("target_agent_id", "BLOB", 0, 0),
        ("target_session_id", "BLOB", 0, 0),
        ("result_coordinator_revision", "INTEGER", 0, 0),
        ("identity_digest", "BLOB", 1, 0),
        ("reconciled_at_ms", "INTEGER", 1, 0),
    ];
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        )
    {
        return Err(AgentDepartureReconciliationError::DamagedSchema);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_foreign_keys(connection: &Connection) -> Result<(), AgentDepartureReconciliationError> {
    let mut statement =
        connection.prepare("PRAGMA foreign_key_list(agent_departure_reconciliations)")?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        if actual.len() >= MAX_SCHEMA_METADATA_ROWS {
            return Err(AgentDepartureReconciliationError::SchemaMetadataTooLarge(
                MAX_SCHEMA_METADATA_ROWS,
            ));
        }
        actual.push((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ));
    }
    actual.sort_unstable();
    let mut expected = vec![
        (
            "activities".to_owned(),
            "activity_id".to_owned(),
            "activity_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "activity_id".to_owned(),
            "activity_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "activity_id".to_owned(),
            "activity_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "agent_id".to_owned(),
            "agent_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "target_agent_id".to_owned(),
            "agent_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "workspace_id".to_owned(),
            "workspace_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_instances".to_owned(),
            "workspace_id".to_owned(),
            "workspace_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "agent_operations_delegations".to_owned(),
            "migration_id".to_owned(),
            "migration_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
        (
            "workspace".to_owned(),
            "workspace_id".to_owned(),
            "workspace_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        ),
    ];
    expected.sort_unstable();
    if actual != expected {
        return Err(AgentDepartureReconciliationError::DamagedSchema);
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" ,", ",")
}

#[cfg(test)]
mod departure_tests;

#[cfg(test)]
mod unit_tests {
    use super::*;
    use forge_domain::CoordinationSnapshot;

    #[test]
    fn request_rejects_nil_identity_and_zero_digest() -> Result<(), Box<dyn std::error::Error>> {
        let command = AgentDepartureCommand::Detach(DetachAgent::new(
            AgentInstanceId::from_uuid(Uuid::from_u128(1)),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            AgentInstanceRevision::INITIAL,
            TimestampMillis::new(3)?,
        ));
        assert!(matches!(
            AgentDepartureReconciliationRequest::new(
                Uuid::nil(),
                command.clone(),
                AgentSessionId::from_uuid(Uuid::from_u128(4)),
                AuthenticatedPrincipal::TrustedStdio,
                [1_u8; 32],
            ),
            Err(AgentDepartureReconciliationError::InvalidRequestId)
        ));
        assert!(matches!(
            AgentDepartureReconciliationRequest::new(
                Uuid::from_u128(5),
                command,
                AgentSessionId::from_uuid(Uuid::from_u128(4)),
                AuthenticatedPrincipal::TrustedStdio,
                [0_u8; 32],
            ),
            Err(AgentDepartureReconciliationError::ZeroIdentityDigest)
        ));
        Ok(())
    }

    #[test]
    fn handoff_request_rejects_a_foreign_caller_session() -> Result<(), Box<dyn std::error::Error>>
    {
        let actor = forge_domain::ActivityCoordinatorActor::new(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            ActivityId::from_uuid(Uuid::from_u128(2)),
            AgentInstanceId::from_uuid(Uuid::from_u128(3)),
            forge_domain::ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            AgentSessionId::from_uuid(Uuid::from_u128(4)),
        );
        let command = AgentDepartureCommand::Handoff(Box::new(AgentHandoff::new(
            actor,
            AgentInstanceRevision::INITIAL,
            AgentInstanceId::from_uuid(Uuid::from_u128(5)),
            AgentSessionId::from_uuid(Uuid::from_u128(6)),
            AuthenticatedPrincipal::TrustedStdio,
            AgentInstanceRevision::INITIAL,
            CoordinationSnapshot::empty(),
            forge_domain::AgentEventId::from_uuid(Uuid::from_u128(7)),
            TimestampMillis::new(8)?,
        )));
        assert!(matches!(
            AgentDepartureReconciliationRequest::new(
                Uuid::from_u128(9),
                command,
                AgentSessionId::from_uuid(Uuid::from_u128(10)),
                AuthenticatedPrincipal::TrustedStdio,
                [1_u8; 32],
            ),
            Err(AgentDepartureReconciliationError::CallerMismatch)
        ));
        Ok(())
    }
}
