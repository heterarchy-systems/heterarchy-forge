//! Durable `dag.settle` terminal effect fact (`fact_kind = 5`).
//!
//! Entries are sequenced in `effect_fact_outbox_entries` (`CHECK(fact_kind BETWEEN 0 AND 7)`)
//! while preserving `WorkspaceSchemaShape` compatibility via checksummed sidecar records
//! colocated under `<state_dir>/dag-settled-outbox/`.

use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, DagRevisionNumber, GoalId, GoalRevision,
    TimestampMillis, WorkspaceId,
};
use rusqlite::Connection;
use uuid::Uuid;

use super::settled_sidecar::{
    SettledSidecarSpec, encode_record_with, insert_entry_by_kind, persist_sidecar, read_sidecar,
    select_entries_by_kind, verify_envelope,
};
use super::{DAG_SETTLED_KIND, DIGEST_BYTES, EffectFactOutboxError, source_delegation};

const PAYLOAD_WITHOUT_CHECKSUM_LEN: usize = 209;
const RECORD_BYTE_LEN: usize = PAYLOAD_WITHOUT_CHECKSUM_LEN + DIGEST_BYTES;

const SPEC: SettledSidecarSpec = SettledSidecarSpec {
    fact_kind: DAG_SETTLED_KIND,
    magic: b"FGDSFCT1",
    subdir: "dag-settled-outbox",
    dir_err: "effect_fact.dag_settled_dir",
    write_err: "effect_fact.dag_settled_write",
    sync_err: "effect_fact.dag_settled_sync",
    rename_err: "effect_fact.dag_settled_rename",
    missing_err: "effect_fact.dag_settled_missing",
    read_err: "effect_fact.dag_settled_read",
    length_err: "effect_fact.dag_settled_length",
    checksum_err: "effect_fact.dag_settled_checksum",
    magic_err: "effect_fact.dag_settled_magic",
    envelope_err: "effect_fact.dag_settled_envelope",
};

/// Parameters constructing one [`DagSettledEffectFact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagSettledEffectFactParts {
    pub settlement_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub activity_id: ActivityId,
    pub goal_id: GoalId,
    pub goal_revision: GoalRevision,
    pub dag_revision: DagRevisionNumber,
    pub settled_file_count: u64,
    pub settled_tree_digest: [u8; DIGEST_BYTES],
    pub coordinator_agent_id: AgentInstanceId,
    pub coordinator_session_id: Option<AgentSessionId>,
    pub settled_at: TimestampMillis,
}

/// Immutable terminal settlement fact emitted when `dag.settle` reaches `Applied`.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DagSettledEffectFact {
    settlement_id: Uuid,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    goal_revision: GoalRevision,
    dag_revision: DagRevisionNumber,
    settled_file_count: u64,
    settled_tree_digest: [u8; DIGEST_BYTES],
    coordinator_agent_id: AgentInstanceId,
    coordinator_session_id: Option<AgentSessionId>,
    settled_at: TimestampMillis,
}

impl DagSettledEffectFact {
    /// Construct and validate a terminal `DagSettled` outbox fact.
    ///
    /// # Errors
    /// Rejects nil identifiers, all-zero tree digests, or file counts exceeding `i64::MAX`.
    pub fn from_parts(parts: DagSettledEffectFactParts) -> Result<Self, EffectFactOutboxError> {
        if parts.settlement_id.is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.settlement_id",
            ));
        }
        if parts.workspace_id.into_uuid().is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.workspace_id",
            ));
        }
        if parts.activity_id.into_uuid().is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.activity_id",
            ));
        }
        if parts.goal_id.into_uuid().is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord("effect_fact.goal_id"));
        }
        if parts.coordinator_agent_id.into_uuid().is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.coordinator_agent_id",
            ));
        }
        if parts
            .coordinator_session_id
            .is_some_and(|id| id.into_uuid().is_nil())
        {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.coordinator_session_id",
            ));
        }
        if parts.settled_tree_digest == [0_u8; DIGEST_BYTES] {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.settled_tree_digest",
            ));
        }
        if i64::try_from(parts.settled_file_count).is_err() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.settled_file_count",
            ));
        }
        Ok(Self {
            settlement_id: parts.settlement_id,
            workspace_id: parts.workspace_id,
            activity_id: parts.activity_id,
            goal_id: parts.goal_id,
            goal_revision: parts.goal_revision,
            dag_revision: parts.dag_revision,
            settled_file_count: parts.settled_file_count,
            settled_tree_digest: parts.settled_tree_digest,
            coordinator_agent_id: parts.coordinator_agent_id,
            coordinator_session_id: parts.coordinator_session_id,
            settled_at: parts.settled_at,
        })
    }

    #[must_use]
    pub const fn settlement_id(self) -> Uuid {
        self.settlement_id
    }

    #[must_use]
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    #[must_use]
    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    #[must_use]
    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    #[must_use]
    pub const fn goal_revision(self) -> GoalRevision {
        self.goal_revision
    }

    #[must_use]
    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }

    #[must_use]
    pub const fn settled_file_count(self) -> u64 {
        self.settled_file_count
    }

    #[must_use]
    pub const fn settled_tree_digest(self) -> [u8; DIGEST_BYTES] {
        self.settled_tree_digest
    }

    #[must_use]
    pub const fn coordinator_agent_id(self) -> AgentInstanceId {
        self.coordinator_agent_id
    }

    #[must_use]
    pub const fn coordinator_session_id(self) -> Option<AgentSessionId> {
        self.coordinator_session_id
    }

    #[must_use]
    pub const fn settled_at(self) -> TimestampMillis {
        self.settled_at
    }
}

pub(crate) fn append_dag_settled(
    connection: &Connection,
    fact: &DagSettledEffectFact,
) -> Result<(), EffectFactOutboxError> {
    if connection.is_autocommit() {
        return Err(EffectFactOutboxError::MissingTransaction);
    }
    let Some(delegation) = source_delegation(connection, fact.workspace_id())? else {
        return Ok(());
    };
    let existing_rows = select_entries_by_kind(connection, fact.workspace_id(), DAG_SETTLED_KIND)?;

    for (seq, migration_id, destination_id) in existing_rows {
        let existing = load(
            connection,
            seq,
            migration_id,
            destination_id,
            fact.workspace_id(),
        )?;
        if existing.settlement_id() == fact.settlement_id()
            || (existing.goal_id() == fact.goal_id()
                && existing.dag_revision() == fact.dag_revision())
        {
            return if &existing == fact
                && migration_id == delegation.migration_id()
                && destination_id == delegation.destination_id()
            {
                Ok(())
            } else {
                Err(EffectFactOutboxError::ReplayConflict)
            };
        }
    }

    let sequence = insert_entry_by_kind(connection, &delegation, DAG_SETTLED_KIND)?;
    let encoded = encode_record(
        sequence,
        delegation.migration_id(),
        delegation.destination_id(),
        fact,
    );
    persist_sidecar(
        connection,
        &SPEC,
        sequence,
        delegation.migration_id(),
        fact.workspace_id(),
        &encoded,
    )
}

pub(super) fn load(
    connection: &Connection,
    sequence: i64,
    expected_migration_id: Uuid,
    expected_destination_id: Uuid,
    expected_workspace_id: WorkspaceId,
) -> Result<DagSettledEffectFact, EffectFactOutboxError> {
    let bytes = read_sidecar::<RECORD_BYTE_LEN>(
        connection,
        &SPEC,
        sequence,
        expected_migration_id,
        expected_workspace_id,
    )?;
    decode_record(
        &bytes,
        sequence,
        expected_migration_id,
        expected_destination_id,
        expected_workspace_id,
    )
}

fn encode_record(
    sequence: i64,
    migration_id: Uuid,
    destination_id: Uuid,
    fact: &DagSettledEffectFact,
) -> [u8; RECORD_BYTE_LEN] {
    encode_record_with::<PAYLOAD_WITHOUT_CHECKSUM_LEN, RECORD_BYTE_LEN>(
        &SPEC,
        sequence,
        migration_id,
        destination_id,
        fact.workspace_id(),
        |writer| {
            writer.push_uuid(fact.settlement_id());
            writer.push_uuid(fact.activity_id().into_uuid());
            writer.push_uuid(fact.goal_id().into_uuid());
            writer.push_i64(fact.goal_revision().get());
            writer.push_i64(fact.dag_revision().get());
            writer.push_u64(fact.settled_file_count());
            writer.push(&fact.settled_tree_digest());
            writer.push_uuid(fact.coordinator_agent_id().into_uuid());
            writer.push_optional_uuid(fact.coordinator_session_id().map(AgentSessionId::into_uuid));
            writer.push_i64(fact.settled_at().get());
        },
    )
}

fn decode_record(
    bytes: &[u8; RECORD_BYTE_LEN],
    expected_sequence: i64,
    expected_migration_id: Uuid,
    expected_destination_id: Uuid,
    expected_workspace_id: WorkspaceId,
) -> Result<DagSettledEffectFact, EffectFactOutboxError> {
    let mut reader = verify_envelope::<PAYLOAD_WITHOUT_CHECKSUM_LEN, RECORD_BYTE_LEN>(
        bytes,
        &SPEC,
        expected_sequence,
        expected_migration_id,
        expected_destination_id,
        expected_workspace_id,
    )?;
    let settlement_id = reader.read_uuid("effect_fact.settlement_id")?;
    let activity_id = ActivityId::from_uuid(reader.read_uuid("effect_fact.activity_id")?);
    let goal_id = GoalId::from_uuid(reader.read_uuid("effect_fact.goal_id")?);
    let goal_revision = GoalRevision::new(reader.read_i64("effect_fact.goal_revision")?)
        .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.goal_revision"))?;
    let dag_revision = DagRevisionNumber::new(reader.read_i64("effect_fact.dag_revision")?)
        .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.dag_revision"))?;
    let settled_file_count = reader.read_u64("effect_fact.settled_file_count")?;
    let settled_tree_digest = reader.read_digest("effect_fact.settled_tree_digest")?;
    let coordinator_agent_id =
        AgentInstanceId::from_uuid(reader.read_uuid("effect_fact.coordinator_agent_id")?);
    let coordinator_session_id = reader
        .read_optional_uuid(
            "effect_fact.coordinator_session_flag",
            "effect_fact.coordinator_session_id",
        )?
        .map(AgentSessionId::from_uuid);
    let settled_at = TimestampMillis::new(reader.read_i64("effect_fact.settled_at")?)
        .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.settled_at"))?;
    reader.ensure_exhausted("effect_fact.dag_settled_trailing_bytes")?;
    DagSettledEffectFact::from_parts(DagSettledEffectFactParts {
        settlement_id,
        workspace_id: expected_workspace_id,
        activity_id,
        goal_id,
        goal_revision,
        dag_revision,
        settled_file_count,
        settled_tree_digest,
        coordinator_agent_id,
        coordinator_session_id,
        settled_at,
    })
}
