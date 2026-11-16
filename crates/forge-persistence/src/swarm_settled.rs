//! Durable `StandaloneSwarm` terminal settlement outbox producer (`fact_kind = 6`).
//!
//! Entries are sequenced atomically in `effect_fact_outbox_entries`
//! (`CHECK(fact_kind BETWEEN 0 AND 7)`) alongside `DAG_SETTLED_KIND = 5`, while
//! keeping `WorkspaceSchemaShape` compatibility via checksummed sidecar records
//! colocated under `<state_dir>/swarm-settled-outbox/`.

use forge_domain::{
    ActivityId, AgentInstanceId, AgentSessionId, SwarmRunId, TimestampMillis, WorkspaceId,
};
use rusqlite::Connection;
use uuid::Uuid;

use crate::workspace_effect_fact_outbox::settled_sidecar::{
    SettledSidecarSpec, encode_record_with, insert_entry_by_kind, persist_sidecar, read_sidecar,
    select_entries_by_kind, select_page_by_kind, verify_envelope,
};
use crate::workspace_effect_fact_outbox::{
    DIGEST_BYTES, EffectFactOutboxError, MAX_PAGE_SIZE, decode_sequence, source_delegation,
};

pub(crate) mod sql;

/// Effect-fact kind tag for `StandaloneSwarm` terminal settlements inside `effect_fact_outbox_entries`.
pub const SWARM_SETTLED_KIND: i64 = 6;

/// Maximum page size accepted by [`query_swarm_settled`], matching the unified effect-fact outbox bound.
pub const MAX_SWARM_SETTLED_QUERY_LIMIT: u32 = MAX_PAGE_SIZE;

const PAYLOAD_WITHOUT_CHECKSUM_LEN: usize = 226;
const RECORD_BYTE_LEN: usize = PAYLOAD_WITHOUT_CHECKSUM_LEN + DIGEST_BYTES;
const SIDECAR_SUBDIR: &str = "swarm-settled-outbox";

const SPEC: SettledSidecarSpec = SettledSidecarSpec {
    fact_kind: SWARM_SETTLED_KIND,
    magic: b"FGSWFCT1",
    subdir: SIDECAR_SUBDIR,
    dir_err: "effect_fact.swarm_settled_dir",
    write_err: "effect_fact.swarm_settled_write",
    sync_err: "effect_fact.swarm_settled_sync",
    rename_err: "effect_fact.swarm_settled_rename",
    missing_err: "effect_fact.swarm_settled_missing",
    read_err: "effect_fact.swarm_settled_read",
    length_err: "effect_fact.swarm_settled_length",
    checksum_err: "effect_fact.swarm_settled_checksum",
    magic_err: "effect_fact.swarm_settled_magic",
    envelope_err: "effect_fact.swarm_settled_envelope",
};

/// Parameters constructing one [`SwarmSettledEffectFact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwarmSettledEffectFactParts {
    pub settlement_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub activity_id: Option<ActivityId>,
    pub swarm_run_id: SwarmRunId,
    pub settled_file_count: u64,
    pub settled_tree_digest: [u8; DIGEST_BYTES],
    pub converged_diff_digest: [u8; DIGEST_BYTES],
    pub coordinator_agent_id: AgentInstanceId,
    pub coordinator_session_id: Option<AgentSessionId>,
    pub settled_at: TimestampMillis,
}

/// Immutable terminal settlement fact emitted when a `StandaloneSwarm` run settles to `<workspace_root>`.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwarmSettledEffectFact {
    settlement_id: Uuid,
    workspace_id: WorkspaceId,
    activity_id: Option<ActivityId>,
    swarm_run_id: SwarmRunId,
    settled_file_count: u64,
    settled_tree_digest: [u8; DIGEST_BYTES],
    converged_diff_digest: [u8; DIGEST_BYTES],
    coordinator_agent_id: AgentInstanceId,
    coordinator_session_id: Option<AgentSessionId>,
    settled_at: TimestampMillis,
}

impl SwarmSettledEffectFact {
    /// Construct and validate a terminal `SwarmSettled` outbox fact.
    ///
    /// # Errors
    /// Rejects nil identifiers, all-zero digests, or file counts exceeding `i64::MAX`.
    pub fn from_parts(parts: SwarmSettledEffectFactParts) -> Result<Self, EffectFactOutboxError> {
        if parts.settlement_id.is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.swarm_settlement_id",
            ));
        }
        if parts.workspace_id.into_uuid().is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.workspace_id",
            ));
        }
        if parts.activity_id.is_some_and(|id| id.into_uuid().is_nil()) {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.activity_id",
            ));
        }
        if parts.swarm_run_id.into_uuid().is_nil() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.swarm_run_id",
            ));
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
        if parts.converged_diff_digest == [0_u8; DIGEST_BYTES] {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.converged_diff_digest",
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
            swarm_run_id: parts.swarm_run_id,
            settled_file_count: parts.settled_file_count,
            settled_tree_digest: parts.settled_tree_digest,
            converged_diff_digest: parts.converged_diff_digest,
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
    pub const fn activity_id(self) -> Option<ActivityId> {
        self.activity_id
    }

    #[must_use]
    pub const fn swarm_run_id(self) -> SwarmRunId {
        self.swarm_run_id
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
    pub const fn converged_diff_digest(self) -> [u8; DIGEST_BYTES] {
        self.converged_diff_digest
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

/// Sequenced outbox record returned when enqueuing or querying `SWARM_SETTLED_KIND = 6` entries.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwarmSettledOutboxEntry {
    sequence: u64,
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    fact: SwarmSettledEffectFact,
}

impl SwarmSettledOutboxEntry {
    fn from_row(
        sequence: i64,
        migration_id: Uuid,
        destination_id: Uuid,
        workspace_id: WorkspaceId,
        fact: SwarmSettledEffectFact,
    ) -> Result<Self, EffectFactOutboxError> {
        Ok(Self {
            sequence: decode_sequence(sequence)?,
            migration_id,
            destination_id,
            workspace_id,
            fact,
        })
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
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

    pub const fn fact(&self) -> &SwarmSettledEffectFact {
        &self.fact
    }
}

/// Atomically enqueue one `SWARM_SETTLED_KIND = 6` outbox fact inside an active caller transaction.
///
/// Returns `Ok(None)` when the workspace has no sealed Agent-operations delegation.
/// Replaying the exact same `(settlement_id, swarm_run_id)` payload is idempotent and returns
/// `Ok(Some(existing))`; mutated replays fail closed with [`EffectFactOutboxError::ReplayConflict`].
pub fn enqueue_swarm_settled(
    connection: &Connection,
    fact: &SwarmSettledEffectFact,
) -> Result<Option<SwarmSettledOutboxEntry>, EffectFactOutboxError> {
    if connection.is_autocommit() {
        return Err(EffectFactOutboxError::MissingTransaction);
    }
    let Some(delegation) = source_delegation(connection, fact.workspace_id())? else {
        return Ok(None);
    };

    let existing_rows =
        select_entries_by_kind(connection, fact.workspace_id(), SWARM_SETTLED_KIND)?;

    for (seq, migration_id, destination_id) in existing_rows {
        let existing = load_record(
            connection,
            seq,
            migration_id,
            destination_id,
            fact.workspace_id(),
        )?;
        if existing.settlement_id() == fact.settlement_id()
            || existing.swarm_run_id() == fact.swarm_run_id()
        {
            if &existing == fact
                && migration_id == delegation.migration_id()
                && destination_id == delegation.destination_id()
            {
                return SwarmSettledOutboxEntry::from_row(
                    seq,
                    migration_id,
                    destination_id,
                    fact.workspace_id(),
                    existing,
                )
                .map(Some);
            }
            return Err(EffectFactOutboxError::ReplayConflict);
        }
    }

    let sequence = insert_entry_by_kind(connection, &delegation, SWARM_SETTLED_KIND)?;
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
    )?;

    SwarmSettledOutboxEntry::from_row(
        sequence,
        delegation.migration_id(),
        delegation.destination_id(),
        fact.workspace_id(),
        *fact,
    )
    .map(Some)
}

/// Query one bounded page of `SWARM_SETTLED_KIND = 6` outbox entries for `workspace_id`
/// strictly after `after` (with `limit` clamped/validated in `1..=MAX_SWARM_SETTLED_QUERY_LIMIT`),
/// verifying every sidecar checksum and envelope.
pub fn query_swarm_settled(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: u64,
    limit: u32,
) -> Result<Vec<SwarmSettledOutboxEntry>, EffectFactOutboxError> {
    if limit == 0 || limit > MAX_SWARM_SETTLED_QUERY_LIMIT {
        return Err(EffectFactOutboxError::InvalidLimit { limit });
    }
    let rows = select_page_by_kind(connection, workspace_id, SWARM_SETTLED_KIND, after, limit)?;

    rows.into_iter()
        .map(|(sequence, migration_id, destination_id)| {
            let fact = load_record(
                connection,
                sequence,
                migration_id,
                destination_id,
                workspace_id,
            )?;
            SwarmSettledOutboxEntry::from_row(
                sequence,
                migration_id,
                destination_id,
                workspace_id,
                fact,
            )
        })
        .collect()
}

pub(crate) fn load_record(
    connection: &Connection,
    sequence: i64,
    expected_migration_id: Uuid,
    expected_destination_id: Uuid,
    expected_workspace_id: WorkspaceId,
) -> Result<SwarmSettledEffectFact, EffectFactOutboxError> {
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
    fact: &SwarmSettledEffectFact,
) -> [u8; RECORD_BYTE_LEN] {
    encode_record_with::<PAYLOAD_WITHOUT_CHECKSUM_LEN, RECORD_BYTE_LEN>(
        &SPEC,
        sequence,
        migration_id,
        destination_id,
        fact.workspace_id(),
        |writer| {
            writer.push_uuid(fact.settlement_id());
            writer.push_optional_uuid(fact.activity_id().map(ActivityId::into_uuid));
            writer.push_uuid(fact.swarm_run_id().into_uuid());
            writer.push_u64(fact.settled_file_count());
            writer.push(&fact.settled_tree_digest());
            writer.push(&fact.converged_diff_digest());
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
) -> Result<SwarmSettledEffectFact, EffectFactOutboxError> {
    let mut reader = verify_envelope::<PAYLOAD_WITHOUT_CHECKSUM_LEN, RECORD_BYTE_LEN>(
        bytes,
        &SPEC,
        expected_sequence,
        expected_migration_id,
        expected_destination_id,
        expected_workspace_id,
    )?;
    let settlement_id = reader.read_uuid("effect_fact.swarm_settlement_id")?;
    let activity_id = reader
        .read_optional_uuid("effect_fact.activity_flag", "effect_fact.activity_id")?
        .map(ActivityId::from_uuid);
    let swarm_run_id = SwarmRunId::from_uuid(reader.read_uuid("effect_fact.swarm_run_id")?);
    let settled_file_count = reader.read_u64("effect_fact.settled_file_count")?;
    let settled_tree_digest = reader.read_digest("effect_fact.settled_tree_digest")?;
    let converged_diff_digest = reader.read_digest("effect_fact.converged_diff_digest")?;
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
    reader.ensure_exhausted("effect_fact.swarm_settled_trailing_bytes")?;
    SwarmSettledEffectFact::from_parts(SwarmSettledEffectFactParts {
        settlement_id,
        workspace_id: expected_workspace_id,
        activity_id,
        swarm_run_id,
        settled_file_count,
        settled_tree_digest,
        converged_diff_digest,
        coordinator_agent_id,
        coordinator_session_id,
        settled_at,
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;

    use forge_domain::{
        ActivityId, AgentInstanceId, AgentSessionId, BootstrapActivity, EstablishWorkspace,
        LocationId, RuntimeInstanceId, SwarmRunId, TimestampMillis, WorkspaceId, WorkspaceRevision,
        WorkspaceRoot,
    };
    use forge_workspace::WorkspaceStateLayout;
    use uuid::Uuid;

    use super::*;
    use crate::{
        AgentOperationsFreezeRequest, DAG_SETTLED_KIND, EffectFact, EffectFactOutboxError,
        WorkspaceStore, WorkspaceStoreError,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    struct Fixture {
        root: PathBuf,
        layout: WorkspaceStateLayout,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn id(seed: u128) -> Uuid {
        Uuid::from_u128(seed)
    }

    fn ts(ms: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(ms)?)
    }

    fn fixture(label: &str) -> TestResult<Fixture> {
        let root =
            std::env::temp_dir().join(format!("forge-swarm-settled-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(id(0xE100));
        let activity_id = ActivityId::from_uuid(id(0xE101));
        let command = EstablishWorkspace::new(
            workspace_id,
            LocationId::from_uuid(id(0xE102)),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            ts(1)?,
        );
        let mut store = WorkspaceStore::open(&layout, &command)?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            RuntimeInstanceId::from_uuid(id(0xE103)),
            ts(100)?,
            ts(2)?,
        ))?;
        drop(store);
        Ok(Fixture {
            root,
            layout,
            workspace_id,
            activity_id,
        })
    }

    fn reopen(fixture: &Fixture) -> TestResult<WorkspaceStore> {
        let existing = WorkspaceStateLayout::inspect_existing(fixture.layout.workspace_root())?
            .ok_or("workspace state layout missing")?;
        Ok(WorkspaceStore::open_existing(&existing)?)
    }

    #[test]
    fn swarm_settled_kind_six_outbox_enqueues_replays_reads_and_detects_conflicts() -> TestResult {
        assert_eq!(DAG_SETTLED_KIND, 5);
        assert_eq!(SWARM_SETTLED_KIND, 6);

        let fixture = fixture("roundtrip")?;
        let mut store = reopen(&fixture)?;
        let fact = SwarmSettledEffectFact::from_parts(SwarmSettledEffectFactParts {
            settlement_id: id(0xE200),
            workspace_id: fixture.workspace_id,
            activity_id: Some(fixture.activity_id),
            swarm_run_id: SwarmRunId::from_uuid(id(0xE201)),
            settled_file_count: 4,
            settled_tree_digest: [0x11; 32],
            converged_diff_digest: [0x22; 32],
            coordinator_agent_id: AgentInstanceId::from_uuid(id(0xE202)),
            coordinator_session_id: Some(AgentSessionId::from_uuid(id(0xE203))),
            settled_at: ts(30)?,
        })?;

        // Non-delegated workspace is a clean no-op.
        assert!(store.append_swarm_settled_effect_fact(&fact)?.is_none());
        assert!(store.swarm_settled_effect_facts(0, 16)?.is_empty());

        let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            id(0xE210),
            id(0xE211),
            ts(4)?,
        )?)?;
        let delegation = store.delegate_agent_operations(&freeze, [0x71; 32], ts(20)?)?;

        // First enqueue emits one SWARM_SETTLED_KIND = 6 row; exact replay is idempotent.
        let first = store
            .append_swarm_settled_effect_fact(&fact)?
            .ok_or("expected enqueued swarm settled outbox entry")?;
        let replay = store
            .append_swarm_settled_effect_fact(&fact)?
            .ok_or("expected idempotent replay entry")?;
        assert_eq!(first, replay);
        assert_eq!(first.migration_id(), delegation.migration_id());
        assert_eq!(first.destination_id(), delegation.destination_id());
        assert_eq!(first.fact(), &fact);

        // Readback page returns exact fact on both specialized and unified effect-fact outbox streams.
        let entries = store.swarm_settled_effect_facts(0, 16)?;
        assert_eq!(entries, vec![first]);
        let unified = store.effect_fact_outbox(0, 16)?;
        assert_eq!(unified.len(), 1);
        assert_eq!(unified[0].sequence(), first.sequence());
        assert_eq!(unified[0].fact(), &EffectFact::SwarmSettled(Box::new(fact)));
        assert!(
            store
                .swarm_settled_effect_facts(first.sequence(), 16)?
                .is_empty()
        );

        // Second distinct swarm run appends sequentially with SWARM_SETTLED_KIND = 6.
        let second_fact = SwarmSettledEffectFact::from_parts(SwarmSettledEffectFactParts {
            settlement_id: id(0xE300),
            workspace_id: fixture.workspace_id,
            activity_id: None,
            swarm_run_id: SwarmRunId::from_uuid(id(0xE301)),
            settled_file_count: 2,
            settled_tree_digest: [0x33; 32],
            converged_diff_digest: [0x44; 32],
            coordinator_agent_id: AgentInstanceId::from_uuid(id(0xE302)),
            coordinator_session_id: None,
            settled_at: ts(40)?,
        })?;
        let second = store
            .append_swarm_settled_effect_fact(&second_fact)?
            .ok_or("expected second swarm settled entry")?;
        assert!(second.sequence() > first.sequence());
        let all = store.swarm_settled_effect_facts(0, 16)?;
        assert_eq!(all, vec![first, second]);

        // Mutated replay for the same settlement/swarm_run fails closed with ReplayConflict.
        let conflicting = SwarmSettledEffectFact::from_parts(SwarmSettledEffectFactParts {
            settlement_id: id(0xE200),
            workspace_id: fixture.workspace_id,
            activity_id: Some(fixture.activity_id),
            swarm_run_id: SwarmRunId::from_uuid(id(0xE201)),
            settled_file_count: 9,
            settled_tree_digest: [0x55; 32],
            converged_diff_digest: [0x66; 32],
            coordinator_agent_id: AgentInstanceId::from_uuid(id(0xE202)),
            coordinator_session_id: Some(AgentSessionId::from_uuid(id(0xE203))),
            settled_at: ts(30)?,
        })?;
        assert!(matches!(
            store.append_swarm_settled_effect_fact(&conflicting),
            Err(WorkspaceStoreError::EffectFactOutbox(
                EffectFactOutboxError::ReplayConflict
            ))
        ));

        // Corrupting the sidecar checksum fails closed on readback.
        let sidecar_path = fixture
            .layout
            .state_root()
            .join(SIDECAR_SUBDIR)
            .join(format!("seq-{}.fact", first.sequence()));
        let mut raw = fs::read(&sidecar_path)?;
        raw[PAYLOAD_WITHOUT_CHECKSUM_LEN] ^= 0xFF;
        fs::write(&sidecar_path, raw)?;
        assert!(matches!(
            store.swarm_settled_effect_facts(0, 16),
            Err(WorkspaceStoreError::EffectFactOutbox(
                EffectFactOutboxError::CorruptRecord("effect_fact.swarm_settled_checksum")
            ))
        ));
        Ok(())
    }

    #[test]
    fn query_swarm_settled_rejects_invalid_limits() -> TestResult {
        let fixture = fixture("limits")?;
        let store = reopen(&fixture)?;
        assert!(matches!(
            store.swarm_settled_effect_facts(0, 0),
            Err(WorkspaceStoreError::EffectFactOutbox(
                EffectFactOutboxError::InvalidLimit { limit: 0 }
            ))
        ));
        assert!(matches!(
            store.swarm_settled_effect_facts(0, MAX_SWARM_SETTLED_QUERY_LIMIT + 1),
            Err(WorkspaceStoreError::EffectFactOutbox(
                EffectFactOutboxError::InvalidLimit { limit }
            )) if limit == MAX_SWARM_SETTLED_QUERY_LIMIT + 1
        ));
        Ok(())
    }

    #[test]
    fn decode_rejects_trailing_envelope_bytes_and_sequence_overflow() -> TestResult {
        let bytes = [0_u8; RECORD_BYTE_LEN];
        let reader = crate::workspace_effect_fact_outbox::settled_sidecar::ByteReader::from_slice(
            &bytes[..4],
        );
        assert!(matches!(
            reader.ensure_exhausted("effect_fact.swarm_settled_trailing_bytes"),
            Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.swarm_settled_trailing_bytes"
            ))
        ));
        assert!(matches!(
            decode_sequence(0),
            Err(EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))
        ));
        assert!(matches!(
            decode_sequence(-1),
            Err(EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))
        ));
        assert_eq!(decode_sequence(7)?, 7);
        Ok(())
    }
}
