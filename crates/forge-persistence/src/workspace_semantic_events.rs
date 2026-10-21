//! Durable, per-Workspace semantic event stream for authoritative lifecycle
//! transitions.
//!
//! Every row is appended inside the exact caller transaction that performs the
//! authoritative state transition, so the stream is atomic with Workspace
//! truth: a rolled-back transition never leaves an event behind. Sequences are
//! allocated from a per-Workspace high-water mark that only ever advances in
//! the same transaction, so sequences are monotonic and never reused. Payload
//! state is intentionally not duplicated; the digest commits only to the
//! canonical subject identity of the transition.

use forge_domain::{
    ActivityId, ChangeSetId, DagNodeId, DagRevisionNumber, DiffId, ExecutionId, GoalId,
    TimestampMillis, VerificationInputId, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_dags;

const MAX_PAGE_SIZE: u32 = 64;
/// Maximum Goal summaries carried by one Workspace semantic snapshot.
pub const MAX_WORKSPACE_SNAPSHOT_GOAL_SUMMARIES: u32 = MAX_PAGE_SIZE;
const UUID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;

/// Domain-separated canonical identity preimage. The digest commits to the
/// event kind tag, Workspace identity, present subject identities, and the
/// subject revision; it never duplicates transition payload state.
const IDENTITY_DIGEST_DOMAIN: &[u8] = b"heterarchy-forge.semantic-event.v1\0";

const EVENTS_SQL: &str = "CREATE TABLE semantic_events (sequence INTEGER PRIMARY KEY NOT NULL CHECK(sequence >= 1), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), event_kind TEXT NOT NULL CHECK(event_kind IN ('goal_created','goal_updated','goal_completed','dag_committed','node_transition','plan_published','execution_begun','execution_terminal','changeset_terminal','diff_terminal','verification_finalized')), subject_goal_id BLOB CHECK(subject_goal_id IS NULL OR (length(subject_goal_id) = 16 AND subject_goal_id != zeroblob(16))), subject_dag_revision INTEGER CHECK(subject_dag_revision IS NULL OR subject_dag_revision >= 1), subject_node_id BLOB CHECK(subject_node_id IS NULL OR (length(subject_node_id) = 16 AND subject_node_id != zeroblob(16))), subject_execution_id BLOB CHECK(subject_execution_id IS NULL OR (length(subject_execution_id) = 16 AND subject_execution_id != zeroblob(16))), subject_change_set_id BLOB CHECK(subject_change_set_id IS NULL OR (length(subject_change_set_id) = 16 AND subject_change_set_id != zeroblob(16))), subject_diff_id BLOB CHECK(subject_diff_id IS NULL OR (length(subject_diff_id) = 16 AND subject_diff_id != zeroblob(16))), subject_verification BLOB CHECK(subject_verification IS NULL OR (length(subject_verification) = 16 AND subject_verification != zeroblob(16))), revision INTEGER NOT NULL CHECK(revision >= 1), payload_digest BLOB(32) NOT NULL CHECK(length(payload_digest) = 32), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0))";
const META_SQL: &str = "CREATE TABLE semantic_events_meta (workspace_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), high_water_seq INTEGER NOT NULL CHECK(high_water_seq >= 0), retained_low INTEGER NOT NULL CHECK(retained_low >= 0))";
const WORKSPACE_SEQUENCE_INDEX_SQL: &str = "CREATE INDEX semantic_events_workspace_sequence_idx ON semantic_events(workspace_id, sequence)";

const OBJECTS: [(&str, &str, &str); 3] = [
    ("table", "semantic_events", EVENTS_SQL),
    ("table", "semantic_events_meta", META_SQL),
    (
        "index",
        "semantic_events_workspace_sequence_idx",
        WORKSPACE_SEQUENCE_INDEX_SQL,
    ),
];

/// Subject identities carried by one semantic event. Absent subjects stay
/// `None`; the durable row encodes them as SQL `NULL` columns.
#[must_use]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticEventSubjects {
    pub goal_id: Option<GoalId>,
    pub dag_revision: Option<DagRevisionNumber>,
    pub node_id: Option<DagNodeId>,
    pub execution_id: Option<ExecutionId>,
    pub change_set_id: Option<ChangeSetId>,
    pub diff_id: Option<DiffId>,
    pub verification: Option<VerificationInputId>,
}

impl SemanticEventSubjects {
    /// The all-absent subject set.
    pub const NONE: Self = Self {
        goal_id: None,
        dag_revision: None,
        node_id: None,
        execution_id: None,
        change_set_id: None,
        diff_id: None,
        verification: None,
    };
}

/// One authoritative Workspace lifecycle transition recorded in the durable
/// semantic event stream. The payload digest is derived by [`Self::new`] from
/// the canonical subject identity; append sites never invent another digest.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticEventAppend {
    kind: SemanticEventKind,
    workspace_id: WorkspaceId,
    subjects: SemanticEventSubjects,
    revision: i64,
    payload_digest: [u8; DIGEST_BYTES],
    observed_at: TimestampMillis,
}

impl SemanticEventAppend {
    /// Build one append input and derive its payload digest from the canonical
    /// subject identity (kind tag + Workspace + subject ids + revision).
    pub fn new(
        kind: SemanticEventKind,
        workspace_id: WorkspaceId,
        subjects: SemanticEventSubjects,
        revision: i64,
        observed_at: TimestampMillis,
    ) -> Self {
        let mut event = Self {
            kind,
            workspace_id,
            subjects,
            revision,
            payload_digest: [0; DIGEST_BYTES],
            observed_at,
        };
        event.payload_digest = event.identity_digest();
        event
    }

    pub const fn kind(&self) -> SemanticEventKind {
        self.kind
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn subjects(&self) -> &SemanticEventSubjects {
        &self.subjects
    }

    pub const fn revision(&self) -> i64 {
        self.revision
    }

    /// SHA-256 over the canonical subject identity of the transition.
    pub const fn payload_digest(&self) -> [u8; DIGEST_BYTES] {
        self.payload_digest
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    fn identity_digest(&self) -> [u8; DIGEST_BYTES] {
        let workspace_uuid = self.workspace_id.into_uuid();
        let goal_uuid = self.subjects.goal_id.map(forge_domain::GoalId::into_uuid);
        let node_uuid = self
            .subjects
            .node_id
            .map(forge_domain::DagNodeId::into_uuid);
        let execution_uuid = self
            .subjects
            .execution_id
            .map(forge_domain::ExecutionId::into_uuid);
        let change_set_uuid = self
            .subjects
            .change_set_id
            .map(forge_domain::ChangeSetId::into_uuid);
        let diff_uuid = self.subjects.diff_id.map(forge_domain::DiffId::into_uuid);
        let verification_uuid = self
            .subjects
            .verification
            .map(forge_domain::VerificationInputId::into_uuid);
        let mut hash = Sha256::new();
        hash.update(IDENTITY_DIGEST_DOMAIN);
        hash.update([self.kind.tag()]);
        hash.update(workspace_uuid.as_bytes());
        hash.update(optional_id_bytes(
            goal_uuid.as_ref().map(|id| *id.as_bytes()),
        ));
        hash.update(optional_revision_bytes(
            self.subjects.dag_revision.map(DagRevisionNumber::get),
        ));
        hash.update(optional_id_bytes(
            node_uuid.as_ref().map(|id| *id.as_bytes()),
        ));
        hash.update(optional_id_bytes(
            execution_uuid.as_ref().map(|id| *id.as_bytes()),
        ));
        hash.update(optional_id_bytes(
            change_set_uuid.as_ref().map(|id| *id.as_bytes()),
        ));
        hash.update(optional_id_bytes(
            diff_uuid.as_ref().map(|id| *id.as_bytes()),
        ));
        hash.update(optional_id_bytes(
            verification_uuid.as_ref().map(|id| *id.as_bytes()),
        ));
        hash.update(self.revision.to_be_bytes());
        hash.finalize().into()
    }
}

fn optional_id_bytes(id: Option<[u8; UUID_BYTES]>) -> [u8; UUID_BYTES + 1] {
    let mut encoded = [0; UUID_BYTES + 1];
    if let Some(bytes) = id {
        encoded[0] = 1;
        encoded[1..].copy_from_slice(&bytes);
    }
    encoded
}

fn optional_revision_bytes(revision: Option<i64>) -> [u8; 9] {
    let mut encoded = [0; 9];
    if let Some(value) = revision {
        encoded[0] = 1;
        encoded[1..].copy_from_slice(&value.to_be_bytes());
    }
    encoded
}

/// Closed set of durable semantic transition kinds.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticEventKind {
    GoalCreated,
    GoalUpdated,
    GoalCompleted,
    DagCommitted,
    NodeTransition,
    PlanPublished,
    ExecutionBegun,
    ExecutionTerminal,
    ChangeSetTerminal,
    DiffTerminal,
    VerificationFinalized,
}

impl SemanticEventKind {
    const fn tag(self) -> u8 {
        match self {
            Self::GoalCreated => 0,
            Self::GoalUpdated => 1,
            Self::GoalCompleted => 2,
            Self::DagCommitted => 3,
            Self::NodeTransition => 4,
            Self::PlanPublished => 5,
            Self::ExecutionBegun => 6,
            Self::ExecutionTerminal => 7,
            Self::ChangeSetTerminal => 8,
            Self::DiffTerminal => 9,
            Self::VerificationFinalized => 10,
        }
    }

    /// Durable TEXT encoding used by the `semantic_events` CHECK contract.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoalCreated => "goal_created",
            Self::GoalUpdated => "goal_updated",
            Self::GoalCompleted => "goal_completed",
            Self::DagCommitted => "dag_committed",
            Self::NodeTransition => "node_transition",
            Self::PlanPublished => "plan_published",
            Self::ExecutionBegun => "execution_begun",
            Self::ExecutionTerminal => "execution_terminal",
            Self::ChangeSetTerminal => "changeset_terminal",
            Self::DiffTerminal => "diff_terminal",
            Self::VerificationFinalized => "verification_finalized",
        }
    }

    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "goal_created" => Some(Self::GoalCreated),
            "goal_updated" => Some(Self::GoalUpdated),
            "goal_completed" => Some(Self::GoalCompleted),
            "dag_committed" => Some(Self::DagCommitted),
            "node_transition" => Some(Self::NodeTransition),
            "plan_published" => Some(Self::PlanPublished),
            "execution_begun" => Some(Self::ExecutionBegun),
            "execution_terminal" => Some(Self::ExecutionTerminal),
            "changeset_terminal" => Some(Self::ChangeSetTerminal),
            "diff_terminal" => Some(Self::DiffTerminal),
            "verification_finalized" => Some(Self::VerificationFinalized),
            _ => None,
        }
    }
}

/// One durable semantic event read back from the stream with its allocated
/// sequence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticEventRecord {
    sequence: u64,
    event: SemanticEventAppend,
}

impl SemanticEventRecord {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn event(&self) -> &SemanticEventAppend {
        &self.event
    }
}

/// Bounded read result: strictly-ordered events after the caller cursor plus
/// the durable cursor metadata for the Workspace.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticEventPage {
    events: Vec<SemanticEventRecord>,
    high_water: u64,
    retained_low: u64,
}

impl SemanticEventPage {
    pub fn events(&self) -> &[SemanticEventRecord] {
        &self.events
    }

    /// Highest sequence ever allocated for this Workspace; the next append
    /// allocates `high_water + 1`.
    pub const fn high_water(&self) -> u64 {
        self.high_water
    }

    /// Lowest sequence still retained for this Workspace. Pruning is not part
    /// of this slice, so this stays at the initial floor while `retained_low`
    /// plumbing remains in place for the future pruning owner.
    pub const fn retained_low(&self) -> u64 {
        self.retained_low
    }
}

/// Append one semantic event inside the caller-owned transaction and advance
/// the Workspace high-water sequence in the same transaction. Returns the
/// allocated sequence; a rollback removes both the event and the allocation.
pub(crate) fn append_semantic_event(
    connection: &Connection,
    event: &SemanticEventAppend,
) -> Result<i64, SemanticEventError> {
    if connection.is_autocommit() {
        return Err(SemanticEventError::MissingTransaction);
    }
    let workspace_uuid = event.workspace_id().into_uuid();
    let workspace_bytes = workspace_uuid.as_bytes();
    let goal_uuid = event
        .subjects()
        .goal_id
        .map(forge_domain::GoalId::into_uuid);
    let node_uuid = event
        .subjects()
        .node_id
        .map(forge_domain::DagNodeId::into_uuid);
    let execution_uuid = event
        .subjects()
        .execution_id
        .map(forge_domain::ExecutionId::into_uuid);
    let change_set_uuid = event
        .subjects()
        .change_set_id
        .map(forge_domain::ChangeSetId::into_uuid);
    let diff_uuid = event
        .subjects()
        .diff_id
        .map(forge_domain::DiffId::into_uuid);
    let verification_uuid = event
        .subjects()
        .verification
        .map(forge_domain::VerificationInputId::into_uuid);
    let high_water = high_water_seq(connection, event.workspace_id())?;
    let sequence = high_water
        .checked_add(1)
        .ok_or(SemanticEventError::SequenceOverflow)?;
    let sequence = i64::try_from(sequence).map_err(|_| SemanticEventError::SequenceOverflow)?;
    connection.execute(
        "INSERT INTO semantic_events(
            sequence, workspace_id, event_kind, subject_goal_id, subject_dag_revision,
            subject_node_id, subject_execution_id, subject_change_set_id, subject_diff_id,
            subject_verification, revision, payload_digest, observed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            sequence,
            workspace_bytes,
            event.kind().as_str(),
            goal_uuid.as_ref().map(Uuid::as_bytes),
            event.subjects().dag_revision.map(DagRevisionNumber::get),
            node_uuid.as_ref().map(Uuid::as_bytes),
            execution_uuid.as_ref().map(Uuid::as_bytes),
            change_set_uuid.as_ref().map(Uuid::as_bytes),
            diff_uuid.as_ref().map(Uuid::as_bytes),
            verification_uuid.as_ref().map(Uuid::as_bytes),
            event.revision(),
            event.payload_digest().as_slice(),
            event.observed_at().get(),
        ],
    )?;
    connection.execute(
        "INSERT INTO semantic_events_meta(workspace_id, high_water_seq, retained_low)
         VALUES (?1, ?2, 0)
         ON CONFLICT(workspace_id) DO UPDATE SET high_water_seq = excluded.high_water_seq",
        params![workspace_bytes, sequence],
    )?;
    Ok(sequence)
}

/// Read one bounded, strictly-ordered page of semantic events strictly after
/// `after`, plus the durable cursor metadata. Pure read; never mutates state.
type RawEventRow = (
    i64,
    String,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    Vec<u8>,
    i64,
);

pub(crate) fn semantic_events_after(
    connection: &Connection,
    workspace_id: WorkspaceId,
    after: u64,
    limit: u32,
) -> Result<SemanticEventPage, SemanticEventError> {
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(SemanticEventError::InvalidLimit { limit });
    }
    let high_water = high_water_seq(connection, workspace_id)?;
    let retained_low = retained_low(connection, workspace_id)?;
    let after = i64::try_from(after).map_err(|_| SemanticEventError::InvalidCursor)?;
    let mut statement = connection.prepare(
        "SELECT sequence, event_kind, subject_goal_id, subject_dag_revision, subject_node_id,
                subject_execution_id, subject_change_set_id, subject_diff_id, subject_verification,
                revision, payload_digest, observed_at_ms
         FROM semantic_events
         WHERE workspace_id = ?1 AND sequence > ?2
         ORDER BY sequence ASC
         LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![workspace_id.into_uuid().as_bytes(), after, limit],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, i64>(11)?,
            ))
        },
    )?;
    let mut events = Vec::new();
    for row in rows {
        let (sequence, event) = decode_event_row(workspace_id, row?)?;
        events.push(SemanticEventRecord { sequence, event });
    }
    Ok(SemanticEventPage {
        events,
        high_water,
        retained_low,
    })
}

/// Decode and integrity-check one durable row against its canonical identity
/// digest.
fn decode_event_row(
    workspace_id: WorkspaceId,
    row: RawEventRow,
) -> Result<(u64, SemanticEventAppend), SemanticEventError> {
    let (
        sequence,
        kind,
        goal_id,
        dag_revision,
        node_id,
        execution_id,
        change_set_id,
        diff_id,
        verification,
        revision,
        digest,
        observed_at_ms,
    ) = row;
    let sequence = u64::try_from(sequence)
        .map_err(|_| SemanticEventError::CorruptRecord("semantic_events.sequence"))?;
    let kind = SemanticEventKind::from_name(&kind).ok_or(SemanticEventError::CorruptRecord(
        "semantic_events.event_kind",
    ))?;
    if revision < 1 {
        return Err(SemanticEventError::CorruptRecord(
            "semantic_events.revision",
        ));
    }
    let event = SemanticEventAppend {
        kind,
        workspace_id,
        subjects: SemanticEventSubjects {
            goal_id: decode_optional_id(goal_id.as_deref(), "semantic_events.subject_goal_id")?
                .map(GoalId::from_uuid),
            dag_revision: decode_optional_revision(dag_revision)?,
            node_id: decode_optional_id(node_id.as_deref(), "semantic_events.subject_node_id")?
                .map(DagNodeId::from_uuid),
            execution_id: decode_optional_id(
                execution_id.as_deref(),
                "semantic_events.subject_execution_id",
            )?
            .map(ExecutionId::from_uuid),
            change_set_id: decode_optional_id(
                change_set_id.as_deref(),
                "semantic_events.subject_change_set_id",
            )?
            .map(ChangeSetId::from_uuid),
            diff_id: decode_optional_id(diff_id.as_deref(), "semantic_events.subject_diff_id")?
                .map(DiffId::from_uuid),
            verification: decode_optional_id(
                verification.as_deref(),
                "semantic_events.subject_verification",
            )?
            .map(VerificationInputId::from_uuid),
        },
        revision,
        payload_digest: decode_digest(&digest)?,
        observed_at: TimestampMillis::new(observed_at_ms)
            .map_err(|_| SemanticEventError::CorruptRecord("semantic_events.observed_at_ms"))?,
    };
    if event.identity_digest() != event.payload_digest {
        return Err(SemanticEventError::CorruptRecord(
            "semantic_events.payload_digest",
        ));
    }
    Ok((sequence, event))
}

fn high_water_seq(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<u64, SemanticEventError> {
    let high_water: Option<i64> = connection
        .query_row(
            "SELECT high_water_seq FROM semantic_events_meta WHERE workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    match high_water {
        None => Ok(0),
        Some(value) => u64::try_from(value)
            .map_err(|_| SemanticEventError::CorruptRecord("semantic_events_meta.high_water_seq")),
    }
}

fn retained_low(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<u64, SemanticEventError> {
    let retained: Option<i64> = connection
        .query_row(
            "SELECT retained_low FROM semantic_events_meta WHERE workspace_id = ?1",
            params![workspace_id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    match retained {
        None => Ok(0),
        Some(value) => u64::try_from(value)
            .map_err(|_| SemanticEventError::CorruptRecord("semantic_events_meta.retained_low")),
    }
}

fn decode_optional_id(
    bytes: Option<&[u8]>,
    field: &'static str,
) -> Result<Option<Uuid>, SemanticEventError> {
    bytes
        .map(Uuid::from_slice)
        .transpose()
        .map_err(|_| SemanticEventError::CorruptRecord(field))
}

fn decode_optional_revision(
    value: Option<i64>,
) -> Result<Option<DagRevisionNumber>, SemanticEventError> {
    value
        .map(DagRevisionNumber::new)
        .transpose()
        .map_err(|_| SemanticEventError::CorruptRecord("semantic_events.subject_dag_revision"))
}

fn decode_digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], SemanticEventError> {
    match <[u8; DIGEST_BYTES]>::try_from(bytes) {
        Ok(digest) => Ok(digest),
        Err(_) => Err(SemanticEventError::CorruptRecord(
            "semantic_events.payload_digest",
        )),
    }
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), SemanticEventError> {
    connection.execute_batch(EVENTS_SQL)?;
    connection.execute_batch(META_SQL)?;
    connection.execute_batch(WORKSPACE_SEQUENCE_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 3] {
    [
        ("table", "semantic_events"),
        ("table", "semantic_events_meta"),
        ("index", "semantic_events_workspace_sequence_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), SemanticEventError> {
    for &(kind, name, expected_sql) in &OBJECTS {
        let sql_length: Option<i64> = connection
            .query_row(
                "SELECT length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if sql_length.is_none() {
            return Err(SemanticEventError::DamagedSchema(name));
        }
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(SemanticEventError::DamagedSchema(name));
        }
    }
    Ok(())
}

fn normalize_sql(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

#[derive(Debug, Error)]
pub enum SemanticEventError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("semantic event append requires the caller-owned transaction")]
    MissingTransaction,
    #[error("semantic event sequence exceeds SQLite range")]
    SequenceOverflow,
    #[error("semantic event cursor exceeds SQLite range")]
    InvalidCursor,
    #[error("semantic event or snapshot limit {limit} is outside 1..={MAX_PAGE_SIZE}")]
    InvalidLimit { limit: u32 },
    #[error("semantic event schema object is damaged: {0}")]
    DamagedSchema(&'static str),
    #[error("semantic event record is corrupt: {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::TransactionBehavior;

    fn workspace() -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(0x5E01))
    }

    fn goal() -> GoalId {
        GoalId::from_uuid(Uuid::from_u128(0x5E02))
    }

    fn sample_event(
        kind: SemanticEventKind,
        revision: i64,
    ) -> Result<SemanticEventAppend, Box<dyn std::error::Error>> {
        Ok(SemanticEventAppend::new(
            kind,
            workspace(),
            SemanticEventSubjects {
                goal_id: Some(goal()),
                ..SemanticEventSubjects::NONE
            },
            revision,
            TimestampMillis::new(12)?,
        ))
    }

    fn event_stream_fixture() -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("CREATE TABLE workspace (workspace_id BLOB PRIMARY KEY)")?;
        connection.execute(
            "INSERT INTO workspace VALUES (?1)",
            params![workspace().into_uuid().as_bytes()],
        )?;
        create_schema(&connection)?;
        Ok(connection)
    }

    fn snapshot_fixture() -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = event_stream_fixture()?;
        connection.execute_batch(
            "CREATE TABLE goals(
                 goal_id BLOB PRIMARY KEY,
                 workspace_id BLOB NOT NULL,
                 activity_id BLOB NOT NULL,
                 revision INTEGER NOT NULL,
                 state INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL
             );
             CREATE TABLE goal_dag_heads(
                 goal_id BLOB PRIMARY KEY,
                 dag_revision INTEGER NOT NULL,
                 head_revision INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL
             )",
        )?;
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0x5E03));
        let second_goal = GoalId::from_uuid(Uuid::from_u128(0x5E04));
        connection.execute(
            "INSERT INTO goals(goal_id,workspace_id,activity_id,revision,state,updated_at_ms)
             VALUES(?1,?2,?3,1,0,20), (?4,?2,?3,1,0,10)",
            params![
                goal().into_uuid().as_bytes(),
                workspace().into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                second_goal.into_uuid().as_bytes(),
            ],
        )?;
        Ok(connection)
    }

    #[test]
    fn identity_digest_commits_to_kind_subjects_and_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = sample_event(SemanticEventKind::GoalCreated, 3)?;
        assert_ne!(
            base.payload_digest(),
            sample_event(SemanticEventKind::GoalUpdated, 3)?.payload_digest(),
            "kind must be part of the canonical identity"
        );
        assert_ne!(
            base.payload_digest(),
            sample_event(SemanticEventKind::GoalCreated, 4)?.payload_digest(),
            "revision must be part of the canonical identity"
        );
        let with_node = SemanticEventAppend::new(
            SemanticEventKind::GoalCreated,
            workspace(),
            SemanticEventSubjects {
                goal_id: Some(goal()),
                node_id: Some(DagNodeId::from_uuid(Uuid::from_u128(0x5E03))),
                ..SemanticEventSubjects::NONE
            },
            3,
            TimestampMillis::new(12)?,
        );
        assert_ne!(
            base.payload_digest(),
            with_node.payload_digest(),
            "subject identities must be part of the canonical identity"
        );
        let empty = SemanticEventAppend::new(
            SemanticEventKind::GoalCreated,
            workspace(),
            SemanticEventSubjects::NONE,
            3,
            TimestampMillis::new(12)?,
        );
        assert_ne!(
            base.payload_digest(),
            empty.payload_digest(),
            "absent subjects must not collide with present subjects"
        );
        Ok(())
    }

    #[test]
    fn append_allocates_monotonic_sequences_and_rolls_back_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = event_stream_fixture()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let first = append_semantic_event(
            &transaction,
            &sample_event(SemanticEventKind::GoalCreated, 1)?,
        )?;
        let second = append_semantic_event(
            &transaction,
            &sample_event(SemanticEventKind::GoalUpdated, 2)?,
        )?;
        assert_eq!(first, 1);
        assert_eq!(second, 2);
        let inside = semantic_events_after(&transaction, workspace(), 0, MAX_PAGE_SIZE)?;
        assert_eq!(inside.events().len(), 2);
        assert_eq!(inside.high_water(), 2);
        transaction.rollback()?;
        let after = semantic_events_after(&connection, workspace(), 0, MAX_PAGE_SIZE)?;
        assert_eq!(after.events().len(), 0, "rollback must remove the events");
        assert_eq!(after.high_water(), 0, "rollback must restore the cursor");
        assert_eq!(after.retained_low(), 0);

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let replayed = append_semantic_event(
            &transaction,
            &sample_event(SemanticEventKind::GoalCreated, 1)?,
        )?;
        assert_eq!(replayed, 1, "an uncommitted sequence must be reusable");
        drop(transaction);
        Ok(())
    }

    #[test]
    fn append_requires_caller_transaction() -> Result<(), Box<dyn std::error::Error>> {
        let connection = event_stream_fixture()?;
        assert!(matches!(
            append_semantic_event(
                &connection,
                &sample_event(SemanticEventKind::GoalCreated, 1)?
            ),
            Err(SemanticEventError::MissingTransaction)
        ));
        Ok(())
    }

    #[test]
    fn bounded_read_enforces_limit_and_reports_cursor_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = event_stream_fixture()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for revision in 1..=5 {
            append_semantic_event(
                &transaction,
                &sample_event(SemanticEventKind::GoalUpdated, revision)?,
            )?;
        }
        transaction.commit()?;

        assert!(matches!(
            semantic_events_after(&connection, workspace(), 0, 0),
            Err(SemanticEventError::InvalidLimit { limit: 0 })
        ));
        assert!(matches!(
            semantic_events_after(&connection, workspace(), 0, MAX_PAGE_SIZE + 1),
            Err(SemanticEventError::InvalidLimit { .. })
        ));

        let first = semantic_events_after(&connection, workspace(), 0, 2)?;
        assert_eq!(first.events().len(), 2);
        assert_eq!(first.events()[0].sequence(), 1);
        assert_eq!(first.events()[1].sequence(), 2);
        assert_eq!(first.high_water(), 5);
        assert_eq!(first.retained_low(), 0);
        assert_eq!(
            first.events()[0].event().kind(),
            SemanticEventKind::GoalUpdated
        );
        assert_eq!(first.events()[0].event().revision(), 1);
        assert_eq!(first.events()[0].event().subjects().goal_id, Some(goal()));

        let second = semantic_events_after(&connection, workspace(), 2, 2)?;
        assert_eq!(second.events().len(), 2);
        assert_eq!(second.events()[0].sequence(), 3);
        let tail = semantic_events_after(&connection, workspace(), 5, MAX_PAGE_SIZE)?;
        assert!(tail.events().is_empty());
        assert_eq!(tail.high_water(), 5);

        // Cursor metadata tracks the Workspace, not the caller cursor.
        let other = WorkspaceId::from_uuid(Uuid::from_u128(0x5E09));
        let foreign = semantic_events_after(&connection, other, 0, MAX_PAGE_SIZE)?;
        assert!(foreign.events().is_empty());
        assert_eq!(foreign.high_water(), 0);
        assert_eq!(foreign.retained_low(), 0);
        Ok(())
    }

    #[test]
    fn snapshot_limit_reports_truncation_without_torn_cursor_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = snapshot_fixture()?;
        let one = workspace_semantic_snapshot(&connection, workspace(), 1)?;
        assert_eq!(one.goals().len(), 1);
        assert!(one.goals_truncated());
        assert_eq!(one.watermark_seq(), 0);
        assert_eq!(one.retained_low(), 0);

        let two = workspace_semantic_snapshot(&connection, workspace(), 2)?;
        assert_eq!(two.goals().len(), 2);
        assert!(!two.goals_truncated());
        assert_eq!(two.watermark_seq(), one.watermark_seq());
        assert_eq!(two.retained_low(), one.retained_low());

        assert!(matches!(
            workspace_semantic_snapshot(&connection, workspace(), 0),
            Err(SemanticEventError::InvalidLimit { limit: 0 })
        ));
        assert!(matches!(
            workspace_semantic_snapshot(
                &connection,
                workspace(),
                MAX_WORKSPACE_SNAPSHOT_GOAL_SUMMARIES + 1
            ),
            Err(SemanticEventError::InvalidLimit { .. })
        ));
        Ok(())
    }

    #[test]
    fn schema_validation_rejects_damaged_and_missing_objects()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = event_stream_fixture()?;
        validate_schema(&connection)?;
        connection.execute_batch("DROP TABLE semantic_events_meta")?;
        assert!(matches!(
            validate_schema(&connection),
            Err(SemanticEventError::DamagedSchema("semantic_events_meta"))
        ));
        connection.execute_batch("ALTER TABLE semantic_events RENAME TO semantic_events_old")?;
        assert!(matches!(
            validate_schema(&connection),
            Err(SemanticEventError::DamagedSchema("semantic_events"))
        ));
        Ok(())
    }
}

/// Closed current-state kind of one summarized Goal.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoalSnapshotState {
    Active,
    Paused,
    Blocked,
    Completed,
    Failed,
    Cancelled,
}

impl GoalSnapshotState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn from_state_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Active),
            1 => Some(Self::Paused),
            2 => Some(Self::Blocked),
            3 => Some(Self::Completed),
            4 => Some(Self::Failed),
            5 => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// Bounded per-Goal current-state summary returned with a Workspace snapshot.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalSnapshotSummary {
    pub goal_id: GoalId,
    pub activity_id: ActivityId,
    pub revision: i64,
    pub state: GoalSnapshotState,
    pub current_dag_revision: Option<DagRevisionNumber>,
    pub current_node_count: Option<u64>,
}

/// One consistent Workspace snapshot: the durable cursor pair plus a bounded
/// Goal/DAG current-state summary, all read inside a single read transaction.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSemanticSnapshot {
    watermark_seq: u64,
    retained_low: u64,
    goals: Vec<GoalSnapshotSummary>,
    goals_truncated: bool,
}

impl WorkspaceSemanticSnapshot {
    pub const fn watermark_seq(&self) -> u64 {
        self.watermark_seq
    }

    pub const fn retained_low(&self) -> u64 {
        self.retained_low
    }

    pub fn goals(&self) -> &[GoalSnapshotSummary] {
        &self.goals
    }

    pub const fn goals_truncated(&self) -> bool {
        self.goals_truncated
    }
}

/// Compose the durable cursor pair and the bounded Goal/DAG summary in one
/// read transaction so a snapshot consumer can never observe a torn cursor.
pub(crate) fn workspace_semantic_snapshot(
    connection: &Connection,
    workspace_id: WorkspaceId,
    goal_limit: u32,
) -> Result<WorkspaceSemanticSnapshot, SemanticEventError> {
    if !(1..=MAX_WORKSPACE_SNAPSHOT_GOAL_SUMMARIES).contains(&goal_limit) {
        return Err(SemanticEventError::InvalidLimit { limit: goal_limit });
    }
    let goal_limit = usize::try_from(goal_limit)
        .map_err(|_| SemanticEventError::InvalidLimit { limit: goal_limit })?;
    let query_limit = i64::try_from(goal_limit + 1)
        .map_err(|_| SemanticEventError::InvalidLimit { limit: u32::MAX })?;
    let transaction = connection.unchecked_transaction()?;
    let watermark_seq = high_water_seq(&transaction, workspace_id)?;
    let retained_low = retained_low(&transaction, workspace_id)?;
    let mut statement = transaction.prepare(
        "SELECT goal_id, activity_id, revision, state
         FROM goals WHERE workspace_id = ?1
         ORDER BY updated_at_ms DESC, goal_id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![workspace_id.into_uuid().as_bytes(), query_limit],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let mut goals = Vec::new();
    let mut goals_truncated = false;
    for row in rows {
        if goals.len() >= goal_limit {
            goals_truncated = true;
            break;
        }
        let (goal_bytes, activity_bytes, revision, state_code) = row?;
        let goal_id = GoalId::from_uuid(
            Uuid::from_slice(&goal_bytes)
                .map_err(|_| SemanticEventError::CorruptRecord("goals.goal_id"))?,
        );
        let activity_id = ActivityId::from_uuid(
            Uuid::from_slice(&activity_bytes)
                .map_err(|_| SemanticEventError::CorruptRecord("goals.activity_id"))?,
        );
        let state = GoalSnapshotState::from_state_code(state_code)
            .ok_or(SemanticEventError::CorruptRecord("goals.state"))?;
        let current_dag = workspace_dags::get_current_in_transaction(&transaction, goal_id)
            .map_err(|_| SemanticEventError::CorruptRecord("dag_heads"))?;
        let (current_dag_revision, current_node_count) = match current_dag {
            Some(stored) => {
                let number = stored.revision().number();
                let count = u64::try_from(stored.nodes().len()).unwrap_or(u64::MAX);
                (Some(number), Some(count))
            }
            None => (None, None),
        };
        goals.push(GoalSnapshotSummary {
            goal_id,
            activity_id,
            revision,
            state,
            current_dag_revision,
            current_node_count,
        });
    }
    drop(statement);
    transaction.commit()?;
    Ok(WorkspaceSemanticSnapshot {
        watermark_seq,
        retained_low,
        goals,
        goals_truncated,
    })
}
