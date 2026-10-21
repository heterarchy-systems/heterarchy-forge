//! Bounded, ordered submission evidence. URLs remain in assignment storage.

use forge_domain::{
    ActivityId, AgentAssignmentId, AgentAssignmentSourceRef, AgentAssignmentState, AgentInstanceId,
    AgentSessionId, ApprovalRequestId, ChangeSetId, CheckpointId, DagNodeId, ExecutionId,
    GoalEvidenceRef, GoalId, MAX_AGENT_ASSIGNMENT_SOURCES, RegisteredAgentAssignment,
    TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    ASSIGNMENT_SUBMITTED_KIND, DIGEST_BYTES, EffectFact, EffectFactOutboxEntry,
    EffectFactOutboxError, decode_digest, decode_uuid, load_entry, source_delegation,
};

pub(super) const SCHEMA_SQL: &str = "CREATE TABLE effect_fact_outbox_assignment_submitted (outbox_sequence INTEGER PRIMARY KEY NOT NULL REFERENCES effect_fact_outbox_entries(sequence), migration_id BLOB NOT NULL CHECK(length(migration_id) = 16 AND migration_id != zeroblob(16)), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16 AND destination_id != zeroblob(16)), workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16 AND workspace_id != zeroblob(16)), activity_id BLOB NOT NULL CHECK(length(activity_id) = 16 AND activity_id != zeroblob(16)), assignment_id BLOB NOT NULL UNIQUE CHECK(length(assignment_id) = 16 AND assignment_id != zeroblob(16)), goal_id BLOB NOT NULL CHECK(length(goal_id) = 16 AND goal_id != zeroblob(16)), node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)), target_agent_id BLOB NOT NULL CHECK(length(target_agent_id) = 16 AND target_agent_id != zeroblob(16)), target_session_id BLOB CHECK(target_session_id IS NULL OR (length(target_session_id) = 16 AND target_session_id != zeroblob(16))), source_count INTEGER NOT NULL CHECK(source_count BETWEEN 0 AND 32), source_digests BLOB, source_kinds BLOB, result_digest BLOB CHECK(result_digest IS NULL OR length(result_digest) = 32), submitted_at_ms INTEGER NOT NULL CHECK(submitted_at_ms >= 0), source_refs_recorded INTEGER NOT NULL DEFAULT 0 CHECK(source_refs_recorded IN (0,1)), CHECK((source_count = 0 AND source_digests IS NULL AND source_kinds IS NULL) OR (source_count > 0 AND source_digests IS NOT NULL AND length(source_digests) = 32 AND source_kinds IS NOT NULL AND length(source_kinds) = source_count)))";

const SOURCE_REFS_RECORDED_COLUMN_SQL: &str =
    "source_refs_recorded INTEGER NOT NULL DEFAULT 0 CHECK(source_refs_recorded IN (0,1))";
pub(super) const SOURCE_REFS_RECORDED_ALTER_SQL: &str = "ALTER TABLE effect_fact_outbox_assignment_submitted ADD COLUMN source_refs_recorded INTEGER NOT NULL DEFAULT 0 CHECK(source_refs_recorded IN (0,1))";
pub(super) const SOURCE_REFS_SQL: &str = "CREATE TABLE effect_fact_outbox_assignment_submitted_source_ref (outbox_sequence INTEGER NOT NULL REFERENCES effect_fact_outbox_entries(sequence), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31), evidence_kind INTEGER NOT NULL CHECK(evidence_kind BETWEEN 0 AND 3), evidence_id BLOB NOT NULL CHECK(length(evidence_id) = 16 AND evidence_id != zeroblob(16)), PRIMARY KEY(outbox_sequence, ordinal))";

/// Exact v47 shape of the submitted payload, before the additive source-ref
/// marker and child table.
pub(super) fn schema_sql_pre_source_refs() -> String {
    SCHEMA_SQL.replace(&format!(", {SOURCE_REFS_RECORDED_COLUMN_SQL}"), "")
}

pub(super) fn add_source_refs_schema(connection: &Connection) -> Result<(), EffectFactOutboxError> {
    connection.execute_batch(SOURCE_REFS_RECORDED_ALTER_SQL)?;
    connection.execute_batch(SOURCE_REFS_SQL)?;
    Ok(())
}

/// One immutable, ordered provenance reference carried by a submitted fact.
/// The ordinal is the position in the complete source list, including URL
/// entries that are intentionally not retained here.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignmentSubmittedSourceRef {
    ordinal: u8,
    evidence: GoalEvidenceRef,
}

impl AssignmentSubmittedSourceRef {
    /// Construct one bounded evidence reference value, without asserting that
    /// any source receipt or referenced evidence exists.
    ///
    /// # Errors
    /// Rejects an out-of-range ordinal or a nil evidence identity.
    pub fn new(ordinal: u8, evidence: GoalEvidenceRef) -> Result<Self, AssignmentSourceRefError> {
        if usize::from(ordinal) >= MAX_AGENT_ASSIGNMENT_SOURCES {
            return Err(AssignmentSourceRefError::Ordinal);
        }
        let id = match evidence {
            GoalEvidenceRef::ChangeSet(id) => id.into_uuid(),
            GoalEvidenceRef::Execution(id) => id.into_uuid(),
            GoalEvidenceRef::Approval(id) => id.into_uuid(),
            GoalEvidenceRef::Checkpoint(id) => id.into_uuid(),
        };
        if id.is_nil() {
            return Err(AssignmentSourceRefError::EvidenceIdentity);
        }
        Ok(Self { ordinal, evidence })
    }

    pub const fn ordinal(self) -> u8 {
        self.ordinal
    }

    pub const fn evidence(self) -> GoalEvidenceRef {
        self.evidence
    }
}

/// Invalid shape of a provenance reference value, before receipt admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentSourceRefError {
    #[error("source reference ordinal is outside the bounded source list")]
    Ordinal,
    #[error("source reference evidence identity must be non-nil")]
    EvidenceIdentity,
}

const SOURCE_DIGEST_DOMAIN: &[u8] = b"heterarchy-forge.assignment-submitted.sources.v1\0";

type LoadedSubmission = (
    AssignmentSubmittedEffectFact,
    Option<Box<[AssignmentSubmittedSourceRef]>>,
);

/// Immutable submission evidence, with at most 32 ordered source kinds.
///
/// `source_digests` commits to the complete ordered source list. Its SHA-256
/// preimage is the domain `heterarchy-forge.assignment-submitted.sources.v1\0`,
/// followed by the source count (u64 big endian), then each source: kind byte,
/// payload length (u64 big endian), payload. Kind 0 uses exact URL UTF-8 bytes.
/// Kind 1 uses a provenance tag (0 `ChangeSet`, 1 Execution, 2 Approval,
/// 3 Checkpoint) and its 16 UUID bytes. Empty sources use `None`.
/// `result_digest` follows kind 2: SHA-256 of the exact report UTF-8 bytes.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignmentSubmittedEffectFact {
    assignment_id: AgentAssignmentId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    goal_id: GoalId,
    node_id: DagNodeId,
    target_agent_id: AgentInstanceId,
    target_session_id: Option<AgentSessionId>,
    sources: SubmissionSources,
    result_digest: Option<[u8; DIGEST_BYTES]>,
    submitted_at: TimestampMillis,
}

impl AssignmentSubmittedEffectFact {
    fn from_assignment_submit(
        assignment: &RegisteredAgentAssignment,
        submitted_at: TimestampMillis,
    ) -> Result<Self, EffectFactOutboxError> {
        ensure_submitted(assignment)?;
        let result = assignment
            .result()
            .ok_or(EffectFactOutboxError::AssignmentNotSubmitted)?;
        Ok(Self {
            assignment_id: assignment.id(),
            workspace_id: assignment.workspace_id(),
            activity_id: assignment.activity_id(),
            goal_id: assignment.goal_id(),
            node_id: assignment.node_id(),
            target_agent_id: assignment.target().agent_id(),
            target_session_id: Some(assignment.target().session_id()),
            sources: SubmissionSources::from_sources(result.sources())?,
            result_digest: Some(Sha256::digest(result.report().as_bytes()).into()),
            submitted_at,
        })
    }

    pub const fn assignment_id(&self) -> AgentAssignmentId {
        self.assignment_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }
    pub const fn goal_id(&self) -> GoalId {
        self.goal_id
    }
    pub const fn node_id(&self) -> DagNodeId {
        self.node_id
    }
    pub const fn target_agent_id(&self) -> AgentInstanceId {
        self.target_agent_id
    }
    pub const fn target_session_id(&self) -> Option<AgentSessionId> {
        self.target_session_id
    }
    pub const fn source_count(&self) -> u8 {
        self.sources.count
    }

    /// SHA-256 of the ordered source listing, or `None` when empty.
    pub fn source_digests(&self) -> Option<[u8; DIGEST_BYTES]> {
        self.sources.digests()
    }

    /// Ordered one-byte source tags: 0 URL, 1 provenance; `None` when empty.
    pub fn source_kinds(&self) -> Option<&[u8]> {
        self.sources.kinds()
    }
    pub const fn result_digest(&self) -> Option<[u8; DIGEST_BYTES]> {
        self.result_digest
    }
    pub const fn submitted_at(&self) -> TimestampMillis {
        self.submitted_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SubmissionSources {
    count: u8,
    kinds: [u8; MAX_AGENT_ASSIGNMENT_SOURCES],
    digest: Option<[u8; DIGEST_BYTES]>,
}

impl SubmissionSources {
    fn empty() -> Self {
        Self {
            count: 0,
            kinds: [0; MAX_AGENT_ASSIGNMENT_SOURCES],
            digest: None,
        }
    }

    fn from_sources(sources: &[AgentAssignmentSourceRef]) -> Result<Self, EffectFactOutboxError> {
        let mut encoded = Self::empty();
        encoded.count = checked_source_count(sources.len())?;
        if sources.is_empty() {
            return Ok(encoded);
        }
        let mut hash = Sha256::new();
        hash.update(SOURCE_DIGEST_DOMAIN);
        hash.update(u64::from(encoded.count).to_be_bytes());
        for (ordinal, source) in sources.iter().enumerate() {
            match source {
                AgentAssignmentSourceRef::Url(url) => {
                    hash.update([0]);
                    let length = u64::try_from(url.as_str().len()).map_err(|_| {
                        EffectFactOutboxError::CorruptRecord("effect_fact.source_length")
                    })?;
                    hash.update(length.to_be_bytes());
                    hash.update(url.as_str().as_bytes());
                }
                AgentAssignmentSourceRef::Provenance(evidence) => {
                    encoded.kinds[ordinal] = 1;
                    hash.update([1]);
                    hash.update(17_u64.to_be_bytes());
                    let (tag, id) = match evidence {
                        GoalEvidenceRef::ChangeSet(id) => (0, id.into_uuid()),
                        GoalEvidenceRef::Execution(id) => (1, id.into_uuid()),
                        GoalEvidenceRef::Approval(id) => (2, id.into_uuid()),
                        GoalEvidenceRef::Checkpoint(id) => (3, id.into_uuid()),
                    };
                    hash.update([tag]);
                    hash.update(id.as_bytes());
                }
            }
        }
        encoded.digest = Some(hash.finalize().into());
        Ok(encoded)
    }

    fn decode(
        count: i64,
        kinds: Option<&[u8]>,
        digests: Option<&[u8]>,
    ) -> Result<Self, EffectFactOutboxError> {
        let count = usize::try_from(count)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.source_count"))?;
        let mut sources = Self::empty();
        sources.count = checked_source_count(count)?;
        if count == 0 && kinds.is_none() && digests.is_none() {
            return Ok(sources);
        }
        let (Some(kinds), Some(digests)) = (kinds, digests) else {
            return Err(EffectFactOutboxError::CorruptRecord("effect_fact.sources"));
        };
        if count == 0
            || kinds.len() != count
            || digests.len() != DIGEST_BYTES
            || kinds.iter().any(|&kind| kind > 1)
        {
            return Err(EffectFactOutboxError::CorruptRecord("effect_fact.sources"));
        }
        sources.kinds[..count].copy_from_slice(kinds);
        sources.digest = Some(
            digests
                .try_into()
                .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.source_digests"))?,
        );
        Ok(sources)
    }

    fn kinds(&self) -> Option<&[u8]> {
        (self.count != 0).then(|| &self.kinds[..usize::from(self.count)])
    }

    fn digests(&self) -> Option<[u8; DIGEST_BYTES]> {
        self.digest
    }
}

fn checked_source_count(count: usize) -> Result<u8, EffectFactOutboxError> {
    if count > MAX_AGENT_ASSIGNMENT_SOURCES {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.source_count",
        ));
    }
    u8::try_from(count)
        .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.source_count"))
}

fn source_refs_from_sources(
    sources: &[AgentAssignmentSourceRef],
) -> Result<Box<[AssignmentSubmittedSourceRef]>, EffectFactOutboxError> {
    checked_source_count(sources.len())?;
    let mut refs = Vec::new();
    for (ordinal, source) in sources.iter().enumerate() {
        let AgentAssignmentSourceRef::Provenance(evidence) = source else {
            continue;
        };
        refs.push(AssignmentSubmittedSourceRef {
            ordinal: u8::try_from(ordinal).map_err(|_| {
                EffectFactOutboxError::CorruptRecord("effect_fact.source_ref.ordinal")
            })?,
            evidence: *evidence,
        });
    }
    Ok(refs.into_boxed_slice())
}

fn ensure_submitted(assignment: &RegisteredAgentAssignment) -> Result<(), EffectFactOutboxError> {
    match assignment.state() {
        AgentAssignmentState::Submitted
        | AgentAssignmentState::Accepted
        | AgentAssignmentState::Rejected => Ok(()),
        AgentAssignmentState::Offered
        | AgentAssignmentState::Running
        | AgentAssignmentState::Cancelled
        | AgentAssignmentState::Interrupted => Err(EffectFactOutboxError::AssignmentNotSubmitted),
    }
}

pub(crate) fn append_assignment_submitted(
    connection: &Connection,
    assignment: &RegisteredAgentAssignment,
) -> Result<(), EffectFactOutboxError> {
    if connection.is_autocommit() {
        return Err(EffectFactOutboxError::MissingTransaction);
    }
    ensure_submitted(assignment)?;
    let Some(delegation) = source_delegation(connection, assignment.workspace_id())? else {
        return Ok(());
    };
    let existing_sequence = connection.query_row(
        "SELECT outbox_sequence FROM effect_fact_outbox_assignment_submitted WHERE assignment_id=?1",
        params![assignment.id().into_uuid().as_bytes()],
        |row| row.get::<_, i64>(0),
    ).optional()?;
    if let Some(sequence) = existing_sequence {
        let existing = load_entry(connection, sequence)?;
        // A review changes updated_at. Only the already recorded submission
        // timestamp can identify a reviewed-row replay; never backfill history.
        let submitted_at = if assignment.state() == AgentAssignmentState::Submitted {
            assignment.updated_at()
        } else if let EffectFact::AssignmentSubmitted(fact) = existing.fact() {
            fact.submitted_at()
        } else {
            return Err(EffectFactOutboxError::ReplayConflict);
        };
        let fact = AssignmentSubmittedEffectFact::from_assignment_submit(assignment, submitted_at)?;
        let source_refs = if existing.submitted_source_refs().is_some() {
            let result = assignment
                .result()
                .ok_or(EffectFactOutboxError::AssignmentNotSubmitted)?;
            Some(source_refs_from_sources(result.sources())?)
        } else {
            None
        };
        let expected = EffectFactOutboxEntry {
            sequence: u64::try_from(sequence)
                .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
            migration_id: delegation.migration_id(),
            destination_id: delegation.destination_id(),
            workspace_id: delegation.workspace_id(),
            fact: EffectFact::AssignmentSubmitted(Box::new(fact)),
            submitted_source_refs: source_refs,
        };
        return if existing == expected {
            Ok(())
        } else {
            Err(EffectFactOutboxError::ReplayConflict)
        };
    }
    if assignment.state() != AgentAssignmentState::Submitted {
        return Err(EffectFactOutboxError::AssignmentNotSubmitted);
    }
    let fact =
        AssignmentSubmittedEffectFact::from_assignment_submit(assignment, assignment.updated_at())?;
    let result = assignment
        .result()
        .ok_or(EffectFactOutboxError::AssignmentNotSubmitted)?;
    let source_refs = source_refs_from_sources(result.sources())?;
    connection.execute(
        "INSERT INTO effect_fact_outbox_entries(migration_id,destination_id,workspace_id,fact_kind) VALUES(?1,?2,?3,?4)",
        params![delegation.migration_id().as_bytes(), delegation.destination_id().as_bytes(), delegation.workspace_id().into_uuid().as_bytes(), ASSIGNMENT_SUBMITTED_KIND],
    )?;
    insert_payload_with_source_refs(
        connection,
        connection.last_insert_rowid(),
        delegation.migration_id(),
        delegation.destination_id(),
        &fact,
        Some(source_refs.as_ref()),
    )
}

fn insert_payload_with_source_refs(
    connection: &Connection,
    sequence: i64,
    migration_id: Uuid,
    destination_id: Uuid,
    fact: &AssignmentSubmittedEffectFact,
    source_refs: Option<&[AssignmentSubmittedSourceRef]>,
) -> Result<(), EffectFactOutboxError> {
    connection.execute(
        "INSERT INTO effect_fact_outbox_assignment_submitted(outbox_sequence,migration_id,destination_id,workspace_id,activity_id,assignment_id,goal_id,node_id,target_agent_id,target_session_id,source_count,source_digests,source_kinds,result_digest,submitted_at_ms,source_refs_recorded) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![sequence, migration_id.as_bytes(), destination_id.as_bytes(), fact.workspace_id().into_uuid().as_bytes(), fact.activity_id().into_uuid().as_bytes(), fact.assignment_id().into_uuid().as_bytes(), fact.goal_id().into_uuid().as_bytes(), fact.node_id().into_uuid().as_bytes(), fact.target_agent_id().into_uuid().as_bytes(), fact.target_session_id().map(|id| id.into_uuid().into_bytes()), fact.source_count(), fact.source_digests(), fact.source_kinds(), fact.result_digest(), fact.submitted_at().get(), i64::from(source_refs.is_some())],
    )?;
    if let Some(source_refs) = source_refs {
        for source_ref in source_refs {
            let (evidence_kind, evidence_id) = encode_source_ref(source_ref.evidence);
            connection.execute(
                "INSERT INTO effect_fact_outbox_assignment_submitted_source_ref(outbox_sequence,ordinal,evidence_kind,evidence_id) VALUES(?1,?2,?3,?4)",
                params![
                    sequence,
                    i64::from(source_ref.ordinal),
                    evidence_kind,
                    evidence_id.as_bytes(),
                ],
            )?;
        }
    }
    Ok(())
}

struct RawSubmission {
    assignment_id: Vec<u8>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    goal_id: Vec<u8>,
    node_id: Vec<u8>,
    target_agent_id: Vec<u8>,
    target_session_id: Option<Vec<u8>>,
    source_count: i64,
    source_digests: Option<Vec<u8>>,
    source_kinds: Option<Vec<u8>>,
    result_digest: Option<Vec<u8>>,
    submitted_at: i64,
    source_refs_recorded: i64,
    migration_id: Vec<u8>,
    destination_id: Vec<u8>,
}

pub(super) fn load_with_source_refs(
    connection: &Connection,
    sequence: i64,
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
) -> Result<LoadedSubmission, EffectFactOutboxError> {
    let raw = connection.query_row(
        "SELECT substr(assignment_id,1,17),substr(workspace_id,1,17),substr(activity_id,1,17),substr(goal_id,1,17),substr(node_id,1,17),substr(target_agent_id,1,17),substr(target_session_id,1,17),source_count,substr(source_digests,1,33),substr(source_kinds,1,33),substr(result_digest,1,33),submitted_at_ms,source_refs_recorded,substr(migration_id,1,17),substr(destination_id,1,17) FROM effect_fact_outbox_assignment_submitted WHERE outbox_sequence=?1",
        params![sequence],
        |row| Ok(RawSubmission { assignment_id: row.get(0)?, workspace_id: row.get(1)?, activity_id: row.get(2)?, goal_id: row.get(3)?, node_id: row.get(4)?, target_agent_id: row.get(5)?, target_session_id: row.get(6)?, source_count: row.get(7)?, source_digests: row.get(8)?, source_kinds: row.get(9)?, result_digest: row.get(10)?, submitted_at: row.get(11)?, source_refs_recorded: row.get(12)?, migration_id: row.get(13)?, destination_id: row.get(14)? }),
    )?;
    if decode_uuid(&raw.workspace_id, "effect_fact.workspace_id")? != workspace_id.into_uuid()
        || decode_uuid(&raw.migration_id, "effect_fact.migration_id")? != migration_id
        || decode_uuid(&raw.destination_id, "effect_fact.destination_id")? != destination_id
    {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.submission_scope",
        ));
    }
    let fact = AssignmentSubmittedEffectFact {
        assignment_id: AgentAssignmentId::from_uuid(decode_uuid(
            &raw.assignment_id,
            "effect_fact.assignment_id",
        )?),
        workspace_id,
        activity_id: ActivityId::from_uuid(decode_uuid(
            &raw.activity_id,
            "effect_fact.activity_id",
        )?),
        goal_id: GoalId::from_uuid(decode_uuid(&raw.goal_id, "effect_fact.goal_id")?),
        node_id: DagNodeId::from_uuid(decode_uuid(&raw.node_id, "effect_fact.node_id")?),
        target_agent_id: AgentInstanceId::from_uuid(decode_uuid(
            &raw.target_agent_id,
            "effect_fact.target_agent_id",
        )?),
        target_session_id: raw
            .target_session_id
            .map(|bytes| {
                decode_uuid(&bytes, "effect_fact.target_session_id").map(AgentSessionId::from_uuid)
            })
            .transpose()?,
        sources: SubmissionSources::decode(
            raw.source_count,
            raw.source_kinds.as_deref(),
            raw.source_digests.as_deref(),
        )?,
        result_digest: raw
            .result_digest
            .map(|bytes| decode_digest(bytes, "effect_fact.result_digest"))
            .transpose()?,
        submitted_at: TimestampMillis::new(raw.submitted_at)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.submitted_at"))?,
    };
    let source_refs = load_source_refs(connection, sequence, &fact, raw.source_refs_recorded)?;
    Ok((fact, source_refs))
}

fn load_source_refs(
    connection: &Connection,
    sequence: i64,
    fact: &AssignmentSubmittedEffectFact,
    marker: i64,
) -> Result<Option<Box<[AssignmentSubmittedSourceRef]>>, EffectFactOutboxError> {
    if marker != 0 && marker != 1 {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.source_refs_recorded",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT ordinal,evidence_kind,substr(evidence_id,1,17) FROM effect_fact_outbox_assignment_submitted_source_ref WHERE outbox_sequence=?1 ORDER BY ordinal ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            sequence,
            i64::try_from(MAX_AGENT_ASSIGNMENT_SOURCES + 1).unwrap_or(i64::MAX)
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        },
    )?;
    let mut refs: Vec<AssignmentSubmittedSourceRef> = Vec::new();
    for row in rows {
        let (ordinal, kind, evidence_id) = row?;
        if refs.len() >= MAX_AGENT_ASSIGNMENT_SOURCES {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.source_refs",
            ));
        }
        let ordinal = u8::try_from(ordinal)
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.source_ref.ordinal"))?;
        let evidence = decode_source_ref(kind, &evidence_id)?;
        if let Some(previous) = refs.last()
            && previous.ordinal >= ordinal
        {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.source_ref.ordinal",
            ));
        }
        refs.push(AssignmentSubmittedSourceRef { ordinal, evidence });
    }
    if marker == 0 {
        if !refs.is_empty() {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.source_refs",
            ));
        }
        return Ok(None);
    }

    let source_kinds = fact.source_kinds().unwrap_or(&[]);
    let expected_count = source_kinds
        .iter()
        .fold(0_usize, |count, &kind| count + usize::from(kind == 1));
    if refs.len() != expected_count {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.source_refs",
        ));
    }
    let mut ref_index = 0;
    for (ordinal, &kind) in source_kinds.iter().enumerate() {
        if kind != 1 {
            continue;
        }
        let source_ref = refs
            .get(ref_index)
            .ok_or(EffectFactOutboxError::CorruptRecord(
                "effect_fact.source_refs",
            ))?;
        if usize::from(source_ref.ordinal) != ordinal {
            return Err(EffectFactOutboxError::CorruptRecord(
                "effect_fact.source_refs",
            ));
        }
        ref_index += 1;
    }
    if ref_index != refs.len() {
        return Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.source_refs",
        ));
    }
    Ok(Some(refs.into_boxed_slice()))
}

fn encode_source_ref(evidence: GoalEvidenceRef) -> (i64, Uuid) {
    match evidence {
        GoalEvidenceRef::ChangeSet(id) => (0, id.into_uuid()),
        GoalEvidenceRef::Execution(id) => (1, id.into_uuid()),
        GoalEvidenceRef::Approval(id) => (2, id.into_uuid()),
        GoalEvidenceRef::Checkpoint(id) => (3, id.into_uuid()),
    }
}

fn decode_source_ref(
    kind: i64,
    evidence_id: &[u8],
) -> Result<GoalEvidenceRef, EffectFactOutboxError> {
    let evidence_id = super::decode_uuid(evidence_id, "effect_fact.source_ref.id")?;
    match kind {
        0 => Ok(GoalEvidenceRef::ChangeSet(ChangeSetId::from_uuid(
            evidence_id,
        ))),
        1 => Ok(GoalEvidenceRef::Execution(ExecutionId::from_uuid(
            evidence_id,
        ))),
        2 => Ok(GoalEvidenceRef::Approval(ApprovalRequestId::from_uuid(
            evidence_id,
        ))),
        3 => Ok(GoalEvidenceRef::Checkpoint(CheckpointId::from_uuid(
            evidence_id,
        ))),
        _ => Err(EffectFactOutboxError::CorruptRecord(
            "effect_fact.source_ref.kind",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mixed_sources() -> Result<Vec<AgentAssignmentSourceRef>, Box<dyn std::error::Error>> {
        Ok(vec![
            AgentAssignmentSourceRef::Url(forge_domain::AgentAssignmentSourceUrl::new(
                "https://example.com/artifact".to_owned(),
            )?),
            AgentAssignmentSourceRef::Provenance(GoalEvidenceRef::ChangeSet(
                forge_domain::ChangeSetId::from_uuid(Uuid::from_u128(7)),
            )),
        ])
    }

    #[test]
    fn source_commitment_preserves_order_identity_and_domain()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = mixed_sources()?;
        let sources = SubmissionSources::from_sources(&input)?;
        assert_eq!(sources.kinds(), Some([0, 1].as_slice()));
        // Independent SHA-256 vector for the documented preimage.
        assert_eq!(
            sources.digest,
            Some([
                0x65, 0x70, 0xd1, 0x2a, 0xa8, 0xc1, 0xd8, 0x2e, 0x0e, 0x73, 0x79, 0x26, 0x7e, 0x29,
                0xe1, 0x44, 0xa8, 0xba, 0xa5, 0x1a, 0xe0, 0xe4, 0x49, 0xb4, 0x43, 0xc9, 0x88, 0x93,
                0x61, 0x8c, 0x25, 0xe9,
            ])
        );
        input.reverse();
        assert_ne!(
            sources.digest,
            SubmissionSources::from_sources(&input)?.digest
        );
        input.reverse();
        input[1] = AgentAssignmentSourceRef::Provenance(GoalEvidenceRef::Execution(
            forge_domain::ExecutionId::from_uuid(Uuid::from_u128(7)),
        ));
        assert_ne!(
            sources.digest,
            SubmissionSources::from_sources(&input)?.digest
        );
        let empty = SubmissionSources::from_sources(&[])?;
        assert_eq!(empty, SubmissionSources::decode(0, None, None)?);
        let maximum =
            SubmissionSources::from_sources(&vec![input[0].clone(); MAX_AGENT_ASSIGNMENT_SOURCES])?;
        assert_eq!(usize::from(maximum.count), MAX_AGENT_ASSIGNMENT_SOURCES);
        assert_eq!(
            maximum,
            SubmissionSources::decode(
                i64::from(maximum.count),
                maximum.kinds(),
                maximum.digest.as_ref().map(<[u8; 32]>::as_slice)
            )?
        );
        Ok(())
    }

    fn assert_source_refs_reject_inconsistent(
        connection: &Connection,
        migration: Uuid,
        destination: Uuid,
        workspace_id: WorkspaceId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE effect_fact_outbox_assignment_submitted SET source_refs_recorded=0",
            [],
        )?;
        assert!(
            load_with_source_refs(connection, 1, migration, destination, workspace_id).is_err()
        );
        connection.execute(
            "UPDATE effect_fact_outbox_assignment_submitted SET source_refs_recorded=1",
            [],
        )?;
        connection.execute(
            "UPDATE effect_fact_outbox_assignment_submitted_source_ref SET evidence_kind=99 WHERE ordinal=1",
            [],
        )?;
        assert!(
            load_with_source_refs(connection, 1, migration, destination, workspace_id).is_err()
        );
        Ok(())
    }

    fn delete_assignment_and_assert_refs_survive(
        connection: &Connection,
        assignment_id: AgentAssignmentId,
        migration: Uuid,
        destination: Uuid,
        workspace_id: WorkspaceId,
        expected_refs: &[AssignmentSubmittedSourceRef],
    ) -> Result<(), Box<dyn std::error::Error>> {
        connection.execute(
            "DELETE FROM agent_assignment_sources WHERE assignment_id=?1",
            params![assignment_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "DELETE FROM agent_assignments WHERE assignment_id=?1",
            params![assignment_id.into_uuid().as_bytes()],
        )?;
        let (_, loaded_refs) =
            load_with_source_refs(connection, 1, migration, destination, workspace_id)?;
        assert_eq!(loaded_refs.as_deref(), Some(expected_refs));
        Ok(())
    }

    #[test]
    fn source_refs_round_trip_and_survive_assignment_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch("CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY)")?;
        connection.execute_batch(super::super::ENTRIES_SQL)?;
        connection.execute_batch(SCHEMA_SQL)?;
        connection.execute_batch(SOURCE_REFS_SQL)?;
        connection.execute_batch(
            "CREATE TABLE agent_assignments(assignment_id BLOB PRIMARY KEY);
             CREATE TABLE agent_assignment_sources(
                 assignment_id BLOB NOT NULL REFERENCES agent_assignments(assignment_id),
                 ordinal INTEGER NOT NULL,
                 PRIMARY KEY(assignment_id, ordinal)
             )",
        )?;
        let migration = Uuid::from_u128(1);
        let destination = Uuid::from_u128(2);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(3));
        let assignment_id = AgentAssignmentId::from_uuid(Uuid::from_u128(4));
        connection.execute(
            "INSERT INTO workspace VALUES(?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO effect_fact_outbox_entries VALUES(1,?1,?2,?3,4)",
            params![
                migration.as_bytes(),
                destination.as_bytes(),
                workspace_id.into_uuid().as_bytes()
            ],
        )?;
        connection.execute(
            "INSERT INTO agent_assignments VALUES(?1)",
            params![assignment_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO agent_assignment_sources VALUES(?1,?2)",
            params![assignment_id.into_uuid().as_bytes(), 1_i64],
        )?;
        let sources = vec![
            AgentAssignmentSourceRef::Url(forge_domain::AgentAssignmentSourceUrl::new(
                "https://example.com/artifact".to_owned(),
            )?),
            AgentAssignmentSourceRef::Provenance(GoalEvidenceRef::ChangeSet(
                ChangeSetId::from_uuid(Uuid::from_u128(5)),
            )),
            AgentAssignmentSourceRef::Provenance(GoalEvidenceRef::Execution(
                ExecutionId::from_uuid(Uuid::from_u128(6)),
            )),
        ];
        let fact = AssignmentSubmittedEffectFact {
            assignment_id,
            workspace_id,
            activity_id: ActivityId::from_uuid(Uuid::from_u128(7)),
            goal_id: GoalId::from_uuid(Uuid::from_u128(8)),
            node_id: DagNodeId::from_uuid(Uuid::from_u128(9)),
            target_agent_id: AgentInstanceId::from_uuid(Uuid::from_u128(10)),
            target_session_id: Some(AgentSessionId::from_uuid(Uuid::from_u128(11))),
            sources: SubmissionSources::from_sources(&sources)?,
            result_digest: Some([42; DIGEST_BYTES]),
            submitted_at: TimestampMillis::new(12)?,
        };
        let source_refs = source_refs_from_sources(&sources)?;
        insert_payload_with_source_refs(
            &connection,
            1,
            migration,
            destination,
            &fact,
            Some(source_refs.as_ref()),
        )?;
        let expected_refs = vec![
            AssignmentSubmittedSourceRef {
                ordinal: 1,
                evidence: GoalEvidenceRef::ChangeSet(ChangeSetId::from_uuid(Uuid::from_u128(5))),
            },
            AssignmentSubmittedSourceRef {
                ordinal: 2,
                evidence: GoalEvidenceRef::Execution(ExecutionId::from_uuid(Uuid::from_u128(6))),
            },
        ];
        let (_, loaded_refs) =
            load_with_source_refs(&connection, 1, migration, destination, workspace_id)?;
        assert_eq!(loaded_refs.as_deref(), Some(expected_refs.as_slice()));

        delete_assignment_and_assert_refs_survive(
            &connection,
            assignment_id,
            migration,
            destination,
            workspace_id,
            &expected_refs,
        )?;

        assert_source_refs_reject_inconsistent(&connection, migration, destination, workspace_id)?;
        Ok(())
    }

    #[test]
    fn submission_payload_round_trip_rejects_corrupt_scope_and_unbounded_sources()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY)")?;
        connection.execute_batch(super::super::ENTRIES_SQL)?;
        connection.execute_batch(SCHEMA_SQL)?;
        connection.execute_batch(SOURCE_REFS_SQL)?;
        let migration = Uuid::from_u128(1);
        let destination = Uuid::from_u128(2);
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(3));
        connection.execute(
            "INSERT INTO workspace VALUES(?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        let fact = AssignmentSubmittedEffectFact {
            assignment_id: AgentAssignmentId::from_uuid(Uuid::from_u128(4)),
            workspace_id,
            activity_id: ActivityId::from_uuid(Uuid::from_u128(5)),
            goal_id: GoalId::from_uuid(Uuid::from_u128(6)),
            node_id: DagNodeId::from_uuid(Uuid::from_u128(7)),
            target_agent_id: AgentInstanceId::from_uuid(Uuid::from_u128(8)),
            target_session_id: Some(AgentSessionId::from_uuid(Uuid::from_u128(9))),
            sources: SubmissionSources::from_sources(&mixed_sources()?)?,
            result_digest: Some([42; DIGEST_BYTES]),
            submitted_at: TimestampMillis::new(10)?,
        };
        connection.execute(
            "INSERT INTO effect_fact_outbox_entries VALUES(1,?1,?2,?3,4)",
            params![
                migration.as_bytes(),
                destination.as_bytes(),
                workspace_id.into_uuid().as_bytes()
            ],
        )?;
        insert_payload_with_source_refs(&connection, 1, migration, destination, &fact, None)?;
        let (loaded_fact, _) =
            load_with_source_refs(&connection, 1, migration, destination, workspace_id)?;
        assert_eq!(loaded_fact, fact);
        assert!(
            load_with_source_refs(
                &connection,
                1,
                Uuid::from_u128(99),
                destination,
                workspace_id
            )
            .is_err()
        );
        assert!(
            connection
                .execute(
                    "UPDATE effect_fact_outbox_assignment_submitted SET source_count=33",
                    []
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "UPDATE effect_fact_outbox_assignment_submitted SET source_kinds=NULL",
                    []
                )
                .is_err()
        );
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        for mutation in [
            "source_digests=zeroblob(1000000)",
            "source_digests=zeroblob(32),source_kinds=x'0002'",
            "source_kinds=zeroblob(1000000)",
            "source_count=-1,source_kinds=NULL,source_digests=NULL",
        ] {
            connection.execute(
                &format!("UPDATE effect_fact_outbox_assignment_submitted SET {mutation}"),
                [],
            )?;
            assert!(
                load_with_source_refs(&connection, 1, migration, destination, workspace_id)
                    .is_err()
            );
        }
        Ok(())
    }
}
