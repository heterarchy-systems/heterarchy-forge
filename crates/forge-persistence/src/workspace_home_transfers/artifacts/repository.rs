//! Single-Workspace owner for immutable Home-artifact stages and seals.

use forge_domain::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentAssignmentId,
    AgentAssignmentOrigin, AgentAssignmentRevision, AgentAssignmentState, AuthenticatedPrincipal,
    DirectTokenId, GitCommitId, GoalId, HomeArtifactArchive, HomeArtifactArchiveError,
    HomeArtifactCaptureIntent, HomeArtifactCaptureIntentError, HomeArtifactId, OAuthGrantId,
    TimestampMillis, WorkspaceId, WorkspaceRevision,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use thiserror::Error;
use uuid::Uuid;

use super::{
    model::{
        HomeArtifactDoctorReference, HomeArtifactDoctorReport, HomeArtifactReadback,
        HomeArtifactSealRecord, HomeArtifactStageRecord,
    },
    schema,
};
use crate::{
    AgentAssignmentStoreError, HomeTransferSourceRecord, HomeTransferSourceState,
    HomeTransferStoreError, WorkspaceStoreError, workspace_agent_assignments,
    workspace_coordinators, workspace_goals,
};

const MAX_DOCTOR_REFERENCES: usize = 256;
const DOCTOR_REFERENCE_PROBE: usize = MAX_DOCTOR_REFERENCES + 1;
const ID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const COMMIT_BYTES: usize = 20;
const ARCHIVE_DIGEST_DOMAIN: &[u8] = b"forge.home-transfer.artifact.archive-snapshot.v1\0";
const SELECT_STAGE_COLUMNS: &str = "substr(handoff_id,1,17),substr(artifact_id,1,17),substr(preparation_id,1,17),substr(workspace_id,1,17),workspace_revision,substr(workspace_root_fingerprint,1,17),substr(activity_id,1,17),substr(goal_id,1,17),substr(predecessor_assignment_id,1,17),predecessor_revision,substr(root_assignment_id,1,17),substr(coordinator_agent_id,1,17),substr(coordinator_session_id,1,17),coordinator_principal_kind,substr(coordinator_principal_id,1,17),coordinator_revision,substr(source_request_digest,1,33),substr(source_outcome_digest,1,33),substr(source_inventory_digest,1,33),source_observed_at_ms,substr(intent_digest,1,33),substr(intent_snapshot,1,2097153),staged_at_ms";

/// Failure while staging, sealing, or reading the immutable Home-artifact journal.
#[derive(Debug, Error)]
pub enum HomeArtifactJournalError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Source(#[from] HomeTransferStoreError),
    #[error(transparent)]
    Assignment(#[from] AgentAssignmentStoreError),
    #[error(transparent)]
    Coordinator(#[from] workspace_coordinators::CoordinatorStoreError),
    #[error(transparent)]
    Goal(#[from] crate::GoalStoreError),
    #[error(transparent)]
    Intent(#[from] HomeArtifactCaptureIntentError),
    #[error(transparent)]
    Archive(#[from] HomeArtifactArchiveError),
    #[error("Home artifact journal conflict: {0}")]
    Conflict(&'static str),
    #[error("Home artifact journal is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("Home artifact predecessor is not quiescent: {0}")]
    Quiescence(&'static str),
    #[error("Home artifact is not eligible for the currently persisted assignment lineage")]
    UnsupportedLineage,
    #[error("Home artifact clock could not establish live authority")]
    Clock,
    #[error("Home artifact journal bounds exceeded: {0}")]
    Bounds(&'static str),
    #[error("Home artifact external read or Git operation failed")]
    External(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("Home artifact {handoff_id} {phase} commit is unconfirmed; read that exact identity")]
    CommitUnconfirmed {
        handoff_id: Uuid,
        phase: &'static str,
        #[source]
        source: Box<rusqlite::Error>,
    },
    #[error("Home artifact {handoff_id} publication is unresolved; read the exact artifact ref")]
    PublicationUnconfirmed {
        handoff_id: Uuid,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("Home artifact {handoff_id} live Workspace binding requires exact readback")]
    LiveBindingReadbackRequired {
        handoff_id: Uuid,
        #[source]
        source: Box<WorkspaceStoreError>,
    },
}

/// Exact stage insert or exact immutable replay. Only `Created` authorizes the
/// caller's one initial Git publication attempt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HomeArtifactStageOutcome {
    Created(HomeArtifactStageRecord),
    Existing(HomeArtifactStageRecord),
}

struct CurrentStageFacts {
    source: HomeTransferSourceRecord,
    assignment: forge_domain::RegisteredAgentAssignment,
    workspace_revision: WorkspaceRevision,
    workspace_root_fingerprint: forge_domain::WorkspaceRootFingerprint,
    activity_id: ActivityId,
    goal_id: GoalId,
    root_assignment_id: AgentAssignmentId,
    source_high_water_ms: i64,
}

impl HomeArtifactStageOutcome {
    pub(crate) const fn record(&self) -> &HomeArtifactStageRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }

    pub(crate) fn may_publish(self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Stage the exact immutable intent and parent Source pins before any Git I/O.
pub(crate) fn stage<C>(
    connection: &mut Connection,
    intent: &HomeArtifactCaptureIntent,
    actor: ActivityCoordinatorActor,
    sample_clock: C,
) -> Result<HomeArtifactStageOutcome, HomeArtifactJournalError>
where
    C: FnOnce() -> Result<TimestampMillis, HomeArtifactJournalError>,
{
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(existing) = load_stage(&transaction, intent.handoff_id())? {
        ensure_exact_intent(&existing, intent)?;
        validate_stage_parent(&transaction, &existing)?;
        transaction.commit()?;
        return Ok(HomeArtifactStageOutcome::Existing(existing));
    }
    if load_stage_by_artifact(&transaction, intent.artifact_id())?.is_some() {
        return Err(HomeArtifactJournalError::Conflict(
            "artifact identity already belongs to another handoff",
        ));
    }

    let facts = validate_source_and_predecessor(&transaction, intent)?;
    if actor.workspace_id() != intent.workspace_id() || actor.activity_id() != facts.activity_id {
        return Err(HomeArtifactJournalError::Conflict(
            "Coordinator Activity or Workspace scope",
        ));
    }
    let staged_at = sample_clock()?;
    if staged_at < facts.source.observed_at()
        || staged_at < facts.assignment.updated_at()
        || staged_at.get() < facts.source_high_water_ms
    {
        return Err(HomeArtifactJournalError::Conflict(
            "stage time precedes current Source census or Assignment",
        ));
    }
    let _authorized_coordinator =
        workspace_coordinators::authorize_live_in_transaction(&transaction, actor, staged_at)?;

    let source_inventory_digest =
        *facts
            .source
            .inventory_digest()
            .ok_or(HomeArtifactJournalError::Corrupt(
                "Prepared Source inventory digest missing",
            ))?;
    let stage = HomeArtifactStageRecord::new(
        intent.clone(),
        intent.workspace_id(),
        facts.workspace_revision,
        facts.workspace_root_fingerprint,
        facts.activity_id,
        facts.goal_id,
        actor,
        *facts.source.request().request_digest().as_bytes(),
        *facts.source.outcome_digest(),
        source_inventory_digest,
        facts.source.observed_at(),
        staged_at,
    );
    if facts.assignment.id() != intent.predecessor_assignment_id()
        || facts.root_assignment_id != intent.root_assignment_id()
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "current Assignment did not match checked capture identity",
        ));
    }
    persist_stage(&transaction, &stage)?;
    let readback = load_stage(&transaction, intent.handoff_id())?
        .ok_or(HomeArtifactJournalError::Corrupt("new stage missing"))?;
    if readback != stage {
        return Err(HomeArtifactJournalError::Corrupt(
            "new stage differs from exact intent and pins",
        ));
    }
    transaction
        .commit()
        .map_err(|source| HomeArtifactJournalError::CommitUnconfirmed {
            handoff_id: intent.handoff_id(),
            phase: "stage",
            source: Box::new(source),
        })?;
    Ok(HomeArtifactStageOutcome::Created(stage))
}

/// Read the exact SQL stage and optional sealed archive without publishing.
pub(crate) fn get(
    connection: &Connection,
    intent: &HomeArtifactCaptureIntent,
) -> Result<Option<HomeArtifactReadback>, HomeArtifactJournalError> {
    let transaction = connection.unchecked_transaction()?;
    let Some(stage) = load_stage(&transaction, intent.handoff_id())? else {
        if load_stage_by_artifact(&transaction, intent.artifact_id())?.is_some() {
            return Err(HomeArtifactJournalError::Conflict(
                "artifact identity belongs to another handoff",
            ));
        }
        transaction.commit()?;
        return Ok(None);
    };
    ensure_exact_intent(&stage, intent)?;
    validate_stage_parent(&transaction, &stage)?;
    let seal = load_seal(&transaction, &stage)?;
    transaction.commit()?;
    Ok(Some(HomeArtifactReadback::new(stage, seal)))
}

/// Read the canonical stage/seal under the caller's existing Source snapshot.
/// This supplies metadata for a handoff proposal, never publication permission
/// or proof of currently hardened bytes.
pub(crate) fn get_by_handoff_id_in_transaction(
    connection: &Connection,
    handoff_id: Uuid,
) -> Result<Option<HomeArtifactReadback>, HomeArtifactJournalError> {
    if handoff_id.is_nil() {
        return Err(HomeArtifactJournalError::Conflict("nil handoff identity"));
    }
    let Some(stage) = load_stage(connection, handoff_id)? else {
        return Ok(None);
    };
    validate_stage_parent(connection, &stage)?;
    let seal = load_seal(connection, &stage)?;
    Ok(Some(HomeArtifactReadback::new(stage, seal)))
}

/// Persist a seal after the Git owner has returned a full exact readback.
/// This function is crate-private; no public method accepts an archive as proof.
pub(crate) fn seal<C>(
    connection: &mut Connection,
    intent: &HomeArtifactCaptureIntent,
    actor: ActivityCoordinatorActor,
    archive: &HomeArtifactArchive,
    sample_clock: C,
) -> Result<HomeArtifactSealRecord, HomeArtifactJournalError>
where
    C: FnOnce() -> Result<TimestampMillis, HomeArtifactJournalError>,
{
    validate_archive_for_intent(archive, intent, None)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stage = load_stage(&transaction, intent.handoff_id())?.ok_or(
        HomeArtifactJournalError::Conflict("stage missing before seal"),
    )?;
    ensure_exact_intent(&stage, intent)?;
    validate_stage_parent(&transaction, &stage)?;

    if let Some(existing) = load_seal(&transaction, &stage)? {
        if existing.archive() != archive {
            return Err(HomeArtifactJournalError::Conflict(
                "sealed archive differs from exact retained ref",
            ));
        }
        transaction.commit()?;
        return Ok(existing);
    }

    if actor.workspace_id() != stage.workspace_id() || actor.activity_id() != stage.activity_id() {
        return Err(HomeArtifactJournalError::Conflict(
            "seal Coordinator scope differs from immutable stage",
        ));
    }
    let sealed_at = sample_clock()?;
    if sealed_at < stage.source_observed_at() || sealed_at < stage.staged_at() {
        return Err(HomeArtifactJournalError::Conflict(
            "seal time precedes Source observation or stage",
        ));
    }
    validate_current_stage(&transaction, &stage, actor, sealed_at)?;
    validate_archive_for_intent(archive, intent, Some(stage.staged_at()))?;
    let archive_digest = persist_seal(&transaction, &stage, actor, archive, sealed_at)?;
    let readback = load_seal(&transaction, &stage)?
        .ok_or(HomeArtifactJournalError::Corrupt("new seal missing"))?;
    if readback.archive() != archive
        || readback.sealed_by() != actor
        || readback.archive_digest() != &archive_digest
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "new seal differs from fully verified archive",
        ));
    }
    transaction
        .commit()
        .map_err(|source| HomeArtifactJournalError::CommitUnconfirmed {
            handoff_id: intent.handoff_id(),
            phase: "seal",
            source: Box::new(source),
        })?;
    Ok(readback)
}

/// Return whether any pending or sealed Home artifact pins this Workspace.
/// A schema-v72 database predates these tables and is compatible; newer
/// schemas missing either table are treated as damaged rather than removable.
pub(crate) fn blocks_state_removal(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<bool, HomeArtifactJournalError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let stage_table = object_exists(connection, "table", "home_transfer_artifact_stages")?;
    let seal_table = object_exists(connection, "table", "home_transfer_artifact_seals")?;
    if !stage_table && !seal_table {
        return if version <= 72 {
            Ok(false)
        } else {
            Err(HomeArtifactJournalError::Corrupt(
                "schema 73+ is missing Home artifact tables",
            ))
        };
    }
    if version <= 72 || !stage_table || !seal_table {
        return Err(HomeArtifactJournalError::Corrupt(
            "partial or unexpected Home artifact schema",
        ));
    }
    schema::validate_schema(connection)?;
    let orphan_seal: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM home_transfer_artifact_seals e LEFT JOIN home_transfer_artifact_stages s ON s.handoff_id=e.handoff_id AND s.artifact_id=e.artifact_id AND s.workspace_id=e.workspace_id WHERE e.workspace_id=?1 AND s.handoff_id IS NULL)",
        params![workspace_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if orphan_seal {
        return Err(HomeArtifactJournalError::Corrupt(
            "orphan seal without exact stage",
        ));
    }
    let pinned: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM home_transfer_artifact_stages WHERE workspace_id=?1) OR EXISTS(SELECT 1 FROM home_transfer_artifact_seals WHERE workspace_id=?1)",
        params![workspace_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    Ok(pinned)
}

/// Observe at most 256 Home artifact references and one truncation probe from
/// the caller's existing read snapshot. This does not open a nested transaction
/// or read archive snapshots / Git objects.
pub(crate) fn doctor_references(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<HomeArtifactDoctorReport, HomeArtifactJournalError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let stage_table = object_exists(connection, "table", "home_transfer_artifact_stages")?;
    let seal_table = object_exists(connection, "table", "home_transfer_artifact_seals")?;
    if !stage_table && !seal_table {
        return if version <= 72 {
            Ok(HomeArtifactDoctorReport::new(Vec::new(), false))
        } else {
            Err(HomeArtifactJournalError::Corrupt(
                "schema 73+ is missing Home artifact tables",
            ))
        };
    }
    if version <= 72 || !stage_table || !seal_table {
        return Err(HomeArtifactJournalError::Corrupt(
            "partial or unexpected Home artifact schema",
        ));
    }
    schema::validate_schema(connection)?;

    let orphan_seal: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM home_transfer_artifact_seals e LEFT JOIN home_transfer_artifact_stages s ON s.handoff_id=e.handoff_id AND s.artifact_id=e.artifact_id AND s.workspace_id=e.workspace_id WHERE e.workspace_id=?1 AND s.handoff_id IS NULL)",
        params![workspace_id.into_uuid().as_bytes()],
        |row| row.get(0),
    )?;
    if orphan_seal {
        return Err(HomeArtifactJournalError::Corrupt(
            "orphan seal without exact stage",
        ));
    }

    let limit = i64::try_from(DOCTOR_REFERENCE_PROBE)
        .map_err(|_| HomeArtifactJournalError::Bounds("Doctor reference limit"))?;
    let mut statement = connection.prepare(
        "SELECT substr(s.handoff_id,1,17),substr(s.artifact_id,1,17),substr(s.preparation_id,1,17),substr(s.workspace_id,1,17),substr(s.predecessor_assignment_id,1,17),s.predecessor_revision,substr(s.root_assignment_id,1,17),substr(s.intent_digest,1,33),substr(s.intent_snapshot,1,113),substr(s.source_request_digest,1,33),substr(s.source_outcome_digest,1,33),substr(s.source_inventory_digest,1,33),s.source_observed_at_ms,p.outcome,substr(p.request_digest,1,33),substr(p.outcome_digest,1,33),substr(p.inventory_digest,1,33),p.observed_at_ms,substr(e.handoff_id,1,17),substr(e.artifact_id,1,17),substr(e.workspace_id,1,17),substr(e.archive_digest,1,33),substr(e.manifest_digest,1,33),substr(e.commit_id,1,21) FROM home_transfer_artifact_stages s LEFT JOIN home_transfer_source_operations p ON p.preparation_id=s.preparation_id AND p.workspace_id=s.workspace_id LEFT JOIN home_transfer_artifact_seals e ON e.handoff_id=s.handoff_id AND e.artifact_id=s.artifact_id AND e.workspace_id=s.workspace_id WHERE s.workspace_id=?1 ORDER BY s.handoff_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![workspace_id.into_uuid().as_bytes(), limit],
        decode_doctor_row,
    )?;
    let rows = rows.collect::<Result<Vec<_>, _>>()?;
    let truncated = rows.len() > MAX_DOCTOR_REFERENCES;
    let mut references = Vec::with_capacity(rows.len().min(MAX_DOCTOR_REFERENCES));
    for row in rows {
        if decode_uuid(&row.workspace_id, "Doctor Workspace id")? != workspace_id.into_uuid() {
            return Err(HomeArtifactJournalError::Corrupt("Doctor Workspace scope"));
        }
        let reference = validate_doctor_row(&row)?;
        if references.len() < MAX_DOCTOR_REFERENCES {
            references.push(reference);
        }
    }
    Ok(HomeArtifactDoctorReport::new(references, truncated))
}

fn persist_stage(
    transaction: &Transaction<'_>,
    stage: &HomeArtifactStageRecord,
) -> Result<(), HomeArtifactJournalError> {
    let intent = stage.intent();
    let snapshot = intent.to_snapshot_bytes()?;
    if snapshot.is_empty() || snapshot.len() > schema::MAX_ARTIFACT_SNAPSHOT_BYTES {
        return Err(HomeArtifactJournalError::Bounds("intent snapshot"));
    }
    let (principal_kind, principal_id) = principal_columns(stage.coordinator().principal());
    transaction.execute(
        "INSERT INTO home_transfer_artifact_stages (handoff_id,artifact_id,preparation_id,workspace_id,workspace_revision,workspace_root_fingerprint,activity_id,goal_id,predecessor_assignment_id,predecessor_revision,root_assignment_id,coordinator_agent_id,coordinator_session_id,coordinator_principal_kind,coordinator_principal_id,coordinator_revision,source_request_digest,source_outcome_digest,source_inventory_digest,source_observed_at_ms,intent_digest,intent_snapshot,staged_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
        params![
            intent.handoff_id().as_bytes(),
            intent.artifact_id().into_uuid().as_bytes(),
            intent.preparation_id().as_bytes(),
            stage.workspace_id().into_uuid().as_bytes(),
            stage.workspace_revision().get(),
            stage.workspace_root_fingerprint().as_bytes(),
            stage.activity_id().into_uuid().as_bytes(),
            stage.goal_id().into_uuid().as_bytes(),
            intent.predecessor_assignment_id().into_uuid().as_bytes(),
            intent.predecessor_revision().get(),
            intent.root_assignment_id().into_uuid().as_bytes(),
            stage.coordinator().agent_id().into_uuid().as_bytes(),
            stage.coordinator().session_id().into_uuid().as_bytes(),
            principal_kind,
            principal_id,
            stage.coordinator().expected_revision().get(),
            &stage.source_request_digest()[..],
            &stage.source_outcome_digest()[..],
            &stage.source_inventory_digest()[..],
            stage.source_observed_at().get(),
            intent.digest().as_bytes().as_slice(),
            &snapshot,
            stage.staged_at().get(),
        ],
    )?;
    Ok(())
}

fn load_seal(
    connection: &Connection,
    stage: &HomeArtifactStageRecord,
) -> Result<Option<HomeArtifactSealRecord>, HomeArtifactJournalError> {
    let raw = connection
        .query_row(
            "SELECT substr(archive_snapshot,1,2097153),substr(archive_digest,1,33),substr(manifest_digest,1,33),substr(commit_id,1,21),sealed_at_ms FROM home_transfer_artifact_seals WHERE handoff_id=?1 AND artifact_id=?2 AND workspace_id=?3",
            params![
                stage.intent().handoff_id().as_bytes(),
                stage.intent().artifact_id().into_uuid().as_bytes(),
                stage.workspace_id().into_uuid().as_bytes(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((snapshot, raw_digest, raw_manifest_digest, raw_commit, sealed_at_ms)) = raw else {
        let orphaned: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM home_transfer_artifact_seals WHERE handoff_id=?1)",
            params![stage.intent().handoff_id().as_bytes()],
            |row| row.get(0),
        )?;
        if orphaned {
            return Err(HomeArtifactJournalError::Corrupt(
                "seal identity differs from exact stage",
            ));
        }
        return Ok(None);
    };
    if snapshot.is_empty() || snapshot.len() > schema::MAX_ARTIFACT_SNAPSHOT_BYTES {
        return Err(HomeArtifactJournalError::Corrupt(
            "seal archive snapshot bound",
        ));
    }
    let archive = HomeArtifactArchive::from_snapshot_bytes(&snapshot)?;
    let archive_digest = decode_digest(&raw_digest, "seal.archive_digest")?;
    let manifest_digest = decode_digest(&raw_manifest_digest, "seal.manifest_digest")?;
    if archive_snapshot_digest(&snapshot) != archive_digest
        || archive.manifest().digest().as_bytes() != &manifest_digest
        || archive.commit_id().object_id().as_bytes() != raw_commit.as_slice()
        || archive.manifest().intent() != stage.intent()
        || archive.manifest().source_observed_at() != stage.staged_at()
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "seal snapshot, stage, and indexed archive facts disagree",
        ));
    }
    let sealed_at = TimestampMillis::new(sealed_at_ms)
        .map_err(|_| HomeArtifactJournalError::Corrupt("seal.sealed_at"))?;
    if sealed_at < stage.staged_at() || sealed_at < stage.source_observed_at() {
        return Err(HomeArtifactJournalError::Corrupt(
            "seal time precedes stage",
        ));
    }
    Ok(Some(HomeArtifactSealRecord::new(
        stage.clone(),
        archive,
        decode_sealed_by(connection, stage)?,
        archive_digest,
        sealed_at,
    )))
}

fn decode_sealed_by(
    connection: &Connection,
    stage: &HomeArtifactStageRecord,
) -> Result<ActivityCoordinatorActor, HomeArtifactJournalError> {
    let raw = connection
        .query_row(
            "SELECT substr(sealed_by_agent_id,1,17),substr(sealed_by_session_id,1,17),sealed_by_principal_kind,substr(sealed_by_principal_id,1,17),sealed_by_revision FROM home_transfer_artifact_seals WHERE handoff_id=?1 AND artifact_id=?2 AND workspace_id=?3",
            params![
                stage.intent().handoff_id().as_bytes(),
                stage.intent().artifact_id().into_uuid().as_bytes(),
                stage.workspace_id().into_uuid().as_bytes(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(HomeArtifactJournalError::Corrupt("seal Coordinator snapshot missing"))?;
    let actor = ActivityCoordinatorActor::new(
        stage.workspace_id(),
        stage.activity_id(),
        forge_domain::AgentInstanceId::from_uuid(decode_uuid(&raw.0, "seal.sealed_by_agent_id")?),
        ActivityCoordinatorRevision::new(raw.4)
            .map_err(|_| HomeArtifactJournalError::Corrupt("seal.sealed_by_revision"))?,
        decode_principal(raw.2, raw.3.as_deref())?,
        forge_domain::AgentSessionId::from_uuid(decode_uuid(&raw.1, "seal.sealed_by_session_id")?),
    );
    Ok(actor)
}

fn persist_seal(
    transaction: &Transaction<'_>,
    stage: &HomeArtifactStageRecord,
    sealed_by: ActivityCoordinatorActor,
    archive: &HomeArtifactArchive,
    sealed_at: TimestampMillis,
) -> Result<[u8; DIGEST_BYTES], HomeArtifactJournalError> {
    let snapshot = archive.to_snapshot_bytes()?;
    if snapshot.is_empty() || snapshot.len() > schema::MAX_ARTIFACT_SNAPSHOT_BYTES {
        return Err(HomeArtifactJournalError::Bounds("archive snapshot"));
    }
    let archive_digest = archive_snapshot_digest(&snapshot);
    let manifest_digest = archive.manifest().digest();
    let (principal_kind, principal_id) = principal_columns(sealed_by.principal());
    transaction.execute(
        "INSERT INTO home_transfer_artifact_seals (handoff_id,artifact_id,workspace_id,archive_snapshot,archive_digest,manifest_digest,commit_id,sealed_at_ms,sealed_by_agent_id,sealed_by_session_id,sealed_by_principal_kind,sealed_by_principal_id,sealed_by_revision) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            stage.intent().handoff_id().as_bytes(),
            stage.intent().artifact_id().into_uuid().as_bytes(),
            stage.workspace_id().into_uuid().as_bytes(),
            &snapshot,
            &archive_digest[..],
            manifest_digest.as_bytes().as_slice(),
            archive.commit_id().object_id().as_bytes(),
            sealed_at.get(),
            sealed_by.agent_id().into_uuid().as_bytes(),
            sealed_by.session_id().into_uuid().as_bytes(),
            principal_kind,
            principal_id,
            sealed_by.expected_revision().get(),
        ],
    )?;
    Ok(archive_digest)
}

fn load_stage(
    connection: &Connection,
    handoff_id: Uuid,
) -> Result<Option<HomeArtifactStageRecord>, HomeArtifactJournalError> {
    if handoff_id.is_nil() {
        return Err(HomeArtifactJournalError::Conflict("nil handoff identity"));
    }
    let sql = format!(
        "SELECT {SELECT_STAGE_COLUMNS} FROM home_transfer_artifact_stages WHERE handoff_id=?1"
    );
    let raw = connection
        .query_row(&sql, params![handoff_id.as_bytes()], decode_raw_stage)
        .optional()?;
    raw.as_ref().map(decode_stage).transpose()
}

fn load_stage_by_artifact(
    connection: &Connection,
    artifact_id: HomeArtifactId,
) -> Result<Option<HomeArtifactStageRecord>, HomeArtifactJournalError> {
    let handoff = connection
        .query_row(
            "SELECT substr(handoff_id,1,17) FROM home_transfer_artifact_stages WHERE artifact_id=?1",
            params![artifact_id.into_uuid().as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    handoff
        .map(|raw| load_stage(connection, decode_uuid(&raw, "stage.handoff_id")?))
        .transpose()
        .map(Option::flatten)
}

struct RawStage {
    handoff_id: Vec<u8>,
    artifact_id: Vec<u8>,
    preparation_id: Vec<u8>,
    workspace_id: Vec<u8>,
    workspace_revision: i64,
    workspace_root_fingerprint: Vec<u8>,
    activity_id: Vec<u8>,
    goal_id: Vec<u8>,
    predecessor_assignment_id: Vec<u8>,
    predecessor_revision: i64,
    root_assignment_id: Vec<u8>,
    coordinator_agent_id: Vec<u8>,
    coordinator_session_id: Vec<u8>,
    coordinator_principal_kind: i64,
    coordinator_principal_id: Option<Vec<u8>>,
    coordinator_revision: i64,
    source_request_digest: Vec<u8>,
    source_outcome_digest: Vec<u8>,
    source_inventory_digest: Vec<u8>,
    source_observed_at_ms: i64,
    intent_digest: Vec<u8>,
    intent_snapshot: Vec<u8>,
    staged_at_ms: i64,
}

fn decode_raw_stage(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawStage> {
    Ok(RawStage {
        handoff_id: row.get(0)?,
        artifact_id: row.get(1)?,
        preparation_id: row.get(2)?,
        workspace_id: row.get(3)?,
        workspace_revision: row.get(4)?,
        workspace_root_fingerprint: row.get(5)?,
        activity_id: row.get(6)?,
        goal_id: row.get(7)?,
        predecessor_assignment_id: row.get(8)?,
        predecessor_revision: row.get(9)?,
        root_assignment_id: row.get(10)?,
        coordinator_agent_id: row.get(11)?,
        coordinator_session_id: row.get(12)?,
        coordinator_principal_kind: row.get(13)?,
        coordinator_principal_id: row.get(14)?,
        coordinator_revision: row.get(15)?,
        source_request_digest: row.get(16)?,
        source_outcome_digest: row.get(17)?,
        source_inventory_digest: row.get(18)?,
        source_observed_at_ms: row.get(19)?,
        intent_digest: row.get(20)?,
        intent_snapshot: row.get(21)?,
        staged_at_ms: row.get(22)?,
    })
}

struct DecodedStageIdentity {
    intent: HomeArtifactCaptureIntent,
    handoff_id: Uuid,
    artifact_id: HomeArtifactId,
    preparation_id: Uuid,
    workspace_id: WorkspaceId,
    workspace_revision: WorkspaceRevision,
    workspace_root_fingerprint: forge_domain::WorkspaceRootFingerprint,
    activity_id: ActivityId,
    goal_id: GoalId,
    predecessor_assignment_id: AgentAssignmentId,
    predecessor_revision: AgentAssignmentRevision,
    root_assignment_id: AgentAssignmentId,
    coordinator: ActivityCoordinatorActor,
}

fn decode_stage_identity(raw: &RawStage) -> Result<DecodedStageIdentity, HomeArtifactJournalError> {
    if raw.intent_snapshot.is_empty()
        || raw.intent_snapshot.len() > schema::MAX_ARTIFACT_SNAPSHOT_BYTES
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "stage intent snapshot bound",
        ));
    }
    let intent = HomeArtifactCaptureIntent::from_snapshot_bytes(&raw.intent_snapshot)?;
    let handoff_id = decode_uuid(&raw.handoff_id, "stage.handoff_id")?;
    let artifact_id = HomeArtifactId::new(decode_uuid(&raw.artifact_id, "stage.artifact_id")?)
        .map_err(|_| HomeArtifactJournalError::Corrupt("stage artifact identity"))?;
    let preparation_id = decode_uuid(&raw.preparation_id, "stage.preparation_id")?;
    let workspace_id =
        WorkspaceId::from_uuid(decode_uuid(&raw.workspace_id, "stage.workspace_id")?);
    let workspace_revision = WorkspaceRevision::new(raw.workspace_revision)
        .map_err(|_| HomeArtifactJournalError::Corrupt("stage.workspace_revision"))?;
    let root_fingerprint_bytes: [u8; 16] = raw
        .workspace_root_fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| HomeArtifactJournalError::Corrupt("stage.workspace_root_fingerprint"))?;
    if root_fingerprint_bytes == [0; 16] {
        return Err(HomeArtifactJournalError::Corrupt(
            "stage.workspace_root_fingerprint is empty",
        ));
    }
    let workspace_root_fingerprint =
        forge_domain::WorkspaceRootFingerprint::from_bytes(root_fingerprint_bytes);
    let activity_id = ActivityId::from_uuid(decode_uuid(&raw.activity_id, "stage.activity_id")?);
    let goal_id = GoalId::from_uuid(decode_uuid(&raw.goal_id, "stage.goal_id")?);
    let predecessor_assignment_id = AgentAssignmentId::from_uuid(decode_uuid(
        &raw.predecessor_assignment_id,
        "stage.predecessor_assignment_id",
    )?);
    let predecessor_revision = AgentAssignmentRevision::new(raw.predecessor_revision)
        .map_err(|_| HomeArtifactJournalError::Corrupt("stage.predecessor_revision"))?;
    let root_assignment_id = AgentAssignmentId::from_uuid(decode_uuid(
        &raw.root_assignment_id,
        "stage.root_assignment_id",
    )?);
    let coordinator_agent_id = forge_domain::AgentInstanceId::from_uuid(decode_uuid(
        &raw.coordinator_agent_id,
        "stage.coordinator_agent_id",
    )?);
    let coordinator_session_id = forge_domain::AgentSessionId::from_uuid(decode_uuid(
        &raw.coordinator_session_id,
        "stage.coordinator_session_id",
    )?);
    let coordinator_revision = ActivityCoordinatorRevision::new(raw.coordinator_revision)
        .map_err(|_| HomeArtifactJournalError::Corrupt("stage.coordinator_revision"))?;
    let coordinator_principal = decode_principal(
        raw.coordinator_principal_kind,
        raw.coordinator_principal_id.as_deref(),
    )?;
    let coordinator = ActivityCoordinatorActor::new(
        workspace_id,
        activity_id,
        coordinator_agent_id,
        coordinator_revision,
        coordinator_principal,
        coordinator_session_id,
    );

    Ok(DecodedStageIdentity {
        intent,
        handoff_id,
        artifact_id,
        preparation_id,
        workspace_id,
        workspace_revision,
        workspace_root_fingerprint,
        activity_id,
        goal_id,
        predecessor_assignment_id,
        predecessor_revision,
        root_assignment_id,
        coordinator,
    })
}

fn decode_stage(raw: &RawStage) -> Result<HomeArtifactStageRecord, HomeArtifactJournalError> {
    let identity = decode_stage_identity(raw)?;
    let source_request_digest =
        decode_digest(&raw.source_request_digest, "stage.source_request_digest")?;
    let source_outcome_digest =
        decode_digest(&raw.source_outcome_digest, "stage.source_outcome_digest")?;
    let source_inventory_digest = decode_digest(
        &raw.source_inventory_digest,
        "stage.source_inventory_digest",
    )?;
    let stored_intent_digest = decode_digest(&raw.intent_digest, "stage.intent_digest")?;
    let source_observed_at = TimestampMillis::new(raw.source_observed_at_ms)
        .map_err(|_| HomeArtifactJournalError::Corrupt("stage.source_observed_at"))?;
    let staged_at = TimestampMillis::new(raw.staged_at_ms)
        .map_err(|_| HomeArtifactJournalError::Corrupt("stage.staged_at"))?;
    if identity.intent.handoff_id() != identity.handoff_id
        || identity.intent.artifact_id() != identity.artifact_id
        || identity.intent.preparation_id() != identity.preparation_id
        || identity.intent.workspace_id() != identity.workspace_id
        || identity.intent.predecessor_assignment_id() != identity.predecessor_assignment_id
        || identity.intent.predecessor_revision() != identity.predecessor_revision
        || identity.intent.root_assignment_id() != identity.root_assignment_id
        || identity.intent.digest().as_bytes() != &stored_intent_digest
        || identity.coordinator.workspace_id() != identity.workspace_id
        || identity.coordinator.activity_id() != identity.activity_id
        || source_observed_at > staged_at
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "stage columns disagree with canonical intent",
        ));
    }
    Ok(HomeArtifactStageRecord::new(
        identity.intent,
        identity.workspace_id,
        identity.workspace_revision,
        identity.workspace_root_fingerprint,
        identity.activity_id,
        identity.goal_id,
        identity.coordinator,
        source_request_digest,
        source_outcome_digest,
        source_inventory_digest,
        source_observed_at,
        staged_at,
    ))
}

fn validate_stage_parent(
    connection: &Connection,
    stage: &HomeArtifactStageRecord,
) -> Result<(), HomeArtifactJournalError> {
    let (source, inventory) = read_parent(connection, stage.intent())?;
    if source.state() != HomeTransferSourceState::Prepared
        || source.request().scope().workspace_id() != stage.workspace_id()
        || stage.workspace_revision() < source.request().scope().workspace_revision()
        || source.request().request_digest().as_bytes() != stage.source_request_digest()
        || source.outcome_digest() != stage.source_outcome_digest()
        || source.inventory_digest() != Some(stage.source_inventory_digest())
        || source.observed_at() != stage.source_observed_at()
        || inventory.workspace_id != stage.workspace_id().into_uuid()
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "stage no longer matches immutable Prepared Source pins",
        ));
    }
    let captured = captured_assignment(&inventory, stage.intent())?;
    let captured_root_assignment_id = match captured.origin {
        super::super::inventory::SourceAssignmentOrigin::CoordinatorOffer => {
            AgentAssignmentId::from_uuid(captured.assignment_id)
        }
        super::super::inventory::SourceAssignmentOrigin::HomeHandoff {
            preparation_id,
            handoff_id,
            predecessor_id,
            root_assignment_id,
        } => {
            if predecessor_id == captured.assignment_id {
                return Err(HomeArtifactJournalError::Corrupt(
                    "stage Home origin immediate predecessor",
                ));
            }
            let origin = forge_domain::AgentAssignmentHomeHandoffOrigin::new(
                preparation_id,
                handoff_id,
                AgentAssignmentId::from_uuid(predecessor_id),
                AgentAssignmentId::from_uuid(root_assignment_id),
            )
            .map_err(|_| HomeArtifactJournalError::Corrupt("stage Home origin identity"))?;
            validate_home_origin_receipt(
                connection,
                AgentAssignmentId::from_uuid(captured.assignment_id),
                origin,
            )?;
            AgentAssignmentId::from_uuid(root_assignment_id)
        }
        super::super::inventory::SourceAssignmentOrigin::CutContinuation { .. } => {
            return Err(HomeArtifactJournalError::Corrupt(
                "stage contains unsupported Cut continuation lineage",
            ));
        }
    };
    if stage.activity_id().into_uuid() != captured.activity_id
        || stage.goal_id().into_uuid() != captured.goal_id
        || captured.workspace_id != stage.workspace_id().into_uuid()
        || captured.assignment_id != stage.intent().predecessor_assignment_id().into_uuid()
        || captured.revision > stage.intent().predecessor_revision().get()
        || captured.cancellation_requested
        || !matches!(
            captured.state,
            super::super::inventory::SourceAssignmentState::Offered
                | super::super::inventory::SourceAssignmentState::Running
        )
        || stage.intent().root_assignment_id() != captured_root_assignment_id
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "stage predecessor differs from captured Source identity",
        ));
    }
    Ok(())
}

/// Check one persisted Home provenance edge without traversing its ancestors.
/// The assignment repository validates the immutable receipt payload digest,
/// exact successor identity, recipient pins, and immediate parent/root pins.
fn validate_home_origin_receipt(
    connection: &Connection,
    successor_assignment_id: AgentAssignmentId,
    expected_origin: forge_domain::AgentAssignmentHomeHandoffOrigin,
) -> Result<(), HomeArtifactJournalError> {
    let pins =
        crate::workspace_agent_assignments::home_origin::read(connection, successor_assignment_id)?
            .ok_or(HomeArtifactJournalError::Corrupt(
                "Home successor assignment row is missing",
            ))?;
    if pins.origin_kind != 1 {
        return Err(HomeArtifactJournalError::Corrupt(
            "Home successor origin discriminator",
        ));
    }
    let acceptance_id = pins
        .home_receipt_id
        .ok_or(HomeArtifactJournalError::Corrupt(
            "Home successor Applied receipt is missing",
        ))?;
    let persisted_origin =
        crate::workspace_home_transfers::handoffs::get_applied_origin_for_assignment(
            connection,
            successor_assignment_id,
            acceptance_id,
        )?;
    if persisted_origin != AgentAssignmentOrigin::HomeHandoff(expected_origin) {
        return Err(HomeArtifactJournalError::Corrupt(
            "Home successor origin differs from its Applied receipt",
        ));
    }
    Ok(())
}

fn read_parent(
    connection: &Connection,
    intent: &HomeArtifactCaptureIntent,
) -> Result<
    (
        HomeTransferSourceRecord,
        crate::workspace_home_transfers::inventory::HomeTransferSourceInventory,
    ),
    HomeArtifactJournalError,
> {
    let (source, inventory) =
        super::super::repository::read_record_with_inventory(connection, intent.preparation_id())?
            .ok_or(HomeArtifactJournalError::Conflict(
                "exact Prepared Source outcome is missing",
            ))?;
    let inventory = inventory.ok_or(HomeArtifactJournalError::Conflict(
        "exact parent Source outcome is not Prepared",
    ))?;
    Ok((source, inventory))
}

/// Build a fresh in-memory observation request over the same Source actors and
/// destination pins while using the Workspace revision actually visible in
/// this transaction. This request is only an input to the read-only native
/// census; it is never persisted, authorized by Orchestration, or substituted
/// for the immutable Prepared parent.
fn current_source_observation_request(
    connection: &Transaction<'_>,
    source: &HomeTransferSourceRecord,
) -> Result<
    (
        forge_domain::HomeTransferSourceRequest,
        TimestampMillis,
        WorkspaceRevision,
        forge_domain::WorkspaceRootFingerprint,
    ),
    HomeArtifactJournalError,
> {
    let (
        raw_workspace,
        workspace_length,
        revision,
        raw_root_fingerprint,
        root_fingerprint_length,
        updated_at_ms,
    ): (Vec<u8>, i64, i64, Vec<u8>, i64, i64) = connection.query_row(
        "SELECT substr(workspace_id,1,17),length(workspace_id),revision,substr(root_fingerprint,1,17),length(root_fingerprint),updated_at_ms FROM workspace WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    let expected_workspace_length = i64::try_from(ID_BYTES)
        .map_err(|_| HomeArtifactJournalError::Corrupt("current Workspace identity length"))?;
    if workspace_length != expected_workspace_length {
        return Err(HomeArtifactJournalError::Corrupt(
            "current Workspace identity length",
        ));
    }
    let workspace_id =
        WorkspaceId::from_uuid(decode_uuid(&raw_workspace, "current Workspace identity")?);
    if workspace_id != source.request().scope().workspace_id() {
        return Err(HomeArtifactJournalError::Conflict(
            "current Workspace identity differs from Prepared parent",
        ));
    }
    let workspace_revision = WorkspaceRevision::new(revision)
        .map_err(|_| HomeArtifactJournalError::Corrupt("current Workspace revision"))?;
    let workspace_updated_at = TimestampMillis::new(updated_at_ms)
        .map_err(|_| HomeArtifactJournalError::Corrupt("current Workspace updated_at"))?;
    if root_fingerprint_length != 16 {
        return Err(HomeArtifactJournalError::Corrupt(
            "current Workspace root fingerprint length",
        ));
    }
    let root_fingerprint_bytes: [u8; 16] = raw_root_fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| HomeArtifactJournalError::Corrupt("current Workspace root fingerprint"))?;
    if root_fingerprint_bytes == [0; 16] {
        return Err(HomeArtifactJournalError::Corrupt(
            "current Workspace root fingerprint is empty",
        ));
    }
    let root_fingerprint =
        forge_domain::WorkspaceRootFingerprint::from_bytes(root_fingerprint_bytes);
    if workspace_revision < source.request().scope().workspace_revision() {
        return Err(HomeArtifactJournalError::Conflict(
            "current Workspace revision regressed from Prepared parent",
        ));
    }
    let scope = forge_domain::HomeTransferSourceScope::new(
        workspace_id,
        workspace_revision,
        source.request().scope().backend_id(),
        source.request().scope().destination_id(),
    )
    .map_err(|error| HomeArtifactJournalError::Source(HomeTransferStoreError::Domain(error)))?;
    let current_delegation = super::super::repository::validate_current_scope(connection, scope)?;
    if current_delegation.migration_id() != source.migration_id()
        || current_delegation.freeze().revision() != source.freeze_revision()
        || current_delegation.destination_id() != source.request().scope().destination_id()
        || current_delegation.manifest_digest().as_slice() != source.delegation_digest().as_slice()
    {
        return Err(HomeArtifactJournalError::Conflict(
            "current delegation differs from immutable Prepared Source pins",
        ));
    }
    let request = forge_domain::HomeTransferSourceRequest::new(
        source.request().witness(),
        scope,
        source.request().subject(),
        source.request().sessions().to_vec(),
        source.request().bindings().to_vec(),
    )
    .map_err(|error| HomeArtifactJournalError::Source(HomeTransferStoreError::Domain(error)))?;
    Ok((
        request,
        workspace_updated_at,
        workspace_revision,
        root_fingerprint,
    ))
}

fn captured_assignment<'a>(
    inventory: &'a crate::workspace_home_transfers::inventory::HomeTransferSourceInventory,
    intent: &HomeArtifactCaptureIntent,
) -> Result<
    &'a crate::workspace_home_transfers::inventory::SourceAssignment,
    HomeArtifactJournalError,
> {
    inventory
        .assignments
        .iter()
        .find(|assignment| {
            assignment.assignment_id == intent.predecessor_assignment_id().into_uuid()
        })
        .ok_or(HomeArtifactJournalError::Conflict(
            "predecessor Assignment is absent from pinned Source inventory",
        ))
}

fn validate_source_and_predecessor(
    connection: &Transaction<'_>,
    intent: &HomeArtifactCaptureIntent,
) -> Result<CurrentStageFacts, HomeArtifactJournalError> {
    let (source, parent_inventory) = read_parent(connection, intent)?;
    validate_prepared_parent(&source, &parent_inventory, intent)?;
    let (
        current_request,
        current_workspace_updated_at,
        current_workspace_revision,
        current_workspace_root_fingerprint,
    ) = current_source_observation_request(connection, &source)?;

    let captured = captured_assignment(&parent_inventory, intent)?;
    validate_pinned_predecessor(captured, intent)?;
    let assignment = current_predecessor(connection, intent, captured)?;
    let current_inventory =
        current_source_inventory(connection, &current_request, intent, &assignment)?;
    let root = validate_current_predecessor_root(connection, &assignment, intent)?;
    let activity_id = assignment.activity_id();
    let goal_id = assignment.goal_id();
    Ok(CurrentStageFacts {
        source,
        assignment,
        workspace_revision: current_workspace_revision,
        workspace_root_fingerprint: current_workspace_root_fingerprint,
        activity_id,
        goal_id,
        root_assignment_id: root,
        source_high_water_ms: current_inventory
            .source_high_water_ms
            .max(current_workspace_updated_at.get()),
    })
}

fn validate_prepared_parent(
    source: &HomeTransferSourceRecord,
    inventory: &crate::workspace_home_transfers::inventory::HomeTransferSourceInventory,
    intent: &HomeArtifactCaptureIntent,
) -> Result<(), HomeArtifactJournalError> {
    if source.state() != HomeTransferSourceState::Prepared
        || source.request().scope().workspace_id() != intent.workspace_id()
        || inventory.workspace_id != intent.workspace_id().into_uuid()
    {
        return Err(HomeArtifactJournalError::Conflict(
            "exact Home artifact Source scope or outcome",
        ));
    }
    Ok(())
}

fn validate_pinned_predecessor(
    captured: &super::super::inventory::SourceAssignment,
    intent: &HomeArtifactCaptureIntent,
) -> Result<(), HomeArtifactJournalError> {
    if captured.workspace_id != intent.workspace_id().into_uuid()
        || captured.assignment_id != intent.predecessor_assignment_id().into_uuid()
        || captured.cancellation_requested
        || !matches!(
            captured.state,
            super::super::inventory::SourceAssignmentState::Offered
                | super::super::inventory::SourceAssignmentState::Running
        )
    {
        return Err(HomeArtifactJournalError::UnsupportedLineage);
    }
    let root_assignment_id = match captured.origin {
        super::super::inventory::SourceAssignmentOrigin::CoordinatorOffer => {
            intent.predecessor_assignment_id()
        }
        super::super::inventory::SourceAssignmentOrigin::HomeHandoff {
            predecessor_id,
            root_assignment_id,
            ..
        } if predecessor_id != captured.assignment_id => {
            AgentAssignmentId::from_uuid(root_assignment_id)
        }
        super::super::inventory::SourceAssignmentOrigin::HomeHandoff { .. }
        | super::super::inventory::SourceAssignmentOrigin::CutContinuation { .. } => {
            return Err(HomeArtifactJournalError::UnsupportedLineage);
        }
    };
    if root_assignment_id != intent.root_assignment_id() {
        return Err(HomeArtifactJournalError::Conflict(
            "caller root does not match pinned Source lineage",
        ));
    }
    Ok(())
}

fn current_predecessor(
    connection: &Transaction<'_>,
    intent: &HomeArtifactCaptureIntent,
    captured: &super::super::inventory::SourceAssignment,
) -> Result<forge_domain::RegisteredAgentAssignment, HomeArtifactJournalError> {
    let assignment = workspace_agent_assignments::get_in_transaction(
        connection,
        intent.predecessor_assignment_id(),
    )?
    .ok_or(HomeArtifactJournalError::Conflict(
        "current predecessor Assignment is missing",
    ))?;
    if assignment.workspace_id() != intent.workspace_id()
        || assignment.id() != intent.predecessor_assignment_id()
        || assignment.revision() != intent.predecessor_revision()
        || assignment.cancellation_requested()
        || !matches!(
            assignment.state(),
            AgentAssignmentState::Offered | AgentAssignmentState::Running
        )
        || assignment.activity_id().into_uuid() != captured.activity_id
        || assignment.goal_id().into_uuid() != captured.goal_id
        || !captured_identity_matches_assignment(captured, &assignment)
    {
        return Err(HomeArtifactJournalError::Conflict(
            "current predecessor Assignment identity, revision, or eligibility",
        ));
    }
    Ok(assignment)
}

fn current_source_inventory(
    connection: &Transaction<'_>,
    request: &forge_domain::HomeTransferSourceRequest,
    intent: &HomeArtifactCaptureIntent,
    assignment: &forge_domain::RegisteredAgentAssignment,
) -> Result<
    crate::workspace_home_transfers::inventory::HomeTransferSourceInventory,
    HomeArtifactJournalError,
> {
    // Re-capture the current Source-owned census in this exact transaction.
    // The immutable Prepared capsule proves lineage; the fresh census proves
    // that active effects have reached owner-recognized terminal closure.
    let inventory =
        crate::workspace_home_transfers::inventory::HomeTransferSourceInventory::capture(
            connection, request,
        )
        .map_err(|error| {
            HomeArtifactJournalError::Source(HomeTransferStoreError::Inventory(Box::new(error)))
        })?;
    if inventory.workspace_id != intent.workspace_id().into_uuid() {
        return Err(HomeArtifactJournalError::Conflict(
            "current Source census Workspace identity",
        ));
    }
    let captured = captured_assignment(&inventory, intent)?;
    if captured.cancellation_requested
        || !captured_identity_matches_assignment(captured, assignment)
    {
        return Err(HomeArtifactJournalError::Conflict(
            "current Source census differs from predecessor Assignment",
        ));
    }
    ensure_predecessor_quiescent(&inventory, intent)?;
    Ok(inventory)
}

fn validate_current_predecessor_root(
    connection: &Transaction<'_>,
    assignment: &forge_domain::RegisteredAgentAssignment,
    intent: &HomeArtifactCaptureIntent,
) -> Result<AgentAssignmentId, HomeArtifactJournalError> {
    let root = match assignment.origin() {
        AgentAssignmentOrigin::CoordinatorOffer => assignment.id(),
        // `current_predecessor` decoded this row from the same Source
        // transaction. The assignment repository resolves each Home origin
        // through its exact Applied receipt and canonical payload checksum.
        AgentAssignmentOrigin::HomeHandoff(origin) => origin.root_assignment_id(),
        AgentAssignmentOrigin::CutContinuation(_) => {
            return Err(HomeArtifactJournalError::UnsupportedLineage);
        }
    };
    if root != intent.root_assignment_id() {
        return Err(HomeArtifactJournalError::Conflict(
            "caller root does not match current Source lineage",
        ));
    }

    let goal = workspace_goals::get_goal(connection, assignment.goal_id())?.ok_or(
        HomeArtifactJournalError::Conflict("current predecessor Goal is missing"),
    )?;
    if goal.workspace_id() != intent.workspace_id()
        || goal.activity_id() != assignment.activity_id()
        || goal.timestamps().created_at() != assignment.goal_created_at()
    {
        return Err(HomeArtifactJournalError::Conflict(
            "predecessor Activity or Goal scope",
        ));
    }
    Ok(root)
}

fn source_origin_matches_assignment(
    captured: super::super::inventory::SourceAssignmentOrigin,
    current: AgentAssignmentOrigin,
) -> bool {
    use super::super::inventory::SourceAssignmentOrigin;
    match (captured, current) {
        (SourceAssignmentOrigin::CoordinatorOffer, AgentAssignmentOrigin::CoordinatorOffer) => true,
        (
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id,
                handoff_id,
                predecessor_id,
                root_assignment_id,
            },
            AgentAssignmentOrigin::HomeHandoff(origin),
        ) => {
            preparation_id == origin.preparation_id()
                && handoff_id == origin.handoff_id()
                && predecessor_id == origin.predecessor_id().into_uuid()
                && root_assignment_id == origin.root_assignment_id().into_uuid()
        }
        _ => false,
    }
}

fn captured_identity_matches_assignment(
    captured: &crate::workspace_home_transfers::inventory::SourceAssignment,
    assignment: &forge_domain::RegisteredAgentAssignment,
) -> bool {
    let coordinator = assignment.coordinator();
    let target = assignment.target();
    captured.assignment_id == assignment.id().into_uuid()
        && captured.workspace_id == assignment.workspace_id().into_uuid()
        && captured.activity_id == assignment.activity_id().into_uuid()
        && captured.goal_id == assignment.goal_id().into_uuid()
        && captured.goal_created_at_ms == assignment.goal_created_at().get()
        && captured.goal_revision == assignment.goal_revision().get()
        && captured.dag_revision == assignment.dag_revision().get()
        && captured.dag_head_revision == assignment.dag_head_revision().get()
        && captured.node_id == assignment.node_id().into_uuid()
        && captured.node_revision == assignment.node_revision().get()
        && captured.coordinator_agent_id == coordinator.agent_id().into_uuid()
        && captured.coordinator_session_id == coordinator.session_id().into_uuid()
        && principal_matches(captured.coordinator_principal, coordinator.principal())
        && captured.coordinator_revision == coordinator.revision().get()
        && captured.target_agent_id == target.agent_id().into_uuid()
        && captured.target_session_id == target.session_id().into_uuid()
        && principal_matches(captured.target_principal, target.principal())
        && captured.target_agent_revision == target.agent_revision().get()
        && captured.revision <= assignment.revision().get()
        && source_budget_matches(captured.credit_budget, assignment.credit_budget())
        && source_origin_matches_assignment(captured.origin, assignment.origin())
        && matches!(
            (captured.state, assignment.state()),
            (
                super::super::inventory::SourceAssignmentState::Offered,
                AgentAssignmentState::Offered | AgentAssignmentState::Running,
            ) | (
                super::super::inventory::SourceAssignmentState::Running,
                AgentAssignmentState::Running,
            ),
        )
}

/// Reject a new stage/seal while current Source owners still expose effects
/// attributable to captured Agent/Session aliases, or overlapping Starting
/// effects in affected Activities. Known unrelated Agent leases, executions,
/// and approvals remain outside this custody fence.
fn ensure_predecessor_quiescent(
    inventory: &crate::workspace_home_transfers::inventory::HomeTransferSourceInventory,
    intent: &HomeArtifactCaptureIntent,
) -> Result<(), HomeArtifactJournalError> {
    let captured_agent_ids = inventory
        .agents
        .iter()
        .map(|agent| agent.agent_id)
        .collect::<BTreeSet<_>>();
    let captured_session_ids = inventory
        .session_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let affected_activity_ids = inventory
        .affected_activity_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    for lease in &inventory.writer_leases {
        if !captured_agent_ids.contains(&lease.agent_id) {
            continue;
        }
        let overlaps_declared_path = lease.entries.iter().any(|entry| {
            intent.paths().iter().any(|path| {
                let requested = path.as_path().as_os_str().as_bytes();
                match entry.kind {
                    super::super::inventory::SourceWriterLeaseScopeKind::ExactPath => {
                        entry.path.as_slice() == requested
                    }
                    super::super::inventory::SourceWriterLeaseScopeKind::DirectorySubtree => {
                        paths_overlap(&entry.path, requested)
                    }
                }
            })
        });
        if overlaps_declared_path {
            return Err(HomeArtifactJournalError::Quiescence(
                "a captured Source Agent has an active Writer Lease over a declared path",
            ));
        }
    }

    for execution in &inventory.executions {
        let attributed_to_captured_source = execution
            .agent_id
            .is_some_and(|agent_id| captured_agent_ids.contains(&agent_id))
            || execution
                .session_id
                .is_some_and(|session_id| captured_session_ids.contains(&session_id));
        let unattributed_in_affected_activity = execution.agent_id.is_none()
            && execution.session_id.is_none()
            && affected_activity_ids.contains(&execution.activity_id);
        if attributed_to_captured_source || unattributed_in_affected_activity {
            return Err(HomeArtifactJournalError::Quiescence(
                "relevant execution remains outside the terminal native-closure census",
            ));
        }
    }

    for approval in &inventory.approvals {
        if !approval_scope_matches_captured_source(
            approval,
            &captured_agent_ids,
            &captured_session_ids,
            &affected_activity_ids,
        ) || !approval_can_admit_or_outlive_source_work(approval)
        {
            continue;
        }
        return Err(HomeArtifactJournalError::Quiescence(
            "captured Source work has pending or active approval authority",
        ));
    }

    for change_set in &inventory.change_sets {
        if affected_activity_ids.contains(&change_set.activity_id)
            && change_set.state == super::super::inventory::SourceChangeSetState::Starting
            && change_set_overlaps_declared_paths(change_set, intent)
        {
            return Err(HomeArtifactJournalError::Quiescence(
                "a Started file/tree effect overlaps a declared artifact path",
            ));
        }
    }
    Ok(())
}

fn approval_scope_matches_captured_source(
    approval: &crate::workspace_home_transfers::inventory::SourceApproval,
    captured_agent_ids: &BTreeSet<Uuid>,
    captured_session_ids: &BTreeSet<Uuid>,
    affected_activity_ids: &BTreeSet<Uuid>,
) -> bool {
    match &approval.attribution {
        super::super::inventory::SourceApprovalAttribution::Known {
            agent_id,
            session_id,
            ..
        } => {
            captured_agent_ids.contains(agent_id)
                || session_id.is_some_and(|session_id| captured_session_ids.contains(&session_id))
        }
        // A legacy Activity approval has no verifiable author or Goal. It
        // remains relevant uncertainty in any Activity covered by the census.
        super::super::inventory::SourceApprovalAttribution::LegacyUnknown => {
            affected_activity_ids.contains(&approval.activity_id)
        }
    }
}

fn approval_can_admit_or_outlive_source_work(
    approval: &crate::workspace_home_transfers::inventory::SourceApproval,
) -> bool {
    use super::super::inventory::{
        SourceApprovalGrant, SourceApprovalState, SourceExecutionGrantState,
    };
    if approval.state == SourceApprovalState::Pending {
        return true;
    }
    match &approval.grant {
        SourceApprovalGrant::Unknown => matches!(
            approval.state,
            SourceApprovalState::Approved | SourceApprovalState::AutoApproved
        ),
        SourceApprovalGrant::Present {
            state: SourceExecutionGrantState::Active,
            consumed_at_ms: None,
            ..
        } => true,
        SourceApprovalGrant::Present { .. } | SourceApprovalGrant::Absent => false,
    }
}

fn change_set_overlaps_declared_paths(
    change_set: &crate::workspace_home_transfers::inventory::SourceChangeSet,
    intent: &HomeArtifactCaptureIntent,
) -> bool {
    let path_overlaps = |raw_path: &[u8]| {
        intent
            .paths()
            .iter()
            .any(|path| paths_overlap(raw_path, path.as_path().as_os_str().as_bytes()))
    };
    if change_set
        .file_mutation
        .as_ref()
        .is_some_and(|mutation| path_overlaps(&mutation.path))
    {
        return true;
    }
    change_set.tree_mutations.iter().any(|mutation| {
        path_overlaps(&mutation.primary_path)
            || mutation
                .secondary_path
                .as_deref()
                .is_some_and(&path_overlaps)
    })
}

fn paths_overlap(left: &[u8], right: &[u8]) -> bool {
    fn same_or_descendant(parent: &[u8], candidate: &[u8]) -> bool {
        candidate == parent
            || (candidate.len() > parent.len()
                && candidate.starts_with(parent)
                && candidate.get(parent.len()) == Some(&b'/'))
    }
    same_or_descendant(left, right) || same_or_descendant(right, left)
}

fn principal_matches(
    captured: super::super::inventory::SourcePrincipal,
    principal: AuthenticatedPrincipal,
) -> bool {
    match (captured, principal) {
        (
            super::super::inventory::SourcePrincipal::TrustedStdio,
            AuthenticatedPrincipal::TrustedStdio,
        ) => true,
        (
            super::super::inventory::SourcePrincipal::DirectToken(captured),
            AuthenticatedPrincipal::DirectToken(principal),
        ) => captured == principal.into_uuid(),
        (
            super::super::inventory::SourcePrincipal::OAuthGrant(captured),
            AuthenticatedPrincipal::OAuthGrant(principal),
        ) => captured == principal.into_uuid(),
        _ => false,
    }
}

fn source_budget_matches(
    captured: Option<super::super::inventory::SourceWorkCreditBudget>,
    current: Option<forge_domain::WorkCreditBudget>,
) -> bool {
    matches!(
        (captured, current),
        (None, None)
            | (
                Some(super::super::inventory::SourceWorkCreditBudget::One),
                Some(forge_domain::WorkCreditBudget::One),
            )
            | (
                Some(super::super::inventory::SourceWorkCreditBudget::Three),
                Some(forge_domain::WorkCreditBudget::Three),
            )
            | (
                Some(super::super::inventory::SourceWorkCreditBudget::Five),
                Some(forge_domain::WorkCreditBudget::Five),
            )
    )
}

fn validate_current_stage(
    connection: &Transaction<'_>,
    stage: &HomeArtifactStageRecord,
    actor: ActivityCoordinatorActor,
    observed_at: TimestampMillis,
) -> Result<(), HomeArtifactJournalError> {
    if actor.workspace_id() != stage.workspace_id() || actor.activity_id() != stage.activity_id() {
        return Err(HomeArtifactJournalError::Conflict(
            "current Coordinator scope differs from immutable stage",
        ));
    }
    let facts = validate_source_and_predecessor(connection, stage.intent())?;
    if facts.activity_id != stage.activity_id()
        || facts.goal_id != stage.goal_id()
        || facts.workspace_revision < stage.workspace_revision()
        || facts.workspace_root_fingerprint != stage.workspace_root_fingerprint()
        || facts.root_assignment_id != stage.intent().root_assignment_id()
        || facts.assignment.revision() != stage.intent().predecessor_revision()
        || facts.source.outcome_digest() != stage.source_outcome_digest()
        || facts.source.observed_at() != stage.source_observed_at()
        || facts.assignment.updated_at() > observed_at
        || facts.source.observed_at() > observed_at
        || facts.source_high_water_ms > observed_at.get()
    {
        return Err(HomeArtifactJournalError::Conflict(
            "stage, parent Source, current census, or predecessor changed before seal",
        ));
    }
    let _authorized_coordinator =
        workspace_coordinators::authorize_live_in_transaction(connection, actor, observed_at)?;
    Ok(())
}

fn ensure_exact_intent(
    stage: &HomeArtifactStageRecord,
    intent: &HomeArtifactCaptureIntent,
) -> Result<(), HomeArtifactJournalError> {
    if stage.intent() != intent {
        return Err(HomeArtifactJournalError::Conflict(
            "handoff identity reused with a changed capture intent",
        ));
    }
    Ok(())
}

fn validate_archive_for_intent(
    archive: &HomeArtifactArchive,
    intent: &HomeArtifactCaptureIntent,
    capture_at: Option<TimestampMillis>,
) -> Result<(), HomeArtifactJournalError> {
    if archive.manifest().intent() != intent
        || capture_at.is_some_and(|expected| archive.manifest().source_observed_at() != expected)
    {
        return Err(HomeArtifactJournalError::Conflict(
            "verified archive does not match exact stage intent or capture time",
        ));
    }
    Ok(())
}

fn principal_columns(principal: AuthenticatedPrincipal) -> (i64, Option<Vec<u8>>) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => (0, None),
        AuthenticatedPrincipal::DirectToken(id) => (1, Some(id.into_uuid().as_bytes().to_vec())),
        AuthenticatedPrincipal::OAuthGrant(id) => (2, Some(id.into_uuid().as_bytes().to_vec())),
    }
}

fn decode_principal(
    kind: i64,
    raw_id: Option<&[u8]>,
) -> Result<AuthenticatedPrincipal, HomeArtifactJournalError> {
    match (kind, raw_id) {
        (0, None) => Ok(AuthenticatedPrincipal::TrustedStdio),
        (1, Some(bytes)) => Ok(AuthenticatedPrincipal::DirectToken(
            DirectTokenId::from_uuid(decode_uuid(bytes, "coordinator.principal")?),
        )),
        (2, Some(bytes)) => Ok(AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(
            decode_uuid(bytes, "coordinator.principal")?,
        ))),
        _ => Err(HomeArtifactJournalError::Corrupt(
            "coordinator principal storage shape",
        )),
    }
}

fn decode_uuid(raw: &[u8], field: &'static str) -> Result<Uuid, HomeArtifactJournalError> {
    if raw.len() != ID_BYTES {
        return Err(HomeArtifactJournalError::Corrupt(field));
    }
    let id = Uuid::from_slice(raw).map_err(|_| HomeArtifactJournalError::Corrupt(field))?;
    if id.is_nil() {
        return Err(HomeArtifactJournalError::Corrupt(field));
    }
    Ok(id)
}

fn decode_digest(
    raw: &[u8],
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], HomeArtifactJournalError> {
    raw.try_into()
        .map_err(|_| HomeArtifactJournalError::Corrupt(field))
}

fn archive_snapshot_digest(snapshot: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(ARCHIVE_DIGEST_DOMAIN);
    digest.update(snapshot);
    digest.finalize().into()
}

fn object_exists(
    connection: &Connection,
    kind: &'static str,
    name: &'static str,
) -> Result<bool, HomeArtifactJournalError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type=?1 AND name=?2)",
        params![kind, name],
        |row| row.get(0),
    )?)
}

struct RawDoctorRow {
    handoff_id: Vec<u8>,
    artifact_id: Vec<u8>,
    preparation_id: Vec<u8>,
    workspace_id: Vec<u8>,
    predecessor_assignment_id: Vec<u8>,
    predecessor_revision: i64,
    root_assignment_id: Vec<u8>,
    intent_digest: Vec<u8>,
    intent_prefix: Vec<u8>,
    stage_source_request_digest: Vec<u8>,
    stage_source_outcome_digest: Vec<u8>,
    stage_source_inventory_digest: Vec<u8>,
    stage_source_observed_at_ms: i64,
    parent_outcome: Option<i64>,
    parent_request_digest: Option<Vec<u8>>,
    parent_outcome_digest: Option<Vec<u8>>,
    parent_inventory_digest: Option<Vec<u8>>,
    parent_observed_at_ms: Option<i64>,
    seal_handoff_id: Option<Vec<u8>>,
    seal_artifact_id: Option<Vec<u8>>,
    seal_workspace_id: Option<Vec<u8>>,
    seal_archive_digest: Option<Vec<u8>>,
    seal_manifest_digest: Option<Vec<u8>>,
    seal_commit_id: Option<Vec<u8>>,
}

fn decode_doctor_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawDoctorRow> {
    Ok(RawDoctorRow {
        handoff_id: row.get(0)?,
        artifact_id: row.get(1)?,
        preparation_id: row.get(2)?,
        workspace_id: row.get(3)?,
        predecessor_assignment_id: row.get(4)?,
        predecessor_revision: row.get(5)?,
        root_assignment_id: row.get(6)?,
        intent_digest: row.get(7)?,
        intent_prefix: row.get(8)?,
        stage_source_request_digest: row.get(9)?,
        stage_source_outcome_digest: row.get(10)?,
        stage_source_inventory_digest: row.get(11)?,
        stage_source_observed_at_ms: row.get(12)?,
        parent_outcome: row.get(13)?,
        parent_request_digest: row.get(14)?,
        parent_outcome_digest: row.get(15)?,
        parent_inventory_digest: row.get(16)?,
        parent_observed_at_ms: row.get(17)?,
        seal_handoff_id: row.get(18)?,
        seal_artifact_id: row.get(19)?,
        seal_workspace_id: row.get(20)?,
        seal_archive_digest: row.get(21)?,
        seal_manifest_digest: row.get(22)?,
        seal_commit_id: row.get(23)?,
    })
}

fn validate_doctor_row(
    row: &RawDoctorRow,
) -> Result<HomeArtifactDoctorReference, HomeArtifactJournalError> {
    let handoff_id = decode_uuid(&row.handoff_id, "Doctor handoff id")?;
    let artifact_uuid = decode_uuid(&row.artifact_id, "Doctor artifact id")?;
    let workspace_id = decode_uuid(&row.workspace_id, "Doctor Workspace id")?;
    let intent_digest = decode_digest(&row.intent_digest, "Doctor intent digest")?;
    let source_request_digest = decode_digest(
        &row.stage_source_request_digest,
        "Doctor stage Source request digest",
    )?;
    let source_outcome_digest = decode_digest(
        &row.stage_source_outcome_digest,
        "Doctor stage Source outcome digest",
    )?;
    let source_inventory_digest = decode_digest(
        &row.stage_source_inventory_digest,
        "Doctor stage Source inventory digest",
    )?;
    if row.predecessor_revision < 1 || row.stage_source_observed_at_ms < 0 {
        return Err(HomeArtifactJournalError::Corrupt("Doctor stage scalar"));
    }
    match (
        row.parent_outcome,
        row.parent_request_digest.as_deref(),
        row.parent_outcome_digest.as_deref(),
        row.parent_inventory_digest.as_deref(),
        row.parent_observed_at_ms,
    ) {
        (Some(0), Some(request), Some(outcome), Some(inventory), Some(observed_at))
            if request == source_request_digest.as_slice()
                && outcome == source_outcome_digest.as_slice()
                && inventory == source_inventory_digest.as_slice()
                && observed_at == row.stage_source_observed_at_ms => {}
        _ => {
            return Err(HomeArtifactJournalError::Corrupt(
                "Doctor stage has no exact Prepared Source parent",
            ));
        }
    }
    validate_intent_prefix(&row.intent_prefix, row)?;

    let (expected_commit, manifest_digest) = match (
        row.seal_handoff_id.as_deref(),
        row.seal_artifact_id.as_deref(),
        row.seal_workspace_id.as_deref(),
        row.seal_archive_digest.as_deref(),
        row.seal_manifest_digest.as_deref(),
        row.seal_commit_id.as_deref(),
    ) {
        (None, None, None, None, None, None) => (None, None),
        (
            Some(handoff),
            Some(artifact),
            Some(workspace),
            Some(archive),
            Some(manifest),
            Some(commit),
        ) => {
            if decode_uuid(handoff, "Doctor seal handoff id")? != handoff_id
                || decode_uuid(artifact, "Doctor seal artifact id")? != artifact_uuid
                || decode_uuid(workspace, "Doctor seal Workspace id")? != workspace_id
                || decode_digest(archive, "Doctor seal archive digest")? == [0; DIGEST_BYTES]
                || decode_digest(manifest, "Doctor seal manifest digest")? == [0; DIGEST_BYTES]
                || commit.len() != COMMIT_BYTES
                || commit.iter().all(|byte| *byte == 0)
            {
                return Err(HomeArtifactJournalError::Corrupt(
                    "Doctor seal identity or digest",
                ));
            }
            (
                Some(GitCommitId::from_sha1_bytes(commit.try_into().map_err(
                    |_| HomeArtifactJournalError::Corrupt("Doctor seal commit id"),
                )?)),
                Some(decode_digest(manifest, "Doctor seal manifest digest")?),
            )
        }
        _ => return Err(HomeArtifactJournalError::Corrupt("Doctor seal row shape")),
    };
    let artifact_id = HomeArtifactId::new(artifact_uuid)
        .map_err(|_| HomeArtifactJournalError::Corrupt("Doctor artifact identity"))?;
    Ok(HomeArtifactDoctorReference::new(
        artifact_id,
        intent_digest,
        expected_commit,
        manifest_digest,
    ))
}

fn validate_intent_prefix(
    prefix: &[u8],
    row: &RawDoctorRow,
) -> Result<(), HomeArtifactJournalError> {
    const PREFIX_BYTES: usize = 113;
    if prefix.len() != PREFIX_BYTES || prefix.get(..5) != Some(b"FHCI\x01") {
        return Err(HomeArtifactJournalError::Corrupt(
            "Doctor bounded intent prefix",
        ));
    }
    let uuid_at = |offset: usize| -> Result<Uuid, HomeArtifactJournalError> {
        let end = offset
            .checked_add(ID_BYTES)
            .ok_or(HomeArtifactJournalError::Corrupt("Doctor intent offset"))?;
        let bytes = prefix
            .get(offset..end)
            .ok_or(HomeArtifactJournalError::Corrupt("Doctor intent prefix"))?;
        decode_uuid(bytes, "Doctor intent identity")
    };
    let stored_revision = i64::from_be_bytes(
        prefix[85..93]
            .try_into()
            .map_err(|_| HomeArtifactJournalError::Corrupt("Doctor intent revision"))?,
    );
    let path_count = u32::from_be_bytes(
        prefix[109..113]
            .try_into()
            .map_err(|_| HomeArtifactJournalError::Corrupt("Doctor intent path count"))?,
    );
    let maximum_path_count = u32::try_from(forge_domain::MAX_HOME_ARTIFACT_PATHS)
        .map_err(|_| HomeArtifactJournalError::Corrupt("Doctor maximum artifact path count"))?;
    if uuid_at(5)? != decode_uuid(&row.artifact_id, "Doctor artifact id")?
        || uuid_at(21)? != decode_uuid(&row.preparation_id, "Doctor preparation id")?
        || uuid_at(37)? != decode_uuid(&row.handoff_id, "Doctor handoff id")?
        || uuid_at(53)? != decode_uuid(&row.workspace_id, "Doctor Workspace id")?
        || uuid_at(69)? != decode_uuid(&row.predecessor_assignment_id, "Doctor predecessor id")?
        || stored_revision != row.predecessor_revision
        || uuid_at(93)? != decode_uuid(&row.root_assignment_id, "Doctor root assignment id")?
        || path_count > maximum_path_count
    {
        return Err(HomeArtifactJournalError::Corrupt(
            "Doctor stage identity differs from bounded intent prefix",
        ));
    }
    Ok(())
}
