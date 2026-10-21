//! Read-only settlement evidence for the exact effects captured by one cut.
//!
//! A drained observation is not an assignment transfer, a recipient acceptance,
//! an issuer credential, or permission to release custody. The next write must
//! independently revalidate it inside its own transaction.

use std::collections::BTreeSet;

use forge_domain::TimestampMillis;
use rusqlite::{Connection, Transaction, params};
use uuid::Uuid;

use super::{
    MAX_WORK_CUT_EFFECTS, WorkCutEffect, WorkCutEffectKind, WorkCutError, WorkCutRecord,
    WorkCutState, decode_id, effects, repository,
};

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkCutEffectSettlement {
    Pending,
    Settled,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCutEffectProgress {
    kind: WorkCutEffectKind,
    id: Uuid,
    revision: i64,
    settlement: WorkCutEffectSettlement,
}

impl WorkCutEffectProgress {
    pub const fn kind(self) -> WorkCutEffectKind {
        self.kind
    }
    pub const fn id(self) -> Uuid {
        self.id
    }
    pub const fn revision(self) -> i64 {
        self.revision
    }
    pub const fn settlement(self) -> WorkCutEffectSettlement {
        self.settlement
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCutDrainObservation {
    cut_id: Uuid,
    cut_revision: i64,
    snapshot_digest: [u8; 32],
    observed_at: TimestampMillis,
    effects: Vec<WorkCutEffectProgress>,
}

impl WorkCutDrainObservation {
    pub const fn cut_id(&self) -> Uuid {
        self.cut_id
    }
    pub const fn cut_revision(&self) -> i64 {
        self.cut_revision
    }
    pub const fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
    pub fn effects(&self) -> &[WorkCutEffectProgress] {
        &self.effects
    }
    pub fn effects_drained(&self) -> bool {
        self.effects
            .iter()
            .all(|effect| effect.settlement == WorkCutEffectSettlement::Settled)
    }
}

// One bounded batch, with exact keys on each live effect owner. LEFT JOIN is
// intentional: a missing effect must be diagnosed, never counted as settled.
const EFFECT_PROGRESS_SQL: &str = "
    SELECT f.effect_kind, f.effect_id, w.workspace_id, w.activity_id,
           w.agent_id, w.state, w.revision
      FROM leadership_work_cut_effects f
      LEFT JOIN writer_leases w ON w.lease_id=f.effect_id
     WHERE f.cut_id=?1 AND f.effect_kind=0
    UNION ALL
    SELECT f.effect_kind, f.effect_id, e.workspace_id, e.activity_id,
           p.agent_id, e.state, e.revision
      FROM leadership_work_cut_effects f
      LEFT JOIN executions e ON e.execution_id=f.effect_id
      LEFT JOIN execution_provenance p ON p.execution_id=e.execution_id
     WHERE f.cut_id=?1 AND f.effect_kind=1
    UNION ALL
    SELECT f.effect_kind, f.effect_id, c.workspace_id, c.activity_id,
           NULL, c.state, c.revision
      FROM leadership_work_cut_effects f
      LEFT JOIN change_sets c ON c.changeset_id=f.effect_id
     WHERE f.cut_id=?1 AND f.effect_kind=2
    ORDER BY 1,2 LIMIT ?2";

pub(super) fn observe(
    connection: &Connection,
    cut_id: Uuid,
    expected_revision: i64,
    observed_at: TimestampMillis,
) -> Result<WorkCutDrainObservation, WorkCutError> {
    let transaction = connection.unchecked_transaction()?;
    let cut = repository::read_record(&transaction, cut_id)?
        .ok_or(WorkCutError::Conflict("cut missing"))?;
    if cut.revision() != expected_revision || cut.state() != WorkCutState::Held {
        return Err(WorkCutError::Conflict("cut drain revision or state"));
    }
    if observed_at < cut.prepared_at() {
        return Err(WorkCutError::Conflict("cut drain observation time"));
    }
    let progress = read_effect_progress(&transaction, &cut)?;
    let captured: BTreeSet<_> = cut
        .effects()
        .iter()
        .map(|effect| (effect.kind(), effect.id()))
        .collect();
    for active in effects::collect(&transaction, cut.request(), cut.inventory())? {
        if !captured.contains(&(active.kind(), active.id())) {
            return Err(WorkCutError::Conflict("new effect crossed held cut"));
        }
    }
    let observation = WorkCutDrainObservation {
        cut_id,
        cut_revision: cut.revision(),
        snapshot_digest: *cut.snapshot_digest(),
        observed_at,
        effects: progress,
    };
    transaction.commit()?;
    Ok(observation)
}

fn read_effect_progress(
    transaction: &Transaction<'_>,
    cut: &WorkCutRecord,
) -> Result<Vec<WorkCutEffectProgress>, WorkCutError> {
    let mut statement = transaction.prepare(EFFECT_PROGRESS_SQL)?;
    let limit = i64::try_from(MAX_WORK_CUT_EFFECTS + 1).map_err(|_| WorkCutError::Bounds)?;
    let mut rows = statement.query(params![cut.request().cut_id().as_bytes(), limit])?;
    let mut progress = Vec::with_capacity(cut.effects().len());
    while let Some(row) = rows.next()? {
        let captured = cut
            .effects()
            .get(progress.len())
            .ok_or(WorkCutError::Bounds)?;
        progress.push(decode_progress(row, cut, *captured)?);
    }
    if progress.len() != cut.effects().len() {
        return Err(WorkCutError::Corrupt("cut effect count"));
    }
    Ok(progress)
}

fn decode_progress(
    row: &rusqlite::Row<'_>,
    cut: &WorkCutRecord,
    captured: WorkCutEffect,
) -> Result<WorkCutEffectProgress, WorkCutError> {
    let kind = match row.get::<_, i64>(0)? {
        0 => WorkCutEffectKind::WriterLease,
        1 => WorkCutEffectKind::Execution,
        2 => WorkCutEffectKind::ChangeSet,
        _ => return Err(WorkCutError::Corrupt("cut effect kind")),
    };
    let id = decode_id(&row.get::<_, Vec<u8>>(1)?)?;
    let workspace: Option<Vec<u8>> = row.get(2)?;
    let activity: Option<Vec<u8>> = row.get(3)?;
    let agent: Option<Vec<u8>> = row.get(4)?;
    let state: Option<i64> = row.get(5)?;
    let revision: Option<i64> = row.get(6)?;
    let (Some(workspace), Some(activity), Some(state), Some(revision)) =
        (workspace, activity, state, revision)
    else {
        return Err(WorkCutError::Conflict("captured effect missing"));
    };
    let agent = agent.as_deref().map(decode_id).transpose()?;
    if kind != captured.kind()
        || id != captured.id()
        || decode_id(&workspace)? != cut.request().workspace_id().into_uuid()
        || decode_id(&activity)? != captured.activity_id().into_uuid()
        || agent
            != captured
                .agent_id()
                .map(forge_domain::AgentInstanceId::into_uuid)
        || revision < captured.revision()
        || (revision == captured.revision() && state != captured.state())
    {
        return Err(WorkCutError::Conflict(
            "captured effect identity or revision",
        ));
    }
    let settlement = match (kind, state) {
        (WorkCutEffectKind::WriterLease | WorkCutEffectKind::ChangeSet, 0)
        | (WorkCutEffectKind::Execution, 0 | 1 | 6) => WorkCutEffectSettlement::Pending,
        (WorkCutEffectKind::WriterLease, 1)
        | (WorkCutEffectKind::Execution, 2..=5)
        | (WorkCutEffectKind::ChangeSet, 1 | 2) => WorkCutEffectSettlement::Settled,
        _ => return Err(WorkCutError::Corrupt("cut effect state")),
    };
    Ok(WorkCutEffectProgress {
        kind,
        id,
        revision,
        settlement,
    })
}
