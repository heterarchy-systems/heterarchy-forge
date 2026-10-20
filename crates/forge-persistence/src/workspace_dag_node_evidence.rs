//! Bounded read access to the immutable evidence attributed to one DAG node.

use forge_domain::{DagNodeId, DagRevisionNumber, GoalEvidenceRef, GoalId, TimestampMillis};
use rusqlite::{Connection, Transaction, params};
use thiserror::Error;

use crate::workspace_goals;

/// Maximum number of node-evidence entries returned by one page.
pub const MAX_DAG_NODE_EVIDENCE_PAGE_SIZE: usize = 128;

/// The immutable Goal/DAG revision/Node identity used by a node-evidence read.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DagNodeEvidenceScope {
    goal_id: GoalId,
    dag_revision: DagRevisionNumber,
    node_id: DagNodeId,
}

impl DagNodeEvidenceScope {
    pub const fn new(goal_id: GoalId, dag_revision: DagRevisionNumber, node_id: DagNodeId) -> Self {
        Self {
            goal_id,
            dag_revision,
            node_id,
        }
    }

    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn dag_revision(self) -> DagRevisionNumber {
        self.dag_revision
    }

    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }
}

/// One canonical Goal evidence reference and the timestamp at which it was
/// associated with the selected DAG node.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagNodeEvidenceEntry {
    evidence: GoalEvidenceRef,
    associated_at: TimestampMillis,
}

impl DagNodeEvidenceEntry {
    pub(crate) const fn new(evidence: GoalEvidenceRef, associated_at: TimestampMillis) -> Self {
        Self {
            evidence,
            associated_at,
        }
    }

    pub const fn evidence(&self) -> GoalEvidenceRef {
        self.evidence
    }

    pub const fn associated_at(&self) -> TimestampMillis {
        self.associated_at
    }
}

/// Cursor for the next page of one exact DAG node scope.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagNodeEvidenceCursor {
    scope: DagNodeEvidenceScope,
    entry: DagNodeEvidenceEntry,
}

impl DagNodeEvidenceCursor {
    pub const fn new(
        scope: DagNodeEvidenceScope,
        associated_at: TimestampMillis,
        evidence: GoalEvidenceRef,
    ) -> Self {
        Self {
            scope,
            entry: DagNodeEvidenceEntry::new(evidence, associated_at),
        }
    }

    pub const fn scope(self) -> DagNodeEvidenceScope {
        self.scope
    }

    pub const fn associated_at(self) -> TimestampMillis {
        self.entry.associated_at
    }

    pub const fn evidence(self) -> GoalEvidenceRef {
        self.entry.evidence
    }
}

/// One bounded page of immutable node-evidence references.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNodeEvidencePage {
    scope: DagNodeEvidenceScope,
    entries: Vec<DagNodeEvidenceEntry>,
    next_cursor: Option<DagNodeEvidenceCursor>,
}

impl DagNodeEvidencePage {
    pub const fn scope(&self) -> DagNodeEvidenceScope {
        self.scope
    }

    pub fn entries(&self) -> &[DagNodeEvidenceEntry] {
        &self.entries
    }

    pub const fn next_cursor(&self) -> Option<DagNodeEvidenceCursor> {
        self.next_cursor
    }

    /// Whether another page exists after this one.
    pub const fn truncated(&self) -> bool {
        self.next_cursor.is_some()
    }
}

#[derive(Debug, Error)]
pub enum DagNodeEvidenceError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Goal(#[from] crate::GoalStoreError),
    #[error("DAG node evidence limit {limit} is outside 1..={maximum}")]
    InvalidLimit { limit: usize, maximum: usize },
    #[error("DAG node evidence cursor does not match the requested scope")]
    CursorScopeMismatch,
    #[error("DAG revision {dag_revision:?} is missing for Goal {goal_id}")]
    DagRevisionMissing {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
    },
    #[error("DAG node {node_id} is missing from Goal {goal_id} revision {dag_revision:?}")]
    NodeMissing {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    },
    #[error("DAG node evidence limit exceeds SQLite integer range")]
    IntegerOverflow,
}

pub(crate) fn read(
    connection: &Connection,
    scope: DagNodeEvidenceScope,
    limit: usize,
    cursor: Option<DagNodeEvidenceCursor>,
) -> Result<DagNodeEvidencePage, DagNodeEvidenceError> {
    if !(1..=MAX_DAG_NODE_EVIDENCE_PAGE_SIZE).contains(&limit) {
        return Err(DagNodeEvidenceError::InvalidLimit {
            limit,
            maximum: MAX_DAG_NODE_EVIDENCE_PAGE_SIZE,
        });
    }
    if cursor.is_some_and(|cursor| cursor.scope != scope) {
        return Err(DagNodeEvidenceError::CursorScopeMismatch);
    }

    let transaction = connection.unchecked_transaction()?;
    validate_scope(&transaction, scope)?;
    let query_limit =
        i64::try_from(limit + 1).map_err(|_| DagNodeEvidenceError::IntegerOverflow)?;
    let mut entries = read_entries(&transaction, scope, cursor, query_limit, limit)?;
    let next_cursor = if entries.len() > limit {
        entries.pop();
        entries
            .last()
            .map(|entry| DagNodeEvidenceCursor::new(scope, entry.associated_at(), entry.evidence()))
    } else {
        None
    };
    transaction.commit()?;
    Ok(DagNodeEvidencePage {
        scope,
        entries,
        next_cursor,
    })
}

fn validate_scope(
    transaction: &Transaction<'_>,
    scope: DagNodeEvidenceScope,
) -> Result<(), DagNodeEvidenceError> {
    let revision_exists: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM goal_dag_revisions
              WHERE goal_id = ?1 AND dag_revision = ?2
         )",
        params![
            scope.goal_id.into_uuid().as_bytes(),
            scope.dag_revision.get()
        ],
        |row| row.get(0),
    )?;
    if !revision_exists {
        return Err(DagNodeEvidenceError::DagRevisionMissing {
            goal_id: scope.goal_id,
            dag_revision: scope.dag_revision,
        });
    }

    let node_exists: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM goal_dag_nodes
              WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3
         )",
        params![
            scope.goal_id.into_uuid().as_bytes(),
            scope.dag_revision.get(),
            scope.node_id.into_uuid().as_bytes(),
        ],
        |row| row.get(0),
    )?;
    if !node_exists {
        return Err(DagNodeEvidenceError::NodeMissing {
            goal_id: scope.goal_id,
            dag_revision: scope.dag_revision,
            node_id: scope.node_id,
        });
    }
    Ok(())
}

fn read_entries(
    transaction: &Transaction<'_>,
    scope: DagNodeEvidenceScope,
    cursor: Option<DagNodeEvidenceCursor>,
    query_limit: i64,
    limit: usize,
) -> Result<Vec<DagNodeEvidenceEntry>, DagNodeEvidenceError> {
    let mut statement = transaction.prepare(
        "SELECT evidence_kind, evidence_id, associated_at_ms
           FROM goal_dag_node_evidence_refs
          WHERE goal_id = ?1 AND dag_revision = ?2 AND node_id = ?3
            AND (
                ?4 IS NULL
                OR associated_at_ms < ?4
                OR (
                    associated_at_ms = ?4
                    AND (
                        evidence_kind > ?5
                        OR (evidence_kind = ?5 AND evidence_id > ?6)
                    )
                )
            )
          ORDER BY associated_at_ms DESC, evidence_kind ASC, evidence_id ASC
          LIMIT ?7",
    )?;
    let cursor_key = cursor.map(|cursor| {
        let (kind, id) = workspace_goals::encode_evidence(cursor.evidence());
        (cursor.associated_at().get(), kind, id)
    });
    let cursor_timestamp = cursor_key.as_ref().map(|key| key.0);
    let cursor_kind = cursor_key.as_ref().map(|key| key.1);
    let cursor_id = cursor_key.as_ref().map(|key| key.2.as_slice());
    let rows = statement.query_map(
        params![
            scope.goal_id.into_uuid().as_bytes(),
            scope.dag_revision.get(),
            scope.node_id.into_uuid().as_bytes(),
            cursor_timestamp,
            cursor_kind,
            cursor_id,
            query_limit,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;

    let mut entries = Vec::with_capacity(limit.min(MAX_DAG_NODE_EVIDENCE_PAGE_SIZE));
    for row in rows {
        let (kind, id, associated_at) = row?;
        let evidence = workspace_goals::decode_evidence(kind, &id)?;
        let associated_at = TimestampMillis::new(associated_at)
            .map_err(|_| crate::GoalStoreError::CorruptRecord("dag_node_evidence.associated_at"))?;
        entries.push(DagNodeEvidenceEntry::new(evidence, associated_at));
    }
    drop(statement);
    Ok(entries)
}
