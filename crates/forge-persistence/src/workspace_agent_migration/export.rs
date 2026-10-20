//! Bounded, typed read pages for a frozen Workspace Agent source.
//!
//! The export is deliberately a source-side observation only.  It does not
//! compute a digest, activate a destination, or change the frozen journal.
//! Every page is read from one `SQLite` snapshot whose header is bound to the
//! exact frozen migration row.

use forge_domain::{
    ActivityCoordinatorBinding, ActivityId, AgentEvent, AgentEventId, AgentInstanceId,
    AgentPresenceRevision, AgentSessionId, InboxReceiptRevision, RegisteredAgentInstance,
    TimestampMillis, WorkspaceId,
};
use rusqlite::Connection;
use thiserror::Error;
use uuid::Uuid;

use crate::{AgentEventStoreError, AgentStoreError, CoordinatorStoreError};

use super::{
    AgentOperationsFreezeState, AgentOperationsMigrationError, load_freeze, validate_schema,
};

/// Maximum number of records returned in one export page.
const PAGE_ROWS_U32: u32 = 64;
pub(crate) const PAGE_ROWS: usize = PAGE_ROWS_U32 as usize;
const QUERY_ROWS: u32 = PAGE_ROWS_U32 + 1;

/// Stable table/key cursor for one frozen source export.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentOperationsExportCursor {
    Participants(Option<AgentInstanceId>),
    Presence(Option<AgentInstanceId>),
    Events(Option<AgentEventId>),
    Inbox(Option<AgentOperationsInboxKey>),
    Coordinators(Option<ActivityId>),
}

impl Default for AgentOperationsExportCursor {
    fn default() -> Self {
        Self::Participants(None)
    }
}

/// Exact composite BLOB key for one durable inbox receipt.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AgentOperationsInboxKey {
    agent: AgentInstanceId,
    session: AgentSessionId,
    event: AgentEventId,
}

impl AgentOperationsInboxKey {
    pub const fn new(
        recipient_agent_id: AgentInstanceId,
        recipient_session_id: AgentSessionId,
        event_id: AgentEventId,
    ) -> Self {
        Self {
            agent: recipient_agent_id,
            session: recipient_session_id,
            event: event_id,
        }
    }

    pub const fn recipient_agent_id(self) -> AgentInstanceId {
        self.agent
    }

    pub const fn recipient_session_id(self) -> AgentSessionId {
        self.session
    }

    pub const fn event_id(self) -> AgentEventId {
        self.event
    }
}

/// Typed persisted presence row retained by the source export.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceRow {
    agent_id: AgentInstanceId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    session_id: AgentSessionId,
    last_seen: TimestampMillis,
    revision: AgentPresenceRevision,
}

impl PresenceRow {
    /// Rehydrate one presence observation after checking its source scope and
    /// raw persisted numeric fields.
    ///
    /// `expected_workspace_id` is the page/header scope.  The source decoder
    /// performs this same comparison before retaining a row, so callers that
    /// receive a remote observation cannot move a row into another Workspace
    /// by constructing the value directly.
    pub fn from_parts(
        expected_workspace_id: WorkspaceId,
        agent_id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        session_id: AgentSessionId,
        last_seen_ms: i64,
        revision: i64,
    ) -> Result<Self, AgentEventStoreError> {
        let last_seen = TimestampMillis::new(last_seen_ms).map_err(|_| {
            AgentEventStoreError::CorruptRecord("agent_presence.last_authenticated_at_ms")
        })?;
        let revision = AgentPresenceRevision::new(revision)
            .map_err(|_| AgentEventStoreError::CorruptRecord("agent_presence.presence_revision"))?;
        Self::from_checked_parts(
            expected_workspace_id,
            agent_id,
            workspace_id,
            activity_id,
            session_id,
            last_seen,
            revision,
        )
    }

    /// Rehydrate from values that have already crossed the domain validation
    /// boundary.  The source decoder and transport adapter can use this when
    /// their numeric fields have already been checked.
    pub fn from_checked_parts(
        expected_workspace_id: WorkspaceId,
        agent_id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        session_id: AgentSessionId,
        last_seen: TimestampMillis,
        revision: AgentPresenceRevision,
    ) -> Result<Self, AgentEventStoreError> {
        if workspace_id != expected_workspace_id {
            return Err(AgentEventStoreError::PresenceIdentityConflict);
        }
        Ok(Self::new(
            agent_id,
            workspace_id,
            activity_id,
            session_id,
            last_seen,
            revision,
        ))
    }

    pub(crate) const fn new(
        agent_id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        session_id: AgentSessionId,
        last_seen: TimestampMillis,
        revision: AgentPresenceRevision,
    ) -> Self {
        Self {
            agent_id,
            workspace_id,
            activity_id,
            session_id,
            last_seen,
            revision,
        }
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn session_id(&self) -> AgentSessionId {
        self.session_id
    }

    pub const fn last_seen(&self) -> TimestampMillis {
        self.last_seen
    }

    pub const fn revision(&self) -> AgentPresenceRevision {
        self.revision
    }
}

/// Typed persisted inbox receipt retaining acknowledged and unacknowledged
/// history alike.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxReceipt {
    key: AgentOperationsInboxKey,
    revision: InboxReceiptRevision,
    acknowledged_at: Option<TimestampMillis>,
}

impl InboxReceipt {
    /// Rehydrate one immutable inbox observation from raw persisted values.
    ///
    /// Page construction adds the remaining cursor/order checks for the
    /// containing export.
    pub fn from_parts(
        key: AgentOperationsInboxKey,
        revision: i64,
        acknowledged_at_ms: Option<i64>,
    ) -> Result<Self, AgentEventStoreError> {
        let revision = InboxReceiptRevision::new(revision)
            .map_err(|_| AgentEventStoreError::CorruptRecord("agent_inbox.receipt_revision"))?;
        let acknowledged_at = acknowledged_at_ms
            .map(|value| {
                TimestampMillis::new(value).map_err(|_| {
                    AgentEventStoreError::CorruptRecord("agent_inbox.acknowledged_at_ms")
                })
            })
            .transpose()?;
        Ok(Self::from_checked_parts(key, revision, acknowledged_at))
    }

    /// Rehydrate from values that have already crossed the domain validation
    /// boundary.
    pub const fn from_checked_parts(
        key: AgentOperationsInboxKey,
        revision: InboxReceiptRevision,
        acknowledged_at: Option<TimestampMillis>,
    ) -> Self {
        Self::new(key, revision, acknowledged_at)
    }

    pub(crate) const fn new(
        key: AgentOperationsInboxKey,
        revision: InboxReceiptRevision,
        acknowledged_at: Option<TimestampMillis>,
    ) -> Self {
        Self {
            key,
            revision,
            acknowledged_at,
        }
    }

    pub const fn key(&self) -> AgentOperationsInboxKey {
        self.key
    }

    pub const fn revision(&self) -> InboxReceiptRevision {
        self.revision
    }

    pub const fn acknowledged_at(&self) -> Option<TimestampMillis> {
        self.acknowledged_at
    }
}

/// A borrowed record view. Homogeneous page vectors retain their original
/// allocation instead of padding every small row to the largest event size.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentOperationsExportRecord<'a> {
    Participant(&'a RegisteredAgentInstance),
    Presence(&'a PresenceRow),
    Event(&'a AgentEvent),
    Inbox(&'a InboxReceipt),
    Coordinator(&'a ActivityCoordinatorBinding),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExportRecords {
    Participants(Vec<RegisteredAgentInstance>),
    Presence(Vec<PresenceRow>),
    Events(Vec<AgentEvent>),
    Inbox(Vec<InboxReceipt>),
    Coordinators(Vec<ActivityCoordinatorBinding>),
}

enum RecordsIter<'a> {
    Participants(std::slice::Iter<'a, RegisteredAgentInstance>),
    Presence(std::slice::Iter<'a, PresenceRow>),
    Events(std::slice::Iter<'a, AgentEvent>),
    Inbox(std::slice::Iter<'a, InboxReceipt>),
    Coordinators(std::slice::Iter<'a, ActivityCoordinatorBinding>),
}
impl<'a> Iterator for RecordsIter<'a> {
    type Item = AgentOperationsExportRecord<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Participants(v) => v.next().map(AgentOperationsExportRecord::Participant),
            Self::Presence(v) => v.next().map(AgentOperationsExportRecord::Presence),
            Self::Events(v) => v.next().map(AgentOperationsExportRecord::Event),
            Self::Inbox(v) => v.next().map(AgentOperationsExportRecord::Inbox),
            Self::Coordinators(v) => v.next().map(AgentOperationsExportRecord::Coordinator),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = ExactSizeIterator::len(self);
        (n, Some(n))
    }
}
impl ExactSizeIterator for RecordsIter<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Participants(v) => v.len(),
            Self::Presence(v) => v.len(),
            Self::Events(v) => v.len(),
            Self::Inbox(v) => v.len(),
            Self::Coordinators(v) => v.len(),
        }
    }
}

/// One bounded source page and its exact continuation cursor.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentOperationsExportPage {
    workspace_id: WorkspaceId,
    destination_id: Uuid,
    migration_id: Uuid,
    freeze_revision: u64,
    requested_cursor: AgentOperationsExportCursor,
    next_cursor: Option<AgentOperationsExportCursor>,
    records: ExportRecords,
}

impl AgentOperationsExportPage {
    fn new(
        workspace_id: WorkspaceId,
        destination_id: Uuid,
        migration_id: Uuid,
        freeze_revision: u64,
        requested_cursor: AgentOperationsExportCursor,
        next_cursor: Option<AgentOperationsExportCursor>,
        records: ExportRecords,
    ) -> Self {
        Self {
            workspace_id,
            destination_id,
            migration_id,
            freeze_revision,
            requested_cursor,
            next_cursor,
            records,
        }
    }

    /// Rehydrate a bounded participant page from a checked transport
    /// observation.  The homogeneous constructor keeps the record family
    /// coupled to the cursor family and continuation rules used by the source
    /// SQLite producer.
    pub fn from_participants(
        workspace_id: WorkspaceId,
        destination_id: Uuid,
        migration_id: Uuid,
        freeze_revision: u64,
        requested_cursor: AgentOperationsExportCursor,
        next_cursor: Option<AgentOperationsExportCursor>,
        records: Vec<RegisteredAgentInstance>,
    ) -> Result<Self, AgentOperationsExportError> {
        let AgentOperationsExportCursor::Participants(after) = requested_cursor else {
            return Err(AgentOperationsExportError::InvalidPage("cursor family"));
        };
        validate_page_header(workspace_id, destination_id, migration_id, freeze_revision)?;
        validate_scoped_rows(
            workspace_id,
            &records,
            after,
            RegisteredAgentInstance::id,
            RegisteredAgentInstance::workspace_id,
        )?;
        validate_continuation(
            ExportFamily::Participants,
            records.len(),
            records.last().map(RegisteredAgentInstance::id),
            next_cursor,
            |cursor| match cursor {
                AgentOperationsExportCursor::Participants(value) => value,
                _ => None,
            },
        )?;
        Ok(Self::new(
            workspace_id,
            destination_id,
            migration_id,
            freeze_revision,
            requested_cursor,
            next_cursor,
            ExportRecords::Participants(records),
        ))
    }

    /// Rehydrate a bounded presence page from a checked transport
    /// observation.
    pub fn from_presence(
        workspace_id: WorkspaceId,
        destination_id: Uuid,
        migration_id: Uuid,
        freeze_revision: u64,
        requested_cursor: AgentOperationsExportCursor,
        next_cursor: Option<AgentOperationsExportCursor>,
        records: Vec<PresenceRow>,
    ) -> Result<Self, AgentOperationsExportError> {
        let AgentOperationsExportCursor::Presence(after) = requested_cursor else {
            return Err(AgentOperationsExportError::InvalidPage("cursor family"));
        };
        validate_page_header(workspace_id, destination_id, migration_id, freeze_revision)?;
        validate_scoped_rows(
            workspace_id,
            &records,
            after,
            PresenceRow::agent_id,
            PresenceRow::workspace_id,
        )?;
        validate_continuation(
            ExportFamily::Presence,
            records.len(),
            records.last().map(PresenceRow::agent_id),
            next_cursor,
            |cursor| match cursor {
                AgentOperationsExportCursor::Presence(value) => value,
                _ => None,
            },
        )?;
        Ok(Self::new(
            workspace_id,
            destination_id,
            migration_id,
            freeze_revision,
            requested_cursor,
            next_cursor,
            ExportRecords::Presence(records),
        ))
    }

    /// Rehydrate a bounded immutable-event page from a checked transport
    /// observation.
    pub fn from_events(
        workspace_id: WorkspaceId,
        destination_id: Uuid,
        migration_id: Uuid,
        freeze_revision: u64,
        requested_cursor: AgentOperationsExportCursor,
        next_cursor: Option<AgentOperationsExportCursor>,
        records: Vec<AgentEvent>,
    ) -> Result<Self, AgentOperationsExportError> {
        let AgentOperationsExportCursor::Events(after) = requested_cursor else {
            return Err(AgentOperationsExportError::InvalidPage("cursor family"));
        };
        validate_page_header(workspace_id, destination_id, migration_id, freeze_revision)?;
        validate_scoped_rows(
            workspace_id,
            &records,
            after,
            AgentEvent::id,
            AgentEvent::workspace_id,
        )?;
        validate_continuation(
            ExportFamily::Events,
            records.len(),
            records.last().map(AgentEvent::id),
            next_cursor,
            |cursor| match cursor {
                AgentOperationsExportCursor::Events(value) => value,
                _ => None,
            },
        )?;
        Ok(Self::new(
            workspace_id,
            destination_id,
            migration_id,
            freeze_revision,
            requested_cursor,
            next_cursor,
            ExportRecords::Events(records),
        ))
    }

    /// Rehydrate a bounded inbox page from a checked transport observation.
    /// Inbox receipts carry no Workspace field themselves; their source scope
    /// is therefore the page header, just as it is for the SQL export query.
    pub fn from_inbox(
        workspace_id: WorkspaceId,
        destination_id: Uuid,
        migration_id: Uuid,
        freeze_revision: u64,
        requested_cursor: AgentOperationsExportCursor,
        next_cursor: Option<AgentOperationsExportCursor>,
        records: Vec<InboxReceipt>,
    ) -> Result<Self, AgentOperationsExportError> {
        let AgentOperationsExportCursor::Inbox(after) = requested_cursor else {
            return Err(AgentOperationsExportError::InvalidPage("cursor family"));
        };
        validate_page_header(workspace_id, destination_id, migration_id, freeze_revision)?;
        validate_rows(&records, after, InboxReceipt::key)?;
        validate_continuation(
            ExportFamily::Inbox,
            records.len(),
            records.last().map(InboxReceipt::key),
            next_cursor,
            |cursor| match cursor {
                AgentOperationsExportCursor::Inbox(value) => value,
                _ => None,
            },
        )?;
        Ok(Self::new(
            workspace_id,
            destination_id,
            migration_id,
            freeze_revision,
            requested_cursor,
            next_cursor,
            ExportRecords::Inbox(records),
        ))
    }

    /// Rehydrate a bounded Coordinator-binding page from a checked transport
    /// observation.
    pub fn from_coordinators(
        workspace_id: WorkspaceId,
        destination_id: Uuid,
        migration_id: Uuid,
        freeze_revision: u64,
        requested_cursor: AgentOperationsExportCursor,
        next_cursor: Option<AgentOperationsExportCursor>,
        records: Vec<ActivityCoordinatorBinding>,
    ) -> Result<Self, AgentOperationsExportError> {
        let AgentOperationsExportCursor::Coordinators(after) = requested_cursor else {
            return Err(AgentOperationsExportError::InvalidPage("cursor family"));
        };
        validate_page_header(workspace_id, destination_id, migration_id, freeze_revision)?;
        validate_scoped_rows(
            workspace_id,
            &records,
            after,
            |row| row.activity_id(),
            |row| row.workspace_id(),
        )?;
        validate_continuation(
            ExportFamily::Coordinators,
            records.len(),
            records.last().map(|row| row.activity_id()),
            next_cursor,
            |cursor| match cursor {
                AgentOperationsExportCursor::Coordinators(value) => value,
                _ => None,
            },
        )?;
        Ok(Self::new(
            workspace_id,
            destination_id,
            migration_id,
            freeze_revision,
            requested_cursor,
            next_cursor,
            ExportRecords::Coordinators(records),
        ))
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn destination_id(&self) -> Uuid {
        self.destination_id
    }

    pub const fn migration_id(&self) -> Uuid {
        self.migration_id
    }

    pub const fn freeze_revision(&self) -> u64 {
        self.freeze_revision
    }

    pub const fn requested_cursor(&self) -> AgentOperationsExportCursor {
        self.requested_cursor
    }

    pub fn next_cursor(&self) -> Option<AgentOperationsExportCursor> {
        self.next_cursor
    }

    pub fn records(&self) -> impl ExactSizeIterator<Item = AgentOperationsExportRecord<'_>> {
        match &self.records {
            ExportRecords::Participants(v) => RecordsIter::Participants(v.iter()),
            ExportRecords::Presence(v) => RecordsIter::Presence(v.iter()),
            ExportRecords::Events(v) => RecordsIter::Events(v.iter()),
            ExportRecords::Inbox(v) => RecordsIter::Inbox(v.iter()),
            ExportRecords::Coordinators(v) => RecordsIter::Coordinators(v.iter()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportFamily {
    Participants,
    Presence,
    Events,
    Inbox,
    Coordinators,
}

impl ExportFamily {
    const fn next(self) -> Option<Self> {
        match self {
            Self::Participants => Some(Self::Presence),
            Self::Presence => Some(Self::Events),
            Self::Events => Some(Self::Inbox),
            Self::Inbox => Some(Self::Coordinators),
            Self::Coordinators => None,
        }
    }
}

fn cursor_family(cursor: AgentOperationsExportCursor) -> ExportFamily {
    match cursor {
        AgentOperationsExportCursor::Participants(_) => ExportFamily::Participants,
        AgentOperationsExportCursor::Presence(_) => ExportFamily::Presence,
        AgentOperationsExportCursor::Events(_) => ExportFamily::Events,
        AgentOperationsExportCursor::Inbox(_) => ExportFamily::Inbox,
        AgentOperationsExportCursor::Coordinators(_) => ExportFamily::Coordinators,
    }
}

fn initial_cursor(cursor: AgentOperationsExportCursor) -> bool {
    matches!(
        cursor,
        AgentOperationsExportCursor::Participants(None)
            | AgentOperationsExportCursor::Presence(None)
            | AgentOperationsExportCursor::Events(None)
            | AgentOperationsExportCursor::Inbox(None)
            | AgentOperationsExportCursor::Coordinators(None)
    )
}

fn validate_page_header(
    _workspace_id: WorkspaceId,
    destination_id: Uuid,
    migration_id: Uuid,
    freeze_revision: u64,
) -> Result<(), AgentOperationsExportError> {
    // The source export can only run while the migration is Frozen, whose
    // durable revision is exactly 1.  Nil Workspace ids are deliberately not
    // rejected here: the source decoder retains that representation and the
    // Workspace scope owner performs the authoritative lookup.
    if migration_id.is_nil() {
        return Err(AgentOperationsExportError::InvalidPage("migration id"));
    }
    if destination_id.is_nil() {
        return Err(AgentOperationsExportError::InvalidPage("destination id"));
    }
    if freeze_revision != 1 {
        return Err(AgentOperationsExportError::InvalidPage("freeze revision"));
    }
    Ok(())
}

fn validate_rows<T, K>(
    records: &[T],
    after: Option<K>,
    key: impl Fn(&T) -> K,
) -> Result<(), AgentOperationsExportError>
where
    K: Copy + Ord,
{
    if records.len() > PAGE_ROWS {
        return Err(AgentOperationsExportError::InvalidPage("row cap"));
    }
    let mut previous = after;
    for row in records {
        let current = key(row);
        if previous.is_some_and(|previous| current <= previous) {
            return Err(AgentOperationsExportError::InvalidPage("cursor/order"));
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_scoped_rows<T, K>(
    workspace_id: WorkspaceId,
    records: &[T],
    after: Option<K>,
    key: impl Fn(&T) -> K,
    row_workspace: impl Fn(&T) -> WorkspaceId,
) -> Result<(), AgentOperationsExportError>
where
    K: Copy + Ord,
{
    validate_rows(records, after, key)?;
    for row in records {
        let actual = row_workspace(row);
        if actual != workspace_id {
            return Err(AgentOperationsExportError::WorkspaceMismatch {
                expected: workspace_id,
                actual,
            });
        }
    }
    Ok(())
}

fn validate_continuation<K>(
    family: ExportFamily,
    record_count: usize,
    last_key: Option<K>,
    next_cursor: Option<AgentOperationsExportCursor>,
    same_family_key: impl Fn(AgentOperationsExportCursor) -> Option<K>,
) -> Result<(), AgentOperationsExportError>
where
    K: Copy + Eq,
{
    let expected_next = family.next();
    match next_cursor {
        None => {
            if expected_next.is_none() {
                Ok(())
            } else {
                Err(AgentOperationsExportError::InvalidPage("continuation"))
            }
        }
        Some(cursor) if cursor_family(cursor) == family => {
            if record_count == PAGE_ROWS
                && last_key.is_some()
                && same_family_key(cursor) == last_key
            {
                Ok(())
            } else {
                Err(AgentOperationsExportError::InvalidPage("continuation"))
            }
        }
        Some(cursor) if expected_next == Some(cursor_family(cursor)) && initial_cursor(cursor) => {
            // A source page with fewer than 64 rows advances to the next
            // family.  Exactly 64 rows may also advance when that family was
            // exhausted precisely at the cap.
            if record_count <= PAGE_ROWS {
                Ok(())
            } else {
                Err(AgentOperationsExportError::InvalidPage("continuation"))
            }
        }
        _ => Err(AgentOperationsExportError::InvalidPage("continuation")),
    }
}

/// Failure while reading one frozen source page.
#[derive(Debug, Error)]
pub enum AgentOperationsExportError {
    #[error(transparent)]
    Migration(#[from] AgentOperationsMigrationError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Agents(#[from] AgentStoreError),
    #[error(transparent)]
    Events(#[from] AgentEventStoreError),
    #[error(transparent)]
    Coordinators(#[from] CoordinatorStoreError),
    #[error("Agent operations migration {0} is released and cannot be exported")]
    Released(Uuid),
    #[error("export record belongs to Workspace {actual}, expected {expected}")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    #[error("invalid Agent operations export page: {0}")]
    InvalidPage(&'static str),
}

/// Read one bounded typed page from the exact frozen source snapshot.
pub(crate) fn export(
    connection: &Connection,
    migration_id: Uuid,
    requested_cursor: AgentOperationsExportCursor,
) -> Result<AgentOperationsExportPage, AgentOperationsExportError> {
    if migration_id.is_nil() {
        return Err(AgentOperationsMigrationError::InvalidMigrationId.into());
    }

    let transaction = connection.unchecked_transaction()?;
    validate_schema(&transaction)?;
    crate::workspace_agents::validate_schema(&transaction)?;
    crate::workspace_agent_events::validate_schema(&transaction)?;
    crate::workspace_coordinators::validate_schema(&transaction)?;

    let freeze = load_freeze(&transaction, migration_id)?.ok_or(
        AgentOperationsMigrationError::MigrationMissing(migration_id),
    )?;
    if freeze.state() != AgentOperationsFreezeState::Frozen {
        return Err(AgentOperationsExportError::Released(migration_id));
    }

    let (records, next_cursor) =
        page_records(&transaction, freeze.workspace_id(), requested_cursor)?;
    let page = AgentOperationsExportPage::new(
        freeze.workspace_id(),
        freeze.destination_id(),
        freeze.migration_id(),
        freeze.revision(),
        requested_cursor,
        next_cursor,
        records,
    );
    transaction.commit()?;
    Ok(page)
}

fn page_records(
    connection: &Connection,
    workspace_id: WorkspaceId,
    cursor: AgentOperationsExportCursor,
) -> Result<(ExportRecords, Option<AgentOperationsExportCursor>), AgentOperationsExportError> {
    match cursor {
        AgentOperationsExportCursor::Participants(after) => {
            let rows = crate::workspace_agents::export_participants(
                connection,
                workspace_id,
                after,
                QUERY_ROWS,
            )?;
            let (rows, next) = split_rows(
                rows,
                RegisteredAgentInstance::id,
                |key| AgentOperationsExportCursor::Participants(Some(key)),
                Some(AgentOperationsExportCursor::Presence(None)),
            );
            let records = ExportRecords::Participants(rows);
            Ok((records, next))
        }
        AgentOperationsExportCursor::Presence(after) => {
            let rows = crate::workspace_agent_events::export_presence(
                connection,
                workspace_id,
                after,
                QUERY_ROWS,
            )?;
            let (rows, next) = split_rows(
                rows,
                PresenceRow::agent_id,
                |key| AgentOperationsExportCursor::Presence(Some(key)),
                Some(AgentOperationsExportCursor::Events(None)),
            );
            let records = ExportRecords::Presence(rows);
            Ok((records, next))
        }
        AgentOperationsExportCursor::Events(after) => {
            let rows = crate::workspace_agent_events::export_events(
                connection,
                workspace_id,
                after,
                QUERY_ROWS,
            )?;
            let (rows, next) = split_rows(
                rows,
                AgentEvent::id,
                |key| AgentOperationsExportCursor::Events(Some(key)),
                Some(AgentOperationsExportCursor::Inbox(None)),
            );
            let records = ExportRecords::Events(rows);
            Ok((records, next))
        }
        AgentOperationsExportCursor::Inbox(after) => {
            let rows = crate::workspace_agent_events::export_inbox(
                connection,
                workspace_id,
                after,
                QUERY_ROWS,
            )?;
            let (rows, next) = split_rows(
                rows,
                InboxReceipt::key,
                |key| AgentOperationsExportCursor::Inbox(Some(key)),
                Some(AgentOperationsExportCursor::Coordinators(None)),
            );
            let records = ExportRecords::Inbox(rows);
            Ok((records, next))
        }
        AgentOperationsExportCursor::Coordinators(after) => {
            let rows = crate::workspace_coordinators::export_coordinators(
                connection,
                workspace_id,
                after,
                QUERY_ROWS,
            )?;
            let (rows, next) = split_rows(
                rows,
                |row| row.activity_id(),
                |key| AgentOperationsExportCursor::Coordinators(Some(key)),
                None,
            );
            let records = ExportRecords::Coordinators(rows);
            Ok((records, next))
        }
    }
}

fn split_rows<T, K, F>(
    mut rows: Vec<T>,
    key: F,
    same_table: impl FnOnce(K) -> AgentOperationsExportCursor,
    next_table: Option<AgentOperationsExportCursor>,
) -> (Vec<T>, Option<AgentOperationsExportCursor>)
where
    K: Copy,
    F: Fn(&T) -> K,
{
    if rows.len() > PAGE_ROWS {
        rows.truncate(PAGE_ROWS);
        match rows.last().map(key) {
            Some(last) => (rows, Some(same_table(last))),
            None => (rows, next_table),
        }
    } else {
        (rows, next_table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{
        ActivityCoordinatorRevision, AgentDeclaredRole, AgentDisplayName, AgentEventKind,
        AgentMembershipRevision, AgentTransportKind, CoordinationSnapshot, CoordinatorSnapshot,
    };

    fn workspace(value: u128) -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(value))
    }

    fn activity(value: u128) -> ActivityId {
        ActivityId::from_uuid(Uuid::from_u128(value))
    }

    fn agent(value: u128) -> AgentInstanceId {
        AgentInstanceId::from_uuid(Uuid::from_u128(value))
    }

    fn session(value: u128) -> AgentSessionId {
        AgentSessionId::from_uuid(Uuid::from_u128(value))
    }

    fn event(value: u128) -> AgentEventId {
        AgentEventId::from_uuid(Uuid::from_u128(value))
    }

    fn timestamp(value: i64) -> TimestampMillis {
        match TimestampMillis::new(value) {
            Ok(value) => value,
            Err(_) => unreachable!("test timestamp is non-negative"),
        }
    }

    fn participant(value: u128, workspace_id: WorkspaceId) -> RegisteredAgentInstance {
        let Ok(display_name) = AgentDisplayName::new(format!("Agent {value}")) else {
            unreachable!("test display name is bounded")
        };
        let Ok(declared_role) = AgentDeclaredRole::new("planner".to_owned()) else {
            unreachable!("test role is bounded")
        };
        RegisteredAgentInstance::create(
            agent(value),
            workspace_id,
            activity(0xA0),
            display_name,
            declared_role,
            AgentTransportKind::Retired,
            timestamp(1),
        )
    }

    #[test]
    fn full_page_continues_after_the_last_exact_key() {
        let rows = (1..=65)
            .map(|value| AgentInstanceId::from_uuid(Uuid::from_u128(value)))
            .collect::<Vec<_>>();
        let (page, next) = split_rows(
            rows,
            |row| *row,
            |key| AgentOperationsExportCursor::Participants(Some(key)),
            Some(AgentOperationsExportCursor::Presence(None)),
        );
        assert_eq!(page.len(), PAGE_ROWS);
        assert_eq!(
            next,
            Some(AgentOperationsExportCursor::Participants(Some(
                AgentInstanceId::from_uuid(Uuid::from_u128(64))
            )))
        );
    }

    #[test]
    fn empty_table_advances_to_the_next_table() {
        let rows: Vec<AgentInstanceId> = Vec::new();
        let (page, next) = split_rows(
            rows,
            |row| *row,
            |key| AgentOperationsExportCursor::Participants(Some(key)),
            Some(AgentOperationsExportCursor::Presence(None)),
        );
        assert!(page.is_empty());
        assert_eq!(next, Some(AgentOperationsExportCursor::Presence(None)));
    }

    #[test]
    fn valid_source_shaped_pages_round_trip_through_closed_constructors()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = workspace(1);
        let destination_id = Uuid::from_u128(2);
        let migration_id = Uuid::from_u128(3);
        let activity_id = activity(4);
        let agent_id = agent(5);
        let session_id = session(6);

        let participant = participant(5, workspace_id);
        let participants = AgentOperationsExportPage::from_participants(
            workspace_id,
            destination_id,
            migration_id,
            1,
            AgentOperationsExportCursor::Participants(None),
            Some(AgentOperationsExportCursor::Presence(None)),
            vec![participant],
        )?;
        assert_eq!(participants.records().len(), 1);
        assert!(matches!(
            participants.records().next(),
            Some(AgentOperationsExportRecord::Participant(value))
                if value.id() == agent_id
        ));

        let presence = PresenceRow::from_parts(
            workspace_id,
            agent_id,
            workspace_id,
            activity_id,
            session_id,
            2,
            AgentPresenceRevision::INITIAL.get(),
        )?;
        let presence_page = AgentOperationsExportPage::from_presence(
            workspace_id,
            destination_id,
            migration_id,
            1,
            AgentOperationsExportCursor::Presence(None),
            Some(AgentOperationsExportCursor::Events(None)),
            vec![presence],
        )?;
        assert_eq!(presence_page.records().len(), 1);

        let participation_event = AgentEvent::new(
            event(7),
            workspace_id,
            activity_id,
            AgentMembershipRevision::INITIAL,
            AgentEventKind::Joined,
            None,
            None,
            CoordinationSnapshot::empty(),
            CoordinationSnapshot::empty(),
            CoordinatorSnapshot::unbound(),
            CoordinatorSnapshot::unbound(),
            timestamp(3),
        );
        let events = AgentOperationsExportPage::from_events(
            workspace_id,
            destination_id,
            migration_id,
            1,
            AgentOperationsExportCursor::Events(None),
            Some(AgentOperationsExportCursor::Inbox(None)),
            vec![participation_event.clone()],
        )?;
        assert_eq!(events.records().len(), 1);

        let receipt = InboxReceipt::from_parts(
            AgentOperationsInboxKey::new(agent_id, session_id, participation_event.id()),
            InboxReceiptRevision::INITIAL.get(),
            None,
        )?;
        let inbox = AgentOperationsExportPage::from_inbox(
            workspace_id,
            destination_id,
            migration_id,
            1,
            AgentOperationsExportCursor::Inbox(None),
            Some(AgentOperationsExportCursor::Coordinators(None)),
            vec![receipt],
        )?;
        assert_eq!(inbox.records().len(), 1);

        let coordinator = ActivityCoordinatorBinding::new(
            workspace_id,
            activity_id,
            agent_id,
            ActivityCoordinatorRevision::INITIAL,
            timestamp(4),
        );
        let coordinators = AgentOperationsExportPage::from_coordinators(
            workspace_id,
            destination_id,
            migration_id,
            1,
            AgentOperationsExportCursor::Coordinators(None),
            None,
            vec![coordinator],
        )?;
        assert_eq!(coordinators.records().len(), 1);
        Ok(())
    }

    #[test]
    fn hostile_row_observations_are_rejected_before_page_construction() {
        let workspace_id = workspace(1);
        let key = AgentOperationsInboxKey::new(agent(1), session(2), event(3));
        assert!(matches!(
            InboxReceipt::from_parts(key, 0, None),
            Err(AgentEventStoreError::CorruptRecord(
                "agent_inbox.receipt_revision"
            ))
        ));
        assert!(matches!(
            PresenceRow::from_parts(
                workspace_id,
                agent(1),
                workspace_id,
                activity(2),
                session(3),
                -1,
                1,
            ),
            Err(AgentEventStoreError::CorruptRecord(
                "agent_presence.last_authenticated_at_ms"
            ))
        ));
        assert!(matches!(
            PresenceRow::from_parts(
                workspace_id,
                agent(1),
                workspace(99),
                activity(2),
                session(3),
                1,
                1,
            ),
            Err(AgentEventStoreError::PresenceIdentityConflict)
        ));
    }

    #[test]
    fn hostile_page_size_is_rejected_before_import() {
        let workspace_id = workspace(1);
        let destination_id = Uuid::from_u128(2);
        let migration_id = Uuid::from_u128(3);
        let oversized = (1..=65)
            .map(|value| participant(value, workspace_id))
            .collect::<Vec<_>>();
        assert!(matches!(
            AgentOperationsExportPage::from_participants(
                workspace_id,
                destination_id,
                migration_id,
                1,
                AgentOperationsExportCursor::Participants(None),
                Some(AgentOperationsExportCursor::Participants(Some(agent(64)))),
                oversized,
            ),
            Err(AgentOperationsExportError::InvalidPage("row cap"))
        ));
    }

    #[test]
    fn hostile_page_scope_and_order_are_rejected_before_import() {
        let workspace_id = workspace(1);
        let destination_id = Uuid::from_u128(2);
        let migration_id = Uuid::from_u128(3);
        let out_of_order = vec![participant(2, workspace_id), participant(1, workspace_id)];
        assert!(matches!(
            AgentOperationsExportPage::from_participants(
                workspace_id,
                destination_id,
                migration_id,
                1,
                AgentOperationsExportCursor::Participants(None),
                Some(AgentOperationsExportCursor::Presence(None)),
                out_of_order,
            ),
            Err(AgentOperationsExportError::InvalidPage("cursor/order"))
        ));

        let foreign = vec![participant(1, workspace(99))];
        assert!(matches!(
            AgentOperationsExportPage::from_participants(
                workspace_id,
                destination_id,
                migration_id,
                1,
                AgentOperationsExportCursor::Participants(None),
                Some(AgentOperationsExportCursor::Presence(None)),
                foreign,
            ),
            Err(AgentOperationsExportError::WorkspaceMismatch { .. })
        ));
    }

    #[test]
    fn hostile_page_continuation_and_cursor_family_are_rejected() {
        let workspace_id = workspace(1);
        let destination_id = Uuid::from_u128(2);
        let migration_id = Uuid::from_u128(3);
        let invalid_continuation = vec![participant(1, workspace_id)];
        assert!(matches!(
            AgentOperationsExportPage::from_participants(
                workspace_id,
                destination_id,
                migration_id,
                1,
                AgentOperationsExportCursor::Participants(None),
                Some(AgentOperationsExportCursor::Participants(Some(agent(1)))),
                invalid_continuation,
            ),
            Err(AgentOperationsExportError::InvalidPage("continuation"))
        ));

        assert!(matches!(
            AgentOperationsExportPage::from_presence(
                workspace_id,
                destination_id,
                migration_id,
                1,
                AgentOperationsExportCursor::Participants(None),
                Some(AgentOperationsExportCursor::Events(None)),
                Vec::new(),
            ),
            Err(AgentOperationsExportError::InvalidPage("cursor family"))
        ));
    }
}
