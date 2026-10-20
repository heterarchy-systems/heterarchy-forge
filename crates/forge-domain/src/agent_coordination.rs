//! Typed Workspace participation, Coordinator handoff, and inbox projections.
//!
//! These values carry durable identity and comparison fences only. They do not
//! decide authentication, inspect a Workspace, or perform any effect. The
//! persistence boundary validates every identity against the same `SQLite`
//! snapshot before applying a transition.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityCoordinatorActor, ActivityCoordinatorRevision, ActivityId, AgentDisplayName,
    AgentFocusNode, AgentInstanceId, AgentInstanceRevision, AgentSessionId, AuthenticatedPrincipal,
    DagHeadRevision, DagRevisionNumber, GoalAttribution, TimestampMillis, WorkspaceId,
};

/// Maximum number of durable participation events returned by one query.
pub const MAX_AGENT_EVENT_RESULTS: u32 = 100;
/// Maximum number of durable inbox entries returned by one query.
pub const MAX_AGENT_INBOX_RESULTS: u32 = 64;
/// Maximum length of event summary/metadata labels in bytes.
pub const MAX_AGENT_EVENT_TEXT_BYTES: usize = 256;

/// Bounded query limit for append-only participation events.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentEventListLimit(u32);

impl AgentEventListLimit {
    pub const DEFAULT: Self = Self(64);

    pub const fn new(value: u32) -> Result<Self, AgentEventListLimitError> {
        if value == 0 || value > MAX_AGENT_EVENT_RESULTS {
            Err(AgentEventListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_AGENT_EVENT_RESULTS,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentEventListLimitError {
    #[error("Agent event list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

/// Bounded query limit for one recipient's inbox.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentInboxListLimit(u32);

impl AgentInboxListLimit {
    pub const DEFAULT: Self = Self(64);

    pub const fn new(value: u32) -> Result<Self, AgentInboxListLimitError> {
        if value == 0 || value > MAX_AGENT_INBOX_RESULTS {
            Err(AgentInboxListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_AGENT_INBOX_RESULTS,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentInboxListLimitError {
    #[error("Agent inbox list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

/// Stable identity for one append-only participation event.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentEventId(Uuid);

impl AgentEventId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }

    /// Derive the stable identity for a lifecycle event whose command does
    /// not carry a caller supplied event id. The explicit domain and framed
    /// fields keep adjacent Agent ids and event kinds from aliasing, while
    /// BLAKE3 keeps the persisted 128-bit identity stable across restarts.
    pub fn for_transition(
        agent_id: AgentInstanceId,
        revision: AgentInstanceRevision,
        kind: AgentEventKind,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"heterarchy-forge:agent-event-id:v1\0");
        hasher.update(&16_u32.to_le_bytes());
        hasher.update(agent_id.into_uuid().as_bytes());
        hasher.update(&revision.get().to_le_bytes());
        hasher.update(&[match kind {
            AgentEventKind::Joined => 0,
            AgentEventKind::Left => 1,
            AgentEventKind::HandoffStarted => 2,
            AgentEventKind::HandoffCompleted => 3,
            AgentEventKind::FocusChanged => 4,
            AgentEventKind::RoleChanged => 5,
        }]);
        let digest = hasher.finalize();
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        Self(Uuid::from_bytes(id))
    }

    /// Identify the planning transfer from one exact Activity revision.
    /// Returning planning authority to an earlier Agent remains a new event.
    pub fn for_coordinator_transfer(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        previous_revision: ActivityCoordinatorRevision,
    ) -> Self {
        let mut hash = blake3::Hasher::new();
        hash.update(b"heterarchy-forge:activity-planning-transfer:v1\0");
        hash.update(workspace_id.into_uuid().as_bytes());
        hash.update(activity_id.into_uuid().as_bytes());
        hash.update(&previous_revision.get().to_le_bytes());
        let digest = hash.finalize();
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        Self(Uuid::from_bytes(id))
    }

    /// Derive the stable identity paired with a caller supplied handoff start
    /// event, with a separate hash domain from ordinary lifecycle transitions.
    pub fn for_handoff_completed(start_event_id: Self) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"heterarchy-forge:agent-handoff-completed:v1\0");
        hasher.update(start_event_id.into_uuid().as_bytes());
        let digest = hasher.finalize();
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        Self(Uuid::from_bytes(id))
    }
}

impl fmt::Display for AgentEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AgentEventId {
    type Err = AgentEventIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(AgentEventIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum AgentEventIdParseError {
    #[error("invalid Agent event UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Monotonic membership sequence within one Workspace/Activity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentMembershipRevision(i64);

impl AgentMembershipRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentMembershipRevisionError> {
        if value < 1 {
            Err(AgentMembershipRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentMembershipRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentMembershipRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for AgentMembershipRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentMembershipRevisionError {
    #[error("Agent membership revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Agent membership revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Monotonic revision for explicit authenticated presence observations.
/// This is intentionally distinct from Agent membership and Agent authority
/// revisions so a presence touch cannot fence a focus or coordinator write.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentPresenceRevision(i64);

impl AgentPresenceRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentPresenceRevisionError> {
        if value < 1 {
            Err(AgentPresenceRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentPresenceRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentPresenceRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentPresenceRevisionError {
    #[error("Agent presence revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Agent presence revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Durable presence partition. These values are mutually exclusive and are
/// derived from attachment, coordinator, and immutable handoff facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PresencePartition {
    CurrentCoordinator,
    ClosedActivity,
    AttachedParticipant,
    HandedOff,
    Detached,
    UnresolvedLegacy,
}

/// One bounded, atomic projection of a Workspace participant.
///
/// `last_authenticated_at` is an observation of the last explicit
/// authenticated participant action. It is never interpreted as an Activity
/// heartbeat or as proof that a chat connection is currently alive.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceSnapshot {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: Option<AgentSessionId>,
    principal: AuthenticatedPrincipal,
    display_name: AgentDisplayName,
    partition: PresencePartition,
    agent_revision: AgentInstanceRevision,
    membership_revision: AgentMembershipRevision,
    presence_revision: AgentPresenceRevision,
    last_authenticated_at: Option<TimestampMillis>,
}

impl PresenceSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: Option<AgentSessionId>,
        principal: AuthenticatedPrincipal,
        display_name: AgentDisplayName,
        partition: PresencePartition,
        agent_revision: AgentInstanceRevision,
        membership_revision: AgentMembershipRevision,
        presence_revision: AgentPresenceRevision,
        last_authenticated_at: Option<TimestampMillis>,
    ) -> Self {
        Self {
            workspace_id,
            activity_id,
            agent_id,
            session_id,
            principal,
            display_name,
            partition,
            agent_revision,
            membership_revision,
            presence_revision,
            last_authenticated_at,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(&self) -> Option<AgentSessionId> {
        self.session_id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn display_name(&self) -> &AgentDisplayName {
        &self.display_name
    }

    pub const fn partition(&self) -> PresencePartition {
        self.partition
    }

    pub const fn agent_revision(&self) -> AgentInstanceRevision {
        self.agent_revision
    }

    pub const fn membership_revision(&self) -> AgentMembershipRevision {
        self.membership_revision
    }

    pub const fn presence_revision(&self) -> AgentPresenceRevision {
        self.presence_revision
    }

    pub const fn last_authenticated_at(&self) -> Option<TimestampMillis> {
        self.last_authenticated_at
    }
}

/// Atomic aggregate used by bounded UI/read projections. Counts are durable
/// query results and therefore remain truthful even when `participants` is
/// capped for transport.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityPresenceSnapshot {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    membership_revision: Option<AgentMembershipRevision>,
    coordinator: CoordinatorSnapshot,
    participants: Vec<PresenceSnapshot>,
    counts: PresenceCounts,
    unread_count: u32,
    unread_join_count: u32,
}

/// Full, untruncated participant partition counts for one Activity.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PresenceCounts {
    current_coordinator: u32,
    closed_activity: u32,
    attached_participants: u32,
    handed_off: u32,
    detached: u32,
    unresolved_legacy: u32,
}

impl PresenceCounts {
    pub const fn new(
        current_coordinator: u32,
        closed_activity: u32,
        attached_participants: u32,
        handed_off: u32,
        detached: u32,
        unresolved_legacy: u32,
    ) -> Self {
        Self {
            current_coordinator,
            closed_activity,
            attached_participants,
            handed_off,
            detached,
            unresolved_legacy,
        }
    }

    pub const fn current_coordinator(self) -> u32 {
        self.current_coordinator
    }

    pub const fn attached_participants(self) -> u32 {
        self.attached_participants
    }

    pub const fn closed_activity(self) -> u32 {
        self.closed_activity
    }

    pub const fn handed_off(self) -> u32 {
        self.handed_off
    }

    pub const fn detached(self) -> u32 {
        self.detached
    }

    pub const fn unresolved_legacy(self) -> u32 {
        self.unresolved_legacy
    }

    pub const fn total(self) -> u32 {
        self.current_coordinator
            .saturating_add(self.attached_participants)
            .saturating_add(self.closed_activity)
            .saturating_add(self.handed_off)
            .saturating_add(self.detached)
            .saturating_add(self.unresolved_legacy)
    }
}

impl ActivityPresenceSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        membership_revision: Option<AgentMembershipRevision>,
        coordinator: CoordinatorSnapshot,
        participants: Vec<PresenceSnapshot>,
        counts: PresenceCounts,
        unread_count: u32,
        unread_join_count: u32,
    ) -> Result<Self, ActivityPresenceSnapshotError> {
        if participants.len() > MAX_AGENT_INBOX_RESULTS as usize {
            return Err(ActivityPresenceSnapshotError::TooManyParticipants {
                actual: participants.len(),
                maximum: MAX_AGENT_INBOX_RESULTS,
            });
        }
        let page = u32::try_from(participants.len()).map_err(|_| {
            ActivityPresenceSnapshotError::TooManyParticipants {
                actual: participants.len(),
                maximum: MAX_AGENT_INBOX_RESULTS,
            }
        })?;
        if counts.total() < page {
            return Err(ActivityPresenceSnapshotError::CountBelowPage {
                count: counts.total(),
                page,
            });
        }
        Ok(Self {
            workspace_id,
            activity_id,
            membership_revision,
            coordinator,
            participants,
            counts,
            unread_count,
            unread_join_count,
        })
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn membership_revision(&self) -> Option<AgentMembershipRevision> {
        self.membership_revision
    }

    pub const fn coordinator(&self) -> CoordinatorSnapshot {
        self.coordinator
    }

    pub fn participants(&self) -> &[PresenceSnapshot] {
        &self.participants
    }

    pub const fn participant_count(&self) -> u32 {
        self.counts.total()
    }

    pub const fn counts(&self) -> PresenceCounts {
        self.counts
    }

    pub const fn unread_count(&self) -> u32 {
        self.unread_count
    }

    pub const fn unread_join_count(&self) -> u32 {
        self.unread_join_count
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivityPresenceSnapshotError {
    #[error("Activity presence page has {actual} participants; maximum is {maximum}")]
    TooManyParticipants { actual: usize, maximum: u32 },
    #[error("Activity presence participant count {count} is below page size {page}")]
    CountBelowPage { count: u32, page: u32 },
}

/// Exact endpoint identity stored in a participation event.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentParticipantRef {
    agent_id: AgentInstanceId,
    session_id: Option<AgentSessionId>,
    principal: AuthenticatedPrincipal,
    display_name: AgentDisplayName,
}

impl AgentParticipantRef {
    pub const fn new(
        agent_id: AgentInstanceId,
        session_id: Option<AgentSessionId>,
        principal: AuthenticatedPrincipal,
        display_name: AgentDisplayName,
    ) -> Self {
        Self {
            agent_id,
            session_id,
            principal,
            display_name,
        }
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(&self) -> Option<AgentSessionId> {
        self.session_id
    }

    pub const fn principal(&self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn display_name(&self) -> &AgentDisplayName {
        &self.display_name
    }
}

/// Exact current Goal, DAG revision, and head node observation used to fence
/// a Coordinator handoff. `None` is a valid empty current plan.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoordinationSnapshot {
    goal: Option<GoalAttribution>,
    dag_revision: Option<DagRevisionNumber>,
    dag_head_revision: Option<DagHeadRevision>,
    node: Option<AgentFocusNode>,
}

impl CoordinationSnapshot {
    pub const fn empty() -> Self {
        Self {
            goal: None,
            dag_revision: None,
            dag_head_revision: None,
            node: None,
        }
    }

    pub fn new(
        goal: Option<GoalAttribution>,
        dag_revision: Option<DagRevisionNumber>,
        dag_head_revision: Option<DagHeadRevision>,
        node: Option<AgentFocusNode>,
    ) -> Result<Self, CoordinationSnapshotError> {
        if goal.is_none()
            && (dag_revision.is_some() || dag_head_revision.is_some() || node.is_some())
        {
            return Err(CoordinationSnapshotError::PlanWithoutGoal);
        }
        if dag_revision.is_none() && (dag_head_revision.is_some() || node.is_some()) {
            return Err(CoordinationSnapshotError::HeadWithoutDag);
        }
        if dag_revision.is_some() && dag_head_revision.is_none() {
            return Err(CoordinationSnapshotError::DagWithoutHead);
        }
        Ok(Self {
            goal,
            dag_revision,
            dag_head_revision,
            node,
        })
    }

    pub const fn goal(&self) -> Option<GoalAttribution> {
        self.goal
    }

    pub const fn dag_revision(&self) -> Option<DagRevisionNumber> {
        self.dag_revision
    }

    pub const fn dag_head_revision(&self) -> Option<DagHeadRevision> {
        self.dag_head_revision
    }

    pub const fn node(&self) -> Option<AgentFocusNode> {
        self.node
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CoordinationSnapshotError {
    #[error("Coordination DAG/head requires a Goal")]
    PlanWithoutGoal,
    #[error("Coordination head requires a DAG revision")]
    HeadWithoutDag,
    #[error("Coordination DAG requires its current head revision")]
    DagWithoutHead,
}

/// Durable Coordinator endpoint snapshot stored before/after a transition.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoordinatorSnapshot {
    agent_id: Option<AgentInstanceId>,
    session_id: Option<AgentSessionId>,
    revision: Option<ActivityCoordinatorRevision>,
}

impl CoordinatorSnapshot {
    pub const fn unbound() -> Self {
        Self {
            agent_id: None,
            session_id: None,
            revision: None,
        }
    }

    pub const fn bound(
        agent_id: AgentInstanceId,
        session_id: Option<AgentSessionId>,
        revision: ActivityCoordinatorRevision,
    ) -> Self {
        Self {
            agent_id: Some(agent_id),
            session_id,
            revision: Some(revision),
        }
    }

    pub const fn agent_id(&self) -> Option<AgentInstanceId> {
        self.agent_id
    }

    pub const fn session_id(&self) -> Option<AgentSessionId> {
        self.session_id
    }

    pub const fn revision(&self) -> Option<ActivityCoordinatorRevision> {
        self.revision
    }
}

/// Append-only participation event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgentEventKind {
    Joined,
    Left,
    HandoffStarted,
    HandoffCompleted,
    FocusChanged,
    RoleChanged,
}

/// One immutable participation event with bounded before/after metadata.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEvent {
    id: AgentEventId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    membership_revision: AgentMembershipRevision,
    kind: AgentEventKind,
    from: Option<AgentParticipantRef>,
    to: Option<AgentParticipantRef>,
    coordination_before: CoordinationSnapshot,
    coordination_after: CoordinationSnapshot,
    coordinator_before: CoordinatorSnapshot,
    coordinator_after: CoordinatorSnapshot,
    observed_at: TimestampMillis,
}

impl AgentEvent {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: AgentEventId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        membership_revision: AgentMembershipRevision,
        kind: AgentEventKind,
        from: Option<AgentParticipantRef>,
        to: Option<AgentParticipantRef>,
        coordination_before: CoordinationSnapshot,
        coordination_after: CoordinationSnapshot,
        coordinator_before: CoordinatorSnapshot,
        coordinator_after: CoordinatorSnapshot,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            workspace_id,
            activity_id,
            membership_revision,
            kind,
            from,
            to,
            coordination_before,
            coordination_after,
            coordinator_before,
            coordinator_after,
            observed_at,
        }
    }

    pub const fn id(&self) -> AgentEventId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn membership_revision(&self) -> AgentMembershipRevision {
        self.membership_revision
    }

    pub const fn kind(&self) -> AgentEventKind {
        self.kind
    }

    pub const fn from(&self) -> Option<&AgentParticipantRef> {
        self.from.as_ref()
    }

    pub const fn to(&self) -> Option<&AgentParticipantRef> {
        self.to.as_ref()
    }

    pub const fn coordination_before(&self) -> CoordinationSnapshot {
        self.coordination_before
    }

    pub const fn coordination_after(&self) -> CoordinationSnapshot {
        self.coordination_after
    }

    pub const fn coordinator_before(&self) -> CoordinatorSnapshot {
        self.coordinator_before
    }

    pub const fn coordinator_after(&self) -> CoordinatorSnapshot {
        self.coordinator_after
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Monotonic compare-and-set revision for one recipient's inbox receipt.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InboxReceiptRevision(i64);

impl InboxReceiptRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, InboxReceiptRevisionError> {
        if value < 1 {
            Err(InboxReceiptRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, InboxReceiptRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(InboxReceiptRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for InboxReceiptRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InboxReceiptRevisionError {
    #[error("Inbox receipt revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Inbox receipt revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// One inbox row addressed to an exact attached Agent/session. Reading this
/// value is observational; it does not acknowledge the receipt.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEntry {
    recipient: AgentParticipantRef,
    event: AgentEvent,
    receipt_revision: InboxReceiptRevision,
    acknowledged_at: Option<TimestampMillis>,
}

impl InboxEntry {
    pub const fn new(
        recipient: AgentParticipantRef,
        event: AgentEvent,
        receipt_revision: InboxReceiptRevision,
        acknowledged_at: Option<TimestampMillis>,
    ) -> Self {
        Self {
            recipient,
            event,
            receipt_revision,
            acknowledged_at,
        }
    }

    pub const fn recipient(&self) -> &AgentParticipantRef {
        &self.recipient
    }

    pub const fn event(&self) -> &AgentEvent {
        &self.event
    }

    pub const fn receipt_revision(&self) -> InboxReceiptRevision {
        self.receipt_revision
    }

    pub const fn acknowledged_at(&self) -> Option<TimestampMillis> {
        self.acknowledged_at
    }

    pub const fn is_acknowledged(&self) -> bool {
        self.acknowledged_at.is_some()
    }
}

/// Atomic, one-shot handoff command. The source relinquishes focus and
/// attachment while the Coordinator binding and event/inbox facts move to the
/// target in one `SQLite` transaction. The target must explicitly reacquire its
/// own focus/lease after this command succeeds.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentHandoff {
    actor: ActivityCoordinatorActor,
    expected_source_agent_revision: AgentInstanceRevision,
    target_agent_id: AgentInstanceId,
    target_session_id: AgentSessionId,
    target_principal: AuthenticatedPrincipal,
    expected_target_revision: AgentInstanceRevision,
    expected_coordination: CoordinationSnapshot,
    event_id: AgentEventId,
    observed_at: TimestampMillis,
}

impl AgentHandoff {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        actor: ActivityCoordinatorActor,
        expected_source_agent_revision: AgentInstanceRevision,
        target_agent_id: AgentInstanceId,
        target_session_id: AgentSessionId,
        target_principal: AuthenticatedPrincipal,
        expected_target_revision: AgentInstanceRevision,
        expected_coordination: CoordinationSnapshot,
        event_id: AgentEventId,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            actor,
            expected_source_agent_revision,
            target_agent_id,
            target_session_id,
            target_principal,
            expected_target_revision,
            expected_coordination,
            event_id,
            observed_at,
        }
    }

    pub const fn actor(self) -> ActivityCoordinatorActor {
        self.actor
    }

    pub const fn expected_source_agent_revision(self) -> AgentInstanceRevision {
        self.expected_source_agent_revision
    }

    pub const fn target_agent_id(self) -> AgentInstanceId {
        self.target_agent_id
    }

    pub const fn target_session_id(self) -> AgentSessionId {
        self.target_session_id
    }

    pub const fn target_principal(self) -> AuthenticatedPrincipal {
        self.target_principal
    }

    pub const fn expected_target_revision(self) -> AgentInstanceRevision {
        self.expected_target_revision
    }

    pub const fn expected_coordination(self) -> CoordinationSnapshot {
        self.expected_coordination
    }

    pub const fn event_id(self) -> AgentEventId {
        self.event_id
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Exact inbox acknowledgement CAS command. A read operation never creates
/// or acknowledges a receipt; only this command mutates the row.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AckAgentInbox {
    recipient_agent_id: AgentInstanceId,
    recipient_session_id: AgentSessionId,
    event_id: AgentEventId,
    expected_receipt_revision: InboxReceiptRevision,
    observed_at: TimestampMillis,
}

impl AckAgentInbox {
    pub const fn new(
        recipient_agent_id: AgentInstanceId,
        recipient_session_id: AgentSessionId,
        event_id: AgentEventId,
        expected_receipt_revision: InboxReceiptRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            recipient_agent_id,
            recipient_session_id,
            event_id,
            expected_receipt_revision,
            observed_at,
        }
    }

    pub const fn recipient_agent_id(self) -> AgentInstanceId {
        self.recipient_agent_id
    }

    pub const fn recipient_session_id(self) -> AgentSessionId {
        self.recipient_session_id
    }

    pub const fn event_id(self) -> AgentEventId {
        self.event_id
    }

    pub const fn expected_receipt_revision(self) -> InboxReceiptRevision {
        self.expected_receipt_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Explicit adoption of one legacy attachment by a validated logical
/// session. The application/control layer validates the session catalog; the
/// Workspace layer compares only the immutable values supplied here.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BindExistingAgentSession {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    expected_agent_revision: AgentInstanceRevision,
    observed_at: TimestampMillis,
}

impl BindExistingAgentSession {
    pub const fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        expected_agent_revision: AgentInstanceRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            workspace_id,
            activity_id,
            agent_id,
            session_id,
            principal,
            expected_agent_revision,
            observed_at,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn expected_agent_revision(self) -> AgentInstanceRevision {
        self.expected_agent_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Explicit authenticated participant observation. It updates presence only;
/// it never changes Agent focus/authority revisions or attachment state.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TouchAgentSession {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    expected_presence_revision: AgentPresenceRevision,
    observed_at: TimestampMillis,
}

impl TouchAgentSession {
    pub const fn new(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
        expected_presence_revision: AgentPresenceRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            workspace_id,
            activity_id,
            agent_id,
            session_id,
            principal,
            expected_presence_revision,
            observed_at,
        }
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn session_id(self) -> AgentSessionId {
        self.session_id
    }

    pub const fn principal(self) -> AuthenticatedPrincipal {
        self.principal
    }

    pub const fn expected_presence_revision(self) -> AgentPresenceRevision {
        self.expected_presence_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordination_snapshot_rejects_partial_plan_identity() {
        let goal = GoalAttribution::new(
            crate::GoalId::from_uuid(Uuid::from_u128(1)),
            crate::GoalRevision::INITIAL,
        );
        assert_eq!(
            CoordinationSnapshot::new(
                None,
                Some(DagRevisionNumber::INITIAL),
                Some(DagHeadRevision::INITIAL),
                None,
            ),
            Err(CoordinationSnapshotError::PlanWithoutGoal)
        );
        assert!(CoordinationSnapshot::new(Some(goal), None, None, None).is_ok());
    }

    #[test]
    fn transition_event_id_has_a_stable_versioned_digest() {
        let agent = AgentInstanceId::from_uuid(Uuid::from_u128(0xA010));
        let adjacent = AgentInstanceId::from_uuid(Uuid::from_u128(0xA011));
        let joined = AgentEventId::for_transition(
            agent,
            AgentInstanceRevision::INITIAL,
            AgentEventKind::Joined,
        );
        assert_eq!(
            joined.into_uuid().as_bytes(),
            &[
                0x82, 0x62, 0xe7, 0x8c, 0x1b, 0x7f, 0xc2, 0x83, 0x0d, 0x87, 0x01, 0x92, 0x52, 0x5d,
                0x5c, 0xcc,
            ]
        );
        assert_eq!(
            joined,
            AgentEventId::for_transition(
                agent,
                AgentInstanceRevision::INITIAL,
                AgentEventKind::Joined,
            )
        );
        assert_ne!(
            joined,
            AgentEventId::for_transition(
                agent,
                AgentInstanceRevision::INITIAL,
                AgentEventKind::Left,
            )
        );
        assert_ne!(
            AgentEventId::for_transition(
                agent,
                AgentInstanceRevision::INITIAL,
                AgentEventKind::Left,
            ),
            AgentEventId::for_transition(
                adjacent,
                AgentInstanceRevision::INITIAL,
                AgentEventKind::Joined,
            )
        );
        assert_ne!(joined, AgentEventId::for_handoff_completed(joined));
    }

    #[test]
    fn handoff_keeps_target_principal_explicit() -> Result<(), Box<dyn std::error::Error>> {
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(2));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(3));
        let source = AgentInstanceId::from_uuid(Uuid::from_u128(4));
        let target = AgentInstanceId::from_uuid(Uuid::from_u128(5));
        let source_session = AgentSessionId::from_uuid(Uuid::from_u128(6));
        let target_session = AgentSessionId::from_uuid(Uuid::from_u128(7));
        let actor = ActivityCoordinatorActor::new(
            workspace_id,
            activity_id,
            source,
            ActivityCoordinatorRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            source_session,
        );
        let command = AgentHandoff::new(
            actor,
            AgentInstanceRevision::INITIAL,
            target,
            target_session,
            AuthenticatedPrincipal::TrustedStdio,
            AgentInstanceRevision::INITIAL,
            CoordinationSnapshot::empty(),
            AgentEventId::from_uuid(Uuid::from_u128(8)),
            TimestampMillis::new(10)?,
        );
        assert_eq!(command.target_session_id(), target_session);
        assert_eq!(command.actor().agent_id(), source);
        Ok(())
    }
}
