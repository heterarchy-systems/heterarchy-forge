//! Typed, bounded identity and public-work projections for attached agents.
//!
//! An agent is a durable participant attached to an existing Activity.  It is
//! deliberately not an Activity and therefore does not own a heartbeat or a
//! lease.  Activity liveness remains the sole lease authority; this module
//! only models the agent's attachment, focus, and operator-safe updates.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ActivityProjection, DagNodeId, DagNodeRevision, DagRevisionNumber, GoalAttribution,
    GoalEvidenceRef, McpTokenId, TimestampMillis, WorkspaceId,
};

pub const MAX_AGENT_DISPLAY_NAME_BYTES: usize = 128;
pub const MAX_AGENT_ROLE_BYTES: usize = 128;
pub const MAX_AGENT_WORK_SUMMARY_BYTES: usize = 2 * 1024;
pub const MAX_AGENT_WORK_EVIDENCE_REFS: usize = 32;
pub const MAX_AGENT_FOCUS_EVENTS: usize = 256;
pub const MAX_AGENT_WORK_UPDATES: usize = 128;
pub const MAX_AGENT_LIST_RESULTS: u32 = 256;

/// Stable opaque identity for one attached agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentInstanceId(Uuid);

impl AgentInstanceId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AgentInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AgentInstanceId {
    type Err = AgentInstanceIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(AgentInstanceIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum AgentInstanceIdParseError {
    #[error("invalid Agent instance UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Monotonic compare-and-set revision for one agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentInstanceRevision(i64);

impl AgentInstanceRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentInstanceRevisionError> {
        if value < 1 {
            Err(AgentInstanceRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentInstanceRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentInstanceRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for AgentInstanceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstanceRevisionError {
    #[error("Agent instance revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Agent instance revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Bounded display metadata.  This is never used as an authorization scope.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgentDisplayName(String);

impl AgentDisplayName {
    pub fn new(value: String) -> Result<Self, AgentMetadataError> {
        validate_metadata_text(&value, MAX_AGENT_DISPLAY_NAME_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for AgentDisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentDisplayName")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Bounded declared role metadata.  A role is descriptive only; it does not
/// grant permissions, filesystem access, execution authority, or MCP scope.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgentDeclaredRole(String);

impl AgentDeclaredRole {
    pub fn new(value: String) -> Result<Self, AgentMetadataError> {
        validate_metadata_text(&value, MAX_AGENT_ROLE_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for AgentDeclaredRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentDeclaredRole")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

fn validate_metadata_text(value: &str, maximum: usize) -> Result<(), AgentMetadataError> {
    if value.trim().is_empty() {
        return Err(AgentMetadataError::Empty);
    }
    if value.len() > maximum {
        return Err(AgentMetadataError::TooLarge {
            actual: value.len(),
            maximum,
        });
    }
    if value.chars().any(|character| {
        character == '\0' || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    }) {
        return Err(AgentMetadataError::ControlCharacter);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentMetadataError {
    #[error("Agent metadata must contain non-whitespace content")]
    Empty,
    #[error("Agent metadata contains a forbidden control character")]
    ControlCharacter,
    #[error("Agent metadata has {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
}

/// Transport metadata for an agent connection.  It is descriptive and does
/// not alter the capabilities granted by the Activity or Workspace scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentTransportKind {
    Mcp,
    Stdio,
    StreamableHttp,
    Other,
}

impl AgentTransportKind {
    pub const fn is_mcp(self) -> bool {
        matches!(self, Self::Mcp | Self::StreamableHttp)
    }
}

/// Durable attachment lifecycle for an agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentAttachmentState {
    Attached,
    Detached,
}

impl AgentAttachmentState {
    pub const fn is_attached(self) -> bool {
        matches!(self, Self::Attached)
    }

    pub const fn is_detached(self) -> bool {
        matches!(self, Self::Detached)
    }
}

/// Exact node identity used by an agent focus.  Node identity includes the
/// expected node revision so a stale focus cannot silently target a replaced
/// node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentFocusNode {
    node_id: DagNodeId,
    expected_revision: DagNodeRevision,
}

impl AgentFocusNode {
    pub const fn new(node_id: DagNodeId, expected_revision: DagNodeRevision) -> Self {
        Self {
            node_id,
            expected_revision,
        }
    }

    pub const fn node_id(self) -> DagNodeId {
        self.node_id
    }

    pub const fn id(self) -> DagNodeId {
        self.node_id()
    }

    pub const fn expected_revision(self) -> DagNodeRevision {
        self.expected_revision
    }

    pub const fn revision(self) -> DagNodeRevision {
        self.expected_revision()
    }
}

/// Current exact focus for an agent.
///
/// The tuple is all-or-nothing by level: a DAG revision requires a Goal, and a
/// node requires both.  There is intentionally no Workspace-global current
/// Goal; each agent carries its own optional focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentFocus {
    goal: Option<GoalAttribution>,
    dag_revision: Option<DagRevisionNumber>,
    node: Option<AgentFocusNode>,
}

impl AgentFocus {
    pub const fn unfocused() -> Self {
        Self {
            goal: None,
            dag_revision: None,
            node: None,
        }
    }

    pub fn new(
        goal: Option<GoalAttribution>,
        dag_revision: Option<DagRevisionNumber>,
        node: Option<AgentFocusNode>,
    ) -> Result<Self, AgentFocusError> {
        if goal.is_none() && (dag_revision.is_some() || node.is_some()) {
            return Err(AgentFocusError::DagOrNodeWithoutGoal);
        }
        if goal.is_some() && dag_revision.is_none() && node.is_some() {
            return Err(AgentFocusError::NodeWithoutDag);
        }
        Ok(Self {
            goal,
            dag_revision,
            node,
        })
    }

    pub const fn goal(self) -> Option<GoalAttribution> {
        self.goal
    }

    pub const fn goal_attribution(self) -> Option<GoalAttribution> {
        self.goal()
    }

    pub const fn dag_revision(self) -> Option<DagRevisionNumber> {
        self.dag_revision
    }

    pub const fn node(self) -> Option<AgentFocusNode> {
        self.node
    }

    pub const fn is_unfocused(self) -> bool {
        self.goal.is_none() && self.dag_revision.is_none() && self.node.is_none()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentFocusError {
    #[error("Agent focus DAG revision or node requires a Goal attribution")]
    DagOrNodeWithoutGoal,
    #[error("Agent focus node requires a DAG revision")]
    NodeWithoutDag,
}

/// Focus history event kind.  Events are append-only in persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentFocusEventKind {
    Attached,
    Changed,
    Detached,
}

/// Monotonic event sequence within one agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentFocusEventSequence(i64);

impl AgentFocusEventSequence {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentFocusEventSequenceError> {
        if value < 1 {
            Err(AgentFocusEventSequenceError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentFocusEventSequenceError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentFocusEventSequenceError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentFocusEventSequenceError {
    #[error("Agent focus event sequence must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Agent focus event sequence overflowed at {current}")]
    Overflow { current: i64 },
}

/// One immutable append-only focus event.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentFocusEvent {
    agent_id: AgentInstanceId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    sequence: AgentFocusEventSequence,
    kind: AgentFocusEventKind,
    focus: AgentFocus,
    observed_at: TimestampMillis,
}

impl AgentFocusEvent {
    #[allow(clippy::too_many_arguments)]
    pub const fn from_parts(
        agent_id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        sequence: AgentFocusEventSequence,
        kind: AgentFocusEventKind,
        focus: AgentFocus,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            agent_id,
            workspace_id,
            activity_id,
            sequence,
            kind,
            focus,
            observed_at,
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

    pub const fn sequence(&self) -> AgentFocusEventSequence {
        self.sequence
    }

    pub const fn kind(&self) -> AgentFocusEventKind {
        self.kind
    }

    pub const fn focus(&self) -> AgentFocus {
        self.focus
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Public work phase shown to operators.  It has no scheduler semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgentWorkPhase {
    Planning,
    Executing,
    Waiting,
    Verifying,
    Completed,
    Blocked,
    Failed,
}

/// Bounded operator-safe work summary.  Private reasoning, raw prompts, and
/// transcripts cannot enter this type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgentWorkSummary(String);

impl AgentWorkSummary {
    pub fn new(value: String) -> Result<Self, AgentWorkSummaryError> {
        if value.trim().is_empty() {
            return Err(AgentWorkSummaryError::Empty);
        }
        if value.len() > MAX_AGENT_WORK_SUMMARY_BYTES {
            return Err(AgentWorkSummaryError::TooLarge {
                actual: value.len(),
                maximum: MAX_AGENT_WORK_SUMMARY_BYTES,
            });
        }
        if value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        }) {
            return Err(AgentWorkSummaryError::ControlCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for AgentWorkSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentWorkSummary")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentWorkSummaryError {
    #[error("Agent work summary must contain non-whitespace content")]
    Empty,
    #[error("Agent work summary contains a forbidden control character")]
    ControlCharacter,
    #[error("Agent work summary has {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
}

/// Monotonic update sequence within one agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentWorkUpdateSequence(i64);

impl AgentWorkUpdateSequence {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, AgentWorkUpdateSequenceError> {
        if value < 1 {
            Err(AgentWorkUpdateSequenceError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AgentWorkUpdateSequenceError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AgentWorkUpdateSequenceError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for AgentWorkUpdateSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentWorkUpdateSequenceError {
    #[error("Agent work update sequence must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Agent work update sequence overflowed at {current}")]
    Overflow { current: i64 },
}

/// Stable identity for one immutable public work update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentWorkUpdateId(Uuid);

impl AgentWorkUpdateId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AgentWorkUpdateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AgentWorkUpdateId {
    type Err = AgentWorkUpdateIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(AgentWorkUpdateIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum AgentWorkUpdateIdParseError {
    #[error("invalid Agent work update UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Immutable public progress record.  Evidence identifiers are references to
/// existing Workspace evidence; the control/persistence boundary validates
/// that every reference belongs to the same Workspace.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkUpdate {
    id: AgentWorkUpdateId,
    agent_id: AgentInstanceId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    sequence: AgentWorkUpdateSequence,
    phase: AgentWorkPhase,
    summary: AgentWorkSummary,
    evidence_refs: Vec<GoalEvidenceRef>,
    observed_at: TimestampMillis,
}

impl AgentWorkUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AgentWorkUpdateId,
        agent_id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        sequence: AgentWorkUpdateSequence,
        phase: AgentWorkPhase,
        summary: AgentWorkSummary,
        mut evidence_refs: Vec<GoalEvidenceRef>,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentWorkUpdateError> {
        if evidence_refs.len() > MAX_AGENT_WORK_EVIDENCE_REFS {
            return Err(AgentWorkUpdateError::TooManyEvidenceRefs {
                actual: evidence_refs.len(),
                maximum: MAX_AGENT_WORK_EVIDENCE_REFS,
            });
        }
        evidence_refs.sort_unstable();
        if evidence_refs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AgentWorkUpdateError::DuplicateEvidenceRef);
        }
        Ok(Self {
            id,
            agent_id,
            workspace_id,
            activity_id,
            sequence,
            phase,
            summary,
            evidence_refs,
            observed_at,
        })
    }

    pub const fn id(&self) -> AgentWorkUpdateId {
        self.id
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

    pub const fn sequence(&self) -> AgentWorkUpdateSequence {
        self.sequence
    }

    pub const fn phase(&self) -> AgentWorkPhase {
        self.phase
    }

    pub const fn summary(&self) -> &AgentWorkSummary {
        &self.summary
    }

    pub fn evidence_refs(&self) -> &[GoalEvidenceRef] {
        &self.evidence_refs
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentWorkUpdateError {
    #[error("Agent work update has {actual} evidence references; maximum is {maximum}")]
    TooManyEvidenceRefs { actual: usize, maximum: usize },
    #[error("Agent work update contains a duplicate evidence reference")]
    DuplicateEvidenceRef,
}

/// Durable projection for one attached agent.  Activity liveness is projected
/// from the existing Activity lease; it is not stored or refreshed here.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAttachmentProjection {
    agent: RegisteredAgentInstance,
    activity: ActivityProjection,
}

impl AgentAttachmentProjection {
    pub const fn new(agent: RegisteredAgentInstance, activity: ActivityProjection) -> Self {
        Self { agent, activity }
    }

    pub const fn agent(&self) -> &RegisteredAgentInstance {
        &self.agent
    }

    pub const fn activity(&self) -> &ActivityProjection {
        &self.activity
    }
}

/// One bounded agent context snapshot used by the UI/transport projection.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContextProjection {
    attachment: AgentAttachmentProjection,
    focus_events: Vec<AgentFocusEvent>,
    work_updates: Vec<AgentWorkUpdate>,
}

impl AgentContextProjection {
    pub fn new(
        attachment: AgentAttachmentProjection,
        focus_events: Vec<AgentFocusEvent>,
        work_updates: Vec<AgentWorkUpdate>,
    ) -> Self {
        Self {
            attachment,
            focus_events,
            work_updates,
        }
    }

    pub const fn attachment(&self) -> &AgentAttachmentProjection {
        &self.attachment
    }

    pub fn focus_events(&self) -> &[AgentFocusEvent] {
        &self.focus_events
    }

    pub fn work_updates(&self) -> &[AgentWorkUpdate] {
        &self.work_updates
    }
}

/// Durable agent projection returned by Workspace persistence.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredAgentInstance {
    id: AgentInstanceId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    display_name: AgentDisplayName,
    declared_role: AgentDeclaredRole,
    transport_kind: AgentTransportKind,
    transport_principal: Option<McpTokenId>,
    attachment_state: AgentAttachmentState,
    focus: AgentFocus,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: AgentInstanceRevision,
}

impl RegisteredAgentInstance {
    pub fn create(
        id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        display_name: AgentDisplayName,
        declared_role: AgentDeclaredRole,
        transport_kind: AgentTransportKind,
        observed_at: TimestampMillis,
    ) -> Self {
        Self::create_with_principal(
            id,
            workspace_id,
            activity_id,
            display_name,
            declared_role,
            transport_kind,
            None,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_with_principal(
        id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        display_name: AgentDisplayName,
        declared_role: AgentDeclaredRole,
        transport_kind: AgentTransportKind,
        transport_principal: Option<McpTokenId>,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            workspace_id,
            activity_id,
            display_name,
            declared_role,
            transport_kind,
            transport_principal,
            attachment_state: AgentAttachmentState::Attached,
            focus: AgentFocus::unfocused(),
            created_at: observed_at,
            updated_at: observed_at,
            revision: AgentInstanceRevision::INITIAL,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        display_name: AgentDisplayName,
        declared_role: AgentDeclaredRole,
        transport_kind: AgentTransportKind,
        attachment_state: AgentAttachmentState,
        focus: AgentFocus,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: AgentInstanceRevision,
    ) -> Result<Self, AgentTransitionError> {
        Self::from_parts_with_principal(
            id,
            workspace_id,
            activity_id,
            display_name,
            declared_role,
            transport_kind,
            None,
            attachment_state,
            focus,
            created_at,
            updated_at,
            revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_principal(
        id: AgentInstanceId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        display_name: AgentDisplayName,
        declared_role: AgentDeclaredRole,
        transport_kind: AgentTransportKind,
        transport_principal: Option<McpTokenId>,
        attachment_state: AgentAttachmentState,
        focus: AgentFocus,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: AgentInstanceRevision,
    ) -> Result<Self, AgentTransitionError> {
        if updated_at.get() < created_at.get() {
            return Err(AgentTransitionError::TimestampOrder);
        }
        if transport_principal.is_some() && !transport_kind.is_mcp() {
            return Err(AgentTransitionError::PrincipalTransportMismatch);
        }
        if attachment_state.is_detached() && !focus.is_unfocused() {
            return Err(AgentTransitionError::DetachedFocus);
        }
        if revision == AgentInstanceRevision::INITIAL
            && (attachment_state.is_detached() || !focus.is_unfocused() || updated_at != created_at)
        {
            return Err(AgentTransitionError::InvalidInitialProjection);
        }
        Ok(Self {
            id,
            workspace_id,
            activity_id,
            display_name,
            declared_role,
            transport_kind,
            transport_principal,
            attachment_state,
            focus,
            created_at,
            updated_at,
            revision,
        })
    }

    pub const fn id(&self) -> AgentInstanceId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn display_name(&self) -> &AgentDisplayName {
        &self.display_name
    }

    pub const fn declared_role(&self) -> &AgentDeclaredRole {
        &self.declared_role
    }

    pub const fn role(&self) -> &AgentDeclaredRole {
        self.declared_role()
    }

    pub const fn transport_kind(&self) -> AgentTransportKind {
        self.transport_kind
    }

    pub const fn transport_principal(&self) -> Option<McpTokenId> {
        self.transport_principal
    }

    pub const fn principal(&self) -> Option<McpTokenId> {
        self.transport_principal()
    }

    pub const fn attachment_state(&self) -> AgentAttachmentState {
        self.attachment_state
    }

    pub const fn state(&self) -> AgentAttachmentState {
        self.attachment_state()
    }

    pub const fn focus(&self) -> AgentFocus {
        self.focus
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> AgentInstanceRevision {
        self.revision
    }

    pub fn set_focus(
        &self,
        expected_revision: AgentInstanceRevision,
        focus: AgentFocus,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentTransitionError> {
        if self.revision != expected_revision {
            return Err(AgentTransitionError::RevisionConflict);
        }
        if self.attachment_state.is_detached() {
            return Err(AgentTransitionError::Detached);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(AgentTransitionError::TimestampOrder);
        }
        Ok(Self {
            focus,
            updated_at: observed_at,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| AgentTransitionError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub fn detach(
        &self,
        expected_revision: AgentInstanceRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AgentTransitionError> {
        if self.revision != expected_revision {
            return Err(AgentTransitionError::RevisionConflict);
        }
        if self.attachment_state.is_detached() {
            return Err(AgentTransitionError::AlreadyDetached);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(AgentTransitionError::TimestampOrder);
        }
        Ok(Self {
            attachment_state: AgentAttachmentState::Detached,
            focus: AgentFocus::unfocused(),
            updated_at: observed_at,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| AgentTransitionError::RevisionOverflow)?,
            ..self.clone()
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AgentTransitionError {
    #[error("Agent instance revision conflict")]
    RevisionConflict,
    #[error("Agent instance revision overflow")]
    RevisionOverflow,
    #[error("Agent timestamp order is invalid")]
    TimestampOrder,
    #[error("Detached Agent cannot retain a focus")]
    DetachedFocus,
    #[error("Agent initial projection is invalid")]
    InvalidInitialProjection,
    #[error("Detached Agent cannot change focus")]
    Detached,
    #[error("Agent is already detached")]
    AlreadyDetached,
    #[error("Agent transport principal requires an MCP transport")]
    PrincipalTransportMismatch,
}

/// Input for creating one agent instance.  The application boundary owns ID
/// generation; the domain only validates the resulting typed value.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachAgent {
    agent: RegisteredAgentInstance,
}

impl AttachAgent {
    pub const fn new(agent: RegisteredAgentInstance) -> Self {
        Self { agent }
    }

    pub const fn agent(&self) -> &RegisteredAgentInstance {
        &self.agent
    }
}

/// Input for changing the exact focus of an attached agent.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAgentFocus {
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
    expected_revision: AgentInstanceRevision,
    focus: AgentFocus,
    observed_at: TimestampMillis,
}

impl SetAgentFocus {
    pub const fn new(
        agent_id: AgentInstanceId,
        activity_id: ActivityId,
        expected_revision: AgentInstanceRevision,
        focus: AgentFocus,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            agent_id,
            activity_id,
            expected_revision,
            focus,
            observed_at,
        }
    }

    pub const fn agent_id(&self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn expected_revision(&self) -> AgentInstanceRevision {
        self.expected_revision
    }

    pub const fn focus(&self) -> AgentFocus {
        self.focus
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Input for appending one immutable operator-safe work update.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishAgentWorkUpdate {
    update: AgentWorkUpdate,
}

impl PublishAgentWorkUpdate {
    pub const fn new(update: AgentWorkUpdate) -> Self {
        Self { update }
    }

    pub const fn update(&self) -> &AgentWorkUpdate {
        &self.update
    }
}

/// Input for detaching one agent instance.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachAgent {
    agent_id: AgentInstanceId,
    activity_id: ActivityId,
    expected_revision: AgentInstanceRevision,
    observed_at: TimestampMillis,
}

impl DetachAgent {
    pub const fn new(
        agent_id: AgentInstanceId,
        activity_id: ActivityId,
        expected_revision: AgentInstanceRevision,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            agent_id,
            activity_id,
            expected_revision,
            observed_at,
        }
    }

    pub const fn agent_id(self) -> AgentInstanceId {
        self.agent_id
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn expected_revision(self) -> AgentInstanceRevision {
        self.expected_revision
    }

    pub const fn observed_at(self) -> TimestampMillis {
        self.observed_at
    }
}

/// Bounded query limit for agent lists/history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentListLimit(u32);

impl AgentListLimit {
    pub const DEFAULT: Self = Self(64);

    pub const fn new(value: u32) -> Result<Self, AgentListLimitError> {
        if value == 0 || value > MAX_AGENT_LIST_RESULTS {
            Err(AgentListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_AGENT_LIST_RESULTS,
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
pub enum AgentListLimitError {
    #[error("Agent list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DagNodeId, DagNodeRevision, DagRevisionNumber, GoalId, GoalRevision};

    fn ids() -> (AgentInstanceId, WorkspaceId, ActivityId, GoalAttribution) {
        (
            AgentInstanceId::from_uuid(Uuid::from_u128(1)),
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            ActivityId::from_uuid(Uuid::from_u128(3)),
            GoalAttribution::new(GoalId::from_uuid(Uuid::from_u128(4)), GoalRevision::INITIAL),
        )
    }

    #[test]
    fn focus_is_exact_and_never_invents_a_global_goal() -> Result<(), Box<dyn std::error::Error>> {
        let (_, _, _, goal) = ids();
        let node = AgentFocusNode::new(
            DagNodeId::from_uuid(Uuid::from_u128(5)),
            DagNodeRevision::INITIAL,
        );
        assert!(AgentFocus::new(None, Some(DagRevisionNumber::INITIAL), None).is_err());
        assert!(AgentFocus::new(Some(goal), None, Some(node)).is_err());
        let focus = AgentFocus::new(Some(goal), Some(DagRevisionNumber::INITIAL), Some(node))?;
        assert_eq!(focus.goal(), Some(goal));
        assert_eq!(focus.dag_revision(), Some(DagRevisionNumber::INITIAL));
        assert_eq!(focus.node(), Some(node));
        assert!(AgentFocus::unfocused().is_unfocused());
        Ok(())
    }

    #[test]
    fn metadata_and_work_update_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
        assert!(AgentDisplayName::new("  ".to_owned()).is_err());
        assert!(AgentDeclaredRole::new("reader\0".to_owned()).is_err());
        let (agent, workspace, activity, _) = ids();
        let summary = AgentWorkSummary::new("Inspecting the current node".to_owned())?;
        let update = AgentWorkUpdate::new(
            AgentWorkUpdateId::from_uuid(Uuid::from_u128(6)),
            agent,
            workspace,
            activity,
            AgentWorkUpdateSequence::INITIAL,
            AgentWorkPhase::Planning,
            summary,
            Vec::new(),
            TimestampMillis::new(10)?,
        )?;
        assert_eq!(update.evidence_refs(), &[]);
        Ok(())
    }

    #[test]
    fn detach_clears_focus_and_increments_revision() -> Result<(), Box<dyn std::error::Error>> {
        let (agent, workspace, activity, _) = ids();
        let instance = RegisteredAgentInstance::create(
            agent,
            workspace,
            activity,
            AgentDisplayName::new("Planner".to_owned())?,
            AgentDeclaredRole::new("planner".to_owned())?,
            AgentTransportKind::Mcp,
            TimestampMillis::new(1)?,
        );
        let detached = instance.detach(AgentInstanceRevision::INITIAL, TimestampMillis::new(2)?)?;
        assert!(detached.attachment_state().is_detached());
        assert!(detached.focus().is_unfocused());
        assert_eq!(detached.revision().get(), 2);
        Ok(())
    }
}
