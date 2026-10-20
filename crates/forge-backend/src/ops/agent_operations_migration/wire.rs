//! Checked wire records and canonical source-observation conversion for Agent-operations migration.

#![allow(
    clippy::clone_on_copy,
    clippy::implicit_clone,
    clippy::large_enum_variant,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "The wire module mirrors a closed, bounded source projection; its conversion arms stay explicit for protocol review."
)]

use super::ScopeDto;
use forge_domain::{
    ActivityCoordinatorBinding, ActivityCoordinatorRevision, ActivityId, AgentAttachmentState,
    AgentDeclaredRole, AgentDisplayName, AgentEvent, AgentEventId, AgentEventKind, AgentFocus,
    AgentFocusNode, AgentInstanceId, AgentInstanceRevision, AgentMembershipRevision,
    AgentParticipantRef, AgentRecordParts, AgentSessionId, AgentTransportKind,
    AuthenticatedPrincipal, CoordinationSnapshot, CoordinatorSnapshot, DagHeadRevision, DagNodeId,
    DagNodeRevision, DagRevisionNumber, GoalAttribution, GoalId, GoalRevision,
    RegisteredAgentInstance, TimestampMillis, WorkspaceId,
};
use forge_persistence::{
    AgentOperationsExportCursor, AgentOperationsExportPage, AgentOperationsExportRecord,
    AgentOperationsFreeze, AgentOperationsFreezeState, AgentOperationsInboxKey,
    AgentOperationsPresenceRow,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client::ForgeHttpClientError;
use crate::error::ForgeError;

const MAX_PAGE_ROWS: usize = 64;

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExportCursorWire {
    Participants {
        #[serde(deserialize_with = "required_option")]
        after_agent_id: Option<Uuid>,
    },
    Presence {
        #[serde(deserialize_with = "required_option")]
        after_agent_id: Option<Uuid>,
    },
    Events {
        #[serde(deserialize_with = "required_option")]
        after_event_id: Option<Uuid>,
    },
    Inbox {
        #[serde(deserialize_with = "required_option")]
        after_recipient_agent_id: Option<Uuid>,
        #[serde(deserialize_with = "required_option")]
        after_recipient_session_id: Option<Uuid>,
        #[serde(deserialize_with = "required_option")]
        after_event_id: Option<Uuid>,
    },
    Coordinators {
        #[serde(deserialize_with = "required_option")]
        after_activity_id: Option<Uuid>,
    },
}

impl Default for ExportCursorWire {
    fn default() -> Self {
        Self::Participants {
            after_agent_id: None,
        }
    }
}

impl ExportCursorWire {
    pub(super) fn decode(self) -> Result<AgentOperationsExportCursor, ForgeError> {
        let optional_id = |value: Option<Uuid>, _label: &'static str| Ok(value);
        Ok(match self {
            Self::Participants { after_agent_id } => AgentOperationsExportCursor::Participants(
                optional_id(after_agent_id, "cursor after_agent_id")?
                    .map(AgentInstanceId::from_uuid),
            ),
            Self::Presence { after_agent_id } => AgentOperationsExportCursor::Presence(
                optional_id(after_agent_id, "cursor after_agent_id")?
                    .map(AgentInstanceId::from_uuid),
            ),
            Self::Events { after_event_id } => AgentOperationsExportCursor::Events(
                optional_id(after_event_id, "cursor after_event_id")?
                    .map(forge_domain::AgentEventId::from_uuid),
            ),
            Self::Inbox {
                after_recipient_agent_id,
                after_recipient_session_id,
                after_event_id,
            } => {
                let agent =
                    optional_id(after_recipient_agent_id, "cursor after_recipient_agent_id")?;
                let session = optional_id(
                    after_recipient_session_id,
                    "cursor after_recipient_session_id",
                )?;
                let event = optional_id(after_event_id, "cursor after_event_id")?;
                match (agent, session, event) {
                    (None, None, None) => AgentOperationsExportCursor::Inbox(None),
                    (Some(agent), Some(session), Some(event)) => {
                        AgentOperationsExportCursor::Inbox(Some(AgentOperationsInboxKey::new(
                            AgentInstanceId::from_uuid(agent),
                            AgentSessionId::from_uuid(session),
                            forge_domain::AgentEventId::from_uuid(event),
                        )))
                    }
                    _ => {
                        return Err(ForgeError::invalid_input(
                            "inbox cursor must carry all three key fields",
                        ));
                    }
                }
            }
            Self::Coordinators { after_activity_id } => AgentOperationsExportCursor::Coordinators(
                optional_id(after_activity_id, "cursor after_activity_id")?
                    .map(ActivityId::from_uuid),
            ),
        })
    }
}

impl From<AgentOperationsExportCursor> for ExportCursorWire {
    fn from(value: AgentOperationsExportCursor) -> Self {
        match value {
            AgentOperationsExportCursor::Participants(after_agent_id) => Self::Participants {
                after_agent_id: after_agent_id.map(|id| id.into_uuid()),
            },
            AgentOperationsExportCursor::Presence(after_agent_id) => Self::Presence {
                after_agent_id: after_agent_id.map(|id| id.into_uuid()),
            },
            AgentOperationsExportCursor::Events(after_event_id) => Self::Events {
                after_event_id: after_event_id.map(|id| id.into_uuid()),
            },
            AgentOperationsExportCursor::Inbox(key) => {
                let (agent, session, event) = key.map_or((None, None, None), |key| {
                    (
                        Some(key.recipient_agent_id().into_uuid()),
                        Some(key.recipient_session_id().into_uuid()),
                        Some(key.event_id().into_uuid()),
                    )
                });
                Self::Inbox {
                    after_recipient_agent_id: agent,
                    after_recipient_session_id: session,
                    after_event_id: event,
                }
            }
            AgentOperationsExportCursor::Coordinators(after_activity_id) => Self::Coordinators {
                after_activity_id: after_activity_id.map(|id| id.into_uuid()),
            },
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(super) enum AgentOperationsResultWire {
    Freeze(AgentOperationsFreezeWire),
    FreezeGet(AgentOperationsFreezeGetResponseWire),
    Export(AgentOperationsExportPageWire),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationsFreezeWire {
    pub scope: ScopeDto,
    pub backend_id: Uuid,
    pub workspace_id: Uuid,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub revision: u64,
    pub state: FreezeStateWire,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FreezeStateWire {
    Frozen,
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationsFreezeGetResponseWire {
    pub scope: ScopeDto,
    pub backend_id: Uuid,
    pub workspace_id: Uuid,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    #[serde(deserialize_with = "required_option")]
    pub freeze: Option<AgentOperationsFreezeWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationsExportPageWire {
    pub scope: ScopeDto,
    pub backend_id: Uuid,
    pub workspace_id: Uuid,
    pub migration_id: Uuid,
    pub destination_id: Uuid,
    pub freeze_revision: u64,
    pub requested_cursor: ExportCursorWire,
    #[serde(deserialize_with = "required_option")]
    pub next_cursor: Option<ExportCursorWire>,
    pub records: Vec<AgentOperationsExportRecordWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentOperationsExportRecordWire {
    Participant {
        agent_id: Uuid,
        workspace_id: Uuid,
        activity_id: Uuid,
        #[serde(deserialize_with = "required_option")]
        session_id: Option<Uuid>,
        display_name: String,
        declared_role: String,
        transport: TransportWire,
        principal: PrincipalWire,
        attachment_state: AttachmentStateWire,
        focus: FocusWire,
        created_at_ms: i64,
        updated_at_ms: i64,
        revision: i64,
    },
    Presence {
        agent_id: Uuid,
        workspace_id: Uuid,
        activity_id: Uuid,
        session_id: Uuid,
        last_seen_ms: i64,
        revision: i64,
    },
    Event {
        event_id: Uuid,
        workspace_id: Uuid,
        activity_id: Uuid,
        membership_revision: i64,
        event_kind: EventKindWire,
        #[serde(deserialize_with = "required_option")]
        from: Option<ParticipantRefWire>,
        #[serde(deserialize_with = "required_option")]
        to: Option<ParticipantRefWire>,
        coordination_before: CoordinationWire,
        coordination_after: CoordinationWire,
        coordinator_before: CoordinatorSnapshotWire,
        coordinator_after: CoordinatorSnapshotWire,
        observed_at_ms: i64,
    },
    Inbox {
        recipient_agent_id: Uuid,
        recipient_session_id: Uuid,
        event_id: Uuid,
        revision: i64,
        #[serde(deserialize_with = "required_option")]
        acknowledged_at_ms: Option<i64>,
    },
    Coordinator {
        workspace_id: Uuid,
        activity_id: Uuid,
        agent_id: Uuid,
        revision: i64,
        updated_at_ms: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrincipalWire {
    pub kind: PrincipalKindWire,
    #[serde(deserialize_with = "required_option")]
    pub token_id: Option<Uuid>,
    #[serde(deserialize_with = "required_option")]
    pub grant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKindWire {
    TrustedStdio,
    DirectToken,
    #[serde(rename = "oauth_grant")]
    OAuthGrant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportWire {
    #[serde(rename = "mcp")]
    Retired,
    Stdio,
    StreamableHttp,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentStateWire {
    Attached,
    Detached,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKindWire {
    Joined,
    Left,
    HandoffStarted,
    HandoffCompleted,
    FocusChanged,
    RoleChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FocusWire {
    #[serde(deserialize_with = "required_option")]
    pub goal_id: Option<Uuid>,
    #[serde(deserialize_with = "required_option")]
    pub goal_revision: Option<i64>,
    #[serde(deserialize_with = "required_option")]
    pub dag_revision: Option<i64>,
    #[serde(deserialize_with = "required_option")]
    pub node_id: Option<Uuid>,
    #[serde(deserialize_with = "required_option")]
    pub node_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParticipantRefWire {
    pub agent_id: Uuid,
    #[serde(deserialize_with = "required_option")]
    pub session_id: Option<Uuid>,
    pub principal: PrincipalWire,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoordinationWire {
    #[serde(deserialize_with = "required_option")]
    pub goal_id: Option<Uuid>,
    #[serde(deserialize_with = "required_option")]
    pub goal_revision: Option<i64>,
    #[serde(deserialize_with = "required_option")]
    pub dag_revision: Option<i64>,
    #[serde(deserialize_with = "required_option")]
    pub dag_head_revision: Option<i64>,
    #[serde(deserialize_with = "required_option")]
    pub node_id: Option<Uuid>,
    #[serde(deserialize_with = "required_option")]
    pub node_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorSnapshotWire {
    #[serde(deserialize_with = "required_option")]
    pub agent_id: Option<Uuid>,
    #[serde(deserialize_with = "required_option")]
    pub session_id: Option<Uuid>,
    #[serde(deserialize_with = "required_option")]
    pub revision: Option<i64>,
}

impl AgentOperationsFreezeWire {
    /// Convert a checked transport observation into the canonical Forge
    /// persistence value consumed by the Orchestration importer.
    pub fn into_native(self) -> Result<AgentOperationsFreeze, ForgeHttpClientError> {
        let state = match self.state {
            FreezeStateWire::Frozen => AgentOperationsFreezeState::Frozen,
            FreezeStateWire::Released => AgentOperationsFreezeState::Released,
        };
        AgentOperationsFreeze::from_parts(
            self.migration_id,
            self.destination_id,
            WorkspaceId::from_uuid(self.workspace_id),
            i64::try_from(self.revision).map_err(|_| ForgeHttpClientError::Protocol)?,
            state,
            self.created_at_ms,
            self.updated_at_ms,
        )
        .map_err(|_| ForgeHttpClientError::Protocol)
    }
}

impl AgentOperationsFreezeGetResponseWire {
    /// Convert an exact freeze readback into the canonical Forge observation.
    pub fn into_native(self) -> Result<Option<AgentOperationsFreeze>, ForgeHttpClientError> {
        self.freeze
            .map(AgentOperationsFreezeWire::into_native)
            .transpose()
    }
}

impl AgentOperationsExportPageWire {
    /// Convert a checked wire page into the canonical Forge page type.  The
    /// persistence constructors retain cursor-family, scope, ordering, and
    /// page-size validation at the source-owned boundary.
    pub fn into_native(self) -> Result<AgentOperationsExportPage, ForgeHttpClientError> {
        let workspace_id = WorkspaceId::from_uuid(self.workspace_id);
        let requested_cursor = self
            .requested_cursor
            .clone()
            .decode()
            .map_err(|_| ForgeHttpClientError::Protocol)?;
        let next_cursor = self
            .next_cursor
            .clone()
            .map(|cursor| cursor.decode())
            .transpose()
            .map_err(|_| ForgeHttpClientError::Protocol)?;
        match requested_cursor {
            AgentOperationsExportCursor::Participants(_) => {
                let mut records = Vec::with_capacity(self.records.len());
                for record in self.records {
                    let AgentOperationsExportRecordWire::Participant {
                        agent_id,
                        workspace_id: row_workspace_id,
                        activity_id,
                        session_id,
                        display_name,
                        declared_role,
                        transport,
                        principal,
                        attachment_state,
                        focus,
                        created_at_ms,
                        updated_at_ms,
                        revision,
                    } = record
                    else {
                        return Err(ForgeHttpClientError::Protocol);
                    };
                    records.push(decode_agent(
                        agent_id,
                        row_workspace_id,
                        activity_id,
                        session_id,
                        display_name,
                        declared_role,
                        transport,
                        principal,
                        attachment_state,
                        focus,
                        created_at_ms,
                        updated_at_ms,
                        revision,
                    )?);
                }
                AgentOperationsExportPage::from_participants(
                    workspace_id,
                    self.destination_id,
                    self.migration_id,
                    self.freeze_revision,
                    requested_cursor,
                    next_cursor,
                    records,
                )
                .map_err(|_| ForgeHttpClientError::Protocol)
            }
            AgentOperationsExportCursor::Presence(_) => {
                let mut records = Vec::with_capacity(self.records.len());
                for record in self.records {
                    let AgentOperationsExportRecordWire::Presence {
                        agent_id,
                        workspace_id: row_workspace_id,
                        activity_id,
                        session_id,
                        last_seen_ms,
                        revision,
                    } = record
                    else {
                        return Err(ForgeHttpClientError::Protocol);
                    };
                    records.push(
                        AgentOperationsPresenceRow::from_parts(
                            workspace_id,
                            AgentInstanceId::from_uuid(agent_id),
                            WorkspaceId::from_uuid(row_workspace_id),
                            ActivityId::from_uuid(activity_id),
                            AgentSessionId::from_uuid(session_id),
                            last_seen_ms,
                            revision,
                        )
                        .map_err(|_| ForgeHttpClientError::Protocol)?,
                    );
                }
                AgentOperationsExportPage::from_presence(
                    workspace_id,
                    self.destination_id,
                    self.migration_id,
                    self.freeze_revision,
                    requested_cursor,
                    next_cursor,
                    records,
                )
                .map_err(|_| ForgeHttpClientError::Protocol)
            }
            AgentOperationsExportCursor::Events(_) => {
                let mut records = Vec::with_capacity(self.records.len());
                for record in self.records {
                    let AgentOperationsExportRecordWire::Event {
                        event_id,
                        workspace_id: row_workspace_id,
                        activity_id,
                        membership_revision,
                        event_kind,
                        from,
                        to,
                        coordination_before,
                        coordination_after,
                        coordinator_before,
                        coordinator_after,
                        observed_at_ms,
                    } = record
                    else {
                        return Err(ForgeHttpClientError::Protocol);
                    };
                    records.push(decode_event(
                        event_id,
                        row_workspace_id,
                        activity_id,
                        membership_revision,
                        event_kind,
                        from,
                        to,
                        coordination_before,
                        coordination_after,
                        coordinator_before,
                        coordinator_after,
                        observed_at_ms,
                    )?);
                }
                AgentOperationsExportPage::from_events(
                    workspace_id,
                    self.destination_id,
                    self.migration_id,
                    self.freeze_revision,
                    requested_cursor,
                    next_cursor,
                    records,
                )
                .map_err(|_| ForgeHttpClientError::Protocol)
            }
            AgentOperationsExportCursor::Inbox(_) => {
                let mut records = Vec::with_capacity(self.records.len());
                for record in self.records {
                    let AgentOperationsExportRecordWire::Inbox {
                        recipient_agent_id,
                        recipient_session_id,
                        event_id,
                        revision,
                        acknowledged_at_ms,
                    } = record
                    else {
                        return Err(ForgeHttpClientError::Protocol);
                    };
                    let key = AgentOperationsInboxKey::new(
                        AgentInstanceId::from_uuid(recipient_agent_id),
                        AgentSessionId::from_uuid(recipient_session_id),
                        AgentEventId::from_uuid(event_id),
                    );
                    records.push(
                        forge_persistence::AgentOperationsInboxReceipt::from_parts(
                            key,
                            revision,
                            acknowledged_at_ms,
                        )
                        .map_err(|_| ForgeHttpClientError::Protocol)?,
                    );
                }
                AgentOperationsExportPage::from_inbox(
                    workspace_id,
                    self.destination_id,
                    self.migration_id,
                    self.freeze_revision,
                    requested_cursor,
                    next_cursor,
                    records,
                )
                .map_err(|_| ForgeHttpClientError::Protocol)
            }
            AgentOperationsExportCursor::Coordinators(_) => {
                let mut records = Vec::with_capacity(self.records.len());
                for record in self.records {
                    let AgentOperationsExportRecordWire::Coordinator {
                        workspace_id: row_workspace_id,
                        activity_id,
                        agent_id,
                        revision,
                        updated_at_ms,
                    } = record
                    else {
                        return Err(ForgeHttpClientError::Protocol);
                    };
                    let revision = ActivityCoordinatorRevision::new(revision)
                        .map_err(|_| ForgeHttpClientError::Protocol)?;
                    let updated_at = TimestampMillis::new(updated_at_ms)
                        .map_err(|_| ForgeHttpClientError::Protocol)?;
                    records.push(ActivityCoordinatorBinding::new(
                        WorkspaceId::from_uuid(row_workspace_id),
                        ActivityId::from_uuid(activity_id),
                        AgentInstanceId::from_uuid(agent_id),
                        revision,
                        updated_at,
                    ));
                }
                AgentOperationsExportPage::from_coordinators(
                    workspace_id,
                    self.destination_id,
                    self.migration_id,
                    self.freeze_revision,
                    requested_cursor,
                    next_cursor,
                    records,
                )
                .map_err(|_| ForgeHttpClientError::Protocol)
            }
        }
    }
}

fn decode_agent(
    agent_id: Uuid,
    workspace_id: Uuid,
    activity_id: Uuid,
    session_id: Option<Uuid>,
    display_name: String,
    declared_role: String,
    transport: TransportWire,
    principal: PrincipalWire,
    attachment_state: AttachmentStateWire,
    focus: FocusWire,
    created_at_ms: i64,
    updated_at_ms: i64,
    revision: i64,
) -> Result<RegisteredAgentInstance, ForgeHttpClientError> {
    RegisteredAgentInstance::from_parts(AgentRecordParts {
        id: AgentInstanceId::from_uuid(agent_id),
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        activity_id: ActivityId::from_uuid(activity_id),
        session_id: session_id.map(AgentSessionId::from_uuid),
        display_name: AgentDisplayName::new(display_name)
            .map_err(|_| ForgeHttpClientError::Protocol)?,
        declared_role: AgentDeclaredRole::new(declared_role)
            .map_err(|_| ForgeHttpClientError::Protocol)?,
        transport_kind: decode_transport(transport),
        principal: decode_principal(principal)?,
        attachment_state: match attachment_state {
            AttachmentStateWire::Attached => AgentAttachmentState::Attached,
            AttachmentStateWire::Detached => AgentAttachmentState::Detached,
        },
        focus: decode_focus(focus)?,
        created_at: TimestampMillis::new(created_at_ms)
            .map_err(|_| ForgeHttpClientError::Protocol)?,
        updated_at: TimestampMillis::new(updated_at_ms)
            .map_err(|_| ForgeHttpClientError::Protocol)?,
        revision: AgentInstanceRevision::new(revision)
            .map_err(|_| ForgeHttpClientError::Protocol)?,
    })
    .map_err(|_| ForgeHttpClientError::Protocol)
}

fn decode_transport(value: TransportWire) -> AgentTransportKind {
    match value {
        TransportWire::Retired => AgentTransportKind::Retired,
        TransportWire::Stdio => AgentTransportKind::Stdio,
        TransportWire::StreamableHttp => AgentTransportKind::StreamableHttp,
        TransportWire::Other => AgentTransportKind::Other,
    }
}

fn decode_principal(value: PrincipalWire) -> Result<AuthenticatedPrincipal, ForgeHttpClientError> {
    match value.kind {
        PrincipalKindWire::TrustedStdio if value.token_id.is_none() && value.grant_id.is_none() => {
            Ok(AuthenticatedPrincipal::TrustedStdio)
        }
        PrincipalKindWire::DirectToken if value.token_id.is_some() && value.grant_id.is_none() => {
            Ok(AuthenticatedPrincipal::DirectToken(
                forge_domain::DirectTokenId::from_uuid(
                    value.token_id.ok_or(ForgeHttpClientError::Protocol)?,
                ),
            ))
        }
        PrincipalKindWire::OAuthGrant if value.grant_id.is_some() && value.token_id.is_none() => {
            Ok(AuthenticatedPrincipal::OAuthGrant(
                forge_domain::OAuthGrantId::from_uuid(
                    value.grant_id.ok_or(ForgeHttpClientError::Protocol)?,
                ),
            ))
        }
        _ => Err(ForgeHttpClientError::Protocol),
    }
}

fn decode_focus(value: FocusWire) -> Result<AgentFocus, ForgeHttpClientError> {
    let goal = match (value.goal_id, value.goal_revision) {
        (None, None) => None,
        (Some(id), Some(revision)) => Some(GoalAttribution::new(
            GoalId::from_uuid(id),
            GoalRevision::new(revision).map_err(|_| ForgeHttpClientError::Protocol)?,
        )),
        _ => return Err(ForgeHttpClientError::Protocol),
    };
    let dag_revision = value
        .dag_revision
        .map(DagRevisionNumber::new)
        .transpose()
        .map_err(|_| ForgeHttpClientError::Protocol)?;
    let node = match (value.node_id, value.node_revision) {
        (None, None) => None,
        (Some(id), Some(revision)) => Some(AgentFocusNode::new(
            DagNodeId::from_uuid(id),
            DagNodeRevision::new(revision).map_err(|_| ForgeHttpClientError::Protocol)?,
        )),
        _ => return Err(ForgeHttpClientError::Protocol),
    };
    AgentFocus::new(goal, dag_revision, node).map_err(|_| ForgeHttpClientError::Protocol)
}

fn decode_event(
    event_id: Uuid,
    workspace_id: Uuid,
    activity_id: Uuid,
    membership_revision: i64,
    event_kind: EventKindWire,
    from: Option<ParticipantRefWire>,
    to: Option<ParticipantRefWire>,
    coordination_before: CoordinationWire,
    coordination_after: CoordinationWire,
    coordinator_before: CoordinatorSnapshotWire,
    coordinator_after: CoordinatorSnapshotWire,
    observed_at_ms: i64,
) -> Result<AgentEvent, ForgeHttpClientError> {
    Ok(AgentEvent::new(
        AgentEventId::from_uuid(event_id),
        WorkspaceId::from_uuid(workspace_id),
        ActivityId::from_uuid(activity_id),
        AgentMembershipRevision::new(membership_revision)
            .map_err(|_| ForgeHttpClientError::Protocol)?,
        match event_kind {
            EventKindWire::Joined => AgentEventKind::Joined,
            EventKindWire::Left => AgentEventKind::Left,
            EventKindWire::HandoffStarted => AgentEventKind::HandoffStarted,
            EventKindWire::HandoffCompleted => AgentEventKind::HandoffCompleted,
            EventKindWire::FocusChanged => AgentEventKind::FocusChanged,
            EventKindWire::RoleChanged => AgentEventKind::RoleChanged,
        },
        from.map(decode_participant_ref).transpose()?,
        to.map(decode_participant_ref).transpose()?,
        decode_coordination(coordination_before)?,
        decode_coordination(coordination_after)?,
        decode_coordinator_snapshot(coordinator_before)?,
        decode_coordinator_snapshot(coordinator_after)?,
        TimestampMillis::new(observed_at_ms).map_err(|_| ForgeHttpClientError::Protocol)?,
    ))
}

fn decode_participant_ref(
    value: ParticipantRefWire,
) -> Result<AgentParticipantRef, ForgeHttpClientError> {
    Ok(AgentParticipantRef::new(
        AgentInstanceId::from_uuid(value.agent_id),
        value.session_id.map(AgentSessionId::from_uuid),
        decode_principal(value.principal)?,
        AgentDisplayName::new(value.display_name).map_err(|_| ForgeHttpClientError::Protocol)?,
    ))
}

fn decode_coordination(
    value: CoordinationWire,
) -> Result<CoordinationSnapshot, ForgeHttpClientError> {
    let goal = match (value.goal_id, value.goal_revision) {
        (None, None) => None,
        (Some(id), Some(revision)) => Some(GoalAttribution::new(
            GoalId::from_uuid(id),
            GoalRevision::new(revision).map_err(|_| ForgeHttpClientError::Protocol)?,
        )),
        _ => return Err(ForgeHttpClientError::Protocol),
    };
    let dag_revision = value
        .dag_revision
        .map(DagRevisionNumber::new)
        .transpose()
        .map_err(|_| ForgeHttpClientError::Protocol)?;
    let dag_head_revision = value
        .dag_head_revision
        .map(DagHeadRevision::new)
        .transpose()
        .map_err(|_| ForgeHttpClientError::Protocol)?;
    let node = match (value.node_id, value.node_revision) {
        (None, None) => None,
        (Some(id), Some(revision)) => Some(AgentFocusNode::new(
            DagNodeId::from_uuid(id),
            DagNodeRevision::new(revision).map_err(|_| ForgeHttpClientError::Protocol)?,
        )),
        _ => return Err(ForgeHttpClientError::Protocol),
    };
    CoordinationSnapshot::new(goal, dag_revision, dag_head_revision, node)
        .map_err(|_| ForgeHttpClientError::Protocol)
}

fn decode_coordinator_snapshot(
    value: CoordinatorSnapshotWire,
) -> Result<CoordinatorSnapshot, ForgeHttpClientError> {
    match (value.agent_id, value.session_id, value.revision) {
        (None, None, None) => Ok(CoordinatorSnapshot::unbound()),
        (Some(agent_id), session_id, Some(revision)) => Ok(CoordinatorSnapshot::bound(
            AgentInstanceId::from_uuid(agent_id),
            session_id.map(AgentSessionId::from_uuid),
            ActivityCoordinatorRevision::new(revision)
                .map_err(|_| ForgeHttpClientError::Protocol)?,
        )),
        _ => Err(ForgeHttpClientError::Protocol),
    }
}

pub(super) fn freeze_wire(
    scope: ScopeDto,
    backend_id: forge_domain::ForgeBackendId,
    freeze: &AgentOperationsFreeze,
) -> AgentOperationsFreezeWire {
    AgentOperationsFreezeWire {
        scope,
        backend_id: backend_id.into_uuid(),
        workspace_id: freeze.workspace_id().into_uuid(),
        migration_id: freeze.migration_id(),
        destination_id: freeze.destination_id(),
        revision: freeze.revision(),
        state: match freeze.state() {
            AgentOperationsFreezeState::Frozen => FreezeStateWire::Frozen,
            AgentOperationsFreezeState::Released => FreezeStateWire::Released,
        },
        created_at_ms: freeze.created_at().get(),
        updated_at_ms: freeze.updated_at().get(),
    }
}

pub(super) fn export_page_wire(
    scope: ScopeDto,
    backend_id: forge_domain::ForgeBackendId,
    page: &AgentOperationsExportPage,
) -> Result<AgentOperationsExportPageWire, ForgeError> {
    let records = page
        .records()
        .map(|record| export_record_wire(record, page.workspace_id()))
        .collect::<Result<Vec<_>, _>>()?;
    if records.len() > MAX_PAGE_ROWS {
        return Err(ForgeError::capacity_exceeded("migration export page"));
    }
    Ok(AgentOperationsExportPageWire {
        scope,
        backend_id: backend_id.into_uuid(),
        workspace_id: page.workspace_id().into_uuid(),
        migration_id: page.migration_id(),
        destination_id: page.destination_id(),
        freeze_revision: page.freeze_revision(),
        requested_cursor: page.requested_cursor().into(),
        next_cursor: page.next_cursor().map(Into::into),
        records,
    })
}

fn export_record_wire(
    record: AgentOperationsExportRecord<'_>,
    workspace_id: WorkspaceId,
) -> Result<AgentOperationsExportRecordWire, ForgeError> {
    match record {
        AgentOperationsExportRecord::Participant(agent) => {
            if agent.workspace_id() != workspace_id {
                return Err(ForgeError::resync_required(
                    "export participant scope changed",
                ));
            }
            Ok(AgentOperationsExportRecordWire::Participant {
                agent_id: agent.id().into_uuid(),
                workspace_id: agent.workspace_id().into_uuid(),
                activity_id: agent.activity_id().into_uuid(),
                session_id: agent.session_id().map(AgentSessionId::into_uuid),
                display_name: agent.display_name().as_str().to_owned(),
                declared_role: agent.declared_role().as_str().to_owned(),
                transport: transport_name(agent.transport_kind()).to_owned(),
                principal: principal_wire(agent.principal()),
                attachment_state: attachment_state_name(agent.attachment_state()).to_owned(),
                focus: focus_wire(agent.focus()),
                created_at_ms: agent.created_at().get(),
                updated_at_ms: agent.updated_at().get(),
                revision: agent.revision().get(),
            })
        }
        AgentOperationsExportRecord::Presence(row) => {
            if row.workspace_id() != workspace_id {
                return Err(ForgeError::resync_required("export presence scope changed"));
            }
            Ok(AgentOperationsExportRecordWire::Presence {
                agent_id: row.agent_id().into_uuid(),
                workspace_id: row.workspace_id().into_uuid(),
                activity_id: row.activity_id().into_uuid(),
                session_id: row.session_id().into_uuid(),
                last_seen_ms: row.last_seen().get(),
                revision: row.revision().get(),
            })
        }
        AgentOperationsExportRecord::Event(event) => {
            if event.workspace_id() != workspace_id {
                return Err(ForgeError::resync_required("export event scope changed"));
            }
            Ok(AgentOperationsExportRecordWire::Event {
                event_id: event.id().into_uuid(),
                workspace_id: event.workspace_id().into_uuid(),
                activity_id: event.activity_id().into_uuid(),
                membership_revision: event.membership_revision().get(),
                event_kind: event_kind_name(event.kind()).to_owned(),
                from: event.from().map(participant_ref_wire),
                to: event.to().map(participant_ref_wire),
                coordination_before: coordination_wire(event.coordination_before()),
                coordination_after: coordination_wire(event.coordination_after()),
                coordinator_before: coordinator_snapshot_wire(event.coordinator_before()),
                coordinator_after: coordinator_snapshot_wire(event.coordinator_after()),
                observed_at_ms: event.observed_at().get(),
            })
        }
        AgentOperationsExportRecord::Inbox(receipt) => Ok(AgentOperationsExportRecordWire::Inbox {
            recipient_agent_id: receipt.key().recipient_agent_id().into_uuid(),
            recipient_session_id: receipt.key().recipient_session_id().into_uuid(),
            event_id: receipt.key().event_id().into_uuid(),
            revision: receipt.revision().get(),
            acknowledged_at_ms: receipt.acknowledged_at().map(TimestampMillis::get),
        }),
        AgentOperationsExportRecord::Coordinator(binding) => {
            if binding.workspace_id() != workspace_id {
                return Err(ForgeError::resync_required(
                    "export coordinator scope changed",
                ));
            }
            Ok(AgentOperationsExportRecordWire::Coordinator {
                workspace_id: binding.workspace_id().into_uuid(),
                activity_id: binding.activity_id().into_uuid(),
                agent_id: binding.agent_id().into_uuid(),
                revision: binding.revision().get(),
                updated_at_ms: binding.updated_at().get(),
            })
        }
    }
}

fn principal_wire(value: AuthenticatedPrincipal) -> PrincipalWire {
    match value {
        AuthenticatedPrincipal::TrustedStdio => PrincipalWire {
            kind: PrincipalKindWire::TrustedStdio,
            token_id: None,
            grant_id: None,
        },
        AuthenticatedPrincipal::DirectToken(id) => PrincipalWire {
            kind: PrincipalKindWire::DirectToken,
            token_id: Some(id.into_uuid()),
            grant_id: None,
        },
        AuthenticatedPrincipal::OAuthGrant(id) => PrincipalWire {
            kind: PrincipalKindWire::OAuthGrant,
            token_id: None,
            grant_id: Some(id.into_uuid()),
        },
    }
}

fn participant_ref_wire(value: &AgentParticipantRef) -> ParticipantRefWire {
    ParticipantRefWire {
        agent_id: value.agent_id().into_uuid(),
        session_id: value.session_id().map(AgentSessionId::into_uuid),
        principal: principal_wire(value.principal()),
        display_name: value.display_name().as_str().to_owned(),
    }
}

fn focus_wire(value: AgentFocus) -> FocusWire {
    FocusWire {
        goal_id: value.goal().map(|goal| goal.goal_id().into_uuid()),
        goal_revision: value.goal().map(|goal| goal.expected_revision().get()),
        dag_revision: value.dag_revision().map(DagRevisionNumber::get),
        node_id: value.node().map(|node| node.node_id().into_uuid()),
        node_revision: value.node().map(|node| node.expected_revision().get()),
    }
}

fn coordination_wire(value: CoordinationSnapshot) -> CoordinationWire {
    CoordinationWire {
        goal_id: value.goal().map(|goal| goal.goal_id().into_uuid()),
        goal_revision: value.goal().map(|goal| goal.expected_revision().get()),
        dag_revision: value.dag_revision().map(DagRevisionNumber::get),
        dag_head_revision: value.dag_head_revision().map(DagHeadRevision::get),
        node_id: value.node().map(|node| node.node_id().into_uuid()),
        node_revision: value.node().map(|node| node.expected_revision().get()),
    }
}

fn coordinator_snapshot_wire(value: CoordinatorSnapshot) -> CoordinatorSnapshotWire {
    CoordinatorSnapshotWire {
        agent_id: value.agent_id().map(AgentInstanceId::into_uuid),
        session_id: value.session_id().map(AgentSessionId::into_uuid),
        revision: value.revision().map(ActivityCoordinatorRevision::get),
    }
}

fn transport_name(value: AgentTransportKind) -> TransportWire {
    match value {
        AgentTransportKind::Retired => TransportWire::Retired,
        AgentTransportKind::Stdio => TransportWire::Stdio,
        AgentTransportKind::StreamableHttp => TransportWire::StreamableHttp,
        AgentTransportKind::Other => TransportWire::Other,
    }
}

fn attachment_state_name(value: forge_domain::AgentAttachmentState) -> AttachmentStateWire {
    match value {
        forge_domain::AgentAttachmentState::Attached => AttachmentStateWire::Attached,
        forge_domain::AgentAttachmentState::Detached => AttachmentStateWire::Detached,
    }
}

fn event_kind_name(value: AgentEventKind) -> EventKindWire {
    match value {
        AgentEventKind::Joined => EventKindWire::Joined,
        AgentEventKind::Left => EventKindWire::Left,
        AgentEventKind::HandoffStarted => EventKindWire::HandoffStarted,
        AgentEventKind::HandoffCompleted => EventKindWire::HandoffCompleted,
        AgentEventKind::FocusChanged => EventKindWire::FocusChanged,
        AgentEventKind::RoleChanged => EventKindWire::RoleChanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use serde_json::json;

    fn scope() -> Value {
        json!({
            "workspace_id": Uuid::from_u128(1),
            "workspace_revision": 1,
            "locator": {
                "location_id": Uuid::from_u128(2),
                "expected_revision": 1,
                "relative_root": "."
            }
        })
    }

    #[test]
    fn missing_freeze_readback_is_rejected() {
        let value = json!({
            "scope": scope(),
            "backend_id": Uuid::from_u128(3),
            "workspace_id": Uuid::from_u128(1),
            "migration_id": Uuid::from_u128(4),
            "destination_id": Uuid::from_u128(5),
        });
        assert!(serde_json::from_value::<AgentOperationsFreezeGetResponseWire>(value).is_err());
    }

    #[test]
    fn missing_export_next_cursor_is_rejected() {
        let value = json!({
            "scope": scope(),
            "backend_id": Uuid::from_u128(3),
            "workspace_id": Uuid::from_u128(1),
            "migration_id": Uuid::from_u128(4),
            "destination_id": Uuid::from_u128(5),
            "freeze_revision": 1,
            "requested_cursor": {"kind": "participants", "after_agent_id": null},
            "records": [],
        });
        assert!(serde_json::from_value::<AgentOperationsExportPageWire>(value).is_err());
    }

    #[test]
    fn missing_cursor_key_is_rejected() {
        let value = json!({"kind": "participants"});
        assert!(serde_json::from_value::<ExportCursorWire>(value).is_err());
    }
}
