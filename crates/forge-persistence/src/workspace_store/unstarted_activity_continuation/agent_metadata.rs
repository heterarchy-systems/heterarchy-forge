//! Closed validation and canonical digest for retained Agent planning metadata.

use forge_domain::{
    ActivityId, AgentEventKind, ExpectedActivityCoordinator, ExpiredActivityRecoveryAgentSnapshot,
    WorkspaceId,
};
use rusqlite::{Connection, params, types::ValueRef};
use sha2::{Digest, Sha256};

use super::UnstartedActivityContinuationStoreError;

const DOMAIN: &[u8] = b"heterarchy.forge.unstarted-activity-continuation.agent-metadata.v1";

pub(super) fn validate_and_digest_agent_metadata(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    expected_agents: &[ExpiredActivityRecoveryAgentSnapshot],
    expected_coordinator: ExpectedActivityCoordinator,
) -> Result<[u8; 32], UnstartedActivityContinuationStoreError> {
    validate_typed_authority(
        connection,
        workspace_id,
        activity_id,
        expected_agents,
        expected_coordinator,
    )?;
    validate_typed_events(connection, workspace_id, activity_id)?;
    validate_relational_counterparts(connection, workspace_id, activity_id)?;

    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for (table, sql) in DIGEST_QUERIES {
        hash_rows(&mut hasher, connection, table, sql, &workspace, &activity)?;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) fn validate_and_digest_agent_metadata_for_test(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    expected_agents: &[ExpiredActivityRecoveryAgentSnapshot],
    expected_coordinator: ExpectedActivityCoordinator,
) -> Result<[u8; 32], UnstartedActivityContinuationStoreError> {
    validate_and_digest_agent_metadata(
        connection,
        workspace_id,
        activity_id,
        expected_agents,
        expected_coordinator,
    )
}

fn validate_typed_events(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let oversized_focus: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (
           SELECT agent_id FROM agent_focus_events WHERE workspace_id=?1 AND activity_id=?2
           GROUP BY agent_id HAVING COUNT(*)>?3)",
        params![
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes(),
            i64::try_from(forge_domain::MAX_AGENT_FOCUS_EVENTS).map_err(|_| {
                UnstartedActivityContinuationStoreError::Corrupt("Agent focus event limit")
            })?
        ],
        |row| row.get(0),
    )?;
    let event_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM agent_events WHERE workspace_id=?1 AND activity_id=?2",
        params![
            workspace_id.into_uuid().as_bytes(),
            activity_id.into_uuid().as_bytes()
        ],
        |row| row.get(0),
    )?;
    if oversized_focus != 0 || event_count > i64::from(forge_domain::MAX_AGENT_EVENT_RESULTS) {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "Agent event metadata exceeds validation bounds",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT o.* FROM agent_effect_outbox_transitions o
         JOIN agent_effect_outbox_entries x ON x.sequence=o.outbox_sequence
         WHERE x.workspace_id=?1 AND o.activity_id=?2 ORDER BY o.outbox_sequence",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        activity_id.into_uuid().as_bytes()
    ])?;
    while let Some(row) = rows.next()? {
        let event = crate::workspace_agent_events::decode_event_at(row, 1).map_err(|_| {
            UnstartedActivityContinuationStoreError::Corrupt("Agent transition outbox metadata")
        })?;
        if !matches!(
            event.kind(),
            AgentEventKind::Joined | AgentEventKind::FocusChanged | AgentEventKind::RoleChanged
        ) {
            return Err(UnstartedActivityContinuationStoreError::Conflict(
                "terminal Agent transition outbox metadata",
            ));
        }
    }
    Ok(())
}

fn validate_typed_authority(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    expected_agents: &[ExpiredActivityRecoveryAgentSnapshot],
    expected_coordinator: ExpectedActivityCoordinator,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let mut actual = crate::workspace_agents::list_for_activity_in_transaction(
        connection,
        workspace_id,
        activity_id,
        forge_domain::MAX_AGENT_LIST_RESULTS + 1,
    )?
    .iter()
    .map(ExpiredActivityRecoveryAgentSnapshot::from_agent)
    .collect::<Vec<_>>();
    if actual.len() > forge_domain::MAX_AGENT_LIST_RESULTS as usize
        || expected_agents.len() > forge_domain::MAX_AGENT_LIST_RESULTS as usize
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "Agent metadata exceeds validation bounds",
        ));
    }
    let mut expected = expected_agents.to_vec();
    actual.sort_by_key(|agent| agent.agent_id().into_uuid());
    expected.sort_by_key(|agent| agent.agent_id().into_uuid());
    if actual != expected {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "Agent metadata differs from probe",
        ));
    }
    if actual.iter().any(|agent| {
        agent.workspace_id() != workspace_id
            || agent.activity_id() != activity_id
            || agent.session_id().is_none()
            || agent.focus().is_err()
    }) {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "Agent metadata scope/session/focus",
        ));
    }

    let coordinator = crate::workspace_coordinators::get_in_transaction(connection, activity_id)?
        .ok_or(UnstartedActivityContinuationStoreError::Conflict(
        "Coordinator metadata missing",
    ))?;
    if coordinator.workspace_id() != workspace_id
        || coordinator.agent_id() != expected_coordinator.agent_id()
        || coordinator.revision().get() != expected_coordinator.revision()
        || coordinator.updated_at() != expected_coordinator.updated_at()
        || !actual
            .iter()
            .any(|agent| agent.agent_id() == coordinator.agent_id() && agent.session_id().is_some())
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "Coordinator metadata differs from probe",
        ));
    }
    Ok(())
}

fn validate_relational_counterparts(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<(), UnstartedActivityContinuationStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    for (label, sql) in INVALID_QUERIES {
        let invalid: i64 = connection.query_row(
            sql,
            params![workspace.as_slice(), activity.as_slice()],
            |row| row.get(0),
        )?;
        if invalid != 0 {
            return Err(UnstartedActivityContinuationStoreError::Conflict(label));
        }
    }
    Ok(())
}

const INVALID_QUERIES: &[(&str, &str)] = &[
    (
        "Agent focus metadata is not planning-only or lacks a valid Agent counterpart",
        "SELECT COUNT(*) FROM agent_focus_events f
         LEFT JOIN agent_instances a ON a.agent_id=f.agent_id AND a.workspace_id=f.workspace_id AND a.activity_id=f.activity_id
         WHERE f.workspace_id=?1 AND f.activity_id=?2 AND (
           a.agent_id IS NULL OR f.event_kind=2 OR f.observed_at_ms>a.updated_at_ms OR
           f.event_sequence<>(SELECT COUNT(*) FROM agent_focus_events p WHERE p.agent_id=f.agent_id AND p.event_sequence<=f.event_sequence) OR
           (f.event_sequence=(SELECT MAX(p.event_sequence) FROM agent_focus_events p WHERE p.agent_id=f.agent_id) AND NOT (
             f.focus_goal_id IS a.focus_goal_id AND f.focus_goal_revision IS a.focus_goal_revision AND
             f.focus_dag_revision IS a.focus_dag_revision AND f.focus_node_id IS a.focus_node_id AND
             f.focus_node_revision IS a.focus_node_revision)))",
    ),
    (
        "Agent presence metadata lacks its exact current binding",
        "SELECT COUNT(*) FROM agent_presence p
         LEFT JOIN agent_instances a ON a.agent_id=p.agent_id AND a.workspace_id=p.workspace_id AND a.activity_id=p.activity_id
         WHERE p.workspace_id=?1 AND p.activity_id=?2 AND (
           a.agent_id IS NULL OR a.attachment_state<>0 OR a.session_id IS NULL OR
           p.session_id<>a.session_id OR p.last_authenticated_at_ms>a.updated_at_ms OR p.presence_revision>a.revision)",
    ),
    (
        "Agent lifecycle metadata is terminal, unmatched, or non-contiguous",
        "SELECT COUNT(*) FROM agent_events e
         WHERE e.workspace_id=?1 AND e.activity_id=?2 AND (
           e.event_kind NOT IN (0,4,5) OR
           e.membership_revision<>(SELECT COUNT(*) FROM agent_events p WHERE p.activity_id=e.activity_id AND p.membership_revision<=e.membership_revision)+(SELECT COUNT(*) FROM agent_effect_outbox_transitions p WHERE p.activity_id=e.activity_id AND p.membership_revision<=e.membership_revision) OR
           (e.from_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=e.from_agent_id AND a.workspace_id=e.workspace_id AND a.activity_id=e.activity_id AND a.session_id=e.from_session_id AND a.principal_kind=e.from_principal_kind AND a.principal_id IS e.from_principal_id AND a.display_name=e.from_display_name)) OR
           (e.to_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=e.to_agent_id AND a.workspace_id=e.workspace_id AND a.activity_id=e.activity_id AND a.session_id=e.to_session_id AND a.principal_kind=e.to_principal_kind AND a.principal_id IS e.to_principal_id AND a.display_name=e.to_display_name)) OR
           (e.before_goal_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM goals g JOIN goal_dag_revisions d ON d.goal_id=g.goal_id AND d.dag_revision=e.before_dag_revision WHERE g.goal_id=e.before_goal_id AND g.workspace_id=e.workspace_id AND g.activity_id=e.activity_id AND g.revision=e.before_goal_revision)) OR
           (e.after_goal_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM goals g JOIN goal_dag_revisions d ON d.goal_id=g.goal_id AND d.dag_revision=e.after_dag_revision WHERE g.goal_id=e.after_goal_id AND g.workspace_id=e.workspace_id AND g.activity_id=e.activity_id AND g.revision=e.after_goal_revision)) OR
           (e.before_coordinator_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=e.before_coordinator_agent_id AND a.workspace_id=e.workspace_id AND a.activity_id=e.activity_id AND a.session_id=e.before_coordinator_session_id)) OR
           (e.after_coordinator_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=e.after_coordinator_agent_id AND a.workspace_id=e.workspace_id AND a.activity_id=e.activity_id AND a.session_id=e.after_coordinator_session_id)))",
    ),
    (
        "Agent inbox metadata is acknowledged, orphaned, or bound to another Session",
        "SELECT COUNT(*) FROM agent_inbox i
         JOIN agent_events e ON e.event_id=i.event_id
         LEFT JOIN agent_instances a ON a.agent_id=i.recipient_agent_id AND a.workspace_id=e.workspace_id AND a.activity_id=e.activity_id
         WHERE e.workspace_id=?1 AND e.activity_id=?2 AND (
           a.agent_id IS NULL OR a.session_id<>i.recipient_session_id OR i.receipt_revision<>1 OR i.acknowledged_at_ms IS NOT NULL)",
    ),
    (
        "Agent inbox row has no target lifecycle parent",
        "SELECT COUNT(*) FROM agent_inbox i
         LEFT JOIN agent_events e ON e.event_id=i.event_id
         JOIN agent_instances a ON a.agent_id=i.recipient_agent_id
         WHERE a.workspace_id=?1 AND a.activity_id=?2 AND e.event_id IS NULL",
    ),
    (
        "Agent focus outbox payload has no exact target focus counterpart",
        "SELECT COUNT(*) FROM agent_effect_outbox_focus o
         JOIN agent_effect_outbox_entries x ON x.sequence=o.outbox_sequence
         LEFT JOIN agent_focus_events f ON f.agent_id=o.agent_id AND f.workspace_id=x.workspace_id AND f.activity_id=o.activity_id AND f.event_sequence=o.event_sequence
           AND f.event_kind=o.event_kind AND f.focus_goal_id IS o.focus_goal_id AND f.focus_goal_revision IS o.focus_goal_revision
           AND f.focus_dag_revision IS o.focus_dag_revision AND f.focus_node_id IS o.focus_node_id AND f.focus_node_revision IS o.focus_node_revision
           AND f.observed_at_ms=o.observed_at_ms
         WHERE x.workspace_id=?1 AND o.activity_id=?2 AND (x.fact_kind<>0 OR f.agent_id IS NULL)",
    ),
    (
        "Agent focus outbox payload is orphaned from its entry",
        "SELECT COUNT(*) FROM agent_effect_outbox_focus o
         LEFT JOIN agent_effect_outbox_entries x ON x.sequence=o.outbox_sequence
         WHERE o.activity_id=?2 AND x.sequence IS NULL AND EXISTS (
           SELECT 1 FROM agent_instances a WHERE a.agent_id=o.agent_id AND a.workspace_id=?1 AND a.activity_id=o.activity_id)",
    ),
    (
        "Agent transition outbox payload is terminal, mismatched, or lacks an Agent counterpart",
        "SELECT COUNT(*) FROM agent_effect_outbox_transitions o
         JOIN agent_effect_outbox_entries x ON x.sequence=o.outbox_sequence
         WHERE x.workspace_id=?1 AND o.activity_id=?2 AND (
           x.fact_kind<>1 OR o.workspace_id<>x.workspace_id OR
           o.membership_revision<>(SELECT COUNT(*) FROM agent_events p WHERE p.activity_id=o.activity_id AND p.membership_revision<=o.membership_revision)+(SELECT COUNT(*) FROM agent_effect_outbox_transitions p WHERE p.activity_id=o.activity_id AND p.membership_revision<=o.membership_revision) OR
           (o.from_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=o.from_agent_id AND a.workspace_id=o.workspace_id AND a.activity_id=o.activity_id AND a.session_id=o.from_session_id AND a.principal_kind=o.from_principal_kind AND a.principal_id IS o.from_principal_id AND a.display_name=o.from_display_name)) OR
           (o.to_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=o.to_agent_id AND a.workspace_id=o.workspace_id AND a.activity_id=o.activity_id AND a.session_id=o.to_session_id AND a.principal_kind=o.to_principal_kind AND a.principal_id IS o.to_principal_id AND a.display_name=o.to_display_name)) OR
           (o.before_goal_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM goals g JOIN goal_dag_revisions d ON d.goal_id=g.goal_id AND d.dag_revision=o.before_dag_revision WHERE g.goal_id=o.before_goal_id AND g.workspace_id=o.workspace_id AND g.activity_id=o.activity_id AND g.revision=o.before_goal_revision)) OR
           (o.after_goal_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM goals g JOIN goal_dag_revisions d ON d.goal_id=g.goal_id AND d.dag_revision=o.after_dag_revision WHERE g.goal_id=o.after_goal_id AND g.workspace_id=o.workspace_id AND g.activity_id=o.activity_id AND g.revision=o.after_goal_revision)) OR
           (o.before_coordinator_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=o.before_coordinator_agent_id AND a.workspace_id=o.workspace_id AND a.activity_id=o.activity_id AND a.session_id=o.before_coordinator_session_id)) OR
           (o.after_coordinator_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_instances a WHERE a.agent_id=o.after_coordinator_agent_id AND a.workspace_id=o.workspace_id AND a.activity_id=o.activity_id AND a.session_id=o.after_coordinator_session_id)))",
    ),
    (
        "Agent transition outbox payload is orphaned from its entry",
        "SELECT COUNT(*) FROM agent_effect_outbox_transitions o
         LEFT JOIN agent_effect_outbox_entries x ON x.sequence=o.outbox_sequence
         WHERE o.workspace_id=?1 AND o.activity_id=?2 AND x.sequence IS NULL",
    ),
    (
        "Agent outbox entry has missing, duplicate, or mismatched target payload",
        "SELECT COUNT(*) FROM agent_effect_outbox_entries x
         WHERE x.workspace_id=?1 AND EXISTS (
           SELECT 1 FROM agent_effect_outbox_focus f WHERE f.outbox_sequence=x.sequence AND f.activity_id=?2
           UNION ALL SELECT 1 FROM agent_effect_outbox_transitions t WHERE t.outbox_sequence=x.sequence AND t.activity_id=?2)
         AND ((x.fact_kind=0 AND ((SELECT COUNT(*) FROM agent_effect_outbox_focus f WHERE f.outbox_sequence=x.sequence)<>1 OR EXISTS (SELECT 1 FROM agent_effect_outbox_transitions t WHERE t.outbox_sequence=x.sequence))) OR
              (x.fact_kind=1 AND ((SELECT COUNT(*) FROM agent_effect_outbox_transitions t WHERE t.outbox_sequence=x.sequence)<>1 OR EXISTS (SELECT 1 FROM agent_effect_outbox_focus f WHERE f.outbox_sequence=x.sequence))))",
    ),
    (
        "Agent outbox recipient lacks an exact transition and Agent/Session counterpart",
        "SELECT COUNT(*) FROM agent_effect_outbox_recipients r
         JOIN agent_effect_outbox_transitions t ON t.outbox_sequence=r.outbox_sequence
         JOIN agent_effect_outbox_entries x ON x.sequence=r.outbox_sequence
         LEFT JOIN agent_instances a ON a.agent_id=r.recipient_agent_id AND a.workspace_id=x.workspace_id AND a.activity_id=t.activity_id
         WHERE x.workspace_id=?1 AND t.activity_id=?2 AND (a.agent_id IS NULL OR a.session_id<>r.recipient_session_id)",
    ),
    (
        "Agent outbox recipient is orphaned from its transition payload",
        "SELECT COUNT(*) FROM agent_effect_outbox_recipients r
         JOIN agent_effect_outbox_entries x ON x.sequence=r.outbox_sequence
         LEFT JOIN agent_effect_outbox_transitions t ON t.outbox_sequence=r.outbox_sequence
         WHERE x.workspace_id=?1 AND t.outbox_sequence IS NULL AND EXISTS (
           SELECT 1 FROM agent_instances a WHERE a.agent_id=r.recipient_agent_id AND a.activity_id=?2)",
    ),
];

const DIGEST_QUERIES: &[(&str, &str)] = &[
    (
        "agent_instances",
        "SELECT * FROM agent_instances WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id",
    ),
    (
        "agent_focus_events",
        "SELECT * FROM agent_focus_events WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id,event_sequence",
    ),
    (
        "agent_presence",
        "SELECT * FROM agent_presence WHERE workspace_id=?1 AND activity_id=?2 ORDER BY agent_id",
    ),
    (
        "agent_events",
        "SELECT * FROM agent_events WHERE workspace_id=?1 AND activity_id=?2 ORDER BY membership_revision,event_id",
    ),
    (
        "agent_inbox",
        "SELECT i.* FROM agent_inbox i JOIN agent_events e ON e.event_id=i.event_id WHERE e.workspace_id=?1 AND e.activity_id=?2 ORDER BY i.recipient_agent_id,i.recipient_session_id,i.event_id",
    ),
    (
        "activity_coordinators",
        "SELECT * FROM activity_coordinators WHERE workspace_id=?1 AND activity_id=?2 ORDER BY activity_id",
    ),
    (
        "agent_effect_outbox_entries",
        "SELECT x.* FROM agent_effect_outbox_entries x WHERE x.workspace_id=?1 AND EXISTS (SELECT 1 FROM agent_effect_outbox_focus f WHERE f.outbox_sequence=x.sequence AND f.activity_id=?2 UNION ALL SELECT 1 FROM agent_effect_outbox_transitions t WHERE t.outbox_sequence=x.sequence AND t.activity_id=?2) ORDER BY x.sequence",
    ),
    (
        "agent_effect_outbox_focus",
        "SELECT f.* FROM agent_effect_outbox_focus f JOIN agent_effect_outbox_entries x ON x.sequence=f.outbox_sequence WHERE x.workspace_id=?1 AND f.activity_id=?2 ORDER BY f.outbox_sequence",
    ),
    (
        "agent_effect_outbox_transitions",
        "SELECT t.* FROM agent_effect_outbox_transitions t JOIN agent_effect_outbox_entries x ON x.sequence=t.outbox_sequence WHERE x.workspace_id=?1 AND t.activity_id=?2 ORDER BY t.outbox_sequence",
    ),
    (
        "agent_effect_outbox_recipients",
        "SELECT r.* FROM agent_effect_outbox_recipients r JOIN agent_effect_outbox_entries x ON x.sequence=r.outbox_sequence JOIN agent_effect_outbox_transitions t ON t.outbox_sequence=r.outbox_sequence WHERE x.workspace_id=?1 AND t.activity_id=?2 ORDER BY r.outbox_sequence,r.hint_index",
    ),
];

fn hash_rows(
    hasher: &mut Sha256,
    connection: &Connection,
    table: &str,
    sql: &str,
    workspace_id: &[u8],
    activity_id: &[u8],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    hash_bytes(hasher, table.as_bytes());
    let mut statement = connection.prepare(sql)?;
    let columns = statement
        .column_names()
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    hash_u64(hasher, columns.len() as u64);
    for column in &columns {
        hash_bytes(hasher, column.as_bytes());
    }
    let mut rows = statement.query(params![workspace_id, activity_id])?;
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .ok_or(UnstartedActivityContinuationStoreError::Corrupt(
                "Agent metadata row count overflow",
            ))?;
        hasher.update([0xFD]);
        for index in 0..columns.len() {
            match row.get_ref(index)? {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hasher.update(value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) => {
                    hasher.update([3]);
                    hash_bytes(hasher, value);
                }
                ValueRef::Blob(value) => {
                    hasher.update([4]);
                    hash_bytes(hasher, value);
                }
            }
        }
        hasher.update([0xFE]);
    }
    hash_u64(hasher, count);
    hasher.update([0xFF]);
    Ok(())
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
