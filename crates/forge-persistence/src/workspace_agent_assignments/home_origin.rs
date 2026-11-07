//! Checked raw assignment pins used by the Home receipt reader.
//!
//! This module deliberately does not call the full assignment decoder. The
//! application ledger reader can compare its immutable successor snapshot with
//! these raw SQL pins without recursing from assignment decoding back into
//! receipt decoding.

use forge_domain::{
    ActivityId, AgentAssignmentCoordinator, AgentAssignmentId, AgentAssignmentOrigin,
    AgentAssignmentRevision, AgentAssignmentState, AgentAssignmentTarget, AgentInstanceId,
    AgentSessionId, DagHeadRevision, DagNodeId, DagNodeRevision, DagRevisionNumber, GoalId,
    GoalRevision, TimestampMillis, WorkCreditBudget, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use super::{
    AgentAssignmentStoreError, decode_activity_coordinator_revision, decode_agent_revision,
    decode_assignment_revision, decode_bool, decode_credit_budget, decode_dag_head_revision,
    decode_dag_node_revision, decode_dag_revision, decode_goal_revision, decode_principal,
    decode_state, decode_timestamp, decode_uuid,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HomeOriginAssignmentPins {
    pub(crate) assignment_id: AgentAssignmentId,
    pub(crate) origin_kind: i64,
    pub(crate) home_receipt_id: Option<Uuid>,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) activity_id: ActivityId,
    pub(crate) goal_id: GoalId,
    pub(crate) goal_created_at: TimestampMillis,
    pub(crate) goal_revision: GoalRevision,
    pub(crate) dag_revision: DagRevisionNumber,
    pub(crate) dag_head_revision: DagHeadRevision,
    pub(crate) node_id: DagNodeId,
    pub(crate) node_revision: DagNodeRevision,
    pub(crate) coordinator: AgentAssignmentCoordinator,
    pub(crate) target: AgentAssignmentTarget,
    pub(crate) credit_budget: Option<WorkCreditBudget>,
    pub(crate) created_at: TimestampMillis,
    pub(crate) updated_at: TimestampMillis,
    pub(crate) revision: AgentAssignmentRevision,
    pub(crate) state: AgentAssignmentState,
    pub(crate) cancellation_requested: bool,
}

struct RawHomeOriginAssignmentPins {
    assignment_id: Vec<u8>,
    origin_kind: i64,
    home_receipt_id: Option<Vec<u8>>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    goal_id: Vec<u8>,
    goal_created_at_ms: i64,
    goal_revision: i64,
    dag_revision: i64,
    dag_head_revision: i64,
    node_id: Vec<u8>,
    node_revision: i64,
    coordinator_agent_id: Vec<u8>,
    coordinator_session_id: Vec<u8>,
    coordinator_principal_kind: i64,
    coordinator_principal_id: Option<Vec<u8>>,
    coordinator_revision: i64,
    target_agent_id: Vec<u8>,
    target_session_id: Vec<u8>,
    target_principal_kind: i64,
    target_principal_id: Option<Vec<u8>>,
    target_agent_revision: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
    revision: i64,
    state: i64,
    cancellation_requested: i64,
    credit_budget: Option<i64>,
}

pub(crate) fn read(
    connection: &Connection,
    assignment_id: AgentAssignmentId,
) -> Result<Option<HomeOriginAssignmentPins>, AgentAssignmentStoreError> {
    let raw = connection
        .query_row(
            "SELECT assignment_id, origin_kind, home_receipt_id, workspace_id, activity_id,
                    goal_id, goal_created_at_ms, goal_revision, dag_revision,
                    dag_head_revision, node_id, node_revision, coordinator_agent_id,
                    coordinator_session_id, coordinator_principal_kind,
                    coordinator_principal_id, coordinator_revision, target_agent_id,
                    target_session_id, target_principal_kind, target_principal_id,
                    target_agent_revision, created_at_ms, updated_at_ms, revision, state,
                    cancellation_requested, credit_budget
             FROM agent_assignments WHERE assignment_id = ?1",
            params![assignment_id.into_uuid().as_bytes()],
            |row| {
                Ok(RawHomeOriginAssignmentPins {
                    assignment_id: row.get(0)?,
                    origin_kind: row.get(1)?,
                    home_receipt_id: row.get(2)?,
                    workspace_id: row.get(3)?,
                    activity_id: row.get(4)?,
                    goal_id: row.get(5)?,
                    goal_created_at_ms: row.get(6)?,
                    goal_revision: row.get(7)?,
                    dag_revision: row.get(8)?,
                    dag_head_revision: row.get(9)?,
                    node_id: row.get(10)?,
                    node_revision: row.get(11)?,
                    coordinator_agent_id: row.get(12)?,
                    coordinator_session_id: row.get(13)?,
                    coordinator_principal_kind: row.get(14)?,
                    coordinator_principal_id: row.get(15)?,
                    coordinator_revision: row.get(16)?,
                    target_agent_id: row.get(17)?,
                    target_session_id: row.get(18)?,
                    target_principal_kind: row.get(19)?,
                    target_principal_id: row.get(20)?,
                    target_agent_revision: row.get(21)?,
                    created_at_ms: row.get(22)?,
                    updated_at_ms: row.get(23)?,
                    revision: row.get(24)?,
                    state: row.get(25)?,
                    cancellation_requested: row.get(26)?,
                    credit_budget: row.get(27)?,
                })
            },
        )
        .optional()?;
    raw.map(decode).transpose()
}

pub(crate) fn decode_origin(
    connection: &Connection,
    assignment_id: AgentAssignmentId,
    origin_kind: i64,
    home_receipt_id: Option<&[u8]>,
) -> Result<AgentAssignmentOrigin, AgentAssignmentStoreError> {
    match (origin_kind, home_receipt_id) {
        (0, None) => Ok(AgentAssignmentOrigin::CoordinatorOffer),
        (0, Some(_)) | (1, None) => Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment.origin_receipt_pair",
        )),
        (1, Some(receipt_id)) => {
            let receipt_id = decode_uuid("assignment.home_receipt_id", receipt_id)?;
            crate::workspace_home_transfers::handoffs::get_applied_origin_for_assignment(
                connection,
                assignment_id,
                receipt_id,
            )
        }
        _ => Err(AgentAssignmentStoreError::CorruptRecord(
            "assignment.origin_discriminator",
        )),
    }
}

fn decode(
    raw: RawHomeOriginAssignmentPins,
) -> Result<HomeOriginAssignmentPins, AgentAssignmentStoreError> {
    let assignment_id =
        AgentAssignmentId::from_uuid(decode_uuid("assignment.assignment_id", &raw.assignment_id)?);
    let home_receipt_id = raw
        .home_receipt_id
        .as_deref()
        .map(|bytes| decode_uuid("assignment.home_receipt_id", bytes))
        .transpose()?;
    match (raw.origin_kind, home_receipt_id) {
        (0, None) | (1, Some(_)) => {}
        _ => {
            return Err(AgentAssignmentStoreError::CorruptRecord(
                "assignment.origin_receipt_pair",
            ));
        }
    }
    let workspace_id =
        WorkspaceId::from_uuid(decode_uuid("assignment.workspace_id", &raw.workspace_id)?);
    let activity_id =
        ActivityId::from_uuid(decode_uuid("assignment.activity_id", &raw.activity_id)?);
    let coordinator = AgentAssignmentCoordinator::new(
        AgentInstanceId::from_uuid(decode_uuid(
            "assignment.coordinator_agent_id",
            &raw.coordinator_agent_id,
        )?),
        AgentSessionId::from_uuid(decode_uuid(
            "assignment.coordinator_session_id",
            &raw.coordinator_session_id,
        )?),
        decode_principal(
            raw.coordinator_principal_kind,
            raw.coordinator_principal_id.as_deref(),
        )?,
        decode_activity_coordinator_revision(raw.coordinator_revision)?,
    );
    let target = AgentAssignmentTarget::new(
        AgentInstanceId::from_uuid(decode_uuid(
            "assignment.target_agent_id",
            &raw.target_agent_id,
        )?),
        AgentSessionId::from_uuid(decode_uuid(
            "assignment.target_session_id",
            &raw.target_session_id,
        )?),
        decode_principal(
            raw.target_principal_kind,
            raw.target_principal_id.as_deref(),
        )?,
        decode_agent_revision(raw.target_agent_revision)?,
    );
    Ok(HomeOriginAssignmentPins {
        assignment_id,
        origin_kind: raw.origin_kind,
        home_receipt_id,
        workspace_id,
        activity_id,
        goal_id: GoalId::from_uuid(decode_uuid("assignment.goal_id", &raw.goal_id)?),
        goal_created_at: decode_timestamp("assignment.goal_created_at_ms", raw.goal_created_at_ms)?,
        goal_revision: decode_goal_revision(raw.goal_revision)?,
        dag_revision: decode_dag_revision(raw.dag_revision)?,
        dag_head_revision: decode_dag_head_revision(raw.dag_head_revision)?,
        node_id: DagNodeId::from_uuid(decode_uuid("assignment.node_id", &raw.node_id)?),
        node_revision: decode_dag_node_revision(raw.node_revision)?,
        coordinator,
        target,
        credit_budget: decode_credit_budget(raw.credit_budget)?,
        created_at: decode_timestamp("assignment.created_at_ms", raw.created_at_ms)?,
        updated_at: decode_timestamp("assignment.updated_at_ms", raw.updated_at_ms)?,
        revision: decode_assignment_revision(raw.revision)?,
        state: decode_state(raw.state)?,
        cancellation_requested: decode_bool(
            "assignment.cancellation_requested",
            raw.cancellation_requested,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_and_home_receipt_discriminators_must_pair_exactly()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        let assignment_id = AgentAssignmentId::from_uuid(Uuid::from_u128(1));
        let receipt_id = Uuid::from_u128(2).into_bytes();

        assert!(matches!(
            decode_origin(&connection, assignment_id, 0, Some(receipt_id.as_slice())),
            Err(AgentAssignmentStoreError::CorruptRecord(
                "assignment.origin_receipt_pair"
            ))
        ));
        assert!(matches!(
            decode_origin(&connection, assignment_id, 1, None),
            Err(AgentAssignmentStoreError::CorruptRecord(
                "assignment.origin_receipt_pair"
            ))
        ));
        assert!(matches!(
            decode_origin(&connection, assignment_id, 2, None),
            Err(AgentAssignmentStoreError::CorruptRecord(
                "assignment.origin_discriminator"
            ))
        ));
        Ok(())
    }
}
