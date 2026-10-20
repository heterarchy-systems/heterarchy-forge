//! Positive provenance for a normally bootstrapped, planning-only Activity.
//!
//! Normal bootstrap has no immutable receipt table.  Its authority is the
//! checked canonical Activity, Workspace, Coordinator, Agent, and delegation
//! projections, together with the planning and census validators owned by the
//! parent continuation module.  This module only proves the origin-specific
//! shape and contributes a domain-separated digest to the continuation plan
//! fence.

use forge_domain::{
    ActivityId, ActivityRevision, ActivityState, AgentSessionId, AuthenticatedPrincipal,
    ExpectedActivityCoordinator, ExpiredActivityRecoveryDelegationFence,
    ExpiredActivityRecoveryProbeScope, RegisteredActivity, WorkspaceId,
};
use rusqlite::{Connection, params, types::ValueRef};
use sha2::{Digest, Sha256};

use super::UnstartedActivityContinuationStoreError;

const DOMAIN: &[u8] =
    b"heterarchy.forge.unstarted-activity-continuation.normal-bootstrap-provenance.v1";
const MAX_ROWS: u64 = 1;

#[allow(
    clippy::too_many_arguments,
    reason = "Origin validation keeps each trusted Workspace, Activity, Session, and delegation fence explicit."
)]
pub(super) fn validate_and_digest_normal_bootstrap_provenance(
    connection: &Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    scope: &ExpiredActivityRecoveryProbeScope,
    expected_activity: &RegisteredActivity,
    initiating_session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    expected_coordinator: ExpectedActivityCoordinator,
    expected_delegation: ExpiredActivityRecoveryDelegationFence,
    expected_delegation_digest: [u8; 32],
) -> Result<[u8; 32], UnstartedActivityContinuationStoreError> {
    if super::provenance::p28_lineage_present(connection, activity_id)? {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "normal bootstrap has P28 lineage",
        ));
    }

    let workspace_raw = super::super::query_workspace_row(connection)?.ok_or(
        UnstartedActivityContinuationStoreError::Corrupt("normal bootstrap Workspace missing"),
    )?;
    let workspace = super::super::decode_workspace(workspace_raw)?;
    if workspace.id() != workspace_id
        || workspace.id() != scope.workspace_id()
        || workspace.revision() != scope.workspace_revision()
        || workspace.location_id() != scope.location_id()
        || workspace.root_fingerprint() != scope.root_fingerprint()
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "normal bootstrap Workspace scope",
        ));
    }

    let raw = super::super::query_activity_row(connection, activity_id)?.ok_or(
        UnstartedActivityContinuationStoreError::Corrupt("normal bootstrap Activity missing"),
    )?;
    let activity = super::super::decode_activity(&raw)?;
    if activity != *expected_activity
        || activity.workspace_id() != workspace_id
        || activity.state() != ActivityState::Open
        || activity.revision() != ActivityRevision::INITIAL
        || activity.created_at() != activity.updated_at()
        || activity.lease_owner_id().is_none()
        || activity
            .lease_until()
            .is_none_or(|lease_until| lease_until <= activity.updated_at())
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "normal bootstrap Activity origin",
        ));
    }

    let (delegation, delegation_digest) =
        super::super::expired_activity_recovery::load_delegation_fence(connection, workspace_id)?;
    if delegation != expected_delegation || delegation_digest != expected_delegation_digest {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "normal bootstrap delegation",
        ));
    }

    let coordinator = crate::workspace_coordinators::get_in_transaction(connection, activity_id)?
        .ok_or(UnstartedActivityContinuationStoreError::Conflict(
        "normal bootstrap Coordinator missing",
    ))?;
    if coordinator.workspace_id() != workspace_id
        || coordinator.agent_id() != expected_coordinator.agent_id()
        || coordinator.revision().get() != expected_coordinator.revision()
        || coordinator.updated_at() != expected_coordinator.updated_at()
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "normal bootstrap Coordinator binding",
        ));
    }
    let member = crate::workspace_agents::get_in_transaction(connection, coordinator.agent_id())?
        .ok_or(UnstartedActivityContinuationStoreError::Conflict(
        "normal bootstrap Coordinator member missing",
    ))?;
    if member.workspace_id() != workspace_id
        || member.activity_id() != activity_id
        || member.session_id() != Some(initiating_session_id)
        || member.principal() != principal
    {
        return Err(UnstartedActivityContinuationStoreError::Conflict(
            "normal bootstrap Coordinator Session binding",
        ));
    }

    let workspace = workspace_id.into_uuid().into_bytes();
    let activity = activity_id.into_uuid().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hash_scope(&mut hasher, scope);
    hash_activity(&mut hasher, expected_activity);
    hash_coordinator(&mut hasher, expected_coordinator);
    hasher.update(initiating_session_id.into_uuid().as_bytes());
    hash_principal(&mut hasher, principal);
    hash_delegation(&mut hasher, expected_delegation);
    hasher.update(expected_delegation_digest);
    for query in DIGEST_QUERIES {
        hash_rows(
            &mut hasher,
            connection,
            query,
            workspace.as_slice(),
            activity.as_slice(),
        )?;
    }
    Ok(hasher.finalize().into())
}

struct DigestQuery {
    table: &'static str,
    sql: &'static str,
    minimum_rows: u64,
}

const DIGEST_QUERIES: &[DigestQuery] = &[
    DigestQuery {
        table: "workspace",
        sql: "SELECT * FROM workspace WHERE workspace_id=?1 ORDER BY singleton",
        minimum_rows: 1,
    },
    DigestQuery {
        table: "activities",
        sql: "SELECT * FROM activities WHERE workspace_id=?1 AND activity_id=?2 ORDER BY activity_id",
        minimum_rows: 1,
    },
    DigestQuery {
        table: "activity_coordinators",
        sql: "SELECT * FROM activity_coordinators WHERE workspace_id=?1 AND activity_id=?2 ORDER BY activity_id",
        minimum_rows: 1,
    },
    DigestQuery {
        table: "agent_operations_delegations",
        sql: "SELECT * FROM agent_operations_delegations WHERE workspace_id=?1 ORDER BY migration_id",
        minimum_rows: 1,
    },
];

fn hash_rows(
    hasher: &mut Sha256,
    connection: &Connection,
    query: &DigestQuery,
    workspace_id: &[u8],
    activity_id: &[u8],
) -> Result<(), UnstartedActivityContinuationStoreError> {
    hash_bytes(hasher, query.table.as_bytes());
    hash_u64(hasher, query.minimum_rows);
    hash_u64(hasher, MAX_ROWS);
    let mut statement = connection.prepare(query.sql)?;
    let columns = statement
        .column_names()
        .iter()
        .map(|column| (*column).to_owned())
        .collect::<Vec<_>>();
    hash_u64(hasher, u64::try_from(columns.len()).unwrap_or(u64::MAX));
    for column in &columns {
        hash_bytes(hasher, column.as_bytes());
    }
    let mut rows = match statement.parameter_count() {
        1 => statement.query(params![workspace_id])?,
        2 => statement.query(params![workspace_id, activity_id])?,
        _ => {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "normal bootstrap provenance query parameter count",
            ));
        }
    };
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .ok_or(UnstartedActivityContinuationStoreError::Corrupt(
                "normal bootstrap provenance row count overflow",
            ))?;
        if count > MAX_ROWS {
            return Err(UnstartedActivityContinuationStoreError::Corrupt(
                "normal bootstrap provenance row bound",
            ));
        }
        hasher.update([0xFD]);
        for index in 0..columns.len() {
            match row.get_ref(index)? {
                ValueRef::Null => {
                    hasher.update([0]);
                    hash_u64(hasher, 0);
                }
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hash_u64(hasher, 8);
                    hasher.update(value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update([2]);
                    hash_u64(hasher, 8);
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
    if count < query.minimum_rows {
        return Err(UnstartedActivityContinuationStoreError::Corrupt(
            "normal bootstrap provenance row missing",
        ));
    }
    hash_u64(hasher, count);
    hasher.update([0xFF]);
    Ok(())
}

fn hash_scope(hasher: &mut Sha256, scope: &ExpiredActivityRecoveryProbeScope) {
    hasher.update(scope.workspace_id().into_uuid().as_bytes());
    hasher.update(scope.workspace_revision().get().to_le_bytes());
    hasher.update(scope.location_id().into_uuid().as_bytes());
    hasher.update(scope.location_revision().get().to_le_bytes());
    hash_bytes(hasher, scope.locator());
    hasher.update(scope.root_fingerprint().as_bytes());
    hasher.update(scope.binding_digest());
}

fn hash_activity(hasher: &mut Sha256, activity: &RegisteredActivity) {
    hasher.update(activity.id().into_uuid().as_bytes());
    hasher.update(activity.workspace_id().into_uuid().as_bytes());
    hasher.update([match activity.state() {
        ActivityState::Open => 1,
        ActivityState::Closed => 0,
        ActivityState::Interrupted => 2,
    }]);
    hasher.update(activity.created_at().get().to_le_bytes());
    hasher.update(activity.updated_at().get().to_le_bytes());
    hasher.update(activity.revision().get().to_le_bytes());
    hash_optional_uuid(
        hasher,
        activity
            .lease_owner_id()
            .map(forge_domain::RuntimeInstanceId::into_uuid),
    );
    hash_optional_i64(
        hasher,
        activity
            .lease_until()
            .map(forge_domain::TimestampMillis::get),
    );
    hasher.update(activity.lease_revision().get().to_le_bytes());
}

fn hash_coordinator(hasher: &mut Sha256, coordinator: ExpectedActivityCoordinator) {
    hasher.update(coordinator.agent_id().into_uuid().as_bytes());
    hasher.update(coordinator.revision().to_le_bytes());
    hasher.update(coordinator.updated_at().get().to_le_bytes());
}

fn hash_delegation(hasher: &mut Sha256, delegation: ExpiredActivityRecoveryDelegationFence) {
    hasher.update(delegation.migration_id().as_bytes());
    hasher.update(delegation.workspace_id().into_uuid().as_bytes());
    hasher.update(delegation.destination_id().as_bytes());
    hasher.update(delegation.revision().to_le_bytes());
    hasher.update(delegation.created_at().get().to_le_bytes());
    hasher.update(delegation.updated_at().get().to_le_bytes());
    hasher.update(delegation.manifest_digest());
    hasher.update(delegation.delegated_at().get().to_le_bytes());
}

fn hash_principal(hasher: &mut Sha256, principal: AuthenticatedPrincipal) {
    match principal {
        AuthenticatedPrincipal::TrustedStdio => hasher.update([0]),
        AuthenticatedPrincipal::DirectToken(id) => {
            hasher.update([1]);
            hasher.update(id.into_uuid().as_bytes());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            hasher.update([2]);
            hasher.update(id.into_uuid().as_bytes());
        }
    }
}

fn hash_optional_uuid(hasher: &mut Sha256, value: Option<uuid::Uuid>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_optional_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hash_u64(hasher, u64::try_from(value.len()).unwrap_or(u64::MAX));
    hasher.update(value);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
