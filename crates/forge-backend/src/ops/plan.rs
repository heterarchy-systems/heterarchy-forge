//! Full bounded plan projections from Forge's durable typed records.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use forge_domain::{DagNodeLifecycle, DagNodeStatus, GoalStatus, GoalVerificationRequirement};
use forge_persistence::StoredDagRevision;
use serde_json::{Value, json};

use crate::error::ForgeError;

pub(super) fn goal_json(value: &forge_domain::RegisteredGoal) -> Value {
    let contract = value.contract();
    let (status_kind, status_reason) = goal_status_json(value.status());
    let verification_requirements = contract
        .verification_requirements()
        .iter()
        .map(goal_verification_json)
        .collect::<Vec<_>>();

    json!({
        "found": true,
        "goal_id": value.id().to_string(),
        "workspace_id": value.workspace_id().to_string(),
        "activity_id": value.activity_id().to_string(),
        "revision": value.revision().get(),
        "status": {
            "kind": status_kind,
            "reason": status_reason,
            "blocker_kind": goal_blocker_kind_json(value.status()),
        },
        "objective": contract.objective().as_str(),
        "success_criteria": contract
            .success_criteria()
            .iter()
            .map(forge_domain::GoalStatement::as_str)
            .collect::<Vec<_>>(),
        "constraints": contract
            .constraints()
            .iter()
            .map(forge_domain::GoalStatement::as_str)
            .collect::<Vec<_>>(),
        "out_of_scope": contract
            .out_of_scope()
            .iter()
            .map(forge_domain::GoalStatement::as_str)
            .collect::<Vec<_>>(),
        "verification_requirements": verification_requirements,
        "stop_conditions": contract
            .stop_conditions()
            .iter()
            .map(forge_domain::GoalStatement::as_str)
            .collect::<Vec<_>>(),
        "created_at_ms": value.timestamps().created_at().get(),
        "updated_at_ms": value.timestamps().updated_at().get(),
    })
}

pub(super) fn dag_json(value: &StoredDagRevision) -> Result<Value, ForgeError> {
    let projections = value
        .revision()
        .project(value.nodes())
        .map_err(|_| ForgeError::internal())?;
    let projections_by_id = projections
        .iter()
        .map(|projection| (projection.node().id(), projection))
        .collect::<HashMap<_, _>>();
    let evidence_by_id = value
        .evidence()
        .iter()
        .map(|summary| (summary.node_id(), summary.count()))
        .collect::<HashMap<_, _>>();

    let nodes = value
        .nodes()
        .iter()
        .map(|node| {
            let projection = projections_by_id
                .get(&node.id())
                .ok_or_else(ForgeError::internal)?;
            Ok(json!({
                "node_id": node.id().to_string(),
                "ordinal": node.definition().ordinal().get(),
                "title": node.definition().title().as_str(),
                "objective": node.definition().objective().as_str(),
                "acceptance": node
                    .definition()
                    .acceptance()
                    .iter()
                    .map(forge_domain::DagAcceptanceCriterion::as_str)
                    .collect::<Vec<_>>(),
                "lifecycle": dag_lifecycle_json(node.lifecycle()),
                "lifecycle_reason": match node.lifecycle() {
                    DagNodeLifecycle::Blocked(reason) | DagNodeLifecycle::Failed(reason) | DagNodeLifecycle::Skipped(reason) => Some(reason.as_str()),
                    DagNodeLifecycle::Pending | DagNodeLifecycle::Active | DagNodeLifecycle::Completed | DagNodeLifecycle::Cancelled => None,
                },
                "status": dag_status_json(projection.status()),
                "waiting_on": projection
                    .waiting_on()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "revision": node.revision().get(),
                "evidence_count": evidence_by_id.get(&node.id()).copied().unwrap_or(0),
                "created_at_ms": node.created_at().get(),
                "updated_at_ms": node.updated_at().get(),
            }))
        })
        .collect::<Result<Vec<_>, ForgeError>>()?;
    let edges = value
        .revision()
        .edges()
        .iter()
        .map(|edge| {
            json!({
                "upstream": edge.upstream().to_string(),
                "downstream": edge.downstream().to_string(),
            })
        })
        .collect::<Vec<_>>();
    let lineage = value
        .lineage()
        .iter()
        .map(|item| {
            json!({
                "prior_node_id": item.prior_node_id().to_string(),
                "successor_node_id": item.successor_node_id().to_string(),
                "kind": dag_lineage_json(item.kind()),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "found": true,
        "goal_id": value.revision().goal_id().to_string(),
        "revision_id": value.revision().id().to_string(),
        "base_goal_revision": value.revision().base_goal_revision().get(),
        "dag_revision": value.revision().number().get(),
        "parent_revision": value.revision().parent().map(forge_domain::DagRevisionNumber::get),
        "created_at_ms": value.revision().created_at().get(),
        "head_revision": value.head().revision().get(),
        "head_updated_at_ms": value.head().updated_at().get(),
        "node_count": value.nodes().len(),
        "nodes": nodes,
        "edges": edges,
        "lineage": lineage,
    }))
}

fn goal_status_json(value: &GoalStatus) -> (&'static str, Option<&str>) {
    match value {
        GoalStatus::Active => ("active", None),
        GoalStatus::Paused => ("paused", None),
        GoalStatus::Blocked(blocker) => ("blocked", Some(blocker.reason().as_str())),
        GoalStatus::Completed => ("completed", None),
        GoalStatus::Failed(failure) => ("failed", Some(failure.reason().as_str())),
        GoalStatus::Cancelled => ("cancelled", None),
    }
}

fn goal_blocker_kind_json(value: &GoalStatus) -> Option<&'static str> {
    use forge_domain::GoalBlockerKind;
    match value {
        GoalStatus::Blocked(blocker) => Some(match blocker.kind() {
            GoalBlockerKind::ApprovalWait => "approval_wait",
            GoalBlockerKind::ExternalDependency => "external_dependency",
            GoalBlockerKind::VerificationFailure => "verification_failure",
            GoalBlockerKind::ResourceLimit => "resource_limit",
            GoalBlockerKind::UserDecision => "user_decision",
            GoalBlockerKind::Other => "other",
        }),
        GoalStatus::Active
        | GoalStatus::Paused
        | GoalStatus::Completed
        | GoalStatus::Failed(_)
        | GoalStatus::Cancelled => None,
    }
}

fn goal_verification_json(value: &GoalVerificationRequirement) -> Value {
    match value {
        GoalVerificationRequirement::ExecutionSucceeded {
            request_digest,
            description,
        } => json!({
            "kind": "execution_succeeded",
            "request_digest": super::encode_hex(request_digest.as_bytes()),
            "description": description.as_str(),
        }),
        GoalVerificationRequirement::FilePresent {
            path,
            expected_hash,
            description,
        } => json!({
            "kind": "file_present",
            "path_base64": URL_SAFE_NO_PAD.encode(path.as_path().as_os_str().as_encoded_bytes()),
            "expected_hash": expected_hash.as_ref().map(ToString::to_string),
            "description": description.as_str(),
        }),
        GoalVerificationRequirement::ChangeSetSealed {
            change_set_id,
            description,
        } => json!({
            "kind": "change_set_sealed",
            "change_set_id": change_set_id.to_string(),
            "description": description.as_str(),
        }),
        GoalVerificationRequirement::CheckpointReady {
            checkpoint_id,
            description,
        } => json!({
            "kind": "checkpoint_ready",
            "checkpoint_id": checkpoint_id.to_string(),
            "description": description.as_str(),
        }),
    }
}

pub(super) fn dag_lifecycle_json(value: &DagNodeLifecycle) -> &'static str {
    match value {
        DagNodeLifecycle::Pending => "pending",
        DagNodeLifecycle::Active => "active",
        DagNodeLifecycle::Blocked(_) => "blocked",
        DagNodeLifecycle::Completed => "completed",
        DagNodeLifecycle::Failed(_) => "failed",
        DagNodeLifecycle::Skipped(_) => "skipped",
        DagNodeLifecycle::Cancelled => "cancelled",
    }
}

/// Reason payload of a blocked/failed/skipped lifecycle, if the variant
/// carries one. Shared with the node lifecycle readback so the HTTP data
/// keeps the same durable reason the native path reads in-transaction.
pub(super) fn dag_lifecycle_reason_json(value: &DagNodeLifecycle) -> Option<&str> {
    match value {
        DagNodeLifecycle::Blocked(reason)
        | DagNodeLifecycle::Failed(reason)
        | DagNodeLifecycle::Skipped(reason) => Some(reason.as_str()),
        DagNodeLifecycle::Pending
        | DagNodeLifecycle::Active
        | DagNodeLifecycle::Completed
        | DagNodeLifecycle::Cancelled => None,
    }
}

fn dag_status_json(value: DagNodeStatus) -> &'static str {
    match value {
        DagNodeStatus::Pending => "pending",
        DagNodeStatus::Ready => "ready",
        DagNodeStatus::Active => "active",
        DagNodeStatus::Blocked => "blocked",
        DagNodeStatus::Completed => "completed",
        DagNodeStatus::Failed => "failed",
        DagNodeStatus::Skipped => "skipped",
        DagNodeStatus::Cancelled => "cancelled",
    }
}

fn dag_lineage_json(value: forge_domain::DagLineageKind) -> &'static str {
    match value {
        forge_domain::DagLineageKind::Split => "split",
        forge_domain::DagLineageKind::Replace => "replace",
        forge_domain::DagLineageKind::Merge => "merge",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn goal_projection_preserves_the_durable_blocker_kind() -> Result<(), Box<dyn std::error::Error>>
    {
        use forge_domain::{
            ActivityId, GoalBlocker, GoalBlockerKind, GoalContract, GoalId, GoalObjective,
            GoalPublicReason, GoalRevision, GoalStatement, GoalStatus, GoalTimestamps,
            RegisteredGoal, TimestampMillis, WorkspaceId,
        };
        let goal = RegisteredGoal::from_parts(
            GoalId::from_uuid(uuid::Uuid::from_u128(1)),
            WorkspaceId::from_uuid(uuid::Uuid::from_u128(2)),
            ActivityId::from_uuid(uuid::Uuid::from_u128(3)),
            GoalContract::new(
                GoalObjective::new("Preserve the reason".to_owned())?,
                vec![GoalStatement::new(
                    "Consumer sees its actual category".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            GoalStatus::Blocked(GoalBlocker::new(
                GoalBlockerKind::ResourceLimit,
                GoalPublicReason::new("Capacity exhausted".to_owned())?,
            )),
            GoalTimestamps::new(TimestampMillis::new(1)?, TimestampMillis::new(2)?)?,
            GoalRevision::new(2)?,
        )?;
        assert_eq!(
            super::goal_json(&goal)["status"]["blocker_kind"],
            "resource_limit"
        );
        Ok(())
    }
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use forge_domain::{
        ExecutionRequestDigest, GoalStatement, GoalVerificationRequirement, WorkspaceRelativePath,
    };

    #[test]
    fn verification_projection_preserves_digest_encoding_and_native_path_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution = GoalVerificationRequirement::ExecutionSucceeded {
            request_digest: ExecutionRequestDigest::from_bytes([0xab; 32]),
            description: GoalStatement::new("approved execution succeeds".to_owned())?,
        };
        let wire = super::goal_verification_json(&execution);
        assert_eq!(wire["request_digest"], "ab".repeat(32));

        let path = WorkspaceRelativePath::new(
            OsString::from_vec(vec![b'a', 0xff, b'.', b'r', b's']).into(),
        )?;
        let file = GoalVerificationRequirement::FilePresent {
            path,
            expected_hash: None,
            description: GoalStatement::new("native path exists".to_owned())?,
        };
        let wire = super::goal_verification_json(&file);
        assert_eq!(wire["path_base64"], "Yf8ucnM");
        assert_eq!(wire["kind"], "file_present");
        Ok(())
    }
}
