//! Typed HTTP adapter for caller-owned Activity lease renewal and release.
//!
//! The dedicated `ActivityLeaseClient` owns the narrow native worker lane and
//! the existing Forge control service owns scope, owner, expiry, uniqueness,
//! and transaction semantics. This module only decodes bounded wire values,
//! submits a single command through the native batch-of-one path, and proves
//! the returned rows before projecting a confirmed result.

use forge_control::{
    ActivityLeaseClient, ActivityLeaseOperation, ActivityOperationStatus, ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityId, ActivityLeaseRevision, ActivityState, RegisteredActivity, ReleaseActivityLease,
    RenewActivityLease, RuntimeInstanceId, TimestampMillis,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{CommandOp, ScopeDto, decode_scope};
use crate::error::{ActivityLeaseReadbackKey, ActivityLeaseReadbackOperation, ForgeError};

const MAX_DURATION_MS: i64 = i64::MAX;

/// One validated Activity lease mutation. Single operations are represented by
/// a native batch containing one command so all transport shapes share the
/// same atomic owner and post-commit proof.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityLeaseCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    request: ActivityLeaseRequest,
}

impl ActivityLeaseCommand {
    /// Return the exact transport operation represented by this command.
    pub const fn op(&self) -> CommandOp {
        self.request.op()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActivityLeaseRequest {
    Renew {
        commands: Vec<RenewActivityLease>,
        batch: bool,
    },
    Release {
        commands: Vec<ReleaseActivityLease>,
        batch: bool,
    },
}

impl ActivityLeaseRequest {
    const fn op(&self) -> CommandOp {
        match self {
            Self::Renew { batch: false, .. } => CommandOp::ActivityLeaseRenew,
            Self::Renew { batch: true, .. } => CommandOp::ActivityLeaseRenewBatch,
            Self::Release { batch: false, .. } => CommandOp::ActivityLeaseRelease,
            Self::Release { batch: true, .. } => CommandOp::ActivityLeaseReleaseBatch,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewBody {
    scope: ScopeDto,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
    duration_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBody {
    scope: ScopeDto,
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewBatchBody {
    scope: ScopeDto,
    commands: Vec<RenewEntryDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBatchBody {
    scope: ScopeDto,
    commands: Vec<ReleaseEntryDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewEntryDto {
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
    duration_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEntryDto {
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
}

/// Parse one of the four frozen Activity lease operation payloads.
pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<ActivityLeaseCommand, ForgeError> {
    match operation {
        CommandOp::ActivityLeaseRenew => parse_renew(payload),
        CommandOp::ActivityLeaseRelease => parse_release(payload),
        CommandOp::ActivityLeaseRenewBatch => parse_renew_batch(payload),
        CommandOp::ActivityLeaseReleaseBatch => parse_release_batch(payload),
        _ => Err(ForgeError::invalid_input(
            "operation is not an Activity lease operation",
        )),
    }
}

fn parse_renew(payload: &Value) -> Result<ActivityLeaseCommand, ForgeError> {
    let body: RenewBody = super::parse_body(payload, "activity.lease.renew payload is invalid")?;
    let scope = decode_scope_checked(&body.scope, "activity.lease.renew")?;
    let command = decode_renew(
        body.activity_id,
        body.runtime_instance_id,
        body.expected_lease_revision,
        body.duration_ms,
    )?;
    Ok(ActivityLeaseCommand {
        scope,
        request: ActivityLeaseRequest::Renew {
            commands: vec![command],
            batch: false,
        },
    })
}

fn parse_release(payload: &Value) -> Result<ActivityLeaseCommand, ForgeError> {
    let body: ReleaseBody =
        super::parse_body(payload, "activity.lease.release payload is invalid")?;
    let scope = decode_scope_checked(&body.scope, "activity.lease.release")?;
    let command = decode_release(
        body.activity_id,
        body.runtime_instance_id,
        body.expected_lease_revision,
    )?;
    Ok(ActivityLeaseCommand {
        scope,
        request: ActivityLeaseRequest::Release {
            commands: vec![command],
            batch: false,
        },
    })
}

fn parse_renew_batch(payload: &Value) -> Result<ActivityLeaseCommand, ForgeError> {
    let body: RenewBatchBody =
        super::parse_body(payload, "activity.lease.renew_batch payload is invalid")?;
    let scope = decode_scope_checked(&body.scope, "activity.lease.renew_batch")?;
    let commands = decode_batch(
        body.commands,
        |entry| {
            decode_renew(
                entry.activity_id,
                entry.runtime_instance_id,
                entry.expected_lease_revision,
                entry.duration_ms,
            )
        },
        "activity.lease.renew_batch",
    )?;
    Ok(ActivityLeaseCommand {
        scope,
        request: ActivityLeaseRequest::Renew {
            commands,
            batch: true,
        },
    })
}

fn parse_release_batch(payload: &Value) -> Result<ActivityLeaseCommand, ForgeError> {
    let body: ReleaseBatchBody =
        super::parse_body(payload, "activity.lease.release_batch payload is invalid")?;
    let scope = decode_scope_checked(&body.scope, "activity.lease.release_batch")?;
    let commands = decode_batch(
        body.commands,
        |entry| {
            decode_release(
                entry.activity_id,
                entry.runtime_instance_id,
                entry.expected_lease_revision,
            )
        },
        "activity.lease.release_batch",
    )?;
    Ok(ActivityLeaseCommand {
        scope,
        request: ActivityLeaseRequest::Release {
            commands,
            batch: true,
        },
    })
}

fn decode_batch<T, U, F>(
    entries: Vec<T>,
    mut decode: F,
    operation: &'static str,
) -> Result<Vec<U>, ForgeError>
where
    F: FnMut(T) -> Result<U, ForgeError>,
{
    if entries.is_empty() || entries.len() > forge_control::MAX_ACTIVITY_LEASE_BATCH {
        return Err(ForgeError::invalid_input(format!(
            "{operation} command count must be between 1 and {}",
            forge_control::MAX_ACTIVITY_LEASE_BATCH
        )));
    }
    entries.into_iter().map(&mut decode).collect()
}

fn decode_renew(
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
    duration_ms: i64,
) -> Result<RenewActivityLease, ForgeError> {
    let activity_id = decode_activity_id(activity_id, "activity lease activity id")?;
    let runtime_instance_id = decode_runtime_instance_id(runtime_instance_id)?;
    let expected_lease_revision = decode_lease_revision(expected_lease_revision)?;
    if !(1..=MAX_DURATION_MS).contains(&duration_ms) {
        return Err(ForgeError::invalid_input(
            "activity lease duration must be positive",
        ));
    }
    let observed_at = TimestampMillis::new(0)
        .map_err(|_| ForgeError::invalid_input("activity lease clock is invalid"))?;
    let lease_until = TimestampMillis::new(duration_ms)
        .map_err(|_| ForgeError::invalid_input("activity lease duration is invalid"))?;
    Ok(RenewActivityLease::new(
        activity_id,
        runtime_instance_id,
        expected_lease_revision,
        lease_until,
        observed_at,
    ))
}

fn decode_release(
    activity_id: Uuid,
    runtime_instance_id: Uuid,
    expected_lease_revision: i64,
) -> Result<ReleaseActivityLease, ForgeError> {
    let observed_at = TimestampMillis::new(0)
        .map_err(|_| ForgeError::invalid_input("activity lease clock is invalid"))?;
    Ok(ReleaseActivityLease::new(
        decode_activity_id(activity_id, "activity lease activity id")?,
        decode_runtime_instance_id(runtime_instance_id)?,
        decode_lease_revision(expected_lease_revision)?,
        observed_at,
    ))
}

/// Execute through the dedicated narrow lease client. A single command is
/// intentionally sent as a one-element native batch.
pub(super) fn execute(
    client: &ActivityLeaseClient,
    command: &ActivityLeaseCommand,
) -> Result<Value, ForgeError> {
    let operation = match &command.request {
        ActivityLeaseRequest::Renew { commands, .. } => client
            .renew_activity_lease_batch(command.scope.clone(), commands.clone())
            .map_err(|error| super::forge_error_of_client(&error))?,
        ActivityLeaseRequest::Release { commands, .. } => client
            .release_activity_lease_batch(command.scope.clone(), commands.clone())
            .map_err(|error| super::forge_error_of_client(&error))?,
    };
    project_confirmed(command, &operation)
}

/// Return the exact durable lease keys retained by the HTTP layer for an
/// admitted unknown outcome. Single operations keep the existing lifecycle
/// hint shape; only true batches use the new ordered key list.
pub(super) fn readback_hint(command: &ActivityLeaseCommand) -> crate::error::ReadbackHint {
    let workspace_id = command.scope.workspace_id().into_uuid();
    match &command.request {
        ActivityLeaseRequest::Renew { commands, batch } => {
            if !batch && let Some(command) = commands.first() {
                return crate::error::ReadbackHint::ActivityLifecycle {
                    workspace_id,
                    activity_id: command.id().into_uuid(),
                    runtime_instance_id: command.runtime_instance_id().into_uuid(),
                    expected_lease_revision: command.expected_lease_revision().get(),
                };
            }
            crate::error::ReadbackHint::ActivityLeaseBatch {
                workspace_id,
                operation: ActivityLeaseReadbackOperation::Renew,
                leases: commands.iter().map(readback_renew_key).collect(),
            }
        }
        ActivityLeaseRequest::Release { commands, batch } => {
            if !batch && let Some(command) = commands.first() {
                return crate::error::ReadbackHint::ActivityLifecycle {
                    workspace_id,
                    activity_id: command.id().into_uuid(),
                    runtime_instance_id: command.runtime_instance_id().into_uuid(),
                    expected_lease_revision: command.expected_lease_revision().get(),
                };
            }
            crate::error::ReadbackHint::ActivityLeaseBatch {
                workspace_id,
                operation: ActivityLeaseReadbackOperation::Release,
                leases: commands.iter().map(readback_release_key).collect(),
            }
        }
    }
}

fn readback_renew_key(command: &RenewActivityLease) -> ActivityLeaseReadbackKey {
    ActivityLeaseReadbackKey {
        activity_id: command.id().into_uuid(),
        runtime_instance_id: command.runtime_instance_id().into_uuid(),
        expected_lease_revision: command.expected_lease_revision().get(),
    }
}

fn readback_release_key(command: &ReleaseActivityLease) -> ActivityLeaseReadbackKey {
    ActivityLeaseReadbackKey {
        activity_id: command.id().into_uuid(),
        runtime_instance_id: command.runtime_instance_id().into_uuid(),
        expected_lease_revision: command.expected_lease_revision().get(),
    }
}

fn project_confirmed(
    command: &ActivityLeaseCommand,
    operation: &ActivityLeaseOperation,
) -> Result<Value, ForgeError> {
    let expected_status = match &command.request {
        ActivityLeaseRequest::Renew { .. } => ActivityOperationStatus::Renewed,
        ActivityLeaseRequest::Release { .. } => ActivityOperationStatus::Released,
    };
    if operation.is_committed_but_unconfirmed()
        || operation.scope() != &command.scope
        || operation.status() != expected_status
        || !rows_match(command, operation.activities())
    {
        return Err(ForgeError::unknown_outcome(Some(readback_hint(command))));
    }
    let mut response = Map::new();
    response.insert("scope".to_owned(), super::scope_json(&command.scope)?);
    response.insert(
        "status".to_owned(),
        json!(super::activity_lifecycle::activity_operation_status_name(
            operation.status()
        )),
    );
    response.insert("committed".to_owned(), json!(operation.is_committed()));
    response.insert("unconfirmed".to_owned(), json!(false));
    let activities = operation
        .activities()
        .iter()
        .map(super::activity_lifecycle::registered_activity_json)
        .collect::<Vec<_>>();
    let batch = match &command.request {
        ActivityLeaseRequest::Renew { batch, .. } | ActivityLeaseRequest::Release { batch, .. } => {
            *batch
        }
    };
    if batch {
        response.insert("activities".to_owned(), Value::Array(activities));
    } else {
        let Some(activity) = activities.into_iter().next() else {
            return Err(ForgeError::unknown_outcome(Some(readback_hint(command))));
        };
        response.insert("activity_id".to_owned(), activity["activity_id"].clone());
        response.insert("activity".to_owned(), activity);
    }
    Ok(Value::Object(response))
}

fn rows_match(command: &ActivityLeaseCommand, rows: &[RegisteredActivity]) -> bool {
    match &command.request {
        ActivityLeaseRequest::Renew { commands, .. } => {
            rows.len() == commands.len()
                && commands
                    .iter()
                    .zip(rows)
                    .all(|(request, row)| renew_row_matches(&command.scope, request, row))
        }
        ActivityLeaseRequest::Release { commands, .. } => {
            rows.len() == commands.len()
                && commands
                    .iter()
                    .zip(rows)
                    .all(|(request, row)| release_row_matches(&command.scope, request, row))
        }
    }
}

fn renew_row_matches(
    scope: &ResolvedWorkspaceScope,
    request: &RenewActivityLease,
    row: &RegisteredActivity,
) -> bool {
    let Some(expected_revision) = request.expected_lease_revision().checked_next().ok() else {
        return false;
    };
    row.workspace_id() == scope.workspace_id()
        && row.id() == request.id()
        && row.state() == ActivityState::Open
        && row.lease_owner_id() == Some(request.runtime_instance_id())
        && row.lease_until().is_some()
        && row.lease_revision() == expected_revision
}

fn release_row_matches(
    scope: &ResolvedWorkspaceScope,
    request: &ReleaseActivityLease,
    row: &RegisteredActivity,
) -> bool {
    let Some(expected_revision) = request.expected_lease_revision().checked_next().ok() else {
        return false;
    };
    row.workspace_id() == scope.workspace_id()
        && row.id() == request.id()
        && row.state() == ActivityState::Open
        && row.lease().is_unleased()
        && row.lease_revision() == expected_revision
}

fn decode_scope_checked(
    scope: &ScopeDto,
    operation: &'static str,
) -> Result<ResolvedWorkspaceScope, ForgeError> {
    if scope.workspace_id.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{operation} Workspace id must not be nil"
        )));
    }
    if scope.locator.location_id.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{operation} Location id must not be nil"
        )));
    }
    decode_scope(scope)
}

fn decode_activity_id(value: Uuid, label: &'static str) -> Result<ActivityId, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(ActivityId::from_uuid(value))
}

fn decode_runtime_instance_id(value: Uuid) -> Result<RuntimeInstanceId, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(
            "activity lease runtime instance id must not be nil",
        ));
    }
    Ok(RuntimeInstanceId::from_uuid(value))
}

fn decode_lease_revision(value: i64) -> Result<ActivityLeaseRevision, ForgeError> {
    ActivityLeaseRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("activity lease revision is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{ActivityLeaseProjection, ActivityRevision, WorkspaceId};
    use serde_json::json;
    use std::error::Error;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn scope_payload() -> Value {
        json!({
            "workspace_id": id(1),
            "workspace_revision": 1,
            "locator": {
                "location_id": id(2),
                "expected_revision": 1,
                "relative_root": "."
            }
        })
    }

    fn renew_payload() -> Value {
        json!({
            "scope": scope_payload(),
            "activity_id": id(3),
            "runtime_instance_id": id(4),
            "expected_lease_revision": 1,
            "duration_ms": 1000,
        })
    }

    fn release_payload() -> Value {
        json!({
            "scope": scope_payload(),
            "activity_id": id(3),
            "runtime_instance_id": id(4),
            "expected_lease_revision": 1,
        })
    }

    #[test]
    fn parser_accepts_single_and_batch_shapes_with_exact_ops() -> Result<(), Box<dyn Error>> {
        let renew = parse(CommandOp::ActivityLeaseRenew, &renew_payload())?;
        assert_eq!(renew.op(), CommandOp::ActivityLeaseRenew);
        let release = parse(CommandOp::ActivityLeaseRelease, &release_payload())?;
        assert_eq!(release.op(), CommandOp::ActivityLeaseRelease);
        let renew_batch = json!({
            "scope": scope_payload(),
            "commands": [renew_payload_without_scope(3), renew_payload_without_scope(5)]
        });
        let renew_batch = parse(CommandOp::ActivityLeaseRenewBatch, &renew_batch)?;
        assert_eq!(renew_batch.op(), CommandOp::ActivityLeaseRenewBatch);
        let release_batch = json!({
            "scope": scope_payload(),
            "commands": [release_payload_without_scope(3)]
        });
        let release_batch = parse(CommandOp::ActivityLeaseReleaseBatch, &release_batch)?;
        assert_eq!(release_batch.op(), CommandOp::ActivityLeaseReleaseBatch);
        Ok(())
    }

    fn renew_payload_without_scope(activity: u128) -> Value {
        json!({
            "activity_id": id(activity),
            "runtime_instance_id": id(4),
            "expected_lease_revision": 1,
            "duration_ms": 1000,
        })
    }

    fn release_payload_without_scope(activity: u128) -> Value {
        json!({
            "activity_id": id(activity),
            "runtime_instance_id": id(4),
            "expected_lease_revision": 1,
        })
    }

    #[test]
    fn parser_rejects_nil_ids_bad_revisions_durations_unknown_fields_and_bad_bounds() {
        let mut nil_activity = renew_payload();
        nil_activity["activity_id"] = json!(Uuid::nil());
        assert!(parse(CommandOp::ActivityLeaseRenew, &nil_activity).is_err());

        let mut bad_revision = renew_payload();
        bad_revision["expected_lease_revision"] = json!(0);
        assert!(parse(CommandOp::ActivityLeaseRenew, &bad_revision).is_err());

        for duration in [0, -1] {
            let mut bad_duration = renew_payload();
            bad_duration["duration_ms"] = json!(duration);
            assert!(parse(CommandOp::ActivityLeaseRenew, &bad_duration).is_err());
        }

        let mut unknown = release_payload();
        unknown["observed_at_ms"] = json!(10);
        assert!(parse(CommandOp::ActivityLeaseRelease, &unknown).is_err());

        let empty = json!({"scope": scope_payload(), "commands": []});
        assert!(parse(CommandOp::ActivityLeaseReleaseBatch, &empty).is_err());

        let too_many = (0..257)
            .map(|value| release_payload_without_scope(value + 10))
            .collect::<Vec<_>>();
        let too_many = json!({"scope": scope_payload(), "commands": too_many});
        assert!(parse(CommandOp::ActivityLeaseReleaseBatch, &too_many).is_err());
    }

    #[test]
    fn readback_hint_preserves_single_and_ordered_batch_keys() -> Result<(), Box<dyn Error>> {
        let single = parse(CommandOp::ActivityLeaseRenew, &renew_payload())?;
        assert_eq!(
            readback_hint(&single),
            crate::error::ReadbackHint::ActivityLifecycle {
                workspace_id: id(1),
                activity_id: id(3),
                runtime_instance_id: id(4),
                expected_lease_revision: 1,
            }
        );

        let batch = parse(
            CommandOp::ActivityLeaseReleaseBatch,
            &json!({
                "scope": scope_payload(),
                "commands": [release_payload_without_scope(3), release_payload_without_scope(5)]
            }),
        )?;
        assert_eq!(
            readback_hint(&batch),
            crate::error::ReadbackHint::ActivityLeaseBatch {
                workspace_id: id(1),
                operation: ActivityLeaseReadbackOperation::Release,
                leases: vec![
                    ActivityLeaseReadbackKey {
                        activity_id: id(3),
                        runtime_instance_id: id(4),
                        expected_lease_revision: 1,
                    },
                    ActivityLeaseReadbackKey {
                        activity_id: id(5),
                        runtime_instance_id: id(4),
                        expected_lease_revision: 1,
                    },
                ],
            }
        );
        Ok(())
    }

    #[test]
    fn confirmed_row_proof_requires_order_owner_and_next_revision() -> Result<(), Box<dyn Error>> {
        let command = parse(
            CommandOp::ActivityLeaseRenewBatch,
            &json!({
                "scope": scope_payload(),
                "commands": [renew_payload_without_scope(3), renew_payload_without_scope(5)]
            }),
        )?;
        let scope = command.scope.clone();
        let ActivityLeaseRequest::Renew { commands, .. } = &command.request else {
            return Err("expected renew request".into());
        };
        let rows = commands
            .iter()
            .map(|request| activity_row(scope.workspace_id(), request))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(rows_match(&command, &rows));
        let reversed = vec![rows[1].clone(), rows[0].clone()];
        assert!(!rows_match(&command, &reversed));

        let wrong_owner = RegisteredActivity::from_parts_with_lease(
            rows[0].id(),
            rows[0].workspace_id(),
            rows[0].state(),
            rows[0].created_at(),
            rows[0].updated_at(),
            rows[0].revision(),
            ActivityLeaseProjection::from_parts(
                Some(RuntimeInstanceId::from_uuid(id(99))),
                rows[0].lease_until(),
                rows[0].lease_revision(),
            )?,
        );
        let mut wrong_rows = rows;
        wrong_rows[0] = wrong_owner;
        assert!(!rows_match(&command, &wrong_rows));
        Ok(())
    }

    fn activity_row(
        workspace_id: WorkspaceId,
        request: &RenewActivityLease,
    ) -> Result<RegisteredActivity, Box<dyn Error>> {
        let expected = request.expected_lease_revision().checked_next()?;
        Ok(RegisteredActivity::from_parts_with_lease(
            request.id(),
            workspace_id,
            ActivityState::Open,
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
            ActivityRevision::new(1)?,
            ActivityLeaseProjection::from_parts(
                Some(request.runtime_instance_id()),
                Some(TimestampMillis::new(1000)?),
                expected,
            )?,
        ))
    }

    #[test]
    fn release_row_proof_requires_open_unleased_next_revision() -> Result<(), Box<dyn Error>> {
        let command = parse(CommandOp::ActivityLeaseRelease, &release_payload())?;
        let ActivityLeaseRequest::Release { commands, .. } = &command.request else {
            return Err("expected release request".into());
        };
        let request = &commands[0];
        let row = RegisteredActivity::from_parts_with_lease(
            request.id(),
            command.scope.workspace_id(),
            ActivityState::Open,
            TimestampMillis::new(1)?,
            TimestampMillis::new(2)?,
            ActivityRevision::new(1)?,
            ActivityLeaseProjection::from_parts(
                None,
                None,
                request.expected_lease_revision().checked_next()?,
            )?,
        );
        assert!(rows_match(&command, &[row]));
        Ok(())
    }
}
