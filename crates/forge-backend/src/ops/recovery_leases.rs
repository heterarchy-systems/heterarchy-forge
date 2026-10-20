//! Typed HTTP adapter for the Workspace recovery-maintenance lease.
//!
//! The durable lease and its compare-and-swap transitions remain owned by
//! forge-control and SQLite. This module only validates the transport shape,
//! constructs the native command with a placeholder observation timestamp,
//! and projects the returned lease snapshot. The control worker replaces that
//! placeholder with its admission-time clock.

use forge_control::{
    ForgeControlClient, RecoveryLeaseAcquisition, RecoveryLeaseClaimOperation,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    ClaimRecoveryLease, RecoveryLeaseDurationMillis, RecoveryLeaseEpoch, RecoveryLeaseRevision,
    RecoveryMaintenanceLease, ReleaseRecoveryLease, RenewRecoveryLease, RuntimeInstanceId,
    TimestampMillis,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{CommandOp, ScopeDto, decode_scope};
use crate::error::ForgeError;

/// One validated recovery-lease command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryLeaseCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) request: RecoveryLeaseRequest,
}

/// Closed request family for the four recovery-lease operations.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryLeaseRequest {
    Get,
    Claim {
        owner_id: RuntimeInstanceId,
        duration: RecoveryLeaseDurationMillis,
    },
    Renew {
        owner_id: RuntimeInstanceId,
        expected_epoch: RecoveryLeaseEpoch,
        expected_revision: RecoveryLeaseRevision,
        duration: RecoveryLeaseDurationMillis,
    },
    Release {
        owner_id: RuntimeInstanceId,
        expected_epoch: RecoveryLeaseEpoch,
        expected_revision: RecoveryLeaseRevision,
    },
}

impl RecoveryLeaseCommand {
    /// Return the canonical operation represented by this command.
    pub const fn op(&self) -> CommandOp {
        match self.request {
            RecoveryLeaseRequest::Get => CommandOp::RecoveryLeaseGet,
            RecoveryLeaseRequest::Claim { .. } => CommandOp::RecoveryLeaseClaim,
            RecoveryLeaseRequest::Renew { .. } => CommandOp::RecoveryLeaseRenew,
            RecoveryLeaseRequest::Release { .. } => CommandOp::RecoveryLeaseRelease,
        }
    }

    /// Return a durable identity only for mutation commands.
    pub(super) fn readback_hint(&self) -> Option<crate::error::ReadbackHint> {
        let workspace_id = self.scope.workspace_id().into_uuid();
        match self.request {
            RecoveryLeaseRequest::Get => None,
            RecoveryLeaseRequest::Claim { owner_id, duration } => {
                Some(crate::error::ReadbackHint::RecoveryLease {
                    workspace_id,
                    owner_id: owner_id.into_uuid(),
                    operation: crate::error::RecoveryLeaseReadbackOperation::Claim,
                    expected_epoch: None,
                    expected_revision: None,
                    duration_ms: Some(duration.get()),
                })
            }
            RecoveryLeaseRequest::Renew {
                owner_id,
                expected_epoch,
                expected_revision,
                duration,
            } => Some(crate::error::ReadbackHint::RecoveryLease {
                workspace_id,
                owner_id: owner_id.into_uuid(),
                operation: crate::error::RecoveryLeaseReadbackOperation::Renew,
                expected_epoch: Some(expected_epoch.get()),
                expected_revision: Some(expected_revision.get()),
                duration_ms: Some(duration.get()),
            }),
            RecoveryLeaseRequest::Release {
                owner_id,
                expected_epoch,
                expected_revision,
            } => Some(crate::error::ReadbackHint::RecoveryLease {
                workspace_id,
                owner_id: owner_id.into_uuid(),
                operation: crate::error::RecoveryLeaseReadbackOperation::Release,
                expected_epoch: Some(expected_epoch.get()),
                expected_revision: Some(expected_revision.get()),
                duration_ms: None,
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBody {
    scope: ScopeDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBody {
    scope: ScopeDto,
    owner_id: Uuid,
    duration_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewBody {
    scope: ScopeDto,
    owner_id: Uuid,
    expected_epoch: i64,
    expected_revision: i64,
    duration_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBody {
    scope: ScopeDto,
    owner_id: Uuid,
    expected_epoch: i64,
    expected_revision: i64,
}

/// Parse one of the four recovery-lease payloads.
pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<RecoveryLeaseCommand, ForgeError> {
    match operation {
        CommandOp::RecoveryLeaseGet => {
            let body: GetBody =
                super::parse_body(payload, "recovery.lease.get payload is invalid")?;
            Ok(RecoveryLeaseCommand {
                scope: decode_scope_checked(&body.scope)?,
                request: RecoveryLeaseRequest::Get,
            })
        }
        CommandOp::RecoveryLeaseClaim => {
            let body: ClaimBody =
                super::parse_body(payload, "recovery.lease.claim payload is invalid")?;
            Ok(RecoveryLeaseCommand {
                scope: decode_scope_checked(&body.scope)?,
                request: RecoveryLeaseRequest::Claim {
                    owner_id: decode_owner(body.owner_id)?,
                    duration: decode_duration(body.duration_ms)?,
                },
            })
        }
        CommandOp::RecoveryLeaseRenew => {
            let body: RenewBody =
                super::parse_body(payload, "recovery.lease.renew payload is invalid")?;
            Ok(RecoveryLeaseCommand {
                scope: decode_scope_checked(&body.scope)?,
                request: RecoveryLeaseRequest::Renew {
                    owner_id: decode_owner(body.owner_id)?,
                    expected_epoch: decode_epoch(body.expected_epoch)?,
                    expected_revision: decode_revision(body.expected_revision)?,
                    duration: decode_duration(body.duration_ms)?,
                },
            })
        }
        CommandOp::RecoveryLeaseRelease => {
            let body: ReleaseBody =
                super::parse_body(payload, "recovery.lease.release payload is invalid")?;
            Ok(RecoveryLeaseCommand {
                scope: decode_scope_checked(&body.scope)?,
                request: RecoveryLeaseRequest::Release {
                    owner_id: decode_owner(body.owner_id)?,
                    expected_epoch: decode_epoch(body.expected_epoch)?,
                    expected_revision: decode_revision(body.expected_revision)?,
                },
            })
        }
        _ => Err(ForgeError::invalid_input(
            "operation is not a recovery lease operation",
        )),
    }
}

/// Execute one recovery-lease request through the existing control authority.
pub(super) fn execute(
    client: &ForgeControlClient,
    command: &RecoveryLeaseCommand,
) -> Result<Value, ForgeError> {
    match command.request {
        RecoveryLeaseRequest::Get => {
            let lease = client
                .recovery_maintenance_lease(command.scope.clone())
                .map_err(|error| super::forge_error_of_client(&error))?;
            project_snapshot(command, "observed", &lease)
        }
        RecoveryLeaseRequest::Claim { owner_id, duration } => {
            let native = ClaimRecoveryLease::new(
                command.scope.workspace_id(),
                owner_id,
                duration,
                zero_timestamp()?,
            )
            .map_err(|_| ForgeError::invalid_input("recovery lease claim is invalid"))?;
            let operation = client
                .claim_recovery_maintenance_lease(command.scope.clone(), native)
                .map_err(|error| super::forge_error_of_client(&error))?;
            project_claim(command, owner_id, &operation)
        }
        RecoveryLeaseRequest::Renew {
            owner_id,
            expected_epoch,
            expected_revision,
            duration,
        } => {
            let native = RenewRecoveryLease::new(
                command.scope.workspace_id(),
                owner_id,
                expected_epoch,
                expected_revision,
                duration,
                zero_timestamp()?,
            )
            .map_err(|_| ForgeError::invalid_input("recovery lease renewal is invalid"))?;
            let lease = client
                .renew_recovery_maintenance_lease(command.scope.clone(), native)
                .map_err(|error| super::forge_error_of_client(&error))?;
            project_renew(command, owner_id, expected_epoch, expected_revision, &lease)
        }
        RecoveryLeaseRequest::Release {
            owner_id,
            expected_epoch,
            expected_revision,
        } => {
            let native = ReleaseRecoveryLease::new(
                command.scope.workspace_id(),
                owner_id,
                expected_epoch,
                expected_revision,
                zero_timestamp()?,
            );
            let lease = client
                .release_recovery_maintenance_lease(command.scope.clone(), native)
                .map_err(|error| super::forge_error_of_client(&error))?;
            project_release(command, expected_epoch, expected_revision, &lease)
        }
    }
}

fn project_claim(
    command: &RecoveryLeaseCommand,
    owner_id: RuntimeInstanceId,
    operation: &RecoveryLeaseClaimOperation,
) -> Result<Value, ForgeError> {
    let acquisition = operation.acquisition();
    let status = match acquisition {
        RecoveryLeaseAcquisition::Acquired => "acquired",
        RecoveryLeaseAcquisition::AlreadyOwned => "already_owned",
        RecoveryLeaseAcquisition::Busy => "busy",
        RecoveryLeaseAcquisition::ClaimConflict => "claim_conflict",
    };
    let lease = operation.lease();
    if let Err(error) = validate_claim(command, owner_id, acquisition, operation.scope(), lease) {
        return if acquisition.is_acquired() {
            Err(ForgeError::unknown_outcome(command.readback_hint()))
        } else {
            Err(error)
        };
    }
    project_snapshot_with_status(command, status, lease)
}

fn project_renew(
    command: &RecoveryLeaseCommand,
    owner_id: RuntimeInstanceId,
    expected_epoch: RecoveryLeaseEpoch,
    expected_revision: RecoveryLeaseRevision,
    lease: &RecoveryMaintenanceLease,
) -> Result<Value, ForgeError> {
    let validation = validate_scope_and_lease(&command.scope, lease)
        .and_then(|()| validate_owner(lease, owner_id))
        .and_then(|()| validate_epoch(lease, expected_epoch))
        .and_then(|()| validate_next_revision(lease, expected_revision));
    if validation.is_err() {
        return Err(ForgeError::unknown_outcome(command.readback_hint()));
    }
    project_snapshot_with_status(command, "renewed", lease)
}

fn project_release(
    command: &RecoveryLeaseCommand,
    expected_epoch: RecoveryLeaseEpoch,
    expected_revision: RecoveryLeaseRevision,
    lease: &RecoveryMaintenanceLease,
) -> Result<Value, ForgeError> {
    let validation = validate_scope_and_lease(&command.scope, lease)
        .and_then(|()| validate_epoch(lease, expected_epoch))
        .and_then(|()| validate_next_revision(lease, expected_revision))
        .and_then(|()| {
            if lease.owner_id().is_none() && lease.lease_until().is_none() {
                Ok(())
            } else {
                Err(ForgeError::resync_required(
                    "recovery lease release readback remains owned",
                ))
            }
        });
    if validation.is_err() {
        return Err(ForgeError::unknown_outcome(command.readback_hint()));
    }
    project_snapshot_with_status(command, "released", lease)
}

fn validate_claim(
    command: &RecoveryLeaseCommand,
    owner_id: RuntimeInstanceId,
    acquisition: RecoveryLeaseAcquisition,
    operation_scope: &ResolvedWorkspaceScope,
    lease: &RecoveryMaintenanceLease,
) -> Result<(), ForgeError> {
    validate_scope_and_lease(&command.scope, lease)?;
    if operation_scope != &command.scope {
        return Err(ForgeError::resync_required(
            "recovery lease claim scope changed",
        ));
    }
    let Some(actual_owner) = lease.owner_id() else {
        return Err(ForgeError::resync_required(
            "recovery lease claim readback has no owner",
        ));
    };
    if lease.lease_until().is_none() || lease.epoch().get() < 1 || lease.revision().get() < 2 {
        return Err(ForgeError::resync_required(
            "recovery lease claim readback is not owned",
        ));
    }
    match acquisition {
        RecoveryLeaseAcquisition::Acquired | RecoveryLeaseAcquisition::AlreadyOwned => {
            if actual_owner != owner_id {
                return Err(ForgeError::resync_required(
                    "recovery lease claim owner does not match",
                ));
            }
        }
        RecoveryLeaseAcquisition::Busy => {
            if actual_owner == owner_id {
                return Err(ForgeError::resync_required(
                    "recovery lease busy readback matches claimant",
                ));
            }
        }
        RecoveryLeaseAcquisition::ClaimConflict => {
            if actual_owner != owner_id {
                return Err(ForgeError::resync_required(
                    "recovery lease claim conflict owner changed",
                ));
            }
        }
    }
    Ok(())
}

fn validate_scope_and_lease(
    scope: &ResolvedWorkspaceScope,
    lease: &RecoveryMaintenanceLease,
) -> Result<(), ForgeError> {
    if lease.workspace_id() != scope.workspace_id() {
        return Err(ForgeError::resync_required(
            "recovery lease readback changed Workspace scope",
        ));
    }
    if let Some(owner) = lease.owner_id()
        && (owner.into_uuid().is_nil() || lease.lease_until().is_none() || lease.epoch().get() == 0)
    {
        return Err(ForgeError::resync_required(
            "recovery lease readback violates ownership invariants",
        ));
    }
    if lease.owner_id().is_none() != lease.lease_until().is_none()
        || lease.revision().get() < 1
        || lease
            .lease_until()
            .is_some_and(|expiry| expiry.get() <= lease.updated_at().get())
    {
        return Err(ForgeError::resync_required(
            "recovery lease readback violates durable invariants",
        ));
    }
    Ok(())
}

fn validate_owner(
    lease: &RecoveryMaintenanceLease,
    expected: RuntimeInstanceId,
) -> Result<(), ForgeError> {
    if lease.owner_id() == Some(expected) && lease.lease_until().is_some() {
        Ok(())
    } else {
        Err(ForgeError::resync_required(
            "recovery lease owner readback does not match",
        ))
    }
}

fn validate_epoch(
    lease: &RecoveryMaintenanceLease,
    expected: RecoveryLeaseEpoch,
) -> Result<(), ForgeError> {
    if lease.epoch() == expected {
        Ok(())
    } else {
        Err(ForgeError::resync_required(
            "recovery lease epoch readback does not match",
        ))
    }
}

fn validate_next_revision(
    lease: &RecoveryMaintenanceLease,
    expected: RecoveryLeaseRevision,
) -> Result<(), ForgeError> {
    let next = expected
        .get()
        .checked_add(1)
        .ok_or_else(|| ForgeError::resync_required("recovery lease revision overflowed"))?;
    if lease.revision().get() == next {
        Ok(())
    } else {
        Err(ForgeError::resync_required(
            "recovery lease revision readback does not match",
        ))
    }
}

fn project_snapshot(
    command: &RecoveryLeaseCommand,
    status: &'static str,
    lease: &RecoveryMaintenanceLease,
) -> Result<Value, ForgeError> {
    validate_scope_and_lease(&command.scope, lease)?;
    project_snapshot_with_status(command, status, lease)
}

fn project_snapshot_with_status(
    command: &RecoveryLeaseCommand,
    status: &'static str,
    lease: &RecoveryMaintenanceLease,
) -> Result<Value, ForgeError> {
    let mut object = Map::new();
    object.insert("scope".to_owned(), super::scope_json(&command.scope)?);
    object.insert("status".to_owned(), json!(status));
    object.insert(
        "lease".to_owned(),
        json!({
            "workspace_id": lease.workspace_id().into_uuid(),
            "owner_id": lease.owner_id().map(RuntimeInstanceId::into_uuid),
            "lease_until_ms": lease.lease_until().map(TimestampMillis::get),
            "epoch": lease.epoch().get(),
            "revision": lease.revision().get(),
            "updated_at_ms": lease.updated_at().get(),
        }),
    );
    object.insert("retry_authorized".to_owned(), json!(false));
    object.insert("request_equivalence_proven".to_owned(), json!(false));
    Ok(Value::Object(object))
}

fn decode_scope_checked(scope: &ScopeDto) -> Result<ResolvedWorkspaceScope, ForgeError> {
    if scope.workspace_id.is_nil() || scope.locator.location_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "recovery lease scope identifiers must not be nil",
        ));
    }
    decode_scope(scope)
}

fn decode_owner(value: Uuid) -> Result<RuntimeInstanceId, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(
            "recovery lease owner id must not be nil",
        ));
    }
    Ok(RuntimeInstanceId::from_uuid(value))
}

fn decode_duration(value: i64) -> Result<RecoveryLeaseDurationMillis, ForgeError> {
    RecoveryLeaseDurationMillis::new(value)
        .map_err(|_| ForgeError::invalid_input("recovery lease duration is invalid"))
}

fn decode_epoch(value: i64) -> Result<RecoveryLeaseEpoch, ForgeError> {
    RecoveryLeaseEpoch::new(value)
        .map_err(|_| ForgeError::invalid_input("recovery lease epoch is invalid"))
}

fn decode_revision(value: i64) -> Result<RecoveryLeaseRevision, ForgeError> {
    RecoveryLeaseRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("recovery lease revision is invalid"))
}

fn zero_timestamp() -> Result<TimestampMillis, ForgeError> {
    TimestampMillis::new(0).map_err(|_| ForgeError::internal())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use serde_json::json;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn scope() -> Value {
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

    fn payload(operation: CommandOp) -> Result<Value, ForgeError> {
        let mut payload = json!({"scope": scope()});
        match operation {
            CommandOp::RecoveryLeaseGet => {}
            CommandOp::RecoveryLeaseClaim => {
                payload["owner_id"] = json!(id(3));
                payload["duration_ms"] = json!(1_000);
            }
            CommandOp::RecoveryLeaseRenew => {
                payload["owner_id"] = json!(id(3));
                payload["expected_epoch"] = json!(1);
                payload["expected_revision"] = json!(2);
                payload["duration_ms"] = json!(1_000);
            }
            CommandOp::RecoveryLeaseRelease => {
                payload["owner_id"] = json!(id(3));
                payload["expected_epoch"] = json!(1);
                payload["expected_revision"] = json!(2);
            }
            _ => {
                return Err(ForgeError::invalid_input(
                    "unsupported recovery lease test operation",
                ));
            }
        }
        Ok(payload)
    }

    fn resolved_scope(workspace: u128) -> Result<ResolvedWorkspaceScope, ForgeError> {
        Ok(ResolvedWorkspaceScope::from_observation(
            forge_domain::WorkspaceId::from_uuid(id(workspace)),
            forge_domain::WorkspaceRevision::new(1).map_err(|_| ForgeError::internal())?,
            forge_control::WorkspaceLocator::new(
                forge_domain::LocationId::from_uuid(id(2)),
                forge_domain::LocationRevision::new(1).map_err(|_| ForgeError::internal())?,
                std::path::Path::new("."),
            )
            .map_err(|_| ForgeError::internal())?,
        ))
    }

    fn owned_lease(
        workspace: u128,
        owner: u128,
        epoch: i64,
        updated_at: i64,
        revision: i64,
    ) -> Result<RecoveryMaintenanceLease, ForgeError> {
        RecoveryMaintenanceLease::from_parts(
            forge_domain::WorkspaceId::from_uuid(id(workspace)),
            Some(RuntimeInstanceId::from_uuid(id(owner))),
            Some(TimestampMillis::new(updated_at + 1_000).map_err(|_| ForgeError::internal())?),
            RecoveryLeaseEpoch::new(epoch).map_err(|_| ForgeError::internal())?,
            TimestampMillis::new(updated_at).map_err(|_| ForgeError::internal())?,
            RecoveryLeaseRevision::new(revision).map_err(|_| ForgeError::internal())?,
        )
        .map_err(|_| ForgeError::internal())
    }

    fn assert_unknown_with_exact_hint(
        result: Result<Value, ForgeError>,
        command: &RecoveryLeaseCommand,
    ) -> Result<(), ForgeError> {
        let error = result.err().ok_or_else(ForgeError::internal)?;
        assert_eq!(error.code(), ErrorCode::UnknownOutcome);
        let expected_hint = command.readback_hint();
        assert_eq!(error.readback(), expected_hint.as_ref());
        Ok(())
    }

    #[test]
    fn parser_rejects_nil_ids_bounds_and_unknown_fields() -> Result<(), ForgeError> {
        let mut claim = payload(CommandOp::RecoveryLeaseClaim)?;
        claim["owner_id"] = json!(Uuid::nil());
        assert!(parse(CommandOp::RecoveryLeaseClaim, &claim).is_err());

        let mut renew = payload(CommandOp::RecoveryLeaseRenew)?;
        renew["expected_epoch"] = json!(-1);
        assert!(parse(CommandOp::RecoveryLeaseRenew, &renew).is_err());

        let mut release = payload(CommandOp::RecoveryLeaseRelease)?;
        release["expected_revision"] = json!(0);
        assert!(parse(CommandOp::RecoveryLeaseRelease, &release).is_err());

        let mut unknown = payload(CommandOp::RecoveryLeaseClaim)?;
        unknown["observed_at_ms"] = json!(1);
        assert!(parse(CommandOp::RecoveryLeaseClaim, &unknown).is_err());
        Ok(())
    }

    #[test]
    fn parser_accepts_all_operations_and_exact_duration_bounds() -> Result<(), ForgeError> {
        for operation in [
            CommandOp::RecoveryLeaseGet,
            CommandOp::RecoveryLeaseClaim,
            CommandOp::RecoveryLeaseRenew,
            CommandOp::RecoveryLeaseRelease,
        ] {
            let command = parse(operation, &payload(operation)?)?;
            assert_eq!(command.op(), operation);
        }
        let mut claim = payload(CommandOp::RecoveryLeaseClaim)?;
        claim["duration_ms"] = json!(999);
        assert!(parse(CommandOp::RecoveryLeaseClaim, &claim).is_err());
        claim["duration_ms"] = json!(300_001);
        assert!(parse(CommandOp::RecoveryLeaseClaim, &claim).is_err());
        claim["duration_ms"] = json!(300_000);
        assert!(parse(CommandOp::RecoveryLeaseClaim, &claim).is_ok());
        Ok(())
    }

    #[test]
    fn readback_hints_are_mutation_only_and_retain_exact_cas_keys() -> Result<(), ForgeError> {
        let command = parse(
            CommandOp::RecoveryLeaseClaim,
            &payload(CommandOp::RecoveryLeaseClaim)?,
        )?;
        let hint = command.readback_hint().ok_or_else(ForgeError::internal)?;
        assert!(matches!(
            hint,
            crate::error::ReadbackHint::RecoveryLease { workspace_id, .. }
                if workspace_id == id(1)
        ));

        let get = parse(
            CommandOp::RecoveryLeaseGet,
            &payload(CommandOp::RecoveryLeaseGet)?,
        )?;
        assert!(get.readback_hint().is_none());
        Ok(())
    }

    #[test]
    fn released_snapshot_projection_has_no_owner_or_retry_authority() -> Result<(), ForgeError> {
        let scope = resolved_scope(1)?;
        let command = RecoveryLeaseCommand {
            scope,
            request: RecoveryLeaseRequest::Get,
        };
        let lease = RecoveryMaintenanceLease::released(
            forge_domain::WorkspaceId::from_uuid(id(1)),
            TimestampMillis::new(10).map_err(|_| ForgeError::internal())?,
        );
        let response = project_snapshot(&command, "observed", &lease)?;
        assert_eq!(response["scope"]["workspace_id"], json!(id(1)));
        assert_eq!(response["status"], "observed");
        assert_eq!(response["lease"]["workspace_id"], json!(id(1)));
        assert_eq!(response["lease"]["owner_id"], Value::Null);
        assert_eq!(response["lease"]["lease_until_ms"], Value::Null);
        assert_eq!(response["lease"]["epoch"], 0);
        assert_eq!(response["lease"]["revision"], 1);
        assert_eq!(response["lease"]["updated_at_ms"], 10);
        assert_eq!(response["retry_authorized"], false);
        assert_eq!(response["request_equivalence_proven"], false);
        Ok(())
    }

    #[test]
    fn malformed_get_readback_is_resync_without_mutation_hint() -> Result<(), ForgeError> {
        let command = parse(
            CommandOp::RecoveryLeaseGet,
            &payload(CommandOp::RecoveryLeaseGet)?,
        )?;
        let lease = RecoveryMaintenanceLease::released(
            forge_domain::WorkspaceId::from_uuid(id(2)),
            TimestampMillis::new(10).map_err(|_| ForgeError::internal())?,
        );

        let error = project_snapshot(&command, "observed", &lease)
            .err()
            .ok_or_else(ForgeError::internal)?;
        assert_eq!(error.code(), ErrorCode::ResyncRequired);
        assert!(error.readback().is_none());
        Ok(())
    }

    #[test]
    fn malformed_renew_readback_is_unknown_with_exact_cas_hint() -> Result<(), ForgeError> {
        let command = parse(
            CommandOp::RecoveryLeaseRenew,
            &payload(CommandOp::RecoveryLeaseRenew)?,
        )?;
        let owner = RuntimeInstanceId::from_uuid(id(3));
        let expected_epoch = RecoveryLeaseEpoch::new(1).map_err(|_| ForgeError::internal())?;
        let expected_revision =
            RecoveryLeaseRevision::new(2).map_err(|_| ForgeError::internal())?;
        let rows = [
            RecoveryMaintenanceLease::released(
                forge_domain::WorkspaceId::from_uuid(id(2)),
                TimestampMillis::new(10).map_err(|_| ForgeError::internal())?,
            ),
            owned_lease(1, 4, 1, 100, 3)?,
            owned_lease(1, 3, 2, 100, 3)?,
            owned_lease(1, 3, 1, 100, 4)?,
        ];

        for lease in &rows {
            assert_unknown_with_exact_hint(
                project_renew(&command, owner, expected_epoch, expected_revision, lease),
                &command,
            )?;
        }
        Ok(())
    }

    #[test]
    fn released_mutation_projection_keeps_native_cas_result_unowned() -> Result<(), ForgeError> {
        let command = parse(
            CommandOp::RecoveryLeaseRelease,
            &payload(CommandOp::RecoveryLeaseRelease)?,
        )?;
        let expected_epoch = RecoveryLeaseEpoch::new(1).map_err(|_| ForgeError::internal())?;
        let expected_revision =
            RecoveryLeaseRevision::new(2).map_err(|_| ForgeError::internal())?;
        let lease = RecoveryMaintenanceLease::from_parts(
            forge_domain::WorkspaceId::from_uuid(id(1)),
            None,
            None,
            expected_epoch,
            TimestampMillis::new(2_000).map_err(|_| ForgeError::internal())?,
            RecoveryLeaseRevision::new(3).map_err(|_| ForgeError::internal())?,
        )
        .map_err(|_| ForgeError::internal())?;

        let response = project_release(&command, expected_epoch, expected_revision, &lease)?;
        assert_eq!(response["status"], "released");
        assert_eq!(response["lease"]["owner_id"], Value::Null);
        assert_eq!(response["lease"]["lease_until_ms"], Value::Null);
        assert_eq!(response["lease"]["epoch"], 1);
        assert_eq!(response["lease"]["revision"], 3);
        assert_eq!(response["retry_authorized"], false);
        assert_eq!(response["request_equivalence_proven"], false);
        Ok(())
    }
}
