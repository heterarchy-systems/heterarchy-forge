//! Strict HTTP DTOs and projections for the pre-delegation Agent-operations
//! migration lifecycle.
//!
//! The persistence/domain records remain the source authority.  This module
//! owns command parsing, dispatch, and readback routing; `wire` owns the
//! bounded serde records and checked transport conversion. Export pages are
//! observations: the adapter never computes a digest, stores a cursor, or
//! changes the source freeze.

use forge_control::{
    AgentOperationsExportRequest, AgentOperationsFreezeReadRequest,
    AgentOperationsFreezeReleaseRequest, AgentOperationsFreezeRequest, ForgeControlClient,
    ResolvedWorkspaceScope,
};
use forge_domain::TimestampMillis;
use forge_persistence::AgentOperationsExportCursor;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{CommandOp, ScopeDto, decode_scope, decode_timestamp, parse_body};
use crate::error::{ForgeError, ReadbackHint};

#[path = "agent_operations_migration/wire.rs"]
pub mod wire;
pub use wire::{
    AgentOperationsExportPageWire, AgentOperationsExportRecordWire,
    AgentOperationsFreezeGetResponseWire, AgentOperationsFreezeWire, AttachmentStateWire,
    CoordinationWire, CoordinatorSnapshotWire, EventKindWire, ExportCursorWire, FocusWire,
    ParticipantRefWire, PrincipalKindWire, PrincipalWire, TransportWire,
};
use wire::{AgentOperationsResultWire, export_page_wire, freeze_wire};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperationsMigrationCommand {
    scope: ResolvedWorkspaceScope,
    scope_dto: ScopeDto,
    request: AgentOperationsMigrationRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentOperationsMigrationRequest {
    Freeze {
        migration_id: Uuid,
        destination_id: Uuid,
        observed_at: TimestampMillis,
    },
    FreezeGet {
        migration_id: Uuid,
        destination_id: Uuid,
    },
    Export {
        migration_id: Uuid,
        destination_id: Uuid,
        cursor: AgentOperationsExportCursor,
    },
    FreezeRelease {
        migration_id: Uuid,
        destination_id: Uuid,
        expected_revision: u64,
        observed_at: TimestampMillis,
    },
}

impl AgentOperationsMigrationCommand {
    pub const fn op(&self) -> CommandOp {
        match &self.request {
            AgentOperationsMigrationRequest::Freeze { .. } => CommandOp::AgentOperationsFreeze,
            AgentOperationsMigrationRequest::FreezeGet { .. } => {
                CommandOp::AgentOperationsFreezeGet
            }
            AgentOperationsMigrationRequest::Export { .. } => CommandOp::AgentOperationsExport,
            AgentOperationsMigrationRequest::FreezeRelease { .. } => {
                CommandOp::AgentOperationsFreezeRelease
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeBody {
    scope: ScopeDto,
    migration_id: Uuid,
    destination_id: Uuid,
    observed_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeGetBody {
    scope: ScopeDto,
    migration_id: Uuid,
    destination_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportBody {
    scope: ScopeDto,
    migration_id: Uuid,
    destination_id: Uuid,
    #[serde(default)]
    cursor: ExportCursorWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeReleaseBody {
    scope: ScopeDto,
    migration_id: Uuid,
    destination_id: Uuid,
    expected_revision: i64,
    observed_at_ms: i64,
}

pub(super) fn parse(
    op: CommandOp,
    payload: &Value,
) -> Result<AgentOperationsMigrationCommand, ForgeError> {
    let (scope_dto, request) = match op {
        CommandOp::AgentOperationsFreeze => {
            let body: FreezeBody =
                parse_body(payload, "agent.operations.freeze payload is invalid")?;
            let request = AgentOperationsMigrationRequest::Freeze {
                migration_id: require_id(body.migration_id, "migration id")?,
                destination_id: require_id(body.destination_id, "destination id")?,
                observed_at: decode_timestamp(body.observed_at_ms)?,
            };
            (body.scope, request)
        }
        CommandOp::AgentOperationsFreezeGet => {
            let body: FreezeGetBody =
                parse_body(payload, "agent.operations.freeze_get payload is invalid")?;
            let request = AgentOperationsMigrationRequest::FreezeGet {
                migration_id: require_id(body.migration_id, "migration id")?,
                destination_id: require_id(body.destination_id, "destination id")?,
            };
            (body.scope, request)
        }
        CommandOp::AgentOperationsExport => {
            let body: ExportBody =
                parse_body(payload, "agent.operations.export payload is invalid")?;
            let request = AgentOperationsMigrationRequest::Export {
                migration_id: require_id(body.migration_id, "migration id")?,
                destination_id: require_id(body.destination_id, "destination id")?,
                cursor: body.cursor.decode()?,
            };
            (body.scope, request)
        }
        CommandOp::AgentOperationsFreezeRelease => {
            let body: FreezeReleaseBody = parse_body(
                payload,
                "agent.operations.freeze_release payload is invalid",
            )?;
            let expected_revision = positive_revision(body.expected_revision)?;
            let request = AgentOperationsMigrationRequest::FreezeRelease {
                migration_id: require_id(body.migration_id, "migration id")?,
                destination_id: require_id(body.destination_id, "destination id")?,
                expected_revision,
                observed_at: decode_timestamp(body.observed_at_ms)?,
            };
            (body.scope, request)
        }
        _ => {
            return Err(ForgeError::invalid_input(
                "operation is not an Agent operations migration operation",
            ));
        }
    };
    let scope = decode_scope(&scope_dto)?;
    Ok(AgentOperationsMigrationCommand {
        scope,
        scope_dto,
        request,
    })
}

pub(super) fn readback_hint(command: &AgentOperationsMigrationCommand) -> Option<ReadbackHint> {
    let workspace_id = command.scope.workspace_id().into_uuid();
    match &command.request {
        AgentOperationsMigrationRequest::Freeze {
            migration_id,
            destination_id,
            observed_at,
        } => Some(ReadbackHint::AgentOperationsFreeze {
            operation: crate::error::AgentOperationsFreezeReadbackOperation::Freeze,
            workspace_id,
            migration_id: *migration_id,
            destination_id: *destination_id,
            expected_revision: None,
            observed_at_ms: observed_at.get(),
        }),
        AgentOperationsMigrationRequest::FreezeRelease {
            migration_id,
            destination_id,
            expected_revision,
            observed_at,
        } => Some(ReadbackHint::AgentOperationsFreeze {
            operation: crate::error::AgentOperationsFreezeReadbackOperation::Release,
            workspace_id,
            migration_id: *migration_id,
            destination_id: *destination_id,
            expected_revision: Some(*expected_revision),
            observed_at_ms: observed_at.get(),
        }),
        AgentOperationsMigrationRequest::FreezeGet { .. }
        | AgentOperationsMigrationRequest::Export { .. } => None,
    }
}

pub(super) fn execute(
    client: &ForgeControlClient,
    backend_id: forge_domain::ForgeBackendId,
    trusted_destination_id: Uuid,
    command: &AgentOperationsMigrationCommand,
) -> Result<Value, ForgeError> {
    let destination_id = command.destination_id();
    if trusted_destination_id.is_nil() || destination_id != trusted_destination_id {
        return Err(ForgeError::auth_failed());
    }
    let result = match &command.request {
        AgentOperationsMigrationRequest::Freeze {
            migration_id,
            destination_id,
            observed_at,
        } => {
            let freeze = client
                .agent_operations_freeze(AgentOperationsFreezeRequest {
                    scope: command.scope.clone(),
                    migration_id: *migration_id,
                    destination_id: *destination_id,
                    observed_at: *observed_at,
                })
                .map_err(|error| super::forge_error_of_client(&error))?;
            AgentOperationsResultWire::Freeze(freeze_wire(
                command.scope_dto.clone(),
                backend_id,
                &freeze,
            ))
        }
        AgentOperationsMigrationRequest::FreezeGet {
            migration_id,
            destination_id,
        } => {
            let freeze = client
                .agent_operations_freeze_read(AgentOperationsFreezeReadRequest {
                    scope: command.scope.clone(),
                    migration_id: *migration_id,
                    destination_id: *destination_id,
                })
                .map_err(|error| super::forge_error_of_client(&error))?;
            AgentOperationsResultWire::FreezeGet(AgentOperationsFreezeGetResponseWire {
                scope: command.scope_dto.clone(),
                backend_id: backend_id.into_uuid(),
                workspace_id: command.scope.workspace_id().into_uuid(),
                migration_id: *migration_id,
                destination_id: *destination_id,
                freeze: freeze
                    .as_ref()
                    .map(|value| freeze_wire(command.scope_dto.clone(), backend_id, value)),
            })
        }
        AgentOperationsMigrationRequest::Export {
            migration_id,
            destination_id,
            cursor,
        } => {
            let page = client
                .agent_operations_export(AgentOperationsExportRequest {
                    scope: command.scope.clone(),
                    migration_id: *migration_id,
                    destination_id: *destination_id,
                    cursor: *cursor,
                })
                .map_err(|error| super::forge_error_of_client(&error))?;
            AgentOperationsResultWire::Export(export_page_wire(
                command.scope_dto.clone(),
                backend_id,
                &page,
            )?)
        }
        AgentOperationsMigrationRequest::FreezeRelease {
            migration_id,
            destination_id,
            expected_revision,
            observed_at,
        } => {
            let freeze = client
                .agent_operations_freeze_release(AgentOperationsFreezeReleaseRequest {
                    scope: command.scope.clone(),
                    migration_id: *migration_id,
                    destination_id: *destination_id,
                    expected_revision: *expected_revision,
                    observed_at: *observed_at,
                })
                .map_err(|error| super::forge_error_of_client(&error))?;
            AgentOperationsResultWire::Freeze(freeze_wire(
                command.scope_dto.clone(),
                backend_id,
                &freeze,
            ))
        }
    };
    let value = serde_json::to_value(result).map_err(|_| ForgeError::internal())?;
    let bytes = serde_json::to_vec(&value).map_err(|_| ForgeError::internal())?;
    if bytes.len() > crate::config::MAX_BODY_BYTES {
        return Err(ForgeError::capacity_exceeded("migration response body"));
    }
    Ok(value)
}

impl AgentOperationsMigrationCommand {
    fn destination_id(&self) -> Uuid {
        match &self.request {
            AgentOperationsMigrationRequest::Freeze { destination_id, .. }
            | AgentOperationsMigrationRequest::FreezeGet { destination_id, .. }
            | AgentOperationsMigrationRequest::Export { destination_id, .. }
            | AgentOperationsMigrationRequest::FreezeRelease { destination_id, .. } => {
                *destination_id
            }
        }
    }
}

fn require_id(value: Uuid, label: &'static str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )))
    } else {
        Ok(value)
    }
}

fn positive_revision(value: i64) -> Result<u64, ForgeError> {
    let revision = u64::try_from(value)
        .map_err(|_| ForgeError::invalid_input("freeze revision is invalid"))?;
    if revision == 0 {
        return Err(ForgeError::invalid_input("freeze revision is invalid"));
    }
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn freeze_payload_is_strict_and_typed() -> Result<(), Box<dyn std::error::Error>> {
        let command = parse(
            CommandOp::AgentOperationsFreeze,
            &json!({
                "scope": scope(),
                "migration_id": Uuid::from_u128(3),
                "destination_id": Uuid::from_u128(4),
                "observed_at_ms": 10,
            }),
        )
        .map_err(|_| "valid freeze payload was rejected")?;
        assert_eq!(command.op(), CommandOp::AgentOperationsFreeze);
        Ok(())
    }

    #[test]
    fn inbox_cursor_requires_the_complete_composite_key() {
        let result = parse(
            CommandOp::AgentOperationsExport,
            &json!({
                "scope": scope(),
                "migration_id": Uuid::from_u128(3),
                "destination_id": Uuid::from_u128(4),
                "cursor": {
                    "kind": "inbox",
                    "after_recipient_agent_id": Uuid::from_u128(5),
                    "after_recipient_session_id": null,
                    "after_event_id": Uuid::from_u128(6),
                }
            }),
        );
        assert!(matches!(result, Err(error) if error.code() == crate::ErrorCode::InvalidInput));
    }

    #[test]
    fn unknown_fields_are_rejected_before_admission() {
        let result = parse(
            CommandOp::AgentOperationsFreezeGet,
            &json!({
                "scope": scope(),
                "migration_id": Uuid::from_u128(3),
                "destination_id": Uuid::from_u128(4),
                "unexpected": true,
            }),
        );
        assert!(matches!(result, Err(error) if error.code() == crate::ErrorCode::InvalidInput));
    }
}
