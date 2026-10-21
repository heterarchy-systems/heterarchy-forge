//! Typed HTTP adapter for registered Location disable and root-state removal.
//!
//! The Location registry, physical-root observation, and owned state cleanup
//! remain owned by forge-control. This module only validates the closed wire
//! forms, forwards the typed native request, and projects current observations
//! without turning them into historical receipts.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use forge_control::{
    ForgeControlClient, LocationRemovalRequest, RemovalStateExpectation, WorkspaceRemovalCleanup,
    WorkspaceRemovalOutcome,
};
use forge_domain::{
    LocationId, LocationRevision, LocationState, RegisteredLocation, WorkspaceRevision,
    WorkspaceRootFingerprint,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::os::unix::ffi::OsStrExt;
use uuid::Uuid;

use super::CommandOp;
use crate::error::ForgeError;

/// One validated Location removal or read-only probe command.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationRemovalCommand {
    Probe { location_id: LocationId },
    Remove { request: LocationRemovalRequest },
}

impl LocationRemovalCommand {
    /// Return the canonical operation represented by this command.
    pub const fn op(&self) -> CommandOp {
        match self {
            Self::Probe { .. } => CommandOp::LocationRemovalProbe,
            Self::Remove { .. } => CommandOp::LocationRemove,
        }
    }

    /// Return a durable identity only for admitted removal mutations.
    pub(super) fn readback_hint(&self) -> Option<crate::error::ReadbackHint> {
        let Self::Remove { request } = self else {
            return None;
        };
        Some(crate::error::ReadbackHint::LocationRemoval {
            location_id: request_location_id(request).into_uuid(),
            expected_revision: request_expected_revision(request).get(),
            mode: request_mode(request),
            expected_root_fingerprint: request_expected_root_fingerprint(request)
                .map(|fingerprint| super::encode_hex(fingerprint.as_bytes())),
            expected_state: request_expected_state(request).map(removal_state_hint),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    location_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveBody {
    location_id: Uuid,
    expected_revision: i64,
    mode: RemovalModeBody,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RemovalModeBody {
    ListOnly,
    DeleteState {
        expected_root_fingerprint: String,
        expected_state: RemovalStateBody,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RemovalStateBody {
    Absent,
    Uninitialized,
    Workspace {
        workspace_id: Uuid,
        workspace_revision: i64,
    },
}

/// Parse one of the closed Location removal operations.
pub(super) fn parse(
    operation: CommandOp,
    payload: &Value,
) -> Result<LocationRemovalCommand, ForgeError> {
    match operation {
        CommandOp::LocationRemovalProbe => {
            let body: ProbeBody =
                super::parse_body(payload, "location.removal_probe payload is invalid")?;
            Ok(LocationRemovalCommand::Probe {
                location_id: decode_location_id(body.location_id)?,
            })
        }
        CommandOp::LocationRemove => {
            let body: RemoveBody =
                super::parse_body(payload, "location.remove payload is invalid")?;
            Ok(LocationRemovalCommand::Remove {
                request: decode_remove_body(body)?,
            })
        }
        _ => Err(ForgeError::invalid_input(
            "operation is not a Location removal operation",
        )),
    }
}

fn decode_remove_body(body: RemoveBody) -> Result<LocationRemovalRequest, ForgeError> {
    let id = decode_location_id(body.location_id)?;
    let expected_revision = decode_revision(body.expected_revision)?;
    match body.mode {
        RemovalModeBody::ListOnly => Ok(LocationRemovalRequest::ListOnly {
            id,
            expected_revision,
        }),
        RemovalModeBody::DeleteState {
            expected_root_fingerprint,
            expected_state,
        } => Ok(LocationRemovalRequest::DeleteState {
            id,
            expected_revision,
            expected_root_fingerprint: decode_root_fingerprint(&expected_root_fingerprint)?,
            expected_state: decode_state(&expected_state)?,
        }),
    }
}

fn decode_location_id(value: Uuid) -> Result<LocationId, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input("Location id must not be nil"));
    }
    Ok(LocationId::from_uuid(value))
}

fn decode_revision(value: i64) -> Result<LocationRevision, ForgeError> {
    LocationRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("Location revision is invalid"))
}

fn decode_root_fingerprint(value: &str) -> Result<WorkspaceRootFingerprint, ForgeError> {
    if value.len() != 32 {
        return Err(ForgeError::invalid_input(
            "root fingerprint must be 32 hex characters",
        ));
    }
    let bytes = super::decode_hex(value)?;
    let bytes = <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| ForgeError::invalid_input("root fingerprint is invalid"))?;
    Ok(WorkspaceRootFingerprint::from_bytes(bytes))
}

fn decode_state(value: &RemovalStateBody) -> Result<RemovalStateExpectation, ForgeError> {
    match value {
        RemovalStateBody::Absent => Ok(RemovalStateExpectation::Absent),
        RemovalStateBody::Uninitialized => Ok(RemovalStateExpectation::Uninitialized),
        RemovalStateBody::Workspace {
            workspace_id,
            workspace_revision,
        } => {
            if workspace_id.is_nil() {
                return Err(ForgeError::invalid_input(
                    "expected Workspace id must not be nil",
                ));
            }
            Ok(RemovalStateExpectation::Workspace {
                id: forge_domain::WorkspaceId::from_uuid(*workspace_id),
                revision: WorkspaceRevision::new(*workspace_revision)
                    .map_err(|_| ForgeError::invalid_input("Workspace revision is invalid"))?,
            })
        }
    }
}

/// Execute one Location removal operation through the existing control owner.
pub(super) fn execute(
    client: &ForgeControlClient,
    command: &LocationRemovalCommand,
) -> Result<Value, ForgeError> {
    match command {
        LocationRemovalCommand::Probe { location_id } => {
            let probe = client
                .location_removal_probe(*location_id)
                .map_err(|error| super::forge_error_of_client(&error))?;
            project_probe(
                *location_id,
                &probe.location,
                &probe.root_fingerprint,
                &probe.state,
            )
        }
        LocationRemovalCommand::Remove { request } => {
            let outcome = client
                .location_remove(*request)
                .map_err(|error| super::forge_error_of_client(&error))?;
            project_remove(command, &outcome)
        }
    }
}

fn project_probe(
    location_id: LocationId,
    location: &RegisteredLocation,
    root_fingerprint: &WorkspaceRootFingerprint,
    state: &RemovalStateExpectation,
) -> Result<Value, ForgeError> {
    if location.id() != location_id || validate_state(state).is_err() {
        return Err(ForgeError::resync_required(
            "Location removal probe readback is inconsistent",
        ));
    }
    let mut response = match location_json(location) {
        Value::Object(object) => object,
        Value::Array(_) | Value::Bool(_) | Value::Null | Value::Number(_) | Value::String(_) => {
            return Err(ForgeError::internal());
        }
    };
    response.insert(
        "root_fingerprint".to_owned(),
        json!(super::encode_hex(root_fingerprint.as_bytes())),
    );
    response.insert("expected_state".to_owned(), removal_state_json(state));
    response.insert(
        "observation".to_owned(),
        json!("current_state_not_historical_receipt"),
    );
    response.insert("retry_authorized".to_owned(), json!(false));
    response.insert("request_equivalence_proven".to_owned(), json!(false));
    Ok(Value::Object(response))
}

fn project_remove(
    command: &LocationRemovalCommand,
    outcome: &WorkspaceRemovalOutcome,
) -> Result<Value, ForgeError> {
    let LocationRemovalCommand::Remove { request } = command else {
        return Err(ForgeError::internal());
    };
    if validate_removed_location(request, &outcome.location).is_err() {
        return Err(ForgeError::unknown_outcome(command.readback_hint()));
    }
    let cleanup = match (request, &outcome.cleanup) {
        (LocationRemovalRequest::ListOnly { .. }, WorkspaceRemovalCleanup::ListingOnly) => {
            "listing_only"
        }
        (LocationRemovalRequest::DeleteState { .. }, WorkspaceRemovalCleanup::StateRemoved) => {
            "state_removed"
        }
        (
            LocationRemovalRequest::DeleteState { .. },
            WorkspaceRemovalCleanup::StateAlreadyAbsent,
        ) => "state_already_absent",
        (_, WorkspaceRemovalCleanup::Incomplete(_)) => {
            return Err(ForgeError::unknown_outcome(command.readback_hint()));
        }
        _ => return Err(ForgeError::unknown_outcome(command.readback_hint())),
    };
    Ok(json!({
        "location": location_json(&outcome.location),
        "cleanup": cleanup,
        "retry_authorized": false,
        "request_equivalence_proven": false,
    }))
}

fn validate_removed_location(
    request: &LocationRemovalRequest,
    location: &RegisteredLocation,
) -> Result<(), ForgeError> {
    let expected_revision = request_expected_revision(request);
    if location.id() != request_location_id(request) || location.state() != LocationState::Disabled
    {
        return Err(ForgeError::resync_required(
            "Location removal returned an unexpected disabled Location",
        ));
    }
    let unchanged = location.revision() == expected_revision;
    let advanced = expected_revision
        .checked_next()
        .is_ok_and(|next| location.revision() == next);
    if unchanged || advanced {
        Ok(())
    } else {
        Err(ForgeError::resync_required(
            "Location removal revision did not match the request fence",
        ))
    }
}

fn location_json(location: &RegisteredLocation) -> Value {
    json!({
        "location_id": location.id().into_uuid(),
        "display_name": location.name().as_str(),
        "root_path_base64": URL_SAFE_NO_PAD.encode(location.root().as_path().as_os_str().as_bytes()),
        "revision": location.revision().get(),
        "state": location_state_name(location.state()),
        "created_at_ms": location.created_at().get(),
        "updated_at_ms": location.updated_at().get(),
    })
}

const fn location_state_name(state: LocationState) -> &'static str {
    match state {
        LocationState::Enabled => "enabled",
        LocationState::Disabled => "disabled",
    }
}

fn removal_state_json(state: &RemovalStateExpectation) -> Value {
    match state {
        RemovalStateExpectation::Absent => json!({"kind": "absent"}),
        RemovalStateExpectation::Uninitialized => json!({"kind": "uninitialized"}),
        RemovalStateExpectation::Workspace { id, revision } => json!({
            "kind": "workspace",
            "workspace_id": id.into_uuid(),
            "workspace_revision": revision.get(),
        }),
    }
}

fn removal_state_hint(
    state: &RemovalStateExpectation,
) -> crate::error::LocationRemovalReadbackState {
    match state {
        RemovalStateExpectation::Absent => crate::error::LocationRemovalReadbackState::Absent,
        RemovalStateExpectation::Uninitialized => {
            crate::error::LocationRemovalReadbackState::Uninitialized
        }
        RemovalStateExpectation::Workspace { id, revision } => {
            crate::error::LocationRemovalReadbackState::Workspace {
                workspace_id: id.into_uuid(),
                workspace_revision: revision.get(),
            }
        }
    }
}

fn request_location_id(request: &LocationRemovalRequest) -> LocationId {
    match request {
        LocationRemovalRequest::ListOnly { id, .. }
        | LocationRemovalRequest::DeleteState { id, .. } => *id,
    }
}

fn request_expected_revision(request: &LocationRemovalRequest) -> LocationRevision {
    match request {
        LocationRemovalRequest::ListOnly {
            expected_revision, ..
        }
        | LocationRemovalRequest::DeleteState {
            expected_revision, ..
        } => *expected_revision,
    }
}

fn request_mode(request: &LocationRemovalRequest) -> crate::error::LocationRemovalReadbackMode {
    match request {
        LocationRemovalRequest::ListOnly { .. } => {
            crate::error::LocationRemovalReadbackMode::ListOnly
        }
        LocationRemovalRequest::DeleteState { .. } => {
            crate::error::LocationRemovalReadbackMode::DeleteState
        }
    }
}

fn request_expected_root_fingerprint(
    request: &LocationRemovalRequest,
) -> Option<WorkspaceRootFingerprint> {
    match request {
        LocationRemovalRequest::ListOnly { .. } => None,
        LocationRemovalRequest::DeleteState {
            expected_root_fingerprint,
            ..
        } => Some(*expected_root_fingerprint),
    }
}

fn request_expected_state(request: &LocationRemovalRequest) -> Option<&RemovalStateExpectation> {
    match request {
        LocationRemovalRequest::ListOnly { .. } => None,
        LocationRemovalRequest::DeleteState { expected_state, .. } => Some(expected_state),
    }
}

fn validate_state(state: &RemovalStateExpectation) -> Result<(), ForgeError> {
    match state {
        RemovalStateExpectation::Absent | RemovalStateExpectation::Uninitialized => Ok(()),
        RemovalStateExpectation::Workspace { id, revision } => {
            if id.into_uuid().is_nil() || revision.get() < 1 {
                Err(ForgeError::resync_required(
                    "Location removal probe returned an invalid Workspace state",
                ))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use forge_domain::{LocationName, LocationRoot, TimestampMillis};

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn payload(operation: CommandOp) -> Result<Value, ForgeError> {
        let payload = match operation {
            CommandOp::LocationRemovalProbe => json!({
                "location_id": id(1),
            }),
            CommandOp::LocationRemove => json!({
                "location_id": id(1),
                "expected_revision": 1,
                "mode": {"kind": "list_only"},
            }),
            _ => {
                return Err(ForgeError::invalid_input(
                    "unsupported Location removal test operation",
                ));
            }
        };
        Ok(payload)
    }

    fn location(state: LocationState, revision: i64) -> Result<RegisteredLocation, ForgeError> {
        Ok(RegisteredLocation::from_parts_with_revision(
            LocationId::from_uuid(id(1)),
            LocationName::new("test Location").map_err(|_| ForgeError::internal())?,
            LocationRoot::from_canonical(std::path::PathBuf::from("/tmp/test-location"))
                .map_err(|_| ForgeError::internal())?,
            state,
            TimestampMillis::new(1).map_err(|_| ForgeError::internal())?,
            TimestampMillis::new(2).map_err(|_| ForgeError::internal())?,
            LocationRevision::new(revision).map_err(|_| ForgeError::internal())?,
        ))
    }

    #[test]
    fn parser_rejects_nil_ids_unknown_fields_and_invalid_confirmation_values()
    -> Result<(), ForgeError> {
        let mut probe = payload(CommandOp::LocationRemovalProbe)?;
        probe["location_id"] = json!(Uuid::nil());
        assert!(parse(CommandOp::LocationRemovalProbe, &probe).is_err());

        let mut list = payload(CommandOp::LocationRemove)?;
        list["unexpected"] = json!(true);
        assert!(parse(CommandOp::LocationRemove, &list).is_err());

        let mut delete = json!({
            "location_id": id(1),
            "expected_revision": 1,
            "mode": {
                "kind": "delete_state",
                "expected_root_fingerprint": "not-hex",
                "expected_state": {"kind": "absent"},
            },
        });
        assert!(parse(CommandOp::LocationRemove, &delete).is_err());
        delete["mode"]["expected_root_fingerprint"] = json!("00".repeat(16));
        delete["mode"]["expected_state"] = json!({
            "kind": "workspace",
            "workspace_id": Uuid::nil(),
            "workspace_revision": 1,
        });
        assert!(parse(CommandOp::LocationRemove, &delete).is_err());
        Ok(())
    }

    #[test]
    fn readback_hints_are_absent_for_probe_and_exact_for_delete() -> Result<(), ForgeError> {
        let probe = parse(
            CommandOp::LocationRemovalProbe,
            &payload(CommandOp::LocationRemovalProbe)?,
        )?;
        assert!(probe.readback_hint().is_none());

        let delete = parse(
            CommandOp::LocationRemove,
            &json!({
                "location_id": id(1),
                "expected_revision": 2,
                "mode": {
                    "kind": "delete_state",
                    "expected_root_fingerprint": "00112233445566778899aabbccddeeff",
                    "expected_state": {"kind": "uninitialized"},
                },
            }),
        )?;
        let hint = delete.readback_hint().ok_or_else(ForgeError::internal)?;
        assert!(matches!(
            hint,
            crate::error::ReadbackHint::LocationRemoval {
                location_id,
                expected_revision: 2,
                ..
            } if location_id == id(1)
        ));
        Ok(())
    }

    #[test]
    fn probe_projection_is_flat_current_observation_without_retry_authority()
    -> Result<(), ForgeError> {
        let location = location(LocationState::Enabled, 1)?;
        let fingerprint = WorkspaceRootFingerprint::from_bytes([0xAB; 16]);
        let response = project_probe(
            LocationId::from_uuid(id(1)),
            &location,
            &fingerprint,
            &RemovalStateExpectation::Uninitialized,
        )?;
        assert_eq!(response["location_id"], json!(id(1)));
        assert_eq!(response["revision"], 1);
        assert_eq!(response["expected_state"]["kind"], "uninitialized");
        assert_eq!(response["retry_authorized"], false);
        assert_eq!(response["request_equivalence_proven"], false);
        Ok(())
    }

    #[test]
    fn malformed_disabled_location_returns_unknown_with_exact_hint() -> Result<(), ForgeError> {
        let command = parse(
            CommandOp::LocationRemove,
            &payload(CommandOp::LocationRemove)?,
        )?;
        let outcome = WorkspaceRemovalOutcome {
            location: location(LocationState::Enabled, 1)?,
            cleanup: WorkspaceRemovalCleanup::ListingOnly,
        };
        let error = project_remove(&command, &outcome)
            .err()
            .ok_or_else(ForgeError::internal)?;
        assert_eq!(error.code(), ErrorCode::UnknownOutcome);
        let hint = command.readback_hint();
        assert_eq!(error.readback(), hint.as_ref());
        Ok(())
    }

    #[test]
    fn incomplete_cleanup_is_unknown_without_native_detail() -> Result<(), ForgeError> {
        let command = parse(
            CommandOp::LocationRemove,
            &payload(CommandOp::LocationRemove)?,
        )?;
        let outcome = WorkspaceRemovalOutcome {
            location: location(LocationState::Disabled, 2)?,
            cleanup: WorkspaceRemovalCleanup::Incomplete(forge_control::WorkspaceRemovalFailure {
                detail: "private filesystem detail".to_owned(),
            }),
        };
        let error = project_remove(&command, &outcome)
            .err()
            .ok_or_else(ForgeError::internal)?;
        assert_eq!(error.code(), ErrorCode::UnknownOutcome);
        assert!(!error.message().contains("private filesystem detail"));
        Ok(())
    }

    #[test]
    fn successful_list_only_projection_keeps_disabled_location_and_flags() -> Result<(), ForgeError>
    {
        let command = parse(
            CommandOp::LocationRemove,
            &payload(CommandOp::LocationRemove)?,
        )?;
        let outcome = WorkspaceRemovalOutcome {
            location: location(LocationState::Disabled, 2)?,
            cleanup: WorkspaceRemovalCleanup::ListingOnly,
        };
        let response = project_remove(&command, &outcome)?;
        assert_eq!(response["location"]["location_id"], json!(id(1)));
        assert_eq!(response["location"]["revision"], 2);
        assert_eq!(response["location"]["state"], "disabled");
        assert_eq!(response["cleanup"], "listing_only");
        assert_eq!(response["retry_authorized"], false);
        assert_eq!(response["request_equivalence_proven"], false);
        Ok(())
    }
}
