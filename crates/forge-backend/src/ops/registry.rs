//! Location topology and workspace-level observability ops.
//!
//! `location.register` / `location.state` expose the existing operator
//! `LocationService` semantics at the backend boundary; the single-owner
//! control worker keeps exclusive durable access. `workspace.doctor` and
//! `verification.projection` are read-only Forge observability projections.
//! All four are issuer-only in this slice: the remote session authority is
//! never consulted and no Orchestration policy is interpreted here.

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use forge_control::WorkspaceDoctorRequest;
use forge_control::{
    ForgeControlClient, RegisterLocationRequest, ResolvedWorkspaceScope,
    WorkspaceDoctorAggregateOutcome as Outcome,
    WorkspaceDoctorObservationConsistency as Consistency,
};
use forge_domain::{LocationId, LocationState, SetLocationState};
use forge_workspace::GitLocalStateDoctor as GitState;

use crate::error::ForgeError;

use super::{Command, ParseResult, ScopeDto, decode_scope, decode_timestamp};

pub(super) fn workspace_registration_readback_hint(
    request: &forge_control::WorkspaceRegistrationRequest,
) -> crate::error::ReadbackHint {
    crate::error::ReadbackHint::WorkspaceRegistration {
        locator: request.locator().encode(),
        proposed_workspace_id: request.proposed_workspace_id().into_uuid(),
        expected_root_fingerprint: super::encode_hex(
            request.expected_root_fingerprint().as_bytes(),
        ),
    }
}

pub(super) fn location_state_readback_hint(
    request: &SetLocationState,
) -> crate::error::ReadbackHint {
    crate::error::ReadbackHint::LocationState {
        location_id: request.id().into_uuid(),
        expected_revision: request.expected_revision().get(),
        desired_state: match request.state() {
            LocationState::Enabled => "enabled",
            LocationState::Disabled => "disabled",
        }
        .to_owned(),
    }
}

pub(super) fn parse_workspace_inventory(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        location_id: Uuid,
        expected_revision: i64,
    }
    let body: Body = super::parse_body(payload, "workspace.inventory payload is invalid")?;
    Ok(Command::WorkspaceInventory {
        request_id,
        location_id: LocationId::from_uuid(body.location_id),
        expected_revision: forge_domain::LocationRevision::new(body.expected_revision)
            .map_err(|_| ForgeError::invalid_input("Location revision is invalid"))?,
    })
}

pub(super) fn execute_workspace_inventory(
    client: &ForgeControlClient,
    location_id: LocationId,
    expected_revision: forge_domain::LocationRevision,
) -> Result<Value, ForgeError> {
    let inventory = client
        .registered_workspace_inventory(location_id, expected_revision)
        .map_err(|error| ForgeError::from_control_client_error(&error))?;
    let entries = inventory.entries().iter().map(|entry| match entry {
        forge_control::WorkspaceInventoryEntry::Registered { scope, workspace, display_name } => json!({
            "status": "registered", "locator": scope.locator().encode(),
            "workspace": registration_workspace_json(workspace), "display_name": display_name,
        }),
        forge_control::WorkspaceInventoryEntry::Unavailable { locator, code, known_workspace_id } => json!({
            "status": "unavailable", "locator": locator.encode(),
            "reason": code.as_str(), "known_workspace_id": known_workspace_id.map(forge_domain::WorkspaceId::into_uuid),
        }),
    }).collect::<Vec<_>>();
    Ok(json!({ "location_id": inventory.location_id().into_uuid(),
        "location_revision": inventory.location_revision().get(), "entries": entries }))
}

pub(super) fn parse_workspace_register(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        locator: String,
        proposed_workspace_id: Uuid,
        expected_root_fingerprint: String,
        observed_at_ms: i64,
    }
    let body: Body = super::parse_body(payload, "workspace.register payload is invalid")?;
    let locator = decode_registration_locator(&body.locator)?;
    if body.expected_root_fingerprint.len() != 32 {
        return Err(ForgeError::invalid_input(
            "root fingerprint must be 32 hex characters",
        ));
    }
    let bytes = super::decode_hex(&body.expected_root_fingerprint)?;
    let bytes = <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| ForgeError::invalid_input("root fingerprint is invalid"))?;
    let request = forge_control::WorkspaceRegistrationRequest::new(
        locator,
        forge_domain::WorkspaceId::from_uuid(body.proposed_workspace_id),
        forge_domain::WorkspaceRootFingerprint::from_bytes(bytes),
        decode_timestamp(body.observed_at_ms)?,
    )
    .map_err(|_| ForgeError::invalid_input("proposed Workspace identity is invalid"))?;
    Ok(Command::WorkspaceRegister {
        request_id,
        request: Box::new(request),
    })
}

pub(super) fn parse_workspace_registration_probe(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        locator: String,
    }
    let body: Body = super::parse_body(payload, "workspace.registration_probe payload is invalid")?;
    Ok(Command::WorkspaceRegistrationProbe {
        request_id,
        locator: decode_registration_locator(&body.locator)?,
    })
}

fn decode_registration_locator(value: &str) -> Result<forge_control::WorkspaceLocator, ForgeError> {
    forge_control::WorkspaceLocator::decode(value)
        .map_err(|_| ForgeError::invalid_input("encoded Workspace locator is invalid"))
}

pub(super) fn execute_workspace_registration_probe(
    client: &ForgeControlClient,
    locator: &forge_control::WorkspaceLocator,
) -> Result<Value, ForgeError> {
    let probe = client
        .probe_workspace_registration(locator.clone())
        .map_err(|error| ForgeError::from_control_client_error(&error))?;
    Ok(json!({
        "locator": probe.locator.encode(),
        "root_fingerprint": super::encode_hex(probe.root_fingerprint.as_bytes()),
        "workspace": probe.workspace.as_ref().map(registration_workspace_json),
        "observation": "current_state_not_historical_receipt",
    }))
}

pub(super) fn execute_workspace_register(
    client: &ForgeControlClient,
    request: &forge_control::WorkspaceRegistrationRequest,
) -> Result<Value, ForgeError> {
    let outcome = client
        .register_workspace(request.clone())
        .map_err(|error| ForgeError::from_control_client_error(&error))?;
    match outcome {
        forge_control::WorkspaceRegistrationOutcome::Confirmed(workspace) => Ok(json!({
            "status": "confirmed", "confirmed": true,
            "workspace": registration_workspace_json(&workspace),
            "locator": request.locator().encode(),
        })),
        forge_control::WorkspaceRegistrationOutcome::CommittedButUnconfirmed {
            workspace,
            reason,
        } => Ok(json!({
            "status": "committed_but_unconfirmed", "confirmed": false,
            "workspace": registration_workspace_json(&workspace),
            "locator": request.locator().encode(),
            "reason": registration_reason(reason),
            "recovery_action": "read_back",
        })),
    }
}

fn registration_workspace_json(workspace: &forge_domain::RegisteredWorkspace) -> Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::os::unix::ffi::OsStrExt;
    json!({
        "workspace_id": workspace.id().into_uuid(),
        "workspace_revision": workspace.revision().get(),
        "location_id": workspace.location_id().into_uuid(),
        "root_path_base64": URL_SAFE_NO_PAD.encode(workspace.root().as_path().as_os_str().as_bytes()),
        "root_fingerprint": super::encode_hex(workspace.root_fingerprint().as_bytes()),
        "created_at_ms": workspace.created_at().get(),
        "updated_at_ms": workspace.updated_at().get(),
    })
}

const fn registration_reason(reason: forge_control::WorkspaceRevalidationReason) -> &'static str {
    use forge_control::WorkspaceRevalidationReason as Reason;
    match reason {
        Reason::LocationRevisionChanged => "location_revision_changed",
        Reason::LocationUnavailable => "location_unavailable",
        Reason::LocationDisabled => "location_disabled",
        Reason::CandidateStale => "candidate_stale",
        Reason::CandidateRootChanged => "candidate_root_changed",
        Reason::CandidateFingerprintChanged => "candidate_fingerprint_changed",
        Reason::LayoutInvalid => "layout_invalid",
        Reason::WorkspaceIdentityChanged => "workspace_identity_changed",
    }
}

pub(super) fn parse_location_register_payload(
    payload: &Value,
) -> Result<RegisterLocationRequest, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        location_id: Uuid,
        name: String,
        path: String,
        observed_at_ms: i64,
    }
    let body: Body = super::parse_body(payload, "location.register payload is invalid")?;
    if body.name.trim().is_empty() {
        return Err(ForgeError::invalid_input("location name must not be empty"));
    }
    if !std::path::Path::new(body.path.as_str()).is_absolute() {
        return Err(ForgeError::invalid_input("location path must be absolute"));
    }
    Ok(RegisterLocationRequest {
        id: LocationId::from_uuid(body.location_id),
        name: body.name,
        selected_path: std::path::PathBuf::from(body.path),
        observed_at: decode_timestamp(body.observed_at_ms)?,
    })
}

pub(super) fn parse_location_state_payload(
    payload: &Value,
) -> Result<SetLocationState, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        location_id: Uuid,
        expected_revision: i64,
        state: LocationStateDto,
        observed_at_ms: i64,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum LocationStateDto {
        Enabled,
        Disabled,
    }
    let body: Body = super::parse_body(payload, "location.state payload is invalid")?;
    let expected_revision = forge_domain::LocationRevision::new(body.expected_revision)
        .map_err(|_| ForgeError::invalid_input("location revision is invalid"))?;
    let state = match body.state {
        LocationStateDto::Enabled => LocationState::Enabled,
        LocationStateDto::Disabled => LocationState::Disabled,
    };
    Ok(SetLocationState::new(
        LocationId::from_uuid(body.location_id),
        expected_revision,
        state,
        decode_timestamp(body.observed_at_ms)?,
    ))
}

pub(super) fn parse_workspace_doctor(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
    }
    let body: Body = super::parse_body(payload, "workspace.doctor payload is invalid")?;
    Ok(Command::WorkspaceDoctor {
        request_id,
        scope: decode_scope(&body.scope)?,
    })
}

pub(super) fn parse_verification_projection(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
    }
    let body: Body = super::parse_body(payload, "verification.projection payload is invalid")?;
    Ok(Command::VerificationProjection {
        request_id,
        scope: decode_scope(&body.scope)?,
    })
}

pub(super) fn execute_location_register(
    client: &ForgeControlClient,
    request: &RegisterLocationRequest,
) -> Result<Value, ForgeError> {
    let location = client
        .register_location(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(location_json(&location))
}

pub(super) fn execute_location_state(
    client: &ForgeControlClient,
    command: &SetLocationState,
) -> Result<Value, ForgeError> {
    let location = client
        .set_location_state(command.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(location_json(&location))
}

fn location_json(location: &forge_domain::RegisteredLocation) -> Value {
    json!({
        "location_id": location.id().into_uuid(),
        "display_name": location.name().as_str(),
        "revision": location.revision().get(),
        "state": match location.state() {
            LocationState::Enabled => "enabled",
            LocationState::Disabled => "disabled",
        },
    })
}

pub(super) fn execute_workspace_doctor(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
) -> Result<Value, ForgeError> {
    let result = client
        .workspace_doctor(WorkspaceDoctorRequest {
            scope: scope.clone(),
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let report = result.report();
    let checkpoints = result.checkpoint_store();
    let diffs = result.diff_artifacts();
    Ok(json!({
        "outcome": match result.outcome() {
            Outcome::Healthy => "healthy",
            Outcome::RecoveryRequired => "recovery_required",
            Outcome::Damaged => "damaged",
            Outcome::Incomplete => "incomplete",
        },
        "observation_consistency": match result.observation_consistency() {
            Consistency::Stable => "stable",
            Consistency::Changed => "changed",
        },
        "git_local_state": match result.git_local_state() {
            GitState::NotGitRepository => "not_git_repository",
            GitState::Verified => "verified",
            GitState::MissingLocalExclude => "missing_local_exclude",
            GitState::TrackedStateConflict => "tracked_state_conflict",
            GitState::StateVisibleToGit => "state_visible_to_git",
            GitState::Unavailable => "unavailable",
        },
        "report": {
            "damaged": report.is_damaged(),
            "requires_recovery": report.requires_recovery(),
        },
        "checkpoint_store": {
            "applicable": checkpoints.applicable(),
            "store_present": checkpoints.store_present(),
            "finding_count": checkpoints.findings().len(),
            "database_truncated": checkpoints.database_truncated(),
            "refs_truncated": checkpoints.refs_truncated(),
        },
        "diff_artifacts": {
            "finding_count": diffs.findings().len(),
            "complete": diffs.is_complete(),
        },
    }))
}

pub(super) fn execute_verification_projection(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
) -> Result<Value, ForgeError> {
    use forge_domain::{VerificationProjectionState, VerificationRunDisposition};
    let projection = client
        .submit_verification_projection(scope.clone())
        .map_err(|error| super::forge_error_of_client(&error))?
        .recv()
        .map_err(|error| super::forge_error_of_client(&error))?;
    let entries = projection
        .entries()
        .iter()
        .map(|entry| {
            json!({
                "command_id": entry.command_id().as_str(),
                "execution_id": entry.execution_id().into_uuid(),
                "state": match entry.state() {
                    VerificationProjectionState::Running => "running",
                    VerificationProjectionState::Passed => "passed",
                    VerificationProjectionState::Failed => "failed",
                },
                "disposition": entry.disposition().map(|disposition| match disposition {
                    VerificationRunDisposition::Accepted => "accepted",
                    VerificationRunDisposition::Rejected => "rejected",
                    VerificationRunDisposition::Incomplete => "incomplete",
                    VerificationRunDisposition::RecoveryRequired => "recovery_required",
                }),
                "updated_at_ms": entry.updated_at().get(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "entries": entries,
        "entry_count": entries.len(),
    }))
}
