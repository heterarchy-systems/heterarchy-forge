//! Typed HTTP adapter for the Workspace queue-capacity preference.
//!
//! The persisted preference remains owned by `forge-control` and SQLite. This
//! module only decodes the closed wire payload, forwards the exact CAS request,
//! and reports the saved record alongside a separate runtime observation. A
//! runtime observation never becomes a second preference or policy authority.

use forge_control::{
    ForgeControlClient, QueueCapacity, QueueRuntimeError, ResolvedWorkspaceScope,
    WorkspaceQueueSettingsRequest,
};
use forge_domain::TimestampMillis;
use forge_persistence::{QueueSettings, QueueSettingsRevision, RegisteredQueueSettings};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CommandOp, ScopeDto, decode_scope};
use crate::error::{ErrorCode, ForgeError};

const MAX_REVISION: i64 = i64::MAX;

/// One validated Workspace queue-preference replacement.
///
/// The expected revision is deliberately optional: `None` is the only valid
/// first insert fence, while an existing record must be updated with its
/// positive revision. The worker supplies the actual observation time after
/// command admission; no caller timestamp is accepted on this wire.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuePreferenceCommand {
    pub(super) scope: ResolvedWorkspaceScope,
    pub(super) settings: QueueSettings,
    pub(super) expected_revision: Option<QueueSettingsRevision>,
}

impl QueuePreferenceCommand {
    /// Return the operation represented by this command.
    pub const fn op(&self) -> CommandOp {
        CommandOp::WorkspaceQueueSettingsReplace
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    scope: ScopeDto,
    capacity: u16,
    expected_revision: Option<i64>,
}

/// Parse the closed `workspace.queue.settings.replace` payload.
pub(super) fn parse(payload: &Value) -> Result<QueuePreferenceCommand, ForgeError> {
    // Serde's nullable Option decoding also accepts an omitted field. Require
    // the insert/update fence explicitly without treating null as omission.
    if !payload
        .as_object()
        .is_some_and(|body| body.contains_key("expected_revision"))
    {
        return Err(ForgeError::invalid_input(
            "queue preference expected_revision is required; use null for the first insert",
        ));
    }
    let body: Body = super::parse_body(
        payload,
        "workspace.queue.settings.replace payload is invalid",
    )?;
    let scope = decode_scope_checked(&body.scope)?;
    let capacity = decode_capacity(body.capacity)?;
    let expected_revision = body.expected_revision.map(decode_revision).transpose()?;
    Ok(QueuePreferenceCommand {
        scope,
        settings: QueueSettings::new(capacity),
        expected_revision,
    })
}

/// Replace the durable preference, then observe the effective runtime through
/// separate native reads. The saved record is retained even when the runtime
/// observation or its post-scope check is unavailable.
pub(super) fn execute(
    client: &ForgeControlClient,
    command: &QueuePreferenceCommand,
) -> Result<Value, ForgeError> {
    let saved = client
        .replace_workspace_queue_settings(WorkspaceQueueSettingsRequest {
            scope: command.scope.clone(),
            settings: command.settings,
            expected_revision: command.expected_revision,
            // The bridge worker owns the real observation clock. Zero is only
            // the deterministic native constructor input for this adapter.
            observed_at: TimestampMillis::new(0).map_err(|_| ForgeError::internal())?,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;

    // The saved record is authoritative for the mutation result. These reads
    // are deliberately performed after the save and remain non-atomic with
    // the runtime snapshot; observation failures are projected below without
    // converting the confirmed save into a failed command.
    let pre_scope = client.workspace_queue_settings(command.scope.clone());
    match pre_scope {
        Ok(Some(pre_saved)) => {
            let runtime = client.workspace_queue_status(command.scope.workspace_id());
            let post_scope = client.workspace_queue_settings(command.scope.clone());
            project_committed(command, &saved, Ok(Some(pre_saved)), runtime, post_scope)
        }
        Ok(None) => committed_observation_error(command, &saved, ForgeError::internal()),
        Err(error) => {
            committed_observation_error(command, &saved, super::forge_error_of_client(&error))
        }
    }
}

fn committed_observation_error(
    command: &QueuePreferenceCommand,
    saved: &RegisteredQueueSettings,
    error: ForgeError,
) -> Result<Value, ForgeError> {
    let observation = observation_error(error);
    committed_projection(
        command,
        saved,
        observation.effective_runtime,
        observation.status,
        observation.error.as_ref(),
    )
}

/// Return the durable identity used by the HTTP layer when an admitted
/// mutation loses its reply. The parent transport attaches this hint only to
/// an `UNKNOWN_OUTCOME` response; it does not authorize a blind retry.
pub(super) fn readback_hint(command: &QueuePreferenceCommand) -> crate::error::ReadbackHint {
    crate::error::ReadbackHint::WorkspaceQueueSettings {
        workspace_id: command.scope.workspace_id().into_uuid(),
        expected_preference_revision: command.expected_revision.map(QueueSettingsRevision::get),
        requested_capacity: command.settings.capacity().slots(),
    }
}

fn project_committed(
    command: &QueuePreferenceCommand,
    saved: &RegisteredQueueSettings,
    pre_scope: Result<Option<RegisteredQueueSettings>, forge_control::ControlClientError>,
    runtime: Result<forge_control::QueueStatus, QueueRuntimeError>,
    post_scope: Result<Option<RegisteredQueueSettings>, forge_control::ControlClientError>,
) -> Result<Value, ForgeError> {
    let observation = observe_runtime(saved, pre_scope, runtime, post_scope);

    committed_projection(
        command,
        saved,
        observation.effective_runtime,
        observation.status,
        observation.error.as_ref(),
    )
}

struct RuntimeObservation {
    effective_runtime: Value,
    status: &'static str,
    error: Option<ForgeError>,
}

fn observe_runtime(
    saved: &RegisteredQueueSettings,
    pre_scope: Result<Option<RegisteredQueueSettings>, forge_control::ControlClientError>,
    runtime: Result<forge_control::QueueStatus, QueueRuntimeError>,
    post_scope: Result<Option<RegisteredQueueSettings>, forge_control::ControlClientError>,
) -> RuntimeObservation {
    let pre_saved = match pre_scope {
        Ok(value) => value,
        Err(error) => return observation_error(super::forge_error_of_client(&error)),
    };
    let post_saved = match post_scope {
        Ok(value) => value,
        Err(error) => return observation_error(super::forge_error_of_client(&error)),
    };
    let Some(pre_saved) = pre_saved else {
        return observation_error(ForgeError::internal());
    };
    let Some(post_saved) = post_saved else {
        return observation_error(ForgeError::internal());
    };
    let status = match runtime {
        Ok(status) => status,
        Err(error) => {
            return observation_error(super::queue_observation::queue_runtime_error(&error));
        }
    };
    let effective_runtime = super::queue_observation::queue_status_json(status);
    let records_match = pre_saved == *saved && post_saved == *saved;
    let status = if runtime_matches_saved(
        status.initialized(),
        status.target_capacity(),
        status.persisted_revision(),
        saved,
        records_match,
    ) {
        "matched"
    } else {
        "different_or_pending"
    };
    RuntimeObservation {
        effective_runtime,
        status,
        error: None,
    }
}

fn observation_error(error: ForgeError) -> RuntimeObservation {
    let status = if is_scope_error(error.code()) {
        "scope_changed"
    } else {
        "unavailable"
    };
    RuntimeObservation {
        effective_runtime: Value::Null,
        status,
        error: Some(error),
    }
}

fn runtime_matches_saved(
    initialized: bool,
    target_capacity: QueueCapacity,
    persisted_revision: Option<u64>,
    saved: &RegisteredQueueSettings,
    records_match: bool,
) -> bool {
    initialized
        && records_match
        && target_capacity == saved.capacity()
        && persisted_revision == Some(saved.revision().get())
}

fn is_scope_error(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::StaleRevision
            | ErrorCode::ResyncRequired
            | ErrorCode::WorkspaceIdentityConflict
            | ErrorCode::WorkspaceRootConflict
            | ErrorCode::WorkspaceScopeOverlap
            | ErrorCode::WorkspaceConfinementDenied
            | ErrorCode::InvalidPathKind
    )
}

fn committed_projection(
    command: &QueuePreferenceCommand,
    saved: &RegisteredQueueSettings,
    effective_runtime: Value,
    application_status: &'static str,
    application_error: Option<&ForgeError>,
) -> Result<Value, ForgeError> {
    let saved_preference = super::queue_observation::saved_preference_json(saved);
    let mut response = json!({
        "scope": super::scope_json(&command.scope)?,
        "save_status": "committed",
        "saved_preference": saved_preference,
        "runtime_application": runtime_application_json(application_status, application_error),
        "observation": "separate_non_atomic_reads",
        "retry_authorized": false,
        "request_equivalence_proven": false,
    });
    response["effective_runtime"] = effective_runtime;
    Ok(response)
}

fn runtime_application_json(status: &'static str, error: Option<&ForgeError>) -> Value {
    json!({
        "status": status,
        "error": error,
    })
}

fn decode_scope_checked(scope: &ScopeDto) -> Result<ResolvedWorkspaceScope, ForgeError> {
    if scope.workspace_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "queue preference scope workspace id must not be nil",
        ));
    }
    if scope.locator.location_id.is_nil() {
        return Err(ForgeError::invalid_input(
            "queue preference scope location id must not be nil",
        ));
    }
    decode_scope(scope)
}

fn decode_capacity(value: u16) -> Result<QueueCapacity, ForgeError> {
    match value {
        32 => Ok(QueueCapacity::C32),
        64 => Ok(QueueCapacity::C64),
        128 => Ok(QueueCapacity::C128),
        256 => Ok(QueueCapacity::C256),
        _ => Err(ForgeError::invalid_input(
            "queue preference capacity must be one of 32, 64, 128, or 256",
        )),
    }
}

fn decode_revision(value: i64) -> Result<QueueSettingsRevision, ForgeError> {
    if !(1..=MAX_REVISION).contains(&value) {
        return Err(ForgeError::invalid_input(
            "queue preference expected revision must be within 1..=i64::MAX",
        ));
    }
    QueueSettingsRevision::new(
        u64::try_from(value)
            .map_err(|_| ForgeError::invalid_input("queue preference revision is invalid"))?,
    )
    .map_err(|_| ForgeError::invalid_input("queue preference revision is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

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

    fn payload(capacity: u16, expected_revision: Value) -> Value {
        let mut value = json!({
            "scope": scope_payload(),
            "capacity": capacity,
        });
        value["expected_revision"] = expected_revision;
        value
    }

    fn parsed(capacity: u16, expected_revision: Value) -> Result<QueuePreferenceCommand, String> {
        parse(&payload(capacity, expected_revision)).map_err(|error| error.message().to_owned())
    }

    #[test]
    fn parser_accepts_closed_capacity_set_and_explicit_insert_fence()
    -> Result<(), Box<dyn std::error::Error>> {
        for capacity in [32, 64, 128, 256] {
            let command = parsed(capacity, Value::Null)?;
            assert_eq!(command.settings.capacity().slots(), capacity);
            assert_eq!(command.expected_revision, None);
            assert_eq!(command.op(), CommandOp::WorkspaceQueueSettingsReplace);
        }
        Ok(())
    }

    #[test]
    fn parser_requires_nullable_cas_and_rejects_invalid_scope_or_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut missing = payload(64, Value::Null);
        missing
            .as_object_mut()
            .ok_or("payload object missing")?
            .remove("expected_revision");
        assert!(parse(&missing).is_err());

        for revision in [0, -1] {
            assert!(parse(&payload(64, json!(revision))).is_err());
        }
        assert!(parse(&payload(64, json!(i64::MAX))).is_ok());
        assert!(parse(&payload(31, Value::Null)).is_err());

        let mut nil_workspace = payload(64, Value::Null);
        nil_workspace["scope"]["workspace_id"] = json!(Uuid::nil());
        assert!(parse(&nil_workspace).is_err());

        let mut nil_location = payload(64, Value::Null);
        nil_location["scope"]["locator"]["location_id"] = json!(Uuid::nil());
        assert!(parse(&nil_location).is_err());
        Ok(())
    }

    #[test]
    fn parser_rejects_caller_clock_and_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        let mut payload = payload(64, Value::Null);
        payload["observed_at_ms"] = json!(10);
        assert!(parse(&payload).is_err());
        payload
            .as_object_mut()
            .ok_or("payload object missing")?
            .remove("observed_at_ms");
        payload["unexpected"] = json!(true);
        assert!(parse(&payload).is_err());
        Ok(())
    }

    #[test]
    fn readback_hint_keeps_preference_cas_identity_without_retry_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = parsed(128, json!(7))?;
        assert_eq!(
            readback_hint(&command),
            crate::error::ReadbackHint::WorkspaceQueueSettings {
                workspace_id: id(1),
                expected_preference_revision: Some(7),
                requested_capacity: 128,
            }
        );
        Ok(())
    }

    #[test]
    fn committed_projection_keeps_saved_record_when_runtime_is_different()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = parsed(256, Value::Null)?;
        let saved = RegisteredQueueSettings::initial(command.settings, TimestampMillis::new(0)?);
        let response = committed_projection(
            &command,
            &saved,
            json!({"capacity": 32}),
            "different_or_pending",
            None,
        )
        .map_err(|error| error.message().to_owned())?;
        assert_eq!(response["save_status"], "committed");
        assert_eq!(response["saved_preference"]["capacity"], 256);
        assert_eq!(response["effective_runtime"]["capacity"], 32);
        assert_eq!(
            response["runtime_application"]["status"],
            "different_or_pending"
        );
        assert_eq!(response["runtime_application"]["error"], Value::Null);
        Ok(())
    }

    #[test]
    fn committed_projection_keeps_saved_record_when_runtime_is_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = parsed(64, Value::Null)?;
        let saved = RegisteredQueueSettings::initial(command.settings, TimestampMillis::new(0)?);
        let response = project_committed(
            &command,
            &saved,
            Ok(Some(saved)),
            Err(QueueRuntimeError::Closed),
            Ok(Some(saved)),
        )
        .map_err(|error| error.message().to_owned())?;
        assert_eq!(response["save_status"], "committed");
        assert_eq!(response["saved_preference"]["capacity"], 64);
        assert_eq!(response["effective_runtime"], Value::Null);
        assert_eq!(response["runtime_application"]["status"], "unavailable");
        assert_eq!(
            response["runtime_application"]["error"]["code"],
            "DEPENDENCY_UNAVAILABLE"
        );
        Ok(())
    }

    #[test]
    fn runtime_match_requires_initialized_current_revision_and_exact_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = parsed(128, Value::Null)?;
        let saved = RegisteredQueueSettings::initial(command.settings, TimestampMillis::new(0)?);
        let revision = saved.revision().get();
        assert!(runtime_matches_saved(
            true,
            saved.capacity(),
            Some(revision),
            &saved,
            true,
        ));
        // The default/uninitialized runtime may have the same capacity but is
        // not proof that the persisted preference was applied.
        assert!(!runtime_matches_saved(
            false,
            saved.capacity(),
            Some(revision),
            &saved,
            true,
        ));
        // A superseding record with the same capacity is not equivalent to
        // this request's saved record.
        assert!(!runtime_matches_saved(
            true,
            saved.capacity(),
            Some(revision + 1),
            &saved,
            false,
        ));
        Ok(())
    }

    #[test]
    fn observation_errors_keep_scope_and_runtime_failures_distinct() {
        let scope = observation_error(ForgeError::resync_required("scope changed"));
        assert_eq!(scope.status, "scope_changed");
        assert_eq!(scope.effective_runtime, Value::Null);
        assert_eq!(
            scope.error.as_ref().map(ForgeError::code),
            Some(ErrorCode::ResyncRequired)
        );

        let runtime = observation_error(ForgeError::dependency_unavailable());
        assert_eq!(runtime.status, "unavailable");
        assert_eq!(runtime.effective_runtime, Value::Null);
        assert_eq!(
            runtime.error.as_ref().map(ForgeError::code),
            Some(ErrorCode::DependencyUnavailable)
        );
    }
}
