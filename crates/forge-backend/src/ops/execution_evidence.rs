//! Native-equivalent authorized execution lookup and generated evidence.

use forge_control::ForgeControlClient;
use forge_domain::{
    ExecutionFailureCode, ExecutionId, ExecutionState, GeneratedArtifactKind,
    GeneratedPackageManifest,
};
use serde_json::{Value, json};

use super::execution::{ExecutionAuthorityDto, ExecutionAuthoritySpec, parse_authority};
use crate::error::ForgeError;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionGetBody {
    authority: ExecutionAuthorityDto,
}

/// Validated authority-scoped execution lookup payload. The authority tuple
/// remains private to this adapter; the parent command enum only needs the
/// durable execution identity for readback hints.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionGetCommand {
    authority: ExecutionAuthoritySpec,
}

impl ExecutionGetCommand {
    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.authority.execution_id
    }
}

/// Parse one exact authority-scoped execution lookup.
pub(super) fn parse(value: &Value) -> Result<ExecutionGetCommand, ForgeError> {
    let body: ExecutionGetBody = super::parse_body(value, "execution.get payload is invalid")?;
    Ok(ExecutionGetCommand {
        authority: parse_authority(body.authority)?,
    })
}

/// Read one authorized execution and project the native bounded execution
/// summary plus its optional generated-package manifest.
pub(super) fn execute_get(
    client: &ForgeControlClient,
    command: &ExecutionGetCommand,
) -> Result<Value, ForgeError> {
    let snapshot = client
        .execution_get_authorized_with_generated_package(
            command.authority.agent_authority.clone(),
            command.authority.execution_id,
        )
        .map_err(|error| super::forge_error_of_client(&error))?;
    let record = snapshot.record();
    Ok(json!({
        "execution_id": record.id().into_uuid(),
        "workspace_id": record.workspace_id().into_uuid(),
        "activity_id": record.activity_id().into_uuid(),
        "state": execution_state_name(record.state()),
        "failure_code": record.failure_code().map(execution_failure_name),
        "revision": record.revision().get(),
        "created_at_ms": record.timestamps().created_at().get(),
        "updated_at_ms": record.timestamps().updated_at().get(),
        "terminal": record.state().is_terminal(),
        "generated_package": snapshot.generated_package().map(generated_package_json),
    }))
}

fn generated_package_json(value: GeneratedPackageManifest) -> Value {
    json!({
        "kind": generated_package_kind(value.kind()),
        "file_name": value.kind().file_name(),
        "content_hash": value.content_hash().to_string(),
        "byte_count": value.byte_count().get(),
    })
}

const fn generated_package_kind(value: GeneratedArtifactKind) -> &'static str {
    match value {
        GeneratedArtifactKind::MacOsInstallerPackage => "mac_os_installer_package",
    }
}

pub(super) const fn execution_state_name(value: ExecutionState) -> &'static str {
    match value {
        ExecutionState::Starting => "starting",
        ExecutionState::Running => "running",
        ExecutionState::Completed => "completed",
        ExecutionState::Failed => "failed",
        ExecutionState::TimedOut => "timed_out",
        ExecutionState::Cancelled => "cancelled",
        ExecutionState::Interrupted => "interrupted",
    }
}

pub(super) const fn execution_failure_name(value: ExecutionFailureCode) -> &'static str {
    match value {
        ExecutionFailureCode::Admission => "admission",
        ExecutionFailureCode::SandboxUnavailable => "sandbox_unavailable",
        ExecutionFailureCode::InvalidWorkingDirectory => "invalid_working_directory",
        ExecutionFailureCode::ProcessSpawn => "process_spawn",
        ExecutionFailureCode::Supervision => "supervision",
    }
}
