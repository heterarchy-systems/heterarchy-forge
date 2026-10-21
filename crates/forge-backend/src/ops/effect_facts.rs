//! Strict HTTP adapter for the delegated effect-fact outbox.

use forge_control::EffectFactOutboxReadRequest;
use forge_control::ForgeControlClient;
use forge_domain::ForgeBackendId;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{ScopeDto, decode_scope};
use crate::error::ForgeError;

pub mod wire;

const MAX_EFFECT_FACT_PAGE: u32 = 64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectFactOutboxBody {
    scope: ScopeDto,
    migration_id: Uuid,
    destination_id: Uuid,
    after: u64,
    limit: u32,
}

/// A validated delegated effect-fact outbox read. The raw scope DTO is kept
/// for the response header; the typed request is the only value passed to
/// Forge control.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectFactOutboxCommand {
    scope: ScopeDto,
    request: EffectFactOutboxReadRequest,
}

/// Parse one strict, preadmission bounded outbox read.
pub(super) fn parse(value: &Value) -> Result<EffectFactOutboxCommand, ForgeError> {
    let body: EffectFactOutboxBody =
        super::parse_body(value, "effect_fact.outbox payload is invalid")?;
    require_id(body.scope.workspace_id, "scope workspace id")?;
    require_id(body.scope.locator.location_id, "scope location id")?;
    let migration_id = require_id(body.migration_id, "migration id")?;
    let destination_id = require_id(body.destination_id, "destination id")?;
    if body.after > i64::MAX as u64 {
        return Err(ForgeError::invalid_input(
            "effect fact outbox cursor exceeds the supported range",
        ));
    }
    if !(1..=MAX_EFFECT_FACT_PAGE).contains(&body.limit) {
        return Err(ForgeError::invalid_input(
            "effect fact outbox limit must be between 1 and 64",
        ));
    }
    let scope = decode_scope(&body.scope)?;
    let request = EffectFactOutboxReadRequest {
        scope,
        migration_id,
        destination_id,
        after: body.after,
        limit: body.limit,
    };
    Ok(EffectFactOutboxCommand {
        scope: body.scope,
        request,
    })
}

/// Read one delegated outbox page. The trusted host destination is checked
/// before the control client is invoked; the request never authenticates
/// itself by carrying a destination identity.
pub(super) fn execute(
    client: &ForgeControlClient,
    trusted_backend_id: ForgeBackendId,
    trusted_destination_id: Uuid,
    command: &EffectFactOutboxCommand,
) -> Result<Value, ForgeError> {
    if trusted_destination_id.is_nil() || trusted_destination_id != command.request.destination_id {
        return Err(ForgeError::auth_failed());
    }
    let entries = client
        .effect_fact_outbox(command.request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    let response = wire::EffectFactOutboxResponse::from_entries(
        command.scope.clone(),
        trusted_backend_id.into_uuid(),
        command.request.migration_id,
        command.request.destination_id,
        command.request.after,
        &entries,
    )?;
    serde_json::to_value(response).map_err(|_| ForgeError::internal())
}

fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must not be nil"
        )));
    }
    Ok(value)
}
